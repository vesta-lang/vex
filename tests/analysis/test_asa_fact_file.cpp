/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_asa_fact_file.cpp
 * @brief Que un hecho sobreviva al disco SIENDO EL MISMO hecho.
 *
 * El test EXIGE las propiedades de las que depende todo lo que se construya
 * encima, no que el fichero se escriba:
 *
 *  - que la DERIVACION siga en pie al volver: un hecho que se apoyaba en otro
 *    tiene que seguir apoyandose en ese y no en el vecino, con los
 *    identificadores recolocados sobre lo que ya hubiera en el almacen;
 *  - que los nombres de productor recuperen su LITERAL, porque ASA los compara
 *    por direccion y una cadena recien leida no se reconoceria a si misma;
 *  - que una huella que no cuadra NO se lea -- responder con hechos de otro
 *    programa es peor que no responder --;
 *  - que un dominio desconocido SE SALTE en vez de romper el fichero, que es lo
 *    que permite añadir productores sin invalidar las caches escritas antes;
 *  - que un fichero truncado se descarte y lo diga;
 *  - y que el NIVEL de cache no cambie lo que se sabe, solo cuanto se guarda.
 */

#include "analysis/asa/fact_base.h"
#include "analysis/asa/fact_file.h"
#include "analysis/asa/fact_store.h"

#include <cstdio>
#include <cstring>
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

/// Un almacen pequeño con una derivacion de dos escalones y dos dominios.
static void poblar(FactStore &a) {
    Fact base;
    base.what.domain = kProducerStructure;
    base.what.code = "structure.shape";
    base.what.a = 3;
    base.what.b = 7;
    base.what.detail = a.intern("tres bloques");
    base.about.kind = Subject::Kind::Function;
    base.about.function = a.intern("f");
    base.seal.certainty = Certainty::Proven;
    base.seal.origin.producer = kProducerStructure;
    base.seal.origin.function = a.intern("f");
    const FactId id_base = a.add(std::move(base));

    Fact rango;
    rango.what.domain = kProducerRanges;
    rango.what.code = "range.bounded";
    rango.what.a = -5;
    rango.what.b = 40;
    rango.what.detail = a.intern("del parametro");
    rango.about.kind = Subject::Kind::Value;
    rango.about.function = a.intern("f");
    rango.about.id = 12;
    rango.seal.certainty = Certainty::Inferred;
    rango.seal.origin.source = Source::Profile;
    rango.seal.origin.producer = kProducerRanges;
    rango.seal.origin.site = 12;
    rango.seal.support.add(kProducerStructure);
    rango.proof.rule = "flujo-de-datos";
    rango.proof.from.push_back(id_base);
    a.add(std::move(rango));
}

// ===========================================================================
// 1. Ida y vuelta: los hechos vuelven enteros y la derivacion se sostiene
// ===========================================================================
static void probar_ida_y_vuelta() {
    FactStore origen;
    poblar(origen);
    const std::vector<uint8_t> bytes =
        serialize(origen, 0xCAFEull, CacheLevel::All, {});
    CHECK(!bytes.empty(), "escribir dos hechos no puede dar un fichero vacio");

    FactStore destino;
    const ReadResult r =
        read_facts(bytes.data(), bytes.size(), 0xCAFEull, destino);
    CHECK(r.ok, "el fichero recien escrito tiene que poder leerse");
    CHECK(r.facts == 2, "vuelven los dos hechos");
    CHECK(r.domains == 2, "cada dominio es su propio registro");
    CHECK(r.lost_proofs == 0, "no se pierde ningun apoyo");
    CHECK(destino.size() == 2, "y quedan depositados en el almacen");

    const Fact &f0 = destino.at(0);
    CHECK(std::string(f0.what.code) == "structure.shape", "el codigo vuelve");
    CHECK(f0.what.a == 3 && f0.what.b == 7, "los numeros vuelven");
    CHECK(std::string(f0.what.detail) == "tres bloques", "el detalle vuelve");
    CHECK(f0.seal.certainty == Certainty::Proven, "la certeza vuelve");

    const Fact &f1 = destino.at(1);
    CHECK(f1.what.a == -5, "un numero negativo no se estropea al guardarlo");
    CHECK(f1.seal.origin.source == Source::Profile, "la fuente vuelve");
    CHECK(f1.about.kind == Subject::Kind::Value, "la clase de sujeto vuelve");
    CHECK(f1.about.id == 12, "y el valor del que habla");

    /* Lo que de verdad importa: el hecho derivado sigue apoyandose EN EL MISMO,
     * y se puede recorrer hacia atras.  Sin esto el fichero guardaria hechos
     * sueltos y no conocimiento. */
    CHECK(f1.proof.from.size() == 1, "el apoyo sobrevive");
    CHECK(f1.proof.from[0] == 0, "y apunta al hecho que lo sostiene");
    CHECK(std::string(f1.proof.rule) == "flujo-de-datos", "la regla vuelve");
    CHECK(destino.explain(1).size() == 2, "la derivacion se recorre entera");
}

// ===========================================================================
// 2. Los nombres vuelven a SER los literales (ASA compara por direccion)
// ===========================================================================
static void probar_identidad_de_nombres() {
    FactStore origen;
    poblar(origen);
    const std::vector<uint8_t> bytes =
        serialize(origen, 1, CacheLevel::All, {});
    FactStore destino;
    read_facts(bytes.data(), bytes.size(), 1, destino);

    CHECK(destino.at(0).what.domain == kProducerStructure,
          "el dominio vuelve a ser el literal, no una copia");
    CHECK(destino.at(1).seal.origin.producer == kProducerRanges,
          "el productor tambien");
    CHECK(destino.at(1).seal.support.depends_on(kProducerStructure),
          "y por eso la dependencia se sigue reconociendo");
    /* Y la consulta por dominio, que va indexada por ese mismo puntero. */
    CHECK(destino.of_domain(kProducerRanges).size() == 1,
          "un hecho de disco se encuentra buscando por su dominio");
}

// ===========================================================================
// 3. Se AÑADE a lo que ya hay, recolocando los identificadores
// ===========================================================================
static void probar_anade_sobre_lo_existente() {
    FactStore origen;
    poblar(origen);
    const std::vector<uint8_t> bytes =
        serialize(origen, 2, CacheLevel::All, {});

    FactStore destino;
    Fact previo;
    previo.what.domain = kProducerLoops;
    previo.what.code = "loop.shape";
    destino.add(std::move(previo));

    const ReadResult r = read_facts(bytes.data(), bytes.size(), 2, destino);
    CHECK(r.ok && destino.size() == 3, "lo leido se suma a lo que ya habia");
    /* El apoyo se ha corrido: el hecho base ya no es el 0, es el 1. */
    CHECK(destino.at(2).proof.from.size() == 1 &&
              destino.at(2).proof.from[0] == 1,
          "los apoyos se recolocan sobre el almacen destino");
}

/**
 * @brief Leer DOS VECES sobre el mismo almacen no duplica nada.
 *
 * Es lo normal, no un caso raro: una compilacion abre la puerta una vez por
 * MOMENTO -- lo de antes de optimizar y lo de despues -- y cada apertura lee
 * el fichero entero, que trae los dos.  Sin esto, la segunda lectura volvia a
 * meter lo que la primera acababa de cargar; y como despues se vuelve a
 * escribir, el fichero crecia SOLO en cada compilacion.  Medido antes del
 * arreglo, sobre el mismo programa: 102 hechos, 306, 714, sin tope.
 *
 * No fallaba, no decia nada, y el almacen acababa afirmando lo mismo tres
 * veces -- que para un consumidor que CUENTA (cuantos accesos no se saben
 * localizar, cuantas vueltas da un bucle) no es ruido: es otra respuesta.
 */
static void read_twice_does_not_duplicate() {
    FactStore origen;
    poblar(origen);
    const std::vector<uint8_t> bytes =
        serialize(origen, 7, CacheLevel::All, {});

    FactStore destino;
    const ReadResult r1 = read_facts(bytes.data(), bytes.size(), 7, destino);
    CHECK(r1.ok && destino.size() == origen.size(),
          "la primera lectura trae todo");
    const size_t tras_una = destino.size();

    const ReadResult r2 = read_facts(bytes.data(), bytes.size(), 7, destino);
    CHECK(r2.ok, "la segunda lectura tampoco falla");
    CHECK(destino.size() == tras_una,
          "y NO anade nada: lo que ya esta no se vuelve a traer");
    CHECK(r2.duplicates > 0,
          "y se dice cuantos se saltaron, que no es lo mismo que no leerlos");
    CHECK(r2.facts == 0, "no deposito ninguno");
}

/**
 * @brief Copiar un almacen copia TAMBIEN sus cadenas.
 *
 * Un hecho guarda `const char *` que apuntan al arena de SU almacen.  La copia
 * por defecto duplicaba los hechos y dejaba los punteros mirando al arena del
 * ORIGINAL: en cuanto ese moria -- y muere, es una local de la compilacion --
 * el detalle de cada hecho era memoria ajena.  En el volcado salia como bytes
 * sin sentido donde tenia que ir el intervalo, y eso es lo BENIGNO: son
 * punteros colgando.
 *
 * Se comprueba con el original ya DESTRUIDO, que es la unica forma de que el
 * fallo se manifieste: mientras vive, los punteros colgados siguen leyendo lo
 * que habia y el test pasaria sin probar nada.
 */
static void copying_leaves_no_dangling_pointers() {
    FactStore copia;
    {
        FactStore original;
        Fact f;
        f.what.domain = kProducerRanges;
        f.what.code = "range.bounded";
        f.what.detail = original.intern("[0,64] i64");
        f.about.kind = Subject::Kind::Value;
        f.about.function = original.intern("una_funcion_con_nombre_largo");
        f.seal.origin.producer = kProducerRanges;
        f.proof.rule = "data-flow";
        original.add(std::move(f));
        copia = original; // <- la copia que hacia el compilador
    } // aqui muere el original, y con el su arena de cadenas

    CHECK(copia.size() == 1, "el hecho sobrevive a la copia");
    if (copia.size() != 1) return;
    const Fact &f = copia.at(0);
    CHECK(std::string(f.what.detail) == "[0,64] i64",
          "y su detalle sigue siendo el suyo, no memoria ajena");
    CHECK(std::string(f.about.function) == "una_funcion_con_nombre_largo",
          "y el nombre de la funcion tambien");
    /* Los nombres CANONICOS se conservan como literales: el ASA compara
     * productores y dominios por DIRECCION, asi que una copia interna no se
     * reconoceria a si misma. */
    CHECK(f.what.domain == kProducerRanges,
          "el dominio sigue siendo el literal canonico, no una copia");
    CHECK(copia.of_domain(kProducerRanges).size() == 1,
          "y por eso se sigue encontrando buscando por su dominio");
}

// ===========================================================================
// 4. Una huella que no cuadra no se lee
// ===========================================================================
static void probar_huella() {
    FactStore origen;
    poblar(origen);
    const std::vector<uint8_t> bytes =
        serialize(origen, 0xAAAAull, CacheLevel::All, {});

    FactStore destino;
    const ReadResult r =
        read_facts(bytes.data(), bytes.size(), 0xBBBBull, destino);
    CHECK(!r.ok, "hechos de otro modulo no se aceptan");
    CHECK(destino.size() == 0, "y no se deposita nada a medias");
    /* Y el motivo es un DATO con su codigo de catalogo, no una frase: quien lo
     * enseñe lo hace en el idioma de quien compila. */
    CHECK(r.reason == ReadReason::OtherModule, "y se dice por que, como dato");
    CHECK(std::string(diag_code(r.reason)) == "VXA042",
          "con su codigo del catalogo multi-idioma");
}

// ===========================================================================
// 5. Un dominio desconocido se SALTA; el resto del fichero se lee
// ===========================================================================
static void probar_dominio_desconocido() {
    FactStore origen;
    poblar(origen);
    const std::vector<uint8_t> bytes =
        serialize(origen, 3, CacheLevel::All, {});

    /* Se simula un productor de otra version tocando la version DEL PRIMER
     * REGISTRO.  Es lo que pasaria de verdad: alguien cambia el contenido de su
     * dominio y las caches escritas antes traen el layout viejo.
     *
     * Y se REHACEN LAS SUMAS, que es la parte que importa: un fichero escrito
     * por otra version tiene las suyas bien.  Sin rehacerlas esto no seria un
     * fichero de otra version sino uno corrupto, y se estaria comprobando otra
     * cosa -- que es justo lo que pasaba antes de que hubiera sumas. */
    std::vector<uint8_t> tocado = bytes;
    const std::string marca(kProducerStructure);
    size_t pos = std::string::npos;
    for (size_t i = 0; i + marca.size() <= tocado.size(); ++i) {
        if (std::memcmp(tocado.data() + i, marca.data(), marca.size()) == 0) {
            pos = i;
            break;
        }
    }
    CHECK(pos != std::string::npos, "el nombre del dominio esta en el fichero");
    if (pos == std::string::npos) return;
    tocado[pos + marca.size()] = 0xFE; // version del hecho, byte bajo.

    /* El registro empieza en la longitud del nombre (4 bytes antes de el); su
     * suma vive tras la version (2) y la huella (8), y el cuerpo acaba donde
     * dice la longitud que va detras. */
    const size_t ini = pos - 4;
    const size_t pos_suma = pos + marca.size() + 2 + 8;
    size_t q = pos_suma + 8;
    uint32_t longitud = 0;
    for (int k = 0; k < 4; ++k)
        longitud |=
            static_cast<uint32_t>(tocado[q + 4 + static_cast<size_t>(k)])
            << (8 * k);
    const size_t fin = q + 8 + longitud;
    const uint64_t suma = record_checksum(tocado.data(), ini, pos_suma, fin);
    for (int k = 0; k < 8; ++k)
        tocado[pos_suma + static_cast<size_t>(k)] =
            static_cast<uint8_t>(suma >> (8 * k));
    const uint64_t global = file_checksum(tocado.data(), tocado.size());
    for (int k = 0; k < 8; ++k)
        tocado[tocado.size() - kTailBytes + 8 + static_cast<size_t>(k)] =
            static_cast<uint8_t>(global >> (8 * k));

    FactStore destino;
    const ReadResult r = read_facts(tocado.data(), tocado.size(), 3, destino);
    CHECK(r.ok, "un dominio ilegible no invalida el fichero entero");
    CHECK(r.skipped == 1, "se cuenta el registro que no se entendio");
    CHECK(r.facts == 1, "y se lee el que si");
    CHECK(r.lost_proofs == 1,
          "el apoyo que se quedo fuera se PIERDE y se cuenta");
    CHECK(destino.at(0).proof.from.empty(),
          "nunca se guarda una referencia a un hecho que no existe");
}

// ===========================================================================
// 6. Un fichero truncado se descarta y lo dice
// ===========================================================================
static void probar_truncado() {
    FactStore origen;
    poblar(origen);
    std::vector<uint8_t> bytes = serialize(origen, 4, CacheLevel::All, {});
    bytes.resize(bytes.size() / 2);

    FactStore destino;
    const ReadResult r = read_facts(bytes.data(), bytes.size(), 4, destino);
    CHECK(!r.ok, "medio fichero no se da por bueno");
    CHECK(destino.size() == 0, "y no se deposita lo que se alcanzo a leer");
}

// ===========================================================================
// 7. El nivel decide CUANTO se guarda, nunca QUE se sabe
// ===========================================================================
static void probar_niveles() {
    FactStore origen;
    poblar(origen);

    /* Estructura es cara de rehacer; rangos, barato y recomputable. */
    const std::vector<DomainCost> costes = {
        {kProducerStructure, 50000, false},
        {kProducerRanges, 10, true},
    };

    CHECK(serialize(origen, 5, CacheLevel::Off, costes).empty(),
          "con la cache apagada no se escribe nada");

    FactStore d_min;
    const std::vector<uint8_t> b_min =
        serialize(origen, 5, CacheLevel::Minimum, costes);
    read_facts(b_min.data(), b_min.size(), 5, d_min);
    CHECK(d_min.size() == 1,
          "el minimo guarda solo lo que no se puede rehacer");

    FactStore d_coste;
    const std::vector<uint8_t> b_coste =
        serialize(origen, 5, CacheLevel::ByCost, costes);
    read_facts(b_coste.data(), b_coste.size(), 5, d_coste);
    CHECK(d_coste.size() == 1, "por coste descarta lo barato de rehacer");

    FactStore d_todo;
    const std::vector<uint8_t> b_todo =
        serialize(origen, 5, CacheLevel::All, costes);
    read_facts(b_todo.data(), b_todo.size(), 5, d_todo);
    CHECK(d_todo.size() == 2, "y el nivel maximo se lo lleva todo");

    /* La regla que hace sano el sistema: los niveles son MONOTONOS.  Lo que
     * guarda uno lo guarda el siguiente, asi que cambiar de nivel no invalida
     * lo que ya hay en disco -- solo deja de producir mas. */
    CHECK(b_min.size() <= b_coste.size() && b_coste.size() <= b_todo.size(),
          "cada nivel contiene al anterior");

    /* Y por coste, con el mismo dominio caro pero recomputable, sigue entrando:
     * el criterio es lo que cuesta rehacerlo, no su naturaleza. */
    const std::vector<DomainCost> caro = {
        {kProducerStructure, 50000, true},
        {kProducerRanges, 10, true},
    };
    FactStore d_caro;
    const std::vector<uint8_t> b_caro =
        serialize(origen, 5, CacheLevel::ByCost, caro);
    read_facts(b_caro.data(), b_caro.size(), 5, d_caro);
    CHECK(d_caro.size() == 1, "lo recomputable pero caro tambien se guarda");
}

// ===========================================================================
// 7b. La invalidacion es POR DOMINIO, no todo-o-nada
//
// Es lo que hace util reutilizar entre compilaciones.  Con una sola huella --
// la del modulo -- tocar una linea de una funcion tiraba TODO, incluido lo que
// no depende del codigo: la alineacion de una seccion no cambia porque alguien
// renombre una variable.
//
// La huella de cada registro se compara con la que HOY tiene ese dominio, y ahi
// hay tres respuestas y no dos: coincide (vale), no coincide (caduco) y cero
// (no se puede comprobar, se acepta).  La tercera es la que permite que los
// dominios aprendan a decirlo de uno en uno sin romper a los demas.
// ===========================================================================
static void probar_invalidacion_por_dominio() {
    FactStore origen;
    poblar(origen);

    /* Se guarda diciendo de que dependia cada uno al producirlo. */
    const std::vector<DomainCost> al_guardar = {
        {kProducerStructure, 100, true, 0xAAAAull},
        {kProducerRanges, 100, true, 0xBBBBull},
    };
    const std::vector<uint8_t> bytes =
        serialize(origen, 7, CacheLevel::All, al_guardar);

    /* 1. Todo igual: se reutiliza entero. */
    FactStore igual;
    read_facts(bytes.data(), bytes.size(), 7, igual, al_guardar);
    CHECK(igual.size() == origen.size(),
          "si nada de lo que miraban cambio, se reutiliza todo");

    /* 2. Cambia lo que mira UNO: cae ese y el otro sobrevive.  Es el caso que
     *    justifica todo el mecanismo. */
    const std::vector<DomainCost> uno_cambio = {
        {kProducerStructure, 100, true, 0xAAAAull},
        {kProducerRanges, 100, true, 0xCCCCull}, // otra cosa mira ahora
    };
    FactStore parcial;
    const ReadResult r =
        read_facts(bytes.data(), bytes.size(), 7, parcial, uno_cambio);
    CHECK(r.stale == 1, "solo caduca el dominio cuyas entradas cambiaron");
    CHECK(parcial.size() > 0 && parcial.size() < origen.size(),
          "y lo del otro se conserva en vez de rehacerse");

    /* 3. Un dominio que NO sabe decir de que depende no sale en la lista, y
     *    entonces lo suyo se acepta sin comprobar.  No es lo mismo que decir
     *    cero: es no haber dicho nada, y tiene que seguir funcionando como
     *    antes de que existiera este mecanismo. */
    FactStore sin_saber;
    read_facts(bytes.data(), bytes.size(), 7, sin_saber, {});
    CHECK(sin_saber.size() == origen.size(),
          "quien no sabe decir de que depende no se invalida por sorpresa");
}

// ===========================================================================
// 8. Un almacen vacio no escribe fichero (no hay nada que decir)
// ===========================================================================
static void probar_vacio() {
    FactStore vacio;
    CHECK(serialize(vacio, 6, CacheLevel::All, {}).empty(),
          "sin hechos no se escribe un fichero con solo cabecera");

    FactStore destino;
    const ReadResult r = read_facts(nullptr, 0, 6, destino);
    CHECK(!r.ok && r.reason == ReadReason::Empty,
          "leer nada dice por que no se pudo");
    CHECK(diag_code(ReadReason::Ok)[0] == '\0',
          "y cuando todo fue bien no hay nada que contar");
}

// ===========================================================================
// 9. La cache es GRANULAR: tocar un dominio no tira los demas
// ===========================================================================
static void probar_granularidad() {
    FactStore origen;
    poblar(origen);

    /* Cada dominio guarda la huella de LO QUE EL MIRO. */
    std::vector<DomainCost> escritos = {
        {kProducerStructure, 0, true, 0x1111ull},
        {kProducerRanges, 0, true, 0x2222ull},
    };
    const std::vector<uint8_t> bytes =
        serialize(origen, 7, CacheLevel::All, escritos);

    /* Cambia lo que miraba UNO de los dos.  Lo suyo caduca; lo del otro no. */
    std::vector<DomainCost> vigentes = {
        {kProducerStructure, 0, true, 0x1111ull},
        {kProducerRanges, 0, true, 0x9999ull},
    };
    FactStore destino;
    const ReadResult r =
        read_facts(bytes.data(), bytes.size(), 7, destino, vigentes);
    CHECK(r.ok, "que un dominio caduque no invalida el fichero");
    CHECK(r.stale == 1, "caduca solo el registro cuya huella cambio");
    CHECK(r.facts == 1, "y se conserva lo del dominio que no se toco");
    CHECK(destino.at(0).what.domain == kProducerStructure,
          "lo que sobrevive es justo lo que no dependia de lo que cambio");

    /* Sin decir nada, se acepta todo: no se puede comprobar, y suponer lo peor
     * tiraria una cache que probablemente vale. */
    FactStore d2;
    CHECK(read_facts(bytes.data(), bytes.size(), 7, d2).facts == 2,
          "quien no dice de que depende se queda como estaba");

    /* Y un dominio que no supo decir de que dependia tampoco se puede tirar. */
    std::vector<DomainCost> sin_huella = {{kProducerStructure, 0, true, 0}};
    const std::vector<uint8_t> b2 =
        serialize(origen, 7, CacheLevel::All, sin_huella);
    FactStore d3;
    CHECK(read_facts(b2.data(), b2.size(), 7, d3, vigentes).stale == 0,
          "sin huella no hay nada que comparar, asi que no caduca");
}

int main() {
    std::printf("=== ASA: los hechos sobreviven al disco ===\n");
    /* El formato no conoce a los productores de nadie, asi que quien tenga
     * literales estables los da de alta.  En el compilador lo hace la base de
     * hechos al construirse; aqui, que no hay ninguna, se hace a mano -- y que
     * el test tenga que hacerlo es justo lo que documenta el requisito. */
    register_asa_canonical_names();
    probar_ida_y_vuelta();
    probar_identidad_de_nombres();
    probar_anade_sobre_lo_existente();
    read_twice_does_not_duplicate();
    copying_leaves_no_dangling_pointers();
    probar_huella();
    probar_dominio_desconocido();
    probar_truncado();
    probar_niveles();
    probar_invalidacion_por_dominio();
    probar_vacio();
    probar_granularidad();
    std::printf("%d comprobaciones, %d fallos\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
