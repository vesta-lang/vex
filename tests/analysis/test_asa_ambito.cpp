/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file test_asa_ambito.cpp
 * @brief DONDE vale un hecho: el alcance y su vocabulario.
 *
 * El alcance decide si un consumidor VE un hecho, y por eso su forma de fallar
 * es peor que la de un calculo mal hecho: un hecho mal sellado no da un
 * resultado equivocado, da SILENCIO.  El consumidor pregunta, no encuentra
 * nada, y se comporta como si el conocimiento no existiera -- que es
 * exactamente lo que no se puede distinguir de "no se sabe".
 *
 * Eso paso de verdad: el hecho de la alineacion de `.data` estaba sellado como
 * `backend = "vm"` y era cierto tambien con el JIT, que parte del mismo
 * bytecode.  Un consumidor que preguntara desde el JIT no lo encontraba, y el
 * hecho llevaba ahi meses sin que nadie lo notara, porque no habia nada que
 * mirar: solo faltaba una respuesta.
 *
 * Se fija tambien el VOCABULARIO, y no por gusto: esos nombres viajan al
 * fichero de hechos y al MCP.  Cambiar uno no rompe la compilacion -- son
 * cadenas --, rompe la lectura de lo que ya se guardo.
 */

#include "analysis/asa/fact.h"
#include "analysis/asa/fact_file.h"
#include "analysis/asa/fact_store.h"
#include "analysis/asa/producers.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <vector>
#include <cstring>

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

/// @brief Un alcance suelto, para no repetir la construccion en cada caso.
static Scope scope(const char *isa, const char *os, const char *backend) {
    Scope a;
    a.isa = isa;
    a.os = os;
    a.backend = backend;
    return a;
}

/**
 * @brief Un campo vacio vale en cualquiera; uno puesto tiene que coincidir.
 */
static void empty_field_matches_anything() {
    std::printf("-- un campo vacio vale en cualquier sitio\n");

    const Scope universal = scope("", "", "");
    CHECK(universal.universal(), "sin ningun campo, el alcance es universal");
    CHECK(universal.holds_in(scope(kIsaX8664, kOsLinux, kBackendAot)),
          "y por tanto vale en un objetivo concreto");

    const Scope only_x86 = scope(kIsaX8664, "", "");
    CHECK(!only_x86.universal(), "con un campo puesto ya no es universal");
    CHECK(only_x86.holds_in(scope(kIsaX8664, kOsWindows, kBackendAot)),
          "coincide la isa y los demas campos no lo restringen");
    CHECK(!only_x86.holds_in(scope(kIsaArm64, kOsLinux, kBackendAot)),
          "otra isa NO lo ve");
}

/**
 * @brief La regresion: un hecho del bytecode se ve desde el interprete Y desde
 *        el JIT, y no desde el nativo.
 *
 * Es LA propiedad que se rompio.  El bytecode es una ISA mas, asi que lo que
 * vale "porque lo coloco el cargador de la maquina" se sella por `isa` y no por
 * `backend`: los dos backends que cargan bytecode lo ven, y ademas queda dicho
 * POR QUE vale en vez de enumerar donde.
 */
static void bytecode_fact_visible_in_both() {
    std::printf("-- un hecho del bytecode lo ven el interprete y el JIT\n");

    const Scope from_bytecode = scope(kIsaVelb, "", "");

    CHECK(from_bytecode.holds_in(scope(kIsaVelb, kOsLinux, kBackendVm)),
          "lo ve el interprete");
    CHECK(from_bytecode.holds_in(scope(kIsaVelb, kOsLinux, kBackendJit)),
          "y lo ve el JIT, que parte del mismo bytecode");
    CHECK(!from_bytecode.holds_in(scope(kIsaX8664, kOsLinux, kBackendAot)),
          "y NO lo ve el nativo, donde no hay cargador de la maquina");

    /* Y la forma ANTIGUA, para dejar dicho por que no valia: sellando por
     * backend, el mismo hecho se volvia invisible desde el JIT. */
    const Scope scoped_by_backend = scope("", "", kBackendVm);
    CHECK(!scoped_by_backend.holds_in(scope(kIsaVelb, kOsLinux, kBackendJit)),
          "sellar por backend lo escondia del JIT: por eso se sella por isa");
}

/**
 * @brief Los tres ejes se cruzan sin mezclarse.
 */
static void axes_are_independent() {
    std::printf("-- los tres ejes se cruzan y no se confunden\n");

    // "Solo en Windows, da igual la isa y el backend."
    const Scope only_windows = scope("", kOsWindows, "");
    CHECK(only_windows.holds_in(scope(kIsaArm64, kOsWindows, kBackendJit)),
          "vale en Windows con cualquier isa y cualquier backend");
    CHECK(!only_windows.holds_in(scope(kIsaArm64, kOsLinux, kBackendJit)),
          "y no vale en Linux");

    // Los dos ejes a la vez tienen que cumplirse LOS DOS.
    const Scope x86_on_linux = scope(kIsaX8664, kOsLinux, "");
    CHECK(x86_on_linux.holds_in(scope(kIsaX8664, kOsLinux, kBackendAot)),
          "cumple los dos campos");
    CHECK(!x86_on_linux.holds_in(scope(kIsaX8664, kOsWindows, kBackendAot)),
          "falla uno y ya no vale");
}

/**
 * @brief El MOMENTO es un eje mas, y se cruza con los otros.
 *
 * Es el eje que faltaba, y su ausencia no daba un error: daba una respuesta.
 * "Este bucle da 64 vueltas" es cierto antes de optimizar y falso despues --
 * el desenrollador lo convierte en cuatro de dieciseis --, asi que sin el
 * momento el mismo hecho valia en un codigo donde no vale.  Y peor: un sujeto
 * de valor nombra un id, y el optimizador los renumera, con lo que preguntar
 * fuera de su momento no lee un valor equivocado por poco -- lee otro valor.
 */
static void stage_is_an_axis_too() {
    std::printf("-- el momento tambien es un eje\n");

    Scope pre;
    pre.stage = kStagePreOpt;
    Scope post;
    post.stage = kStagePostOpt;
    Scope during;
    during.stage = kStageDuringOpt;

    CHECK(pre.holds_in(pre), "lo de antes de optimizar vale antes de optimizar");
    CHECK(!pre.holds_in(post), "y NO vale despues");
    CHECK(!post.holds_in(pre), "ni al reves");
    CHECK(!pre.holds_in(during), "ni en medio: son tres, no dos");

    /* Vacio en el HECHO = vale en cualquier momento.  Es lo correcto para lo
     * que el optimizador no puede cambiar: cuantos parametros declara una
     * funcion no depende de si ya se optimizo. */
    const Scope siempre;
    CHECK(siempre.holds_in(pre) && siempre.holds_in(post) &&
              siempre.holds_in(during),
          "un hecho sin momento vale en todos");

    /* Vacio en la PREGUNTA no es "cualquiera": es no casar con ninguno de los
     * sellados.  A proposito -- asi un consumidor no puede leer por descuido
     * hechos de un codigo que ya no existe --, y por eso quien pregunta tiene
     * que decir en que momento esta. */
    CHECK(!pre.holds_in(Scope{}),
          "preguntar sin momento no trae los hechos sellados con uno");

    // Y se cruza con los demas ejes: tienen que cumplirse TODOS.
    Scope x86_post;
    x86_post.isa = kIsaX8664;
    x86_post.stage = kStagePostOpt;
    Scope aqui;
    aqui.isa = kIsaX8664;
    aqui.stage = kStagePostOpt;
    CHECK(x86_post.holds_in(aqui), "misma isa y mismo momento");
    aqui.stage = kStagePreOpt;
    CHECK(!x86_post.holds_in(aqui), "misma isa pero otro momento: no vale");

    // El vocabulario viaja al disco: se comprueba por VALOR, no por identidad.
    CHECK(std::string(kStagePreOpt) == "pre-opt", "kStagePreOpt");
    CHECK(std::string(kStageDuringOpt) == "in-opt", "kStageDuringOpt");
    CHECK(std::string(kStagePostOpt) == "post-opt", "kStagePostOpt");

    // Un alcance que SOLO restringe el momento sigue siendo restringido, asi
    // que tiene que justificarse igual que cualquier otro.
    CHECK(!post.universal(), "restringir el momento es restringir");
    CHECK(!post.justified(), "y sin motivo no esta justificado");
}

/**
 * @brief El vocabulario, fijado.
 *
 * Estos nombres se ESCRIBEN en el fichero de hechos y se sirven por el MCP.
 * Cambiar uno no rompe ninguna compilacion -- son cadenas --, rompe la lectura
 * de lo que ya se guardo y la de cualquier consumidor de fuera.  Por eso se
 * comprueban por valor y no por identidad.
 */
static void vocabulary_is_pinned() {
    std::printf("-- el vocabulario de los tres ejes\n");

    CHECK(std::strcmp(kBackendVm, "vm") == 0, "backend del interprete");
    CHECK(std::strcmp(kBackendJit, "jit") == 0, "backend del JIT");
    CHECK(std::strcmp(kBackendAot, "aot") == 0, "backend nativo");

    CHECK(std::strcmp(kIsaVelb, "velb") == 0, "el bytecode ES una isa");
    CHECK(std::strcmp(kIsaX8664, "x86-64") == 0, "x86-64");
    CHECK(std::strcmp(kIsaX8632, "x86-32") == 0, "x86-32");
    CHECK(std::strcmp(kIsaArm64, "aarch64") == 0, "aarch64");
    CHECK(std::strcmp(kIsaArm32, "arm") == 0, "arm de 32 bits");
    CHECK(std::strcmp(kIsaRiscv, "riscv") == 0, "riscv");

    CHECK(std::strcmp(kOsWindows, "windows") == 0, "windows");
    CHECK(std::strcmp(kOsLinux, "linux") == 0, "linux");

    /* El bytecode y el interprete NO comparten cadena aunque sean vecinos: son
     * ejes distintos, y con el mismo texto un sello equivocado pasaria
     * desapercibido al leerlo. */
    CHECK(std::strcmp(kIsaVelb, kBackendVm) != 0,
          "la isa del bytecode y el backend del interprete se distinguen");
}

/**
 * @brief Y el PRODUCTOR sella bien: no basta con que `holds_in` sea correcto.
 *
 * Lo de arriba fija la semantica del alcance; esto fija que el hecho salga con
 * el alcance que le toca.  Es la mitad que fallaba: `holds_in` siempre estuvo
 * bien, y el hecho se emitia mal.  Comprobar solo la semantica habria dejado
 * pasar el fallo entero.
 */
static void producer_scopes_by_isa() {
    std::printf("-- el productor sella el hecho del cargador por ISA\n");

    /* Un modulo minimo: una funcion que mirar y UN dato en `.data`.
     *
     * El dato hace falta porque el hecho es sobre la SECCION: sin nada que
     * colocar no hay nada que afirmar, y el productor calla -- con razon. */
    ir::IrModule mod;
    mod.name = "prueba";
    {
        const std::vector<uint8_t> ocho(8, 0);
        const size_t i = mod.static_data.push_back(ocho);
        mod.static_data.meta_at(i).section_name = ".data";
    }
    {
        ir::IrFunction fn;
        fn.name = "main";
        const uint32_t b0 = fn.new_block("entry");
        ir::IrInstr ret;
        ret.op = ir::IrOp::RET;
        ret.dst = ir::IR_NO_VALUE;
        fn.blocks[b0].instrs.push_back(ret);
        mod.functions.push_back(std::move(fn));
    }

    FactStore store;
    /* Con el momento: producir sin decirlo ya no se puede, y es a proposito --
     * un hecho sin momento valdria en todos, incluido aquel en el que es
     * falso. */
    produce(mod, store, {}, kStagePostOpt);

    // El hecho de la alineacion que coloca el cargador de la maquina.
    const Scope *found_scope = nullptr;
    for (const Fact &f : store.all()) {
        if (f.what.code != nullptr &&
            std::strcmp(f.what.code, "layout.section_alignment") == 0) {
            found_scope = &f.scope;
            break;
        }
    }
    CHECK(found_scope != nullptr,
          "el productor emite el hecho de la alineacion");
    if (found_scope == nullptr) return;

    CHECK(std::strcmp(found_scope->isa, kIsaVelb) == 0,
          "sellado por la ISA del bytecode, que es lo que explica el numero");
    CHECK(found_scope->backend == nullptr || found_scope->backend[0] == '\0',
          "y SIN restringir el backend: vale interpretando y con el JIT");
    /* Y el JIT lo encuentra desde SU momento.  Que haya que decirlo es la
     * regla, no un estorbo: el hecho se produjo mirando el codigo de despues
     * de optimizar, y preguntarlo desde otro momento seria leerlo sobre un
     * codigo que no es del que habla. */
    Scope desde_el_jit = scope(kIsaVelb, kOsLinux, kBackendJit);
    desde_el_jit.stage = kStagePostOpt;
    CHECK(found_scope->holds_in(desde_el_jit),
          "de modo que el JIT lo encuentra -- que es lo que fallaba");
}

/**
 * @brief La puerta de consulta distingue "no existe" de "existe y no vale
 * aqui".
 *
 * Es LO que arregla esta clase de fallo.  Devolver solo un puntero hace que las
 * dos situaciones se lean igual, y se arreglan de formas OPUESTAS: una
 * produciendo el hecho, la otra corrigiendo su alcance.
 */
static void query_tells_absent_from_out_of_scope() {
    std::printf(
        "-- consultar sabe decir si el hecho existe pero no vale aqui\n");

    FactStore store;
    {
        Fact f;
        f.what.domain = "prueba";
        f.what.code = "prueba.solo_nativo";
        f.scope.isa = kIsaX8664;
        f.scope.why = "prueba.exige_una_instruccion";
        f.seal.certainty = Certainty::Proven;
        store.add(f);
    }

    const auto from_native =
        store.find("prueba.solo_nativo", scope(kIsaX8664, "", kBackendAot));
    CHECK(static_cast<bool>(from_native), "desde x86-64 se encuentra");
    CHECK(from_native.out_of_scope == 0, "y no descarto nada");

    const auto from_arm =
        store.find("prueba.solo_nativo", scope(kIsaArm64, "", kBackendAot));
    CHECK(!from_arm, "desde arm64 no vale");
    CHECK(from_arm.out_of_scope == 1,
          "pero DICE que habia uno fuera de alcance: existe y esta mal sellado "
          "o preguntas desde otro sitio");

    const auto missing =
        store.find("prueba.no_existe", scope(kIsaArm64, "", kBackendAot));
    CHECK(!missing, "un hecho que no existe tampoco vale");
    CHECK(missing.out_of_scope == 0,
          "y se distingue del anterior: aqui NO hay nada que corregir");
}

/**
 * @brief Un hecho que no consulta nadie se puede saber.
 *
 * Es la senal que un test no puede dar: un test cubre lo que ya sospechabas, y
 * esto sale de lo que no sospechaba nadie.
 */
static void never_queried_is_reported() {
    std::printf("-- se sabe que hechos no miro nadie\n");

    FactStore store;
    for (const char *codigo : {"prueba.mirado", "prueba.olvidado"}) {
        Fact f;
        f.what.domain = "prueba";
        f.what.code = codigo;
        f.seal.certainty = Certainty::Proven;
        store.add(f);
    }

    CHECK(store.never_queried().size() == 2,
          "recien producidos, no los ha mirado nadie");

    const auto r = store.find("prueba.mirado", scope("", "", ""));
    CHECK(static_cast<bool>(r), "se consulta uno");

    const std::vector<FactId> unqueried = store.never_queried();
    CHECK(unqueried.size() == 1, "y queda uno sin mirar");
    CHECK(std::strcmp(store.at(unqueried.front()).what.code,
                      "prueba.olvidado") == 0,
          "y es el que nadie pidio");
}

/**
 * @brief Restringir el alcance obliga a decir por que.
 */
static void narrowing_requires_a_reason() {
    std::printf("-- restringir el alcance sin decir por que se detecta\n");

    CHECK(scope("", "", "").justified(),
          "el alcance universal no restringe: no necesita motivo");

    Scope no_reason = scope(kIsaArm64, "", "");
    CHECK(!no_reason.justified(),
          "restringir sin decir por que NO esta justificado");

    Scope with_reason = no_reason;
    with_reason.why = "prueba.solo_hay_esa_instruccion_ahi";
    CHECK(with_reason.justified(), "con el motivo puesto, si");
}

/**
 * @brief Lo que se guarda en disco vuelve IGUAL: alcance, motivo y por que.
 *
 * La cache es la unica pieza que puede cambiar lo que el compilador SABE sin
 * que nadie toque el codigo, y su forma de fallar es la peor de todas: no da un
 * error, da un hecho distinto.  Aqui fallaba de tres maneras a la vez, y las
 * tres eran mudas:
 *
 *   - cargar con el ambito por defecto DESCARTABA todo hecho sellado, porque
 *     `holds_in` mira si el ambito del hecho cabe en el de quien pregunta y uno
 *     vacio solo admite lo universal.  Se escribian dos hechos y volvia uno;
 *   - el POR QUE del alcance no se guardaba, asi que todo hecho sellado volvia
 *     sin justificar -- justo lo que el volcado marca como sospechoso;
 *   - la CLASE de lo que no se supo tampoco, asi que "se miro y no hay nada que
 *     decir" volvia como "no preguntado", que es la unica de las ocho que dice
 *     que el analisis NO corrio.
 *
 * Ninguna de las tres rompe una compilacion: cambian lo que se sabe, y eso solo
 * se ve si alguien lo compara.  Esto lo compara.
 */
static void disk_round_trip_keeps_scope_and_reason() {
    std::printf("-- lo guardado vuelve igual\n");

    FactStore written;
    {
        Fact f;
        f.what.domain = "prueba.disco";
        f.what.code = "prueba.sellado";
        f.what.a = 64;
        f.scope.isa = kIsaVelb;
        /* El MOMENTO tambien viaja.  Sin guardarlo, un hecho de antes de
         * optimizar volvia del disco valiendo tambien para despues -- y
         * nombrando ids que el optimizador ya habia renumerado --, que es un
         * fallo que no da error: da otra respuesta. */
        f.scope.stage = kStagePreOpt;
        f.scope.why = "prueba.lo_coloca_el_cargador";
        f.seal.certainty = Certainty::Proven;
        f.seal.origin.producer = "prueba.disco";
        written.add(std::move(f));
    }
    {
        Fact f;
        f.what.domain = "prueba.disco";
        f.what.code = "prueba.no_se_sabe";
        f.seal.certainty = Certainty::Unknown;
        f.seal.unknown_reason = UnknownReason::OpaqueBoundary;
        f.seal.origin.producer = "prueba.disco";
        written.add(std::move(f));
    }
    CHECK(written.size() == 2, "se parte de dos hechos");

    const std::vector<uint8_t> bytes = serialize(
        written, /*huella=*/1234, CacheLevel::All, {}, /*compilador=*/7);
    CHECK(!bytes.empty(), "y se empaquetan");

    FactStore read_back;
    const ReadResult r = read_facts(bytes.data(), bytes.size(), /*huella=*/1234,
                                    read_back, {}, /*compilador=*/7);
    CHECK(r.facts == 2, "vuelven los DOS, no uno");
    CHECK(r.out_of_scope == 0, "y ninguno se descarta por alcance");
    CHECK(read_back.size() == 2, "y quedan los dos en el almacen");

    const Fact *sealed = nullptr;
    const Fact *unknown = nullptr;
    for (const Fact &f : read_back.all()) {
        if (std::strcmp(f.what.code, "prueba.sellado") == 0) sealed = &f;
        if (std::strcmp(f.what.code, "prueba.no_se_sabe") == 0) unknown = &f;
    }
    CHECK(sealed != nullptr, "el sellado sobrevive al disco");
    if (sealed != nullptr) {
        CHECK(std::strcmp(sealed->scope.isa, kIsaVelb) == 0,
              "con su ISA intacta");
        CHECK(sealed->scope.justified(),
              "y con su motivo: un alcance sin por que no se puede comprobar");
        CHECK(std::strcmp(sealed->scope.stage, kStagePreOpt) == 0,
              "y con su MOMENTO: sin el valdria tambien despues de optimizar");
        CHECK(sealed->what.a == 64, "y con su valor");
    }
    CHECK(unknown != nullptr, "y el que no sabia, tambien");
    if (unknown != nullptr)
        CHECK(unknown->seal.unknown_reason == UnknownReason::OpaqueBoundary,
              "diciendo por que no sabia, no un generico 'no preguntado'");

    /* Y si quien lee SI dice donde esta, entonces si se estrecha: eso no es un
     * efecto colateral del defecto, es una peticion explicita. */
    FactStore narrowed;
    const ReadResult r2 = read_facts(bytes.data(), bytes.size(), 1234, narrowed,
                                     {}, 7, scope(kIsaX8664, "", ""));
    CHECK(r2.out_of_scope == 1,
          "pedido un ambito ajeno, el sellado se descarta");
    CHECK(narrowed.size() == 1, "y solo queda el que vale en cualquier sitio");
}

int main() {
    std::printf("=== test_asa_ambito ===\n");
    empty_field_matches_anything();
    bytecode_fact_visible_in_both();
    axes_are_independent();
    stage_is_an_axis_too();
    vocabulary_is_pinned();
    producer_scopes_by_isa();
    query_tells_absent_from_out_of_scope();
    never_queried_is_reported();
    narrowing_requires_a_reason();
    disk_round_trip_keeps_scope_and_reason();
    std::printf("=== test_asa_ambito: %d comprobaciones, %d fallidas ===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
