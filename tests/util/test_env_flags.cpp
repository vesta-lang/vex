/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_env_flags.cpp
 * @brief Que los mandos del entorno esten bien declarados y que sus huellas
 *        digan LO QUE TIENEN QUE DECIR.  Ver util/env_flags.h.
 *
 * Lo que se comprueba aqui no es que el codigo corra: es que la huella
 * reaccione exactamente a lo que cambia el binario y a nada mas.  Las dos
 * formas de equivocarse son opuestas y las dos son caras:
 *
 *   de menos  un mando cambia el codigo emitido y no entra en la huella -> la
 *             cache sirve un artefacto compilado con otra configuracion.  No da
 *             error: da un binario que no corresponde al fuente.
 *   de mas    un mando que solo imprime entra en la huella -> pedir tiempos
 *             invalida la cache entera y nadie entiende por que se recompila.
 */

#include "util/env_flags.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>

using namespace util;

static int g_checks = 0;
static int g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  FAIL: %s (linea %d)\n", (msg), __LINE__);           \
        }                                                                      \
    } while (0)

/// Pone (o quita) una variable y relee la tabla, que es lo unico que hace el
/// rebobinado del entorno visible.
static void set_env(const char *nombre, const char *valor) {
#if defined(_WIN32)
    std::string asig = std::string(nombre) + "=" + (valor ? valor : "");
    _putenv(asig.c_str());
#else
    if (valor)
        setenv(nombre, valor, 1);
    else
        unsetenv(nombre);
#endif
    reload_flags_for_testing();
}

/// La tabla esta bien formada: sin nombres repetidos ni vacios.
static void test_tabla_bien_formada() {
    std::set<std::string> vistos;
    for (size_t i = 0; i < kFlagCount; ++i) {
        const FlagInfo &fi = flag_info(static_cast<FlagId>(i));
        CHECK(fi.name != nullptr && fi.name[0] != '\0',
              "todo mando tiene nombre");
        /* Repetido = dos entradas con el mismo nombre.  Da igual cual gane: la
         * huella mezclaria el mismo nombre dos veces y el que lea el codigo
         * creeria que son mandos distintos. */
        CHECK(vistos.insert(fi.name).second == true,
              "ningun nombre repetido en la tabla");
    }
    CHECK(kFlagCount > 100, "la tabla tiene los mandos del proyecto");
}

/// El eje de sistema esta puesto donde toca.
///
/// Los mandos NUESTROS los definimos nosotros, asi que existen en cualquier
/// sistema.  Los del sistema operativo no: decir que `APPDATA` existe en Linux
/// o que `HOME` existe en Windows convierte la tabla en algo que no se puede
/// leer para saber de que depende una compilacion.
static void test_eje_de_sistema() {
    for (size_t i = 0; i < kFlagCount; ++i) {
        const FlagInfo &fi = flag_info(static_cast<FlagId>(i));
        const bool nuestro = std::strncmp(fi.name, "VESTA", 5) == 0 ||
                             std::strncmp(fi.name, "VX_", 3) == 0;
        if (nuestro)
            CHECK(fi.os == FlagOs::Any,
                  "un mando nuestro vale en cualquier sistema");
        if (fi.scope == FlagScope::Emitted)
            CHECK(fi.os == FlagOs::Any,
                  "lo que cambia el binario no puede ser de un solo sistema: "
                  "la huella tiene que significar lo mismo en todos");
    }
    /* Y que el campo se lea de verdad, no solo que este escrito. */
    CHECK(flag_applies_here(FlagOs::Any), "Any aplica siempre");
#if defined(_WIN32)
    CHECK(flag_applies_here(FlagOs::Windows), "en Windows, los de Windows");
    CHECK(!flag_applies_here(FlagOs::Posix), "en Windows, los de POSIX no");
#else
    CHECK(flag_applies_here(FlagOs::Posix), "en POSIX, los de POSIX");
    CHECK(!flag_applies_here(FlagOs::Windows), "en POSIX, los de Windows no");
#endif
}

/// Un informe ENCENDIDO por defecto imprime en cada ejecucion.
///
/// Y eso rompe todo lo que compara salidas.  Paso: `VESTA_PARALELO_STATS` se
/// declaro encendido por error y el interprete empezo a escribir una linea de
/// estadisticas de mas; dos casos e2e que comparan interprete contra AOT
/// empezaron a divergir, y el binario era identico -- la comparacion byte a
/// byte no lo veia porque no esta en el binario, esta en lo que escribe.
///
/// La unica excepcion es una comprobacion que solo habla cuando encuentra algo:
/// esa puede estar puesta sin ensuciar nada.
static void test_informe_no_esta_puesto_por_defecto() {
    for (size_t i = 0; i < kFlagCount; ++i) {
        const FlagInfo &fi = flag_info(static_cast<FlagId>(i));
        if (fi.scope != FlagScope::Report) continue;
        if (fi.kind != FlagKind::BoolOn) continue;
        /* Lista de los que SI pueden: se nombran uno a uno para que anadir
         * otro sea una decision y no un descuido. */
        const bool permitido = std::strcmp(fi.name, "VESTA_ASA_BOUNDS") ==
                               0; // solo avisa si falla
        CHECK(permitido,
              "un informe encendido por defecto imprime siempre y rompe "
              "cualquier comparacion de salidas");
    }
}

/// Sin nada puesto, no hay huella.  Cero, no la semilla del hash.
static void test_sin_mandos_no_hay_huella() {
    CHECK(emitted_fingerprint() == 0,
          "sin mandos puestos, la huella global es cero");
    CHECK(domain_fingerprint(FlagDomain::Optimizer) == 0,
          "sin mandos puestos, la huella del dominio es cero");
    CHECK(emitted_flags_summary().empty(),
          "sin mandos puestos, no hay nada que contar");
}

/// Un mando que cambia el codigo emitido SI entra en la huella de su dominio.
static void test_mando_emitido_entra() {
    const uint64_t antes = domain_fingerprint(FlagDomain::Optimizer);
    set_env("VESTA_NO_FUSE", "1");
    const uint64_t despues = domain_fingerprint(FlagDomain::Optimizer);
    CHECK(antes != despues, "un mando Emitted cambia la huella de su dominio");
    CHECK(despues != 0, "y esa huella ya no es cero");
    CHECK(emitted_fingerprint() != 0, "tambien cambia la huella global");
    CHECK(emitted_flags_summary().find("VESTA_NO_FUSE") != std::string::npos,
          "y se puede DECIR que estaba puesto");
    set_env("VESTA_NO_FUSE", nullptr);
    CHECK(domain_fingerprint(FlagDomain::Optimizer) == antes,
          "al quitarlo, la huella vuelve a lo que era");
}

/// Un mando que solo imprime NO entra.  Pedir tiempos no puede recompilar nada.
static void test_mando_de_informe_no_entra() {
    const uint64_t antes_global = emitted_fingerprint();
    const uint64_t antes_dom = domain_fingerprint(FlagDomain::None);
    set_env("VESTA_TIMES", "1");
    CHECK(emitted_fingerprint() == antes_global,
          "pedir tiempos no cambia la huella global");
    CHECK(domain_fingerprint(FlagDomain::None) == antes_dom,
          "pedir tiempos no cambia ninguna huella");
    set_env("VESTA_TIMES", nullptr);
}

/// El reparto por hilos no cambia lo que sale, asi que no entra.  Que sea
/// cierto lo sostiene tests/vx/incremental_identity_test.py, no este test.
static void test_reparto_no_entra() {
    const uint64_t antes = emitted_fingerprint();
    set_env("VESTA_PARALELO", "0");
    CHECK(emitted_fingerprint() == antes,
          "el reparto por hilos no entra en la huella");
    set_env("VESTA_PARALELO", nullptr);
}

/// LA GRANULARIDAD: tocar un dominio no mueve la huella de otro.  Es lo que
/// permite invalidar poco.
static void test_dominios_no_se_contaminan() {
    const uint64_t opt_antes = domain_fingerprint(FlagDomain::Optimizer);
    const uint64_t jit_antes = domain_fingerprint(FlagDomain::Jit);
    const uint64_t gc_antes = domain_fingerprint(FlagDomain::Gc);

    set_env("VESTA_JIT_NO_FRAMELESS", "1");
    CHECK(domain_fingerprint(FlagDomain::Jit) != jit_antes,
          "un mando del JIT mueve la huella del JIT");
    CHECK(domain_fingerprint(FlagDomain::Optimizer) == opt_antes,
          "pero NO la del optimizador");
    CHECK(domain_fingerprint(FlagDomain::Gc) == gc_antes,
          "ni la de la recoleccion de basura");
    set_env("VESTA_JIT_NO_FRAMELESS", nullptr);
}

/// Dos mandos distintos del mismo dominio dan huellas distintas.  Si no, la
/// huella no distingue configuraciones y sirve para poco.
static void test_mandos_distintos_huellas_distintas() {
    set_env("VESTA_NO_FUSE", "1");
    const uint64_t con_fuse = domain_fingerprint(FlagDomain::Optimizer);
    set_env("VESTA_NO_FUSE", nullptr);
    set_env("VESTA_NO_CMPJMP", "1");
    const uint64_t con_cmpjmp = domain_fingerprint(FlagDomain::Optimizer);
    set_env("VESTA_NO_CMPJMP", nullptr);
    CHECK(con_fuse != con_cmpjmp,
          "dos mandos distintos del mismo dominio no comparten huella");
}

/// El VALOR cuenta, no solo la presencia: un mando numerico con dos valores
/// distintos son dos configuraciones distintas.
static void test_el_valor_cuenta() {
    set_env("VESTA_MODULE_INIT_CHUNK", "64");
    const uint64_t a = domain_fingerprint(FlagDomain::Optimizer);
    set_env("VESTA_MODULE_INIT_CHUNK", "128");
    const uint64_t b = domain_fingerprint(FlagDomain::Optimizer);
    set_env("VESTA_MODULE_INIT_CHUNK", nullptr);
    CHECK(a != b, "cambiar el valor de un mando cambia la huella");
}

/// Los mandos ENCENDIDOS por defecto lo estan sin que nadie los ponga, y solo
/// "0" los apaga.  Es la otra convencion que habia en el codigo, y confundirla
/// con la primera apagaria catorce caminos que hoy son el normal.
static void test_encendidos_por_defecto() {
    set_env("VESTA_SCHED_ALIAS", nullptr);
    CHECK(flag_on(FlagId::SchedAlias), "un BoolOn esta encendido sin ponerlo");
    set_env("VESTA_SCHED_ALIAS", "0");
    CHECK(!flag_on(FlagId::SchedAlias), "\"0\" lo apaga");
    set_env("VESTA_SCHED_ALIAS", "1");
    CHECK(flag_on(FlagId::SchedAlias), "cualquier otra cosa lo deja encendido");
    set_env("VESTA_SCHED_ALIAS", nullptr);

    /* Y el contrario, para que la comprobacion signifique algo: un Bool normal
     * NO esta encendido si nadie lo pone. */
    set_env("VESTA_NO_FUSE", nullptr);
    CHECK(!flag_on(FlagId::NoFuse), "un Bool esta apagado si nadie lo pone");

    /* Apagar uno encendido-por-defecto SI es una configuracion distinta, asi
     * que tiene que notarse en la huella: es codigo distinto. */
    const uint64_t sin_tocar = domain_fingerprint(FlagDomain::Alias);
    set_env("VESTA_SCHED_ALIAS", "0");
    CHECK(domain_fingerprint(FlagDomain::Alias) != sin_tocar,
          "apagar un camino que era el normal cambia la huella");
    set_env("VESTA_SCHED_ALIAS", nullptr);
}

/// Las que el compilador se ESCRIBE a si mismo se releen.
///
/// `VESTA_MC_PREBUILT` no es un mando: es un canal.  `main` la escribe con
/// `putenv` a mitad de la compilacion para pasarle el artefacto comptime al
/// type checker.  Con el valor cacheado del arranque, la segunda fase leia lo
/// de antes de escribir -- y eso no dio error, dio 50 programas compilados de
/// otra forma.  Este test fija que se relee SIN releer la tabla entera.
static void test_valor_vivo_se_relee() {
    CHECK(flag_info(FlagId::McPrebuilt).kind == FlagKind::TextLive,
          "el canal comptime esta declarado como valor vivo");

    set_env("VESTA_MC_PREBUILT", nullptr);
    CHECK(flag_text(FlagId::McPrebuilt).empty(), "de partida, vacio");

    /* Escribir SIN avisar al registro, que es justo lo que hace `main`. */
#if defined(_WIN32)
    _putenv("VESTA_MC_PREBUILT=F:/algo/macros.velb");
#else
    setenv("VESTA_MC_PREBUILT", "F:/algo/macros.velb", 1);
#endif
    CHECK(flag_text(FlagId::McPrebuilt) == "F:/algo/macros.velb",
          "se ve el valor nuevo sin recargar la tabla");

#if defined(_WIN32)
    _putenv("VESTA_MC_PREBUILT=");
#else
    unsetenv("VESTA_MC_PREBUILT");
#endif
    CHECK(flag_text(FlagId::McPrebuilt).empty(), "y se ve cuando se borra");

    /* Y el contrario, para que la comprobacion signifique algo: una cadena
     * NORMAL se lee una vez, y escribirla por detras no la cambia. */
    set_env("VX_CACHE_DIR", "F:/uno");
#if defined(_WIN32)
    _putenv("VX_CACHE_DIR=F:/otro");
#else
    setenv("VX_CACHE_DIR", "F:/otro", 1);
#endif
    CHECK(flag_text(FlagId::CacheDir) == "F:/uno",
          "una cadena normal conserva lo que se leyo al arrancar");
    set_env("VX_CACHE_DIR", nullptr);
}

/// Un solo criterio de "puesto" para todos los mandos.
static void test_criterio_unico_de_puesto() {
    set_env("VESTA_NO_FUSE", "0");
    CHECK(!flag_on(FlagId::NoFuse), "\"0\" es apagado");
    CHECK(flag_present(FlagId::NoFuse), "pero esta presente");
    set_env("VESTA_NO_FUSE", "");
    CHECK(!flag_on(FlagId::NoFuse), "vacio es apagado");
    set_env("VESTA_NO_FUSE", "1");
    CHECK(flag_on(FlagId::NoFuse), "\"1\" es encendido");
    set_env("VESTA_NO_FUSE", "no");
    CHECK(flag_on(FlagId::NoFuse), "cualquier otra cosa es encendido");
    set_env("VESTA_NO_FUSE", nullptr);
    CHECK(!flag_present(FlagId::NoFuse), "quitado es no presente");
}

/// Los numeros y los textos se leen una vez y se devuelven ya convertidos.
static void test_valores_tipados() {
    set_env("VESTA_JIT_THRESHOLD", "1234");
    CHECK(flag_int(FlagId::JitThreshold, -1) == 1234, "se lee el numero");
    set_env("VESTA_JIT_THRESHOLD", nullptr);
    CHECK(flag_int(FlagId::JitThreshold, -1) == -1,
          "si no esta, sale lo que se pidio por defecto");

    set_env("VX_CACHE_DIR", "F:/algun/sitio");
    CHECK(flag_text(FlagId::CacheDir) == "F:/algun/sitio", "se lee el texto");
    set_env("VX_CACHE_DIR", nullptr);
    CHECK(flag_text(FlagId::CacheDir).empty(), "si no esta, sale vacio");
}

int main() {
    /* Se parte de un entorno limpio: si quien lanza el test tiene mandos
     * puestos, las comprobaciones de "sin nada, la huella es cero" medirian su
     * maquina en vez del codigo. */
    for (size_t i = 0; i < kFlagCount; ++i) {
        const FlagInfo &fi = flag_info(static_cast<FlagId>(i));
        if (fi.scope == FlagScope::Emitted) set_env(fi.name, nullptr);
    }

    test_tabla_bien_formada();
    test_eje_de_sistema();
    test_informe_no_esta_puesto_por_defecto();
    test_sin_mandos_no_hay_huella();
    test_mando_emitido_entra();
    test_mando_de_informe_no_entra();
    test_reparto_no_entra();
    test_dominios_no_se_contaminan();
    test_mandos_distintos_huellas_distintas();
    test_el_valor_cuenta();
    test_encendidos_por_defecto();
    test_valor_vivo_se_relee();
    test_criterio_unico_de_puesto();
    test_valores_tipados();

    std::printf("test_env_flags: %d comprobaciones, %d fallidas\n", g_checks,
                g_fail);
    return g_fail == 0 ? 0 : 1;
}
