/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/jit/test_cost_model_uarch.cpp
 * @brief Test del mapeo CPUID -> microarquitectura de la DB de coste.
 *
 * LO QUE VIGILA, y es lo que estaba mal hasta 2026-09-08: en una pieza HIBRIDA
 * la familia y el modelo no bastan.  Un i7-13700KF devuelve el mismo
 * @c CPUID.1 (familia 6, modelo 0xB7) se pregunte desde un core P o desde uno
 * E, y sus 24 hilos son 16 P y 8 E.  El mapeo devolvia siempre
 * @c intel-alderlake-p, asi que un tercio de los cores se costeaba con las
 * latencias y los puertos de otro core -- teniendo la DB la fila
 * @c intel-alderlake-e al lado, con 802 clases propias.
 *
 * No lo nota nadie al compilar ni al ejecutar: el scheduler ordena con numeros
 * equivocados y sale codigo que funciona, solo que peor de lo que podria.  Es la
 * clase de fallo que solo se ve si alguien lo comprueba a proposito.
 *
 * SE PRUEBA SIN TENER LA CPU DELANTE.  @c uarch_from_cpuid recibe lo que CPUID
 * contesto como DATO, asi que aqui se describen piezas que esta maquina no es --
 * un Zen1, un core E -- y se comprueba la decision.  Si el mapeo leyera CPUID
 * por dentro, la rama del core E no la ejercitaria nadie salvo quien tuviera
 * una hibrida y ademas hubiera acertado a correr el test en el core bueno.
 */

#include "jit/sched/cost_model.h"
#include "vx/asm/instr_db.h"

#include <cstdio>
#include <string>

using namespace jit::sched;

static int g_checks = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            std::printf("FAIL: %s\n", (msg));                                  \
            ++g_fail;                                                          \
        }                                                                      \
    } while (0)

/// Describe una pieza: fabricante, familia, modelo, hibrida y clase de core.
static HostCpuId cpu(const char *vendor, unsigned family, unsigned model,
                     bool hybrid = false, unsigned core_type = 0) {
    HostCpuId id;
    id.vendor = vendor;
    id.family = family;
    id.model = model;
    id.hybrid = hybrid;
    id.core_type = core_type;
    return id;
}

static const char *kIntel = "GenuineIntel";
static const char *kAmd = "AuthenticAMD";

int main() {
    std::printf("--- hibridas: el mismo modelo, dos respuestas ---\n");
    {
        // Las dos comprobaciones que siguen piden respuestas DISTINTAS para el
        // mismo (fabricante, familia, modelo).  Esta puesto a proposito: hace
        // que NINGUNA implementacion que ignore core_type pueda pasar las dos,
        // sea cual sea la que devuelva.  Es mas fuerte que comprobar contra el
        // fallo concreto que hubo, porque cubre tambien los que no ha habido.

        // Raptor Lake (i7-13700KF, la maquina de desarrollo): 0xB7.
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0xB7, true, CORE_TYPE_CORE)) ==
                      "intel-alderlake-p",
              "0xB7 en un core P -> alderlake-p");
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0xB7, true, CORE_TYPE_ATOM)) ==
                      "intel-alderlake-e",
              "0xB7 en un core E -> alderlake-e (esto es lo que fallaba)");

        // Los otros modelos de la misma familia hibrida, los cinco.
        const unsigned hibridos[] = {0x97, 0x9A, 0xBF, 0xB7, 0xBA};
        for (unsigned m : hibridos) {
            CHECK(uarch_from_cpuid(cpu(kIntel, 6, m, true, CORE_TYPE_ATOM)) ==
                          "intel-alderlake-e",
                  "todos los modelos hibridos distinguen el core E");
        }

        // Sin clase de core -- pieza no hibrida, o sin la hoja 0x1A -- se
        // queda con la P, que es lo que habia y sigue siendo lo razonable:
        // "no se cual" no es "es un core E".
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0xB7)) == "intel-alderlake-p",
              "sin clase de core se conserva la conducta anterior");
    }

    std::printf("--- lo que no debe haber cambiado ---\n");
    {
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0x2A)) == "intel-sandybridge",
              "sandybridge");
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0x3C)) == "intel-haswell",
              "haswell");
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0x55)) == "intel-skylake-x",
              "skylake-x");
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0xA7)) == "intel-rocketlake",
              "rocketlake");
        CHECK(uarch_from_cpuid(cpu(kIntel, 6, 0xFF)) == "intel-skylake",
              "un Intel moderno desconocido cae en skylake");

        CHECK(uarch_from_cpuid(cpu(kAmd, 0x17, 0x01)) == "amd-zen1", "zen1");
        CHECK(uarch_from_cpuid(cpu(kAmd, 0x17, 0x31)) == "amd-zen2", "zen2");
        CHECK(uarch_from_cpuid(cpu(kAmd, 0x19, 0x21)) == "amd-zen3", "zen3");
        CHECK(uarch_from_cpuid(cpu(kAmd, 0x19, 0x61)) == "amd-zen4", "zen4");
        CHECK(uarch_from_cpuid(cpu(kAmd, 0x1A, 0x44)) == "amd-zen5", "zen5");

        // Un fabricante que no se reconoce NO se adivina: cadena vacia, que
        // lleva al modelo generico.  Devolver "intel-skylake" por si acaso
        // seria costear un procesador con los numeros de otro.
        CHECK(uarch_from_cpuid(cpu("VestaVirtualCPU", 6, 0xB7)).empty(),
              "fabricante desconocido -> generico, no un nombre inventado");
        CHECK(uarch_from_cpuid(cpu("", 0, 0)).empty(), "sin fabricante, igual");
    }

    std::printf("--- y la DB tiene de verdad las dos filas ---\n");
    {
        // Sin esto el test anterior comprobaria que se devuelve un NOMBRE, no
        // que ese nombre lleve a algun sitio.  Un mapeo que apunte a una fila
        // inexistente cae al modelo generico en silencio.
        namespace idb = vx::instr_db;
        const int32_t p = idb::microarch_by_name(idb::Isa::X86,
                                                 "intel-alderlake-p");
        const int32_t e = idb::microarch_by_name(idb::Isa::X86,
                                                 "intel-alderlake-e");
        CHECK(p >= 0, "la DB tiene la fila del core P");
        CHECK(e >= 0, "la DB tiene la fila del core E");
        CHECK(p != e, "y son filas DISTINTAS");
    }

    std::printf("--- y en ESTA maquina, de punta a punta ---\n");
    {
        // Lo de arriba prueba el mapeo; esto prueba la LECTURA, que es la otra
        // mitad y no se puede comprobar con datos inventados.  No se afirma un
        // resultado -- depende de quien ejecute el test --, se imprime: en una
        // hibrida hay que ver nombres DISTINTOS segun el core, y en una que no
        // lo sea, el mismo siempre.  Que sea informativo y no una comprobacion
        // es a proposito: un test que exigiera "alderlake-e" fallaria en
        // cualquier maquina que no fuera la del autor, que es la forma mas
        // rapida de que alguien lo desactive.
        auto m = make_cost_model(SchedIsa::X86_64, "", SchedMode::JIT_AUTO);
        std::printf("    core actual -> %s\n", m->name());
    }

    std::printf("\n--- %d checks, %d fallos ---\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
