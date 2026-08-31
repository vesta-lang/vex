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
 * @file test_trip_count_reason.cpp
 * @brief Un analisis que no sabe algo tiene que decir POR QUE.
 *
 * El contador de iteraciones tenia CUATRO formas de rendirse y todas daban el
 * mismo `-1`.  Quien preguntaba -- el desenrollado, la vectorizacion, el
 * peeling -- no podia distinguirlas, y se arreglan de formas distintas:
 *
 *   - el limite es un valor de EJECUCION: se puede desenrollar con una guarda,
 *     o pedir una precondicion.  El programa esta bien;
 *   - el bucle decrece, o la guarda no es `<`/`<=`: el ANALISIS no cubre esa
 *     forma.  El programa tambien esta bien, y lo que hay que ampliar es el
 *     analisis.
 *
 * Con un solo bit, todos los consumidores se rendian igual en los cuatro casos.
 * Esto fija que cada uno diga lo suyo.
 */

#include "analysis/facts/loop_trip_count.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <vector>

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

using analysis::asa::UnknownReason;

/// Una funcion con UN bloque y las constantes que se le pidan.
///
/// El resolvedor busca la CONST que define cada valor en su bloque, asi que un
/// bucle de prueba no necesita mas que eso: lo que se prueba es la
/// clasificacion, no el recorrido del CFG.
struct Harness {
    ir::IrFunction fn;
    std::vector<int> def_block;

    Harness() {
        fn.name = "prueba";
        fn.new_block("entry");
        /* Los valores tienen que EXISTIR en el pool: el resolvedor descarta
         * cualquier id fuera de `fn.values`, asi que sin esto ninguna constante
         * se encuentra y los cuatro casos darian el mismo motivo -- justo lo
         * que este test viene a distinguir. */
        for (int i = 0; i < 8; ++i)
            fn.new_value(ir::IrType::I64);
        def_block.assign(fn.values.size(), -1);
    }

    /// Define @p v como la constante @p k dentro del unico bloque.
    void constant(ir::IrValueId v, int64_t k) {
        ir::IrInstr in;
        in.op = ir::IrOp::CONST;
        in.dst = v;
        in.imm = static_cast<uint64_t>(k);
        fn.blocks[0].instrs.push_back(in);
        if (v < def_block.size()) def_block[v] = 0;
    }
};

/// Un IV creciente de 0 a `bound` con guarda `<`.
static analysis::LoopIV rising_iv() {
    analysis::LoopIV iv;
    iv.stride = 1;
    iv.init = 1;
    iv.bound = 2;
    iv.cmp_op = ir::IrOp::CMP_LT;
    iv.cmp_offset = 0;
    return iv;
}

/**
 * @brief El caso bueno: se sabe, y entonces no hay motivo que dar.
 */
static void known_has_no_reason() {
    std::printf("-- cuando se sabe, se sabe\n");
    Harness h;
    h.constant(1, 0);  // init = 0
    h.constant(2, 10); // bound = 10
    const analysis::LoopTripInfo t =
        analysis::compute_trip_count(h.fn, h.def_block, rising_iv());
    CHECK(t.known(), "un bucle de 0 a 10 con paso 1 esta contado");
    CHECK(t.trip == 10, "y son diez iteraciones");
}

/**
 * @brief Limite que no es constante: depende de la EJECUCION.
 *
 * Es el caso en el que un consumidor SI puede hacer algo -- desenrollar con
 * guarda --, y por eso separarlo del resto es lo que da valor al motivo.
 */
static void runtime_bound_says_so() {
    std::printf("-- un limite de ejecucion se dice como tal\n");
    Harness h;
    h.constant(1, 0); // init constante; el bound no se define
    const analysis::LoopTripInfo t =
        analysis::compute_trip_count(h.fn, h.def_block, rising_iv());
    CHECK(!t.known(), "no se puede contar");
    CHECK(t.reason == UnknownReason::RuntimeDependent,
          "y el motivo es que depende de la ejecucion, no una forma rara");
    CHECK(std::string(t.code) == "loop.non_constant_bound",
          "con el caso exacto, no solo la clase");
}

/**
 * @brief Inicio que no es constante: mismo motivo, OTRO codigo.
 *
 * La clase es la que decide la accion; el codigo dice cual de los dos casos
 * fue, que es lo que hace falta para arreglarlo.
 */
static void runtime_init_has_its_own_code() {
    std::printf("-- el inicio y el limite son casos distintos\n");
    Harness h;
    h.constant(2, 10); // bound constante; el init no se define
    const analysis::LoopTripInfo t =
        analysis::compute_trip_count(h.fn, h.def_block, rising_iv());
    CHECK(t.reason == UnknownReason::RuntimeDependent, "misma clase");
    CHECK(std::string(t.code) == "loop.non_constant_init",
          "y distinto codigo: se arreglan mirando sitios distintos");
}

/**
 * @brief Bucle que no crece: es el ANALISIS el que no llega.
 *
 * Y decirlo asi importa: llamarlo "depende de la ejecucion" le echaria la culpa
 * al codigo del usuario cuando el bucle puede estar perfectamente acotado.
 */
static void decreasing_loop_is_a_shape_we_dont_cover() {
    std::printf("-- un bucle decreciente es una forma no cubierta\n");
    Harness h;
    h.constant(1, 10);
    h.constant(2, 0);
    analysis::LoopIV iv = rising_iv();
    iv.stride = -1;
    const analysis::LoopTripInfo t =
        analysis::compute_trip_count(h.fn, h.def_block, iv);
    CHECK(!t.known(), "no se cuenta");
    CHECK(t.reason == UnknownReason::ShapeNotRecognized,
          "y NO se le echa la culpa al programa: es el analisis el que no "
          "cubre esa forma");
    CHECK(std::string(t.code) == "loop.non_increasing_iv", "con su codigo");
}

/**
 * @brief Guarda que no es `<` ni `<=`: otra forma no cubierta.
 */
static void unsupported_guard_is_a_shape_too() {
    std::printf("-- una guarda no soportada tambien es forma, no ejecucion\n");
    Harness h;
    h.constant(1, 0);
    h.constant(2, 10);
    analysis::LoopIV iv = rising_iv();
    iv.cmp_op = ir::IrOp::CMP_NE; // `!=`, que este analisis no sabe leer
    const analysis::LoopTripInfo t =
        analysis::compute_trip_count(h.fn, h.def_block, iv);
    CHECK(!t.known(), "no se cuenta");
    CHECK(t.reason == UnknownReason::ShapeNotRecognized, "es una forma");
    CHECK(std::string(t.code) == "loop.unsupported_guard", "con su codigo");
}

/**
 * @brief Y las dos clases NO se confunden entre si.
 *
 * Es la comprobacion que de verdad importa: si alguien vuelve a colapsarlas en
 * un solo motivo, las de arriba podrian seguir pasando por separado y esta no.
 */
static void the_two_classes_stay_apart() {
    std::printf("-- las dos clases no se confunden\n");
    Harness h;
    h.constant(1, 0);
    analysis::LoopIV bajada = rising_iv();
    bajada.stride = -1;
    const analysis::LoopTripInfo por_ejecucion =
        analysis::compute_trip_count(h.fn, h.def_block, rising_iv());
    const analysis::LoopTripInfo por_forma =
        analysis::compute_trip_count(h.fn, h.def_block, bajada);
    CHECK(por_ejecucion.reason != por_forma.reason,
          "un limite de ejecucion y una forma no cubierta NO son lo mismo");
}

int main() {
    std::printf("=== test_trip_count_reason ===\n");
    known_has_no_reason();
    runtime_bound_says_so();
    runtime_init_has_its_own_code();
    decreasing_loop_is_a_shape_we_dont_cover();
    unsupported_guard_is_a_shape_too();
    the_two_classes_stay_apart();
    std::printf("=== test_trip_count_reason: %d comprobaciones, %d fallidas "
                "===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
