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
 * @file test_native_effects.cpp
 * @brief Lo que se DECLARA de una funcion externa tiene que contar.
 *
 * Una nativa es codigo que no esta en el programa: no se puede analizar, asi
 * que sin decir nada lo unico honesto es suponer que hace cualquier cosa.  Eso
 * tumba las CINCO propiedades de efectos de todo el que la llame.
 *
 * El mecanismo para decirlo existia -- `IrNativeEffects`, en la importacion, y
 * hablando de ARGUMENTOS -- y el motor semantico lo aplicaba, pero el camino de
 * los CONTRATOS no lo miraba: se podia declarar y no cambiaba nada de lo que el
 * usuario ve.  Un mecanismo que se usa y no se nota es peor que no tenerlo,
 * porque parece que no funciona.
 *
 * Esto fija las dos mitades: que lo declarado se aporte, y -- lo que de verdad
 * importa -- que lo NO declarado siga siendo conservador.  Una declaracion
 * parcial no puede aprobar por omision lo que nadie dijo.
 */

#include "analyze/fingerprint.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>
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

/// Un modulo con UNA funcion que llama a una nativa por su nombre "lib:fn".
static ir::IrModule module_calling(const std::string &lib_fn) {
    ir::IrModule mod;
    ir::IrFunction fn;
    fn.name = "caller";
    const uint32_t b0 = fn.new_block("entry");
    ir::IrInstr call{};
    call.op = ir::IrOp::CALLN;
    call.dst = fn.new_value(ir::IrType::I64);
    call.func_name = lib_fn;
    fn.append(b0, std::move(call));
    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.dst = ir::IR_NO_VALUE;
    fn.append(b0, std::move(ret));
    mod.functions.push_back(std::move(fn));
    return mod;
}

/// La huella de `caller` tras componer, con o sin el modulo delante.
static analyze::FunctionFingerprint compose_of(const ir::IrModule &mod,
                                               bool with_module) {
    std::vector<analyze::FunctionFingerprint> fps =
        analyze::compute_module_fingerprints(mod);
    analyze::compose_fingerprints(fps, nullptr, with_module ? &mod : nullptr);
    for (const analyze::FunctionFingerprint &f : fps)
        if (f.function == "caller") return f;
    return analyze::FunctionFingerprint{};
}

/**
 * @brief Sin declarar, el cierre es opaco.  Es el punto de partida.
 */
static void undeclared_is_opaque() {
    std::printf("-- una nativa sin declarar deja el cierre opaco\n");
    ir::IrModule mod = module_calling("libc:strlen");
    mod.register_native_import("libc", "strlen", ir::IrNativeEffects{});
    const analyze::FunctionFingerprint fp = compose_of(mod, true);
    CHECK(!fp.effects_known, "nadie dijo nada: no se puede afirmar el cierre");
    CHECK(fp.throws_total, "y los totales son conservadores: puede lanzar");
    CHECK(std::string(fp.opaque_callee) == "libc:strlen",
          "y se NOMBRA a quien lo hace opaco");
}

/**
 * @brief Declarada como inofensiva, el cierre pasa a conocerse.
 *
 * Es el caso que hace util todo el mecanismo: `strlen` solo lee lo que le
 * pasan, asi que quien la llama puede seguir siendo puro.
 */
static void declared_harmless_keeps_the_closure_known() {
    std::printf("-- lo declarado cuenta: el cierre deja de ser opaco\n");
    ir::IrModule mod = module_calling("libc:strlen");
    ir::IrNativeEffects fx;
    fx.declared = true;
    fx.reads_pointee = 1u << 0; // lee lo apuntado por su primer argumento
    mod.register_native_import("libc", "strlen", fx);

    const analyze::FunctionFingerprint fp = compose_of(mod, true);
    CHECK(fp.effects_known, "con lo declarado, el cierre se conoce");
    CHECK(!fp.throws_total, "no lanza");
    CHECK(!fp.panics_total, "no entra en panico");
    CHECK(fp.alloc_sites_total == 0, "y no reserva");
    CHECK(fp.pure, "y quien la llama puede ser PURO: solo lee sus argumentos");
}

/**
 * @brief LO QUE NO SE DECLARA NO SE APRUEBA.
 *
 * Es la mitad que de verdad importa.  Los campos de panic y reserva no existian
 * cuando este camino empezo a mirar las declaraciones, y sin ellos una nativa
 * declarada aportaba CERO reservas y NINGUN panic por omision: un `@alloc(0)`
 * sobre quien llama a `malloc` se daba por bueno, y un `@nopanic` sobre quien
 * llama a `abort` tambien.  El silencio se leia como una demostracion.
 */
static void what_is_declared_is_what_counts() {
    std::printf("-- lo declarado se aporta, cada eje por su cuenta\n");
    ir::IrModule mod = module_calling("libc:malloc");
    ir::IrNativeEffects fx;
    fx.declared = true;
    fx.allocates = true;
    mod.register_native_import("libc", "malloc", fx);

    const analyze::FunctionFingerprint fp = compose_of(mod, true);
    CHECK(fp.effects_known, "se declaro, asi que el cierre se conoce");
    CHECK(fp.alloc_sites_total > 0,
          "y RESERVA: un @alloc(0) sobre esto tiene que incumplirse");
    CHECK(!fp.throws_total, "lo que no se declaro no se aporta: no lanza");

    ir::IrModule mod2 = module_calling("libc:abort");
    ir::IrNativeEffects fx2;
    fx2.declared = true;
    fx2.may_panic = true;
    mod2.register_native_import("libc", "abort", fx2);
    const analyze::FunctionFingerprint fp2 = compose_of(mod2, true);
    CHECK(fp2.panics_total, "el panic es un eje propio y se aporta");
    CHECK(!fp2.throws_total,
          "y NO se confunde con lanzar: son cosas distintas");
}

/**
 * @brief Una nativa que escribe o hace E/S rompe la pureza, no la opacidad.
 *
 * Distinguirlo importa: el cierre se SIGUE conociendo -- se sabe lo que hace --
 * y lo que pasa es que lo que hace no es puro.  Antes las dos cosas caian
 * juntas y no habia forma de decir "se lo que hace, y hace E/S".
 */
static void declared_io_breaks_purity_not_knowledge() {
    std::printf("-- se puede saber lo que hace Y que no sea puro\n");
    ir::IrModule mod = module_calling("io:print");
    ir::IrNativeEffects fx;
    fx.declared = true;
    fx.reads_pointee = 1u << 0;
    fx.io = true;
    mod.register_native_import("io", "print", fx);

    const analyze::FunctionFingerprint fp = compose_of(mod, true);
    CHECK(fp.effects_known, "se sabe lo que hace");
    CHECK(!fp.pure, "y no es puro, porque hace E/S");
}

/**
 * @brief Sin el modulo delante no hay a quien preguntar.
 *
 * El parametro es opcional para no romper a quien no lo tenga, asi que se
 * comprueba que su ausencia se comporta como antes: conservador.  Un
 * comportamiento que dependa de si alguien se acordo de pasar un puntero tiene
 * que ser el SEGURO.
 */
static void without_the_module_it_stays_conservative() {
    std::printf("-- sin modulo, conservador (no se aprueba por descuido)\n");
    ir::IrModule mod = module_calling("libc:strlen");
    ir::IrNativeEffects fx;
    fx.declared = true;
    fx.reads_pointee = 1u << 0;
    mod.register_native_import("libc", "strlen", fx);

    const analyze::FunctionFingerprint fp = compose_of(mod, false);
    CHECK(!fp.effects_known,
          "sin a quien preguntar, el cierre sigue siendo opaco");
}

/**
 * @brief Dos definiciones de la misma nativa que NO coinciden.
 *
 * Es el caso normal cuando dos modulos declaran la misma funcion del sistema y
 * no dicen lo mismo; al fusionarlos llegan juntas.  Antes ganaba la primera y
 * la otra desaparecia: el programa se compilaba segun el ORDEN en que se
 * emitieron las llamadas, que no es una propiedad del programa.
 *
 * Lo que se fija aqui es que el conflicto se MARQUE (para que alguien pueda
 * avisar) y que la resolucion sea la union de lo PEOR: perder precision es
 * aceptable, aprobar de mas no.
 */
static void two_definitions_that_disagree() {
    std::printf("-- dos definiciones que no coinciden: se marca y se pone a "
                "salvo\n");
    ir::IrModule mod = module_calling("libc:memcpy");

    ir::IrNativeEffects solo_lee; // un modulo dice que solo lee
    solo_lee.declared = true;
    solo_lee.reads_pointee = 1u << 1;
    mod.register_native_import("libc", "memcpy", solo_lee);

    ir::IrNativeEffects escribe; // el otro dice que escribe, y que reserva
    escribe.declared = true;
    escribe.writes_pointee = 1u << 0;
    escribe.allocates = true;
    mod.register_native_import("libc", "memcpy", escribe);

    const ir::IrNativeImport *ni = nullptr;
    for (const ir::IrNativeImport &x : mod.native_imports)
        if (x.name == "memcpy") ni = &x;
    CHECK(ni != nullptr, "la nativa sigue registrada una sola vez");
    if (ni == nullptr) return;
    CHECK(ni->effects_conflict, "y el choque queda MARCADO, no tragado");
    CHECK(ni->effects.reads_pointee == (1u << 1),
          "se conserva lo que dijo la primera");
    CHECK(ni->effects.writes_pointee == (1u << 0),
          "y tambien lo que dijo la segunda: es la union, no una eleccion");
    CHECK(ni->effects.allocates,
          "lo peor de las dos se atribuye: aqui, que reserva");

    // Y el llamante lo PAGA: con `allocates` puesto por una de las dos, un
    // @alloc(0) sobre quien la llama tiene que incumplirse.
    const analyze::FunctionFingerprint fp = compose_of(mod, true);
    CHECK(fp.alloc_sites_total > 0,
          "el llamante hereda lo peor, que es el sentido de la union");
}

/**
 * @brief Dos definiciones que dicen LO MISMO no son un conflicto.
 *
 * Importa tanto como lo anterior: un aviso que salta cuando no pasa nada se
 * aprende a ignorar, y entonces tampoco se ve el dia que si pasa.
 */
static void two_identical_definitions_are_not_a_conflict() {
    std::printf("-- dos definiciones iguales no son un choque\n");
    ir::IrModule mod = module_calling("libc:strlen");
    ir::IrNativeEffects fx;
    fx.declared = true;
    fx.reads_pointee = 1u << 0;
    mod.register_native_import("libc", "strlen", fx);
    mod.register_native_import("libc", "strlen", fx);

    for (const ir::IrNativeImport &x : mod.native_imports)
        if (x.name == "strlen")
            CHECK(!x.effects_conflict,
                  "decir dos veces lo mismo no contradice");
}

/**
 * @brief Una definicion y un registro SIN definir tampoco chocan.
 *
 * Es lo que pasa siempre: se declara en un sitio y se llama en otro, y el sitio
 * de llamada registra el import a secas.  Si eso contara como choque, el aviso
 * saltaria en todos los programas que usen la funcion.
 */
static void declaring_then_calling_is_not_a_conflict() {
    std::printf("-- declarar y luego llamar no es un choque\n");
    ir::IrModule mod = module_calling("libc:strlen");
    ir::IrNativeEffects fx;
    fx.declared = true;
    fx.reads_pointee = 1u << 0;
    mod.register_native_import("libc", "strlen", fx);
    mod.register_native_import("libc", "strlen"); // el sitio de llamada

    for (const ir::IrNativeImport &x : mod.native_imports)
        if (x.name == "strlen") {
            CHECK(!x.effects_conflict,
                  "no hay contradiccion: uno no dijo nada");
            CHECK(x.effects.declared,
                  "y lo definido NO se pierde por llamarla despues");
        }
}

int main() {
    std::printf("=== test_native_effects ===\n");
    two_definitions_that_disagree();
    two_identical_definitions_are_not_a_conflict();
    declaring_then_calling_is_not_a_conflict();
    undeclared_is_opaque();
    declared_harmless_keeps_the_closure_known();
    what_is_declared_is_what_counts();
    declared_io_breaks_purity_not_knowledge();
    without_the_module_it_stays_conservative();
    std::printf("=== test_native_effects: %d comprobaciones, %d fallidas ===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
