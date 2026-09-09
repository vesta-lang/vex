/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/analysis/test_asm_bindings.cpp
 * @brief Tests del puente entre el texto de un asm y los valores del programa
 *        (@ref analysis::compute_asm_bindings), del ancho que aporta la CLASE
 *        de un operando, y del UNIVERSO bajo el que se resume una funcion.
 *
 * Las tres piezas responden a la misma pregunta desde sitios distintos: que se
 * puede AFIRMAR de lo que hace un bloque de asm.  Se prueban juntas porque el
 * fallo que motivo el modulo era justamente que cada una vivia por su cuenta.
 */

#include "analysis/effects/ir_effects.h"
#include "analysis/facts/alignment.h"
#include "analysis/facts/ir_facts.h"
#include "analysis/memory/points_to.h"
#include "analysis/facts/asm_bindings.h"
#include "ir/ssa_ir.h"
#include "vx/asm/asm_analyze.h"
#include "vx/asm/asm_effects.h"
#include "vx/parser.h" // fijar el objetivo para probar el analisis por arch

#include <cstdio>

using namespace ir;

/**
 * @brief Analiza un cuerpo que NO tiene operandos elegidos por el compilador.
 *
 * El analisis completo pide el mapa de clases porque el ancho de un `$N` solo
 * lo sabe la clase con la que se declaro.  Los cuerpos de este fichero nombran
 * registros de verdad (`rdi`, `x0`, ...), asi que ahi el mapa correcto es el
 * VACIO, y pasarlo dice eso mismo.
 *
 * Se hace asi, y no llamando a @c asm_analyze_block_no_classes, porque esa
 * variante renuncia al ancho de los accesos -- que es lo que estas pruebas
 * miden --, y porque el camino que interesa probar es el que usa el compilador.
 *
 * @param nasm_body Cuerpo verbatim del bloque.
 * @param arch      Arquitectura con cuya tabla leerlo.
 * @return Los efectos del bloque.
 */
static vx::AsmBlockEffects analizar(const std::string &nasm_body,
                                    const std::string &arch) {
    return vx::asm_analyze_block(nasm_body, arch, {});
}

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("FALLO [%s:%d]: %s\n", __FILE__, __LINE__, msg);       \
        }                                                                      \
    } while (0)

// --------------------------------------------------------------------------
// Utilidades de construccion de IR (minimas, para no arrastrar el frontend).
// --------------------------------------------------------------------------

/// Reserva un hueco y devuelve su valor.
static IrValueId alloca_de(IrFunction &fn, IrBlockId bb, uint64_t bytes) {
    const IrValueId v = fn.new_value(IrType::PTR);
    IrInstr in{};
    in.op = IrOp::ALLOCA;
    in.type = IrType::I8;
    in.dst = v;
    in.imm = bytes;
    fn.append(bb, std::move(in));
    return v;
}

/// Guarda @p val en @p slot.
static void store_en(IrFunction &fn, IrBlockId bb, IrValueId val,
                     IrValueId slot) {
    IrInstr in{};
    in.op = IrOp::STORE;
    in.type = IrType::I64;
    in.dst = IR_NO_VALUE;
    in.operands = {val, slot};
    fn.append(bb, std::move(in));
}

/// Una constante, para tener un valor que guardar.
static IrValueId const_de(IrFunction &fn, IrBlockId bb, uint64_t k) {
    const IrValueId v = fn.new_value(IrType::I64);
    IrInstr in{};
    in.op = IrOp::CONST;
    in.type = IrType::I64;
    in.dst = v;
    in.imm = k;
    fn.append(bb, std::move(in));
    // Marcar el valor como constante: es asi como lo deja el frontend, y como
    // lo lee quien pregunta por el tamano de una reserva.
    fn.values[v].is_const = true;
    fn.values[v].const_val = static_cast<int64_t>(k);
    return v;
}

/// Liga @p slot al operando @p marcador de clase @p clase.
static void ligar_auto(IrFunction &fn, IrValueId slot, int ph_index,
                       const char *reg, const char *clase) {
    AsmRegBinding b{slot, reg, IrType::I64, false, "op"};
    b.reg_auto = true;
    b.ph_index = ph_index;
    b.reg_class = clase;
    fn.asm_reg_bindings.push_back(std::move(b));
}

// --------------------------------------------------------------------------
// 1) Un operando que elige el compilador se nombra `$N` y llega hasta su valor.
// --------------------------------------------------------------------------
static void test_marcador_resuelve_valor() {
    IrFunction fn;
    fn.name = "f";
    const IrBlockId bb = fn.new_block("entry");
    const IrValueId slot = alloca_de(fn, bb, 8);
    const IrValueId v = const_de(fn, bb, 0x1000);
    store_en(fn, bb, v, slot);
    ligar_auto(fn, slot, 0, "r10", "reg");

    const analysis::AsmBindingFacts f = analysis::compute_asm_bindings(fn);
    const analysis::LigaduraAsm *l = f.unica("$0");
    CHECK(l != nullptr, "el marcador $0 tiene que encontrarse");
    if (l == nullptr) return;
    CHECK(f.candidatas("$0").size() == 1, "una sola ligadura responde a $0");
    CHECK(l->hueco == slot, "la ligadura apunta al hueco de la variable");
    CHECK(l->valor == v, "y del hueco se llega a lo que se guardo en el");
    CHECK(l->clase == "reg", "la clase es la que se declaro");
}

// --------------------------------------------------------------------------
// 2) Un registro fijo se nombra por su canonico, venga escrito como venga.
// --------------------------------------------------------------------------
static void test_registro_fijo_canonico() {
    IrFunction fn;
    fn.name = "f";
    const IrBlockId bb = fn.new_block("entry");
    const IrValueId slot = alloca_de(fn, bb, 8);
    const IrValueId v = const_de(fn, bb, 7);
    store_en(fn, bb, v, slot);
    AsmRegBinding b{slot, "eax", IrType::I64, false, "x"};
    b.reg_class = "eax";
    fn.asm_reg_bindings.push_back(std::move(b));

    const analysis::AsmBindingFacts f = analysis::compute_asm_bindings(fn);
    CHECK(f.unica("rax") != nullptr,
          "un `eax` ligado se encuentra por su canonico `rax`");
    CHECK(f.unica("eax") == nullptr,
          "y NO por el alias de ancho, que es como no lo nombra el analisis");
}

// --------------------------------------------------------------------------
// 3) Dos ligaduras con el mismo nombre: se devuelven las DOS, con lo suyo.
//
// Es la diferencia entre "no se cual es" y "no se nada".  Saber que fue una de
// estas dos es lo que permite a quien pregunta seguir afinando -- invalidar los
// dos huecos, nombrar las dos posiciones -- en vez de rendirse y tratar el
// bloque como una barrera para todo.
// --------------------------------------------------------------------------
static void test_varias_candidatas_conservan_lo_suyo() {
    IrFunction fn;
    fn.name = "f";
    const IrBlockId bb = fn.new_block("entry");
    const IrValueId s1 = alloca_de(fn, bb, 8);
    const IrValueId s2 = alloca_de(fn, bb, 8);
    const IrValueId v1 = const_de(fn, bb, 1);
    const IrValueId v2 = const_de(fn, bb, 2);
    store_en(fn, bb, v1, s1);
    store_en(fn, bb, v2, s2);
    AsmRegBinding a{s1, "rax", IrType::I64, false, "x"};
    a.reg_class = "rax";
    AsmRegBinding b{s2, "rax", IrType::I64, false, "y"};
    b.reg_class = "rax";
    fn.asm_reg_bindings.push_back(std::move(a));
    fn.asm_reg_bindings.push_back(std::move(b));

    const analysis::AsmBindingFacts f = analysis::compute_asm_bindings(fn);
    const auto cands = f.candidatas("rax");
    CHECK(cands.size() == 2,
          "dos variables en el mismo registro: dos candidatas");
    CHECK(f.unica("rax") == nullptr,
          "no hay UNA: quien necesita identidad no puede afirmar nada");
    bool vio_s1 = false, vio_s2 = false;
    for (const analysis::LigaduraAsm &l : cands) {
        CHECK(l.hueco != IR_NO_VALUE,
              "cada candidata conserva SU hueco: que haya dos no borra lo que "
              "se sabe de cada una");
        if (l.hueco == s1) {
            vio_s1 = true;
            CHECK(l.valor == v1, "y su contenido");
        }
        if (l.hueco == s2) {
            vio_s2 = true;
            CHECK(l.valor == v2, "y su contenido");
        }
    }
    CHECK(vio_s1 && vio_s2, "las dos aparecen, sin quedarse con la primera");

    // Un nombre que no liga nada sigue sin devolver nada.
    CHECK(f.candidatas("rbx").empty(),
          "un registro no ligado no tiene candidatas");
    CHECK(f.unica("rbx") == nullptr, "ni una unica");
}

// --------------------------------------------------------------------------
// 4) Dos escrituras al mismo hueco: su contenido depende del camino.
// --------------------------------------------------------------------------
static void test_dos_escrituras_sin_valor() {
    IrFunction fn;
    fn.name = "f";
    const IrBlockId bb = fn.new_block("entry");
    const IrValueId slot = alloca_de(fn, bb, 8);
    store_en(fn, bb, const_de(fn, bb, 1), slot);
    store_en(fn, bb, const_de(fn, bb, 2), slot);
    ligar_auto(fn, slot, 3, "r11", "reg");

    const analysis::AsmBindingFacts f = analysis::compute_asm_bindings(fn);
    const analysis::LigaduraAsm *l = f.unica("$3");
    CHECK(l != nullptr, "la ligadura de $3 es unica");
    if (l == nullptr) return;
    CHECK(l->valor == IR_NO_VALUE,
          "con dos escrituras el contenido depende del camino: no se afirma");
}

// --------------------------------------------------------------------------
// 4b) Y lo que eso vale: un bloque con dos variables en el mismo registro sigue
//     diciendo QUE memoria toca, en vez de convertirse en una barrera.
//
// Es la prueba de que devolver las candidatas no es un adorno de la API: el
// efecto del bloque pasa de "escribe en cualquier sitio" -- que impide mover
// nada a su alrededor -- a "escribe en una de estas dos", que es lo que de
// verdad se sabe.
// --------------------------------------------------------------------------
static void test_efecto_localizado_con_dos_candidatas() {
    IrFunction fn;
    fn.name = "f";
    const IrBlockId bb = fn.new_block("entry");
    // Dos reservas distintas, cada una con su puntero guardado en el hueco de
    // una variable ligada AL MISMO registro (dos ambitos del fuente).
    const IrValueId obj1 = alloca_de(fn, bb, 64);
    const IrValueId obj2 = alloca_de(fn, bb, 64);
    const IrValueId h1 = alloca_de(fn, bb, 8);
    const IrValueId h2 = alloca_de(fn, bb, 8);
    store_en(fn, bb, obj1, h1);
    store_en(fn, bb, obj2, h2);
    AsmRegBinding a{h1, "rdi", IrType::PTR, false, "p"};
    a.reg_class = "rdi";
    AsmRegBinding b{h2, "rdi", IrType::PTR, false, "q"};
    b.reg_class = "rdi";
    fn.asm_reg_bindings.push_back(std::move(a));
    fn.asm_reg_bindings.push_back(std::move(b));
    // El bloque escribe por [rdi].
    IrInstr asm_ins{};
    asm_ins.op = IrOp::INLINE_ASM;
    asm_ins.type = IrType::VOID;
    asm_ins.dst = IR_NO_VALUE;
    asm_ins.func_name = "mov [rdi], rax\n";
    asm_ins.operands = {h1, h2};
    fn.append(bb, std::move(asm_ins));

    const analysis::IrFacts facts = analysis::build_ir_facts(fn);
    const analysis::PointsTo pt = analysis::compute_points_to(fn, facts);
    const ir::IrInstr &ins = fn.blocks[bb].instrs.back();
    const analysis::effects::EffectAnalysisResult r =
        analysis::effects::effects_of_instr(fn, facts, pt, ins);

    bool desconocido = false;
    unsigned escrituras = 0;
    for (const analysis::effects::AbstractLoc &l : r.effects.mem.writes.locs) {
        ++escrituras;
        if (l.kind == analysis::effects::AbstractLoc::Kind::Unknown)
            desconocido = true;
    }
    CHECK(!desconocido,
          "con dos candidatas el bloque NO escribe en 'cualquier sitio'");
    CHECK(escrituras == 2, "escribe en una de las dos, y se nombran las dos");
}

// --------------------------------------------------------------------------
// 4e) Y la extension LLEGA al efecto: no es un dato que se calcula y se tira.
//
// Es lo que separa "toca ese objeto" de "toca estos bytes de ese objeto".  Con
// lo primero, dos accesos al mismo objeto se estorban siempre; con lo segundo,
// solo cuando de verdad se pisan.
// --------------------------------------------------------------------------
static void test_extension_llega_al_efecto() {
    IrFunction fn;
    fn.name = "f";
    const IrBlockId bb = fn.new_block("entry");
    const IrValueId obj = alloca_de(fn, bb, 64);
    const IrValueId h = alloca_de(fn, bb, 8);
    store_en(fn, bb, obj, h);
    AsmRegBinding b{h, "rdi", IrType::PTR, false, "p"};
    b.reg_class = "rdi";
    fn.asm_reg_bindings.push_back(std::move(b));
    IrInstr asm_ins{};
    asm_ins.op = IrOp::INLINE_ASM;
    asm_ins.type = IrType::VOID;
    asm_ins.dst = IR_NO_VALUE;
    asm_ins.func_name = "mov [rdi+8], eax\n"; // cuatro bytes, ocho mas alla.
    asm_ins.operands = {h};
    fn.append(bb, std::move(asm_ins));

    std::string os_prev, arch_prev;
    vx::get_aot_condcomp_target(os_prev, arch_prev);
    vx::set_aot_condcomp_target("windows", "x86_64");
    const analysis::IrFacts facts = analysis::build_ir_facts(fn);
    const analysis::PointsTo pt = analysis::compute_points_to(fn, facts);
    const analysis::effects::EffectAnalysisResult r =
        analysis::effects::effects_of_instr(fn, facts, pt,
                                            fn.blocks[bb].instrs.back());
    vx::set_aot_condcomp_target(os_prev, arch_prev);

    bool visto = false;
    for (const analysis::effects::AbstractLoc &l : r.effects.mem.writes.locs) {
        if (l.kind == analysis::effects::AbstractLoc::Kind::Unknown) continue;
        visto = true;
        CHECK(l.width == 4,
              "el efecto dice CUATRO bytes, que es lo que mueve `eax`");
        CHECK(l.off == 8,
              "y a ocho del principio del objeto, que es donde cae");
    }
    CHECK(visto, "la escritura se localizo");
}

// --------------------------------------------------------------------------
// 4c) El asm se analiza con la arquitectura del OBJETIVO, no con una escrita a
//     mano.
//
// El modelo de efectos la llevaba clavada a x86, asi que compilando para ARM
// leia `ldr x0, [x1]` con la tabla equivocada: mnemonico desconocido, registro
// desconocido, y el bloque pasaba a valer "puede hacer cualquier cosa" -- mas
// una laguna del analisis que no existia.
// --------------------------------------------------------------------------
static void test_efecto_usa_el_arch_del_objetivo() {
    std::string os_prev, arch_prev;
    vx::get_aot_condcomp_target(os_prev, arch_prev);

    IrFunction fn;
    fn.name = "f";
    const IrBlockId bb = fn.new_block("entry");
    const IrValueId obj = alloca_de(fn, bb, 64);
    const IrValueId h = alloca_de(fn, bb, 8);
    store_en(fn, bb, obj, h);
    AsmRegBinding b{h, "x1", IrType::PTR, false, "p"};
    b.reg_class = "x1";
    fn.asm_reg_bindings.push_back(std::move(b));
    IrInstr asm_ins{};
    asm_ins.op = IrOp::INLINE_ASM;
    asm_ins.type = IrType::VOID;
    asm_ins.dst = IR_NO_VALUE;
    asm_ins.func_name = "str x0, [x1]\n"; // arm64: guarda por x1.
    asm_ins.operands = {h};
    fn.append(bb, std::move(asm_ins));

    vx::set_aot_condcomp_target("linux", "arm64");
    const analysis::IrFacts facts = analysis::build_ir_facts(fn);
    const analysis::PointsTo pt = analysis::compute_points_to(fn, facts);
    const analysis::effects::EffectAnalysisResult r =
        analysis::effects::effects_of_instr(fn, facts, pt,
                                            fn.blocks[bb].instrs.back());
    vx::set_aot_condcomp_target(os_prev, arch_prev); // restaurar

    CHECK(r.mnemonicos_desconocidos.empty(),
          "una instruccion de arm64 no es un mnemonico desconocido cuando el "
          "objetivo ES arm64");
    bool desconocido = r.effects.mem.writes.locs.empty();
    for (const analysis::effects::AbstractLoc &l : r.effects.mem.writes.locs)
        if (l.kind == analysis::effects::AbstractLoc::Kind::Unknown)
            desconocido = true;
    CHECK(!desconocido,
          "y su escritura se localiza por el registro ligado, como en x86");

    /* El contraste, para que lo de arriba no pase por casualidad: ESA MISMA
     * instruccion, leida con la tabla de x86, no se entiende.  Es exactamente
     * lo que ocurria cuando la arquitectura iba escrita a mano. */
    CHECK(!analizar("str x0, [x1]\n", "x86_64").known(),
          "con la tabla equivocada, la misma instruccion es un desconocido");
}

// --------------------------------------------------------------------------
// 4d) Hasta donde llega un acceso: la extension como EXPRESION.
//
// Un acceso casi nunca es "tantos bytes": es tantos bytes a tanta distancia,
// quiza repetidos tantas veces, y esas cantidades salen de operandos del propio
// bloque.  Lo que se prueba aqui es que el analisis las NOMBRA en vez de decir
// que no sabe -- que es lo que permite acotarlas despues.
// --------------------------------------------------------------------------
static const vx::AsmBlockEffects::Acceso *
primer_acceso(const vx::AsmBlockEffects &e) {
    return e.accesos.empty() ? nullptr : &e.accesos[0];
}

static void test_extension_como_expresion() {
    // (a) Constante: distancia y ancho salen del texto y de la instruccion.
    {
        const vx::AsmBlockEffects e = analizar("mov [rdi+8], rax\n", "x86_64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr && a->valida, "el acceso se describe");
        if (a != nullptr) {
            CHECK(a->extension.const_off == 8, "la distancia es 8");
            CHECK(a->extension.bytes == 8, "y `rax` dice que son 8 bytes");
            CHECK(a->extension.cerrada(),
                  "sin indice ni repeticion: queda cerrada aqui mismo");
        }
    }
    // (b) El ancho lo manda la pista de tamano cuando se escribe.
    {
        const vx::AsmBlockEffects e = analizar("mov byte [rdi], 1\n", "x86_64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr && a->extension.bytes == 1,
              "`byte [rdi]` toca un byte, lo diga quien lo diga");
    }
    // (c) Indice escalado: NO es un acceso sin distancia, es uno a `rcx*8`.
    {
        const vx::AsmBlockEffects e =
            analizar("mov [rbx+rcx*8], rax\n", "x86_64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr && a->base == "rbx", "se llega por `rbx`");
        if (a != nullptr) {
            CHECK(a->extension.indice == "rcx", "y la distancia la pone `rcx`");
            CHECK(a->extension.escala == 8, "escalada por 8");
            CHECK(
                !a->extension.cerrada(),
                "no queda cerrada: hay que acotar `rcx` para saber donde cae");
        }
    }
    // (d) Repeticion: `rep movsb` recorre tantos bytes como diga su contador, y
    //     ese contador tiene NOMBRE.
    {
        const vx::AsmBlockEffects e = analizar("rep movsb\n", "x86_64");
        bool visto_destino = false;
        for (const auto &a : e.accesos) {
            if (!a.escribe) continue;
            visto_destino = true;
            CHECK(a.base == "rdi", "escribe por `rdi`, como dice la ISA");
            CHECK(a.extension.bytes == 1, "cada paso mueve un byte");
            CHECK(a.extension.repeticion == "rcx",
                  "y se repite `rcx` veces -- nombrarlo es lo que permite "
                  "acotarlo despues");
        }
        CHECK(visto_destino, "el destino implicito aparece");
    }
    // (e) Un puntero que el bloque MUEVE no se pierde: se sigue.
    {
        const vx::AsmBlockEffects e =
            analizar("add rdi, 16\nmov [rdi], rax\n", "x86_64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr && a->base == "rdi",
              "sigue siendo el mismo puntero de partida");
        if (a != nullptr)
            CHECK(a->extension.const_off == 16,
                  "solo que dieciseis bytes mas alla: `add` lo mueve, no lo "
                  "borra");
        CHECK(!e.accesos_incompletos,
              "y el bloque NO queda sin describir por haber tocado su base");
    }
    // (f) Copiar el puntero a otro registro tampoco lo pierde.
    {
        const vx::AsmBlockEffects e =
            analizar("mov rdx, rdi\nmov [rdx+4], eax\n", "x86_64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr && a->base == "rdi",
              "el acceso se atribuye a de donde venia el valor");
        if (a != nullptr) {
            CHECK(a->extension.const_off == 4, "a cuatro bytes");
            CHECK(a->extension.bytes == 4, "y `eax` dice que son cuatro");
        }
    }
    // (g) Cargarlo de memoria no es perderlo: se dice de DONDE se cargo.
    {
        const vx::AsmBlockEffects e =
            analizar("mov rdx, [rdi+8]\nmov [rdx], rax\n", "x86_64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr, "hay accesos");
        if (a != nullptr) {
            // El primero es la carga por rdi; el segundo, la escritura por lo
            // que se cargo.
            const vx::AsmBlockEffects::Acceso *escritura = nullptr;
            for (const auto &x : e.accesos)
                if (x.escribe) escritura = &x;
            CHECK(escritura != nullptr, "la escritura aparece");
            if (escritura != nullptr) {
                CHECK(
                    escritura->base == "rdi",
                    "y se atribuye a `rdi`, que es de donde salio el puntero");
                CHECK(
                    escritura->desde_memoria.hay,
                    "diciendo que la direccion estaba GUARDADA, no que es rdi");
                CHECK(escritura->desde_memoria.off == 8,
                      "y a que distancia estaba guardada");
            }
        }
    }
    // (h) arm64: el mismo modelo, sin una linea de x86 en el analisis.
    {
        const vx::AsmBlockEffects e =
            analizar("add x0, x0, #32\nstr x1, [x0]\n", "arm64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr && a->base == "x0", "se llega por `x0`");
        if (a != nullptr)
            CHECK(a->extension.const_off == 32,
                  "y el `add` de arm mueve igual que el de x86");
    }
    {
        const vx::AsmBlockEffects e =
            analizar("str x1, [x0, x2, lsl #3]\n", "arm64");
        const auto *a = primer_acceso(e);
        CHECK(a != nullptr && a->extension.indice == "x2",
              "el indice de arm64 se lee igual");
        if (a != nullptr)
            CHECK(a->extension.escala == 8, "y `lsl #3` escala por ocho");
    }
}

// --------------------------------------------------------------------------
// 5) El ancho lo dice la CLASE.  Sin ella, el texto `$N` no puede decirlo.
// --------------------------------------------------------------------------
static void test_ancho_por_clase() {
    CHECK(vx::asm_ancho_bits_de_clase("xmm") == 128, "xmm mide 128 bits");
    CHECK(vx::asm_ancho_bits_de_clase("ymm") == 256, "ymm mide 256 bits");
    CHECK(vx::asm_ancho_bits_de_clase("zmm") == 512, "zmm mide 512 bits");
    CHECK(vx::asm_ancho_bits_de_clase("xmm3") == 128,
          "un registro concreto se pregunta tal cual");
    CHECK(vx::asm_ancho_bits_de_clase("reg") == 64,
          "`reg` es el banco general del objetivo");
    CHECK(vx::asm_ancho_bits_de_clase("no_es_una_clase") == 0,
          "lo que no se reconoce vale 0, que es 'no se sabe'");

    // Y el efecto que importa: una instruccion que exige "tanto como mida su
    // operando" solo puede resolverse si alguien dice de que clase es el `$1`.
    const std::string cuerpo = "movdqa [$0], $1\n";
    const vx::AsmInferResult sin = vx::asm_infer_clobbers(cuerpo, {});
    CHECK(sin.align_reqs.size() == 1, "movdqa exige alineacion");
    if (sin.align_reqs.size() == 1) {
        CHECK(sin.align_reqs[0].bytes == 0,
              "sin las clases, el ancho del operando no se puede determinar");
        CHECK(sin.align_reqs[0].base == "$0",
              "de donde sale la direccion SI se sabe: es el marcador $0");
    }
    const vx::AsmInferResult con =
        vx::asm_infer_clobbers(cuerpo, {}, {{"$0", "reg"}, {"$1", "xmm"}});
    CHECK(con.align_reqs.size() == 1, "la exigencia sigue estando");
    if (con.align_reqs.size() == 1)
        CHECK(con.align_reqs[0].bytes == 16,
              "con la clase del operando, movdqa exige 16 bytes");

    // La variante ancha exige lo que mida SU operando, no un numero fijo.
    const vx::AsmInferResult ancha = vx::asm_infer_clobbers(
        "vmovdqa [$0], $1\n", {}, {{"$0", "reg"}, {"$1", "ymm"}});
    CHECK(ancha.align_reqs.size() == 1 && ancha.align_reqs[0].bytes == 32,
          "vmovdqa con un operando de 256 bits exige 32");

    // Y la forma que NO exige nada no debe inventarse una exigencia.
    const vx::AsmInferResult libre = vx::asm_infer_clobbers(
        "movdqu [$0], $1\n", {}, {{"$0", "reg"}, {"$1", "xmm"}});
    CHECK(libre.align_reqs.empty(),
          "movdqu no exige alineacion: una letra separa las dos familias");
}

// --------------------------------------------------------------------------
// 6) El universo: de que funciones se puede afirmar algo, y por que.
// --------------------------------------------------------------------------

/// Construye un modulo: `main` llama a `usada(k)`; `huerfana` no la llama
/// nadie.
static IrModule modulo_con_llamada(bool usada_publica) {
    IrModule mod;

    IrFunction usada;
    usada.name = "usada";
    usada.is_public = usada_publica;
    const IrBlockId ub = usada.new_block("entry");
    usada.params.push_back(usada.new_value(IrType::PTR));
    {
        IrInstr r{};
        r.op = IrOp::RET;
        r.dst = IR_NO_VALUE;
        usada.append(ub, std::move(r));
    }

    IrFunction huerfana;
    huerfana.name = "huerfana";
    huerfana.is_public = false;
    const IrBlockId hb = huerfana.new_block("entry");
    huerfana.params.push_back(huerfana.new_value(IrType::PTR));
    {
        IrInstr r{};
        r.op = IrOp::RET;
        r.dst = IR_NO_VALUE;
        huerfana.append(hb, std::move(r));
    }

    IrFunction main_fn;
    main_fn.name = "main";
    const IrBlockId mb = main_fn.new_block("entry");
    /* El argumento: un bloque GRANDE del asignador.  Uno de pila (ALLOCA) solo
     * garantiza los 8 de cualquier ABI; el que pasa de la pagina lo entrega la
     * arena con su cabecera de 64, y eso es lo que hace que el parametro herede
     * algo que sirva para comprobar una exigencia de 16. */
    const IrValueId tam = const_de(main_fn, mb, 8192);
    const IrValueId arg = main_fn.new_value(IrType::PTR);
    {
        IrInstr ra{};
        ra.op = IrOp::RAW_ALLOC;
        ra.type = IrType::PTR;
        ra.dst = arg;
        ra.operands = {tam};
        main_fn.append(mb, std::move(ra));
    }
    {
        IrInstr call{};
        call.op = IrOp::CALL;
        call.type = IrType::VOID;
        call.dst = IR_NO_VALUE;
        call.func_name = "usada";
        call.operands = {arg};
        main_fn.append(mb, std::move(call));
        IrInstr r{};
        r.op = IrOp::RET;
        r.dst = IR_NO_VALUE;
        main_fn.append(mb, std::move(r));
    }

    mod.functions.push_back(std::move(usada));
    mod.functions.push_back(std::move(huerfana));
    mod.functions.push_back(std::move(main_fn));
    return mod;
}

static void test_universo_por_artefacto_y_visibilidad() {
    // (a) Programa entero: no hay un fuera, asi que hasta una funcion publica
    //     tiene todos sus llamantes a la vista.
    {
        const IrModule mod = modulo_con_llamada(/*usada_publica=*/true);
        const analysis::AlignmentSummaries s =
            analysis::compute_alignment_summaries(mod,
                                                  /*programa_cerrado=*/true);
        CHECK(s.universo_de("usada") == analysis::Universo::CerradoConLlamantes,
              "en un ejecutable, una publica con llamantes se resume");
        CHECK(s.universo_de("huerfana") ==
                  analysis::Universo::CerradoSinLlamantes,
              "y de la que no llama nadie se demostro que nadie la llama");
        CHECK(s.universo_de("main") == analysis::Universo::Abierto,
              "a main la llama el sistema: nunca se cierra");
    }
    // (b) Libreria: lo publico sigue siendo alcanzable por quien no se ve.
    {
        const IrModule mod = modulo_con_llamada(/*usada_publica=*/true);
        const analysis::AlignmentSummaries s =
            analysis::compute_alignment_summaries(mod,
                                                  /*programa_cerrado=*/false);
        CHECK(s.universo_de("usada") == analysis::Universo::Abierto,
              "en una libreria, de una publica no se afirma nada aunque se le "
              "vean llamadas");
        CHECK(s.universo_de("huerfana") ==
                  analysis::Universo::CerradoSinLlamantes,
              "lo privado si se cierra: de fuera no se puede alcanzar");
    }
    // (c) Libreria, pero la funcion es PRIVADA: se cierra igual que en (a).
    {
        const IrModule mod = modulo_con_llamada(/*usada_publica=*/false);
        const analysis::AlignmentSummaries s =
            analysis::compute_alignment_summaries(mod,
                                                  /*programa_cerrado=*/false);
        CHECK(s.universo_de("usada") == analysis::Universo::CerradoConLlamantes,
              "una privada tiene todos sus llamantes en el modulo");
    }
}

// --------------------------------------------------------------------------
// 7) Y lo que el resumen sirve para lo que existe: sembrar el parametro.
// --------------------------------------------------------------------------
static void test_resumen_siembra_parametro() {
    const IrModule mod = modulo_con_llamada(/*usada_publica=*/false);
    const analysis::AlignmentSummaries s =
        analysis::compute_alignment_summaries(mod, /*programa_cerrado=*/false);
    const analysis::AlignmentSummaries::Resumen *r = s.lookup("usada");
    CHECK(r != nullptr && r->params.size() == 1,
          "el resumen de `usada` describe su unico parametro");
    if (r == nullptr || r->params.empty()) return;
    // main le pasa una reserva grande; el hecho de alineacion dice de cuanto es
    // multiplo, y el parametro hereda eso en vez de valer "no se sabe nada".
    CHECK(r->params[0].modulo >= 16,
          "una reserva grande llega alineada, y el parametro lo hereda");
    CHECK(r->params[0].resto == 0, "y sin resto: es multiplo exacto");

    // Sin sembrar, dentro de la funcion el parametro no vale nada: es la
    // frontera que el resumen existe para cruzar.
    for (const IrFunction &fn : mod.functions) {
        if (fn.name != "usada") continue;
        const analysis::AlignmentFacts solo =
            analysis::compute_alignment(fn, nullptr);
        CHECK(solo.de(fn.params[0]) == 1,
              "sin resumen, de un parametro no se sabe nada");
        const analysis::AlignmentFacts con =
            analysis::compute_alignment(fn, &s);
        CHECK(con.multiplo_de(fn.params[0], 16),
              "con el resumen, el parametro ya se sabe multiplo de 16");
    }
}

int main() {
    test_marcador_resuelve_valor();
    test_registro_fijo_canonico();
    test_varias_candidatas_conservan_lo_suyo();
    test_dos_escrituras_sin_valor();
    test_efecto_localizado_con_dos_candidatas();
    test_efecto_usa_el_arch_del_objetivo();
    test_extension_como_expresion();
    test_extension_llega_al_efecto();
    test_ancho_por_clase();
    test_universo_por_artefacto_y_visibilidad();
    test_resumen_siembra_parametro();
    std::printf("=== ligaduras de asm + universo: %d checks, %d fallos ===\n",
                g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
