/**
 * @file asm_cfg_test.cpp
 * @brief Tests de la reconstruccion del CFG de bloques de inline asm
 *        (ver vx/asm_cfg.h): bloques basicos + aristas desde labels/saltos.
 */
#include "vx/asm/asm_cfg.h"

#include <algorithm>
#include <cstdio>

using namespace vx;
using vx::instr_db::Isa;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  FAIL: %s (linea %d)\n", (msg), __LINE__);           \
        }                                                                      \
    } while (0)

/// ¿El bloque @p b tiene a @p s como sucesor?
static bool has_succ(const AsmCfg &c, uint32_t b, uint32_t s) {
    const auto &v = c.blocks[b].succs;
    return std::find(v.begin(), v.end(), s) != v.end();
}

int main() {
    std::printf("=== asm_cfg_test ===\n");

    // --- 1) Bloque lineal (sin saltos): un solo bloque basico. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86, "mov rax, rdi\n"
                                           "add rax, rsi\n"
                                           "imul rax, rax\n");
        /* Tres instrucciones MAS el nodo de salida sintetico que el
         * constructor anade a proposito: el bloque asm sale por el final -- por
         * caida de la ultima instruccion o por la rama no tomada de un salto
         * condicional final -- y sin un nodo que represente ese punto, esa rama
         * se queda sin sucesor.  El test contaba solo las reales y llevaba
         * tiempo fallando por eso. */
        CHECK(c.insns.size() == 4, "lineal: 3 instrucciones + la salida");
        CHECK(c.blocks.size() == 1, "lineal: 1 bloque basico");
        CHECK(c.blocks[0].succs.empty(), "lineal: bloque sin sucesores");
        CHECK(!c.has_indirect, "lineal: sin saltos indirectos");
    }

    // --- 2) Rama condicional hacia adelante (if/else + merge). ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86,
                                 "cmp rax, rbx\n" // B0
                                 "jg .mayor\n"    // B0 termina: cond
                                 "mov rcx, 0\n"   // B1 (fallthrough)
                                 "jmp .fin\n"     // B1 termina: uncond
                                 ".mayor:\n"
                                 "mov rcx, 1\n" // B2 (destino de jg)
                                 ".fin:\n"
                                 "mov rax, rcx\n"); // B3 (merge)
        CHECK(c.blocks.size() == 4, "if/else: 4 bloques");
        // B0 (cmp+jg) -> B1 (fallthrough) y B2 (.mayor).
        CHECK(c.blocks[0].term == AsmTerm::CondBranch,
              "B0 termina en rama cond");
        CHECK(c.blocks[0].succs.size() == 2, "B0: 2 sucesores");
        CHECK(has_succ(c, 0, 1) && has_succ(c, 0, 2), "B0 -> B1 y B2");
        // B1 (mov+jmp .fin) -> B3, sin fallthrough (jmp incondicional).
        CHECK(c.blocks[1].term == AsmTerm::UncondJump, "B1 termina en jmp");
        CHECK(c.blocks[1].succs.size() == 1 && has_succ(c, 1, 3),
              "B1 -> B3 (sin fallthrough)");
        // B2 (.mayor: mov) -> B3 (fallthrough al merge).
        CHECK(has_succ(c, 2, 3), "B2 -> B3 (fallthrough al merge)");
        CHECK(c.blocks[2].label == ".mayor", "B2 lleva la etiqueta .mayor");
        // B3 (.fin: mov) es el ultimo, sin sucesores.
        CHECK(c.blocks[3].succs.empty(), "B3 sin sucesores");
        // preds del merge: B1 (por jmp) y B2 (por fallthrough).
        CHECK(c.blocks[3].preds.size() == 2, "merge tiene 2 predecesores");
    }

    // --- 3) Bucle hacia atras (back-edge). ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86,
                                 "mov rcx, 10\n" // B0
                                 ".loop:\n"
                                 "dec rcx\n"     // B1 (destino del back-edge)
                                 "jnz .loop\n"); // B1 termina: cond -> B1
        // Los dos del bucle mas el bloque de salida (ver arriba): por el sale
        // la rama NO tomada del `jnz`.
        CHECK(c.blocks.size() == 3, "bucle: 2 bloques + la salida");
        // B1 se salta a si mismo (back-edge) -> B1 en sus propios sucesores.
        CHECK(has_succ(c, 1, 1), "back-edge B1 -> B1");
        // preds de B1: B0 (fallthrough) y B1 (back-edge).
        CHECK(c.blocks[1].preds.size() == 2, "cabecera del bucle: 2 preds");
    }

    // --- 4) ret corta el flujo (sin sucesores). ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86,
                                 "mov rax, 1\n"
                                 "ret\n"
                                 "mov rax, 2\n"); // codigo muerto tras el ret
        CHECK(c.blocks.size() == 2, "ret: 2 bloques (el 2o es inalcanzable)");
        CHECK(c.blocks[0].term == AsmTerm::Ret, "B0 termina en ret");
        CHECK(c.blocks[0].succs.empty(), "ret: B0 sin sucesores");
        // El 2o bloque no tiene predecesores -> codigo muerto (util para diag).
        CHECK(c.blocks[1].preds.empty(), "codigo muerto: sin predecesores");
    }

    // --- 5) Salto indirecto -> CFG marcado impreciso. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86, "jmp rax\n");
        CHECK(c.has_indirect, "jmp rax: CFG impreciso");
        CHECK(c.blocks[0].term == AsmTerm::Indirect,
              "jmp rax: terminador indirecto");
    }

    /* --- 5.b) Saltos CALCULADOS: hasta donde llega el seguidor. ---
     *
     * La direccion se monta en un registro y se pasa a otro antes de saltar.
     * Mirando solo la etiqueta escrita tal cual, eso se perdia: el destino
     * estaba delante y el grafo lo daba por desconocido.  Lo que NO se puede
     * saber -- una lectura de memoria, un desplazamiento dentro de la etiqueta
     * -- tiene que seguir dandose por desconocido: senalar la linea equivocada
     * es peor que no senalar. */
    {
        // La etiqueta pasa de un registro a otro.
        AsmCfg c = build_asm_cfg(Isa::X86, ".top:\n"
                                           "mov r8, .top\n"
                                           "mov rax, r8\n"
                                           "jmp rax\n");
        CHECK(!c.has_indirect, "copia entre registros: destino conocido");

        // `lea` toma la DIRECCION, que es la misma.
        AsmCfg d = build_asm_cfg(Isa::X86, ".top:\n"
                                           "mov r8, .top\n"
                                           "lea rax, [r8]\n"
                                           "jmp rax\n");
        CHECK(!d.has_indirect, "lea [reg]: destino conocido");

        // `mov` de memoria LEE la etiqueta; lo que hay dentro no es la
        // etiqueta.
        AsmCfg e = build_asm_cfg(Isa::X86, ".top:\n"
                                           "mov r8, .top\n"
                                           "mov rax, [r8]\n"
                                           "jmp rax\n");
        CHECK(e.has_indirect, "mov reg, [reg]: lee memoria, no se sabe");

        // Un desplazamiento apunta DENTRO: a que instruccion cae no se sabe
        // sin ensamblar.
        AsmCfg f = build_asm_cfg(Isa::X86, ".top:\n"
                                           "mov r8, .top\n"
                                           "lea rax, [r8 + 16]\n"
                                           "jmp rax\n");
        CHECK(f.has_indirect,
              "lea [reg + N]: dentro de la etiqueta, no se sabe");

        // Pisar el registro borra lo que se sabia de el.
        AsmCfg g = build_asm_cfg(Isa::X86, ".top:\n"
                                           "mov r8, .top\n"
                                           "mov rax, r8\n"
                                           "xor rax, rax\n"
                                           "jmp rax\n");
        CHECK(g.has_indirect, "registro pisado: se olvida el destino");

        // `push` de un registro que lleva la etiqueta, recogido por el `ret`.
        AsmCfg h = build_asm_cfg(Isa::X86, ".top:\n"
                                           "mov r8, .top\n"
                                           "push r8\n"
                                           "ret\n");
        CHECK(!h.has_indirect, "push reg + ret: destino conocido");
    }

    /* --- 5.c) Saltar FUERA del bloque no es una etiqueta rota. ---
     *
     * En Vesta un bloque `asm` puede saltar a una funcion del modulo: lo
     * resuelve el enlazador y es codigo correcto.  Metiendolo en el mismo saco
     * que una etiqueta mal escrita, un `jmp __vxp_fiber_exit` sacaba un aviso
     * de "etiqueta no definida" sobre la linea buena y ademas tumbaba el
     * analisis del bloque entero.  Un nombre que empieza por `.` SI es local:
     * si no esta, esta mal escrito. */
    {
        AsmCfg c = build_asm_cfg(Isa::X86, "call r12\n"
                                           "jmp __vxp_fiber_exit\n");
        CHECK(c.has_external_target, "jmp a simbolo del modulo: es una salida");
        CHECK(!c.has_unresolved_target, "y no una etiqueta rota");

        AsmCfg d = build_asm_cfg(Isa::X86, "cmp rax, 0\n"
                                           "je __vxp_fiber_exit\n"
                                           "ret\n");
        CHECK(d.has_external_target, "rama condicional a simbolo: salida");

        AsmCfg e = build_asm_cfg(Isa::X86, "jmp .noexiste\n"
                                           "ret\n");
        CHECK(e.has_unresolved_target, "etiqueta local sin definir: rota");
        CHECK(!e.has_external_target, "y no cuenta como salida");

        // El criterio, en el mismo sitio que usa el ensamblador.
        CHECK(asm_is_external_symbol("__vxp_fiber_exit"),
              "un identificador desnudo puede venir de fuera");
        CHECK(!asm_is_external_symbol(".local"),
              "el punto inicial lo hace local de NASM");
        CHECK(!asm_is_external_symbol("[rax + 8]"),
              "una direccion de memoria no es un simbolo");
    }

    // --- 6) call retorna (fallthrough), no corta el bloque en aristas. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86, "call foo\n"
                                           "add rax, 1\n");
        // call+add pueden estar en el mismo bloque (call retorna).
        CHECK(c.blocks.size() == 1, "call: un solo bloque (retorna)");
        CHECK(!c.has_indirect, "call foo: no es indirecto");
    }

    // --- 7) arm64: cbz condicional + b incondicional. ---
    {
        AsmCfg c = build_asm_cfg(Isa::ARM64,
                                 "cbz x0, .zero\n" // B0 cond
                                 "mov x1, #1\n"    // B1
                                 "b .fin\n"        // B1 uncond
                                 ".zero:\n"
                                 "mov x1, #0\n" // B2
                                 ".fin:\n"
                                 "ret\n"); // B3
        CHECK(c.blocks.size() == 4, "arm64: 4 bloques");
        CHECK(c.blocks[0].term == AsmTerm::CondBranch, "arm64 cbz: rama cond");
        CHECK(has_succ(c, 0, 1) && has_succ(c, 0, 2),
              "arm64 cbz -> fall + .zero");
        CHECK(c.blocks[1].term == AsmTerm::UncondJump,
              "arm64 b: incondicional");
        CHECK(has_succ(c, 1, 3), "arm64 b .fin -> B3");
        CHECK(c.blocks[3].term == AsmTerm::Ret, "arm64 ret corta el flujo");
    }

    // --- 8) arm64: b.eq (rama con condicion). ---
    {
        std::string tgt;
        AsmTerm t = asm_classify_term(Isa::ARM64, "b.eq .lbl", tgt);
        CHECK(t == AsmTerm::CondBranch && tgt == ".lbl",
              "arm64 b.eq -> cond .lbl");
        AsmTerm bl = asm_classify_term(Isa::ARM64, "bl fn", tgt);
        CHECK(bl == AsmTerm::Call, "arm64 bl -> call");
    }

    // --- 9) riscv: beq condicional + j incondicional. ---
    {
        std::string tgt;
        CHECK(asm_classify_term(Isa::RISCV, "beq a0, a1, .eq", tgt) ==
                      AsmTerm::CondBranch &&
                  tgt == ".eq",
              "riscv beq -> cond .eq");
        CHECK(asm_classify_term(Isa::RISCV, "j .fin", tgt) ==
                  AsmTerm::UncondJump,
              "riscv j -> uncond");
        CHECK(asm_classify_term(Isa::RISCV, "ret", tgt) == AsmTerm::Ret,
              "riscv ret");
    }

    // --- 10) etiqueta destino no definida -> has_unresolved_target. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86, "jmp .noexiste\n");
        CHECK(c.has_unresolved_target, "salto a etiqueta externa: no resuelto");
    }

    std::printf("=== asm_cfg_test: %d checks OK, %d fallidos ===\n",
                g_checks - g_fail, g_fail);
    return g_fail ? 1 : 0;
}
