/**
 * @file asm_diag_test.cpp
 * @brief Tests de los diagnosticos estructurales del asm sobre el CFG
 *        (ver vx/asm_diag.h): codigo muerto, salto no resuelto, bucle sin
 * salida.
 */
#include "vx/asm/asm_diag.h"

#include <cstdio>
#include <string>

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

/// ¿Hay algun diagnostico con el codigo @p code?
static bool has_code(const std::vector<AsmDiag> &ds, const std::string &code) {
    for (const AsmDiag &d : ds)
        if (d.code == code) return true;
    return false;
}

/// Cuenta diagnosticos con el codigo @p code.
static int count_code(const std::vector<AsmDiag> &ds, const std::string &code) {
    int n = 0;
    for (const AsmDiag &d : ds)
        if (d.code == code) ++n;
    return n;
}

int main() {
    std::printf("=== asm_diag_test ===\n");

    // --- Bloque limpio: 0 diagnosticos. ---
    {
        auto ds = asm_diagnose(Isa::X86, "mov rax, rdi\n"
                                         "add rax, rsi\n");
        CHECK(ds.empty(), "bloque lineal limpio: 0 diagnosticos");
    }

    // --- Codigo muerto tras un ret. ---
    {
        auto ds = asm_diagnose(Isa::X86,
                               "mov rax, 1\n"
                               "ret\n"
                               "mov rax, 2\n"); // inalcanzable
        CHECK(has_code(ds, "VXA001"), "codigo muerto tras ret -> VXA001");
    }

    // --- Codigo muerto tras un jmp incondicional. ---
    {
        auto ds = asm_diagnose(Isa::X86,
                               "jmp .fin\n"
                               "mov rax, 7\n" // inalcanzable
                               ".fin:\n"
                               "mov rax, 0\n");
        CHECK(has_code(ds, "VXA001"), "codigo muerto tras jmp -> VXA001");
    }

    // --- Salto a etiqueta no definida. ---
    {
        auto ds = asm_diagnose(Isa::X86, "cmp rax, 0\n"
                                         "je .noexiste\n"
                                         "mov rax, 1\n");
        CHECK(has_code(ds, "VXA002"), "salto a etiqueta externa -> VXA002");
    }

    /* --- Salto a una FUNCION del modulo: no es un fallo. ---
     *
     * En Vesta un bloque `asm` puede saltar a otra funcion del modulo y lo
     * resuelve el enlazador.  Confundirlo con una etiqueta mal escrita sacaba
     * DOS avisos sobre codigo correcto: "etiqueta no definida" y, como el
     * bloque se quedaba sin salida, "bucle infinito". */
    {
        auto ds = asm_diagnose(Isa::X86, "mov rdi, rbx\n"
                                         "jmp __vxp_fiber_exit\n");
        CHECK(!has_code(ds, "VXA002"),
              "salto a funcion del modulo: sin VXA002");
        CHECK(!has_code(ds, "VXA003"), "y tampoco es un bucle infinito");
    }

    // Una rama condicional a una funcion del modulo, igual.
    {
        auto ds = asm_diagnose(Isa::X86, "cmp rax, 0\n"
                                         "je fiber_exit\n"
                                         "mov rax, 1\n"
                                         "ret\n");
        CHECK(!has_code(ds, "VXA002"), "rama a funcion del modulo: sin VXA002");
    }

    // --- Bucle sin salida (infinito). ---
    {
        auto ds = asm_diagnose(Isa::X86,
                               ".loop:\n"
                               "add rax, 1\n"
                               "jmp .loop\n"); // nunca sale
        CHECK(has_code(ds, "VXA003"), "bucle infinito -> VXA003");
        CHECK(count_code(ds, "VXA003") == 1, "bucle infinito: un solo aviso");
    }

    // --- Bucle CON salida: no debe reportar VXA003. ---
    {
        auto ds = asm_diagnose(Isa::X86,
                               "mov rcx, 10\n"
                               ".loop:\n"
                               "dec rcx\n"
                               "jnz .loop\n"); // sale por fallthrough al final
        CHECK(!has_code(ds, "VXA003"), "bucle con salida: sin VXA003");
    }

    // --- arm64: bucle infinito con b incondicional. ---
    {
        auto ds = asm_diagnose(Isa::ARM64, ".spin:\n"
                                           "add x0, x0, #1\n"
                                           "b .spin\n");
        CHECK(has_code(ds, "VXA003"), "arm64 bucle infinito -> VXA003");
    }

    // --- Salto indirecto: NO se reporta bucle falso (conservador). ---
    {
        auto ds = asm_diagnose(Isa::X86,
                               ".loop:\n"
                               "add rax, 1\n"
                               "jmp rax\n"); // indirecto: podria salir
        CHECK(!has_code(ds, "VXA003"),
              "salto indirecto: sin bucle falso (conservador)");
    }

    // === Dataflow: lecturas de registro sin inicializar (VXA004). ===
    int32_t ua = instr_db::microarch_by_name(Isa::X86, "intel-skylake");
    uint32_t skl = static_cast<uint32_t>(ua < 0 ? 0 : ua);

    // --- Lectura de un registro nunca escrito ni pre-definido -> VXA004. ---
    {
        AsmCfg c =
            build_asm_cfg(Isa::X86, "mov rax, rbx\n"); // lee rbx, escribe rax
        auto ds = asm_diagnose_uninit(c, Isa::X86, {}, skl);
        CHECK(has_code(ds, "VXA004"), "rbx sin inicializar -> VXA004");
    }

    // --- El mismo caso con rbx pre-definido (binding) -> sin aviso. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86, "mov rax, rbx\n");
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rbx"}, skl);
        CHECK(!has_code(ds, "VXA004"), "rbx pre-definido: sin VXA004");
    }

    // --- CERO FALSOS POSITIVOS en un cuerpo register() realista. ---
    {
        // mov rax,rdi ; imul rax,rax ; add rax,rcx  (entradas rdi,rcx via
        // register())
        AsmCfg c = build_asm_cfg(Isa::X86, "mov rax, rdi\n"
                                           "imul rax, rax\n"
                                           "add rax, rcx\n");
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rdi", "rcx"}, skl);
        CHECK(!has_code(ds, "VXA004"),
              "cuerpo register() valido: cero falsos positivos");
    }

    // --- Escritura antes de la lectura suprime el aviso. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86,
                                 "mov rax, 5\n"     // define rax
                                 "add rbx, rax\n"); // lee rax (definido) + rbx
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rbx"}, skl);
        CHECK(!has_code(ds, "VXA004"),
              "rax definido antes de leerse: sin VXA004");
    }

    // --- Una instruccion NO MODELADA suprime el aviso (conservador). ---
    {
        AsmCfg c =
            build_asm_cfg(Isa::X86,
                          "frobnicate_xyz\n" // desconocida -> modelada=false
                          "mov rbx, rax\n"); // rax podria haberla escrito
        auto ds = asm_diagnose_uninit(c, Isa::X86, {}, skl);
        CHECK(!has_code(ds, "VXA004"),
              "instruccion no modelada suprime VXA004 (conservador)");
    }

    // --- Definido en una sola rama -> NO se avisa (MUST-undefined,
    // conservador).
    //     Hay un camino (via .set) donde rax SI esta definido, asi que no
    //     podemos afirmar con certeza que sea un error -> cero falsos
    //     positivos. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86,
                                 "cmp rcx, 0\n" // B0
                                 "je .set\n"
                                 "jmp .use\n" // B1: no define rax
                                 ".set:\n"
                                 "mov rax, 1\n" // B2: define rax
                                 ".use:\n"
                                 "add rdx, rax\n"); // B3: lee rax
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rcx", "rdx"}, skl);
        CHECK(!has_code(ds, "VXA004"),
              "definido en una sola rama: sin VXA004 (MUST-undefined)");
    }

    // --- Indefinido en TODOS los caminos hasta la lectura -> SI avisa. ---
    {
        // Ninguna rama define rax; al leerlo en el merge esta indefinido
        // siempre.
        AsmCfg c = build_asm_cfg(
            Isa::X86,
            "cmp rcx, 0\n" // B0
            "je .b\n"
            "mov rdx, 1\n" // B1
            "jmp .use\n"
            ".b:\n"
            "mov rdx, 2\n" // B2
            ".use:\n"
            "add rdx, rax\n"); // B3: lee rax, indefinido en ambas ramas
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rcx"}, skl);
        CHECK(has_code(ds, "VXA004"),
              "rax indefinido en todos los caminos: VXA004 en el merge");
    }

    // === Dataflow de flags: lectura sin comparacion previa (VXA005). ===

    // --- Rama condicional sin ningun escritor de flags antes -> VXA005. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86,
                                 "mov rax, 0\n" // no toca flags
                                 "jnz .end\n"   // lee flags indefinidas
                                 "add rax, 1\n"
                                 ".end:\n"
                                 "ret\n");
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rax"}, skl);
        CHECK(has_code(ds, "VXA005"), "jnz sin cmp previo -> VXA005");
    }

    // --- cmp antes de la rama -> sin VXA005. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86,
                                 "cmp rax, rbx\n" // escribe flags
                                 "je .eq\n"       // lee flags (definidas)
                                 "mov rax, 0\n"
                                 ".eq:\n"
                                 "ret\n");
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rax", "rbx"}, skl);
        CHECK(!has_code(ds, "VXA005"), "cmp antes de je: sin VXA005");
    }

    // --- test antes de la rama -> sin VXA005. ---
    {
        AsmCfg c = build_asm_cfg(Isa::X86, "test rax, rax\n"
                                           "jz .zero\n"
                                           "mov rbx, 1\n"
                                           ".zero:\n"
                                           "ret\n");
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rax"}, skl);
        CHECK(!has_code(ds, "VXA005"), "test antes de jz: sin VXA005");
    }

    // --- Cuerpo aritmetico sin ramas: ningun VXA005 (nadie lee flags). ---
    {
        AsmCfg c =
            build_asm_cfg(Isa::X86,
                          "mov rax, rdi\n"
                          "add rax, rsi\n"); // escribe flags, nadie las lee
        auto ds = asm_diagnose_uninit(c, Isa::X86, {"rdi", "rsi"}, skl);
        CHECK(!has_code(ds, "VXA005"), "sin lectura de flags: sin VXA005");
    }

    // --- arm64: b.eq sin comparacion previa -> VXA005. ---
    {
        AsmCfg c = build_asm_cfg(Isa::ARM64,
                                 "mov x0, #1\n" // no toca NZCV
                                 "b.eq .l\n"    // lee flags indefinidas
                                 "mov x0, #2\n"
                                 ".l:\n"
                                 "ret\n");
        auto ds = asm_diagnose_uninit(c, Isa::ARM64, {"x0"}, 0);
        CHECK(has_code(ds, "VXA005"), "arm64 b.eq sin cmp previo -> VXA005");
    }

    std::printf("=== asm_diag_test: %d checks OK, %d fallidos ===\n",
                g_checks - g_fail, g_fail);
    return g_fail ? 1 : 0;
}
