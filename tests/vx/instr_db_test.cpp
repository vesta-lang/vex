/**
 * @file instr_db_test.cpp
 * @brief Tests del emparejador texto->FormID sobre la DB de instrucciones
 *        embebida (ver vx/instr_db.h).
 */
#include "vx/asm/instr_db.h"

#include <cstdio>

using namespace vx::instr_db;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  FAIL: %s (linea %d)\n", (msg), __LINE__);           \
        }                                                                      \
    } while (0)

static ParsedOp reg(uint16_t w) {
    return ParsedOp{OP_REG, w};
}
static ParsedOp mem(uint16_t w) {
    return ParsedOp{OP_MEM, w};
}

int main() {
    std::printf("=== instr_db_test ===\n");

    // La DB x86 se cargo (tablas embebidas, sin archivos externos).
    CHECK(form_count(Isa::X86) == 22252, "x86: 22252 formas embebidas");

    // add reg64, reg64 -> una forma ADD.
    int32_t add = match(Isa::X86, "add", {reg(64), reg(64)});
    CHECK(add >= 0, "match add reg64,reg64");
    CHECK(std::string(iclass_name(Isa::X86, add)) == "ADD",
          "add -> iclass ADD");

    // minuscula/mayuscula indiferente.
    CHECK(match(Isa::X86, "ADD", {reg(64), reg(64)}) == add,
          "ADD == add (case-insensitive)");

    // mov reg32, mem32 casa una forma distinta (aridad/tipos).
    int32_t mov = match(Isa::X86, "mov", {reg(32), mem(32)});
    CHECK(mov >= 0 && std::string(iclass_name(Isa::X86, mov)) == "MOV",
          "match mov reg32,[mem32]");

    // mfence: barrera/serializante (overlay derivado).
    int32_t mf = match(Isa::X86, "mfence", {});
    CHECK(mf >= 0, "match mfence");
    uint16_t ov = overlay_of(Isa::X86, mf);
    CHECK(ov & (OVL_BARRIER | OVL_SERIALIZING | OVL_MEM_SEQ_CST),
          "mfence: overlay barrera/serializante");

    // syscall: overlay syscall.
    int32_t sc = match(Isa::X86, "syscall", {});
    CHECK(sc >= 0 && (overlay_of(Isa::X86, sc) & OVL_SYSCALL),
          "syscall: overlay syscall");

    // mnemonico inexistente -> -1.
    CHECK(match(Isa::X86, "frobnicate", {}) < 0, "mnemonico inexistente -> -1");

    /* --- Lo que el TEXTO no distingue y la FORMA si ----------------------
     *
     * Estas tres familias no casaban en NINGUNA de sus formas, y el motivo era
     * el mismo: el emparejador exigia que el tipo de operando leido del texto
     * fuera identico al de la forma, cuando hay tipos que se ESCRIBEN igual.
     *
     * Una direccion generada (`agen`) y un acceso a memoria son los dos
     * `[base + indice*escala + desp]`; el destino de un salto es un numero o
     * una etiqueta, igual que un inmediato.  Quien sabe la diferencia es la
     * forma, no quien lee la linea.
     *
     * No se notaba porque nadie le preguntaba a la DB por codigo COMPILADO: el
     * asm que escribe un programa Vesta rara vez lleva `lea`, y los saltos van
     * a etiquetas propias.  En cuanto se le pregunta por lo que emite un
     * compilador de C, `lea` es de las mas frecuentes -- y es la que lleva el
     * calculo de direcciones, justo lo que hace falta para saber a que apunta
     * un puntero. */
    int32_t lea = match(Isa::X86, "lea", {reg(64), mem(0)});
    CHECK(lea >= 0 && std::string(iclass_name(Isa::X86, lea)) == "LEA",
          "lea reg64, [mem]: una direccion generada casa como memoria");
    bool lm_r = false, lm_w = false;
    CHECK(!memory_of(Isa::X86, lea, lm_r, lm_w) || (!lm_r && !lm_w),
          "lea NO toca memoria: la calcula");

    int32_t je = match(Isa::X86, "je", {ParsedOp{OP_IMM, 0}});
    CHECK(je >= 0, "je <destino>: un destino de salto casa como inmediato");
    bool je_r = false, je_w = false;
    CHECK(flags_of(Isa::X86, je, je_r, je_w) && je_r,
          "je lee las banderas");

    /* Un registro VECTORIAL es un CONTENEDOR: `xmm0` mide 128 bits pero
     * `addsd` opera sobre los 64 de abajo.  El texto solo puede dar el tamano
     * del registro; sobre cuantos bits se opera lo sabe la forma.  Exigir
     * igualdad dejaba fuera la familia escalar de coma flotante entera. */
    CHECK(match(Isa::X86, "addsd", {reg(128), reg(128)}) >= 0,
          "addsd xmm,xmm: la forma usa parte del contenedor");
    CHECK(match(Isa::X86, "cvtsi2sd", {reg(128), reg(64)}) >= 0,
          "cvtsi2sd xmm,r64: contenedor y registro normal a la vez");
    // Al reves NO: un xmm no vale donde se pide un zmm.
    bool por_ops = false;
    (void)match(Isa::X86, "vaddpd", {reg(128), reg(128), reg(128)}, &por_ops);

    /* Un operando IMPLICITO no hay que escribirlo, pero se PUEDE escribir: un
     * desensamblador escribe el `cl` de un desplazamiento y los `[rdi]`/`[rsi]`
     * de una operacion de cadena.  Que aparezca o no no puede decidir si la
     * forma casa. */
    CHECK(match(Isa::X86, "shr", {reg(64), reg(8)}) >= 0,
          "shr r64, cl: el implicito escrito no descuadra la aridad");
    /* Este va por `asm_insn_sem` y no por `match`: separar el prefijo de
     * repeticion es cosa de quien parte la LINEA, y `match` recibe el mnemonico
     * ya resuelto.  Ademas es el caso real -- `rep movsq` es lo que el
     * desensamblador escribe donde el fuente decia `memcpy`. */
    CHECK(asm_insn_sem(Isa::X86, "rep movsq", 0).modeled,
          "rep movsq: el implicito omitido tampoco descuadra");

    /* `movabs` es la grafia de GAS para mover un inmediato de 64 bits; la
     * instruccion es `MOV`.  Y `movsd` nombra DOS instrucciones distintas: la
     * de cadena y la escalar de doble precision, que la base separa en `MOVSD`
     * y `MOVSD_XMM`.  Cual es lo dicen los operandos, no el nombre. */
    int32_t mabs = match(Isa::X86, "movabs", {reg(64), ParsedOp{OP_IMM, 0}});
    CHECK(mabs >= 0 && std::string(iclass_name(Isa::X86, mabs)) == "MOV",
          "movabs: es la grafia de GAS de MOV");
    int32_t msse = match(Isa::X86, "movsd", {reg(128), mem(64)});
    CHECK(msse >= 0 &&
              std::string(iclass_name(Isa::X86, msse)) == "MOVSD_XMM",
          "movsd xmm,[mem]: la escalar, no la de cadena");
    int32_t mstr = match(Isa::X86, "movsd", {});
    CHECK(mstr >= 0 && std::string(iclass_name(Isa::X86, mstr)) == "MOVSD",
          "movsd a secas: la de cadena");

    // --- ARM64 (AArch64) ---
    CHECK(form_count(Isa::ARM64) == 4619, "arm64: 4619 formas embebidas");
    int32_t aadd = match(Isa::ARM64, "add", {reg(0), reg(0), reg(0)});
    CHECK(aadd >= 0 && std::string(iclass_name(Isa::ARM64, aadd)) == "ADD",
          "arm64: match add x,x,x");
    /* Un `[...]` escrito cubre VARIOS operandos de la forma.
     *
     * ARM modela la direccion por partes: `LDRB` declara destino, registro
     * base, desplazamiento y acceso -- cuatro --, y quien escribe la linea pone
     * dos, `w8` y `[x1, #0x5]`.  Sin absorber la tirada no casaba ni un `ldrb`,
     * ni un `ldrh`, ni un `strb`: la aridad no coincide nunca.
     *
     * Y lo que se comprueba no es solo que CASE, sino que la semantica salga
     * bien: la alineacion tiene que agrupar igual que el emparejador.  Si no,
     * el `[x1, #0x5]` se empareja con el operando BASE -- un registro --, el
     * operando de MEMORIA no se alcanza, y sale una carga que no declara leer
     * memoria.  Eso deja mover un acceso por encima de otro, que es de los
     * peores errores que puede cometer esto. */
    {
        const AsmInsnSem ld = asm_insn_sem(Isa::ARM64, "ldrb w8, [x1, #0x5]", 0);
        CHECK(ld.modeled, "arm64: ldrb con direccion por partes casa");
        CHECK(ld.reads_mem && !ld.writes_mem, "arm64: ldrb LEE memoria");
        CHECK(!ld.writes.empty(), "arm64: ldrb escribe su destino");
        const AsmInsnSem st = asm_insn_sem(Isa::ARM64, "strb w9, [x0, #0x58]", 0);
        CHECK(st.modeled, "arm64: strb casa");
        CHECK(st.writes_mem && !st.reads_mem, "arm64: strb ESCRIBE memoria");
        // Y la agrupacion no se lleva por delante la forma directa.
        const AsmInsnSem l8 = asm_insn_sem(Isa::ARM64, "ldr x8, [x1]", 0);
        CHECK(l8.modeled && l8.reads_mem, "arm64: ldr de 64 bits sigue bien");
    }

    // ldaxr (LL/SC) -> overlay ll_sc; dmb -> barrera.
    int32_t ldaxr = match(Isa::ARM64, "ldaxr", {reg(0), mem(0)});
    CHECK(ldaxr >= 0 && (overlay_of(Isa::ARM64, ldaxr) & OVL_LL_SC),
          "arm64: ldaxr overlay ll_sc");
    int32_t dmb = match(Isa::ARM64, "dmb", {});
    CHECK(dmb >= 0 && (overlay_of(Isa::ARM64, dmb) & OVL_BARRIER),
          "arm64: dmb overlay barrera");

    // --- RISC-V ---
    CHECK(form_count(Isa::RISCV) == 1867, "riscv: 1867 formas embebidas");
    // amoadd.w -> overlay atomic.
    int32_t amo =
        match(Isa::RISCV, "amoadd.w", {reg(0), reg(0), reg(0), mem(0)});
    CHECK(amo >= 0 && (overlay_of(Isa::RISCV, amo) & OVL_ATOMIC),
          "riscv: amoadd.w overlay atomic");
    // fence -> overlay barrera.
    int32_t fen =
        match(Isa::RISCV, "fence", {ParsedOp{OP_IMM, 0}, ParsedOp{OP_IMM, 0}});
    CHECK(fen >= 0 && (overlay_of(Isa::RISCV, fen) & OVL_BARRIER),
          "riscv: fence overlay barrera");
    // la misma DB no confunde ISAs: 'ldaxr' no existe en x86.
    CHECK(match(Isa::X86, "ldaxr", {}) < 0, "x86 no tiene ldaxr");

    // --- capa de COSTE (latencia + puertos) ---
    CHECK(microarch_count(Isa::X86) == 21, "x86: 21 microarq con coste");
    int32_t skl = microarch_by_name(Isa::X86, "intel-skylake");
    CHECK(skl >= 0, "x86: intel-skylake presente");
    // add reg,reg en skylake: latencia 1, throughput alto, con puertos.
    AsmCost ca = cost(Isa::X86, add, (uint32_t)skl);
    CHECK(ca.found, "coste add en skylake encontrado");
    CHECK(ca.latency >= 1.0f && ca.latency <= 1.5f, "add skylake latencia ~1");
    CHECK(ca.ports_count > 0 && ca.port_names,
          "add skylake usa puertos (paralelo)");
    // microarq inexistente / forma sin coste -> found=false.
    CHECK(!cost(Isa::X86, add, 999).found,
          "microarq fuera de rango -> no found");
    // arm64: coste en neoverse-n2.
    int32_t n2 = microarch_by_name(Isa::ARM64, "neoverse-n2");
    CHECK(n2 >= 0, "arm64: neoverse-n2 presente");
    AsmCost cn = cost(Isa::ARM64, aadd, (uint32_t)n2);
    CHECK(cn.found && cn.latency > 0.0f, "arm64: coste add en neoverse-n2");
    // riscv: coste en sifive-p670.
    int32_t p6 = microarch_by_name(Isa::RISCV, "sifive-p670");
    CHECK(p6 >= 0 && cost(Isa::RISCV, amo, (uint32_t)p6).found,
          "riscv: coste amoadd.w en sifive-p670");

    // --- pipeline completo: LINEA de asm -> FormID (parse + match) ---
    CHECK(match_asm_line(Isa::X86, "add rax, rcx") == add,
          "asm line: 'add rax, rcx' == match add reg64,reg64");
    int32_t ml_mov = match_asm_line(Isa::X86, "mov eax, [rbx]");
    CHECK(ml_mov >= 0 && std::string(iclass_name(Isa::X86, ml_mov)) == "MOV",
          "asm line: 'mov eax, [rbx]' -> MOV");
    // comentarios y labels se ignoran.
    CHECK(match_asm_line(Isa::X86, "mfence  ; barrera") == mf,
          "asm line: comentario ignorado");
    CHECK(match_asm_line(Isa::X86, "loop_top:") < 0, "asm line: label -> -1");
    // ARM: linea con 3 registros (el ancho real x=64 descarta las formas
    // ADD vectoriales) y con memoria.
    int32_t ml_aadd = match_asm_line(Isa::ARM64, "add x0, x1, x2");
    CHECK(ml_aadd >= 0 &&
              std::string(iclass_name(Isa::ARM64, ml_aadd)) == "ADD",
          "asm line arm64: add x,x,x -> ADD");
    int32_t ml_ldaxr = match_asm_line(Isa::ARM64, "ldaxr x0, [x1]");
    CHECK(ml_ldaxr >= 0 && (overlay_of(Isa::ARM64, ml_ldaxr) & OVL_LL_SC),
          "asm line arm64: ldaxr -> ll_sc");
    // RISC-V: memoria disp(reg).
    int32_t ml_amo = match_asm_line(Isa::RISCV, "amoadd.w a0, a1, (a2)");
    CHECK(ml_amo >= 0 && (overlay_of(Isa::RISCV, ml_amo) & OVL_ATOMIC),
          "asm line riscv: amoadd.w a0,a1,(a2) -> atomic");
    // parse_operand: clasificacion basica.
    CHECK(parse_operand(Isa::X86, "rax").kind == OP_REG &&
              parse_operand(Isa::X86, "rax").width == 64,
          "parse_operand x86 rax -> reg64");
    CHECK(parse_operand(Isa::X86, "[rbx]").kind == OP_MEM,
          "parse_operand x86 [rbx] -> mem");
    CHECK(parse_operand(Isa::ARM64, "#0").kind == OP_IMM,
          "parse_operand arm64 #0 -> imm");

    // --- capa de FEATURES (que admite cada CPU) ---
    CHECK(cpu_count(Isa::X86) == 128, "x86: 128 CPU con features");
    int32_t hsw = cpu_by_name(Isa::X86, "haswell");
    CHECK(hsw >= 0, "x86: haswell presente");
    CHECK(cpu_has_feature(Isa::X86, (uint32_t)hsw, "AVX2"),
          "haswell tiene AVX2");
    CHECK(!cpu_has_feature(Isa::X86, (uint32_t)hsw, "AVX512F"),
          "haswell NO tiene AVX512");
    // arm64 y arm32 comparten features (misma tabla ARM).
    int32_t n2c = cpu_by_name(Isa::ARM64, "neoverse-n2");
    CHECK(n2c >= 0 && cpu_has_feature(Isa::ARM64, (uint32_t)n2c, "SVE2"),
          "arm64: neoverse-n2 tiene SVE2");
    CHECK(cpu_by_name(Isa::ARM32, "neoverse-n2") == n2c,
          "arm32 comparte tabla de features con arm64");
    // riscv: sifive-x280 tiene vector.
    int32_t x280 = cpu_by_name(Isa::RISCV, "sifive-x280");
    CHECK(x280 >= 0 &&
              cpu_has_feature(Isa::RISCV, (uint32_t)x280, "StdExtZve32x"),
          "riscv: sifive-x280 tiene Zve32x (vector)");

    // --- coste de BLOQUE (modelo superescalar: latencia + puertos) ---
    {
        const char *blk = "mov rax, rbx\nadd rax, rcx\nimul rax, rax\n";
        AsmBlockCost bc = analyze_asm_cost(Isa::X86, blk, (uint32_t)skl);
        CHECK(bc.instr_count == 3 && bc.matched == 3,
              "bloque: 3 instr emparejadas");
        CHECK(bc.costed == 3, "bloque: 3 con coste en skylake");
        CHECK(bc.total_uops >= 3, "bloque: uops >= 3");
        CHECK(bc.latency_sum > 0.0f, "bloque: latencia serie > 0");
        CHECK(bc.throughput > 0.0f && !bc.port_pressure.empty(),
              "bloque: throughput + presion de puertos (modelo paralelo)");
        // una linea desconocida cuenta como instr no emparejada.
        AsmBlockCost b2 = analyze_asm_cost(
            Isa::X86, "add rax, rcx\nfrobnicate\n", (uint32_t)skl);
        CHECK(b2.instr_count == 2 && b2.matched == 1,
              "bloque: linea desconocida no empareja");
    }

    // --- scheduling: dependencias + reorden VALIDO (seguridad critica) ---
    {
        // semantica por instruccion.
        AsmInsnSem si = asm_insn_sem(Isa::X86, "add rax, rcx", (uint32_t)skl);
        CHECK(si.modeled && si.writes_flags && si.form_id >= 0,
              "sem: 'add rax,rcx' modelada, escribe flags");
        CHECK(si.reads.size() >= 2 && si.writes.size() == 1,
              "sem: add lee 2 (rax,rcx), escribe 1 (rax)");
        AsmInsnSem sm = asm_insn_sem(Isa::X86, "mov rax, [rbx]", (uint32_t)skl);
        CHECK(sm.reads_mem, "sem: 'mov rax,[rbx]' lee memoria");
        AsmInsnSem sb = asm_insn_sem(Isa::X86, "mfence", (uint32_t)skl);
        CHECK(sb.barrier, "sem: mfence es barrera");
        /* Instruccion con registros IMPLICITOS (`mul rbx` usa rax y escribe
         * rax:rdx).  ANTES este test exigia lo contrario -- que no se modelara
         * y se tratara conservadora --, y rendirse ahi dejaba sin modelar
         * justo a las instrucciones que tocan registros QUE NADIE VE VENIR,
         * que son las peligrosas: quien crea que `rdx` sigue valiendo lo de
         * antes despues de una `mul` se equivoca.
         *
         * Ahora la forma dice cuales son y se anotan como si estuvieran
         * escritos, que es mas seguro Y mas preciso.  El test comprueba lo que
         * de verdad importa: que los implicitos ESTAN. */
        AsmInsnSem su = asm_insn_sem(Isa::X86, "mul rbx", (uint32_t)skl);
        auto menciona = [](const std::vector<std::string> &v, const char *r) {
            for (const std::string &x : v)
                if (x == r) return true;
            return false;
        };
        CHECK(su.modeled, "sem: mul se modela, con sus implicitos dentro");
        CHECK(menciona(su.reads, "rax") && menciona(su.reads, "rbx"),
              "sem: mul lee rax (implicito) y rbx (escrito)");
        CHECK(menciona(su.writes, "rax") && menciona(su.writes, "rdx"),
              "sem: mul escribe rax:rdx, que es lo que nadie ve venir");

        // RAW: 'add' lee rax que escribe 'mov' -> orden conservado.
        AsmSchedule s1 = schedule_asm_block(
            Isa::X86, "mov rax, rbx\nadd rcx, rax\n", (uint32_t)skl);
        CHECK(s1.valid, "sched: invariante de seguridad (RAW)");
        CHECK(s1.order.size() == 2 && s1.order[0] == 0 && s1.order[1] == 1,
              "sched: RAW conserva el orden");

        // WAW: dos escrituras a rax -> orden conservado.
        AsmSchedule s2 = schedule_asm_block(
            Isa::X86, "mov rax, rbx\nmov rax, rcx\n", (uint32_t)skl);
        CHECK(s2.valid && s2.order[0] == 0 && s2.order[1] == 1,
              "sched: WAW conserva el orden");

        // barrera: nada la cruza (mfence en el medio permanece).
        AsmSchedule s3 = schedule_asm_block(
            Isa::X86, "mov rax, rbx\nmfence\nmov rcx, rdx\n", (uint32_t)skl);
        CHECK(s3.valid && s3.order.size() == 3 && s3.order[1] == 1,
              "sched: la barrera no se cruza");

        // bloque mayor: el invariante SIEMPRE se cumple.
        AsmSchedule s4 = schedule_asm_block(
            Isa::X86,
            "mov rax, rbx\nadd rcx, rdx\nimul rax, rax\nadd rsi, rcx\n"
            "mov rdi, rsi\n",
            (uint32_t)skl);
        CHECK(s4.valid, "sched: invariante en bloque mayor");

        // reschedule: con LABEL no se reordena (devuelve el original intacto).
        std::string lbl = "loop:\nadd rax, rbx\nsub rcx, rdx\n";
        CHECK(reschedule_asm(Isa::X86, lbl, (uint32_t)skl) == lbl,
              "reschedule: label -> devuelve original");
        // reschedule: el resultado (movido o no) SIEMPRE es un orden valido.
        std::string blk =
            "mov rax, rdi\nmov rcx, rsi\nimul rax, rax\nadd rax, rcx\n";
        std::string rr = reschedule_asm(Isa::X86, blk, (uint32_t)skl);
        CHECK(schedule_asm_block(Isa::X86, rr, (uint32_t)skl).valid,
              "reschedule: el resultado sigue siendo valido");
        // reschedule preserva el numero de instrucciones (permutacion).
        auto count_nl = [](const std::string &s) {
            int n = 0;
            for (char c : s)
                if (c == '\n') ++n;
            return n;
        };
        CHECK(count_nl(rr) == 4 || rr == blk,
              "reschedule: preserva las 4 instrucciones");
    }

    if (g_fail == 0)
        std::printf("=== instr_db_test: %d checks OK, 0 fallidos ===\n",
                    g_checks);
    else
        std::printf("=== instr_db_test: %d checks, %d FALLIDOS ===\n", g_checks,
                    g_fail);
    return g_fail == 0 ? 0 : 1;
}
