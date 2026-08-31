/**
 * @file test_fingerprint.cpp
 * @brief Tests de la huella computacional por-funcion (recursos + efectos +
 *        composicion interprocedural).  Ver analyze/fingerprint.h.
 */
#include "analyze/fingerprint.h"
#include "ir/ssa_ir.h"

#include <cstdio>
#include <string>

using namespace analyze;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  FAIL: %s (linea %d)\n", (msg), __LINE__);           \
        }                                                                      \
    } while (0)

// Construye una funcion con un unico bloque conteniendo las instrucciones
// dadas.
static ir::IrFunction fn_with(const std::string &name,
                              std::vector<ir::IrInstr> instrs) {
    ir::IrFunction f;
    f.name = name;
    f.ret_type = ir::IrType::I64;
    ir::IrBlock bb;
    bb.name = "entry";
    bb.instrs = std::move(instrs);
    f.blocks.push_back(std::move(bb));
    return f;
}

static ir::IrInstr op(ir::IrOp o) {
    ir::IrInstr i{};
    i.op = o;
    return i;
}
static ir::IrInstr call(const std::string &name) {
    ir::IrInstr i{};
    i.op = ir::IrOp::CALL;
    i.func_name = name;
    return i;
}
static ir::IrInstr alloca_of(ir::IrType t, uint64_t count) {
    ir::IrInstr i{};
    i.op = ir::IrOp::ALLOCA;
    i.type = t;
    i.imm = count;
    return i;
}
static ir::IrInstr binop(ir::IrOp o) {
    ir::IrInstr i{};
    i.op = o;
    return i;
}

// Bloque de inline asm: el cuerpo NASM viaja en func_name ( AS).
static ir::IrInstr asm_block(const std::string &body) {
    ir::IrInstr i{};
    i.op = ir::IrOp::INLINE_ASM;
    i.func_name = body;
    return i;
}

static const FunctionFingerprint *
find(const std::vector<FunctionFingerprint> &v, const std::string &n) {
    for (const auto &f : v)
        if (f.function == n) return &f;
    return nullptr;
}

int main() {
    std::printf("=== test_fingerprint ===\n");

    ir::IrModule mod;
    mod.functions.push_back(fn_with("leaf", {op(ir::IrOp::RET)}));
    mod.functions.push_back(
        fn_with("allocs", {op(ir::IrOp::GC_ALLOC), op(ir::IrOp::RET)}));
    mod.functions.push_back(
        fn_with("thrower", {op(ir::IrOp::THROW), op(ir::IrOp::RET)}));
    mod.functions.push_back(fn_with(
        "caller", {call("allocs"), call("thrower"), op(ir::IrOp::RET)}));
    mod.functions.push_back(fn_with("rec", {call("rec"), op(ir::IrOp::RET)}));
    mod.functions.push_back(
        fn_with("dynamic", {op(ir::IrOp::CALLVIRT), op(ir::IrOp::RET)}));
    mod.functions.push_back(fn_with(
        "stackuser", {alloca_of(ir::IrType::I64, 3), op(ir::IrOp::RET)}));
    // pure_math: solo aritmetica -> pura.
    mod.functions.push_back(
        fn_with("pure_math", {binop(ir::IrOp::ADD), binop(ir::IrOp::MUL),
                              op(ir::IrOp::RET)}));
    // writer: tiene STORE -> impura local.
    mod.functions.push_back(
        fn_with("writer", {op(ir::IrOp::STORE), op(ir::IrOp::RET)}));
    // pure_caller: llama a pure_math -> pura por composicion.
    mod.functions.push_back(
        fn_with("pure_caller", {call("pure_math"), op(ir::IrOp::RET)}));
    // impure_caller: llama a writer -> impura por composicion.
    mod.functions.push_back(
        fn_with("impure_caller", {call("writer"), op(ir::IrOp::RET)}));
    // asm_pure: asm sin memoria/call/atomica -> conserva la pureza local
    // (antes CUALQUIER asm rompia la pureza; ahora se analiza el cuerpo).
    mod.functions.push_back(
        fn_with("asm_pure", {asm_block("popcnt rax, rdi"), op(ir::IrOp::RET)}));
    // asm_mem: asm que toca memoria -> impuro.
    mod.functions.push_back(
        fn_with("asm_mem", {asm_block("mov [rax], rbx"), op(ir::IrOp::RET)}));
    // asm_stack: marco EXPLICITO (sub rsp, 32) -> se cuenta en el parcial.
    mod.functions.push_back(
        fn_with("asm_stack", {asm_block("sub rsp, 32"), op(ir::IrOp::RET)}));

    auto fps = compute_module_fingerprints(mod);
    CHECK(fps.size() == 14, "14 huellas");

    // -- Locales -------------------------------------------------------------
    const auto *leaf = find(fps, "leaf");
    CHECK(leaf && leaf->alloc_sites == 0 && !leaf->throws && !leaf->panics,
          "leaf: sin alloc/throw/panic");
    const auto *allocs = find(fps, "allocs");
    CHECK(allocs && allocs->alloc_sites == 1, "allocs: 1 sitio de alloc");
    const auto *thrower = find(fps, "thrower");
    CHECK(thrower && thrower->throws, "thrower: throws local");
    const auto *stackuser = find(fps, "stackuser");
    CHECK(stackuser && stackuser->stack_bytes == 24,
          "stackuser: 3*i64 = 24 bytes de stack");
    const auto *rec0 = find(fps, "rec");
    CHECK(rec0 && rec0->self_recursive, "rec: self_recursive local");
    const auto *dyn0 = find(fps, "dynamic");
    CHECK(dyn0 && dyn0->has_dynamic_call, "dynamic: llamada dinamica");

    // -- Composicion interprocedural -----------------------------------------
    compose_fingerprints(fps);

    const auto *caller = find(fps, "caller");
    CHECK(caller && caller->alloc_sites_total == 1,
          "caller: alloc_sites_total=1 (via allocs)");
    CHECK(caller && caller->throws_total,
          "caller: throws_total=true (via thrower)");
    CHECK(caller && !caller->panics_total, "caller: panics_total=false");
    CHECK(caller && caller->effects_known,
          "caller: efectos conocidos (callees estaticos)");
    CHECK(caller && !caller->recursive, "caller: no recursivo");

    const auto *rec = find(fps, "rec");
    CHECK(rec && rec->recursive, "rec: recursive tras compose");

    const auto *dyn = find(fps, "dynamic");
    CHECK(dyn && !dyn->effects_known,
          "dynamic: effects_known=false (llamada opaca)");
    CHECK(
        dyn && dyn->throws_total,
        "dynamic: throws_total CONSERVADOR=true (no se puede probar ausencia)");

    const auto *leaf2 = find(fps, "leaf");
    CHECK(leaf2 && leaf2->alloc_sites_total == 0 && !leaf2->throws_total &&
              leaf2->effects_known,
          "leaf: probablemente @alloc(0) @nothrow (sound)");

    // -- Pureza (local + compuesta) ------------------------------------------
    const auto *pm = find(fps, "pure_math");
    CHECK(pm && pm->pure_local && pm->pure, "pure_math: pura");
    const auto *wr = find(fps, "writer");
    CHECK(wr && !wr->pure_local && !wr->pure, "writer: impura (STORE)");
    const auto *pc = find(fps, "pure_caller");
    CHECK(pc && pc->pure, "pure_caller: pura por composicion");
    const auto *ic = find(fps, "impure_caller");
    CHECK(ic && !ic->pure, "impure_caller: impura por composicion");

    /* -- Vectoriales: escribir el vector del llamante NO es puro -------------
     *
     * Estaban todas en la lista de puras bajo el epigrafe "compute + reduccion
     * local", y para las VEC_ACC_* eso es cierto -- su acumulador es un ALLOCA
     * de la propia funcion --, pero VEC_UNOP/BINOP/BINOP_S/FMA escriben a
     * traves de su primer operando, que es el puntero DESTINO del bucle y viene
     * de fuera.  El vocabulario de acceso siempre dijo que escriben; esta lista
     * decia que no, y ganaba esta: una funcion cuyo unico trabajo era rellenar
     * un vector salia pura, y un @pure declarado sobre ella se aprobaba.
     *
     * Es la clase de acceso EN EL IR.  A donde baje cada una -- un MOVUPD en el
     * JIT, un scratch en la pila de la VM en el interprete -- cambia por
     * objetivo y no es lo que @pure promete: la promesa es sobre la memoria del
     * PROGRAMA, no sobre por donde pase el backend para escribirla. */
    for (const auto &c : {std::make_pair("vec_unop", ir::IrOp::VEC_UNOP),
                          std::make_pair("vec_binop", ir::IrOp::VEC_BINOP),
                          std::make_pair("vec_binop_s", ir::IrOp::VEC_BINOP_S),
                          std::make_pair("vec_fma", ir::IrOp::VEC_FMA)}) {
        const auto f = compute_fingerprint(
            fn_with(c.first, {op(c.second), op(ir::IrOp::RET)}), "x86_64");
        CHECK(!f.pure_local && !f.pure,
              "una op vectorial que escribe el destino del llamante no es "
              "pura");
    }
    for (const auto &c :
         {std::make_pair("vec_acc_zero", ir::IrOp::VEC_ACC_ZERO),
          std::make_pair("vec_acc_add", ir::IrOp::VEC_ACC_ADD),
          std::make_pair("vec_acc_store", ir::IrOp::VEC_ACC_STORE),
          std::make_pair("vec_bcast", ir::IrOp::VEC_BCAST)}) {
        const auto f = compute_fingerprint(
            fn_with(c.first, {op(c.second), op(ir::IrOp::RET)}), "x86_64");
        CHECK(f.pure_local && f.pure,
              "el acumulador de una reduccion es local: eso SI sigue siendo "
              "puro");
    }
    const auto *dyn2 = find(fps, "dynamic");
    CHECK(dyn2 && !dyn2->pure, "dynamic: no se puede probar pura");
    const auto *allocs2 = find(fps, "allocs");
    CHECK(allocs2 && allocs2->pure,
          "allocs: allocar es puro (construye su retorno)");

    // --- inline asm: efectos EXACTOS del cuerpo (no caja negra total) --------
    const auto *ap = find(fps, "asm_pure");
    CHECK(ap && ap->pure_local && ap->frame_opaque,
          "asm_pure: pura local (asm sin mem/call) + marco opaco (implicito)");
    const auto *am = find(fps, "asm_mem");
    CHECK(am && !am->pure_local, "asm_mem: impura (el asm toca memoria)");
    const auto *as = find(fps, "asm_stack");
    CHECK(as && as->stack_bytes == 32,
          "asm_stack: marco explicito contado (sub rsp, 32)");

    // --- inline asm ARM64: se analiza con la tabla del arch (no la de x86) ---
    // add x0, x1, x2 (arm64 puro) -> pura local con arch arm64.
    const auto ap64 = compute_fingerprint(
        fn_with("arm_pure", {asm_block("add x0, x1, x2"), op(ir::IrOp::RET)}),
        "arm64");
    CHECK(ap64.pure_local, "arm64: add x0,x1,x2 puro (tabla arm64)");
    // ldr x0, [x1] (carga arm64) -> toca memoria -> impura.
    const auto am64 = compute_fingerprint(
        fn_with("arm_mem", {asm_block("ldr x0, [x1]"), op(ir::IrOp::RET)}),
        "arm64");
    CHECK(!am64.pure_local, "arm64: ldr [x1] impura (toca memoria)");
    // el arch IMPORTA: ldaxr (LL/SC arm64) analizado como x86_64 no se reconoce
    // -> conservador (impuro), no un falso puro.
    const auto llsc_x86 = compute_fingerprint(
        fn_with("llsc", {asm_block("ldaxr x0, [x1]"), op(ir::IrOp::RET)}),
        "x86_64");
    CHECK(!llsc_x86.pure_local,
          "ldaxr con arch x86_64: mnemonico desconocido -> conservador");

    if (g_fail == 0)
        std::printf("=== test_fingerprint: %d checks OK, 0 fallidos ===\n",
                    g_checks);
    else
        std::printf("=== test_fingerprint: %d checks, %d FALLIDOS ===\n",
                    g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
