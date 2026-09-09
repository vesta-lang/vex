/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/*
 * tests/analysis/test_analysis_store.cpp
 *
 * That keeping the REASONING between compilations (a) preserves what it said
 * and (b) is ALWAYS cheaper than redoing it.
 *
 * Both halves are needed.  A store that returns something other than what it
 * was given serves facts about another program; one that returns the right
 * thing but slower than recomputing is a cache that SLOWS THINGS DOWN, which is
 * the only way this mechanism can do harm.
 *
 * Why it is MEASURED instead of guarded by a threshold: "only store it if it
 * took more than a millisecond" was considered and rejected -- that hides the
 * bad case behind a heuristic instead of fixing it.  Loading must win ALWAYS;
 * the day it does not, that is a defect in the store or in one analysis's
 * format, and this benchmark is what says so.
 *
 * How it is measured: interleaved and in BOTH orders, which is the project
 * rule -- two consecutive runs cannot tell a change from noise.  And with the
 * work repeated many times, because a single pass over one function is lost in
 * the clock's resolution.
 *
 * This file is written entirely in English, on purpose.  The compiler may speak
 * Spanish because its text comes from the multi-language catalog; a test has no
 * catalog, so writing it in Spanish would pin it to one language forever.
 */

#include "analysis/facts/ir_facts.h"
#include "analysis/manager/analysis_store.h"
#include "ir/ssa_ir.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace analysis;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg);        \
        }                                                                      \
    } while (0)

/*
 * A function with a real body: `n_instr` chained operations.
 *
 * A toy function is not enough: what is measured is walking it versus reading
 * it, and with three instructions both are zero.  Chained -- each one uses the
 * previous result -- so the def-use table has something to resolve instead of
 * coming out empty.
 */
static ir::IrFunction make_function(const char *name, uint32_t n_instr) {
    ir::IrFunction fn;
    fn.name = name;
    fn.ret_type = ir::IrType::I32;
    fn.values.resize(n_instr + 2);
    for (size_t i = 0; i < fn.values.size(); ++i)
        fn.values[i].type = ir::IrType::I32;

    ir::IrBlock block;
    ir::IrInstr constant;
    constant.op = ir::IrOp::CONST;
    constant.type = ir::IrType::I32;
    constant.dst = 0;
    constant.imm = 1;
    block.instrs.push_back(constant);

    for (uint32_t i = 1; i <= n_instr; ++i) {
        ir::IrInstr add;
        add.op = ir::IrOp::ADD;
        add.type = ir::IrType::I32;
        add.dst = i;
        add.operands.push_back(i - 1);
        add.operands.push_back(0);
        add.source_line = 10 + i;
        block.instrs.push_back(add);
    }

    ir::IrInstr ret;
    ret.op = ir::IrOp::RET;
    ret.type = ir::IrType::I32;
    ret.dst = ir::IR_NO_VALUE;
    ret.operands.push_back(n_instr);
    block.instrs.push_back(ret);

    fn.blocks.push_back(std::move(block));
    return fn;
}

/// Microseconds off a monotonic clock.
static long long now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

/// Keeps the optimizer from deleting work whose result nobody looks at: without
/// this the benchmark would compare an empty loop against a real read.
static void keep(const IrFacts &f) {
    if (f.block_count == 0xFFFFFFFFu) std::printf(" ");
}

// ---------------------------------------------------------------------------
// 1) What comes out is what went in.  Before measuring anything: a fast cache
//    that returns something else is not a cache, it is a harder bug to find.
// ---------------------------------------------------------------------------
static void test_round_trip() {
    const ir::IrFunction fn = make_function("f", 64);
    const IrFacts original = build_ir_facts(fn);

    const std::vector<uint8_t> bytes = serialize_ir_facts(original);
    CHECK(!bytes.empty(), "something was written");

    IrFacts back;
    CHECK(deserialize_ir_facts(bytes.data(), bytes.size(), fn, back),
          "and it could be read again");

    CHECK(back.def_idx == original.def_idx, "definitions match");
    CHECK(back.def_block == original.def_block, "and their blocks match");
    CHECK(back.param_of == original.param_of, "parameters match");
    CHECK(back.used == original.used, "who reads each value matches");
    CHECK(back.static_callees == original.static_callees, "callees match");
    CHECK(back.block_count == original.block_count, "block count matches");
    CHECK(back.loop_count == original.loop_count, "loop count matches");
    CHECK(back.recursive == original.recursive, "recursion matches");
    CHECK(back.has_dynamic_call == original.has_dynamic_call,
          "dynamic calls match");

    /* And what must be REHYDRATED: without the owner, `def` answers nullptr to
     * everything -- which reads as "this function defines nothing", right in
     * type and wrong in content.  That is why the owner is a required argument
     * of the deserializer and not something set afterwards. */
    CHECK(back.owner == &fn, "the owner is set");
    bool defs_ok = true;
    for (ir::IrValueId v = 0; v < fn.values.size(); ++v)
        if (back.def(v) != original.def(v)) defs_ok = false;
    CHECK(defs_ok, "and `def` resolves to the SAME instruction as before");
}

// ---------------------------------------------------------------------------
// 2) Broken bytes are NOT accepted.  A format that believes anything turns a
//    damaged file into invented facts.
// ---------------------------------------------------------------------------
static void test_rejects_garbage() {
    const ir::IrFunction fn = make_function("f", 8);
    IrFacts out;

    CHECK(!deserialize_ir_facts(nullptr, 0, fn, out), "nothing is not analysis");

    const uint8_t garbage[] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(!deserialize_ir_facts(garbage, sizeof garbage, fn, out),
          "nor is garbage: the format marker does not match");

    /* Cut in half: the marker DOES match, so this covers what the marker
     * cannot -- that an incomplete structure is not accepted. */
    std::vector<uint8_t> truncated = serialize_ir_facts(build_ir_facts(fn));
    truncated.resize(truncated.size() / 2);
    CHECK(!deserialize_ir_facts(truncated.data(), truncated.size(), fn, out),
          "nor an analysis cut in half");

    /* And facts about ANOTHER function: the coherence check is what stops us
     * answering about values that do not exist if two keys ever collided. */
    const ir::IrFunction other = make_function("g", 40);
    const std::vector<uint8_t> from_other =
        serialize_ir_facts(build_ir_facts(other));
    CHECK(!deserialize_ir_facts(from_other.data(), from_other.size(), fn, out),
          "nor facts belonging to a different function");
}

// ---------------------------------------------------------------------------
// 3) The KEY separates what it must.  If two different things shared a key,
//    one's bytes would be read as the other's -- which is not an error, it is
//    an invented result.
// ---------------------------------------------------------------------------
static void test_key_separates() {
    const AnalysisStore store(/*compiler*/ 7, /*config*/ 11);
    const uint64_t base = store.key_of("an.analysis", 1, 0xABCD, "pre-opt");

    CHECK(base == store.key_of("an.analysis", 1, 0xABCD, "pre-opt"),
          "the same question gives the same key");
    CHECK(base != store.key_of("other.analysis", 1, 0xABCD, "pre-opt"),
          "another ANALYSIS, another key");
    CHECK(base != store.key_of("an.analysis", 2, 0xABCD, "pre-opt"),
          "another FORMAT version, another key");
    CHECK(base != store.key_of("an.analysis", 1, 0x1234, "pre-opt"),
          "another FUNCTION, another key");
    CHECK(base != store.key_of("an.analysis", 1, 0xABCD, "post-opt"),
          "another STAGE, another key");

    const AnalysisStore other_compiler(/*compiler*/ 8, /*config*/ 11);
    CHECK(base != other_compiler.key_of("an.analysis", 1, 0xABCD, "pre-opt"),
          "another COMPILER, another key: it may conclude something else");
    const AnalysisStore other_config(/*compiler*/ 7, /*config*/ 12);
    CHECK(base != other_config.key_of("an.analysis", 1, 0xABCD, "pre-opt"),
          "another CONFIGURATION, another key");

    /* The separator between texts: without it ("ab","c") and ("a","bc") would
     * mix the same sequence and two different analyses would share a key. */
    CHECK(store.key_of("ab", 1, 1, "c") != store.key_of("a", 1, 1, "bc"),
          "and the texts cannot be confused with each other");
}

// ---------------------------------------------------------------------------
// 4) THE BENCHMARK: loading must be cheaper than computing.  Always.
// ---------------------------------------------------------------------------

/// How many times each side of the benchmark repeats its work.
static const int kRounds = 200;

/// Recomputing the analysis from scratch, `kRounds` times.
static long long time_compute(const ir::IrFunction &fn) {
    const long long t0 = now_us();
    for (int i = 0; i < kRounds; ++i)
        keep(build_ir_facts(fn));
    return now_us() - t0;
}

/// Getting it back out of the store, `kRounds` times.
static long long time_load(AnalysisStore &store, uint64_t key,
                           const ir::IrFunction &fn) {
    const long long t0 = now_us();
    for (int i = 0; i < kRounds; ++i) {
        std::vector<uint8_t> bytes;
        IrFacts f;
        if (store.load(key, bytes))
            deserialize_ir_facts(bytes.data(), bytes.size(), fn, f);
        keep(f);
    }
    return now_us() - t0;
}

/*
 * Looking the entry up and copying its bytes -- WITHOUT touching the disk.
 *
 * Mind what this measures.  `load` does no I/O: the bundle is read whole in
 * `open` and served from memory afterwards.  Calling this "reading" would be a
 * tool that lies, which has already happened in this project.  The disk cost is
 * measured separately, by opening.
 */
static long long time_lookup_and_copy(AnalysisStore &store, uint64_t key) {
    const long long t0 = now_us();
    for (int i = 0; i < kRounds; ++i) {
        std::vector<uint8_t> bytes;
        if (store.load(key, bytes) && bytes.empty()) std::printf(" ");
    }
    return now_us() - t0;
}

/// Decoding bytes already in memory, `kRounds` times.
static long long time_decode(const std::vector<uint8_t> &bytes,
                             const ir::IrFunction &fn) {
    const long long t0 = now_us();
    for (int i = 0; i < kRounds; ++i) {
        IrFacts f;
        deserialize_ir_facts(bytes.data(), bytes.size(), fn, f);
        keep(f);
    }
    return now_us() - t0;
}

/*
 * The only part that touches the disk, and it happens ONCE per module.
 *
 * Measured on its own so the decision to keep one file per MODULE -- instead of
 * one per analysis, which is what this benchmark knocked down -- is backed by a
 * number and not by a memory.
 */
static long long time_open(const std::string &path) {
    const long long t0 = now_us();
    for (int i = 0; i < kRounds; ++i) {
        AnalysisStore store(1, 1);
        store.open(path);
    }
    return now_us() - t0;
}

static void test_load_beats_compute() {
    /* A genuinely large function: what is compared is walking it against
     * reading it, and with a toy body both are zero. */
    const ir::IrFunction fn = make_function("large", 4000);

    const char *tmp = std::getenv("TEMP");
    const std::string path =
        std::string(tmp != nullptr ? tmp : ".") + "/vesta_analysis_store.bin";
    AnalysisStore store(/*compiler*/ 1, /*config*/ 1);
    store.open(path);

    const uint64_t key =
        store.key_of(kIrFactsAnalysisName, kIrFactsFormat, 0xF00D, "pre-opt");
    store.store(key, serialize_ir_facts(build_ir_facts(fn)));

    // One warm-up round each, so the system cache favours neither side.
    time_compute(fn);
    time_load(store, key, fn);

    /* INTERLEAVED AND IN BOTH ORDERS.  Two consecutive runs cannot tell the
     * change from noise: whatever the first one gains can be the machine
     * warming up, and in the other order it comes out the other way. */
    const long long compute_a = time_compute(fn);
    const long long load_a = time_load(store, key, fn);
    const long long load_b = time_load(store, key, fn);
    const long long compute_b = time_compute(fn);

    const long long compute_us = compute_a + compute_b;
    const long long load_us = load_a + load_b;
    std::printf("  [bench] %d rounds x2: compute=%lld us, load=%lld us (%.2fx)\n",
                kRounds, compute_us, load_us,
                load_us > 0 ? (double)compute_us / (double)load_us : 0.0);

    std::vector<uint8_t> stored_bytes;
    store.load(key, stored_bytes);
    std::printf("  [bench] inside load: lookup+copy=%lld us, decode=%lld us"
                " (%d rounds, no disk)\n",
                time_lookup_and_copy(store, key),
                time_decode(stored_bytes, fn), kRounds);
    std::printf("  [bench] opening the bundle (ONCE per module): %.1f us\n",
                (double)time_open(path) / (double)kRounds);

    CHECK(load_us < compute_us,
          "loading from the store must be CHEAPER than computing; if it is "
          "not, the cache slows things down and the store or the format needs "
          "fixing");
}

int main() {
    test_round_trip();
    test_rejects_garbage();
    test_key_separates();
    test_load_beats_compute();
    std::printf("=== analysis store: %d checks, %d failures ===\n", g_checks,
                g_fail);
    return g_fail == 0 ? 0 : 1;
}
