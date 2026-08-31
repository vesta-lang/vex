/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/vreg_pipeline.cpp
 * @brief Implementacion del orquestador vreg ( D.7, commit 5c).
 *        Ver vreg_pipeline.h y doc/REGALLOC.md.
 */

#include "util/env_flags.h"
#include <thread>
#include <functional>
#include "jit/vreg_pipeline.h"

#include "ir/ir_vec_ops.h" // cuales son las operaciones vectoriales
#include "ir/ssa_ir.h"
#include "jit/auto_jit.h"
#include "jit/code_cache.h"
#include "jit/win_unwind.h" // describirle el marco al sistema
#include "jit/codegen_target.h"
#include "jit/interval.h"
#include "jit/jit_registry.h"
#include "codegen/regalloc.h"
#include "jit/machine_ir.h"
#include "jit/peephole.h"
#include "vx/asm/asm_effects.h" // isa_host: para quien se genera este codigo
#include "jit/regalloc_rewrite.h"
#include "jit/sched/machine_sched.h"
#include "jit/shape_constraints.h"
#include "jit/ssa_coalesce.h"
#include "jit/target_reginfo.h"
#include "jit/jit_timing.h" // telemetria de tiempo de compilacion
#include "jit/vreg_select.h"
#include "jit/x86_64/x86_target.h"
#include "jit/x86_encoder.h"

#include "codegen/timeline_builder.h" // build_allocation_result (RegAlloc->timeline)
#include "codegen/rbank/allocate.h" // rbank_allocate (allocator UNICO)
#include "codegen/rbank/allocator_diagnostics.h" // AllocatorDiagnostics (3er nivel)
#include "codegen/rbank/function_snapshot.h" // query<RematFacts> (instrumento)
#include "codegen/rbank/measure.h" // instrumento de medicion (diagnostico)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

namespace jit {

namespace {
/**
 * @brief Reserva VEC_ACC DEMAND-DRIVEN (Fase 2): ¿la funcion @p fn necesita
 *        reservar XMM10-13?  True si usa CUALQUIER op vectorial (VEC_*): esas
 *        pueden ocupar XMM10-13 (los 4 acumuladores de reduccion + el broadcast
 *        en XMM13).  Las funciones PURAMENTE ESCALARES FP no tocan esos
 * registros
 *        -> el allocator puede asignarselos (14 lanes FP en vez de 10).  La
 * MISMA condicion decide la reserva Y el uso (el selector solo fija XMM13-idx
 * si hay ops VEC_*), asi que nadie pisa un acumulador vivo. Gate
 * VESTA_NO_WIDE_HOME=1 fuerza la reserva SIEMPRE (A/B = comportamiento
 *        anterior: 10 lanes para toda funcion).
 */
/**
 * @brief ¿Necesita @p fn el scratch del banco ancho (XMM14/15)?
 *
 * El reescritor los usa para traer un valor derramado, para legalizar las
 * operaciones de dos operandos y para romper ciclos al permutar registros --
 * todo eso solo aparece si la funcion opera con FLOTANTES.  Una funcion cuyo
 * unico uso del banco ancho son los operandos de un bloque asm no hace nada de
 * eso, asi que reservarlos le quita dos ranuras de las dieciseis sin motivo.
 *
 * Se responde por el TIPO de los valores, que es lo que decide si el reescritor
 * llegara a emitir movimientos de coma flotante.  Ante la duda, reservar.
 *
 * @param fn Funcion IR.
 * @return true si hay que reservarlos.
 */
bool fn_needs_fp_scratch(const ir::IrFunction &fn) {
    for (const auto &v : fn.values)
        if (v.type == ir::IrType::F32 || v.type == ir::IrType::F64) return true;
    return false;
}

/**
 * @brief ¿Puede @p fn usar el banco ancho EXTENDIDO de AVX-512 (zmm16..31)?
 *
 * Hacen falta las dos cosas: que el procesador los tenga y que la funcion NO
 * vaya a emitir instrucciones de coma flotante propias.  Lo segundo no es una
 * precaucion sino un limite real -- esos registros solo se codifican con EVEX y
 * el codificador de las instrucciones de coma flotante no sabe emitirlo.  Los
 * operandos de un bloque asm si pueden usarlos: ese texto lo ensambla otro que
 * si sabe.
 *
 * Las capacidades vienen del OBJETIVO, no de esta maquina: el camino nativo
 * genera binarios para otras y no puede preguntarse por la suya.
 *
 * @param fn Funcion IR.
 * @param caps Lo que el OBJETIVO declara saber hacer.
 * @return true si se le pueden ofrecer las 32 ranuras.
 */
bool fn_can_use_wide512(const ir::IrFunction &fn, const BackendCaps &caps) {
    return caps.avx512f && !fn_needs_fp_scratch(fn);
}

bool fn_needs_vec_reserve(const ir::IrFunction &fn) {
    static const bool gate_force = util::flag_on(util::FlagId::NoWideHome);
    if (gate_force) return true;
    // Reservar si la funcion usa el camino vectorial, sea cual sea la
    // operacion: es la MISMA condicion que decide el USO de XMM10-13, y de eso
    // depende que nadie pise un acumulador vivo.  Enumerarlas aqui a mano ya
    // dejo fuera VEC_FMA_S, que fija XMM13-idx igual que sus companeras.
    for (const auto &b : fn.blocks)
        for (const auto &in : b.instrs)
            if (ir::is_vec_op(in.op)) return true;
    return false;
}

// El SHADOW MODE (comparar rbank vs linear_scan en paralelo) fue el andamio que
// valido el switch a rbank; cumplido su proposito, su infraestructura
// (ShadowStats/ ShadowReport/validate_coloring) vive en codegen/rbank/shadow.h
// para los TESTS.  En produccion rbank es el allocator UNICO -- no hay con que
// comparar en el hot path.

// --- INSTRUMENTO DE MEDICION (gated VESTA_REMAT_MEASURE=1; diagnostico, no
// cambia
//     el codigo emitido).  Mide el POTENCIAL de dos mejoras para decidir cual
//     paga primero: (a) spills recomputables (RematFacts) y (b) falsas
//     interferencias del envolvente.  El numero decide el peldano real. ---
codegen::rbank::RematMeasure g_remat_agg;
codegen::rbank::RematDetail g_remat_detail;
codegen::rbank::EnvelopeMeasure g_env_agg;
codegen::rbank::PressureMeasure g_pressure_agg;
codegen::rbank::SpillTrace g_spill_trace_agg;
codegen::rbank::AllocatorDiagnostics g_alloc_diag_agg;
uint32_t g_measure_funcs = 0;
std::mutex g_measure_mtx;

bool measure_enabled() {
    static const bool on = util::flag_on(util::FlagId::RematMeasure);
    return on;
}

// Politica de spill de rbank.  DOS politicas, seleccionables (no escondidas):
//   - Belady (DEFAULT): victima por next-use (MachineNextUseFacts) / coste.
//   - Lifetime (A/B, VESTA_BELADY=0): victima por duracion restante / coste.
// Medido (A/B): en el bench de presion SIMETRICO (16 acumuladores loop-carried)
// Belady no baja spills porque todos los valores tienen next-use casi igual
// (poca info temporal).  El cuello REAL es el GREEDY: derrama ~14 cuando el
// minimo teorico (overflow_exact) es 6.  Belady queda DEFAULT (correcto por
// diff_harness; es la eleccion de victima informada por el conocimiento), y la
// palanca pendiente para que el allocator sea rentable es CERRAR ESE GAP del
// greedy (instrumentar con la maquinaria de Facts por que derrama de mas, luego
// reconsiderar la politica).
bool belady_enabled() {
    static const bool on = util::flag_on(util::FlagId::Belady);
    return on;
}

// Recovery Pass (2a pasada) on/off para A/B.  Default ON; VESTA_RECOVERY=0 ->
// greedy sin recuperacion (baseline con la asignacion incompleta).  Permite
// medir el diagnostico (spills / candidate / wasted_area) con y sin la pasada,
// mismo binario.
bool recovery_enabled() {
    static const bool on = util::flag_on(util::FlagId::Recovery);
    return on;
}

// Fragmentation Recovery (splitting, 3a pasada) on/off para A/B.  Devuelve a
// REGISTRO POR TRAMOS los spills que no caben enteros en ninguna lane -- la
// clase `partially` de la taxonomia (62,5% de los spills del corpus).  Cuando
// esta OFF el plan ni se calcula y el codigo emitido es identico al de antes
// (coste cero).
bool splitting_enabled() {
    static const bool on = util::flag_on(util::FlagId::Splitting);
    return on;
}

void print_measure_summary() {
    std::lock_guard<std::mutex> lk(g_measure_mtx);
    if (g_measure_funcs == 0) return;
    const codegen::rbank::RematMeasure &r = g_remat_agg;
    const codegen::rbank::EnvelopeMeasure &e = g_env_agg;
    const uint32_t kGpLanes =
        14; // GP allocatable x86-64 (r0..r15 menos rsp/rbp).
    const double pct_remat =
        r.spills_total ? 100.0 * r.spills_rematerializable / r.spills_total
                       : 0.0;
    const double pct_false =
        e.pairs_envelope ? 100.0 * e.false_interfere / e.pairs_envelope : 0.0;
    std::fprintf(
        stderr,
        "\n=== [measure] potencial de mejoras del asignador (%u funciones) "
        "===\n"
        "  (a) REMAT:     spills=%u  recomputables=%u (%.1f%%)  de los cuales "
        "HOJA"
        " (CONST/dir, remat casi garantizado)=%u (%.1f%%)\n"
        "      META spills: en_loop(HOT)=%u  frios=%u   |   recomputables "
        "en_loop=%u"
        " frios=%u   |   CONST imm32(fusionable ARRIBA)=%u imm64=%u\n"
        "  (b) ENVOLVENTE: interferencias env=%llu exactas=%llu falsas=%llu"
        " (%.1f%% inventadas por el envolvente)\n"
        "  (c) PRESION GP: pico env=%u exact=%u | overflow(%u lanes) env=%u"
        " exact=%u | avoidable(envolvente)=%u  [exact = minimo teorico de "
        "spills]\n"
        "  (d) VICTIMA (Belady): muerta(sin next-use)=%.1f%%  uso-lejano=%.1f%%"
        "  de %llu spills  [si casi todo es muerta, Belady ~= duracion]\n"
        "  (e) GREEDY: spills=%u vs minimo(overflow_exact)=%u | pico@%u "
        "vivos=%u"
        " ocupadas=%u LIBRES=%u en-spill=%u -> idle_cap=%u | "
        "max_lanes_ociosas=%u"
        " en %llu puntos | AREA_ociosa=%llu lane-pos  [idle_cap = cap. ociosa "
        "del pico]\n"
        "  (f) TAXONOMIA spills: structural(inevitable)=%llu  fully(grafo)=%llu"
        "  partially(Splitting)=%llu | RECUPERACION fully: Fully=%llu "
        "Recovered=%llu"
        " Potential=%llu\n"
        "  (g) SPLITTING techo: splitting_potential=%llu de "
        "wasted_lane_area=%llu"
        " (%.1f%% del area recuperable por una Fragmentation Recovery ideal)\n"
        "  (h) SPLITTING real: valores=%llu tramos=%llu usos=%llu | AREA "
        "Potential=%llu"
        " Recovered=%llu (%.1f%%) Remaining=%llu | descartados forma=%llu "
        "coste=%llu\n"
        "  (i) SPLITTING perfil: ACEPTADO len=%.1f usos=%.1f ganancia=%.1f | "
        "RECHAZADO"
        " len=%.1f usos=%.1f ganancia=%.1f  [medias por tramo; guia el tuning "
        "del modelo]\n",
        g_measure_funcs, r.spills_total, r.spills_rematerializable, pct_remat,
        r.spills_remat_leaf,
        r.spills_total ? 100.0 * r.spills_remat_leaf / r.spills_total : 0.0,
        g_remat_detail.spills_in_loop, g_remat_detail.spills_cold,
        g_remat_detail.remat_in_loop, g_remat_detail.remat_cold,
        g_remat_detail.const_imm32, g_remat_detail.const_imm64,
        (unsigned long long)e.pairs_envelope, (unsigned long long)e.pairs_exact,
        (unsigned long long)e.false_interfere, pct_false,
        g_pressure_agg.peak_env_gp, g_pressure_agg.peak_exact_gp, kGpLanes,
        codegen::rbank::PressureMeasure::overflow(g_pressure_agg.peak_env_gp,
                                                  kGpLanes),
        codegen::rbank::PressureMeasure::overflow(g_pressure_agg.peak_exact_gp,
                                                  kGpLanes),
        g_pressure_agg.avoidable_gp(kGpLanes),
        g_spill_trace_agg.spills_total
            ? 100.0 * g_spill_trace_agg.victims_dead /
                  g_spill_trace_agg.spills_total
            : 0.0,
        g_spill_trace_agg.spills_total
            ? 100.0 * g_spill_trace_agg.victims_alive /
                  g_spill_trace_agg.spills_total
            : 0.0,
        (unsigned long long)g_spill_trace_agg.spills_total,
        g_alloc_diag_agg.spilled_total,
        codegen::rbank::PressureMeasure::overflow(g_pressure_agg.peak_exact_gp,
                                                  kGpLanes),
        g_alloc_diag_agg.peak_position, g_alloc_diag_agg.live_values,
        g_alloc_diag_agg.occupied_lanes, g_alloc_diag_agg.free_lanes,
        g_alloc_diag_agg.spilled_in_peak, g_alloc_diag_agg.peak_idle_capacity,
        g_alloc_diag_agg.max_wasted_lanes,
        (unsigned long long)g_alloc_diag_agg.points_wasting,
        (unsigned long long)g_alloc_diag_agg.wasted_lane_area,
        (unsigned long long)g_spill_trace_agg.tax_structural,
        (unsigned long long)g_spill_trace_agg.tax_fully,
        (unsigned long long)g_spill_trace_agg.tax_partially,
        (unsigned long long)g_spill_trace_agg.tax_fully,
        (unsigned long long)g_spill_trace_agg.rec_greedy,
        (unsigned long long)(g_spill_trace_agg.tax_fully >=
                                     g_spill_trace_agg.rec_greedy
                                 ? g_spill_trace_agg.tax_fully -
                                       g_spill_trace_agg.rec_greedy
                                 : 0),
        (unsigned long long)g_spill_trace_agg.tax_splitting_potential,
        (unsigned long long)g_alloc_diag_agg.wasted_lane_area,
        g_alloc_diag_agg.wasted_lane_area
            ? 100.0 * g_spill_trace_agg.tax_splitting_potential /
                  g_alloc_diag_agg.wasted_lane_area
            : 0.0,
        // (h) Potential -> Recovered -> Remaining: la metodologia aplicada al
        // splitting. Potential = techo medido ANTES (area libre de los
        // partially); Recovered = lo que la transformacion consigue de verdad;
        // Remaining = margen para el siguiente sprint (edge splitting, rangos
        // exactos, pesos de frecuencia...).
        (unsigned long long)g_spill_trace_agg.split_values,
        (unsigned long long)g_spill_trace_agg.split_intervals,
        (unsigned long long)g_spill_trace_agg.split_uses,
        (unsigned long long)g_spill_trace_agg.tax_splitting_potential,
        (unsigned long long)g_spill_trace_agg.split_area,
        g_spill_trace_agg.tax_splitting_potential
            ? 100.0 * g_spill_trace_agg.split_area /
                  g_spill_trace_agg.tax_splitting_potential
            : 0.0,
        (unsigned long long)(g_spill_trace_agg.tax_splitting_potential >=
                                     g_spill_trace_agg.split_area
                                 ? g_spill_trace_agg.tax_splitting_potential -
                                       g_spill_trace_agg.split_area
                                 : 0),
        (unsigned long long)g_spill_trace_agg.split_rej_shape,
        (unsigned long long)g_spill_trace_agg.split_rej_cost,
        // (i) Medias: sin ellas, tocar los parametros del cost model seria a
        // ciegas -- se sabria que el numero sube, no POR QUE.  Comparar "lo
        // aceptado" con "lo rechazado por poco" es lo que permite afirmar donde
        // esta el umbral.
        g_spill_trace_agg.split_intervals
            ? 1.0 * g_spill_trace_agg.split_area /
                  g_spill_trace_agg.split_intervals
            : 0.0,
        g_spill_trace_agg.split_intervals
            ? 1.0 * g_spill_trace_agg.split_uses /
                  g_spill_trace_agg.split_intervals
            : 0.0,
        g_spill_trace_agg.split_intervals
            ? 1.0 * g_spill_trace_agg.split_acc_gain /
                  g_spill_trace_agg.split_intervals
            : 0.0,
        g_spill_trace_agg.split_rej_cost
            ? 1.0 * g_spill_trace_agg.split_rej_area /
                  g_spill_trace_agg.split_rej_cost
            : 0.0,
        g_spill_trace_agg.split_rej_cost
            ? 1.0 * g_spill_trace_agg.split_rej_uses /
                  g_spill_trace_agg.split_rej_cost
            : 0.0,
        g_spill_trace_agg.split_rej_cost
            ? 1.0 * g_spill_trace_agg.split_rej_gain /
                  g_spill_trace_agg.split_rej_cost
            : 0.0);
}

/** @brief Corre el instrumento (gated) sobre una funcion tras la asignacion. */
void run_measure(const ir::IrFunction &fn, const IntervalResult &ivs,
                 const codegen::RegAlloc &ra) {
    if (!measure_enabled()) return;
    static std::once_flag atexit_once;
    std::call_once(atexit_once, [] { std::atexit(print_measure_summary); });
    codegen::rbank::FunctionSnapshot snap;
    snap.fn = &fn;
    const codegen::rbank::RematMeasure rm =
        codegen::rbank::measure_remat(ra, snap.remat_facts());
    const codegen::rbank::RematDetail rd = codegen::rbank::measure_remat_detail(
        ra, snap.remat_facts(), snap.value_reqs());
    const codegen::rbank::EnvelopeMeasure em =
        codegen::rbank::measure_envelope(ivs);
    const codegen::rbank::PressureMeasure pm =
        codegen::rbank::measure_pressure(ivs);
    const codegen::rbank::AllocatorDiagnostics ad =
        codegen::rbank::compute_allocator_diagnostics(
            ivs, ra, 14u); // 14 = GP allocatable.
    std::lock_guard<std::mutex> lk(g_measure_mtx);
    g_remat_agg.add(rm);
    g_remat_detail.add(rd);
    g_env_agg.add(em);
    g_pressure_agg.add(pm);
    g_alloc_diag_agg.add(ad);
    ++g_measure_funcs;
}

/** @brief Envuelve rbank_allocate con el Fact de next-use (Belady): computa
 *         @c MachineNextUseFacts(mf) y lo cablea al allocator (salvo
 * VESTA_BELADY=0), y le pasa el @c SpillTrace de razon-de-victima solo cuando
 * el instrumento esta activo.  compute_next_use es barato (2 pasadas sobre mf).
 */
codegen::RegAlloc rbank_allocate_belady(const IntervalResult &ivs,
                                        const MFunction &mf,
                                        const TargetRegInfo &tri, bool vec,
                                        codegen::AssignmentPlan *plan_out) {
    /* Restricciones que impone la FORMA de las instrucciones (ver
     * jit/shape_constraints.h): el asignador puede EVITAR el estorbo en vez de
     * que el reescritor lo apane despues. */
    const codegen::rbank::ConstraintSet forma =
        recoger_restricciones_de_forma(mf);
    if (!forma.items.empty() && util::flag_on(util::FlagId::FormaDebug))
        std::fprintf(stderr, "[forma] %s: %zu restricciones\n", mf.name.c_str(),
                     forma.items.size());
    jit::MachineNextUseFacts nu;
    const jit::MachineNextUseFacts *nup = nullptr;
    if (belady_enabled()) {
        nu = jit::compute_next_use(mf);
        nup = &nu;
    }
    codegen::rbank::SpillTrace st;
    codegen::rbank::SpillTrace *stp = measure_enabled() ? &st : nullptr;
    const uint32_t nvregs = mf.vreg_count;
    // El plan solo se calcula si el caller lo consume Y el splitting esta
    // activo.
    codegen::AssignmentPlan *pp = splitting_enabled() ? plan_out : nullptr;
    codegen::RegAlloc ra = codegen::rbank::rbank_allocate(
        ivs, nvregs, tri, vec, nup, stp, recovery_enabled(), pp,
        forma.items.empty() ? nullptr : &forma);
    if (stp) {
        std::lock_guard<std::mutex> lk(g_measure_mtx);
        g_spill_trace_agg.add(st);
    }
    // DEBUG Pilar 2: dump de la asignacion si VESTA_VREG_DUMP es substring del
    // nombre de la funcion.  Muestra vregs totales, spills, y por vreg su Loc.
    {
        const std::string &want = util::flag_text(util::FlagId::VregDump);
        if (!want.empty() && mf.name.find(want) != std::string::npos) {
            uint32_t n_reg = 0, n_spill = 0, n_none = 0;
            for (uint32_t v = 0; v < nvregs && v < ra.assign.size(); ++v) {
                switch (ra.assign[v].loc) {
                case codegen::RegAlloc::Loc::REG: n_reg++; break;
                case codegen::RegAlloc::Loc::SPILL: n_spill++; break;
                default: n_none++; break;
                }
            }
            fprintf(
                stderr,
                "[vreg-dump] %s: vregs=%u reg=%u SPILL=%u none=%u slots=%u\n",
                mf.name.c_str(), nvregs, n_reg, n_spill, n_none,
                ra.num_spill_slots);
            for (uint32_t v = 0; v < nvregs && v < ra.assign.size(); ++v)
                if (ra.assign[v].loc == codegen::RegAlloc::Loc::SPILL)
                    fprintf(stderr, "  [vreg-dump]   v%u -> SPILL slot %u\n", v,
                            ra.assign[v].slot);
            // ADDs con inmediato en el MachineIR PRE-rewrite (mf): localiza el
            // `add d_at, 8` de la copia struct y si el rewrite lo elimina.
            for (size_t b = 0; b < mf.blocks.size(); ++b)
                for (const auto &in : mf.blocks[b].instrs)
                    if (in.op == MOp::ADD &&
                        (in.src2.kind == MOperandKind::IMM32 ||
                         in.src1.kind == MOperandKind::IMM32)) {
                        const MOperand &imm =
                            in.src2.kind == MOperandKind::IMM32 ? in.src2
                                                                : in.src1;
                        fprintf(
                            stderr,
                            "  [vreg-dump]   ADD b%zu dst(k=%d v=%d) += %d\n",
                            b, (int)in.dst.kind, in.dst.value, imm.value);
                    }
        }
    }
    return ra;
}

/**
 * @brief Scheduler machine-level (C2.15) sobre el MFunction fisico, tras el
 *        regalloc y antes de encodear.  Default ON; @c VESTA_SCHED=0 lo
 * desactiva (A/B).  Reordena por camino critico/latencia respetando el DAG
 * completo de dependencias -> oculta latencias y expone ILP al core
 * superescalar.
 */
void maybe_schedule(MFunction &pf, sched::EffIsa isa, sched::SchedMode mode) {
    // Default ON: reordena por camino critico + RECURSOS (latencia + puertos +
    // issue-width + throughput reciproco) del modelo de coste.  VESTA_SCHED=0
    // lo desactiva (A/B).
    static const bool on = util::flag_on(util::FlagId::Sched);
    if (!on) return;
    // Modelo de coste segun el modo: JIT auto-detecta la microarquitectura del
    // host (cpuid/MIDR) y usa los datos EXACTOS de la DB; AOT usa el generico
    // salvo --cpu explicito.  Construir es barato (cpuid una vez); sin estado
    // mutable compartido -> seguro con el compile paralelo (M8).
    const sched::SchedIsa sisa = (isa == sched::EffIsa::ARM64)
                                     ? sched::SchedIsa::ARM64
                                     : sched::SchedIsa::X86_64;
    std::unique_ptr<sched::SchedCostModel> cm =
        sched::make_cost_model(sisa, sched::sched_cpu(), mode);
    const int moved = sched::schedule_function(pf, *cm, isa);
    // Diagnostico opt-in (VESTA_SCHED_EFF=1): volcado del modelo de efectos por
    // instruccion (post-schedule) para cotejar 1:1 con Capstone.
    static const bool dump_eff = util::flag_on(util::FlagId::SchedEff);
    if (dump_eff) {
        auto rk = [](uint32_t k) -> std::string {
            if (k == UINT32_MAX) return "-";
            static const char *gp[16] = {
                "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
            if (k < 16) return gp[k];
            if (k < 32) return "xmm" + std::to_string(k - 16);
            return "k" + std::to_string(k);
        };
        std::fprintf(stderr, "[eff] === %s ===\n", pf.name.c_str());
        for (const MBlock &b : pf.blocks)
            for (const MInstr &mi : b.instrs) {
                sched::MEffects e = sched::machine_effects(pf, mi, isa);
                const char *mn = sched::mop_mnemonic(mi.op, isa);
                std::string s =
                    mn ? mn : ("op#" + std::to_string(static_cast<int>(mi.op)));
                s += " R[";
                for (uint32_t r : e.reads)
                    s += rk(r) + " ";
                s += "] W[";
                for (uint32_t r : e.writes)
                    s += rk(r) + " ";
                s += "]";
                if (e.reads_flags) s += " rF";
                if (e.writes_flags) s += " wF";
                if (e.reads_mem) s += " rMem";
                if (e.writes_mem) s += " wMem";
                if (e.is_barrier) s += " BARRIER";
                std::fprintf(stderr, "[eff] %s\n", s.c_str());
            }
    }
    // Diagnostico opt-in (VESTA_SCHED_STATS=1): cuanto reordena de verdad.
    static const bool stats = util::flag_on(util::FlagId::SchedStats);
    if (stats) {
        long instrs = 0;
        for (const MBlock &b : pf.blocks)
            instrs += (long)b.instrs.size();
        static long tot_moved = 0, tot_instr = 0, funcs = 0, touched = 0;
        tot_moved += moved;
        tot_instr += instrs;
        ++funcs;
        if (moved) ++touched;
        std::fprintf(stderr,
                     "[sched-stats] modelo=%s puertos=%d issue=%d | acum: "
                     "funcs=%ld tocadas=%ld moved=%ld instr=%ld (%.1f%% mov)\n",
                     cm->name(), cm->port_count(), cm->issue_width(), funcs,
                     touched, tot_moved, tot_instr,
                     tot_instr ? 100.0 * tot_moved / tot_instr : 0.0);
    }
}

/**
 * @brief Rellena lo que solo se puede rellenar cuando ya se sabe DONDE va el
 *        codigo.
 *
 * Se codifica antes de pedir sitio en la cima, asi que todo lo que dependa de
 * la direccion propia queda en hueco y se completa aqui: entre el memcpy y el
 * commit, que es la unica ventana en la que hay direccion y todavia no se
 * ejecuta nada.
 *
 * Son dos cosas.  Las entradas de una tabla de saltos, que son direcciones
 * absolutas de ocho bytes.  Y los saltos relativos a una direccion conocida --
 * la cola de una llamada a otra funcion --, donde lo que se escribe es la
 * DISTANCIA; si no cabe en los 32 bits del salto no hay vuelta atras, asi que
 * se dice que no y la funcion se ejecuta interpretada.
 *
 * Estaba escrito TRES veces, una por cada camino que compila (normal, sin
 * reparto de registros, y con reentrada a mitad de bucle).  Tres copias de un
 * parcheo es donde una se queda sin lo que se le anade a las otras.
 *
 * @param pf   La funcion, con sus huecos pendientes.
 * @param code Donde quedo, ya copiada.
 * @return @c false si algun salto no alcanza; entonces no se puede usar.
 */
bool patch_after_alloc(const MFunction &pf, uint8_t *code) {
    /* Tabla de saltos densa: la entrada guarda la direccion ABSOLUTA del brazo,
     * que es la base mas el offset de su label. */
    for (const auto &f : pf.addr_table_fixups) {
        if (f.label < pf.label_offsets.size() &&
            pf.label_offsets[f.label] != UINT32_MAX) {
            const uint64_t target =
                reinterpret_cast<uint64_t>(code) + pf.label_offsets[f.label];
            std::memcpy(code + f.patch_at, &target, sizeof(uint64_t));
        }
    }
    /* Saltos relativos a una direccion ya conocida.  Ver
     * @c MFunction::rel_jump_fixups. */
    for (const auto &f : pf.rel_jump_fixups) {
        const int64_t from = static_cast<int64_t>(
            reinterpret_cast<uint64_t>(code) + f.instr_end);
        const int64_t delta = static_cast<int64_t>(f.target) - from;
        if (delta < INT32_MIN || delta > INT32_MAX) return false;
        const int32_t rel = static_cast<int32_t>(delta);
        std::memcpy(code + f.patch_at, &rel, sizeof(int32_t));
    }
    return true;
}
} // namespace

uint8_t *vreg_compile(const ir::IrFunction &fn, CodeCache &cc,
                      const CallResolver &resolve_call, const VregEntries &ent,
                      const CallResolver &resolve_native,
                      const CallResolver &resolve_symbol, size_t *out_code_size,
                      std::vector<LineMapEntry> *out_line_map) {
    /* Watchdog CTPE: propagar el handler de safepoint de la CodeCache al
     * thread_local que lee vreg_select.  Se hace AQUI (mismo hilo que
     * vreg_select) porque el eager-compile de CTPE puede correr en un hilo
     * distinto al que activo el modo; la CodeCache es el objeto compartido.
     * Fuera de CTPE, cc.ctpe_safepoint_handler == 0 -> sin polls. */
    vreg_set_ctpe_safepoint_handler(cc.ctpe_safepoint_handler);
    /* Telemetria de compilacion (RAII: cuenta tambien los abandonos por
     * fallback). El JIT compila DURANTE la ejecucion, asi que el reloj de pared
     * mezcla compilar y ejecutar; separarlos es lo que permite saber si una
     * optimizacion del codigo generado se esta comiendo su propia ganancia en
     * tiempo de compilacion. */
    ScopedJitTimer _jt(fn.name.c_str());
    if (JitTiming::detail_enabled()) { // desglose por funcion: volcado al
                                       // terminar.
        static std::once_flag once;
        std::call_once(once,
                       [] { std::atexit([] { print_jit_timing(true); }); });
    }

    /* 1. Seleccionar MachineIR de vregs (VM_ABI).  Si la funcion usa un
     *    op fuera del subset soportado, abortar -> fallback. */
    MFunction mf;
    /* Se pide la correlacion codigo-nativo <-> linea del fuente solo cuando
     * alguien la va a guardar.  Es lo que permite decir DONDE fallo un
     * programa compilado: ahi el PC de la maquina virtual no se va
     * actualizando -- ese es el punto de compilar --, de modo que sin esta
     * tabla se llega a la funcion pero no a la linea. */
    if (!vreg_select(fn, mf, AbiKind::VM, resolve_call, ent, resolve_native,
                     resolve_symbol, /*pic=*/true,
                     /*target_sysv=*/host_is_sysv(),
                     /*mode32=*/false, FloatIsa::SSE2,
                     /*emit_line_map=*/out_line_map != nullptr))
        return nullptr;

    /* Reserva VEC_ACC demand-driven: XMM10-13 asignables si la funcion NO usa
     * el path vectorial (14 lanes FP escalares en vez de 10). */
    const TargetRegInfo &tri =
        target_x86_64_vm_abi(fn_needs_vec_reserve(fn), fn_needs_fp_scratch(fn),
                             fn_can_use_wide512(fn, backend_caps_host()));

    /* 2. Intervalos + P1 coalescing + 3. asignacion (commit 6: el linear_scan
     *    FUERZA a slot los GC roots vivos a traves de un call).
     *    P1 (register coalescing): une vregs move-related no-interferentes
     *    para eliminar las copias de PHI/2-address.  Si coalesce algo,
     *    reconstruye los intervalos sobre la forma coalescida. */
    IntervalResult ivs = build_intervals(mf, tri);
    if (apply_ssa_coalesce(mf, fn, dst_kind_of_isa(vx::isa_host())))
        ivs = build_intervals(mf, tri);

    /* Allocator UNICO: rbank (linear_scan jubilado).  El verificador
     * adversarial de GC roots de abajo + diff_harness (0 bugs) + e2e (724/0)
     * son su oraculo. */
    codegen::AssignmentPlan
        plan; // Fragmentation Recovery (vacio si el splitting esta OFF).
    codegen::RegAlloc ra =
        rbank_allocate_belady(ivs, mf, tri, fn_needs_vec_reserve(fn), &plan);

    /* Instrumento de medicion (gated VESTA_REMAT_MEASURE; diagnostico, no
     * cambia el codigo): potencial de remat + falsas interferencias del
     * envolvente. */
    run_measure(fn, ivs, ra);

    /* 3b. Verificador adversarial (commit 6): TODO GC root vivo a traves
     *     de un call DEBE estar en un slot, para que su stackmap lo
     *     describa.  Si por algun bug del allocator quedara en un registro,
     *     el GC no lo veria -> corrupcion del heap.  En vez de arriesgarlo,
     *     hacemos FALLBACK seguro al path de slots.  Coste O(NV*calls),
     *     despreciable frente a encode/commit. */
    if (!ivs.call_positions.empty()) {
        for (uint32_t v = 0; v < mf.vreg_count; ++v) {
            const LiveInterval &lv = ivs.intervals[v];
            if (!lv.is_gc()) continue;
            for (uint32_t cp : ivs.call_positions) {
                if (lv.covers(cp) && !ra.spilled(v)) {
#ifndef NDEBUG
                    std::fprintf(
                        stderr,
                        "[vreg] GC root v%u vivo a traves de call no spilled "
                        "en '%s' -> fallback a slots\n",
                        v, fn.name.c_str());
#endif
                    return nullptr;
                }
            }
        }
    }

    /* 4. Rewrite a fisico (VM_ABI) + stackmaps de GC roots en cada CALL. */
    MFunction pf = rewrite_to_physical(
        mf, codegen::build_allocation_result(ra, &ivs, plan), tri, AbiKind::VM,
        &ivs);

    /* Un bloque de inline-asm que se quedo SIN BYTES deja la funcion haciendo
     * otra cosa, asi que se rechaza aqui y se queda para el interprete: mas
     * lenta, pero correcta.  El motivo ya se conto al reescribir. */
    if (pf.asm_sin_bytes) return nullptr;

    /* 4b. P1 peephole: borrar los self-moves (`mov rX, rX`) que el coalescing
     *     dejo al asignar el mismo fisico a los dos extremos de una copia. */
    peephole_physical(pf);
    /* El JIT genera codigo que se ejecuta AQUI, asi que la ISA es la del host y
     * se PREGUNTA.  Estaba escrita a mano como x86: correcta mientras el camino
     * vreg solo compile para x86, pero deja de serlo en cuanto arm64 entre por
     * aqui -- y lo haria en silencio, dando a instrucciones de una arquitectura
     * los efectos de otra. */
    maybe_schedule(pf, vx::isa_host(), sched::SchedMode::JIT_AUTO);

    /* 3. Encode a bytes. */
    X86Encoder enc;
    std::vector<uint8_t> bytes;
    if (enc.encode(pf, bytes) == 0 || bytes.empty()) return nullptr;

    /* La correlacion codigo-nativo <-> linea que el codificador acaba de
     * construir.  Es lo unico que permite decir en que linea estaba un
     * programa compilado al fallar. */
    if (out_line_map) *out_line_map = std::move(pf.line_map);

    /* 4. Alojar en el code cache + commit (flush icache). */
    _jt.set_code_bytes(static_cast<uint32_t>(bytes.size())); // telemetria.
    uint8_t *code = cc.alloc(bytes.size(), 16);
    if (!code) return nullptr;
    /* Cuanto ocupa.  Quien registra la funcion lo necesita para poder decir,
     * ante un fallo en codigo nativo, si una direccion cae DENTRO de ella;
     * sin el tamano solo se puede adivinar por proximidad y se acaba
     * senalando la funcion equivocada. */
    if (out_code_size) *out_code_size = bytes.size();
    std::memcpy(code, bytes.data(), bytes.size());
    /* Jump table densa (SWITCH_DENSE): parchear cada entrada de 8 bytes con la
     * direccion nativa absoluta del brazo (base + label_offset).  POST-memcpy
     * (base = code) y PRE-commit (antes del flush icache). */
    if (!patch_after_alloc(pf, code)) return nullptr;
    cc.commit(code, bytes.size());
    /* Y como se desenrolla, para que un fallo del procesador dentro de esta
     * funcion se pueda recoger y contar en vez de matar el proceso en
     * silencio.  Ver @c jit/win_unwind.h.  Fuera de Windows no hace nada. */
    register_jit_unwind(code, bytes.size(), pf, cc);

    /* Disasm opt-in (VESTA_JIT_DISASM=1) del codigo vreg generado. */
    static const bool dis = util::flag_on(util::FlagId::JitDisasm);
    if (dis) debug_dump_jit_code(fn.name + " [vreg]", code, bytes.size());

    /* 5. Registrar en el JitRegistry con los stackmaps reales (commit 6):
     *    describen los GC roots vivos a traves de cada CALL (en slots),
     *    para que el GC los escanee del stack durante un sweep.
     *
     *    frame_size para el WALK POR TAMANO DE FRAME (scan_aot_frames, usado
     *    tambien por el scan preciso del GC en modo interp+JIT): RBP - RSP en
     *    un safepoint call = callee-saved pushes + spill_bytes.  Ese valor
     * exacto ya lo lleva cada stackmap (frame_size_for_scan(), identico en
     * todos);
     *    @c num_spill_slots por si solo NO incluye los callee-saved, asi que
     *    registrarlo daria un RBP mal reconstruido y el GC no veria los roots.
     *    Sin stackmaps (funcion sin calls) el valor no se consume en el walk.
     */
    const uint32_t scan_frame_size =
        pf.stackmaps.empty() ? static_cast<uint32_t>(8u * ra.num_spill_slots)
                             : pf.stackmaps.front().frame_size;
    JitRegistry::instance().register_function(
        code, code + bytes.size(), pf.stackmaps, scan_frame_size, "vreg");

    return code;
}

uint8_t *vreg_compile_callback(const ir::IrFunction &fn, CodeCache &cc,
                               const VregCallbackOpts &cb,
                               const CallResolver &resolve_call,
                               const VregEntries &ent,
                               const CallResolver &resolve_native,
                               const CallResolver &resolve_symbol) {
    /* Identico a vreg_compile pero pasando el VregCallbackOpts al selector:
     * el prologo/epilogo del entry siguen la convencion de ABI C nativo. */
    MFunction mf;
    if (!vreg_select(fn, mf, AbiKind::VM, resolve_call, ent, resolve_native,
                     resolve_symbol, /*pic=*/true,
                     /*target_sysv=*/host_is_sysv(),
                     /*mode32=*/false, FloatIsa::SSE2, /*emit_line_map=*/false,
                     cb))
        return nullptr;

    const TargetRegInfo &tri =
        target_x86_64_vm_abi(fn_needs_vec_reserve(fn), fn_needs_fp_scratch(fn),
                             fn_can_use_wide512(fn, backend_caps_host()));

    IntervalResult ivs = build_intervals(mf, tri);
    if (apply_ssa_coalesce(mf, fn, dst_kind_of_isa(vx::isa_host())))
        ivs = build_intervals(mf, tri);
    codegen::AssignmentPlan
        plan; // Fragmentation Recovery (vacio si el splitting esta OFF).
    codegen::RegAlloc ra = rbank_allocate_belady(
        ivs, mf, tri, fn_needs_vec_reserve(fn), &plan); // allocator UNICO.

    /* Verificador adversarial de GC roots (igual que vreg_compile). */
    if (!ivs.call_positions.empty()) {
        for (uint32_t v = 0; v < mf.vreg_count; ++v) {
            const LiveInterval &lv = ivs.intervals[v];
            if (!lv.is_gc()) continue;
            for (uint32_t cp : ivs.call_positions) {
                if (lv.covers(cp) && !ra.spilled(v)) return nullptr;
            }
        }
    }

    MFunction pf = rewrite_to_physical(
        mf, codegen::build_allocation_result(ra, &ivs, plan), tri, AbiKind::VM,
        &ivs);

    /* Un bloque de inline-asm que se quedo SIN BYTES deja la funcion haciendo
     * otra cosa, asi que se rechaza aqui y se queda para el interprete: mas
     * lenta, pero correcta.  El motivo ya se conto al reescribir. */
    if (pf.asm_sin_bytes) return nullptr;
    peephole_physical(pf);
    /* El JIT genera codigo que se ejecuta AQUI, asi que la ISA es la del host y
     * se PREGUNTA.  Estaba escrita a mano como x86: correcta mientras el camino
     * vreg solo compile para x86, pero deja de serlo en cuanto arm64 entre por
     * aqui -- y lo haria en silencio, dando a instrucciones de una arquitectura
     * los efectos de otra. */
    maybe_schedule(pf, vx::isa_host(), sched::SchedMode::JIT_AUTO);

    X86Encoder enc;
    std::vector<uint8_t> bytes;
    if (enc.encode(pf, bytes) == 0 || bytes.empty()) return nullptr;

    uint8_t *code = cc.alloc(bytes.size(), 16);
    if (!code) return nullptr;
    std::memcpy(code, bytes.data(), bytes.size());
    if (!patch_after_alloc(pf, code)) return nullptr;
    cc.commit(code, bytes.size());
    /* Y como se desenrolla, para que un fallo del procesador dentro de esta
     * funcion se pueda recoger y contar en vez de matar el proceso en
     * silencio.  Ver @c jit/win_unwind.h.  Fuera de Windows no hace nada. */
    register_jit_unwind(code, bytes.size(), pf, cc);

    static const bool dis = util::flag_on(util::FlagId::JitDisasm);
    if (dis) debug_dump_jit_code(fn.name + " [vreg-cb]", code, bytes.size());

    const uint32_t scan_frame_size =
        pf.stackmaps.empty() ? static_cast<uint32_t>(8u * ra.num_spill_slots)
                             : pf.stackmaps.front().frame_size;
    JitRegistry::instance().register_function(
        code, code + bytes.size(), pf.stackmaps, scan_frame_size, "vreg-cb");

    return code;
}

/*
 * Orquestador AOT ARCH-NEUTRAL: pipeline completo (seleccion -> intervalos ->
 * regalloc -> rewrite -> scheduler -> encode -> traduccion de relocs) a traves
 * de un @c CodegenTarget cualquiera.  Lo comparten x86 y arm64.
 */
std::vector<uint8_t> vreg_compile_native_target(
    const ir::IrFunction &fn, const CodegenTarget &target,
    std::vector<NativeReloc> *relocs_out,
    std::vector<LineMapEntry> *line_map_out,
    std::vector<std::pair<uint32_t, std::string>> *asm_labels_out,
    std::vector<Stackmap> *stackmaps_out) {
    if (relocs_out) relocs_out->clear();
    if (line_map_out) line_map_out->clear();
    if (asm_labels_out) asm_labels_out->clear();
    if (stackmaps_out) stackmaps_out->clear();

    /* El codigo NATIVO no lleva NUNCA polls de safepoint del watchdog CTPE.
     *
     * Ese poll llama al handler del watchdog, cuya direccion solo es valida
     * DENTRO del proceso del compilador: en el binario emitido es una llamada a
     * memoria muerta -> access violation al primer back-edge.  El gate vive en
     * un thread_local que solo escribe @c vreg_compile (camino JIT), asi que
     * tras un precomputo CTPE quedaba RANCIO -- @c jit_set_ctpe_safepoint(0)
     * limpia el campo de la CodeCache, pero nada re-propagaba el 0 al
     * thread_local -- y la emision nativa posterior en ese mismo hilo heredaba
     * el handler.  Se pone a 0 aqui: la distincion correcta no es "¿hay CTPE en
     * esta compilacion?" sino "¿este codigo se ejecuta AQUI o se ENVIA?". */
    vreg_set_ctpe_safepoint_handler(0);

    /* 1. SELECCION: IR (SSA) -> MachineIR de vregs (ABI HOST_LEAF). */
    MFunction mf;
    if (!target.select(fn, mf)) return {};
    const TargetRegInfo &tri = target.reg_info();

    /* 2. Intervalos + P1 coalescing + 3. asignacion linear-scan (COMUN a todo
     *    target: toman el TargetRegInfo). */
    IntervalResult ivs = build_intervals(mf, tri);
    /* Aqui el objetivo NO es el host: se genera un binario para donde diga el
     * target, que es quien contesta -- igual que el scheduler de mas abajo. */
    if (apply_ssa_coalesce(mf, fn, dst_kind_of_isa(target.sched_isa())))
        ivs = build_intervals(mf, tri);
    /* El path AOT baja por @c CodegenTarget::rewrite, que aun consume la @c
     * RegAlloc plana (no el @c AllocationResult) -> no puede materializar un
     * plan.  Se le pasa nullptr explicitamente: no es que no haya splitting, es
     * que este path todavia no sabe consumirlo. */
    codegen::RegAlloc ra =
        rbank_allocate_belady(ivs, mf, tri, fn_needs_vec_reserve(fn), nullptr);

    /* 4. REWRITE a fisico (prologo/epilogo + spills de la ABI del target). */
    MFunction pf = target.rewrite(mf, ra, ivs);
    target.peephole(pf);
    maybe_schedule(pf, target.sched_isa(), sched::SchedMode::AOT_GENERIC);

    /* 5. ENCODE a bytes maquina del target. */
    std::vector<uint8_t> bytes;
    if (target.encode(pf, bytes) == 0 || bytes.empty()) return {};

    /* Solo-LSP: el encoder ya poblo pf.line_map (si emit_line_map).  La
     * entregamos al caller para la vista correlada fuente <-> asm. */
    if (line_map_out) *line_map_out = std::move(pf.line_map);
    if (asm_labels_out) *asm_labels_out = std::move(pf.asm_labels);
    /*  AOT-GC (Inc 1): stackmaps de raices GC (pc_offset relativo a la
     * funcion + slots GcHandle), poblados por rewrite_to_physical en cada
     * safepoint/CALL.  El encoder ya fijo pc_offset al byte real del call. */
    if (stackmaps_out) *stackmaps_out = std::move(pf.stackmaps);

    /* AOT: traducir las MReloc del encoder (sym_idx -> reloc_symbols) a
     * NativeReloc con el NOMBRE del simbolo resuelto, para que el driver
     * las aplique sin depender de la tabla interna del MFunction. */
    if (relocs_out) {
        relocs_out->reserve(pf.relocs.size());
        for (const MReloc &r : pf.relocs) {
            NativeReloc nr;
            switch (r.kind) {
            case MRelocKind::CALL_REL32:
                nr.kind = NativeReloc::Kind::CALL_REL32;
                break;
            case MRelocKind::DATA_REL32:
                nr.kind = NativeReloc::Kind::DATA_REL32;
                break;
            case MRelocKind::ABS64: nr.kind = NativeReloc::Kind::ABS64; break;
            case MRelocKind::ABS32: nr.kind = NativeReloc::Kind::ABS32; break;
            case MRelocKind::TPOFF32:
                nr.kind = NativeReloc::Kind::TPOFF32;
                break;
            case MRelocKind::SECREL32:
                nr.kind = NativeReloc::Kind::SECREL32;
                break;
            case MRelocKind::ARM64_CALL26:
                nr.kind = NativeReloc::Kind::ARM64_CALL26;
                break;
            }
            nr.offset = r.patch_at;
            nr.addend = r.addend;
            nr.symbol = (r.sym_idx < pf.reloc_symbols.size())
                            ? pf.reloc_symbols[r.sym_idx]
                            : std::string();
            relocs_out->push_back(std::move(nr));
        }
    }

    /* Disasm opt-in (VESTA_JIT_DISASM=1) del codigo AOT generado. */
    static const bool dis = util::flag_on(util::FlagId::JitDisasm);
    if (dis)
        debug_dump_jit_code(fn.name + " [aot-native]", bytes.data(),
                            bytes.size());

    return bytes;
}

std::vector<uint8_t> vreg_compile_native(
    const ir::IrFunction &fn, const CallResolver &resolve_call,
    const VregEntries &ent, const CallResolver &resolve_native,
    const CallResolver &resolve_symbol, std::vector<NativeReloc> *relocs_out,
    bool pic, bool target_sysv, bool mode32, FloatIsa fisa, bool emit_line_map,
    std::vector<LineMapEntry> *line_map_out,
    std::vector<std::pair<uint32_t, std::string>> *asm_labels_out,
    std::vector<Stackmap> *stackmaps_out, const std::string &cpu) {
    /* Ruta AOT x86: construye el X86Target y delega en el orquestador comun.
     * Reserva VEC_ACC demand-driven (misma politica que el JIT).
     *
     * La microarquitectura, si se da, manda sobre el nivel de coma flotante:
     * es la fuente mas precisa de las tres y no depende de la maquina que
     * compila.  Vacia = el comportamiento de siempre. */
    const X86Target target(
        resolve_call, ent, resolve_native, resolve_symbol, pic, target_sysv,
        mode32, fisa, emit_line_map, fn_needs_vec_reserve(fn),
        fn_needs_fp_scratch(fn),
        fn_can_use_wide512(fn, resolve_backend_caps(cpu,
                                                    /*jit_host=*/false, fisa)));
    return vreg_compile_native_target(fn, target, relocs_out, line_map_out,
                                      asm_labels_out, stackmaps_out);
}

uint8_t *vreg_compile_osr(const ir::IrFunction &fn, CodeCache &cc,
                          const CallResolver &resolve_call,
                          const VregEntries &ent,
                          const CallResolver &resolve_native,
                          const CallResolver &resolve_symbol,
                          uint32_t header_block, uint8_t **osr_entry_out,
                          const std::vector<uint32_t> *required_captures) {
    if (osr_entry_out) *osr_entry_out = nullptr;

    /* 1-3: identico a vreg_compile (selector + intervals + regalloc +
     * verificador adversarial de GC roots). */
    MFunction mf;
    if (!vreg_select(fn, mf, AbiKind::VM, resolve_call, ent, resolve_native,
                     resolve_symbol))
        return nullptr;
    const TargetRegInfo &tri =
        target_x86_64_vm_abi(fn_needs_vec_reserve(fn), fn_needs_fp_scratch(fn),
                             fn_can_use_wide512(fn, backend_caps_host()));
    IntervalResult ivs = build_intervals(mf, tri);
    codegen::AssignmentPlan
        plan; // Fragmentation Recovery (vacio si el splitting esta OFF).
    codegen::RegAlloc ra = rbank_allocate_belady(
        ivs, mf, tri, fn_needs_vec_reserve(fn), &plan); // allocator UNICO.
    if (!ivs.call_positions.empty()) {
        for (uint32_t vv = 0; vv < mf.vreg_count; ++vv) {
            const LiveInterval &lv = ivs.intervals[vv];
            if (!lv.is_gc()) continue;
            for (uint32_t cp : ivs.call_positions) {
                if (lv.covers(cp) && !ra.spilled(vv)) return nullptr;
            }
        }
    }

    /* 4. Rewrite a fisico en modo OSR-ENTRY (suprime el trigger C1 y
     *    appendea el bloque OSR-entry para @p header_block). */
    OsrEmit osr;
    osr.mode = OsrEmit::C2_ENTRY;
    osr.header_block = static_cast<MBlockId>(header_block);
    osr.required_captures = required_captures; // red de seguridad live-in
    MFunction pf = rewrite_to_physical(
        mf, codegen::build_allocation_result(ra, &ivs, plan), tri, AbiKind::VM,
        &ivs, &osr);

    /* Un bloque de inline-asm que se quedo SIN BYTES deja la funcion haciendo
     * otra cosa, asi que se rechaza aqui y se queda para el interprete: mas
     * lenta, pero correcta.  El motivo ya se conto al reescribir. */
    if (pf.asm_sin_bytes) return nullptr;
    /* El JIT genera codigo que se ejecuta AQUI, asi que la ISA es la del host y
     * se PREGUNTA.  Estaba escrita a mano como x86: correcta mientras el camino
     * vreg solo compile para x86, pero deja de serlo en cuanto arm64 entre por
     * aqui -- y lo haria en silencio, dando a instrucciones de una arquitectura
     * los efectos de otra. */
    maybe_schedule(pf, vx::isa_host(), sched::SchedMode::JIT_AUTO);
    if (!osr.osr_entry_valid) return nullptr; // no se pudo emitir el entry

    /* 5. Encode. */
    X86Encoder enc;
    std::vector<uint8_t> bytes;
    if (enc.encode(pf, bytes) == 0 || bytes.empty()) return nullptr;

    /* 6. Alojar + commit. */
    uint8_t *code = cc.alloc(bytes.size(), 16);
    if (!code) return nullptr;
    std::memcpy(code, bytes.data(), bytes.size());
    /* Jump table densa (SWITCH_DENSE): parchear entradas con la direccion
     * nativa del brazo (base + label_offset).  POST-memcpy, PRE-commit. */
    if (!patch_after_alloc(pf, code)) return nullptr;
    cc.commit(code, bytes.size());
    /* Y como se desenrolla, para que un fallo del procesador dentro de esta
     * funcion se pueda recoger y contar en vez de matar el proceso en
     * silencio.  Ver @c jit/win_unwind.h.  Fuera de Windows no hace nada. */
    register_jit_unwind(code, bytes.size(), pf, cc);

    /* 7. Resolver la direccion absoluta del OSR-entry via el offset que el
     *    encoder dejo en label_offsets. */
    if (osr.osr_entry_label < pf.label_offsets.size() &&
        pf.label_offsets[osr.osr_entry_label] != UINT32_MAX) {
        if (osr_entry_out)
            *osr_entry_out = code + pf.label_offsets[osr.osr_entry_label];
    } else {
        return nullptr; // offset no resuelto
    }

    static const bool dis = util::flag_on(util::FlagId::JitDisasm);
    if (dis) debug_dump_jit_code(fn.name + " [vreg-osr]", code, bytes.size());

    /* 8. Registrar el blob C2 en el JitRegistry (stackmaps de sus CALLs).
     *    frame_size = RBP - RSP en un safepoint (callee-saved + spill_bytes),
     *    tomado del stackmap: @c num_spill_slots por si solo no incluye los
     *    callee-saved -> el scan_aot_frames reconstruiria mal el RBP.  Ver el
     *    comentario equivalente en vreg_compile. */
    const uint32_t scan_frame_size =
        pf.stackmaps.empty() ? static_cast<uint32_t>(8u * ra.num_spill_slots)
                             : pf.stackmaps.front().frame_size;
    JitRegistry::instance().register_function(
        code, code + bytes.size(), pf.stackmaps, scan_frame_size, "vreg-osr");

    return code;
}

} // namespace jit
