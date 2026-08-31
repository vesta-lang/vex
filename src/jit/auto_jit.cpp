/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/auto_jit.cpp
 * @brief Implementacion del auto-JIT trigger.
 *
 * Singleton lazy del @c JitCompiler (con su @c CodeCache + @c RuntimeEntries).
 * La construccion se difiere a la primera vez que se compila un metodo, asi
 * programas que jamas alcanzan el threshold no pagan el coste de inicializar
 * el JIT subsystem (10-50 KB de VM reservada para code cache).
 */

#include <algorithm>
#include "util/env_flags.h"
#include <thread>
#include <functional>
#include "jit/auto_jit.h"
#include "jit/jit_compile_options.h"
#include "jit/code_cache.h"
#include "jit/runtime_entries.h"
#include "jit/vreg_pipeline.h"
#include "jit/osr_registry.h" // registro de bucles re-entrables
#include "jit/naked_native.h" // FN.3: vrt_callind + compile_naked_native
#include "vesta_rt/public.h"
#include "ffi/virtual_lib_registry.h" // Sprint JIT-cross-fn: virtual fn lookup
#include "loader/loader.h"
#include "loader/oop_types.h"
#include "jit/jit_facts.h" // base de hechos: se CONSULTA, no se construye aqui
#include "ir/ir_optimizer.h"         // C2.4: devirt especulativa + inline
#include "ir/passes/if_conversion.h" // auto-PGO del JIT: re-if-conversion
#include "ir/passes/select_simplify.h"
#include "ir/passes/select_policy.h"
#include "jit/jit_branch_prof.h"
#include "runtime/profile.h"  // bridge runtime->IR del perfil medido
#include "debug/debug_info.h" // PC -> linea fuente
#include "runtime/proceso_runtime.h"
#include "runtime/runtime.h"
#include "runtime/scheduler.h"
#include "runtime/exception_runtime.h" // callback-ABI: get_current_executing_process + jit_proc_tls_index
#include "ir/ssa_ir.h"
#include <cstring>

#include <capstone/capstone.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <utility>
#include <vector>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace jit {

/// Sufijo de la variante que usa el JIT (@Target("mode:jit")).
///
/// Es un contrato de NOMBRE con el frontend (vx::ast::kSufijoVarianteJit); se
/// repite aqui en vez de incluir el AST entero para no atar el JIT al
/// frontend, que es independiente por diseno.
static constexpr const char *kSufijoVarianteJit = "__jit";

/* ===================================================================== */
/* Threshold global                                                       */
/* ===================================================================== */

/**
 * @brief Default: 1500 (JIT por defecto, tier C1-like estilo HotSpot).
 *
 * Un metodo/funcion se JIT-compila tras 1500 invocaciones.  Valor por
 * estudio empirico: el threshold NO es sensible en [100,20000] (mismo
 * resultado), 1500 esta sobre el break-even de metodos pesados (~1k) y bajo
 * los call-counts de codigo hot (millones); los metodos triviales (break-
 * even alto ~20k) se inlinean antes de compilar -> sin compile-waste.
 * Coincide con el tier C1 de HotSpot.
 *
 * Seguridad: el sandbox bajo JIT esta cerrado (maybe_compile_method /
 * maybe_compile_callvm_target / eager-compile de main bailan si
 * sandbox_active -> el interp enforcea las caps).
 *
 * Validado: e2e 263/0 forzando T=1500.  Un bug previo del path
 * native-callback (el thunk no forzaba el compile a threshold moderado ->
 * test 173 colgaba) se arreglo en native_callback.cpp (vx_get_native_thunk
 * fuerza el compile inmediato sea cual sea el threshold).
 *
 * Override: @c set_jit_threshold / env var @c VESTA_JIT_THRESHOLD;
 * `-m jit` = 1 (agresivo), `-m vm`/`-m interp` = UINT32_MAX (interp puro).
 */
uint32_t g_jit_threshold = 1500;

/**
 * @brief Warning toggleable + counters de auditoria.
 */
bool g_jit_warn_unsupported = false;
bool g_jit_disasm = false;
/* Sprint string-perf-6 (2026-06-02): emit del MIPS counter per-block
 * en el JIT.  Default OFF porque cuesta ~3ns por block ejecutado;
 * en hot loops con muchos bloques (e.g. bench_branch_unpredict con
 * 13 blocks/iter) el overhead puede llegar al 50%.  Solo se activa
 * cuando el usuario pide --stats o VESTA_JIT_STATS=1. */
bool g_jit_emit_instr_counter = false;
uint64_t g_jit_compiled_count = 0;
uint64_t g_jit_unsupported_count = 0;
uint64_t g_jit_no_ir_count = 0;

/* FN.3: direccion nativa de __vx_swapctx (la fija el force-eager de fibras). */
uint64_t g_vx_swapctx_native = 0;

/* C2 tier-up (2026-06-07).  OPT-IN: g_c2_threshold == 0 (default) deja el
 * C2 totalmente apagado -> el Selector NO emite el contador on-entry y el
 * comportamiento C1 queda intacto (cero regresion).  Cuando se setea
 * VESTA_C2_THRESHOLD=N>0, las funciones con CALLVIRT compiladas por el path
 * Selector llevan un contador de invocaciones; al cruzar N se recompilan
 * (C2) y se hace swap atomico del codigo.  VESTA_C2_LOG=1 loguea las clases
 * observadas en los IC slots durante el recompile (PoC C2.1/C2.2).
 * VESTA_C2_TIER_ALL=1 instrumenta TODAS las funciones (no solo las con
 * CALLVIRT) -- para A/B futuro.
 *
 * NOTA: la observacion de clases solo existe en el path Selector (que usa
 * el PIC via vrt_callvirt_ic); el path vreg (default) hace dispatch inline
 * sin PIC.  Por eso el C2 se valida con VESTA_JIT_VREGS=0.  Wirearlo al
 * path vreg (PIC) y el OSR para hotness de loop-en-main son follow-ups. */
uint32_t g_c2_threshold = 0;
bool g_c2_log = false;
bool g_c2_tier_all = false;
bool g_c2_vreg = false; /* experimento: recompilar C2 por path vreg */
uint64_t g_c2_tierup_count = 0;

/* C2 reclaim: true cuando el C2 esta activo -> enter_jit instrumenta la
 * quiescencia (ver interp_jit_bridge.h).  Default false = cero overhead. */
bool g_jit_reclaim_active = false;

/* Lazy init del threshold desde env var en la primera consulta. */
namespace {
std::once_flag g_env_init_flag;
void init_threshold_from_env() {
    {
        /* Fuera de rango o no numerico -> se queda el umbral de siempre, que
         * es lo que hacia antes al no poder convertirlo. */
        const long v = util::flag_int(util::FlagId::JitThreshold, -1);
        if (v >= 0 && v <= static_cast<long>(UINT32_MAX))
            g_jit_threshold = static_cast<uint32_t>(v);
    }
    /* Tambien leer VESTA_JIT_WARN_UNSUPPORTED para activar el
     * sistema de warnings de IR ops no soportadas. */
    if (util::flag_on(util::FlagId::JitWarnUnsupported))
        g_jit_warn_unsupported = true;
    /* VESTA_JIT_DISASM=1 -> dumpear los bytes generados + disasm. */
    if (util::flag_on(util::FlagId::JitDisasm)) g_jit_disasm = true;
    /* VESTA_JIT_STATS=1 -> emit del MIPS counter per-block (opt-in
     * porque cuesta ~3ns/block; en hot loops el overhead es alto). */
    if (util::flag_on(util::FlagId::JitStats)) g_jit_emit_instr_counter = true;
    /* C2 tier-up (opt-in).  VESTA_C2_THRESHOLD=N activa el tier-up con
     * umbral N; ausente o 0 = C2 apagado (default). */
    {
        const long v = util::flag_int(util::FlagId::C2Threshold, -1);
        if (v >= 0 && v <= static_cast<long>(UINT32_MAX))
            g_c2_threshold = static_cast<uint32_t>(v);
    }
    if (util::flag_on(util::FlagId::C2Log)) g_c2_log = true;
    if (util::flag_on(util::FlagId::C2TierAll)) g_c2_tier_all = true;
    if (util::flag_on(util::FlagId::C2Vreg)) g_c2_vreg = true;
    /* Activar la quiescencia de enter_jit SOLO si el C2 esta on.
     * Se setea aqui (init unica, antes de cualquier enter_jit) para
     * que los pares enter/exit esten siempre balanceados. */
    g_jit_reclaim_active = (g_c2_threshold != 0);
}

/* Singleton lazy del JIT subsystem (compiler + cache + entries). */
std::once_flag g_jit_init_flag;
CodeCache *g_code_cache = nullptr;
RuntimeEntries *g_runtime_entries = nullptr;
std::mutex g_compile_mtx;

/* OSR ( D.8, 2c): tabla loop_id -> direccion del OSR-entry del C2
 * precompilado.  Se rellena en eager_compile_function tras compilar el
 * C1 de cada funcion (un C2-con-OSR-entry por loop detectado).  El
 * handler instalado en regalloc_rewrite la consulta cuando un loop
 * cruza el umbral; devolver la direccion dispara el frame-swap C1->C2.
 * Lookup-puro en runtime (sin compilar -> sin GC) => el state-transfer
 * por buffer es GC-safe (host_ptr capturados siguen frescos). */
std::unordered_map<uint64_t, uint64_t> g_osr_entry_map;

/** @brief Gate del C2 OPTIMIZADO del OSR (default ON).  VESTA_OSR_OPT=0
 *  -> el C2 es un recompile plano (== C1) para A/B del beneficio del
 *  inline agresivo.  Cacheado (1 getenv). */
bool osr_opt_enabled() {
    static const bool on = util::flag_on(util::FlagId::OsrOpt);
    return on;
}

/** @brief Metodos ya recompilados a tier-2 (auto-PGO) -> no repetir. */
std::unordered_set<const void *> g_tier2_done;
std::mutex g_tier2_mtx;
/** @brief Bandera: recompilacion tier-2 en curso.  Cuando esta activa, el
 * bloque PGO de maybe_compile_method NO re-vuelca el perfil (ya lo poblo
 * maybe_tier2 desde g_jit_line_ctrs por linea), solo aplica la if-conversion.
 * Global plano (no thread_local: MinGW/DLL + emutls da problemas de link); la
 * recompilacion va serializada por g_tier2_mtx, asi que no hay concurrencia
 * real. */
bool g_tier2_recompiling = false;

/** @brief Delta (invocaciones tras tier-1) para disparar tier-2.  DINAMICO: no
 *  un numero fijo, sino proporcional al umbral de tier-1 (mas caliente = mas
 *  datos antes de re-optimizar), con un minimo razonable y override por env
 *  VESTA_JIT_TIER2_DELTA.  Asi escala con la config de hotness del run. */
uint32_t jit_tier2_delta() {
    static const uint32_t env_override = static_cast<uint32_t>(
        std::max<long>(0, util::flag_int(util::FlagId::JitTier2Delta, 0)));
    if (env_override) return env_override;
    const uint32_t t = g_jit_threshold;
    if (t == UINT32_MAX) return UINT32_MAX; // JIT off
    uint32_t d = t;         // 1x el umbral de tier-1 (proporcional a hotness)
    if (d < 2000) d = 2000; // suelo: suficientes muestras para P estable
    return d;
}

/** @brief Handler de OSR instalado via set_osr_handler.  Lookup del
 *  OSR-entry precompilado para @p loop_id (0 si no hay variante). */
uint64_t osr_lookup_handler(uint64_t loop_id) {
    auto it = g_osr_entry_map.find(loop_id);
    return (it != g_osr_entry_map.end()) ? it->second : 0;
}

void init_jit_subsystem() {
    g_code_cache = new CodeCache();
    g_runtime_entries = new RuntimeEntries();
    g_runtime_entries->resolve();
    /* OSR: instalar el handler de lookup (antes de cualquier compile,
     * por tanto antes de cualquier trigger en runtime). */
    set_osr_handler(&osr_lookup_handler);
}

/* Construye el VregEntries desde los runtime entries resueltos. */
VregEntries make_vreg_entries() {
    VregEntries e;
    if (g_runtime_entries) {
        e.callvirt = reinterpret_cast<uint64_t>(g_runtime_entries->callvirt);
        e.callm = reinterpret_cast<uint64_t>(g_runtime_entries->callm);
        e.callitf = reinterpret_cast<uint64_t>(g_runtime_entries->callitf);
        e.unwrap_throw =
            reinterpret_cast<uint64_t>(g_runtime_entries->unwrap_throw);
        e.proc_pid = reinterpret_cast<uint64_t>(g_runtime_entries->proc_pid);
        e.gc_deref = reinterpret_cast<uint64_t>(g_runtime_entries->gc_deref);
        e.gc_handle =
            reinterpret_cast<uint64_t>(g_runtime_entries->gc_handle_for_ptr);
        e.gc_write_barrier =
            reinterpret_cast<uint64_t>(g_runtime_entries->gc_write_barrier);
        e.raw_alloc = reinterpret_cast<uint64_t>(g_runtime_entries->raw_alloc);
        /* Si el programa trae su asignador, el monton es el suyo: el selector
         * lo necesita para no usar el atajo que replica el de la maquina. */
        e.alloc_del_programa = jit::g_alloc_del_programa;
        e.free_del_programa = jit::g_free_del_programa;
        e.raw_free = reinterpret_cast<uint64_t>(g_runtime_entries->raw_free);
        e.gc_allocp =
            reinterpret_cast<uint64_t>(g_runtime_entries->gc_alloc_payload);
        e.newobj = reinterpret_cast<uint64_t>(g_runtime_entries->newobj_handle);
        e.newobjs = reinterpret_cast<uint64_t>(g_runtime_entries->newobjs);
        e.dlopen = reinterpret_cast<uint64_t>(g_runtime_entries->dlopen);
        e.str_conv = reinterpret_cast<uint64_t>(g_runtime_entries->str_conv);
        e.panic_str = reinterpret_cast<uint64_t>(g_runtime_entries->panic_str);
        /* Excepciones in-JIT (Opcion B). */
        e.tryenter_jit =
            reinterpret_cast<uint64_t>(g_runtime_entries->tryenter_jit);
        e.tryleave = reinterpret_cast<uint64_t>(g_runtime_entries->tryleave);
        e.throw_user =
            reinterpret_cast<uint64_t>(g_runtime_entries->throw_user);
        /* Offsets handoff RSP/RBP del tryenter in-JIT (offsetof type-based;
         * conditionally-supported en tipo no-standard-layout, OK en GCC). */
        e.jit_exc_rsp_off =
            static_cast<int32_t>(offsetof(runtime::ProcessVM, jit_exc_rsp));
        e.jit_exc_rbp_off =
            static_cast<int32_t>(offsetof(runtime::ProcessVM, jit_exc_rbp));
        /* Class registry (Fase 2). */
        e.findclass = reinterpret_cast<uint64_t>(g_runtime_entries->findclass);
        e.findmethod =
            reinterpret_cast<uint64_t>(g_runtime_entries->findmethod);
        e.findfield = reinterpret_cast<uint64_t>(g_runtime_entries->findfield);
        e.defclass = reinterpret_cast<uint64_t>(g_runtime_entries->defclass);
        e.setmethdbg =
            reinterpret_cast<uint64_t>(g_runtime_entries->setmethdbg);
        e.deffield = reinterpret_cast<uint64_t>(g_runtime_entries->deffield);
        e.defmethod = reinterpret_cast<uint64_t>(g_runtime_entries->defmethod);
        e.addadvice = reinterpret_cast<uint64_t>(g_runtime_entries->addadvice);
        /* String ops (cluster cobertura 2026-06-09). */
        e.str_make = reinterpret_cast<uint64_t>(g_runtime_entries->str_make);
        e.str_make_h =
            reinterpret_cast<uint64_t>(g_runtime_entries->str_make_h);
        e.str_len = reinterpret_cast<uint64_t>(g_runtime_entries->str_len);
        e.str_cat = reinterpret_cast<uint64_t>(g_runtime_entries->str_cat);
        e.str_slice = reinterpret_cast<uint64_t>(g_runtime_entries->str_slice);
        e.str_cmp = reinterpret_cast<uint64_t>(g_runtime_entries->str_cmp);
        e.str_raw = reinterpret_cast<uint64_t>(g_runtime_entries->str_raw);
        e.str_get_bytes =
            reinterpret_cast<uint64_t>(g_runtime_entries->str_get_bytes);
        e.call_bc_function =
            reinterpret_cast<uint64_t>(g_runtime_entries->call_bc_function);
        e.callclosure =
            reinterpret_cast<uint64_t>(g_runtime_entries->callclosure);
        /* FN.3: fibras nativas en JIT.  swapctx la fija el force-eager al
         * compilar __vx_swapctx (0 si el programa no usa fibras); callind es
         * el helper de runtime, un simbolo estatico siempre disponible. */
        e.swapctx = g_vx_swapctx_native;
        e.callind = reinterpret_cast<uint64_t>(&vrt_callind);
        /* Fallback de LOAD_VM/STORE_VM (page-miss del vm_mem). */
        e.vm_read_u8 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_read_u8);
        e.vm_read_u16 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_read_u16);
        e.vm_read_u32 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_read_u32);
        e.vm_read_u64 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_read_u64);
        e.vm_write_u8 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_write_u8);
        e.vm_write_u16 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_write_u16);
        e.vm_write_u32 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_write_u32);
        e.vm_write_u64 =
            reinterpret_cast<uint64_t>(g_runtime_entries->vm_write_u64);
    }
    return e;
}

/* C2-cimiento (2026-06-07): IC slots DIRECCIONABLES por call site.
 *
 * g_ic_slots:    clave (fn_pc<<8 | ordinal) -> addr del slot PIC
 *                (64 bytes: 4 entradas [class_ptr][jit_code]).
 * g_fn_ic_keys:  fn_pc -> lista de claves de sus IC sites (CALLVIRT),
 *                para que el futuro pase C2 itere los slots de una fn
 *                caliente y lea las clases observadas (especular).
 *
 * Ambos se tocan SOLO en compile time (bajo g_compile_mtx).  El runtime
 * (vrt_callvirt_ic) escribe DENTRO de los slots, no en estos mapas.
 *
 * @c get_ic_slot(key): si key!=0 reusa el slot existente del call site
 * (estable entre recompilaciones) o lo crea; si key==0 aloca un slot
 * fresco no-direccionable (NATIVE_ABI / ICs no-PIC). */
std::unordered_map<uint64_t, uint64_t> g_ic_slots;
std::unordered_map<uint64_t, std::vector<uint64_t>> g_fn_ic_keys;

uint64_t get_ic_slot(uint64_t key) {
    if (g_code_cache == nullptr) return 0;
    if (key != 0) {
        auto it = g_ic_slots.find(key);
        if (it != g_ic_slots.end()) return it->second;
    }
    uint8_t *slot = g_code_cache->alloc(64, 64);
    if (slot == nullptr) return 0;
    std::memset(slot, 0, 64);
    const uint64_t addr = reinterpret_cast<uint64_t>(slot);
    if (key != 0) {
        g_ic_slots[key] = addr;
        g_fn_ic_keys[key >> 8].push_back(key);
    }
    return addr;
}

/* Callback call-fallback (jubilacion de slots): cuando no hay TLS-direct
 * (Linux, o Windows si TlsAlloc fallo), el prologo del callback debe cargar
 * proc via un CALL a get_current_executing_process.  Ese call clobbea los
 * arg-regs nativos (que aun tienen los args del callback).  Este stub los
 * PRESERVA: guarda los GP-args (push/pop) + los FP-args (movsd) alrededor del
 * call y devuelve proc en RAX, para que el marshalling posterior lea los args
 * intactos.  Se genera una vez en el code cache (ABI del HOST: JIT ==
 * host==target).  Devuelve 0 si el subsistema JIT no esta listo. */
uint64_t cb_preserving_get_proc() {
    static uint64_t g_stub = 0;
    if (g_stub != 0) return g_stub;
    /* Asegurar el subsistema JIT (code cache) inicializado: en modo interp
     * (-m vm) este helper puede llamarse antes de que nada mas lo inicialice
     * -> sin esto g_code_cache seria null, el stub 0, y el LOAD_PROC-fallback
     * del callback haria `call 0` (SIGSEGV). */
    std::call_once(g_jit_init_flag, init_jit_subsystem);
    if (g_code_cache == nullptr) return 0;
    const uint64_t getproc =
        reinterpret_cast<uint64_t>(&runtime::get_current_executing_process);
    std::vector<uint8_t> b;
    auto imm64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i)
            b.push_back((v >> (i * 8)) & 0xFF);
    };
    /* Prologo comun: alinear rsp a 16 via rbp (agnostico a la alineacion de
     * entrada, que depende del nº de callee-saved del frame del callback). */
    const uint8_t pro[] = {
        0x55,                   /* push rbp */
        0x48, 0x89, 0xE5,       /* mov rbp, rsp */
        0x48, 0x83, 0xE4, 0xF0, /* and rsp, -16 */
    };
    b.assign(pro, pro + sizeof(pro));
    const uint8_t epi[] = {
        0x48, 0x89, 0xEC, /* mov rsp, rbp */
        0x5D,             /* pop rbp */
        0xC3,             /* ret */
    };
#if defined(_WIN32)
    /* Win64: preservar RCX,RDX,R8,R9 + XMM0-3.  0x60 = shadow(0x20) + 4 GP
     * (0x20) + 4 XMM (0x20); 16-aligned.  GP en [rsp+0x20..], XMM en
     * [rsp+0x40..]; shadow [rsp+0..0x20] para el call a get_proc. */
    const uint8_t win[] = {
        0x48, 0x83, 0xEC, 0x60,             /* sub rsp, 0x60 */
        0x48, 0x89, 0x4C, 0x24, 0x20,       /* mov [rsp+0x20], rcx */
        0x48, 0x89, 0x54, 0x24, 0x28,       /* mov [rsp+0x28], rdx */
        0x4C, 0x89, 0x44, 0x24, 0x30,       /* mov [rsp+0x30], r8 */
        0x4C, 0x89, 0x4C, 0x24, 0x38,       /* mov [rsp+0x38], r9 */
        0xF2, 0x0F, 0x11, 0x44, 0x24, 0x40, /* movsd [rsp+0x40], xmm0 */
        0xF2, 0x0F, 0x11, 0x4C, 0x24, 0x48, /* movsd [rsp+0x48], xmm1 */
        0xF2, 0x0F, 0x11, 0x54, 0x24, 0x50, /* movsd [rsp+0x50], xmm2 */
        0xF2, 0x0F, 0x11, 0x5C, 0x24, 0x58, /* movsd [rsp+0x58], xmm3 */
        0x48, 0xB8};                        /* mov rax, imm64 */
    b.insert(b.end(), win, win + sizeof(win));
    imm64(getproc);
    const uint8_t win2[] = {
        0xFF, 0xD0,                         /* call rax  (rax = proc) */
        0x48, 0x8B, 0x4C, 0x24, 0x20,       /* mov rcx, [rsp+0x20] */
        0x48, 0x8B, 0x54, 0x24, 0x28,       /* mov rdx, [rsp+0x28] */
        0x4C, 0x8B, 0x44, 0x24, 0x30,       /* mov r8, [rsp+0x30] */
        0x4C, 0x8B, 0x4C, 0x24, 0x38,       /* mov r9, [rsp+0x38] */
        0xF2, 0x0F, 0x10, 0x44, 0x24, 0x40, /* movsd xmm0, [rsp+0x40] */
        0xF2, 0x0F, 0x10, 0x4C, 0x24, 0x48, /* movsd xmm1, [rsp+0x48] */
        0xF2, 0x0F, 0x10, 0x54, 0x24, 0x50, /* movsd xmm2, [rsp+0x50] */
        0xF2, 0x0F, 0x10, 0x5C, 0x24, 0x58, /* movsd xmm3, [rsp+0x58] */
    };
    b.insert(b.end(), win2, win2 + sizeof(win2));
#else
    /* SysV: preservar RDI,RSI,RDX,RCX,R8,R9 + XMM0-7.  0x70 = 6 GP (0x30) +
     * 8 XMM (0x40); 16-aligned.  Sin shadow.  GP en [rsp+0..], XMM en
     * [rsp+0x30..]. */
    const uint8_t sv[] = {
        0x48, 0x83, 0xEC, 0x70,             /* sub rsp, 0x70 */
        0x48, 0x89, 0x3C, 0x24,             /* mov [rsp+0x00], rdi */
        0x48, 0x89, 0x74, 0x24, 0x08,       /* mov [rsp+0x08], rsi */
        0x48, 0x89, 0x54, 0x24, 0x10,       /* mov [rsp+0x10], rdx */
        0x48, 0x89, 0x4C, 0x24, 0x18,       /* mov [rsp+0x18], rcx */
        0x4C, 0x89, 0x44, 0x24, 0x20,       /* mov [rsp+0x20], r8 */
        0x4C, 0x89, 0x4C, 0x24, 0x28,       /* mov [rsp+0x28], r9 */
        0xF2, 0x0F, 0x11, 0x44, 0x24, 0x30, /* movsd [rsp+0x30], xmm0 */
        0xF2, 0x0F, 0x11, 0x4C, 0x24, 0x38, /* movsd [rsp+0x38], xmm1 */
        0xF2, 0x0F, 0x11, 0x54, 0x24, 0x40, /* movsd [rsp+0x40], xmm2 */
        0xF2, 0x0F, 0x11, 0x5C, 0x24, 0x48, /* movsd [rsp+0x48], xmm3 */
        0xF2, 0x0F, 0x11, 0x64, 0x24, 0x50, /* movsd [rsp+0x50], xmm4 */
        0xF2, 0x0F, 0x11, 0x6C, 0x24, 0x58, /* movsd [rsp+0x58], xmm5 */
        0xF2, 0x0F, 0x11, 0x74, 0x24, 0x60, /* movsd [rsp+0x60], xmm6 */
        0xF2, 0x0F, 0x11, 0x7C, 0x24, 0x68, /* movsd [rsp+0x68], xmm7 */
        0x48, 0xB8};                        /* mov rax, imm64 */
    b.insert(b.end(), sv, sv + sizeof(sv));
    imm64(getproc);
    const uint8_t sv2[] = {
        0xFF, 0xD0,                         /* call rax  (rax = proc) */
        0x48, 0x8B, 0x3C, 0x24,             /* mov rdi, [rsp+0x00] */
        0x48, 0x8B, 0x74, 0x24, 0x08,       /* mov rsi, [rsp+0x08] */
        0x48, 0x8B, 0x54, 0x24, 0x10,       /* mov rdx, [rsp+0x10] */
        0x48, 0x8B, 0x4C, 0x24, 0x18,       /* mov rcx, [rsp+0x18] */
        0x4C, 0x8B, 0x44, 0x24, 0x20,       /* mov r8, [rsp+0x20] */
        0x4C, 0x8B, 0x4C, 0x24, 0x28,       /* mov r9, [rsp+0x28] */
        0xF2, 0x0F, 0x10, 0x44, 0x24, 0x30, /* movsd xmm0, [rsp+0x30] */
        0xF2, 0x0F, 0x10, 0x4C, 0x24, 0x38, /* movsd xmm1, [rsp+0x38] */
        0xF2, 0x0F, 0x10, 0x54, 0x24, 0x40, /* movsd xmm2, [rsp+0x40] */
        0xF2, 0x0F, 0x10, 0x5C, 0x24, 0x48, /* movsd xmm3, [rsp+0x48] */
        0xF2, 0x0F, 0x10, 0x64, 0x24, 0x50, /* movsd xmm4, [rsp+0x50] */
        0xF2, 0x0F, 0x10, 0x6C, 0x24, 0x58, /* movsd xmm5, [rsp+0x58] */
        0xF2, 0x0F, 0x10, 0x74, 0x24, 0x60, /* movsd xmm6, [rsp+0x60] */
        0xF2, 0x0F, 0x10, 0x7C, 0x24, 0x68, /* movsd xmm7, [rsp+0x68] */
    };
    b.insert(b.end(), sv2, sv2 + sizeof(sv2));
#endif
    b.insert(b.end(), epi, epi + sizeof(epi));
    uint8_t *code = g_code_cache->alloc(b.size(), 16);
    if (code == nullptr) return 0;
    std::memcpy(code, b.data(), b.size());
    g_code_cache->commit(code, b.size());
    g_stub = reinterpret_cast<uint64_t>(code);
    return g_stub;
}

/* C2 tier-up: contador de invocaciones por funcion (keyed por fn_pc),
 * conjunto de fns ya tieradas (idempotencia), y mapa fn_pc -> MethodInfo
 * (para hacer swap de method->jit_code ademas del pc-map).  Tocados
 * bajo g_compile_mtx. */
std::unordered_map<uint64_t, uint64_t> g_tier_counters;
std::unordered_set<uint64_t> g_tiered_pcs;
std::unordered_map<uint64_t, loader::MethodInfo *> g_pc_to_method;
/* fn_pc -> (code_start, code_size) del C1, para devolver la region al
 * free-list del CodeCache cuando la funcion sube a C2. */
std::unordered_map<uint64_t, std::pair<uint8_t *, size_t>> g_c1_region;

/* Quiescencia + free-list pendiente (reclaim C2).  g_jit_active_frames
 * es la profundidad de frames JIT en pila nativa (atomic, tocado en el
 * borde enter_jit).  g_pending_free son regiones C1 a reciclar; se
 * drenan (devuelven al CodeCache) cuando g_jit_active_frames llega a 0.
 * g_pending_free + g_pending_free_count se mutan bajo g_compile_mtx;
 * g_pending_free_count se lee lock-free en jit_frame_exit para decidir
 * si drenar (eventual-consistente: una lectura obsoleta solo difiere el
 * drain al proximo 0). */
std::atomic<int64_t> g_jit_active_frames{0};
std::vector<std::pair<uint8_t *, size_t>> g_pending_free;
std::atomic<size_t> g_pending_free_count{0};

/* Reserva (o reusa) el contador de 8 bytes para fn_pc en el code cache
 * (mismo pool RWX que el codigo; el JIT lee/escribe estos bytes pero no
 * los ejecuta).  Zero-init.  Estable entre recompilaciones del call
 * site (mismo fn_pc -> mismo contador). */
uint64_t reserve_tier_counter(uint64_t fn_pc) {
    if (g_code_cache == nullptr || fn_pc == 0) return 0;
    auto it = g_tier_counters.find(fn_pc);
    if (it != g_tier_counters.end()) return it->second;
    uint8_t *slot = g_code_cache->alloc(8, 8);
    if (slot == nullptr) return 0;
    std::memset(slot, 0, 8);
    const uint64_t addr = reinterpret_cast<uint64_t>(slot);
    g_tier_counters[fn_pc] = addr;
    return addr;
}
} // namespace

// CTPE: inicializa el subsistema JIT (idempotente) y devuelve la direccion del
// handler de safepoint.  Fuera del namespace anonimo -> linkage externo (la usa
// comptime_vm.cpp).  Puede llamar a init_jit_subsystem/g_jit_init_flag del
// namespace anonimo porque son visibles en el namespace jit envolvente (mismo
// TU).
uint64_t jit_safepoint_handler_addr() noexcept {
    std::call_once(g_jit_init_flag, init_jit_subsystem);
    return g_runtime_entries ? reinterpret_cast<uint64_t>(
                                   g_runtime_entries->safepoint_handler)
                             : 0;
}

void jit_set_ctpe_safepoint(uint64_t handler_addr) noexcept {
    std::call_once(g_jit_init_flag, init_jit_subsystem);
    if (g_code_cache) g_code_cache->ctpe_safepoint_handler = handler_addr;
}

/* Sprint B.1: expose el CodeCache global al runtime (native_callback.cpp).
 * Bypass el namespace anonimo de los singletons; el caller solo recibe
 * un puntero const-correcto. */
CodeCache *get_or_init_code_cache() noexcept {
    std::call_once(g_jit_init_flag, init_jit_subsystem);
    return g_code_cache;
}

/* FN.3: fuera del namespace anonimo -- la llama loader.cpp (linkage externa).
 */
/** @brief El asignador del programa, ya compilado (0 = no hay).  Lo pone el
 *  cargador; lo lee el selector para saber cual es el monton. */
/**
 * @brief Especializar una llamada por lo que se sabe de sus argumentos.
 *
 * Meter el cuerpo de la funcion llamada y plegar lo conocido deja SOLO el
 * camino que ese caso recorre.  Medido en una copia de tamano conocido: 111 ms
 * contra 123 sin ella.
 *
 * Se apaga con VESTA_JIT_NO_ESPECIALIZAR=1 para comparar.
 */
static bool jit_sin_especializar_reservas() {
    static const bool off = util::flag_on(util::FlagId::JitNoEspecializar);
    return off;
}

/**
 * @brief Si hay que contar en voz alta cada decision de especializacion.
 *
 * Con @c VESTA_JIT_ESPECIALIZAR_DEBUG=1.  Renunciar en silencio es lo que hace
 * que una optimizacion se pudra sin que nadie se entere: el que renuncia, dice
 * por que.
 */
static bool jit_especializar_debug() {
    static const bool on = util::flag_on(util::FlagId::JitEspecializarDebug);
    return on;
}

/**
 * @brief Cuenta el veredicto de la especializacion con su prueba.
 *
 * Una linea por funcion considerada, en campos fijos para poder agregarla con
 * una herramienta: el veredicto, cuantos sitios se miraron, cuantos traian algo
 * sabido, y -- cuando lo hay -- el hecho concreto que sostiene el si, con la
 * certeza de donde salio.
 *
 * @param fn        Funcion considerada.
 * @param cotas     Lo que se supo de sus sitios de llamada y reserva.
 * @param sello     Procedencia y certeza del conocimiento de rangos usado.
 * @param cuerpos   Cuantos cuerpos de los llamados estan disponibles.
 * @param asignador Si entre ellos esta el asignador del programa.
 */
static void explicar_especializacion(const ir::IrFunction &fn,
                                     const CotasDeLosSitios &cotas,
                                     const analysis::asa::Seal &sello,
                                     size_t cuerpos, bool asignador) {
    const char *motivo = "";
    if (!cotas.hay)
        motivo =
            cotas.sitios == 0 ? " motivo=sin-sitios" : " motivo=nada-acotado";
    else if (cuerpos == 0)
        motivo = " motivo=sin-cuerpos";
    std::fprintf(
        stderr,
        "[especializar] %-28s veredicto=%s sitios=%u/%u operandos=%u/%u "
        "cuerpos=%zu%s%s",
        fn.name.c_str(), (cotas.hay && cuerpos != 0) ? "si" : "no",
        cotas.sitios_con_cota, cotas.sitios, cotas.operandos_con_cota,
        cotas.operandos, cuerpos, asignador ? " asignador=si" : "", motivo);
    if (cotas.hay) {
        int64_t lo = 0, hi = 0;
        if (cotas.rango.vista_con_signo(lo, hi))
            std::fprintf(stderr, " prueba=%s v%u en [%lld,%lld]",
                         cotas.sitio.c_str(), cotas.valor,
                         static_cast<long long>(lo),
                         static_cast<long long>(hi));
        else
            std::fprintf(stderr, " prueba=%s v%u acotado", cotas.sitio.c_str(),
                         cotas.valor);
        std::fprintf(stderr, " certeza=%s",
                     analysis::asa::certainty_name(sello.certainty));
    }
    std::fprintf(stderr, "\n");
}

uint64_t g_alloc_del_programa = 0;
uint64_t g_free_del_programa = 0;

uint64_t ensure_vx_swapctx_native(runtime::ProcessVM *vm) noexcept {
    if (g_vx_swapctx_native != 0) return g_vx_swapctx_native;
    if (vm == nullptr) return 0;
    /* compile_naked_native aplica el arch-guard x86-64 y devuelve 0 fuera de
     * esa arquitectura -> el llamante deja el grafo de fibra en el interp. */
    const uint64_t a = jit::compile_naked_native(vm, "__vx_swapctx");
    if (a != 0) g_vx_swapctx_native = a;
    return g_vx_swapctx_native;
}

namespace {

/* Cache global de compilaciones eager: nombre -> ptr al codigo nativo.
 * Sentinela IN_PROGRESS (1) marca compilation en curso para detectar
 * ciclos (mutua recursion).  Nullptr explicito (0) significa "no
 * compilable" (cached failure, evita reintentos).
 *
 * Vive bajo g_compile_mtx para safety multi-thread aunque por ahora
 * solo el load_executable invoca eager-compile (1 thread).  Compartido
 * tambien con maybe_compile_method (D.3-C+ auto-JIT trigger). */
constexpr uint64_t EAGER_IN_PROGRESS = 1;
std::unordered_map<std::string, uint64_t> g_eager_cache;
} // namespace

void set_jit_threshold(uint32_t threshold) noexcept {
    g_jit_threshold = threshold;
}

/* Forzar lectura del env var VESTA_JIT_THRESHOLD (+ warn/disasm) AHORA
 * en lugar de esperar al primer maybe_compile_*.  Util para que main.cpp
 * llame al inicio y la eager-compile pass del Loader vea el threshold
 * correcto.
 *
 * Idempotente: usa el mismo std::call_once que el path lazy.  Si ya
 * corrio (otro thread o lazy fire previo), no-op. */
void init_threshold_from_env_now() noexcept {
    std::call_once(g_env_init_flag, init_threshold_from_env);
}

/* C2 tier-up: handler invocado por el contador on-entry del codigo C1
 * cuando cruza el umbral.  Recompila la funcion (C2) y hace swap del
 * codigo.  Definido mas abajo; se toma su direccion en las opts. */
void c2_tier_up(runtime::ProcessVM *vm, uint64_t fn_pc) noexcept;

/* ===================================================================== */
/* maybe_compile_method                                                   */
/* ===================================================================== */

void maybe_compile_method(runtime::ProcessVM *vm,
                          loader::MethodInfo *method) noexcept {
    /* Init lazy de threshold desde env (1 vez por proceso). */
    std::call_once(g_env_init_flag, init_threshold_from_env);

    /* Fast path: si JIT esta off (threshold = UINT32_MAX) o el
     * metodo ya fue JIT-compilado o el counter no llego al
     * threshold, retornar inmediatamente.  Coste: 1 cmp + 1 cmp =
     * ~1 ns (branch predicted). */
    if (g_jit_threshold == UINT32_MAX) return;
    if (method->jit_code != nullptr) return;
    /* El asignador no espera a calentarse.
     *
     * Contar invocaciones sirve para decidir SI merece la pena compilar algo, y
     * en estas la respuesta ya se sabe: las usa todo el codigo que reserva
     * memoria.  Ademas, mientras no esten compiladas conviven dos caminos de
     * reserva en el mismo proceso, y eso es justo lo que no puede durar. */
    const bool del_asignador =
        method->name.data != nullptr &&
        ((method->name.size == 11 &&
          std::memcmp(method->name.data, "__vx_malloc", 11) == 0) ||
         (method->name.size == 9 &&
          std::memcmp(method->name.data, "__vx_free", 9) == 0));
    if (!del_asignador && method->invocation_count < g_jit_threshold) return;

    /* SEGURIDAD (sandbox bajo JIT): si hay un sandbox activo (algun modulo
     * con caps restringidas, M.sandbox Sprint A), NO JIT-compilar.  El
     * codigo JIT-eated emite CALLN/CALLNI/dlopen/spawn/etc. SIN el check de
     * capabilities que el interprete SI hace (check_cap_at_pc) -> dejar la
     * funcion en interp garantiza el enforcement del sandbox.  Coste cero
     * cuando no hay sandbox (1 branch predicho not-taken; sandbox_active es
     * false en el caso default).  Prerrequisito para habilitar JIT por
     * defecto sin abrir un hueco de seguridad. */
    if (vm->scheduler.vm_reference.loader_public.sandbox_active) return;

    /* Slow path: el counter cruzo el threshold y el metodo NO
     * tiene jit_code aun.  Intentar compilar. */

    /* Construir lookup key: "<ClassName>__<methodName>".
     * stringx es un struct {uint8_t* data, uint32_t size}; lo
     * convertimos a string via reinterpret_cast (los bytes son
     * UTF-8/ASCII puro segun el frontend). */
    auto stringx_to_str = [](const loader::stringx &sx) -> std::string {
        if (!sx.data || sx.size == 0) return {};
        return std::string(reinterpret_cast<const char *>(sx.data), sx.size);
    };
    std::string key;
    if (method->owner_class) {
        const std::string cls = stringx_to_str(method->owner_class->name);
        if (!cls.empty()) {
            key += cls;
            key += "__";
        }
    }
    key += stringx_to_str(method->name);

    /* Buscar el IrFunction en los executables del Loader.
     * El Loader vive en VM (compartido entre procesos).  Iteramos
     * sus executables y consultamos su ir_lookup. */
    const ir::IrFunction *ir_fn = nullptr;
    const std::unordered_map<std::string, uint64_t> *owning_symtab = nullptr;
    const std::unordered_map<std::string, size_t> *owning_lookup = nullptr;
    const std::vector<ir::IrFunction> *owning_funcs = nullptr;
    runtime::VM &owning_vm = vm->scheduler.vm_reference;

    /* Construir lista de claves alternativas a probar (en orden de
     * preferencia).  Los constructores en Vesta se mangleean como
     * "ClassName__ctor" en IR, pero MethodInfo::name == ClassName
     * para constructores -> el key naive "ClassName__ClassName"
     * no funciona.  Detectamos el caso y agregamos fallback. */
    std::vector<std::string> candidate_keys{key};
    if (method->owner_class) {
        const std::string cls = stringx_to_str(method->owner_class->name);
        const std::string mtd = stringx_to_str(method->name);
        if (!cls.empty() && cls == mtd) {
            /* Es ctor: probar "ClassName__ctor". */
            candidate_keys.push_back(cls + "__ctor");
        }
    }

    for (const auto &exe : owning_vm.loader_public.executables) {
        for (const auto &k : candidate_keys) {
            auto it = exe->ir_lookup.find(k);
            if (it != exe->ir_lookup.end() &&
                it->second < exe->ir_functions.size()) {
                ir_fn = &exe->ir_functions[it->second];
                owning_symtab = &exe->symbol_table;
                owning_lookup = &exe->ir_lookup;
                owning_funcs = &exe->ir_functions;
                break;
            }
        }
        if (ir_fn) break;
    }

    if (!ir_fn) {
        /* Sin IR disponible (e.g. .velb v2 sin seccion @ir, o
         * fn no encontrada).  No intentamos otra vez en
         * subsequent calls -- marcamos como "fallido" via
         * increment del counter mas alla del threshold para que
         * el check `invocation_count < threshold` no vuelva a
         * disparar.  Workaround simple: setear counter a
         * UINT32_MAX. */
        ++g_jit_no_ir_count;
        if (g_jit_warn_unsupported) {
            std::fprintf(stderr,
                         "[jit] no IR encontrado para metodo '%s' (build sin "
                         "--vx o .velb v2)\n",
                         key.c_str());
        }
        method->invocation_count = UINT32_MAX;
        return;
    }

    /* Init lazy del JIT subsystem. */
    std::call_once(g_jit_init_flag, init_jit_subsystem);

    /* Compilar bajo mutex (el JitRegistry necesita acceso exclusivo
     * + el code cache puede tener races en multi-thread). */
    std::lock_guard<std::mutex> lk(g_compile_mtx);

    /* Doble-check tras adquirir el lock (otro thread podria haber
     * compilado mientras nosotros esperabamos). */
    if (method->jit_code != nullptr) return;

    /* Resolver de simbolos del linker (STR_LIT_ADDR / LABEL_ADDR, Phase
     * D.3-H) desde el symbol_table del executable propietario.  Se reusa
     * que lee el camino de registros virtuales. */
    CallResolver mc_sym_res;
    if (owning_symtab != nullptr) {
        const auto *st_ptr = owning_symtab;
        mc_sym_res = [st_ptr](const std::string &n) -> uint64_t {
            auto it = st_ptr->find(n);
            return it == st_ptr->end() ? 0 : it->second;
        };
    }

    /*  D.7: el intento vreg se MOVIO mas abajo (tras construir el
     * resolver recursivo de user-fns + native_resolver) para que un metodo
     * que llama a otra funcion Vesta resuelva la callee por vreg en vez de
     * caer a slots por "call(no-resolver)". */

    /* Phase: compile_with_opts pasando el symbol_table de la
     * executable que poseyo este metodo, para que el mini-parser
     * resuelva @Absolute("X") y los CALLs a __module_init / __new_<X>. */
    JitCompileOptions mc_opts;
    mc_opts.runtime = g_runtime_entries;
    mc_opts.safepoint_handler_addr =
        reinterpret_cast<uint64_t>(g_runtime_entries->safepoint_handler);
    mc_opts.resolve_symbol = mc_sym_res; /* reusa el resolver de arriba */
    /* Resolver native fn (CALLN): obtener acceso al FFI via el
     * Loader del VM owning. */
    /* IC slot reservation: aloca 16 bytes en el code cache (mismo
     * pool RWX) y los zero-init.  El JIT-eated codigo lee/escribe
     * estos bytes pero no los ejecuta. */
    /* IC slots direccionables por call site (C2-cimiento).  PIC de 4
     * entradas x 16 bytes = 64 bytes, cache-line aligned, zero-init.
     * @c get_ic_slot reusa el slot del call site (clave != 0) o aloca uno
     * fresco (clave 0). */
    mc_opts.reserve_ic_slot = [](uint64_t key) -> uint64_t {
        return get_ic_slot(key);
    };
    /* El contador del nivel dos lo emite el prologo del camino de registros
     * virtuales y viaja en VregEntries (ver mas abajo), no en estas opciones.
     */
    ffi::FFI *ffi_ptr = &owning_vm.loader_public.ffi_loader;
    auto native_resolver = [ffi_ptr](const std::string &name) -> uint64_t {
        size_t colon = name.find(':');
        if (colon == std::string::npos) return 0;
        std::string lib = name.substr(0, colon);
        std::string func = name.substr(colon + 1);
        /* Sprint JIT-cross-fn 2026-06-01: virtual lib registry FIRST.
         * Permite resolver libs in-process como "vesta_runtime",
         * "vesta_comptime" via punteros C registrados sin pasar por
         * LoadLibrary.  Bloqueante para callbacks B.1 (el thunk
         * generator vive en `vx_get_native_thunk` virtual fn). */
        void *vfn = ffi::lookup_virtual_fn(lib, func);
        if (vfn != nullptr) {
            return reinterpret_cast<uint64_t>(vfn);
        }
        try {
            void *mod = ffi_ptr->load_native_module(lib);
            if (!mod) return 0;
            void *fn = ffi_ptr->resolve_native_symbol(mod, func);
            return reinterpret_cast<uint64_t>(fn);
        } catch (...) {
            return 0;
        }
    };
    mc_opts.resolve_native_fn = native_resolver;
    /* lectura de vm_mem en compile-time para inlining.
     * Permite que el JIT lea el valor cacheado en @c s_<X>
     * (typically @c ClassInfo*) durante el compile de @c __new_<X>
     * y emita @c mov rN, imm64 directo en lugar de @c vrt_vm_read_u64
     * en cada iteracion.  El proceso (vm) tiene el static_data del
     * .velb ya cargado al momento del JIT compile (poblado por
     * @c __module_init durante el arranque). */
    runtime::ProcessVM *proc_for_read = vm;
    mc_opts.read_vmem_u64 = [proc_for_read](uint64_t vaddr) -> uint64_t {
        try {
            return proc_for_read->vm_mem.read_u64(vaddr);
        } catch (...) {
            return 0;
        }
    };
    /* offsets desde @c ProcessVM* hacia los punteros
     * @c nursery_bump_ y @c nursery_end_ del @c GcHeap embebido.
     * Se computan en runtime via aritmetica de direcciones porque
     * @c GcHeap NO es standard-layout (referencias + vector).  Una
     * vez computados, el JIT los embebe como disp32 en las
     * instrucciones x86-64 del bump-pointer inline. */
    const int64_t nb_off =
        reinterpret_cast<int64_t>(&proc_for_read->gc_heap.nursery_bump_) -
        reinterpret_cast<int64_t>(proc_for_read);
    const int64_t ne_off =
        reinterpret_cast<int64_t>(&proc_for_read->gc_heap.nursery_end_) -
        reinterpret_cast<int64_t>(proc_for_read);
    if (nb_off >= INT32_MIN && nb_off <= INT32_MAX && ne_off >= INT32_MIN &&
        ne_off <= INT32_MAX) {
        mc_opts.nursery_bump_offset = static_cast<int32_t>(nb_off);
        mc_opts.nursery_end_offset = static_cast<int32_t>(ne_off);
        mc_opts.register_alloc_addr =
            reinterpret_cast<uint64_t>(&vrt_register_alloc);
    }
    /* Offset de exc_frame_stack + exc_free_list para inline tryleave
     * (7 instr x86-64 vs ~20-30 de vrt_tryleave call) sin leak. */
    {
        const int64_t exc_off =
            reinterpret_cast<int64_t>(&proc_for_read->exc_frame_stack) -
            reinterpret_cast<int64_t>(proc_for_read);
        const int64_t free_off =
            reinterpret_cast<int64_t>(&proc_for_read->exc_free_list) -
            reinterpret_cast<int64_t>(proc_for_read);
        if (exc_off >= INT32_MIN && exc_off <= INT32_MAX) {
            mc_opts.exc_frame_stack_offset = static_cast<int32_t>(exc_off);
        }
        if (free_off >= INT32_MIN && free_off <= INT32_MAX) {
            mc_opts.exc_free_list_offset = static_cast<int32_t>(free_off);
        }
    }
    /* Direccion absoluta del contador MIPS para JIT.  El proc tiene
     * referencia al scheduler estable durante su vida; su counter
     * vive en una addr fija.  Embebemos directo como imm64 en el
     * codigo emitido. */
    /* Sprint string-perf-6: counter solo se emite si --stats /
     * VESTA_JIT_STATS=1. */
    mc_opts.jit_instr_counter_addr =
        g_jit_emit_instr_counter
            ? reinterpret_cast<uint64_t>(
                  &proc_for_read->scheduler.profiler_jit_instr_counter)
            : 0;
    /* Resolver user-fns: para evitar recursion arbitraria con cycles,
     * usamos cache global g_eager_cache + resolver simple no-recursive
     * (intenta lookup en cache; si no, intenta eager compile de la
     * callee).  Compartido con eager_compile_function. */
    if (owning_lookup != nullptr && owning_funcs != nullptr) {
        const auto *lk_ptr = owning_lookup;
        const auto *fn_ptr = owning_funcs;
        const auto *st_ptr2 = owning_symtab;
        auto ic_reserver_mc = mc_opts.reserve_ic_slot;
        auto vmem_reader_mc = mc_opts.read_vmem_u64;
        const int32_t nb_off_mc = mc_opts.nursery_bump_offset;
        const int32_t ne_off_mc = mc_opts.nursery_end_offset;
        const uint64_t reg_alloc_mc = mc_opts.register_alloc_addr;
        const int32_t exc_off_mc = mc_opts.exc_frame_stack_offset;
        const int32_t exc_free_off_mc = mc_opts.exc_free_list_offset;
        const uint64_t jit_counter_mc = mc_opts.jit_instr_counter_addr;
        mc_opts.resolve_user_fn =
            [lk_ptr, fn_ptr, st_ptr2, native_resolver, ic_reserver_mc,
             vmem_reader_mc, nb_off_mc, ne_off_mc, reg_alloc_mc, exc_off_mc,
             exc_free_off_mc,
             jit_counter_mc](const std::string &n) -> uint64_t {
            auto cit = g_eager_cache.find(n);
            if (cit != g_eager_cache.end()) {
                if (cit->second == EAGER_IN_PROGRESS) return 0;
                return cit->second;
            }
            auto lit = lk_ptr->find(n);
            if (lit == lk_ptr->end() || lit->second >= fn_ptr->size()) {
                g_eager_cache[n] = 0;
                return 0;
            }
            g_eager_cache[n] = EAGER_IN_PROGRESS;
            const ir::IrFunction &child_ir = (*fn_ptr)[lit->second];
            JitCompileOptions child_opts;
            child_opts.runtime = g_runtime_entries;
            child_opts.safepoint_handler_addr = reinterpret_cast<uint64_t>(
                g_runtime_entries->safepoint_handler);
            if (st_ptr2) {
                const auto *sp = st_ptr2;
                child_opts.resolve_symbol =
                    [sp](const std::string &x) -> uint64_t {
                    auto i2 = sp->find(x);
                    return i2 == sp->end() ? 0 : i2->second;
                };
            }
            child_opts.resolve_native_fn = native_resolver;
            child_opts.reserve_ic_slot = ic_reserver_mc;
            child_opts.read_vmem_u64 = vmem_reader_mc;
            child_opts.nursery_bump_offset = nb_off_mc;
            child_opts.nursery_end_offset = ne_off_mc;
            child_opts.register_alloc_addr = reg_alloc_mc;
            child_opts.exc_frame_stack_offset = exc_off_mc;
            child_opts.exc_free_list_offset = exc_free_off_mc;
            child_opts.jit_instr_counter_addr = jit_counter_mc;
            size_t vc_size = 0;
            std::vector<LineMapEntry> vc_lines;
            uint8_t *vc =
                vreg_compile(child_ir, *g_code_cache, {}, make_vreg_entries(),
                             native_resolver, child_opts.resolve_symbol,
                             &vc_size, &vc_lines);
            if (vc != nullptr) {
                const uint64_t a = reinterpret_cast<uint64_t>(vc);
                g_eager_cache[n] = a;
                ++g_jit_compiled_count;
                if (st_ptr2) {
                    auto sit = st_ptr2->find("code." + n);
                    if (sit != st_ptr2->end() && sit->second != 0) {
                        register_jit_code_at_pc(sit->second,
                                                reinterpret_cast<void *>(vc),
                                                vc_size, &vc_lines);
                    }
                }
                if (g_jit_warn_unsupported)
                    std::fprintf(stderr,
                                 "[jit-vreg] eager callee compilado '%s'\n",
                                 n.c_str());
                return a;
            }
            /* Si el camino de registros virtuales no sabe con esta llamada, se
             * devuelve 0: quien llama vera la llamada sin resolver y se ira
             * tambien al interprete, que siempre es correcto. */
            g_eager_cache[n] = 0;
            ++g_jit_unsupported_count;
            return 0;
        };
    }

    /* Auto-PGO del JIT (opt-in VESTA_JIT_PGO): re-decide la if-conversion de
     * esta funcion caliente con el perfil de branches MEDIDO en runtime.  El
     * JIT sigue VM-independiente: la re-optimizacion solo lee ir::g_branch_
     * profile (datos planos); el UNICO acceso a la VM es el bridge que mapea
     * PC->linea con el debug_info (aqui, en el glue que si tiene la VM). */
    ir::IrFunction pgo_clone;
    const ir::IrFunction *compile_ir = ir_fn;
    if (g_tier2_recompiling) {
        /* Tier-2: g_branch_profile ya lo poblo maybe_tier2 desde los contadores
         * NATIVOS por linea (g_jit_line_ctrs).  Solo re-if-convertimos. */
        pgo_clone = *ir_fn;
        bool any = ir::ir_pass_if_conversion(pgo_clone);
        any = ir::ir_pass_select_simplify(pgo_clone) || any;
        if (any) compile_ir = &pgo_clone;
        if (g_jit_warn_unsupported)
            std::fprintf(stderr,
                         "[jit-pgo] tier-2 '%s': re-if-conversion %s (perfil "
                         "nativo medido)\n",
                         key.c_str(), any ? "cambio el IR" : "sin cambio");
    } else if (runtime::profile::lite_profile_active()) {
        /* Tier-1: bridge del profiler ligero del interp (PC->linea via
         * debug_info).  Util cuando el metodo corrio en interp (tier-0). */
        const int applied = runtime::profile::profile_apply_branch_lines(
            [&](uint64_t pc) -> uint32_t {
                for (const auto &exe : owning_vm.loader_public.executables) {
                    if (!exe || !exe->debug_info) continue;
                    auto info =
                        exe->debug_info->lookup_line(static_cast<uint32_t>(pc));
                    if (info.found && info.line > 0) return info.line;
                }
                return 0;
            });
        pgo_clone = *ir_fn;
        bool any = ir::ir_pass_if_conversion(pgo_clone);
        any = ir::ir_pass_select_simplify(pgo_clone) || any;
        if (any) compile_ir = &pgo_clone;
        if (g_jit_warn_unsupported && applied > 0)
            std::fprintf(stderr,
                         "[jit-pgo] '%s': %d lineas de perfil medido, "
                         "re-if-conversion %s\n",
                         key.c_str(), applied,
                         any ? "cambio el IR" : "sin cambio");
    }

    /* Compilar por el camino de registros virtuales, con el resolvedor
     * recursivo y el de nativas ya construidos (mc_opts): las llamadas a otras
     * funciones Vesta se resuelven y compilan por el mismo camino. */
    {
        /* Exponer el MethodInfo al vreg para que su prologo emita el contador
         * tier-2 (inc [&method->invocation_count] + call tier2_request).  Se
         * limpia tras compilar.  En tier-2 (g_tier2_recompiling) el vreg NO
         * emite el contador (el codigo optimizado final no re-cuenta). */
        g_vreg_compiling_method = method;
        VregEntries vent = make_vreg_entries();
        if (!g_tier2_recompiling && jit::jit_branch_prof_emit_enabled()) {
            /* Emitir el contador tier-2 en el prologo: cuenta invocaciones (sea
             * cual sea el llamante: interp, vrt_callvirt, o dispatch inline
             * nativo) y dispara la recompilacion al cruzar el umbral. */
            const uint64_t d = jit_tier2_delta();
            uint64_t thr = static_cast<uint64_t>(g_jit_threshold) + d;
            if (thr >= UINT32_MAX) thr = UINT32_MAX - 1;
            vent.tier2_request =
                reinterpret_cast<uint64_t>(&jit_tier2_request_entry);
            vent.tier2_ctr_addr =
                reinterpret_cast<uint64_t>(&method->invocation_count);
            vent.tier2_method_ptr = reinterpret_cast<uint64_t>(method);
            vent.tier2_threshold = static_cast<uint32_t>(thr);
        }
        size_t vcode_size = 0;
        std::vector<LineMapEntry> vcode_lines;
        uint8_t *vcode = vreg_compile(
            *compile_ir, *g_code_cache, mc_opts.resolve_user_fn, vent,
            mc_opts.resolve_native_fn, mc_sym_res, &vcode_size, &vcode_lines);
        g_vreg_compiling_method = nullptr;
        if (vcode != nullptr) {
            method->jit_code = reinterpret_cast<void *>(vcode);
            if (method->code_vaddr != 0)
                register_jit_code_at_pc(method->code_vaddr,
                                        reinterpret_cast<void *>(vcode),
                                        vcode_size, &vcode_lines);
            ++g_jit_compiled_count;
            if (g_jit_warn_unsupported)
                std::fprintf(stderr, "[jit-vreg] compilado '%s'\n",
                             key.c_str());
            return;
        }
        if (g_jit_warn_unsupported)
            std::fprintf(stderr, "[jit-vreg] '%s' no soportada -> interp\n",
                         key.c_str());
        /* Un metodo que el camino de registros virtuales no sabe compilar se
         * queda en el INTERPRETE, que siempre es correcto.  Aqui no hay ningun
         * caso que necesite codigo nativo si o si: los callbacks nunca pasan
         * por esta funcion, van por compile_native_callback.
         *
         * Y se marca para NO REINTENTARLO.  Quien lo marcaba era la rama del
         * selector jubilado; cuando esa rama dejo de ejecutarse, la marca se
         * fue con ella, y como el contador de invocaciones solo sube, a partir
         * del umbral se volvia a intentar la compilacion entera en CADA
         * llamada a un metodo que nunca iba a compilar. */
        ++g_jit_unsupported_count;
        method->invocation_count = UINT32_MAX;
    }
}

/** @brief Metodo que se esta compilando por maybe_compile_method AHORA mismo
 *  (para que el prologo del vreg pueda emitir el contador tier-2 con la
 *  direccion de su invocation_count).  nullptr fuera de maybe_compile_method o
 *  para compilaciones sin MethodInfo (eager por-nombre, callbacks). */
loader::MethodInfo *g_vreg_compiling_method = nullptr;

/** @brief Entry-point del prologo tier-2 (lo llama el codigo JIT-eado).  Recibe
 *  (proc, method_ptr) en la convencion C nativa; dispara la recompilacion. */
extern "C" void jit_tier2_request_entry(void *proc,
                                        uint64_t method_ptr) noexcept {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
    auto *method = reinterpret_cast<loader::MethodInfo *>(method_ptr);
    if (vm && method) maybe_tier2_method(vm, method);
}

void tier2_tick(runtime::ProcessVM *vm, loader::MethodInfo *method) noexcept {
    /* Se llama desde el fast-path de CALLVIRT (metodo ya JIT-eado) SOLO cuando
     * el guard barato de alli paso.  Cuenta invocaciones tras tier-1 y dispara
     * la recompilacion tier-2 al cruzar el delta dinamico.  Vive aqui (TU
     * separada) para no engordar exec_instr_callvirt (hacerlo inline alli hacia
     * caer el linker del DLL). */
    if (!jit::jit_branch_prof_emit_enabled()) return;
    if (method->invocation_count == UINT32_MAX) return;
    if (++method->invocation_count >=
        static_cast<uint64_t>(g_jit_threshold) + jit_tier2_delta()) {
        maybe_tier2_method(vm, method);
    }
}

void maybe_tier2_method(runtime::ProcessVM *vm,
                        loader::MethodInfo *method) noexcept {
    if (method == nullptr || method->jit_code == nullptr) return;
    if (!jit::jit_branch_prof_emit_enabled()) return;
    {
        std::lock_guard<std::mutex> lk(g_tier2_mtx);
        if (g_tier2_done.count(method)) return;
        g_tier2_done.insert(method);
    }

    /* Localizar el IR del metodo (mismo mangling que maybe_compile_method). */
    auto sx = [](const loader::stringx &s) -> std::string {
        if (!s.data || s.size == 0) return {};
        return std::string(reinterpret_cast<const char *>(s.data), s.size);
    };
    std::string key;
    if (method->owner_class) {
        const std::string cls = sx(method->owner_class->name);
        if (!cls.empty()) key += cls + "__";
    }
    key += sx(method->name);
    std::vector<std::string> keys{key};
    if (method->owner_class) {
        const std::string cls = sx(method->owner_class->name);
        if (!cls.empty() && cls == sx(method->name))
            keys.push_back(cls + "__ctor");
    }
    runtime::VM &owning_vm = vm->scheduler.vm_reference;
    const ir::IrFunction *ir_fn = nullptr;
    for (const auto &exe : owning_vm.loader_public.executables) {
        for (const auto &k : keys) {
            auto it = exe->ir_lookup.find(k);
            if (it != exe->ir_lookup.end() &&
                it->second < exe->ir_functions.size()) {
                ir_fn = &exe->ir_functions[it->second];
                break;
            }
        }
        if (ir_fn) break;
    }
    if (!ir_fn) return; // sin IR -> no se puede re-optimizar

    /* Poblar g_branch_profile desde los contadores NATIVOS por linea: para cada
     * BR_COND del IR, leer g_jit_line_ctrs[line & mask] (que el codigo tier-1
     * incremento en runtime) y fijar P(mispredict) = min/total.
     * VM-independiente (clave = source_line del IR, sin PC ni debug_info). */
    uint64_t total_samples = 0;
    for (const auto &blk : ir_fn->blocks) {
        if (blk.instrs.empty()) continue;
        const ir::IrInstr &term = blk.instrs.back();
        if (term.op != ir::IrOp::BR_COND || term.source_line == 0) continue;
        const uint32_t idx = term.source_line & jit::kJitLineMask;
        const uint32_t tk = jit::g_jit_line_ctrs[idx].taken;
        const uint32_t nt = jit::g_jit_line_ctrs[idx].not_taken;
        const uint64_t tot = static_cast<uint64_t>(tk) + nt;
        if (tot == 0) continue;
        total_samples += tot;
        const uint32_t minor = tk < nt ? tk : nt;
        const double p = static_cast<double>(minor) / static_cast<double>(tot);
        ir::set_branch_profile_entry(term.source_line, p);
    }
    if (total_samples == 0) return; // sin datos medidos -> nada que re-decidir

    /* Recompilar con el perfil nativo: forzar jit_code=null, activar la bandera
     * tier-2 (el bloque PGO de maybe_compile_method solo re-if-convierte, sin
     * re-volcar), y re-compilar.  Si falla, restaurar el codigo tier-1. */
    void *old_code = method->jit_code;
    const uint32_t old_ic = method->invocation_count;
    method->jit_code = nullptr;
    method->invocation_count = g_jit_threshold; // permite el path de compile
    g_tier2_recompiling = true;
    maybe_compile_method(vm, method);
    g_tier2_recompiling = false;
    if (method->jit_code == nullptr) {
        /* Recompile tier-2 fallo (no deberia: tier-1 compilo) -> conservar el
         * codigo tier-1 valido. */
        method->jit_code = old_code;
        method->invocation_count = old_ic;
    } else {
        /* Tier-2 listo: sentinela UINT32_MAX corta el conteo del fast-path del
         * interp (no mas re-triggers para este metodo). */
        method->invocation_count = UINT32_MAX;
    }
    (void)old_ic;
}

/* ===================================================================== */
/* get_jit_stats_summary                                                  */
/* ===================================================================== */

/* ===================================================================== */
/* eager_compile_function                                                 */
/* ===================================================================== */

/* (g_eager_cache + EAGER_IN_PROGRESS declarados arriba en namespace
 * anonimo para que maybe_compile_method tambien los pueda usar
 * sin forward-decls feos.) */

CompileResult eager_compile_function(
    const ir::IrFunction &ir_fn,
    const std::unordered_map<std::string, size_t> *ir_lookup,
    const std::vector<ir::IrFunction> *ir_functions,
    const std::unordered_map<std::string, uint64_t> *symbol_table,
    std::function<uint64_t(const std::string &)> resolve_native_fn,
    std::function<uint64_t(uint64_t)> read_vmem_u64,
    int32_t exc_frame_stack_offset, int32_t exc_free_list_offset,
    uint64_t jit_instr_counter_addr, JitFactBase *hechos, bool callback_entry,
    uint64_t callback_get_proc_addr, int32_t callback_tls_gs_disp) {
    /* @Target("mode:jit"): si el modulo trae una variante para el JIT, se
     * compila SU cuerpo bajo la identidad de la funcion pedida.  El interprete
     * sigue ejecutando la del nombre desnudo y ningun punto de llamada cambia:
     * el reemplazo ocurre al instalar el codigo nativo.
     *
     * La decision de que version usa cada motor vive en el CODIGO, con
     * @Target; aqui solo se le hace caso. */
    const ir::IrFunction *ir_elegida = &ir_fn;
    if (ir_lookup != nullptr && ir_functions != nullptr) {
        const std::string nombre_jit =
            ir_fn.name + std::string(kSufijoVarianteJit);
        auto itv = ir_lookup->find(nombre_jit);
        if (itv != ir_lookup->end() && itv->second < ir_functions->size()) {
            ir_elegida = &(*ir_functions)[itv->second];
        }
    }
    /* Init lazy de threshold desde env (1 vez por proceso). */
    std::call_once(g_env_init_flag, init_threshold_from_env);

    /* Si JIT esta off, no compilar. */
    if (g_jit_threshold == UINT32_MAX) {
        return CompileResult{};
    }

    /* Init lazy del JIT subsystem. */
    std::call_once(g_jit_init_flag, init_jit_subsystem);

    /* Compilar bajo el mismo mutex que maybe_compile_method (el
     * JitRegistry necesita acceso exclusivo). */
    std::lock_guard<std::mutex> lk(g_compile_mtx);

    /* Si ya esta cacheado, retornar el ptr (excepto sentinelas).
     * En modo callback NO usamos g_eager_cache para el top-level: su
     * ABI (entry nativo) difiere del VM_ABI que la cache by-name asume;
     * confundirlos daria un caller VM_ABI saltando a un entry nativo.
     *
     * Este corte va ANTES de mirar nada del cuerpo: lo que ya esta compilado no
     * se vuelve a estudiar.  La variante @Target ya esta elegida, y la
     * especializacion no cambia el nombre, asi que la clave es la misma que
     * tendria despues. */
    if (!callback_entry && !ir_elegida->name.empty()) {
        auto it = g_eager_cache.find(ir_elegida->name);
        if (it != g_eager_cache.end() && it->second != 0 &&
            it->second != EAGER_IN_PROGRESS) {
            CompileResult cached{};
            cached.fn = reinterpret_cast<JitFn>(it->second);
            return cached;
        }
    }

    /* Especializacion por lo que se sabe AQUI.
     *
     * Una llamada no es una caja negra: si su cuerpo esta en el modulo y en
     * este punto se conocen sus argumentos, meter el cuerpo y plegar las
     * constantes deja SOLO el camino que ese caso recorre -- sin las ramas que
     * ya no pueden darse.  Vale para CUALQUIER funcion, no para una en
     * concreto: lo que cambia por sitio son los hechos que se conocen.
     *
     * Una reserva entra por la misma puerta: es una llamada al asignador del
     * programa, solo que escrita como instruccion.  Convertirla la mete en el
     * mismo mecanismo, y ahi el asignador se especializa como cualquier otra
     * -- siguiendo ademas a quien lo sustituya con @AllocatorOverride, cosa
     * que el atajo escrito a mano en el generador de codigo no puede hacer.
     *
     * Es el mismo bucle de inline + constantes que ya usan el OSR y la
     * devirtualizacion. */
    ir::IrFunction esp_clone;
    if (!callback_entry && ir_lookup != nullptr && ir_functions != nullptr &&
        !jit_sin_especializar_reservas()) {
        /* Que cuerpos hacen falta: los de las llamadas de esta funcion, mas el
         * del asignador si reserva memoria. */
        std::unordered_set<std::string> quiero;
        bool reserva = false;
        for (const auto &bb : ir_elegida->blocks)
            for (const auto &in : bb.instrs) {
                if (in.op == ir::IrOp::RAW_ALLOC)
                    reserva = true;
                else if (in.op == ir::IrOp::CALL && !in.func_name.empty())
                    quiero.insert(in.func_name);
            }
        if (reserva) quiero.insert("__vx_malloc");
        std::vector<size_t> cuerpos;
        for (const auto &nom : quiero) {
            auto it2 = ir_lookup->find(nom);
            if (it2 != ir_lookup->end() && it2->second < ir_functions->size())
                cuerpos.push_back(it2->second);
        }
        const bool hay_asignador =
            reserva && ir_lookup->count("__vx_malloc") != 0;

        /* Y AHORA el criterio: solo merece la pena si de los argumentos se
         * sabe algo que permita podar.  Sin eso, meter el cuerpo solo engorda
         * el codigo -- medido: la reserva pasaba de 199 a 293 ms al inlinar un
         * asignador cuyas ramas no dependen del tamano sino de que hay en la
         * lista libre, que no es un hecho del IR.
         *
         * El hecho no es "es una constante": es que el valor este ACOTADO.  Un
         * tamano que se sabe menor que el tope del slab poda la rama de los
         * bloques grandes aunque no sea constante. */
        bool merece = false;
        {
            /* Regla 1: el consumidor NO construye la base de hechos, la RECIBE.
             * Quien compila el modulo la pasa (@p hechos) y el conocimiento se
             * calcula una vez y se reparte entre todas sus funciones; una
             * compilacion suelta se monta la suya aqui como ultimo recurso,
             * igual que hacen LICM/DSE/planificador cuando nadie les da la
             * tabla points-to.
             *
             * Lo que se pregunta es que se sabe de los argumentos con los que
             * se llega a cada llamada o reserva; la decision -- si eso basta
             * para especializar -- se toma aqui, que es donde se conoce el
             * coste.
             *
             * Falta cruzar mas de un dominio: los rangos dicen lo que vale un
             * ARGUMENTO, no lo que hay en el ESTADO que de verdad decide las
             * ramas del asignador.  Ese hecho existe -- alguien lo sabe -- pero
             * hoy no llega hasta aqui; cuando llegue, es un productor mas sobre
             * esta misma base y este sitio no cambia. */
            JitFactBase propia;
            JitFactBase &base = (hechos != nullptr) ? *hechos : propia;
            const CotasDeLosSitios cotas =
                cotas_de_los_sitios(*ir_elegida, base.ranges(*ir_elegida));
            merece = cotas.hay;
            if (jit_especializar_debug())
                explicar_especializacion(
                    *ir_elegida, cotas, base.seal(kProducerRanges, *ir_elegida),
                    cuerpos.size(), hay_asignador);
        }
        if (merece && !cuerpos.empty() && (hay_asignador || !quiero.empty())) {
            esp_clone = *ir_elegida;
            if (hay_asignador)
                for (auto &bb : esp_clone.blocks)
                    for (auto &in : bb.instrs)
                        if (in.op == ir::IrOp::RAW_ALLOC) {
                            in.op = ir::IrOp::CALL;
                            in.func_name = "__vx_malloc";
                        }
            ir::IrModule tmp;
            tmp.functions.push_back(esp_clone);
            for (size_t idx : cuerpos)
                tmp.functions.push_back((*ir_functions)[idx]);
            for (int it3 = 0; it3 < 5; ++it3) {
                bool any = ir::ir_pass_inline_multiblock(tmp, 256);
                any = ir::ir_pass_inline(tmp, 256) || any;
                any = ir::ir_pass_const_fold(tmp.functions[0]) || any;
                any = ir::ir_pass_copy_prop(tmp.functions[0]) || any;
                any = ir::ir_pass_simplify(tmp.functions[0]) || any;
                any = ir::ir_pass_dce(tmp.functions[0]) || any;
                if (!any) break;
            }
            esp_clone = std::move(tmp.functions[0]);
            ir_elegida = &esp_clone; // se compila la version especializada
        }
    }

    const ir::IrFunction &ir_fn_sel = *ir_elegida;

    /*  D.7 perf-gaps (2026-06-06): el intento vreg top-level se
     * MOVIO mas abajo (tras construir el resolver recursivo de user-fns),
     * para que `main` y cualquier funcion que llame a otras funciones Vesta
     * compile por el path de registros virtuales en vez de caer a slots.
     * Antes este bloque corria aqui con resolve_call = {} (vacio): el
     * primer `IrOp::CALL` a una user-fn hacia bailar el vreg a slots
     * (codegen inferior).  Medido: mem_struct/mem_class/pic_real/callvirt
     * tenian su hot loop en main -> corrian por slots.  Ver el bloque
     * reubicado tras `resolver = *resolver_holder;`. */

    /* Recursive resolver: cuando el Selector encuentra CALL a una
     * funcion user, llama a este callback que (1) chequea cache,
     * (2) busca su IR, (3) recursivamente eager-compila, (4) devuelve
     * la direccion.  Ciclos se cortan con el sentinela IN_PROGRESS:
     * si una funcion B en compilacion llama a A que tambien esta en
     * compilacion (mutua recursion), el inner resolve devuelve 0 y
     * B queda unsupported -- los ciclos en lenguajes user requieren
     * indirect-call-tables ( D.5+). */
    /* Phase: resolver de simbolos via symbol_table del Loader.
     * Resuelve `@Absolute("code.s_K")` strings dentro de raw_asm a su
     * direccion VM absoluta.  Nullptr-safe: si no hay symbol_table,
     * el callback retorna 0 y el mini-parser cae a unsupported para
     * @Absolute refs (backward compatible). */
    std::function<uint64_t(const std::string &)> sym_resolver{};
    if (symbol_table != nullptr) {
        const auto *sym_ptr = symbol_table;
        sym_resolver = [sym_ptr](const std::string &name) -> uint64_t {
            auto it = sym_ptr->find(name);
            if (it == sym_ptr->end()) return 0;
            return it->second;
        };
    }

    std::shared_ptr<std::function<uint64_t(const std::string &)>>
        resolver_holder;
    std::function<uint64_t(const std::string &)> resolver{};
    if (ir_lookup != nullptr && ir_functions != nullptr) {
        const auto *lookup_ptr = ir_lookup;
        const auto *funcs_ptr = ir_functions;
        resolver_holder =
            std::make_shared<std::function<uint64_t(const std::string &)>>();
        /* Cuerpo del resolver: captura su propio shared_ptr para que
         * la recursion pueda referenciar el mismo callback en cada
         * nivel.  Esto permite resolucion arbitrariamente profunda
         * sin perder el callback. */
        auto ic_reserver = [](uint64_t key) -> uint64_t {
            return get_ic_slot(key);
        };
        *resolver_holder =
            [lookup_ptr, funcs_ptr, resolver_holder, sym_resolver,
             resolve_native_fn, ic_reserver, read_vmem_u64,
             exc_frame_stack_offset, exc_free_list_offset,
             jit_instr_counter_addr](const std::string &name) -> uint64_t {
            /* Chequear cache primero. */
            auto cit = g_eager_cache.find(name);
            if (cit != g_eager_cache.end()) {
                if (cit->second == EAGER_IN_PROGRESS) return 0;
                return cit->second;
            }
            /* Buscar IR de la callee. */
            auto lit = lookup_ptr->find(name);
            if (lit == lookup_ptr->end() || lit->second >= funcs_ptr->size()) {
                g_eager_cache[name] = 0;
                return 0;
            }
            /* Marcar IN_PROGRESS antes de recursar. */
            g_eager_cache[name] = EAGER_IN_PROGRESS;
            /* Recursive compile con el MISMO resolver para que la
             * callee pueda resolver SUS propias user CALLs.  Use
             * shared_ptr capturado para que la lambda inner haga ref
             * a este callback. */
            /* @Target("mode:jit"): mismo criterio que arriba, tambien para los
             * llamados.  Un callee con variante se compila desde SU version de
             * JIT; el interprete sigue ejecutando la del nombre desnudo. */
            const ir::IrFunction *child_sel = &(*funcs_ptr)[lit->second];
            {
                auto itv2 =
                    lookup_ptr->find(name + std::string(kSufijoVarianteJit));
                if (itv2 != lookup_ptr->end() &&
                    itv2->second < funcs_ptr->size())
                    child_sel = &(*funcs_ptr)[itv2->second];
            }
            const ir::IrFunction &child_ir = *child_sel;
            JitCompileOptions opts;
            opts.runtime = g_runtime_entries;
            opts.safepoint_handler_addr = reinterpret_cast<uint64_t>(
                g_runtime_entries->safepoint_handler);
            opts.resolve_user_fn = *resolver_holder; /* SAME resolver */
            opts.resolve_symbol = sym_resolver;      /* propagar  D.3-H */
            opts.resolve_native_fn =
                resolve_native_fn;              /* propagar CALLN resolver */
            opts.reserve_ic_slot = ic_reserver; /* IC slots */
            opts.read_vmem_u64 = read_vmem_u64; /*  D.7.opt inline */
            opts.exc_frame_stack_offset =
                exc_frame_stack_offset; /* inline tryleave */
            opts.exc_free_list_offset = exc_free_list_offset; /* no leak */
            opts.jit_instr_counter_addr =
                jit_instr_counter_addr; /* MIPS counter */
            /* La llamada se compila por el camino de registros virtuales,
             * pasandole el PROPIO resolvedor (recursivo) para que las llamadas
             * de dentro se resuelvan a sus direcciones. */
            size_t vc_size2 = 0;
            std::vector<LineMapEntry> vc_lines2;
            uint8_t *vc = vreg_compile(
                child_ir, *g_code_cache, *resolver_holder, make_vreg_entries(),
                resolve_native_fn, sym_resolver, &vc_size2, &vc_lines2);
            if (vc != nullptr) {
                const uint64_t va = reinterpret_cast<uint64_t>(vc);
                g_eager_cache[name] = va;
                ++g_jit_compiled_count;
                if (sym_resolver) {
                    const uint64_t pc = sym_resolver("code." + name);
                    if (pc != 0)
                        register_jit_code_at_pc(pc,
                                                reinterpret_cast<void *>(vc),
                                                vc_size2, &vc_lines2);
                }
                if (g_jit_warn_unsupported)
                    std::fprintf(stderr,
                                 "[jit-vreg] eager callee compilado '%s'\n",
                                 name.c_str());
                return va;
            }
            /* Si no sabe con ella se devuelve 0: quien llama vera la llamada
             * sin resolver y se ira al interprete tambien. */
            g_eager_cache[name] = 0;
            ++g_jit_unsupported_count;
            return 0;
        };
        resolver = *resolver_holder;
    }

    /* Setup opciones del top-level compile (main). */
    JitCompileOptions top_opts;
    top_opts.runtime = g_runtime_entries;
    top_opts.safepoint_handler_addr =
        reinterpret_cast<uint64_t>(g_runtime_entries->safepoint_handler);
    top_opts.resolve_user_fn = resolver;
    top_opts.resolve_symbol = sym_resolver;
    top_opts.resolve_native_fn = resolve_native_fn;
    top_opts.read_vmem_u64 = read_vmem_u64;
    top_opts.exc_frame_stack_offset = exc_frame_stack_offset;
    top_opts.exc_free_list_offset = exc_free_list_offset;
    top_opts.jit_instr_counter_addr = jit_instr_counter_addr;
    {
        top_opts.reserve_ic_slot = [](uint64_t key) -> uint64_t {
            return get_ic_slot(key);
        };
    }
    /* NOTA C2: NO instrumentamos el contador on-entry en los compiles
     * top-level (eager).  Esas funciones (main + targets de CALLVM) son
     * "address-taken" (su direccion la entrego resolve_user_fn / quedan en
     * g_eager_cache) -> el reclaim de su C1 requeriria redirigir CALLs
     * directas horneadas, que no es seguro en v1.  El C2 tier-up se limita
     * a metodos alcanzados por CALLVIRT (path maybe_compile_method), cuyo
     * C1 SI es reciclable (solo refs de PIC + frames en vuelo).  La
     * generalizacion (tabla de CALL indirecta) es un follow-up. */

    /* callback-ABI: el top-level se compila con entry nativo.  El cuerpo
     * sigue siendo VM_ABI (RBX=proc) -> los callees usan el resolver
     * normal (VM_ABI), solo cambia el entry de esta funcion. */
    /* Como se lee el ProcessVM en un callback -- por TLS directo o llamando al
     * runtime -- viaja en VregCallbackOpts, que es lo que mira quien compila el
     * entry.  Aqui solo se marca que ESTA funcion es un callback. */
    if (callback_entry) top_opts.callback_entry = true;

    /* Marcar IN_PROGRESS antes de compilar para detectar self-recursion.
     * En callback NO tocamos g_eager_cache (su ABI difiere del VM_ABI). */
    if (!callback_entry && !ir_fn_sel.name.empty()) {
        g_eager_cache[ir_fn_sel.name] = EAGER_IN_PROGRESS;
    }

    /*  D.7 perf-gaps (2026-06-06): intento vreg top-level CON el
     * resolver recursivo de user-fns ya construido.  Ahora `main` (y
     * cualquier funcion con `IrOp::CALL` a otra funcion Vesta) compila por
     * el path de registros virtuales en vez de bailar a slots al primer
     * call.  El resolver compila recursivamente las callees y devuelve su
     * direccion; los CALLs del vreg emiten `CALL addr` directo.
     *
     * El path vreg NO conoce el modo callback (entry nativo); en callback
     * forzamos el path del Selector (slots + regalloc rewrite) que SI lo
     * implementa. */
    if (!callback_entry) {
        size_t vcode_size = 0;
        std::vector<LineMapEntry> vcode_lines;
        uint8_t *vcode = vreg_compile(ir_fn_sel, *g_code_cache, resolver,
                                      make_vreg_entries(), resolve_native_fn,
                                      sym_resolver, &vcode_size, &vcode_lines);
        if (vcode != nullptr) {
            if (!ir_fn_sel.name.empty())
                g_eager_cache[ir_fn_sel.name] =
                    reinterpret_cast<uint64_t>(vcode);
            /* NOTA: el registro pc->jit lo hace el caller
             * (maybe_compile_callvm_target) desde el CompileResult; no lo
             * duplicamos aqui para no registrar compiles degenerados. */
            /* --- OSR 2c: precompilar una variante C2-con-OSR-entry por cada
             * loop que el C1 acaba de detectar para esta funcion.  El C1
             * (vreg_compile arriba) registro sus back-edges en
             * regalloc_rewrite (loop_ids + header_block).  Aqui, con los
             * MISMOS resolvers, compilamos el C2 con OSR-entry y guardamos
             * su direccion en g_osr_entry_map[loop_id].  El handler de
             * runtime hace lookup -> dispara el frame-swap.  No-op si OSR
             * esta off (osr_loop_count()==0).  Plano (sin opt) en 2c; la
             * optimizacion del C2 es el paso siguiente. */
            if (!ir_fn_sel.name.empty()) {
                const uint32_t nloops = osr_loop_count();
                for (uint64_t lid = 0; lid < nloops; ++lid) {
                    if (g_osr_entry_map.count(lid)) continue; // ya precompilado
                    std::string fnm;
                    uint32_t hdr = 0;
                    if (!osr_loop_info(lid, fnm, hdr)) continue; // abortado/oob
                    if (fnm != ir_fn_sel.name) continue;         // otra funcion
                    /* Red de seguridad: los vids que el C1 capturo al buffer.
                     * El OSR-entry del C2 solo puede leer estos (si su live-in
                     * pide otro, vreg_compile_osr aborta -> no swap). */
                    std::vector<uint32_t> captured;
                    osr_loop_captures(lid, captured);

                    /* --- PASO 4: C2 OPTIMIZADO ---
                     * Inline AGRESIVO de las CALLs del loop caliente (el
                     * code-size no importa: el loop domina el tiempo).  O2
                     * dejo helpers como CALL por su threshold conservador
                     * (12); aqui subimos a 256 -> elimina el CALL + el
                     * marshalling VM_ABI de args por memoria.  Block ids
                     * preservados (el inline esplicea single-block en sitio)
                     * -> el header_block del C1 sigue valido.  Gate
                     * VESTA_OSR_OPT=0 -> recompile plano (para A/B). */
                    const ir::IrFunction *compile_ir = &ir_fn_sel;
                    ir::IrFunction opt_clone;
                    if (osr_opt_enabled() && ir_lookup != nullptr &&
                        ir_functions != nullptr) {
                        opt_clone = ir_fn_sel; /* clon mutable */
                        ir::IrModule tmp;
                        tmp.functions.push_back(opt_clone);
                        /* Anadir las user-fns que el loop llama (para inline).
                         */
                        std::unordered_set<std::string> added;
                        for (const auto &blk : opt_clone.blocks)
                            for (const auto &in2 : blk.instrs)
                                if (in2.op == ir::IrOp::CALL &&
                                    !in2.func_name.empty() &&
                                    !added.count(in2.func_name)) {
                                    auto cl = ir_lookup->find(in2.func_name);
                                    if (cl != ir_lookup->end() &&
                                        cl->second < ir_functions->size()) {
                                        tmp.functions.push_back(
                                            (*ir_functions)[cl->second]);
                                        added.insert(in2.func_name);
                                    }
                                }
                        /* Inline agresivo + limpieza a fixpoint. */
                        bool any_opt = false;
                        for (int it = 0; it < 5; ++it) {
                            bool any = ir::ir_pass_inline(tmp, 256);
                            any =
                                ir::ir_pass_const_fold(tmp.functions[0]) || any;
                            any =
                                ir::ir_pass_copy_prop(tmp.functions[0]) || any;
                            any = ir::ir_pass_simplify(tmp.functions[0]) || any;
                            any = ir::ir_pass_dce(tmp.functions[0]) || any;
                            any_opt = any_opt || any;
                            if (!any) break;
                        }
                        opt_clone = std::move(tmp.functions[0]);
                        compile_ir = &opt_clone;
                        if (g_jit_warn_unsupported && any_opt)
                            std::fprintf(
                                stderr,
                                "[jit-osr] C2 optimizado (inline agresivo) "
                                "para loop %llu (fn '%s')\n",
                                static_cast<unsigned long long>(lid),
                                ir_fn_sel.name.c_str());
                    }

                    uint8_t *osr_entry = nullptr;
                    uint8_t *c2 = vreg_compile_osr(
                        *compile_ir, *g_code_cache, resolver,
                        make_vreg_entries(), resolve_native_fn, sym_resolver,
                        hdr, &osr_entry, &captured);
                    if (c2 != nullptr && osr_entry != nullptr) {
                        g_osr_entry_map[lid] =
                            reinterpret_cast<uint64_t>(osr_entry);
                        if (g_jit_warn_unsupported)
                            std::fprintf(
                                stderr,
                                "[jit-osr] C2-entry para loop %llu (fn '%s', "
                                "header bb%u) @ %p\n",
                                static_cast<unsigned long long>(lid),
                                ir_fn_sel.name.c_str(), hdr,
                                static_cast<void *>(osr_entry));
                    } else if (g_jit_warn_unsupported) {
                        std::fprintf(
                            stderr,
                            "[jit-osr] loop %llu (fn '%s') no precompilo C2 "
                            "(unsupported o live-in mismatch)\n",
                            static_cast<unsigned long long>(lid),
                            ir_fn_sel.name.c_str());
                    }
                }
            }
            CompileResult r{};
            r.fn = reinterpret_cast<JitFn>(vcode);
            r.code_start = vcode;
            /* OJO: no se rellena @c r.code_size.  Quien recibe este resultado
             * lo usa como senal de que hay una region C1 que puede reciclar al
             * subir de nivel, y darsela aqui hacia que reciclara codigo que
             * seguia en uso.  La extension se apunta abajo, directamente, que
             * es para lo que hace falta.
             *
             * Y queda registrada su extension nativa.  Hasta ahora esto solo
             * lo hacia quien compila por una llamada; una funcion compilada de
             * antemano -- `main`, sin ir mas lejos -- no entraba en el mapa, y
             * un fallo dentro de ella no se podia atribuir a nadie. */
            if (symbol_table != nullptr && !ir_fn_sel.name.empty()) {
                auto sit = symbol_table->find("code." + ir_fn_sel.name);
                // El punto de entrada puede figurar sin el prefijo de seccion.
                if (sit == symbol_table->end())
                    sit = symbol_table->find(ir_fn_sel.name);
                if (sit != symbol_table->end())
                    register_jit_region(sit->second,
                                        reinterpret_cast<void *>(vcode),
                                        vcode_size, &vcode_lines);
            }
            if (g_jit_warn_unsupported)
                std::fprintf(stderr, "[jit-vreg] eager compilado '%s'\n",
                             ir_fn_sel.name.c_str());
            return r;
        }
        if (g_jit_warn_unsupported)
            std::fprintf(stderr,
                         "[jit-vreg] '%s' no soportada (eager) -> slots\n",
                         ir_fn_sel.name.c_str());
    }

    /* Jubilacion slots (A3): en el compile top-level (eager), un NO-callback
     * que el vreg no compilo NO cae a slots -> corre en interp (correcto).  Los
     * CALLBACKS (callback_entry) SI necesitan una direccion de codigo NATIVO
     * (va a una API C: qsort/Win32/CRT) -> el interprete no es un puntero de fn
     * valido, asi que siguen usando el selector-slots como unica via hasta que
     * el vreg cubra su subset (fase A4).  VESTA_JIT_VREGS=0 reactiva slots. */
    /* Jubilacion slots (A4): compilar el callback por el PATH VREG (default).
     * El subset vreg-callback cubre leaf/no-hoja (save-set) + args por reg y
     * pila + retorno float + params f64.  Lo que aun no cubre (call-fallback
     * sin TLS = Linux, params f32, SIMD >8B) BAILA a slots (abajo).
     * VESTA_VREG_CALLBACKS=0 fuerza slots para todos (A/B testing). */
    static const bool g_vreg_callbacks =
        util::flag_on(util::FlagId::VregCallbacks);
    if (callback_entry && g_vreg_callbacks) {
        VregCallbackOpts cbopts;
        cbopts.callback_entry = true;
        cbopts.get_proc_addr = callback_get_proc_addr;
        cbopts.tls_gs_disp = callback_tls_gs_disp;
        uint8_t *vcode = vreg_compile_callback(ir_fn_sel, *g_code_cache, cbopts,
                                               resolver, make_vreg_entries(),
                                               resolve_native_fn, sym_resolver);
        if (vcode != nullptr) {
            if (g_jit_warn_unsupported)
                std::fprintf(stderr, "[jit-vreg] callback compilado '%s'\n",
                             ir_fn_sel.name.c_str());
            CompileResult r{};
            r.fn = reinterpret_cast<JitFn>(vcode);
            r.code_start = vcode;
            return r;
        }
        /* Un callback que el vreg no compila queda SIN codigo nativo (el
         * selector-slots esta retirado): `as_native_callback` entrega 0 y el
         * programa muere al invocarlo.  No damos por hecho la causa -- el
         * mensaje anterior afirmaba "SIMD>8B o argc>12", y cuando la causa era
         * otra (una op sin cubrir, un simbolo sin resolver) mandaba a
         * investigar al sitio equivocado.  `VESTA_JIT_VREGS_DEBUG=1` imprime el
         * motivo real que decidio el selector. */
        std::fprintf(stderr,
                     "[jit] callback '%s': el selector vreg no lo compila -> "
                     "sin codigo nativo (as_native_callback devolvera 0).\n"
                     "  motivo exacto: ejecuta con VESTA_JIT_VREGS_DEBUG=1\n",
                     ir_fn_sel.name.c_str());
    }

    /* Jubilacion slots (borrado): el selector-slots esta retirado.  El
     * top-level de un no-callback que el vreg no compilo cae a interp
     * (res.unsupported); un callback sin codigo vreg queda sin fn (arriba). */
    CompileResult res;
    res.fn = nullptr;
    res.unsupported = true;
    if (res.fn != nullptr) {
        ++g_jit_compiled_count;
        /* callback-ABI: NO cachear by-name ni registrar en el pc-map (su
         * entry es nativo, no VM_ABI).  El caller cachea por fn_pc en su
         * propia tabla.  Los callees (VM_ABI) ya se registraron normal. */
        if (!callback_entry && !ir_fn_sel.name.empty()) {
            g_eager_cache[ir_fn_sel.name] = reinterpret_cast<uint64_t>(res.fn);
        }
        /* D.5-callvm-hook: registrar pc -> jit en el mapa global. */
        if (!callback_entry && sym_resolver && !ir_fn_sel.name.empty()) {
            const uint64_t pc = sym_resolver("code." + ir_fn_sel.name);
            if (pc != 0) {
                register_jit_code_at_pc(pc, reinterpret_cast<void *>(res.fn));
            }
        }
        if (g_jit_disasm) {
            debug_dump_jit_code(ir_fn_sel.name.empty() ? "<anon>"
                                                       : ir_fn_sel.name,
                                res.code_start, res.code_size);
        }
    } else {
        ++g_jit_unsupported_count;
        if (!callback_entry && !ir_fn_sel.name.empty()) {
            g_eager_cache[ir_fn_sel.name] = 0; /* cachear failure */
        }
    }
    return res;
}

/* ===================================================================== */
/* debug_dump_jit_code (debugging aid)                         */
/* ===================================================================== */
void debug_dump_jit_code(const std::string &name, const uint8_t *code,
                         size_t code_size) {
    if (!code || code_size == 0) {
        std::fprintf(stderr, "[jit disasm] '%s': codigo vacio\n", name.c_str());
        return;
    }
    std::fprintf(stderr, "[jit disasm] === %s (%zu bytes @ %p) ===\n",
                 name.c_str(), code_size, static_cast<const void *>(code));
    /* Hex dump compacto: 16 bytes por linea con offset. */
    for (size_t i = 0; i < code_size; i += 16) {
        std::fprintf(stderr, "  %04zx:", i);
        for (size_t j = 0; j < 16 && i + j < code_size; ++j) {
            std::fprintf(stderr, " %02x", code[i + j]);
        }
        std::fprintf(stderr, "\n");
    }
    /* Disasm via Capstone (x86-64). */
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::fprintf(stderr, "[jit disasm] cs_open fallo\n");
        return;
    }
    // VESTA_JIT_DISASM_REGS=1: detalle de acceso a registros (implicitos
    // incluidos) para verificar el modelo de efectos del scheduler.
    const bool regs = util::flag_on(util::FlagId::JitDisasmRegs);
    cs_option(handle, CS_OPT_DETAIL, regs ? CS_OPT_ON : CS_OPT_OFF);
    cs_insn *insn = nullptr;
    const size_t count = cs_disasm(handle, code, code_size,
                                   reinterpret_cast<uint64_t>(code), 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; ++i) {
            std::fprintf(stderr, "  %p: %-10s %-24s",
                         reinterpret_cast<void *>(insn[i].address),
                         insn[i].mnemonic, insn[i].op_str);
            if (regs && insn[i].detail) {
                cs_regs rd, wr;
                uint8_t nrd = 0, nwr = 0;
                if (cs_regs_access(handle, &insn[i], rd, &nrd, wr, &nwr) == 0) {
                    std::fprintf(stderr, " R[");
                    for (uint8_t k = 0; k < nrd; ++k)
                        std::fprintf(stderr, "%s ", cs_reg_name(handle, rd[k]));
                    std::fprintf(stderr, "] W[");
                    for (uint8_t k = 0; k < nwr; ++k)
                        std::fprintf(stderr, "%s ", cs_reg_name(handle, wr[k]));
                    std::fprintf(stderr, "]");
                }
            }
            std::fprintf(stderr, "\n");
        }
        cs_free(insn, count);
    } else {
        std::fprintf(stderr, "  (Capstone no pudo desensamblar)\n");
    }
    cs_close(&handle);
    std::fprintf(stderr, "[jit disasm] === fin %s ===\n", name.c_str());
}

std::string get_jit_stats_summary() {
    std::ostringstream oss;
    oss << "[jit stats] threshold=";
    if (g_jit_threshold == UINT32_MAX) {
        oss << "(disabled)";
    } else {
        oss << g_jit_threshold;
    }
    oss << "  compiled=" << g_jit_compiled_count
        << "  unsupported=" << g_jit_unsupported_count
        << "  no_ir=" << g_jit_no_ir_count;
    return oss.str();
}

/* ===================================================================== */
/* Sprint D.5-callvm-trigger: counter por PC + auto-compile en CALLVM     */
/* ===================================================================== */
/*
 * Diseño: similar a maybe_compile_method pero parametrizado por PC en
 * lugar de MethodInfo*.  El hook en exec_instr_callvm llama a este
 * helper en cada CALLVM cuyo target NO esta en el pc-map; cuando el
 * counter cruza el threshold, busca la IR correspondiente al PC y la
 * compila via @c eager_compile_function (que reusa el pipeline
 * recursivo: callees se compilan transitively).
 *
 * Counter por PC: @c unordered_map<uint64_t, uint32_t>.  Valor sentinela
 * UINT32_MAX = "ya intentado y fallo" (no reintentar -- evita oscilar
 * compile/fail/recompile en loops calientes con funciones unsupported).
 *
 * Reverse symbol_table (pc -> name): construido lazy por executable;
 * cacheado en @c g_exec_pc_to_name por puntero del executable.  El
 * symbol_table del .velb tiene entries "code.<fn_name>" -> pc; el
 * cache invierte y strip el prefijo "code.".
 */
namespace {
std::unordered_map<uint64_t, uint32_t> g_callvm_counters;
std::unordered_map<uint64_t, uint8_t>
    g_callvm_attempts; /* JIT-cross-fn 2026-06-01 */
std::mutex g_callvm_mtx;
/* Sprint JIT-cross-fn counter cache reintentos:
 * Cuando un compile attempt falla, en lugar de marcar
 * `cnt = UINT32_MAX` permanente, registramos un attempt count.
 * El proximo intento ocurre tras RETRY_INTERVAL invocaciones
 * adicionales.  Tras MAX_ATTEMPTS fails, queda como cached
 * failure final (UINT32_MAX).  Asi cuando una fn falla por
 * contexto temporal (e.g. dep callee no estaba compilada
 * todavia), reintentar puede tener exito si el contexto
 * cambia entre invocaciones (ahora callee ya esta JIT-eada). */
constexpr uint32_t kCompileRetryInterval = 1000;
constexpr uint8_t kCompileMaxAttempts = 3;
/* pc -> name (lazy por executable).  Key: puntero al Executable.  */
std::unordered_map<const void *, std::unordered_map<uint64_t, std::string>>
    g_exec_pc_to_name;
} // namespace

/* Forward decl: definida mas abajo (interfaz publica). */
void maybe_compile_callvm_target(runtime::ProcessVM *vm,
                                 uint64_t target_pc) noexcept;

/* ===================================================================== */
/* Sprint D.5-callvm-hook: mapa pc -> jit_code                              */
/* ===================================================================== */
/*
 * Diseño:
 *   - @c g_pc_jit_active es un flag rapido (lectura sin lock) que el hot
 *     path de @c exec_instr_callvm consulta antes de tocar el mapa.
 *     Falso por defecto = cero overhead cuando JIT esta off.
 *   - El mapa @c g_pc_to_jit_code esta protegido por @c g_pc_jit_mtx
 *     porque la compilacion puede correr en paralelo a la ejecucion
 *     en  D.8 (multi-thread compile).  Hoy single-thread compile,
 *     pero el mutex no hace daño y prepara la transicion.
 *   - El flag NUNCA se resetea (incluso si limpiamos el mapa para
 *     tests).  El coste es 1 hashmap lookup extra por callvm tras un
 *     reset, despreciable.
 */
bool g_pc_jit_active = false;
namespace {
std::mutex g_pc_jit_mtx;
std::unordered_map<uint64_t, void *> g_pc_to_jit_code;
/// Extension del codigo nativo de cada funcion registrada: direccion virtual
/// -> [inicio, inicio+tamano).  Solo se rellena cuando el tamano consta; sirve
/// para saber, ante un fallo en codigo nativo, en que funcion cayo.
struct RegionNativa {
    uint64_t inicio;
    uint64_t tamano;
    /// Donde cambia la linea del fuente dentro del codigo: pares
    /// (desplazamiento, linea) ORDENADOS y sin repetir la linea anterior.
    /// Guardar una entrada por instruccion maquina seria varias veces mas
    /// grande sin decir nada nuevo; asi son unas pocas decenas por funcion.
    std::vector<std::pair<uint32_t, uint32_t>> lineas;
};
std::unordered_map<uint64_t, RegionNativa> g_pc_to_region;
} // namespace

void register_jit_region(uint64_t vaddr, void *fn, size_t code_size,
                         const std::vector<LineMapEntry> *line_map) noexcept {
    /* SOLO la extension, sin tocar a donde despacha una llamada.
     *
     * Son dos cosas distintas y hay sitios donde solo se puede apuntar una: el
     * compilado por adelantado deja codigo que el llamante decide si usar, de
     * modo que meterlo en el mapa de despacho cambia a donde va una llamada --
     * y eso rompio un programa.  Para explicar un fallo basta con saber que
     * trozo de memoria ocupa cada funcion.
     *
     * La direccion 0 se apunta igual: el codigo empieza ahi, asi que es la
     * direccion legitima del punto de entrada. */
    if (!fn || code_size == 0) return;
    RegionNativa r{reinterpret_cast<uint64_t>(fn), (uint64_t)code_size, {}};
    if (line_map != nullptr) {
        uint32_t ultima = 0;
        for (const LineMapEntry &e : *line_map) {
            if (e.source_line == 0 || e.source_line == ultima) continue;
            r.lineas.emplace_back(e.byte_offset, e.source_line);
            ultima = e.source_line;
        }
    }
    std::lock_guard<std::mutex> lk(g_pc_jit_mtx);
    g_pc_to_region[vaddr] = std::move(r);
}

bool lookup_region_by_native_pc(uint64_t native_pc, uint64_t &out_inicio,
                                uint64_t &out_tam) noexcept {
    if (native_pc == 0) return false;
    std::lock_guard<std::mutex> lk(g_pc_jit_mtx);
    for (const auto &kv : g_pc_to_region) {
        if (native_pc < kv.second.inicio) continue;
        if (native_pc - kv.second.inicio >= kv.second.tamano) continue;
        out_inicio = kv.second.inicio;
        out_tam = kv.second.tamano;
        return true;
    }
    return false;
}

bool lookup_line_by_native_pc(uint64_t native_pc, uint32_t &out_line) noexcept {
    /* En que linea del fuente estaba el codigo nativo que fallo.
     *
     * Se busca el ultimo cambio de linea que quede en o antes del punto del
     * fallo: entre dos cambios, la linea es la del primero. */
    if (native_pc == 0) return false;
    std::lock_guard<std::mutex> lk(g_pc_jit_mtx);
    for (const auto &kv : g_pc_to_region) {
        if (native_pc < kv.second.inicio) continue;
        const uint64_t off = native_pc - kv.second.inicio;
        if (off >= kv.second.tamano) continue;
        uint32_t linea = 0;
        for (const auto &p : kv.second.lineas) {
            if (p.first > off) break;
            linea = p.second;
        }
        if (linea == 0) return false;
        out_line = linea;
        return true;
    }
    return false;
}

void register_jit_code_at_pc(
    uint64_t vaddr, void *fn, size_t code_size,
    const std::vector<LineMapEntry> *line_map) noexcept {
    if (!fn) return;
    if (code_size != 0) register_jit_region(vaddr, fn, code_size, line_map);
    if (vaddr == 0) return;
    std::lock_guard<std::mutex> lk(g_pc_jit_mtx);
    g_pc_to_jit_code[vaddr] = fn;
    g_pc_jit_active = true;
    if (g_jit_warn_unsupported) {
        std::fprintf(stderr, "[jit] pc-map register: 0x%llx -> %p\n",
                     static_cast<unsigned long long>(vaddr), fn);
    }
}

bool lookup_vaddr_by_native_pc(uint64_t native_pc,
                               uint64_t &out_vaddr) noexcept {
    /* La busqueda al reves: de una direccion de codigo NATIVO a la funcion
     * que la contiene.
     *
     * Hace falta para explicar un fallo ocurrido dentro de codigo compilado.
     * El codigo nativo no va actualizando el PC de la maquina virtual -- ese
     * es justamente el punto de compilarlo --, asi que al fallar el PC que se
     * conserva es viejo y la traza senalaba la funcion equivocada.  Lo unico
     * fiable es la direccion nativa del fallo, y de ella se llega a la funcion
     * quedandose con la mas alta que no la pase.
     *
     * Se recorre el mapa entero (decenas de entradas) porque esto ocurre una
     * vez, al morir el programa: no compensa mantener una estructura ordenada
     * viva para un caso que no se repite.
     *
     * @param native_pc Direccion donde fallo el codigo nativo.
     * @param[out] out_vaddr Direccion virtual de la funcion que la contiene.
     * @return true si cae dentro de alguna.  Se devuelve aparte del valor
     *         porque 0 es una direccion valida -- el codigo empieza ahi -- y
     *         no puede hacer de "no encontrado".
     */
    if (native_pc == 0) return false;
    std::lock_guard<std::mutex> lk(g_pc_jit_mtx);
    for (const auto &kv : g_pc_to_region) {
        if (native_pc < kv.second.inicio) continue;
        if (native_pc - kv.second.inicio >= kv.second.tamano) continue;
        out_vaddr = kv.first;
        return true;
    }
    /* Si la direccion no cae dentro de ninguna funcion de tamano conocido, NO
     * se adivina por proximidad: atribuir el fallo a la funcion mas cercana
     * por debajo senala una que no tiene nada que ver, que es peor que no
     * decir nada -- quien lee se va a mirar donde no toca. */
    return false;
}

void *lookup_jit_code_at_pc(uint64_t vaddr) noexcept {
    if (!g_pc_jit_active) return nullptr;
    std::lock_guard<std::mutex> lk(g_pc_jit_mtx);
    auto it = g_pc_to_jit_code.find(vaddr);
    return (it == g_pc_to_jit_code.end()) ? nullptr : it->second;
}

void clear_jit_code_at_pc_map() noexcept {
    std::lock_guard<std::mutex> lk(g_pc_jit_mtx);
    g_pc_to_jit_code.clear();
    /* NO reseteamos g_pc_jit_active: el flag es sticky a proposito
     * (ver comentario arriba).  Tests pueden setearlo manualmente. */
}

/* ===================================================================== */
/* Sprint D.5-callvm-trigger: implementacion                              */
/* ===================================================================== */

/**
 * @brief Counter trigger para CALLVM/CALLVMR: cada miss del pc-map
 *        incrementa el counter de ese PC; al cruzar threshold,
 *        intenta compilar la funcion via @c eager_compile_function.
 *
 * Coste fast path (JIT off o counter < threshold): 1 lock + 1 hash
 * lookup + 1 increment = ~30 ns.  Coste slow path (threshold cruzado):
 * el del compile completo (~1-10 ms para funciones tipicas).  Solo
 * paga slow path UNA vez por funcion en toda la ejecucion (tras el
 * compile, el pc-map captura todos los CALLVMs subsiguientes).
 *
 * Sentinela UINT32_MAX en el counter = "ya intentado, fallo".  No
 * reintenta para evitar oscilacion.  Si la funcion era compilable
 * pero el primer intento fallo por race conditions, el usuario debe
 * reiniciar el proceso (caso muy raro).
 */
void maybe_compile_callvm_target(runtime::ProcessVM *vm,
                                 uint64_t target_pc) noexcept {
    std::call_once(g_env_init_flag, init_threshold_from_env);
    if (g_jit_threshold == UINT32_MAX) {
        return;
    }
    /* Si ya esta compilado (otro hilo gano la carrera), salir. */
    if (lookup_jit_code_at_pc(target_pc) != nullptr) return;

    /* SEGURIDAD (sandbox bajo JIT): mismo guard que maybe_compile_method.
     * El codigo CALLVM JIT-eated emite CALLN/CALLNI/spawn/etc. sin el check
     * de capabilities (check_cap_at_pc); dejar la funcion en interp garantiza
     * el enforcement.  Coste cero sin sandbox (branch predicho not-taken). */
    if (vm->scheduler.vm_reference.loader_public.sandbox_active) return;

    /* Acquire mutex para counter + tabla de executables.  Necesario
     * porque maybe_compile_method tambien usa g_compile_mtx; la
     * separacion en mutex distinto (g_callvm_mtx para counters) evita
     * contencion innecesaria entre CALLVM hot path y CALLVIRT path. */
    std::lock_guard<std::mutex> cmlk(g_callvm_mtx);
    auto &cnt = g_callvm_counters[target_pc];
    if (cnt == UINT32_MAX) return; /* cached failure FINAL */
    ++cnt;
    if (cnt < g_jit_threshold) {
        return;
    }

    /* Sprint JIT-cross-fn counter cache reintentos:
     * Determinar si toca compilar AHORA segun attempt count.
     * Attempt #i ocurre cuando cnt = threshold + i * RETRY_INTERVAL. */
    auto &att = g_callvm_attempts[target_pc];
    if (att >= kCompileMaxAttempts) {
        /* Ya agotamos los reintentos -- marcar permanente. */
        cnt = UINT32_MAX;
        return;
    }
    const uint32_t needed =
        g_jit_threshold + static_cast<uint32_t>(att) * kCompileRetryInterval;
    if (cnt < needed) {
        /* Aun no toca el siguiente attempt; warming. */
        return;
    }
    /* Esta es la attempt #(att+1).  Incrementar attempt antes del
     * compile para que reintentos paralelos no entren simultaneo. */
    ++att;

    /* Buscar el IrFunction correspondiente a target_pc iterando los
     * executables del VM.  Construir pc->name lazy por executable. */
    runtime::VM &owning_vm = vm->scheduler.vm_reference;
    const ir::IrFunction *ir_fn = nullptr;
    const loader::Executable *owning_exe = nullptr;
    std::string fn_name;
    for (auto &exe_ptr : owning_vm.loader_public.executables) {
        const loader::Executable *exe = exe_ptr.get();
        /* Construir pc->name lazy (1 vez por executable). */
        auto &pc_to_name = g_exec_pc_to_name[exe];
        if (pc_to_name.empty() && !exe->symbol_table.empty()) {
            for (const auto &kv : exe->symbol_table) {
                /* Solo nos interesan los simbolos "code.<fn_name>".
                 * Stripped el prefijo "code." para matchear con
                 * @c ir_lookup. */
                if (kv.first.rfind("code.", 0) == 0) {
                    pc_to_name[kv.second] = kv.first.substr(5);
                }
            }
        }
        auto pn_it = pc_to_name.find(target_pc);
        if (pn_it == pc_to_name.end()) continue;
        std::string candidate_name = pn_it->second;
        /* Sprint JIT-cross-fn 2026-06-01: el frontend Vesta añade
         * sufijo `_entry_<N>` al label del bytecode (entry block).
         * El ir_lookup usa el nombre limpio.  Strip el sufijo si
         * existe para que el lookup matchee. */
        {
            const std::string suffix = "_entry_";
            auto pos = candidate_name.rfind(suffix);
            if (pos != std::string::npos) {
                /* Confirmar que tras el sufijo solo hay digitos. */
                bool only_digits = true;
                for (size_t k = pos + suffix.size(); k < candidate_name.size();
                     ++k) {
                    if (candidate_name[k] < '0' || candidate_name[k] > '9') {
                        only_digits = false;
                        break;
                    }
                }
                if (only_digits) {
                    candidate_name = candidate_name.substr(0, pos);
                }
            }
        }
        auto lit = exe->ir_lookup.find(candidate_name);
        if (lit == exe->ir_lookup.end()) continue;
        if (lit->second >= exe->ir_functions.size()) continue;
        ir_fn = &exe->ir_functions[lit->second];
        owning_exe = exe;
        fn_name = candidate_name;
        break;
    }

    if (ir_fn == nullptr) {
        /* No hay IR para este PC (e.g. helper sintetico sin nombre,
         * o codigo de runtime que no esta en ir_functions).  Cached
         * failure ya esta en cnt = UINT32_MAX. */
        ++g_jit_no_ir_count;
        return;
    }

    /* Construir callbacks equivalentes a los que loader.cpp pasa al
     * eager_compile inicial.  Reusan ffi_loader del VM + el propio
     * proceso para vm_mem.read_u64 + offsets calculados sobre el
     * propio objeto ProcessVM. */
    ffi::FFI *ffi_ptr = &owning_vm.loader_public.ffi_loader;
    auto resolve_native = [ffi_ptr](const std::string &name) -> uint64_t {
        size_t colon = name.find(':');
        if (colon == std::string::npos) return 0;
        std::string lib = name.substr(0, colon);
        std::string func = name.substr(colon + 1);
        /* Sprint JIT-cross-fn: virtual lib registry FIRST. */
        void *vfn = ffi::lookup_virtual_fn(lib, func);
        if (vfn != nullptr) {
            return reinterpret_cast<uint64_t>(vfn);
        }
        try {
            void *mod = ffi_ptr->load_native_module(lib);
            if (!mod) return 0;
            void *fn = ffi_ptr->resolve_native_symbol(mod, func);
            return reinterpret_cast<uint64_t>(fn);
        } catch (...) {
            return 0;
        }
    };
    runtime::ProcessVM *proc_for_read = vm;
    auto read_vmem_cb = [proc_for_read](uint64_t vaddr) -> uint64_t {
        try {
            return proc_for_read->vm_mem.read_u64(vaddr);
        } catch (...) {
            return 0;
        }
    };
    int32_t exc_off = 0, exc_free_off = 0;
    {
        const int64_t off64 = reinterpret_cast<int64_t>(&vm->exc_frame_stack) -
                              reinterpret_cast<int64_t>(vm);
        const int64_t free64 = reinterpret_cast<int64_t>(&vm->exc_free_list) -
                               reinterpret_cast<int64_t>(vm);
        if (off64 >= INT32_MIN && off64 <= INT32_MAX)
            exc_off = static_cast<int32_t>(off64);
        if (free64 >= INT32_MIN && free64 <= INT32_MAX)
            exc_free_off = static_cast<int32_t>(free64);
    }
    /* Sprint string-perf-6: counter solo se emite si --stats /
     * VESTA_JIT_STATS=1. */
    const uint64_t jit_counter_addr =
        g_jit_emit_instr_counter
            ? reinterpret_cast<uint64_t>(
                  &vm->scheduler.profiler_jit_instr_counter)
            : 0;

    /* Llamar a eager_compile_function que ya hace el trabajo
     * completo: construye el resolver recursivo, registra en
     * pc-map al exito (via mi D.5-callvm-hook), maneja cache,
     * todo.  Si exito, el pc-map captura este PC y todos sus
     * callees transitivamente. */
    try {
        CompileResult __cr = eager_compile_function(
            *ir_fn, &owning_exe->ir_lookup, &owning_exe->ir_functions,
            &owning_exe->symbol_table, resolve_native, read_vmem_cb, exc_off,
            exc_free_off, jit_counter_addr);
        /* BugFix 171 native-callback (2026-06-05): la rama VREG de
         * eager_compile_function registra el codigo SOLO por nombre
         * (g_eager_cache), NO por PC.  El path slot si registra por PC
         * via la registracion top-level, pero el vreg retornaba antes.
         * Sin la entrada pc-map, `lookup_jit_code_at_pc(target_pc)`
         * devuelve null y `as_native_callback` (que busca por PC) genera
         * un thunk=0 -> qsort recibe comparator NULL -> no ordena.
         * Registramos aqui el resultado top-level por PC para cubrir
         * ambos paths (idempotente: register sobrescribe con el mismo fn). */
        if (__cr.fn != nullptr) {
            register_jit_code_at_pc(target_pc,
                                    reinterpret_cast<void *>(__cr.fn));
        }
        /* Independiente del resultado: si exito, register_jit_code_at_pc
         * ya se llamo desde dentro de eager_compile_function via la
         * registracion top-level.  Si fallo, queda como cached failure
         * tanto en g_eager_cache (por nombre) como en cnt (UINT32_MAX). */
        if (g_jit_warn_unsupported) {
            const bool ok = (lookup_jit_code_at_pc(target_pc) != nullptr);
            std::fprintf(stderr,
                         "[jit] callvm-trigger pc=0x%llx name='%s' -> %s\n",
                         static_cast<unsigned long long>(target_pc),
                         fn_name.c_str(), ok ? "compiled" : "unsupported");
        }
    } catch (...) {
        /* Cualquier excepcion del compile se ignora; quedamos en
         * cached failure y futuras invocaciones fallback a interp. */
    }
}

/* ===================================================================== */
/* compile_native_callback: entry de ABI C nativo para callbacks Vesta      */
/* ===================================================================== */

uint64_t compile_native_callback(runtime::ProcessVM *vm,
                                 uint64_t vx_fn_pc) noexcept {
    if (vm == nullptr) return 0;

    /* Cache propia por PC: la misma fn puede tener version VM_ABI (pc-map)
     * y version callback-ABI (esta tabla).  Sentinela 0 = aun no/ fallo. */
    static std::mutex g_cb_mtx;
    static std::unordered_map<uint64_t, uint64_t> g_cb_cache;
    {
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        auto it = g_cb_cache.find(vx_fn_pc);
        if (it != g_cb_cache.end()) return it->second;
    }

    /* Buscar el IrFunction + executable propietario para este PC.
     * Mismo procedimiento que @c maybe_compile_callvm_target. */
    runtime::VM &owning_vm = vm->scheduler.vm_reference;
    const ir::IrFunction *ir_fn = nullptr;
    const loader::Executable *owning_exe = nullptr;
    {
        /* g_exec_pc_to_name esta protegido por g_callvm_mtx (mismo que
         * maybe_compile_callvm_target).  NO usar g_compile_mtx aqui: lo
         * tomara eager_compile_function despues -> deadlock. */
        std::lock_guard<std::mutex> cmlk(g_callvm_mtx);
        for (auto &exe_ptr : owning_vm.loader_public.executables) {
            const loader::Executable *exe = exe_ptr.get();
            auto &pc_to_name = g_exec_pc_to_name[exe];
            if (pc_to_name.empty() && !exe->symbol_table.empty()) {
                for (const auto &kv : exe->symbol_table) {
                    if (kv.first.rfind("code.", 0) == 0) {
                        pc_to_name[kv.second] = kv.first.substr(5);
                    }
                }
            }
            auto pn_it = pc_to_name.find(vx_fn_pc);
            if (pn_it == pc_to_name.end()) continue;
            std::string candidate_name = pn_it->second;
            /* Strip sufijo `_entry_<N>` igual que maybe_compile_callvm_target.
             */
            {
                const std::string suffix = "_entry_";
                auto pos = candidate_name.rfind(suffix);
                if (pos != std::string::npos) {
                    bool only_digits = true;
                    for (size_t k = pos + suffix.size();
                         k < candidate_name.size(); ++k) {
                        if (candidate_name[k] < '0' ||
                            candidate_name[k] > '9') {
                            only_digits = false;
                            break;
                        }
                    }
                    if (only_digits)
                        candidate_name = candidate_name.substr(0, pos);
                }
            }
            auto lit = exe->ir_lookup.find(candidate_name);
            if (lit == exe->ir_lookup.end()) continue;
            if (lit->second >= exe->ir_functions.size()) continue;
            ir_fn = &exe->ir_functions[lit->second];
            owning_exe = exe;
            break;
        }
    }
    if (ir_fn == nullptr || owning_exe == nullptr) {
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        g_cb_cache[vx_fn_pc] = 0;
        return 0;
    }

    /* Callbacks de resolucion identicos a maybe_compile_callvm_target. */
    ffi::FFI *ffi_ptr = &owning_vm.loader_public.ffi_loader;
    auto resolve_native = [ffi_ptr](const std::string &name) -> uint64_t {
        size_t colon = name.find(':');
        if (colon == std::string::npos) return 0;
        std::string lib = name.substr(0, colon);
        std::string func = name.substr(colon + 1);
        void *vfn = ffi::lookup_virtual_fn(lib, func);
        if (vfn != nullptr) return reinterpret_cast<uint64_t>(vfn);
        try {
            void *mod = ffi_ptr->load_native_module(lib);
            if (!mod) return 0;
            void *fn = ffi_ptr->resolve_native_symbol(mod, func);
            return reinterpret_cast<uint64_t>(fn);
        } catch (...) {
            return 0;
        }
    };
    runtime::ProcessVM *proc_for_read = vm;
    auto read_vmem_cb = [proc_for_read](uint64_t vaddr) -> uint64_t {
        try {
            return proc_for_read->vm_mem.read_u64(vaddr);
        } catch (...) {
            return 0;
        }
    };
    int32_t exc_off = 0, exc_free_off = 0;
    {
        const int64_t off64 = reinterpret_cast<int64_t>(&vm->exc_frame_stack) -
                              reinterpret_cast<int64_t>(vm);
        const int64_t free64 = reinterpret_cast<int64_t>(&vm->exc_free_list) -
                               reinterpret_cast<int64_t>(vm);
        if (off64 >= INT32_MIN && off64 <= INT32_MAX)
            exc_off = static_cast<int32_t>(off64);
        if (free64 >= INT32_MIN && free64 <= INT32_MAX)
            exc_free_off = static_cast<int32_t>(free64);
    }
    const uint64_t jit_counter_addr =
        g_jit_emit_instr_counter
            ? reinterpret_cast<uint64_t>(
                  &vm->scheduler.profiler_jit_instr_counter)
            : 0;

    /* Resolver TLS-direct (Win64) o fallback por call para LOAD_PROC.  El
     * fallback usa el STUB que preserva los arg-regs alrededor del call a
     * get_current_executing_process (sin el, el call borraria los args del
     * callback antes del marshalling). */
    const uint64_t getproc_addr = cb_preserving_get_proc();
    int32_t tls_gs_disp = -1;
#if defined(_WIN32)
    /* VESTA_CB_FORCE_CALL=1: fuerza el fallback por call (para validar el stub
     * en Windows, donde normalmente hay TLS-direct). */
    static const bool force_call = util::flag_on(util::FlagId::CbForceCall);
    if (!force_call) {
        const unsigned long idx = runtime::jit_proc_tls_index();
        if (idx != 0xFFFFFFFFu && idx < 64) {
            tls_gs_disp = static_cast<int32_t>(0x1480u + idx * 8u);
        }
    }
#endif

    /* El callback REQUIERE codigo nativo AHORA (su direccion va a Win32/
     * qsort).  Forzar el compile aunque el JIT este desactivado por flag
     * (-m vm): salvar/forzar/restaurar el threshold global, como hacia el
     * wrapper del thunk previo. */
    uint64_t result = 0;
    try {
        const uint32_t saved_thr = g_jit_threshold;
        if (saved_thr == UINT32_MAX) set_jit_threshold(1);
        CompileResult cr = eager_compile_function(
            *ir_fn, &owning_exe->ir_lookup, &owning_exe->ir_functions,
            &owning_exe->symbol_table, resolve_native, read_vmem_cb, exc_off,
            exc_free_off, jit_counter_addr, /*hechos=*/nullptr,
            /*callback_entry=*/true, getproc_addr, tls_gs_disp);
        if (saved_thr == UINT32_MAX) set_jit_threshold(saved_thr);
        result = cr.fn ? reinterpret_cast<uint64_t>(cr.fn) : 0;
        if (g_jit_warn_unsupported) {
            std::fprintf(stderr, "[jit] native-callback pc=0x%llx -> %s\n",
                         static_cast<unsigned long long>(vx_fn_pc),
                         result ? "compiled" : "unsupported");
        }
    } catch (...) {
        result = 0;
    }

    std::lock_guard<std::mutex> lk(g_cb_mtx);
    g_cb_cache[vx_fn_pc] = result;
    return result;
}

/* ===================================================================== */
/* C2 reclaim: quiescencia (enter_jit) + drain del free-list             */
/* ===================================================================== */

namespace {
/* Devuelve las regiones C1 pendientes al free-list del CodeCache.
 * Solo se invoca con g_jit_active_frames == 0 (ningun frame JIT en
 * pila nativa) -> las regiones son inalcanzables (PIC limpiado,
 * dispatch reapuntado a C2, frames en vuelo drenados). */
void drain_pending_free() {
    std::lock_guard<std::mutex> lk(g_compile_mtx);
    size_t freed = 0;
    if (!g_pending_free.empty() && g_code_cache != nullptr) {
        for (auto &r : g_pending_free) {
            g_code_cache->free_region(r.first, r.second);
            ++freed;
        }
    }
    g_pending_free.clear();
    g_pending_free_count.store(0, std::memory_order_release);
    if (g_c2_log && freed != 0) {
        std::fprintf(stderr,
                     "[c2] reclaim: %zu region(es) C1 liberada(s) al free-list "
                     "(quiescencia); free-list ahora = %zu\n",
                     freed, g_code_cache->free_region_count());
    }
}
} // namespace

void jit_frame_enter() noexcept {
    g_jit_active_frames.fetch_add(1, std::memory_order_acq_rel);
}

void jit_frame_exit() noexcept {
    /* fetch_sub devuelve el valor PREVIO; == 1 significa que acabamos de
     * dejarlo en 0 -> instante sin ningun frame JIT en pila.  Si hay
     * regiones pendientes, es seguro reciclarlas ahora. */
    if (g_jit_active_frames.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        if (g_pending_free_count.load(std::memory_order_acquire) != 0) {
            drain_pending_free();
        }
    }
}

/* ===================================================================== */
/* C2 tier-up: recompile-and-swap                                         */
/* ===================================================================== */
/*
 * Invocado por el contador on-entry del codigo C1 al cruzar el umbral.
 * (1) resuelve fn_pc -> IrFunction (igual que maybe_compile_callvm_target),
 * (2) [PoC C2.1/C2.2] lee los IC slots del call site y loguea las clases
 *     observadas (frio / monomorfico / polimorfico / megamorfico) si
 *     VESTA_C2_LOG=1,
 * (3) recompila la funcion por el path Selector con opts C2 (mismas que C1
 *     pero SIN contador -> codigo terminal), reusando los IC slots
 *     calientes; las callees ya estan compiladas (resolver no-recursivo via
 *     g_eager_cache),
 * (4) swap atomico: pc-map (dispatch CALLVM) + method->jit_code (CALLVIRT).
 *
 * El codigo C1 viejo NO se libera (leak aceptable v1, sin use-after-free:
 * los frames en curso y las entradas de PIC que lo referencian siguen
 * siendo validos).  Idempotente via g_tiered_pcs.  El recompile corre en el
 * host stack del frame JIT que disparo el contador; no ejecuta codigo Vesta
 * -> no hay GC ni re-entrancia de compile (g_compile_mtx no lo tiene este
 * thread).
 */
void c2_tier_up(runtime::ProcessVM *vm, uint64_t fn_pc) noexcept {
    if (vm == nullptr || fn_pc == 0) return;
    try {
        /* --- Resolucion pc -> IR (bajo g_callvm_mtx, orden consistente
         *     con maybe_compile_callvm_target). --- */
        runtime::VM &owning_vm = vm->scheduler.vm_reference;
        const ir::IrFunction *ir_fn = nullptr;
        const loader::Executable *owning_exe = nullptr;
        std::string fn_name;
        {
            std::lock_guard<std::mutex> cmlk(g_callvm_mtx);
            for (auto &exe_ptr : owning_vm.loader_public.executables) {
                const loader::Executable *exe = exe_ptr.get();
                auto &pc_to_name = g_exec_pc_to_name[exe];
                if (pc_to_name.empty() && !exe->symbol_table.empty()) {
                    for (const auto &kv : exe->symbol_table) {
                        if (kv.first.rfind("code.", 0) == 0)
                            pc_to_name[kv.second] = kv.first.substr(5);
                    }
                }
                auto pn_it = pc_to_name.find(fn_pc);
                if (pn_it == pc_to_name.end()) continue;
                std::string cand = pn_it->second;
                /* strip sufijo _entry_<N> (igual que las otras rutas). */
                {
                    const std::string suffix = "_entry_";
                    auto pos = cand.rfind(suffix);
                    if (pos != std::string::npos) {
                        bool only_digits = true;
                        for (size_t k = pos + suffix.size(); k < cand.size();
                             ++k)
                            if (cand[k] < '0' || cand[k] > '9') {
                                only_digits = false;
                                break;
                            }
                        if (only_digits) cand = cand.substr(0, pos);
                    }
                }
                auto lit = exe->ir_lookup.find(cand);
                if (lit == exe->ir_lookup.end() ||
                    lit->second >= exe->ir_functions.size())
                    continue;
                ir_fn = &exe->ir_functions[lit->second];
                owning_exe = exe;
                fn_name = cand;
                break;
            }
        }
        if (ir_fn == nullptr || owning_exe == nullptr) return;

        std::lock_guard<std::mutex> lk(g_compile_mtx);
        /* Idempotencia: solo una vez por fn_pc.  La insercion ocurre ya
         * (incluso si saltamos abajo) para que el contador on-entry no
         * vuelva a invocar el handler. */
        if (g_tiered_pcs.count(fn_pc)) return;
        g_tiered_pcs.insert(fn_pc);
        std::call_once(g_jit_init_flag, init_jit_subsystem);

        /* SKIP address-taken: si la direccion de esta funcion fue
         * entregada por resolve_user_fn (esta en g_eager_cache), hay CALLs
         * directas con imm horneado a su C1 que NO podemos redirigir sin
         * recompilar a los callers.  Liberar su C1 seria use-after-free.
         * En v1 NO la subimos a C2 (asi no se crea ningun C1 huerfano ->
         * cero leak).  El target reclaimable son metodos via CALLVIRT
         * (no quedan en g_eager_cache).  La generalizacion (tabla de CALL
         * indirecta) es un follow-up. */
        {
            auto eit = g_eager_cache.find(fn_name);
            if (eit != g_eager_cache.end() && eit->second != 0 &&
                eit->second != EAGER_IN_PROGRESS) {
                if (g_c2_log)
                    std::fprintf(stderr,
                                 "[c2] skip-tier '%s' (address-taken) -- queda "
                                 "C1 (sin leak)\n",
                                 fn_name.c_str());
                return;
            }
        }

        /* --- (2) PoC C2.1/C2.2: leer IC slots + loguear clases. --- */
        if (g_c2_log) {
            auto kit = g_fn_ic_keys.find(fn_pc);
            if (kit == g_fn_ic_keys.end() || kit->second.empty()) {
                std::fprintf(
                    stderr, "[c2] tier-up '%s' (pc=0x%llx): sin IC sites\n",
                    fn_name.c_str(), static_cast<unsigned long long>(fn_pc));
            } else {
                for (uint64_t key : kit->second) {
                    auto sit = g_ic_slots.find(key);
                    if (sit == g_ic_slots.end() || sit->second == 0) continue;
                    const uint64_t *slot =
                        reinterpret_cast<const uint64_t *>(sit->second);
                    int distinct = 0;
                    for (int e = 0; e < 4; ++e)
                        if (slot[e * 2] != 0) ++distinct;
                    const char *kind = (distinct == 0)   ? "frio"
                                       : (distinct == 1) ? "monomorfico"
                                       : (distinct < 4)  ? "polimorfico"
                                                         : "megamorfico";
                    std::fprintf(
                        stderr,
                        "[c2] call site %s:%u -> %s (clases distintas=%d)\n",
                        fn_name.c_str(), static_cast<unsigned>(key & 0xFFu),
                        kind, distinct);
                }
            }
        }

        /* --- (3) recompile C2 por el path Selector (terminal). --- */
        JitCompileOptions c2;
        c2.runtime = g_runtime_entries;
        c2.safepoint_handler_addr =
            reinterpret_cast<uint64_t>(g_runtime_entries->safepoint_handler);
        const auto *st_ptr = &owning_exe->symbol_table;
        c2.resolve_symbol = [st_ptr](const std::string &n) -> uint64_t {
            auto it = st_ptr->find(n);
            return it == st_ptr->end() ? 0 : it->second;
        };
        c2.reserve_ic_slot = [](uint64_t key) -> uint64_t {
            return get_ic_slot(key); /* reusa el PIC caliente */
        };
        ffi::FFI *ffi_ptr = &owning_vm.loader_public.ffi_loader;
        c2.resolve_native_fn = [ffi_ptr](const std::string &name) -> uint64_t {
            size_t colon = name.find(':');
            if (colon == std::string::npos) return 0;
            std::string lib = name.substr(0, colon);
            std::string func = name.substr(colon + 1);
            void *vfn = ffi::lookup_virtual_fn(lib, func);
            if (vfn != nullptr) return reinterpret_cast<uint64_t>(vfn);
            try {
                void *mod = ffi_ptr->load_native_module(lib);
                if (!mod) return 0;
                return reinterpret_cast<uint64_t>(
                    ffi_ptr->resolve_native_symbol(mod, func));
            } catch (...) {
                return 0;
            }
        };
        runtime::ProcessVM *proc = vm;
        c2.read_vmem_u64 = [proc](uint64_t v) -> uint64_t {
            try {
                return proc->vm_mem.read_u64(v);
            } catch (...) {
                return 0;
            }
        };
        /* Callees ya compiladas en C1 -> resolver NO-recursivo via cache. */
        c2.resolve_user_fn = [](const std::string &n) -> uint64_t {
            auto it = g_eager_cache.find(n);
            if (it != g_eager_cache.end() && it->second != 0 &&
                it->second != EAGER_IN_PROGRESS)
                return it->second;
            return 0;
        };
        /* Offsets de nursery + register_alloc para inline de NEWOBJ. */
        {
            const int64_t nb =
                reinterpret_cast<int64_t>(&proc->gc_heap.nursery_bump_) -
                reinterpret_cast<int64_t>(proc);
            const int64_t ne =
                reinterpret_cast<int64_t>(&proc->gc_heap.nursery_end_) -
                reinterpret_cast<int64_t>(proc);
            if (nb >= INT32_MIN && nb <= INT32_MAX && ne >= INT32_MIN &&
                ne <= INT32_MAX) {
                c2.nursery_bump_offset = static_cast<int32_t>(nb);
                c2.nursery_end_offset = static_cast<int32_t>(ne);
                c2.register_alloc_addr =
                    reinterpret_cast<uint64_t>(&vrt_register_alloc);
            }
        }
        /* Offsets de exc para inline de tryleave. */
        {
            const int64_t eo =
                reinterpret_cast<int64_t>(&proc->exc_frame_stack) -
                reinterpret_cast<int64_t>(proc);
            const int64_t fo = reinterpret_cast<int64_t>(&proc->exc_free_list) -
                               reinterpret_cast<int64_t>(proc);
            if (eo >= INT32_MIN && eo <= INT32_MAX)
                c2.exc_frame_stack_offset = static_cast<int32_t>(eo);
            if (fo >= INT32_MIN && fo <= INT32_MAX)
                c2.exc_free_list_offset = static_cast<int32_t>(fo);
        }
        c2.jit_instr_counter_addr =
            g_jit_emit_instr_counter
                ? reinterpret_cast<uint64_t>(
                      &proc->scheduler.profiler_jit_instr_counter)
                : 0;
        /* NO tier_up_* -> el codigo C2 es terminal (no se re-instrumenta). */

        /* --- C2.4: devirt especulativa de los IC sites monomorficos. ---
         * Para cada CALLVIRT cuyo PIC observo EXACTAMENTE 1 clase, emite
         * un guard (clase == T) ? CALL directo : CALLVIRT, e inlinea el
         * CALL (si el callee es 1-bloque-RET) + plega.  Correcto por
         * construccion: el callee se resuelve de C->vtable[vtbl_idx] con
         * la MISMA C del guard, asi que si el guard pasa el target es
         * exacto; si no, cae al CALLVIRT original. */
        const ir::IrFunction *compile_target = ir_fn;
        ir::IrFunction spec_clone;
        {
            /* ordinal -> (dst, vtbl_idx) recorriendo los CALLVIRT en el
             * mismo orden en que el Selector asigno las claves de IC. */
            std::vector<std::pair<ir::IrValueId, uint64_t>> cv_by_ord;
            for (const auto &bb : ir_fn->blocks)
                for (const auto &ins : bb.instrs)
                    if (ins.op == ir::IrOp::CALLVIRT)
                        cv_by_ord.push_back({ins.dst, ins.imm});

            std::vector<ir::SpecDevirtSite> sites;
            std::unordered_set<std::string> callee_names;
            auto kit2 = g_fn_ic_keys.find(fn_pc);
            if (kit2 != g_fn_ic_keys.end()) {
                for (uint64_t key : kit2->second) {
                    const uint32_t ord = static_cast<uint32_t>(key & 0xFFu);
                    if (ord >= cv_by_ord.size()) continue;
                    auto sit = g_ic_slots.find(key);
                    if (sit == g_ic_slots.end() || sit->second == 0) continue;
                    const uint64_t *slot =
                        reinterpret_cast<const uint64_t *>(sit->second);
                    int distinct = 0;
                    uint64_t cptr = 0;
                    for (int e = 0; e < 4; ++e)
                        if (slot[e * 2] != 0) {
                            ++distinct;
                            if (distinct == 1) cptr = slot[e * 2];
                        }
                    if (distinct != 1 || cptr == 0)
                        continue; /* solo monomorfico */
                    const ir::IrValueId cv_dst = cv_by_ord[ord].first;
                    const uint64_t vtbl_idx = cv_by_ord[ord].second;
                    if (cv_dst == ir::IR_NO_VALUE) continue; /* void: sin PHI */
                    loader::ClassInfo *cls =
                        reinterpret_cast<loader::ClassInfo *>(cptr);
                    if (!cls->vtable || vtbl_idx >= cls->vtable_size) continue;
                    loader::MethodInfo *m = cls->vtable[vtbl_idx];
                    if (!m || !m->name.data || m->name.size == 0) continue;
                    std::string cn =
                        (cls->name.data && cls->name.size)
                            ? std::string(reinterpret_cast<const char *>(
                                              cls->name.data),
                                          cls->name.size)
                            : std::string();
                    std::string mn(reinterpret_cast<const char *>(m->name.data),
                                   m->name.size);
                    std::string callee = cn + "__" + mn;
                    /* callee debe existir y ser inlineable (1 bloque, RET):
                     * si no, el CALL del fast-path quedaria sin resolver. */
                    auto cl = owning_exe->ir_lookup.find(callee);
                    if (cl == owning_exe->ir_lookup.end() ||
                        cl->second >= owning_exe->ir_functions.size())
                        continue;
                    const ir::IrFunction &cf =
                        owning_exe->ir_functions[cl->second];
                    if (cf.blocks.size() != 1 || cf.blocks[0].instrs.empty() ||
                        cf.blocks[0].instrs.back().op != ir::IrOp::RET)
                        continue;
                    sites.push_back(ir::SpecDevirtSite{cv_dst, cptr, callee});
                    callee_names.insert(callee);
                }
            }

            if (!sites.empty()) {
                spec_clone = *ir_fn; /* clon mutable */
                if (ir::ir_pass_speculative_devirt(spec_clone, sites)) {
                    ir::IrModule tmp;
                    tmp.functions.push_back(spec_clone);
                    for (const auto &cn : callee_names) {
                        auto cl = owning_exe->ir_lookup.find(cn);
                        if (cl != owning_exe->ir_lookup.end() &&
                            cl->second < owning_exe->ir_functions.size())
                            tmp.functions.push_back(
                                owning_exe->ir_functions[cl->second]);
                    }
                    /* inline del CALL fast-path + limpieza a fixpoint. */
                    for (int it = 0; it < 5; ++it) {
                        bool any = ir::ir_pass_inline(tmp);
                        any = ir::ir_pass_const_fold(tmp.functions[0]) || any;
                        any = ir::ir_pass_copy_prop(tmp.functions[0]) || any;
                        any = ir::ir_pass_simplify(tmp.functions[0]) || any;
                        any = ir::ir_pass_dce(tmp.functions[0]) || any;
                        if (!any) break;
                    }
                    spec_clone = std::move(tmp.functions[0]);
                    compile_target = &spec_clone;
                    if (g_c2_log)
                        std::fprintf(stderr,
                                     "[c2] devirt especulativa: %zu site(s) "
                                     "monomorfico(s) en '%s'\n",
                                     sites.size(), fn_name.c_str());
                }
            }
        }

        /* Compilar el IR especulado.  Por defecto via el Selector (slots);
         * con VESTA_C2_VREG via el path de registros virtuales (regalloc
         * real) -- experimento para medir si el inline rinde cuando los
         * valores viven en registros y no en slots. */
        JitFn c2_fn = nullptr;
        size_t c2_size = 0;
        const uint8_t *c2_code = nullptr;
        bool c2_unsupported = false;
        /* El nivel dos recompila el IR especulado por el mismo camino que el
         * JIT normal: registros virtuales con asignador de verdad. */
        {
            ffi::FFI *ffi2 = &owning_vm.loader_public.ffi_loader;
            auto nat_res = [ffi2](const std::string &name) -> uint64_t {
                size_t colon = name.find(':');
                if (colon == std::string::npos) return 0;
                std::string lib = name.substr(0, colon);
                std::string func = name.substr(colon + 1);
                void *vfn = ffi::lookup_virtual_fn(lib, func);
                if (vfn) return reinterpret_cast<uint64_t>(vfn);
                try {
                    void *m = ffi2->load_native_module(lib);
                    if (!m) return 0;
                    return reinterpret_cast<uint64_t>(
                        ffi2->resolve_native_symbol(m, func));
                } catch (...) {
                    return 0;
                }
            };
            auto user_res = [](const std::string &n) -> uint64_t {
                auto it = g_eager_cache.find(n);
                if (it != g_eager_cache.end() && it->second != 0 &&
                    it->second != EAGER_IN_PROGRESS)
                    return it->second;
                return 0;
            };
            /* Se pide tambien el TAMANO: quien lo rellenaba era la rama del
             * selector jubilado, asi que sin esto c2_size se quedaba a cero y
             * el volcado de VESTA_JIT_DISASM del nivel dos -- que exige
             * tamano != 0 -- no salia nunca. */
            uint8_t *vc = vreg_compile(*compile_target, *g_code_cache, user_res,
                                       make_vreg_entries(), nat_res,
                                       c2.resolve_symbol, &c2_size);
            if (vc != nullptr) {
                c2_fn = reinterpret_cast<JitFn>(vc);
                c2_code = vc;
            }
        }
        /* Si el recompile por registros virtuales (arriba) no produjo codigo,
         * la funcion se queda en el nivel uno -- ver el "queda C1" de abajo. */
        if (c2_fn == nullptr) {
            /* No se pudo recompilar (alguna op sin contexto recursivo).
             * Queda C1; g_tiered_pcs evita reintentos. */
            if (g_c2_log)
                std::fprintf(
                    stderr,
                    "[c2] recompile '%s' fallo (unsupported=%d) -- queda C1\n",
                    fn_name.c_str(), c2_unsupported ? 1 : 0);
            return;
        }

        /* --- (4) swap + reclaim sin leak. ---
         *
         * (a) Capturar el entry C1 (lo que el PIC cachea) ANTES del swap.
         * (b) Reapuntar dispatch a C2: pc-map (CALLVM) + method->jit_code
         *     (CALLVIRT).  Son stores de puntero; los lectores ven C1 o C2,
         *     ambos validos.
         * (c) Invalidar las entradas de PIC que cachean C1: poner SOLO el
         *     class_ptr a 0 (store de 8 bytes alineado = atomico en x86).
         *     Un lector concurrente del PIC o (i) ve class=0 -> miss ->
         *     re-popula con C2, o (ii) ve la class vieja -> carga el code
         *     viejo (C1, AUN VIVO) -> lo llama sin crash.  NO tocamos el
         *     campo code; el class=0 ya basta para que nadie nuevo entre.
         * (d) Encolar la region C1 a pending-free; se LIBERA recien en la
         *     quiescencia (g_jit_active_frames==0, drain en jit_frame_exit)
         *     cuando NO hay frames en vuelo -> ningun lector la ejecuta y
         *     ningun frame la tiene en pila.  Cero leak, cero
         *     use-after-free. */
        auto mit = g_pc_to_method.find(fn_pc);
        loader::MethodInfo *method =
            (mit != g_pc_to_method.end()) ? mit->second : nullptr;
        const uint64_t old_code =
            method ? reinterpret_cast<uint64_t>(method->jit_code)
                   : reinterpret_cast<uint64_t>(lookup_jit_code_at_pc(fn_pc));

        register_jit_code_at_pc(fn_pc, reinterpret_cast<void *>(c2_fn));
        if (method) method->jit_code = reinterpret_cast<void *>(c2_fn);

        /* (c) invalidar entradas de PIC == old_code (class_ptr -> 0). */
        if (old_code != 0) {
            for (auto &kv : g_ic_slots) {
                uint64_t *slot = reinterpret_cast<uint64_t *>(kv.second);
                if (slot == nullptr) continue;
                for (int e = 0; e < 4; ++e) {
                    if (slot[e * 2 + 1] == old_code) {
                        slot[e * 2] = 0; /* class_ptr: future miss -> C2 */
                    }
                }
            }
        }

        /* (d) encolar la region C1 para reciclar en la quiescencia. */
        auto rit = g_c1_region.find(fn_pc);
        if (rit != g_c1_region.end()) {
            g_pending_free.push_back(rit->second);
            g_pending_free_count.store(g_pending_free.size(),
                                       std::memory_order_release);
            g_c1_region.erase(rit);
        }

        ++g_c2_tierup_count;
        if (g_c2_log) {
            std::fprintf(stderr,
                         "[c2] tier-up '%s' (pc=0x%llx) -> C2 (%zu bytes, "
                         "vreg); C1 a free-list pendiente\n",
                         fn_name.c_str(),
                         static_cast<unsigned long long>(fn_pc), c2_size);
        }
        if (g_jit_disasm && c2_code != nullptr && c2_size != 0) {
            debug_dump_jit_code(fn_name + " [C2]", c2_code, c2_size);
        }
    } catch (...) {
        /* Cualquier fallo deja la funcion en C1 (correcto). */
    }
}

} // namespace jit
