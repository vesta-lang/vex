/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/auto_jit.h
 * @brief Auto-JIT trigger: cuando un metodo se invoca
 *        repetidamente, busca su IR en el Loader y lo JIT-compila.
 *
 * = Threshold =
 *
 * El threshold global @c g_jit_threshold controla cuantas invocaciones
 * deben acumular antes de disparar la compilacion JIT.  Default:
 * @c UINT32_MAX (JIT desactivado).  El usuario lo configura via:
 *   - Env var @c VESTA_JIT_THRESHOLD=N (al inicio de la VM).
 *   - CLI flag @c --jit-threshold N (futuro).
 *   - API runtime @c set_jit_threshold(N) (testing).
 *
 * Threshold tipico: 100-1000.  Demasiado bajo = compile overhead supera
 * la ganancia del JIT (programas que no son hot pagan compile time
 * extra).  Demasiado alto = JIT nunca se dispara para loops cortos.
 */

#ifndef VESTA_JIT_AUTO_JIT_H
#define VESTA_JIT_AUTO_JIT_H

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace runtime {
class ProcessVM;
}
namespace loader {
struct MethodInfo;
}
namespace ir {
struct IrFunction;
}

namespace jit {
struct LineMapEntry; ///< correlacion codigo-nativo <-> linea (machine_ir.h)
}

namespace jit {

/**
 * @brief Threshold global de invocaciones para auto-JIT.
 *        Default: UINT32_MAX (JIT desactivado).
 */
extern uint32_t g_jit_threshold;

/**
 * @brief Configura el threshold runtime (para tests / CLI flag).
 */
void set_jit_threshold(uint32_t threshold) noexcept;

/**
 * @brief Fuerza la lectura del env var @c VESTA_JIT_THRESHOLD (+ warn +
 *        disasm) AHORA, en lugar de esperar al primer @c maybe_compile_*.
 *
 * Llamado por @c main al inicio para que la eager-compile pass del
 * Loader vea el threshold del env var (sin esta llamada, threshold
 * sigue siendo UINT32_MAX hasta que un callvirt/callvm trigger la
 * inicializacion lazy, momento en que la oportunidad de eager compile
 * ya paso).
 *
 * Idempotente: usa @c std::call_once internamente.  Llamadas
 * subsiguientes son no-op. */
void init_threshold_from_env_now() noexcept;

/* ===================================================================== */
/* Sistema de warnings para depuracion del JIT                            */
/* ===================================================================== */

/**
 * @brief Si true, el Selector imprime a stderr cada vez que encuentra
 *        una IR op no soportada, indicando funcion + op + linea fuente.
 *
 * Activado via env var @c VESTA_JIT_WARN_UNSUPPORTED=1 al inicio de
 * la VM.  Util para depurar por que una funcion concreta no se
 * JIT-compila ("ah, usa DIV que aun no implemente").
 *
 * Default: false (sin warnings, debug discretamente).
 */
extern bool g_jit_warn_unsupported;

/**
 * @brief Sprint string-perf-6: gate del MIPS counter per-block en JIT.
 * Default false; main.cpp lo activa cuando se pasa --stats o
 * VESTA_JIT_STATS=1.  Sin esto el JIT no emite las 2 instrs
 * `mov rax, imm64; add [rax], N` per block, ahorrando ~3 ns per
 * block ejecutado.  En hot loops con muchos bloques pequenos
 * (e.g. branch_unpredict) la diferencia llega al 30-50% del wall.
 */
extern bool g_jit_emit_instr_counter;

/**
 * @brief Si true, tras cada compilacion exitosa se imprime a stderr
 *        el dump de las MInstrs generadas + el disasm hex/asm del
 *        codigo nativo via Capstone.  Activado por env var
 *        @c VESTA_JIT_DISASM=1.  Default: false.
 *
 * Util para depurar comportamiento incorrecto del JIT (e.g. crash
 * tras un compile exitoso): permite ver exactamente que bytes se
 * emitieron y donde el codigo nativo se desvia de lo esperado.
 */
extern bool g_jit_disasm;

/**
 * @brief Dumpea a stderr los bytes generados + disasm Capstone para
 *        una funcion JIT-compilada.  Llamado tras cada compile
 *        exitoso cuando @c g_jit_disasm == true.
 */
void debug_dump_jit_code(const std::string &name, const uint8_t *code,
                         size_t code_size);

/**
 * @brief Counters globales para introspeccion del JIT:
 *   - g_jit_compiled_count: funciones JIT-compiladas exitosamente.
 *   - g_jit_unsupported_count: intentos fallidos por IR op no soportada.
 *   - g_jit_no_ir_count: intentos fallidos por IR no encontrado en
 *     Loader (e.g. .velb v2 sin seccion @ir).
 *
 * Util para auditar % de funciones JIT-eatables en programas reales.
 */
extern uint64_t g_jit_compiled_count;
extern uint64_t g_jit_unsupported_count;
extern uint64_t g_jit_no_ir_count;

/**
 * @brief FN.3: direccion NATIVA de @c __vx_swapctx (context-switch @Naked de
 *        vx_fiber.vx), compilada por el force-eager del grafo de fibra.
 *        El vreg la lee (via @c make_vreg_entries -> VregEntries::swapctx) para
 *        emitir un CALL nativo directo en @c IrOp::SWAPCTX (JIT).  0 = fibras
 *        en JIT no inicializadas (o arquitectura sin backend x86-64).
 */
extern uint64_t g_vx_swapctx_native;

/** @brief El asignador del programa, ya compilado (0 = no hay).  Lo pone el
 *  cargador tras compilarlo; lo lee el selector para saber cual es el monton
 *  y no usar el atajo que replica el de la maquina. */
extern uint64_t g_alloc_del_programa;
/** @brief El que libera, del mismo programa.  Va con el de arriba. */
extern uint64_t g_free_del_programa;

/**
 * @brief FN.3: materializa @c __vx_swapctx (context-switch @Naked) como codigo
 *        NATIVO y deja su direccion en @c g_vx_swapctx_native (idempotente).
 *
 * Es el primer paso del force-eager del grafo de fibra: compila el primitivo de
 * fiber-switch por la via naked (@c compile_naked_native, HOST_LEAF) para que
 * el vreg pueda emitir un CALL nativo directo a el en @c IrOp::SWAPCTX (pieza
 * 3). Arch-guard x86-64: fuera de esa arquitectura no hay asm valido ->
 * devuelve 0 (el llamante deja el grafo de fibra en el interprete con un aviso
 * claro).
 *
 * @param vm  ProcessVM del proceso principal (acceso al Loader/executables).
 * @return la direccion nativa de __vx_swapctx, o 0 si no se pudo compilar.
 */
uint64_t ensure_vx_swapctx_native(runtime::ProcessVM *vm) noexcept;

/**
 * @brief Inicializa el subsistema JIT (idempotente) y devuelve la direccion del
 *        handler de safepoint (@c vrt_safepoint_handler).  La usa el modo CTPE
 *        para activar los polls de watchdog en el codigo precomputado.  0 si el
 *        subsistema no pudo inicializarse.
 */
uint64_t jit_safepoint_handler_addr() noexcept;

/**
 * @brief Activa/desactiva el watchdog CTPE: setea la direccion del handler de
 *        safepoint en la CodeCache global.  Con != 0, el codegen vreg emite un
 *        poll en cada back-edge de las funciones compiladas.  0 = off.  Debe
 *        restaurarse a 0 tras compilar el programa a precomputar.
 */
void jit_set_ctpe_safepoint(uint64_t handler_addr) noexcept;

/**
 * @brief Devuelve un snapshot legible del estado del JIT
 *        (counters + threshold).  Util para printear al final del
 *        programa con @c --jit-stats flag.
 */
std::string get_jit_stats_summary();

/**
 * @brief Maybe compila el metodo si su counter supera el threshold.
 *
 * Llamado por @c exec_instr_callvirt (fast path) en cada invocacion.
 * Coste fast path (threshold no superado): 1 cmp + 1 branch = ~1 ns.
 *
 * Flujo cuando se dispara:
 *   1. Lookup en Loader::executables del @c IrFunction con nombre
 *      @c "<ClassName>__<methodName>".
 *   2. Si encontrado, llama a @c JitCompiler::compile(*ir, VM_ABI).
 *   3. Si exito, @c method->jit_code = result.fn.
 *   4. Proxima invocacion via CALLVIRT despacha al codigo nativo
 *      (hook en exec_instr_callvirt ya implementado en D.3-C).
 *
 * Si la busqueda IR falla (programa sin IR embebido en .velb v2,
 * funcion sin IR por algun caso edge, etc.), @c method->jit_code
 * queda en nullptr y futuras invocaciones reincrementan el counter.
 * Para evitar busquedas repetidas, podriamos marcar method como
 * "JIT-failed" pero por ahora la complejidad no se justifica.
 *
 * @param vm     ProcessVM actual (para acceder a Loader via scheduler).
 * @param method MethodInfo cuyo counter acaba de incrementarse.
 */
void maybe_compile_method(runtime::ProcessVM *vm,
                          loader::MethodInfo *method) noexcept;

/**
 * @brief Auto-PGO tier-2: recompila un metodo ya JIT-eado (tier-1) usando el
 *        perfil de branches MEDIDO en runtime por el propio codigo nativo
 *        (contadores por source_line en @c g_jit_line_ctrs).  Re-decide la
 *        if-conversion con datos reales y hace swap de @c jit_code. Idempotente
 *        (una vez por metodo).  Seguro: ambas versiones son correctas, el swap
 *        solo cambia el layout de branches; las llamadas en curso terminan en
 * el codigo viejo.
 */
void maybe_tier2_method(runtime::ProcessVM *vm,
                        loader::MethodInfo *method) noexcept;

/// @brief Metodo en compilacion por maybe_compile_method (para que el prologo
///        del vreg emita el contador tier-2).  nullptr si no aplica.
extern loader::MethodInfo *g_vreg_compiling_method;

/// @brief Entry del prologo tier-2 (lo llama el codigo JIT-eado).
extern "C" void jit_tier2_request_entry(void *proc,
                                        uint64_t method_ptr) noexcept;

/// @brief Tick del auto-PGO tier-2: cuenta la invocacion de un metodo ya
///        JIT-eado y dispara @c maybe_tier2_method al cruzar el delta.  Vive en
///        su propia TU (no inline en exec_instr_callvirt: hacerlo alli hace
///        caer el linker del DLL por el tamano de esa funcion).
void tier2_tick(runtime::ProcessVM *vm, loader::MethodInfo *method) noexcept;

/* Forward decl de CompileResult (definido en jit_compile_options.h). */
struct CompileResult;

/* La base de hechos del ASA (@c analysis/asa/fact_base.h).  Aqui solo se pasa
 * por puntero, asi que basta declararla: no hace falta arrastrar los dominios
 * de analisis a todo el que incluya esta cabecera.  El nombre corto es el que
 * usan los consumidores del JIT (@c jit/jit_facts.h); no es otro tipo. */
} // namespace jit
namespace analysis {
namespace asa {
class FactBase;
}
} // namespace analysis
namespace jit {
using JitFactBase = analysis::asa::FactBase;

/**
 * @brief Compila una @c IrFunction usando el JIT subsystem (lazy
 *        init si es la primera invocacion).
 *
 * Usado por el Loader para eager-compile de @c main, ya que main
 * no se invoca via CALLVIRT (es free function) y el hook auto-JIT
 * normal no lo dispara.  Si el JIT esta desactivado
 * (@c g_jit_threshold == UINT32_MAX), devuelve @c CompileResult{}
 * sin compilar.
 *
 * @param ir_fn La funcion IR a compilar.
 * @param ir_lookup Mapa nombre -> indice en @p ir_functions.  Si no
 *        es nullptr, habilita el resolver de CALL a user functions
 *        via recursive eager-compile.
 * @param ir_functions Vector con todas las funciones IR del ejecutable.
 *        Usado para resolver llamadas user-fn -> compile + return ptr.
 * @param hechos Base de hechos del modulo (@c jit/jit_facts.h).  Lo que el
 *        compilador sabe del programa, para que sus consumidores -- hoy el
 *        especializador de llamadas -- CONSULTEN en vez de redescubrirlo cada
 *        uno.  Quien compile varias funciones del mismo modulo pasa la misma
 *        base y el conocimiento se reparte.  nullptr = compilacion suelta: el
 *        consumidor se monta la suya como ultimo recurso.
 * @return Resultado de la compilacion (fn=nullptr si fallo o JIT off).
 */
CompileResult eager_compile_function(
    const ir::IrFunction &ir_fn,
    const std::unordered_map<std::string, size_t> *ir_lookup = nullptr,
    const std::vector<ir::IrFunction> *ir_functions = nullptr,
    const std::unordered_map<std::string, uint64_t> *symbol_table = nullptr,
    std::function<uint64_t(const std::string &)> resolve_native_fn = nullptr,
    std::function<uint64_t(uint64_t)> read_vmem_u64 = nullptr,
    int32_t exc_frame_stack_offset = 0, int32_t exc_free_list_offset = 0,
    uint64_t jit_instr_counter_addr = 0, JitFactBase *hechos = nullptr,
    /* callback-ABI (2026-06-06): si @p callback_entry es true, el
     * TOP-LEVEL @p ir_fn se compila con entry de ABI C nativo (callable
     * por qsort/Win32) en vez de VM_ABI.  Sus callees siguen siendo
     * VM_ABI (resolver normal).  El top-level NO se registra en el
     * pc-map ni en @c g_eager_cache (su ABI difiere del VM_ABI). */
    bool callback_entry = false, uint64_t callback_get_proc_addr = 0,
    int32_t callback_tls_gs_disp = -1);

/* ===================================================================== */
/* Sprint D.5-callvm-hook: dispatch interp -> JIT en CALLVM                */
/* ===================================================================== */

/**
 * @brief Flag rapido (fast path): true si HAY al menos una funcion
 *        registrada en el mapa @c pc -> jit_code.  Permite que
 *        @c exec_instr_callvm haga una sola lectura atomic relaxed
 *        antes de tocar el mapa (que requiere lock).
 *
 * Diseño: cuando JIT esta desactivado o no se ha compilado nada,
 * @c g_pc_jit_active == false -> @c exec_instr_callvm evita
 * lookup_jit_code_at_pc completamente.  Tan pronto como una funcion
 * se eager-compila, el flag se setea a true para siempre (no se
 * resetea por invalidate -- el coste de 1 hashmap lookup adicional
 * por callvm tras un invalidate es despreciable).
 */
extern bool g_pc_jit_active;

/**
 * @brief Registra que la funcion en @p vaddr (bytecode VM address)
 *        tiene codigo nativo JIT en @p fn.
 *
 * Llamado tras cada compilacion eager exitosa.  Multiples llamadas
 * con el mismo @p vaddr sobreescriben (caso re-compile tras deopt).
 *
 * @param vaddr Direccion VM del primer byte del bytecode de la funcion.
 * @param fn    Puntero al codigo nativo (calling convention
 *              @c JitFn(vrt_proc*) -> uint64_t).
 */
void register_jit_code_at_pc(
    uint64_t vaddr, void *fn, size_t code_size = 0,
    const std::vector<LineMapEntry> *line_map = nullptr) noexcept;

/**
 * @brief Lookup O(1) amortizado: devuelve el ptr nativo si la funcion
 *        @p vaddr tiene JIT, sino @c nullptr.
 *
 * Llamado por @c exec_instr_callvm en cada invocacion (solo cuando
 * @c g_pc_jit_active == true).  Thread-safe via lock interno.
 *
 * @param vaddr Direccion VM del target del CALLVM.
 * @return      Codigo JIT o @c nullptr.
 */
void *lookup_jit_code_at_pc(uint64_t vaddr) noexcept;

/**
 * @brief De una direccion de codigo NATIVO a la funcion que la contiene.
 *
 * La busqueda al reves de @c lookup_jit_code_at_pc.  Sirve para explicar un
 * fallo ocurrido dentro de codigo compilado: ahi el PC de la maquina virtual
 * no se va actualizando -- ese es el punto de compilar --, de modo que lo
 * unico fiable es la direccion nativa del fallo.
 *
 * @param native_pc Direccion donde fallo el codigo nativo.
 * @param[out] out_vaddr Direccion virtual de la funcion que la contiene.
 * @return true si cae dentro de alguna.  El hallazgo va aparte del valor
 *         porque 0 es una direccion valida y no puede hacer de "no
 *         encontrado".
 */
bool lookup_vaddr_by_native_pc(uint64_t native_pc,
                               uint64_t &out_vaddr) noexcept;

/**
 * @brief Apunta SOLO que trozo de memoria ocupa el codigo de una funcion.
 *
 * Sin tocar a donde despacha una llamada, que es cosa distinta y no siempre se
 * decide en el mismo sitio.  Lo necesita @c lookup_vaddr_by_native_pc para
 * poder atribuir un fallo ocurrido en codigo nativo.
 *
 * @param vaddr Direccion virtual de la funcion (0 es valida: el codigo
 *              empieza ahi).
 * @param fn Inicio de su codigo nativo.
 * @param code_size Cuanto ocupa.
 */
void register_jit_region(
    uint64_t vaddr, void *fn, size_t code_size,
    const std::vector<LineMapEntry> *line_map = nullptr) noexcept;

/**
 * @brief En que linea del fuente estaba el codigo NATIVO que fallo.
 *
 * @param native_pc Direccion del fallo.
 * @param[out] out_line Linea del fuente.
 * @return true si se pudo determinar.
 */
bool lookup_line_by_native_pc(uint64_t native_pc, uint32_t &out_line) noexcept;

/**
 * @brief El trozo de codigo NATIVO que contiene una direccion.
 *
 * Para poder ensenar que se estaba ejecutando de verdad cuando lo que corrio
 * fue codigo compilado: ahi las instrucciones de la maquina virtual no son las
 * que se ejecutaron.
 *
 * @param native_pc Direccion dentro del codigo.
 * @param[out] out_inicio Primer byte del codigo de esa funcion.
 * @param[out] out_tam Cuanto ocupa.
 * @return true si la direccion cae dentro de alguna funcion compilada.
 */
bool lookup_region_by_native_pc(uint64_t native_pc, uint64_t &out_inicio,
                                uint64_t &out_tam) noexcept;

/**
 * @brief Limpia el mapa @c pc -> jit_code (no libera el code cache).
 *        Util para tests; en produccion no se usa.
 */
void clear_jit_code_at_pc_map() noexcept;

/**
 * @brief Sprint D.5-callvm-trigger: dispara la compilacion JIT de la
 *        funcion en @p target_pc cuando un CALLVM la invoca
 *        repetidamente desde codigo interpretado.
 *
 * Llamado por @c exec_instr_callvm en cada CALLVM cuyo target NO
 * tiene jit_code en el pc-map (lookup miss).  Mantiene un counter
 * por PC; al cruzar @c g_jit_threshold, intenta compilar la funcion.
 *
 * El compile usa el pipeline completo de @c eager_compile_function
 * (con resolver recursivo) asi los callees se compilan transitively.
 * Sentinela @c UINT32_MAX en el counter = "ya intentado y fallo"
 * (no reintenta para evitar oscilacion compile/fail/recompile).
 *
 * Fast path coste (counter < threshold): ~30 ns (1 lock + 1 hash
 * lookup + 1 increment).  Tras cualquier compile exitoso, el
 * pc-map captura todos los CALLVMs subsiguientes -> el trigger
 * NUNCA se vuelve a invocar para ese PC.  Funcion sin IR -> cached
 * failure inmediato.
 *
 * @param vm        Proceso virtual actual (necesario para acceder
 *                  al Loader del VM).
 * @param target_pc Direccion VM del primer byte del bytecode de la
 *                  funcion que el CALLVM esta apuntando.
 */
void maybe_compile_callvm_target(runtime::ProcessVM *vm,
                                 uint64_t target_pc) noexcept;

/**
 * @brief Compila la funcion cuyo bytecode empieza en @p vx_fn_pc con
 *        un ENTRY de ABI C nativo (callback) y devuelve su direccion
 *        host, callable directamente por qsort/Win32/etc.
 *
 * Reemplaza el thunk hand-emitted de @c native_callback.cpp: en vez de
 * generar un wrapper que adapta C-ABI -> VM-ABI -> jit_fn, compila la
 * funcion DIRECTAMENTE con el entry nativo (modo callback del selector).
 * El cuerpo se lowerea como VM_ABI (RBX=proc), pero el prologo lee
 * @c ProcessVM* via TLS/call y mueve los args nativos a los params; solo
 * salva/restaura el banco de registros VM si el cuerpo puede ensuciarlo.
 *
 * Cachea por @p vx_fn_pc (cache propia, separada del pc-map VM_ABI: la
 * misma funcion puede tener una version VM_ABI y una callback-ABI).
 *
 * @param vm         Proceso virtual actual (para acceder al Loader).
 * @param vx_fn_pc  Direccion VM del primer byte del bytecode de la fn.
 * @return Direccion host del codigo callback, o 0 si no se pudo compilar.
 */
uint64_t compile_native_callback(runtime::ProcessVM *vm,
                                 uint64_t vx_fn_pc) noexcept;

class CodeCache; // fwd decl
/**
 * @brief Acceso al CodeCache global del JIT subsystem.
 *
 * Inicializa el subsistema JIT (lazy via @c std::call_once) si aun no
 * existe.  Util para clientes externos al JIT que necesitan alocar
 * codigo nativo en el code cache compartido.
 *
 * Thread-safe.  Retorna un puntero no-nulo.
 */
CodeCache *get_or_init_code_cache() noexcept;

} // namespace jit

#endif // VESTA_JIT_AUTO_JIT_H
