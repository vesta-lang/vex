/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file transpiler_base.h
 * @brief Core compartido del transpiler IR -> codigo fuente (C, Java, JS, ...).
 *
 * Este modulo orquesta el lowering de un @c ir::IrModule a un lenguaje
 * destino delegando la generacion concreta de codigo en un @c IPortBackend.
 *
 * Responsabilidades del core (compartidas entre TODOS los backends):
 *   - Recorrer @c IrModule::functions una a una.
 *   - Para cada funcion, recorrer @c IrFunction::blocks en orden.
 *   - Convertir PHI nodes en parallel-move al final de cada predecesor
 *     (los lenguajes target no tienen PHI nativo; los simulamos con
 *      asignaciones explicitas antes del salto al sucesor).
 *   - Garantizar declaracion previa de TODOS los SSA values al inicio de
 *     cada funcion (necesario para C: variables declaradas antes de uso;
 *     irrelevante para Java/JS pero no estorba).
 *   - Manejar el mapeo IrValueId -> nombre de variable destino.
 *
 * Responsabilidades del backend (especificas del lenguaje):
 *   - Tipos: como se mapea IrType al lenguaje destino.
 *   - Sintaxis: como se escribe una asignacion, un goto, un return.
 *   - Runtime: como llamar al GC, throw exceptions, etc.
 *   - Prelude/postamble: includes, defines, headers.
 *
 * Esta separacion permite agregar backends nuevos (Java, JS, ...) implementando
 * ~30 metodos virtuales sin tocar el lowering CFG/PHI compartido.
 *
 * = Convencion de nombres SSA value -> variable destino =
 *
 * Cada @c IrValueId se mapea a @c "v" + str(id).  Los parametros usan
 * @c IrValue::name si no esta vacio, o @c "p" + str(idx).  El backend puede
 * sobreescribir esta convencion via @c rename_value.
 *
 * = Ejemplo de uso =
 *
 * @code
 *   ir::IrModule irmod = ...;
 *   port::PortOptions opts;
 *   port::CBackend backend(opts);
 *   port::Transpiler tx(irmod, opts, backend);
 *   std::string source = tx.run();
 *   // source contiene codigo C listo para compilar.
 * @endcode
 */

#ifndef PORT_TRANSPILER_BASE_H
#define PORT_TRANSPILER_BASE_H

#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "ir/ssa_ir.h"
#include "port/port_options.h"

namespace port {

// Forward decl.
class Transpiler;

/**
 * @brief Resultado del proceso de transpilacion.
 */
struct TranspileResult {
    bool ok = false;         ///< True si no hubo errores fatales.
    std::string source_text; ///< Codigo fuente generado (C, Java, ...).
    std::vector<std::string> warnings; ///< IR ops no soportadas, etc.
    std::vector<std::string>
        errors; ///< Errores fatales si @c strict_unsupported.
};

/**
 * @brief Contexto de emision pasado a cada hook del backend.
 *
 * Encapsula la salida actual + estado del transpiler para que el backend
 * NO necesite saber detalles internos (mapeo SSA->var, indent, etc.).
 */
struct EmitContext {
    std::ostream &out;        ///< Stream donde escribir el output.
    int indent_level;         ///< Indentacion actual (en pasos de 4 spaces).
    const ir::IrFunction *fn; ///< Funcion actual (nullptr fuera de funcion).
    const ir::IrBlock *bb;    ///< Bloque actual (nullptr fuera de bloque).
    const PortOptions *opts;  ///< Opciones globales del transpiler.
    const Transpiler *tx;     ///< Puntero al transpiler para acceder a analisis
                              ///< (use_count, inline candidates).

    /**
     * @brief Emite N espacios segun @c indent_level.
     */
    void indent() const;
};

/**
 * @brief Interfaz que cada backend (C, Java, JS, ...) debe implementar.
 *
 * Los metodos pure-virtual son los OBLIGATORIOS.  Los demas tienen
 * implementacion default razonable que el backend puede sobreescribir.
 */
class IPortBackend {
  public:
    virtual ~IPortBackend() = default;

    // -------- IDENTIFICACION --------

    /** Nombre del lenguaje destino ("C", "Java", "JavaScript", ...). */
    virtual const char *language_name() const = 0;

    /** Extension del archivo de salida ("c", "java", "js", ...). */
    virtual const char *file_extension() const = 0;

    // -------- FILTRO DE FUNCIONES --------

    /**
     * @brief Determina si el transpiler debe SALTAR esta funcion.
     *
     * Default: false (emitir todas).  Backends pueden override para
     * filtrar:
     *   - @c __module_init (no util en C standalone)
     *   - @c __new_<X> (reemplazado por @c Class__new del backend)
     *   - Funciones nativas stub
     */
    virtual bool should_skip_function(const ir::IrFunction &fn,
                                      const ir::IrModule &mod) const {
        (void)fn;
        (void)mod;
        return false;
    }

    // -------- EXPRESIONES (acceso a valores) --------

    /**
     * @brief Formatea un SSA value como expresion del lenguaje destino.
     *
     * Default: @c "v<id>".  Los backends que soportan single-use inlining
     * (Nivel A) sobreescriben para devolver la expresion completa cuando
     * el value es @c is_inline_candidate.  Permite que el transpiler core
     * emita @c if/while/return correctos sin saber detalles del backend.
     */
    virtual std::string format_value(EmitContext &ctx, ir::IrValueId v) const {
        (void)ctx;
        if (v == ir::IR_NO_VALUE) return "0";
        return "v" + std::to_string(v);
    }

    // -------- TIPOS --------

    /**
     * @brief Nombre del tipo destino para un @c IrType dado.
     *
     * @param t IR type a mapear.
     * @param is_host_ptr Si el SSA value tiene @c is_host_ptr=true.
     *                    Solo relevante cuando @c t==PTR; algunos backends
     *                    emiten distinto tipo para host vs VM ptr.
     * @return Nombre del tipo en el lenguaje destino.
     */
    virtual std::string type_for(ir::IrType t, bool is_host_ptr) const = 0;

    /** Tipo "void" en el lenguaje destino. */
    virtual std::string void_type() const = 0;

    /** Tipo entero por defecto (i64) -- usado para variables sin tipo. */
    virtual std::string default_int_type() const = 0;

    // -------- ESTRUCTURA DE ARCHIVO --------

    /**
     * @brief Emite header del archivo: includes, defines, typedefs.
     *
     * Llamado UNA vez al inicio del output, antes de cualquier funcion.
     */
    virtual void emit_prelude(EmitContext &ctx, const ir::IrModule &mod) = 0;

    /**
     * @brief Emite footer del archivo: cleanup, main wrapper, etc.
     *
     * Llamado UNA vez al final del output.  Default: no-op.
     */
    virtual void emit_postamble(EmitContext &ctx, const ir::IrModule &mod) {
        (void)ctx;
        (void)mod;
    }

    // -------- ESTRUCTURA DE FUNCION --------

    /**
     * @brief Emite la firma de la funcion ("int32_t add(int32_t a, ...)").
     *
     * No incluye el cuerpo ni las llaves; solo @c "return_type name(params)".
     * El transpiler base añade @c " {" o @c "{\n" segun convencion.
     */
    virtual void emit_fn_signature(EmitContext &ctx,
                                   const ir::IrFunction &fn) = 0;

    /**
     * @brief Emite la apertura del cuerpo de la funcion (@c "{").
     * Default: emite @c "{\n".
     */
    virtual void emit_fn_open(EmitContext &ctx) {
        ctx.out << "{\n";
        ctx.indent_level++;
    }

    /**
     * @brief Emite el cierre del cuerpo (@c "}").
     * Default: emite @c "}\n\n".
     */
    virtual void emit_fn_close(EmitContext &ctx) {
        ctx.indent_level--;
        ctx.out << "}\n\n";
    }

    /**
     * @brief Emite la declaracion de un SSA value local.
     *
     * Llamado UNA vez por value al inicio de cada funcion (antes del
     * primer bloque).  En C: @c "int32_t v3 = 0;".  En Java: idem.
     * En JS podria ser @c "let v3 = 0;" o no-op (typeless).
     *
     * @param id Id del valor SSA.
     * @param value Descriptor (tipo, is_host_ptr).
     */
    virtual void emit_local_decl(EmitContext &ctx, ir::IrValueId id,
                                 const ir::IrValue &value) = 0;

    // -------- BLOQUES Y CONTROL FLOW --------

    /**
     * @brief Nombre del label correspondiente a un bloque basico.
     *
     * Default: @c "bb_" + str(block_id).  Permite override si el
     * lenguaje destino requiere convenciones distintas.
     */
    virtual std::string label_for(ir::IrBlockId id) const {
        return "bb_" + std::to_string(id);
    }

    /**
     * @brief Emite la definicion del label (@c "bb_3:").
     * Default: emite @c "bb_3:\n".
     */
    virtual void emit_label_def(EmitContext &ctx, ir::IrBlockId id) {
        ctx.out << label_for(id) << ":\n";
    }

    /**
     * @brief Emite un salto incondicional (BR).
     * Default C-style: @c "goto bb_3;".
     */
    virtual void emit_goto(EmitContext &ctx, ir::IrBlockId target) {
        ctx.indent();
        ctx.out << "goto " << label_for(target) << ";\n";
    }

    /**
     * @brief Emite un salto condicional (BR_COND).
     * Default: @c "if (v_cond) goto bb_t; else goto bb_f;".
     */
    virtual void emit_cond_branch(EmitContext &ctx, ir::IrValueId cond,
                                  ir::IrBlockId true_id,
                                  ir::IrBlockId false_id);

    /**
     * @brief Emite un return.
     * @param val IR_NO_VALUE si void; valor sino.
     */
    virtual void emit_return(EmitContext &ctx, ir::IrValueId val) = 0;

    // -------- INSTRUCCIONES SCALAR --------

    /** Emite una constante: @c "v0 = 42;" o @c "v0 = 3.14;". */
    virtual void emit_const(EmitContext &ctx, ir::IrValueId dst, uint64_t imm,
                            ir::IrType t) = 0;

    /** Emite un copy: @c "v0 = v1;". */
    virtual void emit_mov(EmitContext &ctx, ir::IrValueId dst,
                          ir::IrValueId src, ir::IrType t) = 0;

    /** Emite una op binaria: @c "v0 = v1 + v2;". */
    virtual void emit_binop(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                            ir::IrValueId lhs, ir::IrValueId rhs,
                            ir::IrType t) = 0;

    /** Emite un FMA (round(a*b+c), 1 SOLO redondeo): @c "v0 = fma(v1,v2,v3);".
     *  Default: comentario TODO (backend futuro sin FMA). */
    virtual void emit_fma(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId a,
                          ir::IrValueId b, ir::IrValueId c, ir::IrType t) {
        (void)dst;
        (void)a;
        (void)b;
        (void)c;
        (void)t;
        ctx.indent();
        ctx.out << "/* TODO backend sin emit_fma */\n";
    }

    /** Emite una op unaria: @c "v0 = -v1;" o @c "v0 = ~v1;". */
    virtual void emit_unop(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                           ir::IrValueId src, ir::IrType t) = 0;

    /** Emite una comparacion: @c "v0 = (v1 == v2);". */
    virtual void emit_cmp(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                          ir::IrValueId lhs, ir::IrValueId rhs,
                          ir::IrType operand_type) = 0;

    /** Emite una conversion (SEXT/ZEXT/TRUNC/CAST/ITOF/FTOI/etc.). */
    virtual void emit_convert(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                              ir::IrValueId src, ir::IrType dst_type,
                              ir::IrType src_type) = 0;

    // -------- MEMORIA --------

    /** Emite alocacion en stack: @c "uint8_t buf[N]; void *v0 = buf;". */
    virtual void emit_alloca(EmitContext &ctx, ir::IrValueId dst,
                             uint64_t size_bytes) = 0;

    /** Emite LOAD: @c "v0 = *(int32_t*)v_addr;". */
    virtual void emit_load(EmitContext &ctx, ir::IrValueId dst,
                           ir::IrValueId addr, ir::IrType t,
                           bool is_host_ptr) = 0;

    /** Emite STORE: @c "*(int32_t*)v_addr = v_val;". */
    virtual void emit_store(EmitContext &ctx, ir::IrValueId val,
                            ir::IrValueId addr, ir::IrType t,
                            bool is_host_ptr) = 0;

    /** Emite raw alloc: @c "v0 = (void*)malloc(size);". */
    virtual void emit_raw_alloc(EmitContext &ctx, ir::IrValueId dst,
                                ir::IrValueId size) = 0;

    /** Emite raw free: @c "free(v_ptr);". */
    virtual void emit_raw_free(EmitContext &ctx, ir::IrValueId ptr) = 0;

    // -------- LLAMADAS --------

    /** Emite call directo: @c "v0 = my_func(v_a, v_b);". */
    virtual void emit_call(EmitContext &ctx, ir::IrValueId dst,
                           const std::string &func_name,
                           ir::IrValueList args,
                           ir::IrType ret_type) = 0;

    /** Emite call indirecto via puntero: @c "v0 = ((fn_t)v_fn)(v_a, ...);". */
    virtual void emit_call_indirect(EmitContext &ctx, ir::IrValueId dst,
                                    ir::IrValueId fn_ptr,
                                    ir::IrValueList args,
                                    ir::IrType ret_type) = 0;

    /**
     * @brief Emite CALLVIRT (dispatch virtual por vtable index).
     *
     * Default: emite stub @c emit_unsupported (no soportado).  El
     * backend C lo sobreescribe para emitir:
     *   - Direct call si el tipo concreto de @c obj es conocido (devirt).
     *   - Vtable lookup si el tipo no se puede determinar (Mode VIRTUAL).
     */
    virtual void emit_callvirt(EmitContext &ctx, ir::IrValueId dst,
                               ir::IrValueId obj, uint32_t vtable_idx,
                               ir::IrValueList args,
                               ir::IrType ret_type) {
        (void)ctx;
        (void)dst;
        (void)obj;
        (void)vtable_idx;
        (void)args;
        (void)ret_type;
        ctx.indent();
        ctx.out << "/* CALLVIRT no soportado en este backend */\n";
    }

    /**
     * @brief Emite CALLM (dispatch via @c MethodInfo* dinamico).
     *
     * Usado por interfaces y reflexion: el receptor @c obj es de tipo
     * abstracto y @c method_ptr fue resuelto via @c findmethod en
     * runtime.  En port C, el backend lo lowers a sealed dispatch
     * cuando el tipo concreto del receiver se conoce; sino emite stub
     * (requeriria ClassRegistry runtime).
     *
     * Default: emit_unsupported.
     */
    virtual void emit_callm(EmitContext &ctx, ir::IrValueId dst,
                            ir::IrValueId obj, ir::IrValueId method_ptr,
                            ir::IrValueList args,
                            ir::IrType ret_type) {
        (void)dst;
        (void)obj;
        (void)method_ptr;
        (void)args;
        (void)ret_type;
        ctx.indent();
        ctx.out << "/* CALLM no soportado en este backend */\n";
    }

    /**
     * @brief Emite CALLCLOSURE (call a un closure via slot 16 bytes).
     *
     * @c slot_ptr apunta a un struct @c {fn_addr, env_addr} en stack.
     * El backend lo casts a un function pointer del tipo apropiado y
     * llama @c fn(env_addr, args...).  Si @c env_addr == 0, el callee
     * es una funcion libre sin captura.
     *
     * Default: emit_unsupported.
     */
    virtual void emit_call_closure(EmitContext &ctx, ir::IrValueId dst,
                                   ir::IrValueId slot_ptr,
                                   ir::IrValueList args,
                                   ir::IrType ret_type,
                                   const ir::IrInstr &ins) {
        (void)dst;
        (void)slot_ptr;
        (void)args;
        (void)ret_type;
        (void)ins;
        ctx.indent();
        ctx.out << "/* CALLCLOSURE no soportado en este backend */\n";
    }

    /**
     * @brief Emite el call al trampoline de un SPAWN_ARGS multi-arg.
     *
     * El transpiler ya alloco @c __sa con los args; el backend conoce
     * el helper destino y emite el dispatch.  Backend C: registra el
     * (helper_name, argc) y emite el trampoline al final del modulo.
     *
     * Default: emit_unsupported.
     */
    virtual void emit_spawn_trampoline_call(EmitContext &ctx,
                                            ir::IrValueId fn_ptr, size_t argc,
                                            const std::string &args_var) {
        (void)fn_ptr;
        (void)argc;
        (void)args_var;
        ctx.indent();
        ctx.out << "/* SPAWN_ARGS multi-arg no soportado en este backend */\n";
    }

    /**
     * @brief Emite STR_LIT_ADDR: carga la direccion de un literal estatico.
     *
     * @c imm es el indice en @c IrModule::static_data.  El backend C
     * lo resuelve a la direccion de @c __str_<imm> emitido en el prelude.
     *
     * Default: emit_unsupported.
     */
    virtual void emit_str_lit_addr(EmitContext &ctx, ir::IrValueId dst,
                                   uint64_t imm, ir::IrType t) {
        (void)ctx;
        (void)dst;
        (void)imm;
        (void)t;
        ctx.indent();
        ctx.out << "/* STR_LIT_ADDR no soportado en este backend */\n";
    }

    /**
     * @brief Emite RAW_ASM: bloque de codigo del lenguaje destino verbatim
     *        o equivalente reconocido por pattern-match.
     *
     * @c asm_text es el texto del @c .vel raw_asm; @c operands son los
     * SSA values referenciados por @c {src0}, @c {src1}, etc.  El backend
     * C trata de match el texto con una tabla de patrones (strmake,
     * strcat, monenter, gchandle, etc.) y emite el equivalente C
     * correspondiente.  Si no matchea, emit_unsupported.
     *
     * Default: emit_unsupported.
     */
    virtual void emit_raw_asm(EmitContext &ctx, ir::IrValueId dst,
                              const std::string &asm_text,
                              ir::IrValueList operands, ir::IrType t) {
        (void)dst;
        (void)asm_text;
        (void)operands;
        (void)t;
        ctx.indent();
        ctx.out << "/* RAW_ASM no soportado en este backend */\n";
    }

    /**
     * @brief  AS inc.3: hook para inline asm nativo (IrOp::INLINE_ASM).
     *
     * El backend que soporte asm de la CPU host (port-C) lo materializa
     * (e.g. @c __asm__ __volatile__).  Default: delega en
     * @c emit_unsupported (otros backends no lo soportan todavia).
     */
    virtual void emit_inline_asm(EmitContext &ctx, const ir::IrInstr &instr) {
        emit_unsupported(ctx, instr);
    }

    // -------- GENERICO PARA IR OPS NO IMPLEMENTADAS --------

    /**
     * @brief Hook para IR ops no soportadas por el backend.
     *
     * Default: emite un comentario @c "// TODO: <op_name>" y un stub
     * que asigna 0 al destino (si tiene dst).  El transpiler core
     * incrementa @c warnings con el nombre.  Si
     * @c PortOptions::strict_unsupported, se trata como error fatal.
     */
    virtual void emit_unsupported(EmitContext &ctx, const ir::IrInstr &instr);

    // -------- ASIGNACIONES PARA PHI (parallel-move) --------

    /**
     * @brief Emite una asignacion @c "v_dst = v_src;".
     *
     * Llamado por el core ANTES del terminador de cada predecesor para
     * resolver los PHIs del bloque sucesor.  Default: emite
     * @c "    v_dst = v_src;\n".
     */
    virtual void emit_phi_copy(EmitContext &ctx, ir::IrValueId dst,
                               ir::IrValueId src, ir::IrType t);
};

/**
 * @brief Informacion de analisis per-funcion usada para generar codigo
 *        optimo en el lenguaje destino.
 *
 * Se rellena en @c Transpiler::analyze_function ANTES de la emision.
 * El backend la consulta via @c EmitContext::tx->use_count(v), etc.
 */
struct FunctionAnalysis {
    /// Numero total de usos de cada SSA value (incluye phi_args).
    /// Indice = IrValueId.  Valor 0 = no usado (DCE-able).
    std::vector<uint32_t> use_count;

    /// Para cada SSA value, puntero a la IrInstr que lo define.
    /// nullptr para parametros y para values no definidos por una instr.
    std::vector<const ir::IrInstr *> def_instr;

    /// True si el value tiene exactamente 1 uso Y su definicion es una
    /// operacion pura (sin efectos secundarios; no LOAD, no CALL).
    /// El backend lo usa para INLINEAR la expresion en el uso en vez de
    /// declarar una variable intermedia.  Ej.: @c "v3 = v1 + v2; v8 = v3 * v4;"
    /// con @c v3 inlineable se convierte en @c "v8 = (v1 + v2) * v4;".
    std::vector<bool> is_inline_candidate;

    /// Bloque que contiene el primer (y unico) uso de cada value
    /// inline-candidate.  Util si el backend quiere validar que el uso
    /// no cruza side-effects (no implementado en v1).
    std::vector<ir::IrBlockId> single_use_block;

    /// Para cada bloque, sus predecesores en el CFG.  Calculado en O(N)
    /// recorriendo todas las instrucciones.  Util para detectar bloques
    /// huerfanos (sin preds, candidatos para suppression del label).
    std::vector<std::vector<ir::IrBlockId>> block_preds;
};

/**
 * @brief Orquestador del transpiler.  Bajos @c ir::IrModule a codigo
 *        destino delegando en @c IPortBackend.
 */
class Transpiler {
  public:
    Transpiler(const ir::IrModule &mod, const PortOptions &opts,
               IPortBackend &backend)
        : mod_(mod), opts_(opts), backend_(backend) {}

    /**
     * @brief Ejecuta la transpilacion completa.
     * @return Resultado con el codigo fuente o errores.
     */
    TranspileResult run();

    // -------- ACCESORES PARA EL BACKEND --------

    /**
     * @brief Numero de usos de un SSA value en la funcion actual.
     */
    uint32_t use_count(ir::IrValueId v) const {
        if (v >= ana_.use_count.size()) return 0;
        return ana_.use_count[v];
    }

    /**
     * @brief Instruccion que define un SSA value (nullptr si param o no
     * encontrada).
     */
    const ir::IrInstr *def_of(ir::IrValueId v) const {
        if (v >= ana_.def_instr.size()) return nullptr;
        return ana_.def_instr[v];
    }

    /**
     * @brief El value se puede inlinear en su uso?
     *
     * True si single-use + def es pura.  El backend lo usa para evitar
     * declarar la variable intermedia y emitir la expresion en el sitio.
     */
    bool is_inline_candidate(ir::IrValueId v) const {
        if (v >= ana_.is_inline_candidate.size()) return false;
        return ana_.is_inline_candidate[v];
    }

    /**
     * @brief El bloque tiene predecesores en el CFG?
     *
     * Util para suprimir labels innecesarios cuando un bloque solo se
     * alcanza por fall-through (en C, el entry block tipicamente).
     */
    bool block_has_preds(ir::IrBlockId bid) const {
        if (bid >= ana_.block_preds.size()) return false;
        return !ana_.block_preds[bid].empty();
    }

  private:
    const ir::IrModule &mod_;
    const PortOptions &opts_;
    IPortBackend &backend_;
    FunctionAnalysis ana_; ///< Recalculado en cada emit_function.

    /**
     * @brief Pre-pasada de analisis de una funcion: cuenta usos, identifica
     *        candidatos a inlining, computa preds del CFG.
     *
     * Debe llamarse ANTES de @c emit_function para que los hooks del
     * backend tengan acceso correcto a @c is_inline_candidate, etc.
     */
    void analyze_function(const ir::IrFunction &fn);

    /**
     * @brief Emite una funcion completa.
     */
    void emit_function(EmitContext &ctx, const ir::IrFunction &fn);

    /**
     * @brief Emite las declaraciones de todos los SSA values al inicio.
     *
     * Skip de values que son @c is_inline_candidate (se emiten via
     * @c value_expr del backend al usarse).
     */
    void emit_value_declarations(EmitContext &ctx, const ir::IrFunction &fn);

    /**
     * @brief Emite un bloque basico completo: label + instrucciones +
     * terminator.
     */
    void emit_block(EmitContext &ctx, const ir::IrBlock &bb,
                    const ir::IrFunction &fn);

    /**
     * @brief Emite una instruccion no-terminator (no BR/BR_COND/RET).
     */
    void emit_instr(EmitContext &ctx, const ir::IrInstr &ins);

    /**
     * @brief Emite PHI copies del bloque actual hacia el target_bb.
     *
     * Antes de un BR o BR_COND, este metodo busca PHIs en el sucesor
     * y emite las asignaciones @c "v_phi_dst = v_phi_arg_from_us;".
     */
    void emit_phi_copies_for_edge(EmitContext &ctx, const ir::IrFunction &fn,
                                  ir::IrBlockId from_bb, ir::IrBlockId to_bb);

    /**
     * @brief Helper: el bloque tiene PHIs al inicio?
     *
     * Los PHIs por convencion estan al PRINCIPIO del bloque (los emite
     * el lowering al crear el bloque sucesor con multiples predecesores).
     * Si la primera instruccion del bloque no es PHI, no hay PHIs.
     */
    bool block_has_phis(const ir::IrFunction &fn, ir::IrBlockId bid) const;

    // =====================================================================
    //  Nivel C: structured emission via deteccion de patrones de bloques
    // =====================================================================

    /**
     * @brief Clasificacion estructural de un bloque header.
     *
     * Resultado de @c classify_structure usado por @c emit_region para
     * decidir si emitir @c while/if/else en lugar de @c goto.
     */
    struct StructureInfo {
        enum Kind {
            NONE,         ///< No estructurable; emitir como goto-style.
            SIMPLE_LOOP,  ///< while (cond) {body}; back-edge a header.
            IF_THEN,      ///< if (cond) {then}; sin else.
            IF_THEN_ELSE, ///< if (cond) {then} else {else}; ambos al merge.
        } kind = NONE;

        /// Bloque donde reside el cuerpo del then / loop body.
        ir::IrBlockId then_block = ir::IR_NO_BLOCK;
        /// Bloque del else (solo en IF_THEN_ELSE).
        ir::IrBlockId else_block = ir::IR_NO_BLOCK;
        /// Punto de convergencia: exit del loop, merge del if.
        ir::IrBlockId merge_block = ir::IR_NO_BLOCK;
        /// Si true, la condicion debe negarse antes de emitirla.  Cubre
        /// patrones como @c "while_body es false branch" o
        /// @c "if-not-cond".  El backend emite @c "!(cond)" o invierte
        /// la comparacion segun sea posible.
        bool inverted = false;
    };

    /**
     * @brief Clasifica el bloque header segun su estructura de control.
     *
     * Reconoce patrones:
     *   - SIMPLE_LOOP: bb termina con BR_COND donde uno de los targets
     *     termina inmediatamente con BR(bb).
     *   - IF_THEN_ELSE: bb termina con BR_COND donde ambos targets terminan
     *     con BR a un mismo merge.
     *   - IF_THEN: bb termina con BR_COND donde uno de los targets termina
     *     con BR al OTRO target (sin else), o termina con RET/UNREACHABLE.
     *
     * Para CFGs irreducibles o patrones no canonicos devuelve NONE.
     */
    StructureInfo classify_structure(const ir::IrFunction &fn,
                                     const ir::IrBlock &bb) const;

    /**
     * @brief Emite una region de la CFG con emision estructurada.
     *
     * Recorre los bloques desde @c start hasta @c stop (excluido).
     * Marca bloques visitados.  Para cada bloque, detecta su estructura
     * via @c classify_structure y emite la forma @c while/if/else
     * correspondiente.  Bloques no estructurables se emiten goto-style.
     *
     * @param ctx Contexto de emision.
     * @param fn Funcion actual.
     * @param start Bloque inicial.
     * @param stop Bloque limite (IR_NO_BLOCK = hasta fin de funcion).
     * @param visited Mapa de bloques ya emitidos (para deteccion de
     *                back-edges + duplicados).
     */
    void emit_region(EmitContext &ctx, const ir::IrFunction &fn,
                     ir::IrBlockId start, ir::IrBlockId stop,
                     std::vector<bool> &visited);

    /**
     * @brief Emite las instrucciones no-PHI no-terminator de un bloque.
     */
    void emit_block_body_no_term(EmitContext &ctx, const ir::IrBlock &bb);

    /**
     * @brief Emite el terminator de un bloque en estilo goto.  Solo
     *        usado como fallback cuando el bloque NO es estructurable.
     */
    void emit_block_terminator(EmitContext &ctx, const ir::IrFunction &fn,
                               const ir::IrBlock &bb);
};

} // namespace port

#endif // PORT_TRANSPILER_BASE_H
