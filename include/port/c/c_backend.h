/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file c_backend.h
 * @brief Backend C del transpiler IR -> codigo fuente.
 *
 * Genera codigo C99/C11 portable y eficiente listo para compilar con
 * @c gcc/clang -O3 -std=c11.  Caracteristicas:
 *
 *   - Tipos via @c stdint.h (default): int8_t..int64_t, uint8_t..uint64_t,
 *     double/float, void*.  Tamanos exactos cross-platform.
 *
 *   - SSA values 1:1 a variables C locales nombradas @c v<id> (v0, v1, ...).
 *     El compilador host (GCC/Clang -O3) hace SU PROPIO regalloc.  No
 *     intentamos asignar registros nosotros (delegacion total a la cadena
 *     de optimizacion C, que es ~30 anos de tuning sobre x86/ARM).
 *
 *   - Basic blocks como labels con @c goto.  GCC -O2+ los maneja como CFG
 *     y aplica optimizaciones (jump threading, tail dup, etc.) iguales que
 *     si fueran branches del frontend C.  Resultado: equivalente en perf
 *     al codigo escrito a mano con @c if/while/for.
 *
 *   - PHIs lowered a parallel-move en cada predecesor (logica en
 *     @c transpiler_base.cpp).
 *
 *   - LOAD/STORE con cast explicito al tipo correcto:
 *         @c "v0 = *(int32_t*)v_addr;"
 *         @c "*(int32_t*)v_addr = v_val;"
 *
 *   - CALL directos por nombre.  Si la funcion target es una @c CallVirt o
 *     @c CallM (requeriria GC + vtables), se emite stub @c emit_unsupported.
 *
 *   - Excepciones: por defecto setjmp/longjmp (configurable).
 *
 *   - Sin GC por defecto: NEWOBJ / GETFIELD / SETFIELD / strings emiten
 *     stub "unsupported".  Para programas que SI usan estos, el usuario
 *     debe pasar @c --port-gc=vesta y enlazar contra @c vesta_rt.lib.
 *
 * = Hot-path optimization =
 *
 * El truco para que el codigo generado sea optimo es minimizar la
 * informacion que ocultamos al compilador:
 *
 *   - Cada SSA value declarado con su tipo CONCRETO (no @c uint64_t para
 *     todo).  Asi GCC sabe si puede usar registros de 8/16/32 bits y
 *     hacer SIMD cuando aplique.
 *
 *   - Casts explicitos en LOAD/STORE permiten al optimizer hacer alias
 *     analysis correctamente (strict aliasing -fno-strict-aliasing no
 *     necesario porque los casts son a tipos compatibles).
 *
 *   - Sin overhead de runtime VM: nada de check de ProcessVM, nada de
 *     stackmaps, nada de safepoint polls.  El codigo C es exactamente
 *     lo que escribiriamos a mano.
 *
 *   - Atributos GCC opcionales (via @c emit_compiler_hints):
 *       @c __attribute__((hot))  en funciones con profile alto
 *       @c __attribute__((cold)) en funciones de error/setup
 *       @c __restrict__          en host_ptr params no aliasing
 */

#ifndef PORT_C_BACKEND_H
#define PORT_C_BACKEND_H

#include "port/transpiler_base.h"

namespace port {

class CBackend : public IPortBackend {
  public:
    explicit CBackend(const PortOptions &opts) : opts_(opts) {}

    // -------- IDENTIFICACION --------
    const char *language_name() const override { return "C"; }
    const char *file_extension() const override { return "c"; }

    // -------- EXPRESIONES --------
    std::string format_value(EmitContext &ctx, ir::IrValueId v) const override {
        return value_expr(ctx, v);
    }

    // -------- FILTRO DE FUNCIONES --------
    bool should_skip_function(const ir::IrFunction &fn,
                              const ir::IrModule &mod) const override;

    // -------- TIPOS --------
    std::string type_for(ir::IrType t, bool is_host_ptr) const override;
    std::string void_type() const override { return "void"; }
    std::string default_int_type() const override { return "int64_t"; }

    // -------- ESTRUCTURA DE ARCHIVO --------
    void emit_prelude(EmitContext &ctx, const ir::IrModule &mod) override;
    void emit_postamble(EmitContext &ctx, const ir::IrModule &mod) override;

    /**
     * @brief Emite las definiciones de TODAS las clases del modulo.
     *
     * Por cada @c ir::IrClass:
     *   - Forward decl del @c typedef struct (para que metodos puedan
     *     referenciar la clase).
     *   - Layout completo del struct (fields en orden de offset).
     *   - Forward decl del constructor @c Class__new() y @c Class__delete().
     *   - Forward decls de cada metodo: @c Class__method(Class *self, ...).
     *
     * El orden topologico (super antes que sub) se respeta para evitar
     * forward references inválidas en C.
     */
    void emit_class_decls(EmitContext &ctx, const ir::IrModule &mod);

    /**
     * @brief Emite los CUERPOS del constructor + destructor + helper @c new.
     *
     * Separado de @c emit_class_decls porque los cuerpos pueden referenciar
     * cualquier otra clase del modulo (decls forward) y por tanto deben
     * emitirse AL FINAL, tras todas las decls.
     */
    void emit_class_bodies(EmitContext &ctx, const ir::IrModule &mod);

    // -------- ESTRUCTURA DE FUNCION --------
    void emit_fn_signature(EmitContext &ctx, const ir::IrFunction &fn) override;
    void emit_local_decl(EmitContext &ctx, ir::IrValueId id,
                         const ir::IrValue &value) override;

    // -------- CONTROL FLOW --------
    void emit_return(EmitContext &ctx, ir::IrValueId val) override;
    void emit_cond_branch(EmitContext &ctx, ir::IrValueId cond,
                          ir::IrBlockId true_id,
                          ir::IrBlockId false_id) override;
    void emit_phi_copy(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId src,
                       ir::IrType t) override;

    // -------- INSTRUCCIONES --------
    void emit_const(EmitContext &ctx, ir::IrValueId dst, uint64_t imm,
                    ir::IrType t) override;
    void emit_mov(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId src,
                  ir::IrType t) override;
    void emit_binop(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                    ir::IrValueId lhs, ir::IrValueId rhs,
                    ir::IrType t) override;
    void emit_fma(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId a,
                  ir::IrValueId b, ir::IrValueId c, ir::IrType t) override;
    void emit_unop(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                   ir::IrValueId src, ir::IrType t) override;
    void emit_cmp(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                  ir::IrValueId lhs, ir::IrValueId rhs,
                  ir::IrType operand_type) override;
    void emit_convert(EmitContext &ctx, ir::IrOp op, ir::IrValueId dst,
                      ir::IrValueId src, ir::IrType dst_type,
                      ir::IrType src_type) override;

    // -------- MEMORIA --------
    void emit_alloca(EmitContext &ctx, ir::IrValueId dst,
                     uint64_t size_bytes) override;
    void emit_load(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId addr,
                   ir::IrType t, bool is_host_ptr) override;
    void emit_store(EmitContext &ctx, ir::IrValueId val, ir::IrValueId addr,
                    ir::IrType t, bool is_host_ptr) override;
    void emit_raw_alloc(EmitContext &ctx, ir::IrValueId dst,
                        ir::IrValueId size) override;
    void emit_raw_free(EmitContext &ctx, ir::IrValueId ptr) override;

    // -------- LLAMADAS --------
    void emit_call(EmitContext &ctx, ir::IrValueId dst,
                   const std::string &func_name,
                   ir::IrValueList args,
                   ir::IrType ret_type) override;
    void emit_call_indirect(EmitContext &ctx, ir::IrValueId dst,
                            ir::IrValueId fn_ptr,
                            ir::IrValueList args,
                            ir::IrType ret_type) override;
    void emit_callvirt(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId obj,
                       uint32_t vtable_idx,
                       ir::IrValueList args,
                       ir::IrType ret_type) override;

    void emit_call_closure(EmitContext &ctx, ir::IrValueId dst,
                           ir::IrValueId slot_ptr,
                           ir::IrValueList args,
                           ir::IrType ret_type,
                           const ir::IrInstr &ins) override;

    void emit_callm(EmitContext &ctx, ir::IrValueId dst, ir::IrValueId obj,
                    ir::IrValueId method_ptr,
                    ir::IrValueList args,
                    ir::IrType ret_type) override;

    void emit_spawn_trampoline_call(EmitContext &ctx, ir::IrValueId fn_ptr,
                                    size_t argc,
                                    const std::string &args_var) override;

    // -------- STRINGS Y RAW_ASM --------

    /**
     * @brief Carga la direccion de un literal estatico interned.
     * Emite @c "v_dst = (void*)__str_<imm>;" usando los buffers
     * emitidos por @c emit_static_data en el prelude.
     */
    void emit_str_lit_addr(EmitContext &ctx, ir::IrValueId dst, uint64_t imm,
                           ir::IrType t) override;

    /**
     * @brief Pattern-match texto de raw_asm contra la tabla de patrones
     * conocidos (strmake, strcat, gchandle, gcderef, monenter, etc).
     * Cada patron mapea a una secuencia C equivalente. Si no matchea,
     * emit_unsupported con el texto truncado.
     */
    void emit_raw_asm(EmitContext &ctx, ir::IrValueId dst,
                      const std::string &asm_text,
                      ir::IrValueList operands,
                      ir::IrType t) override;

    ///  AS inc.3: inline asm nativo (IrOp::INLINE_ASM) -> bloque
    /// @c __asm__ __volatile__(".intel_syntax noprefix\n ...") con las
    /// variables register() como operandos GCC y los clobbers.
    void emit_inline_asm(EmitContext &ctx, const ir::IrInstr &instr) override;

    ///  AS inc.3: devuelve el binding register("reg") asociado al
    /// ALLOCA @p id en la funcion actual, o nullptr si @p id no es un
    /// slot register-bound.  Consultado por emit_local_decl/alloca/
    /// load/store para materializar la variable C con register-pin.
    const ir::AsmRegBinding *reg_binding_for(const EmitContext &ctx,
                                             ir::IrValueId id) const;

    /**
     * @brief Emite una llamada nativa (CALLN @c "lib:sym").
     *
     * Para builtins conocidos (vio_print_*, vio_print_buf, vmath_*),
     * emit bridge a stdio/math C estandar (sin requerir libs Vesta).
     * Para simbolos desconocidos, emit @c extern declaration + direct
     * call al simbolo @c sym (usuario enlaza la lib correspondiente).
     */
    void emit_native_call(EmitContext &ctx, ir::IrValueId dst,
                          const std::string &lib, const std::string &sym,
                          ir::IrValueList args,
                          ir::IrType ret_type);

    /**
     * @brief Emite el runtime VxString inline al inicio del .c.
     *
     * Solo se invoca si @c opts_.strings == Managed Y el modulo usa
     * strings (detectado via STR_LIT_ADDR o raw_asm "str*").  Emite:
     *   - typedef struct VxString { ... };
     *   - vx_str_make_lit / vx_str_make / vx_str_concat / vx_str_eq
     *   - vx_str_len / vx_str_byte_len / vx_str_raw / vx_str_free
     *   - Linked list per-thread + warn on leak at exit.
     */
    void emit_string_runtime(EmitContext &ctx);

    /**
     * @brief Emite los literales de @c IrModule::static_data como
     *        @c static @c const arrays con nombre @c __str_<i>.
     *
     * Solo se invoca si el modulo tiene @c static_data no vacio.  Lo
     * llama @c emit_prelude justo antes de las clases.
     */
    void emit_static_data(EmitContext &ctx, const ir::IrModule &mod);

    /**
     * @brief Carga un snippet @c .v.c desde @c stdlib/port/c/ y lo
     *        emite en @c ctx.out.  Si el snippet tiene @c freestanding-skip:yes
     *        y estamos en modo freestanding, no emite nada.  Si no se
     *        encuentra el archivo, emite stub inline + warning a stderr.
     *
     * @param name Nombre base del snippet (sin extension).  El loader
     *             busca @c <stdlib_port_c_dir>/<name>.v.c.
     * @return true si el snippet fue emitido (o omitido legitimamente
     *         por freestanding-skip).  false si hubo error de IO.
     */
    bool emit_snippet(EmitContext &ctx, const std::string &name);

    /**
     * @brief Resuelve el path absoluto al directorio @c stdlib/port/c.
     *        Usa @c PortOptions::stdlib_port_c_dir si esta seto, sino
     *        busca relativo al ejecutable actual.
     */
    std::string resolve_stdlib_dir() const;

  private:
    const PortOptions &opts_;

    // -------- Estado per-modulo (set en emit_prelude) --------

    /**
     * @brief Mapa nombre -> IrClass para lookup O(1) durante emision.
     */
    std::unordered_map<std::string, const ir::IrClass *> class_by_name_;

    // -------- Estado per-funcion (set al entrar a cada IrFunction) --------

    /**
     * @brief Tipo concreto inferido por SSA value durante emision de
     *        la funcion actual.  Vacio = tipo desconocido (use generic).
     *
     * Llenado por @c infer_concrete_types al entrar a una funcion.  El
     * emit_call con func_name @c "__new_<X>" marca el dst con concrete
     * type @c "X".  MOV propaga; PHI interseca (si conflicto => "").
     */
    std::unordered_map<ir::IrValueId, std::string> concrete_type_;

    // -------- Helpers --------

    const ir::IrClass *lookup_class(const std::string &name) const;

    /**
     * @brief Devuelve el nombre del field en @c cls que esta en
     *        @c offset y tiene tipo @c type, o cadena vacia si no
     *        existe.  Util para emitir @c "obj->fieldname" en lugar
     *        de @c "*(int32_t*)((char*)obj+24)".
     */
    std::string field_name_at_offset(const ir::IrClass &cls, uint32_t offset,
                                     ir::IrType type) const;

    /**
     * @brief Set de SSA values que SE PUEDEN stack-allocate.
     *
     * Llenado por @c analyze_escapes durante @c emit_fn_signature.
     * Cuando una @c CALL a @c __new_<X> produce un value en este set,
     * @c emit_call emite stack alloc en lugar de heap.
     */
    std::unordered_set<ir::IrValueId> stack_alloc_candidates_;

    /**
     * @brief Set de aridades de SPAWN_ARGS encontradas en el modulo.
     *
     * Cada aridad N requiere un @c __vx_trampoline_<N> que desempaca
     * @c (fn_ptr, args...) y llama al helper.  Se emite una sola vez
     * por N en @c emit_postamble.
     */
    mutable std::unordered_set<size_t> spawn_trampoline_arities_;

    /**
     * @brief Stack-allocated objects en la funcion actual (RAII).
     *
     * Pares @c (dst_value_id, class_name) para cada @c __new_<X> que
     * fue emitido como stack alloc.  En @c emit_return iteramos en
     * orden inverso para invocar @c Class__~dtor(&__stk_id) antes
     * del return -- exactamente como C++ stack destructors.
     *
     * Si la clase no tiene destructor (campo @c IrClass::has_destructor
     * false), no emitimos nada (calloc + dtor seria no-op).
     */
    std::vector<std::pair<ir::IrValueId, std::string>> stack_alloc_in_fn_;

    /**
     * @brief Pre-pasada per-funcion: rastrea el tipo concreto de cada
     *        SSA value via SSA propagation desde calls a @c __new_<X>,
     *        MOV, PHI.  Llenado @c concrete_type_.
     *
     * Para funciones metodo (nombre @c <Class>__<method>), tambien
     * marca el primer parametro (@c this) con tipo @c Class.
     */
    void infer_concrete_types(const ir::IrFunction &fn);

    /**
     * @brief Analisis de escape per-funcion: identifica resultados de
     *        @c __new_<X> que NO escapan del scope local y son seguros
     *        para stack alloc.
     *
     * Heuristica conservativa: un value @c v PUEDE stack-allocarse si
     * TODOS sus usos son:
     *   - @c CALL/CALLVIRT/CALLM donde @c v es @c this (primer arg).
     *     Asume que los metodos no guardan @c this fuera.
     *   - @c LOAD/STORE para acceso a fields propios.
     *   - Lectura puntual (e.g. @c emit_return de @c value(t)) sin
     *     persistencia.
     *
     * SI escapa si aparece como:
     *   - @c RET (returned from function).
     *   - Operando de @c STORE como VALOR (stored to memory).
     *   - Pasado a CALL como arg distinto del primero.
     */
    void analyze_escapes(const ir::IrFunction &fn);

    /**
     * @brief Intenta reconocer el patron @c "ADD base + const_N" como
     *        acceso a un field tipado de una clase.
     *
     * @return Cadena C @c "base->fieldname" o vacio si no aplica.
     *
     * Esta optimizacion -- la pieza clave del Mode TRIVIAL -- convierte
     * aritmetica byte-wise generica del IR en accesos tipados:
     *
     *   IR:    %2 = add.ptr %this, const 24
     *          %3 = load.i32 %2
     *
     *   C sin optimizar: @c "*(int32_t*)((char*)v_this + 24)"
     *   C con esta opt:  @c "v_this->count"
     *
     * GCC genera el mismo asm en ambos casos a @c -O3, pero el segundo
     * es legible para humanos y permite alias analysis fino.
     */
    std::string try_match_field_access(EmitContext &ctx, ir::IrValueId addr,
                                       ir::IrType type) const;

    /**
     * @brief Sanitiza el nombre de una funcion para usarlo como simbolo C.
     *
     * Reemplaza caracteres invalidos (`.`, `:`, `<`, `>`, `__`) por `_`
     * para que sea un identificador C valido.  Detecta el caso especial
     * @c "main" -> @c "vx_main" para evitar colision con @c main()
     * de C cuando emit_postamble lo envuelve.
     */
    std::string sanitize_name(const std::string &n) const;

    /**
     * @brief Helper: emite el lhs de una asignacion ("v0 = ").
     */
    void emit_assign_lhs(EmitContext &ctx, ir::IrValueId dst) const;

    /**
     * @brief Para tipos sin signo, devuelve el cast C correspondiente.
     */
    std::string cast_for(ir::IrType t, bool is_host_ptr) const;

    // -------- Expression inlining (Nivel A de optimizacion) --------

    /**
     * @brief Construye la expresion C para LEER un SSA value.
     *
     * Si el value es @c is_inline_candidate (single-use + def pura),
     * recursivamente construye la expresion completa del defining
     * instr en lugar de devolver @c "v<id>".  Esto elimina variables
     * temporales y produce codigo C mas idiomatico.
     *
     * Ejemplos:
     *   - Value @c v3 con def @c "v3 = const 1": @c "v0 = v_x + v3"
     *     se convierte en @c "v0 = v_x + 1".
     *   - Cadena de constants: @c "v0 = ((10 + 20) * 3)".
     *   - Comparacion dentro de if: @c "if ((v_n <= 1)) goto bb_1;".
     */
    std::string value_expr(EmitContext &ctx, ir::IrValueId v) const;

    /**
     * @brief Construye la expresion C correspondiente al opcode + operandos
     *        de una @c IrInstr (sin asignacion lhs).  Recursivo via
     *        @c value_expr para los operandos.
     */
    std::string build_inline_expr(EmitContext &ctx,
                                  const ir::IrInstr &ins) const;

    /**
     * @brief Formatea un literal constante con su tipo C correspondiente.
     * @param imm Valor crudo (bits para float, valor para int).
     * @param t Tipo del literal.
     */
    std::string format_const_literal(uint64_t imm, ir::IrType t) const;
};

} // namespace port

#endif // PORT_C_BACKEND_H
