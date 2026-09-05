/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir_builder.h
 * @brief API de alto nivel para emitir SSA IR -- usable por cualquier frontend.
 *
 * Esta clase es el equivalente de @c llvm::IRBuilder en LLVM: encapsula los
 * detalles de construccion de @c IrInstr / @c IrValue / @c IrBlock detras de
 * una API ergonomica.  Cualquier frontend (Vesta, futuro Java-like, C-like,
 * Python-like, etc.) puede targetar este IR sin tener que conocer la
 * representacion interna.
 *
 * = Modelo de uso =
 *
 * @code
 * ir::IrModule mod;
 * mod.name = "ejemplo";
 *
 * // Crear funcion: i32 add(i32 a, i32 b)
 * auto &fn = mod.functions.emplace_back();
 * fn.name = "add";
 * fn.ret_type = ir::IrType::I32;
 * ir::IrBuilder b(fn);
 *
 * auto a = b.param(ir::IrType::I32, "a");
 * auto bb = b.param(ir::IrType::I32, "b");
 *
 * auto entry = b.new_block("entry");
 * b.set_insert_point(entry);
 *
 * auto sum = b.add(a, bb, ir::IrType::I32);
 * b.ret(sum);
 * @endcode
 *
 * = Lo que el IR garantiza al frontend (contrato) =
 *
 * - SSA estricta: cada IrValueId se define exactamente una vez (excepto
 *   los parametros que se "definen" en la entrada de la funcion).
 * - Tipos estaticos: cada valor lleva su @c IrType.  El builder valida
 *   compatibilidad en tiempo de compilacion (assertions en debug).
 * - PHI explicitos: los valores que se unen en merge points requieren
 *   @c phi() con sus phi_args (no hay "join" implicito).
 * - Memoria explicita: LOAD/STORE para acceder memoria.  ALLOCA reserva
 *   en stack.  RAW_ALLOC reserva en heap host.
 * - Calls explicitas: CALL (directa por nombre), CALLIND (via puntero),
 *   CALLVIRT (via vtable), CALLN (FFI nativo).
 *
 * = Lo que NO esta en el IR (responsabilidad del frontend) =
 *
 * - Type checking / inferencia: el frontend valida tipos antes de emitir.
 *   El IR asume que los tipos ya estan correctos.
 * - Optimizaciones AST-level: const folding de literales en source, etc.
 *   El IR optimizer hace folding sobre IR, no sobre AST.
 * - Generic monomorphization: el frontend genera una funcion IR por
 *   instanciacion concreta.  El IR no tiene concepto de generics.
 * - Closures con captura: el frontend lowera lambdas a env+helper.
 *   El IR tiene CALLCLOSURE para invocarlas (env + fn_ptr inline).
 *
 * = Extensions opcionales =
 *
 * El IR core (aritmetica, memoria, control de flujo, calls) es suficiente
 * para cualquier lenguaje imperativo.  Las extensiones son opt-in:
 *
 * - OOP: CALLVIRT + NEWOBJ + vtable.  Modelo Java-style con herencia
 *   simple.  Frontends que no usan OOP pueden ignorar estas ops.
 * - Async: SPAWN + AWAIT + FULFILL.  Modelo de procesos coroutines.
 * - Exceptions: TRYENTER + TRYLEAVE + THROW.  Modelo SEH-like con
 *   handler chain.
 * - Strings: STRMAKE + STRCAT + STRLEN.  Modelo de StringObject GC.
 * - ADTs: MAKE_VARIANT + MATCH_VARIANT (semantic markers para C2 JIT;
 *   no necesarios para correctness, solo para optimizaciones).
 *
 * El frontend que no quiera usar cierta extension simplemente NO emite
 * esas ops; el resto del pipeline (optimizer + emitter) funciona igual.
 */

#ifndef IR_BUILDER_H
#define IR_BUILDER_H

#include "ir/ssa_ir.h"
#include <string>
#include <vector>

namespace ir {

/**
 * @brief Builder ergonomico para emitir SSA IR.
 *
 * Mantiene "insert point" (bloque actual donde se appendean instrs).
 * Helpers para cada categoria de operacion con typing automatico.
 * Thread-unsafe: usar uno por funcion siendo construida.
 */
class IrBuilder {
  public:
    explicit IrBuilder(IrFunction &fn) noexcept
        : fn_(fn), current_block_(IR_NO_BLOCK) {}

    /// @return La funcion sobre la que opera el builder.
    IrFunction &function() noexcept { return fn_; }

    // -- Bloques basicos ----------------------------------------------------

    /// Crea un nuevo bloque vacio y lo agrega a la funcion.
    /// @param name nombre legible (opcional; se autogenera si esta vacio).
    IrBlockId new_block(const std::string &name = "");

    /// Establece el bloque actual donde se appendearan instrucciones.
    void set_insert_point(IrBlockId block) noexcept { current_block_ = block; }

    /// @return El bloque actual.
    IrBlockId current_block() const noexcept { return current_block_; }

    // -- Parametros ---------------------------------------------------------

    /// Crea un parametro de funcion.  Llamar en orden para todos los params
    /// ANTES de crear bloques basicos (los params se "definen" en entry).
    IrValueId param(IrType type, const std::string &name = "");

    // -- Constantes ---------------------------------------------------------

    IrValueId const_i32(int32_t v);
    IrValueId const_i64(int64_t v);
    IrValueId const_u32(uint32_t v);
    IrValueId const_u64(uint64_t v);
    IrValueId const_bool(bool v);
    IrValueId const_ptr(uint64_t addr); ///< Puntero crudo VM.
    IrValueId const_null_ptr() { return const_ptr(0); }

    // -- Aritmetica entera --------------------------------------------------

    IrValueId add(IrValueId a, IrValueId b, IrType type);
    IrValueId sub(IrValueId a, IrValueId b, IrType type);
    IrValueId mul(IrValueId a, IrValueId b, IrType type);
    IrValueId sdiv(IrValueId a, IrValueId b, IrType type); ///< signed
    IrValueId udiv(IrValueId a, IrValueId b, IrType type); ///< unsigned
    IrValueId smod(IrValueId a, IrValueId b, IrType type);
    IrValueId umod(IrValueId a, IrValueId b, IrType type);
    IrValueId neg(IrValueId v, IrType type);

    IrValueId and_(IrValueId a, IrValueId b, IrType type);
    IrValueId or_(IrValueId a, IrValueId b, IrType type);
    IrValueId xor_(IrValueId a, IrValueId b, IrType type);
    IrValueId not_(IrValueId v, IrType type);
    IrValueId shl(IrValueId a, IrValueId b, IrType type);
    IrValueId shr(IrValueId a, IrValueId b, IrType type); ///< logical
    IrValueId sar(IrValueId a, IrValueId b, IrType type); ///< arithmetic

    // -- Comparaciones ------------------------------------------------------

    IrValueId cmp_eq(IrValueId a, IrValueId b);
    IrValueId cmp_ne(IrValueId a, IrValueId b);
    IrValueId cmp_lt(IrValueId a, IrValueId b); ///< signed
    IrValueId cmp_le(IrValueId a, IrValueId b);
    IrValueId cmp_gt(IrValueId a, IrValueId b);
    IrValueId cmp_ge(IrValueId a, IrValueId b);
    IrValueId cmp_ult(IrValueId a, IrValueId b); ///< unsigned
    IrValueId cmp_ule(IrValueId a, IrValueId b);
    IrValueId cmp_ugt(IrValueId a, IrValueId b);
    IrValueId cmp_uge(IrValueId a, IrValueId b);

    // -- Casts --------------------------------------------------------------

    IrValueId sext(IrValueId v, IrType to); ///< sign-extend
    IrValueId zext(IrValueId v, IrType to); ///< zero-extend
    IrValueId trunc(IrValueId v, IrType to);
    IrValueId bitcast(IrValueId v, IrType to);

    // -- Memoria ------------------------------------------------------------

    /// Reserva @p size_bytes en el stack del proceso VM.  @return puntero VM.
    IrValueId alloca_bytes(uint32_t size_bytes);

    /// Reserva en heap host (raw malloc).  @return host_ptr (is_host_ptr=true).
    IrValueId raw_alloc(IrValueId size_bytes);
    /// Libera un host_ptr devuelto por @c raw_alloc.
    void raw_free(IrValueId ptr);

    /// Lee @p type bytes desde el puntero @p ptr.  Si @c ptr.is_host_ptr,
    /// el emisor usa @c movh (memoria host); sino @c mov (memoria VM).
    IrValueId load(IrValueId ptr, IrType type);
    /// Escribe @p value (de tipo @p type) en @p ptr.
    void store(IrValueId value, IrValueId ptr, IrType type);

    // -- Control de flujo ---------------------------------------------------

    /// Salto incondicional al bloque @p target.
    void br(IrBlockId target);

    /// Salto condicional: si @c cond != 0 va a @p t, sino a @p f.
    void br_cond(IrValueId cond, IrBlockId t, IrBlockId f);

    /// Retorna void (sin valor).
    void ret_void();
    /// Retorna @p value (debe coincidir con @c fn.ret_type).
    void ret(IrValueId value);

    /// PHI node: el valor depende de cual predecesor fue ejecutado.
    /// @param pairs lista de (predecesor_bloque, valor_desde_ese_predecesor).
    IrValueId phi(IrType type,
                  const std::vector<std::pair<IrBlockId, IrValueId>> &pairs);

    // -- Calls --------------------------------------------------------------

    /// CALL directa por nombre.  Lo resuelve el linker al patchear.
    IrValueId call(const std::string &fn_name,
                   IrValueList args, IrType ret_type);
    /// Version sin valor de retorno (void).
    void call_void(const std::string &fn_name,
                   IrValueList args);

    /// CALL indirecta via puntero a funcion (en runtime).
    IrValueId call_indirect(IrValueId fn_ptr,
                            IrValueList args,
                            IrType ret_type);

    /// CALL nativa (FFI).  @p lib_func = "lib:func" (ver vesta_io etc.).
    IrValueId call_native(const std::string &lib_func,
                          IrValueList args, IrType ret_type);

    // -- Helpers comunes ----------------------------------------------------

    /// Inserta una instruccion ya construida en el bloque actual.
    void append(IrInstr ins);

    /// Aloca un slot stack de @p n bytes + STORE inicial + return ALLOCA ptr.
    /// Util para variables locales con valor inicial.
    IrValueId alloca_init(IrValueId initial, IrType type);

  private:
    /// Crea un nuevo SSA value con tipo dado y nombre opcional.
    IrValueId new_value(IrType type, const std::string &name = "");

    /// Builder principal de instrucciones binarias.
    IrValueId binop(IrOp op, IrValueId a, IrValueId b, IrType type);

    /// Builder principal de comparaciones.
    IrValueId cmpop(IrOp op, IrValueId a, IrValueId b);

    /// Builder principal de unary ops.
    IrValueId unop(IrOp op, IrValueId v, IrType type);

    /// Builder principal de casts.
    IrValueId castop(IrOp op, IrValueId v, IrType to);

    IrFunction &fn_;
    IrBlockId current_block_;
};

} // namespace ir

#endif // IR_BUILDER_H
