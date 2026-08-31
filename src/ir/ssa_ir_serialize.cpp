/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ssa_ir_serialize.cpp
 * @brief Serializer/deserializer binario del IR SSA para embeber en .velb.
 *
 * El IR generado por el frontend Vesta se puede persistir dentro del
 * binario @c .velb en una seccion @c @ir (magic @c VEIR).  Esto permite:
 *
 *   - **JIT a partir del binario sin recompilar**: el loader recupera el
 *     IR del .velb y lo pasa al JitCompiler.  Sin esto, el JIT solo
 *     podria trabajar con codigo compilado in-process durante una
 *     ejecucion (perdiendo el speedup post-warmup en runs cortos).
 *
 *   - **AOT futuro ( D.10+)**: el optimizer del JIT puede operar
 *     ANTES de la ejecucion sobre el IR del .velb y persistir codigo
 *     nativo en un .velao adicional.
 *
 *   - **Debugging / tooling**: dumps del IR sirven para ver lo que el
 *     frontend genero sin tener que recompilar con flags especiales.
 *
 * Diseno del formato:
 *   - **Little-endian** consistente con el resto del .velb.
 *   - **Schema fijo por @c IrInstr**: serializamos SIEMPRE los mismos
 *     campos (op, type, dst, flags, source_line, imm, operands,
 *     func_name, func_ptr, target_block, false_block, phi_args)
 *     incluso si una op concreta no usa alguno.  Trade-off: ~10-20% mas
 *     de espacio que un schema variable, pero parser/writer mucho mas
 *     simples y robustos.  Una v2 podria optimizar via "op -> field set"
 *     (variable-length encoding por op) cuando el espacio importe.
 *   - **Strings con length prefix u32**: simple, no requiere escapes ni
 *     terminadores; tolera bytes arbitrarios (incluyendo NUL embebidos).
 *   - **IDs como u32**: cabe cualquier IR razonable (4G values/blocks)
 *     sin gastar el espacio de un u64.
 */

#include "ir/ssa_ir_serialize.h"

// deflate para la seccion @ir (ver kIrCompressionLevel).
#include "miniz.h"

#include <cstring>

namespace ir {

/* ===================================================================== */
/* IrValue                                                                */
/* ===================================================================== */

namespace {

// Bits del byte flags por IrValue.  Compactamos 5 bools en un byte
// en lugar de un byte por flag (ahorra ~5 bytes por SSA value).
// El orden es estable -- NO reordenar entre versiones del formato
// sin bump del version field, porque los .velb antiguos quedarian
// ininterpretables.
constexpr uint8_t IRVAL_FLAG_PARAM = 1 << 0; ///< Parametro formal de la funcion
constexpr uint8_t IRVAL_FLAG_CONST =
    1 << 1; ///< Constante compile-time (const_val valido)
constexpr uint8_t IRVAL_FLAG_HOST_PTR =
    1 << 2; ///< Puntero a memoria host (no VM)
constexpr uint8_t IRVAL_FLAG_POINTEE_HOST_PTR =
    1 << 3; ///< Puntero VM cuyo contenido apunta a host
constexpr uint8_t IRVAL_FLAG_GC_OBJECT = 1 << 4;
/// v11: el valor lleva el registro fisico donde lo dejo el asignador.  Es un
/// bit y no un byte fijo porque la mayoria de valores no lo tienen (murieron o
/// se derramaron) y el intermedio se llevaria un byte por cada uno.
constexpr uint8_t IRVAL_FLAG_HAS_REG = 1 << 5; ///< Host_ptr a objeto GC-managed

// Bits del byte flags por IrInstr.  Solo 2 bits usados: el resto
// queda para extensiones futuras sin cambio de formato.
constexpr uint8_t INSTR_FLAG_PRESERVE =
    1 << 0; ///< No eliminar aunque dst este muerto (side-effect implicito)
constexpr uint8_t INSTR_FLAG_IS_CALL_SITE =
    1 << 1; ///< Marca instruccion como call site (para stackmaps)
constexpr uint8_t INSTR_FLAG_HOST_ALLOCA =
    1 << 2; ///< ALLOCA auto-promovida a host stack ( D.jit-mem-model)
constexpr uint8_t INSTR_FLAG_HOST_ALLOCA_EXPLICIT_FREE =
    1 << 3; ///< Sprint mem-loop-fix: RAW_FREE preservado para liberar in-loop
constexpr uint8_t INSTR_FLAG_RET_IMPLICIT =
    1 << 4; ///< @Naked: RET sintetico de caida-al-final (no `return` explicito)

// Bits del byte flags por IrFunction.
constexpr uint8_t FN_FLAG_NATIVE =
    1 << 0; ///< Funcion FFI (sin body IR; solo declaracion)
constexpr uint8_t FN_FLAG_VARIADIC =
    1 << 1; ///< Acepta nargs variable (R15 contiene el count)
constexpr uint8_t FN_FLAG_NAKED =
    1 << 2; ///<  NR @Naked: sin prologo/epilogo/ret (ISRs/stubs)
constexpr uint8_t FN_FLAG_NO_FP_CONTRACT =
    1 << 3; ///< @fp(strict)/-ffp-contract=off: fp_contract=false.  Bit NEGATIVO
            ///< (se pone cuando es false) -> caches viejas sin el bit -> true.
constexpr uint8_t FN_FLAG_PRIVATE =
    1 << 4; ///< Privada al modulo: nadie de fuera puede llamarla, asi que el
            ///< modulo tiene TODOS sus sitios de llamada a la vista.  Bit
            ///< NEGATIVO a proposito (se pone cuando NO es publica), igual que
            ///< el de contraccion: el default del lenguaje es publico, y asi un
            ///< IR viejo sin el bit se lee como publico, que es lo prudente --
            ///< de una publica no se afirma nada de sus llamantes.

/**
 * @brief Serializa un @c IrValue al stream binario.
 *
 * Layout: @c [u8 type][u8 flags][u64 const_val if is_const].
 * El @c id NO se serializa porque se recupera del indice en
 * @c IrFunction::values[].  Total: 2 bytes para values normales,
 * 10 bytes para constantes (el @c const_val solo se emite si
 * @c is_const, ahorrando 8 bytes por value no-constante; en una
 * funcion tipica >70% de los values no son constantes, asi que
 * el ahorro acumulado es significativo).
 */
void write_value(std::vector<uint8_t> &o, const IrValue &v) {
    write_u8(o, static_cast<uint8_t>(v.type));
    // Compactar los 5 bools en un byte para minimizar el footprint
    // del IR serializado (los values son la mayoria del .velb IR).
    uint8_t flags = 0;
    if (v.is_param) flags |= IRVAL_FLAG_PARAM;
    if (v.is_const) flags |= IRVAL_FLAG_CONST;
    if (v.is_host_ptr) flags |= IRVAL_FLAG_HOST_PTR;
    if (v.pointee_is_host_ptr) flags |= IRVAL_FLAG_POINTEE_HOST_PTR;
    if (v.is_gc_object) flags |= IRVAL_FLAG_GC_OBJECT;
    if (v.reg != IR_NO_REG) flags |= IRVAL_FLAG_HAS_REG;
    write_u8(o, flags);
    // Solo paga el byte quien vive en un registro (ver IRVAL_FLAG_HAS_REG).
    if (v.reg != IR_NO_REG) write_u8(o, v.reg);
    // Optimizacion: const_val solo ocupa espacio si el value es
    // realmente una constante.  Una funcion tipica tiene ~30%
    // constantes, el resto son SSA values normales que no necesitan
    // const_val.  El deserializer respeta el flag.
    if (v.is_const) {
        write_u64(o, v.const_val);
    }
}

/**
 * @brief Deserializa un @c IrValue desde el stream binario.
 *
 * Inverso exacto de @c write_value.  Los @c read_u8 / @c read_u64
 * devuelven false si no hay suficientes bytes restantes; cualquier
 * fallo propaga inmediatamente.  Si el bit @c is_const no esta
 * activo, @c const_val queda en 0 (valor default del IrValue
 * recien construido).
 */
bool read_value(const std::vector<uint8_t> &in, size_t &off, IrValue &v) {
    uint8_t type_byte = 0, flags = 0;
    // Lecturas defensivas: si el buffer se acaba, abort temprano.
    if (!read_u8(in, off, type_byte)) return false;
    if (!read_u8(in, off, flags)) return false;
    v.type = static_cast<IrType>(type_byte);
    // Decodificacion explicita de cada bit a su bool correspondiente.
    // El compilador idealmente lo colapsa a operaciones bitwise + cmovs.
    v.is_param = (flags & IRVAL_FLAG_PARAM) != 0;
    v.is_const = (flags & IRVAL_FLAG_CONST) != 0;
    v.is_host_ptr = (flags & IRVAL_FLAG_HOST_PTR) != 0;
    v.pointee_is_host_ptr = (flags & IRVAL_FLAG_POINTEE_HOST_PTR) != 0;
    v.is_gc_object = (flags & IRVAL_FLAG_GC_OBJECT) != 0;
    // v11: el registro solo viaja si el valor tenia uno.
    if (flags & IRVAL_FLAG_HAS_REG) {
        if (!read_u8(in, off, v.reg)) return false;
    } else {
        v.reg = IR_NO_REG;
    }
    // const_val solo se leyo si el writer la emitio; sin el flag
    // queda en su valor default (0).  Mismo principio que write_value.
    if (v.is_const) {
        if (!read_u64(in, off, v.const_val)) return false;
    }
    return true;
}

/**
 * @brief Serializa un @c IrInstr completo al stream binario.
 *
 * Tamano por instr: ~30 bytes minimo + 4 por operando + tamano
 * del func_name + 8 por phi_arg.  En IR tipico (~200 instrs por
 * funcion) -> ~10-15 KB por funcion serializada.
 *
 * Schema fijo: emitimos TODOS los campos aunque la op especifica
 * no los use.  Ejemplo: @c IrOp::ADD no usa @c target_block ni
 * @c phi_args pero igual los emitimos como 0 / vacio.  Esto
 * sacrifica espacio por simplificar el formato y permite que el
 * deserializer use un solo path sin tener que conocer el set de
 * campos por op.
 */
void write_instr(std::vector<uint8_t> &o, const IrInstr &i) {
    // op va en u16 porque el set de opcodes ya pasa los 200 (no
    // cabe en u8) y queremos espacio para crecer sin cambio de
    // formato.
    write_u16(o, static_cast<uint16_t>(i.op));
    write_u8(o, static_cast<uint8_t>(i.type));
    // dst es IrValueId (u32 en el storage).  IR_NO_VALUE (UINT32_MAX)
    // indica "esta op no produce valor" (e.g. STORE, RET void).
    write_u32(o, static_cast<uint32_t>(i.dst));
    uint8_t flags = 0;
    if (i.preserve) flags |= INSTR_FLAG_PRESERVE;
    if (i.is_call_site) flags |= INSTR_FLAG_IS_CALL_SITE;
    if (i.ret_implicit) flags |= INSTR_FLAG_RET_IMPLICIT;
    if (i.host_alloca) flags |= INSTR_FLAG_HOST_ALLOCA;
    if (i.host_alloca_explicit_free)
        flags |= INSTR_FLAG_HOST_ALLOCA_EXPLICIT_FREE;
    write_u8(o, flags);
    // source_line: util para diagnosticos y stack traces.  0 si
    // el frontend no aporto info de linea.
    write_u32(o, i.source_line);
    // source_column: sin ella no se puede senalar CUAL de las cosas que caben
    // en una linea fallo, solo en cual.  Viaja desde v8.
    write_u32(o, i.source_column);
    // source_len: donde ACABA el trozo de fuente.  Con la columna sola se
    // sabe donde empieza, y sin el final no se puede recortar el texto para
    // nombrar un operando.  Viaja desde v9.
    write_u32(o, i.source_len);
    // inline_site: de que llamada aplanada vino la instruccion (v10).
    write_u32(o, i.inline_site);
    // imm: campo polivalente.  Para CONST contiene el valor; para
    // CALL contiene flags/args adicionales; para ops sin imm es 0.
    write_u64(o, i.imm);
    // operands: lista de IrValueId.  Maximo 255 por op (suficiente
    // para cualquier op concebible; CALL con mas args es raro pero
    // tampoco esperamos > 255 args reales en codigo Vesta normal).
    const size_t opc = i.operands.size();
    write_u8(o, opc > 255 ? 255 : static_cast<uint8_t>(opc));
    for (size_t k = 0; k < opc && k < 255; ++k) {
        write_u32(o, static_cast<uint32_t>(i.operands[k]));
    }
    // func_name: solo significativo para CALL/CALLN/CALLIND.
    // Para otras ops queda como cadena vacia (write_str emite
    // un u32=0 length sin payload).
    write_str(o, i.func_name);
    // func_ptr (puntero a funcion para CALLIND/CALLCLOSURE) +
    // target_block y false_block (para BR/BR_COND).  Cero si la
    // op no los usa.
    write_u32(o, static_cast<uint32_t>(i.func_ptr));
    write_u32(o, static_cast<uint32_t>(i.target_block));
    write_u32(o, static_cast<uint32_t>(i.false_block));
    // phi_args: lista de (block, value) para PHI nodes.  Vacio
    // para ops no-PHI.  Mismo limite de 255 por simetria con
    // operands.
    const size_t pc = i.phi_args.size();
    write_u8(o, pc > 255 ? 255 : static_cast<uint8_t>(pc));
    for (size_t k = 0; k < pc && k < 255; ++k) {
        write_u32(o, static_cast<uint32_t>(i.phi_args[k].value));
        write_u32(o, static_cast<uint32_t>(i.phi_args[k].block));
    }
    // jump_targets: tabla de bloques del SWITCH_DENSE (jump table denso).
    // Count u32 (un switch denso puede tener >255 entradas).  Vacio en el
    // resto de ops.  (Formato v6/v8.)
    const size_t jtc = i.jump_targets.size();
    write_u32(o, static_cast<uint32_t>(jtc));
    for (size_t k = 0; k < jtc; ++k)
        write_u32(o, i.jump_targets[k]);
    // call_abi_regs: ABI custom del CALLIND (registro por arg desde el tipo del
    // puntero).  Count 0 = ABI estandar (todas las ops no-CALLIND).  (Formato
    // v7.)
    const size_t abc = i.call_abi_regs.size();
    write_u32(o, static_cast<uint32_t>(abc));
    for (size_t k = 0; k < abc; ++k)
        write_str(o, i.call_abi_regs[k]);
}

/**
 * @brief Deserializa un @c IrInstr completo desde el stream.
 *
 * Inverso exacto de @c write_instr.  Cualquier @c read_* que
 * falle (buffer truncado) propaga inmediatamente con false.
 *
 * Garantia post-condicion: si retorna true, todos los campos de
 * @c i estan poblados con valores consistentes.  Los vectors
 * (@c operands, @c phi_args) fueron clear+reserve+push para
 * evitar fragmentacion del heap incluso en programas con muchas
 * funciones.
 */
bool read_instr(const std::vector<uint8_t> &in, size_t &off, IrInstr &i) {
    uint16_t op_v = 0;
    uint8_t type_v = 0, flags = 0;
    uint32_t dst_v = 0, source_line = 0;
    uint64_t imm = 0;
    // Lecturas en exactamente el mismo orden que el writer; los
    // fallos cortan toda la operacion (NO intentamos recovery
    // parcial: una IR malformada no es util incluso si recuperamos
    // la primera mitad).
    if (!read_u16(in, off, op_v)) return false;
    if (!read_u8(in, off, type_v)) return false;
    if (!read_u32(in, off, dst_v)) return false;
    if (!read_u8(in, off, flags)) return false;
    if (!read_u32(in, off, source_line)) return false;
    uint32_t source_column = 0;
    if (!read_u32(in, off, source_column)) return false;
    uint32_t source_len = 0;
    if (!read_u32(in, off, source_len)) return false;
    uint32_t inline_site = IR_NO_INLINE_SITE;
    if (!read_u32(in, off, inline_site)) return false;
    if (!read_u64(in, off, imm)) return false;
    i.op = static_cast<IrOp>(op_v);
    i.type = static_cast<IrType>(type_v);
    i.dst = static_cast<IrValueId>(dst_v);
    i.preserve = (flags & INSTR_FLAG_PRESERVE) != 0;
    i.is_call_site = (flags & INSTR_FLAG_IS_CALL_SITE) != 0;
    i.ret_implicit = (flags & INSTR_FLAG_RET_IMPLICIT) != 0;
    i.host_alloca = (flags & INSTR_FLAG_HOST_ALLOCA) != 0;
    i.host_alloca_explicit_free =
        (flags & INSTR_FLAG_HOST_ALLOCA_EXPLICIT_FREE) != 0;
    i.source_line = source_line;
    i.source_column = source_column;
    i.source_len = source_len;
    i.inline_site = inline_site;
    i.imm = imm;
    /* operands */
    uint8_t opc = 0;
    if (!read_u8(in, off, opc)) return false;
    i.operands.clear();
    i.operands.reserve(opc);
    for (uint8_t k = 0; k < opc; ++k) {
        uint32_t v = 0;
        if (!read_u32(in, off, v)) return false;
        i.operands.push_back(static_cast<IrValueId>(v));
    }
    /* func_name */
    if (!read_str(in, off, i.func_name)) return false;
    /* func_ptr / target_block / false_block */
    uint32_t fp = 0, tb = 0, fb = 0;
    if (!read_u32(in, off, fp)) return false;
    if (!read_u32(in, off, tb)) return false;
    if (!read_u32(in, off, fb)) return false;
    i.func_ptr = static_cast<IrValueId>(fp);
    i.target_block = static_cast<IrBlockId>(tb);
    i.false_block = static_cast<IrBlockId>(fb);
    /* phi_args */
    uint8_t pc = 0;
    if (!read_u8(in, off, pc)) return false;
    i.phi_args.clear();
    i.phi_args.reserve(pc);
    for (uint8_t k = 0; k < pc; ++k) {
        uint32_t v = 0, b = 0;
        if (!read_u32(in, off, v)) return false;
        if (!read_u32(in, off, b)) return false;
        IrPhiArg a{static_cast<IrValueId>(v), static_cast<IrBlockId>(b)};
        i.phi_args.push_back(a);
    }
    /* jump_targets (SWITCH_DENSE) -- formato v6/v8. */
    uint32_t jtc = 0;
    if (!read_u32(in, off, jtc)) return false;
    i.jump_targets.clear();
    i.jump_targets.reserve(jtc);
    for (uint32_t k = 0; k < jtc; ++k) {
        uint32_t t = 0;
        if (!read_u32(in, off, t)) return false;
        i.jump_targets.push_back(t);
    }
    /* call_abi_regs (ABI custom del CALLIND) -- formato v7. */
    uint32_t abc = 0;
    if (!read_u32(in, off, abc)) return false;
    i.call_abi_regs.clear();
    i.call_abi_regs.reserve(abc);
    for (uint32_t k = 0; k < abc; ++k) {
        std::string r;
        if (!read_str(in, off, r)) return false;
        i.call_abi_regs.push_back(std::move(r));
    }
    return true;
}

void write_block(std::vector<uint8_t> &o, const IrBlock &b) {
    write_str(o, b.name);
    write_u32(o, static_cast<uint32_t>(b.instrs.size()));
    for (const auto &i : b.instrs)
        write_instr(o, i);
    write_u32(o, static_cast<uint32_t>(b.preds.size()));
    for (auto p : b.preds)
        write_u32(o, static_cast<uint32_t>(p));
    write_u32(o, static_cast<uint32_t>(b.succs.size()));
    for (auto s : b.succs)
        write_u32(o, static_cast<uint32_t>(s));
}

bool read_block(const std::vector<uint8_t> &in, size_t &off, IrBlock &b) {
    if (!read_str(in, off, b.name)) return false;
    uint32_t n_instrs = 0;
    if (!read_u32(in, off, n_instrs)) return false;
    b.instrs.clear();
    b.instrs.reserve(n_instrs);
    for (uint32_t k = 0; k < n_instrs; ++k) {
        IrInstr i;
        if (!read_instr(in, off, i)) return false;
        b.instrs.push_back(std::move(i));
    }
    uint32_t n_preds = 0;
    if (!read_u32(in, off, n_preds)) return false;
    b.preds.clear();
    b.preds.reserve(n_preds);
    for (uint32_t k = 0; k < n_preds; ++k) {
        uint32_t v = 0;
        if (!read_u32(in, off, v)) return false;
        b.preds.push_back(static_cast<IrBlockId>(v));
    }
    uint32_t n_succs = 0;
    if (!read_u32(in, off, n_succs)) return false;
    b.succs.clear();
    b.succs.reserve(n_succs);
    for (uint32_t k = 0; k < n_succs; ++k) {
        uint32_t v = 0;
        if (!read_u32(in, off, v)) return false;
        b.succs.push_back(static_cast<IrBlockId>(v));
    }
    return true;
}

} // namespace

/* ===================================================================== */
/* serialize_function / deserialize_function                              */
/* ===================================================================== */

/**
 * @brief Serializa una @c IrFunction completa.
 *
 * @return Numero de bytes que se escribieron en @c out (la posicion
 *         final menos la inicial).  Util si el caller quiere saber
 *         el tamano de esta funcion concreta sin recalcular.
 *
 * Orden de campos en el stream:
 *   1. name (string)
 *   2. ret_type (u8) + fn_flags (u8: native, variadic)
 *   3. params: count u32 + IrValueId[count]
 *   4. values: count u32 + IrValue[count]  (cada uno con su layout)
 *   5. blocks: count u32 + IrBlock[count]
 *   6. metadata de generics: template_name + n type_args + type_args[]
 */
size_t serialize_function(const IrFunction &fn, std::vector<uint8_t> &out) {
    const size_t start = out.size();

    write_str(out, fn.name);
    write_u8(out, static_cast<uint8_t>(fn.ret_type));
    // Empaquetar los 2 bools de la funcion en un solo byte (mismo
    // patron que en values).
    uint8_t fn_flags = 0;
    if (fn.is_native) fn_flags |= FN_FLAG_NATIVE;
    if (fn.is_variadic) fn_flags |= FN_FLAG_VARIADIC;
    if (fn.is_naked) fn_flags |= FN_FLAG_NAKED;
    if (!fn.fp_contract) fn_flags |= FN_FLAG_NO_FP_CONTRACT;
    if (!fn.is_public) fn_flags |= FN_FLAG_PRIVATE;
    write_u8(out, fn_flags);

    // Params: lista de IrValueId que apuntan a entries en values[]
    // que tienen is_param=true.  Duplicacion intencional para que el
    // lookup "i-esimo parametro" sea O(1) sin filtrar values[].
    write_u32(out, static_cast<uint32_t>(fn.params.size()));
    for (auto p : fn.params)
        write_u32(out, static_cast<uint32_t>(p));

    // ABI custom por funcion (register("rXX") en params): registro fisico de
    // entrada por parametro, alineado con params[].  Count 0 = ABI estandar (el
    // caso comun; no ocupa mas que el u32 del count).
    write_u32(out, static_cast<uint32_t>(fn.param_abi_regs.size()));
    for (const auto &r : fn.param_abi_regs)
        write_str(out, r);

    // Values: TODOS los SSA values de la funcion.  El indice en este
    // array ES el IrValueId (los ids son densos 0..N-1).
    write_u32(out, static_cast<uint32_t>(fn.values.size()));
    for (const auto &v : fn.values)
        write_value(out, v);

    // Blocks: cada uno incluye sus propias instrs + preds + succs.
    // El indice en este array ES el IrBlockId.
    write_u32(out, static_cast<uint32_t>(fn.blocks.size()));
    for (const auto &b : fn.blocks)
        write_block(out, b);

    // Metadata para generics monomorphizados: el frontend Vesta setea
    // template_name (e.g. "List") y type_args (e.g. ["i32"]) al
    // monomorphizar @c List<i32>.  Util para tools que quieran
    // mostrar el template original en stack traces; el JIT no lo usa.
    write_str(out, fn.generic_template_name);
    write_u32(out, static_cast<uint32_t>(fn.generic_type_args.size()));
    for (const auto &s : fn.generic_type_args)
        write_str(out, s);

    //  AS inc.5: bindings register() + clobber-lists del inline-asm.
    // Necesarios para que el JIT (que compila desde el @ir del .velb)
    // reconstruya el pin de registros del INLINE_ASM.  La mayoria de
    // funciones tienen ambos vacios (8 bytes: dos counts a 0).
    write_u32(out, static_cast<uint32_t>(fn.asm_reg_bindings.size()));
    for (const auto &b : fn.asm_reg_bindings) {
        write_u32(out, static_cast<uint32_t>(b.alloca_value));
        write_str(out, b.reg);
        write_u8(out, static_cast<uint8_t>(b.type));
        write_u8(out, b.is_vector ? 1u : 0u);
        write_str(out, b.name);
        // operando `reg` auto (RA elige el fisico) + su placeholder $N.
        write_u8(out, b.reg_auto ? 1u : 0u);
        write_u32(out, static_cast<uint32_t>(b.ph_index));
        /* La clase declarada (v13).  Tiene que cruzar esta frontera: el AOT y
         * el JIT compilan desde el IR serializado, no desde el de memoria, y
         * sin la clase el ancho del operando se pierde justo donde hace falta
         * comprobarlo. */
        write_str(out, b.reg_class);
    }
    write_u32(out, static_cast<uint32_t>(fn.asm_clobber_lists.size()));
    for (const auto &lst : fn.asm_clobber_lists) {
        write_u32(out, static_cast<uint32_t>(lst.size()));
        for (const auto &s : lst)
            write_str(out, s);
    }
    /* Prestamos (v12).  Lo que el borrow checker demuestra tiene que cruzar
     * esta frontera o no lo ve nadie: `--analyze`, el JIT y el AOT leen el IR
     * de la cache, no el de memoria.  Vacio en casi todas las funciones. */
    write_u32(out, static_cast<uint32_t>(fn.borrow_facts.size()));
    for (const auto &b : fn.borrow_facts) {
        write_u32(out, static_cast<uint32_t>(b.value));
        write_u32(out, static_cast<uint32_t>(b.owner));
        write_u8(out, b.mutable_ ? 1u : 0u);
        write_u8(out, static_cast<uint8_t>(b.owner_kind));
        write_u32(out, b.line);
        write_str(out, b.owner_name);
    }
    // ASA: instrucciones ASM_MICRO (asm opaco liftado).  El @c imm de cada
    // IrInstr ASM_MICRO indexa esta tabla; necesaria para que JIT/AOT (que
    // compilan desde el @ir del .velb/.vxir) reconstruyan la plantilla + los
    // efectos.  Casi siempre vacio (4 bytes: un count a 0).
    write_u32(out, static_cast<uint32_t>(fn.asm_micros.size()));
    for (const auto &am : fn.asm_micros) {
        write_u8(out, am.isa);
        write_u32(out, am.form_id);
        write_str(out, am.tmpl);
        write_u8(out, am.eff);
        // Lista PLANA de operandos (orden textual; roles en flags).
        write_u32(out, static_cast<uint32_t>(am.operands.size()));
        for (const auto &op : am.operands) {
            write_u8(out, static_cast<uint8_t>(op.kind));
            write_u8(out, op.flags);
            write_u8(out, op.regclass);
            write_u32(out, static_cast<uint32_t>(op.width));
            write_u32(out, static_cast<uint32_t>(
                               static_cast<uint16_t>(op.fixed_phys)));
            write_u32(out, static_cast<uint32_t>(op.value));
            write_u64(out, static_cast<uint64_t>(op.imm));
        }
    }

    // AOT 2b: seccion de salida del codigo + permisos (dev OS).
    write_str(out, fn.section);
    write_str(out, fn.section_perms);
    // AOT: ubicacion fija (@at) + orden (@order) de la seccion.
    write_u64(out, (uint64_t)fn.section_at);
    write_u32(out, (uint32_t)fn.section_order);

    // Subsistema de coste (--analyze): contrato @complexity.  Metadata pura;
    // viaja en el cache para que el modo --analyze (que reusa el .vxir /
    // ir_module_cache_bytes) pueda comparar contra la complejidad inferida.
    write_str(out, fn.complexity_expr);
    write_u32(out, static_cast<uint32_t>(fn.complexity_vars.size()));
    for (const auto &s : fn.complexity_vars)
        write_str(out, s);
    // v5/v6: contratos @complexity por dimension (PARCIAL/TOTAL x PRE/POST).
    write_str(out, fn.complexity_partial_pre);
    write_str(out, fn.complexity_partial_post);
    write_str(out, fn.complexity_total_pre);
    write_str(out, fn.complexity_total_post);

    // v10: llamadas que se aplanaron aqui al inlinar.  Sin ellas, el codigo
    // que vino de otra funcion conserva SUS lineas pero se atribuye a esta, y
    // la traza senala un sitio que no es.  Casi siempre vacio (4 bytes).
    write_u32(out, static_cast<uint32_t>(fn.inline_sites.size()));
    for (const auto &s : fn.inline_sites) {
        write_str(out, s.callee);
        write_u32(out, s.line);
        write_u32(out, s.column);
        write_u32(out, s.parent);
    }

    return out.size() - start;
}

bool deserialize_function(const std::vector<uint8_t> &in, size_t &off,
                          IrFunction &out) {
    out = IrFunction{};

    if (!read_str(in, off, out.name)) return false;
    uint8_t ret_type_b = 0, fn_flags = 0;
    if (!read_u8(in, off, ret_type_b)) return false;
    if (!read_u8(in, off, fn_flags)) return false;
    out.ret_type = static_cast<IrType>(ret_type_b);
    out.is_native = (fn_flags & FN_FLAG_NATIVE) != 0;
    out.is_variadic = (fn_flags & FN_FLAG_VARIADIC) != 0;
    out.is_naked = (fn_flags & FN_FLAG_NAKED) != 0;
    out.fp_contract = (fn_flags & FN_FLAG_NO_FP_CONTRACT) == 0;
    out.is_public = (fn_flags & FN_FLAG_PRIVATE) == 0;

    /* params */
    uint32_t n_params = 0;
    if (!read_u32(in, off, n_params)) return false;
    out.params.clear();
    out.params.reserve(n_params);
    for (uint32_t k = 0; k < n_params; ++k) {
        uint32_t v = 0;
        if (!read_u32(in, off, v)) return false;
        out.params.push_back(static_cast<IrValueId>(v));
    }

    /* ABI custom por funcion (register en params): registro por parametro. */
    uint32_t n_abi = 0;
    if (!read_u32(in, off, n_abi)) return false;
    out.param_abi_regs.clear();
    out.param_abi_regs.reserve(n_abi);
    for (uint32_t k = 0; k < n_abi; ++k) {
        std::string r;
        if (!read_str(in, off, r)) return false;
        out.param_abi_regs.push_back(std::move(r));
    }

    /* values */
    uint32_t n_values = 0;
    if (!read_u32(in, off, n_values)) return false;
    out.values.clear();
    out.values.reserve(n_values);
    for (uint32_t k = 0; k < n_values; ++k) {
        IrValue v;
        v.id = static_cast<IrValueId>(k); /* id es el indice en el vector */
        if (!read_value(in, off, v)) return false;
        out.values.push_back(std::move(v));
    }

    /* blocks */
    uint32_t n_blocks = 0;
    if (!read_u32(in, off, n_blocks)) return false;
    out.blocks.clear();
    out.blocks.reserve(n_blocks);
    for (uint32_t k = 0; k < n_blocks; ++k) {
        IrBlock b;
        b.id = static_cast<IrBlockId>(k); /* id es el indice */
        if (!read_block(in, off, b)) return false;
        out.blocks.push_back(std::move(b));
    }

    /* metadata */
    if (!read_str(in, off, out.generic_template_name)) return false;
    uint32_t n_args = 0;
    if (!read_u32(in, off, n_args)) return false;
    out.generic_type_args.clear();
    out.generic_type_args.reserve(n_args);
    for (uint32_t k = 0; k < n_args; ++k) {
        std::string s;
        if (!read_str(in, off, s)) return false;
        out.generic_type_args.push_back(std::move(s));
    }

    /*  AS inc.5: bindings register() + clobber-lists del inline-asm. */
    uint32_t n_bind = 0;
    if (!read_u32(in, off, n_bind)) return false;
    out.asm_reg_bindings.clear();
    out.asm_reg_bindings.reserve(n_bind);
    for (uint32_t k = 0; k < n_bind; ++k) {
        AsmRegBinding b;
        uint32_t av = 0;
        uint8_t ty = 0, vec = 0;
        if (!read_u32(in, off, av)) return false;
        b.alloca_value = static_cast<IrValueId>(av);
        if (!read_str(in, off, b.reg)) return false;
        if (!read_u8(in, off, ty)) return false;
        b.type = static_cast<IrType>(ty);
        if (!read_u8(in, off, vec)) return false;
        b.is_vector = (vec != 0);
        if (!read_str(in, off, b.name)) return false;
        // reg_auto + ph_index.
        uint8_t ra_auto = 0;
        uint32_t phi = 0;
        if (!read_u8(in, off, ra_auto)) return false;
        if (!read_u32(in, off, phi)) return false;
        b.reg_auto = (ra_auto != 0);
        b.ph_index = static_cast<int>(static_cast<int32_t>(phi));
        // Clase declarada (v13): ver la nota del emisor.
        if (!read_str(in, off, b.reg_class)) return false;
        out.asm_reg_bindings.push_back(std::move(b));
    }
    uint32_t n_clob = 0;
    if (!read_u32(in, off, n_clob)) return false;
    out.asm_clobber_lists.clear();
    out.asm_clobber_lists.reserve(n_clob);
    for (uint32_t k = 0; k < n_clob; ++k) {
        uint32_t n_s = 0;
        if (!read_u32(in, off, n_s)) return false;
        std::vector<std::string> lst;
        lst.reserve(n_s);
        for (uint32_t j = 0; j < n_s; ++j) {
            std::string s;
            if (!read_str(in, off, s)) return false;
            lst.push_back(std::move(s));
        }
        out.asm_clobber_lists.push_back(std::move(lst));
    }
    /* Prestamos (v12): ver la nota del emisor. */
    uint32_t n_pres = 0;
    if (!read_u32(in, off, n_pres)) return false;
    out.borrow_facts.clear();
    out.borrow_facts.reserve(n_pres);
    for (uint32_t k = 0; k < n_pres; ++k) {
        IrFunction::BorrowFact b;
        uint32_t v = 0, o = 0;
        uint8_t mut = 0, kind = 0;
        if (!read_u32(in, off, v)) return false;
        if (!read_u32(in, off, o)) return false;
        if (!read_u8(in, off, mut)) return false;
        if (!read_u8(in, off, kind)) return false;
        if (!read_u32(in, off, b.line)) return false;
        if (!read_str(in, off, b.owner_name)) return false;
        b.value = static_cast<IrValueId>(v);
        b.owner = static_cast<IrValueId>(o);
        b.mutable_ = (mut != 0);
        b.owner_kind = static_cast<IrFunction::BorrowOwnerKind>(kind);
        out.borrow_facts.push_back(std::move(b));
    }
    // ASA: instrucciones ASM_MICRO (asm opaco liftado).
    uint32_t n_micro = 0;
    if (!read_u32(in, off, n_micro)) return false;
    out.asm_micros.clear();
    out.asm_micros.reserve(n_micro);
    for (uint32_t k = 0; k < n_micro; ++k) {
        AsmMicro am;
        uint8_t isa_u = 0, eff_u = 0;
        if (!read_u8(in, off, isa_u)) return false;
        am.isa = isa_u;
        if (!read_u32(in, off, am.form_id)) return false;
        if (!read_str(in, off, am.tmpl)) return false;
        if (!read_u8(in, off, eff_u)) return false;
        am.eff = eff_u;
        uint32_t n_ops = 0;
        if (!read_u32(in, off, n_ops)) return false;
        am.operands.reserve(n_ops);
        for (uint32_t j = 0; j < n_ops; ++j) {
            AsmMicroOperand op;
            uint8_t kind = 0, flags = 0, rc = 0;
            uint32_t wid = 0, fx = 0, val = 0;
            uint64_t imm = 0;
            if (!read_u8(in, off, kind)) return false;
            if (!read_u8(in, off, flags)) return false;
            if (!read_u8(in, off, rc)) return false;
            if (!read_u32(in, off, wid)) return false;
            if (!read_u32(in, off, fx)) return false;
            if (!read_u32(in, off, val)) return false;
            if (!read_u64(in, off, imm)) return false;
            op.kind = static_cast<AsmOperandKind>(kind);
            op.flags = flags;
            op.regclass = rc;
            op.width = static_cast<uint16_t>(wid);
            op.fixed_phys = static_cast<int16_t>(static_cast<uint16_t>(fx));
            op.value = static_cast<IrValueId>(val);
            op.imm = static_cast<int64_t>(imm);
            am.operands.push_back(op);
        }
        out.asm_micros.push_back(std::move(am));
    }
    // AOT 2b: seccion de salida del codigo + permisos.
    if (!read_str(in, off, out.section)) return false;
    if (!read_str(in, off, out.section_perms)) return false;
    // AOT: ubicacion fija (@at) + orden (@order).
    uint64_t at_u = 0;
    uint32_t ord_u = 0;
    if (!read_u64(in, off, at_u)) return false;
    if (!read_u32(in, off, ord_u)) return false;
    out.section_at = (int64_t)at_u;
    out.section_order = (int32_t)ord_u;
    // Subsistema de coste (--analyze): contrato @complexity.
    if (!read_str(in, off, out.complexity_expr)) return false;
    uint32_t cvn = 0;
    if (!read_u32(in, off, cvn)) return false;
    out.complexity_vars.clear();
    out.complexity_vars.reserve(cvn);
    for (uint32_t k = 0; k < cvn; ++k) {
        std::string s;
        if (!read_str(in, off, s)) return false;
        out.complexity_vars.push_back(std::move(s));
    }
    // v5/v6: contratos @complexity por dimension (PARCIAL/TOTAL x PRE/POST).
    if (!read_str(in, off, out.complexity_partial_pre)) return false;
    if (!read_str(in, off, out.complexity_partial_post)) return false;
    if (!read_str(in, off, out.complexity_total_pre)) return false;
    if (!read_str(in, off, out.complexity_total_post)) return false;
    // v10: llamadas aplanadas al inlinar (ver el lado de escritura).
    uint32_t n_sites = 0;
    if (!read_u32(in, off, n_sites)) return false;
    out.inline_sites.clear();
    out.inline_sites.reserve(n_sites);
    for (uint32_t k = 0; k < n_sites; ++k) {
        InlineSite s;
        if (!read_str(in, off, s.callee)) return false;
        if (!read_u32(in, off, s.line)) return false;
        if (!read_u32(in, off, s.column)) return false;
        if (!read_u32(in, off, s.parent)) return false;
        out.inline_sites.push_back(std::move(s));
    }
    return true;
}

/* ===================================================================== */
/* emit_ir_section / parse_ir_section                                     */
/* ===================================================================== */

/**
 * @brief Emite la seccion @c @ir completa para el .velb.
 *
 * Layout de la seccion:
 *   - Header (12 bytes):
 *     - u32 magic (@c VEIR)
 *     - u16 version
 *     - u16 reserved (0 para alineamiento, futuras flags)
 *     - u32 fn_count
 *   - fn_count funciones concatenadas (cada una serializada por
 *     @c serialize_function).
 *
 * El caller (linker .velb) toma el resultado y lo escribe en una
 * seccion dedicada del binario.  El loader, al detectar la seccion,
 * llama a @c parse_ir_section para reconstruir el vector de IrFunctions.
 */
std::vector<uint8_t> emit_ir_section(const std::vector<IrFunction> &functions) {
    // Primero el cuerpo en claro: las funciones concatenadas.  No hay padding
    // entre ellas; el parser avanza con el tamano de cada una.
    std::vector<uint8_t> cuerpo;
    cuerpo.reserve(functions.size() * 512);
    for (const auto &fn : functions) {
        (void)serialize_function(fn, cuerpo); // ignoramos el retorno aqui
    }

    /* Y se COMPRIME.  Esta seccion es, con diferencia, la parte mas grande del
     * artefacto: medido en un proyecto de 6k lineas, 5,75 MiB de los 7,56 --
     * el 76% --, y el fichero entero se reescribe en cada reconstruccion.
     *
     * Comprime muchisimo porque es una serializacion muy repetitiva.  Sobre esa
     * seccion real, con miniz: nivel 3 da 13,8x en 22,9 ms, y el 6 da 15,2x en
     * 56,8.  Se usa el 3 porque la diferencia de tamano son 40 KiB sobre 7,5
     * MiB -- nada -- y el tiempo es menos de la mitad.
     *
     * El reparto del coste cae donde debe: comprimir se paga UNA vez, al
     * producir el artefacto (~23 ms sobre los ~1,9 s de una compilacion en
     * frio), mientras que el ahorro se cobra cada vez que el artefacto se
     * escribe, se lee o se guarda en un cache.  Descomprimir (~4 ms) solo lo
     * paga quien de verdad use el intermedio: el JIT y el AOT. */
    std::vector<uint8_t> out;
    out.reserve(64 + cuerpo.size() / 8);
    write_u32(out, IR_SECTION_MAGIC);
    write_u16(out, IR_SECTION_VERSION);

    mz_ulong tope = mz_compressBound(static_cast<mz_ulong>(cuerpo.size()));
    std::vector<uint8_t> comprimido(tope);
    mz_ulong final_len = tope;
    const bool ok = !cuerpo.empty() &&
                    mz_compress2(comprimido.data(), &final_len, cuerpo.data(),
                                 static_cast<mz_ulong>(cuerpo.size()),
                                 kIrCompressionLevel) == MZ_OK &&
                    final_len < cuerpo.size();

    if (ok) {
        write_u16(out, kIrFlagDeflate);
        write_u32(out, static_cast<uint32_t>(functions.size()));
        // Cuanto ocupa en claro: quien lo lea necesita saber cuanto reservar
        // antes de descomprimir, y fiarse de lo que diga el propio flujo seria
        // fiarse de un fichero que puede estar corrupto.
        write_u32(out, static_cast<uint32_t>(cuerpo.size()));
        out.insert(out.end(), comprimido.begin(),
                   comprimido.begin() + static_cast<size_t>(final_len));
    } else {
        /* Sin comprimir, y no es un caso de error: una seccion vacia, o una que
         * no encoge, se guarda tal cual.  Que el formato admita las dos formas
         * evita tener que decidir aqui si "no comprimio" es un fallo. */
        write_u16(out, 0);
        write_u32(out, static_cast<uint32_t>(functions.size()));
        out.insert(out.end(), cuerpo.begin(), cuerpo.end());
    }
    return out;
}

/**
 * @brief Parsea la seccion @c @ir desde un buffer (tipicamente el
 *        mmap del .velb).
 *
 * @param data         Buffer completo del .velb (lectura solo).
 * @param offset       Offset dentro de @c data donde empieza @c VEIR.
 * @param section_size Tamano de la seccion (segun el header del .velb).
 * @param functions    Vector que rellenamos.  Se @c clear primero, asi
 *                     llamar repetidamente sobre el mismo vector funciona.
 * @return @c true si el parseo fue exitoso; @c false en cualquier error
 *         (magic incorrecto, version no soportada, buffer truncado,
 *         fn_count sospechosamente grande).
 *
 * Politica de seguridad: este parser puede leer bytes que vienen de
 * un .velb potencialmente corrupto o malicioso.  Por eso validamos:
 *   - Magic correcto (VEIR).
 *   - Version exacta (rechazamos versiones futuras desconocidas; un
 *     v2 podria tener layout incompatible).
 *   - fn_count <= 100000 (hard cap defensivo).
 *   - Cada deserializacion individual no excede @c section_end.
 */
bool parse_ir_section(const std::vector<uint8_t> &data, size_t offset,
                      size_t section_size, std::vector<IrFunction> &functions) {
    functions.clear();

    // Validar el tamano minimo (al menos el header completo de 12 bytes:
    // magic 4 + version 2 + reserved 2 + fn_count 4) y que la seccion
    // no se salga del buffer.
    if (section_size < 12) return false;
    if (offset + section_size > data.size()) return false;

    size_t off = offset;
    uint32_t magic = 0;
    if (!read_u32(data, off, magic)) return false;
    // Magic check: si no es VEIR, el caller paso un offset
    // equivocado o la seccion esta corrupta.  Abortar antes de
    // intentar parsear nada interpretable.
    if (magic != IR_SECTION_MAGIC) return false;

    uint16_t version = 0;
    uint16_t flags = 0;
    if (!read_u16(data, off, version)) return false;
    if (!read_u16(data, off, flags)) return false;
    // Version exacta: un schema distinto parseado como este daria basura.
    if (version != IR_SECTION_VERSION) return false;
    // Y ninguna bandera que no se sepa interpretar.  Ignorar una bandera
    // desconocida es leer un cuerpo que no es el que se cree estar leyendo.
    if ((flags & ~kIrFlagDeflate) != 0) return false;

    uint32_t fn_count = 0;
    if (!read_u32(data, off, fn_count)) return false;

    /* Si viene comprimida, se descomprime a un bufer propio y se parsea DE AHI.
     * Se recorre el mismo codigo en los dos casos: tener dos caminos de
     * deserializacion era pedir que uno de los dos se quedara atras. */
    std::vector<uint8_t> claro;
    const std::vector<uint8_t> *fuente = &data;
    size_t cuerpo_ini = off;
    size_t cuerpo_fin = offset + section_size;
    if ((flags & kIrFlagDeflate) != 0) {
        uint32_t sin_comprimir = 0;
        if (!read_u32(data, off, sin_comprimir)) return false;
        // Tope defensivo: el tamano en claro lo dice el propio fichero, que
        // puede estar corrupto.  Sin limite, uno alterado pediria reservar
        // gigabytes antes de descubrir que no cuadra.
        if (sin_comprimir > (1u << 30)) return false;
        claro.resize(sin_comprimir);
        mz_ulong salida = sin_comprimir;
        const size_t comprimido_len = (offset + section_size) - off;
        if (mz_uncompress(claro.data(), &salida, data.data() + off,
                          static_cast<mz_ulong>(comprimido_len)) != MZ_OK)
            return false;
        if (salida != sin_comprimir) return false;
        fuente = &claro;
        cuerpo_ini = 0;
        cuerpo_fin = claro.size();
    }
    const std::vector<uint8_t> &data_cuerpo = *fuente;
    off = cuerpo_ini;

    // Hard cap defensivo: programas con >100000 funciones IR son
    // imposibles en la practica (incluso un programa enorme tendria
    // ~5000 funciones).  Sin este cap, un .velb malicioso con un
    // fn_count enorme (UINT32_MAX) forzaria a @c functions.reserve a
    // intentar alocar TBs de memoria, crasheando con OOM.
    if (fn_count > 100000) return false;

    functions.reserve(fn_count);
    const size_t section_end = offset + section_size;
    // Loop de deserializacion: cada funcion avanza @c off por su
    // propio tamano.  Verificamos antes (off >= end -> truncada) y
    // despues (off > end -> overflow de la seccion).
    for (uint32_t i = 0; i < fn_count; ++i) {
        // Si ya pasamos el fin del cuerpo antes de empezar a leer
        // esta funcion, el fn_count es inconsistente con el tamano.
        if (off >= cuerpo_fin) return false;
        IrFunction fn;
        if (!deserialize_function(data_cuerpo, off, fn)) return false;
        // Validacion post-deserialize: la funcion no debe haberse
        // "comido" mas bytes de los que pertenecen al cuerpo.
        if (off > cuerpo_fin) return false;
        functions.push_back(std::move(fn));
    }
    return true;
}

/* ===================================================================== */
/* emit_ir_module_cache / parse_ir_module_cache  (.vxir)                 */
/* ===================================================================== */

/**
 * @brief Serializa una @c StaticDataStore verbatim (pool + entries + meta).
 *
 * Se persiste el pool de bytes y los @c byte_offset/@c byte_len tal cual
 * para que la reconstruccion sea byte-exacta (el merge cross-module
 * depende de offsets estables dentro del pool del dep).
 */
void serialize_static_data(const IrModule::StaticDataStore &sd,
                           std::vector<uint8_t> &out) {
    write_u8(out, sd.alignment_default);
    // Pool de bytes contiguo.
    write_u32(out, static_cast<uint32_t>(sd.bytes.size()));
    out.insert(out.end(), sd.bytes.begin(), sd.bytes.end());
    // Entries (rangos + meta).
    write_u32(out, static_cast<uint32_t>(sd.entries.size()));
    for (const auto &e : sd.entries) {
        write_u32(out, e.byte_offset);
        write_u32(out, e.byte_len);
        write_u64(out, e.meta.content_hash);
        write_u16(out, e.meta.alignment);
        write_u8(out, e.meta.flags);
        write_u16(out, e.meta.source_module_idx);
        write_str(out, e.meta.section_name);
        write_str(out, e.meta.section_perms);           // AOT 2b
        write_u64(out, (uint64_t)e.meta.section_at);    // AOT @at
        write_u32(out, (uint32_t)e.meta.section_order); // AOT @order
        // AOT Inc 3: referencias a simbolos en bloques `bytes` (dq main).
        write_u32(out, static_cast<uint32_t>(e.meta.sym_refs.size()));
        for (const auto &sr : e.meta.sym_refs) {
            write_u32(out, sr.offset);
            write_u8(out, sr.width);
            write_u8(out, sr.is_rel);
            write_str(out, sr.sym);
        }
        // Global compartido a nivel de programa (CPU dispatch fp-table).
        write_str(out, e.meta.shared_key);
        //  NR / dev-OS: nombre exportado del bloque (cross-block symref).
        write_str(out, e.meta.symbol_name);
    }
}

bool deserialize_static_data(const std::vector<uint8_t> &in, size_t &off,
                             IrModule::StaticDataStore &sd) {
    sd.clear();
    if (!read_u8(in, off, sd.alignment_default)) return false;
    uint32_t pool_len = 0;
    if (!read_u32(in, off, pool_len)) return false;
    if (off + pool_len > in.size()) return false;
    sd.bytes.assign(in.begin() + off, in.begin() + off + pool_len);
    off += pool_len;
    uint32_t entry_count = 0;
    if (!read_u32(in, off, entry_count)) return false;
    // Cap defensivo: un dep real tiene a lo sumo unos pocos miles de slots.
    if (entry_count > 2000000u) return false;
    sd.entries.reserve(entry_count);
    for (uint32_t i = 0; i < entry_count; ++i) {
        IrModule::StaticDataStore::Entry e{};
        if (!read_u32(in, off, e.byte_offset)) return false;
        if (!read_u32(in, off, e.byte_len)) return false;
        if (!read_u64(in, off, e.meta.content_hash)) return false;
        if (!read_u16(in, off, e.meta.alignment)) return false;
        if (!read_u8(in, off, e.meta.flags)) return false;
        if (!read_u16(in, off, e.meta.source_module_idx)) return false;
        if (!read_str(in, off, e.meta.section_name)) return false;
        if (!read_str(in, off, e.meta.section_perms)) return false; // AOT 2b
        uint64_t sat_u = 0;
        uint32_t sord_u = 0;
        if (!read_u64(in, off, sat_u)) return false;  // AOT @at
        if (!read_u32(in, off, sord_u)) return false; // AOT @order
        e.meta.section_at = (int64_t)sat_u;
        e.meta.section_order = (int32_t)sord_u;
        // AOT Inc 3: referencias a simbolos.
        uint32_t nrefs = 0;
        if (!read_u32(in, off, nrefs)) return false;
        if (nrefs > 1000000u) return false; // cap defensivo
        e.meta.sym_refs.reserve(nrefs);
        for (uint32_t k = 0; k < nrefs; ++k) {
            IrModule::StaticDataMeta::SymRef sr;
            if (!read_u32(in, off, sr.offset)) return false;
            if (!read_u8(in, off, sr.width)) return false;
            if (!read_u8(in, off, sr.is_rel)) return false;
            if (!read_str(in, off, sr.sym)) return false;
            e.meta.sym_refs.push_back(std::move(sr));
        }
        // Global compartido a nivel de programa (CPU dispatch fp-table).
        if (!read_str(in, off, e.meta.shared_key)) return false;
        //  NR / dev-OS: nombre exportado del bloque (cross-block symref).
        if (!read_str(in, off, e.meta.symbol_name)) return false;
        // Validar que el rango cae dentro del pool.
        if (static_cast<uint64_t>(e.byte_offset) + e.byte_len > sd.bytes.size())
            return false;
        sd.entries.push_back(std::move(e));
    }
    return true;
}

std::vector<uint8_t> emit_ir_module_cache(const IrModule &mod) {
    std::vector<uint8_t> out;
    write_u32(out, IR_MODULE_CACHE_MAGIC);
    write_u16(out, IR_MODULE_CACHE_VERSION);
    write_u16(out, 0); // reserved

    // 1) Funciones: reusa el formato @ir (con su header VEIR propio).
    //    Guardamos su longitud para poder delimitar la sub-seccion al leer.
    std::vector<uint8_t> fn_bytes = emit_ir_section(mod.functions);
    write_u32(out, static_cast<uint32_t>(fn_bytes.size()));
    out.insert(out.end(), fn_bytes.begin(), fn_bytes.end());

    // 2) static_data (lo que faltaba: la causa del bug code.s_* colgante).
    serialize_static_data(mod.static_data, out);

    // 3) globals (nombre -> IrValueId).
    write_u32(out, static_cast<uint32_t>(mod.globals.size()));
    for (const auto &g : mod.globals) {
        write_str(out, g.first);
        write_u32(out, static_cast<uint32_t>(g.second));
    }

    // 4) tabla de nombres de valores SSA (debug-info para el LSP: args/vars).
    //    NO va en el @ir del .velb (emit_ir_section, produccion) -> cero
    //    coste en el binario; solo en este cache (LSP + .vxir dev).  Por
    //    funcion: count + un string por value (vacio si el value no tiene
    //    nombre de fuente).  El indice ES el IrValueId.
    write_u32(out, static_cast<uint32_t>(mod.functions.size()));
    for (const auto &fn : mod.functions) {
        write_u32(out, static_cast<uint32_t>(fn.values.size()));
        for (const auto &v : fn.values)
            write_str(out, v.name);
    }

    // 5) native_imports (lib, name): el AOT los usa para mapear cada simbolo
    //    FFI extern a su DLL real (kernel32.dll, user32.dll, ...) en vez de
    //    asumir msvcrt.dll.  Sin esto, `extern "kernel32.dll" {...}` resolvia
    //    desde msvcrt -> fallo de carga del PE.
    /*    Con lo DECLARADO sobre cada una (v11).  Va aqui y no se recalcula
     *    despues porque quien lo sabe es el frontend, y a partir de este punto
     *    -- el JIT, el AOT, `--analyze` -- todos leen el IR de la cache: una
     *    declaracion que no cruce esta frontera no la ve nadie. */
    write_u32(out, static_cast<uint32_t>(mod.native_imports.size()));
    for (const auto &ni : mod.native_imports) {
        write_str(out, ni.lib);
        write_str(out, ni.name);
        const IrNativeEffects &fx = ni.effects;
        write_u8(out, fx.declared ? 1u : 0u);
        write_u32(out, fx.reads_pointee);
        write_u32(out, fx.writes_pointee);
        /* Los dos ultimos bits son NUEVOS (panic y reserva).  Caben en el mismo
         * byte, asi que el formato no cambia de tamano; un fichero viejo los
         * trae a cero, que es el valor conservador y no el permisivo -- lo
         * contrario haria que una cache antigua aprobara contratos que no se
         * han comprobado. */
        write_u8(out, uint8_t((fx.reads_global ? 1u : 0u) |
                              (fx.writes_global ? 2u : 0u) |
                              (fx.io ? 4u : 0u) | (fx.may_throw ? 8u : 0u) |
                              (fx.nondeterministic ? 16u : 0u) |
                              (fx.comptime ? 32u : 0u) |
                              (fx.may_panic ? 64u : 0u) |
                              (fx.allocates ? 128u : 0u)));
    }
    return out;
}

bool parse_ir_module_cache(const std::vector<uint8_t> &data, IrModule &out) {
    size_t off = 0;
    uint32_t magic = 0;
    if (!read_u32(data, off, magic)) return false;
    if (magic != IR_MODULE_CACHE_MAGIC)
        return false; // formato viejo -> recompilar
    uint16_t version = 0, reserved = 0;
    if (!read_u16(data, off, version)) return false;
    if (!read_u16(data, off, reserved)) return false;
    if (version != IR_MODULE_CACHE_VERSION) return false;

    // 1) Funciones.
    uint32_t fn_len = 0;
    if (!read_u32(data, off, fn_len)) return false;
    if (off + fn_len > data.size()) return false;
    if (!parse_ir_section(data, off, fn_len, out.functions)) return false;
    off += fn_len;

    // 2) static_data.
    if (!deserialize_static_data(data, off, out.static_data)) return false;

    // 3) globals.
    out.globals.clear();
    uint32_t gcount = 0;
    if (!read_u32(data, off, gcount)) return false;
    if (gcount > 2000000u) return false;
    for (uint32_t i = 0; i < gcount; ++i) {
        std::string name;
        uint32_t vid = 0;
        if (!read_str(data, off, name)) return false;
        if (!read_u32(data, off, vid)) return false;
        out.globals.emplace(std::move(name), static_cast<IrValueId>(vid));
    }

    // 4) tabla de nombres de valores SSA (debug-info).  Si el stream se acabo
    //    (cache mas viejo sin la tabla pero con misma version -> no deberia
    //    pasar por el bump, pero somos defensivos), se omite sin error.
    uint32_t nfns = 0;
    if (read_u32(data, off, nfns)) {
        if (nfns > 2000000u) return false;
        for (uint32_t f = 0; f < nfns; ++f) {
            uint32_t nvals = 0;
            if (!read_u32(data, off, nvals)) return false;
            if (nvals > 50000000u) return false;
            for (uint32_t v = 0; v < nvals; ++v) {
                std::string nm;
                if (!read_str(data, off, nm)) return false;
                if (f < out.functions.size() &&
                    v < out.functions[f].values.size())
                    out.functions[f].values[v].name = std::move(nm);
            }
        }
    }

    // 5) native_imports (lib, name).  Defensivo: si el stream se acabo (no
    //    deberia por el bump de version), se omite sin error.
    out.native_imports.clear();
    uint32_t nimp = 0;
    if (read_u32(data, off, nimp)) {
        if (nimp > 2000000u) return false;
        for (uint32_t i = 0; i < nimp; ++i) {
            std::string lib, name;
            if (!read_str(data, off, lib)) return false;
            if (!read_str(data, off, name)) return false;
            IrNativeEffects fx;
            uint8_t decl = 0, bits = 0;
            if (!read_u8(data, off, decl)) return false;
            if (!read_u32(data, off, fx.reads_pointee)) return false;
            if (!read_u32(data, off, fx.writes_pointee)) return false;
            if (!read_u8(data, off, bits)) return false;
            fx.declared = decl != 0;
            fx.reads_global = (bits & 1u) != 0;
            fx.writes_global = (bits & 2u) != 0;
            fx.io = (bits & 4u) != 0;
            fx.may_throw = (bits & 8u) != 0;
            fx.nondeterministic = (bits & 16u) != 0;
            fx.comptime = (bits & 32u) != 0;
            fx.may_panic = (bits & 64u) != 0;
            fx.allocates = (bits & 128u) != 0;
            out.register_native_import(std::move(lib), std::move(name), fx);
        }
    }
    return true;
}

} // namespace ir
