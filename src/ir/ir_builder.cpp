/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir_builder.cpp
 * @brief Implementacion del builder de SSA IR para multi-language frontends.
 *
 * Patron general de todas las factorias:
 *   1. Reservar un IrValueId para el destino (cuando la op produce valor).
 *   2. Rellenar @c IrInstr con el opcode, tipo, dst y operandos.
 *   3. Llamar @c append() que lo empuja al bloque activo
 *      (@c current_block_).
 *
 * Decisiones de diseno:
 *   - @c append() es no-op si no hay bloque activo.  Permite que el frontend
 *     emita instrucciones "sueltas" durante experimentos sin crashear; el
 *     resultado es codigo perdido en lugar de un assert fatal (mejor DX).
 *   - Las helpers @c add / @c sub / etc. son thin wrappers sobre @c binop()
 *     para que el frontend NO tenga que recordar el opcode IR exacto.  Es
 *     cero overhead (todos son @c inline candidates) y reduce errores.
 *   - Las constantes (@c const_i32 etc.) EMITEN una @c IrOp::CONST en lugar
 *     de solo marcar @c is_const=true.  Razon: el optimizer hace lookups
 *     por opcode (e.g. const-fold busca CONST en sus inputs) y el emisor
 *     IR tambien lo necesita visible.  Si solo se marcase el bit, las
 *     constantes serian "fantasmas" sin definicion explicita.
 */

#include "ir/ir_builder.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <cassert>

namespace ir {

// =========================================================================
//  Bloques
// =========================================================================

/**
 * @brief Crea un nuevo basic block al final de @c fn_.blocks.
 *
 * El nombre opcional es solo para diagnostico (impresion del IR, mensajes
 * de error); si esta vacio, generamos @c "bb_<id>" como fallback.  No se
 * usa para identidad: el regalloc y el emisor trabajan con @c IrBlockId.
 */
IrBlockId IrBuilder::new_block(const std::string &name) {
    const IrBlockId id = static_cast<IrBlockId>(fn_.blocks.size());
    IrBlock bb;
    bb.id = id;
    bb.name = name.empty() ? ("bb_" + std::to_string(id)) : name;
    fn_.blocks.push_back(std::move(bb));
    return id;
}

// =========================================================================
//  Parametros de funcion
// =========================================================================

/**
 * @brief Registra un parametro formal de la funcion.
 *
 * El @c IrValueId resultante es accesible inmediatamente como cualquier
 * SSA value, pero ademas queda marcado con @c is_param=true para que el
 * emisor IR (a) no espere una instruccion que lo defina, y (b) lo extraiga
 * de la calling convention al entrar al cuerpo (regs R1..R12, stack mas
 * alla del 12).  El orden de llamadas determina el orden ABI: @c param(0)
 * va a R1, @c param(1) a R2, etc.
 */
IrValueId IrBuilder::param(IrType type, const std::string &name) {
    const IrValueId id = new_value(type, name);
    fn_.values[id].is_param = true;
    fn_.params.push_back(id);
    return id;
}

// =========================================================================
//  Constantes
//
//  Cada const_* sigue el mismo patron (reserva valor + marca is_const +
//  emite CONST).  La duplicacion entre las variantes i32/i64/u32/u64/bool/
//  ptr es deliberada: cada tipo necesita su propio @c IrType para que el
//  emisor IR escoja la mnemonica correcta (e.g. const.i32 vs const.i64)
//  y para que casts implicitos no descarten precision.
// =========================================================================

IrValueId IrBuilder::const_i32(int32_t v) {
    const IrValueId id = new_value(IrType::I32);
    fn_.values[id].is_const = true;
    // Reinterpretamos como uint64 preservando el patron de bits (sign-extend
    // primero a int64 para garantizar que -1 se serializa como 0xFFF...FF
    // y no como 0x...FF cubierto de ceros, que cambiaria el valor).
    fn_.values[id].const_val = static_cast<uint64_t>(static_cast<int64_t>(v));
    IrInstr ins{};
    ins.op = IrOp::CONST;
    ins.type = IrType::I32;
    ins.dst = id;
    ins.imm = static_cast<uint64_t>(static_cast<int64_t>(v));
    append(std::move(ins));
    return id;
}

IrValueId IrBuilder::const_i64(int64_t v) {
    const IrValueId id = new_value(IrType::I64);
    fn_.values[id].is_const = true;
    fn_.values[id].const_val = static_cast<uint64_t>(v);
    IrInstr ins{};
    ins.op = IrOp::CONST;
    ins.type = IrType::I64;
    ins.dst = id;
    ins.imm = static_cast<uint64_t>(v);
    append(std::move(ins));
    return id;
}

IrValueId IrBuilder::const_u32(uint32_t v) {
    const IrValueId id = new_value(IrType::U32);
    fn_.values[id].is_const = true;
    // u32 a u64 es zero-extend natural en C++: el cast widening no toca
    // los bits altos.  No hay diferencia con i32 en el codegen, pero el
    // tipo del SSA value es importante para reglas de signed/unsigned
    // en comparaciones y divisiones aguas abajo.
    fn_.values[id].const_val = v;
    IrInstr ins{};
    ins.op = IrOp::CONST;
    ins.type = IrType::U32;
    ins.dst = id;
    ins.imm = v;
    append(std::move(ins));
    return id;
}

IrValueId IrBuilder::const_u64(uint64_t v) {
    const IrValueId id = new_value(IrType::U64);
    fn_.values[id].is_const = true;
    fn_.values[id].const_val = v;
    IrInstr ins{};
    ins.op = IrOp::CONST;
    ins.type = IrType::U64;
    ins.dst = id;
    ins.imm = v;
    append(std::move(ins));
    return id;
}

IrValueId IrBuilder::const_bool(bool v) {
    const IrValueId id = new_value(IrType::BOOL);
    fn_.values[id].is_const = true;
    // Convencion VestaVM: BOOL = i8 con valores {0, 1}.  No usamos otros
    // valores para "true" (a diferencia de C donde cualquier no-cero lo
    // es) porque el bytecode @c setcc y @c jmp.j* esperan 0/1 estrictos.
    fn_.values[id].const_val = v ? 1u : 0u;
    IrInstr ins{};
    ins.op = IrOp::CONST;
    ins.type = IrType::BOOL;
    ins.dst = id;
    ins.imm = v ? 1u : 0u;
    append(std::move(ins));
    return id;
}

IrValueId IrBuilder::const_ptr(uint64_t addr) {
    const IrValueId id = new_value(IrType::PTR);
    fn_.values[id].is_const = true;
    fn_.values[id].const_val = addr;
    IrInstr ins{};
    ins.op = IrOp::CONST;
    ins.type = IrType::PTR;
    ins.dst = id;
    ins.imm = addr;
    append(std::move(ins));
    return id;
}

// =========================================================================
//  Aritmetica binaria
//
//  Las versiones tipadas (add/sub/mul/etc.) son sintactic sugar sobre
//  @c binop().  El frontend siempre debe pasar el @c IrType correcto
//  porque el emisor lo usa para elegir la mnemonica precisa (add.i32 vs
//  add.i64 vs add.f64): si pasa el tipo equivocado el codigo emitido
//  silenciosamente trunca o reinterpreta bits.
// =========================================================================

/**
 * @brief Helper generico que crea cualquier instr binaria a dos operandos.
 * @param op   Opcode IR.  Debe ser uno de ADD/SUB/MUL/DIV/MOD/AND/OR/XOR/
 *             SHL/SHR/SAR (responsabilidad del caller).
 * @param a    Operando izquierdo (left).
 * @param b    Operando derecho (right).
 * @param type Tipo del resultado y de ambos operandos (no se hace cast).
 */
IrValueId IrBuilder::binop(IrOp op, IrValueId a, IrValueId b, IrType type) {
    const IrValueId id = new_value(type);
    IrInstr ins{};
    ins.op = op;
    ins.type = type;
    ins.dst = id;
    // SSA two-address: ambos operandos son SSA values fijos; el destino
    // es un valor fresco.  El emisor decide despues si emite ADD reg-reg
    // (dst=src1) tras coalescing o variante 3-operandos @c adds3.
    ins.operands = {a, b};
    append(std::move(ins));
    return id;
}

// Helpers tipadas: cero overhead tras inlining; existen para que el
// frontend exprese intenciones (add/sub/...) en lugar de buscar el opcode
// en la enum.  La distincion sdiv/udiv y smod/umod actualmente comparten
// el mismo IrOp (DIV/MOD); el tipo del operando (I32 vs U32) determina
// signed vs unsigned en el emisor.
IrValueId IrBuilder::add(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::ADD, a, b, t);
}
IrValueId IrBuilder::sub(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::SUB, a, b, t);
}
IrValueId IrBuilder::mul(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::MUL, a, b, t);
}
IrValueId IrBuilder::sdiv(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::DIV, a, b, t);
}
IrValueId IrBuilder::udiv(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::DIV, a, b, t);
}
IrValueId IrBuilder::smod(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::MOD, a, b, t);
}
IrValueId IrBuilder::umod(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::MOD, a, b, t);
}

IrValueId IrBuilder::and_(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::AND, a, b, t);
}
IrValueId IrBuilder::or_(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::OR, a, b, t);
}
IrValueId IrBuilder::xor_(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::XOR, a, b, t);
}
// Distincion SHL/SHR/SAR:
//   - SHL: shift logico izquierda (rellena con 0).
//   - SHR: shift logico derecha (rellena con 0; usar para unsigned).
//   - SAR: shift aritmetico derecha (rellena con el bit de signo; signed).
// El frontend debe escoger correctamente segun el tipo del operando: para
// i32 firmado, un @c >> debe bajar a SAR; para u32 debe bajar a SHR.
IrValueId IrBuilder::shl(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::SHL, a, b, t);
}
IrValueId IrBuilder::shr(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::SHR, a, b, t);
}
IrValueId IrBuilder::sar(IrValueId a, IrValueId b, IrType t) {
    return binop(IrOp::SAR, a, b, t);
}

// =========================================================================
//  Operaciones unarias
// =========================================================================

/**
 * @brief Helper generico para instrucciones unarias (NEG, NOT, etc.).
 */
IrValueId IrBuilder::unop(IrOp op, IrValueId v, IrType type) {
    const IrValueId id = new_value(type);
    IrInstr ins{};
    ins.op = op;
    ins.type = type;
    ins.dst = id;
    ins.operands = {v};
    append(std::move(ins));
    return id;
}

// neg = negacion aritmetica (0 - v); not_ = complemento bitwise (~v).
// El sufijo @c _ en @c not_ evita colision con el operador C++ @c not.
IrValueId IrBuilder::neg(IrValueId v, IrType t) {
    return unop(IrOp::NEG, v, t);
}
IrValueId IrBuilder::not_(IrValueId v, IrType t) {
    return unop(IrOp::NOT, v, t);
}

// =========================================================================
//  Comparaciones
//
//  Todas devuelven BOOL (8-bit con valores {0, 1}).  Existen tanto las
//  signed (LT/LE/GT/GE) como las unsigned (ULT/ULE/UGT/UGE) porque la
//  comparacion bitwise depende del signo: para i32 negativos, el bit alto
//  es 1 y serian "mayores" sin signo aunque "menores" con signo.
// =========================================================================

/**
 * @brief Helper que crea cualquier comparacion de dos operandos.
 * @return SSA value de tipo BOOL.
 */
IrValueId IrBuilder::cmpop(IrOp op, IrValueId a, IrValueId b) {
    const IrValueId id = new_value(IrType::BOOL);
    IrInstr ins{};
    ins.op = op;
    ins.type = IrType::BOOL;
    ins.dst = id;
    ins.operands = {a, b};
    append(std::move(ins));
    return id;
}

// Comparaciones signed (LT/LE/GT/GE) y unsigned (ULT/ULE/UGT/UGE).  EQ y
// NE no tienen variantes signed/unsigned: la igualdad bitwise es la misma
// para ambos casos.
IrValueId IrBuilder::cmp_eq(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_EQ, a, b);
}
IrValueId IrBuilder::cmp_ne(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_NE, a, b);
}
IrValueId IrBuilder::cmp_lt(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_LT, a, b);
}
IrValueId IrBuilder::cmp_le(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_LE, a, b);
}
IrValueId IrBuilder::cmp_gt(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_GT, a, b);
}
IrValueId IrBuilder::cmp_ge(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_GE, a, b);
}
IrValueId IrBuilder::cmp_ult(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_ULT, a, b);
}
IrValueId IrBuilder::cmp_ule(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_ULE, a, b);
}
IrValueId IrBuilder::cmp_ugt(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_UGT, a, b);
}
IrValueId IrBuilder::cmp_uge(IrValueId a, IrValueId b) {
    return cmpop(IrOp::CMP_UGE, a, b);
}

// =========================================================================
//  Casts entre tipos
//
//  Cuatro semanticas distintas:
//    - SEXT: widening con sign-extension (i8 -> i32 preserva signo).
//    - ZEXT: widening con zero-extension (u8 -> u32 rellena con 0).
//    - TRUNC: narrowing (i64 -> i32 descarta los 32 bits altos).
//    - BITCAST: reinterpretacion sin cambiar bits (i64 -> f64 o ptr -> i64).
//
//  El frontend debe escoger la correcta para no corromper valores.  Por
//  ejemplo @c sext(i8 -1) -> i32 produce -1 (0xFFFFFFFF), mientras que
//  @c zext(i8 -1) -> i32 produce 255 (0x000000FF): los dos son validos,
//  pero solo uno es lo que el programa Vesta pidio segun el tipo declarado.
// =========================================================================

/**
 * @brief Helper que crea cualquier instr de cast unaria.
 */
IrValueId IrBuilder::castop(IrOp op, IrValueId v, IrType to) {
    const IrValueId id = new_value(to);
    IrInstr ins{};
    ins.op = op;
    ins.type = to;
    ins.dst = id;
    ins.operands = {v};
    append(std::move(ins));
    return id;
}

IrValueId IrBuilder::sext(IrValueId v, IrType t) {
    return castop(IrOp::SEXT, v, t);
}
IrValueId IrBuilder::zext(IrValueId v, IrType t) {
    return castop(IrOp::ZEXT, v, t);
}
IrValueId IrBuilder::trunc(IrValueId v, IrType t) {
    return castop(IrOp::TRUNC, v, t);
}
IrValueId IrBuilder::bitcast(IrValueId v, IrType t) {
    return castop(IrOp::BITCAST, v, t);
}

// =========================================================================
//  Memoria
//
//  Dos categorias:
//    1. STACK (vm_mem del proceso): @c alloca_bytes reserva en el stack VM
//       y devuelve un puntero VM (sin @c is_host_ptr).  LOAD/STORE
//       posteriores emiten @c mov sobre memoria VM.
//    2. HEAP HOST (RawAllocator): @c raw_alloc llama a malloc del host y
//       devuelve un puntero con @c is_host_ptr=true.  LOAD/STORE posteriores
//       emiten @c movh (host mem).  El frontend debe llamar @c raw_free
//       para liberar.
// =========================================================================

/**
 * @brief Reserva @c size_bytes en el stack VM del proceso actual.
 *
 * El tipo del resultado es @c PTR.  El emisor IR lo baja a @c subsp + un
 * SSA value que captura el nuevo @c rsp.  El slot es valido hasta el RET
 * de la funcion contenedora; el frame se libera automaticamente con
 * @c leave.  Si se quiere liberar antes (e.g. tras un loop interno),
 * actualmente NO esta soportado: el codigo se ejecuta hasta el RET.
 */
IrValueId IrBuilder::alloca_bytes(uint32_t size_bytes) {
    const IrValueId id = new_value(IrType::PTR);
    IrInstr ins{};
    ins.op = IrOp::ALLOCA;
    ins.type =
        IrType::I8; // El tipo del slot es opaco; usamos I8 como sentinela.
    ins.dst = id;
    ins.imm = size_bytes;
    append(std::move(ins));
    return id;
}

/**
 * @brief Aloca memoria en el heap del host (via RawAllocator).
 *
 * El SSA value resultante se marca @c is_host_ptr=true para que cualquier
 * LOAD/STORE indirecto a traves de el emita @c movh (memoria host) en lugar
 * de @c mov (memoria VM).  El frontend debe garantizar el @c raw_free
 * correspondiente: no hay GC sobre la memoria raw.
 */
IrValueId IrBuilder::raw_alloc(IrValueId size_bytes) {
    const IrValueId id = new_value(IrType::PTR);
    fn_.values[id].is_host_ptr = true;
    IrInstr ins{};
    ins.op = IrOp::RAW_ALLOC;
    ins.type = IrType::PTR;
    ins.dst = id;
    ins.operands = {size_bytes};
    append(std::move(ins));
    return id;
}

/**
 * @brief Libera un bloque previamente obtenido por @c raw_alloc.
 *
 * Es no-op si @c ptr es null (el RawAllocator lo valida internamente).
 * Doble free NO esta detectado y producira undefined behavior segun
 * decida la implementacion del allocator host (tipicamente crash).
 */
void IrBuilder::raw_free(IrValueId ptr) {
    IrInstr ins{};
    ins.op = IrOp::RAW_FREE;
    ins.type = IrType::VOID;
    ins.operands = {ptr};
    append(std::move(ins));
}

/**
 * @brief Lee @c sizeof(type) bytes desde @c ptr y devuelve el valor cargado.
 *
 * El emisor decide @c mov o @c movh consultando el flag @c is_host_ptr del
 * SSA value de @c ptr.  Para tipos < 8 bytes (i8/i16/i32) puede emitir el
 * patron narrow (loadz) que carga + zero-extend en una sola instruccion.
 */
IrValueId IrBuilder::load(IrValueId ptr, IrType type) {
    const IrValueId id = new_value(type);
    IrInstr ins{};
    ins.op = IrOp::LOAD;
    ins.type = type;
    ins.dst = id;
    ins.operands = {ptr};
    append(std::move(ins));
    return id;
}

/**
 * @brief Escribe @c value (de tipo @c type) en la direccion @c ptr.
 *
 * No produce SSA value de retorno (es un side-effect puro).  Si @c value
 * es de un tipo distinto al pasado en @c type, el emisor puede truncar
 * silenciosamente: es responsabilidad del frontend hacer @c trunc explicito
 * antes si la diferencia de ancho importa.
 */
void IrBuilder::store(IrValueId value, IrValueId ptr, IrType type) {
    IrInstr ins{};
    ins.op = IrOp::STORE;
    ins.type = type;
    ins.operands = {value, ptr};
    append(std::move(ins));
}

// =========================================================================
//  Control de flujo
// =========================================================================

/**
 * @brief Branch incondicional al bloque @c target.
 *
 * Debe ser la ULTIMA instruccion del bloque actual: cualquier instr
 * posterior queda como codigo muerto que el pase de DCE/unreachable
 * eliminara, pero idealmente el frontend no las emite.
 */
void IrBuilder::br(IrBlockId target) {
    IrInstr ins{};
    ins.op = IrOp::BR;
    ins.type = IrType::VOID;
    ins.target_block = target;
    append(std::move(ins));
}

/**
 * @brief Branch condicional: si @c cond es no-cero, ir a @c t; si cero, a @c f.
 *
 * El SSA value @c cond puede ser de cualquier tipo entero; el emisor lo
 * compara contra 0 con @c cmp + @c jmp.j*.  El bytecode tambien admite el
 * patron fusionado @c cmpjmp (cmp + branch en una sola instr) cuando el
 * optimizer detecta que el predecesor genera la comparacion.
 */
void IrBuilder::br_cond(IrValueId cond, IrBlockId t, IrBlockId f) {
    IrInstr ins{};
    ins.op = IrOp::BR_COND;
    ins.type = IrType::VOID;
    ins.operands = {cond};
    ins.target_block = t;
    ins.false_block = f;
    append(std::move(ins));
}

/**
 * @brief Retorna sin valor (RET implicito para funciones void).
 */
void IrBuilder::ret_void() {
    IrInstr ins{};
    ins.op = IrOp::RET;
    ins.type = IrType::VOID;
    append(std::move(ins));
}

/**
 * @brief Retorna devolviendo @c value en r0 (calling convention VM).
 *
 * El tipo del @c IrInstr se toma del SSA value (con fallback a I64 si por
 * algun motivo el value-id es invalido), no del declarado de la funcion:
 * eso es responsabilidad del checker.  Aqui solo escribimos lo que se nos
 * pide; el emisor convertira si es necesario.
 */
void IrBuilder::ret(IrValueId value) {
    IrInstr ins{};
    ins.op = IrOp::RET;
    ins.type =
        (value < fn_.values.size()) ? fn_.values[value].type : IrType::I64;
    ins.operands = {value};
    append(std::move(ins));
}

/**
 * @brief Crea una instruccion PHI con N pares (predecesor, valor).
 *
 * Una PHI vive al inicio de un bloque que tiene >1 predecesor y selecciona
 * el valor adecuado segun por cual borde llegamos al bloque.  Por SSA, cada
 * variable que cambia entre ramas requiere su propia PHI en el merge.
 *
 * @param type  Tipo del valor seleccionado (debe ser uniforme entre ramas).
 * @param pairs Lista @c [(bb_pred, value_from_pred), ...].  Debe cubrir
 *              TODOS los predecesores del bloque actual; el numero de pares
 *              tiene que igualar @c preds.size() del bloque o el emisor
 *              dejara registros sin inicializar.
 */
IrValueId
IrBuilder::phi(IrType type,
               const std::vector<std::pair<IrBlockId, IrValueId>> &pairs) {
    const IrValueId id = new_value(type);
    IrInstr ins{};
    ins.op = IrOp::PHI;
    ins.type = type;
    ins.dst = id;
    ins.phi_args.reserve(pairs.size());
    for (const auto &p : pairs) {
        IrPhiArg pa;
        pa.block = p.first;
        pa.value = p.second;
        ins.phi_args.push_back(pa);
    }
    append(std::move(ins));
    return id;
}

// =========================================================================
//  Llamadas a funciones
//
//  Tres variantes con calling conventions sutilmente distintas:
//    - CALL:    intra-modulo, callee identificado por nombre.  El linker
//               resuelve la direccion en el .velb a un @c @Absolute(...).
//    - CALLIND: indirecta, callee es un SSA value (puntero ya cargado).
//               Usado para function pointers y closures.
//    - CALLN:   nativa via FFI.  @c func_name lleva @c "lib:funcion" para
//               que el loader localice la funcion via @c dlsym.
// =========================================================================

/**
 * @brief Call directo a una funcion del modulo por nombre.
 *
 * El nombre debe coincidir con un label en el bytecode generado.  El
 * linker emite el @c @Absolute(...) que el emisor reemplaza por la VA
 * real en el patch pass.  Si la funcion no existe en el modulo, el
 * linker reportara unresolved symbol al final.
 */
IrValueId IrBuilder::call(const std::string &fn_name,
                          IrValueList args, IrType ret_type) {
    // Si el callee no devuelve nada, no reservamos SSA value (dst queda
    // como IR_NO_VALUE).  Asi el DCE no intenta mantener viva una
    // "variable" sin definicion conceptual.
    const IrValueId id =
        (ret_type == IrType::VOID) ? IR_NO_VALUE : new_value(ret_type);
    IrInstr ins{};
    ins.op = IrOp::CALL;
    ins.type = ret_type;
    ins.dst = id;
    ins.func_name = fn_name;
    ins.operands = args;
    append(std::move(ins));
    return id;
}

/**
 * @brief Variante explicita para callee void (azucar sintactico).
 *
 * Equivalente a @c call(fn_name, args, IrType::VOID) pero deja claro en
 * el sitio de uso que no hay valor de retorno.  Mejora la legibilidad
 * del frontend cuando se ejecuta una funcion por sus efectos laterales.
 */
void IrBuilder::call_void(const std::string &fn_name,
                          IrValueList args) {
    IrInstr ins{};
    ins.op = IrOp::CALL;
    ins.type = IrType::VOID;
    ins.func_name = fn_name;
    ins.operands = args;
    append(std::move(ins));
}

/**
 * @brief Call a una funcion via puntero (function pointer / first-class).
 *
 * @c fn_ptr debe ser un SSA value que contiene la direccion del codigo.
 * Tipicamente proviene de un @c LOAD de un slot que guarda function
 * values, o de un @c STR_LIT_ADDR (no esta soportado en este builder
 * por simplicidad; el frontend Vesta tiene helpers especializados).
 */
IrValueId IrBuilder::call_indirect(IrValueId fn_ptr,
                                   IrValueList args,
                                   IrType ret_type) {
    const IrValueId id =
        (ret_type == IrType::VOID) ? IR_NO_VALUE : new_value(ret_type);
    IrInstr ins{};
    ins.op = IrOp::CALLIND;
    ins.type = ret_type;
    ins.dst = id;
    ins.func_ptr = fn_ptr; // SSA value, no @c operands[0]: para que el
                           // DCE / liveness lo trate como un campo distinto
                           // de los argumentos posicionales.
    ins.operands = args;
    append(std::move(ins));
    return id;
}

/**
 * @brief Call a una funcion nativa cargada via plugin / DLL.
 *
 * @c lib_func tiene el formato @c "modulo:funcion" (ej. @c "vesta_io:print").
 * El loader del .velb registra la importacion y resuelve a la direccion real
 * via @c dlsym / @c GetProcAddress al cargar el modulo nativo.
 */
IrValueId IrBuilder::call_native(const std::string &lib_func,
                                 IrValueList args,
                                 IrType ret_type) {
    const IrValueId id =
        (ret_type == IrType::VOID) ? IR_NO_VALUE : new_value(ret_type);
    IrInstr ins{};
    ins.op = IrOp::CALLN;
    ins.type = ret_type;
    ins.dst = id;
    ins.func_name = lib_func; // formato lib:funcion
    ins.operands = args;
    append(std::move(ins));
    return id;
}

// =========================================================================
//  Helpers internos
// =========================================================================

/**
 * @brief añade una instruccion al final del bloque actual.
 *
 * Politica defensiva: si no hay bloque activo (@c current_block_ ==
 * IR_NO_BLOCK o fuera de rango), descartamos silenciosamente la
 * instruccion.  Esto evita crashes mientras el frontend esta en pleno
 * lowering y nos da una oportunidad de detectar codigo malformado en
 * el siguiente pase de validacion (que comprobara que cada SSA value
 * tiene exactamente una definicion).
 */
void IrBuilder::append(IrInstr ins) {
    if (current_block_ == IR_NO_BLOCK || current_block_ >= fn_.blocks.size()) {
        return; // no-op: el frontend olvido set_insert_point
    }
    fn_.blocks[current_block_].instrs.push_back(std::move(ins));
}

/**
 * @brief Reserva un slot de stack del tamano de @c type y le escribe
 *        @c initial inmediatamente.
 *
 * Patron clasico de "create + initialize" para variables locales con
 * inicializador.  Existe como helper porque la secuencia ALLOCA + STORE
 * aparece en virtualmente cada @c let x = expr; del frontend.
 *
 * El tamano se redondea al alto a 8 bytes incluso para tipos mas pequenos
 * (BOOL/I8/I16/I32): garantiza que el slot sea reusable para tipos mayores
 * sin tener que realocar y simplifica el alignment al alto.  El coste es
 * trivial (max 7 bytes desperdiciados por variable).
 */
IrValueId IrBuilder::alloca_init(IrValueId initial, IrType type) {
    // Eje de RANURA del vocabulario unico: el hueco de pila de un valor.  Aqui
    // habia otra copia de esa tabla.
    uint32_t bytes = type_slot_bytes(type);
    // Redondear al alto a 8 bytes: cualquier slot tiene capacidad de
    // qword, lo que permite alocacion uniforme + reuso entre tipos.
    if (bytes < 8) bytes = 8;
    const IrValueId slot = alloca_bytes(bytes);
    store(initial, slot, type);
    return slot;
}

/**
 * @brief Crea un IrValue nuevo (SSA destination fresh) sin emitir
 *        ninguna instruccion.
 *
 * Usado internamente por todas las factorias de instrucciones para
 * obtener el destino antes de construir la @c IrInstr.  El nombre opcional
 * es para impresion / debug; si esta vacio generamos @c "%<id>" como
 * nombre canonico (compatible con la notacion textual del IR).
 */
IrValueId IrBuilder::new_value(IrType type, const std::string &name) {
    const IrValueId id = static_cast<IrValueId>(fn_.values.size());
    IrValue v;
    v.id = id;
    v.type = type;
    v.name = name.empty() ? ("%" + std::to_string(id)) : name;
    fn_.values.push_back(std::move(v));
    return id;
}

} // namespace ir
