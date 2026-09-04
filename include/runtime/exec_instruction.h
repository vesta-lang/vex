/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file exec_instruction.h
 * @brief Tablas de acceso a registros y declaraciones de todos los ejecutores
 * de instrucciones.
 *
 * Define:
 *   - MASKS[4] y SIGNBIT[4]: constantes para operaciones con signo.
 *   - read_reg_table[4] / write_reg_table[4]: despacho de lectura/escritura
 * segun modo (8/16/32/64 bits).
 *   - read_special_table[12] / write_special_table[12]: acceso a registros
 * especiales (CUR0-CUR3, RIP, RBP, RSP, RFLAGS).
 *   - read_special() / write_special(): wrappers seguros con comprobacion de
 * rango.
 *   - Declaraciones de todos los ejecutores: ALU reg, ALU imm, ALU SIB, control
 * de flujo, pila, FFI nativa, GC, raw allocator y sistema OOP.
 *
 * Si CAMBIA lo que hace un manejador, hay que regenerar la base de datos de la
 * VM (`src/runtime/instr_db_vm_gen.cpp`): guarda que toca cada opcode sin
 * nombrarlo en un operando --banderas, pila, marco, contador de programa--, y
 * de ahi sale si dos instrucciones se pueden reordenar.  Se deriva del CODIGO
 * MAQUINA de estas funciones, asi que cambiar una y no regenerar deja la tabla
 * mintiendo.  Las instrucciones estan en la cabecera de
 * `src/runtime/decode_table.cpp`; `test_efectos_opcodes` avisa si no cuadra.
 */

#ifndef EXEC_INSTRUCTION_H
#define EXEC_INSTRUCTION_H

#include <cstdint>
#include "decode_table.h"
#include "emmit/emmit_decl.h"

namespace runtime {

// =========================================================================
//  Constantes para operaciones con signo
// =========================================================================

/**
 * @brief Mascaras de bits para los cuatro modos de tamano de operando.
 *
 * Indice 0 = 8 bits (byte), 1 = 16 bits (word), 2 = 32 bits (dword), 3 = 64
 * bits (qword).
 */
static constexpr uint64_t MASKS[4] = {
    0xFFULL,              ///< Mascara para operando de  8 bits
    0xFFFFULL,            ///< Mascara para operando de 16 bits
    0xFFFFFFFFULL,        ///< Mascara para operando de 32 bits
    0xFFFFFFFFFFFFFFFFULL ///< Mascara para operando de 64 bits
};

/**
 * @brief Indice del bit de signo para cada modo de tamano de operando.
 *
 * Indice 0 = bit 7 (8b), 1 = bit 15 (16b), 2 = bit 31 (32b), 3 = bit 63 (64b).
 */
static constexpr int SIGNBIT[4] = {7, 15, 31, 63};

// =========================================================================
//  Tablas de lectura de registros generales (modo 0-3 -> 8/16/32/64 bits)
// =========================================================================

using ReadRegFn = uint64_t (*)(
    ProcessVM *, uint8_t); ///< Tipo de funcion de lectura de registro

/** @brief Lee el byte bajo del registro @p r. */
static uint64_t read_reg8(ProcessVM *vm, uint8_t r) {
    return vm->registers.regs[r].byte_lo();
}

/** @brief Lee la word baja del registro @p r. */
static uint64_t read_reg16(ProcessVM *vm, uint8_t r) {
    return vm->registers.regs[r].word_lo();
}

/** @brief Lee la dword baja del registro @p r. */
static uint64_t read_reg32(ProcessVM *vm, uint8_t r) {
    return vm->registers.regs[r].dword_lo();
}

/** @brief Lee la qword completa del registro @p r. */
static uint64_t read_reg64(ProcessVM *vm, uint8_t r) {
    return vm->registers.regs[r].qword();
}

/**
 * @brief Tabla de funciones de lectura indexada por modo (0=8b, 1=16b, 2=32b,
 * 3=64b).
 *
 * Permite seleccionar el tamano de lectura con un simple indice en lugar de un
 * switch.
 */
static constexpr ReadRegFn read_reg_table[] = {
    read_reg8,  ///< modo 0 ->  8 bits
    read_reg16, ///< modo 1 -> 16 bits
    read_reg32, ///< modo 2 -> 32 bits
    read_reg64  ///< modo 3 -> 64 bits
};

// =========================================================================
//  Tablas de escritura de registros generales (modo 0-3 -> 8/16/32/64 bits)
// =========================================================================

using WriteRegFn =
    void (*)(ProcessVM *, uint8_t,
             uint64_t); ///< Tipo de funcion de escritura de registro

/** @brief Escribe el byte bajo del registro @p r con el valor @p v. */
static void write_reg8(ProcessVM *vm, uint8_t r, uint64_t v) {
    vm->registers.regs[r].byte_lo(v);
}

/** @brief Escribe la word baja del registro @p r con el valor @p v. */
static void write_reg16(ProcessVM *vm, uint8_t r, uint64_t v) {
    vm->registers.regs[r].word_lo(v);
}

/** @brief Escribe la dword baja del registro @p r con el valor @p v. */
static void write_reg32(ProcessVM *vm, uint8_t r, uint64_t v) {
    vm->registers.regs[r].dword_lo(v);
}

/** @brief Escribe la qword completa del registro @p r con el valor @p v. */
static void write_reg64(ProcessVM *vm, uint8_t r, uint64_t v) {
    vm->registers.regs[r].qword(v);
}

/**
 * @brief Tabla de funciones de escritura indexada por modo (0=8b, 1=16b, 2=32b,
 * 3=64b).
 */
static constexpr WriteRegFn write_reg_table[] = {
    write_reg8,  ///< modo 0 ->  8 bits
    write_reg16, ///< modo 1 -> 16 bits
    write_reg32, ///< modo 2 -> 32 bits
    write_reg64  ///< modo 3 -> 64 bits
};

// =========================================================================
//  Registros especiales: CUR0-CUR3, RIP, RBP, RSP, RFLAGS
// =========================================================================

using ReadSpecialFn = uint64_t (*)(
    ProcessVM *); ///< Tipo de funcion de lectura de registro especial

static uint64_t read_cur0(ProcessVM *vm) {
    return vm->registers.cur[0].qword();
} ///< Lee CUR0
static uint64_t read_cur1(ProcessVM *vm) {
    return vm->registers.cur[1].qword();
} ///< Lee CUR1
static uint64_t read_cur2(ProcessVM *vm) {
    return vm->registers.cur[2].qword();
} ///< Lee CUR2
static uint64_t read_cur3(ProcessVM *vm) {
    return vm->registers.cur[3].qword();
} ///< Lee CUR3
static uint64_t read_rip(ProcessVM *vm) {
    return vm->registers.rip.raw();
} ///< Lee RIP
static uint64_t read_rbp(ProcessVM *vm) {
    return vm->registers.base_pointer.raw();
} ///< Lee RBP
static uint64_t read_rsp(ProcessVM *vm) {
    return vm->registers.stack_pointer.raw();
} ///< Lee RSP
static uint64_t read_rflags(ProcessVM *vm) {
    return vm->registers.flags.raw();
} ///< Lee RFLAGS

/**
 * @brief Tabla de funciones de lectura de registros especiales.
 *
 * Indexada por el codigo de registro especial (0-11).
 * Entradas 4-7 son nullptr (reservadas para uso futuro).
 *
 * Mapa de indices:
 *   0=CUR0, 1=CUR1, 2=CUR2, 3=CUR3, 4-7=nullptr, 8=RIP, 9=RBP, 10=RSP,
 * 11=RFLAGS
 */
static constexpr ReadSpecialFn read_special_table[12] = {
    read_cur0,  ///< 0  -> CUR0
    read_cur1,  ///< 1  -> CUR1
    read_cur2,  ///< 2  -> CUR2
    read_cur3,  ///< 3  -> CUR3
    nullptr,    ///< 4  -> reservado
    nullptr,    ///< 5  -> reservado
    nullptr,    ///< 6  -> reservado
    nullptr,    ///< 7  -> reservado
    read_rip,   ///< 8  -> RIP
    read_rbp,   ///< 9  -> RBP
    read_rsp,   ///< 10 -> RSP
    read_rflags ///< 11 -> RFLAGS
};

/// Entradas de las tablas de registros especiales.  Se DERIVA del array en vez
/// de escribirse: un literal se queda atras el dia que la tabla crezca, y el
/// que se queda atras aqui no da un error -- deja pasar un indice invalido.
constexpr size_t kSpecialCount =
    sizeof(read_special_table) / sizeof(read_special_table[0]);

/**
 * @brief Nombres de los registros especiales para mensajes de diagnostico.
 *
 * Indexado igual que read_special_table (0-11).
 */
static const char *regs_special[] = {
    "cur0",    "cur1",    "cur2", "cur3", "nullptr", "nullptr",
    "nullptr", "nullptr", "rip",  "rbp",  "rsp",     "rflags",
};

/**
 * @brief Lee el valor de un registro especial de forma segura.
 *
 * Comprueba que el codigo de registro es valido y que la funcion
 * de lectura no es nullptr antes de llamarla.
 *
 * @param vm   Proceso virtual propietario de los registros.
 * @param code Codigo del registro especial (0-11).
 * @return Valor del registro, o 0 si el codigo es invalido.
 */
inline uint64_t read_special(ProcessVM *vm, uint8_t code) {
    if (code >= kSpecialCount || read_special_table[code] == nullptr) {
        return 0; // codigo invalido o entrada reservada
    }
    return read_special_table[code](vm);
}

// =========================================================================
//  Tablas de escritura de registros especiales
// =========================================================================

using WriteSpecialFn =
    void (*)(ProcessVM *, uint64_t); ///< Tipo de funcion de escritura especial

static void write_cur0(ProcessVM *vm, uint64_t v) {
    vm->registers.cur[0].qword(v);
} ///< Escribe CUR0
static void write_cur1(ProcessVM *vm, uint64_t v) {
    vm->registers.cur[1].qword(v);
} ///< Escribe CUR1
static void write_cur2(ProcessVM *vm, uint64_t v) {
    vm->registers.cur[2].qword(v);
} ///< Escribe CUR2
static void write_cur3(ProcessVM *vm, uint64_t v) {
    vm->registers.cur[3].qword(v);
} ///< Escribe CUR3

/**
 * @brief Escribe RIP y marca did_jump para que el pipeline no avance el PC
 * automaticamente.
 *
 * Cualquier escritura en RIP constituye un salto; la instruccion que la provoca
 * debe asegurarse de no avanzar el PC de forma adicional.
 */
static void write_rip(ProcessVM *vm, uint64_t v) {
    vm->registers.rip.raw(v);
    vm->decoded_ptr->flags_info.did_jump =
        true; // marcar salto para evitar doble avance del PC
}

static void write_rbp(ProcessVM *vm, uint64_t v) {
    vm->registers.base_pointer.raw(v);
} ///< Escribe RBP
static void write_rsp(ProcessVM *vm, uint64_t v) {
    vm->registers.stack_pointer.raw(v);
} ///< Escribe RSP
static void write_rflags(ProcessVM *vm, uint64_t v) {
    vm->registers.flags.set_raw(v);
} ///< Escribe RFLAGS

/**
 * @brief Tabla de funciones de escritura de registros especiales.
 *
 * Mismo mapa de indices que read_special_table.
 * Entradas 4-7 son nullptr (reservadas).
 */
static constexpr WriteSpecialFn write_special_table[] = {
    write_cur0,  ///< 0  -> CUR0
    write_cur1,  ///< 1  -> CUR1
    write_cur2,  ///< 2  -> CUR2
    write_cur3,  ///< 3  -> CUR3
    nullptr,     ///< 4  -> reservado
    nullptr,     ///< 5  -> reservado
    nullptr,     ///< 6  -> reservado
    nullptr,     ///< 7  -> reservado
    write_rip,   ///< 8  -> RIP (marca did_jump)
    write_rbp,   ///< 9  -> RBP
    write_rsp,   ///< 10 -> RSP
    write_rflags ///< 11 -> RFLAGS
};

/* Las dos tablas se indexan con el MISMO codigo, asi que tienen que medir lo
 * mismo: si una crece y la otra no, el codigo valido para una se sale de la
 * otra. */
static_assert(sizeof(write_special_table) / sizeof(write_special_table[0]) ==
                  kSpecialCount,
              "read_special_table y write_special_table deben tener el mismo "
              "numero de entradas");

/**
 * @brief Escribe un valor en un registro especial de forma segura.
 *
 * @param vm   Proceso virtual propietario de los registros.
 * @param code Codigo del registro especial (0-11).
 * @param v    Valor a escribir en el registro.
 *
 * @note La guarda comparaba `code` contra `sizeof(write_special_table)`, que
 *       son los BYTES (96), no las entradas (12).  Como `code` sale de
 *       `reg2 & 0xF`, los codigos 12..15 pasaban la comprobacion, leian FUERA
 *       del array y, si lo leido no era nulo, se LLAMABA a ese puntero.  El
 *       propio mensaje del aviso decia "code >= 12", que era la intencion.
 */
inline void write_special(ProcessVM *vm, uint8_t code, uint64_t v) {
    if (code >= kSpecialCount || write_special_table[code] == nullptr) {
        VM_ASSERT(false,
                  "write_special: code=" + std::to_string(code) +
                      " fuera de rango (validos 0.." +
                      std::to_string(kSpecialCount - 1) + ")",
                  {});
        return; // codigo invalido: no hacer nada en release
    }
    write_special_table[code](vm, v);
}

// =========================================================================
//  Ejecutores: tipo registro
// =========================================================================

/**
 * @brief Ejecuta INC o DEC segun el campo _signed_instruct de la instruccion.
 *
 *   - _signed_instruct == 0 -> INC: incrementa el registro en 1.
 *   - _signed_instruct == 1 -> DEC: decrementa el registro en 1.
 *
 * @param vm    Proceso virtual que ejecuta la instruccion.
 * @param instr Instruccion descodificada.
 */
void exec_instr_inc_dec_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta MOV reg, reg: copia el valor de un registro en otro. */
void exec_instr_mov_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta ADD reg, reg: suma dos registros y actualiza flags. */
void exec_instr_add_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta SUB reg, reg: resta dos registros y actualiza flags. */
void exec_instr_sub_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta MUL reg, reg: multiplica dos registros y actualiza flags. */
void exec_instr_mul_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta CMP reg, reg: resta sin guardar resultado; solo actualiza
 * flags. */
void exec_instr_cmp_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta AND reg, reg: AND bit a bit y actualiza flags. */
void exec_instr_and_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta OR reg, reg: OR bit a bit y actualiza flags. */
void exec_instr_or_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta XOR reg, reg: XOR bit a bit y actualiza flags. */
void exec_instr_xor_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta DIV reg, reg: division entera y actualiza flags. */
void exec_instr_div_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta NOT reg: complemento a uno del registro. */
void exec_instr_not_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta SHL reg, reg: desplazamiento logico a la izquierda. */
void exec_instr_shl_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta SHR reg, reg: desplazamiento logico a la derecha. */
void exec_instr_shr_reg(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta SAR reg, reg: desplazamiento aritmetico a la derecha
 * (preserva signo). */
void exec_instr_sar_reg(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: modo SIB (Scale-Index-Base)
// =========================================================================

/** @brief Ejecuta ADD con acceso a memoria SIB. */
void exec_instr_add_sib(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta SUB con acceso a memoria SIB. */
void exec_instr_sub_sib(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta MUL con acceso a memoria SIB. */
void exec_instr_mul_sib(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta DIV con acceso a memoria SIB. */
void exec_instr_div_sib(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta CMP con acceso a memoria SIB. */
void exec_instr_cmp_sib(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta MOV con acceso a memoria SIB. */
void exec_instr_mov_sib(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Direccion efectiva de un operando de memoria codificado SIB.
 *
 * Codificacion del campo `scale`: bit 2 = hay indice, bits 1-0 = desplazamiento
 *   0 -> indice * 1     2 -> indice * 4
 *   1 -> indice * 2     3 -> indice * 8
 *
 * EN LA CABECERA a proposito: la usan el manejador (`exec_instruction_alu.cpp`)
 * y la ruta rapida del interprete (`scheduler.cpp`), y tiene que ser la MISMA
 * cuenta en los dos.  Copiada en dos sitios, el dia que difieran no daria un
 * error de compilacion -- daria otra direccion, que es mucho peor.
 *
 * @param vm    Proceso que ejecuta.
 * @param instr Instruccion descodificada, con sus campos `mem_data`.
 * @return      La direccion efectiva, de 64 bits.
 */
inline uint64_t sib_effective_addr(ProcessVM *vm, const DecodedInstr &instr) {
    const uint64_t base =
        vm->registers.regs[instr.data_instruction.mem_data.reg_base].raw();
    // bit 2 del campo `scale` dice si hay registro de indice
    if (((instr.data_instruction.mem_data.scale >> 2) & 1) == 0) return base;
    const uint64_t index =
        vm->registers.regs[instr.data_instruction.mem_data.reg_index].raw();
    const uint8_t scale = instr.data_instruction.mem_data.scale & 0x3;
    return base + (index << scale); // base + indice * (1 << escala)
}
/** @brief Ejecuta MOVC: movimiento entre registro y memoria virtual o del host.
 */
void exec_instr_movc_mem(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta MOVC reg,reg: movimiento de cursor de registro a registro. */
void exec_instr_movc_reg(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: tipo inmediato
// =========================================================================

/** @brief Ejecuta ADD reg, imm: suma un inmediato al registro y actualiza
 * flags. */
void exec_instr_add_imm(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta SUB reg, imm: resta un inmediato del registro y actualiza
 * flags. */
void exec_instr_sub_imm(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta MUL reg, imm: multiplica el registro por un inmediato. */
void exec_instr_mul_imm(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta DIV reg, imm: divide el registro entre un inmediato. */
void exec_instr_div_imm(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta CMP reg, imm: compara registro con inmediato; solo flags. */
void exec_instr_cmp_imm(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta MOD reg, reg: resto de la division entera y actualiza flags.
 */
void exec_instr_mod_reg(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta MOD con acceso a memoria SIB. */
void exec_instr_mod_sib(ProcessVM *vm, const DecodedInstr &instr);
/** @brief Ejecuta MOD reg, imm: resto de la division con inmediato. */
void exec_instr_mod_imm(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta SETCC r_dst, cond: almacena 0 o 1 en el registro segun la
 * condicion de flags.
 *
 * Encoding FIXED_4: [0x00][0x43][byte2][0x00]
 *   byte2 = (cond<<4) | dst_reg
 * El codigo de condicion es el mismo que usa JCC (0x00=JO, 0x0F=siempre).
 */
void exec_instr_setcc(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta SEXT r_dst, N: sign-extiende r_dst desde N bits (8/16/32)
 * a 64.
 */
void exec_instr_sext(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief CSEL r_dst, r_cond, r_a, r_b : @c dst = (cond != 0) ? a : b.
 *
 * Super-instruccion (1 despacho) del @c IrOp::SELECT para el INTERPRETE
 * dispatch-bound: sustituye la mascara branchless (~8 ops:
 * @c subu/xor/and/xor + cargas) que penalizaba branch_unpredict 2.3x.  El
 * SELECT del IR es una primitiva SEMANTICA -- el JIT/AOT lo bajan a @c cmov,
 * el interp a esta op.  Encoding FIXED_4 (decode_instr_four_reg):
 * @c [0x00][0x7E][b2][b3] con b2=(dst<<4)|cond, b3=(a<<4)|b.
 */
void exec_instr_csel(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta TRYENTER: apila un nuevo frame de excepcion en
 * exc_frame_stack.
 *
 * Encoding FIXED_4 REG: [0x00][0x44][ctrl][byte3]
 *   reg1 = registro con la PC handler (direccion absoluta en VM)
 *   reg2 = registro con ClassInfo* del tipo capturado (0 = catch-all)
 */
void exec_instr_tryenter(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta TRYLEAVE: desapila el frame de excepcion del tope de
 * exc_frame_stack.
 *
 * Encoding FIXED_2: [0x00][0x45]
 */
void exec_instr_tryleave(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: instrucciones de cadenas (StringObject)
// =========================================================================

/**
 * @brief Ejecuta STRMAKE r_dst, r_src: crea un StringObject a partir de un
 * buffer en VM.
 *
 * Encoding FIXED_4: [0x00][0x46][ctrl][byte3]
 *   ctrl = (r_dst<<4)|r_src   - r_src apunta al buffer UTF-8 en memoria VM
 *   byte3 = (encoding<<4)|r_len - r_len contiene la longitud en bytes
 * r_dst recibe el GcHandle del nuevo StringObject.
 */
void exec_instr_strmake(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRMAKE_H r_dst, r_src: crea StringObject desde buffer HOST.
 *
 * Variante de STRMAKE (0x46) para casos donde el buffer reside en memoria
 * del proceso host (resultado de @c malloc, @c gcallocp, etc.) en lugar de
 * memoria VM.  Este escenario aparece naturalmente en codigo Vesta que
 * combina punteros raw (`u8* buf = malloc(n)`) con la API de strings:
 * `string s = str_make(buf, n)`.
 *
 * Encoding FIXED_4: [0x00][0x55][ctrl][byte3]  -- mismo layout que STRMAKE.
 *   ctrl  = (r_dst<<4)|r_src   r_src contiene host_ptr (uint64) al buffer
 *   byte3 = (encoding<<4)|r_len r_len contiene byte_len del buffer
 */
void exec_instr_strmake_h(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRLEN r_dst, r_src: almacena el numero de code points en
 * r_dst.
 *
 * Encoding FIXED_4: [0x00][0x47][ctrl][0x00]  ctrl = (r_dst<<4)|r_src
 */
void exec_instr_strlen(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRCAT r_dst, r_a, r_b: concatena dos StringObjects en uno
 * nuevo.
 *
 * Encoding FIXED_4: [0x00][0x48][ctrl][byte3]  ctrl=(r_dst<<4)|r_a, byte3=r_b
 */
void exec_instr_strcat(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRCMP r_dst, r_a, r_b: compara dos StringObjects.
 *
 * r_dst recibe -1, 0 o 1. ZF/SF se actualizan segun el resultado.
 * Encoding FIXED_4: [0x00][0x49][ctrl][byte3]  ctrl=(r_dst<<4)|r_a, byte3=r_b
 */
void exec_instr_strcmp(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRCONV r_dst, r_src, enc: convierte la codificacion de un
 * StringObject.
 *
 * Encoding FIXED_4: [0x00][0x4A][ctrl][byte3]  ctrl=(r_dst<<4)|r_src,
 * byte3=encoding Crea un nuevo StringObject con la codificacion indicada.
 */
void exec_instr_strconv(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRRAW r_dst, r_src: devuelve un puntero host al buffer
 * interno del string.
 *
 * Util para pasar strings a la Win32 API (MessageBoxA, CreateFileA, etc.).
 * Encoding FIXED_4: [0x00][0x4B][ctrl][0x00]  ctrl=(r_dst<<4)|r_src
 * r_dst recibe la direccion host (uint64) del buffer de datos del StringObject.
 */
void exec_instr_strraw(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRSLICE r_dst, r_src, r_range: vista sin copia sobre un
 * substring.
 *
 * r_range debe contener (cp_start << 32) | cp_len (ambos en code points).
 * Materializa ROPE antes de crear el slice.
 * Encoding FIXED_4: [0x00][0x4C][ctrl][byte3]  ctrl=(r_dst<<4)|r_src,
 * byte3=r_range (nibble)
 */
void exec_instr_strslice(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRFLAT r_dst, r_src: materializa ROPE/SLICE a FLAT.
 *
 * Si el origen ya es FLAT, r_dst recibe el mismo GcHandle sin copiar.
 * Encoding FIXED_4: [0x00][0x4D][ctrl][0x00]  ctrl=(r_dst<<4)|r_src
 */
void exec_instr_strflat(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRHASH r_dst, r_src: calcula y cachea el hash FNV-1a.
 *
 * Materializa ROPE/SLICE si es necesario. r_dst recibe el hash de 32 bits.
 * Encoding FIXED_4: [0x00][0x4E][ctrl][0x00]  ctrl=(r_dst<<4)|r_src
 */
void exec_instr_strhash(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRINTERN r_dst, r_src: interna el string en el pool del
 * proceso.
 *
 * Devuelve el GcHandle canonico (puede diferir de r_src si ya existia un
 * identico). Encoding FIXED_4: [0x00][0x4F][ctrl][0x00]  ctrl=(r_dst<<4)|r_src
 */
void exec_instr_strintern(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta STRGETENC r_dst, r_src: almacena el byte de codificacion en
 * r_dst. */
void exec_instr_strgetenc(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta STRGETBYTES r_dst, r_src: almacena el byte_len en r_dst. */
void exec_instr_strgetbytes(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta STRGETKIND r_dst, r_src: almacena el kind (0=FLAT 1=ROPE
 * 2=SLICE) en r_dst. */
void exec_instr_strgetkind(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRRESERVE r_dst, r_cap: aloca FLAT vacio con capacidad
 * reservada.
 *
 * Permite patron string-builder: STRRESERVE -> STRRAW (write) -> STRFINALIZE.
 * Encoding FIXED_4: [0x00][0x53][ctrl][0x00]  ctrl=(r_dst<<4)|r_cap
 */
void exec_instr_strreserve(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta STRFINALIZE r_dst, r_newlen: actualiza byte_len/length/hash de
 * un FLAT mutable.
 *
 * Debe usarse tras STRRESERVE + escritura directa en el buffer.
 * Encoding FIXED_4: [0x00][0x54][ctrl][0x00]  ctrl=(r_dst<<4)|r_newlen
 */
void exec_instr_strfinalize(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETMETHAT r_cls, r_idx: variante reg-reg de getmethod (0xD9).
 *
 * Devuelve en R00 el puntero host a MethodInfo del metodo i-esimo, o 0 si
 * cls es nulo o idx >= cls->method_count.  Permite iteracion dinamica
 * via builtin Vesta `getMethodAt(cls, i)` (idx desde registro, no inmediato).
 * Encoding FIXED_4: [0x00][0x6E][ctrl][0x00] con ctrl=(r_idx<<4)|r_cls.
 */
void exec_instr_getmethat(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETFLDAT r_cls, r_idx: variante reg-reg de getfield (0xD8).
 *
 * Devuelve en R00 el puntero host a FieldInfo del campo i-esimo, o 0.
 * Builtin Vesta `getFieldAt(cls, i)`.  Encoding FIXED_4 igual que getmethat.
 */
void exec_instr_getfldat(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETARGC r_dst: deposita el numero de argumentos del script.
 *
 * Lee `vm->scheduler.vm_reference.script_args.size()` y lo escribe en r_dst.
 * Encoding FIXED_4: [0x00][0x6B][ctrl][0x00] con ctrl=(r_dst<<4).
 * Builtin Vesta `args_count()`.
 */
void exec_instr_getargc(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETARG r_dst, r_idx: aloca StringObject con arg[idx].
 *
 * Lee idx de r_idx; si idx < script_args.size(), aloca un StringObject FLAT
 * (UTF-8) con los bytes del arg correspondiente y deposita el GcHandle en
 * r_dst.  Si idx fuera de rango, deposita 0 (GC_NULL_HANDLE).
 * Encoding FIXED_4: [0x00][0x6C][ctrl][0x00] con ctrl=(r_dst<<4)|r_idx.
 * Builtin Vesta `args_get(i)`.
 */
void exec_instr_getarg(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: control de flujo y pila
// =========================================================================

/**
 * @brief Ejecuta HLT: detiene el proceso de forma cooperativa.
 *
 * Emite EVT_HALT al scheduler y marca la instruccion como bloqueante para
 * que execute_instruction() no avance el PC.
 */
void exec_instr_hlt(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta PUSH: apila un valor decrementando RSP.
 *
 * PUSH: RSP -= size; [RSP] = value.
 */
void exec_instr_push(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta POP: desapila un valor incrementando RSP.
 *
 * POP: value = [RSP]; RSP += size.
 */
void exec_instr_pop(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta CALLN: llamada a funcion nativa del host.
 *
 * Puede bloquear la VM si la funcion nativa bloquea el hilo.
 * Soporta hasta 12 argumentos en R01-R12; devuelve resultado en R00.
 */
void exec_instr_calln(ProcessVM *vm, const DecodedInstr &instr);

/** @brief Ejecuta XCHG: intercambia dos valores entre registros (generales y/o
 * especiales). */
void exec_instr_xchg(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta JMP/Jcc: salto absoluto condicional o incondicional.
 *
 * Codigos de condicion (campo cond):
 *   0x00=je/jz, 0x01=jne/jnz, 0x02=jcs/jae, 0x03=jcc/jb,
 *   0x04=jmi,   0x05=jpl,      0x06=jvs,     0x07=jvc,
 *   0x08=jhi,   0x09=jls,      0x0A=jge,     0x0B=jlt,
 *   0x0C=jgt,   0x0D=jle,      0x0F=jmp (siempre).
 */
void exec_instr_jmp(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta CALLVM: llamada a subrutina de bytecode.
 *
 * Empuja ret_addr (RIP + size_instr) en la pila y salta a addr.
 */
void exec_instr_callvm(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta RET: retorno de subrutina.
 *
 * Desapila la direccion de retorno, descarta el FrameHeader OOP activo si
 * existe y salta a la direccion de retorno.
 */
void exec_instr_ret(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta ENTER: crea un marco de pila (prologo de funcion).
 *
 * Secuencia: push RBP -> mov RBP, RSP -> sub RSP, frame_size.
 */
void exec_instr_enter(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta LEAVE: destruye el marco de pila actual (epilogo de funcion).
 *
 * Secuencia: mov RSP, RBP -> pop RBP.
 */
void exec_instr_leave(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta JMPR: salto incondicional a la direccion contenida en un
 * registro.
 *
 * Soporta registros generales y especiales segun el campo reg_ext.
 */
void exec_instr_jmpr(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta CALLVMR: llamada indirecta a subrutina via registro.
 *
 * Empuja ret_addr en la pila y salta al valor del registro indicado.
 */
void exec_instr_callvmr(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta JREL: salto relativo condicional o incondicional.
 *
 * Mismos codigos de condicion que JMP.
 * Destino = PC + size_instr + disp32 (relativo a la instruccion siguiente).
 * Formato extendido: [0x00][0x2D][cond][pad][disp32] = 8 bytes.
 */
void exec_instr_jrel(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta MOV inmediato: asignacion de inmediato a registro o memoria.
 *
 * Tres variantes segun direction y _signed_instruct:
 *   1. d=1, s=1 -> escribir en registro especial.
 *   2. d=0, s=0 -> mov reg, imm.
 *   3. d=1, s=0 -> mov [reg], imm.
 */
void exec_instr_inmed_mov(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: cursores y acceso a memoria host (0x00 0xC0 .. 0xC2)
// =========================================================================

/**
 * @brief Ejecuta READCUR: lee N bytes de la direccion host en curN -> dest_reg.
 *
 * reg1 = registro destino; reg2 = indice del cursor (0-3).
 * Tamano segun mode: 0=byte, 1=word, 2=dword, 3=qword.
 */
void exec_instr_readcur(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta WRITECUR: escribe N bytes de src_reg en la direccion host en
 * curN.
 *
 * reg1 = registro fuente; reg2 = indice del cursor (0-3).
 * Tamano segun mode: 0=byte, 1=word, 2=dword, 3=qword.
 */
void exec_instr_writecur(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GCDEREF: convierte un GcHandle en puntero host y lo almacena
 * en curN.
 *
 * reg1 = registro con el GcHandle; reg2 = indice del cursor destino (0-3).
 */
void exec_instr_gcderef(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETPID: deposita el PID encoded del proceso actual en r_dst.
 *
 * El formato es @c (scheduler_id << 32) | (local_pid & 0xFFFFFFFF), igual
 * convencion que devuelve @c spawn en R0 al crear un proceso hijo.  Asi
 * el hijo puede tomar su propio PID con @c getpid y enviarselo al padre
 * via mailbox para iniciar comunicacion bidireccional.
 *
 * Para uso en @c msgsend, este formato funciona como "PID local" porque
 * @c distrib::DistRuntime::msgsend extrae el local_pid de los bits 31-0
 * y busca el proceso en cualquier scheduler.
 *
 * Formato: [0x00][0x57][byte2][0x00]  (FIXED_4)
 *   byte2 bits 3-0 = r_dst.
 *
 * @param vm    Proceso virtual cuyo PID se devuelve.
 * @param instr reg_data.reg1 = r_dst.
 */
void exec_instr_getpid(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GCHANDLE: lookup inverso payload_ptr -> GcHandle.
 *
 * Es el inverso de @c GCDEREF: dado un puntero host al payload de un objeto
 * GC vivo, devuelve el GcHandle del objeto.  Usa @c GcHeap::handle_for_ptr
 * que mantiene un mapa hash interno para coste O(1) amortizado.
 *
 * Si el puntero no corresponde a ningun objeto vivo (no esta en el mapa
 * inverso), devuelve @c GC_NULL_HANDLE.  El llamante puede comprobar este
 * caso para fallar limpio (no hay segfault ni corrupcion).
 *
 * Caso de uso primario: @c synchronized(obj) en Vesta.  El frontend tiene
 * @c obj como host_ptr (resultado de @c gcderef en el constructor); para
 * @c monenter necesita el GcHandle, que lo obtiene con @c GCHANDLE.
 *
 * Formato: [0x00][0x55][byte2][0x00]  (FIXED_4)
 *   byte2 = (r_src << 4) | r_dst.
 *
 * @param vm    Proceso virtual que ejecuta GCHANDLE.
 * @param instr Instruccion descodificada con reg_data.reg1 = r_dst, reg2 =
 * r_src.
 */
void exec_instr_gchandle(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta MVTAKE: move-and-take de 8 bytes en memoria VM.
 *
 * Semantica: copia un qword desde la direccion en r_src hasta la
 * direccion en r_dst, y deja en cero la direccion fuente.  Es el
 * primitivo de move ownership para smart pointers (unique<T>,
 * shared<T>) sin atomicidad cross-thread (el move siempre es
 * single-owner por construccion).  Tres pasos atomicos en codigo VM,
 * pensado para colapsar a 3 instrucciones host x86-64 cuando el JIT
 * lo recozca (load + store + zero-store).
 *
 * Formato: [0x00][0x72][byte2][0x00]  (FIXED_4)
 *   byte2 = (r_src_addr << 4) | r_dst_addr.
 *
 * Postcondiciones:
 *   *(u64*)[r_dst] = *(u64*)[r_src]
 *   *(u64*)[r_src] = 0
 *
 * @param vm    Proceso virtual que ejecuta MVTAKE.
 * @param instr Instruccion descodificada con reg_data.reg1=r_dst, reg2=r_src.
 */
void exec_instr_mvtake(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Registra el host_ptr en r_ptr para cleanup automatico
 * en RET / do_throw / TAILCALL del frame actual (opcode 0x7E).
 *
 * Sprint MMM-ext leak-fix (2026-06-01).  Tras `alloc` que produce
 * un host_ptr y cuyo IR ALLOCA tenia `host_alloca=true` (marcado
 * por @c ir_pass_promote_callned_allocas), el bytecode emit
 * inserta @c htrack para que el ptr se libere al destruir el
 * frame, sin necesidad de RAW_FREE explicito ni leaks en throw.
 *
 * Si no hay frame activo (codigo top-level fuera de cualquier
 * funcion), es no-op.
 */
void exec_instr_htrack(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief GCFINAL r_box, kind (0x7F): registra/desregistra el finalizador GC
 *        del box en r_box (kind!=0 registra, kind==0 desregistra).
 */
void exec_instr_gcfinal(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief GCFINALC r_box, r_dtor (opcode 0x8D): registra un finalizador
 *        CLASS_DTOR para un gc<Clase> con ~Clase() (dtor concreto en r_dtor).
 */
void exec_instr_gcfinalc(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief GCFINALL (opcode 0x8E): finaliza todo objeto GC vivo con recurso
 *        interno (builtin gc_finalize_all()).  Determinista.
 */
void exec_instr_gcfinall(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief GCCOLLECT (0x8C): fuerza minor+major GC del proceso + drena
 *        finalizadores.  Builtin Vesta gc_collect().
 */
void exec_instr_gccollect(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta super-instrucciones ALU 3-operandos (0x73-0x7B).
 *
 * Combina @c mov rd,rs1 + OP rd,rs2 en una sola instruccion VM.  La
 * operacion se determina por opcode_index (0x73 adds3, 0x74 subs3,
 * 0x75 muls3, 0x76 addu3, 0x77 subu3, 0x78 mulu3, 0x79 and3, 0x7A or3,
 * 0x7B xor3).  Lee r_src1 y r_src2 de los nibbles altos de byte2 y
 * byte3 respect., escribe en r_dst (nibble bajo de byte2).  Actualiza
 * ZF/SF/CF/OF segun semantica de la operacion.
 */
void exec_instr_alu3(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta super-instruccion LOAD con zero-extend (loadz / loadzh).
 *
 * Combina @c mov rd,0 + @c mov rd_sized,[rs] en una sola instruccion VM.
 * El tamano (8/16/32/64 bits) se selecciona por @c flags_info.mode; el
 * bit @c _signed_instruct = 1 indica que el puntero es HOST (loadzh
 * opcode 0x7D), 0 = VM mem (loadz opcode 0x7C).
 */
void exec_instr_loadz(ProcessVM *vm, const DecodedInstr &instr);

/* --- Memoria masiva (0xB6-0xB9): memset/memcpy en memoria VM y HOST ---
 * Ver src/runtime/exec_instruction_mem.cpp.  Las cuatro comparten el formato
 * fisico de 3 registros (Convention B, mismo layout de nibbles que alu3). */
/** @brief memset r_dst, r_val, r_len -- relleno en memoria VIRTUAL. */
void exec_instr_memset(ProcessVM *vm, const DecodedInstr &instr);
/** @brief memseth r_dst, r_val, r_len -- relleno en memoria del HOST. */
void exec_instr_memseth(ProcessVM *vm, const DecodedInstr &instr);
/** @brief memcpy r_dst, r_src, r_len -- copia en memoria VIRTUAL. */
void exec_instr_memcpy(ProcessVM *vm, const DecodedInstr &instr);
/** @brief memcpyh r_dst, r_src, r_len -- copia en memoria del HOST. */
void exec_instr_memcpyh(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta ADDCUR: suma un inmediato con signo al registro cursor
 * indicado.
 *
 * Permite avanzar (imm > 0) o retroceder (imm < 0) el cursor en un numero
 * arbitrario de bytes sin necesidad del patron xchg/adds/xchg.
 *
 * Formato: [0x00][0xC3][ctrl][pad][imm_lo][imm_hi]  (FIXED_6)
 *   ctrl bits 5-4 = cur_idx (0-3); imm16 = desplazamiento con signo.
 */
void exec_instr_addcur(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta VMCOPY: copia bytes de VM memory a host memory (cursor).
 *
 * Copia mem_data.reg_base bytes desde VM memory[rSrc] a host memory[curN].
 * Tras la copia avanza automaticamente curN y rSrc en rLen bytes.
 * Usa la ruta SIMD mas rapida disponible (AVX-512, AVX2, SSE2 o memcpy).
 *
 * Formato: [0x00][0xC4][byte_A][byte_B]  (FIXED_4)
 *   byte_A bits 5-4 = cur_idx, bits 3-0 = rSrc; byte_B bits 7-4 = rLen.
 */
void exec_instr_vmcopy(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta VCOPYH: copia bytes de host memory (cursor) a VM memory.
 *
 * Inverso de VMCOPY: copia rLen bytes desde host memory[curN] a VM
 * memory[rDst]. Avanza curN y rDst en rLen bytes tras la copia.
 *
 * Formato: [0x00][0xC5][byte_A][byte_B]  (FIXED_4)
 *   byte_A bits 5-4 = cur_idx, bits 3-0 = rDst; byte_B bits 7-4 = rLen.
 */
void exec_instr_vcopyh(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETPROC rN: carga el puntero al proceso actual en rN.
 *
 * El valor almacenado es el ProcessVM* del proceso que ejecuta la instruccion,
 * reinterpretado como uint64_t.  Puede pasarse a una funcion nativa via calln
 * para que acceda a la memoria VM del proceso a traves de la VestaPluginAPI.
 *
 * Formato: [0x00][0xC6][ctrl][0x00]  (FIXED_4, ctrl bits 7-4 = reg_dst)
 */
void exec_instr_getproc(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETVM rN: carga el puntero a la instancia VM propietaria en
 * rN.
 *
 * Sigue la cadena ProcessVM -> Scheduler::vm_reference para obtener la VM*.
 *
 * Formato: [0x00][0xC7][ctrl][0x00]  (FIXED_4, ctrl bits 7-4 = reg_dst)
 */
void exec_instr_getvm(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GETMGR rN: carga el puntero al ManageVM del gestor en rN.
 *
 * Sigue la cadena ProcessVM -> Scheduler::vm_reference -> VM::mgr_vm.
 *
 * Formato: [0x00][0xC8][ctrl][0x00]  (FIXED_4, ctrl bits 7-4 = reg_dst)
 */
void exec_instr_getmgr(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: GC generacional (0x00 0xA0 .. 0xA5)
// =========================================================================

/**
 * @brief Ejecuta NEWOBJ: aloca un objeto gestionado por el GC.
 *
 * reg1 = registro con puntero a ClassInfo.  Inicializa ObjectHeader con
 * GC_OWNED. Devuelve GcHandle en R00; GC_NULL_HANDLE si no hay memoria.
 */
void exec_instr_newobj(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta NEWOBJS ( Z): aloca instancia en SharedHeap.
 *
 * Variante shared de NEWOBJ.  Aloca en vm.shared_heap, registra el
 * host_ptr en shared_handle_table, e inicializa ObjectHeader con
 * hash_code = handle (con SHARED_HANDLE_BIT) para reverse lookup
 * O(1) desde gchandle.
 */
void exec_instr_newobjs(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GCRUN: fuerza un ciclo de GC menor.
 *
 * Llama a minor_gc(); si old_used >= threshold tambien ejecuta major_gc().
 */
void exec_instr_gcrun(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GCCONFIG: ajusta el umbral de promocion a la generacion
 * antigua.
 *
 * reg1 = registro con el nuevo umbral en bytes.
 */
void exec_instr_gcconfig(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GCDROP: libera un objeto del heap GC por handle.
 *
 * reg1 = registro con el GcHandle a liberar.
 */
void exec_instr_gc_drop(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GCWB (write barrier): notifica una escritura sobre un objeto
 * antiguo.
 *
 * Registra el handle en el remembered set para que el minor GC lo trate como
 * raiz. reg1 = registro con el GcHandle del objeto antiguo modificado.
 */
void exec_instr_gcwb(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta GCALLOC: aloca un bloque bruto en el heap GC sin ObjectHeader.
 *
 * reg1 = registro con el tamano en bytes.  Devuelve GcHandle en R00.
 */
void exec_instr_gcalloc(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: atomics i64 ( Z, opcodes 0x00 0xA9 .. 0xAD)
// =========================================================================
void exec_instr_atomicld(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_atomicst(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_atomicadd(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_atomiccas(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_sharedstat(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_gcpromote(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_gcdemote(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: raw allocator (0x00 0xB0 .. 0xB2)
// =========================================================================

/**
 * @brief Ejecuta RAWALLOC: aloca memoria bruta no gestionada por el GC.
 *
 * reg1 = tamano en bytes.  Devuelve puntero host en R00 (0 si falla).
 */
void exec_instr_raw_alloc(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta RAWFREE: libera un bloque de memoria bruta por puntero.
 *
 * reg1 = puntero host al bloque a liberar.
 */
void exec_instr_raw_free(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta RAWREALLOC: redimensiona un bloque de memoria bruta.
 *
 * reg1 = puntero original; reg2 = nuevo tamano en bytes.
 * Devuelve el nuevo puntero host en R00 (0 si falla).
 */
void exec_instr_raw_realloc(ProcessVM *vm, const DecodedInstr &instr);

// =========================================================================
//  Ejecutores: sistema de objetos OOP (0x00 0xD0 .. 0xEB)
// =========================================================================

/** @brief NEWOBJRAW: aloca objeto raw sin GC; inicializa ObjectHeader con
 * RAW_OWNED. */
void exec_instr_newobjraw(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CALLVIRT: llamada virtual via vtable; empuja FrameHeader. */
void exec_instr_callvirt(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CALLM: llamada via MethodInfo* directo (sin vtable lookup); util para
 *         dispatch dinamico (interfaces, reflexion).  Recorre advice_chain
 * igual que CALLVIRT. */
void exec_instr_callm(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CALLITF: dispatch de interfaz via itable.  Lee un ItfCallParams
 *         (r_params) con nombre de interfaz + metodo + indice + count, resuelve
 *         el MethodInfo* concreto via la itable lazy de la clase del receptor
 *         (indice O(1) tras warmup) y despacha como CALLM (con advice_chain).
 */
void exec_instr_callitf(ProcessVM *vm, const DecodedInstr &instr);
/** @brief PROCEED: dentro de un advice @Around, invoca el target original via
 *         frame.proceed_target con la calling convention actual (r1=this, args
 * en r2..). */
void exec_instr_proceed(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CALLSUPER: llamada al metodo de la superclase via vtable de la clase
 * indicada. */
void exec_instr_callsuper(ProcessVM *vm, const DecodedInstr &instr);
/** @brief THROW: lanza una excepcion buscando handler en la cadena de frames.
 */
void exec_instr_throw(ProcessVM *vm, const DecodedInstr &instr);
/** @brief RETHROW: relanza la excepcion activa (current_exception). */
void exec_instr_rethrow(ProcessVM *vm, const DecodedInstr &instr);
/** @brief GETCLASS: obtiene el puntero a ClassInfo del ObjectHeader del objeto.
 */
void exec_instr_getclass(ProcessVM *vm, const DecodedInstr &instr);
/** @brief INSTANCEOF: comprueba si el objeto es instancia de la clase indicada.
 */
void exec_instr_instanceof(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CHECKCAST: verifica el tipo; THROW si es incompatible, devuelve ptr
 * si ok. */
void exec_instr_checkcast(ProcessVM *vm, const DecodedInstr &instr);
/** @brief GETFIELD: obtiene puntero a FieldInfo por indice en la clase. */
void exec_instr_getfield(ProcessVM *vm, const DecodedInstr &instr);
/** @brief GETMETHOD: obtiene puntero a MethodInfo por indice en la clase. */
void exec_instr_getmethod(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FIELDCOUNT: devuelve el numero de campos de la clase. */
void exec_instr_fieldcount(ProcessVM *vm, const DecodedInstr &instr);
/** @brief METHODCOUNT: devuelve el numero de metodos de la clase. */
void exec_instr_methodcount(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CLASSNAME: devuelve puntero host al nombre de la clase. */
void exec_instr_classname(ProcessVM *vm, const DecodedInstr &instr);

// --- Reflexion y documentacion ---

/** @brief CLASSDOC: devuelve puntero al texto de documentacion de la clase. */
void exec_instr_classdoc(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CLASSATTRCOUNT: devuelve el numero de atributos de la clase. */
void exec_instr_classattrcount(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CLASSATTRKEY: devuelve puntero a la clave del atributo indicado. */
void exec_instr_classattrkey(ProcessVM *vm, const DecodedInstr &instr);
/** @brief CLASSATTRVAL: devuelve puntero al valor del atributo indicado. */
void exec_instr_classattrval(ProcessVM *vm, const DecodedInstr &instr);

/** @brief METHODNAME: devuelve puntero al nombre del metodo. */
void exec_instr_methodname(ProcessVM *vm, const DecodedInstr &instr);
/** @brief METHODDOC: devuelve puntero a la documentacion del metodo. */
void exec_instr_methoddoc(ProcessVM *vm, const DecodedInstr &instr);
/** @brief METHODDESC: devuelve puntero al descriptor de tipo del metodo. */
void exec_instr_methoddesc(ProcessVM *vm, const DecodedInstr &instr);
/** @brief METHODATTRCOUNT: devuelve el numero de atributos del metodo. */
void exec_instr_methodattrcount(ProcessVM *vm, const DecodedInstr &instr);
/** @brief METHODATTRKEY: devuelve puntero a la clave del atributo del metodo.
 */
void exec_instr_methodattrkey(ProcessVM *vm, const DecodedInstr &instr);
/** @brief METHODATTRVAL: devuelve puntero al valor del atributo del metodo. */
void exec_instr_methodattrval(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FIELDNAME: devuelve puntero al nombre del campo. */
void exec_instr_fieldname(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FIELDDOC: devuelve puntero a la documentacion del campo. */
void exec_instr_fielddoc(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FIELDATTRCOUNT: devuelve el numero de atributos del campo. */
void exec_instr_fieldattrcount(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FIELDATTRKEY: devuelve puntero a la clave del atributo del campo. */
void exec_instr_fieldattrkey(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FIELDATTRVAL: devuelve puntero al valor del atributo del campo. */
void exec_instr_fieldattrval(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Corutinas y fibras  (opcodes extendidos 0xEC-0xEF)
// -------------------------------------------------------------------------

/**
 * @brief YIELD: el proceso cede voluntariamente la CPU al scheduler.
 * @param vm    Proceso virtual que ejecuta YIELD.
 * @param instr Instruccion descodificada (sin operandos).
 */
void exec_instr_yield(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief RESUME: reactiva un proceso en BLOCKED/WAITING poniendolo en READY.
 * @param vm    Proceso virtual que ejecuta RESUME.
 * @param instr reg1 = PID del proceso a reactivar.
 */
void exec_instr_resume(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief SPAWN: crea un nuevo proceso virtual en la direccion del registro.
 *
 * El nuevo proceso arranca en PC=reg1; R0 del proceso llamante recibe el PID.
 *
 * @param vm    Proceso virtual que ejecuta SPAWN.
 * @param instr reg1 = direccion de inicio del nuevo proceso.
 */
void exec_instr_spawn(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief SPAWN_ON con hint de scheduler.
 *
 * Crea un nuevo proceso con PC=reg1 y lo asigna a un scheduler
 * concreto segun el valor (signed) en reg2:
 *   - reg2 == -1 (Here): mismo scheduler que el padre.
 *   - reg2 >=  0       : pinned al scheduler reg2 % num_schedulers.
 *
 * Sirve a `spawn here { ... }` y `spawn on(N) { ... }` en Vesta.
 * El resto (PC, RSP/RBP, copia de codigo, make_ready, retorno del PID
 * encoded en R0) es identico a SPAWN.
 *
 * @param vm    Proceso virtual que ejecuta SPAWN_ON.
 * @param instr reg1 = direccion de inicio; reg2 = scheduler hint signed.
 */
void exec_instr_spawn_on(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief LOADMOD r_path_addr, r_path_len -- carga dinamica de un .velb.
 *
 * Lee `path_len` bytes desde `vm_mem[path_addr]` (string UTF-8 con la ruta
 * al archivo .velb), abre el archivo, llama a `Loader::load_module_dynamic`
 * y deja el resultado en R0:
 *   - 0 si el archivo no existe o esta vacio (failure).
 *   - init_pc del modulo cargado (>0) en caso de exito.
 *
 * NO ejecuta automaticamente el modulo cargado: el caller (la builtin Vesta
 * @c loadmodule) debe usar `callvmr` con el init_pc devuelto para
 * invocar el main del nuevo modulo, cuyo prologo llama a `__module_init`
 * y registra las clases en el ClassRegistry global.
 *
 * @param vm    Proceso virtual que invoca la carga.
 * @param instr reg1 = registro con direccion VM al buffer de path,
 *              reg2 = registro con longitud en bytes del path.
 */
void exec_instr_loadmod(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Ejecuta UNLOADMOD r_path_addr, r_path_len: descarga modulo dinamico.
 *
 * Mismo formato que loadmod (path en VM mem).  Delega en
 * `Loader::unload_module_dynamic(path)`.  R0 = 1 si descargado, 0 si no
 * encontrado.
 */
void exec_instr_unloadmod(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief PANIC (0x5A): lanza un @c FatalError con kind=FATAL_USER_ABORT
 *        y message = bytes leidos de @c [vm_addr, len] desde la VM mem.
 *
 * Usado por el builtin Vesta @c panic("...") para abortar el proceso de
 * forma capturable.  Si hay try/catch FatalError activo lo captura;
 * si no, mata el proceso (no la VM).
 *
 * @param vm    Proceso virtual que ejecuta panic.
 * @param instr reg1 = registro con direccion VM del mensaje,
 *              reg2 = registro con longitud en bytes del mensaje.
 */
void exec_instr_panic(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief SETMETHDBG (0x5B): registra debug info para un MethodInfo*.
 *
 * params en VM mem (24 bytes):
 *   +0  [8]  method_ptr   (debe coincidir con r_method, redundancia)
 *   +8  [8]  file_addr    (VA del nombre del archivo)
 *   +16 [4]  file_len     (longitud en bytes)
 *   +20 [4]  start_line   (linea 1-based del inicio del metodo)
 *
 * Idempotente: sobreescribe entrada previa para el mismo MethodInfo.
 * Emitido por @c __module_init del frontend Vesta tras cada @c defmethod.
 */
void exec_instr_setmethdbg(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief SWAPCTX: intercambio de contexto cooperativo entre dos fibras.
 *
 * Guarda {PC, SP, BP, R0-R15} en el buffer VM de reg2 y carga desde reg1.
 * Layout del buffer (152 bytes):
 *   [0..7]    PC  (8 bytes)
 *   [8..15]   SP  (8 bytes)
 *   [16..23]  BP  (8 bytes)
 *   [24..151] R0..R15 (128 bytes)
 *
 * @param vm    Proceso virtual que ejecuta SWAPCTX.
 * @param instr reg1 = ctx destino, reg2 = ctx origen (VM addresses).
 */
void exec_instr_swapctx(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Closures GC y raw  (opcodes extendidos 0x20-0x23)
// -------------------------------------------------------------------------

/**
 * @brief MKCLOSURE: crea un ClosureObject gestionado por el GC.
 * @param vm    Proceso virtual que ejecuta MKCLOSURE.
 * @param instr reg1 = MethodInfo*, reg2 = env addr en memoria VM.
 */
void exec_instr_mkclosure(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief CALLCLOSURE: invoca un ClosureObject GC a traves de su MethodInfo.
 * @param vm    Proceso virtual que ejecuta CALLCLOSURE.
 * @param instr reg1 = GcHandle del ClosureObject.
 */
void exec_instr_callclosure(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MKRAWCLOSURE: crea un RawClosureObject sin GC (para FFI nativo).
 * @param vm    Proceso virtual que ejecuta MKRAWCLOSURE.
 * @param instr reg1 = fn_addr, reg2 = env_addr en memoria VM.
 */
void exec_instr_mkrawclosure(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief CALLRAWCLOSURE: invoca la funcion nativa de un RawClosureObject.
 * @param vm    Proceso virtual que ejecuta CALLRAWCLOSURE.
 * @param instr reg1 = puntero raw al RawClosureObject.
 */
void exec_instr_callrawclosure(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// TCO  (opcode extendido 0x24)
// -------------------------------------------------------------------------

/**
 * @brief TAILCALL: llamada en posicion de cola; reutiliza el frame actual.
 *
 * Restaura SP al frame_base del FrameHeader activo y salta a la funcion
 * destino sin empujar una nueva direccion de retorno.
 *
 * @param vm    Proceso virtual que ejecuta TAILCALL.
 * @param instr reg1 = direccion de la funcion destino.
 */
void exec_instr_tailcall(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Nullable  (opcodes extendidos 0x25-0x26)
// -------------------------------------------------------------------------

/**
 * @brief ISNULL: r_dst = (r_src == 0) ? 1 : 0. Sin excepcion.
 * @param vm    Proceso virtual que ejecuta ISNULL.
 * @param instr reg1 = destino, reg2 = valor a comprobar.
 */
void exec_instr_isnull(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief UNWRAP: r_dst = r_src si != 0; lanza NullPointerException si == 0.
 * @param vm    Proceso virtual que ejecuta UNWRAP.
 * @param instr reg1 = destino, reg2 = valor nullable.
 */
void exec_instr_unwrap(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Tabla de saltos y cambio de tipo  (opcodes extendidos 0x27-0x28)
// -------------------------------------------------------------------------

/**
 * @brief JUMPTABLE: salto O(1) por valor entero sobre una tabla de direcciones.
 *
 * Lee la direccion de la posicion r_val de la tabla apuntada por r_table y
 * salta a ella.  Si r_val >= count no salta (cae al siguiente opcode).
 *
 * @param vm    Proceso virtual que ejecuta JUMPTABLE.
 * @param instr mem_data.reg_base=r_val, mem_data.reg_index=r_table,
 * mem_data.scale=count.
 */
void exec_instr_jumptable(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief TYPESWITCH: despacho por tipo de objeto (O(n) sobre n entradas de la
 * tabla).
 *
 * Obtiene ClassInfo del ObjectHeader del objeto en r_obj.  Recorre la tabla de
 * pares [ClassInfo*, target_addr] buscando la clase exacta.  Si encuentra
 * coincidencia salta a target_addr; si no, cae al siguiente opcode.
 *
 * @param vm    Proceso virtual que ejecuta TYPESWITCH.
 * @param instr mem_data.reg_base=r_obj, mem_data.reg_index=r_table,
 * mem_data.scale=count.
 */
void exec_instr_typeswitch(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Async/await nativo  (opcodes extendidos 0x29-0x2C)
// -------------------------------------------------------------------------

/**
 * @brief FUTURE: crea un FutureObject gestionado por el GC en estado PENDING.
 *
 * Aloca mediante gc_heap.alloc y devuelve el GcHandle en R0.
 * El handle debe pasarse a FULFILL o REJECT para resolverlo, y a AWAIT para
 * esperar.
 *
 * @param vm    Proceso virtual que ejecuta FUTURE.
 * @param instr Sin operandos (FIXED_2).
 */
void exec_instr_future(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief AWAIT: suspende el proceso hasta que el FutureObject sea resuelto.
 *
 * Si el future ya esta RESOLVED o REJECTED: escribe result en R0 y continua.
 * Si sigue PENDING: registra el PID del proceso en waiter_pid y bloquea
 * (blocking=true) sin avanzar el PC.  Al ser despertado por FULFILL/REJECT
 * re-ejecuta AWAIT, que ahora encuentra el estado resuelto y retorna el valor.
 *
 * @param vm    Proceso virtual que ejecuta AWAIT.
 * @param instr reg1 = GcHandle del FutureObject.
 */
void exec_instr_await(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FULFILL: resuelve un FutureObject con un valor (RESOLVED).
 *
 * Escribe result=r_val y state=RESOLVED en el FutureObject.
 * Si waiter_pid != 0 llama a make_ready(waiter_pid) para despertar al proceso.
 *
 * @param vm    Proceso virtual que ejecuta FULFILL.
 * @param instr reg1 = GcHandle del FutureObject, reg2 = valor de resolucion.
 */
void exec_instr_fulfill(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief REJECT: rechaza un FutureObject con un codigo de error (REJECTED).
 *
 * Escribe result=r_err y state=REJECTED en el FutureObject.
 * Si waiter_pid != 0 llama a make_ready(waiter_pid) para despertar al proceso.
 *
 * @param vm    Proceso virtual que ejecuta REJECT.
 * @param instr reg1 = GcHandle del FutureObject, reg2 = codigo de error.
 */
void exec_instr_reject(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Aritmetica de puntero de pila  (opcodes extendidos 0x2E-0x2F)
// -------------------------------------------------------------------------

/**
 * @brief SUBSP: resta un inmediato al puntero de pila RSP o RBP.
 *
 * Tipicamente usado para reservar espacio de variables locales al inicio
 * de una funcion sin usar la instruccion generica SUB.
 *
 * @param vm    Proceso virtual que ejecuta SUBSP.
 * @param instr inmmed_data.reg=0 (RSP) o 1 (RBP); inmmed_data.inmmed = delta.
 */
void exec_instr_subsp(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief ADDSP: suma un inmediato al puntero de pila RSP o RBP.
 *
 * Tipicamente usado para liberar el espacio de variables locales al final
 * de una funcion.
 *
 * @param vm    Proceso virtual que ejecuta ADDSP.
 * @param instr inmmed_data.reg=0 (RSP) o 1 (RBP); inmmed_data.inmmed = delta.
 */
void exec_instr_addsp(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Referencias debiles  (opcodes extendidos 0x30, 0x32, 0x34)
// -------------------------------------------------------------------------

/**
 * @brief WEAKREF: crea una referencia debil opaca a un objeto GC.
 *
 * Registra el GcHandle en la tabla de referencias debiles del GcHeap.
 * El GC anula automaticamente la referencia si el objeto es recolectado.
 * Devuelve el indice opaco (uint32_t) en R0.
 *
 * @param vm    Proceso virtual que ejecuta WEAKREF.
 * @param instr reg1 = GcHandle del objeto.
 */
void exec_instr_weakref(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief DEREF_WEAK: desreferencia un indice de weak ref.
 *
 * Si el objeto sigue vivo: r_dst = GcHandle original.
 * Si el objeto fue recolectado: r_dst = GC_NULL_HANDLE (0xFFFFFFFF).
 *
 * @param vm    Proceso virtual que ejecuta DEREF_WEAK.
 * @param instr reg1 = registro destino, reg2 = indice opaco de la weak ref.
 */
void exec_instr_deref_weak(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FREE_WEAK: libera una entrada de la tabla de weak refs.
 *
 * Debe llamarse cuando ya no se necesita la referencia debil para no
 * acumular entradas muertas en la tabla.
 *
 * @param vm    Proceso virtual que ejecuta FREE_WEAK.
 * @param instr reg1 = indice opaco de la weak ref a liberar.
 */
void exec_instr_free_weak(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Monitor / sincronizacion  (opcodes extendidos 0x35-0x39)
// -------------------------------------------------------------------------

/**
 * @brief MONENTER: adquiere el monitor reentrante del objeto GC.
 *
 * Si el monitor esta libre o ya lo posee el proceso actual, lo adquiere e
 * incrementa lock_depth en ObjectHeader.  Si esta ocupado por otro proceso,
 * el proceso actual entra en la cola de espera (blocking=true) y re-ejecuta
 * MONENTER al ser despertado por MONEXIT.
 *
 * @param vm    Proceso virtual que ejecuta MONENTER.
 * @param instr reg1 = GcHandle del objeto cuyo monitor se quiere adquirir.
 */
void exec_instr_monenter(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MONEXIT: libera el monitor del objeto GC.
 *
 * Decrementa lock_depth.  Cuando llega a 0, el monitor queda libre; si hay
 * procesos en la cola de espera del GcHeap, despierta al primero (make_ready).
 *
 * @param vm    Proceso virtual que ejecuta MONEXIT.
 * @param instr reg1 = GcHandle del objeto cuyo monitor se libera.
 */
void exec_instr_monexit(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MONWAIT: libera completamente el monitor y suspende el proceso.
 *
 * Libera el monitor (lock_depth -> 0) y registra el PID en la cola de espera
 * del monitor.  El proceso queda bloqueado hasta que MONNOTI o MONNOTA lo
 * despierte.  Tras despertar debe llamar MONENTER para readquirir el lock.
 *
 * @param vm    Proceso virtual que ejecuta MONWAIT.
 * @param instr reg1 = GcHandle del objeto.
 */
void exec_instr_monwait(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MONNOTI: despierta un proceso de la cola de espera del monitor.
 *
 * Extrae el primer PID de monitor_waiters_ y llama make_ready.  No transfiere
 * la propiedad del monitor; el proceso despertado debe llamar MONENTER de
 * nuevo.
 *
 * @param vm    Proceso virtual que ejecuta MONNOTI.
 * @param instr reg1 = GcHandle del objeto.
 */
void exec_instr_monnoti(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MONNOTA: despierta todos los procesos de la cola de espera del
 * monitor.
 *
 * Extrae todos los PIDs de monitor_waiters_ y llama make_ready en cada uno.
 *
 * @param vm    Proceso virtual que ejecuta MONNOTA.
 * @param instr reg1 = GcHandle del objeto.
 */
void exec_instr_monnota(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Genericos en tiempo de ejecucion  (opcode extendido 0x3A)
// -------------------------------------------------------------------------

/**
 * @brief SPECIALIZE: instancia en tiempo de ejecucion una clase generica.
 *
 * Codificacion FIXED_4: byte2 = (r_dst<<4)|r_class, byte3 =
 * (r_types<<4)|r_count. r_class = registro con puntero a ClassInfo generica
 * (CLASS_FLAG_GENERIC). r_types = registro con puntero a array de ClassInfo*
 * (tipos concretos). r_count = nibble bajo de byte3; numero de parametros de
 * tipo (1-15). r_dst   = nibble alto de byte2; registro destino para el
 * ClassInfo* result.
 *
 * Si la especializacion ya existe en la cache del Loader la retorna
 * directamente. Si no, clona el ClassInfo original sustituyendo los type_params
 * por los concretos.
 *
 * @param vm    Proceso virtual que ejecuta SPECIALIZE.
 * @param instr byte2=(r_dst<<4)|r_class, byte3=(r_types<<4)|r_count.
 */
void exec_instr_specialize(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Meta-programacion OOP (opcodes extendidos 0xC9-0xCC)
//
// Permiten definir clases en runtime via @c ClassRegistry.  El bytecode
// construye structs DefXxxParams en memoria VM y las pasa por puntero;
// el ejecutor las lee y delega al @c class_registry() del Loader.
// -------------------------------------------------------------------------

/**
 * @brief Crea una clase nueva con el nombre indicado en los parametros.
 *        Devuelve ClassInfo* en r_dst (0 si fallo).
 */
void exec_instr_defclass(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Anade un campo a la clase en r_dst.  R0 recibe 1/0 (ok/fail).
 */
void exec_instr_deffield(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Anade un metodo a la clase en r_dst.  R0 recibe el indice
 *        del metodo en la vtable o UINT32_MAX si fallo.
 */
void exec_instr_defmethod(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Busca una clase por nombre.  Devuelve ClassInfo* en r_dst
 *        (0 si no existe).
 */
void exec_instr_findclass(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Busca un metodo por nombre dentro de una clase via su tabla
 *        hash (O(1)).  Devuelve MethodInfo* en r_dst (0 si no existe).
 *        Pareja con @c addadvice para registrar aspectos en runtime.
 */
void exec_instr_findmethod(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Busca un campo por nombre dentro de una clase via su tabla
 *        hash (O(1)).  Devuelve FieldInfo* en r_dst (0 si no existe).
 *        Reusa el layout @c FindMethodParamsLayout para los params.
 */
void exec_instr_findfield(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Registra un advice (BEFORE/AFTER/AROUND) sobre un metodo
 *        target.  R0 = 1 ok / 0 fallo (firmas incompatibles, etc).
 *        El kind viaja en el byte3 de la instruccion.
 */
void exec_instr_addadvice(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Lee un static field (i64) de una clase (opcode extended 0x60).
 *
 * Operandos descodificados (data_instruction.static_data):
 *   r0     = registro destino (recibe el valor i64 leido)
 *   r1     = registro con ClassInfo* (host pointer al descriptor)
 *   offset = byte offset dentro de @c ClassInfo::static_data
 *
 * Lee 8 bytes desde @c cls->static_data + offset (memoria HOST).  El
 * frontend Vesta hace truncate post-load para tipos mas pequenos
 * (i8/i16/i32) usando el mismo patron que para fields de instancia.
 *
 * Si @c cls es nullptr o @c cls->static_data es nullptr (la clase no
 * declara static fields), lanza @c FATAL_NULL_POINTER capturable via
 * @c try { } catch (FatalError) { }.
 */
void exec_instr_getstatic(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Carga una libreria nativa por nombre (FFI runtime, opcode 0x62).
 *
 * Operandos (data_instruction.mem_data):
 *   reg_base   = r_dst             (recibe el handle host como i64)
 *   reg_index  = r_path_addr        (registro con direccion VM del nombre)
 *   reg_final  = r_path_len         (registro con longitud del nombre, bytes)
 *
 * Lee los bytes del path desde @c vm_mem y delega a
 * @c FFI::load_native_module (LoadLibraryA / dlopen).  Devuelve el handle
 * cacheado como puntero host (uint64_t) en r_dst.  Si la carga falla,
 * lanza @c FATAL_NULL_POINTER capturable.  El handle es valido durante
 * toda la sesion (cache global del FFI).
 */
void exec_instr_dlopen(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Resuelve un simbolo de una libreria nativa cargada (opcode 0x63).
 *
 * Operandos (data_instruction.mem_data):
 *   reg_base   = r_dst        (recibe la direccion del simbolo, i64)
 *   reg_index  = r_handle     (registro con handle de @c dlopen)
 *   reg_final  = r_name_addr  (registro con direccion VM del nombre)
 *   scale      = r_name_len   (registro con longitud del nombre)
 *
 * Lee los bytes del nombre desde @c vm_mem y delega a
 * @c GetProcAddress / @c dlsym.  Devuelve la direccion del simbolo como
 * @c uint64_t en r_dst.  Si no se encuentra, lanza @c FATAL_NULL_POINTER
 * capturable.
 */
void exec_instr_dlsym(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Invoca una funcion nativa por puntero (FFI dinamico, opcode 0x64).
 *
 * Operandos (data_instruction.reg_data):
 *   reg1 = r_fn  (registro con direccion del simbolo, ya resuelto via dlsym)
 *
 * Convencion espejo de CALLN estatico: argc en R15 (clamp a [0,12]),
 * args en R01..R12, retorno en R00.  Reusa exactamente
 * @c invoke_native_unchecked para mantener la misma calling convention.
 * Sin proteccion SEH/EH: si necesitas captura de crashes nativos, usa
 * el wrapper estatico CALLN o envuelve la llamada en @c try/@c catch
 * @c FatalError desde Vesta.
 */
void exec_instr_callni(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Aloca un bloque GC y deposita host_ptr al payload en r_dst (0x65).
 *
 * Operandos:
 *   reg1 = r_dst  (registro destino para host_ptr)
 *   reg2 = r_size (registro con tamano en bytes)
 *
 * Equivalente fusionado a:
 *   gcalloc r_size       ; R0 = handle
 *   gcderef cur0, r0     ; cur0 = host_ptr
 *   xchg cur0, r_dst     ; r_dst = host_ptr
 * pero en una sola instruccion VM.  3x speedup en creacion de envs
 * para closures que escapan (gap O del roadmap).  Si OOM, lanza
 * FATAL_OUT_OF_MEMORY capturable via try/catch.
 */
void exec_instr_gcallocp(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Spawn que copia R1..R[R15] del padre al child (0x66).
 *
 * Operandos:
 *   reg1 = r_pc   (registro con direccion de inicio del child)
 *   R15 (implicito) = argc (numero de args 0..12)
 *   R1..R[argc] (implicitos) = args
 *
 * Antes de make_ready, copia los regs R1..R[argc] del padre a los
 * mismos slots del child, asi el child ve los args directamente sin
 * necesidad de msgrecv + deserializar buffer.  Calling convention
 * identica a CALLVM.  Devuelve PID encoded del child en R0 del padre.
 * Mismo set up de PC, RSP/RBP, copy_executables_to que @c spawn.
 */
void exec_instr_spawnargs(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Fulfill + hlt fusionados (0x67).
 *
 * Operandos:
 *   reg1 = r_fut   (registro con handle del Future)
 *   reg2 = r_value (registro con valor a depositar)
 *
 * Equivalente fusionado a:
 *   fulfill r_fut, r_value   ; resolver future + wake waiter
 *   hlt                       ; terminar proceso
 * Usado por el helper sintetico de @Async para que cada `return X`
 * del body se reduzca a 1 instruccion VM en lugar de 2.
 */
void exec_instr_fulfillhlt(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Cmp signed + jcc fusionados (0x68).
 *
 * Equivalente atomic a la secuencia:
 *   cmps r_a, r_b           ; setea ZF/SF/CF/OF segun a-b signed
 *   jmp.cond target         ; salta si la condicion se cumple
 * en una sola instruccion VM.  Reduce 2 instr -> 1 por comparacion
 * condicional en hot loops.
 *
 * Operandos descodificados:
 *   static_data.r0     = r_a
 *   static_data.r1     = r_b
 *   static_data._pad   = cond_byte (0x00..0x0D, mismo set que jmp.j*)
 *   static_data.offset = target u32 (direccion absoluta)
 *
 * Si la condicion se cumple, escribe @c rip = offset y marca did_jump.
 */
void exec_instr_cmpjmp(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Cmp unsigned + jcc fusionados (0x69).
 *
 * Identico a @c exec_instr_cmpjmp pero hace comparacion unsigned (cmpu).
 */
void exec_instr_cmpjmpu(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Decremento + branch-if-not-zero (0x6A).
 *
 * Equivalente atomic a:
 *   subs r_counter, 1
 *   jmp.jne target           ; salta si r_counter != 0
 * en una sola instruccion VM.  Reduce 2-3 instr -> 1 por iteracion en
 * loops contadores estilo `for (i = N; i > 0; i--)`.
 *
 * Operandos descodificados:
 *   static_data.r0     = r_counter
 *   static_data.offset = target u32
 */
void exec_instr_decjnz(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Empuja a la pila N registros segun el bitmask (opcode extended 0x6B).
 *
 * Cada bit puesto en @c data_instruction.mask_data.mask representa un
 * registro general (bit r = r0..r15).  Itera bits ascendentes via TZCNT,
 * decrementa RSP por (popcount(mask)*8) en una sola escritura, y empuja
 * cada registro a su slot.  Equivalente a una secuencia de N push, pero
 * en 1 instr VM con aritmetica de pila amortizada.
 */
void exec_instr_fastpush(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Desempila N registros del bitmask en orden simetrico a fastpush.
 *
 * Restaura cada registro marcado en el mask leyendo de slots descendentes
 * y luego incrementa RSP por (popcount(mask)*8).  Para un mismo mask,
 * revierte exactamente el efecto de @c fastpush.
 */
void exec_instr_fastpop(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Escribe un static field (i64) en una clase (opcode extended 0x61).
 *
 * Operandos descodificados (data_instruction.static_data):
 *   r0     = registro con ClassInfo* (host pointer al descriptor)
 *   r1     = registro con valor a escribir (i64)
 *   offset = byte offset dentro de @c ClassInfo::static_data
 *
 * Escribe 8 bytes a @c cls->static_data + offset (memoria HOST).  El
 * frontend Vesta hace truncate / sign-extend pre-store para tipos mas
 * pequenos cuando el field declarado es signed.
 *
 * Mismo manejo de errores que @c getstatic: @c FATAL_NULL_POINTER si
 * @c cls o @c static_data son nullptr.
 */
void exec_instr_setstatic(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief mld r_dst, [base +/- index*scale +/- disp] : load universal (1
 * despacho).
 * @brief mst [base +/- index*scale +/- disp], r_src : store universal.
 *
 * Resuelven la codificacion que faltaba (rbp/rsp como base, que el SIB no
 * admite): el acceso a slots de derrame (rbp-relative) pasa de 3 instrucciones
 * a 1.  base in {r0-r15, rbp(16), rsp(17)}, index*scale (x1..64), disp int16,
 * ancho 1/2/4/8 (GP), host/vm.  Encoding FIXED_8 (decode_instr_mem_full).
 */
void exec_instr_mld(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_mst(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Punto flotante escalar y vectorial  (opcodes extendidos 0xF0-0xFC)
//
// Codificacion del campo mode (2 bits en ctrl byte bits[7:6]):
//   0 = escalar f64 (F0-F15, 64 bits)
//   1 = XMM packed  (128 bits)
//   2 = YMM packed  (256 bits)
//   3 = ZMM packed  (512 bits)
// Tipo de elemento en _signed_instruct (bit[5]):
//   0 = double (f64 por lane)
//   1 = float  (f32 por lane)
// -------------------------------------------------------------------------

/** @brief FMOV: copia un registro ZMM a otro respetando el zeroing de aliasing.
 */
void exec_instr_fmov(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FADD: suma flotante (escalar o packed); reg1 += reg2. */
void exec_instr_fadd(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @defgroup fbin_isa Binarias de coma flotante, una variante por ISA
 * @brief El manejador COMPLETO compilado para un nivel de ISA concreto.
 *
 * Cada una lleva `[[gnu::target(...)]]`, con lo que el cuerpo SIMD se mete en
 * linea dentro de ella y no queda ninguna llamada.  Cual usar se decide UNA
 * vez -- con @ref float_isa_level, al construir la tabla de despacho del
 * interprete --, no en cada instruccion.  Ver la explicacion larga junto a
 * `DEF_FBIN_ISA` en `src/runtime/exec_instruction_float.cpp`.
 * @{
 */
/* Escalares: no dependen del nivel de ISA. */
void exec_instr_fadd_s(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_fsub_s(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_fmul_s(ProcessVM *vm, const DecodedInstr &instr);
void exec_instr_fdiv_s(ProcessVM *vm, const DecodedInstr &instr);

/* Empaquetadas: por nivel de ISA (sse2/avx/avx512) Y por ancho (x=128,
 * y=256, z=512 bits).  Fijar tambien el ancho es lo que convierte el bucle
 * SIMD en operaciones rectas. */
#define VESTA_DECL_FBIN_ISA(suffix)                                            \
    void exec_instr_fadd_##suffix##_x(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fadd_##suffix##_y(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fadd_##suffix##_z(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fsub_##suffix##_x(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fsub_##suffix##_y(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fsub_##suffix##_z(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fmul_##suffix##_x(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fmul_##suffix##_y(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fmul_##suffix##_z(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fdiv_##suffix##_x(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fdiv_##suffix##_y(ProcessVM *, const DecodedInstr &);      \
    void exec_instr_fdiv_##suffix##_z(ProcessVM *, const DecodedInstr &);

VESTA_DECL_FBIN_ISA(sse2)
VESTA_DECL_FBIN_ISA(avx)
VESTA_DECL_FBIN_ISA(avx512)
#undef VESTA_DECL_FBIN_ISA

/// @brief Nivel de ISA de coma flotante de esta maquina: 0=SSE2, 1=AVX,
///        2=AVX-512.  Se detecta una vez y se cachea.
int float_isa_level();

/**
 * @brief Manejador ya especializado para la ISA de esta maquina, si lo hay.
 *
 * Se llama al DESCODIFICAR, y lo que devuelve se guarda en
 * @c DecodedInstr::exec_cached.  Asi la especializacion la aprovechan TODOS
 * los consumidores -- el camino lento del interprete y tambien `exec_bundle`,
 * que no pasa por la tabla de rutas rapidas -- sin que ninguno tenga que
 * saber que existe.
 *
 * Se llama DESPUES de descodificar, no antes: hace falta el `mode`, que es de
 * donde sale el ancho, y ese lo rellena el decodificador.
 *
 * @param opcode2 Opcode de la tabla extendida.
 * @param mode    Ancho del operando (0=escalar, 1=128, 2=256, 3=512 bits).
 * @return El manejador especializado, o @c nullptr si esa instruccion no tiene
 *         variantes (y entonces se deja el generico).
 */
void (*float_exec_specialized(uint8_t opcode2, uint8_t mode))(
    ProcessVM *, const DecodedInstr &);
/** @} */

/** @brief FSUB: resta flotante; reg1 -= reg2. */
void exec_instr_fsub(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FMUL: multiplicacion flotante; reg1 *= reg2. */
void exec_instr_fmul(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FDIV: division flotante; reg1 /= reg2. */
void exec_instr_fdiv(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FCMP: comparacion flotante; establece ZF (igual), SF (menor), CF
 * (NaN).
 * @param vm    Proceso virtual.
 * @param instr reg1 comparado con reg2 (escalar f64/f32 o primera lane packed).
 */
void exec_instr_fcmp(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FSQRT: raiz cuadrada flotante; reg1 = sqrt(reg2). */
void exec_instr_fsqrt(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FABS: valor absoluto flotante; reg1 = |reg2|. */
void exec_instr_fabs(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FNEG: negacion flotante; reg1 = -reg2. */
void exec_instr_fneg(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FCVT: conversion entre registro GP y registro ZMM.
 *
 * direction == 0: GP(reg1) -> ZMM(reg2)  (int a float/double)
 * direction == 1: ZMM(reg1) -> GP(reg2)  (float/double a int, truncado)
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = GP, reg2 = ZMM; direction = sentido de conversion.
 */
void exec_instr_fcvt(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FEXTEND: convierte f32 -> f64 dentro del banco ZMM.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = ZMM destino, reg2 = ZMM fuente.
 */
void exec_instr_fextend(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FNARROW: convierte f64 -> f32 dentro del banco ZMM.
 *
 * @param vm    Proceso virtual.
 * @param instr reg1 = ZMM destino, reg2 = ZMM fuente.
 */
void exec_instr_fnarrow(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FMADD escalar fusionado (0x5F): fd = fma(fa, fb, fd) -- un solo
 *  redondeo (C std::fma).  Convention B: byte2=(fa<<4)|fd, byte3=(fb<<4)|isf32.
 *  Lo emite la auto-vectorizacion (VEC_FMA) para que el interprete coincida
 *  bit-a-bit con VFMADD231PD del JIT (que tambien fusiona con 1 redondeo). */
void exec_instr_fmadd(ProcessVM *vm, const DecodedInstr &instr);

/** @brief FMIN escalar (0x80): reg1 = fmin(reg1, reg2). */
void exec_instr_fmin(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FMAX escalar (0x81): reg1 = fmax(reg1, reg2). */
void exec_instr_fmax(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FFLOOR escalar (0x82): reg1 = floor(reg2). */
void exec_instr_ffloor(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FCEIL escalar (0x83): reg1 = ceil(reg2). */
void exec_instr_fceil(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FROUND escalar (0x84): reg1 = round(reg2). */
void exec_instr_fround(ProcessVM *vm, const DecodedInstr &instr);
/** @brief FTRUNC escalar (0x85): reg1 = trunc(reg2). */
void exec_instr_ftrunc(ProcessVM *vm, const DecodedInstr &instr);
/** @brief BITG2Z (0x86): bitcast GP reg -> ZMM reg (sin memoria). */
void exec_instr_bitg2z(ProcessVM *vm, const DecodedInstr &instr);
/** @brief BITZ2G (0x87): bitcast ZMM reg -> GP reg (sin memoria). */
void exec_instr_bitz2g(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FMOVI: carga un inmediato IEEE 754 en un registro ZMM.
 * @param vm    Proceso virtual.
 * @param instr inmmed_data.reg = ZMM destino; inmmed_data.inmmed = bits f64.
 */
void exec_instr_fmovi(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FLOAD: carga datos flotantes desde memoria VM a un registro ZMM.
 * @param vm    Proceso virtual.
 * @param instr reg1 = ZMM destino, reg2 = GP con direccion VM; mode = ancho.
 */
void exec_instr_fload(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief FSTORE: almacena datos flotantes desde un registro ZMM a memoria VM.
 * @param vm    Proceso virtual.
 * @param instr reg1 = GP con direccion VM, reg2 = ZMM fuente; mode = ancho.
 */
void exec_instr_fstore(ProcessVM *vm, const DecodedInstr &instr);

// -------------------------------------------------------------------------
// Instrucciones distribuidas  (opcodes extendidos 0x3B-0x3E)
// -------------------------------------------------------------------------

/**
 * @brief RSPAWN: crea un proceso en un nodo remoto.
 * @param vm    Proceso virtual que ejecuta RSPAWN.
 * @param instr reg1 = r_fn (dir bytecode), reg2 = r_node (indice NodeRegistry).
 */
void exec_instr_rspawn(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MSGSEND: envia un mensaje a otro proceso (local o remoto).
 * @param vm    Proceso virtual emisor.
 * @param instr mem_data: reg_base=r_pid, reg_index=r_addr, reg_final=r_len.
 */
void exec_instr_msgsend(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MSGRECV: extrae el primer mensaje del buzon; bloquea si vacio.
 * @param vm    Proceso virtual receptor.
 * @param instr reg1 = r_buf (dir VM destino), reg2 = r_max (tamano maximo).
 */
void exec_instr_msgrecv(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief MEMSYNC: sincroniza una region de memoria con un nodo remoto.
 * @param vm    Proceso virtual que ejecuta MEMSYNC.
 * @param instr reg1 = r_params (dir de MemsyncParams en VM memory).
 */
void exec_instr_memsync(ProcessVM *vm, const DecodedInstr &instr);

/**
 * @brief Descodifica FMOVI: ctrl_byte con ZMM index empaquetado + imm64.
 *
 * Formato (11 bytes): [0x00][0xFA][ctrl][imm64].
 * ctrl: bits[7:6]=ancho, bit[5]=is_f32, bits[3:0]=zmm_idx.
 *
 * @param vm    Proceso virtual.
 * @param instr Estructura que se rellena con el ZMM index y el inmediato.
 */
void decode_instr_fmowi(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Instala el runner de finalizadores GC en el GcHeap del proceso.
 *
 * El runner ejecuta el deleter/dtor customizable de un objeto GC colectado que
 * poseia un recurso interno (unique/shared) y escapo su scope.  Reentra al
 * interprete (bytecode, portable) para correr el mismo deleter que el cleanup
 * determinista de scope.  Lo llama el ctor de ProcessVM.
 */
void install_gc_finalizer_runner(ProcessVM *vm);

} // namespace runtime

#endif // EXEC_INSTRUCTION_H
