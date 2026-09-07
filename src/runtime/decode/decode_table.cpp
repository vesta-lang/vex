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

/**                                                                            \
 * @file decode_table.cpp                                                      \
 * @brief Definicion de las tablas de decodificacion de instrucciones de       \
 * VestaVM.                                                                    \
 *                                                                             \
 * Contiene las tablas estaticas de despacho:                                  \
 *   - @c decode_table_primary : instrucciones de un byte (0x01-0xFF)          \
 *   - @c decode_table_extended: instrucciones de dos bytes con prefijo 0x00   \
 *                                                                             \
 * AL ANADIR O CAMBIAR UNA INSTRUCCION, REGENERAR LA BASE DE DATOS DE LA VM    \
 * ---------------------------------------------------------------------      \
 * `include/runtime/instr_db_vm.h` y `src/runtime/instr_db_vm_gen.cpp` guardan \
 * lo que cada opcode TOCA sin nombrarlo en un operando --banderas, pila,      \
 * marco, contador de programa-- y lo que cuesta.  De ahi sale la respuesta a  \
 * "son estas dos instrucciones independientes?", que es lo que permite        \
 * reordenar al formar un paquete, fusionar y vectorizar.                      \
 *                                                                             \
 * Esa tabla se GENERA de lo que se deriva del codigo maquina de los           \
 * manejadores, no la escribe nadie:                                           \
 *                                                                             \
 *     test_efectos_opcodes --json > efectos.json                              \
 *     test_coste_opcodes                    # escribe coste_opcodes.json      \
 *     python tools/import/gen_instr_db_vm.py efectos.json coste_opcodes.json  \
 *                                                                             \
 * Hay que regenerarla al anadir una instruccion aqui, al quitarla, y tambien  \
 * cuando CAMBIE lo que hace su manejador aunque el opcode siga igual.  Una    \
 * tabla que diga que un opcode no toca las banderas cuando ya las toca no da  \
 * un error: hace que se reordenen dos instrucciones que si dependian, y eso   \
 * da OTRO RESULTADO.                                                          \
 *                                                                             \
 * No hace falta acordarse: `test_efectos_opcodes` la comprueba en cada        \
 * ejecucion contra lo derivado y sale con codigo 1 diciendo QUE instruccion   \
 * difiere.                                                                    \
 */                                                                            \
#include "runtime/decode_table.h"

#include "emmit/emmit_decl.h"
#include "runtime/exec_instruction.h"

namespace runtime {
/**
 * @brief Tabla de opcodes primarios del bytecode VestaVM.
 *
 * Contiene 256 entradas (0x00-0xFF).  Cada instruccion con primer byte
 * distinto de 0x00 se despacha directamente desde esta tabla.  La entrada
 * 0x00 (EXT_OPCODE) no se ejecuta directamente; cuando el primer byte es
 * 0x00 se selecciona decode_table_extended usando el segundo byte como indice.
 *
 * Cada entrada es un InstrFormat con: nombre mnemotecnico, modo de
 * direccionamiento, modo de tamano, puntero al ejecutor y puntero al
 * decodificador.  Las entradas con exec/decode == nullptr son ranuras
 * reservadas o no implementadas.
 */
InstrFormat decode_table_primary[0X100] = {
    /* 0x00 */ {// aunque el 0x00 no se usa, lo definimos por seguridad.
                "EXT_OPCODE", Assembly::Bytecode::AddressingMode::NONE,
                Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x01 */
    {// vminfo
     "vminfo", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, nullptr, nullptr},

    /* 0x02 */
    {// vminfomanager
     "vminfomanager", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, nullptr, nullptr},

    /* 0x03 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x04 */
    {// inc / dec
     "inc / dec", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_inc_dec_reg,
     decode_instr_one_op_reg},

    /* 0x05 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x06 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x07 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x08 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x09 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x0A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x0B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x0C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x0D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x0E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x0F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x10 */
    {// callvm addr: push ret_addr; jmp addr
     "callvm", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_10, exec_instr_callvm,
     decode_instr_jump},

    /* 0x11 */
    {// jmp/jcc: [0x11][cond][8-byte addr]; cond=0x0F => incondicional
     "jmp", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_10, exec_instr_jmp,
     decode_instr_jump},

    /* 0x12 */
    {// push
     "push", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_push,
     decode_instr_push_pop},

    /* 0x13 */
    {// pop
     "pop", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_pop,
     decode_instr_push_pop},

    /* 0x14 */
    {//
     "xchg", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_xchg,
     decode_instr_xchg},

    /* 0x15 */
    {// jmpr reg: salta a la direccion almacenada en un registro
     "jmpr", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_jmpr,
     decode_instr_push_pop},

    /* 0x16 */
    {// callvmr reg: callvm con direccion en registro
     "callvmr", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_callvmr,
     decode_instr_push_pop},

    /* 0x17 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x18 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x19 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x1A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x1B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x1C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x1D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x1E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x1F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x20 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x21 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x22 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x23 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x24 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x25 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x26 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x27 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x28 */
    {// enter frame_size: push rbp; mov rbp,rsp; sub rsp,frame_size
     "enter", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_10, exec_instr_enter,
     decode_instr_jump},

    /* 0x29 */
    {// leave: mov rsp,rbp; pop rbp
     "leave", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, exec_instr_leave,
     decode_instr_no_operands},

    /* 0x2A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x2B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x2C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x2D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x2E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x2F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x30 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x31 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x32 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x33 */
    {// nop1
     "nop1", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x34 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x35 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x36 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x37 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x38 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x39 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x3A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x3B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x3C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x3D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x3E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x3F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x40 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x41 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x42 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x43 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x44 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x45 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x46 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x47 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x48 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x49 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x4A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x4B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x4C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x4D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x4E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x4F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x50 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x51 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x52 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x53 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x54 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x55 */
    {//
     "callnr", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x56 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x57 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x58 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x59 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x5A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x5B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x5C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x5D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x5E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x5F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* Formas con memoria de la logica y los desplazamientos, 0x60-0x65.
     *
     * En la tabla PRIMARIA a proposito, y no con sus hermanas de la extendida.
     * Dos razones, las dos medibles:
     *
     *   - TAMANO.  Aqui la instruccion mide 4 bytes (`[op][ctrl][regs][index]`)
     *     y alli 6 (`[0x00][op2][ctrl][regs][index][pad]`).  La icache se
     *     indexa por pc EN BYTES, asi que un tercio menos de bytes es un tercio
     *     mas de alcance para el mismo numero de conjuntos.
     *   - SITIO.  La extendida tiene 221 ranuras cogidas y 35 libres; la
     *     primaria, 11 y 240.  Meter aqui lo que quepa deja la extendida para
     *     lo que de verdad no quepa.
     *
     * El descodificador es EL MISMO (`decode_instr_sib`): mira
     * `is_not_extended` y ajusta de donde arranca el bloque de campos. */
    /* 0x60 */
    {// and reg, [sib]  ||  and [sib], reg
     "and", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_and_sib,
     decode_instr_sib},

    /* 0x61 */
    {// or reg, [sib]  ||  or [sib], reg
     "or", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_or_sib,
     decode_instr_sib},

    /* 0x62 */
    {// xor reg, [sib]  ||  xor [sib], reg
     "xor", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_xor_sib,
     decode_instr_sib},

    /* 0x63 */
    {// shl reg, [sib]  ||  shl [sib], reg
     "shl", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_shl_sib,
     decode_instr_sib},

    /* 0x64 */
    {// shr reg, [sib]  ||  shr [sib], reg
     "shr", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_shr_sib,
     decode_instr_sib},

    /* 0x65 */
    {// sar reg, [sib]  ||  sar [sib], reg
     "sar", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_sar_sib,

     decode_instr_sib},
    /* 0x66 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x67 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x68 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x69 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x6A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x6B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x6C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x6D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x6E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x6F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x70 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x71 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x72 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x73 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x74 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x75 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x76 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x77 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x78 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x79 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x7A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x7B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x7C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x7D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x7E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x7F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x80 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x81 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x82 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x83 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x84 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x85 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x86 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x87 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x88 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x89 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x90 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x91 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x92 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x93 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x94 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x95 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x96 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x97 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x98 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x99 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA0 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA1 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA2 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA3 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA4 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA5 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA6 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA7 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA8 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA9 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xAA */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xAB */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xAC */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xAD */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xAE */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xAF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB0 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB1 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB2 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB3 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB4 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB5 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB6 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB7 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB8 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB9 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBA */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBB */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBC */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBD */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBE */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC0 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC1 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC2 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC3 */
    {// ret: pop addr de la pila y salta a ella
     "ret", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, exec_instr_ret,
     decode_instr_no_operands},

    /* 0xC4 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC5 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC6 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC7 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC8 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC9 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xCA */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xCB */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xCC */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xCD */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xCE */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xCF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD0 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD1 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD2 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD3 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD4 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD5 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD6 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD7 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD8 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xD9 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xDA */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xDB */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xDC */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xDD */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xDE */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xDF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE0 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE1 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE2 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE3 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE4 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE5 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE6 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE7 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE8 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xE9 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xEA */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xEB */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xEC */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xED */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xEE */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xEF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF0 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF1 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF2 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF3 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF4 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF5 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF6 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF7 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF8 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xF9 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xFA */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xFB */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xFC */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xFD */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xFE */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xFF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

};

/**
 * @brief Tabla de opcodes extendidos del bytecode VestaVM.
 *
 * Se utiliza cuando el primer byte de la instruccion es 0x00 (prefijo de
 * extension).  En ese caso el segundo byte actua como opcode2 y se usa como
 * indice en esta tabla.  Contiene 256 entradas (0x00-0xFF) que cubren las
 * instrucciones ALU, MOV, SIB, MOVC, saltos relativos, OOP y GC.
 *
 * Convenio de rangos destacados:
 *   0x05-0x13  ALU reg,reg y variantes (ADD/SUB/MUL/DIV/CMP/AND/OR/XOR...)
 *   0x14-0x1F  MOV, MOVH, SIB, MOVC, XCHG
 *   0x2D       JREL (salto relativo con desplazamiento de 32 bits con signo)
 *   0xA0-0xA5  instrucciones GC generacional
 * (GCALLOC/GCRUN/GCCONFIG/GCDROP/GCWB/NEWOBJ) 0xB0-0xB2  allocator bruto
 * (RAWALLOC/RAWFREE/RAWREALLOC) 0xC0-0xC2  cursores y GCDEREF
 * (READCUR/WRITECUR/GCDEREF) 0xD0-0xEB  sistema de objetos
 * (NEWOBJRAW/CALLVIRT/CALLSUPER/THROW/...)
 */
InstrFormat decode_table_extended[0X100] = {
    /* 0x00 */ {// edmw4
                "edmw4", Assembly::Bytecode::AddressingMode::NONE,
                Assembly::Bytecode::InstrSizeMode::FIXED_4, nullptr, nullptr},

    /* 0x01 */
    {// edmw6
     "edmw6", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, nullptr, nullptr},

    /* 0x02 */
    {// edm
     "edm", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, nullptr, nullptr},

    /* 0x03 */
    {
        // hlt
        "hlt", Assembly::Bytecode::AddressingMode::NONE,
        Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_hlt,
        decode_instr_simple // sin descodificacion compleja
                            // `decode_instr_simple`
    },

    /* 0x04 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x05 */
    {// add reg, reg
     "add", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_add_reg,
     decode_instr_two_op_reg},

    /* 0x06 */
    {// add reg, 0x1000 || [reg], 0x1000
     "add", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_add_imm,
     decode_instr_inmed_reg},

    /* 0x07 */
    {// add REG, SIB || SIB, REG
     "add", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_add_sib,
     decode_instr_sib},

    /* 0x08 */
    {// sub reg, reg
     "sub", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_sub_reg,
     decode_instr_two_op_reg},

    /* 0x09 */
    {// sub reg, 0x1000 || [reg], 0x1000
     "sub", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_sub_imm,
     decode_instr_inmed_reg},

    /* 0x0A */
    {// sub REG, SIB || SIB, REG
     "sub", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_sub_sib,
     decode_instr_sib},

    /* 0x0B */
    {// mul reg, reg
     "mul", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_mul_reg,
     decode_instr_two_op_reg},

    /* 0x0C */
    {// mul reg, 0x1000 || [reg], 0x1000
     "mul", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_mul_imm,
     decode_instr_inmed_reg},

    /* 0x0D */
    {// mul REG, SIB || SIB, REG
     "mul", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_mul_sib,
     decode_instr_sib},

    /* 0x0E */
    {// div reg, reg
     "div", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_div_reg,
     decode_instr_two_op_reg},

    /* 0x0F */
    {// div reg, 0x1000 || [reg], 0x1000
     "div", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_div_imm,
     decode_instr_inmed_reg},

    /* 0x10 */
    {// div REG, SIB || SIB, REG
     "div", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_div_sib,
     decode_instr_sib},

    /* 0x11 */
    {// cmp reg, reg
     "cmp", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_cmp_reg,
     decode_instr_two_op_reg},

    /* 0x12 */
    {// cmp reg, 0x1000 || [reg], 0x1000
     "cmp", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_cmp_imm,
     decode_instr_inmed_reg},

    /* 0x13 */
    {// cmp REG, SIB || SIB, REG
     "cmp", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_cmp_sib,
     decode_instr_sib},

    /* 0x14 */
    {// mov reg, reg
     "mov", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_mov_reg,
     decode_instr_simple_mov},

    /* 0x15 */
    {// mov reg, 0x1000 || [reg], 0x1000 || reg_ext, 0x1000
     "mov", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_inmed_mov,
     decode_instr_inmed_mov},

    /* 0x16 */
    {// mov REG, SIB || SIB, REG
     "mov", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_mov_sib,
     decode_instr_sib},

    /* 0x17 */
    {// and reg, reg
     "and", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_and_reg,
     decode_instr_two_op_reg},

    /* 0x18 */
    {// or reg, reg
     "or", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_or_reg,
     decode_instr_two_op_reg},

    /* 0x19 */
    {// xor reg, reg
     "xor", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_xor_reg,
     decode_instr_two_op_reg},

    /* 0x1A */
    {// not reg (unario)
     "not", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_not_reg,
     decode_instr_two_op_reg},

    /* 0x1B */
    {// shl reg, reg
     "shl", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_shl_reg,
     decode_instr_two_op_reg},

    /* 0x1C */
    {// shr reg, reg
     "shr", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_shr_reg,
     decode_instr_two_op_reg},

    /* 0x1D */
    {// sar reg, reg
     "sar", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_sar_reg,
     decode_instr_two_op_reg},

    /* 0x1E */
    {// movc/movch reg1,[reg2],flag || [reg1],reg2,flag
     "movc", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_movc_mem,
     decode_instr_movc},

    /* 0x1F */
    {// movc reg1, reg2, flag
     "movc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_movc_reg,
     decode_instr_movc},

    /* 0x20  mkclosure r_method, r_env: crea ClosureObject GC y retorna handle
       en R0 */
    {"mkclosure", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_mkclosure,
     decode_instr_two_op_reg},

    /* 0x21  callclosure r_closure: invoca el MethodInfo del ClosureObject GC */
    {"callclosure", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_callclosure,
     decode_instr_two_op_reg},

    /* 0x22  mkrawclosure r_fn, r_env: crea RawClosureObject sin GC y retorna
       puntero en R0 */
    {"mkrawclosure", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_mkrawclosure,
     decode_instr_two_op_reg},

    /* 0x23  callrawclosure r_closure: invoca la funcion nativa del
       RawClosureObject */
    {"callrawclosure", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_callrawclosure,
     decode_instr_two_op_reg},

    /* 0x24  tailcall r_fn: salto en posicion de cola; reutiliza el frame actual
     */
    {"tailcall", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_tailcall,
     decode_instr_two_op_reg},

    /* 0x25  isnull r_dst, r_src: r_dst = (r_src == 0) ? 1 : 0 */
    {"isnull", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_isnull,
     decode_instr_two_op_reg},

    /* 0x26  unwrap r_dst, r_src: r_dst = r_src o throw NullPointerException si
       nulo */
    {"unwrap", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_unwrap,
     decode_instr_two_op_reg},

    /* 0x27  jumptable r_val, r_table, count: salto O(1) por valor entero */
    {"jumptable", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_jumptable,
     decode_instr_jumptable},

    /* 0x28  typeswitch r_obj, r_table, count: despacho por clase (O(n)) */
    {"typeswitch", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_typeswitch,
     decode_instr_jumptable},

    /* 0x29  future: crea FutureObject GC en estado PENDING; R0 = GcHandle */
    {"future", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_future,
     decode_instr_no_operands},

    /* 0x2A  await r_fut: bloquea el proceso hasta que el future se resuelva */
    {"await", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_await,
     decode_instr_two_op_reg},

    /* 0x2B  fulfill r_fut, r_val: resuelve el future con un valor */
    {"fulfill", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fulfill,
     decode_instr_two_op_reg},

    /* 0x2C  reject r_fut, r_err: rechaza el future con un codigo de error */
    {"reject", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_reject,
     decode_instr_two_op_reg},

    /* 0x2D  jrel cond, disp32: salto relativo condicional con desplazamiento
     * 32-bit [0x00][0x2D][cond][pad][disp32] = 8 bytes */
    {"jrel", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_jrel,
     decode_instr_jrel},

    /* 0x2E  subsp rsp|rbp, imm: RSP/RBP -= imm (reserva frame de variables
       locales) */
    {"subsp", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_subsp,
     decode_instr_inmed_reg},

    /* 0x2F  addsp rsp|rbp, imm: RSP/RBP += imm (libera frame de variables
       locales) */
    {"addsp", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_addsp,
     decode_instr_inmed_reg},

    /* 0x30  weakref r_handle: registra GcHandle en la tabla de weak refs; R0 =
       indice opaco */
    {"weakref", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_weakref,
     decode_instr_two_op_reg},

    /* 0x31  loop: salto condicional de bucle con contador en registro */
    {"loop", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, nullptr, nullptr},

    /* 0x32  deref_weak r_dst, r_idx: r_dst = GcHandle si vivo, GC_NULL_HANDLE
       si muerto */
    {"deref_weak", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_deref_weak,
     decode_instr_two_op_reg},

    /* 0x33  nop2: no operacion de 2 bytes */
    {"nop2", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, nullptr, nullptr},

    /* 0x34  free_weak r_idx: libera una entrada de la tabla de weak refs */
    {"free_weak", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_free_weak,
     decode_instr_two_op_reg},

    /* 0x35  monenter reg_handle: adquiere el monitor reentrante del objeto GC
     */
    {"monenter", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_monenter,
     decode_instr_two_op_reg},

    /* 0x36  monexit reg_handle: libera el monitor del objeto GC */
    {"monexit", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_monexit,
     decode_instr_two_op_reg},

    /* 0x37  monwait reg_handle: libera el monitor y suspende el proceso */
    {"monwait", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_monwait,
     decode_instr_two_op_reg},

    /* 0x38  monnoti reg_handle: despierta un proceso de la cola de espera */
    {"monnoti", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_monnoti,
     decode_instr_two_op_reg},

    /* 0x39  monnota reg_handle: despierta todos los procesos de la cola de
       espera */
    {"monnota", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_monnota,
     decode_instr_two_op_reg},

    /* 0x3A  specialize r_dst, r_class, r_types, count: instancia clase generica
     */
    {"specialize", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_specialize,
     decode_instr_jumptable},

    /* 0x3B  rspawn r_fn, r_node -> R0 = GcHandle del FutureObject */
    {"rspawn", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_rspawn,
     decode_instr_two_op_reg},

    /* 0x3C  msgsend r_pid, r_addr, r_len */
    {"msgsend", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_msgsend,
     decode_instr_three_reg},

    /* 0x3D  msgrecv r_buf, r_max -> R0 = bytes recibidos */
    {"msgrecv", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_msgrecv,
     decode_instr_two_op_reg},

    /* 0x3E  memsync r_params */
    {"memsync", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_memsync,
     decode_instr_two_op_reg},

    /* 0x3F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x40 mods/modu reg, reg */
    {"mod", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_mod_reg,
     decode_instr_two_op_reg},

    /* 0x41 mods/modu reg, imm */
    {"mod", Assembly::Bytecode::AddressingMode::MEM,
     Assembly::Bytecode::InstrSizeMode::MIXED_SIZE, exec_instr_mod_imm,
     decode_instr_inmed_reg},

    /* 0x42 mods/modu SIB */
    {"mod", Assembly::Bytecode::AddressingMode::SIB,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_mod_sib,
     decode_instr_sib},

    /* 0x43 setcc r_dst, cond */
    {"setcc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_setcc,
     decode_instr_raw_bytes},

    /* 0x44 tryenter r_handler, r_type */
    {"tryenter", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_tryenter,
     decode_instr_raw_bytes},

    /* 0x45 tryleave */
    {// Sin operandos; usa decode_instr_simple porque la salida del
     // decoder (al margen del exec) DEBE rellenar size_instr.  Si
     // decode == nullptr, el decoder corto-circuita la instruccion
     // en line 882 de decode_instruction.cpp como invalida y el
     // proceso queda "halt"-ed pero sin avance de PC, causando
     // bucle silencioso o cuelgue del scheduler.
     "tryleave", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_tryleave,
     decode_instr_simple},

    /* 0x46 strmake r_dst, r_src, r_len */
    {"strmake", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strmake,
     decode_instr_raw_bytes},

    /* 0x47 strlen r_dst, r_src */
    {"strlen", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strlen,
     decode_instr_raw_bytes},

    /* 0x48 strcat r_dst, r_a, r_b */
    {"strcat", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strcat,
     decode_instr_raw_bytes},

    /* 0x49 strcmp r_dst, r_a, r_b */
    {"strcmp", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strcmp,
     decode_instr_raw_bytes},

    /* 0x4A strconv r_dst, r_src, enc */
    {"strconv", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strconv,
     decode_instr_raw_bytes},

    /* 0x4B strraw r_dst, r_src */
    {"strraw", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strraw,
     decode_instr_raw_bytes},

    /* 0x4C  strslice r_dst, r_src, r_range */
    {"strslice", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strslice,
     decode_instr_raw_bytes},

    /* 0x4D  strflat r_dst, r_src */
    {"strflat", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strflat,
     decode_instr_raw_bytes},

    /* 0x4E  strhash r_dst, r_src */
    {"strhash", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strhash,
     decode_instr_raw_bytes},

    /* 0x4F  strintern r_dst, r_src */
    {"strintern", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strintern,
     decode_instr_raw_bytes},

    /* 0x50  strgetenc r_dst, r_src */
    {"strgetenc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strgetenc,
     decode_instr_raw_bytes},

    /* 0x51  strgetbytes r_dst, r_src */
    {"strgetbytes", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strgetbytes,
     decode_instr_raw_bytes},

    /* 0x52  strgetkind r_dst, r_src */
    {"strgetkind", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strgetkind,
     decode_instr_raw_bytes},

    /* 0x53  strreserve r_dst, r_cap */
    {"strreserve", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strreserve,
     decode_instr_raw_bytes},

    /* 0x54  strfinalize r_dst, r_newlen */
    {"strfinalize", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strfinalize,
     decode_instr_raw_bytes},

    /* 0x55 */
    {//
     "calln", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_10, exec_instr_calln,
     decode_instr_calln},

    /* 0x56 */
    {// gchandle r_dst, r_src  - lookup inverso payload_ptr -> GcHandle
     // (O(1) via mapa hash en GcHeap).  Devuelve GC_NULL_HANDLE si el
     // puntero no corresponde a ningun objeto vivo.  Usado por Vesta
     // synchronized(obj) para obtener el handle desde el host_ptr.
     "gchandle", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gchandle,
     decode_instr_two_op_reg},

    /* 0x57 */
    {// getpid r_dst  - deposita encoded PID del proceso actual en r_dst.
     // Formato: (scheduler_id<<32) | (local_pid & 0xFFFFFFFF).
     "getpid", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getpid,
     decode_instr_two_op_reg},

    /* 0x58  spawnon r_fn, r_hint - spawn con scheduler hint:
              hint = -1 (signed) -> Here (mismo scheduler que el padre)
              hint >= 0          -> Pinned al scheduler hint%num_schedulers
              Sirve a Vesta `spawn here { }` y `spawn on(N) { }`. */
    {"spawnon", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_spawn_on,
     decode_instr_two_op_reg},

    /* 0x59  loadmod r_path_addr, r_path_len - carga dinamica de un .velb
              desde el filesystem; r0 = init_pc (entry del modulo) o 0 si
              failure.  El caller invoca el modulo via callvmr r0 para
              que su prologo de main corra __module_init y registre las
              clases nuevas en el ClassRegistry global. */
    {"loadmod", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_loadmod,
     decode_instr_two_op_reg},

    /* 0x5A  panic r_msg_addr, r_msg_len - lanza FatalError con
              kind = FATAL_USER_ABORT y message = bytes[vm_addr,len].
              Capturable desde Vesta via try/catch (FatalError e). */
    {"panic", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_panic,
     decode_instr_two_op_reg},

    /* 0x5B  setmethdbg r_method, r_params - : registra debug
              info para un MethodInfo (file + start_line) en la tabla
              global g_method_debug.  Lo emite el frontend Vesta tras
              cada defmethod en __module_init.  El stack trace lo
              consulta para mostrar "(file.vx:42)" en vez de
              "(pc=0xADDR)" en cada frame. */
    {"setmethdbg", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_setmethdbg,
     decode_instr_two_op_reg},

    /* 0x5C  fextend zmm_dst, zmm_src - convierte f32 -> f64 dentro del
              banco ZMM.  Lo emite IrOp::F32TOF64 (frontend Vesta hace
              `f64 d = f32_var;`).  Mismo encoding que fadd/fmov. */
    {"fextend", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fextend,
     decode_instr_simple_mov},

    /* 0x5D  fnarrow zmm_dst, zmm_src - convierte f64 -> f32 dentro del
              banco ZMM.  Lo emite IrOp::F64TOF32 (frontend Vesta hace
              `f32 f = f64_var;`).  Mismo encoding que fadd/fmov. */
    {"fnarrow", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fnarrow,
     decode_instr_simple_mov},

    /* 0x5E  strmake_h r_dst, r_src, r_len (FIXED_4)
             Crea StringObject FLAT desde un buffer en memoria HOST.
             Variante de strmake (0x46) para casos donde el buffer
             proviene de malloc/gcallocp/str_cstr y no de memoria VM.
             Misma encoding que strmake; ver exec_instr_strmake_h. */
    {"strmake_h", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_strmake_h,
     decode_instr_raw_bytes},

    /* 0x5F  fmadd[.ps] fd, fa, fb (FIXED_4, Convention B)
             Multiplica-acumula fusionado: fd = fma(fa, fb, fd), 1 redondeo.
             byte2=(fa<<4)|fd, byte3=(fb<<4)|isf32.  Lo emite VEC_FMA para que
             el interp coincida con VFMADD231PD del JIT. */
    {"fmadd", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fmadd,
     decode_instr_raw_bytes},

    /* 0x60  getstatic r_dst, r_class, offset_u32 (FIXED_8)
             Lee 8 bytes desde cls->static_data + offset (HOST mem).
             El frontend Vesta hace truncate post-load para tipos < 8 bytes.
             Ver exec_instr_getstatic en exec_instruction_meta.cpp. */
    {"getstatic", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_getstatic,
     decode_instr_static_offset},

    /* 0x61  setstatic r_class, r_value, offset_u32 (FIXED_8)
             Escribe 8 bytes a cls->static_data + offset (HOST mem).
             El frontend Vesta hace truncate / sign-ext pre-store si
             necesario.  Ver exec_instr_setstatic. */
    {"setstatic", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_setstatic,
     decode_instr_static_offset},

    /* 0x62  dlopen r_dst, r_path_addr, r_path_len (FIXED_4, FFI runtime)
             Carga libreria nativa por path leido desde vm_mem; devuelve
             handle host en r_dst.  Ver exec_instr_dlopen. */
    {"dlopen", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_dlopen,
     decode_instr_dlopen_dlsym},

    /* 0x63  dlsym r_dst, r_handle, r_name_addr, r_name_len (FIXED_4)
             Resuelve simbolo nativo en una libreria cargada; devuelve
             fn_addr en r_dst.  Ver exec_instr_dlsym. */
    {"dlsym", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_dlsym,
     decode_instr_dlopen_dlsym},

    /* 0x64  callni r_fn (FIXED_4, FFI runtime)
             Invoca funcion nativa por puntero (r_fn).  argc en R15,
             args en R01..R12, retorno en R00.  Misma calling convention
             que CALLN estatico (mismo invoke_native_unchecked). */
    {"callni", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_callni,
     decode_instr_callni},

    /* 0x65  gcallocp r_dst, r_size (FIXED_4)
             GC alloc + host_ptr al payload directo en r_dst (1 instr VM
             vs 3 de la secuencia gcalloc+gcderef+xchg).  Optimizacion
             para envs heap de closures (mejora I optimizada). */
    {"gcallocp", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcallocp,
     decode_instr_gcallocp},

    /* 0x66  spawnargs r_pc (FIXED_4)
             Spawn que copia R1..R[R15] del padre al child antes de
             make_ready.  Calling convention identica a CALLVM (argc en
             R15, args en R1..R12).  Elimina la serializacion via
             msgsend para pasar args al spawn body (mejora II
             optimizada).  Devuelve PID encoded del child en R0. */
    {"spawnargs", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_spawnargs,
     decode_instr_spawnargs},

    /* 0x67  fulfillhlt r_fut, r_value (FIXED_4)
             Fusion atomic de fulfill (0x2B) + hlt (0x03) para el path
             critico del helper sintetico de @Async: cada `return X`
             del body baja a 1 instruccion VM en lugar de 2. */
    {"fulfillhlt", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fulfillhlt,
     decode_instr_fulfillhlt},

    /* 0x68  cmpjmp.cc r_a, r_b, target (FIXED_8, signed)
             Cmp signed + jmp.cc fusionados.  Equivalente a:
               cmps r_a, r_b
               jmp.cond target
             en 1 instruccion VM.  Encoding: [0x00][0x68][b2][cond][u32].
             Mejora ~33-50% en bytes y elimina 1 instr VM por comparacion
             condicional en hot loops. */
    {"cmpjmp", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_cmpjmp,
     decode_instr_cmpjmp},

    /* 0x69  cmpjmpu.cc r_a, r_b, target (FIXED_8, unsigned)
             Identico a 0x68 pero comparacion unsigned (CF se setea
             segun a<b unsigned). */
    {"cmpjmpu", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_cmpjmpu,
     decode_instr_cmpjmp},

    /* 0x6A  decjnz r_counter, target (FIXED_8)
             Decremento + branch-if-not-zero en 1 instr.  Equivalente a:
               subs r_counter, 1
               jmp.jne target
             Reduce 2-3 instr VM -> 1 por iteracion en loops contadores. */
    {"decjnz", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_decjnz,
     decode_instr_decjnz},

    /* 0x6B  getargc r_dst (FIXED_4)
             Deposita el numero de argumentos del script (argv del programa
             Vesta) en r_dst.  Builtin Vesta `args_count() -> i32`.  Lee de
             vm->scheduler.vm_reference.script_args.size(). */
    {"getargc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getargc,
     decode_instr_two_op_reg},

    /* 0x6C  getarg r_dst, r_idx (FIXED_4)
             Aloca un StringObject FLAT con el contenido del arg[idx] y
             deposita su GcHandle en r_dst.  Si idx fuera de rango,
             deposita 0 (GC_NULL_HANDLE).  Builtin Vesta `args_get(i) ->
       string`.
     */
    {"getarg", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getarg,
     decode_instr_two_op_reg},

    /* 0x6D  unloadmod r_path_addr, r_path_len (FIXED_4)
             Descarga un modulo previamente cargado via loadmod.  Mismo
             formato de operandos.  R0 = 1 si descargado, 0 si no encontrado.
             Builtin Vesta `unloadmodule(path) -> i32`. */
    {"unloadmod", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_unloadmod,
     decode_instr_two_op_reg},

    /* 0x6E  getmethat r_class, r_idx (FIXED_4)
             Variante reg-reg de getmethod (0xD9).  R00 = &cls->methods[idx]
             o 0 si fuera de rango / nulo.  Builtin Vesta `getMethodAt(cls, i)`.
     */
    {"getmethat", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getmethat,
     decode_instr_two_op_reg},

    /* 0x6F  getfldat r_class, r_idx (FIXED_4)
             Variante reg-reg de getfield (0xD8).  R00 = &cls->fields[idx]
             o 0 si fuera de rango / nulo.  Builtin Vesta `getFieldAt(cls, i)`.
     */
    {"getfldat", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getfldat,
     decode_instr_two_op_reg},

    /* 0x70  fastpush <mask16> (FIXED_4)
             Empuja a la pila los registros marcados en mask en orden
             ascendente (r0 primero, r_max ultimo).  1 instr VM reemplaza
             N x push reg.  Equivalente a:
               subsp rsp, N*8
               for each bit r in mask asc:
                 [rsp + offset] = reg[r]  (offset descendente desde N-1) */
    {"fastpush", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fastpush,
     decode_instr_fastmask},

    /* 0x71  fastpop <mask16> (FIXED_4)
             Desempila los registros marcados restaurando los valores en
             orden simetrico al fastpush con el mismo mask.  Avanza RSP
             por N*8 al final. */
    {"fastpop", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fastpop,
     decode_instr_fastmask},

    /* 0x72  mvtake r_dst_addr, r_src_addr (FIXED_4)
             Move-and-take: copia un qword desde [r_src_addr] a
             [r_dst_addr] y zerifica [r_src_addr] en una sola
             instruccion VM (3 host x86-64 cuando llegue el JIT).
             Primitivo de move-ownership para smart pointers
             unique<T> y shared<T>: tras la operacion, el slot
             fuente queda invalidado (binding == null) lo que
             garantiza que el cleanup automatico en scope exit
             no haga double-free.  No es atomic cross-thread por
             diseno (move es siempre intra-thread).
             Encoding: [0x00][0x72][byte2][0x00] con
             byte2 = (r_src<<4) | r_dst. */
    {"mvtake", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_mvtake,
     decode_instr_two_op_reg},

    /* 0x73  adds3 r_dst, r_src1, r_src2  (FIXED_4)
             Super-instruccion ADD signed con 3 operandos.  Combina
             `mov rd, rs1; adds rd, rs2` en una sola instruccion VM. */
    {"adds3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x74  subs3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"subs3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x75  muls3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"muls3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x76  addu3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"addu3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x77  subu3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"subu3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x78  mulu3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"mulu3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x79  and3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"and3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x7A  or3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"or3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x7B  xor3 r_dst, r_src1, r_src2  (FIXED_4) */
    {"xor3", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_alu3,
     decode_instr_raw_bytes},

    /* 0x7C  loadz r_dst, r_src  (FIXED_4)
             Super-instruccion: load N-bit con zero-extend a 64-bit en
             una sola instruccion VM.  Sustituye el patron tipico:
                 mov r_dst, 0       ; (clear)
                 mov r_dst.d, [src] ; (32-bit load preserving upper)
             que el emisor IR genera para LOAD i8/i16/i32/u8/u16/u32.
             Encoding:
                 [0x00][0x7C][ctrl][regs]
                 ctrl bits 7-6 = mode (0=8b, 1=16b, 2=32b, 3=64b)
                 ctrl bit  5   = is_host (1 = host_ptr, 0 = VM mem)
                 regs = (r_src<<4) | r_dst */
    {"loadz", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_loadz,
     decode_instr_simple_mov},

    /* 0x7D  loadzh r_dst, r_src  (FIXED_4)
             Variante HOST de loadz.  Mismo encoding pero el bit s
             del ctrl byte = 1.  Lee desde memoria del proceso host
             en lugar del vm_mem virtual. */
    {"loadzh", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_loadz,
     decode_instr_simple_mov},

    /* 0x7E  htrack r_ptr (FIXED_4)
             Sprint MMM-ext leak-fix (2026-06-01): registra el host_ptr
             en r_ptr para cleanup automatico cuando el frame actual
             se destruye (RET / do_throw / TAILCALL).  Emitido por el
             bytecode emit del interp DESPUES de un `alloc` cuyo IR
             ALLOCA lleva flag `host_alloca=true`.  Cero overhead para
             frames que no contienen host_allocas (no-op si nadie lo
             invoca). */
    {"htrack", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_htrack,
     decode_instr_two_op_reg},

    /* 0x7F  gcfinal r_box, kind (FIXED_4)
             Registra un finalizador GC para el box (objeto GC con recurso
             interno) en r_box.  Marca el bit has_finalizer + finalizer_kind
             en el GcHeader.  kind!=0 registra, kind==0 desregistra (cleanup
             determinista de scope, anti-doble-free).  Emitido por el lowering
             de gc_box(unique_with/shared) tras el GC_ALLOCP.
             encoding [0x00][0x7F][0x00][n2], n2 = (kind<<4)|r_box. */
    {"gcfinal", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcfinal,
     decode_instr_two_op_reg},
    /* 0x80  fmin dst, src: FP min escalar nativo */
    {"fmin", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fmin,
     decode_instr_simple_mov},

    /* 0x81  fmax dst, src: FP max escalar nativo */
    {"fmax", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fmax,
     decode_instr_simple_mov},

    /* 0x82  ffloor dst, src: FP floor escalar nativo */
    {"ffloor", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_ffloor,
     decode_instr_simple_mov},

    /* 0x83  fceil dst, src: FP ceil escalar nativo */
    {"fceil", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fceil,
     decode_instr_simple_mov},

    /* 0x84  fround dst, src: FP round escalar nativo */
    {"fround", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fround,
     decode_instr_simple_mov},

    /* 0x85  ftrunc dst, src: FP trunc escalar nativo */
    {"ftrunc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_ftrunc,
     decode_instr_simple_mov},

    /* 0x86  bitg2z fX, rN: bitcast GP -> ZMM directo */
    {"bitg2z", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_bitg2z,
     decode_instr_simple_mov},

    /* 0x87  bitz2g rN, fX: bitcast ZMM -> GP directo */
    {"bitz2g", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_bitz2g,
     decode_instr_simple_mov},

    /* 0x88 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x89 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x8C  gccollect (ZERO, FIXED_2): fuerza minor+major GC del proceso +
             drena finalizadores.  Builtin Vesta gc_collect(). */
    {"gccollect", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_gccollect,
     decode_instr_simple},

    /* 0x8D  gcfinalc r_box, r_dtor (FIXED_4)
             Registra un finalizador CLASS_DTOR para el gc<Clase> con ~Clase()
             en r_box.  r_dtor contiene el vaddr del <Clase>____dtor concreto
             (dispatch estatico, CALL directo).  El sweep invoca dtor(obj) por
             bytecode reentrante al colectar el objeto.
             encoding [0x00][0x8D][0x00][n2], n2 = (r_dtor<<4)|r_box. */
    {"gcfinalc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcfinalc,
     decode_instr_two_op_reg},

    /* 0x8E  gcfinall (ZERO, FIXED_2): finaliza todo objeto GC vivo con recurso
             interno.  Builtin Vesta gc_finalize_all().  Determinista. */
    {"gcfinall", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_gcfinall,
     decode_instr_simple},

    /* 0x8F  csel r_dst, r_cond, r_a, r_b (FIXED_4): dst = cond ? a : b.
       Super-instruccion del IrOp::SELECT para el interp.  Ver exec_instr_csel.
     */
    {"csel", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_csel,
     decode_instr_four_reg},

    /* 0x90  mld r_dst, [base +/- index*scale +/- disp] (FIXED_8): load
       universal. base in {r0-r15, rbp, rsp}.  Ver exec_instr_mld. */
    {"mld", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_mld,
     decode_instr_mem_full},

    /* 0x91  mst [base +/- index*scale +/- disp], r_src (FIXED_8): store
       universal. */
    {"mst", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_8, exec_instr_mst,
     decode_instr_mem_full},

    /* 0x92  sext r_dst, N (FIXED_4): sign-extiende r_dst desde N bits
       (8/16/32) a 64.  b2=r_dst, b3=N.  1 instr vs mov+shl+sar. */
    {"sext", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_sext,
     decode_instr_raw_bytes},

    /* 0x93 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x94 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x95 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x96 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x97 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x98 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x99 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9A */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9B */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9C */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9D */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9E */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0x9F */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xA0 */
    {// NEWOBJ reg_classinfo -> R0 = GcHandle
     // reg1 = host_ptr a ClassInfo; alloc classinfo->instance_size bytes,
     // escribe ObjectHeader (class_ptr, OBJ_FLAG_GC_OWNED, hash).
     "newobj", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_newobj,
     decode_instr_two_op_reg},

    /* 0xA1 */
    {// GCRUN (sin operandos) - dispara minor+major GC del proceso
     "gcrun", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_gcrun,
     decode_instr_simple},

    /* 0xA2 */
    {// GCCONFIG reg_threshold - ajusta umbral de OldGen para major GC
     "gcconfig", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcconfig,
     decode_instr_two_op_reg},

    /* 0xA3 */
    {// DROP reg_handle - libera el GcHandle en el registro
     "drop", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gc_drop,
     decode_instr_two_op_reg},

    /* 0xA4 */
    {// GCWB reg_old_handle - registra el handle OLD en el remembered set
     "gcwb", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcwb,
     decode_instr_two_op_reg},

    /* 0xA5 */
    {// GCALLOC reg_size -> R0 = GcHandle
     // Reserva size bytes en el GC heap sin escribir ObjectHeader.
     "gcalloc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcalloc,
     decode_instr_two_op_reg},

    /* 0xA6 */
    {// NEWOBJS reg_cls -> aloca en SharedHeap ( Z.6).  Registra
     // el host_ptr en shared_handle_table y guarda el shared handle
     // en ObjectHeader.hash_code para reverse lookup O(1).
     "newobjs", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_newobjs,
     decode_instr_two_op_reg},

    /* 0xA7 */
    {// GCPROMOTE r_dst, r_src - deep-copy de local a SharedHeap.
     "gcpromote", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcpromote,
     decode_instr_two_op_reg},

    /* 0xA8 */
    {// GCDEMOTE r_dst, r_src - deep-copy de SharedHeap a local.
     "gcdemote", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcdemote,
     decode_instr_two_op_reg},

    /* 0xA9 */
    {// ATOMICLD reg_dst_sized, reg_addr - width-aware (ctrl-byte mode).
     "atomicld", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_atomicld,
     decode_instr_simple_mov},

    /* 0xAA */
    {// ATOMICST reg_addr, reg_val_sized - width-aware (ctrl-byte mode).
     "atomicst", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_atomicst,
     decode_instr_simple_mov},

    /* 0xAB */
    {// ATOMICCAS reg_dst_sized, reg_addr, reg_exp, reg_des - FIXED_6
     // (ctrl+regs).
     "atomiccas", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_atomiccas,
     decode_instr_atomic_rmw},

    /* 0xAC */
    {// ATOMICADD reg_dst_sized, reg_addr, reg_delta - FIXED_6 (ctrl+regs).
     "atomicadd", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_atomicadd,
     decode_instr_atomic_rmw},

    /* 0xAD */
    {// SHAREDSTAT reg_dst, reg_op - introspeccion SharedHeap.
     // op=0 bytes, op=1 alloc_count, op=2 gc_collect.
     "sharedstat", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_sharedstat,
     decode_instr_two_op_reg},

    /* 0xAE  callitf r_obj, r_params: dispatch de interfaz via itable */
    {"callitf", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_callitf,
     decode_instr_two_op_reg},

    /* 0xAF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB0 */
    {// ALLOC reg_size -> R0 = ptr host real
     "alloc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_raw_alloc,
     decode_instr_two_op_reg},

    /* 0xB1 */
    {// FREE reg_ptr - libera el bloque en el puntero host
     "free", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_raw_free,
     decode_instr_two_op_reg},

    /* 0xB2 */
    {// REALLOC reg_ptr, reg_size -> R0 = nuevo ptr host
     "realloc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_raw_realloc,
     decode_instr_two_op_reg},

    /* 0xB3 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB4 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB5 */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xB6  memset r_dst, r_val, r_len: relleno en memoria VIRTUAL
       Convention B (raw bytes): byte2 = (rB << 4) | rA, byte3 = (rC << 4),
       el MISMO layout de 3 registros que alu3 -- por eso comparten emisor. */
    {"memset", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_memset,
     decode_instr_raw_bytes},

    /* 0xB7  memseth r_dst, r_val, r_len: relleno en memoria del HOST
       Convention B (raw bytes): byte2 = (rB << 4) | rA, byte3 = (rC << 4),
       el MISMO layout de 3 registros que alu3 -- por eso comparten emisor. */
    {"memseth", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_memseth,
     decode_instr_raw_bytes},

    /* 0xB8  memcpy r_dst, r_src, r_len: copia en memoria VIRTUAL
       Convention B (raw bytes): byte2 = (rB << 4) | rA, byte3 = (rC << 4),
       el MISMO layout de 3 registros que alu3 -- por eso comparten emisor. */
    {"memcpy", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_memcpy,
     decode_instr_raw_bytes},

    /* 0xB9  memcpyh r_dst, r_src, r_len: copia en memoria del HOST
       Convention B (raw bytes): byte2 = (rB << 4) | rA, byte3 = (rC << 4),
       el MISMO layout de 3 registros que alu3 -- por eso comparten emisor. */
    {"memcpyh", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_memcpyh,
     decode_instr_raw_bytes},

    /* 0xBA */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBB */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBC */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBD */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBE */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xBF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},

    /* 0xC0 */
    {// readcur dest_reg, curN  - lee N bytes de la dir. host en curN ->
     // dest_reg
     "readcur", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_readcur,
     decode_instr_cursor_rw},

    /* 0xC1 */
    {// writecur curN, src_reg  - escribe src_reg en la dir. host en curN
     "writecur", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_writecur,
     decode_instr_cursor_rw},

    /* 0xC2 */
    {// gcderef curN, handle_reg  - GcHandle -> puntero raw payload en curN
     "gcderef", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_gcderef,
     decode_instr_cursor_rw},

    /* 0xC3 */
    {// addcur curN, imm16  - suma imm16 con signo al registro cursor curN
     "addcur", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_6, exec_instr_addcur,
     decode_instr_addcur},

    /* 0xC4 */
    {// vmcopy curN, rSrc, rLen  - copia rLen bytes de VM memory[rSrc] ->
     // host[curN]
     "vmcopy", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_vmcopy,
     decode_instr_vmcopy},

    /* 0xC5 */
    {// vcopyh rDst, curN, rLen  - copia rLen bytes de host[curN] -> VM
     // memory[rDst]
     "vcopyh", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_vcopyh,
     decode_instr_vmcopy},

    /* 0xC6 */
    {// getproc rN  - almacena el puntero ProcessVM* del proceso actual en rN
     "getproc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getproc,
     decode_instr_two_op_reg},

    /* 0xC7 */
    {// getvm rN  - almacena el puntero VM* de la instancia propietaria en rN
     "getvm", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getvm,
     decode_instr_two_op_reg},

    /* 0xC8 */
    {// getmgr rN  - almacena el puntero ManageVM* del gestor de instancias en
     // rN
     "getmgr", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getmgr,
     decode_instr_two_op_reg},

    /* 0xC9  defclass r_dst, r_params: crear clase nueva */
    {"defclass", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_defclass,
     decode_instr_two_op_reg},

    /* 0xCA  deffield r_class, r_params: anadir field a clase */
    {"deffield", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_deffield,
     decode_instr_two_op_reg},

    /* 0xCB  defmethod r_class, r_params: anadir method a clase */
    {"defmethod", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_defmethod,
     decode_instr_two_op_reg},

    /* 0xCC  findclass r_dst, r_params: buscar clase por nombre */
    {"findclass", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_findclass,
     decode_instr_two_op_reg},

    /* 0xCD  findmethod r_dst, r_params: buscar metodo por nombre dentro de
       clase */
    {"findmethod", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_findmethod,
     decode_instr_two_op_reg},

    /* 0xCE  addadvice r_target, r_advice (kind en byte3): registrar advice AOP
     */
    {"addadvice", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_addadvice,
     decode_instr_raw_bytes},

    /* 0xCF  findfield r_dst, r_params: buscar field por nombre dentro de clase
     */
    {"findfield", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_findfield,
     decode_instr_two_op_reg},

    /* 0xD0 */
    {// NEWOBJRAW reg_classinfo, reg_size -> R0 = host_ptr
     "newobjraw", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_newobjraw,
     decode_instr_two_op_reg},

    /* 0xD1 */
    {// CALLVIRT reg_obj, vtable_idx
     "callvirt", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_callvirt,
     decode_instr_oop_reg_imm8},

    /* 0xD2 */
    {// CALLSUPER reg_classinfo, vtable_idx
     "callsuper", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_callsuper,
     decode_instr_oop_reg_imm8},

    /* 0xD3 */
    {// THROW reg_obj
     "throw", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_throw,
     decode_instr_two_op_reg},

    /* 0xD4 */
    {// RETHROW
     "rethrow", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_rethrow,
     decode_instr_simple},

    /* 0xD5 */
    {// GETCLASS reg_obj -> R0 = ClassInfo*
     "getclass", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getclass,
     decode_instr_two_op_reg},

    /* 0xD6 */
    {// INSTANCEOF reg_obj, reg_classinfo -> R0 = bool
     "instanceof", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_instanceof,
     decode_instr_two_op_reg},

    /* 0xD7 */
    {// CHECKCAST reg_obj, reg_classinfo -> R0 = reg_obj o THROW
     "checkcast", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_checkcast,
     decode_instr_two_op_reg},

    /* 0xD8 */
    {// GETFIELD reg_classinfo, field_idx -> R0 = FieldInfo*
     "getfield", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getfield,
     decode_instr_oop_reg_imm8},

    /* 0xD9 */
    {// GETMETHOD reg_classinfo, method_idx -> R0 = MethodInfo*
     "getmethod", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_getmethod,
     decode_instr_oop_reg_imm8},

    /* 0xDA */
    {// FIELDCOUNT reg_classinfo -> R0 = uint64
     "fieldcount", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fieldcount,
     decode_instr_two_op_reg},

    /* 0xDB */
    {// METHODCOUNT reg_classinfo -> R0 = uint64
     "methodcount", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_methodcount,
     decode_instr_two_op_reg},

    /* 0xDC */
    {// CLASSNAME reg_classinfo -> R0 = char*
     "classname", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_classname,
     decode_instr_two_op_reg},

    /* 0xDD */
    {"classdoc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_classdoc,
     decode_instr_two_op_reg},

    /* 0xDE */
    {"classattrcount", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_classattrcount,
     decode_instr_two_op_reg},

    /* 0xDF */
    {"classattrkey", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_classattrkey,
     decode_instr_oop_reg_imm8},

    /* 0xE0 */
    {"classattrval", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_classattrval,
     decode_instr_oop_reg_imm8},

    /* 0xE1 */
    {"methodname", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_methodname,
     decode_instr_two_op_reg},

    /* 0xE2 */
    {"methoddoc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_methoddoc,
     decode_instr_two_op_reg},

    /* 0xE3 */
    {"methoddesc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_methoddesc,
     decode_instr_two_op_reg},

    /* 0xE4 */
    {"methodattrcount", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_methodattrcount,
     decode_instr_two_op_reg},

    /* 0xE5 */
    {"methodattrkey", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_methodattrkey,
     decode_instr_oop_reg_imm8},

    /* 0xE6 */
    {"methodattrval", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_methodattrval,
     decode_instr_oop_reg_imm8},

    /* 0xE7 */
    {"fieldname", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fieldname,
     decode_instr_two_op_reg},

    /* 0xE8 */
    {"fielddoc", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fielddoc,
     decode_instr_two_op_reg},

    /* 0xE9 */
    {"fieldattrcount", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fieldattrcount,
     decode_instr_two_op_reg},

    /* 0xEA */
    {"fieldattrkey", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fieldattrkey,
     decode_instr_oop_reg_imm8},

    /* 0xEB */
    {"fieldattrval", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fieldattrval,
     decode_instr_oop_reg_imm8},

    /* 0xEC  yield: cede el quantum al scheduler */
    {"yield", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_yield,
     decode_instr_simple},

    /* 0xED  resume reg: reactiva el proceso cuyo PID esta en reg */
    {"resume", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_resume,
     decode_instr_two_op_reg},

    /* 0xEE  spawn reg: crea nuevo proceso en la direccion del registro */
    {"spawn", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_spawn,
     decode_instr_two_op_reg},

    /* 0xEF  swapctx reg_dst, reg_src: intercambio de contexto entre fibras */
    {"swapctx", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_swapctx,
     decode_instr_two_op_reg},

    /* 0xF0  fmov dst, src: copia registro ZMM con zeroing de aliasing */
    {"fmov", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fmov,
     decode_instr_simple_mov},

    /* 0xF1  fadd dst, src: suma flotante escalar o packed */
    {"fadd", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fadd,
     decode_instr_simple_mov},

    /* 0xF2  fsub dst, src: resta flotante */
    {"fsub", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fsub,
     decode_instr_simple_mov},

    /* 0xF3  fmul dst, src: multiplicacion flotante */
    {"fmul", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fmul,
     decode_instr_simple_mov},

    /* 0xF4  fdiv dst, src: division flotante */
    {"fdiv", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fdiv,
     decode_instr_simple_mov},

    /* 0xF5  fcmp a, b: comparacion flotante; establece ZF/SF/CF */
    {"fcmp", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fcmp,
     decode_instr_simple_mov},

    /* 0xF6  fsqrt dst, src: raiz cuadrada flotante */
    {"fsqrt", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fsqrt,
     decode_instr_simple_mov},

    /* 0xF7  fabs dst, src: valor absoluto flotante */
    {"fabs", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fabs,
     decode_instr_simple_mov},

    /* 0xF8  fneg dst, src: negacion flotante */
    {"fneg", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fneg,
     decode_instr_simple_mov},

    /* 0xF9  fcvt gp, zmm: conversion int<->float entre bancos */
    {"fcvt", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fcvt,
     decode_instr_simple_mov},

    /* 0xFA  fmowi zmm_idx, imm64: carga inmediato IEEE 754 en registro ZMM */
    {"fmowi", Assembly::Bytecode::AddressingMode::INMED,
     Assembly::Bytecode::InstrSizeMode::FIXED_11, exec_instr_fmovi,
     decode_instr_fmowi},

    /* 0xFB  fload zmm_dst, gp_addr: carga flotante desde memoria VM */
    {"fload", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fload,
     decode_instr_two_op_reg},

    /* 0xFC  fstore gp_addr, zmm_src: almacena flotante en memoria VM */
    {"fstore", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_fstore,
     decode_instr_two_op_reg},

    /* 0xFD  callm r_obj, r_method: dispatch dinamico via MethodInfo* */
    {"callm", Assembly::Bytecode::AddressingMode::REG,
     Assembly::Bytecode::InstrSizeMode::FIXED_4, exec_instr_callm,
     decode_instr_two_op_reg},

    /* 0xFE  proceed: invoca target original de un AROUND (sin operandos) */
    {"proceed", Assembly::Bytecode::AddressingMode::NONE,
     Assembly::Bytecode::InstrSizeMode::FIXED_2, exec_instr_proceed,
     decode_instr_simple},

    /* 0xFF */
    {//
     "", Assembly::Bytecode::AddressingMode::COUNT,
     Assembly::Bytecode::InstrSizeMode::FIXED_1, nullptr, nullptr},
};
} // namespace runtime
