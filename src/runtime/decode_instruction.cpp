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
 * @file decode_instruction.cpp                                                \
 * @brief Implementacion del decodificador de instrucciones de VestaVM.        \
 *                                                                             \
 * Implementa la funcion principal de decodificacion que convierte bytes del   \
 * bytecode en estructuras DecodedInstr, resolviendo la tabla primaria y la    \
 * tabla extendida (prefijo 0x00) de instrucciones.                            \
 */                                                                            \
#include "ffi/native_ffi.h"
#include "runtime/decode_table.h"
#include "runtime/dispatch_table.h"
#include "runtime/runtime.h"
#include <cstdio> // debug temporal

// Activar con -DDEBUG_DECODE_PRINT para volcar cada instruccion descodificada
// #define DEBUG_DECODE_PRINT
#ifdef DEBUG_DECODE_PRINT
/**
 * @brief Imprime informacion de descodificacion de la instruccion en curso.
 *
 * Escribe por la salida de depuracion el PC, un mensaje, el nombre de la
 * instruccion y los argumentos variadicos adicionales.
 */
#define DBG_DECODE(PC, msg, Instr, ...)                                        \
    do {                                                                       \
        vesta::scout_decode()                                                  \
            << "[PC=" << std::setw(6) << (PC) << "] " << msg << " "            \
            << std::string(Instr) << " " << __VA_ARGS__ << std::endl;          \
    } while (0)

/**
 * @brief Vuelca en hexadecimal los @p size bytes a partir del PC actual.
 *
 * Lee los bytes de la memoria virtual del proceso y los imprime con
 * dump_memory(). Sale con codigo -1 si @p size supera 12 (limite de seguridad).
 */
#define DBG_DECODE_DUMP(vm, instr, size)                                       \
    do {                                                                       \
        if (size > 12) {                                                       \
            vesta::scout_decode() << "size(" << (uint64_t)size << ") > 10 ";   \
            exit(-1);                                                          \
        }                                                                      \
        uint8_t *exit_data = new uint8_t[size];                                \
        vm->vm_mem.read_bytes(vm->registers.rip.raw(), exit_data, size);       \
        vesta::scout_decode().dump_memory(exit_data, size);                    \
        vesta::scout_decode() << std::endl;                                    \
        delete[] exit_data;                                                    \
    } while (0)

#else
// En release ambos macros se reducen a no-ops para eliminar todo overhead
#define DBG_DECODE(PC, ...)                                                    \
    do {                                                                       \
    } while (0)
#define DBG_DECODE_DUMP(PC, ...)                                               \
    do {                                                                       \
    } while (0)
#endif

/**
 * @brief Devuelve la marca de tiempo actual en nanosegundos.
 *
 * Implementacion inline que usa CLOCK_MONOTONIC para medir intervalos de
 * tiempo de alta resolucion.  Solo se invoca cuando has_hooks esta activo
 * para evitar penalizacion en el hot-path de produccion.
 *
 * @return Tiempo monotono actual expresado en nanosegundos.
 */
inline uint64_t now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts); // leer reloj monotono del SO
    return (uint64_t)ts.tv_sec * 1000000000ULL +
           ts.tv_nsec; // convertir a nanosegundos totales
}

namespace runtime {
using clock = std::chrono::high_resolution_clock;

// -------------------------------------------------------------------------
// OOP - decodificador para instrucciones de la forma [reg1, imm8]
// Formato: [0x00][opcode][reg_byte][imm8]
//   reg_byte bits 3-0 -> reg1 (registro general)
//   imm8              -> reg2 (indice de vtable/campo/metodo, 0-255)
// -------------------------------------------------------------------------

/**
 * @brief Descodifica una instruccion OOP del tipo [reg, imm8].
 *
 * Lee el byte de registro y el inmediato de 8 bits situados en las
 * posiciones PC+2 y PC+3 respectivamente.  El nibble bajo del byte de
 * registro contiene el numero de registro general; el imm8 codifica el
 * indice de vtable, campo o metodo (rango 0-255).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_oop_reg_imm8(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = Assembly::Bytecode::instr_size(
        instr.metadata->size); // fijar longitud de instruccion

    // las instrucciones extendidas siempre tienen prefijo 0x00, por eso el
    // offset es +2
    uint64_t offset = vm->registers.rip.raw() + 2;
    uint16_t data =
        vm->vm_mem.read_u16(offset); // leer reg_byte e imm8 de una sola lectura

    uint8_t reg_byte =
        static_cast<uint8_t>(data & 0xFF); // byte 2: contiene el registro
    uint8_t imm8 = static_cast<uint8_t>((data >> 8) &
                                        0xFF); // byte 3: indice de vtable/campo

    instr.data_instruction.reg_data.reg1 =
        reg_byte & 0x0F; // bits 3-0 = numero de registro general
    instr.data_instruction.reg_data.reg2 =
        imm8; // 0-255 = indice de metodo o campo
}

/**
 * @brief Descodifica una instruccion con direccionamiento SIB.
 *
 * Lee 4 bytes tras los 2 bytes de opcode extendido y extrae los campos:
 *   - ctrl_byte: mode (2 bits), signed (1 bit), direction (1 bit), scale (2
 * bits), has_index (1 bit)
 *   - regs_byte: reg_final (nibble alto), reg_base (nibble bajo)
 *   - index_byte: reg_index (nibble bajo)
 *
 * La escala efectiva se codifica como scale | (has_index << 2) en
 * mem_data.scale para que el ejecutor pueda distinguir si existe un registro
 * indice.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_sib(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // fijar longitud

    // 4 bytes tras los 2 bytes de opcode: ctrl | regs | index | pad
    uint64_t offset = vm->registers.rip.raw() + 2;
    uint32_t data = vm->vm_mem.read_u32(offset); // lectura de bloque de 4 bytes

    uint8_t ctrl_byte =
        static_cast<uint8_t>(data & 0xFF); // byte de control SIB
    uint8_t regs_byte =
        static_cast<uint8_t>((data >> 8) & 0xFF); // registro base/final
    uint8_t index_byte =
        static_cast<uint8_t>((data >> 16) & 0xFF); // registro indice

    // extraer subcampos del byte de control
    instr.flags_info.mode = (ctrl_byte >> 6) & 0x3; // modo de acceso (tamano)
    instr.flags_info._signed_instruct =
        (ctrl_byte >> 5) & 0x1; // operacion con signo
    instr.flags_info.direction =
        (ctrl_byte >> 4) & 0x1; // direccion lectura/escritura
    uint8_t scale =
        (ctrl_byte >> 2) & 0x3; // escala del indice (0=x1,1=x2,2=x4,3=x8)
    uint8_t has_index = (ctrl_byte >> 1) & 0x1; // si hay registro indice

    // extraer registros de los bytes correspondientes
    instr.data_instruction.mem_data.reg_final =
        regs_byte >> 4; // nibble alto = registro destino/fuente
    instr.data_instruction.mem_data.reg_base =
        regs_byte & 0x0F; // nibble bajo = registro base
    instr.data_instruction.mem_data.reg_index =
        index_byte & 0x0F; // nibble bajo = registro indice
    // bits 1-0 de scale = escala real; bit 2 = has_index para indicar presencia
    // del indice
    instr.data_instruction.mem_data.scale = scale | (has_index << 2);
}

/**
 * @brief Descodifica una instruccion de dos operandos registro-registro.
 *
 * Cubre ADD, SUB, MUL, DIV, MOV y similares de la forma "OP reg1, reg2".
 * Lee 2 bytes tras el opcode: el primero contiene el modo (bits 7-6) y el
 * segundo contiene ambos registros codificados como nibble alto/bajo.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_two_op_reg(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = Assembly::Bytecode::instr_size(
        instr.metadata->size); // tamano constante

    // calcular offset al primer byte de datos segun si es opcode extendido o
    // primario
    uint64_t offset = vm->registers.rip.raw() +
                      ((instr.flags_info.is_not_extended != 0) ? 1 : 2);

    // leer los dos bytes de datos de la instruccion
    uint16_t data = vm->vm_mem.read_u16(offset);

    uint8_t n1 = static_cast<uint8_t>(data & 0x00FF); // byte de modo
    uint8_t n2 =
        static_cast<uint8_t>((data & 0xFF00) >> 8); // byte de registros

    // ctrl byte: mode(2) | signed(1) | dir(1) | reg(4)
    // Extraer mode, _signed_instruct y direction del byte de control.
    // Sin extraer el bit signed, las variantes con/sin signo
    // (cmpu/cmps, addu/adds, etc.) compartirian _signed_instruct con
    // el valor residual de la icache, llevando a semantica indefinida
    // en CF/OF.  Bug observado: cmpu r2(0), r3(3) tomaba la rama
    // erronea porque _signed_instruct quedaba a 1 -> SubOp::flags
    // entraba por la rama signed y dejaba CF=0 en lugar de CF=1.
    instr.flags_info.mode = (n1 >> 6) & 0b11; // ancho del operando
    instr.flags_info._signed_instruct =
        (n1 >> 5) & 0b1;                          // variante con/sin signo
    instr.flags_info.direction = (n1 >> 4) & 0b1; // direccion (reservado)

    // los dos registros se codifican en el mismo byte: nibble bajo = reg1,
    // nibble alto = reg2
    instr.data_instruction.reg_data.reg1 = static_cast<uint8_t>(n2 & 0xF);
    instr.data_instruction.reg_data.reg2 = static_cast<uint8_t>(n2 >> 4);

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " r" << (int)instr.data_instruction.reg_data.reg1 << ", "
                    << " r" << (int)instr.data_instruction.reg_data.reg2);

    DBG_DECODE_DUMP(vm, instr,
                    Assembly::Bytecode::instr_size(instr.metadata->size));
}

/**
 * @brief Descodifica instrucciones con codificacion de bytes crudos (string
 * ops, setcc, tryenter).
 *
 * A diferencia de decode_instr_two_op_reg, esta funcion almacena los bytes2 y
 * byte3 en bruto en reg1 y reg2, de modo que las instrucciones de strings
 * pueden extraer nibbles directamente: reg1 = byte2  (ctrl)  = (r_dst<<4) |
 * r_src reg2 = byte3  (extra) = (r3<<4) | ...
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_raw_bytes(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo

    uint64_t offset = vm->registers.rip.raw() +
                      ((instr.flags_info.is_not_extended != 0) ? 1 : 2);

    uint16_t data = vm->vm_mem.read_u16(offset);

    // almacenar byte2 y byte3 en bruto para que exec pueda extraer nibbles
    instr.data_instruction.reg_data.reg1 =
        static_cast<uint8_t>(data & 0x00FF); // byte2 crudo
    instr.data_instruction.reg_data.reg2 =
        static_cast<uint8_t>((data & 0xFF00) >> 8); // byte3 crudo

    DBG_DECODE(instr.pc, "Instruccion decode_raw_bytes: ", instr.metadata->name,
               " b2=" << std::hex << (int)instr.data_instruction.reg_data.reg1
                      << " b3=" << (int)instr.data_instruction.reg_data.reg2
                      << std::dec);
    DBG_DECODE_DUMP(vm, instr,
                    Assembly::Bytecode::instr_size(instr.metadata->size));
}

/**
 * @brief Descodifica una instruccion MOV registro-registro con byte de control.
 *
 * Similar a decode_instr_two_op_reg pero extrae ademas los campos
 * _signed_instruct y direction del byte de control para soportar las
 * variantes MOV con extension de signo y MOV con direccion inversa.
 *
 * Formato del byte de control (n1):
 *   bits 7-6 -> mode
 *   bit  5   -> signed (_signed_instruct)
 *   bit  4   -> direction
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_simple_mov(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // fijar longitud

    uint64_t offset = vm->registers.rip.raw() +
                      ((instr.flags_info.is_not_extended != 0) ? 1 : 2);
    uint16_t data =
        vm->vm_mem.read_u16(offset); // leer byte de control y byte de registros

    uint8_t n1 = static_cast<uint8_t>(data & 0x00FF); // byte de control
    uint8_t n2 =
        static_cast<uint8_t>((data & 0xFF00) >> 8); // byte de registros

    // ctrl byte: mode(2) | signed(1) | dir(1) | 0000
    instr.flags_info.mode = (n1 >> 6) & 0b11; // modo de acceso a memoria
    instr.flags_info._signed_instruct = (n1 >> 5) & 0b1; // extension de signo
    instr.flags_info.direction = (n1 >> 4) & 0b1; // direccion del movimiento

    // regs byte: reg2(4) | reg1(4)
    instr.data_instruction.reg_data.reg1 =
        static_cast<uint8_t>(n2 & 0xF); // nibble bajo = reg destino
    instr.data_instruction.reg_data.reg2 =
        static_cast<uint8_t>(n2 >> 4); // nibble alto = reg fuente

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " r" << (int)instr.data_instruction.reg_data.reg1 << ", "
                    << " r" << (int)instr.data_instruction.reg_data.reg2);
    DBG_DECODE_DUMP(vm, instr,
                    Assembly::Bytecode::instr_size(instr.metadata->size));
}

/**
 * @brief Descodifica una instruccion MOV con operando inmediato de longitud
 * variable.
 *
 * El byte de datos en PC+2 controla el modo, signo, direccion y numero de
 * registro. La longitud del inmediato depende del modo codificado (1/2/4/8
 * bytes).
 *
 * Caso especial: si direction==1 y signed==1, se usa un registro especial de 6
 * bits (combinando mode<<4 | reg) con un inmediato fijo de 64 bits.
 *
 * Formato del byte de datos (PC+2):
 *   bits 7-6 -> mode  (0=8b, 1=16b, 2=32b, 3=64b)
 *   bit  5   -> signed
 *   bit  4   -> direction
 *   bits 3-0 -> registro
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_inmed_mov(ProcessVM *vm, DecodedInstr &instr) {
    // leer el byte de metadatos en PC+2
    uint8_t data = vm->vm_mem[vm->registers.rip.raw() + 2];

    // leer 8 bytes del inmediato de golpe; se usaran 1, 2, 4 u 8 segun el modo
    uint64_t inmed = vm->vm_mem.read_u64(vm->registers.rip.raw() + 3);

    // extraer los campos del byte de datos
    instr.flags_info.mode =
        (data >> 6) & 0b11; // bits 7-6: modo (tamano del inmediato)
    instr.flags_info._signed_instruct =
        (data >> 5) & 0b1; // bit 5: operacion con signo
    instr.flags_info.direction =
        (data >> 4) & 0b1; // bit 4: direccion del movimiento
    instr.data_instruction.inmmed_data.reg =
        data & 0b1111; // bits 3-0: numero de registro

    // caso especial: direction=1 y signed=1 -> registro especial de 6 bits con
    // inmediato de 64 bits
    if (instr.flags_info.direction == 1 &&
        instr.flags_info._signed_instruct == 1) {
        instr.data_instruction.inmmed_data.inmmed =
            inmed; // guardar inmediato de 64 bits

        // 2 bytes opcode + 1 byte datos + 8 bytes inmediato = 11 bytes totales
        instr.flags_info.size_instr = 2 + 1 + 8;
        instr.flags_info.reg_ext =
            true; // indicar que usa un registro extendido especial

        // combinar mode (bits adicionales) con reg para formar el codigo de 6
        // bits del registro especial
        instr.data_instruction.inmmed_data.reg =
            instr.flags_info.mode << 4 | instr.data_instruction.inmmed_data.reg;

        DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
                   " " << regs_special[instr.data_instruction.inmmed_data.reg]
                       << ", "
                       << (uint64_t)instr.data_instruction.inmmed_data.inmmed);
        DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);

        return; // salir: el resto del codigo solo aplica a la descodificacion
                // convencional
    }

    /**
     * Longitud variable: 3 bytes fijos (2 opcode + 1 datos) mas la longitud del
     * inmediato que depende del modo codificado.
     */
    instr.flags_info.size_instr =
        3 + Assembly::Bytecode::mode_to_bytes(instr.flags_info.mode);

    // recortar el inmediato leido al numero de bytes que corresponde al modo
    switch (instr.flags_info.mode) {
    case 0b00:
        instr.data_instruction.inmmed_data.inmmed = (uint8_t)inmed;
        break; //  8 bits
    case 0b01:
        instr.data_instruction.inmmed_data.inmmed = (uint16_t)inmed;
        break; // 16 bits
    case 0b10:
        instr.data_instruction.inmmed_data.inmmed = (uint32_t)inmed;
        break; // 32 bits
    default:
        instr.data_instruction.inmmed_data.inmmed = inmed;
        break; // 64 bits
    }

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " r" << (int)instr.data_instruction.inmmed_data.reg << ", "
                    << (uint64_t)instr.data_instruction.inmmed_data.inmmed);
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion de un solo byte sin operandos relevantes.
 *
 * Simplemente fija size_instr a partir de los metadatos de la tabla de
 * descodificacion y emite el volcado de depuracion si esta activo.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_simple(ProcessVM *vm, DecodedInstr &instr) {
    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name, "");
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion de un solo registro (INC/DEC y similares).
 *
 * Verifica que la instruccion tiene exactamente 2 bytes de longitud.
 * El unico byte de datos codifica mode (bits 5-4), la variante INC/DEC
 * (bit 6) y el numero de registro (bits 3-0).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_one_op_reg(ProcessVM *vm, DecodedInstr &instr) {
    VM_ASSERT(
        instr_size(instr.metadata->size) == 2,
        std::string(
            "VM::decode_instr_one_op_reg() Instruccion invalida en RIP[") +
                vesta::hex64(vm->registers.rip.raw()) + "] opcode1(" +
                vesta::hex64(instr.flags_info.is_not_extended) + ") opcode2(" +
                vesta::hex64(instr.flags_info.opcode_index) + ")\n"
            << "decode_instr_one_op_reg() Error la instruccion encontrada no "
               "tiene size 2 sino un size: "
            << instr_size(instr.metadata->size) << "\n",
        {
            vesta::scout() << vesta::dump(vm->vm_mem, vm->registers.rip.raw(),
                                          64)
                           << std::endl;
        });
    instr.flags_info.size_instr = Assembly::Bytecode::instr_size(
        instr.metadata->size); // tamano siempre 2

    // leer el unico byte de datos (byte opcode+1)
    uint8_t data = vm->vm_mem[vm->registers.rip.raw() + 1];

    // bits 5-4: modo de acceso (tamano del operando)
    instr.flags_info.mode = (data >> 4) & 0b11;

    // bit 6: 0 = INC, 1 = DEC
    instr.flags_info._signed_instruct = (data >> 6) & 0b1;

    // bits 3-0: numero de registro a operar
    instr.data_instruction.reg_data.reg1 = static_cast<uint8_t>(data & 0xF);

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " r" << (int)instr.data_instruction.reg_data.reg1);
    DBG_DECODE_DUMP(vm, instr,
                    Assembly::Bytecode::instr_size(instr.metadata->size));
}

/**
 * @brief Descodifica una instruccion MOVC o MOVCH de acceso a memoria (4
 * bytes).
 *
 * Formato: [0x00][0x1E][ctrl][byte4]
 *   ctrl: host(2 bits) | direction(1 bit) | reg1(4 bits)
 *     bits 7-6 == 0b10 -> MOVCH (acceso a memoria del host)
 *     bits 7-6 == 0b00 -> MOVC  (acceso a memoria virtual de la VM)
 *   byte4: flag_code(3 bits en bits 7-5) | reg2(5 bits)
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_movc(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // MOVC/MOVCH es siempre de 4 bytes

    uint64_t base = vm->registers.rip.raw() + 2; // offset al byte de control
    uint8_t ctrl = vm->vm_mem[base];   // byte de control de la instruccion
    uint8_t b4 = vm->vm_mem[base + 1]; // cuarto byte: codigo de flag y reg2

    // bits 7-6 del ctrl: 0b10 = MOVCH (host), 0b00 = MOVC (vm)
    uint8_t host_bits = (ctrl >> 6) & 0b11;
    instr.flags_info._signed_instruct =
        (host_bits == 0b10) ? 1 : 0;                // 1 = modo host
    instr.flags_info.direction = (ctrl >> 5) & 0b1; // bit 5: direccion
    instr.flags_info.mode = 3; // siempre qword para movimientos de registro
    instr.data_instruction.reg_data.reg1 =
        ctrl & 0xF; // nibble bajo ctrl = reg1 (destino o fuente)
    instr.data_instruction.reg_data.reg2 =
        (b4 >> 5) & 0x7; // bits 7-5 de byte4 = codigo de flag
    instr.data_instruction.inmmed_data.reg =
        b4 & 0x1F; // bits 4-0 de byte4 = reg2
}

/**
 * @brief Descodifica una instruccion PUSH o POP.
 *
 * Verifica que la instruccion tiene 2 bytes.  El byte de datos distingue
 * entre registro general y registro especial mediante el bit 6:
 *   - bit 6 == 0 -> registro general: mode (bits 5-4), reg (bits 3-0)
 *   - bit 6 == 1 -> registro especial: codigo de 6 bits (bits 5-0)
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_push_pop(ProcessVM *vm, DecodedInstr &instr) {
    VM_ASSERT(instr_size(instr.metadata->size) == 2,
              std::string(
                  "VM::decode_instr_push_pop() Instruccion invalida en RIP[") +
                      vesta::hex64(vm->registers.rip.raw()) + "] opcode1(" +
                      vesta::hex64(instr.flags_info.is_not_extended) +
                      ") opcode2(" +
                      vesta::hex64(instr.flags_info.opcode_index) + ")\n"
                  << "decode_instr_push_pop() Error la instruccion encontrada "
                     "no tiene size 2 sino un size: "
                  << instr_size(instr.metadata->size) << "\n",
              {
                  vesta::scout()
                      << vesta::dump(vm->vm_mem, vm->registers.rip.raw(), 64)
                      << std::endl;
              });
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // siempre 2 bytes

    // leer el unico byte de datos tras el opcode
    uint8_t data = vm->vm_mem[vm->registers.rip.raw() + 1];

    // bit 6: indica si el operando es un registro especial
    uint8_t reg_ext = (data >> 6) & 0b1;
    instr.flags_info.reg_ext = reg_ext;

    if (reg_ext == 1) {
        // REGISTRO ESPECIAL: codigo de 6 bits en bits 5-0
        uint8_t reg_code = data & 0b00111111; // bits 0..5
        instr.data_instruction.reg_data.reg1 = reg_code;
        instr.flags_info.mode =
            0; // modo no aplicable para registros especiales
    } else {
        // REGISTRO GENERAL: modo en bits 5-4, codigo de registro en bits 3-0
        uint8_t mode = (data >> 4) & 0b11; // bits 4..5 = modo
        uint8_t reg_code = data & 0b1111;  // bits 0..3 = registro

        instr.flags_info.mode = mode;
        instr.data_instruction.reg_data.reg1 = reg_code;
    }

    instr.flags_info.size_instr = 2; // confirmar longitud fija
    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " r" << (int)instr.data_instruction.reg_data.reg1);
    DBG_DECODE_DUMP(vm, instr,
                    Assembly::Bytecode::instr_size(instr.metadata->size));
}

/**
 * @brief Descodifica una instruccion ALU con inmediato de longitud variable y
 * registro.
 *
 * Esta funcion solo aplica a instrucciones de la tabla extendida (prefijo
 * 0x00). El byte de datos en PC+2 codifica modo, signo, direccion y registro.
 * El campo direction indica si el inmediato opera sobre el registro
 * directamente o sobre la memoria apuntada por dicho registro.
 *
 * Formato del byte de datos (PC+2):
 *   bits 7-6 -> mode   (0=8b, 1=16b, 2=32b, 3=64b)
 *   bit  5   -> signed
 *   bit  4   -> direction (0=reg, 1=[reg])
 *   bits 3-0 -> numero de registro
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_inmed_reg(ProcessVM *vm, DecodedInstr &instr) {
    VM_ASSERT(instr.flags_info.is_not_extended == false,
              std::string(
                  "VM::decode_instr_inmed_reg() Instruccion invalida en RIP[") +
                      vesta::hex64(vm->registers.rip.raw()) + "] opcode1(" +
                      vesta::hex64(instr.flags_info.is_not_extended) +
                      ") opcode2(" +
                      vesta::hex64(instr.flags_info.opcode_index) + ")\n"
                  << "decode_instr_inmed_reg() instr.is_not_extended == false "
                  << "Error la instruccion encontrada deberia usar extension "
                     "de signo pero no lo hace por algun motivo: "
                  << std::to_string(instr.flags_info.is_not_extended) << "\n",
              {
                  vesta::scout()
                      << vesta::dump(vm->vm_mem, vm->registers.rip.raw(), 64)
                      << std::endl;
              });

    /**
     * Byte de datos en PC+2 con el siguiente layout de campos:
     *   0b mm s d rrrr
     *      |  | | +--- reg   (4 bits): numero de registro
     *      |  | +----- d     (1 bit):  direccion (0=reg, 1=[reg])
     *      |  +------- s     (1 bit):  signo
     *      +----------- mode (2 bits): tamano del inmediato
     */
    uint8_t data = vm->vm_mem[vm->registers.rip.raw() + 2]; // byte de control

    // leer 8 bytes del inmediato; se recortaran al modo elegido
    uint64_t inmed = vm->vm_mem.read_u64(vm->registers.rip.raw() + 3);

    /**
     * direction=0: opera sobre el registro        (adds reg, 0x1000)
     * direction=1: opera sobre la memoria de reg  (adds [reg], 0x1000)
     */
    instr.flags_info.mode =
        (data >> 6) & 0b11; // bits 7-6: modo (tamano inmediato)
    instr.flags_info._signed_instruct = (data >> 5) & 0b1; // bit 5: signo
    instr.flags_info.direction = (data >> 4) & 0b1; // bit 4: modo de acceso
    instr.data_instruction.inmmed_data.reg =
        data & 0b1111; // bits 3-0: registro

    /**
     * Longitud variable: 3 bytes fijos (2 opcode + 1 datos) mas la longitud del
     * inmediato segun el modo codificado en los bits 7-6 del byte de datos.
     */
    instr.flags_info.size_instr =
        3 + Assembly::Bytecode::mode_to_bytes(instr.flags_info.mode);

    // recortar el inmediato leido al numero de bytes que corresponde al modo
    switch (instr.flags_info.mode) {
    case 0b00:
        instr.data_instruction.inmmed_data.inmmed = (uint8_t)inmed;
        break; //  8 bits
    case 0b01:
        instr.data_instruction.inmmed_data.inmmed = (uint16_t)inmed;
        break; // 16 bits
    case 0b10:
        instr.data_instruction.inmmed_data.inmmed = (uint32_t)inmed;
        break; // 32 bits
    default:
        instr.data_instruction.inmmed_data.inmmed = inmed;
        break; // 64 bits
    }

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " r" << (int)instr.data_instruction.reg_data.reg1 << ", "
                    << (uint64_t)instr.data_instruction.inmmed_data.inmmed);
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion XCHG con operandos mixtos (general o
 * especial).
 *
 * Lee 2 bytes tras el prefijo 0x00 y el opcode (offset PC+2).
 * Cada byte codifica un operando: bits 5-0 = codigo de registro,
 * bit 6 = flag que indica si es registro especial (1) o general (0).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_xchg(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo

    // leer los 2 bytes de datos saltando el opcode extendido (PC+2)
    uint16_t data = vm->vm_mem.read_u16(vm->registers.rip.raw() + 2);

    auto byte1 = static_cast<uint8_t>(data & 0xFF); // byte del primer operando
    auto byte2 = static_cast<uint8_t>(data >> 8);   // byte del segundo operando

    // bits 5-0 = codigo de registro, bit 6 = flag de tipo (0=general,
    // 1=especial)
    instr.data_instruction.regs_data_extent.reg1 =
        byte1 & 0b11'1111; // codigo registro 1
    instr.data_instruction.regs_data_extent.reg1_flags =
        byte1 >> 6 & 0b1; // tipo registro 1
    instr.data_instruction.regs_data_extent.reg2 =
        byte2 & 0b11'1111; // codigo registro 2
    instr.data_instruction.regs_data_extent.reg2_flags =
        byte2 >> 6 & 0b1; // tipo registro 2

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name, "");
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion de lectura/escritura de registros cursor.
 *
 * Lee 2 bytes tras los 2 bytes de opcode extendido (offset PC+2).
 * El byte de control codifica el modo de acceso (bits 7-6) y el indice
 * del cursor (bits 5-4).  El segundo byte contiene el numero de registro
 * general (nibble bajo).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_cursor_rw(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo

    // los 2 bytes de datos empiezan tras los 2 bytes de opcode extendido
    uint64_t offset = vm->registers.rip.raw() + 2;
    uint16_t data =
        vm->vm_mem.read_u16(offset); // leer byte de control y byte de registro

    uint8_t ctrl = static_cast<uint8_t>(data & 0x00FF); // byte de control
    uint8_t reg =
        static_cast<uint8_t>((data & 0xFF00) >> 8); // byte de registro general

    // ctrl_byte: bits 7-6 = mode (tamano del acceso), bits 5-4 = indice del
    // cursor (0-3)
    instr.flags_info.mode = (ctrl >> 6) & 0b11; // modo de acceso
    instr.data_instruction.reg_data.reg2 =
        (ctrl >> 4) & 0b11; // indice del cursor destino/fuente
    instr.data_instruction.reg_data.reg1 =
        reg & 0xF; // numero del registro general

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name, "");
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica ADDCUR: avance/retroceso del cursor por inmediato con
 * signo.
 *
 * Formato (FIXED_6): [0x00][0xC3][ctrl][pad][imm_lo][imm_hi]
 *   ctrl bits 5-4: cur_idx (0-3).
 *   imm16: desplazamiento con signo (little-endian, bytes 4-5).
 *
 * El inmediato se almacena en los bytes 2-3 del campo raw_data.raw1 para
 * que sea accesible desde exec_instr_addcur sin un campo adicional en el
 * union DecodedInstr.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_addcur(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // 6 bytes

    // leer los 4 bytes de datos (bytes 2-5 de la instruccion)
    uint64_t offset = vm->registers.rip.raw() + 2;
    uint32_t data32 = vm->vm_mem.read_u32(offset);

    uint8_t ctrl = static_cast<uint8_t>(data32 & 0xFF); // byte 2: ctrl
    // byte 3 (bits 8-15): padding, se ignora
    int16_t imm16 = static_cast<int16_t>(
        (data32 >> 16) & 0xFFFF); // bytes 4-5: inmediato con signo

    // cur_idx en reg2 (patron identico a decode_instr_cursor_rw)
    instr.data_instruction.reg_data.reg2 = (ctrl >> 4) & 0x3;

    // almacenar imm16 en los bytes 2-3 de raw_data.raw1 (superpuestos con el
    // union)
    auto *raw =
        reinterpret_cast<uint8_t *>(&instr.data_instruction.raw_data.raw1);
    raw[2] = static_cast<uint8_t>(imm16 & 0xFF);
    raw[3] = static_cast<uint8_t>((imm16 >> 8) & 0xFF);

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name, "");
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica VMCOPY / VCOPYH: copia entre VM memory y host memory
 * (cursor).
 *
 * Formato compartido (FIXED_4): [0x00][0xC4 o 0xC5][byte_A][byte_B]
 *   byte_A bits 5-4: cur_idx (0-3).
 *   byte_A bits 3-0: rSrc o rDst (registro VM).
 *   byte_B bits 7-4: rLen (registro de longitud).
 *
 * Los tres operandos se almacenan en mem_data para mantener coherencia
 * con las instrucciones SIB que ya usan ese campo para base/index/final.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_vmcopy(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // 4 bytes

    uint64_t offset = vm->registers.rip.raw() + 2;
    uint16_t data16 = vm->vm_mem.read_u16(offset);

    uint8_t byte_A =
        static_cast<uint8_t>(data16 & 0xFF); // primer byte de datos
    uint8_t byte_B =
        static_cast<uint8_t>((data16 >> 8) & 0xFF); // segundo byte de datos

    instr.data_instruction.mem_data.reg_final =
        (byte_A >> 4) & 0x3; // cur_idx (2 bits)
    instr.data_instruction.mem_data.reg_base =
        byte_A & 0xF; // rSrc/rDst (4 bits)
    instr.data_instruction.mem_data.reg_index =
        (byte_B >> 4) & 0xF; // rLen (4 bits)

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name, "");
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion de salto absoluto (10 bytes fijos).
 *
 * Formato: [opcode][cond_o_reservado][8 bytes addr] = 10 bytes (FIXED_10).
 * El campo reg del inmediato almacena la condicion de salto y el campo
 * inmmed guarda la direccion absoluta de destino.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_jump(ProcessVM *vm, DecodedInstr &instr) {
    // [opcode][cond_o_reservado][8 bytes addr] = 10 bytes (FIXED_10, opcode
    // primario)
    instr.data_instruction.inmmed_data.reg =
        vm->vm_mem[vm->registers.rip.raw() + 1]; // codigo de condicion
    instr.data_instruction.inmmed_data.inmmed = vm->vm_mem.read_u64(
        vm->registers.rip.raw() + 2); // direccion absoluta de destino
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo

    VM_ASSERT(instr.metadata->size <= Assembly::Bytecode::InstrSizeMode::COUNT,
              "Instruccion con longitud no encontrada: "
                  << (int)Assembly::Bytecode::InstrSizeMode::COUNT,
              exit(-1););

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               "[" << (int)instr.data_instruction.inmmed_data.reg << "] "
                   << (uint64_t)instr.data_instruction.inmmed_data.inmmed);
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion sin operandos.
 *
 * Fija size_instr a partir de los metadatos y emite el volcado de
 * depuracion.  Usada por instrucciones como NOP, RET, HALT, etc.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_no_operands(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = Assembly::Bytecode::instr_size(
        instr.metadata->size); // tamano segun tabla
    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name, "");
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion de salto relativo (FIXED_8 extendido).
 *
 * Formato: [0x00][0x2D][cond][padding][disp32] (8 bytes totales).
 * El desplazamiento de 32 bits se lee en little-endian desde PC+4 y se
 * extiende con signo a 64 bits para soportar saltos hacia atras.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_jrel(ProcessVM *vm, DecodedInstr &instr) {
    // [0x00][0x2D][cond][padding][disp32] - extended FIXED_8
    instr.data_instruction.inmmed_data.reg =
        vm->vm_mem[vm->registers.rip.raw() + 2]; // byte de condicion
    uint32_t raw_disp = 0;
    vm->vm_mem.read_bytes(vm->registers.rip.raw() + 4, &raw_disp,
                          4); // leer desplazamiento de 32 bits
    // extension de signo: int32 -> int64 -> uint64 para preservar el signo en
    // la aritmetica de punteros
    instr.data_instruction.inmmed_data.inmmed = static_cast<uint64_t>(
        static_cast<int64_t>(static_cast<int32_t>(raw_disp)));
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // 8 bytes fijos

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               "[" << (int)instr.data_instruction.inmmed_data.reg << "] "
                   << (uint64_t)instr.data_instruction.inmmed_data.inmmed);
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica una instruccion de llamada a funcion nativa (CALLN).
 *
 * Lee la direccion de la funcion nativa desde PC+2 (8 bytes).  El numero
 * de argumentos (argc) se cachea directamente desde R15 en la fase de
 * descodificacion para que tanto el puntero de funcion como argc esten
 * disponibles desde la icache; esto permite al predictor de saltos de la
 * CPU nativa predecir correctamente el switch(argc) tras la primera
 * ejecucion del mismo PC.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
/**
 * @brief Descodifica JUMPTABLE / TYPESWITCH (3 operandos en 2 bytes, FIXED_4).
 *
 * Formato: [0x00][opcode2][byte2][byte3]
 *   byte2 bits 7-4 = r_val/r_obj, bits 3-0 = r_table.
 *   byte3          = count (numero de entradas).
 * Almacena en mem_data: reg_base=r_val, reg_index=r_table, scale=count.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion descodificada que se rellena.
 */
void decode_instr_jumptable(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;             // FIXED_4
    uint64_t base = vm->registers.rip.raw() + 2; // saltar opcode1 + opcode2
    uint8_t b2 = vm->vm_mem[base];     // byte empaquetado: r_val|r_table
    uint8_t b3 = vm->vm_mem[base + 1]; // count
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F; // r_val/r_obj
    instr.data_instruction.mem_data.reg_index = b2 & 0x0F;       // r_table
    instr.data_instruction.mem_data.scale = b3;                  // count
}

void decode_instr_three_reg(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // FIXED_4: opcode1 + opcode2 + b2 + b3
    uint64_t base = vm->registers.rip.raw() + 2; // saltar opcode1 + opcode2
    uint8_t b2 = vm->vm_mem[base];               // (r_pid<<4) | r_addr
    uint8_t b3 = vm->vm_mem[base + 1];           // (r_len<<4) | 0
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F;  // r_pid
    instr.data_instruction.mem_data.reg_index = b2 & 0x0F;        // r_addr
    instr.data_instruction.mem_data.reg_final = (b3 >> 4) & 0x0F; // r_len
}

// Descodificador de 4 regs empacados en FIXED_4: 4 nibbles en 2 bytes.
//   byte2 (rip+2) = (r0 << 4) | r1
//   byte3 (rip+3) = (r2 << 4) | r3
// Util para atomiccas: r0=dst, r1=addr, r2=expected, r3=desired.
void decode_instr_four_reg(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    uint8_t b3 = vm->vm_mem[base + 1];
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F;  // r0
    instr.data_instruction.mem_data.reg_index = b2 & 0x0F;        // r1
    instr.data_instruction.mem_data.reg_final = (b3 >> 4) & 0x0F; // r2
    instr.data_instruction.mem_data.scale = b3 & 0x0F;            // r3
}

// Atomicos RMW width-aware (atomicadd/atomiccas, FIXED_6): igual que four_reg
// pero con un ctrl-byte DELANTE que porta el mode (ancho 8/16/32/64).  Layout:
//   [0x00][op][ctrl=mode<<6][b2=(base<<4)|index][b3=(final<<4)|scale][pad].
void decode_instr_atomic_rmw(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 6; // FIXED_6
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t ctrl = vm->vm_mem[base];
    uint8_t b2 = vm->vm_mem[base + 1];
    uint8_t b3 = vm->vm_mem[base + 2];
    instr.flags_info.mode = (ctrl >> 6) & 0x3; // ancho: 0=8b 1=16b 2=32b 3=64b
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F;  // dst
    instr.data_instruction.mem_data.reg_index = b2 & 0x0F;        // addr
    instr.data_instruction.mem_data.reg_final = (b3 >> 4) & 0x0F; // exp/delta
    instr.data_instruction.mem_data.scale = b3 & 0x0F;            // des/0
}

/**
 * @brief Descodificador de @c getstatic / @c setstatic (FIXED_8).
 *
 * Layout fisico desde @c rip+2 (post-prefijo extendido):
 *   byte 0 (rip+2): regs_byte = (r0 << 4) | r1
 *   byte 1 (rip+3): _pad8 (reservado, debe ser 0)
 *   bytes 2-5     : offset uint32 little-endian
 *
 * Para getstatic: r0=r_dst, r1=r_class.
 * Para setstatic: r0=r_class, r1=r_value.
 */
void decode_instr_static_offset(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        8; // FIXED_8: prefix(2) + regs(1) + pad(1) + offset(4)
    uint64_t base = vm->registers.rip.raw() + 2;     // saltar opcode1 + opcode2
    uint8_t regs_byte = vm->vm_mem[base];            // (r0<<4) | r1
    uint32_t offset = vm->vm_mem.read_u32(base + 2); // bytes 4-7 absolutos
    instr.data_instruction.static_data.r0 = (regs_byte >> 4) & 0x0F;
    instr.data_instruction.static_data.r1 = regs_byte & 0x0F;
    instr.data_instruction.static_data.offset = offset;
}

/**
 * @brief Descodificador de @c mld / @c mst (load/store universal, FIXED_8).
 *
 * Layout desde @c rip+2: @c [ctrl][basef][regs][disp16 LE][pad].
 *   ctrl : [7]=host [6:4]=width_code(->1/2/4/8/16/32/64B) [3]=has_index
 * [2:0]=scale basef: [7]=bank(GP/FP) [6]=idx_sub [5]=sign_ext [4:0]=base(0-17)
 *   regs : [7:4]=dst/src [3:0]=index
 * Pre-decodifica todo a @c mem_full para que el exec sea minimo (el decode se
 * cachea; el coste real es de ejecucion).
 */
void decode_instr_mem_full(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 8; // FIXED_8
    // Una sola lectura de 8 bytes (la instruccion entera) en vez de 5 accesos
    // byte a byte -> 1 lookup TLB/pagina.  Layout de raw (LE):
    //   b0=0x00 b1=op2 b2=ctrl b3=basef b4=regs b5=disp_lo b6=disp_hi b7=pad
    const uint64_t raw = vm->vm_mem.read_u64(vm->registers.rip.raw());
    const uint8_t ctrl = static_cast<uint8_t>(raw >> 16);
    const uint8_t basef = static_cast<uint8_t>(raw >> 24);
    const uint8_t regs = static_cast<uint8_t>(raw >> 32);
    const int16_t disp = static_cast<int16_t>(raw >> 40);
    auto &m = instr.data_instruction.mem_full;
    m.width = static_cast<uint8_t>(1u << ((ctrl >> 4) & 0x07)); // 1..64 bytes
    m.scale = ctrl & 0x07;                                      // shift 0..6
    m.base = basef & 0x1F;                                      // 0..17
    m.index = regs & 0x0F;
    m.reg = (regs >> 4) & 0x0F;
    m.disp = disp;
    uint8_t f = 0;
    if (ctrl & 0x80) f |= 0x01;  // host
    if (ctrl & 0x08) f |= 0x02;  // has_index
    if (basef & 0x40) f |= 0x04; // idx_sub
    if (basef & 0x20) f |= 0x08; // sign_ext
    if (basef & 0x80) f |= 0x10; // bank (FP/ZMM)
    m.flags = f;
}

/**
 * @brief Decoder compartido para @c dlopen (3 regs) y @c dlsym (4 regs).
 *
 * Lee 2 bytes desde @c rip+2 y los desempaqueta en 4 nibbles que se
 * almacenan en @c mem_data (reg_base, reg_index, reg_final, scale).
 */
void decode_instr_dlopen_dlsym(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // FIXED_4: prefix(2) + b2 + b3
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    uint8_t b3 = vm->vm_mem[base + 1];
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F; // r_dst
    instr.data_instruction.mem_data.reg_index =
        b2 & 0x0F; // rB (path_addr / handle)
    instr.data_instruction.mem_data.reg_final =
        (b3 >> 4) & 0x0F; // rC (path_len / name_addr)
    instr.data_instruction.mem_data.scale =
        b3 & 0x0F; // rD (solo dlsym: name_len)
}

/**
 * @brief Decoder de @c callni (FIXED_4, 1 registro en byte2 hi-nibble).
 */
void decode_instr_callni(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // FIXED_4: prefix(2) + b2 + b3
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    instr.data_instruction.reg_data.reg1 = (b2 >> 4) & 0x0F; // r_fn
    instr.data_instruction.reg_data.reg2 = 0;                // sin uso
}

/**
 * @brief Decoder de @c gcallocp (FIXED_4, 2 regs en byte2).
 * Layout: [0x00][0x65][b2][0x00] con b2 = (r_dst<<4) | r_size.
 * Aloca en GcHeap y deposita host_ptr al payload directo en r_dst.
 */
void decode_instr_gcallocp(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    instr.data_instruction.reg_data.reg1 = (b2 >> 4) & 0x0F; // r_dst
    instr.data_instruction.reg_data.reg2 = b2 & 0x0F;        // r_size
}

/**
 * @brief Decoder de @c spawnargs (FIXED_4, 1 reg en byte2 hi-nibble).
 * Layout: [0x00][0x66][b2][0x00] con b2 = (r_pc<<4).  argc se lee de R15.
 */
void decode_instr_spawnargs(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    instr.data_instruction.reg_data.reg1 = (b2 >> 4) & 0x0F; // r_pc
    instr.data_instruction.reg_data.reg2 = 0;
}

/**
 * @brief Decoder de @c fulfillhlt (FIXED_4, 2 regs en byte2).
 * Layout: [0x00][0x67][b2][0x00] con b2 = (r_fut<<4) | r_value.
 */
void decode_instr_fulfillhlt(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    instr.data_instruction.reg_data.reg1 = (b2 >> 4) & 0x0F; // r_fut
    instr.data_instruction.reg_data.reg2 = b2 & 0x0F;        // r_value
}

/**
 * @brief Decoder de @c cmpjmp / @c cmpjmpu (FIXED_8).
 * Layout: [0x00][0x68|0x69][b2][cond][target_u32_LE]
 *   static_data.r0     = r_a
 *   static_data.r1     = r_b
 *   static_data._pad   = cond_byte (0x00..0x0D)
 *   static_data.offset = target u32
 */
void decode_instr_cmpjmp(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 8;
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    uint8_t cond = vm->vm_mem[base + 1];
    instr.data_instruction.static_data.r0 = (b2 >> 4) & 0x0F;
    instr.data_instruction.static_data.r1 = b2 & 0x0F;
    instr.data_instruction.static_data._pad = static_cast<uint16_t>(cond);
    instr.data_instruction.static_data.offset = vm->vm_mem.read_u32(base + 2);
}

/**
 * @brief Decoder de @c decjnz (FIXED_8, 1 reg + target).
 * Layout: [0x00][0x6A][b2][0x00][target_u32_LE]
 *   static_data.r0     = r_counter
 *   static_data.offset = target u32
 */
void decode_instr_decjnz(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 8;
    uint64_t base = vm->registers.rip.raw() + 2;
    uint8_t b2 = vm->vm_mem[base];
    instr.data_instruction.static_data.r0 = (b2 >> 4) & 0x0F;
    instr.data_instruction.static_data.r1 = 0;
    instr.data_instruction.static_data._pad = 0;
    instr.data_instruction.static_data.offset = vm->vm_mem.read_u32(base + 2);
}

/**
 * @brief Descodifica @c fastpush / @c fastpop (extended 0x6B / 0x6C, FIXED_4).
 *
 * Layout fisico: [0x00][opcode2][mask_lo][mask_hi]
 * Bytes [rip+2..rip+3] forman el mask uint16 little-endian.
 */
void decode_instr_fastmask(ProcessVM *vm, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    const uint64_t base = vm->registers.rip.raw() + 2;
    const uint8_t lo = vm->vm_mem[base];
    const uint8_t hi = vm->vm_mem[base + 1];
    instr.data_instruction.mask_data.mask =
        static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " mask=0x" << std::hex
                          << (unsigned)instr.data_instruction.mask_data.mask
                          << std::dec);
}

void decode_instr_calln(ProcessVM *vm, DecodedInstr &instr) {
    instr.data_instruction.inmmed_data.inmmed = vm->vm_mem.read_u64(
        vm->registers.rip.raw() + 2); // direccion de la funcion nativa

    // tamano de la instruccion para luego incrementar rip tras la ejecucion
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size);

    // argc se cachea en decode para que exec pueda obtenerlo sin acceder a
    // registros: al ser constante por PC, el IBP de la CPU predecira bien el
    // switch(argc) tras la primera ejecucion
    instr.data_instruction.inmmed_data.reg =
        static_cast<uint64_t>(vm->registers.regs[R15].qword());
    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               "[" << (int)instr.data_instruction.inmmed_data.reg << "] "
                   << (uint64_t)instr.data_instruction.inmmed_data.inmmed);
    DBG_DECODE_DUMP(vm, instr, instr.flags_info.size_instr);
}

/**
 * @brief Descodifica la instruccion apuntada por el RIP del proceso.
 *
 * Implementa un ciclo de descodificacion con icache de un nivel:
 *   - HIT:  si icache[PC % ICACHE_SIZE].pc == PC se reutiliza la entrada
 * existente.
 *   - MISS: se selecciona la tabla de descodificacion (primaria o extendida),
 *           se obtienen los metadatos, se llama al metodo decode() de la
 * instruccion y se guarda el resultado en la icache.
 *
 * Si has_hooks esta activo se acumula el tiempo de descodificacion en
 * scheduler.time_decode y se llaman los hooks de DebugStage::DecodeBegin/End.
 *
 * @param process Proceso virtual cuyo RIP apunta a la instruccion a
 * descodificar.
 */
/**
 * @brief Elige los metadatos de una instruccion por sus dos primeros
 * bytes.
 *
 * Lo comparten la descodificacion normal y la que solo MIRA: sin
 * compartirlo,
 * el dia que se anada una tabla o cambie el prefijo, una de las
 * dos se queda
 * atras -- y seria la de mirar, que es la que casi nadie
 * ejecuta.
 *
 * @param b0 Primer byte (0x00 = tabla extendida).
 * @param b1
 * Segundo byte, solo si el primero es 0x00.
 * @return Los metadatos, o @c
 * nullptr si la instruccion no es utilizable.
 */
static InstrFormat *select_metadata(uint8_t b0, uint8_t b1) {
    InstrFormat *table = decode_table_primary;
    uint8_t index = b0;
    if (b0 == 0x00) {
        table = decode_table_extended;
        index = b1;
    }
    InstrFormat &m = table[index];
    if (m.exec == nullptr || m.decode == nullptr ||
        m.mode >= Assembly::Bytecode::AddressingMode::COUNT)
        return nullptr;
    return &m;
}

bool decode_peek(ProcessVM *process, uint64_t pc, DecodedInstr &out) {
    if (process == nullptr) return false;
    out = DecodedInstr{};
    out.pc = pc;
    out.flags_info.is_not_extended = process->vm_mem[pc];
    if (out.flags_info.is_not_extended == 0x00)
        out.flags_info.opcode_index = process->vm_mem[pc + 1];

    InstrFormat *m = select_metadata(out.flags_info.is_not_extended,
                                     out.flags_info.opcode_index);
    if (m == nullptr) return false;
    out.metadata = m;
    out.exec_cached = m->exec;

    /* Las funciones de descodificacion leen el PC del proceso, no el que se

     * * les pasa.  Se le pone el que interesa y se le devuelve el suyo: es lo

     * * unico que se toca, y queda como estaba pase lo que pase. */
    const uint64_t rip_previo = process->registers.rip.raw();
    process->registers.rip.qword(pc);
    m->decode(process, out);
    process->registers.rip.qword(rip_previo);
    return true;
}

void decode_instruction(ProcessVM *process) {
    const bool measuring =
        process->scheduler.has_hooks; // activar medicion solo si hay hooks
    vm_hook(process, DebugStage::DecodeBegin); // hook de inicio de fase
    PROFILE_START
    const uint64_t t1 =
        measuring ? now_ns() : 0; // marca de tiempo inicial (solo si se mide)

    uint64_t pc = process->registers.rip.raw(); // PC actual del proceso

    // --- CACHE HIT ---
    // Si la entrada de la icache corresponde a este PC se reutiliza el
    // resultado anterior. Importante: la icache no detecta modificaciones en
    // tiempo de ejecucion del codigo.
    DecodedInstr *cached = icache_lookup(process, pc);
    if (cached != nullptr && process->decoded_ptr != nullptr) {
        process->decoded_ptr = cached; // apuntar al cache sin copiar

        if (measuring)
            process->scheduler.time_decode += now_ns() - t1; // acumular tiempo

        PROFILE_END("DECODER");
        vm_hook(process, DebugStage::DecodeEnd); // hook de fin de fase
        return;
    }

    /**
     * Prefetch de la siguiente instruccion para aprovechar el tiempo de
     * descodificacion: rw=0 -> lectura, locality=1 -> mantener en L2
     */
    __builtin_prefetch(&process->vm_mem[pc + 16], 0, 1);

    DecodedInstr decode_tmp{}; // buffer temporal de descodificacion
    decode_tmp.pc = pc;        // guardar PC de la instruccion
    decode_tmp.flags_info.is_not_extended =
        process->vm_mem[pc]; // leer primer byte (0x00 = extendido)

    if (decode_tmp.flags_info.is_not_extended == 0x00) {
        decode_tmp.flags_info.opcode_index =
            process->vm_mem[pc + 1]; // leer segundo byte del opcode extendido
    }

    // --- CACHE MISS: descodificar desde cero ---

    InstrFormat *table = decode_table_primary; // tabla de opcodes por defecto
    uint8_t index =
        decode_tmp.flags_info.is_not_extended; // indice en la tabla primaria

    // si el primer byte es 0x00 se selecciona la tabla extendida
    if (decode_tmp.flags_info.is_not_extended == 0x00) {
        table = decode_table_extended;
        index = decode_tmp.flags_info.opcode_index;
    }

    InstrFormat &metadata = table[index]; // obtener metadatos de la instruccion

    // instruccion sin implementar o invalida: guardar metadata minima y dejar
    // que execute_instruction la trate como HLT (evita abortar en procesos
    // spawn con memoria vacia que leen ceros al inicio de su espacio de
    // direcciones)
    if (metadata.exec == nullptr || metadata.decode == nullptr ||
        metadata.mode >= Assembly::Bytecode::AddressingMode::COUNT) {
        decode_tmp.metadata =
            &metadata; // enlazar metadata (exec/decode pueden ser null)
        decode_tmp.exec_cached =
            nullptr; // sentinel: el run_loop detecta nullptr y emite HALT
        DecodedInstr *slot = icache_victim(process, pc);
        *slot = decode_tmp; // cachear para que decoded_ptr sea valido
        process->decoded_ptr = slot;
        if (measuring) process->scheduler.time_decode += now_ns() - t1;
        PROFILE_END("DECODER")
        vm_hook(process, DebugStage::DecodeEnd);
        return; // execute_instruction detectara exec==nullptr y haltara el
                // proceso
    }

    // validar que el modo de direccionamiento es reconocido (solo en modo
    // debug)
    VM_ASSERT(
        metadata.mode < Assembly::Bytecode::AddressingMode::COUNT,

        std::string("VM::decode_instruction() Instruccion invalida en RIP[") +
                vesta::hex64(process->registers.rip.raw()) + "] opcode1(" +
                vesta::hex64(decode_tmp.flags_info.is_not_extended) +
                ") opcode2(" +
                vesta::hex64(decode_tmp.flags_info.opcode_index) + ")"
            << "Bytes64: " << "\n",
        vesta::scout() << vesta::dump(process->vm_mem,
                                      process->registers.rip.raw(), 64)
                       << std::endl;
        vm_hook(process, DebugStage::DecodeEnd););

    decode_tmp.metadata =
        &metadata; // enlazar metadatos al temporal de descodificacion
    // Cachear el puntero a la exec_fn al lado del decoded instr.  El
    // scheduler en su inner loop usa `d->exec_cached(...)` directo en
    // vez de `d->metadata->exec(...)` (doble indireccion); ahorra un
    // potencial cache miss por instruccion VM ejecutada.
    decode_tmp.exec_cached = metadata.exec;

    // llamar al metodo especializado de descodificacion de la instruccion
    metadata.decode(process, decode_tmp);

    // guardar el resultado en la icache (muy importante: despues de llamar a
    // decode).  `icache_victim` elige la via a desalojar; con una sola via es
    // la entrada de siempre.
    DecodedInstr *slot = icache_victim(process, pc);
    *slot = decode_tmp;

    // apuntar decoded_ptr a la entrada de la icache (sin copiar)
    process->decoded_ptr = slot;

    if (measuring)
        process->scheduler.time_decode +=
            now_ns() - t1; // acumular tiempo de descodificacion

    PROFILE_END("DECODER");
    vm_hook(process, DebugStage::DecodeEnd); // hook de fin de fase
}

/**
 * @brief Ejecuta la instruccion descodificada apuntada por decoded_ptr del
 * proceso.
 *
 * Llama al metodo exec() de los metadatos de la instruccion y, si no hubo
 * salto ni bloqueo, avanza el RIP en size_instr bytes.  Si la instruccion
 * es bloqueante retorna EVT_IO_WAIT sin avanzar el PC.
 *
 * Acumula el tiempo de ejecucion en scheduler.time_exec si has_hooks esta
 * activo, e invoca los hooks de DebugStage::ExecuteBegin/End.
 *
 * @param process Proceso virtual cuya instruccion descodificada se ejecuta.
 * @return EVT_IO_WAIT si la instruccion es bloqueante; EVT_EXEC_DONE en caso
 * contrario.
 */
vm_event execute_instruction(ProcessVM *process) {
    const bool measuring =
        process->scheduler.has_hooks; // activar medicion solo si hay hooks
    vm_hook(process, DebugStage::ExecuteBegin); // hook antes de ejecutar
    PROFILE_START

    const uint64_t t1 = measuring ? now_ns() : 0; // marca de tiempo inicial

    // ejecutar la instruccion descodificada; si exec es null, tratar como HLT
    // (instruccion invalida)
    if (!process->decoded_ptr->metadata->exec) {
        process->scheduler.on_event(
            EVT_HALT); // opcode sin implementacion: detener el proceso
        vm_hook(process, DebugStage::ExecuteEnd);
        return EVT_HALT;
    }
    process->decoded_ptr->metadata->exec(process, *process->decoded_ptr);

    /**
     * Si la instruccion requiere esperar E/S u otro recurso, no avanzar el PC:
     * la instruccion debe volver a ejecutarse cuando el bloqueo se resuelva.
     */
    if (process->decoded_ptr->flags_info.blocking) {
        vm_hook(process, DebugStage::ExecuteEnd);
        return EVT_IO_WAIT; // indicar bloqueo al scheduler
    }

    // si la instruccion NO modifico el PC (no es un salto), avanzarlo
    // manualmente
    if (!process->decoded_ptr->flags_info.did_jump)
        // avanzar el puntero de instruccion al siguiente opcode
        process->registers.rip.qword(
            process->registers.rip.raw() +
            process->decoded_ptr->flags_info.size_instr);
    else
        process->decoded_ptr->flags_info.did_jump =
            false; // desmarcar salto para la proxima iteracion

    // actualizar contadores de profiling
    process->scheduler.profiler_instr_counter++;
    if (measuring)
        process->scheduler.time_exec +=
            now_ns() - t1; // acumular tiempo de ejecucion

    PROFILE_END("EXECUTER");
    vm_hook(process, DebugStage::ExecuteEnd); // hook tras ejecutar

    return EVT_EXEC_DONE; // indicar exito al scheduler
}
} // namespace runtime
