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
#include "runtime/bundle.h"
#include "runtime/bundle/ooo.h"
#include "runtime/bundle/predecode.h"
#include "runtime/decode_table.h"
#include "runtime/dispatch_table.h"
#include "runtime/runtime.h"
#include "util/reloj.h"
#include <cstdio> // debug temporal

namespace {

/**
 * @brief Cuantos bytes del cursor se pueden volcar sin salirse del buffer.

 * *
 * El volcado de un aserto es diagnostico: leer 64 bytes fijos desde el
 * inicio
 * de la instruccion se sale del buffer en cuanto la instruccion esta
 * al final
 * -- y justo el caso que se quiere diagnosticar (bytes truncados)
 * es el que
 * mas cerca del borde ocurre.  El cursor ya sabe cuanto queda
 * legible.
 */
inline uint16_t cursor_dump_len(const runtime::InstrCursor &c) {
    return static_cast<uint16_t>(c.available < 64u ? c.available : 64u);
}

} // namespace

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
        vm->vm_mem.read_bytes(c.addr, exit_data, size);                        \
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
 * @brief Marca de tiempo actual, en TICKS del reloj mas fino de la maquina.
 *
 * Usa @ref util::reloj, que en un procesador con contador de ciclos invariante
 * lee el contador directamente (~0,3 ns de resolucion) y cae a
 * @c steady_clock si el procesador no lo garantiza.
 *
 * Antes leia @c CLOCK_MONOTONIC.  En Windows eso sale de
 * @c QueryPerformanceCounter, que corre a 10 MHz: **un salto cada 100 ns**.
 * Lo que se cronometra aqui es UNA instruccion de la maquina virtual, que
 * cuesta unos 3 ns -- con esa granularidad el 97% de las lecturas daban CERO y
 * el 3% daban 100, asi que `time_decode` y `time_exec` no median el tiempo,
 * median cada cuanto el reloj se dignaba a saltar.  Ademas se lee mas barato,
 * y se lee dos veces por instruccion.
 */
inline uint64_t now_ticks() { return util::reloj::ahora(); }

/**
 * @brief Nanosegundos transcurridos desde la marca @p t1.
 *
 * La conversion se hace sobre la DIFERENCIA, no sobre cada lectura: el valor
 * absoluto del contador de ciclos es enorme y convertirlo perderia en el
 * redondeo justo los pocos nanosegundos que se quieren medir.
 */
inline uint64_t elapsed_ns(uint64_t t1) {
    return (uint64_t)util::reloj::a_ns(util::reloj::ahora() - t1);
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
void decode_instr_oop_reg_imm8(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = Assembly::Bytecode::instr_size(
        instr.metadata->size); // fijar longitud de instruccion

    // las instrucciones extendidas siempre tienen prefijo 0x00, por eso el
    // offset es +2
    uint64_t offset = c.addr + 2;
    uint16_t data =
        c.read_u16(offset); // leer reg_byte e imm8 de una sola lectura

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
 * Sirve a las DOS tablas.  En la extendida ocupa 6 bytes
 * (`[0x00][op2][ctrl][regs][index][pad]`) y en la primaria 4
 * (`[op][ctrl][regs][index]`), sin el relleno.  Los campos son los mismos:
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
void decode_instr_sib(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // fijar longitud

    /* Los mismos tres campos en las DOS tablas, y un solo `u32` en las dos.
     *
     * Extendida: `[0x00][op2][ctrl][regs][index][pad]`.  El bloque arranca tras
     * los dos bytes de opcode, y el relleno existe solo para que la lectura de
     * cuatro bytes no se salga de la instruccion.
     *
     * Primaria: `[op][ctrl][regs][index]`.  El bloque arranca EN el opcode, asi
     * que los campos quedan un byte mas arriba y el relleno sobra.  Leer desde
     * `addr + 1` habria dejado las cuentas identicas, pero se sale un byte de
     * la instruccion, y al final de una pagina eso no es un byte de mas: es un
     * fallo de acceso. */
    const bool primaria = instr.flags_info.is_not_extended != 0;
    const uint32_t bruto = c.read_u32(c.addr + (primaria ? 0u : 2u));
    const uint32_t data = primaria ? (bruto >> 8) : bruto;

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
void decode_instr_two_op_reg(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = Assembly::Bytecode::instr_size(
        instr.metadata->size); // tamano constante

    // calcular offset al primer byte de datos segun si es opcode extendido o
    // primario
    uint64_t offset =
        c.addr + ((instr.flags_info.is_not_extended != 0) ? 1 : 2);

    // leer los dos bytes de datos de la instruccion
    uint16_t data = c.read_u16(offset);

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
void decode_instr_raw_bytes(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo

    uint64_t offset =
        c.addr + ((instr.flags_info.is_not_extended != 0) ? 1 : 2);

    uint16_t data = c.read_u16(offset);

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
void decode_instr_simple_mov(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // fijar longitud

    uint64_t offset =
        c.addr + ((instr.flags_info.is_not_extended != 0) ? 1 : 2);
    uint16_t data =
        c.read_u16(offset); // leer byte de control y byte de registros

    uint8_t n1 = static_cast<uint8_t>(data & 0x00FF); // byte de control
    uint8_t n2 =
        static_cast<uint8_t>((data & 0xFF00) >> 8); // byte de registros

    // ctrl byte: mode(2) | signed(1) | dir(1) | 0000
    instr.flags_info.mode = (n1 >> 6) & 0b11; // modo de acceso a memoria
    instr.flags_info._signed_instruct = (n1 >> 5) & 0b1; // extension de signo
    instr.flags_info.direction = (n1 >> 4) & 0b1; // direccion del movimiento

    /* Y que ESTA instancia nombra un registro especial, que para `mov` es lo
     * mismo que el bit de signo: `exec_instr_mov_reg` llega a rip/rsp/rbp solo
     * por esa rama.
     *
     * Lo pone el decodificador y no lo deduce cada consumidor a partir del
     * opcode, que es como estaba: un hecho POR OPCODE ("este `mov` PUEDE hablar
     * con rip") usado donde hacia falta uno POR INSTANCIA ("este `mov` habla
     * con rip").  Con la version gruesa, el reordenador y el reparto trataban
     * como intocable a cualquier `mov`, y con `push` pasaba lo mismo -- el 75%
     * de los paquetes no se podian repartir por eso. */
    instr.flags_info.reg_ext = (instr.flags_info._signed_instruct != 0);

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
void decode_instr_inmed_mov(const InstrCursor &c, DecodedInstr &instr) {
    // leer el byte de metadatos en PC+2
    uint8_t data = c[c.addr + 2];

    // leer 8 bytes del inmediato de golpe; se usaran 1, 2, 4 u 8 segun el modo
    uint64_t inmed = c.read_u64(c.addr + 3);

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
void decode_instr_simple(const InstrCursor &c, DecodedInstr &instr) {
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
void decode_instr_one_op_reg(const InstrCursor &c, DecodedInstr &instr) {
    VM_ASSERT(
        instr_size(instr.metadata->size) == 2,
        std::string(
            "VM::decode_instr_one_op_reg() Instruccion invalida en RIP[") +
                vesta::hex64(c.addr) + "] opcode1(" +
                vesta::hex64(instr.flags_info.is_not_extended) + ") opcode2(" +
                vesta::hex64(instr.flags_info.opcode_index) + ")\n"
            << "decode_instr_one_op_reg() Error la instruccion encontrada no "
               "tiene size 2 sino un size: "
            << instr_size(instr.metadata->size) << "\n",
        {
            vesta::scout() << vesta::dump(c.base, cursor_dump_len(c))
                           << std::endl;
        });
    instr.flags_info.size_instr = Assembly::Bytecode::instr_size(
        instr.metadata->size); // tamano siempre 2

    // leer el unico byte de datos (byte opcode+1)
    uint8_t data = c[c.addr + 1];

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
void decode_instr_movc(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // MOVC/MOVCH es siempre de 4 bytes

    uint64_t base = c.addr + 2; // offset al byte de control
    uint8_t ctrl = c[base];     // byte de control de la instruccion
    uint8_t b4 = c[base + 1];   // cuarto byte: codigo de flag y reg2

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
void decode_instr_push_pop(const InstrCursor &c, DecodedInstr &instr) {
    VM_ASSERT(instr_size(instr.metadata->size) == 2,
              std::string(
                  "VM::decode_instr_push_pop() Instruccion invalida en RIP[") +
                      vesta::hex64(c.addr) + "] opcode1(" +
                      vesta::hex64(instr.flags_info.is_not_extended) +
                      ") opcode2(" +
                      vesta::hex64(instr.flags_info.opcode_index) + ")\n"
                  << "decode_instr_push_pop() Error la instruccion encontrada "
                     "no tiene size 2 sino un size: "
                  << instr_size(instr.metadata->size) << "\n",
              {
                  vesta::scout()
                      << vesta::dump(c.base, cursor_dump_len(c)) << std::endl;
              });
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // siempre 2 bytes

    // leer el unico byte de datos tras el opcode
    uint8_t data = c[c.addr + 1];

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
void decode_instr_inmed_reg(const InstrCursor &c, DecodedInstr &instr) {
    VM_ASSERT(instr.flags_info.is_not_extended == false,
              std::string(
                  "VM::decode_instr_inmed_reg() Instruccion invalida en RIP[") +
                      vesta::hex64(c.addr) + "] opcode1(" +
                      vesta::hex64(instr.flags_info.is_not_extended) +
                      ") opcode2(" +
                      vesta::hex64(instr.flags_info.opcode_index) + ")\n"
                  << "decode_instr_inmed_reg() instr.is_not_extended == false "
                  << "Error la instruccion encontrada deberia usar extension "
                     "de signo pero no lo hace por algun motivo: "
                  << std::to_string(instr.flags_info.is_not_extended) << "\n",
              {
                  vesta::scout()
                      << vesta::dump(c.base, cursor_dump_len(c)) << std::endl;
              });

    /**
     * Byte de datos en PC+2 con el siguiente layout de campos:
     *   0b mm s d rrrr
     *      |  | | +--- reg   (4 bits): numero de registro
     *      |  | +----- d     (1 bit):  direccion (0=reg, 1=[reg])
     *      |  +------- s     (1 bit):  signo
     *      +----------- mode (2 bits): tamano del inmediato
     */
    uint8_t data = c[c.addr + 2]; // byte de control

    // leer 8 bytes del inmediato; se recortaran al modo elegido
    uint64_t inmed = c.read_u64(c.addr + 3);

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
void decode_instr_xchg(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo

    // leer los 2 bytes de datos saltando el opcode extendido (PC+2)
    uint16_t data = c.read_u16(c.addr + 2);

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
void decode_instr_cursor_rw(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // tamano fijo

    // los 2 bytes de datos empiezan tras los 2 bytes de opcode extendido
    uint64_t offset = c.addr + 2;
    uint16_t data =
        c.read_u16(offset); // leer byte de control y byte de registro

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
void decode_instr_addcur(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // 6 bytes

    // leer los 4 bytes de datos (bytes 2-5 de la instruccion)
    uint64_t offset = c.addr + 2;
    uint32_t data32 = c.read_u32(offset);

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
void decode_instr_vmcopy(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size); // 4 bytes

    uint64_t offset = c.addr + 2;
    uint16_t data16 = c.read_u16(offset);

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
void decode_instr_jump(const InstrCursor &c, DecodedInstr &instr) {
    // [opcode][cond_o_reservado][8 bytes addr] = 10 bytes (FIXED_10, opcode
    // primario)
    instr.data_instruction.inmmed_data.reg =
        c[c.addr + 1]; // codigo de condicion
    instr.data_instruction.inmmed_data.inmmed =
        c.read_u64(c.addr + 2); // direccion absoluta de destino
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
void decode_instr_no_operands(const InstrCursor &c, DecodedInstr &instr) {
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
void decode_instr_jrel(const InstrCursor &c, DecodedInstr &instr) {
    // [0x00][0x2D][cond][padding][disp32] - extended FIXED_8
    instr.data_instruction.inmmed_data.reg = c[c.addr + 2]; // byte de condicion
    const uint32_t raw_disp =
        c.read_u32(c.addr + 4); // desplazamiento de 32 bits
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
void decode_instr_jumptable(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // FIXED_4
    uint64_t base = c.addr + 2;      // saltar opcode1 + opcode2
    uint8_t b2 = c[base];            // byte empaquetado: r_val|r_table
    uint8_t b3 = c[base + 1];        // count
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F; // r_val/r_obj
    instr.data_instruction.mem_data.reg_index = b2 & 0x0F;       // r_table
    instr.data_instruction.mem_data.scale = b3;                  // count
}

void decode_instr_three_reg(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // FIXED_4: opcode1 + opcode2 + b2 + b3
    uint64_t base = c.addr + 2;      // saltar opcode1 + opcode2
    uint8_t b2 = c[base];            // (r_pid<<4) | r_addr
    uint8_t b3 = c[base + 1];        // (r_len<<4) | 0
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F;  // r_pid
    instr.data_instruction.mem_data.reg_index = b2 & 0x0F;        // r_addr
    instr.data_instruction.mem_data.reg_final = (b3 >> 4) & 0x0F; // r_len
}

// Descodificador de 4 regs empacados en FIXED_4: 4 nibbles en 2 bytes.
//   byte2 (rip+2) = (r0 << 4) | r1
//   byte3 (rip+3) = (r2 << 4) | r3
// Util para atomiccas: r0=dst, r1=addr, r2=expected, r3=desired.
void decode_instr_four_reg(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
    uint8_t b3 = c[base + 1];
    instr.data_instruction.mem_data.reg_base = (b2 >> 4) & 0x0F;  // r0
    instr.data_instruction.mem_data.reg_index = b2 & 0x0F;        // r1
    instr.data_instruction.mem_data.reg_final = (b3 >> 4) & 0x0F; // r2
    instr.data_instruction.mem_data.scale = b3 & 0x0F;            // r3
}

// Atomicos RMW width-aware (atomicadd/atomiccas, FIXED_6): igual que four_reg
// pero con un ctrl-byte DELANTE que porta el mode (ancho 8/16/32/64).  Layout:
//   [0x00][op][ctrl=mode<<6][b2=(base<<4)|index][b3=(final<<4)|scale][pad].
void decode_instr_atomic_rmw(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 6; // FIXED_6
    uint64_t base = c.addr + 2;
    uint8_t ctrl = c[base];
    uint8_t b2 = c[base + 1];
    uint8_t b3 = c[base + 2];
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
void decode_instr_static_offset(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr =
        8; // FIXED_8: prefix(2) + regs(1) + pad(1) + offset(4)
    uint64_t base = c.addr + 2;             // saltar opcode1 + opcode2
    uint8_t regs_byte = c[base];            // (r0<<4) | r1
    uint32_t offset = c.read_u32(base + 2); // bytes 4-7 absolutos
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
void decode_instr_mem_full(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 8; // FIXED_8
    // Una sola lectura de 8 bytes (la instruccion entera) en vez de 5 accesos
    // byte a byte -> 1 lookup TLB/pagina.  Layout de raw (LE):
    //   b0=0x00 b1=op2 b2=ctrl b3=basef b4=regs b5=disp_lo b6=disp_hi b7=pad
    const uint64_t raw = c.read_u64(c.addr);
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
void decode_instr_dlopen_dlsym(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // FIXED_4: prefix(2) + b2 + b3
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
    uint8_t b3 = c[base + 1];
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
void decode_instr_callni(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4; // FIXED_4: prefix(2) + b2 + b3
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
    instr.data_instruction.reg_data.reg1 = (b2 >> 4) & 0x0F; // r_fn
    instr.data_instruction.reg_data.reg2 = 0;                // sin uso
}

/**
 * @brief Decoder de @c gcallocp (FIXED_4, 2 regs en byte2).
 * Layout: [0x00][0x65][b2][0x00] con b2 = (r_dst<<4) | r_size.
 * Aloca en GcHeap y deposita host_ptr al payload directo en r_dst.
 */
void decode_instr_gcallocp(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
    instr.data_instruction.reg_data.reg1 = (b2 >> 4) & 0x0F; // r_dst
    instr.data_instruction.reg_data.reg2 = b2 & 0x0F;        // r_size
}

/**
 * @brief Decoder de @c spawnargs (FIXED_4, 1 reg en byte2 hi-nibble).
 * Layout: [0x00][0x66][b2][0x00] con b2 = (r_pc<<4).  argc se lee de R15.
 */
void decode_instr_spawnargs(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
    instr.data_instruction.reg_data.reg1 = (b2 >> 4) & 0x0F; // r_pc
    instr.data_instruction.reg_data.reg2 = 0;
}

/**
 * @brief Decoder de @c fulfillhlt (FIXED_4, 2 regs en byte2).
 * Layout: [0x00][0x67][b2][0x00] con b2 = (r_fut<<4) | r_value.
 */
void decode_instr_fulfillhlt(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
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
void decode_instr_cmpjmp(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 8;
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
    uint8_t cond = c[base + 1];
    instr.data_instruction.static_data.r0 = (b2 >> 4) & 0x0F;
    instr.data_instruction.static_data.r1 = b2 & 0x0F;
    instr.data_instruction.static_data._pad = static_cast<uint16_t>(cond);
    instr.data_instruction.static_data.offset = c.read_u32(base + 2);
}

/**
 * @brief Decoder de @c decjnz (FIXED_8, 1 reg + target).
 * Layout: [0x00][0x6A][b2][0x00][target_u32_LE]
 *   static_data.r0     = r_counter
 *   static_data.offset = target u32
 */
void decode_instr_decjnz(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 8;
    uint64_t base = c.addr + 2;
    uint8_t b2 = c[base];
    instr.data_instruction.static_data.r0 = (b2 >> 4) & 0x0F;
    instr.data_instruction.static_data.r1 = 0;
    instr.data_instruction.static_data._pad = 0;
    instr.data_instruction.static_data.offset = c.read_u32(base + 2);
}

/**
 * @brief Descodifica @c fastpush / @c fastpop (extended 0x6B / 0x6C, FIXED_4).
 *
 * Layout fisico: [0x00][opcode2][mask_lo][mask_hi]
 * Bytes [rip+2..rip+3] forman el mask uint16 little-endian.
 */
void decode_instr_fastmask(const InstrCursor &c, DecodedInstr &instr) {
    instr.flags_info.size_instr = 4;
    const uint64_t base = c.addr + 2;
    const uint8_t lo = c[base];
    const uint8_t hi = c[base + 1];
    instr.data_instruction.mask_data.mask =
        static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);

    DBG_DECODE(instr.pc, "Instruccion decode: ", instr.metadata->name,
               " mask=0x" << std::hex
                          << (unsigned)instr.data_instruction.mask_data.mask
                          << std::dec);
}

void decode_instr_calln(const InstrCursor &c, DecodedInstr &instr) {
    instr.data_instruction.inmmed_data.inmmed =
        c.read_u64(c.addr + 2); // direccion de la funcion nativa

    // tamano de la instruccion para luego incrementar rip tras la ejecucion
    instr.flags_info.size_instr =
        Assembly::Bytecode::instr_size(instr.metadata->size);

    // argc se cachea en decode para que exec pueda obtenerlo sin acceder a
    // registros: al ser constante por PC, el IBP de la CPU predecira bien el
    // switch(argc) tras la primera ejecucion
    // `argc` (R15) lo pone `cachear_estado_de_runtime`, no este decoder: es
    // estado del proceso, no parte del formato de la instruccion.
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
/**
 * @brief Puede este opcode tener variante por nivel de ISA y ancho?
 *
 * Solo los cuatro binarios de coma flotante (`fadd`, `fsub`, `fmul`, `fdiv`,
 * extendidos 0xF1..0xF4) la tienen.  Preguntarlo AQUI ahorra una llamada entre
 * unidades de traduccion por cada instruccion extendida descodificada -- que
 * son casi todas -- para que la respuesta sea `nullptr`: `float_exec_specialized`
 * vive en `exec_instruction_float.cpp`, asi que no se puede incrustar y el
 * compilador tiene que montar la llamada entera.
 *
 * La resta sin signo hace el rango en UNA comparacion: cualquier opcode por
 * debajo de 0xF1 se envuelve a un numero grande.
 */
[[gnu::always_inline]] inline bool has_float_variant(uint8_t opcode2,
                                                     uint8_t b0) {
    return b0 == 0x00 && (uint8_t)(opcode2 - 0xF1u) <= 3u;
}

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

/// Bytes maximos que ocupa una instruccion (la mas larga es FIXED_11).
static constexpr size_t INSTR_BYTES_MAX = 16;

/**
 * @brief Cursor sobre los bytes de la instruccion que hay en @p pc.
 *
 * SIN COPIAR cuando se puede, que es casi siempre.  `InstrCursor` ya es un
 * puntero mas una longitud, asi que si los @ref INSTR_BYTES_MAX bytes caben
 * enteros en la pagina que la memoria de la VM tiene cacheada, se apunta
 * directamente a ella y no se mueve un solo byte.
 *
 * El respaldo -- copiar byte a byte -- sigue existiendo y hace falta: la
 * memoria de la VM es paginada y una instruccion puede CRUZAR de pagina, y ahi
 * un puntero crudo no serviria para las dos mitades.
 *
 * El comentario que habia aqui decia que el coste era irrelevante porque
 * descodificar solo ocurre al fallar la icache, "el 0,57% de las ejecuciones".
 * Medido con VTune, esa cifra es falsa: `cursor_en` retira 1.186 millones de
 * instrucciones del anfitrion y el `operator[]` que llamaba 1.675 -- entre las
 * dos, mas del 20% del trabajo en un programa cuyo bucle no cabe en la icache
 * --.  Dieciseis accesos por descodificacion, para leer una instruccion que
 * suele medir uno o cuatro bytes.
 *
 * El puntero vale mientras se descodifica: `m->decode` solo LEE bytes del
 * cursor y no toca la memoria de la VM, asi que la pagina no se puede mover
 * por debajo.
 */
static InstrCursor cursor_en(ProcessVM *process, uint64_t pc,
                             uint8_t (&buf)[INSTR_BYTES_MAX]) {
    auto &mem = process->vm_mem;
    const uint64_t offset = pc & 0xFFF;
    if (offset + INSTR_BYTES_MAX <= 4096) {
        /* Un acceso para forzar la cache de pagina -- y de paso la asignacion
         * perezosa si la pagina aun no existia --, y despues el puntero. */
        (void)mem[pc];
        uint8_t *host = mem.jit_cached_page_host();
        if (host != nullptr && mem.jit_cached_page_vaddr() == (pc & ~0xFFFULL))
            return InstrCursor{host + offset, INSTR_BYTES_MAX, pc};
    }
    for (size_t i = 0; i < INSTR_BYTES_MAX; ++i)
        buf[i] = mem[pc + i];
    return InstrCursor{buf, INSTR_BYTES_MAX, pc};
}

/**
 * @brief Lo que `calln` necesita del proceso y NO es descodificar.
 *
 * `calln` cachea `argc` (R15) en el momento de descodificar para que `exec` no
 * tenga que leer un registro: al ser constante por PC, el predictor de saltos
 * acierta el `switch(argc)` desde la segunda vez.  Es una cache de RUNTIME, no
 * parte del formato de la instruccion, asi que vive aqui y no dentro del
 * decoder -- que asi se queda puro como los otros 32.
 */
static void cachear_estado_de_runtime(ProcessVM *process, const InstrFormat &m,
                                      DecodedInstr &out) {
    if (m.decode == &decode_instr_calln)
        out.data_instruction.inmmed_data.reg =
            static_cast<uint64_t>(process->registers.regs[R15].qword());
}

bool decode_peek(ProcessVM *process, uint64_t pc, DecodedInstr &out,
                 vm::VirtualMemory::PageView *view) {
    if (process == nullptr) return false;
    out = DecodedInstr{};
    out.pc = pc;

    /* Con `view`, esto lo puede llamar OTRO HILO.
     *
     * La diferencia no es la TLB -- consultarla no muta nada --: es la cache de
     * pagina del objeto, que se escribe en cada acceso y que dos lectores se
     * pisan.  Con la cache del llamante no queda estado compartido, y a cambio
     * hay que aceptar que una pagina sin mapear se conteste con "no se puede"
     * en vez de asignarla, porque asignar SI muta. */
    if (view != nullptr) {
        const uint8_t *p = process->vm_mem.host_ptr_readonly(pc, *view);
        if (p == nullptr) return false;
        out.flags_info.is_not_extended = *p;
        if (out.flags_info.is_not_extended == 0x00) {
            const uint8_t *p1 =
                process->vm_mem.host_ptr_readonly(pc + 1, *view);
            if (p1 == nullptr) return false;
            out.flags_info.opcode_index = *p1;
        }
    } else {
        out.flags_info.is_not_extended = process->vm_mem[pc];
        if (out.flags_info.is_not_extended == 0x00)
            out.flags_info.opcode_index = process->vm_mem[pc + 1];
    }

    InstrFormat *m = select_metadata(out.flags_info.is_not_extended,
                                     out.flags_info.opcode_index);
    if (m == nullptr) return false;
    out.metadata = m;
    out.exec_cached = m->exec;

    /* Antes habia que FALSEAR el rip del proceso: los decoders leian el PC del
     * proceso en vez del que se les pasaba, asi que mirar otra direccion
     * obligaba a ponerlo, descodificar y devolverlo.  Con el cursor la
     * direccion es un argumento y el proceso no se toca. */
    uint8_t buf[INSTR_BYTES_MAX];
    if (view != nullptr) {
        /* Los bytes, uno a uno y con la cache del llamante.  Mas lento que el
         * cursor normal -- que devuelve un puntero a la pagina -- y da igual:
         * esto corre FUERA del camino critico, y a cambio no toca nada
         * compartido.
         *
         * SI UN BYTE NO SE PUEDE LEER, SE ABANDONA.  Aqui habia un relleno con
         * ceros -- "el decodificador ya aguanta bytes cualesquiera" -- y era el
         * fallo: la VM mapea las paginas de forma PEREZOSA, asi que leer por
         * delante entra en codigo que el hilo principal todavia no ha
         * ejecutado y cuya pagina AUN NO EXISTE.  Con el relleno se
         * descodificaba una instruccion inventada y se publicaba para un `pc`
         * que el principal SI iba a ejecutar despues.
         *
         * Medido, mezcla `memoria`: con adelanto 1, 8 y 1 valores incorrectos
         * en tres tandas; sin adelanto, cero en tres.  Un valor por defecto que
         * "funciona" convierte un error en un resultado equivocado, y este no
         * fallaba en ningun sitio -- daba `R0 = 0` donde tocaba 30769 --. */
        for (size_t i = 0; i < INSTR_BYTES_MAX; ++i) {
            const uint8_t *p =
                process->vm_mem.host_ptr_readonly(pc + i, *view);
            if (p == nullptr) return false; // no se sabe: no se adelanta nada
            buf[i] = *p;
        }
        m->decode(InstrCursor{buf, INSTR_BYTES_MAX, pc}, out);
    } else {
        m->decode(cursor_en(process, pc, buf), out);
    }
    /* Las binarias de coma flotante tienen variante por nivel de ISA Y por
     * ancho, con el cuerpo SIMD ya metido en linea.  Se elige AQUI -- DESPUES
     * de descodificar, que es cuando `mode` ya esta puesto -- y no en cada
     * ejecucion: asi la aprovechan todos los consumidores, incluido
     * `exec_bundle`, que no pasa por la tabla de rutas rapidas del interprete
     * y por tanto no veria una especializacion que viviera solo alli. */
    if (has_float_variant(out.flags_info.opcode_index,
                          out.flags_info.is_not_extended)) {
        if (auto *esp = float_exec_specialized(out.flags_info.opcode_index,
                                               out.flags_info.mode))
            out.exec_cached = esp;
    }
    cachear_estado_de_runtime(process, *m, out);
    return true;
}

/**
 * @brief El cuerpo, con la consulta de icache como parametro de PLANTILLA.
 *
 * @tparam AlreadyMissed El llamante YA miro la icache y fallo.  Entonces
 *                       volver a mirarla es una busqueda de mas en una tabla
 *                       de 256 KB -- casi seguro un fallo de cache del
 *                       anfitrion -- cuya respuesta ya se conoce.
 *
 * El camino caliente del planificador hace exactamente eso: consulta, y si
 * falla llama aqui.  Los demas llamantes no consultan, asi que la comprobacion
 * sigue existiendo para ellos.  Con dos instanciaciones no hay que elegir: la
 * del planificador no lleva ni la busqueda ni la rama.
 */
template <bool AlreadyMissed>
static void decode_impl(ProcessVM *process) {
    const bool measuring =
        process->scheduler.has_hooks; // activar medicion solo si hay hooks
    vm_hook(process, DebugStage::DecodeBegin); // hook de inicio de fase
    PROFILE_START
    const uint64_t t1 =
        measuring ? now_ticks() : 0; // marca inicial (solo si se mide)

    uint64_t pc = process->registers.rip.raw(); // PC actual del proceso

    // --- CACHE HIT ---
    // Si la entrada de la icache corresponde a este PC se reutiliza el
    // resultado anterior. Importante: la icache no detecta modificaciones en
    // tiempo de ejecucion del codigo.
    if constexpr (!AlreadyMissed) {
    DecodedInstr *cached = icache_lookup(process, pc);
    if (cached != nullptr && process->decoded_ptr != nullptr) {
        process->decoded_ptr = cached; // apuntar al cache sin copiar

        if (measuring)
            process->scheduler.time_decode += elapsed_ns(t1); // acumular

        PROFILE_END("DECODER");
        vm_hook(process, DebugStage::DecodeEnd); // hook de fin de fase
        return;
    }
    }

#if VM_BUNDLES
    /* LA TRAIA HECHA EL AYUDANTE?
     *
     * Descodificar es el 5,7% del banco -- cinco veces lo que cuesta formar
     * paquetes --, y es trabajo independiente por construccion: una funcion del
     * bytecode, que ya esta.  Si el ayudante llego antes, aqui solo queda
     * copiar 64 bytes, que es lo que este camino ya hacia de todas formas.
     *
     * Rendirse no cuesta nada: si no esta, o esta a medias, se descodifica como
     * siempre.  Por eso no hay ninguna espera. */
    /* Solo el DUENYO del ayudante mira la tabla.
     *
     * Las entradas se guardan por `pc`, y dos programas distintos usan las
     * mismas direcciones: sin esta condicion un proceso cosechaba
     * instrucciones que otro habia dejado ahi y ejecutaba OTRO PROGRAMA.  No
     * fallaba: contaba 253.772 instrucciones donde el programa tenia
     * 7.995.405, o sea que se iba por donde no debia y terminaba antes.
     *
     * Y la condicion es exacta, no una precaucion: quien no ha encargado nada
     * no tiene nada suyo ahi dentro. */
    if (__builtin_expect(process->bundle_ooo_on &&
                             g_ooo_owner.load(std::memory_order_relaxed) ==
                                 process,
                         0)) {
        if (__builtin_expect(!process->ooo_try_decode, 0)) {
            /* Apagado, pero no para siempre: se cuenta hacia el reintento.  Un
             * programa recorre FASES y la respuesta cambia con ellas. */
            if (--process->ooo_decode_wait == 0) {
                process->ooo_try_decode = true;
                process->ooo_decode_probe = 0;
                process->ooo_decode_hits = 0;
            }
        } else {
        DecodedInstr pre;
        const bool hit = predecode_probe(pc, pre);
        /* La PRUEBA: acierta bastante como para compensar?
         *
         * Cada consulta fallida cuesta una linea de cache que el ayudante esta
         * escribiendo, asi que fallar mucho es peor que no intentarlo.  Se
         * decide con el dato al cerrar la ventana, no antes. */
        process->ooo_decode_hits += hit ? 1u : 0u;
        if (__builtin_expect(++process->ooo_decode_probe >=
                                 ProcessVM::kDecodeProbe,
                             0)) {
            // La mitad.  Por debajo, la linea disputada se come lo que ahorra.
            if (process->ooo_decode_hits * 2 >= process->ooo_decode_probe) {
                // Compensa: se sigue, y el proximo reintento vuelve a ser corto.
                process->ooo_decode_backoff = 0;
            } else {
                process->ooo_try_decode = false;
                process->ooo_decode_backoff =
                    process->ooo_decode_backoff == 0
                        ? ProcessVM::kDecodeRetry
                        : (process->ooo_decode_backoff <
                                   ProcessVM::kDecodeRetryMax / 2
                               ? process->ooo_decode_backoff * 2
                               : ProcessVM::kDecodeRetryMax);
                process->ooo_decode_wait = process->ooo_decode_backoff;
            }
            process->ooo_decode_probe = 0;
            process->ooo_decode_hits = 0;
        }
        if (hit) {
            /* Se instala igual que el camino normal, incluida la ranura de
             * reserva cuando la victima es la que se esta ejecutando: eso no lo
             * puede saltar nadie, ni siquiera un camino mas rapido. */
            DecodedInstr *slot_pre = icache_victim(process, pc);
            if (slot_pre == nullptr) slot_pre = &process->decoded_scratch;
#if VM_BUNDLES && ICACHE_HEAD_SHIFT
            /* Lo mismo que hace el camino normal, y por lo mismo: si lo que se
             * va a pisar era la CABECERA de un paquete de otra direccion, esta
             * ranura esta disputada y hay que apuntarlo ANTES de pisarla. */
            const bool was_bundle_head_pre =
                (slot_pre != &process->decoded_scratch) &&
                slot_pre->pc != pc && slot_pre->exec_cached == &exec_bundle;
#endif
            *slot_pre = pre;
#if VM_BUNDLES && ICACHE_HEAD_SHIFT
            if (was_bundle_head_pre) process->icache_head_clash = pc;
#endif
#if VM_BUNDLES
            /* Y FORMAR PAQUETE, que es lo que el camino normal hace justo
             * despues de instalar.
             *
             * Saltarselo no era solo perder el paquete: la entrada queda como
             * una instruccion suelta donde el resto del sistema espera poder
             * encontrar una cabecera, y eso es un estado que el camino normal
             * no produce nunca.  Un atajo tiene que dejar el mismo estado que
             * el camino que ataja, no uno parecido. */
            bundle_try_form(process, slot_pre, pc);
#endif
            process->decoded_ptr = slot_pre;
            if (process->bundle_stats_on)
                ++process->bundle_stats.predecode_hits;
            if (measuring) process->scheduler.time_decode += elapsed_ns(t1);
            PROFILE_END("DECODER");
            vm_hook(process, DebugStage::DecodeEnd);
            return;
        }
        if (process->bundle_stats_on)
            ++process->bundle_stats.predecode_misses;
        }
    }
#endif

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
        if (slot == nullptr) slot = &process->decoded_scratch;
        *slot = decode_tmp; // cachear para que decoded_ptr sea valido
        process->decoded_ptr = slot;
        if (measuring) process->scheduler.time_decode += elapsed_ns(t1);
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
    uint8_t instr_buf[INSTR_BYTES_MAX];
    metadata.decode(cursor_en(process, pc, instr_buf), decode_tmp);
    // Y AHORA, con `mode` ya puesto, la variante por ISA y ancho si la hay.
    // Ver el otro sitio que rellena `exec_cached`, mas arriba en este fichero.
    if (has_float_variant(decode_tmp.flags_info.opcode_index,
                          decode_tmp.flags_info.is_not_extended)) {
        if (auto *esp =
                float_exec_specialized(decode_tmp.flags_info.opcode_index,
                                       decode_tmp.flags_info.mode))
            decode_tmp.exec_cached = esp;
    }
    cachear_estado_de_runtime(process, metadata, decode_tmp);

    // guardar el resultado en la icache (muy importante: despues de llamar a
    // decode).  `icache_victim` elige la via a desalojar; con una sola via es
    // la entrada de siempre.
    // `icache_victim` devuelve nullptr cuando la ranura que tocaria es la que
    // se esta ejecutando: esa no se puede pisar sin dejar rancio el puntero que
    // sostiene el run_loop.  En ese caso se descodifica SIN cachear, usando un
    // hueco de reserva del proceso.  Es correcto -- la instruccion se ejecuta
    // igual -- y solo cuesta que la proxima vez vuelva a fallar.
    DecodedInstr *slot = icache_victim(process, pc);
    if (slot == nullptr) slot = &process->decoded_scratch;
#if VM_BUNDLES && ICACHE_HEAD_SHIFT
    /* QUE HABIA AQUI ANTES, mirado ANTES de pisarlo.
     *
     * Si la entrada que se va a sobrescribir era la CABECERA de un paquete de
     * otra direccion, esta ranura esta disputada: dos sitios del programa
     * caen en ella y se desalojan el uno al otro en cada vuelta.  Se apunta,
     * y `bundle_try_form` lo usa para correr la cabecera una instruccion.
     *
     * Tiene que ser aqui y no alli: cuando `bundle_try_form` corre, la entrada
     * YA se reclamo para el `pc` nuevo y el ocupante anterior se perdio.  Se
     * intento comprobarlo alli primero y no se disparaba ni una vez. */
    const bool was_bundle_head =
        (slot != &process->decoded_scratch) && slot->pc != pc &&
        slot->exec_cached == &exec_bundle;
#endif
    *slot = decode_tmp;

#if VM_BUNDLES && ICACHE_HEAD_SHIFT
    if (was_bundle_head) process->icache_head_clash = pc;
#endif

#if VM_BUNDLES
    // Formar paquete, si procede.  Va AQUI y no en el hot path a proposito:
    // este es el camino de FALLO, que esta medido en el 0,57% de las
    // ejecuciones, asi que el analisis se amortiza por PC.  Si no forma nada,
    // la entrada se queda como estaba y todo sigue igual.
    bundle_try_form(process, slot, pc);
#endif

    // apuntar decoded_ptr a la entrada de la icache (sin copiar)
    process->decoded_ptr = slot;

    if (measuring)
        process->scheduler.time_decode +=
            elapsed_ns(t1); // acumular tiempo de descodificacion

    PROFILE_END("DECODER");
    vm_hook(process, DebugStage::DecodeEnd); // hook de fin de fase
}

void decode_instruction(ProcessVM *process) { decode_impl<false>(process); }

void decode_instruction_after_miss(ProcessVM *process) {
    decode_impl<true>(process);
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

    const uint64_t t1 = measuring ? now_ticks() : 0; // marca inicial

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
            elapsed_ns(t1); // acumular tiempo de ejecucion

    PROFILE_END("EXECUTER");
    vm_hook(process, DebugStage::ExecuteEnd); // hook tras ejecutar

    return EVT_EXEC_DONE; // indicar exito al scheduler
}
} // namespace runtime
