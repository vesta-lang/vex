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
 * @file decode_instruction.h
 * @brief Declaraciones del pipeline de descodificacion y ejecucion de
 * instrucciones VestaVM.
 *
 * Define:
 *   - InstrFormat: metadatos de una instruccion (nombre, modo, tamano, exec,
 * decode).
 *   - Macros de profiling PROFILE_START/PROFILE_END (activos con -DVM_PROFILE).
 *   - Macro VM_ASSERT (activo con -DVM_DEBUG_CHECKS): aborta con mensaje si
 * falla una condicion.
 *   - Declaraciones de todos los descodificadores especializados.
 *   - Declaraciones de decode_instruction() y execute_instruction().
 */

#ifndef DECODE_INSTRUCTION_H
#define DECODE_INSTRUCTION_H

#include <cstdint>
#include "decode_table.h"
#include "runtime.h"
#include "emmit/emmit_decl.h"

// --- Macros de profiling de alta precision (activos solo con -DVM_PROFILE) ---
#ifdef VM_PROFILE
/**
 * @brief Inicia una medicion de tiempo con resolucion de nanosegundos.
 *
 * Define la variable __t0 con la marca de tiempo actual usando
 * std::chrono::high_resolution_clock.  Debe ir seguido de PROFILE_END().
 */
#define PROFILE_START auto __t0 = clock::now();

/**
 * @brief Finaliza una medicion e imprime la duracion en nanosegundos.
 *
 * @param label Etiqueta de texto que identifica el bloque medido en la salida.
 */
#define PROFILE_END(label)                                                     \
    do {                                                                       \
        auto __t1 = clock::now();                                              \
        std::cout << "[" << label << "] "                                      \
                  << std::chrono::duration_cast<std::chrono::nanoseconds>(     \
                         __t1 - __t0)                                          \
                         .count()                                              \
                  << " ns\n";                                                  \
    } while (0)
#else
#define PROFILE_START      ///< No-op en modo release: sin overhead de medicion
#define PROFILE_END(label) ///< No-op en modo release: sin overhead de medicion
#endif

/**
 * @defgroup VM_ASSERT Macro de asercion de depuracion VM
 * @{
 *
 * VM_ASSERT verifica una condicion durante la descodificacion y ejecucion.
 * Si la condicion falla en modo debug (VM_DEBUG_CHECKS activo) imprime
 * el mensaje, ejecuta el bloque de codigo de recuperacion y llama a abort().
 *
 * Se desactiva completamente en release para maximizar el rendimiento en las
 * fases de decode/execute que son hot-path.
 *
 * @param cond Condicion booleana que debe ser verdadera.
 * @param msg  Mensaje de error (puede contener operador << de stream).
 * @param code Bloque de codigo de diagnostico adicional (se ejecuta antes de
 * abort()).
 */
#ifdef VM_DEBUG_CHECKS
#pragma message("VM_DEBUG_CHECKS fue activada")
#define VM_ASSERT(cond, msg, code)                                             \
    do {                                                                       \
        if (!(cond)) {                                                         \
            vesta::scout() << "[VM ASSERT] " << msg << "\n";                   \
            code;                                                              \
            abort();                                                           \
        }                                                                      \
    } while (0)
#else
#define VM_ASSERT(cond, msg, code)                                             \
    do {                                                                       \
    } while (0) ///< No-op en release
#endif
/** @} */

namespace runtime {

struct DecodedInstr; ///< Declaracion adelantada de la instruccion descodificada
class ProcessVM;     ///< Declaracion adelantada del proceso virtual

/**
 * @brief Lo unico que hace falta para descodificar: bytes y direccion.
 *
 * Descodificar es una funcion PURA de los bytes de la instruccion.  Los
 * decoders pedian un @c ProcessVM entero solo para leer @c registers.rip y
 * unos bytes de @c vm_mem, y ese acoplamiento tenia un coste real: cualquiera
 * que quisiera saber la forma de una instruccion sin ejecutarla -- el
 * desensamblador, un analisis, una herramienta -- no podia usar el decoder de
 * la VM y acababa reinterpretando los bytes por su cuenta.  El desensamblador
 * lo hacia en dos funciones de 300 lineas, y sus propios comentarios registran
 * los bugs que eso produjo: condiciones de salto atribuidas al reves, un `sext`
 * que mostraba un registro que no interviene.
 *
 * Con el cursor hay UN solo decoder para todos.  La VM le pasa un puntero
 * dentro de su propia memoria; el desensamblador, su buffer.
 *
 * Ofrece los mismos accesos que se usaban sobre @c vm_mem, POR DIRECCION
 * ABSOLUTA, para que los decoders lean igual que antes.
 */
struct InstrCursor {
    const uint8_t *base = nullptr; ///< primer byte de la instruccion
    size_t available = 0;          ///< bytes legibles desde @c base
    uint64_t addr = 0;             ///< direccion virtual de @c base

    /// Byte en una direccion absoluta.  Fuera de rango devuelve 0: un buffer
    /// truncado da una instruccion incompleta, no una lectura invalida.
    uint8_t operator[](uint64_t vaddr) const {
        const uint64_t off = vaddr - addr;
        return (off < available) ? base[off] : 0u;
    }

    uint16_t read_u16(uint64_t vaddr) const { return read<uint16_t>(vaddr); }
    uint32_t read_u32(uint64_t vaddr) const { return read<uint32_t>(vaddr); }
    uint64_t read_u64(uint64_t vaddr) const { return read<uint64_t>(vaddr); }

  private:
    /// Little-endian byte a byte: no supone alineacion ni el endianness del
    /// host, y respeta el limite del buffer.
    template <typename T> T read(uint64_t vaddr) const {
        T v = 0;
        for (size_t i = 0; i < sizeof(T); ++i)
            v |= static_cast<T>(static_cast<T>((*this)[vaddr + i]) << (8 * i));
        return v;
    }
};

/**
 * @brief Metadatos de una instruccion del bytecode VestaVM.
 *
 * Cada entrada de decode_table_primary y decode_table_extended es un
 * InstrFormat.  El par (exec, decode) forma el contrato de la instruccion:
 *   - decode() extrae los operandos del flujo de bytes y los almacena en
 * DecodedInstr.
 *   - exec()   aplica la semantica de la instruccion sobre el estado del
 * proceso.
 *
 * Las entradas con mode == AddressingMode::COUNT o exec/decode == nullptr son
 * ranuras no implementadas o reservadas; el descodificador abortara si las
 * encuentra (solo en modo VM_DEBUG_CHECKS).
 */
typedef struct InstrFormat {
    /**
     * @brief Nombre mnemotecnico de la instruccion (p.ej. "add", "mov", "hlt").
     *
     * Usado solo para diagnostico y mensajes de error; no influye en la
     * ejecucion.
     */
    const char *name;

    /**
     * @brief Modo de direccionamiento de la instruccion.
     *
     * Indica como se codifican los operandos en el flujo de bytes.
     * El valor COUNT se usa como centinela de entrada invalida: si el
     * descodificador encuentra una entrada con mode == COUNT significa que
     * la tabla no esta completamente inicializada o hay un opcode incorrecto.
     */
    Assembly::Bytecode::AddressingMode mode =
        Assembly::Bytecode::AddressingMode::COUNT;

    /**
     * @brief Modo de tamano de la instruccion (numero de bytes que ocupa).
     *
     * Determina cuantos bytes debe avanzar el PC tras la ejecucion.
     * Los modos posibles son FIXED_1, FIXED_2, FIXED_4, FIXED_6, FIXED_8,
     * FIXED_10 y VAR (longitud variable).
     */
    Assembly::Bytecode::InstrSizeMode size =
        Assembly::Bytecode::InstrSizeMode::FIXED_1;

    /**
     * @brief Puntero a la funcion que implementa la semantica de la
     * instruccion.
     *
     * Se invoca durante la fase EXECUTE del pipeline.  Es responsable de
     * modificar registros, memoria, banderas u otros componentes de la VM.
     * No debe avanzar el PC; si la instruccion realiza un salto debe marcar
     * decoded_ptr->flags_info.did_jump = true para que execute_instruction()
     * no avance el PC automaticamente.
     *
     * @param vm    Proceso virtual sobre el que se ejecuta la instruccion.
     * @param instr Instruccion descodificada con todos sus operandos.
     */
    void (*exec)(ProcessVM *, const DecodedInstr &) = nullptr;

    /**
     * @brief Puntero a la funcion que descodifica los operandos de la
     * instruccion.
     *
     * Se invoca durante la fase DECODE del pipeline.  Lee los bytes del flujo
     * a partir del PC actual y rellena los campos de la estructura
     * DecodedInstr. No debe modificar el estado visible del proceso (registros,
     * memoria...).
     *
     * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
     * @param instr Estructura de instruccion que se rellena con los operandos.
     */
    void (*decode)(const InstrCursor &, DecodedInstr &) = nullptr;
} InstrFormat;

// =========================================================================
//  Descodificadores especializados por tipo de instruccion
// =========================================================================

/**
 * @brief Descodifica una instruccion de dos operandos registro-registro.
 *
 * Cubre ADD/SUB/MUL/DIV/CMP/AND/OR/XOR reg,reg y similares.
 * Lee mode (bits 7-6 del byte de control) y los dos registros del byte de regs.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_two_op_reg(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica instrucciones con codificacion de bytes crudos.
 *
 * Almacena byte2 en reg1 y byte3 en reg2 sin extraccion de nibbles.
 * Usado por instrucciones de strings (0x43-0x54) cuya convencion de encoding
 * es (r_dst<<4)|r_src en byte2, datos adicionales en byte3.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_raw_bytes(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica una instruccion de un solo registro con modo (INC/DEC).
 *
 * Formato: [opcode1][byte]
 *   byte: bits 5-4 = mode, bit 6 = variante (0=INC, 1=DEC), bits 3-0 =
 * registro.
 *
 * Solo aplica a instrucciones de la tabla primaria (sin prefijo 0x00).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_one_op_reg(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica una instruccion MOV registro-registro con byte de control.
 *
 * Similar a decode_instr_two_op_reg pero extrae ademas _signed_instruct y
 * direction del byte de control para soportar las variantes con extension
 * de signo y con direccion inversa.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_simple_mov(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica instrucciones de un solo byte sin operandos (NOP, HLT...).
 *
 * Solo fija size_instr a partir de los metadatos; no lee bytes adicionales.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_simple(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica instrucciones ALU inmediato-registro (ADD/SUB/MUL/DIV/CMP
 * imm,reg).
 *
 * Solo aplica a instrucciones de la tabla extendida (prefijo 0x00).
 * Longitud variable: 3 bytes fijos + longitud del inmediato segun el modo.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_inmed_reg(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica una instruccion CALLN (llamada a funcion nativa).
 *
 * Lee la direccion de la funcion nativa (8 bytes) y cachea argc desde R15
 * para que el predictor de saltos de la CPU pueda optimizar el switch(argc).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_calln(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica PUSH/POP con soporte de registros generales y especiales.
 *
 * Formato: [opcode][byte]
 *   bit 6 del byte == 1 -> registro especial (codigo de 6 bits).
 *   bit 6 del byte == 0 -> registro general (mode en bits 5-4, reg en bits
 * 3-0).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_push_pop(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica MOV con inmediato de longitud variable.
 *
 * Tres variantes segun direction y _signed_instruct:
 *   1. d=1, s=1 -> registro especial + imm64 (11 bytes).
 *   2. d=0, s=0 -> mov reg, imm (longitud variable segun modo).
 *   3. d=1, s=0 -> mov [reg], imm (longitud variable segun modo).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_inmed_mov(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica MOVC/MOVCH: movimiento entre registro y memoria (4 bytes
 * fijos).
 *
 * Formato: [0x00][0x1E][ctrl][byte4]
 *   bits 7-6 del ctrl: 0b10 = MOVCH (host), 0b00 = MOVC (VM).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_movc(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica XCHG con operandos mixtos (generales y/o especiales).
 *
 * Cada byte de datos codifica: bits 5-0 = codigo de registro,
 * bit 6 = flag de tipo (0=general, 1=especial).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_xchg(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica JMP/Jcc y CALLVM (salto absoluto, 10 bytes fijos).
 *
 * Formato: [opcode][cond_o_reservado][8 bytes addr]
 *   cond 0x0F (o no reconocido) = salto incondicional.
 *   cond 0x00-0x0D = salto condicional Jcc.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_jump(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica instrucciones sin operandos (RET, LEAVE).
 *
 * Solo fija size_instr a partir de los metadatos de la tabla.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_no_operands(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica JREL: salto relativo condicional (FIXED_8 extendido).
 *
 * Formato: [0x00][0x2D][cond][padding][disp32] = 8 bytes.
 * El disp32 se extiende con signo a 64 bits para soportar saltos hacia atras.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_jrel(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica instrucciones OOP de la forma [reg, imm8].
 *
 * Cubre CALLVIRT, CALLSUPER, GETFIELD, GETMETHOD.
 * Formato: [0x00][opcode][reg_byte][imm8] (FIXED_4).
 *   reg_byte bits 3-0 = registro general.
 *   imm8 = indice de vtable/campo/metodo (0-255).
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_oop_reg_imm8(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica instrucciones de lectura/escritura via cursor
 * (READCUR/WRITECUR/GCDEREF).
 *
 * Formato: [0x00][opcode][ctrl_byte][reg_byte] (FIXED_4).
 *   ctrl_byte bits 7-6 = mode, bits 5-4 = cursor index (0-3).
 *   reg_byte  bits 3-0 = registro general.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_cursor_rw(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica ADDCUR: avance/retroceso del cursor por inmediato con
 * signo.
 *
 * Formato: [0x00][0xC3][ctrl][pad][imm_lo][imm_hi] (FIXED_6).
 *   ctrl bits 5-4 = cur_idx (0-3); bytes 4-5 = imm16 con signo.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_addcur(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica VMCOPY y VCOPYH: copia entre VM memory y host memory.
 *
 * Formato compartido: [0x00][0xC4|0xC5][byte_A][byte_B] (FIXED_4).
 *   byte_A bits 5-4 = cur_idx, bits 3-0 = rSrc/rDst.
 *   byte_B bits 7-4 = rLen.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_vmcopy(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica instrucciones SIB (Scale-Index-Base).
 *
 * Formato: [0x00][opcode2][ctrl][regs][index][pad] (FIXED_6).
 *   ctrl: mode(2) | signed(1) | direction(1) | scale(2) | has_index(1) | 0
 *   regs: dst(4) | base(4)
 *   index: bits 3-0 = registro indice
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_sib(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica JUMPTABLE / TYPESWITCH (3 operandos empaquetados,
 * FIXED_4).
 *
 * Formato: [0x00][0x27|0x28][byte2][byte3]
 *   byte2 bits 7-4 = r_val/r_obj, bits 3-0 = r_table.
 *   byte3 = count (numero de entradas, uint8).
 * Resultado en mem_data: reg_base=r_val, reg_index=r_table, scale=count.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_jumptable(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica una instruccion de tres registros (msgsend).
 *
 * Formato FIXED_4: [0x00][opcode2][b2][b3]
 *   b2 = (r_pid<<4) | r_addr
 *   b3 = (r_len<<4)
 * Almacena en mem_data: reg_base=r_pid, reg_index=r_addr, reg_final=r_len.
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_three_reg(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica 4 regs empacados en FIXED_4 (4 nibbles, 2 bytes):
 *   byte2 (rip+2) = (r0 << 4) | r1
 *   byte3 (rip+3) = (r2 << 4) | r3
 * Almacena en mem_data: reg_base=r0, reg_index=r1, reg_final=r2, scale=r3.
 * Util para @c atomiccas (dst, addr, exp, des).
 */
void decode_instr_four_reg(const InstrCursor &c, DecodedInstr &instr);
void decode_instr_atomic_rmw(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica una instruccion de acceso a static field (getstatic /
 *        setstatic, FIXED_8).
 *
 * Formato fisico: @c [0x00][opcode2][regs_byte][_pad8][offset_u32_LE]
 *   regs_byte = (r0 << 4) | r1
 *   offset    = uint32 little-endian (bytes 4-7 desde el inicio)
 *
 * Almacena en @c data_instruction.static_data:
 *   r0     = nibble alto de regs_byte
 *   r1     = nibble bajo de regs_byte
 *   offset = uint32 leido de los 4 ultimos bytes
 *
 * El significado de r0/r1 depende del opcode:
 *   - getstatic: r0=r_dst, r1=r_class
 *   - setstatic: r0=r_class, r1=r_value
 *
 * @param vm    Proceso virtual cuyo RIP apunta al inicio de la instruccion.
 * @param instr Estructura de instruccion que se rellena.
 */
void decode_instr_static_offset(const InstrCursor &c, DecodedInstr &instr);

/// @brief Decoder de mld/mst (load/store universal, FIXED_8).  Lee la instr en
///        1 read_u64 y pre-decodifica a mem_full.  Ver exec_instr_mld/mst.
void decode_instr_mem_full(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodificador de @c dlopen / @c dlsym (FFI runtime, FIXED_4).
 *
 * Layout fisico desde @c rip+2:
 *   byte 0 (rip+2): b2 = (r_dst<<4) | rB
 *   byte 1 (rip+3): b3 = (rC<<4)    | rD
 *
 * Almacena en @c data_instruction.mem_data:
 *   reg_base  = nibble alto de b2 (r_dst)
 *   reg_index = nibble bajo de b2 (rB)
 *   reg_final = nibble alto de b3 (rC)
 *   scale     = nibble bajo de b3 (rD, solo usado por dlsym)
 *
 * Para dlopen: r_dst=destino, rB=r_path_addr, rC=r_path_len, rD=0.
 * Para dlsym:  r_dst=destino, rB=r_handle,    rC=r_name_addr, rD=r_name_len.
 */
void decode_instr_dlopen_dlsym(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodificador de @c callni (FIXED_4, 1 reg) para FFI runtime.
 *
 * Layout: @c [0x00][0x64][b2][b3] donde @c b2 = (r_fn<<4) | 0.
 * Almacena @c r_fn en @c data_instruction.reg_data.reg1.  El argc se
 * lee en runtime desde R15 igual que CALLN estatico.
 */
void decode_instr_callni(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Decoder de @c gcallocp (FIXED_4, 2 regs en byte2).
 * Layout: [0x00][0x65][b2][0x00] con b2 = (r_dst<<4) | r_size.
 */
void decode_instr_gcallocp(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Decoder de @c spawnargs (FIXED_4, 1 reg en byte2 hi-nibble).
 * Layout: [0x00][0x66][b2][0x00] con b2 = (r_pc<<4).  argc se lee de R15
 * en runtime (mismo modelo que callni / callvm).
 */
void decode_instr_spawnargs(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Decoder de @c fulfillhlt (FIXED_4, 2 regs en byte2).
 * Layout: [0x00][0x67][b2][0x00] con b2 = (r_fut<<4) | r_value.
 */
void decode_instr_fulfillhlt(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Decoder de @c cmpjmp / @c cmpjmpu (FIXED_8, 2 regs + cond + target).
 *
 * Layout: [0x00][0x68|0x69][b2][cond][target_u32].
 * Reusa la struct @c static_data de @c data_instruction:
 *   static_data.r0     = r_a (b2 high nibble)
 *   static_data.r1     = r_b (b2 low nibble)
 *   static_data._pad   = cond_byte (0x00..0x0D)
 *   static_data.offset = target u32
 */
void decode_instr_cmpjmp(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Decoder de @c decjnz (FIXED_8, 1 reg + target).
 *
 * Layout: [0x00][0x6A][b2][0x00][target_u32].
 *   static_data.r0     = r_counter (b2 high nibble)
 *   static_data.offset = target u32
 */
void decode_instr_decjnz(const InstrCursor &c, DecodedInstr &instr);

/**
 * @brief Descodifica @c fastpush / @c fastpop (extended 0x6B / 0x6C).
 *
 * Layout: [0x00][opcode2][mask_lo][mask_hi].  El mask uint16 (LE) se
 * almacena en @c data_instruction.mask_data.mask.
 */
void decode_instr_fastmask(const InstrCursor &c, DecodedInstr &instr);

// =========================================================================
//  Funciones principales del pipeline
// =========================================================================

/**
 * @brief Ejecuta la instruccion descodificada apuntada por decoded_ptr del
 * proceso.
 *
 * Llama a metadata->exec() y, si no hubo salto ni bloqueo, avanza el RIP.
 * Si la instruccion es bloqueante retorna EVT_IO_WAIT sin avanzar el PC.
 * Acumula tiempo de ejecucion en scheduler.time_exec si has_hooks esta activo.
 *
 * Posibles valores de retorno:
 *   - EVT_EXEC_DONE  -> instruccion completada correctamente.
 *   - EVT_IO_WAIT    -> instruccion bloqueante; no avanzar el PC.
 *   - EVT_HALT       -> instruccion HLT; detener el proceso.
 *   - EVT_ERROR      -> error fatal durante la ejecucion.
 *
 * @param process Proceso virtual cuya instruccion descodificada se ejecuta.
 * @return Evento que la FSM del scheduler debe procesar.
 */
vm_event execute_instruction(ProcessVM *process);

/**
 * @brief Descodifica la instruccion apuntada por el RIP del proceso.
 *
 * Implementa un ciclo de descodificacion con icache:
 *   - HIT:  si icache[PC % ICACHE_SIZE].pc == PC se reutiliza la entrada.
 *   - MISS: selecciona tabla primaria o extendida, llama al descodificador
 *           especializado y guarda el resultado en la icache.
 *
 * @param process Proceso virtual cuyo RIP apunta a la instruccion a
 * descodificar.
 */
/**
 * @brief Descodifica la instruccion de una direccion SIN tocar el proceso.
 *
 * La descodificacion normal escribe en la cache de instrucciones y deja el
 * proceso apuntando al resultado, asi que no sirve para MIRAR: recorrer un
 * rango con ella alteraria la ejecucion.  Esta solo lee.
 *
 * Hace falta para poder ensenar el codigo maquina de alrededor de un fallo, y
 * la necesitan igual el desensamblador y el depurador.
 *
 * @param process Proceso de cuya memoria se lee.
 * @param pc Direccion de la instruccion.
 * @param out Recibe la instruccion descodificada.
 * @return @c false si en esa direccion no hay una instruccion utilizable.
 */
bool decode_peek(ProcessVM *process, uint64_t pc, DecodedInstr &out);

void decode_instruction(ProcessVM *process);

} // namespace runtime

#endif // DECODE_INSTRUCTION_H
