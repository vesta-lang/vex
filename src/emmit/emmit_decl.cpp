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
 * @file emmit_decl.cpp                                                        \
 * @brief Implementacion de las funciones de emision de bytecode para VestaVM. \
 *                                                                             \
 * Implementa todas las funciones emit_* que generan bytes de instrucciones:   \
 *  - @c emit_ctrl_byte()              : byte de control [modo|s|d|reg]        \
 *  - @c encode_reg_general()          : codifica nombre de registro a indice  \
 * 4-bit                                                                       \
 *  - @c emit_inc_dec()                : INC/DEC con byte de datos combinado   \
 *  - @c emit_instr_reg()              : instruccion binaria registro-registro \
 *  - @c emit_instr_inmed()            : instruccion con operando inmediato    \
 *  - @c emit_instr_inmed_with_annotation(): inmediato con relocalizacion por  \
 * anotacion                                                                   \
 *  - @c emit_instr_mem()              : instruccion con operando de memoria   \
 * (etiqueta relativa)                                                         \
 *  - @c emit_instr_sib()              : instruccion con direccionamiento SIB  \
 *  - @c emit_mov_sib()                : variante MOV/MOVH con SIB             \
 *  - @c emit_movc()                   : MOVC/MOVCH (copia de memoria con      \
 * codigo de flags)                                                            \
 *  - @c emit_movc_reg()               : MOVC registro-registro                \
 *  - @c emit_jcc()                    : saltos condicionales                  \
 *  - @c emit_jmp()                    : salto incondicional                   \
 *  - @c emit_call()                   : llamada a funcion                     \
 *  - @c emit_ret()                    : retorno de funcion                    \
 *  - @c emit_push() / @c emit_pop()   : operaciones de pila                   \
 *  - @c emit_nop()                    : instruccion NOP                       \
 *  - @c emit_hlt()                    : instruccion HLT                       \
 *  - @c emit_syscall()                : llamada al sistema                    \
 *  - @c emit_int()                    : interrupcion software                 \
 *  - @c emit_gcnew() / @c emit_gcfree(): instrucciones GC                     \
 *  - @c emit_new() / @c emit_free()   : instrucciones OOP                     \
 */                                                                            \
#include "emmit/emmit_decl.h"

#include "emmit/parser_to_bytecode.h"

#ifdef DEBUG_EMIT
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)                                                       \
    if (0) {                                                                   \
        printf(__VA_ARGS__);                                                   \
    }
#endif

/**
 *  las funciones emit_* generan los bytes restantes de una instruccion
 * El llamante (emit_instruction) es responsable de emitir el/los bytes de
 * opcode primero.
 */
namespace Assembly::Bytecode {

// =========================================================================
// Funciones auxiliares internas
// =========================================================================

/**
 * @brief Emite un byte de control con el layout estandar [modo|s|d|reg].
 *
 * Layout de bits:  bits[7:6] = modo (ancho de operando)
 *              bit[5]    = s    (flag de signo o marcador de registro especial)
 *              bit[4]    = d    (direccion: 0=destino reg, 1=destino mem)
 *              bits[3:0] = reg  (codigo de registro de 4 bits, nibble bajo)
 *
 * @param out  Escritor de bytes de salida.
 * @param mode Codigo de ancho de 2 bits (0=8b, 1=16b, 2=32b, 3=64b).
 * @param s    Flag de 1 bit signo/especial.
 * @param d    Flag de direccion de 1 bit.
 * @param reg  Codigo de registro (solo los 4 bits bajos).
 */
static void emit_ctrl_byte(ByteWriter &out, uint8_t mode, uint8_t s, uint8_t d,
                           uint8_t reg) {
    out.emit8(
        static_cast<uint8_t>((mode << 6) | // modo ocupa bits 7-6
                             (s << 5) |    // s ocupa el bit 5
                             (d << 4) |    // d ocupa el bit 4
                             (reg & 0xF)   // reg ocupa bits 3-0 (nibble bajo)
                             ));
}

// =========================================================================
// Codificacion de registros
// =========================================================================

/**
 * @brief Codifica un nombre de registro (rN / rNN) a su codigo numerico de 4
 * bits.
 *
 * r0-r9   -> 0-9    (un digito despues de 'r')
 * r10-r15 -> 10-15  (dos digitos; la forma r01 se acepta como r1)
 *
 * @param name  Nombre de registro terminado en nulo (ej: "r07", "r15").
 * @return      Codigo de registro de 4 bits (0-15).
 * @throws std::runtime_error Si el nombre no coincide con el patron esperado.
 */
uint8_t encode_reg_general(const char *const name) {
    uint8_t n_reg = 0; // acumula el indice numerico del registro

    if (name[0] == 'r' || name[0] == 'R') {
        if (name[1] && isdigit(static_cast<unsigned char>(name[1]))) {
            n_reg = name[1] - '0'; // primer digito despues de 'r'
            if (name[2] && isdigit(static_cast<unsigned char>(name[2]))) {
                if (n_reg != 0) {
                    // numero de dos digitos, ej: r10, r15
                    return (n_reg * 10) + (name[2] - '0');
                }
                // forma r01 con cero inicial: devolver solo el segundo digito
                return (name[2] - '0');
            }
            return n_reg; // registro de un digito, ej: r7
        }
        throw std::runtime_error("Invalid register: missing digit after 'r'");
    }
    throw std::runtime_error("Invalid register: name must start with 'r'");
}

// =========================================================================
// Emision de INC / DEC
// =========================================================================

/**
 * @brief Emite el byte de datos para una instruccion INC o DEC.
 *
 * Layout del byte:  bits[7:6] = modo (ancho de operando)
 *               bit[6]    = b    (0 = INC, 1 = DEC; almacenado como bit 0x40)
 *               bits[3:0] = codigo de registro
 *
 * @param instruction_parser Nodo de instruccion parseado.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion (opcode, modo de tamano).
 * @param assembly_ctx       Contexto del ensamblador (no usado, requerido por
 * la firma).
 */
void emit_inc_dec(const vm::Instruction *instruction_parser,
                  ByteWriter &code_final, const InstrInfo *now_instr,
                  Assembler *assembly_ctx) {
    // bit 6: 0=INC, 1=DEC
    uint8_t reg = (instruction_parser->opcode == "inc") ? 0 : 0b01000000;

    auto s = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    if (s == nullptr)
        throw std::runtime_error("INC/DEC: operand must be a register");

    uint8_t mode = encode_mode(s->size_bits); // codigo de ancho de 2 bits
    reg += mode << 4;                         // modo ocupa bits 5-4
    reg +=
        encode_reg_general(s->name.c_str()); // codigo de registro en bits 3-0
    code_final.emit8(reg); // emitir el byte de datos combinado

    DEBUG_PRINT("Emitiendo INC/DEC 0x%x REG: 0x%x, Size: %llu\n",
                now_instr->opcode1, reg, instr_size(now_instr->sizeMode));
}

// =========================================================================
// Emision de instruccion binaria generica (reg, reg)
// =========================================================================

/**
 * @brief Emite dos bytes de datos para instruccion binaria registro-registro.
 *
 * Byte 1 (ctrl):  [modo(2) | signo(1) | 0 | 0000]
 * Byte 2 (regs):  [reg2(4) | reg1(4)]
 *
 * Ambos registros deben tener el mismo size_bits.
 *
 * @param instruction_parser Nodo de instruccion parseado.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_reg(const vm::Instruction *instruction_parser,
                    ByteWriter &code_final, const InstrInfo *now_instr,
                    Assembler *assembly_ctx) {
    auto reg1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto reg2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (reg1 == nullptr || reg2 == nullptr)
        throw std::runtime_error("Instruction " + instruction_parser->opcode +
                                 " requires two register operands");

    if (reg1->size_bits != reg2->size_bits)
        throw std::runtime_error("Instruction " + instruction_parser->opcode +
                                 " " + reg1->name + " " + reg2->name +
                                 ": operands must have the same size");

    bool is_a_signed =
        is_signed(instruction_parser->opcode);   // detectar variante con signo
    uint8_t mode = encode_mode(reg1->size_bits); // codigo de ancho de 2 bits

    // byte ctrl: modo | signo | 0 | 0000
    emit_ctrl_byte(code_final, mode, is_a_signed ? 1 : 0, 0, 0);

    // byte reg: reg2 en nibble alto, reg1 en nibble bajo
    code_final.emit8(encode_reg_general(reg2->name.c_str()) << 4 |
                     encode_reg_general(reg1->name.c_str()));

    DEBUG_PRINT("Emitiendo %s 0x%02x 0x%02x REG1(%s): 0x%02x, REG2(%s): 0x%02x "
                "MODE: %d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode1,
                now_instr->opcode2, reg1->name.c_str(),
                encode_reg_general(reg2->name.c_str()) << 4, reg2->name.c_str(),
                encode_reg_general(reg1->name.c_str()), mode);
}

// =========================================================================
// Instruccion con inmediato y anotacion (referencia a etiqueta)
// =========================================================================

/**
 * @brief Emite un byte ctrl + placeholder de relocalizacion para instruccion
 * con anotacion.
 *
 * Maneja tres tipos de anotacion:
 *   - "Method"   -> absolute pointer-sized relocation using the machine word
 * size.
 *   - "Relative" -> relative relocation sized to the register width.
 *   - "Absolute" -> absolute relocation sized to the register width.
 *
 * El valor placeholder emitido es siempre 0; el enlazador lo parchea al
 * enlazar.
 *
 * @param instruction_parser Nodo parseado (operandos[0]=reg,
 * operandos[1]=anotacion).
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador (propietario de la tabla
 * de relocalizaciones).
 */
void emit_instr_inmed_with_annotation(const vm::Instruction *instruction_parser,
                                      ByteWriter &code_final,
                                      const InstrInfo *now_instr,
                                      Assembler *assembly_ctx) {
    bool is_a_signed =
        is_signed(instruction_parser->opcode); // detectar variante con signo

    auto reg = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto annotacion = dynamic_cast<vm::AnnotationNode *>(
        instruction_parser->operands[1].get());

    if (annotacion == nullptr)
        throw std::runtime_error("emit_instr_inmed_with_annotation(): expected "
                                 "annotation operand for: " +
                                 instruction_parser->opcode);

    if (annotacion->key == "Method") {
        // anotacion Method: usar el ancho del puntero maquina
        uint8_t mode =
            encode_mode(sizeof(void *) * 8); // modo de tamano de puntero
        bool mem_dest = false; // el destino siempre es un registro

        emit_ctrl_byte(
            code_final, mode, is_a_signed ? 1 : 0, mem_dest ? 1 : 0,
            encode_reg_general(reg->name.c_str())); // emitir byte de control

        // registrar la relocalizacion para que el enlazador parchee el
        // placeholder
        Relocation rel;
        rel.symbol =
            annotacion->value; // symbol name (e.g. "kernel32.dll:Func")
        rel.section = assembly_ctx->current_section->name;
        rel.offset = code_final.offset;      // posicion de escritura actual
        rel.type = size_ptr_in_this_machine; // relocalizacion absoluta al ancho
                                             // del puntero

        assembly_ctx->ctx.add_relocation(rel); // registrar relocalizacion

        // emitir bytes placeholder (el enlazador los parcheara)
        if (size_ptr_in_this_machine == Type::Absolute64)
            code_final.emit64(0);
        else if (size_ptr_in_this_machine == Type::Absolute32)
            code_final.emit32(0);
        else if (size_ptr_in_this_machine == Type::Absolute16)
            code_final.emit16(0);
        else if (size_ptr_in_this_machine == Type::Absolute8)
            code_final.emit8(0);
        else
            throw std::runtime_error(
                "emit_instr_inmed_with_annotation(): unsupported pointer size "
                "for Method annotation");

    } else {
        // anotacion Relative/Absolute: tamano de relocalizacion sigue ancho del
        // registro
        uint8_t mode = encode_mode(
            reg->size_bits);   // ancho de 2 bits segun tamano del registro
        bool mem_dest = false; // el destino siempre es un registro

        emit_ctrl_byte(
            code_final, mode, is_a_signed ? 1 : 0, mem_dest ? 1 : 0,
            encode_reg_general(reg->name.c_str())); // emitir byte de control

        Relocation rel;
        rel.symbol = annotacion->value;
        rel.section = assembly_ctx->current_section->name;
        rel.offset =
            code_final.offset; // posicion de escritura despues del byte ctrl

        // derivar tipo de relocalizacion desde la clave de anotacion
        if (annotacion->key == "Relative") {
            rel.type =
                mode_to_type_relocation_rel(mode); // e.g. Relative32 for mode=2
        } else if (annotacion->key == "Absolute") {
            rel.type =
                mode_to_type_relocation_abs(mode); // e.g. Absolute64 for mode=3
        } else {
            throw std::runtime_error(
                "emit_instr_inmed_with_annotation(): unsupported annotation: " +
                annotacion->key);
        }

        if (rel.type == Type::NO_VALID)
            throw std::runtime_error(
                "emit_instr_inmed_with_annotation(): unsupported annotation: " +
                annotacion->key);

        assembly_ctx->ctx.add_relocation(rel); // registrar relocalizacion

        uint64_t val_inmmed = 0; // placeholder: el enlazador sobreescribira
        size_t size_in_bytes =
            mode_to_bytes(mode); // numero de bytes placeholder a emitir
        code_final.emit_bytes(&val_inmmed, size_in_bytes); // emitir placeholder
    }
}

// =========================================================================
// Emision generica de instruccion con inmediato
// =========================================================================

/**
 * @brief Emite un byte ctrl + valor inmediato para instruccion con operando
 * inmediato.
 *
 * Maneja tres sub-casos:
 *   1. operands[1] is an annotation -> delegates to
 * emit_instr_inmed_with_annotation.
 *   2. operands[0] is a register    -> direction=0 (register destination).
 *   3. operands[0] is memory        -> direction=1 (memory destination).
 *
 * El valor inmediato se valida para que quepa en el ancho del registro.
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_inmed(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    if (now_instr->opcode1 != 0x00)
        throw std::runtime_error(
            "emit_instr_inmed: opcode1 != 0x00 not implemented");

    bool is_a_signed =
        is_signed(instruction_parser->opcode); // detectar variante con signo

    auto n0 = instruction_parser->operands[0].get(); // primer operando
    auto n1 = instruction_parser->operands[1].get(); // segundo operando

    auto inmmed_str = dynamic_cast<vm::NumberOperand *>(
        n1); // intentar leer el valor inmediato

    auto reg = dynamic_cast<vm::RegisterOperand *>(n0); // destino registro
    auto mem = dynamic_cast<vm::MemoryOperand *>(n0);   // destino memoria
    bool mem_dest = reg == nullptr; // verdadero cuando el destino es memoria

    if ((mem == nullptr) || inmmed_str == nullptr) {
        // verificar si el segundo operando es una referencia de anotacion
        if (auto annotacion = dynamic_cast<vm::AnnotationNode *>(n1)) {
            emit_instr_inmed_with_annotation(instruction_parser, code_final,
                                             now_instr, assembly_ctx);
            return;
        }

        // ni anotacion ni combinacion valida inmediato/memoria
        if (mem == nullptr && inmmed_str == nullptr)
            throw std::runtime_error(
                "emit_instr_inmed: " + instruction_parser->opcode +
                ": could not locate a register or immediate operand; check "
                "syntax");
    }

    // parsear el valor inmediato numerico
    auto inmmed_opt = vm::parse_number_safe(inmmed_str->value);
    if (inmmed_opt == std::nullopt)
        throw std::runtime_error("emit_instr_inmed: invalid number: " +
                                 inmmed_str->value);

    uint64_t val_inmmed = inmmed_opt.value(); // valor inmediato parseado
    ImmType type = detect_imm_type((int64_t)val_inmmed,
                                   is_a_signed); // clasificar por ancho de bits

    if (mem_dest) {
        // destino memoria: extract the base register from the memory operand
        reg = static_cast<vm::RegisterOperand *>(mem->expr.get());
        if (reg == nullptr) {
            std::cout << "emit_instr_inmed: " << instruction_parser->opcode
                      << ": expected register inside memory operand\n";
            mem->expr->print(0);
            throw std::runtime_error("emit_instr_inmed: " +
                                     instruction_parser->opcode);
        }
    }

    uint8_t mode =
        encode_mode(reg->size_bits); // codigo de ancho de 2 bits del registro

    // validar que el inmediato cabe en el ancho del registro
    int instr_imm_bits =
        immtype_bits(type); // bits requeridos para el inmediato
    int instr_mode_bits = mode_to_bits(mode); // bits del modo de registro

    if (instr_imm_bits > instr_mode_bits)
        throw std::runtime_error(
            "emit_instr_inmed: immediate " + std::to_string(val_inmmed) + " (" +
            std::to_string(instr_imm_bits) + " bits) exceeds mode " +
            std::to_string(mode) + " (" + std::to_string(instr_mode_bits) +
            " bits)");

    // byte ctrl: modo | signo | dest_mem | reg
    emit_ctrl_byte(code_final, mode, is_a_signed ? 1 : 0, mem_dest ? 1 : 0,
                   encode_reg_general(reg->name.c_str()));

    // emitir bytes del inmediato segun ancho del registro
    code_final.emit_bytes(&val_inmmed, mode_to_bytes(mode));

    DEBUG_PRINT("Emitiendo %s 0x%02x 0x%02x REG(%s): 0x%02x, INMED 0x%llx "
                "TYPE: %d MODE: %d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode1,
                now_instr->opcode2, reg->name.c_str(),
                encode_reg_general(reg->name.c_str()), val_inmmed, type, mode);
}

// =========================================================================
// Emision de instruccion con operando de memoria (etiqueta relativa)
// =========================================================================

/**
 * @brief Emite un byte ctrl + relocalizacion relativa de 40 bits para
 * instruccion con etiqueta.
 *
 * Espera exactamente un operando de memoria (con etiqueta) y un operando de
 * registro. El placeholder de 40 bits es parcheado por el enlazador con
 * relocalizacion Relative40.
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_mem(const vm::Instruction *instruction_parser,
                    ByteWriter &code_final, const InstrInfo *now_instr,
                    Assembler *assembly_ctx) {
    if (now_instr->opcode1 != 0x00)
        throw std::runtime_error(
            "emit_instr_mem: opcode1 != 0x00 not implemented");

    bool is_a_signed =
        is_signed(instruction_parser->opcode); // detectar variante con signo

    auto n0 = instruction_parser->operands[0].get(); // primer operando
    auto n1 = instruction_parser->operands[1].get(); // segundo operando

    uint8_t direccion = 1; // default: [mem], reg
    auto mem = dynamic_cast<vm::MemoryOperand *>(n0);
    auto reg = dynamic_cast<vm::RegisterOperand *>(n1);

    // intentar el layout inverso si el primer operando no es memoria
    if (mem == nullptr || reg == nullptr) {
        direccion = 0; // reversed: reg, [mem]
        mem = dynamic_cast<vm::MemoryOperand *>(n1);
        reg = dynamic_cast<vm::RegisterOperand *>(n0);
    }

    if (mem == nullptr || reg == nullptr)
        throw std::runtime_error(
            "emit_instr_mem: " + instruction_parser->opcode +
            ": requires one memory operand and one register operand");

    uint8_t mode = encode_mode(
        reg->size_bits); // ancho de 2 bits segun tamano del registro

    // byte ctrl: codifica modo, signo, direccion y registro
    emit_ctrl_byte(code_final, mode, is_a_signed ? 1 : 0,
                   direccion, // nota: el orden de campos es s, d aqui
                   encode_reg_general(reg->name.c_str()));
    // Note: the emit_ctrl_byte layout is mode|s|d|reg; 'direccion' maps to the
    // 'd' bit.

    // extraer el nombre de etiqueta de la expresion de memoria
    auto lalbel = dynamic_cast<vm::LabelOperand *>(mem->expr.get());

    Relocation rel;
    rel.symbol = lalbel->name; // etiqueta destino
    rel.section = assembly_ctx->current_section
                      ->name;       // seccion que contiene esta instruccion
    rel.offset = code_final.offset; // posicion de escritura del placeholder
    rel.type = Type::Relative40;    // relocalizacion relativa de 40 bits

    assembly_ctx->ctx.add_relocation(
        rel); // registrar relocalizacion para el enlazador

    // emitir placeholder de 40 bits (5 bytes, parcheado por enlazador)
    code_final.emit40(0x1122334455);
}

// =========================================================================
// Funciones auxiliares para parsear expresiones SIB
// =========================================================================

/**
 * @brief Convierte un ExprNode* a un subtipo AST concreto via void* para evitar
 * UB.
 *
 * El parser almacena a veces objetos no-ExprNode (RegisterOperand,
 * NumberOperand) como ExprNode* via static_cast. Este helper recupera el tipo
 * original de forma segura pasando por void* -> ASTNode* primero, luego
 * dynamic_cast a T.
 *
 * @tparam T Tipo destino (debe ser subclase de ASTNode).
 * @param  node Puntero ExprNode (puede apuntar a un T).
 * @return      Puntero a T, o nullptr si la conversion falla.
 */
template <typename T> static const T *sib_cast(const vm::ExprNode *node) {
    // reinterpretar via void* para romper la suposicion ExprNode*, luego
    // dynamic_cast
    return dynamic_cast<const T *>(
        static_cast<const vm::ASTNode *>(static_cast<const void *>(node)));
}

/**
 * @brief Extrae el desplazamiento de escala de un nodo de escala
 * (NumberOperand).
 *
 * Convierte el entero bruto (1/2/4/8) al encoding de desplazamiento de 2 bits:
 *   1 -> 0,  2 -> 1,  4 -> 2,  8 -> 3.
 *
 * @param  node ExprNode que se espera sea un NumberOperand.
 * @return      Valor de desplazamiento de 2 bits, o 0 si el nodo no es un
 * numero.
 */
static uint8_t parse_scale(const vm::ExprNode *node) {
    auto *sc = sib_cast<vm::NumberOperand>(
        node);         // intentar leer la escala como numero
    if (!sc) return 0; // sin escala: tratar como *1 (shift=0)
    int sv = std::stoi(sc->value, nullptr, 0); // parsear el valor de escala
    return (sv <= 1)   ? 0
           : (sv == 2) ? 1
           : (sv == 4) ? 2
                       : 3; // mapear a desplazamiento de 2 bits
}

/**
 * @brief Recorre el AST de una expresion de memoria y extrae base, indice y
 * escala.
 *
 * Formas soportadas:
 *   [base]               -> base establecido, index=0, scale=0
 *   [base + index]       -> base e indice establecidos, scale=0
 *   [base + index*scale] -> los tres establecidos
 *   [index*scale + base] -> igual, operandos intercambiados
 *   [index*scale]        -> sin base, solo indice y escala
 *
 * @param  expr  Raiz del AST de la expresion de direccion de memoria.
 * @param  base  [out] Indice del registro base codificado.
 * @param  index [out] Indice del registro indice codificado.
 * @param  scale [out] Desplazamiento de escala de 2 bits.
 */
static void parse_sib_expr(const vm::ASTNode *expr, uint8_t &base,
                           uint8_t &index, uint8_t &scale) {
    base = 0;
    index = 0;
    scale = 0; // inicializar a cero (sin base/indice/escala)

    if (auto *reg = dynamic_cast<const vm::RegisterOperand *>(expr)) {
        base = encode_reg_general(reg->name.c_str()); // forma simple [base]
        return;
    }

    auto *bin = dynamic_cast<const vm::BinaryExpr *>(expr);
    if (!bin) throw std::runtime_error("SIB: unsupported memory expression");

    if (bin->op == '*') {
        // [index*scale] -- no base register
        auto *idx =
            sib_cast<vm::RegisterOperand>(bin->left.get()); // try left as index
        auto *sc = bin->left.get(); // tentatively left as scale
        if (!idx) {
            idx = sib_cast<vm::RegisterOperand>(
                bin->right.get()); // el indice esta a la derecha
            sc = bin->left.get();  // la escala esta a la izquierda
        } else {
            sc = bin->right.get(); // la escala esta a la derecha
        }
        if (idx)
            index =
                encode_reg_general(idx->name.c_str()); // encode index register
        scale = parse_scale(sc);                       // extract 2-bit scale
        return;
    }

    if (bin->op == '+') {
        auto *left_reg = sib_cast<vm::RegisterOperand>(
            bin->left.get()); // try left as register
        auto *left_mul = dynamic_cast<const vm::BinaryExpr *>(
            bin->left.get()); // try left as multiply
        auto *right_reg = sib_cast<vm::RegisterOperand>(
            bin->right.get()); // try right as register
        auto *right_mul = dynamic_cast<const vm::BinaryExpr *>(
            bin->right.get()); // try right as multiply

        if (left_reg && right_reg) {
            // [base + index] with scale=1
            base = encode_reg_general(left_reg->name.c_str());
            index = encode_reg_general(right_reg->name.c_str());
            scale = 0; // shift=0 means *1
        } else if (left_reg && right_mul && right_mul->op == '*') {
            // [base + index*scale]
            base = encode_reg_general(left_reg->name.c_str());
            auto *idx = sib_cast<vm::RegisterOperand>(
                right_mul->left.get());        // index on left
            auto *sc = right_mul->right.get(); // scale on right
            if (!idx) {
                idx = sib_cast<vm::RegisterOperand>(
                    right_mul->right.get()); // index on right
                sc = right_mul->left.get();  // scale on left
            }
            if (idx)
                index = encode_reg_general(idx->name.c_str()); // encode index
            scale = parse_scale(sc);                           // extract scale
        } else if (left_mul && left_mul->op == '*' && right_reg) {
            // [index*scale + base]
            base = encode_reg_general(right_reg->name.c_str());
            auto *idx = sib_cast<vm::RegisterOperand>(
                left_mul->left.get());        // index on left
            auto *sc = left_mul->right.get(); // scale on right
            if (!idx) {
                idx = sib_cast<vm::RegisterOperand>(
                    left_mul->right.get()); // index on right
                sc = left_mul->left.get();  // scale on left
            }
            if (idx)
                index = encode_reg_general(idx->name.c_str()); // encode index
            scale = parse_scale(sc);                           // extract scale
        } else {
            throw std::runtime_error(
                "SIB: unrecognised memory expression form");
        }
        return;
    }

    throw std::runtime_error("SIB: unsupported memory operator");
}

// =========================================================================
// Emision de instrucciones SIB
// =========================================================================

/**
 * @brief Emite cuatro bytes para una instruccion con direccionamiento SIB.
 *
 * Disposicion de bytes:
 *   byte2 (ctrl):    mode(2) | signed(1) | dir(1) | scale(2) | has_index(1) | 0
 *   byte3 (regs):    dst_reg(4) | base_reg(4)
 *   byte4 (index):   index_reg(4) | 0000
 *   byte5 (pad):     0x00
 *
 * @param instruction_parser Instruccion parseada (un registro y un operando de
 * memoria).
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_sib(const vm::Instruction *instruction_parser,
                    ByteWriter &code_final, const InstrInfo *now_instr,
                    Assembler *assembly_ctx) {
    // Para MOV SIB el bit _signed_instruct (bit 5 del ctrl) selecciona
    // memoria HOST cuando se activa.  Reutilizamos la misma helper
    // (is_signed) para ALU con signo y añadimos is_host_sib() para los
    // mnemonicos que mapean al modo host.  Los conjuntos son disjuntos.
    bool is_a_signed = is_signed(instruction_parser->opcode) ||
                       is_host_sib(instruction_parser->opcode);

    auto *op0 = instruction_parser->operands[0].get(); // primer operando
    auto *op1 = instruction_parser->operands[1].get(); // segundo operando

    vm::RegisterOperand *reg_op = nullptr;
    vm::MemoryOperand *mem_op = nullptr;
    uint8_t direction = 0; // 0 = reg, [mem] ; 1 = [mem], reg

    if (auto *r = dynamic_cast<vm::RegisterOperand *>(op0)) {
        reg_op = r;                                      // register on the left
        mem_op = dynamic_cast<vm::MemoryOperand *>(op1); // memory on the right
        direction = 0; // el destino es el registro
    } else {
        mem_op = dynamic_cast<vm::MemoryOperand *>(op0); // memory on the left
        reg_op =
            dynamic_cast<vm::RegisterOperand *>(op1); // register on the right
        direction = 1;                                // el destino es memoria
    }

    if (!reg_op || !mem_op)
        throw std::runtime_error(
            "SIB: " + instruction_parser->opcode +
            " requires one register and one SIB memory operand");

    uint8_t base = 0, index = 0, scale = 0;
    parse_sib_expr(mem_op->expr.get(), base, index,
                   scale); // decodificar la expresion de direccion

    // has_index is set whenever the expression is a BinaryExpr (base+index
    // form)
    uint8_t has_index =
        (dynamic_cast<const vm::BinaryExpr *>(mem_op->expr.get()) != nullptr)
            ? 1
            : 0;

    uint8_t mode = encode_mode(reg_op->size_bits); // codigo de ancho de 2 bits
    uint8_t dst_reg = encode_reg_general(
        reg_op->name.c_str()); // 4-bit destination register code

    // ctrl: mode(2) | signed(1) | dir(1) | scale(2) | has_index(1) | 0
    uint8_t ctrl =
        (uint8_t)((mode << 6) |                  // operand width
                  ((is_a_signed ? 1 : 0) << 5) | // signed flag
                  (direction << 4) | // direction: 0=reg dst, 1=mem dst
                  ((scale & 0x3)
                   << 2) |         // 2-bit scale shift (0=*1, 1=*2, 2=*4, 3=*8)
                  (has_index << 1) // 1=has index register
        );
    code_final.emit8(ctrl); // emitir byte de control

    code_final.emit8((dst_reg << 4) | (base & 0xF)); // emit reg/base byte
    code_final.emit8(index & 0xF); // emit index register byte (low nibble)
    code_final.emit8(0x00);        // emit padding byte
}

// =========================================================================
// XCHG instruction emission
// =========================================================================

/**
 * @brief Emite los bytes de datos para una instruccion XCHG.
 *
 * Disposicion de bytes:
 *   byte1 (flags):  0x00  (reserved, not yet used)
 *   byte2 (reg1):   special-bit(1) | mode(2) | reg_code(4)   or  special-bit(1)
 * | special_code(6) byte3 (reg2):   same encoding as byte2
 *
 * El bit especial (bit 6) distingue registros generales de
 * especiales/extendidos.
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_xchg(const vm::Instruction *instruction_parser,
               ByteWriter &code_final, const InstrInfo *now_instr,
               Assembler *assembly_ctx) {
    auto reg1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto reg2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (reg1 == nullptr)
        throw std::runtime_error("XCHG: missing first register operand");
    if (reg2 == nullptr)
        throw std::runtime_error("XCHG: missing second register operand");

    uint8_t flags = 0;       // flags byte is reserved and always 0 for now
    code_final.emit8(flags); // emit flags byte

    // determine whether each register is special/extended
    std::optional<uint8_t> opt_special1 = encode_special_register(reg1->name);
    std::optional<uint8_t> opt_special2 = encode_special_register(reg2->name);

    // codificar el primer byte de registro
    uint8_t byte1 = 0;
    if (opt_special1) {
        byte1 = 0b0100'0000; // set special-register marker bit
        byte1 = byte1 |
                opt_special1.value(); // lower 6 bits = special register code
    } else {
        uint8_t mode =
            encode_mode(reg1->size_bits); // codigo de ancho de 2 bits
        uint8_t reg_code =
            encode_reg_general(reg1->name.c_str()); // 4-bit register code
        byte1 = byte1 | (mode << 4 | reg_code);     // pack mode and register
    }

    // codificar el segundo byte de registro
    uint8_t byte2 = 0;
    if (opt_special2) {
        byte2 = 0b0100'0000; // set special-register marker bit
        byte2 = byte2 |
                opt_special2.value(); // lower 6 bits = special register code
    } else {
        uint8_t mode =
            encode_mode(reg2->size_bits); // codigo de ancho de 2 bits
        uint8_t reg_code =
            encode_reg_general(reg2->name.c_str()); // 4-bit register code
        byte2 = byte2 | (mode << 4 | reg_code);     // pack mode and register
    }

    code_final.emit8(byte1); // emit first operand byte
    code_final.emit8(byte2); // emit second operand byte
}

// =========================================================================
// PUSH / POP emission
// =========================================================================

/**
 * @brief Emite un byte de datos para una instruccion PUSH o POP.
 *
 * Disposicion de bytes:
 *   General register:  0 | mode(2) | reg_code(4)
 *   Special register:  1 | special_code(6)
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_pop_push(const vm::Instruction *instruction_parser,
                   ByteWriter &code_final, const InstrInfo *now_instr,
                   Assembler *assembly_ctx) {
    auto n0 = instruction_parser->operands[0].get();
    auto reg = dynamic_cast<vm::RegisterOperand *>(n0);

    if (reg == nullptr)
        throw std::runtime_error("PUSH/POP: expected a register operand");

    std::optional<uint8_t> opt_special =
        encode_special_register(reg->name); // verificar si es registro especial
    uint8_t byte = 0x00;                    // final encoded byte

    if (opt_special) {
        // special/extended register: bit 6 set, lower 6 bits = register code
        uint8_t reg_ext = 1;
        uint8_t reg_code = opt_special.value();
        byte = (reg_ext << 6) | reg_code; // [1 | special_code(6)]
    } else {
        // general register: bit 6 clear, next 2 bits = mode, lower 4 bits =
        // register
        uint8_t reg_ext = 0;
        uint8_t mode = encode_mode(reg->size_bits); // 2-bit width
        uint8_t reg_code =
            encode_reg_general(reg->name.c_str()); // 4-bit register code
        byte =
            (reg_ext << 6) | (mode << 4) | reg_code; // [0 | mode(2) | reg(4)]
    }

    code_final.emit8(byte); // emitir el byte codificado
}

// =========================================================================
// MOV reg, reg emission (with special/extended register support)
// =========================================================================

/**
 * @brief Emite dos bytes de datos para MOV con dos operandos de registro.
 *
 * Forma estandar (ambos generales):
 *   byte1 (ctrl):  mode(2) | 0 | 0 | 0000   (is_a_signed=0, direction=0)
 *   byte2 (regs):  reg2(4) | reg1(4)
 *
 * Forma con registro especial (uno general, uno especial/extendido):
 *   is_a_signed=1 se usa como marca de uso de registro especial.
 *   direction=0 -> MOV reg_ext, reg   (escribir especial desde general)
 *   direction=1 -> MOV reg, reg_ext   (leer especial a general)
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_mov_reg(const vm::Instruction *instruction_parser,
                        ByteWriter &code_final, const InstrInfo *now_instr,
                        Assembler *assembly_ctx) {
    auto reg1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto reg2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (reg1 == nullptr || reg2 == nullptr)
        throw std::runtime_error("MOV: requires two register operands");

    if (reg1->size_bits != reg2->size_bits)
        throw std::runtime_error("MOV " + reg1->name + " " + reg2->name +
                                 ": registers must be the same size");

    std::optional<uint8_t> opt_reg1_special =
        encode_special_register(reg1->name);
    std::optional<uint8_t> opt_reg2_special =
        encode_special_register(reg2->name);

    bool r1_special =
        opt_reg1_special
            .has_value(); // verdadero si reg1 es un registro especial
    bool r2_special =
        opt_reg2_special
            .has_value(); // verdadero si reg2 es un registro especial

    if (r1_special && r2_special)
        throw std::runtime_error(
            "MOV: cannot use two special/extended registers");

    if (!r1_special && !r2_special) {
        // standard MOV reg1, reg2 (both general registers)
        uint8_t mode = encode_mode(reg1->size_bits); // 2-bit width
        uint8_t is_a_signed = 0; // s=0 signals general-register form
        uint8_t direction = 0;   // d=0, no direction concept here

        emit_ctrl_byte(code_final, mode, is_a_signed, direction,
                       0); // emit ctrl (lower nibble unused)
        code_final.emit8(  // emit register pair byte
            encode_reg_general(reg2->name.c_str()) << 4 |
            encode_reg_general(reg1->name.c_str()));

        DEBUG_PRINT("Emitiendo %s 0x%02x 0x%02x REG1(%s): 0x%02x, REG2(%s): "
                    "0x%02x MODE: %d\n",
                    instruction_parser->opcode.c_str(), now_instr->opcode1,
                    now_instr->opcode2, reg1->name.c_str(),
                    encode_reg_general(reg2->name.c_str()) << 4,
                    reg2->name.c_str(), encode_reg_general(reg1->name.c_str()),
                    mode);
        return;
    }

    // One operand is a special register.
    // is_a_signed=1 marks the special-register variant (see
    // exec_instr_mov_reg).
    uint8_t is_a_signed = 1;

    // determine which is the general and which is the special register
    uint8_t reg_general =
        r1_special ? encode_reg_general(reg2->name.c_str())  // reg2 is general
                   : encode_reg_general(reg1->name.c_str()); // reg1 is general
    uint8_t reg_special =
        r1_special ? opt_reg1_special.value() : opt_reg2_special.value();

    // direction=0: MOV reg_ext, reg  (write special <- general)
    // direction=1: MOV reg, reg_ext  (write general <- special)
    uint8_t direction = r1_special ? 0 : 1;

    // El campo mode del ctrl byte representa SIEMPRE el ancho del operando
    // general (que coincide con reg1->size_bits == reg2->size_bits).  Antes se
    // extraian bits[5:4] del codigo del registro especial, lo que para
    // rsp/rbp/rip/rflags siempre daba mode=0 (8 bits) y truncaba MOV a un solo
    // byte.  Ahora todos los registros especiales (cur* y rsp/rbp/rip/rflags)
    // caben en 4 bits, por lo que el selector se transmite enteramente en el
    // nibble alto de byte2 y el ejecutor reconstruye el codigo con `reg2 &
    // 0xF`, ignorando mode.
    uint8_t mode = encode_mode(reg1->size_bits);

    emit_ctrl_byte(code_final, mode, is_a_signed, direction,
                   0); // ctrl: mode | 1 | direction | 0000

    // byte2: special register code in high nibble, general register in low
    // nibble
    code_final.emit8((reg_special & 0x0F) << 4 | (reg_general & 0x0F));

    DEBUG_PRINT("Emitiendo %s 0x%02x 0x%02x REG1(%s): 0x%02x, REG2(%s): 0x%02x "
                "MODE: %d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode1,
                now_instr->opcode2, reg1->name.c_str(), reg_special,
                reg2->name.c_str(), reg_general, mode);
}

// =========================================================================
// MOV reg/mem, immed emission
// =========================================================================

/**
 * @brief Emite el byte ctrl y los bytes inmediatos para una instruccion MOV
 * inmediato.
 *
 * Formas soportadas:
 *   MOV reg,      imm    -> s=0, d=0, general register destination
 *   MOV [reg],    imm    -> s=1, d=0, memory destination (register holds
 * address) MOV reg_ext,  imm    -> s=1, d=1, special register destination MOV
 * reg, @Annotation -> relocation placeholder (Method / Relative / Absolute)
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_mov_inmed(const vm::Instruction *instruction_parser,
                          ByteWriter &code_final, const InstrInfo *now_instr,
                          Assembler *assembly_ctx) {
    uint8_t is_a_signed = 0; // s bit: 0=general, 1=memory/special
    uint8_t mode = 0;        // 2-bit operand width
    uint8_t direction = 0;   // d bit
    uint8_t size_bytes = 0;  // numero de bytes inmediatos a emitir

    auto n0 = instruction_parser->operands[0].get(); // destination operand
    auto n1 = instruction_parser->operands[1]
                  .get(); // source operand (immediate or annotation)

    auto inmmed_str = dynamic_cast<vm::NumberOperand *>(
        n1);                 // intentar leer inmediato numerico
    uint64_t val_inmmed = 0; // will be set below if numeric

    if (inmmed_str != nullptr) {
        auto inmmed_opt = vm::parse_number_safe(
            inmmed_str->value); // parsear la cadena numerica
        if (inmmed_opt == std::nullopt)
            throw std::runtime_error("MOV imm: invalid number: " +
                                     inmmed_str->value);
        val_inmmed = inmmed_opt.value(); // store parsed value
    }

    auto reg =
        dynamic_cast<vm::RegisterOperand *>(n0); // try general/special register
    auto mem = dynamic_cast<vm::MemoryOperand *>(n0); // try memory operand
    bool mem_dest =
        reg == nullptr; // verdadero cuando el primer operando es memoria

    if (auto annotacion = dynamic_cast<vm::AnnotationNode *>(n1)) {
        // annotation operand: set up a relocation
        if (annotacion->key == "Method") {
            // Method annotation: adjust register size to pointer width
            if (reg != nullptr) {
                reg->size_bits = sizeof(void *) * 8; // force pointer-sized mode
            } else if (mem != nullptr) {
                reg = static_cast<vm::RegisterOperand *>(mem->expr.get());
                reg->size_bits = sizeof(void *) * 8; // force pointer-sized mode
            }

            Relocation rel;
            rel.symbol = annotacion->value; // e.g. "kernel32.dll:GetTickCount"
            rel.section = assembly_ctx->current_section->name;
            rel.offset =
                code_final.offset + 1; // +1 skips the ctrl byte emitted later
            rel.type =
                size_ptr_in_this_machine; // absolute pointer-sized relocation

            assembly_ctx->ctx.add_relocation(rel); // registrar relocalizacion

        } else {
            // Relative or Absolute annotation: use register size for relocation
            // width
            if (reg != nullptr) {
                mode = encode_mode(reg->size_bits); // derive mode from register
            } else if (mem != nullptr) {
                reg = static_cast<vm::RegisterOperand *>(mem->expr.get());
                mode = encode_mode(
                    reg->size_bits); // derive mode from register inside memory
            }

            Relocation rel;
            rel.symbol = annotacion->value;
            rel.section = assembly_ctx->current_section->name;
            rel.offset = code_final.offset + 1; // +1 skips ctrl byte

            // choose relocation type based on annotation key
            if (annotacion->key == "Relative") {
                rel.type = mode_to_type_relocation_rel(
                    mode); // sized relative relocation
            } else if (annotacion->key == "Absolute") {
                rel.type = mode_to_type_relocation_abs(
                    mode); // sized absolute relocation
            } else {
                throw std::runtime_error(
                    "emit_instr_mov_inmed: unsupported annotation: " +
                    annotacion->key);
            }

            if (rel.type == Type::NO_VALID)
                throw std::runtime_error(
                    "emit_instr_mov_inmed: unsupported annotation: " +
                    annotacion->key);

            assembly_ctx->ctx.add_relocation(rel); // registrar relocalizacion
            val_inmmed = 0; // placeholder: el enlazador sobreescribira
        }
    }

    if (mem_dest) {
        // destino memoria: s=1 to distinguish from general-register form
        is_a_signed = 1;
        reg = static_cast<vm::RegisterOperand *>(
            mem->expr.get()); // base register of [reg]
        if (reg == nullptr) {
            std::cout << "MOV imm: " << instruction_parser->opcode
                      << ": expected register inside memory operand\n";
            mem->expr->print(0);
            throw std::runtime_error("MOV imm: " + instruction_parser->opcode);
        }
    } else {
        std::optional<uint8_t> opt_reg_special =
            encode_special_register(reg->name);
        is_a_signed =
            opt_reg_special.has_value() ? 1 : 0; // s=1 for special registers

        if (is_a_signed == 1) {
            // special/extended register destination
            uint8_t reg_special = opt_reg_special.value();
            mode = (reg_special >> 4) &
                   0b11;   // extract mode from special register encoding
            direction = 1; // d=1 for special register forms

            emit_ctrl_byte(
                code_final, mode, is_a_signed, direction,
                reg_special &
                    0x0F); // emit ctrl with special register in low nibble

            size_bytes = sizeof(uint64_t); // siempre emitir inmediato de 64
                                           // bits para registros especiales
            code_final.emit_bytes(&val_inmmed,
                                  size_bytes); // emit immediate placeholder
            return;
        }
    }

    // general register (or memory) destination
    mode = encode_mode(
        reg->size_bits); // ancho de 2 bits segun tamano del registro

    // validar que el inmediato cabe en el ancho del registro
    ImmType type = detect_imm_type((int64_t)val_inmmed,
                                   is_a_signed); // clasificar inmediato
    int instr_imm_bits = immtype_bits(type); // required bits for the immediate
    int instr_mode_bits =
        mode_to_bits(mode); // bits available in the register mode

    if (instr_imm_bits > instr_mode_bits)
        throw std::runtime_error(
            "emit_instr_mov_inmed: immediate " + std::to_string(val_inmmed) +
            " (" + std::to_string(instr_imm_bits) + " bits) exceeds mode " +
            std::to_string(mode) + " (" + std::to_string(instr_mode_bits) +
            " bits)");

    direction = 0; // d=0 for general register / memory destination

    emit_ctrl_byte(
        code_final, mode, is_a_signed, direction,
        encode_reg_general(reg->name.c_str())); // emitir byte de control

    code_final.emit_bytes(&val_inmmed,
                          mode_to_bytes(mode)); // emit immediate bytes
}

// =========================================================================
// CALLN immediate emission
// =========================================================================

/**
 * @brief Emite el marcador de llamada nativa para una instruccion CALLN
 * @Metodo().
 *
 * The 8-byte placeholder (0x1122334455667788) is patched by the linker using
 * a Native_Method relocation that encodes the library and function names.
 *
 * @param instruction_parser Instruccion parseada (operands[0] = anotacion
 * @Metodo).
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_calln_inmmed(const vm::Instruction *instruction_parser,
                             ByteWriter &code_final, const InstrInfo *now_instr,
                             Assembler *assembly_ctx) {
    auto method = dynamic_cast<vm::AnnotationNode *>(
        instruction_parser->operands[0].get());
    if (method == nullptr)
        throw std::runtime_error("CALLN: expected @Method(\"lib:func\") "
                                 "annotation as first operand");

    Relocation rel;
    rel.symbol = method->value; // e.g. "kernel32.dll:GetTickCount"
    rel.section = assembly_ctx->current_section->name;
    rel.type = Type::Native_Method; // native call relocation type
    rel.offset =
        code_final.offset; // capture offset before emitting placeholder

    uint64_t placeholder =
        0x1122334455667788; // recognisable sentinel patched by linker
    code_final.emit_bytes(
        &placeholder, size_relocation_emmit(rel.type)); // emitir placeholder

    assembly_ctx->ctx.add_relocation(
        rel); // registrar para parcheo del enlazador
}

// =========================================================================
// MOV SIB emission (delegates to emit_instr_sib)
// =========================================================================

/**
 * @brief Emite una instruccion MOV con direccionamiento SIB.
 *        Delegates entirely to emit_instr_sib; the s-bit selects VM vs host
 * memory at runtime.
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_mov_sib(const vm::Instruction *instruction_parser,
                        ByteWriter &code_final, const InstrInfo *now_instr,
                        Assembler *assembly_ctx) {
    emit_instr_sib(instruction_parser, code_final, now_instr,
                   assembly_ctx); // emisor SIB compartido
}

// =========================================================================
// One-register instruction emission (NOT, etc.)
// =========================================================================

/**
 * @brief Emite dos bytes para una instruccion de un solo registro.
 *
 * Byte 1 (ctrl):  modo(2) | 000000   (bits 5-0 son cero)
 * Byte 2 (reg):   0000 | reg(4)
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_one_reg(const vm::Instruction *instruction_parser,
                        ByteWriter &code_final, const InstrInfo *now_instr,
                        Assembler *assembly_ctx) {
    auto reg = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    if (reg == nullptr)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requires a register operand");

    uint8_t mode = encode_mode(reg->size_bits); // codigo de ancho de 2 bits
    code_final.emit8(static_cast<uint8_t>(
        mode << 6)); // byte ctrl: solo bits de modo activos, el resto cero
    code_final.emit8(encode_reg_general(
        reg->name.c_str())); // byte reg: nibble bajo = registro
}

// =========================================================================
// Emision de instrucciones con tres registros (msgsend r_pid, r_addr, r_len)
// =========================================================================

/**
 * @brief Emite dos bytes de operandos para instrucciones de tres registros.
 *
 * Byte 1 (b2): (r1<<4) | r2
 * Byte 2 (b3): (r3<<4)
 *
 * @param instruction_parser Instruccion parseada con tres operandos registro.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_three_reg(const vm::Instruction *instruction_parser,
                          ByteWriter &code_final, const InstrInfo *now_instr,
                          Assembler *assembly_ctx) {
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto r3 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get());
    if (r1 == nullptr || r2 == nullptr || r3 == nullptr)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requires three register operands");

    uint8_t idx1 =
        encode_reg_general(r1->name.c_str()); // primer registro (nibble alto)
    uint8_t idx2 =
        encode_reg_general(r2->name.c_str()); // segundo registro (nibble bajo)
    uint8_t idx3 = encode_reg_general(
        r3->name.c_str()); // tercer registro (nibble alto del byte 3)

    code_final.emit8(static_cast<uint8_t>((idx1 << 4) | (idx2 & 0x0F))); // b2
    code_final.emit8(static_cast<uint8_t>((idx3 << 4)));                 // b3
}

// Emite 4 regs empacados en FIXED_4 (4 nibbles, 2 bytes).  Layout:
//   b2 = (r0 << 4) | r1
//   b3 = (r2 << 4) | r3
// Util para @c atomiccas (dst, addr, exp, des).
void emit_instr_four_reg(const vm::Instruction *instruction_parser,
                         ByteWriter &code_final,
                         const InstrInfo * /*now_instr*/,
                         Assembler * /*assembly_ctx*/
) {
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto r3 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get());
    auto r4 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[3].get());
    if (r1 == nullptr || r2 == nullptr || r3 == nullptr || r4 == nullptr)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requires four register operands");

    uint8_t idx1 = encode_reg_general(r1->name.c_str());
    uint8_t idx2 = encode_reg_general(r2->name.c_str());
    uint8_t idx3 = encode_reg_general(r3->name.c_str());
    uint8_t idx4 = encode_reg_general(r4->name.c_str());

    code_final.emit8(static_cast<uint8_t>((idx1 << 4) | (idx2 & 0x0F))); // b2
    code_final.emit8(static_cast<uint8_t>((idx3 << 4) | (idx4 & 0x0F))); // b3
}

// =========================================================================
// Cursor read/write (readcur / writecur) emission
// =========================================================================

/**
 * @brief Emite dos bytes para una instruccion de lectura o escritura de cursor.
 *
 * Byte 1 (ctrl):  modo(2) | indice_cursor(2) | 0000
 * Byte 2 (reg):   codigo del registro general
 *
 * writecur curN, reg -> primer operando es un cursor (cur0-cur3)
 * readcur  reg, curN -> segundo operando es un cursor
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_cursor_rw(const vm::Instruction *instruction_parser,
                    ByteWriter &code_final, const InstrInfo *now_instr,
                    Assembler *assembly_ctx) {
    auto reg0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto reg1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (reg0 == nullptr || reg1 == nullptr)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requires two register operands");

    std::optional<uint8_t> opt0 =
        encode_special_register(reg0->name); // verificar si reg0 es cursor
    std::optional<uint8_t> opt1 =
        encode_special_register(reg1->name); // verificar si reg1 es cursor

    uint8_t cur_idx, gen_reg, mode;

    if (opt0) {
        // writecur curN, src_reg: first operand is the cursor
        if (opt0.value() > 3)
            throw std::runtime_error(
                "writecur: first operand must be cur0-cur3");
        cur_idx = opt0.value() & 0b11; // extract 2-bit cursor index
        gen_reg =
            encode_reg_general(reg1->name.c_str()); // general register code
        mode = encode_mode(reg1->size_bits); // ancho desde el registro general
    } else {
        // readcur dest_reg, curN: second operand is the cursor
        if (!opt1)
            throw std::runtime_error(instruction_parser->opcode +
                                     ": one operand must be cur0-cur3");
        gen_reg =
            encode_reg_general(reg0->name.c_str()); // general register code
        cur_idx = opt1.value() & 0b11;       // extract 2-bit cursor index
        mode = encode_mode(reg0->size_bits); // ancho desde el registro general
    }

    // ctrl byte: mode(2) | cursor_index(2) | 0000
    code_final.emit8(static_cast<uint8_t>((mode << 6) | (cur_idx << 4)));
    code_final.emit8(gen_reg); // register byte
}

// =========================================================================
// GC dereference (gcderef) emission
// =========================================================================

/**
 * @brief Emite dos bytes para una instruccion gcderef.
 *
 * gcderef curN, handle_reg
 *
 * Byte 1 (ctrl):  0000 | indice_cursor(2) | 00   (el modo no aplica)
 * Byte 2 (reg):   codigo del registro handle
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_gcderef(const vm::Instruction *instruction_parser,
                  ByteWriter &code_final, const InstrInfo *now_instr,
                  Assembler *assembly_ctx) {
    auto cur_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto handle_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (cur_op == nullptr || handle_op == nullptr)
        throw std::runtime_error(
            "gcderef: requires two register operands (curN, handle_reg)");

    std::optional<uint8_t> opt_cur = encode_special_register(cur_op->name);
    if (!opt_cur)
        throw std::runtime_error("gcderef: first operand must be cur0-cur3");

    uint8_t cur_idx = opt_cur.value() & 0b11; // 2-bit cursor index
    uint8_t handle_reg =
        encode_reg_general(handle_op->name.c_str()); // handle register code

    // ctrl byte: bits 5-4 hold the cursor index; mode is not used for gcderef
    code_final.emit8(static_cast<uint8_t>(cur_idx << 4));
    code_final.emit8(handle_reg); // handle register byte
}

// =========================================================================
// addcur / vmcopy / vcopyh emission
// =========================================================================

/**
 * @brief Emite dos bytes de datos para la instruccion addcur curN, imm16.
 *
 * addcur curN, imm16  ->  [ctrl][0x00][imm_lo][imm_hi]
 *   ctrl = (cur_idx << 4)
 *
 * El operando imm puede ser un literal entero (positivo o negativo).
 *
 * @param instruction_parser Instruccion parseada (operandos: curN, imm).
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_addcur(const vm::Instruction *instruction_parser,
                 ByteWriter &code_final, const InstrInfo *now_instr,
                 Assembler *assembly_ctx) {
    auto *cur_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *imm_op = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[1].get());

    if (!cur_op || !imm_op)
        throw std::runtime_error("addcur: requiere (curN, imm16)");

    std::optional<uint8_t> opt_cur = encode_special_register(cur_op->name);
    if (!opt_cur || opt_cur.value() > 3)
        throw std::runtime_error("addcur: primer operando debe ser cur0-cur3");

    uint8_t cur_idx = opt_cur.value() & 0x3;

    // el campo value de NumberOperand es una cadena; parsear a numerico
    auto imm_opt = vm::parse_number_safe(imm_op->value);
    if (!imm_opt)
        throw std::runtime_error("addcur: inmediato invalido: " +
                                 imm_op->value);
    int16_t imm16 =
        static_cast<int16_t>(imm_opt.value()); // truncar a 16 bits con signo

    code_final.emit8(
        static_cast<uint8_t>(cur_idx << 4)); // ctrl: bits 5-4 = cur_idx
    code_final.emit8(0x00);                  // padding
    code_final.emit8(static_cast<uint8_t>(imm16 & 0xFF));        // imm_lo
    code_final.emit8(static_cast<uint8_t>((imm16 >> 8) & 0xFF)); // imm_hi
}

/**
 * @brief Emite dos bytes de datos para vmcopy curN, rSrc, rLen.
 *
 * vmcopy curN, rSrc, rLen  ->  [byte_A][byte_B]
 *   byte_A = (cur_idx << 4) | rSrc
 *   byte_B = (rLen    << 4)
 *
 * @param instruction_parser Instruccion parseada (operandos: curN, rSrc, rLen).
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_vmcopy(const vm::Instruction *instruction_parser,
                 ByteWriter &code_final, const InstrInfo *now_instr,
                 Assembler *assembly_ctx) {
    auto *cur_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *src_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *len_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get());

    if (!cur_op || !src_op || !len_op)
        throw std::runtime_error(
            "vmcopy: requiere (curN, rSrc, rLen) todos registros");

    std::optional<uint8_t> opt_cur = encode_special_register(cur_op->name);
    if (!opt_cur || opt_cur.value() > 3)
        throw std::runtime_error("vmcopy: primer operando debe ser cur0-cur3");

    uint8_t cur_idx = opt_cur.value() & 0x3;
    uint8_t r_src = encode_reg_general(src_op->name.c_str());
    uint8_t r_len = encode_reg_general(len_op->name.c_str());

    code_final.emit8(
        static_cast<uint8_t>((cur_idx << 4) | (r_src & 0xF))); // byte_A
    code_final.emit8(static_cast<uint8_t>(r_len << 4));        // byte_B
}

/**
 * @brief Emite dos bytes de datos para vcopyh rDst, curN, rLen.
 *
 * vcopyh rDst, curN, rLen  ->  [byte_A][byte_B]
 *   byte_A = (cur_idx << 4) | rDst
 *   byte_B = (rLen    << 4)
 *
 * @param instruction_parser Instruccion parseada (operandos: rDst, curN, rLen).
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_vcopyh(const vm::Instruction *instruction_parser,
                 ByteWriter &code_final, const InstrInfo *now_instr,
                 Assembler *assembly_ctx) {
    auto *dst_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *cur_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *len_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get());

    if (!dst_op || !cur_op || !len_op)
        throw std::runtime_error(
            "vcopyh: requiere (rDst, curN, rLen) todos registros");

    std::optional<uint8_t> opt_cur = encode_special_register(cur_op->name);
    if (!opt_cur || opt_cur.value() > 3)
        throw std::runtime_error("vcopyh: segundo operando debe ser cur0-cur3");

    uint8_t cur_idx = opt_cur.value() & 0x3;
    uint8_t r_dst = encode_reg_general(dst_op->name.c_str());
    uint8_t r_len = encode_reg_general(len_op->name.c_str());

    code_final.emit8(
        static_cast<uint8_t>((cur_idx << 4) | (r_dst & 0xF))); // byte_A
    code_final.emit8(static_cast<uint8_t>(r_len << 4));        // byte_B
}

// =========================================================================
// Absolute 64-bit instruction emission (callvm, enter, jmp abs)
// =========================================================================

/**
 * @brief Emite el byte de condicion/opcode2 seguido de una direccion absoluta
 * de 8 bytes.
 *
 * Usada por callvm, enter e instrucciones de salto absoluto.
 * El operando puede ser un literal numerico o una anotacion @Label (reubicacion
 * Absolute64).
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Instruction metadata (opcode2 is used as the
 * condition byte).
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_abs64(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    code_final.emit8(
        now_instr
            ->opcode2); // emit condition byte (or opcode2 for callvm/enter)

    auto *op = instruction_parser->operands[0].get(); // single operand

    if (auto *num = dynamic_cast<vm::NumberOperand *>(op)) {
        // numeric immediate: parse and emit 64 bits
        auto val_opt = vm::parse_number_safe(num->value);
        if (!val_opt)
            throw std::runtime_error("emit_instr_abs64: invalid number: " +
                                     num->value);
        code_final.emit64(
            val_opt.value()); // emitir el valor de 64 bits directamente
    } else if (auto *lbl = dynamic_cast<vm::AnnotationNode *>(op)) {
        // referencia de etiqueta via @Absolute("nombre"): relocalizacion
        // Absolute64
        Relocation rel;
        rel.symbol = lbl->value;
        rel.section = assembly_ctx->current_section->name;
        rel.offset = code_final.offset;
        rel.type = Type::Absolute64;
        assembly_ctx->ctx.add_relocation(rel);
        code_final.emit64(0);
    } else if (auto *lbl = dynamic_cast<vm::LabelOperand *>(op)) {
        // referencia de etiqueta directa: el linker registra simbolos como
        // "seccion.etiqueta"
        Relocation rel;
        rel.symbol = assembly_ctx->current_section->name + "." + lbl->name;
        rel.section = assembly_ctx->current_section->name;
        rel.offset = code_final.offset;
        rel.type = Type::Absolute64;
        assembly_ctx->ctx.add_relocation(rel);
        code_final.emit64(0);
    } else {
        throw std::runtime_error("emit_instr_abs64: '" +
                                 instruction_parser->opcode +
                                 "': expected a number or label operand");
    }
}

// =========================================================================
// Relative jump (jrel) emission
// =========================================================================

/**
 * @brief Mapea el sufijo de un salto condicional a su codigo de condicion de 1
 * byte.
 *
 * El sufijo sigue a un punto: ej. "jmp.je", "callvm.jlt".
 * Devuelve 0x0F para saltos incondicionales (sin sufijo).
 *
 * @param opcode Cadena completa del opcode incluyendo el sufijo opcional.
 * @return       Codigo de condicion de 1 byte (0x00-0x0D condicional, 0x0F
 * incondicional).
 */
static uint8_t suffix_to_cond(const std::string &opcode) {
    size_t dot = opcode.find('.'); // localizar el separador de punto
    if (dot == std::string::npos) return 0x0F; // no suffix -> unconditional

    std::string s = opcode.substr(dot + 1);    // extract suffix after the dot
    if (s == "je" || s == "jz") return 0x00;   // equal / zero
    if (s == "jne" || s == "jnz") return 0x01; // not equal / not zero
    if (s == "jcs" || s == "jb")
        return 0x02; // carry set / below sin signo (CF==1, a < b)
    if (s == "jcc" || s == "jae")
        return 0x03;             // carry clear / above or equal (CF==0, a >= b)
    if (s == "jmi") return 0x04; // minus (sign set)
    if (s == "jpl") return 0x05; // plus (sign clear)
    if (s == "jvs") return 0x06; // overflow set
    if (s == "jvc") return 0x07; // overflow clear
    if (s == "jhi") return 0x08; // higher (unsigned greater)
    if (s == "jls") return 0x09; // lower or same (unsigned)
    if (s == "jge") return 0x0A; // greater or equal (signed)
    if (s == "jlt") return 0x0B; // less than (signed)
    if (s == "jgt") return 0x0C; // greater than (signed)
    if (s == "jle") return 0x0D; // less or equal (signed)
    return 0x0F;                 // unknown suffix: treated as unconditional
}

/**
 * @brief Emite los bytes restantes para una instruccion de salto relativo.
 *
 * Disposicion (despues de que el llamante ya emitio [0x00][0x2D]):
 *   byte3: codigo de condicion (de suffix_to_cond)
 *   byte4: relleno 0x00
 *   bytes5-8: desplazamiento con signo de 32 bits (o marcador de reubicacion)
 *
 * @param instruction_parser Instruccion parseada (operands[0] = numero o
 * etiqueta).
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_jrel(const vm::Instruction *instruction_parser,
               ByteWriter &code_final, const InstrInfo *now_instr,
               Assembler *assembly_ctx) {
    code_final.emit8(
        suffix_to_cond(instruction_parser->opcode)); // condition code byte
    code_final.emit8(0x00);                          // padding byte

    auto *op =
        instruction_parser->operands[0].get(); // displacement or label operand

    if (auto *num = dynamic_cast<vm::NumberOperand *>(op)) {
        auto val_opt = vm::parse_number_safe(num->value);
        if (!val_opt)
            throw std::runtime_error("emit_jrel: invalid number: " +
                                     num->value);
        int32_t disp = static_cast<int32_t>(
            val_opt.value()); // truncar a 32 bits con signo
        code_final.emit32(static_cast<uint32_t>(disp)); // emit displacement
    } else if (auto *lbl = dynamic_cast<vm::AnnotationNode *>(op)) {
        // label reference: register a Relative32 relocation and emit a
        // placeholder
        Relocation rel;
        rel.symbol = lbl->value;
        rel.section = assembly_ctx->current_section->name;
        rel.offset =
            code_final
                .offset; // position of the 4-byte displacement placeholder
        rel.type =
            Type::Relative32; // linker will patch with PC-relative offset
        assembly_ctx->ctx.add_relocation(rel);
        code_final.emit32(0); // placeholder; overwritten by linker
    } else {
        throw std::runtime_error("emit_jrel: '" + instruction_parser->opcode +
                                 "': expected a number or label operand");
    }
}

// =========================================================================
// OOP instructions: reg + imm8 (callvirt, callsuper, getfield, getmethod)
// =========================================================================

/**
 * @brief Emite [byte_reg][imm8] para instrucciones OOP que toman un registro y
 * un indice de 8 bits.
 *
 * reg_byte: los 4 bits inferiores = codigo de registro (bits 7-4 son cero).
 * imm8:     los 8 bits inferiores del valor inmediato.
 *
 * @param instruction_parser Instruccion parseada (operands[0]=reg,
 * operands[1]=imm8).
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_reg_imm8(const vm::Instruction *instruction_parser,
                         ByteWriter &code_final, const InstrInfo *now_instr,
                         Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 2)
        throw std::runtime_error("emit_instr_reg_imm8: '" +
                                 instruction_parser->opcode +
                                 "' requires (reg, imm8)");

    auto *reg_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    if (reg_op == nullptr)
        throw std::runtime_error("emit_instr_reg_imm8: '" +
                                 instruction_parser->opcode +
                                 "': first operand must be a register");

    auto *num_op = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[1].get());
    if (num_op == nullptr)
        throw std::runtime_error(
            "emit_instr_reg_imm8: '" + instruction_parser->opcode +
            "': second operand must be an integer (0-255)");

    uint8_t reg_byte =
        encode_reg_general(reg_op->name.c_str()) & 0x0F; // 4-bit register code

    auto val_opt =
        vm::parse_number_safe(num_op->value); // parse immediate value
    if (!val_opt)
        throw std::runtime_error("emit_instr_reg_imm8: invalid number: " +
                                 num_op->value);

    uint8_t imm8 =
        static_cast<uint8_t>(val_opt.value() & 0xFF); // truncate to 8 bits

    code_final.emit8(reg_byte); // emit register byte
    code_final.emit8(imm8);     // emit 8-bit immediate

    DEBUG_PRINT("Emitiendo %s 0x%02x reg=%d imm8=%d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode2,
                reg_byte, imm8);
}

// =========================================================================
// SUBSP / ADDSP -- aritmetica de puntero de pila con inmediato
// =========================================================================

/**
 * @brief Emite un byte ctrl + inmediato de 64 bits para subsp/addsp.
 *
 * El primer operando debe ser "rsp" o "rbp"; el segundo es el inmediato.
 * Formato: [0x00][opcode2][ctrl][imm64] donde ctrl = (3<<6)|sp_bp.
 * Se usa siempre modo=3 (64 bits) porque RSP/RBP son registros de 64 bits.
 *
 * @param instruction_parser Instruccion parseada.
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_spimm(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 2)
        throw std::runtime_error("emit_instr_spimm: '" +
                                 instruction_parser->opcode +
                                 "' requires (rsp|rbp, imm)");

    auto *reg_op = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    if (reg_op == nullptr)
        throw std::runtime_error("emit_instr_spimm: '" +
                                 instruction_parser->opcode +
                                 "': first operand must be rsp or rbp");

    const std::string &rname = reg_op->name;
    uint8_t sp_bp = 0; // 0 = RSP, 1 = RBP
    if (rname == "rbp")
        sp_bp = 1;
    else if (rname != "rsp")
        throw std::runtime_error(
            "emit_instr_spimm: '" + instruction_parser->opcode +
            "': first operand must be rsp or rbp, got " + rname);

    auto *num_op = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[1].get());
    if (num_op == nullptr)
        throw std::runtime_error("emit_instr_spimm: '" +
                                 instruction_parser->opcode +
                                 "': second operand must be an immediate");

    auto val_opt = vm::parse_number_safe(num_op->value);
    if (!val_opt)
        throw std::runtime_error("emit_instr_spimm: invalid number: " +
                                 num_op->value);

    uint8_t ctrl = (3u << 6) | sp_bp; // modo=3 (64-bit), sp_bp en bits 1:0
    uint64_t val_immed = val_opt.value();

    code_final.emit8(ctrl);       // byte de control
    code_final.emit64(val_immed); // inmediato de 64 bits (little-endian)

    DEBUG_PRINT("Emitiendo %s 0x%02x ctrl=0x%02x imm=0x%llx\n",
                instruction_parser->opcode.c_str(), now_instr->opcode2, ctrl,
                (unsigned long long)val_immed);
}

// =========================================================================
// JUMPTABLE / TYPESWITCH -- despacho por valor o por tipo
// =========================================================================

/**
 * @brief Emite los dos bytes de operandos para jumptable/typeswitch.
 *
 * Formato de la instruccion completa (FIXED_4):
 *   [0x00][opcode2][byte2][byte3]
 * donde:
 *   byte2 bits 7-4 = r_val/r_obj (registro del valor o del objeto)
 *   byte2 bits 3-0 = r_table     (registro con la direccion de la tabla)
 *   byte3          = count        (numero de entradas, uint8)
 *
 * @param instruction_parser Instruccion parseada (3 operandos: reg, reg, imm).
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_jumptable(const vm::Instruction *instruction_parser,
                          ByteWriter &code_final, const InstrInfo *now_instr,
                          Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 3)
        throw std::runtime_error("emit_instr_jumptable: '" +
                                 instruction_parser->opcode +
                                 "' requires (r_val, r_table, count)");

    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *op2 = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[2].get());

    if (!op0 || !op1 || !op2)
        throw std::runtime_error("emit_instr_jumptable: '" +
                                 instruction_parser->opcode +
                                 "': operands must be (reg, reg, imm8)");

    uint8_t r_val = encode_reg_general(op0->name.c_str()) & 0x0F;   // 4 bits
    uint8_t r_table = encode_reg_general(op1->name.c_str()) & 0x0F; // 4 bits

    auto cnt_opt = vm::parse_number_safe(op2->value);
    if (!cnt_opt)
        throw std::runtime_error("emit_instr_jumptable: invalid count: " +
                                 op2->value);

    uint8_t count =
        static_cast<uint8_t>(cnt_opt.value() & 0xFF); // truncar a 8 bits

    uint8_t byte2 =
        (r_val << 4) | r_table; // empaqueta ambos registros en un byte
    code_final.emit8(byte2);    // byte empaquetado de registros
    code_final.emit8(count);    // numero de entradas de la tabla

    DEBUG_PRINT("Emitiendo %s 0x%02x r_val=%d r_table=%d count=%d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode2, r_val,
                r_table, count);
}

/**
 * @brief Emite los dos bytes de operandos para @c addadvice (0xCE).
 *
 * Formato FIXED_4 con convencion B (raw bytes):
 *   [0x00][0xCE][byte2][byte3]
 * donde:
 *   byte2 bits 7-4 = r_advice (registro con MethodInfo* del advice)
 *   byte2 bits 3-0 = r_target (registro con MethodInfo* del target)
 *   byte3          = kind (0=BEFORE, 1=AFTER, 2=AROUND)
 *
 * El opcode prefix (0x00, 0xCE) ya lo emite el helper estandar antes de
 * llamar a este emitter; aqui solo escribimos los dos bytes de operandos.
 *
 * @param instruction_parser Instruccion parseada (3 operandos: r_target,
 * r_advice, kind imm).
 */
void emit_instr_addadvice(const vm::Instruction *instruction_parser,
                          ByteWriter &code_final, const InstrInfo *now_instr,
                          Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 3)
        throw std::runtime_error("emit_instr_addadvice: '" +
                                 instruction_parser->opcode +
                                 "' requires (r_target, r_advice, kind)");

    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *op2 = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[2].get());

    if (!op0 || !op1 || !op2)
        throw std::runtime_error("emit_instr_addadvice: '" +
                                 instruction_parser->opcode +
                                 "': operands must be (reg, reg, imm8)");

    uint8_t r_target = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_advice = encode_reg_general(op1->name.c_str()) & 0x0F;

    auto kind_opt = vm::parse_number_safe(op2->value);
    if (!kind_opt)
        throw std::runtime_error("emit_instr_addadvice: invalid kind: " +
                                 op2->value);
    uint8_t kind = static_cast<uint8_t>(kind_opt.value() & 0xFF);

    uint8_t byte2 = (r_advice << 4) | r_target;
    code_final.emit8(byte2);
    code_final.emit8(kind);

    DEBUG_PRINT("Emitiendo %s 0x%02x r_target=%d r_advice=%d kind=%d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode2,
                r_target, r_advice, kind);
}

/**
 * @brief Emite super-instruccion LOAD con zero-extend (loadz / loadzh).
 *
 * Combina @c mov rd,0 + @c mov rd_sized,[rs] en una sola instruccion VM.
 * Reduce el coste de cargar un i8/i16/i32 de la memoria con zero-extension
 * a 64-bit, patron que el IR emitter genera para CADA LOAD i8/i16/i32.
 *
 * Sintaxis:  loadz r_dst_sized, r_src
 * Encoding:  [0x00][0x7C][ctrl][regs]
 *   ctrl bits 7-6 = mode (0=8b, 1=16b, 2=32b, 3=64b)  <- de r_dst.size_bits
 *   ctrl bit  5   = is_host (1 = host_ptr, 0 = VM mem)
 *   regs = (r_src<<4) | r_dst
 *
 * @c loadzh tiene la misma estructura pero opcode 0x7D y is_host=1.
 *
 * @param instruction_parser Instruccion parseada (2 operandos: reg, reg).
 */
void emit_instr_loadz(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 2)
        throw std::runtime_error("emit_instr_loadz: '" +
                                 instruction_parser->opcode +
                                 "' requires (r_dst, r_src)");

    auto *reg_dst = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *reg_src = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (!reg_dst || !reg_src)
        throw std::runtime_error("emit_instr_loadz: '" +
                                 instruction_parser->opcode +
                                 "': operands must be (reg, reg)");

    uint8_t mode = encode_mode(reg_dst->size_bits); /* 0=8b..3=64b */
    /* is_host se codifica en el bit s: 1 para loadzh (host), 0 para loadz (VM).
     */
    uint8_t is_host = (now_instr->opcode2 == 0x7D) ? 1u : 0u;

    emit_ctrl_byte(code_final, mode, is_host, 0, 0);
    code_final.emit8(static_cast<uint8_t>(
        (encode_reg_general(reg_src->name.c_str()) << 4) |
        (encode_reg_general(reg_dst->name.c_str()) & 0x0F)));

    DEBUG_PRINT("Emitiendo %s 0x%02x mode=%d host=%d dst=%d src=%d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode2, mode,
                is_host, encode_reg_general(reg_dst->name.c_str()),
                encode_reg_general(reg_src->name.c_str()));
}

// =========================================================================
//  Atomicos width-aware (0xA9-0xAC).  El ANCHO (mode 8/16/32/64) va en el
//  ctrl-byte, leido del sufijo de tamano (.b/.w/.d) del registro de VALOR.  La
//  direccion es siempre un puntero de 64 bits (registro sin sufijo).
//  ld/st: FIXED_4 [0x00][op][ctrl][regs] (reusa decode_instr_simple_mov).
//  add/cas: FIXED_6 [0x00][op][ctrl][b2][b3][pad] (decode_instr_atomic_rmw).
// =========================================================================

/// ATOMICLD dst_sized, addr  ->  [ctrl=mode][regs=(addr<<4)|dst].
void emit_instr_atomic_ld(const vm::Instruction *ip, ByteWriter &code,
                          const InstrInfo *, Assembler *) {
    auto *dst = dynamic_cast<vm::RegisterOperand *>(ip->operands[0].get());
    auto *addr = dynamic_cast<vm::RegisterOperand *>(ip->operands[1].get());
    if (!dst || !addr)
        throw std::runtime_error("atomicld: requiere (reg_dst, reg_addr)");
    emit_ctrl_byte(code, encode_mode(dst->size_bits), 0, 0, 0);
    code.emit8(
        static_cast<uint8_t>((encode_reg_general(addr->name.c_str()) << 4) |
                             (encode_reg_general(dst->name.c_str()) & 0x0F)));
}

/// ATOMICST addr, val_sized  ->  [ctrl=mode][regs=(val<<4)|addr].
void emit_instr_atomic_st(const vm::Instruction *ip, ByteWriter &code,
                          const InstrInfo *, Assembler *) {
    auto *addr = dynamic_cast<vm::RegisterOperand *>(ip->operands[0].get());
    auto *val = dynamic_cast<vm::RegisterOperand *>(ip->operands[1].get());
    if (!addr || !val)
        throw std::runtime_error("atomicst: requiere (reg_addr, reg_val)");
    emit_ctrl_byte(code, encode_mode(val->size_bits), 0, 0, 0);
    code.emit8(
        static_cast<uint8_t>((encode_reg_general(val->name.c_str()) << 4) |
                             (encode_reg_general(addr->name.c_str()) & 0x0F)));
}

/// ATOMICADD dst_sized, addr, delta_sized
///   -> [ctrl=mode][b2=(dst<<4)|addr][b3=(delta<<4)|0][pad].
void emit_instr_atomic_add(const vm::Instruction *ip, ByteWriter &code,
                           const InstrInfo *, Assembler *) {
    auto *dst = dynamic_cast<vm::RegisterOperand *>(ip->operands[0].get());
    auto *addr = dynamic_cast<vm::RegisterOperand *>(ip->operands[1].get());
    auto *delta = dynamic_cast<vm::RegisterOperand *>(ip->operands[2].get());
    if (!dst || !addr || !delta)
        throw std::runtime_error("atomicadd: requiere (dst, addr, delta)");
    emit_ctrl_byte(code, encode_mode(dst->size_bits), 0, 0, 0);
    code.emit8(
        static_cast<uint8_t>((encode_reg_general(dst->name.c_str()) << 4) |
                             (encode_reg_general(addr->name.c_str()) & 0x0F)));
    code.emit8(
        static_cast<uint8_t>(encode_reg_general(delta->name.c_str()) << 4));
    code.emit8(0); // pad (FIXED_6)
}

/// ATOMICCAS dst_sized, addr, exp_sized, des_sized
///   -> [ctrl=mode][b2=(dst<<4)|addr][b3=(exp<<4)|des][pad].
void emit_instr_atomic_cas(const vm::Instruction *ip, ByteWriter &code,
                           const InstrInfo *, Assembler *) {
    auto *dst = dynamic_cast<vm::RegisterOperand *>(ip->operands[0].get());
    auto *addr = dynamic_cast<vm::RegisterOperand *>(ip->operands[1].get());
    auto *exp = dynamic_cast<vm::RegisterOperand *>(ip->operands[2].get());
    auto *des = dynamic_cast<vm::RegisterOperand *>(ip->operands[3].get());
    if (!dst || !addr || !exp || !des)
        throw std::runtime_error("atomiccas: requiere (dst, addr, exp, des)");
    emit_ctrl_byte(code, encode_mode(dst->size_bits), 0, 0, 0);
    code.emit8(
        static_cast<uint8_t>((encode_reg_general(dst->name.c_str()) << 4) |
                             (encode_reg_general(addr->name.c_str()) & 0x0F)));
    code.emit8(
        static_cast<uint8_t>((encode_reg_general(exp->name.c_str()) << 4) |
                             (encode_reg_general(des->name.c_str()) & 0x0F)));
    code.emit8(0); // pad (FIXED_6)
}

/**
 * @brief Emite super-instrucciones ALU 3-operandos.
 *
 * Combina `mov rd, rs1; OP rd, rs2` en una sola instruccion VM cuando rd
 * NO coincide con rs1 (el patron que el regalloc coalesce no logra eliminar).
 *
 * Formato fisico FIXED_4:
 *   [0x00][opcode2][byte2][byte3]
 * donde:
 *   opcode2 codifica la operacion (adds3=0x73, subs3=0x74, ...,
 * signed/unsigned) byte2 = (r_src1 << 4) | r_dst        (mismo nibble layout
 * que mvtake/addadvice) byte3 = (r_src2 << 4) | flags_low    (flags low siempre
 * 0; reservado)
 *
 * Convencion textual:  adds3 r_dst, r_src1, r_src2
 *
 * @param instruction_parser Instruccion parseada (3 operandos registro).
 */
void emit_instr_alu3(const vm::Instruction *instruction_parser,
                     ByteWriter &code_final, const InstrInfo *now_instr,
                     Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 3)
        throw std::runtime_error("emit_instr_alu3: '" +
                                 instruction_parser->opcode +
                                 "' requires (r_dst, r_src1, r_src2)");

    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *op2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get());

    if (!op0 || !op1 || !op2)
        throw std::runtime_error("emit_instr_alu3: '" +
                                 instruction_parser->opcode +
                                 "': operands must be (reg, reg, reg)");

    uint8_t r_dst = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_src1 = encode_reg_general(op1->name.c_str()) & 0x0F;
    uint8_t r_src2 = encode_reg_general(op2->name.c_str()) & 0x0F;

    uint8_t byte2 = static_cast<uint8_t>((r_src1 << 4) | r_dst);
    uint8_t byte3 = static_cast<uint8_t>((r_src2 << 4));

    code_final.emit8(byte2);
    code_final.emit8(byte3);

    DEBUG_PRINT("Emitiendo %s 0x%02x r_dst=%d r_src1=%d r_src2=%d\n",
                instruction_parser->opcode.c_str(), now_instr->opcode2, r_dst,
                r_src1, r_src2);
}

/**
 * @brief Emite los operandos de @c getstatic / @c setstatic (0x60 / 0x61).
 *
 * Formato fisico FIXED_8:
 *   [0x00][opcode2][regs_byte][_pad8=0][offset_u32_LE]
 * donde:
 *   regs_byte bits 7-4 = r0
 *   regs_byte bits 3-0 = r1
 *   offset uint32      = byte offset dentro de ClassInfo::static_data
 *
 * Convencion de operandos (textual):
 *   getstatic r_dst,   r_class, offset    -> r0=r_dst,   r1=r_class
 *   setstatic r_class, r_value, offset    -> r0=r_class, r1=r_value
 *
 * El prefijo (0x00, opcode2) ya lo emite el helper estandar antes de invocar
 * a este emisor; aqui escribimos los 6 bytes restantes (regs + pad + offset).
 *
 * @param instruction_parser Instruccion parseada (3 operandos: reg, reg, imm).
 */
void emit_instr_static(const vm::Instruction *instruction_parser,
                       ByteWriter &code_final, const InstrInfo *now_instr,
                       Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 3)
        throw std::runtime_error("emit_instr_static: '" +
                                 instruction_parser->opcode +
                                 "' requires (reg, reg, offset_u32)");

    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *op2 = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[2].get());

    if (!op0 || !op1 || !op2)
        throw std::runtime_error("emit_instr_static: '" +
                                 instruction_parser->opcode +
                                 "': operands must be (reg, reg, imm32)");

    uint8_t r0 = encode_reg_general(op0->name.c_str()) & 0x0F; // 4 bits
    uint8_t r1 = encode_reg_general(op1->name.c_str()) & 0x0F; // 4 bits

    auto off_opt = vm::parse_number_safe(op2->value);
    if (!off_opt)
        throw std::runtime_error("emit_instr_static: invalid offset: " +
                                 op2->value);
    uint32_t offset = static_cast<uint32_t>(off_opt.value() & 0xFFFFFFFFULL);

    uint8_t regs_byte = (r0 << 4) | r1;        // empaquetar 2 regs en byte2
    code_final.emit8(regs_byte);               // byte 2 = (r0<<4) | r1
    code_final.emit8(static_cast<uint8_t>(0)); // byte 3 = padding reservado
    code_final.emit32(offset);                 // bytes 4-7 = offset uint32 LE

    DEBUG_PRINT("Emitiendo %s 0x%02x r0=%d r1=%d offset=0x%x\n",
                instruction_parser->opcode.c_str(), now_instr->opcode2, r0, r1,
                offset);
}

/**
 * @brief Emite mld / mst (load/store universal, FIXED_8).
 *
 * Operandos (.vel, forma explicita que emite el ir_emitter):
 *   op0 = reg (dst para mld / src para mst)
 *   op1 = reg index (r0 si no se usa)
 *   op2 = ctrlword (imm16) que empaqueta:
 *     bits[4:0]=base(0-17)  bits[7:5]=scale(0-6)  bits[10:8]=width_code(0-6)
 *     bit[11]=host  bit[12]=has_index  bit[13]=idx_sub  bit[14]=sign_ext
 * bit[15]=bank op3 = disp16 (imm, ya en complemento a 2 de 16 bits) Emite los 6
 * bytes de payload: [ctrl][basef][regs][disp16 LE][pad].
 */
void emit_instr_mem_full(const vm::Instruction *instruction_parser,
                         ByteWriter &code_final,
                         const InstrInfo * /*now_instr*/,
                         Assembler * /*assembly_ctx*/) {
    if (instruction_parser->operands.size() < 4)
        throw std::runtime_error(
            instruction_parser->opcode +
            ": requires (reg, reg_index, ctrlword, disp16)");
    auto *op_dst = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op_idx = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *op_ctrl = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[2].get());
    auto *op_disp = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[3].get());
    if (!op_dst || !op_idx || !op_ctrl || !op_disp)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": operands must be (reg, reg, imm16, imm16)");

    const uint8_t dst = encode_reg_general(op_dst->name.c_str()) & 0x0F;
    const uint8_t index = encode_reg_general(op_idx->name.c_str()) & 0x0F;
    const uint32_t cw = static_cast<uint32_t>(
        vm::parse_number_safe(op_ctrl->value).value_or(0) & 0xFFFFULL);
    const uint16_t disp = static_cast<uint16_t>(
        vm::parse_number_safe(op_disp->value).value_or(0) & 0xFFFFULL);

    const uint8_t base = cw & 0x1F;
    const uint8_t scale = (cw >> 5) & 0x07;
    const uint8_t wcode = (cw >> 8) & 0x07;
    const uint8_t host = (cw >> 11) & 1;
    const uint8_t has_index = (cw >> 12) & 1;
    const uint8_t idx_sub = (cw >> 13) & 1;
    const uint8_t sign_ext = (cw >> 14) & 1;
    const uint8_t bank = (cw >> 15) & 1;

    const uint8_t ctrl = (host << 7) | (wcode << 4) | (has_index << 3) | scale;
    const uint8_t basef = (bank << 7) | (idx_sub << 6) | (sign_ext << 5) | base;
    const uint8_t regs = (dst << 4) | index;

    code_final.emit8(ctrl);  // byte 2
    code_final.emit8(basef); // byte 3
    code_final.emit8(regs);  // byte 4
    code_final.emit16(disp); // bytes 5-6 (LE)
    code_final.emit8(0);     // byte 7 = pad
}

/**
 * @brief Emite los operandos de @c dlopen (0x62, FIXED_4, 3 regs).
 */
void emit_instr_dlopen(const vm::Instruction *instruction_parser,
                       ByteWriter &code_final, const InstrInfo *now_instr,
                       Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 3)
        throw std::runtime_error("emit_instr_dlopen: '" +
                                 instruction_parser->opcode +
                                 "' requires (r_dst, r_path_addr, r_path_len)");

    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *op2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get());
    if (!op0 || !op1 || !op2)
        throw std::runtime_error(
            "emit_instr_dlopen: operandos deben ser registros");

    uint8_t r_dst = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_path_addr = encode_reg_general(op1->name.c_str()) & 0x0F;
    uint8_t r_path_len = encode_reg_general(op2->name.c_str()) & 0x0F;
    uint8_t b2 = (r_dst << 4) | r_path_addr;
    uint8_t b3 = (r_path_len << 4);
    code_final.emit8(b2);
    code_final.emit8(b3);

    DEBUG_PRINT("Emitiendo dlopen 0x62 r_dst=%d r_path_addr=%d r_path_len=%d\n",
                r_dst, r_path_addr, r_path_len);
}

/**
 * @brief Emite los operandos de @c dlsym (0x63, FIXED_4, 4 regs).
 */
void emit_instr_dlsym(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 4)
        throw std::runtime_error(
            "emit_instr_dlsym: '" + instruction_parser->opcode +
            "' requires (r_dst, r_handle, r_name_addr, r_name_len)");

    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto *op2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get());
    auto *op3 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[3].get());
    if (!op0 || !op1 || !op2 || !op3)
        throw std::runtime_error(
            "emit_instr_dlsym: operandos deben ser registros");

    uint8_t r_dst = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_handle = encode_reg_general(op1->name.c_str()) & 0x0F;
    uint8_t r_name_addr = encode_reg_general(op2->name.c_str()) & 0x0F;
    uint8_t r_name_len = encode_reg_general(op3->name.c_str()) & 0x0F;
    uint8_t b2 = (r_dst << 4) | r_handle;
    uint8_t b3 = (r_name_addr << 4) | r_name_len;
    code_final.emit8(b2);
    code_final.emit8(b3);

    DEBUG_PRINT("Emitiendo dlsym 0x63 r_dst=%d r_handle=%d r_name_addr=%d "
                "r_name_len=%d\n",
                r_dst, r_handle, r_name_addr, r_name_len);
}

/**
 * @brief Emite los operandos de @c callni (0x64, FIXED_4, 1 reg).
 */
void emit_instr_callni(const vm::Instruction *instruction_parser,
                       ByteWriter &code_final, const InstrInfo *now_instr,
                       Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 1)
        throw std::runtime_error("emit_instr_callni: '" +
                                 instruction_parser->opcode +
                                 "' requires (r_fn)");

    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    if (!op0)
        throw std::runtime_error(
            "emit_instr_callni: operando debe ser un registro");

    uint8_t r_fn = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t b2 = (r_fn << 4);
    uint8_t b3 = 0;
    code_final.emit8(b2);
    code_final.emit8(b3);

    DEBUG_PRINT("Emitiendo callni 0x64 r_fn=%d\n", r_fn);
}

/**
 * @brief Emite los operandos de @c gcallocp (extended 0x65, FIXED_4, 2 regs).
 *
 * Encoding fisico: [0x00][0x65][b2][0x00]
 *   b2 = (r_dst << 4) | r_size  (4 bits cada nibble)
 *   b3 = 0 (reservado)
 *
 * El opcode prefix (0x00 0x65) lo emite el caller (parser_to_bytecode).
 */
void emit_instr_gcallocp(const vm::Instruction *instruction_parser,
                         ByteWriter &code_final, const InstrInfo *now_instr,
                         Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 2)
        throw std::runtime_error("emit_instr_gcallocp: '" +
                                 instruction_parser->opcode +
                                 "' requiere (r_dst, r_size)");
    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    if (!op0 || !op1)
        throw std::runtime_error(
            "emit_instr_gcallocp: ambos operandos deben ser registros");
    uint8_t r_dst = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_size = encode_reg_general(op1->name.c_str()) & 0x0F;
    uint8_t b2 = static_cast<uint8_t>((r_dst << 4) | r_size);
    code_final.emit8(b2);
    code_final.emit8(0);
    DEBUG_PRINT("Emitiendo gcallocp 0x65 r_dst=%d r_size=%d\n", r_dst, r_size);
}

/**
 * @brief Emite los operandos de @c spawnargs (extended 0x66, FIXED_4, 1 reg).
 *
 * Encoding fisico: [0x00][0x66][b2][0x00]
 *   b2 = (r_pc << 4) | 0
 *   b3 = 0
 *
 * R15 contiene argc, R1..R[argc] los args (mismo que CALLVM).
 */
void emit_instr_spawnargs(const vm::Instruction *instruction_parser,
                          ByteWriter &code_final, const InstrInfo *now_instr,
                          Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 1)
        throw std::runtime_error("emit_instr_spawnargs: '" +
                                 instruction_parser->opcode +
                                 "' requiere (r_pc)");
    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    if (!op0)
        throw std::runtime_error(
            "emit_instr_spawnargs: el operando debe ser un registro");
    uint8_t r_pc = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t b2 = static_cast<uint8_t>(r_pc << 4);
    code_final.emit8(b2);
    code_final.emit8(0);
    DEBUG_PRINT("Emitiendo spawnargs 0x66 r_pc=%d\n", r_pc);
}

/**
 * @brief Emite los operandos de @c fulfillhlt (extended 0x67, FIXED_4, 2 regs).
 *
 * Encoding fisico: [0x00][0x67][b2][0x00]
 *   b2 = (r_fut << 4) | r_value
 *   b3 = 0
 *
 * Combina @c fulfill r_fut, r_value + @c hlt en 1 instruccion.
 */
void emit_instr_fulfillhlt(const vm::Instruction *instruction_parser,
                           ByteWriter &code_final, const InstrInfo *now_instr,
                           Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 2)
        throw std::runtime_error("emit_instr_fulfillhlt: '" +
                                 instruction_parser->opcode +
                                 "' requiere (r_fut, r_value)");
    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    if (!op0 || !op1)
        throw std::runtime_error(
            "emit_instr_fulfillhlt: ambos operandos deben ser registros");
    uint8_t r_fut = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_val = encode_reg_general(op1->name.c_str()) & 0x0F;
    uint8_t b2 = static_cast<uint8_t>((r_fut << 4) | r_val);
    code_final.emit8(b2);
    code_final.emit8(0);
    DEBUG_PRINT("Emitiendo fulfillhlt 0x67 r_fut=%d r_value=%d\n", r_fut,
                r_val);
}

/**
 * @brief Helper interno: emite el target u32 (4 bytes LE) para cmpjmp/decjnz.
 *
 * Acepta NumberOperand (literal numerico), AnnotationNode (@Absolute("...")),
 * o LabelOperand (referencia directa).  Para labels, registra una reloc
 * @c Type::Absolute32 que el linker resolvera tras layout.  Si el VA del
 * target excede 4GB, el linker lanzara error -- limitacion conocida; la
 * VM Vesta hoy nunca emite codigo en VA > 1GB.
 */
static void emit_target_u32_label(const vm::ASTNode *op, ByteWriter &code_final,
                                  Assembler *assembly_ctx,
                                  const char *ctx_name) {
    if (auto *num = dynamic_cast<const vm::NumberOperand *>(op)) {
        auto val_opt = vm::parse_number_safe(num->value);
        if (!val_opt)
            throw std::runtime_error(std::string(ctx_name) +
                                     ": numero invalido: " + num->value);
        if (val_opt.value() > 0xFFFFFFFFULL) {
            throw std::runtime_error(
                std::string(ctx_name) +
                ": target literal excede u32 (VA > 4GB no soportado)");
        }
        code_final.emit32(static_cast<uint32_t>(val_opt.value()));
    } else if (auto *lbl = dynamic_cast<const vm::AnnotationNode *>(op)) {
        Relocation rel;
        rel.symbol = lbl->value;
        rel.section = assembly_ctx->current_section->name;
        rel.offset = code_final.offset;
        rel.type = Type::Absolute32;
        assembly_ctx->ctx.add_relocation(rel);
        code_final.emit32(0);
    } else if (auto *lbl = dynamic_cast<const vm::LabelOperand *>(op)) {
        Relocation rel;
        rel.symbol = assembly_ctx->current_section->name + "." + lbl->name;
        rel.section = assembly_ctx->current_section->name;
        rel.offset = code_final.offset;
        rel.type = Type::Absolute32;
        assembly_ctx->ctx.add_relocation(rel);
        code_final.emit32(0);
    } else {
        throw std::runtime_error(
            std::string(ctx_name) +
            ": el ultimo operando debe ser un label o direccion u32");
    }
}

/**
 * @brief Helper interno: extrae el cond_byte (0x00..0x0D) del sufijo
 *        ".jX" del mnemonic de cmpjmp/cmpjmpu.  Reusa @c suffix_to_cond
 *        que ya hace este mapeo para jmp.j*.
 */
static uint8_t cmpjmp_cond_from_opcode(const std::string &opcode) {
    uint8_t c = suffix_to_cond(opcode);
    if (c == 0x0F) {
        // sufijo invalido (incondicional no tiene sentido para cmpjmp)
        throw std::runtime_error(
            "cmpjmp: requiere un sufijo de condicion .je/.jne/.jge/etc, "
            "recibido: " +
            opcode);
    }
    return c;
}

/**
 * @brief Emite los operandos de @c cmpjmp.cc (extended 0x68, FIXED_8).
 *
 * Encoding fisico: [0x00][0x68][b2][cond][target_u32_LE]
 *   b2 = (r_a<<4) | r_b
 *   cond = 0x00..0x0D segun sufijo del mnemonic.
 *
 * Comparacion signed (cmps), branch si la condicion se cumple.
 */
void emit_instr_cmpjmp_signed(const vm::Instruction *instruction_parser,
                              ByteWriter &code_final,
                              const InstrInfo *now_instr,
                              Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 3)
        throw std::runtime_error("emit_instr_cmpjmp_signed: '" +
                                 instruction_parser->opcode +
                                 "' requiere (r_a, r_b, label)");
    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    if (!op0 || !op1)
        throw std::runtime_error("emit_instr_cmpjmp_signed: los dos primeros "
                                 "operandos deben ser registros");

    uint8_t r_a = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_b = encode_reg_general(op1->name.c_str()) & 0x0F;
    uint8_t b2 = static_cast<uint8_t>((r_a << 4) | r_b);
    uint8_t cond = cmpjmp_cond_from_opcode(instruction_parser->opcode);

    code_final.emit8(b2);
    code_final.emit8(cond);
    emit_target_u32_label(instruction_parser->operands[2].get(), code_final,
                          assembly_ctx, "emit_instr_cmpjmp_signed");

    DEBUG_PRINT("Emitiendo cmpjmp.cc 0x68 r_a=%d r_b=%d cond=0x%X\n", r_a, r_b,
                cond);
}

/**
 * @brief Emite los operandos de @c cmpjmpu.cc (extended 0x69, FIXED_8).
 *
 * Identico a @c cmpjmp_signed pero comparacion unsigned (cmpu).
 */
void emit_instr_cmpjmp_unsigned(const vm::Instruction *instruction_parser,
                                ByteWriter &code_final,
                                const InstrInfo *now_instr,
                                Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 3)
        throw std::runtime_error("emit_instr_cmpjmp_unsigned: '" +
                                 instruction_parser->opcode +
                                 "' requiere (r_a, r_b, label)");
    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *op1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    if (!op0 || !op1)
        throw std::runtime_error("emit_instr_cmpjmp_unsigned: los dos primeros "
                                 "operandos deben ser registros");

    uint8_t r_a = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t r_b = encode_reg_general(op1->name.c_str()) & 0x0F;
    uint8_t b2 = static_cast<uint8_t>((r_a << 4) | r_b);
    uint8_t cond = cmpjmp_cond_from_opcode(instruction_parser->opcode);

    code_final.emit8(b2);
    code_final.emit8(cond);
    emit_target_u32_label(instruction_parser->operands[2].get(), code_final,
                          assembly_ctx, "emit_instr_cmpjmp_unsigned");

    DEBUG_PRINT("Emitiendo cmpjmpu.cc 0x69 r_a=%d r_b=%d cond=0x%X\n", r_a, r_b,
                cond);
}

/**
 * @brief Emite los operandos de @c decjnz r_counter, label (extended 0x6A,
 * FIXED_8).
 *
 * Encoding fisico: [0x00][0x6A][b2][0x00][target_u32_LE]
 *   b2 = (r_counter<<4) | 0
 */
void emit_instr_decjnz(const vm::Instruction *instruction_parser,
                       ByteWriter &code_final, const InstrInfo *now_instr,
                       Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 2)
        throw std::runtime_error("emit_instr_decjnz: '" +
                                 instruction_parser->opcode +
                                 "' requiere (r_counter, label)");
    auto *op0 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    if (!op0)
        throw std::runtime_error(
            "emit_instr_decjnz: el primer operando debe ser un registro");

    uint8_t r_cnt = encode_reg_general(op0->name.c_str()) & 0x0F;
    uint8_t b2 = static_cast<uint8_t>(r_cnt << 4);
    code_final.emit8(b2);
    code_final.emit8(0); // padding
    emit_target_u32_label(instruction_parser->operands[1].get(), code_final,
                          assembly_ctx, "emit_instr_decjnz");

    DEBUG_PRINT("Emitiendo decjnz 0x6A r_counter=%d\n", r_cnt);
}

// =========================================================================
// FASTPUSH / FASTPOP - push/pop multiple registers via bitmask
// =========================================================================

/**
 * @brief Emite los 2 bytes de mascara para @c fastpush / @c fastpop.
 *
 * El operando es un literal numerico (0..0xFFFF) donde el bit r representa
 * el registro general rN.  Encoding little-endian:
 *   byte 0: mask & 0xFF
 *   byte 1: (mask >> 8) & 0xFF
 */
void emit_instr_fastmask(const vm::Instruction *instruction_parser,
                         ByteWriter &code_final, const InstrInfo *now_instr,
                         Assembler *assembly_ctx) {
    if (instruction_parser->operands.size() < 1)
        throw std::runtime_error(
            "emit_instr_fastmask: '" + instruction_parser->opcode +
            "' requiere un operando inmediato (bitmask de 16 bits)");

    auto *num = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[0].get());
    if (!num)
        throw std::runtime_error(
            "emit_instr_fastmask: el operando debe ser un literal numerico");

    auto parsed = vm::parse_number_safe(num->value);
    if (!parsed)
        throw std::runtime_error("emit_instr_fastmask: numero invalido: " +
                                 num->value);

    uint64_t val = parsed.value();
    if (val > 0xFFFFu)
        throw std::runtime_error("emit_instr_fastmask: bitmask " +
                                 std::to_string(val) +
                                 " excede 16 bits (max 0xFFFF)");

    code_final.emit8(static_cast<uint8_t>(val & 0xFF));        // bits r0..r7
    code_final.emit8(static_cast<uint8_t>((val >> 8) & 0xFF)); // bits r8..r15

    DEBUG_PRINT("Emitiendo %s mask=0x%04X\n",
                instruction_parser->opcode.c_str(), (unsigned)val);
}

// =========================================================================
// MOVC / MOVCH -- conditional move based on a flag
// =========================================================================

/**
 * @brief Codifica el nombre de un flag a su codigo de 3 bits usado en
 * instrucciones MOVC/MOVCH.
 *
 * Flag codes: SF=0, ZF=1, CF=2, OF=3, DM=4 (must match read_flag() in
 * exec_instruction_alu.cpp).
 *
 * @param name  Flag name string ("SF", "ZF", "CF", "OF", or "DM").
 * @return      3-bit flag code (0-4).
 * @throws std::runtime_error for unknown flag names.
 */
static uint8_t encode_flag(const std::string &name) {
    if (name == "SF") return 0; // sign flag
    if (name == "ZF") return 1; // zero flag
    if (name == "CF") return 2; // carry flag
    if (name == "OF") return 3; // overflow flag
    if (name == "DM") return 4; // direction/mode flag
    throw std::runtime_error("emit_instr_movc: unknown flag: " + name);
}

/**
 * @brief Emite la codificacion para instrucciones MOVC / MOVCH.
 *
 * Supports:
 *   movc  reg1, [reg2], flag  (0x1E, host=0, d=0) -- load from VM memory if
 * flag set movc  [reg1], reg2, flag  (0x1E, host=0, d=1) -- store to VM memory
 * if flag set movch reg1, [reg2], flag  (0x1E, host=1, d=0) -- load from host
 * memory if flag set movch [reg1], reg2, flag  (0x1E, host=1, d=1) -- store to
 * host memory if flag set movc  reg1, reg2, flag    (0x1F, host=0, d=0) --
 * register-to-register if flag set
 *
 * Encoding for 0x1E:
 *   ctrl:  host_bits(2) | d(1) | r_nonbracket(5)  (bits[7:6]: 0b10=MOVCH,
 * 0b00=MOVC) byte4: flag_code(3) | r_bracket(5)
 *
 * Encoding for 0x1F:
 *   ctrl:  0b00 | 0 | reg1(4)
 *   byte4: flag_code(3) | reg2(5)
 *
 * @param instruction_parser Instruccion parseada (3 operandos: op0, op1,
 * etiqueta_flag).
 * @param code_final         Escritor de bytes de salida.
 * @param now_instr          Metadatos de instruccion (opcode2 selecciona
 * variante 0x1E vs 0x1F).
 * @param assembly_ctx       Contexto del ensamblador (no usado; requerido por
 * la firma de funcion).
 */
void emit_instr_movc(const vm::Instruction *instruction_parser,
                     ByteWriter &code_final, const InstrInfo *now_instr,
                     Assembler * /*assembly_ctx*/
) {
    if (instruction_parser->operands.size() != 3)
        throw std::runtime_error(
            "emit_instr_movc: requires exactly 3 operands");

    auto *op0 = instruction_parser->operands[0].get(); // primer operando
    auto *op1 = instruction_parser->operands[1].get(); // segundo operando
    auto *op2 =
        instruction_parser->operands[2].get(); // third operand (flag name)

    // third operand must be a flag identifier (LabelOperand)
    std::string flag_name;
    if (auto *lab = dynamic_cast<vm::LabelOperand *>(op2))
        flag_name = lab->name; // e.g. "ZF", "CF"
    else
        throw std::runtime_error("emit_instr_movc: third operand must be a "
                                 "flag name (ZF/SF/CF/OF/DM)");

    uint8_t flag_code = encode_flag(flag_name); // 3-bit flag selector
    bool is_movch =
        (instruction_parser->opcode == "movch"); // true if host memory

    auto *reg0 = dynamic_cast<vm::RegisterOperand *>(op0); // op0 as register
    auto *mem0 = dynamic_cast<vm::MemoryOperand *>(op0);   // op0 as memory
    auto *reg1 = dynamic_cast<vm::RegisterOperand *>(op1); // op1 as register
    auto *mem1 = dynamic_cast<vm::MemoryOperand *>(op1);   // op1 as memory

    // ---- 0x1E: one operand is memory ----
    if (now_instr->opcode2 == 0x1E) {
        uint8_t d;                                  // direction bit
        const vm::RegisterOperand *reg_a = nullptr; // register inside []
        const vm::RegisterOperand *reg_b = nullptr; // the other register

        if (mem0 != nullptr && reg1 != nullptr) {
            // movc [reg_a], reg_b, flag  -> d=1 (memory is destination)
            d = 1;
            reg_a = dynamic_cast<vm::RegisterOperand *>(
                mem0->expr.get()); // unwrap [...]
            reg_b = reg1;
        } else if (reg0 != nullptr && mem1 != nullptr) {
            // movc reg_b, [reg_a], flag  -> d=0 (register is destination)
            d = 0;
            reg_a = dynamic_cast<vm::RegisterOperand *>(
                mem1->expr.get()); // unwrap [...]
            reg_b = reg0;
        } else {
            throw std::runtime_error("emit_instr_movc (0x1E): one operand must "
                                     "be memory and the other a register");
        }

        if (!reg_a)
            throw std::runtime_error("emit_instr_movc (0x1E): the expression "
                                     "inside [] must be a register");

        uint8_t r_mem =
            encode_reg_general(reg_a->name.c_str()); // register used as address
        uint8_t r_reg = encode_reg_general(
            reg_b->name.c_str()); // the non-bracketed register

        // ctrl: host_bits(2) | d(1) | r_reg(5)
        // bits[7:6]: 0b10 = MOVCH, 0b00 = MOVC
        uint8_t host_bits = is_movch ? 0b10 : 0b00;
        uint8_t ctrl = (uint8_t)((host_bits << 6) | (d << 5) |
                                 (r_reg & 0xF)); // empaquetar campos
        uint8_t b4 = (uint8_t)((flag_code << 5) |
                               (r_mem & 0x1F)); // flag y registro de direccion

        code_final.emit8(ctrl); // emitir byte de control
        code_final.emit8(b4);   // emitir byte4
        return;
    }

    // ---- 0x1F: ambos operandos son registros ----
    if (!reg0 || !reg1)
        throw std::runtime_error(
            "emit_instr_movc (0x1F): both operands must be registers");

    uint8_t r1c =
        encode_reg_general(reg0->name.c_str()); // codigo de registro destino
    uint8_t r2c =
        encode_reg_general(reg1->name.c_str()); // codigo de registro fuente

    // ctrl: 0b00 | 0 | reg1(4)
    code_final.emit8(r1c & 0xF); // emitir byte de control (registro destino)
    code_final.emit8(
        (uint8_t)((flag_code << 5) |
                  (r2c & 0x1F))); // emitir byte4 (flag + source reg)
}

// =============================================================================
// Emision de instrucciones del banco ZMM (flotante escalar y vectorial)
// =============================================================================

/**
 * @brief Emite una instruccion ZMM registro-registro (fadd, fsub, fmul, etc.).
 *
 * Byte ctrl: mode(2) | is_f32(1) | 00000
 * Byte regs: idx2(4) | idx1(4)
 *
 * @param instruction_parser Instruccion del AST.
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Descriptor de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_freg(const vm::Instruction *instruction_parser,
                     ByteWriter &code_final, const InstrInfo *now_instr,
                     Assembler *assembly_ctx) {
    (void)assembly_ctx;
    (void)now_instr;

    auto *r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (!r1 || !r2)
        throw std::runtime_error(
            instruction_parser->opcode +
            ": se requieren dos operandos de registro ZMM");

    const uint8_t idx1 = zmm_reg_index(r1->name); // indice ZMM destino (0-15)
    const uint8_t idx2 = zmm_reg_index(r2->name); // indice ZMM fuente  (0-15)
    const uint8_t mode =
        zmm_reg_mode(r1->name); // ancho deducido del prefijo del destino

    // is_f32 = 1 si el mnemonico tiene sufijo ".ps" (packed single precision
    // float)
    const bool is_f32 =
        (instruction_parser->opcode.find(".ps") != std::string::npos);

    const uint8_t ctrl = static_cast<uint8_t>(
        (mode << 6) | (is_f32 ? (1 << 5) : 0)); // byte de control
    const uint8_t regs =
        static_cast<uint8_t>((idx2 << 4) | idx1); // byte de registros

    code_final.emit8(ctrl); // emitir byte de control
    code_final.emit8(regs); // emitir byte de registros
}

/**
 * @brief Emite FMADD (3 operandos ZMM): fd = fma(fa, fb, fd).
 *
 * FIXED_4, Convention B (decode_instr_raw_bytes): byte2 = (fa<<4)|fd,
 * byte3 = (fb<<4)|is_f32.  Sin byte de control de modo (la op es escalar; el
 * vectorizador la usa por lane).  El sufijo @c .ps activa el bit is_f32.
 */
void emit_instr_fmadd(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    (void)assembly_ctx;
    (void)now_instr;
    auto *r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get()); // fd
    auto *r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get()); // fa
    auto *r3 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[2].get()); // fb
    if (!r1 || !r2 || !r3)
        throw std::runtime_error(
            instruction_parser->opcode +
            ": se requieren tres operandos de registro ZMM");
    const uint8_t fd = zmm_reg_index(r1->name);
    const uint8_t fa = zmm_reg_index(r2->name);
    const uint8_t fb = zmm_reg_index(r3->name);
    const bool is_f32 =
        (instruction_parser->opcode.find(".ps") != std::string::npos);
    code_final.emit8(static_cast<uint8_t>((fa << 4) | fd)); // byte2
    code_final.emit8(
        static_cast<uint8_t>((fb << 4) | (is_f32 ? 1 : 0))); // byte3
}

/**
 * @brief Emite instrucciones ZMM unarias (fsqrt, fabs, fneg) con un solo
 * operando.
 *
 * El registro destino actua tambien como fuente: el mismo indice ZMM ocupa
 * tanto el nibble alto como el nibble bajo del byte de registros.
 * Esto es equivalente a llamar emit_instr_freg con r1 == r2.
 *
 * @param instruction_parser Instruccion del AST (un operando ZMM).
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Descriptor de la instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_freg_unary(const vm::Instruction *instruction_parser,
                           ByteWriter &code_final, const InstrInfo *now_instr,
                           Assembler *assembly_ctx) {
    (void)assembly_ctx;
    (void)now_instr;

    auto *r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());

    if (!r1)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": se requiere un operando de registro ZMM");

    const uint8_t idx = zmm_reg_index(r1->name); // indice ZMM (0-15)
    const uint8_t mode = zmm_reg_mode(r1->name); // ancho del registro
    const bool is_f32 =
        (instruction_parser->opcode.find(".ps") != std::string::npos);

    const uint8_t ctrl = static_cast<uint8_t>(
        (mode << 6) | (is_f32 ? (1 << 5) : 0)); // byte ctrl
    const uint8_t regs =
        static_cast<uint8_t>((idx << 4) | idx); // dst=src=mismo reg

    code_final.emit8(ctrl); // emitir byte de control
    code_final.emit8(
        regs); // emitir byte de registros (mismo indice en ambos nibbles)
}

/**
 * @brief Emite la instruccion FMOWI (carga inmediato IEEE 754 de 64 bits en
 * ZMM).
 *
 * Formato del payload (9 bytes):
 *   Byte  0: ctrl = mode(2) | is_f32(1) | zmm_idx(4)
 *   Bytes 1-8: bits IEEE 754 del inmediato de 64 bits
 *
 * @param instruction_parser Instruccion del AST.
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Descriptor de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_fmowi(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    (void)assembly_ctx;
    (void)now_instr;

    auto *r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *imm = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[1].get());

    if (!r1 || !imm)
        throw std::runtime_error(
            "fmowi: se requiere un registro ZMM y un inmediato de 64 bits");

    const uint8_t idx = zmm_reg_index(r1->name); // indice ZMM destino (0-15)
    const uint8_t mode = zmm_reg_mode(r1->name); // ancho del registro
    const bool is_f32 =
        (instruction_parser->opcode.find(".ps") != std::string::npos);

    // parsear el valor inmediato (bits IEEE 754 codificados como entero)
    auto bits_opt = vm::parse_number_safe(imm->value);
    if (!bits_opt)
        throw std::runtime_error("fmowi: inmediato invalido: " + imm->value);

    // empaquetar mode(2), is_f32(1) y zmm_idx(4) en un solo byte de control
    const uint8_t ctrl = static_cast<uint8_t>(
        (mode << 6) | (is_f32 ? (1 << 5) : 0) | (idx & 0x0F));
    const uint64_t bits = *bits_opt; // bits IEEE 754 del inmediato

    code_final.emit8(ctrl);  // byte de control con registro empaquetado
    code_final.emit64(bits); // inmediato de 64 bits (bits IEEE 754)
}

/**
 * @brief Emite las instrucciones FLOAD y FSTORE (acceso a memoria VM).
 *
 * Byte ctrl: mode(2) | 000000
 * Byte regs: gp_idx(4) | zmm_idx(4)
 *
 * @param instruction_parser Instruccion del AST.
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Descriptor de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_fmem(const vm::Instruction *instruction_parser,
                     ByteWriter &code_final, const InstrInfo *now_instr,
                     Assembler *assembly_ctx) {
    (void)assembly_ctx;
    (void)now_instr;

    auto *r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (!r1 || !r2)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": se requieren dos operandos de registro");

    // fload:  r1=zmm_dst, r2=gp_addr
    // fstore: r1=gp_addr, r2=zmm_src
    const bool is_fstore = (instruction_parser->opcode == "fstore");
    uint8_t zmm_idx, gp_idx, mode;

    if (is_fstore) {
        gp_idx = encode_reg_general(r1->name.c_str()); // GP con la direccion VM
        zmm_idx = zmm_reg_index(r2->name);             // ZMM fuente
        mode = zmm_reg_mode(r2->name); // ancho del registro ZMM fuente
    } else {
        zmm_idx = zmm_reg_index(r1->name);             // ZMM destino
        gp_idx = encode_reg_general(r2->name.c_str()); // GP con la direccion VM
        mode = zmm_reg_mode(r1->name); // ancho del registro ZMM destino
    }

    const uint8_t ctrl =
        static_cast<uint8_t>(mode << 6); // byte de control: solo mode
    const uint8_t regs =
        static_cast<uint8_t>((gp_idx << 4) | zmm_idx); // GP alto, ZMM bajo

    code_final.emit8(ctrl); // emitir byte de control
    code_final.emit8(regs); // emitir byte de registros
}

/**
 * @brief Emite la instruccion FCVT (conversion int<->float).
 *
 * Byte ctrl: mode(2) | is_f32(1) | direction(1) | 0000
 * Byte regs: gp_idx(4) | zmm_idx(4)
 *
 * @param instruction_parser Instruccion del AST.
 * @param code_final         Escritor de bytecode.
 * @param now_instr          Descriptor de instruccion.
 * @param assembly_ctx       Contexto del ensamblador.
 */
void emit_instr_fcvt(const vm::Instruction *instruction_parser,
                     ByteWriter &code_final, const InstrInfo *now_instr,
                     Assembler *assembly_ctx) {
    (void)assembly_ctx;
    (void)now_instr;

    auto *r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());

    if (!r1 || !r2)
        throw std::runtime_error(
            "fcvt: se requieren dos operandos de registro");

    const bool is_f32 =
        (instruction_parser->opcode.find(".ps") != std::string::npos);

    uint8_t gp_idx, zmm_idx, mode, direction;

    if (is_zmm_register(r1->name)) {
        // ZMM(r1) -> GP(r2) : float a int (direction=1)
        zmm_idx = zmm_reg_index(r1->name);
        gp_idx = encode_reg_general(r2->name.c_str());
        mode = zmm_reg_mode(r1->name);
        direction = 1;
    } else {
        // GP(r1) -> ZMM(r2) : int a float (direction=0)
        gp_idx = encode_reg_general(r1->name.c_str());
        zmm_idx = zmm_reg_index(r2->name);
        mode = zmm_reg_mode(r2->name);
        direction = 0;
    }

    // ctrl: mode(7:6) | is_f32(5) | direction(4) | 0000
    const uint8_t ctrl = static_cast<uint8_t>(
        (mode << 6) | (is_f32 ? (1 << 5) : 0) | (direction << 4));
    const uint8_t regs =
        static_cast<uint8_t>((gp_idx << 4) | zmm_idx); // GP alto, ZMM bajo

    code_final.emit8(ctrl); // emitir byte de control
    code_final.emit8(regs); // emitir byte de registros
}

// =========================================================================
// Sprint string-perf-5: emit_instr_bitcast_zg para bitg2z/bitz2g.
// Codifica un GP + un ZMM en el mismo byte de registros.
// Layout: regs = (gp_idx << 4) | zmm_idx (alto=GP, bajo=ZMM).
// =========================================================================
void emit_instr_bitcast_zg(const vm::Instruction *instruction_parser,
                           ByteWriter &code_final, const InstrInfo *now_instr,
                           Assembler *assembly_ctx) {
    (void)assembly_ctx;
    (void)now_instr;
    auto *r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto *r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    if (!r1 || !r2)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": se requieren dos operandos de registro");

    uint8_t gp_idx, zmm_idx, mode;
    if (is_zmm_register(r1->name)) {
        // bitg2z fX, rN: r1=ZMM dst, r2=GP src
        zmm_idx = zmm_reg_index(r1->name);
        gp_idx = encode_reg_general(r2->name.c_str());
        mode = zmm_reg_mode(r1->name);
    } else {
        // bitz2g rN, fX: r1=GP dst, r2=ZMM src
        gp_idx = encode_reg_general(r1->name.c_str());
        zmm_idx = zmm_reg_index(r2->name);
        mode = zmm_reg_mode(r2->name);
    }
    const uint8_t ctrl = static_cast<uint8_t>(mode << 6);
    const uint8_t regs = static_cast<uint8_t>((gp_idx << 4) | zmm_idx);
    code_final.emit8(ctrl);
    code_final.emit8(regs);
}

// =========================================================================
// emit_str_two_reg: Convention B, 2 registros - para instrucciones de string
// =========================================================================

/**
 * @brief Emite b2=(r_dst<<4)|r_src, b3=0 para instrucciones de string de dos
 * registros.
 *
 * Convention B: byte2 lleva los dos indices de registro, byte3 es cero.
 * Usado por strlen, strflat, strhash, strintern, strgetenc, strgetbytes,
 * strgetkind, strreserve, strfinalize, strraw.
 */
void emit_str_two_reg(const vm::Instruction *instruction_parser,
                      ByteWriter &code_final, const InstrInfo *now_instr,
                      Assembler *assembly_ctx) {
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    if (!r1 || !r2)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requiere dos operandos registro");

    uint8_t idx1 =
        encode_reg_general(r1->name.c_str()); // r_dst: nibble alto de b2
    uint8_t idx2 =
        encode_reg_general(r2->name.c_str()); // r_src: nibble bajo de b2

    code_final.emit8(static_cast<uint8_t>((idx1 << 4) | (idx2 & 0x0F))); // b2
    code_final.emit8(0x00); // b3 siempre cero
}

// =========================================================================
// emit_strconv: Convention B, 2 registros + encoding literal
// =========================================================================

/**
 * @brief Emite b2=(r_dst<<4)|r_src, b3=(enc<<4) para STRCONV.
 *
 * El tercer operando es un literal numerico (StringEncoding 0-4)
 * que se codifica en el nibble alto de b3.
 */
void emit_strconv(const vm::Instruction *instruction_parser,
                  ByteWriter &code_final, const InstrInfo *now_instr,
                  Assembler *assembly_ctx) {
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    auto enc = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[2].get());
    if (!r1 || !r2 || !enc)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requiere r_dst, r_src, enc_literal");

    uint8_t idx1 = encode_reg_general(r1->name.c_str());
    uint8_t idx2 = encode_reg_general(r2->name.c_str());
    uint8_t enc_val = static_cast<uint8_t>(std::stoull(enc->value) & 0x0F);

    code_final.emit8(static_cast<uint8_t>((idx1 << 4) | (idx2 & 0x0F))); // b2
    code_final.emit8(
        static_cast<uint8_t>(enc_val << 4)); // b3: enc en nibble alto
}

// =========================================================================
// emit_setcc: Convention B, 1 registro + codigo de condicion literal
// =========================================================================

/**
 * @brief Emite b2=(cond<<4)|r_dst, b3=0 para SETCC.
 *
 * El segundo operando es un literal numerico (codigo de condicion 0-15).
 */
void emit_setcc(const vm::Instruction *instruction_parser,
                ByteWriter &code_final, const InstrInfo *now_instr,
                Assembler *assembly_ctx) {
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto cond = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[1].get());
    if (!r1 || !cond)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requiere r_dst, cond_literal");

    uint8_t idx1 = encode_reg_general(r1->name.c_str());
    uint8_t cond_val = static_cast<uint8_t>(std::stoull(cond->value) & 0x0F);

    code_final.emit8(
        static_cast<uint8_t>((cond_val << 4) | (idx1 & 0x0F))); // b2
    code_final.emit8(0x00);                                     // b3
}

// =========================================================================
// emit_sext: Convention B, 1 registro + ancho literal (8/16/32)
// =========================================================================

/**
 * @brief Emite b2=r_dst (nibble bajo), b3=N (ancho fuente en bits).
 *
 * `sext r_dst, N` sign-extiende r_dst desde N bits (8/16/32) a 64.  El ancho
 * va en el byte3 completo (no cabe en un nibble como el cond de setcc).
 */
void emit_sext(const vm::Instruction *instruction_parser,
               ByteWriter &code_final, const InstrInfo *now_instr,
               Assembler *assembly_ctx) {
    (void)now_instr;
    (void)assembly_ctx;
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto width = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[1].get());
    if (!r1 || !width)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requiere r_dst, N_literal (8/16/32)");
    uint8_t idx1 = encode_reg_general(r1->name.c_str());
    uint8_t width_val = static_cast<uint8_t>(std::stoull(width->value) & 0xFF);
    code_final.emit8(static_cast<uint8_t>(idx1 & 0x0F)); // b2 = r_dst
    code_final.emit8(width_val);                         // b3 = N (bits)
}

// emit_gcfinal: gcfinal r_box, kind.  byte2=0, byte3=(kind<<4)|r_box.
// Mismo empaquetado que decode_instr_two_op_reg espera (reg1=r_box en el
// nibble bajo, reg2=kind en el nibble alto).
void emit_gcfinal(const vm::Instruction *instruction_parser,
                  ByteWriter &code_final, const InstrInfo *now_instr,
                  Assembler *assembly_ctx) {
    (void)now_instr;
    (void)assembly_ctx;
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto kind = dynamic_cast<vm::NumberOperand *>(
        instruction_parser->operands[1].get());
    if (!r1 || !kind)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requiere r_box, kind_literal");
    uint8_t idx1 = encode_reg_general(r1->name.c_str());
    uint8_t kind_val = static_cast<uint8_t>(std::stoull(kind->value) & 0x0F);
    code_final.emit8(0x00); // b2 ctrl
    code_final.emit8(
        static_cast<uint8_t>((kind_val << 4) | (idx1 & 0x0F))); // b3
}

// emit_gcfinalc: `gcfinalc` / `gcfinalu` r_box, r_target.
//
// Registra un finalizador diciendo A QUIEN llamar: el destructor concreto de
// una clase (`gcfinalc`) o el liberador de un `unique` (`gcfinalu`).  Los dos
// comparten opcode y se distinguen por los dos bits altos del byte de control,
// igual que `mods` y `modu`: cero es el destructor de clase, que es lo que ese
// byte significaba cuando estaba sin usar, asi que el bytecode que ya existe
// sigue diciendo lo mismo.
//
// b2 = kind<<6, b3 = (r_target<<4)|r_box -- el mismo empaquetado que
// decode_instr_two_op_reg (reg1 nibble bajo, reg2 alto).
void emit_gcfinalc(const vm::Instruction *instruction_parser,
                   ByteWriter &code_final, const InstrInfo *now_instr,
                   Assembler *assembly_ctx) {
    (void)now_instr;
    (void)assembly_ctx;
    auto r1 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[0].get());
    auto r2 = dynamic_cast<vm::RegisterOperand *>(
        instruction_parser->operands[1].get());
    if (!r1 || !r2)
        throw std::runtime_error(instruction_parser->opcode +
                                 ": requiere r_box, r_target");
    uint8_t idx1 = encode_reg_general(r1->name.c_str()); // r_box
    uint8_t idx2 = encode_reg_general(r2->name.c_str()); // r_target
    // El mnemonico elige a quien se llama; ver arriba por que el cero es el
    // destructor de clase.
    const uint8_t kind = (instruction_parser->opcode == "gcfinalu") ? 1u : 0u;
    code_final.emit8(static_cast<uint8_t>(kind << 6));                   // b2
    code_final.emit8(static_cast<uint8_t>((idx2 << 4) | (idx1 & 0x0F))); // b3
}

} // namespace Assembly::Bytecode
