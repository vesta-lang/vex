#include <optional>
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
 * @file helpers_emmit_parser_to_bytecode.cpp
 * @brief Funciones auxiliares de emision de bytecode del ensamblador de
 * VestaVM.
 *
 * Contiene las implementaciones de las funciones @c emit_inc_dec(),
 * @c emit_instr_reg(), @c emit_instr_inmed(), @c emit_instr_sib(),
 * @c emit_instr_movc(), @c emit_jrel(), @c emit_cursor_rw(), @c emit_gcderef()
 * y otras funciones de emision referenciadas en @c InstrTable.
 */
#include "emmit/parser_to_bytecode.h"
#include "emmit/mnemonic.h" // consulta por indice, no por hash de cadena

namespace Assembly::Bytecode {
size_t Assembler::size_of_directive(const std::string &dir) const {
    if (dir == "db") return 1;
    if (dir == "dw") return 2;
    if (dir == "dd") return 4;
    if (dir == "dq") return 8;

    // Puntero del tamano de la VM (64 bits)
    if (dir == "ptr") return sizeof(uint64_t);

    throw std::runtime_error("Unknown data directive: " + dir);
}

/**
 * 1 Recibir el valor final (ya evaluado)
 * 2 Escribirlo en little-endian
 * 3 Usar el tamano correcto segun la directiva
 *
 * @param dir
 * @param value
 */
void Assembler::emit_directive(const std::string &dir, uint64_t value) {
    size_t size = size_of_directive(dir);

    for (size_t i = 0; i < size; ++i) {
        output.emit8(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

/**
 * Las cadenas deben emitirse caracter a caracter
 * @param data datos de la cadena
 */
void Assembler::emit_data(const vm::DataDecl *data) {
    for (auto &expr : data->values) {
        if (auto s = vm::node_as<vm::StringExpr>(expr.get())) {
            for (char c : s->value)
                output.emit8(static_cast<uint8_t>(c));
            continue;
        }

        // `dq @Absolute("code.<sym>")`: referencia absoluta a un simbolo (reloc
        // datos->codigo).  La usa la vtable de los structs @Virtual.  Registra
        // una relocacion @c Absolute64 que el linker rebasa a la direccion VM
        // final del simbolo y emite 8 bytes placeholder (el linker los
        // parchea).
        if (auto ar = vm::node_as<vm::AbsRefExpr>(expr.get())) {
            Relocation rel;
            rel.symbol = ar->symbol;
            rel.section = current_section ? current_section->name : "";
            rel.offset = static_cast<uint64_t>(output.offset);
            rel.type = Type::Absolute64;
            ctx.add_relocation(rel);
            for (int i = 0; i < 8; ++i)
                output.emit8(0x00); // placeholder
            continue;
        }

        // Para numeros, labels, expresiones:
        uint64_t v = eval_expr(expr.get());
        emit_directive(data->directive, v);
    }
}

const InstrInfo &Assembler::select_variant(
    const std::string &mnemonic,
    const std::vector<std::unique_ptr<vm::ASTNode>> &ops) const {
    /* Por INDICE, no hasheando el nombre.  Esto corre una vez por instruccion
     * emitida, y hasta ahora cada una pagaba el hash de su mnemonico ademas de
     * la comparacion de la cadena al resolver la colision.
     *
     * El indice se construye UNA vez desde la misma tabla -- no hay una segunda
     * copia de los datos: apunta a ella.  Y la tabla sigue escrita por nombre,
     * que es lo que una persona lee y edita. */
    static const emmit::MnemonicIndex<std::vector<InstrInfo>> kIndex(
        InstrTable);
    const std::vector<InstrInfo> *found =
        kIndex.find(emmit::mnemonic_from_text(mnemonic.c_str()));
    if (found == nullptr)
        throw std::runtime_error(
            "select_variant(): Unknown instruction in InstrTable: " + mnemonic);

    const auto &variants = *found;

    // si es un registro el primero
    AddressingMode mode = AddressingMode::NONE;

    // si no tiene operandos, suponemos que es una instruccion sin tal
    if (ops.size() == 0) goto search_variante_None;

    if (auto s = vm::node_as<vm::RegisterOperand>(ops[0].get())) {
        mode = AddressingMode::REG;
    }

    // si hay mas de dos operandos, entonces, el primer operando si es un
    // registro no se puede usar para averiguar el direccionamiento de la
    // instruccion.
    if (ops.size() >= 2) {
        // si el segundo operando es de tipo memoria, el modo de
        // direccionamiento es este u SIB
        if (auto s = vm::node_as<vm::MemoryOperand>(ops[1].get())) {
            mode = AddressingMode::MEM;

            if (auto bin = vm::node_as<vm::BinaryExpr>(s->expr.get())) {
                if (bin->op == '-' || bin->op == '+' || bin->op == '*') {
                    mode = AddressingMode::SIB;
                }
            }
        }

        // si el op2 es un registro, el modo de direcionamiento confirmado es
        // registro
        else if (auto s = vm::node_as<vm::RegisterOperand>(ops[1].get())) {
            mode = AddressingMode::REG;
        } else if (auto s = vm::node_as<vm::AnnotationNode>(ops[1].get())) {
            // si el segundo operando es una notacion
            if (s->key == "Method" || s->key == "Relative" ||
                s->key == "Absolute") {
                // si el segundo operando es una notacion Method
                // entonces el modo de operacion es de tipo INMEDIATO, y se esta
                // pidiendo indica la direccion de memoria de un metodo que debe
                // haber sido cargado por el loader-linker en run time.
                mode = AddressingMode::INMED;
            } else {
                throw std::runtime_error(
                    "select_variant(): No se permite usar esta notacion (" +
                    s->key + ") en la instruccion: " + mnemonic);
            }
        }

        // es de tipo inmed [0x1000]
        else if (auto s = vm::node_as<vm::NumberOperand>(ops[1].get())) {
            mode = AddressingMode::INMED;
        }

        // si el operando 1 es de tipo memoria, el resto de operandos da igual
        // de que tipo sea, ya que siempre sera memoria. por eso usar if y no
        // else if aqui
        if (auto s = vm::node_as<vm::MemoryOperand>(ops[0].get())) {
            mode = AddressingMode::MEM;

            if (auto bin = vm::node_as<vm::BinaryExpr>(s->expr.get())) {
                if (bin->op == '-' || bin->op == '+' || bin->op == '*') {
                    mode = AddressingMode::SIB;
                }
            }
        }

        // error?
    } else {
        // si solo hay un operando, y fue un registro, entonces, es correcto

        // si no hubo registro, y solo hay un operando, debe ser un inmediato
        if (auto s = vm::node_as<vm::NumberOperand>(ops[0].get())) {
            mode = AddressingMode::INMED;
        } else if (auto s = vm::node_as<vm::LabelOperand>(ops[0].get())) {
            // un label como destino de salto se trata como inmediato (direccion
            // absoluta)
            mode = AddressingMode::INMED;
        } else if (auto s = vm::node_as<vm::AnnotationNode>(ops[0].get())) {
            // si el segundo operando es una notacion
            if (s->key == "Method" || s->key == "Relative" ||
                s->key == "Absolute") {
                // si el segundo operando es una notacion Method
                // entonces el modo de operacion es de tipo INMEDIATO, y se esta
                // pidiendo indica la direccion de memoria de un metodo que debe
                // haber sido cargado por el loader-linker en run time.
                mode = AddressingMode::INMED;
            } else {
                throw std::runtime_error(
                    "select_variant(): No se permite usar esta notacion (" +
                    s->key + ") en la instruccion: " + mnemonic);
            }
        }
    }

    // si este caso se da, quiere decir que el operando usa un inmediato que se
    // mueve a memoria, por ejemplo: adds [r0], 0x1000 tambien cubre anotaciones
    // @Absolute/@Relative/@Method como inmediatos (el linker sobreescribe el
    // placeholder al resolver el simbolo).
    if (mode == AddressingMode::MEM) {
        if (auto s = vm::node_as<vm::NumberOperand>(ops[1].get())) {
            mode = AddressingMode::INMED;
        } else if (auto s = vm::node_as<vm::AnnotationNode>(ops[1].get())) {
            if (s->key == "Method" || s->key == "Relative" ||
                s->key == "Absolute") {
                mode = AddressingMode::INMED;
            }
        }
    }

    // si mode sigue siendo MEM y la instruccion no tiene variante MEM explicita
    // (p.ej. mov r0,[r1] o adds r0,[r1]) -> usar SIB.
    // Instrucciones como movc que tienen variante MEM real no deben caer aqui.
    if (mode == AddressingMode::MEM) {
        bool has_mem_variant = false;
        for (const auto &v : variants) {
            if (v.mode == AddressingMode::MEM) {
                has_mem_variant = true;
                break;
            }
        }
        if (!has_mem_variant) mode = AddressingMode::SIB;
    }

    // alguna instrucciones como los NOP no tiene operandos,
    // por lo que todoo el analisis anterior se puede saltar
search_variante_None:
    int idx = -1;
    for (int i = 0; i < variants.size(); ++i) {
        if (variants[i].mode == mode) {
            idx = i; // indice obtenido, sabemos cual es la variante
            break;
        }
    }

    if (idx != -1) {
        return variants[idx]; // devolvemos la variante
    }

    throw std::runtime_error(
        "select_variant(): Unknown instruction variants: " + mnemonic);
}

void Assembler::emit_instruction(const vm::Instruction *instr) {
    const auto &info = select_variant(instr->opcode, instr->operands);

    // Offset de INICIO de esta instruccion (antes de emitir ningun byte).  El
    // stackmap preciso que porta esta instruccion se registra EN este offset:
    // es donde estara el rip del interprete cuando el GC corra en su PC.  Vale
    // para AMBOS tipos de safepoint (misma semantica):
    //   - Directo (newobj/gcalloc/gccollect/...): el marcador `// @sm` va SOBRE
    //     el opcode del safepoint; su rip == este offset.
    //   - Return-site (tras callvm/callvirt): el marcador `// @sm` va sobre la
    //     PRIMERA instruccion posterior al call; el ret_addr que el call empuja
    //     == este offset (el frame walk lee [rbp+8] = este offset).
    const uint32_t instr_start_offset = static_cast<uint32_t>(output.offset);

    // Stackmap preciso pendiente de publicar: se rellena con los slots del
    // marcador `// @sm` y su byte_offset se fija al INICIO de la instruccion
    // portadora (@c instr_start_offset), al final de esta funcion.
    std::optional<Context::StackmapRec> pending_stackmap;

    // Si la instruccion tiene linea fuente Vesta registrada por el
    // parser (capturada del marcador `// @line N` del lexer),
    // anadirla a la tabla debug del Context.  El offset que
    // guardamos es el del INICIO de la instruccion en el bytecode
    // del modulo.  El linker convierte mas tarde a offset absoluto
    // dentro del .velb sumando module_base_offset.
    if (instr->source_line > 0) {
        ctx.debug_lines.push_back(
            {static_cast<uint32_t>(output.offset),
             static_cast<uint32_t>(instr->source_line),
             static_cast<uint32_t>(instr->source_column)});
    }

    // Stackmap PRECISO ( E.1): si la instruccion lleva un marcador
    // `// @sm <hex>`, decodificar el hex y registrar el par
    // (byte_offset_del_modulo, slots).  El linker suma el offset del code
    // section para producir el offset absoluto y emite la seccion VSMP.
    //
    // Formato hex: pares de digitos hex = bytes.  Layout de bytes (LE):
    //   [u16 slot_count] [slot_count * { u8 location, u8 gc_kind }]
    if (!instr->stackmap_hex.empty()) {
        const std::string &hx = instr->stackmap_hex;
        // Helper: par de digitos hex -> byte.  Solo procesamos si la
        // longitud es par (defensivo ante corrupcion).
        auto hexval = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        if ((hx.size() % 2) == 0 && hx.size() >= 4) {
            std::vector<uint8_t> bytes;
            bytes.reserve(hx.size() / 2);
            bool ok = true;
            for (size_t i = 0; i + 1 < hx.size(); i += 2) {
                const int hi = hexval(hx[i]);
                const int lo = hexval(hx[i + 1]);
                if (hi < 0 || lo < 0) {
                    ok = false;
                    break;
                }
                bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
            }
            if (ok && bytes.size() >= 2) {
                const uint16_t slot_count =
                    static_cast<uint16_t>(bytes[0] | (bytes[1] << 8));
                // Cada slot son 2 bytes; validamos que caben.
                if (static_cast<size_t>(2) + slot_count * 2 <= bytes.size()) {
                    pending_stackmap.emplace();
                    Context::StackmapRec &rec = *pending_stackmap;
                    rec.slots.reserve(slot_count);
                    size_t p = 2;
                    for (uint16_t k = 0; k < slot_count; ++k) {
                        Context::StackmapSlotRec s;
                        s.location = bytes[p++];
                        s.gc_kind = bytes[p++];
                        rec.slots.push_back(s);
                    }
                    // byte_offset se fija DESPUES de emitir esta instruccion:
                    // el marcador `// @sm` que produjo el emisor va ligado a la
                    // instruccion de CALL (el lexer lo consume en el skip de
                    // whitespace tras el call), pero la raiz debe registrarse
                    // en el RETURN_PC = offset del byte SIGUIENTE al call (lo
                    // que callvm/callvirt empujan como ret_addr).  Por eso
                    // diferimos la asignacion del offset al final de la
                    // emision.
                }
            }
        }
    }

    // 1 opcode1
    output.emit8(info.opcode1);

    // 2 si opcode1 == 0x00, emito opcode2
    if (info.opcode1 == 0x00) output.emit8(info.opcode2);

    // 3 resto de campos segun la instruccion (flags, reg, SIB, addr, etc.)
    //    aqui ya mirar los operandos y generar el encoding real.
    if (info.emit != nullptr) {
        info.emit(instr, output, &info, this);
    } else {
        // si la instruccion tiene direccionamiento y no tiene funcion de
        // emision, no esta implementada, para el resto de casos donde es None,
        // la instruccion solo codifica sus opcodes
        if (info.mode != AddressingMode::NONE) {
            std::cout << "La instruccion: " << instr->opcode
                      << " no esta implementada en el ensamblador, no tiene "
                         "una unidad de emision"
                      << std::endl;
        }
    }

    // Fijar el offset del stackmap pendiente y publicarlo.  El PC bajo el que
    // el scan busca el stackmap depende del TIPO de safepoint:
    //
    //   - DIRECTO (newobj/gcalloc/...): el marcador `// @sm` queda ligado al
    //     propio opcode del safepoint; el rip del interprete cuando el GC corre
    //     ES el INICIO de esa instruccion -> byte_offset = instr_start_offset.
    //
    //   - RETURN-SITE (tras callvm/callvirt/callm): el emisor coloca el
    //   marcador
    //     `// @sm` JUSTO DESPUES del call, con la INTENCION de ligarlo a la
    //     instruccion siguiente (el return_pc).  Pero el lexer lo captura en el
    //     lookahead que cierra el parse del PROPIO call -> el marcador queda
    //     ligado al CALL, no a la instruccion posterior.  El frame-walk del
    //     scan preciso lee el return_pc = [rbp+8], que es el offset del byte
    //     SIGUIENTE al call (lo que callvm/callvirt empujan como ret_addr) = el
    //     INICIO + el tamano del call = @c output.offset TRAS emitir el call.
    //     Por eso el stackmap de un carrier de tipo CALL se registra en el
    //     offset POST-emit (return_pc), no en su inicio.  Sin esto el stackmap
    //     queda mal-keyed (nunca coincide con el return_pc del walk) y las
    //     raices GC vivas SOLO alcanzables desde un frame CALLER (p.ej. el `l`
    //     de una lista enlazada construida en un helper) se pierden -> UAF con
    //     el GC moving del nursery preciso.
    if (pending_stackmap) {
        const bool call_carrier =
            (instr->opcode == "callvm" || instr->opcode == "callvirt" ||
             instr->opcode == "callm");
        pending_stackmap->byte_offset =
            call_carrier ? static_cast<uint32_t>(output.offset)
                         : instr_start_offset;
        ctx.stackmap_recs.push_back(std::move(*pending_stackmap));
        pending_stackmap.reset();
    }
}
} // namespace Assembly::Bytecode
