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
 * @file parser_to_bytecode.cpp
 * @brief Implementacion del ensamblador de 3 fases de VestaVM.
 *
 * Implementa los metodos de @c Assembly::Bytecode::Assembler:
 * constructor, @c first_pass(), @c compute_label_sizes(), @c emit_pass(),
 * @c assemble(), @c emit_instruction(), @c emit_data(), @c select_variant(),
 * @c eval_expr(), @c eval_operand(), @c apply_annotation() y @c
 * apply_directive().
 */
#include "emmit/parser_to_bytecode.h"
#include "emmit/mnemonic.h" // consulta por indice, no por hash de cadena
#include <algorithm>        // UCRT64: no transitivo

#include "cli/sync_io.h"

namespace Assembly::Bytecode {
uint64_t Assembler::eval_operand(const vm::ASTNode *op) {
    // numero inmediato como operando
    if (auto num = dynamic_cast<const vm::NumberOperand *>(op)) {
        return vm::parse_number(num->value);
    }

    // label como operando
    if (auto lab = dynamic_cast<const vm::LabelOperand *>(op)) {
        auto it = symbol_table.find(lab->name);
        if (it == symbol_table.end())
            throw std::runtime_error("Label no definido: " + lab->name);
        return it->second->address;
    }

    // si algun dia permitir expresiones como operando:
    if (auto expr = dynamic_cast<const vm::ExprNode *>(op)) {
        return eval_expr(const_cast<vm::ExprNode *>(expr));
    }

    // throw std::runtime_error("Operando no valido para directiva (se esperaba
    // numero o label)");
    return 0;
}

uint64_t Assembler::eval_expr(vm::ExprNode *expr) {
    if (auto n = dynamic_cast<vm::NumberExpr *>(expr))
        return vm::parse_number(n->value);

    if (auto l = dynamic_cast<vm::LabelExpr *>(expr))
        return symbol_table[l->name]->address;

    if (auto b = dynamic_cast<vm::BinaryExpr *>(expr)) {
        uint64_t L = eval_expr(b->left.get());
        uint64_t R = eval_expr(b->right.get());
        switch (b->op) {
        case '+': return L + R;
        case '-': return L - R;
        case '*': return L * R;
        case '/': return L / R;
        }
    }

    throw std::runtime_error("Invalid expression");
}

Assembler::Assembler() {
    symbol_table.clear();
}

void Assembler::compute_label_sizes() {
    for (auto &[spaceName, space] : ctx.space_address) {
        for (auto &[sectionName, section] : space.table_section) {
            // Obtener labels ordenados por offset
            std::vector<Label *> ordered;
            ordered.reserve(section.table_label.size());

            for (auto &[name, lbl] : section.table_label)
                ordered.push_back(&lbl);

            std::sort(ordered.begin(), ordered.end(), [](Label *a, Label *b) {
                return a->address < b->address;
            });

            // Calcular tamanos
            for (size_t i = 0; i < ordered.size(); ++i) {
                uint64_t start = ordered[i]->address;
                uint64_t end;

                if (i + 1 < ordered.size())
                    end = ordered[i + 1]->address;
                else
                    end = section.size_real; // ultimo label

                ordered[i]->size = end - start;
            }
        }
    }
}

std::vector<uint8_t>
Assembler::assemble(const std::vector<std::unique_ptr<vm::ASTNode>> &ast) {
    uint64_t offset = 0;

    // por ahora esta seccion y espacio contendra la meta informacion y la anade
    // el ensamblador
    ctx.add_space("MetaSpace", 0x0, 0x0);
    ctx.get_space("MetaSpace")->add_section("strings", 0x0, 0x0);

    // 1 Primera pasada
    for (auto &node : ast)
        first_pass(node.get(), offset);

    // cerrar el tramo de la ultima seccion activa: su tamano son los bytes
    // emitidos hasta el final del flujo.
    close_section_layout(offset);

    current_section = nullptr;
    current_label = nullptr;

    // conociendo el offset de cada seccion y label, se puede
    // calcular el tamano de cada label
    // compute_label_sizes();

    for (auto &node : ast)
        emit_pass(node.get());

    // 2 Segunda pasada (datos)
    /*for (auto &node: ast)
        second_pass_data(node.get());

    current_offset = 0;

    // 3 Tercera pasada (codigo)
    for (auto &node: ast)
        third_pass_code(node.get());*/

    // una vez realizado todas las fases de analisis de etiquetas
    // y emision de codigo, se puede computar las direcciones de inicio
    // y final de cada seccion.
    ctx.compute_all_ranges();
    return output.output;
}

void Assembler::emit_pass(const vm::ASTNode *node) {
    // Si el nodo es una etiqueta (LabelNode)
    if (auto lab = dynamic_cast<const vm::LabelNode *>(node)) {
        if (current_section == nullptr)
            throw std::runtime_error("Label no definido: " + lab->name);
        current_label = current_section->get_label(lab->name);
        // Recorre todos los nodos dentro del cuerpo de la etiqueta
        // y vuelve a llamar a emit_pass recursivamente.
        for (auto &child : lab->body)
            emit_pass(child.get());
    }

    // Si el nodo es una declaracion de datos
    else if (auto data = dynamic_cast<const vm::DataDecl *>(node)) {
        emit_data(data); // Llama al manejador especifico para datos
    }

    // debemos evaluar las notaciones section, para poder averiguar en que
    // seccion y label se encuentra el codigo.
    else if (auto annotation = dynamic_cast<const vm::AnnotationNode *>(node)) {
        if (annotation->key == "Section") {
            std::string section_name;
            for (const auto &child : annotation->children) {
                if (child->key == "Name") {
                    section_name = child->value;
                    break;
                }
            }

            this->current_section = this->ctx.get_section(section_name);

            // Reproducir el relleno de alineacion que la primera pasada dio por
            // supuesto: la imagen es plana, asi que los bytes de la seccion
            // deben empezar exactamente en su stream_offset.  Sin este relleno
            // los offsets del flujo no cuadrarian con las direcciones
            // virtuales calculadas.
            if (this->current_section != nullptr &&
                this->current_section->layout_started) {
                if (output.offset > this->current_section->stream_offset) {
                    // las dos pasadas discrepan: seria un fallo del
                    // ensamblador, no del programa del usuario.  Mejor abortar
                    // que emitir un binario con las direcciones corridas.
                    throw std::runtime_error(
                        "Error interno: descuadre entre pasadas en la seccion "
                        "'" +
                        section_name + "': el flujo va por " +
                        std::to_string(output.offset) +
                        " pero la seccion empieza en " +
                        std::to_string(this->current_section->stream_offset));
                }
                while (output.offset < this->current_section->stream_offset)
                    output.emit8(0x00);
            }
        }
    }
    // Si el nodo es una instruccion
    else if (auto instr = dynamic_cast<const vm::Instruction *>(node)) {
        // Si la instruccion es una pseudo-instruccion (directiva)
        if (PseudoInstructions.count(instr->opcode)) {
            apply_directive(instr); // Aplica la directiva correspondiente
        } else {
            // Si es una instruccion real, emite su codigo maquina,
            // se debe conocer la seccion y label
            emit_instruction(instr);
        }
    }
}

void Assembler::close_section_layout(uint64_t offset) {
    // solo tienen tramo las secciones en las que se llego a entrar
    if (current_section == nullptr || !current_section->layout_started) return;

    // el tamano real de la seccion son los bytes emitidos desde que se entro en
    // ella.  Se calcula aqui (y no al emitir cada dato) para que cuente tambien
    // el codigo, no solo las directivas de datos.
    current_section->size_real = offset - current_section->stream_offset;
}

void Assembler::begin_section_layout(uint64_t &offset) {
    if (current_section == nullptr) return;

    uint32_t align = current_section->size_align_section;
    if (align == 0) align = 1; // defensivo: align_up exige potencia de 2

    // alinear el flujo: como la imagen es plana, alinear el offset del flujo es
    // exactamente alinear la direccion virtual de la seccion.  El hueco lo
    // rellenara emit_pass con ceros para que ambas pasadas coincidan.
    offset = align_up(offset, align);

    current_section->stream_offset = offset;
    current_section->layout_started = true;
    current_section->size_real = 0;
}

void Assembler::first_pass(const vm::ASTNode *node, uint64_t &offset) {
    // --- LABELS ---
    if (auto lab = dynamic_cast<const vm::LabelNode *>(node)) {
        // solo aplicar si el formato es velb
        if (!current_section && ctx.format_output == "velb")
            throw std::runtime_error("Label fuera de una seccion");

        // offset inicial de la label
        uint64_t start = offset;

        // registrar la label en la seccion, tamano temporal = 0.
        // La direccion de una label es RELATIVA al inicio de su seccion; el
        // linker le suma la direccion base de la seccion para obtener la
        // direccion absoluta.
        if (current_section != nullptr) {
            current_section->add_label(
                lab->name, offset - current_section->stream_offset, 0);
            current_label = current_section->get_label(lab->name);
        }

        symbol_table[lab->name] = current_label;

        // Guardar seccion actual, al usar first_pass puede cambiar
        // si hay un label vacio con una notacion section despues
        Section *saved_section = current_section;

        // procesar el cuerpo de la label
        for (auto &child : lab->body)
            first_pass(child.get(), offset);

        // ahora offset ha avanzado -> calcular tamano real
        uint64_t size = offset - start;

        // actualizar tamano real en la seccion
        if (saved_section) saved_section->update_label_size(lab->name, size);
    }

    // para nodos de tipo anotacion, no todos los nodos de este tipo, se tienen
    // en cuenta.
    else if (auto data = dynamic_cast<const vm::AnnotationNode *>(node)) {
        // @Section declara Y activa una seccion: marca la frontera entre el
        // tramo de flujo de la seccion anterior y el de la nueva.
        const bool is_section = (data->key == "Section");

        // cerrar el tramo de la seccion que termina (antes de alinear, para no
        // imputarle el relleno de la siguiente)
        if (is_section) close_section_layout(offset);

        apply_annotation(data); // apply_section actualiza current_section

        // abrir el tramo de la nueva seccion (alinea el flujo)
        if (is_section) begin_section_layout(offset);
    }

    // --- DECLARACION DE DATOS CON SUS DIRECTIVAS ---
    else if (auto data = dynamic_cast<const vm::DataDecl *>(node)) {
        if (!current_section && ctx.format_output == "velb")
            throw std::runtime_error("Label fuera de una seccion");

        // Validar que el label no este vacio
        if (data->label.empty()) {
            throw std::runtime_error("Error: declaracion de datos sin label.");
        }

        // Validar que el label no este duplicado
        if (symbol_table.find(data->label) != symbol_table.end()) {
            throw std::runtime_error("Error: label duplicado: '" + data->label +
                                     "'");
        }

        size_t elem_size = size_of_directive(data->directive);
        size_t offset_label = offset; // debemos guardar el offset de la label,
        // ya que se modificara en el for el offset global y se perdera la
        // referencia

        // guarda el tamano real de la label
        size_t size_of_label = 0;
        for (auto &expr : data->values) {
            if (auto s = dynamic_cast<vm::StringExpr *>(expr.get())) {
                size_of_label += s->value.size();
                offset += s->value.size();
            } else {
                size_of_label += elem_size;
                offset += elem_size;
            }
        }

        if (current_section == nullptr) {
            vesta::scout() << "ERROR: No declaraste ningun seccion en tu codigo"
                           << std::endl;
            exit(EXIT_FAILURE);
        }

        // anadir a la seccion actual el nuevo label, con direccion relativa al
        // inicio de la seccion (el tamano real de la seccion se calcula al
        // cerrar su tramo, en close_section_layout)
        current_section->add_label(
            data->label, offset_label - current_section->stream_offset,
            size_of_label);

        // anadimos la label a la seccion, una vez obtenida su tamano real
        symbol_table[data->label] = current_section->get_label(data->label);
    }

    // --- INSTRUCCIONES Y DIRECTIVAS ---
    else if (auto instr = dynamic_cast<const vm::Instruction *>(node)) {
        {
            /* Es una instruccion real?  Por indice: esto corre por cada nodo
             * del programa, y el nombre ya no se hashea -- se traduce una vez a
             * mnemonico y de ahi es una lectura.  El indice se construye una
             * vez sobre la misma tabla; no hay copia de los datos. */
            static const emmit::MnemonicIndex<std::vector<InstrInfo>> kIndex(
                InstrTable);
            const std::vector<InstrInfo> *variantes =
                kIndex.find(emmit::mnemonic_from_text(instr->opcode.c_str()));

            if (variantes == nullptr) {
                // No esta en la tabla -> puede ser una pseudo-instruccion
                // (directiva) o un error del usuario.

                if (PseudoInstructions.count(instr->opcode)) {
                    if (instr->opcode == "align") {
                        /* si es align, en la primera fase se debe aplicar aqui,
                         * ya que sino offset y current_offset se
                         * desincronizaran.
                         */
                        // No ocupan espacio, configuran el entorno / emisor
                        vm::NumberOperand *number =
                            dynamic_cast<vm::NumberOperand *>(
                                instr->operands[0].get());
                        uint64_t align = eval_operand(number);

                        if (align == 0 || (align & (align - 1)) != 0)
                            throw std::runtime_error(
                                "Error: align debe ser potencia de 2.");

                        // alineamos el offset local al tamano indicado.
                        offset = (offset + align - 1) & ~(align - 1);
                    } else
                        apply_directive(instr);
                    return;
                }

                throw std::runtime_error(
                    "Error: instruccion o directiva desconocida: '" +
                    instr->opcode + "'");
            }

            // Instruccion valida -> sumar su tamano

            const auto &info = select_variant(instr->opcode, instr->operands);
            switch (info.sizeMode) {
            case InstrSizeMode::FIXED_1: {
                offset += 1;
                break;
            }
            case InstrSizeMode::FIXED_2: {
                offset += 2;
                break;
            }
            case InstrSizeMode::FIXED_4: {
                offset += 4;
                break;
            }
            case InstrSizeMode::FIXED_6: {
                offset += 6;
                break;
            }
            case InstrSizeMode::FIXED_8: {
                offset += 8;
                break;
            }
            case InstrSizeMode::FIXED_10: {
                offset += 10;
                break;
            }
            case InstrSizeMode::FIXED_11: {
                offset += 11;
                break;
            }

            // por ahora este caso solo existe para las instrucciones
            // inmediatas, pues su tamano depende del modo de operacion el
            // usuario elija, se debe examinar que tamano escogio el programador
            case InstrSizeMode::MIXED_SIZE: {
                auto n0 = instr->operands[0].get();
                auto n1 = instr->operands[1].get();

                auto inmmed_str = dynamic_cast<vm::NumberOperand *>(n1);

                auto reg = dynamic_cast<vm::RegisterOperand *>(n0);
                auto mem = dynamic_cast<vm::MemoryOperand *>(n0);

                // si no se obtuvo un registro, y se obtuvo un operando memoria
                // esto es true.
                if (reg == nullptr) {
                    reg = dynamic_cast<vm::RegisterOperand *>(mem->expr.get());
                    if (reg == nullptr) {
                        std::cout << "Error instruccion: " + instr->opcode +
                                         " esperaba un registro para acceder a "
                                         "memoria pero obtuvo algo distinto: "
                                  << std::endl;
                        mem->expr->print(0);
                        throw std::runtime_error("Error instruccion: " +
                                                 instr->opcode);
                    }
                }
                uint8_t mode = encode_mode(reg->size_bits);
                // las instrucciones inmediatas usan 3 bytes de inicio siempre +
                // bytes del inmediato.
                offset += 3 + mode_to_bytes(mode);
                break;
            }
            default: {
                std::cout << "Error instruccion: " + instr->opcode +
                                 " instruccion de size desconocido. "
                          << std::endl;
                throw std::runtime_error("Error instruccion: " + instr->opcode);
            }
            }
        }
    }
}

void Assembler::apply_annotation(const vm::AnnotationNode *annotation) {
    // si la notacion esta permitida por el ensamblador entonces tiene efecto y
    // describe alguna informacion necesaria para este ensamblador.
    const emmit::Directive d =
        emmit::directive_from_text(annotation->key.c_str());
    if (const AnnotationHandler h = handler_of(d)) {
        h(annotation, *this); // Ejecuta la funcion asociada
        return;
    }

    // si no era una notacion permitida por el ensamblador, se mira si es una
    // notacion de tipo documentacion, estas notaciones no tienen ningun efecto
    // en el ensamblador en primer lugar
    if (annotation_allow_doc.find(annotation->key) !=
        annotation_allow_doc.end()) {
        // mas adeltante, generar secciones de documentacion + metadatos con
        // esta informacion.
        return;
    }

    throw std::runtime_error("Error: la notacion: " + annotation->key +
                             " no es una notacion valida");
}

void Assembler::apply_directive(const vm::Instruction *instr) {
    const std::string &op = instr->opcode;

    // --- org ---
    /*if (op == "org") {
        if (instr->operands.size() != 1)
            throw std::runtime_error("Error: org requiere 1 operando.");

        if (true) {
            uint64_t new_addr = eval_operand(instr->operands[0].get());
            current_offset = default_address = new_addr;
        } else {
            instr->operands[0]->print(4);
            throw std::runtime_error("Error: org requiere 2 operando.");
        }

        return;
    }*/

    // --- align ---
    if (op == "align") {
        if (instr->operands.size() != 1)
            throw std::runtime_error("Error: align requiere 1 operando.");

        vm::NumberOperand *number =
            dynamic_cast<vm::NumberOperand *>(instr->operands[0].get());
        uint64_t align = eval_operand(number);

        if (align == 0 || (align & (align - 1)) != 0)
            throw std::runtime_error("Error: align debe ser potencia de 2.");

        while (output.offset % align != 0) {
            output.emit8(0x00);
        }

        return;
    }

    if (op == "import") {
        if (instr->operands.size() != 1)
            throw std::runtime_error(
                "Error: import requiere un string don el archivo a incluir.");
    }

    throw std::runtime_error("Error: directiva desconocida: " + op);
}
} // namespace Assembly::Bytecode
