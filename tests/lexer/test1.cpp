/*
 * VestaVM - Máquina Virtual Distribuida
 *
 * Copyright © 2026 David López.T (DesmonHak) (Castilla y León, ES)
 * Licencia VMProject
 *
 * USO LIBRE NO COMERCIAL con atribución obligatoria.
 * PROHIBIDO lucro sin permiso escrito.
 *
 * Descargo: Autor no responsable por modificaciones.
 */

#include <iostream>
#include <cassert>

#include "json.hpp"
#include "emmit/parser_to_bytecode.h"
#include "lexer/lexer.h"
#include "parser/parser.h"
#include "profiler/timer.h"

#include "../util/mem_stats.h"

void print_program(const std::vector<std::unique_ptr<vm::ASTNode>> &program,
                   int indent = 0) {
    std::cout << "=== PROGRAM AST ===" << std::endl;
    for (const auto &node : program) {
        if (node) {
            node->print(indent);
            std::cout << std::endl;
        }
    }
    std::cout << "===================" << std::endl;
}

void print_AnnotationNode(const vm::AnnotationNode *node, int indent = 0) {
    std::string pad(indent, ' ');
    std::cout << pad << node->key;
    if (!node->value.empty()) std::cout << " = " << node->value;
    std::cout << std::endl;

    for (const auto &child : node->children) {
        if (auto childAnno = dynamic_cast<vm::AnnotationNode *>(child.get())) {
            print_AnnotationNode(childAnno, indent + 2);
        }
    }
}

void print_doc_ast(const std::vector<std::unique_ptr<vm::ASTNode>> &program,
                   int indent = 0) {
    for (const auto &node : program) {
        if (!node) continue;

        // Tomamos el puntero crudo de la clase base
        vm::ASTNode *basePtr = node.get();

        // Intentamos hacer downcast a AnnotationNode
        if (auto annoNode = dynamic_cast<vm::AnnotationNode *>(basePtr)) {
            std::cout << "=== PROGRAM DOC ===" << std::endl;
            print_AnnotationNode(annoNode, indent);
        } else if (auto LabelNode = dynamic_cast<vm::LabelNode *>(basePtr)) {
            // LabelNode->print(indent);

            // Recursión sobre el cuerpo de la sección
            print_doc_ast(LabelNode->body, indent + 2);
        }
        // Otros tipos de nodos base
        // else basePtr->print(indent);
    }
}

int main() {
    Timer global;

    Timer t_read;
    const std::string name_file("test.vel");
    std::ifstream file(name_file); // o "codigo.txt", "programa.vm", etc.
    if (!file.is_open()) {
        std::cerr << "ERROR: No se pudo abrir: " << name_file << std::endl;
        return 1;
    }
    // Leer todo el archivo en un string
    std::string code((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    std::cout << "[Tiempo lectura archivo] " << t_read.us() << " us "
              << t_read.ms() << " ms\n";

    if (code.empty()) {
        std::cerr << "ERROR: Archivo vacío\n";
        return 1;
    }
    vm::Lexer lexer(code);

    /*while (true) {
        vm::Token tok = lexer.next_token();
        std::cout << "Token: "
                  << token_type_to_string(tok.type)
                  << ", lexeme: '" << tok.lexeme
                  << "', line: " << tok.line
                  << ", col: " << tok.column << "\n";

        if (tok.type == vm::TokenType::EndOfFile)
            break;
    }*/

    try {
        Timer t_parser;
        vm::Parser parser(lexer);
        auto program = parser.parse();
        std::cout << "[Tiempo parser] " << t_parser.us() << " us "
                  << t_parser.ms() << " ms\n";

        print_program(program);
        print_doc_ast(program);

        // resolver dependencias
        std::unordered_set<std::string> imported_files;
        Assembly::Bytecode::resolve_imports(program, imported_files);

        Timer t_asm;
        Assembly::Bytecode::Assembler MyAsm{};
        auto bytes = MyAsm.assemble(program);
        std::cout << "\n[Tiempo de ensamblado] " << t_asm.us() << " us "
                  << t_asm.ms() << " ms\n";

        // imprimir el contexto que el ensamblador genero
        print_context(MyAsm.ctx);

        const size_t BYTES_PER_LINE = 16;
        size_t count = 0;

        for (uint8_t b : bytes) {
            // Nueva línea cada 16 bytes
            if (count % BYTES_PER_LINE == 0) {
                if (count != 0) std::cout << "\n";
                std::cout << std::setw(8) << std::setfill('0') << std::hex
                          << count << ": ";
            }

            // Imprimir byte en hex, 2 dígitos
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)b
                      << " ";

            count++;
        }
        std::cout << std::dec; // restaurar a modo decimal

        std::cout << std::endl;

        Assembly::Bytecode::print_context_with_bytes(MyAsm.ctx, bytes);

    } catch (const vm::ParseError &e) {
        std::cerr << "\nPARSE ERROR\n"
                  << "Linea " << e.line << ":" << e.column << "\n"
                  << "  " << e.what() << "\n";
        return 1; // Exit code 1 (error)
    }

    std::cout << "\n[Lexer Test] Finalizado\n";

    print_memory_stats();
    std::cout << "\n[Tiempo total] " << global.us() << " us " << global.ms()
              << " ms\n";
    return 0;
}
