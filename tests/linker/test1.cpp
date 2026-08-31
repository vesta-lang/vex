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
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>

#include "cli/sync_io.h"

#include "../util/mem_stats.h"

#include "emmit/parser_to_bytecode.h"
#include "lexer/lexer.h"
#include "parser/parser.h"
#include "profiler/timer.h"
#include "linker/velb_linker_bytecode.h"

using namespace Assembly::Bytecode;

int main() {
    Timer global;

    // Leer archivo fuente
    const std::string name_file("test.vel");
    std::ifstream file(name_file);
    if (!file.is_open()) {
        std::cerr << "ERROR: No se pudo abrir: " << name_file << "\n";
        return 1;
    }

    std::string code((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());

    if (code.empty()) {
        std::cerr << "ERROR: Archivo vacio\n";
        return 1;
    }

    // Lexer + Parser

    vm::Lexer lexer(code);
    vm::Parser parser(lexer);

    std::vector<std::unique_ptr<vm::ASTNode>> program;
    Timer t_parser;
    try {
        program = parser.parse();
    } catch (const vm::ParseError &e) {
        std::cerr << "Parse error: " << e.what() << "\n";
        return 1;
    }
    std::cout << "[Tiempo parser] " << t_parser.us() << " us " << t_parser.ms()
              << " ms\n";

    // Resolver imports
    std::unordered_set<std::string> imported_files;
    resolve_imports(program, imported_files);

    // Ensamblar
    Assembler asmblr;
    Timer t_asm;
    auto bytecode = asmblr.assemble(program);
    std::cout << "[Tiempo Assembler] " << t_asm.us() << " us " << t_asm.ms()
              << " ms\n";

#ifdef DEBUG_EMIT
    std::cout << "\n=== CONTEXTO GENERADO POR EL ENSAMBLADOR ===\n";
    print_context(asmblr.ctx);

    std::cout << "\n=== BYTES GENERADOS ===\n";
    for (size_t i = 0; i < bytecode.size(); ++i) {
        if (i % 16 == 0)
            std::cout << "\n"
                      << std::setw(8) << std::setfill('0') << std::hex << i
                      << ": ";
        std::cout << std::setw(2) << std::setfill('0') << std::hex
                  << (int)bytecode[i] << " ";
    }
    std::cout << std::dec << "\n\n";

    print_context_with_bytes(asmblr.ctx, bytecode);
#endif

    // LINKER
    Linker::LinkerOptions opts;
    opts.optimize_bytecode = true;
    opts.generate_map_file = true;
    opts.output_path = "program.velb";
    opts.map_file_path = "program.velb-map";
    opts.verbose = true;

    Timer t_linker;
    Linker::Linker linker(opts);

    // Añadir el ensamblado crudo
    linker.add_assembly_unit(bytecode, &asmblr.ctx);

    // añadir objetos externos
    // linker.add_object_file("libmath.velo");
    // linker.add_static_library("stdlib.vela");

    // Construir ejecutable
    linker.write_to_file(opts.output_path);

    // Generar map file
    if (opts.generate_map_file) linker.write_map_file(opts.map_file_path);

    // Reporte
    const auto &report = linker.get_report();
    std::cout << "[Tiempo Linker] " << std::dec << t_linker.us() << " us "
              << t_linker.ms() << " ms\n";

    std::cout << "\n=== LINKER REPORT ===\n";
    std::cout << "Modulos enlazados: " << std::dec << (int)report.modules_linked
              << "\n";
    std::cout << "Simbolos resueltos: " << std::dec
              << (int)report.symbols_resolved << "\n";
    std::cout << "Relocaciones aplicadas: " << std::dec
              << (int)report.relocations_applied << "\n";
    std::cout << "Optimizaciones aplicadas: " << std::dec
              << (int)report.optimizations_applied << "\n";

    if (!report.errors.empty()) {
        std::cout << "\n=== ERRORES ===\n";
        for (auto &e : report.errors)
            std::cout << " - " << e << "\n";
    }

    if (!report.warnings.empty()) {
        std::cout << "\n=== WARNINGS ===\n";
        for (auto &w : report.warnings)
            std::cout << " - " << w << "\n";
    }

    std::cout << "\n=== RELOCATIONS ===\n";
    for (const auto &r : report.relocations_log) {
        std::cout << "[Reloc] module=" << r.module << " symbol=" << r.symbol
                  << " type=" << Linker::reloc_type_to_string(r.type)
                  << " offset=0x" << std::hex << r.offset << " value=0x"
                  << std::hex << r.value_written << std::dec << "\n";
    }
    std::cout << "Archivo final generado por el linker" << std::endl;
    std::cout << vesta::dump(linker.result->output.data(),
                             linker.result->output.size());

    std::cout << std::dec;
    std::cout << "\n[Tiempo total] " << global.us() << " us " << global.ms()
              << " ms\n";

    print_memory_stats();

    return 0;
}
