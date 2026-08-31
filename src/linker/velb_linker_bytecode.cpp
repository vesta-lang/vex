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
 * @file velb_linker_bytecode.cpp
 * @brief Implementacion del linker de bytecode VELB para VestaVM.
 *
 * Implementa la clase @c Assembly::Bytecode::Linker::Linker:
 * carga de modulos objeto (@c add_object_file, @c add_assembly_unit),
 * resolucion de simbolos (@c resolve_symbols), aplicacion de relocalizaciones
 * (@c apply_relocations), optimizacion (@c optimize_modules),
 * y construccion del ejecutable final VELB (@c build_executable, @c
 * write_to_file).
 */
#include "util/env_flags.h"
#include "linker/velb_linker_bytecode.h"
#include <algorithm> // UCRT64: no transitivo

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unordered_map>
#include "emmit/bytereader.h"
#include "emmit/parser_to_bytecode.h"
#include "loader/loader.h"
#include "debug/debug_info.h"

namespace Assembly::Bytecode::Linker {
/* Profiler interno del linker (opt-in via env VESTA_LINKER_PROFILE=1).
 * Instrumenta cada fase de build_executable para identificar el hot path real
 * antes de optimizar a ciegas.  Cero overhead cuando el env var no esta
 * seteado. */
static bool linker_profile_enabled() {
    static int cached = -1;
    if (cached < 0) {
        cached = util::flag_on(util::FlagId::LinkerProfile) ? 1 : 0;
    }
    return cached == 1;
}

struct LinkerPhaseTimer {
    const char *name;
    std::chrono::steady_clock::time_point t0;
    bool enabled;
    LinkerPhaseTimer(const char *n)
        : name(n), enabled(linker_profile_enabled()) {
        if (enabled) t0 = std::chrono::steady_clock::now();
    }
    ~LinkerPhaseTimer() {
        if (!enabled) return;
        auto t1 = std::chrono::steady_clock::now();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                      .count();
        std::fprintf(stderr, "[linker-prof] %-24s %8lld us\n", name,
                     static_cast<long long>(us));
        std::fflush(stderr);
    }
};

/* RAII para medir tamano emitido por una fase.  Reporta delta de output.size()
 * para detectar fases que escriben muchos bytes (candidatos a pre-reserve). */
struct LinkerPhaseSize {
    const char *name;
    const std::vector<uint8_t> &buf;
    size_t start_size;
    bool enabled;
    LinkerPhaseSize(const char *n, const std::vector<uint8_t> &b)
        : name(n), buf(b), start_size(b.size()),
          enabled(linker_profile_enabled()) {}
    ~LinkerPhaseSize() {
        if (!enabled) return;
        size_t delta = buf.size() - start_size;
        if (delta > 0) {
            std::fprintf(stderr, "[linker-prof]   %-22s +%8zu bytes\n", name,
                         delta);
            std::fflush(stderr);
        }
    }
};

// cambiar en un futuro, por ahora para pruebas me vale
static uint64_t simple_checksum(const std::vector<uint8_t> &data) {
    uint64_t sum = 0;
    for (auto b : data)
        sum += b;
    return sum;
}

void Linker::add_object_file(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        add_errorf(report, LinkerError::Type::IOError,
                   ("No se pudo abrir objeto: " + path).c_str());
        return;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());

    if (data.empty()) {
        add_errorf(report, LinkerError::Type::IOError,
                   ("Objeto vacio: " + path).c_str());
        return;
    }

    // TODO: aqui parsear formato .velo/.velb parcial.
    // Por ahora, lo tratamos como un modulo con bytecode plano y sin contexto
    // real.

    Module m;
    m.name = path;
    m.bytecode = std::move(data);
    m.is_object = true;

    // TODO: rellenar m.ctx, m.local_symbols, m.relocations segun el formato
    // real.

    modules.push_back(std::move(m));
    report.modules_linked++;
}

void Linker::add_object_memory(const std::vector<uint8_t> &data) {
    if (data.empty()) {
        add_warningf(report, LinkerWarning::Type::IOWarning,
                     ("add_object_memory: buffer vacio"));
        return;
    }

    Module m;
    m.name = "<memory-object>";
    m.bytecode = data;
    m.is_object = true;

    // TODO: parsear cabecera interna si la hay.

    modules.push_back(std::move(m));
    report.modules_linked++;
}

void Linker::add_static_library(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        add_errorf(report, LinkerError::Type::IOError,
                   ("No se pudo abrir libreria estatica: " + path).c_str());
        return;
    }

    // TODO: parsear header VELA, tabla de modulos, etc.
    // Por ahora solo registramos la ruta.

    StaticLibrary lib;
    lib.path = path;
    libraries.push_back(std::move(lib));
}

/**
 * - calcular el offset base donde se anadira la nueva seccion
 * - desplazar labels
 * - desplazar relocaciones
 * - concatenar bytecode
 * @param dest
 * @param src
 */
/*void Linker::merge_section(Section &dest, const Section &src) {
    uint64_t base = dest.size_real;

    // Copiar labels con offset ajustado
    for (const auto &[labelName, lbl]: src.table_label) {
        Label newLbl = lbl;
        newLbl.address += base;
        dest.table_label[labelName] = newLbl;
    }

    // Copiar bytecode
    dest.bytecode.insert(dest.bytecode.end(),
                         src.bytecode.begin(),
                         src.bytecode.end());

    // Actualizar tamano
    dest.size_real += src.size_real;
}*/

/**
 * - concatenar secciones
 * - recalcular offsets
 * - actualizar labels
 * - desplazar bytecode
 * - ajustar relocaciones
 * @param dest
 * @param src
 */
void Linker::merge_space_address(Space &dest, const Space &src) {
    for (const auto &[secName, sec] : src.table_section) {
        auto it = dest.table_section.find(secName);

        if (it == dest.table_section.end()) {
            // No existe, copiar seccion completa
            dest.table_section[secName] = sec;
        } else {
            // Ya existe, fusionar secciones
            // merge_section(it->second, sec);
        }
    }
}

uint64_t Linker::register_import(const ImportEntry &imp) {
    std::string key = imp.library + ":" + imp.function;

    // ?Ya existe?
    auto it = import_lookup.find(key);
    if (it != import_lookup.end()) {
        return it->second; // devolver indice existente
    }

    // Crear nueva entrada
    uint64_t new_index = import_table.size();

    ImportEntry copy = imp;
    copy.index = new_index;

    import_table.push_back(copy);
    import_lookup[key] = new_index;

    return new_index;
}

void Linker::add_assembly_unit(const std::vector<uint8_t> &bytecode,
                               const Context *ctx) {
    /**
     * Problemas resueltos:
     *      - 1 espacio de direcciones solapados, si se solapan se emite un
     * error.
     *      - 2 La posibilidad de que dos archivos (modulos) contengan el mismo
     * espacio de direcciones con un mismo nombre, si ese caso se da, fusionamos
     * los espacios de direcciones.
     *      - 3 Este problema es causado por la solucion del segundo problema,
     * al fusionar espacios de direcciones, estamos espandiendo el tamano del
     * espacio en uno de los modulos, donde otras secciones de este podria
     * esperar existir en ese rango de direcciones, lo que causara un
     * solapamiento de los espacios de direcciones. La solucion a este problema
     * puede ser reubicar el siguiente espacio de direcciones, pero debo emitir
     * un warning de esto. Mientras todos los modulos usen los mismos espacios
     * de direcciones o no use espacios de direcciones muy solapados entre
     * ellos, no deberia haber problema.
     */
    Module m;
    m.name = "<assembly-unit>";
    m.bytecode = bytecode;
    m.ctx = *ctx; // copia del contexto
    m.is_object = false;

    // anadir las relocalizaciones del modulo a todo_ el linker
    m.relocations.insert(m.relocations.end(), ctx->relocations.begin(),
                         ctx->relocations.end());

    for (const auto &imp : ctx->import_table) {
        uint64_t global_index = register_import(imp);

        // IMPORTANTE:
        // Debe actualizar las relocaciones del modulo que usen este import.
        // Ejemplo: CALLN <local_index> -> CALLN <global_index>
    }

    // Fusionar espacios del modulo en el linker
    for (const auto &[spaceName, space] : ctx->space_address) {
        // Comprobar si se solapa con otros espacios ya existentes
        for (const auto &[existingName, existingSpace] : spaces_address) {
            /**
             * Si el espacio que estamos revisando (existingName)
             * tiene el mismo nombre que el espacio que estamos anadiendo
             * (spaceName), entonces NO debemos comprobar solapamiento entre
             * ellos. Porque:
             *   - Si tienen el mismo nombre, no son espacios distintos.
             *   - Son dos partes del mismo espacio logico (por ejemplo, ambos
             * son "code").
             *   - Esos espacios no deben compararse entre si, sino fusionarse.
             */
            if (existingName == spaceName)
                continue; // este se fusiona, no se compara

            if (ranges_overlap(&existingSpace.range, &space.range)) {
                std::cout << "Error: el espacio '" + spaceName +
                                 "' del modulo se solapa con el espacio '" +
                                 existingName + "' ya existente."
                          << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        // Existe ya este espacio en el linker?
        auto it = spaces_address.find(spaceName);

        if (it == spaces_address.end()) {
            // No existe -> copiarlo tal cual
            spaces_address[spaceName] = space;
        } else {
            // Ya existe -> fusionar
            merge_space_address(it->second, space);
        }
    }

    // configuramos el start_pc indicado el ensamblador
    final_header.start_pc = ctx->start_pc;

    if (final_header.start_pc == 0) {
        void *ptr = reinterpret_cast<void *>(
            static_cast<uintptr_t>(final_header.start_pc));

        add_warningf(report, LinkerWarning::Type::PCDefault,
                     "Estas usando una direccion PC(%p) por defecto?", ptr);
    }

    modules.push_back(std::move(m));
    report.modules_linked++;
}

void Linker::resolve_symbols() {
    global_symbols.clear();
    symbol_info.clear();
    if (linker_profile_enabled()) {
        size_t total_labels = 0;
        for (const auto &mod : modules) {
            for (const auto &[sp, space] : mod.ctx.space_address) {
                for (const auto &[sn, sec] : space.table_section) {
                    total_labels += sec.table_label.size();
                }
            }
        }
        std::fprintf(
            stderr,
            "[linker-prof]   resolve_symbols: modulos=%zu, total_labels=%zu\n",
            modules.size(), total_labels);
        std::fflush(stderr);
    }

    // iteramos sobre cada modulo
    for (auto &mod : modules) {
        // Recorremos espacios -> secciones
        for (const auto &[spaceName, space] : mod.ctx.space_address) {
            for (const auto &[sectionName, section] : space.table_section) {
                uint64_t base = section.memory.address_init;

                // Extraer labels de la seccion en un vector ordenado
                std::vector<std::pair<std::string, const Label *>> ordered;

                for (const auto &[labelName, label] : section.table_label) {
                    ordered.push_back({labelName, &label});
                }

                // ordenar las label por las direcciones.
                std::sort(ordered.begin(), ordered.end(), [](auto &a, auto &b) {
                    return a.second->address < b.second->address;
                });

                // Calcular tamano de cada label
                for (size_t i = 0; i < ordered.size(); ++i) {
                    const auto &[labelName, label] = ordered[i];

                    uint64_t start = label->address;
                    uint64_t end;

                    uint64_t section_real_size = section.size_real;
                    if (i + 1 < ordered.size()) {
                        // siguiente label
                        end = ordered[i + 1].second->address;
                    } else {
                        end = section_real_size;
                    }

                    uint64_t size = end - start;

                    // Construir nombre completo
                    std::string fullName = sectionName + "." + labelName;

                    // Direccion absoluta
                    uint64_t absolute = base + start;

                    //
                    // Duplicados
                    if (global_symbols.count(fullName)) {
                        add_errorf(report, LinkerError::Type::DuplicateSymbol,
                                   ("Simbolo duplicado: " + fullName +
                                    " en modulo " + mod.name)
                                       .c_str());
                        continue;
                    }

                    // Registrar simbolo global
                    global_symbols[fullName] = absolute;

                    // Registrar informacion extendida
                    SymbolInfo info;
                    info.space = spaceName;
                    info.section = sectionName;
                    info.relative = start;
                    info.absolute = absolute;
                    info.file_offset = 0; // se rellenara despues
                    info.size = size;
                    info.module = mod.name;

                    symbol_info[fullName] = info;

                    report.symbols_resolved++;
                }
            }
        }
    }

    // TODO: resolver simbolos indefinidos
}

void Linker::apply_relocations() {
    // limpiar la tabla de relocations capturadas (por si se llama
    // mas de una vez en un mismo Linker).
    applied_relocations_.clear();
    if (linker_profile_enabled()) {
        size_t total_relocs = 0;
        for (const auto &mod : modules)
            total_relocs += mod.relocations.size();
        std::fprintf(
            stderr,
            "[linker-prof]   apply_relocations: modulos=%zu, total_relocs=%zu, "
            "global_symbols=%zu, import_lookup=%zu\n",
            modules.size(), total_relocs, global_symbols.size(),
            import_lookup.size());
        std::fflush(stderr);
    }

    // cuando se concatenan bytecodes en `merge_sections`, cada
    // modulo se anade en orden.  Aqui llevamos un acumulador del offset
    // de cada modulo dentro del @c final_bytecode para registrar
    // direcciones absolutas con offsets RELATIVOS A FINAL_BYTECODE
    // (no relativos al modulo).  El loader luego anade
    // @c offset_real_bytecode + section.file_offset para llegar al .velb.
    uint64_t module_base_offset = 0;
    // Recorrer todos los modulos cargados
    // Cada modulo tiene:
    // su propio bytecode
    // su propia tabla de relocaciones
    // su propio nombre (para logs)
    for (auto &mod : modules) {
        // Recorre todas las relocaciones del modulo.
        // Cada rel contiene:
        // rel.symbol -> nombre del simbolo a resolver
        // rel.offset -> posicion en el bytecode donde escribir la direccion
        // rel.type -> tipo de relocacion (ABS64, REL32, REL64)
        for (const auto &rel : mod.relocations) {
            // Busca el simbolo en la tabla global
            auto it = global_symbols.find(rel.symbol);

            bool import_code = false;
            // Si no existe, error de simbolo no resuelto.
            // equivalente a: ld: undefined reference to `foo'
            if (it == global_symbols.end()) {
                // si no es un simbolo global que hace referencia a codigo
                // de la VM, entonces puede ser un simbolo global a codigo
                // externo:
                it = import_lookup.find(rel.symbol);
                if (it == import_lookup.end()) {
                    add_errorf(
                        report, LinkerError::Type::RelocationError,
                        ("Relocacion: simbolo no resuelto: " + rel.symbol)
                            .c_str());
                    continue;
                }
                // es codigo importado, se debe procceder de otra manera.
                import_code = true;
            }

            if (import_code == false) {
                // Obtiene la direccion final del simbolo
                // Esta direccion ya fue calculada previamente por el linker al:
                //     concatenar modulos
                //     aplicar alineaciones
                //     asignar direcciones virtuales
                //     resolver secciones
                uint64_t target_addr = it->second;

                if (rel.offset + sizeof(uint64_t) > mod.bytecode.size()) {
                    add_errorf(
                        report, LinkerError::Type::RelocationError,
                        ("Relocacion fuera de rango en modulo " + mod.name)
                            .c_str());
                    continue;
                }
                uint64_t rel_address = 0;

                switch (rel.type) {
                // Escribe la direccion absoluta de 64 bits.
                // mov rax, [foo]   ->   se escribe la direccion absoluta de foo
                case Type::Absolute64: {
                    std::memcpy(&mod.bytecode[rel.offset], &target_addr,
                                sizeof(uint64_t));
                    // capturar la relocation en la tabla persistente
                    // para que el loader pueda re-aplicarla con un nuevo
                    // base address (rebase transparente sin flags).
                    entry_relocation_table e{};
                    e.bytecode_offset = module_base_offset + rel.offset;
                    e.target_value = target_addr;
                    e.type = static_cast<uint8_t>(RelocTypeVELB::ABSOLUTE64);
                    applied_relocations_.push_back(e);
                    break;
                }

                // Direccion absoluta truncada a 32 bits.  Usada por
                // cmpjmp/cmpjmpu/decjnz (encoding FIXED_8 con target
                // u32).  Si el target excede 2^32 lanza error claro.
                case Type::Absolute32: {
                    if (target_addr > 0xFFFFFFFFULL) {
                        add_errorf(
                            report, LinkerError::Type::RelocationError,
                            ("Reloc ABS32 fuera de rango (target VA > 4GB) "
                             "para simbolo " +
                             rel.symbol)
                                .c_str());
                        continue;
                    }
                    uint32_t addr32 = static_cast<uint32_t>(target_addr);
                    if (rel.offset + sizeof(uint32_t) > mod.bytecode.size()) {
                        add_errorf(
                            report, LinkerError::Type::RelocationError,
                            ("Reloc ABS32 fuera de rango en modulo " + mod.name)
                                .c_str());
                        continue;
                    }
                    std::memcpy(&mod.bytecode[rel.offset], &addr32,
                                sizeof(uint32_t));
                    // Capturar para la tabla persistente.  El loader
                    // usa el mismo mecanismo de rebase para ABS32:
                    // re-trunca al nuevo base address.
                    entry_relocation_table e{};
                    e.bytecode_offset = module_base_offset + rel.offset;
                    e.target_value = target_addr;
                    e.type = static_cast<uint8_t>(RelocTypeVELB::ABSOLUTE32);
                    applied_relocations_.push_back(e);
                    break;
                }

                // Esto es un PC-relative displacement, tipico de:
                // call foo; jmp bar
                // El +4 es porque la instruccion ya habra avanzado 4 bytes
                // cuando se evalua el PC. int32_t rel32 = target_addr -
                // (rel.offset + 4);
                case Type::Relative32: {
                    // offset relativo simplificado (suponemos PC en rel.offset
                    // + 4)
                    int32_t rel32 =
                        static_cast<int32_t>(target_addr - (rel.offset + 4));
                    rel_address = rel32;
                    if (rel.offset + sizeof(int32_t) > mod.bytecode.size()) {
                        add_errorf(
                            report, LinkerError::Type::RelocationError,
                            ("Reloc REL32 fuera de rango en modulo " + mod.name)
                                .c_str());
                        continue;
                    }
                    std::memcpy(&mod.bytecode[rel.offset], &rel32,
                                sizeof(int32_t));
                    break;
                }

                // Lo mismo que REL32, pero con 64 bits.
                case Type::Relative64: {
                    int64_t rel64 =
                        static_cast<int64_t>(target_addr - (rel.offset + 8));
                    rel_address = rel64;
                    std::memcpy(&mod.bytecode[rel.offset], &rel64,
                                sizeof(int64_t));
                    break;
                }
                default:
                    throw std::runtime_error(
                        "Linker::apply_relocations() Error: la relocalizacion "
                        "de tipo " +
                        std::to_string((int)rel.type) +
                        " definido por el simbolo " + rel.symbol +
                        " de la seccion " + rel.section + " con offset en " +
                        std::to_string(rel.offset) + " no existe.");
                }

                // anadir relocalizacion aplicada al reporte:
                RelocReportEntry entry;
                entry.module = mod.name;
                entry.symbol = rel.symbol;
                entry.offset = rel.offset;
                entry.type = rel.type;
                entry.value_written =
                    (rel.type == Type::Relative32)   ? (uint32_t)rel_address
                    : (rel.type == Type::Relative64) ? (uint64_t)rel_address
                                                     : target_addr;

                report.relocations_log.push_back(entry);
            }
            // si es una relocalizacion a un simbolo nativo:
            else {
                // indice de la funcion nativa buscada.
                uint64_t index_import_table = 0;
                switch (rel.type) {
                case Type::Native_Method: // usado unicamente por CALLN
                case Type::Absolute64: {
                    // usado por el resto de instrucciones cuando se usa
                    // notacion @Method

                    // obtenemos el index en la tabla de importacion del metodo
                    // dado.
                    auto entry_index = import_lookup.find(rel.symbol);
                    if (entry_index == import_lookup.end()) {
                        // error: simbolo no encontrado
                        throw std::runtime_error(
                            "Simbolo " + rel.symbol +
                            " no encontrado en la tabla de importacion.");
                    }

                    // indice del simbolo en la tabla de importacion.
                    index_import_table = entry_index->second;

                    // para Native_Method y Absolute64
                    // size_relocation_emmit(rel.type) siempre sera 8

                    // parcheamos el offset con el valor que queremos
                    std::memcpy(&mod.bytecode[rel.offset], &index_import_table,
                                size_relocation_emmit(rel.type));

                    break;
                }
                default:
                    throw std::runtime_error(
                        "Linker::apply_relocations() Error: la relocalizacion "
                        "de tipo " +
                        std::to_string((int)rel.type) +
                        " no existe, definido por el simbolo " + rel.symbol +
                        " de la seccion '" + rel.section + "' con offset en " +
                        std::to_string(rel.offset) + ".");
                }

                // creamos una entrada en la tabla de importacion
                entry_import_table entry_import;
                entry_import.offset_bytecode = rel.offset;
                entry_import.offset_signature_string =
                    index_import_table; // aun no se usa

                /**
                 * En esta fase aun la tabla de cadenas no fue construida, ya
                 * que se genera en la fase de construccion del hader. Debemos
                 * almacenar el index del metodo en la tabla import_lookup para
                 * luego poder parchearlo con los offsets reales mas
                 * posteriormente.
                 */
                entry_import.offset_function_string = index_import_table;
                entry_import.offset_module_string = index_import_table;

                table_import_method.push_back(entry_import);

                // anadir relocalizacion aplicada al reporte:
                RelocReportEntry entry;
                entry.module = mod.name;
                entry.symbol = rel.symbol;
                entry.offset = rel.offset;
                entry.type = rel.type;
                entry.value_written = index_import_table;

                report.relocations_log.push_back(entry);
            }

            report.relocations_applied++;
        }
        // avanzar el offset acumulado al final del bytecode de este
        // modulo, para que las relocations del proximo modulo se registren
        // con offsets correctos relativos al final_bytecode.
        module_base_offset += mod.bytecode.size();
    }
}

void Linker::optimize_modules() {
    if (!options.optimize_bytecode) return;

    for (auto &mod : modules) {
        // TODO: implementar optimizaciones reales de bytecode. Usaria Optimizer
        // Por ahora, no hacemos nada, solo contamos el modulo.
        // Ejemplo: eliminar NOPs, fusionar instrucciones triviales, etc.

        report.optimizations_applied++;
    }
}

void Linker::merge_address_spaces() {
    // Aqui deberia usar Context para fusionar los espacios de direcciones
    // de todos los modulos. Por ahora, lo simplificamos:
    //
    // - asumimos un unico espacio de direcciones
    // - las secciones se concatenan linealmente

    // TODO: usar Context para algo real.
}

void Linker::merge_sections() {
    final_bytecode.clear();
    final_sections.clear();

    // Concatenar bytecode de todos los modulos
    for (auto &mod : modules) {
        final_bytecode.insert(final_bytecode.end(), mod.bytecode.begin(),
                              mod.bytecode.end());
    }

    // Construir final_sections a partir de los Context de cada modulo
    for (auto &mod : modules) {
        // para cada espacio de direcciones del modulo
        for (const auto &[spaceName, space] : mod.ctx.space_address) {
            // cada cada seccion dentro del espacio de direcciones del modulo
            for (const auto &[sectionName, section] : space.table_section) {
                section_info_linker sec{};
                sec.memory.address = section.memory;
                // aqui se esta almacenando la direccion virtual de inicio y
                // final
                // sec.memory.address.address_final = section.size_real; //
                // debemos cambiar la direccion final para usar
                // la direccion real dentro del archivo, y no usar la direccion
                // final virtual. la seccion puede ocupar 49 bytes realmente en
                // el archivo, pero al cargarse demandar 1kB de memoria.
                sec.name = section.name;
                // tal vez deba calcular el offset al nombre de la seccion aqui
                // tambien?

                final_sections.push_back(sec);
            }
        }
    }
}

void Linker::build_header() {
    // std::memset(&final_header, 0, sizeof(final_header));
    // no poner a 0, por que la funcion add_assembly_unit que agrega una unidad
    // de ensamblado, configura el campo start_pc segun el contexto que haya
    // procesado en el ensamblado, al llamarse la funcion add_assembly_unit
    // antes que build_header, si realizamos el memset el campo quedaria a 0 de
    // nuevo eliminando configuraciones anteriores de funciones previas.

    final_header.magic.firma = MAGIC_NUMBER_VELB;
    final_header.format_v = VERSION_VELB; // 0x2 (añade tabla de relocations)

    final_header.max_v = 0; // 0.0.0 => compatible con futuras
    final_header.min_v = 0; // 0.0.0 => retrocompatible

    final_header.checksum = simple_checksum(final_bytecode);

    final_header.flags = 0;

    /* La fecha NO sale del reloj.  Sellar la hora de compilacion hacia que dos
     * compilaciones del mismo fuente dieran ficheros distintos -- en ocho bytes
     * de cabecera y en nada mas --, y eso rompe dos cosas: el build deja de ser
     * reproducible, y cualquiera que compare dos `.velb` por su huella para
     * saber si algo cambio esta comparando relojes.  Costo caro: se dio por
     * cierto durante mucho tiempo que el compilador era no-determinista, y el
     * unico byte que se movia era este.
     *
     * Con `SOURCE_DATE_EPOCH` -- el mando estandar de los builds reproducibles,
     * que pone quien empaqueta -- se sella lo que diga; sin el, cero.  El campo
     * se queda en la cabecera: el formato no cambia y volver a poner una fecha
     * es una linea. */
    final_header.timestamp =
        static_cast<uint64_t>(util::flag_int(util::FlagId::SourceDateEpoch, 0));
    final_header.arch = 1; // debo definir las arch posibles

    final_header.count = static_cast<section_count>(final_sections.size());

    // cantidad de espacios de direcciones
    final_header.n_spaces = spaces_address.size();

    // Extraer espacios a un vector temporal
    std::vector<std::pair<std::string, Space>> ordered_spaces;
    ordered_spaces.reserve(spaces_address.size());

    for (auto &kv : spaces_address) {
        ordered_spaces.push_back(kv);
    }

    // Ordenar por address_init
    std::sort(
        ordered_spaces.begin(), ordered_spaces.end(), [](auto &a, auto &b) {
            return a.second.range.address_init < b.second.range.address_init;
        });

    // Copiar al header en orden de direcciones
    final_header.address_spaces =
        new table_spaces_address[final_header.n_spaces];

    // La tabla de secciones ira justo despues del header, es necesario
    // haber asignado primero final_header.n_spaces, o esta funcion fallara,
    // ya que para calcular el offset de la tabla, es necesario conocercuantas
    // entradas de espacio de direcciones hay
    final_header.table_offset = compute_sections_base_offset();

    // donde esta la seccion de strings
    final_header.offset_section_strings = final_header.table_offset;

    build_section_strings(final_header.table_offset);

    // los strings va antes que la tabla de secciones
    final_header.table_offset +=
        spaces_address["MetaSpace"].table_section["strings"].size_real;

    // calcular el offset relativo de cada espacio de direcciones en el archivo.
    // requiere que las secciones esten ordenadas por direcciones de inicio
    uint64_t current_offset = 0;
    for (auto space : ordered_spaces) {
        spaces_address[space.first].file_offset = current_offset;

        uint64_t space_size = compute_space_size(space.second);
        current_offset += space_size;
    }

    for (int i = 0; i < final_header.n_spaces; ++i) {
        table_spaces_address *const space = &final_header.address_spaces[i];

        // al macenar las direcciones
        space->address = ordered_spaces[i].second.range;

        // guardar el offset al bytecode de cada espacio de direcciones
        // calculado previamente.
        space->offset_bytecode =
            spaces_address[ordered_spaces[i].first].file_offset;

        // por ahora los offset a los nombres de la seccion de strings no se
        // calculara aqui.
        space->offset_section_strings =
            string_offsets[ordered_spaces[i].second.name_section];
    }

    // anadir a cada seccion el offset al nombre de su stirng
    for (auto &final_section : final_sections) {
        final_section.memory.offset_string = string_offsets[final_section.name];
    }

    /**
     * La tabla de secciones contiene entradas de (8 * 3) bytes, donde los
     * primeros 8 bytes son para la direccion virtual de la seccion, los 8
     * posteriores para la direccion virtual final y los ultimos 8 bytes para el
     * offset a la tabla de strings.
     */
    // La tabla de SECCIONES tiene una entrada por SECCION, no por espacio de
    // direcciones.  Multiplicar por n_spaces acertaba solo mientras hubiera
    // tantos espacios como secciones (el caso historico: 1 espacio real +
    // MetaSpace, y 2 secciones: `code` + la auxiliar `strings`).  En cuanto
    // aparece una tercera seccion el bytecode se situa 24 bytes antes de donde
    // esta -> todo lo de detras (imports, @ir, simbolos) queda corrido y el
    // loader acaba leyendo el magic del propio fichero como nombre de libreria.
    // El loader ya usaba el conteo correcto (`exe.sections.size()`), asi que
    // ambos solo coincidian por accidente.
    uint64_t init_bytecode = final_header.table_offset +
                             sizeof(section_range_memory) * final_header.count;
    // inicio del bytecode, es el offset dentro del archivo final donde se
    // encuentra todo el bytecode.

    // offset de inicio de la tabla de importacion
    uint64_t init_table_import = init_bytecode + final_bytecode.size();
    final_header.offset_import_table =
        init_table_import; // offset a la tabla de importacion.
    final_header.size_import_table =
        table_import_method
            .size(); // cantidad de entradas de la tabla de importacion
    for (auto &entry : table_import_method) {
        // buscamos el nombre de la libreria del metodo nativo a traves del
        // indice temporal que esta almacenado en entry.offset_module_string,
        // debemos usar los strings obtenidos para guardar los datos correctos
        // de la tabla de importacion
        std::string name_lib = import_table[entry.offset_module_string].library;
        std::string name_method =
            import_table[entry.offset_module_string].function;

        // parchemos los offset a la tabla strings con los valores reales,
        // eliminando los valores temporales que tenian:
        entry.offset_function_string =
            string_offsets[name_method]; // offset al nombre del metodo.
        entry.offset_module_string =
            string_offsets[name_lib]; // offset al nombre de la lib
    }
}

void Linker::build_section_strings(uint64_t offset_init) {
    string_pool.clear();
    string_offsets.clear();
    string_blob.clear();

    // Recoger strings de espacios de direcciones
    for (const auto &[name, space] : spaces_address) {
        string_pool.push_back(name);
    }

    // Recoger strings de secciones
    for (const auto &[spaceName, space] : spaces_address) {
        for (const auto &[secName, sec] : space.table_section) {
            string_pool.push_back(secName);
        }
    }

    // Recoger strings de labels SOLO si no estamos en modo strip.
    // Los nombres de label no los referencia ningun campo del .velb
    // post-resolucion (el loader no los lee), asi que omitirlos
    // reduce el ejecutable ~9% en programas grandes.  El .velb-map
    // sigue mostrandolos porque usa la tabla interna del linker, no
    // el string_blob.
    if (!options.strip_labels) {
        for (const auto &[spaceName, space] : spaces_address) {
            for (const auto &[secName, sec] : space.table_section) {
                for (const auto &[labName, lab] : sec.table_label) {
                    string_pool.push_back(labName);
                }
            }
        }
    }

    // Recoger strings de imports (librerias y funciones)
    for (const auto &imp : import_table) {
        string_pool.push_back(imp.library);
        string_pool.push_back(imp.function);
    }

    // Eliminar duplicados
    std::sort(string_pool.begin(), string_pool.end());
    string_pool.erase(std::unique(string_pool.begin(), string_pool.end()),
                      string_pool.end());

    // Construir blob y mapa de offsets
    uint64_t offset = offset_init; // depende del offset de inicio, todo_ se
                                   // calcula en base a este

    for (const auto &s : string_pool) {
        string_offsets[s] = offset;

        // copiar caracteres
        for (char c : s)
            string_blob.push_back(static_cast<uint8_t>(c));

        // terminador nulo
        string_blob.push_back(0);

        offset += s.size() + 1;
    }

    // Crear seccion especial "strings"
    // sec.bytecode = string_blob;
    Section *sec = &spaces_address["MetaSpace"].table_section["strings"];
    // Insertar en el espacio "meta"
    sec->size_align_section = 1;
    sec->size_real = align_up(string_blob.size(), 16);
}

uint64_t Linker::compute_sections_base_offset() const {
    // el espacio real de todo_ el header es la cantidad de espacios de
    // direcciones po el tamano de una entrada de rango de memoria (16 bytes
    // para inicio y fin)
    const uint64_t size_table_space_address =
        (final_header.n_spaces * sizeof(table_spaces_address));

    // se resta el tamano del puntero de table_spaces_address, ya que en el
    // archivo, la tabla va espacio de direcciones va direcamente incrustado, en
    // lugar de ser un puntero.
    const uint32_t relative_size_header =
        sizeof(HeaderVELB) - sizeof(table_spaces_address *);

    const uint64_t size_table_sections =
        final_sections.size() * sizeof(section_range_memory);

    // el hader siempre esta alineado a 16 bytes
    return align_up((relative_size_header +
                     size_table_space_address) /*+ size_table_sections*/,
                    16);
}

void Linker::compute_symbol_file_offsets() {
    // @c SymbolInfo::file_offset es el offset del simbolo dentro de
    // @c final_bytecode (asi lo consume write_map_file para volcar sus bytes).
    //
    // La imagen es plana: dentro de un espacio de direcciones, la distancia de
    // una direccion virtual a la base del espacio es su offset en el flujo de
    // bytecode.  Es el mismo invariante que aplica el loader al derivar el
    // offset de fichero de cada seccion
    // (file_offset = space->file_offset + (address_init -
    // space->range.address_init)).
    for (auto &[name, info] : symbol_info) {
        auto it_space = spaces_address.find(info.space);
        if (it_space == spaces_address.end()) continue;

        const uint64_t space_base = it_space->second.range.address_init;
        if (info.absolute < space_base) continue; // fuera del espacio

        info.file_offset =
            it_space->second.file_offset + (info.absolute - space_base);
    }
}

/**
 * Obtener el string de un offset en especifico
 * @param offset offset del string a buscar
 * @return string si existe en ese offset
 */
std::string Linker::get_string_from_offset(uint64_t offset) const {
    if (offset >= string_blob.size()) return "<invalid-offset>";

    const char *start = reinterpret_cast<const char *>(&string_blob[offset]);

    // Buscar el terminador nulo sin salirnos del buffer
    size_t max_len = string_blob.size() - offset;
    size_t len = strnlen(start, max_len);

    return std::string(start, len);
}

void Linker::build_section_table() {
    // Validar que hay secciones
    if (final_sections.empty()) {
        throw std::runtime_error("No hay secciones para construir la tabla.");
    }

    // Ordenar por direccion virtual
    std::sort(final_sections.begin(), final_sections.end(),
              [](const section_info_linker &a, const section_info_linker &b) {
                  return a.memory.address.address_init <
                         b.memory.address.address_init;
              });

    // debemos restar el tamano de la seccion de cadenas.
    compute_symbol_file_offsets();

    // Validar que no se solapan, primero debemos a ver calculado los offset de
    // cada string anteriormente
    for (size_t i = 1; i < final_sections.size(); ++i) {
        std::string n1 = final_sections[i - 1].name;
        std::string n2 = final_sections[i].name;
        if (final_sections[i].memory.address.address_init <
            final_sections[i - 1].memory.address.address_final) {
            // si es el espacio de direcciones especiales, entonces, lo
            // ignoramos aunque se solape siempre y cuando sus direcciones
            // tengas tamano 0 (no se usa dentro de la VM) por el codigo
            if (((n2 == "strings") &&
                 (final_sections[i].memory.address.address_final -
                  final_sections[i].memory.address.address_init) == 0) ||
                (n1 == "strings")
                // si lo agrego el ensamblador, entonces el espacio deberia ser
                // 0, si lo anadio el usuario, y no asigno estos espacios, se
                // debera analizar
            )
                continue;

            throw std::runtime_error(
                "Secciones solapadas en memoria virtual. seccion: " + n1 +
                " y seccion: " + n2);
        }
    }

    //    NO asignamos offsets aqui (eso lo hace build_executable)
    //    porque depende del tamano del header y de la tabla misma.
}

std::vector<uint8_t> Linker::build_executable() {
    LinkerPhaseTimer __t_total("TOTAL build_executable");
    if (linker_profile_enabled()) {
        std::fprintf(stderr,
                     "[linker-prof] === inicio build_executable: modulos=%zu, "
                     "libs=%zu, ir_bytes=%zu ===\n",
                     modules.size(), libraries.size(), ir_section_bytes.size());
        std::fflush(stderr);
    }
    result->output.reserve(4096); // evita realocaciones
    {
        LinkerPhaseTimer __t("resolve_symbols");
        resolve_symbols();
    }
    {
        LinkerPhaseTimer __t("apply_relocations");
        apply_relocations();
    }
    {
        LinkerPhaseTimer __t("optimize_modules");
        optimize_modules();
    }
    {
        LinkerPhaseTimer __t("merge_address_spaces");
        merge_address_spaces();
    }
    {
        LinkerPhaseTimer __t("merge_sections");
        merge_sections();
    }

    {
        LinkerPhaseTimer __t("build_header");
        build_header();
    }
    {
        LinkerPhaseTimer __t("build_section_table");
        build_section_table();
    }

    // escribir tabla de espacio de direcciones
    auto write_space_address = [&](HeaderVELB &v) {
        for (int i = 0; i < final_header.n_spaces; ++i) {
            result->emit64(final_header.address_spaces[i].address.address_init);
            result->emit64(
                final_header.address_spaces[i].address.address_final);

            // offset a la tabla de strings
            result->emit64(
                final_header.address_spaces[i].offset_section_strings);

            // offset al bytecode para el espacio de direcciones,
            // con este se calcula el inicio de cada la seccion en el bytecode
            result->emit64(final_header.address_spaces[i].offset_bytecode);
        }
    };

    LinkerPhaseTimer __t_emit_header("emit_header_fields");
    LinkerPhaseSize __s_emit_header("emit_header_fields", result->output);
    result->emit32(final_header.magic.firma);
    result->emit32(final_header.format_v);

    result->emit32(final_header.max_v);
    result->emit32(final_header.min_v);

    result->emit64(final_header.checksum);

    result->emit64(final_header.flags);
    result->emit64(final_header.timestamp);
    result->emit32(final_header.arch);

    result->emit32(final_header.count);

    result->emit64(final_header.table_offset);

    result->emit64(final_header.n_spaces);

    // indicar offset la seccion de cadenas espaciales.
    result->emit64(final_header.offset_section_strings);

    // Indicar el valor de PC al cargar el programa
    result->emit64(final_header.start_pc);

    // Indicar el offset a la tabla de importacion
    result->emit64(final_header.offset_import_table);

    // Indicar el offset a la tabla de labels
    result->emit64(final_header.offset_label_table);

    // Indicar el tamano de la tabla de importacion
    result->emit32(final_header.size_import_table);

    // indicar el tamano de la tabla de etiquetas.
    result->emit32(final_header.size_label_table);

    // campos de depuracion (añadidos al struct pero antes no se emitian, lo que
    // desplazaba compute_sections_base_offset() 16 bytes respecto a la posicion
    // real del blob de strings)
    const size_t header_pos_offset_debug = result->offset;
    result->emit64(
        final_header.offset_debug_section); // 0 por ahora; patcheado al final
    const size_t header_pos_size_debug = result->offset;
    result->emit32(
        final_header.size_debug_section); // 0 por ahora; patcheado al final
    const size_t header_pos_debug_level = result->offset;
    result->emit8(final_header.debug_level); // 0 por ahora; patcheado al final
    result->emit8(final_header._debug_pad[0]);
    result->emit8(final_header._debug_pad[1]);
    result->emit8(final_header._debug_pad[2]);

    // tabla de relocations.  Los valores reales se patchean DESPUES
    // de escribir el bytecode (para conocer la posicion exacta).  Aqui
    // emitimos placeholders 0; los reescribiremos via write64_at /
    // write32_at una vez sepamos donde queda la tabla en el archivo.
    const size_t header_pos_offset_reloc = result->offset; // recordar pos
    result->emit64(final_header.offset_reloc_table);       // 0 por ahora
    const size_t header_pos_size_reloc = result->offset;
    result->emit32(final_header.size_reloc_table); // 0 por ahora
    /* placeholder para offset_ir_section + size_ir_section.
     * Los actualizamos al final via write64_at/write32_at una vez
     * conocemos la posicion exacta en el output buffer. */
    const size_t header_pos_offset_ir = result->offset;
    result->emit64(final_header.offset_ir_section); // 0 por ahora
    const size_t header_pos_size_ir = result->offset;
    result->emit32(final_header.size_ir_section); // 0 por ahora

    /*  E.1: placeholder para offset_stackmap_section +
     * size_stackmap_section.  Los patcheamos al final via
     * write64_at/write32_at tras conocer la posicion de la seccion VSMP. */
    const size_t header_pos_offset_stackmap = result->offset;
    result->emit64(final_header.offset_stackmap_section); // 0 por ahora
    const size_t header_pos_size_stackmap = result->offset;
    result->emit32(final_header.size_stackmap_section); // 0 por ahora
    /* Relleno para mantener el header serializado en 160 bytes (multiplo de
     * 16), consistente con sizeof(HeaderVELB)-sizeof(ptr). */
    result->emit32(final_header._stackmap_pad); // 0

    // el header siempre debe estar alineado a 16 bytes
    while (result->offset % 16 != 0) {
        result->emit8(0x00);
    }

    // escribir tabla de espacios
    write_space_address(final_header);

    for (uint64_t i = 0; i < string_blob.size(); ++i) {
        result->emit8(string_blob[i]);
    }

    // la tabla de strings alineado a 16 bytes
    while (result->offset % 16 != 0) {
        result->emit8(0x00);
    }

    // escribir tabla se secciones, supondre que el offset de la tabla este
    // bien calculada y se este apuntando a este sitio.
    for (auto &sec : final_sections) {
        result->emit64(sec.memory.address.address_init);
        result->emit64(sec.memory.address.address_final);
        result->emit64(sec.memory.offset_string);
    }

    // este es el offset base al bytecode, necesitamos conocerlo para hacer el
    // parcheo en la tabla de espacio de direcciones, ya que ahora tiene un
    // offset relativo en el que se tomo como base offset el valor 0.
    uint64_t base_bytecode_offset = result->offset;

    uint64_t entry_size = 4 * sizeof(uint64_t); // 32
    uint64_t table_pos = sizeof(HeaderVELB) - sizeof(table_spaces_address *);

    for (int i = 0; i < final_header.n_spaces; ++i) {
        auto &space = final_header.address_spaces[i];

        uint64_t patched = space.offset_bytecode + base_bytecode_offset;

        uint64_t field_pos = table_pos + i * entry_size + 3 * sizeof(uint64_t);
        // parchemos el offset relativo de la tabla de espacios.
        result->write64_at(patched, field_pos);
    }

    // anadir el bytecode al final
    {
        LinkerPhaseTimer __t("emit_bytecode_insert");
        LinkerPhaseSize __s("emit_bytecode_insert", result->output);
        result->output.insert(result->output.end(), final_bytecode.begin(),
                              final_bytecode.end());
    }

    {
        LinkerPhaseTimer __t_imp("emit_import_table");
        LinkerPhaseSize __s_imp("emit_import_table", result->output);
        for (auto &entry : table_import_method) {
            result->emit32(entry.offset_module_string);
            result->emit32(entry.offset_function_string);
            result->emit32(entry.offset_signature_string);
            result->emit32(entry.offset_bytecode);
        }
    } // fin emit_import_table

    // emitir la tabla de relocations al final del archivo.
    // Cada entry son 24 bytes packed: bytecode_offset (u64) + target_value
    // (u64) + type (u8) + pad (u8x7).  El header se patchea con el
    // offset y size al concluir la emision.
    //
    // CRITICO: `result->offset` NO se actualiza al hacer
    // `output.insert(...)` directamente con final_bytecode (vease arriba),
    // asi que NO refleja la posicion real del cursor en el archivo.
    // Usar `output.size()` que SI es la posicion real al final del buffer.
    if (!applied_relocations_.empty()) {
        LinkerPhaseTimer __t_rel("emit_reloc_table");
        LinkerPhaseSize __s_rel("emit_reloc_table", result->output);
        if (linker_profile_enabled()) {
            std::fprintf(stderr, "[linker-prof]   reloc_entries=%zu\n",
                         applied_relocations_.size());
            std::fflush(stderr);
        }
        // Alineacion 8 bytes para acceso eficiente.
        while (result->output.size() % 8 != 0) {
            result->output.push_back(0x00);
        }
        const uint64_t reloc_table_file_offset = result->output.size();
        // Reservar espacio y escribir cada entry directamente al buffer
        // (sin pasar por emit*, que actualizan offset, mantenido como
        // contador relativo al header, no a la posicion final del file).
        const size_t entry_bytes = 24;
        const size_t total = entry_bytes * applied_relocations_.size();
        result->output.reserve(result->output.size() + total);
        for (const auto &e : applied_relocations_) {
            const size_t base = result->output.size();
            result->output.resize(base + entry_bytes, 0x00);
            std::memcpy(&result->output[base + 0], &e.bytecode_offset, 8);
            std::memcpy(&result->output[base + 8], &e.target_value, 8);
            result->output[base + 16] = e.type;
            // bytes 17..23 quedan a 0 (padding) por el resize.
        }
        // Patchear los campos del header con el offset y size correctos.
        result->write64_at(reloc_table_file_offset, header_pos_offset_reloc);
        result->write32_at(static_cast<uint32_t>(applied_relocations_.size()),
                           header_pos_size_reloc);
        // Tambien actualizar el final_header en memoria por consistencia
        // (e.g. para write_map_file / dumps).
        final_header.offset_reloc_table = reloc_table_file_offset;
        final_header.size_reloc_table =
            static_cast<uint32_t>(applied_relocations_.size());
    }

    // === SECCION DEBUG ===
    // Acumulamos todas las DebugLineRec de todos los modulos con sus
    // offsets ABSOLUTOS dentro del .velb (sumando module_base_offset
    // que se acumulo durante apply_relocations + offset_real_bytecode
    // que es la posicion del code section dentro del file).
    //
    // Layout binario emitido (matchea include/debug/debug_info.h):
    //   [DebugSectionHeader (24 B)]
    //   [DebugLineEntry[]   (line_count * 12 B)]
    //   [strings blob       (paths de archivos fuente, 0-terminados)]
    //
    // Patchea offset_debug_section + size_debug_section + debug_level
    // en el header del .velb.  Si no hay info de debug recolectada
    // (compilacion sin --vx-debug), no escribimos nada y los campos
    // quedan a 0 (loader detecta size==0 y omite la carga).
    {
        LinkerPhaseTimer __t_dbg("emit_debug_section");
        LinkerPhaseSize __s_dbg("emit_debug_section", result->output);
        // Recolectar todas las entradas de todos los modulos.
        // Mismo loop que apply_relocations: module_base_offset se
        // incrementa por mod.bytecode.size() en orden.
        uint64_t bc_base = 0;
        /* Entradas de nivel 3: llevan la COLUMNA ademas de la linea.  Cuestan
         * cuatro bytes mas por instruccion y son lo que permite senalar cual de
         * las cosas que caben en una linea fallo, en vez de solo en cual. */
        std::vector<debug::DebugLineEntry3> all_entries;
        // Strings blob + interning de paths.  Cada path unico aparece
        // 1 sola vez; los DebugLineEntry referencian su offset.
        std::vector<uint8_t> strings_blob;
        std::unordered_map<std::string, uint32_t> string_pool;
        auto intern_string = [&](const std::string &s) -> uint32_t {
            auto it = string_pool.find(s);
            if (it != string_pool.end()) return it->second;
            uint32_t off = static_cast<uint32_t>(strings_blob.size());
            strings_blob.insert(strings_blob.end(), s.begin(), s.end());
            strings_blob.push_back(0); // null terminator
            string_pool[s] = off;
            return off;
        };

        for (const auto &mod : modules) {
            if (!mod.ctx.debug_lines.empty()) {
                const std::string fname = mod.ctx.debug_source_file.empty()
                                              ? mod.name
                                              : mod.ctx.debug_source_file;
                const uint32_t file_off = intern_string(fname);
                for (const auto &rec : mod.ctx.debug_lines) {
                    debug::DebugLineEntry3 e{};
                    // offset ABSOLUTO dentro del .velb: hay que
                    // sumar el offset del code section dentro del
                    // file (offset_real_bytecode), no solo el
                    // module_base_offset.  El runtime resuelve PCs
                    // contra el inicio del code section, no contra
                    // el inicio del file -- por eso usamos solo el
                    // offset interno al code (bc_base + rec.offset).
                    e.bytecode_offset =
                        static_cast<uint32_t>(bc_base + rec.byte_offset);
                    e.line_number = rec.source_line;
                    e.file_offset = file_off;
                    // La COLUMNA, que es lo que distingue cual de las cosas de
                    // la linea fallo.  Viajaba desde el compilador hasta aqui y
                    // se perdia en el ultimo paso: la entrada se escribia con
                    // sitio para ella y en blanco.
                    e.column = static_cast<uint16_t>(rec.source_column);
                    e._pad = 0;
                    all_entries.push_back(e);
                }
            }
            bc_base += mod.bytecode.size();
        }

        if (!all_entries.empty()) {
            // Ordenar por bytecode_offset para que lookup_line use
            // busqueda binaria correctamente.
            std::sort(all_entries.begin(), all_entries.end(),
                      [](const debug::DebugLineEntry3 &a,
                         const debug::DebugLineEntry3 &b) {
                          return a.bytecode_offset < b.bytecode_offset;
                      });

            // Alineacion 8 bytes para el header.
            while (result->output.size() % 8 != 0) {
                result->output.push_back(0x00);
            }
            const uint64_t debug_section_offset = result->output.size();

            // Emitir DebugSectionHeader (24 B).
            debug::DebugSectionHeader hdr{};
            hdr.magic = debug::DEBUG_SECTION_MAGIC;
            hdr.version = debug::DEBUG_FORMAT_VERSION;
            hdr.level = debug::DEBUG_LEVEL_FULL;
            hdr._pad = 0;
            hdr.line_count = static_cast<uint32_t>(all_entries.size());
            hdr.var_count = 0;
            hdr.scope_count = 0;
            hdr.strings_size = static_cast<uint32_t>(strings_blob.size());
            const size_t hdr_off = result->output.size();
            result->output.resize(hdr_off + sizeof(hdr), 0x00);
            std::memcpy(&result->output[hdr_off], &hdr, sizeof(hdr));

            // Emitir DebugLineEntry[].
            for (const auto &e : all_entries) {
                const size_t base = result->output.size();
                result->output.resize(base + sizeof(e), 0x00);
                std::memcpy(&result->output[base], &e, sizeof(e));
            }

            // Emitir strings blob.
            if (!strings_blob.empty()) {
                result->output.insert(result->output.end(),
                                      strings_blob.begin(), strings_blob.end());
            }

            const uint64_t debug_section_total =
                result->output.size() - debug_section_offset;

            // Patchear el header.
            result->write64_at(debug_section_offset, header_pos_offset_debug);
            result->write32_at(static_cast<uint32_t>(debug_section_total),
                               header_pos_size_debug);
            // Escribir debug_level (1 byte) directamente en el buffer.
            if (header_pos_debug_level < result->output.size()) {
                result->output[header_pos_debug_level] =
                    static_cast<uint8_t>(debug::DEBUG_LEVEL_FULL);
            }

            final_header.offset_debug_section = debug_section_offset;
            final_header.size_debug_section =
                static_cast<uint32_t>(debug_section_total);
            final_header.debug_level = debug::DEBUG_LEVEL_FULL;
        }
    }

    /* emitir seccion @c @ir si el caller la proporciono.
     * Los bytes vienen pre-serializados (magic + header + funciones)
     * via @c ir::emit_ir_section.  El linker simplemente los
     * appendea al final y patchea offset/size en el header. */
    if (!ir_section_bytes.empty()) {
        LinkerPhaseTimer __t_ir("emit_ir_and_sym");
        LinkerPhaseSize __s_ir("emit_ir_and_sym", result->output);
        if (linker_profile_enabled()) {
            std::fprintf(stderr, "[linker-prof]   ir_bytes=%zu\n",
                         ir_section_bytes.size());
            std::fflush(stderr);
        }
        const uint64_t ir_offset = result->output.size();
        result->output.insert(result->output.end(), ir_section_bytes.begin(),
                              ir_section_bytes.end());

        /* appendear @sym section justo despues del @ir.
         * Layout:
         *   +0 [4]  magic "VSYM"
         *   +4 [2]  version = 1
         *   +6 [2]  reserved = 0
         *   +8 [4]  entry_count
         *   +12 [..] entries: name_len u16 + name bytes + addr u64
         *
         * Backward compat: el loader parsea @ir; si quedan bytes
         * tras @ir + size_ir_section, intenta leer "VSYM".  Si no
         * matcha, simplemente ignora.  No requiere nuevos campos
         * en el header. */
        std::vector<uint8_t> sym_bytes;
        sym_bytes.reserve(4 + 2 + 2 + 4 + 256);
        auto put32 = [&sym_bytes](uint32_t v) {
            for (int i = 0; i < 4; ++i)
                sym_bytes.push_back(static_cast<uint8_t>(v >> (i * 8)));
        };
        auto put16 = [&sym_bytes](uint16_t v) {
            sym_bytes.push_back(static_cast<uint8_t>(v & 0xFF));
            sym_bytes.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        };
        auto put64 = [&sym_bytes](uint64_t v) {
            for (int i = 0; i < 8; ++i)
                sym_bytes.push_back(static_cast<uint8_t>(v >> (i * 8)));
        };
        /* Magic "VSYM". */
        sym_bytes.push_back('V');
        sym_bytes.push_back('S');
        sym_bytes.push_back('Y');
        sym_bytes.push_back('M');
        put16(1); /* version */
        put16(0); /* reserved */

        /* Recolectar TODOS los labels resueltos con su address final. */
        uint32_t count = 0;
        const size_t count_pos = sym_bytes.size();
        put32(0); /* placeholder, patcheamos al final */
        for (const auto &[spaceName, space] : spaces_address) {
            for (const auto &[secName, sec] : space.table_section) {
                for (const auto &[labName, lab] : sec.table_label) {
                    if (labName.empty()) continue;
                    /* emitimos el nombre QUALIFIED
                     * "section.label" porque eso es lo que las
                     * referencias `@Absolute("section.label")` usan
                     * para resolverse (ver emmit_decl.cpp:1423). */
                    std::string qname = secName + "." + labName;
                    if (qname.size() > 0xFFFF) continue;
                    put16(static_cast<uint16_t>(qname.size()));
                    for (char c : qname)
                        sym_bytes.push_back(static_cast<uint8_t>(c));
                    /* Address ABSOLUTO post-link: `lab.address` es relativo a
                     * su seccion, asi que hay que sumarle la base de esta.  Con
                     * una sola seccion (que empezaba en 0) ambos coincidian;
                     * con varias, un simbolo de la segunda seccion se emitia
                     * con su offset dentro de ella y el JIT no lo resolvia. */
                    put64(sec.memory.address_init + lab.address);
                    ++count;
                }
            }
        }
        /* Patchear count en su placeholder. */
        for (int i = 0; i < 4; ++i)
            sym_bytes[count_pos + i] = static_cast<uint8_t>(count >> (i * 8));

        /* Appendear los bytes del symbol section. */
        result->output.insert(result->output.end(), sym_bytes.begin(),
                              sym_bytes.end());

        /* size_ir_section incluye AHORA los bytes del @ir + @sym
         * para que el loader sepa donde termina la region "metadata". */
        const uint32_t total_size =
            static_cast<uint32_t>(ir_section_bytes.size() + sym_bytes.size());

        /* Patchear header in-place. */
        result->write64_at(ir_offset, header_pos_offset_ir);
        result->write32_at(total_size, header_pos_size_ir);

        final_header.offset_ir_section = ir_offset;
        final_header.size_ir_section = total_size;
    }

    /*  E.1: emitir seccion @c VSMP con los stackmaps precisos del
     * interprete.  Recolectamos los recs de cada modulo, sumando el offset
     * del code section (mismo esquema que la seccion debug DVBG) para
     * producir offsets absolutos, ordenamos por pc_offset y serializamos.
     *
     * Backward-compat: si ningun modulo tiene stackmaps, no se escribe la
     * seccion (offset/size quedan a 0 -> GC preciso no-op). */
    {
        // Recolectar todas las entradas con offset absoluto.
        struct FlatStackmap {
            uint32_t pc_offset;
            const Context::StackmapRec *rec;
        };
        std::vector<FlatStackmap> flat;
        uint64_t sm_bc_base = 0;
        for (const auto &mod : modules) {
            for (const auto &rec : mod.ctx.stackmap_recs) {
                flat.push_back(
                    {static_cast<uint32_t>(sm_bc_base + rec.byte_offset),
                     &rec});
            }
            sm_bc_base += mod.bytecode.size();
        }

        if (!flat.empty()) {
            // Ordenar por pc_offset para lookup por busqueda binaria.
            std::sort(flat.begin(), flat.end(),
                      [](const FlatStackmap &a, const FlatStackmap &b) {
                          return a.pc_offset < b.pc_offset;
                      });

            // Alineacion 8 bytes.
            while (result->output.size() % 8 != 0) {
                result->output.push_back(0x00);
            }
            const uint64_t vsmp_offset = result->output.size();

            // Serializar VSMP: magic + version + reserved + count + entries.
            std::vector<uint8_t> vsmp;
            auto vput16 = [&vsmp](uint16_t v) {
                vsmp.push_back(static_cast<uint8_t>(v & 0xFF));
                vsmp.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            };
            auto vput32 = [&vsmp](uint32_t v) {
                for (int i = 0; i < 4; ++i)
                    vsmp.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
            };
            vsmp.push_back('V');
            vsmp.push_back('S');
            vsmp.push_back('M');
            vsmp.push_back('P');
            vput16(1); /* version */
            vput16(0); /* reserved */
            vput32(static_cast<uint32_t>(flat.size()));
            for (const auto &fs : flat) {
                vput32(fs.pc_offset);
                vput16(static_cast<uint16_t>(fs.rec->slots.size()));
                for (const auto &s : fs.rec->slots) {
                    vsmp.push_back(s.location);
                    vsmp.push_back(s.gc_kind);
                }
            }

            result->output.insert(result->output.end(), vsmp.begin(),
                                  vsmp.end());
            const uint32_t vsmp_total = static_cast<uint32_t>(vsmp.size());

            result->write64_at(vsmp_offset, header_pos_offset_stackmap);
            result->write32_at(vsmp_total, header_pos_size_stackmap);
            final_header.offset_stackmap_section = vsmp_offset;
            final_header.size_stackmap_section = vsmp_total;
        }
    }

    return result->output;
}

void Linker::write_to_file(const std::string &path) {
    auto exe = build_executable();

    std::ofstream f(path, std::ios::binary);
    if (!f) {
        add_errorf(report, LinkerError::Type::IOError,
                   ("No se pudo abrir para escribir: " + path).c_str());
        return;
    }

    f.write(reinterpret_cast<const char *>(exe.data()),
            static_cast<std::streamsize>(exe.size()));
    if (!f) {
        add_errorf(report, LinkerError::Type::IOError,
                   ("Error escribiendo ejecutable: " + path).c_str());
    }

    if (options.generate_map_file && !options.map_file_path.empty()) {
        write_map_file(options.map_file_path);
    }
}

void Linker::write_map_file(const std::string &path) {
    std::ofstream f(path);
    if (!f) {
        add_errorf(report, LinkerError::Type::IOError,
                   ("No se pudo escribir map file: " + path).c_str());
        return;
    }

    f << "VELB MAP FILE\n";
    f << "Executable: " << options.output_path << "\n";

    std::time_t t = std::time(nullptr);
    f << "Generated: " << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S")
      << "\n";
    f << "Linker Version: 1.0\n";
    f << "PC address init: " << final_header.start_pc << "\n\n";

    report.print_report(f);

    if (result->output.size() >= sizeof(HeaderVELB)) {
        HeaderVELB hdr{};
        std::memcpy(&hdr, result->output.data(), sizeof(HeaderVELB));

        f << "=== VELB HEADER ===\n";
        f << "Magic: " << (char)hdr.magic.firma_byte[0]
          << (char)hdr.magic.firma_byte[1] << (char)hdr.magic.firma_byte[2]
          << (char)hdr.magic.firma_byte[3] << "\n";

        f << "Format version: " << hdr.format_v << "\n";
        f << "VM version: min=" << hdr.min_v << " max=" << hdr.max_v << "\n";
        f << "Checksum: 0x" << std::hex << hdr.checksum << std::dec << "\n";
        f << "Flags: 0x" << std::hex << hdr.flags << std::dec << "\n";
        f << "Timestamp: " << hdr.timestamp << "\n";
        f << "Target arch: " << hdr.arch << "\n";
        f << "Section count: " << hdr.count << "\n";
        f << "Section table offset: 0x" << std::hex << hdr.table_offset
          << std::dec << "\n";
        f << "Spaces count: " << hdr.n_spaces << "\n";
        f << "Strings table offset: 0x" << std::hex
          << hdr.offset_section_strings << std::dec << "\n";
        f << "Start PC: 0x" << std::hex << hdr.start_pc << std::dec << "\n\n";
    }

    f << "=== MODULES INCLUDED ===\n";
    for (size_t i = 0; i < modules.size(); ++i)
        f << "[" << i << "] " << modules[i].name << "\n";
    f << "\n";

    // Ordenar simbolos por VA
    std::vector<std::pair<std::string, SymbolInfo>> sorted;
    for (auto &p : symbol_info)
        sorted.push_back(p);

    std::sort(sorted.begin(), sorted.end(), [](auto &a, auto &b) {
        return a.second.absolute < b.second.absolute;
    });

    uint64_t offset_space_address =
        align_up(sizeof(HeaderVELB) - sizeof(table_spaces_address *), 16);

    if (final_bytecode.size() >=
        (offset_space_address +
         sizeof(table_spaces_address) * final_header.n_spaces)) {
        f << "=== ADDRESS SPACES ===\n";
        for (uint64_t i = 0; i < final_header.n_spaces; ++i) {
            auto sp = final_header.address_spaces[i];
            f << "[" << i << "]\n";
            f << "  VA Range: 0x" << std::hex << sp.address.address_init
              << " - 0x" << std::hex << sp.address.address_final << "\n";
            f << "  FILE: 0x" << std::hex << sp.offset_bytecode << "\n";
            f << "  String offset: 0x" << std::hex << sp.offset_section_strings
              << " (" << std::dec << sp.offset_section_strings << ")\n\n";
        }
    }

    f << "=== SYMBOLS BY SECTION ===\n";

    std::string current_section;

    for (auto &[name, info] : sorted) {
        // Cambio de seccion -> imprimir encabezado
        if (info.section != current_section) {
            current_section = info.section;
            f << "\n[SECTION " << current_section << "]\n";
        }

        f << "  " << name << "\n";
        f << "    VA:   0x" << std::hex << info.absolute << "\n";
        f << "    FILE: 0x" << info.file_offset << "\n";
        f << "    REL:  0x" << info.relative << "\n";
        f << "    SIZE: " << std::dec << info.size << " bytes\n";

        // Mostrar codigo hexadecimal
        f << "    HEX:  ";

        if (info.file_offset + info.size <= final_bytecode.size()) {
            for (uint64_t i = 0; i < info.size; ++i) {
                uint8_t b = final_bytecode[info.file_offset + i];
                f << std::hex << std::setw(2) << std::setfill('0') << (int)b
                  << " ";
            }
        } else {
            f << "(fuera de rango)";
        }

        f << "\n";
    }

    f << "\n=== SECTIONS ===\n";
    for (const auto &sec : final_sections) {
        const size_t size = compute_sections_base_offset();

        f << "[" << get_string_from_offset(sec.memory.offset_string - size)
          << "]\n";

        f << "  VA Range: 0x" << std::hex << sec.memory.address.address_init
          << " - 0x" << sec.memory.address.address_final << "\n";

        f << "  FILE Off String: 0x" << sec.memory.offset_string << "\n";

        f << "  Size: " << std::dec
          << (sec.memory.address.address_final -
              sec.memory.address.address_init)
          << " bytes\n";

        f << "  OffsetString table: " << std::hex << sec.memory.offset_string
          << " " << std::dec << sec.memory.offset_string << "\n\n";
    }

    f << "\n=== RELOCATIONS ===\n";
    for (const auto &r : report.relocations_log) {
        f << "[Reloc] module=" << r.module << " symbol=" << r.symbol
          << " type=" << reloc_type_to_string(r.type) << " offset=0x"
          << std::hex << r.offset << " value=0x" << std::hex << r.value_written
          << std::dec << "\n";
    }

    f << "\n=== IMPORTS ===\n";
    for (const auto &entry : import_table) {
        f << "[Import] library=" << entry.library
          << " function=" << entry.function << " index=" << entry.index
          << std::dec << "\n";
    }

    f << "\n=== FINAL SIZE ===\n";
    f << "Executable size: " << final_bytecode.size() << " bytes\n" << std::dec;
}
} // namespace Assembly::Bytecode::Linker
