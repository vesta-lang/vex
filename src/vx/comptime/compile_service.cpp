/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/comptime/compile_service.cpp
 * @brief Implementacion de "compila este IR y damelo listo".  Ver
 *        @c vx/comptime/compile_service.h.
 */

#include "vx/comptime/compile_service.h"

#include "ir/ir_emitter.h"
#include "ir/ssa_ir.h"
#include "util/assembler_multiprocess.h"
#include "util/file_read.h"
#include "vx/comptime/comptime_vm.h"

#include <filesystem>
#include <functional>
#include <system_error>

namespace vx {

namespace {

/// Donde van los intermedios de este servicio.  Junto al resto de lo generado,
/// no mezclado con el fuente.
constexpr const char *kIntermediateDir = ".cache/ctpe/tmp";

} // namespace

const char *compile_failure_code(CompileFailure f) {
    switch (f) {
    case CompileFailure::None: return nullptr;
    case CompileFailure::Emit: return "VXA047";
    case CompileFailure::Assemble: return "VXA048";
    case CompileFailure::Read: return "VXA049";
    case CompileFailure::Load: return "VXA050";
    }
    return nullptr;
}

CompiledIr compile_ir_to_bytecode(const ir::IrModule &mod,
                                  const ir::EmitOptions &emit_opts,
                                  const std::vector<uint8_t> *ir_section,
                                  const std::string &diag_name) {
    CompiledIr r;
    r.subject = diag_name;

    // 1) IR -> texto `.vel`.
    ir::EmitResult e =
        ir::ir_emit_module(const_cast<ir::IrModule &>(mod), emit_opts);
    if (!e.ok) {
        r.failure = CompileFailure::Emit;
        return r;
    }

    std::error_code ec;
    std::filesystem::create_directories(kIntermediateDir, ec);
    /* El nombre sale del CONTENIDO, no de un contador: dos compilaciones del
     * mismo texto usan el mismo intermedio, y dos distintas no se pisan aunque
     * corran a la vez. */
    const std::string base =
        std::string(kIntermediateDir) + "/" + diag_name + "_" +
        std::to_string(std::hash<std::string>{}(e.vel_text));

    // 2) Texto -> `.velb`.  Desde la fuente EN MEMORIA: el texto lo acaba de
    //    producir la linea de arriba, asi que escribirlo para que la siguiente
    //    lo vuelva a leer seria trabajo puro.  El nombre se conserva para los
    //    diagnosticos, no para abrir nada.
    const int rc = asm_multi_process::run_worker_from_source(
        e.vel_text, base + ".vel", base,
        /*skip_preprocessor=*/true,
        /*keep_labels=*/false, ir_section,
        /*emit_map=*/false);
    if (rc != 0) {
        r.failure = CompileFailure::Assemble;
        return r;
    }

    // 3) Leer el bytecode.
    if (!util::read_whole_file(base + ".velb", r.velb) || r.velb.empty()) {
        r.failure = CompileFailure::Read;
        r.velb.clear();
        return r;
    }

    r.ok = true;
    return r;
}

std::unique_ptr<ComptimeRuntime>
compile_ir_and_load(const ir::IrModule &mod, const ir::EmitOptions &emit_opts,
                    const std::vector<uint8_t> *ir_section,
                    const std::string &diag_name, CompiledIr *out) {
    CompiledIr c =
        compile_ir_to_bytecode(mod, emit_opts, ir_section, diag_name);
    if (!c.ok) {
        if (out) *out = std::move(c);
        return nullptr;
    }

    auto rt = std::make_unique<ComptimeRuntime>();
    if (!rt->load_macros_from_bytes(std::move(c.velb))) {
        if (out) {
            CompiledIr failed;
            failed.failure = CompileFailure::Load;
            failed.subject = diag_name;
            *out = std::move(failed);
        }
        return nullptr;
    }
    /* `velb` quedo movido dentro del runtime; el resultado que se devuelve dice
     * que salio bien y no arrastra una copia del bytecode. */
    if (out) {
        CompiledIr done;
        done.ok = true;
        done.subject = diag_name;
        *out = std::move(done);
    }
    return rt;
}

} // namespace vx
