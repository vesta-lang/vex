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
 * @file native_backend.cpp
 * @brief Implementacion de los backends de codegen nativo (x86 y arm64).
 */

#include "util/env_flags.h"
#include "toolchain/native_backend.h"

#include <capstone/capstone.h>

#include "jit/arm64/arm64_select.h"
#include "jit/arm64/arm64_target.h"
#include "jit/vreg_pipeline.h"
#include "vx/asm/asm_backend.h"

#include <cstdlib>

namespace aot {

namespace {

/// Backend x86: envuelve @c jit::vreg_compile_native (comportamiento identico
/// al del driver antes del desacoplamiento).
class X86Backend : public NativeBackend {
  public:
    explicit X86Backend(AotArch a) : arch_(a) {}
    AotArch arch() const override { return arch_; }
    const char *name() const override { return "x86"; }
    NativeCompileResult
    compile_function(const ir::IrFunction &fn,
                     const NativeCompileOpts &opts) override {
        NativeCompileResult r;
        r.bytes = jit::vreg_compile_native(
            fn, {}, {}, {}, {}, &r.relocs, opts.pic, opts.target_sysv,
            opts.mode32, opts.fisa, opts.want_line_map,
            opts.want_line_map ? &r.line_map : nullptr,
            /*asm_labels_out=*/nullptr,
            /*stackmaps_out=*/&r.stackmaps, opts.cpu,
            /*unwind_out=*/&r.unwind);
        return r;
    }

  private:
    AotArch arch_;
};

/// Backend arm64: baja la funcion a texto AArch64 (arm64_emit_asm) y lo
/// ensambla con Keystone.  Subconjunto entero (incluye ramas, llamadas
/// intra-unit y atomicos); las funciones con ops no soportadas devuelven bytes
/// vacios.
class Arm64Backend : public NativeBackend {
  public:
    AotArch arch() const override { return AotArch::ARM64; }
    const char *name() const override { return "arm64"; }
    NativeCompileResult
    compile_function(const ir::IrFunction &fn,
                     const NativeCompileOpts &opts) override {
        (void)opts;
        NativeCompileResult r;

        /* El codegen arm64 se activa SOLO aqui, cuando el TARGET es arm
         * (make_native_backend(ARM64) construyo este backend).  Path por
         * defecto: VREG (MachineIR + regalloc generico + scheduler) via el
         * orquestador arch-neutral con Arm64Target; el template queda como
         * fallback para las funciones fuera del subset vreg. VESTA_ARM64_VREG=0
         * fuerza el template (escape-hatch de depuracion). */
        static const bool use_vreg = util::flag_on(util::FlagId::Arm64Vreg);
        if (use_vreg) {
            jit::Arm64Target target;
            std::vector<jit::NativeReloc> relocs;
            std::vector<uint8_t> bytes =
                jit::vreg_compile_native_target(fn, target, &relocs);
            if (!bytes.empty()) {
                r.bytes = std::move(bytes);
                r.relocs = std::move(relocs);
                return r;
            }
            // vacio -> fuera del subset; cae al template.
        }

        bool unsupported = false;
        std::vector<std::string> call_targets;
        const std::string text = jit::arm64::arm64_emit_asm(
            fn, unsupported, jit::arm64::Arm64Abi::AAPCS64, &call_targets);
        if (unsupported || text.empty()) return r; // no soportada.
        if (!vx::g_asm_backend) return r; // sin ensamblador registrado.
        vx::AsmAssembleResult asmres =
            vx::g_asm_backend->assemble(text, vx::AsmArch::ARM64);
        if (!asmres.ok)
            return r; // sintaxis no ensamblable -> tratar como no soportada.
        r.bytes = std::move(asmres.bytes);
        // Relocs cross-funcion (R_AARCH64_CALL26): cada CALL se emitio como un
        // `bl 0` placeholder; como el control de flujo local usa b/b.cond/cbnz
        // (nunca bl), TODO `bl` del cuerpo es una llamada.  Desensamblamos con
        // Capstone, y el i-esimo `bl` recibe el i-esimo target -> el driver
        // parchea su imm26 a la VA real (BFS del callee incluido).
        if (!call_targets.empty() && !r.bytes.empty()) {
            csh h;
            if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &h) ==
                CS_ERR_OK) {
                cs_insn *insn = nullptr;
                size_t n = cs_disasm(h, r.bytes.data(), r.bytes.size(),
                                     /*addr=*/0, /*count=*/0, &insn);
                size_t ci = 0;
                for (size_t i = 0; i < n && ci < call_targets.size(); ++i) {
                    if (insn[i].id != ARM64_INS_BL) continue;
                    jit::NativeReloc rl;
                    rl.kind = jit::NativeReloc::Kind::ARM64_CALL26;
                    rl.offset =
                        static_cast<uint32_t>(insn[i].address); // base 0
                    rl.symbol = call_targets[ci++];
                    r.relocs.push_back(std::move(rl));
                }
                if (insn) cs_free(insn, n);
                cs_close(&h);
            }
        }
        return r;
    }
};

} // namespace

std::unique_ptr<NativeBackend> make_native_backend(AotArch arch) {
    switch (arch) {
    case AotArch::X86_64:
    case AotArch::X86_32:
    case AotArch::X86_16:
        return std::unique_ptr<NativeBackend>(new X86Backend(arch));
    case AotArch::ARM64:
        return std::unique_ptr<NativeBackend>(new Arm64Backend());
    default: return nullptr;
    }
}

} // namespace aot
