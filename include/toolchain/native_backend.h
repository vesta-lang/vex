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
 * @file native_backend.h
 * @brief Abstraccion de BACKEND DE CODEGEN NATIVO por arquitectura ( H.5).
 *
 * Desacopla el driver AOT del codegen concreto: en vez de llamar directamente a
 * @c jit::vreg_compile_native (x86-only), el driver obtiene un @ref
 * NativeBackend segun el @ref aot::AotArch del target y le pide compilar cada
 * @c ir::IrFunction a bytes maquina + relocaciones.  Anadir una arquitectura =
 * implementar esta interfaz, sin tocar el driver.
 *
 *   - x86 (@ref make_native_backend con X86_64/X86_32): envuelve
 *     @c vreg_compile_native (mismo comportamiento que antes).
 *   - arm64 (@ref make_native_backend con ARM64): @c jit::arm64::arm64_emit_asm
 *     + ensamblado Keystone (AArch64).
 */

#ifndef VX_TOOLCHAIN_NATIVE_BACKEND_H
#define VX_TOOLCHAIN_NATIVE_BACKEND_H

#include <cstdint>
#include <memory>
#include <vector>

#include "aot/aot_native.h"          // AotArch
#include "codegen/frame_unwind.h"    // FrameUnwind
#include "ir/ssa_ir.h"               // IrFunction
#include "jit/jit_registry.h"        // Stackmap
#include "jit/vreg_pipeline.h"       // NativeReloc, FloatIsa

namespace aot {

/// Configuracion del target para el codegen.  Los campos x86-especificos los
/// ignoran las demas arquitecturas.
struct NativeCompileOpts {
    bool pic = true;         ///< referencias a datos position-independent.
    bool target_sysv = true; ///< ABI x86: true=SysV(ELF), false=Win64(PE).
    bool mode32 = false;     ///< x86-32 (modo protegido).
    jit::FloatIsa fisa = jit::FloatIsa::SSE2; ///< ISA de float x86.
    /// Pedir la correlacion codigo-nativo <-> linea del fuente.
    ///
    /// Es un DATO: no cambia ni un byte de lo emitido (el codificador solo
    /// apunta, en paralelo, en que desplazamiento empieza cada linea).  Sirve
    /// para que un consumidor EXTERNO pueda explicar despues un fallo a partir
    /// de su direccion, sin que el binario lleve nada que lo explique por si
    /// mismo -- meterle codigo cambiaria el programa que se depura.
    bool want_line_map = false;
    /// Microarquitectura concreta ("znver3", "skylake", ...).  Vacia = lo que
    /// se deduzca de @c fisa.  Misma fuente que `--cpu`: decide contra la base
    /// de datos de instrucciones que se permite emitir el generador, sin
    /// depender de la maquina que compila.
    std::string cpu;
};

/// Resultado del codegen de UNA funcion.  @c bytes vacio => no soportada.
struct NativeCompileResult {
    std::vector<uint8_t> bytes;
    std::vector<jit::NativeReloc> relocs;
    std::vector<jit::Stackmap> stackmaps;
    /// Donde cambia la linea del fuente dentro de @c bytes.  Vacio salvo que
    /// se pidiera con @c NativeCompileOpts::want_line_map.
    std::vector<jit::LineMapEntry> line_map;
    /// Que hizo el prologo, para poder deshacer el marco.
    ///
    /// Sin codificar y sin bandera que lo pida, al contrario que
    /// @c line_map: describirlo no cuesta nada -- el codegen ya sabe que
    /// guardo, solo hay que apuntarlo -- y quien decide si acaba en el
    /// binario, y en que formato, es el driver con `--unwind`.  Ponerle aqui
    /// un interruptor obligaria a decidirlo dos veces.
    ///
    /// Queda vacio en los backends que aun no lo describen; el driver lo
    /// trata como "esta funcion no aporta tabla", no como un error.
    codegen::FrameUnwind unwind;
};

/// Backend de codegen nativo de una arquitectura.
struct NativeBackend {
    virtual ~NativeBackend() = default;
    /// Arquitectura del backend.
    virtual AotArch arch() const = 0;
    /// Nombre legible (para diagnosticos).
    virtual const char *name() const = 0;
    /// Compila @p fn a bytes nativos + relocs + stackmaps.
    virtual NativeCompileResult
    compile_function(const ir::IrFunction &fn,
                     const NativeCompileOpts &opts) = 0;
};

/// Crea el backend de @p arch, o nullptr si no hay codegen para esa arch.
std::unique_ptr<NativeBackend> make_native_backend(AotArch arch);

} // namespace aot

#endif // VX_TOOLCHAIN_NATIVE_BACKEND_H
