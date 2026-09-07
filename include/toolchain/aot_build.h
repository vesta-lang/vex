/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file toolchain/aot_build.h
 * @brief Emisor AOT nativo (PE/ELF) reutilizable, extraido de main.cpp.
 */

#ifndef VESTA_TOOLCHAIN_AOT_BUILD_H
#define VESTA_TOOLCHAIN_AOT_BUILD_H

#include <cstdint>
#include <string>

#include "aot/aot_analyze.h" // aot::Tier
#include "vx/compiler.h"     // vx::CompileResult / vx::CompileOptions

namespace vesta {
namespace tc {

/**
 * @struct AotOptions
 * @brief Opciones del emisor AOT (sin acoplar a cxxopts).
 *
 * Reune los flags @c -m aot que antes se leian del @c cxxopts::ParseResult.
 * Al ser una struct plana, cualquier consumidor (el binario @c vm, el servidor
 * @c vesta_lsp) la puede rellenar y llamar a @c compile_aot sin depender del
 * parser de la CLI.  Las cadenas vacias significan "no especificado" (se aplica
 * el valor por defecto por host/tier).
 */
/**
 * @brief Que descripcion de desenrollado se emite en el artefacto nativo.
 *
 * SON DOS MECANISMOS, no dos plataformas, y por eso se piden por separado.  Una
 * PE puede llevar los dos a la vez: las TABLAS son lo unico que el
 * desenrollador del sistema sabe leer en Windows x64, y el CFI de DWARF es lo
 * que usan gdb, libunwind y el runtime de excepciones de MinGW -- con el que
 * este enlazador tiene que convivir, porque acepta sus objetos --.
 *
 * NO ES INFORMACION DE DEPURACION y no cuelga de `--debug-info`.  Lo parece, y
 * ahi esta la trampa: si colgara, el binario de release seria justo el que no
 * se puede diagnosticar cuando falla, que es el que le llega a la gente.
 *
 * AQUI NO SE OBLIGA.  La ABI de x64 de Microsoft exige estos datos en toda
 * funcion que no sea hoja, y MSVC no da forma de quitarlos; aqui el defecto los
 * pone y cualquiera puede quitarlos.  Un kernel que lleve su propio
 * desenrollador es un caso legitimo, y `--freestanding` no decide por el.
 */
enum class UnwindEmit {
    /// Lo que pida el contenedor: PE -> tablas, ELF -> CFI.  Es el defecto por
    /// el mismo motivo que en gcc y clang, donde las tablas van encendidas
    /// incluso en C sin excepciones: sin ellas no se puede desenrollar desde
    /// un punto cualquiera, que es lo que hacen un perfilador y un depurador.
    AUTO = 0,
    NONE,  ///< nada.  Explicito, y motivado por tamano.
    TABLE, ///< `.pdata` / `.xdata`.  Solo PE; en ELF no hay donde ponerlas.
    CFI,   ///< `.eh_frame`.  Vale en PE y en ELF.
    BOTH,  ///< las dos, donde el contenedor lo permita.
};

struct AotOptions {
    aot::Tier tier = aot::Tier::BARE; ///< bare|embed|full.
    /// --unwind: como se describe el marco.  Ver @ref UnwindEmit.
    UnwindEmit unwind = UnwindEmit::AUTO;
    bool freestanding = false;        ///< --freestanding (sin libc).
    bool no_exceptions = false;       ///< --no-exceptions.
    bool no_io = false;               ///< --no-io.
    bool no_mem = false;              ///< --no-mem (sin slab allocator).
    std::string arch = "x86-64";      ///< --aot-arch: x86-64 | x86-32.
    std::string float_isa = "sse2"; ///< --float-isa: sse2|x87|avx|avx512f|auto.
    std::string format;             ///< --format: "" (host) | pe | elf.
    std::string emit;               ///< --emit: "" (exe) | obj | shared | bin.
    bool no_pie = false;            ///< --no-pie (refs absolutas, no PIC).
    std::string bin_base;           ///< --bin-base (hex; solo .bin).
    std::string sysroot;            ///< --sysroot (para el auto-link).
    std::string argv0;              ///< Ruta del ejecutable (localizar stdlib).
    /// Ruta del `.vx` compilado.  Se anota en el fichero acompanante de
    /// depuracion para poder ensenar despues la linea de fuente.
    std::string source_path;
    /// Nivel de informacion de depuracion embebida en el artefacto nativo:
    ///   0 = ninguna (default; cero coste, binario mas pequeno).
    ///   1 = simbolos de FUNCION (.symtab / COFF symtab) -> backtraces con
    ///       nombres en gdb/WinDbg/lldb.
    ///   2 = + tabla de lineas (fuente<->PC)  [futuro: DWARF .debug_line].
    ///   3 = + variables locales/tipos        [futuro: DWARF .debug_info].
    /// Los niveles 2-3 se construyen sobre el mismo mapa nombre->VA del
    /// nivel 1. Eje DWARF de `--debug-info`: symtab y (manana) `.debug_line`.
    /// Lo consumen depuradores y desensambladores AJENOS.
    int debug_level = 0;
    /// Eje del LENGUAJE de `--debug-info` (la parte tras el punto): el fichero
    /// acompanante `.vxdbg`.  Va aparte porque son mecanismos distintos y el
    /// nuestro no puede contaminar al otro: no toca el binario.
    int lang_debug_level = 0;
};

/**
 * @brief Emite el artefacto AOT nativo del modulo ya compilado por el frontend.
 *
 * Reusa el mismo camino que producia el ejecutable AOT en @c main.cpp: parsea
 * el IR embebido en @p cr, auto-bundlea los runtimes necesarios (excepciones,
 * I/O, colecciones), baja a codigo nativo con el back-end vreg (HOST_LEAF), y
 * escribe el .exe/.o/.so/.bin (PE o ELF, x86-64/x86-32) con el emisor y el
 * linker propios.
 *
 * @param cr          Resultado del frontend (IR embebido + simbolos AOT).
 * @param copts       Opciones de compilacion usadas por el frontend.
 * @param out_prefix  Prefijo del artefacto de salida (@c -o).
 * @param opt         Opciones AOT (formato, emit, arch, tier, ...).
 * @return @c EXIT_SUCCESS / @c EXIT_FAILURE.
 */
int compile_aot(const vx::CompileResult &cr, const vx::CompileOptions &copts,
                std::string out_prefix, const AotOptions &opt);

} // namespace tc
} // namespace vesta

#endif // VESTA_TOOLCHAIN_AOT_BUILD_H
