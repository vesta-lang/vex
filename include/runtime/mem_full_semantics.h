/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/mem_full_semantics.h
 * @brief Que direccion calcula y que valor carga un `mld`.
 *
 * POR QUE ESTA APARTE
 * -------------------
 * Lo usan DOS: el manejador de `mld` (0x90) y la instruccion FUSIONADA que
 * carga y opera en un paso.  Escrito dos veces se separaria en cuanto alguien
 * tocara un ancho o el signo, y el modo de fallar es el peor: el mismo programa
 * daria un valor suelto y otro dentro de un paquete, sin que nada avise.
 *
 * LO QUE NO CUBRE, Y POR QUE
 * --------------------------
 * El banco de coma flotante (bit 4 de `flags`).  Ahi `mld` no escribe un
 * registro general sino un ZMM, reinterpretando los bits, asi que no hay
 * "valor cargado" que devolver: es otra operacion.  Quien fusione tiene que
 * mirarlo y renunciar; lo hace `bundle_fuse.cpp`.
 */

#ifndef VESTA_RUNTIME_MEM_FULL_SEMANTICS_H
#define VESTA_RUNTIME_MEM_FULL_SEMANTICS_H

#include <cstdint>
#include <cstring>

#include "runtime/proceso_runtime.h"

namespace runtime {

/// Bits de `mem_full::flags`, con nombre para no repartir constantes sueltas.
enum : uint8_t {
    kMemHost = 0x01,     ///< la direccion es del proceso anfitrion
    kMemHasIndex = 0x02, ///< lleva registro indice
    kMemIndexSub = 0x04, ///< el indice se RESTA
    kMemSignExt = 0x08,  ///< extension de signo para anchos < 8
    kMemFpBank = 0x10,   ///< el destino es el banco ZMM, no el general
};

/**
 * @brief La direccion efectiva: `base +/- (index << scale) +/- disp`.
 *
 * @param base 0-15 = rN, 16 = rbp, 17 = rsp.  Los dos ultimos son los que el
 *             direccionamiento SIB no admite, y son justo los del derrame.
 */
[[gnu::always_inline]] inline uint64_t
mem_full_addr(ProcessVM *vm, uint8_t base, int16_t disp, uint8_t flags,
              uint8_t index, uint8_t scale) {
    uint64_t addr = base < 16
                        ? vm->registers.regs[base].qword()
                        : (base == 16 ? vm->registers.base_pointer.raw()
                                      : vm->registers.stack_pointer.raw());
    addr += static_cast<uint64_t>(static_cast<int64_t>(disp));
    if (flags & kMemHasIndex) {
        const uint64_t idx = vm->registers.regs[index].qword() << scale;
        if (flags & kMemIndexSub)
            addr -= idx; // idx_sub
        else
            addr += idx;
    }
    return addr;
}

/**
 * @brief El valor que carga un `mld`, ya extendido a 64 bits.
 *
 * @param vm    Maquina.
 * @param m     Operandos del `mld`.  El banco FP NO se admite aqui: ver la
 *              cabecera del fichero.
 * @param addr  Direccion efectiva, ya calculada.
 */
template <typename MemFull>
[[gnu::always_inline]] inline uint64_t
mem_full_load(ProcessVM *vm, const MemFull &m, uint64_t addr) {
    uint64_t val = 0;
    if (m.flags & kMemHost) {
        std::memcpy(&val, reinterpret_cast<const void *>(addr),
                    m.width <= 8 ? m.width : 8);
    } else {
        switch (m.width) {
        case 1: val = vm->vm_mem.read_u8(addr); break;
        case 2: val = vm->vm_mem.read_u16(addr); break;
        case 4: val = vm->vm_mem.read_u32(addr); break;
        /* read_u64_fast: cache de pagina -> memcpy directo en acierto (~1 ns)
         * frente al recorrido completo de la TLB (~50 ns).  `mld` es la carga
         * universal del bucle caliente -- arrays, locales, campos -- y sus
         * accesos caen MAYORMENTE en la misma pagina.  En acceso disperso baja
         * al camino lento, que es correcto y sin regresion. */
        default: val = vm->vm_mem.read_u64_fast(addr); break;
        }
    }
    if (m.flags & kMemSignExt) { // extension de signo para anchos < 8
        switch (m.width) {
        case 1:
            val = static_cast<uint64_t>(
                static_cast<int64_t>(static_cast<int8_t>(val)));
            break;
        case 2:
            val = static_cast<uint64_t>(
                static_cast<int64_t>(static_cast<int16_t>(val)));
            break;
        case 4:
            val = static_cast<uint64_t>(
                static_cast<int64_t>(static_cast<int32_t>(val)));
            break;
        default: break;
        }
    }
    return val;
}

/**
 * @brief Escribe @p val donde dice un `mst`, con su ancho y su destino.
 *
 * El companyero de @ref mem_full_load, y esta aqui por lo mismo: lo comparte el
 * manejador de `mst` con las fusionadas que hacen varios accesos de una vez.
 *
 * @param vm    Maquina.
 * @param m     Operandos del `mst`.  El banco FP NO se admite: el valor a
 *              escribir sale de un ZMM y eso lo resuelve `exec_instr_mst`.
 * @param addr  Direccion efectiva, ya calculada.
 * @param val   Los bytes a escribir, ya en un entero de 64 bits.
 */
template <typename MemFull>
[[gnu::always_inline]] inline void
mem_full_store(ProcessVM *vm, const MemFull &m, uint64_t addr, uint64_t val) {
    if (m.flags & kMemHost) {
        std::memcpy(reinterpret_cast<void *>(addr), &val,
                    m.width <= 8 ? m.width : 8);
        return;
    }
    switch (m.width) {
    case 1: vm->vm_mem.write_u8(addr, static_cast<uint8_t>(val)); break;
    case 2: vm->vm_mem.write_u16(addr, static_cast<uint16_t>(val)); break;
    case 4: vm->vm_mem.write_u32(addr, static_cast<uint32_t>(val)); break;
    default: vm->vm_mem.write_u64_fast(addr, val); break; // ver `mem_full_load`
    }
}

} // namespace runtime

#endif // VESTA_RUNTIME_MEM_FULL_SEMANTICS_H
