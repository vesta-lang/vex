/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file runtime/exec_instruction_mem.cpp
 * @brief Instrucciones de MEMORIA MASIVA: memset / memcpy, en sus variantes de
 *        memoria del HOST y de memoria VIRTUAL (0xB6-0xB9).
 *
 * POR QUE SON INSTRUCCIONES DE LA VM Y NO UNA LLAMADA.  Rellenar y copiar
 * regiones son las dos primitivas mas usadas de cualquier programa real (toda
 * declaracion de array o struct empieza por un relleno a cero).  Resolverlas
 * con una llamada externa anyade el sobrecoste de la llamada a algo que se
 * resuelve con un punado de movimientos vectoriales, y ademas ATA la operacion
 * a la memoria del host: un plugin no puede escribir en la memoria VIRTUAL de
 * un proceso.  Como instrucciones se obtienen las dos variantes con la misma
 * semantica y sin intermediarios.
 *
 * MEDIDO (lo que motivo su existencia): antes de esto, el lowering desplegaba
 * el relleno a cero en un STORE por cada 8 bytes SIN LIMITE, asi que `i32[8192]
 * arr;` -- una DECLARACION -- producia 16397 instrucciones, 86 KB de codigo y
 * 1,7 s de compilacion, con un unico bloque basico de 16405 instrucciones. Aqui
 * eso es UNA instruccion.
 *
 * DE DONDE SALEN LOS MOVIMIENTOS.  De @c util/mem/vesta_memcpy.h y
 * @c util/mem/vesta_memset.h, en @c vesta_alloc.  Antes vivian AQUI DENTRO, en el
 * anonimo de este fichero y sin cabecera, asi que solo los podia usar el
 * interprete: el asignador, que necesita exactamente lo mismo, llamaba a
 * @c std::memset teniendolos al lado.  Son primitivas de memoria del anfitrion,
 * no instrucciones de la maquina virtual, y su sitio es la libreria de memoria.
 *
 * El por que de no delegar en la libc y como funciona el despacho por capacidad
 * de la CPU estan explicados alli, con los bancos que lo miden.
 *
 * VARIANTES VIRTUALES.  La memoria del proceso esta PAGINADA (TLB, paginas de
 * 4 KiB), asi que un rango arbitrario NO tiene un puntero host contiguo: van
 * por trozos de una pagina con un bufer en PILA (sin reservar memoria), y
 * dentro de cada trozo usan las mismas rutinas vectoriales.
 *
 * SEGURIDAD.  Una longitud por encima del tope (@c kMaxBulkBytes) LANZA un
 * FatalError capturable, no se ignora: casi siempre es un registro con basura
 * colandose como tamano, y tratarlo como no-op dejaria la region sin
 * inicializar para que el fallo aparezca mucho despues y en otro sitio.  Las
 * direcciones virtuales las validan @c read_bytes / @c write_bytes, que es
 * donde vive esa responsabilidad.
 */

#include "runtime/exception_runtime.h"
#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/vm_block_mem.h" // el recorrido por paginas, en UN sitio
#include "util/mem/vesta_memcpy.h"    // los movimientos, en UN sitio
#include "util/mem/vesta_memset.h"

#include <cstddef>
#include <cstdint>

namespace runtime {

namespace {

/// Tope defensivo: una longitud absurda casi siempre es un registro con basura,
/// no una intencion.  Cortar aqui convierte un cuelgue en un error localizable.
constexpr uint64_t kMaxBulkBytes = 1ull << 32; // 4 GiB

/**
 * @brief Decodifica los tres registros de una instruccion de memoria masiva.
 *
 * Convention B (@c decode_instr_raw_bytes) con el MISMO layout de nibbles que
 * @c alu3 / @c mvtake -- se reutiliza su emisor, asi que el formato fisico ya
 * estaba probado:
 *
 *     byte2 = (r_b << 4) | r_a        byte3 = (r_c << 4)
 *
 * donde para @c memset (r_a, r_b, r_c) = (dst, val, len) y para @c memcpy
 * (dst, src, len).
 */
struct MemOperands {
    uint8_t a, b, c;
};
inline MemOperands decode_mem_ops(const DecodedInstr &instr) noexcept {
    const uint8_t byte2 = instr.data_instruction.reg_data.reg1;
    const uint8_t byte3 = instr.data_instruction.reg_data.reg2;
    return {static_cast<uint8_t>(byte2 & 0x0F),
            static_cast<uint8_t>((byte2 >> 4) & 0x0F),
            static_cast<uint8_t>((byte3 >> 4) & 0x0F)};
}

/**
 * @brief Longitud validada.  Devuelve 0 (nada que hacer) o lanza.
 *
 * Una longitud por encima del tope es SIEMPRE un error -- casi siempre un
 * registro con basura que se cuela como tamano.  Antes esto devolvia 0 en
 * silencio, y un @c len corrupto se comportaba como un no-op: el programa
 * seguia con la region SIN inicializar y el fallo aparecia mucho despues, en
 * otro sitio.  Un FatalError es capturable y apunta al lugar real.
 */
inline bool bulk_len(ProcessVM *vm, uint8_t r_len, uint64_t &out) {
    out = vm->registers.regs[r_len].qword();
    if (out > kMaxBulkBytes) {
        throw_fatalf(vm, FATAL_ILLEGAL_INSTRUCTION,
                     "operacion de memoria masiva con longitud invalida: %llu "
                     "bytes (tope %llu)",
                     (unsigned long long)out,
                     (unsigned long long)kMaxBulkBytes);
        return false;
    }
    return out != 0;
}

/// Trozo de trabajo de las variantes virtuales: una pagina.
constexpr size_t kChunk = 4096;

} // namespace

/** @brief @c memseth r_dst, r_val, r_len -- relleno en memoria del HOST. */
void exec_instr_memseth(ProcessVM *vm, const DecodedInstr &instr) {
    const MemOperands o = decode_mem_ops(instr);
    uint64_t n = 0;
    if (!bulk_len(vm, o.c, n)) return;
    auto *dst = reinterpret_cast<uint8_t *>(vm->registers.regs[o.a].qword());
    if (dst == nullptr) return;
    util::vesta_memset(
        dst, static_cast<uint8_t>(vm->registers.regs[o.b].qword() & 0xFF),
        static_cast<size_t>(n));
}

/** @brief @c memcpyh r_dst, r_src, r_len -- copia en memoria del HOST. */
void exec_instr_memcpyh(ProcessVM *vm, const DecodedInstr &instr) {
    const MemOperands o = decode_mem_ops(instr);
    uint64_t n = 0;
    if (!bulk_len(vm, o.c, n)) return;
    auto *dst = reinterpret_cast<uint8_t *>(vm->registers.regs[o.a].qword());
    auto *src =
        reinterpret_cast<const uint8_t *>(vm->registers.regs[o.b].qword());
    if (dst == nullptr || src == nullptr) return;
    /* `vesta_memmove` y no `vesta_memcpy`: el intermedio NO garantiza que las
     * dos regiones sean disjuntas. */
    util::vesta_memmove(dst, src, static_cast<size_t>(n));
}

void vm_block_fill(ProcessVM &vm, uint64_t vaddr, uint8_t value, uint64_t len) {
    if (len == 0) return;
    uint8_t buf[kChunk];
    /* El patron se construye UNA vez y se reusa en cada pagina. */
    util::vesta_memset(buf, value,
                       static_cast<size_t>(len < kChunk ? len : kChunk));
    while (len > 0) {
        const size_t k = static_cast<size_t>(len < kChunk ? len : kChunk);
        vm.vm_mem.write_bytes(vaddr, buf, k);
        vaddr += k;
        len -= k;
    }
}

void vm_block_copy(ProcessVM &vm, uint64_t dst, uint64_t src, uint64_t len) {
    if (len == 0 || dst == src) return;
    uint8_t buf[kChunk];
    /* Con solape y destino POR DELANTE se recorre HACIA ATRAS: es el
     * equivalente por trozos de lo que hace @c vesta_memmove en un bloque, y
     * lo que impide pisar lo que aun falta por leer. */
    if (dst > src && dst < src + len) {
        uint64_t rem = len;
        while (rem > 0) {
            const size_t k = static_cast<size_t>(rem < kChunk ? rem : kChunk);
            rem -= k;
            vm.vm_mem.read_bytes(src + rem, buf, k);
            vm.vm_mem.write_bytes(dst + rem, buf, k);
        }
        return;
    }
    uint64_t off = 0;
    while (off < len) {
        const size_t k =
            static_cast<size_t>((len - off) < kChunk ? (len - off) : kChunk);
        vm.vm_mem.read_bytes(src + off, buf, k);
        vm.vm_mem.write_bytes(dst + off, buf, k);
        off += k;
    }
}

/** @brief @c memset r_dst, r_val, r_len -- relleno en memoria VIRTUAL. */
void exec_instr_memset(ProcessVM *vm, const DecodedInstr &instr) {
    const MemOperands o = decode_mem_ops(instr);
    uint64_t n = 0;
    if (!bulk_len(vm, o.c, n)) return;
    vm_block_fill(*vm, vm->registers.regs[o.a].qword(),
                  static_cast<uint8_t>(vm->registers.regs[o.b].qword() & 0xFF),
                  n);
}

/** @brief @c memcpy r_dst, r_src, r_len -- copia dentro de memoria VIRTUAL. */
void exec_instr_memcpy(ProcessVM *vm, const DecodedInstr &instr) {
    const MemOperands o = decode_mem_ops(instr);
    uint64_t n = 0;
    if (!bulk_len(vm, o.c, n)) return;
    vm_block_copy(*vm, vm->registers.regs[o.a].qword(),
                  vm->registers.regs[o.b].qword(), n);
}

} // namespace runtime
