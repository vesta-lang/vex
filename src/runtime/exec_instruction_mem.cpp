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
 * POR QUE NO SE DELEGA EN LA LIBC.  Seria comodo llamar a @c memcpy/@c memset
 * del sistema, pero la premisa "la libc siempre trae la version optima" es
 * FALSA: en Windows el CRT de MinGW resuelve la copia byte a byte, y en Linux
 * quedariamos a merced de que libc traiga la distribucion.  Eso no es una
 * optimizacion, es una loteria distinta en cada maquina.  Estas son primitivas
 * del lenguaje: su rendimiento tiene que ser NUESTRO y reproducible.
 *
 * COMO SE CONSIGUE.  Tipos vectoriales de GCC/Clang
 * (@c __attribute__((vector_size))) para mover de 16, 32 y 64 bytes por
 * iteracion, con DESPACHO EN RUNTIME por capacidad de la CPU
 * (@c __builtin_cpu_supports): la version AVX2 se compila con
 * @c __attribute__((target("avx2"))) -- asi el binario NO exige AVX2 para
 * arrancar, pero lo usa cuando la maquina lo tiene.  El camino base (SSE2) esta
 * garantizado en todo x86-64.  Fuera de x86 el mismo codigo vectorial se mapea
 * a lo que tenga el target (p.ej. NEON) sin cambios.
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

#include <cstddef>
#include <cstdint>

namespace runtime {

namespace {

/* --- Tipos vectoriales ---------------------------------------------------
 * @c vector_size le pide al compilador el registro vectorial mas ancho que
 * pueda usar para ese tamano, y las lecturas/escrituras se hacen con
 * @c may_alias para que sean legales sobre @c uint8_t* sin romper el aliasing
 * estricto.  No hay intrinsecos de una ISA concreta: el mismo codigo vale para
 * x86 (SSE/AVX) y para cualquier otro target con unidades vectoriales. */
/* @c aligned(1) es IMPRESCINDIBLE, no un detalle: sin el, un tipo vectorial
 * tiene alineacion NATURAL (16/32 bytes) y el compilador emite el movimiento
 * ALINEADO (`movdqa`), que FALLA con SIGSEGV en cuanto la direccion no lo esta
 * -- y aqui las direcciones vienen del programa, sin garantia ninguna.  Con
 * @c aligned(1) se emiten los movimientos no alineados (`movdqu`/`vmovdqu`),
 * que en las CPU modernas cuestan lo mismo cuando el dato SI esta alineado. */
typedef uint8_t v16 __attribute__((vector_size(16), may_alias, aligned(1)));
typedef uint8_t v32 __attribute__((vector_size(32), may_alias, aligned(1)));

/// Tope defensivo: una longitud absurda casi siempre es un registro con basura,
/// no una intencion.  Cortar aqui convierte un cuelgue en un error localizable.
constexpr uint64_t kMaxBulkBytes = 1ull << 32; // 4 GiB

/* --- Copia: camino base (SSE2, garantizado en todo x86-64) --------------- */

/**
 * @brief Copia @p n bytes con movimientos de 16 bytes (4 por iteracion).
 *
 * Desenrollado a 64 bytes por vuelta: el bucle emite 4 cargas y 4 escrituras
 * independientes, que el core superescalar solapa; ir de 16 en 16 sin
 * desenrollar deja la unidad de carga a media capacidad.
 */
void copy_sse(uint8_t *d, const uint8_t *s, uint64_t n) noexcept {
    while (n >= 64) {
        v16 a = *reinterpret_cast<const v16 *>(s);
        v16 b = *reinterpret_cast<const v16 *>(s + 16);
        v16 c = *reinterpret_cast<const v16 *>(s + 32);
        v16 e = *reinterpret_cast<const v16 *>(s + 48);
        *reinterpret_cast<v16 *>(d) = a;
        *reinterpret_cast<v16 *>(d + 16) = b;
        *reinterpret_cast<v16 *>(d + 32) = c;
        *reinterpret_cast<v16 *>(d + 48) = e;
        d += 64;
        s += 64;
        n -= 64;
    }
    while (n >= 16) {
        *reinterpret_cast<v16 *>(d) = *reinterpret_cast<const v16 *>(s);
        d += 16;
        s += 16;
        n -= 16;
    }
    if (n >= 8) {
        __builtin_memcpy(d, s, 8); // tamano CONSTANTE -> se expande inline
        d += 8;
        s += 8;
        n -= 8;
    }
    while (n--)
        *d++ = *s++;
}

void fill_sse(uint8_t *d, uint8_t v, uint64_t n) noexcept {
    v16 pat;
    for (unsigned i = 0; i < 16; ++i)
        pat[i] = v;
    while (n >= 64) {
        *reinterpret_cast<v16 *>(d) = pat;
        *reinterpret_cast<v16 *>(d + 16) = pat;
        *reinterpret_cast<v16 *>(d + 32) = pat;
        *reinterpret_cast<v16 *>(d + 48) = pat;
        d += 64;
        n -= 64;
    }
    while (n >= 16) {
        *reinterpret_cast<v16 *>(d) = pat;
        d += 16;
        n -= 16;
    }
    if (n >= 8) {
        __builtin_memcpy(d, &pat, 8);
        d += 8;
        n -= 8;
    }
    while (n--)
        *d++ = v;
}

/* --- Copia: camino AVX2 -------------------------------------------------- */

#if defined(__x86_64__) || defined(_M_X64)
#define VESTA_HAS_X86_DISPATCH 1

/* @c target("avx2") compila SOLO estas funciones con AVX2 habilitado, sin
 * exigirlo al binario entero: el despacho de abajo comprueba la CPU antes de
 * llamarlas.  Es la forma de aprovechar la extension sin perder portabilidad
 * del ejecutable. */
__attribute__((target("avx2"))) void copy_avx2(uint8_t *d, const uint8_t *s,
                                               uint64_t n) noexcept {
    while (n >= 128) {
        v32 a = *reinterpret_cast<const v32 *>(s);
        v32 b = *reinterpret_cast<const v32 *>(s + 32);
        v32 c = *reinterpret_cast<const v32 *>(s + 64);
        v32 e = *reinterpret_cast<const v32 *>(s + 96);
        *reinterpret_cast<v32 *>(d) = a;
        *reinterpret_cast<v32 *>(d + 32) = b;
        *reinterpret_cast<v32 *>(d + 64) = c;
        *reinterpret_cast<v32 *>(d + 96) = e;
        d += 128;
        s += 128;
        n -= 128;
    }
    while (n >= 32) {
        *reinterpret_cast<v32 *>(d) = *reinterpret_cast<const v32 *>(s);
        d += 32;
        s += 32;
        n -= 32;
    }
    if (n >= 16) {
        *reinterpret_cast<v16 *>(d) = *reinterpret_cast<const v16 *>(s);
        d += 16;
        s += 16;
        n -= 16;
    }
    if (n >= 8) {
        __builtin_memcpy(d, s, 8);
        d += 8;
        s += 8;
        n -= 8;
    }
    while (n--)
        *d++ = *s++;
}

__attribute__((target("avx2"))) void fill_avx2(uint8_t *d, uint8_t v,
                                               uint64_t n) noexcept {
    v32 pat;
    for (unsigned i = 0; i < 32; ++i)
        pat[i] = v;
    while (n >= 128) {
        *reinterpret_cast<v32 *>(d) = pat;
        *reinterpret_cast<v32 *>(d + 32) = pat;
        *reinterpret_cast<v32 *>(d + 64) = pat;
        *reinterpret_cast<v32 *>(d + 96) = pat;
        d += 128;
        n -= 128;
    }
    while (n >= 32) {
        *reinterpret_cast<v32 *>(d) = pat;
        d += 32;
        n -= 32;
    }
    if (n >= 16) {
        *reinterpret_cast<v16 *>(d) = *reinterpret_cast<const v16 *>(&pat);
        d += 16;
        n -= 16;
    }
    if (n >= 8) {
        __builtin_memcpy(d, &pat, 8);
        d += 8;
        n -= 8;
    }
    while (n--)
        *d++ = v;
}

/// Tiene AVX2 esta CPU?  Se consulta UNA vez (el resultado no cambia).
bool cpu_has_avx2() noexcept {
    static const bool yes = [] {
        __builtin_cpu_init();
        return __builtin_cpu_supports("avx2") != 0;
    }();
    return yes;
}
#endif // x86-64

/* --- Punto de entrada: despacho por capacidad de la CPU ------------------ */

inline void copy_fast(uint8_t *d, const uint8_t *s, uint64_t n) noexcept {
#ifdef VESTA_HAS_X86_DISPATCH
    if (cpu_has_avx2()) {
        copy_avx2(d, s, n);
        return;
    }
#endif
    copy_sse(d, s, n);
}

inline void fill_fast(uint8_t *d, uint8_t v, uint64_t n) noexcept {
#ifdef VESTA_HAS_X86_DISPATCH
    if (cpu_has_avx2()) {
        fill_avx2(d, v, n);
        return;
    }
#endif
    fill_sse(d, v, n);
}

/**
 * @brief Copia tolerante a SOLAPAMIENTO (equivalente a @c memmove).
 *
 * El IR no garantiza regiones disjuntas.  Con solape y @c d>s la copia hacia
 * delante pisaria la fuente antes de leerla, asi que ese caso se recorre HACIA
 * ATRAS.  El resto va por el camino vectorial rapido.
 */
void move_fast(uint8_t *d, const uint8_t *s, uint64_t n) noexcept {
    if (d == s || n == 0) return;
    if (d < s || d >= s + n) {
        copy_fast(d, s, n);
        return;
    } // sin solape util
    // Solapan con el destino por detras: copiar de atras hacia delante.
    uint64_t i = n;
    while (i >= 16) {
        i -= 16;
        *reinterpret_cast<v16 *>(d + i) = *reinterpret_cast<const v16 *>(s + i);
    }
    while (i--)
        d[i] = s[i];
}

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
    fill_fast(dst, static_cast<uint8_t>(vm->registers.regs[o.b].qword() & 0xFF),
              n);
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
    move_fast(dst, src, n);
}

void vm_block_fill(ProcessVM &vm, uint64_t vaddr, uint8_t value, uint64_t len) {
    if (len == 0) return;
    uint8_t buf[kChunk];
    /* El patron se construye UNA vez y se reusa en cada pagina. */
    fill_fast(buf, value, len < kChunk ? len : kChunk);
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
     * equivalente por trozos de lo que hace @c move_fast dentro de un bloque, y
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
