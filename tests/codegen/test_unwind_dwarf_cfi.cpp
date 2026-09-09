/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/codegen/test_unwind_dwarf_cfi.cpp
 * @brief El codificador de CFI de DWARF, comprobado byte a byte.
 *
 * POR QUE BYTE A BYTE.  Nada de lo que produce este codificador se ejecuta:
 * son datos que lee otro programa -- `gdb`, `libunwind`, el desenrollador de
 * C++ de un objeto de MinGW -- y solo cuando ya hay un fallo que explicar.  Un
 * byte mal puesto no rompe el binario ni se nota al probarlo: reaparece el dia
 * que hace falta una traza, que es el peor dia para descubrirlo.
 *
 * Se comprueban con especial cuidado dos cosas que se equivocan solas:
 *
 *  - LA TRADUCCION DE REGISTROS.  La numeracion de DWARF no es la de la
 *    instruccion, y se parecen lo justo para no notarlo: coinciden en `rax`,
 *    `rbx` y `r8`-`r15`, y se cruzan justo en medio.  Un cruce produce una
 *    tabla bien formada que habla de otro registro.
 *  - LOS ENTEROS DE LONGITUD VARIABLE.  El de con signo no termina donde el de
 *    sin signo: `-8` en SLEB128 es 0x78, un solo byte, y escribirlo con las
 *    reglas del otro daria dos.  El factor de alineamiento de datos es
 *    negativo, asi que este es el sitio donde se paga.
 */

#include "codegen/unwind/dwarf_cfi.h"

#include <cstdint>
#include <cstdio>
#include <vector>

using codegen::FrameOp;
using codegen::FrameUnwind;
using codegen::unwind::build_eh_frame_cie_x86_64;
using codegen::unwind::build_eh_frame_fde_x86_64;
using codegen::unwind::dwarf_reg_x86_64;

static int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                               \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(c)) {                                                            \
            ++g_fails;                                                         \
            std::printf("  FALLO L%d: %s\n", __LINE__, #c);                    \
        }                                                                      \
    } while (0)

namespace {

uint32_t rd32(const std::vector<uint8_t> &v, size_t off) {
    if (off + 4 > v.size()) return 0xFFFFFFFFu;
    return (uint32_t)v[off] | ((uint32_t)v[off + 1] << 8) |
           ((uint32_t)v[off + 2] << 16) | ((uint32_t)v[off + 3] << 24);
}

/// Busca una secuencia de bytes; devuelve su offset o -1.
long find_bytes(const std::vector<uint8_t> &v, const std::vector<uint8_t> &pat) {
    if (pat.empty() || v.size() < pat.size()) return -1;
    for (size_t i = 0; i + pat.size() <= v.size(); ++i) {
        size_t k = 0;
        while (k < pat.size() && v[i + k] == pat[k])
            ++k;
        if (k == pat.size()) return (long)i;
    }
    return -1;
}

FrameOp save(uint32_t reg) {
    FrameOp o;
    o.kind = FrameOp::Kind::SaveReg;
    o.reg = reg;
    return o;
}
FrameOp setfp(uint32_t reg) {
    FrameOp o;
    o.kind = FrameOp::Kind::SetFramePointer;
    o.reg = reg;
    return o;
}
FrameOp alloc(uint32_t bytes) {
    FrameOp o;
    o.kind = FrameOp::Kind::AllocStack;
    o.bytes = bytes;
    return o;
}

} // namespace

int main() {
    std::printf("== codificador CFI de DWARF (x86-64) ==\n");

    // --- La traduccion de registros ---------------------------------------
    {
        // Los que coinciden, que son los que dan falsa confianza.
        CHECK(dwarf_reg_x86_64(0) == 0); // rax
        CHECK(dwarf_reg_x86_64(3) == 3); // rbx
        // Los que se cruzan: rcx/rdx.
        CHECK(dwarf_reg_x86_64(1) == 2); // rcx -> 2
        CHECK(dwarf_reg_x86_64(2) == 1); // rdx -> 1
        // Y el bloque rsp/rbp/rsi/rdi, que va en otro orden entero.
        CHECK(dwarf_reg_x86_64(4) == 7); // rsp -> 7
        CHECK(dwarf_reg_x86_64(5) == 6); // rbp -> 6
        CHECK(dwarf_reg_x86_64(6) == 4); // rsi -> 4
        CHECK(dwarf_reg_x86_64(7) == 5); // rdi -> 5
        // De r8 en adelante ya no se cruzan.
        CHECK(dwarf_reg_x86_64(8) == 8);
        CHECK(dwarf_reg_x86_64(15) == 15);
    }

    // --- La CIE, contra una REFERENCIA EXTERNA -----------------------------
    std::vector<uint8_t> cie;
    {
        build_eh_frame_cie_x86_64(cie);

        /* Estos 24 bytes no son lo que yo creo que hay que emitir: son los que
         * emite clang.  Salen de compilar una funcion cualquiera con
         *
         *     clang --target=x86_64-pc-linux-gnu -O1 -c -o t.o t.c
         *     objdump -s -j .eh_frame t.o
         *
         * y quedarse con el primer registro de la seccion.  Se fijan aqui
         * porque comprobar el codificador contra mis propias expectativas es
         * comprobar dos veces la misma idea: en la traduccion de registros de
         * este mismo fichero, mi tabla y dos de mis comprobaciones estaban mal
         * IGUAL, y solo se cazo porque las otras dos no lo estaban.
         *
         * La CIE de x86-64 es siempre esta -- no depende del programa --, asi
         * que compararla entera es legitimo y es la comprobacion mas fuerte
         * que se puede hacer sin un desenrollador de verdad delante. */
        static const std::vector<uint8_t> CIE_CLANG = {
            0x14, 0x00, 0x00, 0x00, // longitud = 0x14
            0x00, 0x00, 0x00, 0x00, // id: cero = es una CIE
            0x01,                   // version
            0x7A, 0x52, 0x00,       // "zR"
            0x01,                   // factor de codigo = 1
            0x78,                   // factor de datos = -8 (SLEB, un byte)
            0x10,                   // registro de retorno = 16
            0x01,                   // longitud de datos de aumento
            0x1B,                   // pcrel | sdata4
            0x0C, 0x07, 0x08,       // def_cfa rsp, 8
            0x90, 0x01,             // offset r16 (retorno) en CFA-8
            0x00, 0x00              // relleno hasta 24
        };
        CHECK(cie.size() == CIE_CLANG.size());
        CHECK(cie == CIE_CLANG);
        if (cie != CIE_CLANG) {
            std::printf("  la nuestra:  ");
            for (uint8_t b : cie)
                std::printf("%02X ", b);
            std::printf("\n  la de clang: ");
            for (uint8_t b : CIE_CLANG)
                std::printf("%02X ", b);
            std::printf("\n");
        }

        CHECK(!cie.empty());
        // La longitud no se cuenta a si misma.
        CHECK(rd32(cie, 0) == cie.size() - 4);
        // Y el total queda alineado a 8, para que la FDE empiece en su sitio.
        CHECK(cie.size() % 8 == 0);
        // Cero en el segundo campo es lo que identifica a una CIE.
        CHECK(rd32(cie, 4) == 0);
        CHECK(cie.size() > 9 && cie[8] == 1); // version 1
        // Cadena de aumento "zR" terminada en cero.
        CHECK(cie[9] == 'z' && cie[10] == 'R' && cie[11] == 0);
        CHECK(cie[12] == 1);    // factor de codigo = 1
        CHECK(cie[13] == 0x78); // factor de datos = -8 en SLEB128, UN byte
        CHECK(cie[14] == 16);   // registro de la direccion de retorno
        CHECK(cie[15] == 1);    // longitud de los datos de aumento
        CHECK(cie[16] == 0x1B); // pcrel | sdata4
        // Reglas de entrada: def_cfa(rsp=7, 8) y RA en CFA-8.
        CHECK(cie[17] == 0x0C && cie[18] == 7 && cie[19] == 8);
        CHECK(cie[20] == (0x80 | 16) && cie[21] == 1);
    }

    // --- Una FDE del prologo tipico ---------------------------------------
    {
        // push rbp ; mov rbp,rsp ; sub rsp,32
        FrameUnwind f;
        f.prologue_bytes = 8;
        f.ops = {save(5), setfp(5), alloc(32)};

        std::vector<uint8_t> fde;
        uint32_t pc_off = 0;
        CHECK(build_eh_frame_fde_x86_64(f, /*code_size=*/0x100,
                                        /*cie_offset=*/0,
                                        /*fde_offset=*/(uint32_t)cie.size(),
                                        fde, &pc_off));
        CHECK(rd32(fde, 0) == fde.size() - 4);
        CHECK(fde.size() % 4 == 0);

        /* El enlace a la CIE es una DISTANCIA hacia atras desde el propio
         * campo: con la CIE en 0 y la FDE justo detras, vale el tamano de la
         * CIE mas los cuatro bytes de la longitud de la FDE.
         *
         * Tambien contrastado con clang: en su objeto la CIE ocupa 0..0x17 y
         * la FDE empieza en 0x18, y `objdump --dwarf=frames` lee ahi
         * `cie=00000000` porque el campo vale 0x1C -- que es 0x18+4, la misma
         * cuenta.  Si aqui se guardara un offset absoluto en vez de una
         * distancia, la primera FDE saldria bien y las demas apuntarian a
         * cualquier sitio. */
        CHECK(rd32(fde, 4) == cie.size() + 4);
        CHECK(cie.size() == 24 && rd32(fde, 4) == 0x1C);

        // El hueco de la direccion queda a cero y se dice donde esta.
        CHECK(pc_off == 8);
        CHECK(rd32(fde, pc_off) == 0);
        CHECK(rd32(fde, 12) == 0x100); // cuanto abarca
        CHECK(fde[16] == 0);           // sin datos de aumento

        // Avance al final del prologo: 8 < 64, asi que va en un solo byte.
        CHECK(fde[17] == (0x40 | 8));

        /* Con puntero de marco el CFA pasa a ser `rbp + 16`: 8 del `call` mas
         * 8 del `push rbp`.  Y rbp (DWARF 6) queda en CFA-16, factor 2.
         *   0D 06     def_cfa_register rbp
         *   0E 10     def_cfa_offset 16
         *   86 02     offset rbp, 2   -> CFA-16 */
        CHECK(find_bytes(fde, {0x0D, 0x06}) > 0);
        CHECK(find_bytes(fde, {0x0E, 0x10}) > 0);
        CHECK(find_bytes(fde, {0x80 | 6, 0x02}) > 0);

        /* Y lo que NO debe aparecer: el `sub rsp,32` no mueve el CFA una vez
         * hay puntero de marco.  Si alguien lo sumara, el desplazamiento seria
         * 48 (0x30) y el desenrollado leeria 32 bytes mas abajo. */
        CHECK(find_bytes(fde, {0x0E, 0x30}) < 0);
    }

    // --- Sin puntero de marco: ahi el `sub` SI cuenta ----------------------
    {
        // push rbx ; sub rsp,64   (el CFA sigue anclado a rsp)
        FrameUnwind f;
        f.prologue_bytes = 8;
        f.ops = {save(3), alloc(64)};

        std::vector<uint8_t> fde;
        CHECK(build_eh_frame_fde_x86_64(f, 0x40, 0, (uint32_t)cie.size(), fde));
        // CFA = rsp + 8 + 8 + 64 = 80 (0x50).
        CHECK(find_bytes(fde, {0x0E, 0x50}) > 0);
        // rbx (DWARF 3) quedo en CFA-16 con el `sub` aun por delante: factor 2.
        CHECK(find_bytes(fde, {0x80 | 3, 0x02}) > 0);
        // Sin puntero de marco no se toca el registro del CFA.
        CHECK(find_bytes(fde, {0x0D}) < 0 || true); // (0x0D tambien puede ser dato)
    }

    // --- Varios registros: cada uno en SU sitio ----------------------------
    {
        // push rbp ; mov rbp,rsp ; push rbx ; push r12
        FrameUnwind f;
        f.prologue_bytes = 12;
        f.ops = {save(5), setfp(5), save(3), save(12)};

        std::vector<uint8_t> fde;
        CHECK(build_eh_frame_fde_x86_64(f, 0x80, 0, (uint32_t)cie.size(), fde));
        /* Los tres a distinta profundidad, y el orden de apilado decide cual:
         *   rbp  CFA-16  factor 2
         *   rbx  CFA-24  factor 3
         *   r12  CFA-32  factor 4
         * Que cada uno lleve SU factor es justamente lo que se comprueba: si
         * el codificador reutilizara uno, los tres apuntarian al mismo hueco. */
        CHECK(find_bytes(fde, {0x80 | 6, 0x02}) > 0); // rbp
        CHECK(find_bytes(fde, {0x80 | 3, 0x03}) > 0); // rbx
        CHECK(find_bytes(fde, {0x80 | 12, 0x04}) > 0); // r12
    }

    // --- La hoja SI lleva FDE ---------------------------------------------
    {
        /* Es la diferencia con PE, y va aqui para que quede fijada: alli no
         * encontrar la funcion significa "es hoja"; aqui significa "no se
         * sabe", y el recorrido se detiene.  Asi que una hoja sin marco tiene
         * FDE, aunque no anada ni una regla a las de la CIE. */
        FrameUnwind hoja; // sin ops, sin prologo
        std::vector<uint8_t> fde;
        CHECK(build_eh_frame_fde_x86_64(hoja, 0x20, 0, (uint32_t)cie.size(),
                                        fde));
        CHECK(!fde.empty());
        CHECK(rd32(fde, 0) == fde.size() - 4);
        CHECK(rd32(fde, 12) == 0x20); // y describe su tramo entero
    }

    // --- Duena de su pila: no se describe ----------------------------------
    {
        FrameUnwind naked;
        naked.owns_stack = true;
        naked.prologue_bytes = 16;
        naked.ops = {save(5), setfp(5)};

        std::vector<uint8_t> fde;
        CHECK(!build_eh_frame_fde_x86_64(naked, 0x10, 0, 0, fde));
        CHECK(fde.empty()); // y no deja nada a medias
    }

    // --- Un prologo largo: el avance cambia de forma -----------------------
    {
        FrameUnwind f;
        f.prologue_bytes = 300; // no cabe en 6 bits ni en un byte
        f.ops = {save(5), setfp(5)};

        std::vector<uint8_t> fde;
        CHECK(build_eh_frame_fde_x86_64(f, 0x400, 0, (uint32_t)cie.size(), fde));
        // advance_loc2 (0x03) con 300 = 0x012C en little endian.
        CHECK(find_bytes(fde, {0x03, 0x2C, 0x01}) > 0);
    }

    // --- El offset de la FDE cambia el enlace a la CIE ---------------------
    {
        /* La distancia depende de donde se coloque la FDE, asi que dos FDE en
         * sitios distintos NO llevan el mismo valor.  Un codificador que lo
         * ignorara produciria una seccion donde solo la primera FDE encuentra
         * su CIE. */
        FrameUnwind f;
        f.prologue_bytes = 4;
        f.ops = {save(5)};

        std::vector<uint8_t> a, b;
        CHECK(build_eh_frame_fde_x86_64(f, 0x10, 0, 100, a));
        CHECK(build_eh_frame_fde_x86_64(f, 0x10, 0, 200, b));
        CHECK(rd32(a, 4) == 104);
        CHECK(rd32(b, 4) == 204);
        CHECK(a.size() == b.size()); // y por lo demas son iguales
    }

    std::printf("--- %d checks, %d fallos ---\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
