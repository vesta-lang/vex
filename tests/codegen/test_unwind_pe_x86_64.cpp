/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/codegen/test_unwind_pe_x86_64.cpp
 * @brief El codificador de @c UNWIND_INFO: que escribe, y cuando NO escribe.
 *
 * Se comprueban los BYTES, uno a uno, y no que la funcion devuelva true.  El
 * consumidor de esto no es codigo nuestro: es el desenrollador del sistema, que
 * no valida nada y se cree lo que lea.  Una descripcion mal formada no da un
 * error, da un salto a una direccion inventada -- que es exactamente el fallo
 * que esta capa existe para evitar --, asi que "compila y devuelve true" no
 * dice nada.
 *
 * Y se comprueba tanto lo que emite como lo que CALLA.  Los cuatro casos en los
 * que no hay que describir nada son parte del contrato, no atajos: si el
 * codificador emitiera una descripcion vacia donde debe callarse, el sistema
 * dejaria de aplicar su suposicion de hoja -- que ahi es la correcta -- y
 * pasaria a seguir una tabla que no dice la verdad.
 *
 * Este fichero NO depende de Windows: el codificador se compila en cualquier
 * anfitrion porque el AOT genera PE desde Linux.  Que el test corra en los dos
 * sitios es parte de lo que se esta comprobando.
 */

#include "codegen/unwind/pe_x86_64.h"

#include <cstdio>
#include <vector>

using codegen::FrameOp;
using codegen::FrameUnwind;
using codegen::unwind::build_pe_x86_64;

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

/* Numeracion de MReg, repetida aqui a proposito: el codificador NO la conoce
 * -- recibe el numero del objetivo y lo escribe --, asi que el test tampoco
 * debe incluir la cabecera del JIT para saberla.  Si algun dia cambia, este
 * fichero seguira comprobando lo que comprueba: que el numero que entra es el
 * que sale. */
constexpr uint32_t RBX = 3;
constexpr uint32_t RBP = 5;
constexpr uint32_t R12 = 12;
constexpr uint32_t XMM0 = 16;

/// Codigos de operacion, para leer las aserciones sin contar bits.
constexpr uint8_t UWOP_PUSH_NONVOL = 0;
constexpr uint8_t UWOP_ALLOC_LARGE = 1;
constexpr uint8_t UWOP_ALLOC_SMALL = 2;
constexpr uint8_t UWOP_SET_FPREG = 3;

/// El byte de operacion, que empaqueta el codigo y su informacion.
constexpr uint8_t opbyte(uint8_t op, uint8_t info) {
    return static_cast<uint8_t>(op | (info << 4));
}

/// Un prologo tipico: `push rbp ; mov rbp, rsp ; sub rsp, n`.
FrameUnwind typical(uint32_t prologue_bytes, uint32_t stack) {
    FrameUnwind f;
    f.prologue_bytes = prologue_bytes;
    f.ops.push_back({FrameOp::Kind::SaveReg, RBP, 0});
    f.ops.push_back({FrameOp::Kind::SetFramePointer, RBP, 0});
    if (stack > 0) f.ops.push_back({FrameOp::Kind::AllocStack, 0, stack});
    return f;
}

} // namespace

int main() {
    std::printf("== codificador UNWIND_INFO (PE x86-64) ==\n");

    // --- Cuando NO hay que describir nada -------------------------------
    {
        std::vector<uint8_t> out;

        // El cuerpo es dueno de su pila: describirlo seria mentir.
        FrameUnwind naked = typical(9, 32);
        naked.owns_stack = true;
        CHECK(!build_pe_x86_64(naked, out));
        CHECK(out.empty());

        // Nadie midio el prologo: la suposicion de hoja del sistema es la
        // correcta, asi que callarse es lo acertado.
        CHECK(!build_pe_x86_64(typical(0, 32), out));
        CHECK(out.empty());

        // El prologo no cabe en el campo del formato (un byte).
        CHECK(!build_pe_x86_64(typical(256, 32), out));
        CHECK(out.empty());

        // Un prologo medido pero que no hizo nada tampoco se describe.
        FrameUnwind vacio;
        vacio.prologue_bytes = 4;
        CHECK(!build_pe_x86_64(vacio, out));
        CHECK(out.empty());

        // Y el borde de arriba SI vale: 255 es el ultimo que cabe.
        CHECK(build_pe_x86_64(typical(255, 32), out));
        CHECK(!out.empty() && out[1] == 255);
    }

    // --- El prologo tipico, byte a byte ---------------------------------
    {
        std::vector<uint8_t> out;
        CHECK(build_pe_x86_64(typical(9, 32), out));

        /* Tres codigos de una ranura cada uno: la cabecera son 4 bytes y cada
         * ranura dos. */
        CHECK(out.size() == 4u + 2u * 3u);
        CHECK(out[0] == 1);   // version 1, sin banderas
        CHECK(out[1] == 9);   // donde acaba el prologo
        CHECK(out[2] == 3);   // ranuras
        CHECK(out[3] == RBP); // registro de marco, desplazamiento 0

        /* Van del FINAL del prologo hacia el principio, que es el orden en que
         * el desenrollador los aplica para deshacerlo.  O sea, al reves de como
         * se ejecutaron. */
        CHECK(out[4] == 9);
        CHECK(out[5] == opbyte(UWOP_ALLOC_SMALL, 32 / 8 - 1)); // sub rsp, 32
        CHECK(out[6] == 9);
        CHECK(out[7] == opbyte(UWOP_SET_FPREG, 0)); // mov rbp, rsp
        CHECK(out[8] == 9);
        CHECK(out[9] == opbyte(UWOP_PUSH_NONVOL, RBP)); // push rbp
    }

    // --- Las tres formas de describir la reserva de pila -----------------
    {
        std::vector<uint8_t> out;

        // Hasta 128 bytes y multiplo de 8: cabe en el propio codigo.
        CHECK(build_pe_x86_64(typical(9, 128), out));
        CHECK(out[5] == opbyte(UWOP_ALLOC_SMALL, 128 / 8 - 1));
        CHECK(out[2] == 3); // sigue siendo una ranura por codigo

        // Multiplo de 8 pero mayor: una ranura extra, el tamano en RANURAS.
        CHECK(build_pe_x86_64(typical(9, 136), out));
        CHECK(out[2] == 4); // una ranura mas que antes
        CHECK(out[5] == opbyte(UWOP_ALLOC_LARGE, 0));
        CHECK(out[6] == (136 / 8) % 256); // little endian, parte baja
        CHECK(out[7] == (136 / 8) / 256);

        // No multiplo de 8: dos ranuras extra, y el tamano en BYTES.
        CHECK(build_pe_x86_64(typical(9, 12), out));
        CHECK(out[2] == 5); // dos ranuras mas que el caso pequeno
        CHECK(out[5] == opbyte(UWOP_ALLOC_LARGE, 1));
        CHECK(out[6] == 12 && out[7] == 0);
        CHECK(out[8] == 0 && out[9] == 0); // parte alta

        // Y una reserva de cero no produce codigo, pero no invalida el resto.
        FrameUnwind sin_pila = typical(4, 0);
        CHECK(build_pe_x86_64(sin_pila, out));
        CHECK(out[2] == 2); // solo el push y el mov
    }

    // --- Registros: el orden y quien queda fuera ------------------------
    {
        std::vector<uint8_t> out;

        /* Prologo completo: push rbp ; mov rbp,rsp ; push rbx ; push r12 ;
         * sub rsp, 16.  Se comprueba que salen al reves y con su numero. */
        FrameUnwind f;
        f.prologue_bytes = 16;
        f.ops.push_back({FrameOp::Kind::SaveReg, RBP, 0});
        f.ops.push_back({FrameOp::Kind::SetFramePointer, RBP, 0});
        f.ops.push_back({FrameOp::Kind::SaveReg, RBX, 0});
        f.ops.push_back({FrameOp::Kind::SaveReg, R12, 0});
        f.ops.push_back({FrameOp::Kind::AllocStack, 0, 16});

        CHECK(build_pe_x86_64(f, out));
        CHECK(out[2] == 5);
        CHECK(out[5] == opbyte(UWOP_ALLOC_SMALL, 16 / 8 - 1));
        CHECK(out[7] == opbyte(UWOP_PUSH_NONVOL, R12));
        CHECK(out[9] == opbyte(UWOP_PUSH_NONVOL, RBX));
        CHECK(out[11] == opbyte(UWOP_SET_FPREG, 0));
        CHECK(out[13] == opbyte(UWOP_PUSH_NONVOL, RBP));

        /* Un registro del banco ancho no se describe con PUSH_NONVOL: se salva
         * de otra forma y meterlo aqui daria un numero de registro que no es.
         * Se ignora, y lo demas sigue saliendo. */
        FrameUnwind con_xmm;
        con_xmm.prologue_bytes = 8;
        con_xmm.ops.push_back({FrameOp::Kind::SaveReg, RBP, 0});
        con_xmm.ops.push_back({FrameOp::Kind::SaveReg, XMM0, 0});
        CHECK(build_pe_x86_64(con_xmm, out));
        CHECK(out[2] == 1); // solo RBP
        CHECK(out[5] == opbyte(UWOP_PUSH_NONVOL, RBP));

        /* Sin puntero de marco, el campo del registro queda a cero: no es "el
         * registro 0", es "no hay". */
        FrameUnwind sin_fp;
        sin_fp.prologue_bytes = 4;
        sin_fp.ops.push_back({FrameOp::Kind::SaveReg, RBX, 0});
        CHECK(build_pe_x86_64(sin_fp, out));
        CHECK(out[3] == 0);
    }

    // --- El tope de ranuras ---------------------------------------------
    {
        std::vector<uint8_t> out;
        const uint32_t max = codegen::unwind::PE_X86_64_MAX_SLOTS;

        // Justo en el tope: entra.
        FrameUnwind lleno;
        lleno.prologue_bytes = 200;
        for (uint32_t i = 0; i < max; ++i)
            lleno.ops.push_back({FrameOp::Kind::SaveReg, i % 16, 0});
        CHECK(build_pe_x86_64(lleno, out));
        CHECK(out[2] == max);
        CHECK(out.size() == 4u + 2u * max);

        // Una mas: se niega, y no deja nada a medias.
        lleno.ops.push_back({FrameOp::Kind::SaveReg, RBX, 0});
        CHECK(!build_pe_x86_64(lleno, out));
        CHECK(out.empty());
    }

    // --- La salida se sobrescribe, no se acumula ------------------------
    {
        /* Quien llama reutiliza el vector entre funciones; si el codificador
         * anadiera en vez de sobrescribir, la segunda descripcion llevaria la
         * primera pegada delante y el sistema leeria basura. */
        std::vector<uint8_t> out;
        CHECK(build_pe_x86_64(typical(9, 32), out));
        const size_t primera = out.size();
        CHECK(build_pe_x86_64(typical(9, 32), out));
        CHECK(out.size() == primera);

        // Y un fallo tras un exito tampoco deja el anterior.
        CHECK(!build_pe_x86_64(typical(0, 32), out));
        CHECK(out.empty());
    }

    std::printf("--- %d checks, %d fallos ---\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
