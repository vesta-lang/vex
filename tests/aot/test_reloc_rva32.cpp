/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/aot/test_reloc_rva32.cpp
 * @brief La relocation RVA32: lo que escribe, y sobre todo lo que RECHAZA.
 *
 * POR QUE ESTE Y NO OTRO.  Las otras relocations escriben un valor y si sale
 * mal se nota: el programa salta a donde no es y muere.  Un RVA mal escrito no
 * hace eso -- va en una TABLA que nadie ejecuta --, asi que produce una entrada
 * bien formada que apunta a cualquier sitio, y quien la sigue es el
 * desenrollador del sistema, cuando ya hay un fallo entre manos.  El sintoma
 * seria un proceso que muere sin decir nada, que es justo lo que estas tablas
 * vienen a arreglar.
 *
 * De ahi que la mitad de las comprobaciones sean de casos que deben FALLAR:
 * truncar a 32 bits en silencio es la manera de convertir un error detectable
 * en uno que no lo es.
 */

#include "aot/aot_emit_shim.h"

/* El aplicador es una funcion en linea de la cabecera interna del emisor.  Se
 * incluye tal cual: probar lo que de verdad corre es el motivo de que este
 * fichero exista, y una copia aqui probaria la copia. */
#include "../../src/aot/common/aot_emit_internal.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

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

/// Lee los cuatro bytes que dejo la relocation, en little endian.
uint32_t leer32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

} // namespace

int main() {
    std::printf("== relocation RVA32 ==\n");

    const uint64_t BASE = 0x140000000ull; // base tipica de un PE de 64 bits

    // --- Lo que escribe --------------------------------------------------
    {
        uint8_t sitio[8];
        std::memset(sitio, 0xCC, sizeof(sitio));

        // Un objetivo 0x1234 por encima de la base da ese desplazamiento.
        CHECK(apply_reloc(sitio, BASE + 0x10, BASE + 0x1234, AOT_RELOC_RVA32,
                          BASE) == 1);
        CHECK(leer32(sitio) == 0x1234u);
        // Y no toca lo de al lado: son cuatro bytes, no ocho.
        CHECK(sitio[4] == 0xCC);

        // El propio comienzo de la imagen es el RVA cero, que es legitimo.
        CHECK(apply_reloc(sitio, BASE, BASE, AOT_RELOC_RVA32, BASE) == 1);
        CHECK(leer32(sitio) == 0u);

        // El ultimo que cabe: 4 GiB menos uno.
        CHECK(apply_reloc(sitio, BASE, BASE + 0xFFFFFFFFull, AOT_RELOC_RVA32,
                          BASE) == 1);
        CHECK(leer32(sitio) == 0xFFFFFFFFu);

        /* No depende de la VA del sitio, a diferencia de REL32.  Se comprueba
         * porque es la confusion natural entre las dos: un RVA es relativo a
         * la IMAGEN, no a donde se escribe. */
        CHECK(apply_reloc(sitio, BASE + 0x900000, BASE + 0x40, AOT_RELOC_RVA32,
                          BASE) == 1);
        CHECK(leer32(sitio) == 0x40u);
    }

    // --- Lo que rechaza, que es el motivo del fichero --------------------
    {
        uint8_t sitio[8];
        const uint8_t intacto = 0x5A;

        // Objetivo POR DEBAJO de la base: no tiene RVA.  Restar daria un
        // numero enorme que cabe en 32 bits despues de truncar, y ese es
        // exactamente el resultado plausible y falso que hay que evitar.
        std::memset(sitio, intacto, sizeof(sitio));
        CHECK(apply_reloc(sitio, BASE, BASE - 1, AOT_RELOC_RVA32, BASE) == 0);
        CHECK(sitio[0] == intacto); // y no escribio nada

        // Mas de 4 GiB por encima: no cabe en el campo.
        std::memset(sitio, intacto, sizeof(sitio));
        CHECK(apply_reloc(sitio, BASE, BASE + 0x100000000ull, AOT_RELOC_RVA32,
                          BASE) == 0);
        CHECK(sitio[0] == intacto);

        // Sin base de imagen -- un ELF, un objeto suelto --: no aplica.  Es lo
        // que impide que un emisor que no puede resolverla escriba la
        // direccion entera creyendo que es un desplazamiento.
        std::memset(sitio, intacto, sizeof(sitio));
        CHECK(apply_reloc(sitio, BASE, BASE + 0x10, AOT_RELOC_RVA32,
                          AOT_NO_IMAGE_BASE) == 0);
        CHECK(sitio[0] == intacto);
    }

    // --- Que no se haya roto ninguna de las otras ------------------------
    {
        /* La base es un parametro NUEVO en una funcion que ya existia; se
         * comprueba que las demas siguen ignorandola, para que anadirla no
         * haya cambiado nada por el camino. */
        uint8_t sitio[8];

        std::memset(sitio, 0, sizeof(sitio));
        CHECK(apply_reloc(sitio, 0x1000, 0x2000, AOT_RELOC_REL32,
                          AOT_NO_IMAGE_BASE) == 1);
        CHECK(leer32(sitio) == 0x2000u - (0x1000u + 4u));

        std::memset(sitio, 0, sizeof(sitio));
        CHECK(apply_reloc(sitio, 0x1000, 0xABCD, AOT_RELOC_IMM32, BASE) == 1);
        CHECK(leer32(sitio) == 0xABCDu); // el valor entero, sin restar la base

        std::memset(sitio, 0, sizeof(sitio));
        CHECK(apply_reloc(sitio, 0x1000, BASE + 8, AOT_RELOC_ABS64, BASE) == 1);
        CHECK(leer32(sitio) == (uint32_t)((BASE + 8) & 0xFFFFFFFFull));
        CHECK(leer32(sitio + 4) == (uint32_t)((BASE + 8) >> 32));

        // Y un kind que no existe sigue devolviendo 0.
        CHECK(apply_reloc(sitio, 0, 0, 99, BASE) == 0);
    }

    std::printf("--- %d checks, %d fallos ---\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
