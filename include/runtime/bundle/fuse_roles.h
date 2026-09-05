/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/fuse_roles.h
 * @brief Que PAPEL puede jugar una instruccion en una fusion, en un byte.
 *
 * POR QUE UN PAPEL Y NO UNA PREGUNTA POR PAR
 * ------------------------------------------
 * Si un par se puede fusionar depende solo de QUE CLASE es cada una: un `mov`
 * reg,reg, una ALU de tres operandos, una carga, un `mov` con inmediato, un
 * acceso a memoria.  Esa clase no cambia entre preguntas.
 *
 * Y eso decide la forma del codigo.  El reordenador pregunta "si emito esta
 * detras de aquella, se fusionarian?" una vez POR CANDIDATA Y POR PASO --
 * cientos de veces por paquete --, asi que resolverlo con una llamada que
 * repita las comprobaciones seria pagar el analisis entero cada vez.
 * Clasificando UNA vez por instruccion, la pregunta del par queda en dos
 * lecturas de byte y unos ANDs, que es lo que ese bucle admite.
 *
 * El coste pasa de O(k^2) comprobaciones a O(k) clasificaciones mas O(1) por
 * par.
 *
 * QUE NO ES
 * ---------
 * No dice que la fusion vaya a cuajar: la vivacidad y los topes dependen del
 * contexto y los mira el fusionador despues.  Aqui sobra ser optimista --
 * acercar dos que al final no fusionan cuesta una reordenacion; no acercarlas
 * pierde la fusion entera --.
 */

#ifndef VESTA_RUNTIME_BUNDLE_FUSE_ROLES_H
#define VESTA_RUNTIME_BUNDLE_FUSE_ROLES_H

#include <cstdint>

#include "runtime/bundle/alu3_semantics.h"
#include "runtime/mem_full_semantics.h"
#include "runtime/proceso_runtime.h"

namespace runtime {

/// Los papeles.  Una instruccion puede tener VARIOS: `mld` es carga y ademas
/// acceso a memoria, y las dos cosas abren patrones distintos.
enum FuseRole : uint8_t {
    FR_NONE = 0,
    FR_MOV_REG = 1u << 0,  ///< `mov rd, rs` general de 64 bits
    FR_MOV_IMM = 1u << 1,  ///< `mov rd, K` general de 64 bits
    FR_ALU3 = 1u << 2,     ///< ALU de tres operandos (0x73-0x7B)
    FR_GP_LOAD = 1u << 3,  ///< `mld` al banco general
    FR_MEM = 1u << 4,      ///< `mld` o `mst` al banco general
    FR_ALU2 = 1u << 5,     ///< ALU de dos operandos con forma de tres
    FR_KILLS = 1u << 6,    ///< pisa su destino ENTERO, sin leerlo
};

/// Ancho de 64 bits en el campo `mode`.
constexpr uint8_t kFuseMode64 = 3;

/**
 * @brief Clasifica @p d.  Una pasada de comparaciones sobre campos de bits que
 *        ya estan en la misma palabra.
 */
[[gnu::always_inline]] inline uint8_t fuse_role(const DecodedInstr &d) {
    if (d.flags_info.is_not_extended != 0x00) return FR_NONE;
    // Una YA fusionada no vuelve a entrar: sus campos de opcode no la describen.
    if (d.flags_info.absorbed != 0) return FR_NONE;

    const uint8_t op = (uint8_t)d.flags_info.opcode_index;
    uint8_t r = FR_NONE;

    if (op == 0x14 && d.flags_info._signed_instruct == 0 &&
        d.flags_info.mode == kFuseMode64)
        r |= FR_MOV_REG;
    if (op == 0x15 && d.flags_info.direction == 0 &&
        d.flags_info._signed_instruct == 0 && d.flags_info.mode == kFuseMode64)
        r |= FR_MOV_IMM;
    if (op >= kAlu3First && op <= kAlu3Last) r |= (uint8_t)(FR_ALU3 | FR_KILLS);
    /* `loadz`/`loadzh` (0x7C/0x7D) tambien pisan el destino entero: existen
     * justamente para extender con ceros. */
    if (op == 0x7C || op == 0x7D) r |= FR_KILLS;
    if ((op == 0x90 || op == 0x91) &&
        (d.data_instruction.mem_full.flags & kMemFpBank) == 0) {
        r |= FR_MEM;
        /* `mld` escribe con `qword()` sea cual sea el ancho, asi que pisa el
         * registro ENTERO -- un `mld` de un byte deja los otros siete a cero o
         * a signo, nunca a lo que hubiera --. */
        if (op == 0x90) r |= (uint8_t)(FR_GP_LOAD | FR_KILLS);
    }
    /* ALU de dos operandos que TIENE variante de tres: es la segunda mitad del
     * patron `mov` + ALU.  Las seis con forma de tres operandos. */
    if ((op == 0x05 || op == 0x08 || op == 0x0B || op == 0x17 || op == 0x18 ||
         op == 0x19) &&
        d.flags_info.mode == kFuseMode64)
        r |= FR_ALU2;
    return r;
}

/**
 * @brief Podrian fusionarse una con papel @p a seguida de otra con papel @p b?
 *
 * Una fila por patron, y se lee como la lista de lo que el fusionador sabe
 * hacer.  Sin ramas dependientes de datos: son ANDs y un `or`.
 */
[[gnu::always_inline]] inline bool fuse_roles_pairable(uint8_t a, uint8_t b) {
    return ((a & FR_MOV_REG) && (b & FR_ALU2)) ||   // mov + ALU -> ALU de 3
           ((a & FR_KILLS) && (b & FR_MOV_REG)) ||  // redirigir el destino
           ((a & FR_ALU3) && (b & FR_ALU3)) ||      // dos ALU encadenadas
           ((a & FR_GP_LOAD) && (b & FR_ALU3)) ||   // cargar y operar
           ((a & FR_MOV_IMM) && (b & FR_ALU3)) ||   // operar con constante
           ((a & FR_MOV_REG) && (b & FR_MOV_REG)) || // tanda de `mov`
           ((a & FR_MEM) && (b & FR_MEM));           // tanda de memoria
}

} // namespace runtime

#endif // VESTA_RUNTIME_BUNDLE_FUSE_ROLES_H
