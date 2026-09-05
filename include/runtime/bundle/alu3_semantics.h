/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/alu3_semantics.h
 * @brief Que calcula, y que banderas deja, cada ALU de tres operandos.
 *
 * POR QUE ESTA APARTE
 * -------------------
 * Lo usan DOS: el manejador de `adds3`..`xor3` (0x73-0x7B) y las instrucciones
 * SINTETICAS que el fusionador construye encadenando dos de ellas.  Escrito dos
 * veces se separaria en cuanto alguien tocara una bandera, y el modo de fallar
 * es el peor de todos: el mismo programa daria un resultado interpretado suelto
 * y otro dentro de un paquete, sin que nada avise.
 *
 * ESTA PENSADO PARA DESAPARECER AL COMPILAR
 * -----------------------------------------
 * El `switch` es sobre @p opc, y cuando quien llama pasa una constante -- que es
 * lo que hace la version sintetica, especializada por plantilla -- el compilador
 * se queda con la rama que toca y borra el resto.  La sintetica acaba siendo
 * literalmente un `add` y un `xor`, sin mirar ningun byte de operacion ni
 * ejecutar ninguna rama.  Por eso es una funcion `always_inline` con el opcode
 * por argumento, y no una tabla de punteros: un puntero no se puede plegar.
 */

#ifndef VESTA_RUNTIME_ALU3_SEMANTICS_H
#define VESTA_RUNTIME_ALU3_SEMANTICS_H

#include <cstdint>

#include "runtime/rflags.h"

namespace runtime {

/// Opcodes de la familia de tres operandos, para indexar sin escribirlos.
constexpr uint8_t kAlu3First = 0x73; ///< `adds3`
constexpr uint8_t kAlu3Last = 0x7B;  ///< `xor3`
constexpr uint32_t kAlu3Count = kAlu3Last - kAlu3First + 1; // nueve

/**
 * @brief El resultado de una ALU de tres operandos, y los bits CF/OF que deja.
 *
 * ZF y SF no salen de aqui: son iguales en las nueve y los calcula quien
 * escribe las banderas, de una vez y con un store puro.
 *
 * @param opc    Opcode de la familia (0x73-0x7B).  Constante en el camino
 *               sintetico, variable en el manejador normal.
 * @param a      Primera fuente.
 * @param b      Segunda fuente.
 * @param cf_of  Sale con @c RF_CF o @c RF_OF si la operacion los levanta.
 * @return El resultado de 64 bits.
 */
[[gnu::always_inline]] inline uint64_t alu3_apply(uint8_t opc, uint64_t a,
                                                  uint64_t b, uint8_t &cf_of) {
    cf_of = 0;
    switch (opc) {
    case 0x73:
    case 0x76: { // adds3 / addu3
        const uint64_t res = a + b;
        if (opc == 0x73) {
            if (((static_cast<int64_t>(a) ^ static_cast<int64_t>(res)) &
                 (static_cast<int64_t>(b) ^ static_cast<int64_t>(res))) < 0)
                cf_of = RF_OF; // con signo: desborda, y no toca CF
        } else if (res < a) {
            cf_of = RF_CF; // sin signo: acarreo, y no toca OF
        }
        return res;
    }
    case 0x74:
    case 0x77: { // subs3 / subu3
        const uint64_t res = a - b;
        if (opc == 0x74) {
            if (((static_cast<int64_t>(a) ^ static_cast<int64_t>(b)) &
                 (static_cast<int64_t>(a) ^ static_cast<int64_t>(res))) < 0)
                cf_of = RF_OF;
        } else if (a < b) {
            cf_of = RF_CF;
        }
        return res;
    }
    case 0x75: // muls3
        return static_cast<uint64_t>(static_cast<int64_t>(a) *
                                     static_cast<int64_t>(b));
    case 0x78: return a * b; // mulu3
    case 0x79: return a & b; // and3
    case 0x7A: return a | b; // or3
    case 0x7B: return a ^ b; // xor3
    default: return 0;       // opcode que no es de esta familia
    }
}

/// Las banderas que deja un resultado: ZF y SF, mas los CF/OF que traiga.
/// Store PURO, sin leer el valor anterior: ver `rflags.h`.
[[gnu::always_inline]] inline uint8_t alu3_flags(uint64_t res, uint8_t cf_of) {
    uint8_t nf = cf_of;
    if (res == 0) nf |= RF_ZF;
    if (static_cast<int64_t>(res) < 0) nf |= RF_SF;
    return nf;
}

} // namespace runtime

#endif // VESTA_RUNTIME_ALU3_SEMANTICS_H
