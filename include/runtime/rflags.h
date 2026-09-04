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

/**                                                                            \
 * @file rflags.h                                                              \
 * @brief Registro de flags de la maquina virtual de VestaVM.                  \
 *                                                                             \
 * Define @c RFlags: union que expone los flags SF, ZF, CF, OF, DM             \
 * tanto como bits individuales (a traves de un bitfield) como valor           \
 * completo de 64 bits.                                                        \
 */                                                                            \
#ifndef RFLAGS_H
#define RFLAGS_H

#include <cstdint>

/**
 * @brief Registro de banderas de la maquina virtual.
 *
 * Agrupa en una union el acceso bit a bit (campo bits) y el acceso
 * completo como entero de 64 bits (campo raw).  Los cinco bits
 * definidos son:
 *   - SF (bit 0): bandera de signo; 1 si el resultado es negativo.
 *   - ZF (bit 1): bandera de cero; 1 si el resultado es cero.
 *   - CF (bit 2): bandera de acarreo; 1 si hubo carry/borrow.
 *   - OF (bit 3): bandera de desbordamiento con signo.
 *   - DM (bit 4): bandera de modo distribuido.
 */
/**
 * @defgroup RF_bits Posiciones de las banderas ARITMETICAS dentro de `arith`
 * @brief Las cuatro que produce una operacion, para poder componerlas en un
 *        registro y escribirlas de una sola vez.
 * @{
 */
enum : uint8_t {
    RF_SF = 1u << 0, ///< signo
    RF_ZF = 1u << 1, ///< cero
    RF_CF = 1u << 2, ///< acarreo
    RF_OF = 1u << 3, ///< desbordamiento con signo
};
/** @} */

/**
 * @brief Registro de banderas de la maquina virtual.
 *
 * POR QUE DM VIVE APARTE, que es lo unico raro de esta estructura.
 *
 * Las cuatro banderas ARITMETICAS comparten un byte (@c arith) y el modo
 * distribuido NO esta con ellas, aunque en el valor observable de `raw` siga
 * ocupando el bit 4 como siempre.
 *
 * Antes las cinco estaban en el mismo campo de bits, y eso tenia un precio que
 * no se veia leyendo el codigo: `flags.bits.ZF = x` sobre un campo de bits no
 * es una escritura, es un LEE-MODIFICA-ESCRIBE del byte entero.  Cada
 * operacion ALU hacia CUATRO, una por bandera, y las cuatro sobre la misma
 * direccion -- o sea encadenadas por el reenvio de almacen a carga, cada una
 * esperando a la anterior.  Medido con VTune sobre `test_mips`: 6,73 s de unos
 * 25, el 27% del interprete, calculando banderas de `adds` y `subs`.
 *
 * Y habia una segunda consecuencia, peor que la lentitud.  El derivador de
 * efectos camina el codigo maquina de los manejadores, ve ese lee-modifica-
 * escribe y concluye -- correctamente, a su nivel -- que `add` LEE las
 * banderas.  La tabla generada marcaba `add`, `sub`, `xor`, `adds3`... con
 * `VE_R_FLAGS`, que semanticamente es falso: un `add` no lee banderas.  Como
 * esa tabla es de donde sale si dos instrucciones son independientes, cada par
 * de operaciones aritmeticas parecia dependiente entre si por las banderas, y
 * eso es justo lo que impide reordenar al formar un paquete.
 *
 * Con DM fuera, una operacion aritmetica escribe `arith` de una vez y sin
 * leerlo: un store puro, sin cadena de dependencias y sin lectura que el
 * derivador pueda ver.
 *
 * El valor de `raw` NO cambia: se recompone con DM en el bit 4, porque el
 * bytecode lo expone como registro especial (RFLAGS) y ahi si es ABI.
 */
typedef struct RFlags_t {
    union {
        struct {
            uint8_t SF : 1; ///< Bandera de signo: 1 si el resultado es negativo
            uint8_t ZF : 1; ///< Bandera de cero: 1 si el resultado es cero
            uint8_t CF : 1; ///< Bandera de acarreo: 1 si hubo carry o borrow
            uint8_t OF : 1; ///< Bandera de desbordamiento: 1 si hubo overflow
                            ///< con signo
        } bits;             ///< Acceso individual a cada bandera aritmetica

        uint8_t arith; ///< Las cuatro de golpe.  Escribirlo es un store PURO.
    };

    /// Modo distribuido: 1 activa semantica distribuida.  Fuera del byte
    /// aritmetico a proposito (ver la explicacion de arriba).  Nadie lo
    /// escribe hoy; se lee en `movc`, en el volcado del proceso y en el
    /// depurador.
    uint8_t DM;

    /// @brief Valor observable de 64 bits.  SF=0, ZF=1, CF=2, OF=3, DM=4.
    uint64_t raw() const {
        return (uint64_t)arith | ((uint64_t)(DM & 1u) << 4);
    }

    /// @brief Fija las banderas desde el valor observable de 64 bits.
    void set_raw(uint64_t v) {
        arith = (uint8_t)(v & 0x0Fu);
        DM = (uint8_t)((v >> 4) & 1u);
    }
} RFlags_t;

/**
 * @defgroup COND_macros Macros de condicion sobre RFlags_t
 * @brief Evaluan combinaciones de banderas para implementar ramas
 * condicionales.
 *
 * Cada macro recibe el campo bits del RFlags_t y devuelve una expresion
 * booleana que refleja la condicion aritmetica correspondiente.
 * @{
 */

/** @brief Igual (==): ZF=1 -> el resultado fue cero -> lhs == rhs */
#define COND_EQ(flags) ((flags).ZF == 1)

/** @brief No igual (!=): ZF=0 -> el resultado no fue cero -> lhs != rhs */
#define COND_NE(flags) ((flags).ZF == 0)

/** @brief Carry set: CF=1 -> hubo acarreo -> lhs >= rhs (unsigned) */
#define COND_CS(flags) ((flags).CF == 1)

/** @brief Carry clear: CF=0 -> sin acarreo -> lhs < rhs (unsigned) */
#define COND_CC(flags) ((flags).CF == 0)

/** @brief Minus: SF=1 -> resultado negativo -> lhs < rhs (signed) */
#define COND_MI(flags) ((flags).SF == 1)

/** @brief Plus: SF=0 -> resultado no negativo -> lhs >= 0 */
#define COND_PL(flags) ((flags).SF == 0)

/** @brief Overflow set: OF=1 -> desbordamiento aritmetico con signo */
#define COND_VS(flags) ((flags).OF == 1)

/** @brief Overflow clear: OF=0 -> sin desbordamiento con signo */
#define COND_VC(flags) ((flags).OF == 0)

/** @brief Unsigned higher: CF=1 y ZF=0 -> lhs > rhs (unsigned) */
#define COND_HI(flags) ((flags).CF == 1 && (flags).ZF == 0)

/** @brief Unsigned lower or same: CF=0 o ZF=1 -> lhs <= rhs (unsigned) */
#define COND_LS(flags) ((flags).CF == 0 || (flags).ZF == 1)

/** @brief Signed greater or equal: SF==OF -> lhs >= rhs (signed) */
#define COND_GE(flags) ((flags).SF == (flags).OF)

/** @brief Signed less than: SF!=OF -> lhs < rhs (signed) */
#define COND_LT(flags) ((flags).SF != (flags).OF)

/** @brief Signed greater than: ZF=0 y SF==OF -> lhs > rhs (signed) */
#define COND_GT(flags) ((flags).ZF == 0 && (flags).SF == (flags).OF)

/** @brief Signed less or equal: ZF=1 o SF!=OF -> lhs <= rhs (signed) */
#define COND_LE(flags) ((flags).ZF == 1 || (flags).SF != (flags).OF)

/** @} */ // fin del grupo COND_macros

#endif // RFLAGS_H
