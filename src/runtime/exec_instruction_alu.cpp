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
/**
 * @file exec_instruction_alu.cpp
 * @brief Implementacion de las instrucciones ALU, logicas, saltos y movimiento
 * de VestaVM.
 *
 * Implementa las estructuras Op (AddOp, SubOp, CmpOp, MulOp, DivOp, AndOp,
 * OrOp, XorOp, ShlOp, ShrOp, SarOp, IncOp, DecOp, NotOp) y las funciones:
 *  - @c alu_core() / @c alu_core_unary() : nucleo de ejecucion ALU con flags
 *  - @c exec_instr_add/sub/mul/div/cmp/and/or/xor/shl/shr/sar/not/inc/dec :
 * despacho de ALU
 *  - @c exec_instr_mov_reg / @c exec_instr_mov_imm / @c exec_instr_mov_sib :
 * instrucciones MOV
 *  - @c exec_instr_movc / @c exec_instr_movc_reg                           :
 * MOV condicional
 *  - @c exec_instr_push / @c exec_instr_pop                                :
 * pila
 *  - @c exec_instr_jcc / @c exec_instr_jmp / @c exec_instr_jrel            :
 * saltos
 *  - @c exec_instr_call / @c exec_instr_ret                                :
 * llamada/retorno
 *  - @c exec_instr_callvm / @c exec_instr_calln / @c exec_instr_enter      :
 * llamadas VM/nativas
 *  - @c exec_instr_syscall / @c exec_instr_int                             :
 * llamadas al sistema
 */
#include "runtime/exec_instruction.h"
#include "runtime/exception_runtime.h"
#include "runtime/profile.h" // Sprint D.6 (2026-06-03): PGO counters
#include <cstdio>
#include <cstdlib>

namespace runtime {

// =========================================================================
// Concepto Op (informal):
//   static constexpr bool is_compare;
//   static T compute(T a, T b);          operaciones binarias
//   static T compute(T a);               operaciones unarias
//   static void flags(ProcessVM*, T a, T b, T result, bool is_signed);  binaria
//   static void flags(ProcessVM*, T a, T result);                        unaria
// =========================================================================

// -------------------------------------------------------------------------
// LogicFlagsBase - flags() compartido para operaciones bitwise (AND, OR, XOR)
// -------------------------------------------------------------------------

/**
 * @brief Comportamiento comun de flags para operaciones binarias bitwise.
 *
 * AND / OR / XOR siempre limpian CF y OF (semantica Intel x86).
 * Las estructuras Op derivadas solo necesitan proveer compute(); flags() se
 * hereda.
 */
/* CONVENIO DE `flags()`: DEVUELVE los bits, no los escribe.
 *
 * Antes cada `Op::flags` escribia CF y OF directamente en `vm->registers`, y
 * `compute_with_flags` hacia lo propio con ZF y SF.  Eran cuatro
 * lee-modifica-escribe encadenados sobre el mismo byte -- ver la explicacion
 * larga en `include/runtime/rflags.h` --, que costaban el 27% del interprete
 * y ademas hacian que el derivador de efectos marcase `add` como LECTOR de
 * banderas, con lo que dos operaciones aritmeticas nunca parecian
 * independientes.
 *
 * Ahora cada `flags()` devuelve un `uint8_t` con sus bits ya colocados
 * (`RF_CF`, `RF_OF`), quien llama compone tambien SF y ZF, y se escribe UNA
 * vez.  Sigue recibiendo `vm` porque hay operaciones -- INC y DEC -- que
 * PRESERVAN el acarreo y necesitan el valor anterior. */
struct LogicFlagsBase {
    /**
     * @brief Limpia CF y OF; ZF/SF los compone quien llama.
     * @tparam T Ancho entero sin signo de los operandos.
     * @return Cero: una operacion bitwise no produce acarreo ni desborda.
     */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T /*a*/, T /*b*/,
                                T /*result*/, bool /*is_signed*/) {
        return 0;
    }
};

// =========================================================================
// Estructuras Op unarias
// =========================================================================

/**
 * @brief INC: incrementa el operando en 1.
 *
 * CF se preserva (no se modifica) para coincidir con la semantica INC de x86.
 * OF se limpia porque INC se trata siempre como sin signo aqui.
 * ZF se establece explicitamente en flags() para evitar calcularlo dos veces.
 */
struct IncOp {
    static constexpr bool is_compare =
        false; // el resultado se escribe de vuelta

    /** @brief Returns a + 1. */
    template <typename T> static inline T compute(T a) { return a + 1; }

    /**
     * @brief Preserva CF, limpia OF.
     * @return El CF ANTERIOR, que es lo que INC preserva; OF a cero.
     */
    template <typename T>
    static inline uint8_t flags(ProcessVM *vm, T /*a*/, T /*result*/) {
        // Unica operacion que necesita el valor previo: por eso `flags()`
        // sigue recibiendo `vm` aunque la mayoria no lo use.
        return (uint8_t)(vm->registers.flags.arith & RF_CF);
    }
};

/**
 * @brief DEC: decrementa el operando en 1.
 *
 * Misma semantica CF/OF/ZF que INC, coincidiendo con el comportamiento DEC de
 * x86.
 */
struct DecOp {
    static constexpr bool is_compare =
        false; // el resultado se escribe de vuelta

    /** @brief Returns a - 1. */
    template <typename T> static inline T compute(T a) { return a - 1; }

    /**
     * @brief Preserva CF, limpia OF.  Misma semantica que INC.
     * @return El CF ANTERIOR; OF a cero.
     */
    template <typename T>
    static inline uint8_t flags(ProcessVM *vm, T /*a*/, T /*result*/) {
        return (uint8_t)(vm->registers.flags.arith & RF_CF);
    }
};

/**
 * @brief NOT: complemento bit a bit.
 *
 * CF y OF se limpian (misma convencion que AND/OR/XOR).
 */
struct NotOp {
    static constexpr bool is_compare =
        false; // el resultado se escribe de vuelta

    /** @brief Returns ~a. */
    template <typename T> static inline T compute(T a) { return ~a; }

    /**
     * @brief Limpia CF y OF; ZF/SF los compone `alu_core_unary`.
     * @return Cero.
     */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T /*a*/, T /*result*/) {
        return 0;
    }
};

// =========================================================================
// Estructuras Op binarias
// =========================================================================

/**
 * @brief ADD: suma con deteccion de acarreo/desbordamiento.
 *
 * - Modo con signo:  OF = desbordamiento con signo, CF = 0.
 * - Modo sin signo: CF = acarreo sin signo, OF = 0.
 */
struct AddOp {
    static constexpr bool is_compare =
        false; // el resultado se escribe de vuelta

    /** @brief Returns a + b. */
    template <typename T> static inline T compute(T a, T b) { return a + b; }

    /** @brief Devuelve CF u OF segun is_signed. */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T a, T b, T result,
                                bool is_signed) {
        using ST = std::make_signed_t<T>;   // vista con signo para verificacion
                                            // de desbordamiento
        using UT = std::make_unsigned_t<T>; // vista sin signo para verificacion
                                            // de acarreo
        if (is_signed) {
            ST sa = (ST)a, sb = (ST)b, sres = (ST)result;
            // regla de desbordamiento con signo; ADD con signo no activa CF
            return ((sa ^ sres) & (sb ^ sres)) < 0 ? RF_OF : 0;
        }
        UT ua = (UT)a, ub = (UT)b;
        // acarreo si hubo vuelta al inicio; ADD sin signo no activa OF
        return ((UT)(ua + ub)) < ua ? RF_CF : 0;
    }
};

/**
 * @brief SUB: resta con deteccion de prestamo/desbordamiento.
 *
 * - Modo con signo:  OF = desbordamiento con signo, CF = 0.
 * - Modo sin signo: CF = prestamo (a < b), OF = 0.
 */
struct SubOp {
    static constexpr bool is_compare =
        false; // el resultado se escribe de vuelta

    /** @brief Returns a - b. */
    template <typename T> static inline T compute(T a, T b) { return a - b; }

    /** @brief Devuelve CF (prestamo) u OF (desbordamiento) segun is_signed. */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T a, T b, T result,
                                bool is_signed) {
        using ST = std::make_signed_t<T>;   // vista con signo para verificacion
                                            // de desbordamiento
        using UT = std::make_unsigned_t<T>; // vista sin signo para verificacion
                                            // de prestamo
        if (is_signed) {
            ST sa = (ST)a, sb = (ST)b, sres = (ST)result;
            // regla de desbordamiento de SUB con signo; no activa CF
            return ((sa ^ sb) & (sa ^ sres)) < 0 ? RF_OF : 0;
        }
        UT ua = (UT)a, ub = (UT)b;
        return ua < ub ? RF_CF : 0; // prestamo cuando a < b; no activa OF
    }
};

/**
 * @brief CMP: comparacion implementada como SUB sin escribir el resultado.
 *
 * is_compare = true impide que alu_core almacene el resultado.
 * Los flags son identicos a SubOp.
 */
struct CmpOp {
    static constexpr bool is_compare =
        true; // el resultado se descarta (solo comparacion)

    /** @brief Returns a - b (result is discarded by alu_core). */
    template <typename T> static inline T compute(T a, T b) { return a - b; }

    /** @brief Delega en SubOp::flags (misma semantica de resta). */
    template <typename T>
    static inline uint8_t flags(ProcessVM *vm, T a, T b, T result,
                                bool is_signed) {
        return SubOp::flags(vm, a, b, result,
                            is_signed); // reutilizar la logica de SUB
    }
};

/**
 * @brief MUL / IMUL: multiplicacion con deteccion de desbordamiento.
 *
 * - Con signo (IMUL): OF = desbordamiento con signo, CF = 0.
 * - Sin signo (MUL): CF = OF = flag de desbordamiento.
 */
struct MulOp {
    static constexpr bool is_compare =
        false; // el resultado se escribe de vuelta

    /** @brief Returns a * b. */
    template <typename T> static inline T compute(T a, T b) { return a * b; }

    /** @brief Detects multiplication overflow and sets CF/OF accordingly. */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T a, T b, T result,
                             bool is_signed) {
        using ST =
            std::make_signed_t<T>; // vista con signo para verificacion de IMUL
        using UT =
            std::make_unsigned_t<T>; // vista sin signo para verificacion de MUL
        bool overflow = false;       // tentativamente sin desbordamiento

        if (is_signed) {
            ST sa = (ST)a;
            ST sb = (ST)b;
            constexpr ST S_MIN =
                std::numeric_limits<ST>::min(); // valor mas negativo
            constexpr ST S_MAX =
                std::numeric_limits<ST>::max(); // valor mas positivo

            if (sa == 0 || sb == 0) {
                overflow = false; // el producto es cero, sin desbordamiento
            } else if (sa == -1) {
                overflow = (sb == S_MIN); // -1 * INT_MIN desborda
            } else if (sb == -1) {
                overflow = (sa == S_MIN); // INT_MIN * -1 desborda
            } else {
                // verificacion general de desbordamiento con signo usando
                // division
                overflow = (sa > 0)
                               ? (sb > 0 ? sa > S_MAX / sb : sb < S_MIN / sa)
                               : (sb > 0 ? sa < S_MIN / sb : sa < S_MAX / sb);
            }
            // IMUL activa OF en desbordamiento y limpia CF
            return overflow ? RF_OF : 0;
        }
        {
            UT ua = (UT)a;
            UT ub = (UT)b;
            if (ua == 0 || ub == 0) {
                overflow = false; // trivialmente sin desbordamiento
            } else {
                constexpr UT U_MAX =
                    std::numeric_limits<UT>::max(); // valor maximo sin signo
                overflow =
                    ua >
                    (U_MAX /
                     ub); // desbordamiento si el cociente supera al divisor
            }
            // MUL sin signo activa CF y OF a la vez en desbordamiento
            return overflow ? (uint8_t)(RF_CF | RF_OF) : 0;
        }
    }
};

/**
 * @brief DIV / IDIV: division entera.
 *
 * Solo se devuelve el cociente; el resto se descarta.
 * Division por cero o desbordamiento con signo establece OF y CF.
 */
struct DivOp {
    static constexpr bool is_compare =
        false; // el cociente se escribe de vuelta
    static constexpr bool is_division =
        true; // trait detectado por compute_with_flags

    /** @brief Returns a / b (quotient only; divide-by-zero must be checked by
     * caller). Sprint edge-bugs: guard explicito anti-UB.  La verificacion real
     *  con throw_fatal vive en compute_with_flags antes de compute. */
    template <typename T> static inline T compute(T a, T b) {
        return (b == 0) ? T(0) : a / b;
    }

    /** @brief Devuelve OF|CF si hubo division por cero o IDIV INT_MIN/-1. */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T a, T b, T result,
                                bool is_signed) {
        using ST = std::make_signed_t<T>; // vista con signo para verificacion
                                          // de desbordamiento IDIV
        (void)result; // lo usa alu_core; aqui no hace falta
        // la division por cero es una condicion excepcional
        if (b == 0) return RF_OF | RF_CF;
        if (is_signed) {
            ST sa = (ST)a;
            ST sb = (ST)b;
            // IDIV INT_MIN / -1 desbordaria el registro de cociente
            if (sa == std::numeric_limits<ST>::min() && sb == -1)
                return RF_OF | RF_CF;
        }
        // division normal: ni desbordamiento ni acarreo.  La sin signo nunca
        // desborda salvo por cero, que ya se trato arriba.
        return 0;
    }
};

// Operaciones binarias bitwise -- todas heredan LogicFlagsBase (CF=OF=0).

/** @brief AND: bitwise AND. Clears CF and OF via LogicFlagsBase. */
struct AndOp : LogicFlagsBase {
    static constexpr bool is_compare = false;
    template <typename T> static inline T compute(T a, T b) { return a & b; }
};

/** @brief OR: bitwise OR. Clears CF and OF via LogicFlagsBase. */
struct OrOp : LogicFlagsBase {
    static constexpr bool is_compare = false;
    template <typename T> static inline T compute(T a, T b) { return a | b; }
};

/** @brief XOR: bitwise XOR. Clears CF and OF via LogicFlagsBase. */
struct XorOp : LogicFlagsBase {
    static constexpr bool is_compare = false;
    template <typename T> static inline T compute(T a, T b) { return a ^ b; }
};

/**
 * @brief SHL: desplazamiento logico a la izquierda.
 *
 * CF = ultimo bit desplazado fuera del lado MSB.
 * OF = CF XOR MSB(resultado)  (definido solo para desplazamiento de 1).
 */
struct ShlOp {
    static constexpr bool is_compare = false;

    /** @brief Returns (unsigned)a << (b & (bits-1)). */
    template <typename T> static inline T compute(T a, T b) {
        using UT = std::make_unsigned_t<T>; // sin signo para comportamiento de
                                            // desplazamiento definido
        uint32_t shift =
            (uint32_t)b &
            (sizeof(T) * 8 -
             1); // enmascarar el conteo de desplazamiento al rango valido
        return (T)((UT)a << shift);
    }

    /** @brief CF sale del bit desplazado fuera y OF del MSB resultante. */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T a, T b, T result, bool) {
        using UT = std::make_unsigned_t<T>;
        uint32_t shift = (uint32_t)b &
                         (sizeof(T) * 8 - 1); // mismo enmascarado que compute()
        if (shift == 0) return 0; // desplazamiento cero deja CF y OF limpios
        UT ua = (UT)a;
        UT cf_bit =
            (ua >> (sizeof(T) * 8 - shift)) & 1; // bit desplazado fuera
        UT msb = ((UT)result >> (sizeof(T) * 8 - 1)) & 1;
        // OF = CF XOR nuevo MSB (regla SHL de x86)
        return (uint8_t)((cf_bit ? RF_CF : 0) | ((cf_bit ^ msb) ? RF_OF : 0));
    }
};

/**
 * @brief SHR: desplazamiento logico a la derecha (sin signo).
 *
 * CF = ultimo bit desplazado fuera del lado LSB.
 * OF se limpia (regla x86 para SHR).
 */
struct ShrOp {
    static constexpr bool is_compare = false;

    /** @brief Returns (unsigned)a >> (b & (bits-1)). */
    template <typename T> static inline T compute(T a, T b) {
        using UT = std::make_unsigned_t<T>; // desplazamiento derecho sin signo
                                            // rellena con 0
        uint32_t shift =
            (uint32_t)b &
            (sizeof(T) * 8 - 1); // enmascarar el conteo de desplazamiento
        return (T)((UT)a >> shift);
    }

    /** @brief CF = ultimo bit desplazado fuera; OF a cero. */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T a, T b, T /*result*/,
                                bool) {
        using UT = std::make_unsigned_t<T>;
        uint32_t shift = (uint32_t)b &
                         (sizeof(T) * 8 - 1); // mismo enmascarado que compute()
        if (shift == 0) return 0; // desplazamiento cero deja CF y OF limpios
        UT ua = (UT)a;
        // SHR nunca activa OF
        return ((ua >> (shift - 1)) & 1) ? RF_CF : 0;
    }
};

/**
 * @brief SAR: desplazamiento aritmetico a la derecha (con signo).
 *
 * Rellena con el bit de signo (extension de signo), equivalente a division con
 * signo por 2^shift. CF = ultimo bit desplazado fuera; OF = 0.
 */
struct SarOp {
    static constexpr bool is_compare = false;

    /** @brief Returns (signed)a >> (b & (bits-1)) with sign extension. */
    template <typename T> static inline T compute(T a, T b) {
        using ST = std::make_signed_t<T>; // desplazamiento derecho con signo
                                          // para extension de signo
        uint32_t shift =
            (uint32_t)b &
            (sizeof(T) * 8 - 1); // enmascarar el conteo de desplazamiento
        return (T)((ST)a >> shift);
    }

    /** @brief CF = ultimo bit desplazado fuera; OF a cero (regla x86). */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T a, T b, T /*result*/,
                                bool) {
        using UT = std::make_unsigned_t<T>;
        uint32_t shift = (uint32_t)b &
                         (sizeof(T) * 8 - 1); // mismo enmascarado que compute()
        if (shift == 0) return 0; // desplazamiento cero deja CF y OF limpios
        UT ua = (UT)a;
        return ((ua >> (shift - 1)) & 1) ? RF_CF : 0;
    }
};

// =========================================================================
// Nucleo auxiliar ALU: compute_with_flags
// Centraliza la actualizacion de ZF/SF compartida por alu_core,
// binary_mem_imm_wrapper, y sib_mem_dst_wrapper para que la logica este en un
// solo lugar.
// =========================================================================

/**
 * @brief Ejecuta Op sobre (a, b), actualiza ZF/SF/CF/OF y devuelve el
 * resultado.
 *
 * ZF y SF siempre se derivan del resultado.
 * CF y OF son especificos de Op y los establece Op::flags().
 *
 * @tparam T         Ancho entero sin signo de los operandos.
 * @tparam Op        Estructura de operacion que provee compute() y flags().
 * @param  vm        Puntero a la maquina virtual.
 * @param  a         Primer operando (destino / acumulador).
 * @param  b         Segundo operando (fuente / inmediato).
 * @param  is_signed Selecciona semantica de flags con signo vs sin signo.
 * @return           El resultado calculado (mismo tipo T).
 */
// Sprint edge-bugs (2026-06-02): detection SFINAE de Op::is_division.  Si la
// estructura Op declara `static constexpr bool is_division = true` y el
// divisor es cero, lanzamos FatalError capturable ANTES de tocar compute().
// Por defecto (Op sin el trait) la rama se compila-fuera (constexpr false).
template <typename Op, typename = void>
struct OpIsDivision : std::false_type {};
template <typename Op>
struct OpIsDivision<Op, std::void_t<decltype(Op::is_division)>>
    : std::integral_constant<bool, Op::is_division> {};

template <typename T, typename Op>
inline T compute_with_flags(ProcessVM *vm, T a, T b, bool is_signed,
                            bool *abortado = nullptr) {
    using UT = std::make_unsigned_t<T>; // vista sin signo para verificaciones
                                        // de flags a nivel de bits
    T res;
    if constexpr (OpIsDivision<Op>::value) {
        if (b == 0) {
            if (abortado) *abortado = true;
            // Division (o modulo) por cero: lanzar FatalError capturable.
            //
            // OJO: `throw_fatal` RETORNA.  Aqui ponia que hacia un salto largo
            // al marco del `try` mas cercano, y de ahi salia que quien llama
            // pudiera seguir tranquilamente escribiendo el resultado -- que es
            // justo lo que hacia, encima del registro donde `do_throw` acababa
            // de dejar el objeto de la excepcion.  Cuando el destino de la
            // division era ESE registro (r0), el `catch` recibia un cero y
            // moria al leerle un campo.  Por eso se avisa de que se aborto: una
            // division que fallo no produce ningun resultado que escribir.
            // Sin mensaje propio: el tipo de fallo ya lo cuenta el catalogo,
            // en el idioma de quien lee.  Repetirlo aqui en una cadena fija
            // seria decir lo mismo dos veces y solo en castellano.
            throw_fatal(vm, FATAL_DIVISION_BY_ZERO, nullptr);
            return T(0); // unreachable; setea defensivo
        }
        if (is_signed) {
            using ST = std::make_signed_t<T>;
            ST sa = (ST)a;
            ST sb = (ST)b;
            if (sa == std::numeric_limits<ST>::min() && sb == -1) {
                // IDIV INT_MIN / -1: desbordamiento; tratar como FATAL.
                if (abortado) *abortado = true;
                throw_fatal(vm, FATAL_DIVISION_BY_ZERO, nullptr);
                return T(0);
            }
            // Sprint edge-bugs (2026-06-02): bug de signo en MOD/DIV.  Las
            // tablas usan binary_wrapper<uint32_t, ModOp> aun para
            // is_signed=true. Esto hacia que -7 % 3 (a=0xFFFFFFF9, b=3)
            // computase 0 unsigned. Convencion C/x86: el signo del resultado
            // sigue el dividendo. Para corregir, reinterpretamos los operandos
            // como signed cuando is_signed=true y la operacion es division.
            res = (T)Op::template compute<ST>(sa, sb);
        } else {
            res = Op::compute(a, b); // semantica unsigned
        }
    } else {
        res = Op::compute(a, b); // ejecutar la operacion
    }
    /* Las cuatro banderas se componen en un registro y se escriben de UNA vez.
     *
     * Antes eran cuatro asignaciones a campos de bits del mismo byte -- dos
     * aqui y dos dentro de `Op::flags` --, o sea cuatro lee-modifica-escribe
     * encadenados sobre la misma direccion.  Costaban el 27% del interprete
     * medido con VTune, y ademas hacian que el derivador de efectos viera un
     * `add` LEYENDO las banderas.  Ver `include/runtime/rflags.h`. */
    constexpr int SIGN_BIT =
        sizeof(T) * 8 - 1; // indice del bit de mayor peso (signo)
    uint8_t nf = (res == 0) ? RF_ZF : 0;                 // ZF
    if ((static_cast<UT>(res) >> SIGN_BIT) & 1) nf |= RF_SF; // SF
    nf |= Op::flags(vm, a, b, res, is_signed);           // CF/OF segun Op
    vm->registers.flags.arith = nf; // store PURO: no lee el valor anterior
    return res; // el llamante decide si almacenar el resultado
}

// =========================================================================
// alu_core -- ALU binaria con destino de registro
// =========================================================================

/**
 * @brief Nucleo ALU binario: calcula Op(a, b), actualiza flags y escribe en un
 * registro.
 *
 * @tparam T             Ancho entero sin signo de los operandos.
 * @tparam Op            Estructura de operacion (compute + flags).
 * @param  vm            Puntero a la maquina virtual.
 * @param  a             Primer operando (valor actual del registro destino).
 * @param  b             Segundo operando (inmediato, valor de registro o de
 * memoria).
 * @param  is_signed     Selecciona semantica con signo vs sin signo para CF/OF.
 * @param  dst_reg_index Indice del registro destino en vm->registers.regs[].
 *
 * @note Cuando Op::is_compare == true el resultado NO se escribe de vuelta
 * (semantica CMP).
 */
template <typename T, typename Op>
inline void alu_core(ProcessVM *vm, T a, T b, bool is_signed,
                     int dst_reg_index) {
    bool abortado = false;
    T result = compute_with_flags<T, Op>(
        vm, a, b, is_signed, &abortado); // calcular y actualizar flags
    if constexpr (!Op::is_compare) {
        // La operacion fallo: no hay resultado, y escribir uno pisaria el
        // registro que el manejador de la excepcion necesita.
        if (abortado) return;
        // escribir el resultado de vuelta en el registro destino al ancho
        // correcto
        auto &dst = vm->registers.regs[dst_reg_index];
        if constexpr (sizeof(T) == 1)
            dst.byte_lo((uint8_t)result); // escritura de 8 bits
        else if constexpr (sizeof(T) == 2)
            dst.word_lo((uint16_t)result); // escritura de 16 bits
        else if constexpr (sizeof(T) == 4)
            dst.dword_lo((uint32_t)result); // escritura de 32 bits
        else
            dst.qword((uint64_t)result); // escritura de 64 bits
    }
}

// =========================================================================
// alu_core_unary -- ALU unaria con destino de registro
// =========================================================================

/**
 * @brief Nucleo ALU unario: calcula Op(a), actualiza ZF/SF y escribe en un
 * registro.
 *
 * ZF y SF se establecen genericamente aqui; Op::flags() maneja CF/OF.
 *
 * @tparam T             Ancho entero sin signo.
 * @tparam Op            Estructura de operacion unaria (compute + flags, sin
 * parametro is_signed).
 * @param  vm            Puntero a la maquina virtual.
 * @param  a             Operando (valor actual del registro destino).
 * @param  dst_reg_index Indice del registro destino.
 */
template <typename T, typename Op>
inline void alu_core_unary(ProcessVM *vm, T a, int dst_reg_index) {
    using UT = std::make_unsigned_t<T>; // vista sin signo para extraccion de SF
    T result = Op::compute(a);                  // aplicar la operacion unaria
    constexpr int SIGN_BIT = sizeof(T) * 8 - 1; // indice del bit de signo
    // Mismo criterio que en `compute_with_flags`: componer y escribir una vez.
    // OJO con el ORDEN: `Op::flags` de INC y DEC LEE el CF anterior para
    // preservarlo, asi que tiene que llamarse ANTES de escribir el byte.
    uint8_t nf = (result == 0) ? RF_ZF : 0;                     // ZF
    if ((static_cast<UT>(result) >> SIGN_BIT) & 1) nf |= RF_SF; // SF
    nf |= Op::flags(vm, a, result);          // CF/OF segun Op
    vm->registers.flags.arith = nf;          // store PURO
    auto &dst =
        vm->registers.regs[dst_reg_index]; // referencia al registro destino
    if constexpr (sizeof(T) == 1)
        dst.byte_lo((uint8_t)result); // escritura de 8 bits
    else if constexpr (sizeof(T) == 2)
        dst.word_lo((uint16_t)result); // escritura de 16 bits
    else if constexpr (sizeof(T) == 4)
        dst.dword_lo((uint32_t)result); // escritura de 32 bits
    else
        dst.qword((uint64_t)result); // escritura de 64 bits
}

// =========================================================================
// Aliases de tipo para tablas de despacho
// =========================================================================

typedef GeneralRegister
    &Reg; // abreviatura para referencia de registro en firmas de tabla

/** @brief Signature for binary reg-reg (or reg-imm via wrapper) dispatch
 * functions. */
using BinaryFn = void (*)(ProcessVM *, Reg, Reg, bool, int);

/** @brief Signature for unary (INC/DEC/NOT) dispatch functions. */
using UnaryFn = void (*)(ProcessVM *, Reg, int);

/** @brief Signature for binary immediate dispatch functions. */
using BinaryImmFn = void (*)(ProcessVM *, Reg &, uint64_t, bool, int);

/** @brief Signature for binary memory+immediate dispatch functions. */
using BinaryMemImmFn = void (*)(ProcessVM *, uint64_t, uint64_t, bool);

// =========================================================================
// Plantillas wrapper -- adaptan los nucleos ALU genericos a tipos de tabla de
// despacho
// =========================================================================

/**
 * @brief Adapta alu_core para despacho de operandos inmediatos.
 *        Extrae el valor bruto de dst y convierte imm a T antes de llamar a
 * alu_core.
 */
template <typename T, typename Op>
static void binary_imm_wrapper(ProcessVM *vm, Reg &dst, uint64_t imm,
                               bool is_signed, int rdst) {
    alu_core<T, Op>(vm, dst.raw(), (T)imm, is_signed,
                    rdst); // delegar con tipos correctos
}

/**
 * @brief Adapta compute_with_flags para operaciones inmediatas con destino de
 * memoria. Lee de la memoria virtual, aplica Op y escribe el resultado (excepto
 * CmpOp).
 */
template <typename T, typename Op>
static void binary_mem_imm_wrapper(ProcessVM *vm, uint64_t addr, uint64_t imm,
                                   bool is_signed) {
    T val =
        vm->vm_mem.read_any<T>(addr); // cargar el valor actual de la memoria VM
    bool abortado = false;
    T res = compute_with_flags<T, Op>(vm, val, (T)imm, is_signed,
                                      &abortado); // calcular y actualizar flags
    if constexpr (!Op::is_compare)
        if (!abortado)
            vm->vm_mem.write_any<T>(
                addr, res); // escribir de vuelta a menos que sea CMP
}

/**
 * @brief Wrapper MOV reg-a-reg: copia src a dst al ancho T; NO toca los flags.
 */
template <typename T>
static void mov_wrapper(ProcessVM *vm, Reg dst, Reg src, bool /*unused*/,
                        int rdst) {
    T value = src.raw(); // leer registro fuente como valor de ancho T
    auto &d = vm->registers.regs[rdst]; // referencia al registro destino
    if constexpr (sizeof(T) == 1)
        d.byte_lo((uint8_t)value); // copia de 8 bits
    else if constexpr (sizeof(T) == 2)
        d.word_lo((uint16_t)value); // copia de 16 bits
    else if constexpr (sizeof(T) == 4)
        d.dword_lo((uint32_t)value); // copia de 32 bits
    else
        d.qword((uint64_t)value); // copia de 64 bits
    // MOV no modifica ningun flag
}

/**
 * @brief Adapta alu_core para despacho binario registro-registro.
 */
template <typename T, typename Op>
static void binary_wrapper(ProcessVM *vm, Reg &dst, Reg &src, bool is_signed,
                           int rdst) {
    alu_core<T, Op>(vm, dst.raw(), src.raw(), is_signed,
                    rdst); // delegar con ambos valores de registro
}

/**
 * @brief Adapta alu_core_unary para despacho unario.
 */
template <typename T, typename Op>
static void unary_wrapper(ProcessVM *vm, Reg &dst, int rdst) {
    alu_core_unary<T, Op>(vm, dst.raw(), rdst); // delegar con valor de registro
}

// =========================================================================
// Macros de declaracion de tablas de despacho
// Cada macro produce un array static constexpr de cuatro punteros a funcion
// (uno por ancho de operando: 8, 16, 32, 64 bits).
// =========================================================================

/** @brief Declares a binary reg-reg dispatch table for Op. */
#define DECL_BIN_TABLE(name, Op)                                               \
    static constexpr BinaryFn name##_table[] = {                               \
        &binary_wrapper<uint8_t, Op>, &binary_wrapper<uint16_t, Op>,           \
        &binary_wrapper<uint32_t, Op>, &binary_wrapper<uint64_t, Op>}

/** @brief Declares a unary dispatch table for Op. */
#define DECL_UNARY_TABLE(name, Op)                                             \
    static constexpr UnaryFn name##_table[] = {                                \
        &unary_wrapper<uint8_t, Op>, &unary_wrapper<uint16_t, Op>,             \
        &unary_wrapper<uint32_t, Op>, &unary_wrapper<uint64_t, Op>}

/** @brief Declares the paired reg-imm and mem-imm dispatch tables for Op. */
#define DECL_IMM_TABLES(name, Op)                                              \
    static constexpr BinaryImmFn name##_imm_table[] = {                        \
        &binary_imm_wrapper<uint8_t, Op>, &binary_imm_wrapper<uint16_t, Op>,   \
        &binary_imm_wrapper<uint32_t, Op>, &binary_imm_wrapper<uint64_t, Op>}; \
    static constexpr BinaryMemImmFn name##_mem_imm_table[] = {                 \
        &binary_mem_imm_wrapper<uint8_t, Op>,                                  \
        &binary_mem_imm_wrapper<uint16_t, Op>,                                 \
        &binary_mem_imm_wrapper<uint32_t, Op>,                                 \
        &binary_mem_imm_wrapper<uint64_t, Op>}

// --- Tablas registro-registro (11 operaciones) ---
DECL_BIN_TABLE(mul, MulOp);
DECL_BIN_TABLE(add, AddOp);
DECL_BIN_TABLE(sub, SubOp);
DECL_BIN_TABLE(cmp, CmpOp);
DECL_BIN_TABLE(div, DivOp);
DECL_BIN_TABLE(and, AndOp);
DECL_BIN_TABLE(or, OrOp);
DECL_BIN_TABLE(xor, XorOp);
DECL_BIN_TABLE(shl, ShlOp);
DECL_BIN_TABLE(shr, ShrOp);
DECL_BIN_TABLE(sar, SarOp);

// mov_table es especial: usa mov_wrapper, no binary_wrapper
static constexpr BinaryFn mov_table[] = {
    &mov_wrapper<uint8_t>,  // MOV de 8 bits
    &mov_wrapper<uint16_t>, // MOV de 16 bits
    &mov_wrapper<uint32_t>, // MOV de 32 bits
    &mov_wrapper<uint64_t>  // MOV de 64 bits
};

// --- Tablas unarias (3 operaciones) ---
DECL_UNARY_TABLE(inc, IncOp);
DECL_UNARY_TABLE(dec, DecOp);
DECL_UNARY_TABLE(not, NotOp);

// --- Tablas de inmediatos (5 operaciones emparejadas) ---
DECL_IMM_TABLES(add, AddOp);
DECL_IMM_TABLES(sub, SubOp);
DECL_IMM_TABLES(mul, MulOp);
DECL_IMM_TABLES(div, DivOp);
DECL_IMM_TABLES(cmp, CmpOp);

#undef DECL_BIN_TABLE
#undef DECL_UNARY_TABLE
#undef DECL_IMM_TABLES

// =========================================================================
// Macro de funcion exec para inmediatos
// Genera exec_instr_<nombre>_imm:
//   direction==0 -> el operando es un registro
//   direction==1 -> el operando es una direccion de memoria (reg base, sin
//   indice/escala)
// =========================================================================

/**
 * @brief Macro que genera una funcion exec_instr_<nombre>_imm.
 *
 * @param name     Mnemonic de instruccion (ej: add, sub).
 * @param imm_tbl  Nombre de la tabla de despacho BinaryImmFn.
 * @param mem_tbl  Nombre de la tabla de despacho BinaryMemImmFn.
 */
#define DEFINE_IMM_EXEC(name, imm_tbl, mem_tbl)                                \
    void exec_instr_##name##_imm(ProcessVM *vm, const DecodedInstr &instr) {   \
        const int rdst = instr.data_instruction.inmmed_data.reg;               \
        uint64_t imm = instr.data_instruction.inmmed_data.inmmed;              \
        if (instr.flags_info.direction == 0) {                                 \
            /* direction=0: el destino es un registro */                       \
            imm_tbl[instr.flags_info.mode](vm, vm->registers.regs[rdst], imm,  \
                                           instr.flags_info._signed_instruct,  \
                                           rdst);                              \
            return;                                                            \
        }                                                                      \
        /* direction=1: el destino es memoria en la direccion almacenada en el \
         * registro rdst */                                                    \
        uint64_t addr = vm->registers.regs[rdst].raw();                        \
        mem_tbl[instr.flags_info.mode](vm, addr, imm,                          \
                                       instr.flags_info._signed_instruct);     \
    }

DEFINE_IMM_EXEC(add, add_imm_table, add_mem_imm_table)
DEFINE_IMM_EXEC(sub, sub_imm_table, sub_mem_imm_table)
DEFINE_IMM_EXEC(mul, mul_imm_table, mul_mem_imm_table)
DEFINE_IMM_EXEC(div, div_imm_table, div_mem_imm_table)
DEFINE_IMM_EXEC(cmp, cmp_imm_table, cmp_mem_imm_table)

#undef DEFINE_IMM_EXEC

// =========================================================================
// Macros de funciones exec registro-registro
// DEFINE_REG_EXEC:        pasa is_signed desde los flags de instruccion
// DEFINE_REG_EXEC_NOSIGN: siempre pasa false (operaciones bitwise y de
// desplazamiento)
// =========================================================================

/**
 * @brief Genera exec_instr_<nombre>_reg para operaciones binarias con/sin
 * signo. Lee reg1 (dst) y reg2 (src) de la instruccion decodificada.
 */
#define DEFINE_REG_EXEC(name)                                                  \
    void exec_instr_##name##_reg(ProcessVM *vm, const DecodedInstr &instr) {   \
        const int rdst = instr.data_instruction.reg_data                       \
                             .reg1; /* indice del registro destino */          \
        const int rsrc = instr.data_instruction.reg_data                       \
                             .reg2; /* indice del registro fuente */           \
        name##_table[instr.flags_info.mode](                                   \
            vm, vm->registers.regs[rdst], vm->registers.regs[rsrc],            \
            instr.flags_info._signed_instruct,                                 \
            rdst); /* despacho por modo (ancho) */                             \
    }

/**
 * @brief Genera exec_instr_<nombre>_reg para operaciones bitwise/desplazamiento
 * sin semantica de signo. Siempre pasa false como is_signed; CF/OF son
 * definidos por la estructura Op.
 */
#define DEFINE_REG_EXEC_NOSIGN(name)                                           \
    void exec_instr_##name##_reg(ProcessVM *vm, const DecodedInstr &instr) {   \
        const int rdst = instr.data_instruction.reg_data                       \
                             .reg1; /* indice del registro destino */          \
        const int rsrc = instr.data_instruction.reg_data                       \
                             .reg2; /* indice del registro fuente */           \
        name##_table[instr.flags_info.mode](                                   \
            vm, vm->registers.regs[rdst], vm->registers.regs[rsrc], false,     \
            rdst); /* sin semantica de signo para operaciones                  \
                      bitwise/desplazamiento */                                \
    }

// Operaciones binarias que distinguen entre con/sin signo
DEFINE_REG_EXEC(add)
DEFINE_REG_EXEC(mul)
DEFINE_REG_EXEC(sub)
DEFINE_REG_EXEC(cmp)
DEFINE_REG_EXEC(div)

// Operaciones bitwise y de desplazamiento: is_signed es irrelevante para CF/OF
// (ver estructuras Op)
DEFINE_REG_EXEC_NOSIGN(and)
DEFINE_REG_EXEC_NOSIGN(or)
DEFINE_REG_EXEC_NOSIGN(xor)
DEFINE_REG_EXEC_NOSIGN(shl)
DEFINE_REG_EXEC_NOSIGN(shr)
DEFINE_REG_EXEC_NOSIGN(sar)

#undef DEFINE_REG_EXEC
#undef DEFINE_REG_EXEC_NOSIGN

// =========================================================================
// Funciones exec especiales (no pueden generarse con los macros anteriores)
// =========================================================================

/**
 * @brief Ejecuta una instruccion MOV reg-reg o MOV reg_ext-reg.
 *
 * Cuando el bit 's' es 0: MOV estandar reg1, reg2.
 * Cuando el bit 's' es 1: MOV con registro especial/extendido.
 *   d=0 -> escribir registro especial desde registro general.
 *   d=1 -> leer registro especial a registro general.
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Instruccion decodificada con campos reg_data y flags_info.
 */
void exec_instr_mov_reg(ProcessVM *vm, const DecodedInstr &instr) {
    uint8_t s =
        instr.flags_info._signed_instruct; // s=1 significa que un operando es
                                           // un registro especial
    uint8_t d =
        instr.flags_info.direction; // 0=escribir especial, 1=leer especial
    uint8_t mode = instr.flags_info.mode; // selector de ancho de operando
    uint8_t reg1 =
        instr.data_instruction.reg_data.reg1; // primer campo de registro
    uint8_t reg2 =
        instr.data_instruction.reg_data.reg2; // segundo campo de registro

    if (s == 0) {
        // MOV estandar reg1, reg2 -- sin registros especiales
        mov_table[mode](vm, vm->registers.regs[reg1], vm->registers.regs[reg2],
                        false, reg1);
        return;
    }

    // s=1: variante reg_ext -- todos los codigos de registros especiales caben
    // en 4 bits (cur0..cur3 = 0..3, rip/rbp/rsp/rflags = 8..11), por lo que el
    // selector se halla unicamente en el nibble alto de byte2 (campo reg2 tras
    // decodificar).  El campo mode del ctrl byte indica el ancho real del
    // operando general y se respeta para mov_table[mode], evitando
    // truncamientos accidentales (antes mode siempre era 0 por venir de
    // bits[5:4] del codigo especial, lo que truncaba a 8 bits).
    uint8_t special =
        (uint8_t)(reg2 & 0xF); // codigo de registro especial (4 bits)
    if (d == 0) {
        // MOV reg_ext, reg -- escribir valor de registro general en registro
        // especial
        write_special(vm, special, vm->registers.regs[reg1].raw());
    } else {
        // MOV reg, reg_ext -- leer valor de registro especial a registro
        // general
        uint64_t val =
            read_special(vm, special); // obtener el registro especial
        GeneralRegister tmp;
        tmp.qword(val); // envolver en registro general temporal
        mov_table[mode](vm, vm->registers.regs[reg1], tmp, false,
                        reg1); // copiar al destino
    }
}

/**
 * @brief Ejecuta NOT reg: complemento bitwise de un solo registro.
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Instruccion decodificada; reg1 es el operando y el destino.
 */
void exec_instr_not_reg(ProcessVM *vm, const DecodedInstr &instr) {
    const int rdst = instr.data_instruction.reg_data
                         .reg1; // el registro es tanto fuente como destino
    not_table[instr.flags_info.mode](vm, vm->registers.regs[rdst],
                                     rdst); // despacho por ancho
}

/**
 * @brief Ejecuta INC o DEC sobre un registro.
 *
 * El bit 's' codifica la variante: 0 = INC, 1 = DEC.
 * Este encoding reutiliza el bit de signo ya que INC/DEC no tienen semantica de
 * signo.
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Decoded instruction; reg1 is the operand/destination.
 */
void exec_instr_inc_dec_reg(ProcessVM *vm, const DecodedInstr &instr) {
    const int rdst =
        instr.data_instruction.reg_data.reg1; // operand register index
    if (instr.flags_info._signed_instruct == 0)
        inc_table[instr.flags_info.mode](vm, vm->registers.regs[rdst],
                                         rdst); // INC variant
    else
        dec_table[instr.flags_info.mode](vm, vm->registers.regs[rdst],
                                         rdst); // DEC variant
}

// =========================================================================
// SIB (Scale-Index-Base) memory access helpers
// =========================================================================

/* `sib_effective_addr` VIVE AHORA EN `include/runtime/exec_instruction.h`.
 *
 * Se movio porque la ruta rapida del interprete (`L_MOV_SIB`, en
 * `scheduler.cpp`) necesita la MISMA aritmetica de direccion.  La alternativa
 * era copiarla alli, y una direccion efectiva calculada de dos formas es
 * exactamente la clase de duplicado que un dia deja de coincidir sin que nadie
 * lo note: no daria un error, daria OTRA DIRECCION. */

/**
 * @brief SIB direction=0 wrapper: dst_reg = Op(dst_reg, mem[sib]).
 *        Reads the memory operand and feeds it to alu_core as source.
 */
template <typename T, typename Op>
static void sib_reg_dst_wrapper(ProcessVM *vm, uint64_t addr, uint64_t dst_val,
                                bool is_signed, int dst_reg) {
    T src = vm->vm_mem.read_any<T>(addr); // read source value from VM memory
    alu_core<T, Op>(vm, (T)dst_val, src, is_signed,
                    dst_reg); // compute and store into dst_reg
}

/**
 * @brief SIB direction=1 wrapper: mem[sib] = Op(mem[sib], reg).
 *        Reads, computes, and writes back to virtual memory (unless CmpOp).
 */
template <typename T, typename Op>
static void sib_mem_dst_wrapper(ProcessVM *vm, uint64_t addr, uint64_t reg_val,
                                bool is_signed, int) {
    T mem_val = vm->vm_mem.read_any<T>(addr); // load target from VM memory
    bool abortado = false;
    T res = compute_with_flags<T, Op>(vm, mem_val, (T)reg_val, is_signed,
                                      &abortado); // compute and set flags
    if constexpr (!Op::is_compare)
        if (!abortado)
            vm->vm_mem.write_any<T>(addr,
                                    res); // write back (CMP discards result)
}

/** @brief Signature for SIB dispatch functions. */
using SIBFn = void (*)(ProcessVM *, uint64_t, uint64_t, bool, int);

// MOV [sib] variants (not arithmetic -- no flags involved)

/** @brief SIB MOV direction=0: load from VM memory into a general register. */
template <typename T>
static void sib_mov_to_reg(ProcessVM *vm, uint64_t addr, uint64_t, bool,
                           int dst_reg) {
    T val = vm->vm_mem.read_any<T>(addr);  // read T-width value from VM memory
    auto &d = vm->registers.regs[dst_reg]; // referencia al registro destino
    if constexpr (sizeof(T) == 1)
        d.byte_lo((uint8_t)val); // escritura de 8 bits
    else if constexpr (sizeof(T) == 2)
        d.word_lo((uint16_t)val); // escritura de 16 bits
    else if constexpr (sizeof(T) == 4)
        d.dword_lo((uint32_t)val); // escritura de 32 bits
    else
        d.qword((uint64_t)val); // escritura de 64 bits
}

/** @brief SIB MOV direction=1: store a general register value into VM memory.
 */
template <typename T>
static void sib_mov_to_mem(ProcessVM *vm, uint64_t addr, uint64_t reg_val, bool,
                           int) {
    vm->vm_mem.write_any<T>(
        addr, (T)reg_val); // write truncated register value to VM memory
}

/** @brief MOVH direction=0: load from host (native) memory into a general
 * register. */
template <typename T>
static void movh_to_reg(ProcessVM *vm, uint64_t addr, uint64_t, bool,
                        int dst_reg) {
    T val = *reinterpret_cast<const T *>(
        addr); // dereference native pointer -- bypasses VM memory
    auto &d = vm->registers.regs[dst_reg];
    if constexpr (sizeof(T) == 1)
        d.byte_lo((uint8_t)val); // escritura de 8 bits
    else if constexpr (sizeof(T) == 2)
        d.word_lo((uint16_t)val); // escritura de 16 bits
    else if constexpr (sizeof(T) == 4)
        d.dword_lo((uint32_t)val); // escritura de 32 bits
    else
        d.qword((uint64_t)val); // escritura de 64 bits
}

/** @brief MOVH direction=1: store a register value into host (native) memory.
 */
template <typename T>
static void movh_to_mem(ProcessVM *, uint64_t addr, uint64_t reg_val, bool,
                        int) {
    *reinterpret_cast<T *>(addr) =
        static_cast<T>(reg_val); // write to native address
}

// SIB dispatch tables for MOV and MOVH
static constexpr SIBFn mov_sib_to_reg_table[] = {
    &sib_mov_to_reg<uint8_t>, &sib_mov_to_reg<uint16_t>,
    &sib_mov_to_reg<uint32_t>, &sib_mov_to_reg<uint64_t>};
static constexpr SIBFn mov_sib_to_mem_table[] = {
    &sib_mov_to_mem<uint8_t>, &sib_mov_to_mem<uint16_t>,
    &sib_mov_to_mem<uint32_t>, &sib_mov_to_mem<uint64_t>};
static constexpr SIBFn movh_to_reg_table[] = {
    &movh_to_reg<uint8_t>, &movh_to_reg<uint16_t>, &movh_to_reg<uint32_t>,
    &movh_to_reg<uint64_t>};
static constexpr SIBFn movh_to_mem_table[] = {
    &movh_to_mem<uint8_t>, &movh_to_mem<uint16_t>, &movh_to_mem<uint32_t>,
    &movh_to_mem<uint64_t>};

/**
 * @brief Generic SIB execution helper shared by all arithmetic SIB
 * instructions.
 *
 * Reads direction from the decoded instruction to choose between:
 *   direction=0 -> reg = Op(reg, mem[sib])
 *   direction=1 -> mem[sib] = Op(mem[sib], reg)
 *
 * @tparam Op     Operation struct (not used directly here; embedded in the
 * table).
 * @param  vm     Pointer to the virtual machine.
 * @param  instr  Decoded instruction.
 * @param  reg_dst Table for direction=0 (reg destination).
 * @param  mem_dst Table for direction=1 (memory destination).
 */
template <typename Op>
static void exec_sib_generic(ProcessVM *vm, const DecodedInstr &instr,
                             const SIBFn reg_dst[4], const SIBFn mem_dst[4]) {
    const int dst = instr.data_instruction.mem_data
                        .reg_final; // final (non-SIB) register index
    uint64_t addr = sib_effective_addr(vm, instr); // compute effective address
    uint64_t rval = vm->registers.regs[dst].raw(); // current register value
    bool sign = instr.flags_info._signed_instruct; // signed/unsigned selector
    int mode = instr.flags_info.mode; // selector de ancho de operando
    if (instr.flags_info.direction == 0)
        reg_dst[mode](vm, addr, rval, sign, dst); // reg = Op(reg, mem)
    else
        mem_dst[mode](vm, addr, rval, sign, dst); // mem = Op(mem, reg)
}

// =========================================================================
// DEFINE_SIB_EXEC macro
// Declares both SIB dispatch tables and the exec function in one shot.
// =========================================================================

/**
 * @brief Declares SIB tables and the exec function for a binary ALU
 * instruction.
 *
 * Expands to:
 *   - static constexpr SIBFn <name>_sib_reg_dst[4]  (direction=0 table)
 *   - static constexpr SIBFn <name>_sib_mem_dst[4]  (direction=1 table)
 *   - void exec_instr_<name>_sib(ProcessVM*, const DecodedInstr&)
 */
#define DEFINE_SIB_EXEC(name, Op)                                              \
    static constexpr SIBFn name##_sib_reg_dst[] = {                            \
        &sib_reg_dst_wrapper<uint8_t, Op>, &sib_reg_dst_wrapper<uint16_t, Op>, \
        &sib_reg_dst_wrapper<uint32_t, Op>,                                    \
        &sib_reg_dst_wrapper<uint64_t, Op>};                                   \
    static constexpr SIBFn name##_sib_mem_dst[] = {                            \
        &sib_mem_dst_wrapper<uint8_t, Op>, &sib_mem_dst_wrapper<uint16_t, Op>, \
        &sib_mem_dst_wrapper<uint32_t, Op>,                                    \
        &sib_mem_dst_wrapper<uint64_t, Op>};                                   \
    void exec_instr_##name##_sib(ProcessVM *vm, const DecodedInstr &instr) {   \
        exec_sib_generic<Op>(vm, instr, name##_sib_reg_dst,                    \
                             name##_sib_mem_dst);                              \
    }

DEFINE_SIB_EXEC(add, AddOp)
DEFINE_SIB_EXEC(sub, SubOp)
DEFINE_SIB_EXEC(mul, MulOp)
DEFINE_SIB_EXEC(div, DivOp)
DEFINE_SIB_EXEC(cmp, CmpOp)

#undef DEFINE_SIB_EXEC

// =========================================================================
// MOV SIB (special: s=1 means MOVH -- access host/native memory)
// =========================================================================

/**
 * @brief Executes a MOV or MOVH SIB instruction.
 *
 * s=0 (MOVC): accesses virtual machine memory.
 * s=1 (MOVH): accesses host process memory directly via native pointer.
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Decoded instruction with mem_data, flags_info fields.
 */
void exec_instr_mov_sib(ProcessVM *vm, const DecodedInstr &instr) {
    const int dst =
        instr.data_instruction.mem_data.reg_final; // register counterpart
    uint64_t addr = sib_effective_addr(vm, instr); // effective address
    uint64_t rval = vm->registers.regs[dst].raw(); // register value
    int mode = instr.flags_info.mode;              // operand width
    bool host =
        instr.flags_info._signed_instruct; // s=1 selects MOVH (host memory)

    if (!host) {
        // MOVC: access virtual machine memory
        if (instr.flags_info.direction == 0)
            mov_sib_to_reg_table[mode](vm, addr, rval, false,
                                       dst); // load from VM mem
        else
            mov_sib_to_mem_table[mode](vm, addr, rval, false,
                                       dst); // store to VM mem
    } else {
        // MOVH: access host native memory
        if (instr.flags_info.direction == 0)
            movh_to_reg_table[mode](vm, addr, rval, false,
                                    dst); // load from host mem
        else
            movh_to_mem_table[mode](vm, addr, rval, false,
                                    dst); // store to host mem
    }
}

// =========================================================================
// MOVC / MOVCH -- conditional move based on a flag
// =========================================================================

/**
 * @brief Reads a flag register value by its 3-bit code.
 *
 * Flag code encoding: SF=0, ZF=1, CF=2, OF=3, DM=4.
 *
 * @param vm        Pointer to the virtual machine.
 * @param flag_code 3-bit flag selector.
 * @return          Boolean value of the selected flag.
 */
inline bool read_flag(ProcessVM *vm, uint8_t flag_code) {
    switch (flag_code & 0x7) {
    case 0: return vm->registers.flags.bits.SF; // sign flag
    case 1: return vm->registers.flags.bits.ZF; // zero flag
    case 2: return vm->registers.flags.bits.CF; // acarreo flag
    case 3: return vm->registers.flags.bits.OF; // desbordamiento flag
    case 4: return vm->registers.flags.DM; // direction / mode flag
    default: return false; // unknown code: treated as not set
    }
}

/**
 * @brief Executes MOVC/MOVCH with a memory operand (opcode2 = 0x1E).
 *
 * Encoding: [0x00][0x1E][ctrl][byte4]
 *   ctrl: host_bits(2)|d(1)|r_nonbracket(5)   bits[7:6]=0b10->MOVCH, 0b00->MOVC
 *   byte4: flag_code(3)|r_bracket(5)
 *
 * Moves data only if the specified flag is set.
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Decoded instruction fields (see above encoding).
 */
void exec_instr_movc_mem(ProcessVM *vm, const DecodedInstr &instr) {
    uint8_t flag_code =
        instr.data_instruction.reg_data.reg2; // 3-bit flag selector from byte4
    uint8_t reg1 =
        instr.data_instruction.reg_data.reg1; // the non-bracketed register
    uint8_t reg2 =
        instr.data_instruction.inmmed_data.reg; // the register inside []
    bool host = instr.flags_info
                    ._signed_instruct; // 0=MOVC (VM mem), 1=MOVCH (host mem)
    bool dir = instr.flags_info.direction; // 0=[reg2]->reg1, 1=reg2->[reg1]

    if (!read_flag(vm, flag_code)) return; // condition not met: skip the move

    // determine which register holds the memory address and which holds the
    // value
    uint64_t addr =
        vm->registers.regs[dir ? reg1 : reg2].raw(); // address register
    uint64_t val =
        vm->registers.regs[dir ? reg2 : reg1].raw(); // value register

    if (!host) {
        // MOVC: use virtual machine memory
        if (!dir) {
            uint64_t v =
                vm->vm_mem.read_u64(addr); // load 64-bit value from VM memory
            vm->registers.regs[reg1].qword(v); // write to destination register
        } else {
            vm->vm_mem.write_u64(addr,
                                 val); // write register value to VM memory
        }
    } else {
        // MOVCH: use host process memory
        if (!dir) {
            uint64_t v = *reinterpret_cast<const uint64_t *>(
                addr);                         // load from native pointer
            vm->registers.regs[reg1].qword(v); // write to destination register
        } else {
            *reinterpret_cast<uint64_t *>(addr) =
                val; // write register value to native address
        }
    }
}

/**
 * @brief Executes MOVC reg, reg, flag (opcode2 = 0x1F).
 *
 * Encoding: [0x00][0x1F][ctrl][byte4]
 *   ctrl: 0b00|0|reg1(4)
 *   byte4: flag_code(3)|reg2(5)
 *
 * Copies reg2 to reg1 only if the specified flag is set; uses mode for width.
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Decoded instruction fields.
 */
void exec_instr_movc_reg(ProcessVM *vm, const DecodedInstr &instr) {
    uint8_t flag_code =
        instr.data_instruction.reg_data.reg2; // 3-bit flag selector
    uint8_t reg1 =
        instr.data_instruction.reg_data.reg1; // destination register index
    uint8_t reg2 =
        instr.data_instruction.inmmed_data.reg; // source register index

    if (!read_flag(vm, flag_code)) return; // condition not met: skip the move

    GeneralRegister tmp;
    tmp.qword(
        vm->registers.regs[reg2].raw()); // copy source into temp (full 64-bit)
    mov_table[instr.flags_info.mode](vm, vm->registers.regs[reg1], tmp, false,
                                     reg1); // conditional MOV at mode width
}

// =========================================================================
// ModOp -- modulo entero (resto de la division)
//
// mods/modu: r_dst = r_dst % r_src
// Resultado indefinido si el divisor es cero; en ese caso se activan CF y OF
// para que el programa pueda detectar el error.
// =========================================================================

/**
 * @brief MOD / UMOD: resto de la division entera.
 *
 * - Con signo  (mods): resultado tiene el signo del dividendo (semantica C %).
 * - Sin signo  (modu): resultado siempre no negativo.
 * Division por cero: resultado = 0, CF = 1, OF = 1.
 */
struct ModOp {
    static constexpr bool is_compare =
        false; // el resultado se escribe de vuelta
    static constexpr bool is_division = true; // trait para compute_with_flags

    /** @brief Returns a % b (divide-by-zero must be checked externally; we
     * return 0). */
    template <typename T> static inline T compute(T a, T b) {
        if (b == 0)
            return static_cast<T>(
                0); // division por cero: resultado definido como 0
        return a % b;
    }

    /** @brief Devuelve CF|OF si hubo division por cero; cero si no. */
    template <typename T>
    static inline uint8_t flags(ProcessVM * /*vm*/, T /*a*/, T b, T /*result*/,
                                bool /*is_signed*/) {
        // b == 0 es la condicion excepcional; lo demas es una operacion normal
        return b == 0 ? (uint8_t)(RF_OF | RF_CF) : 0;
    }
};

// re-declarar los macros de tablas para ModOp (fueron indefinidos tras las
// instrucciones ALU base)
#define DECL_BIN_TABLE(n, Op)                                                  \
    static constexpr BinaryFn n##_table[] = {                                  \
        &binary_wrapper<uint8_t, Op>, &binary_wrapper<uint16_t, Op>,           \
        &binary_wrapper<uint32_t, Op>, &binary_wrapper<uint64_t, Op>}

#define DECL_IMM_TABLES(n, Op)                                                 \
    static constexpr BinaryImmFn n##_imm_table[] = {                           \
        &binary_imm_wrapper<uint8_t, Op>, &binary_imm_wrapper<uint16_t, Op>,   \
        &binary_imm_wrapper<uint32_t, Op>, &binary_imm_wrapper<uint64_t, Op>}; \
    static constexpr BinaryMemImmFn n##_mem_imm_table[] = {                    \
        &binary_mem_imm_wrapper<uint8_t, Op>,                                  \
        &binary_mem_imm_wrapper<uint16_t, Op>,                                 \
        &binary_mem_imm_wrapper<uint32_t, Op>,                                 \
        &binary_mem_imm_wrapper<uint64_t, Op>}

#define DEFINE_REG_EXEC(n)                                                     \
    void exec_instr_##n##_reg(ProcessVM *vm, const DecodedInstr &instr) {      \
        const int rdst = instr.data_instruction.reg_data.reg1;                 \
        const int rsrc = instr.data_instruction.reg_data.reg2;                 \
        n##_table[instr.flags_info.mode](                                      \
            vm, vm->registers.regs[rdst], vm->registers.regs[rsrc],            \
            instr.flags_info._signed_instruct, rdst);                          \
    }

#define DEFINE_IMM_EXEC(n, imm_tbl, mem_tbl)                                   \
    void exec_instr_##n##_imm(ProcessVM *vm, const DecodedInstr &instr) {      \
        const int rdst = instr.data_instruction.inmmed_data.reg;               \
        uint64_t imm = instr.data_instruction.inmmed_data.inmmed;              \
        if (instr.flags_info.direction == 0) {                                 \
            imm_tbl[instr.flags_info.mode](vm, vm->registers.regs[rdst], imm,  \
                                           instr.flags_info._signed_instruct,  \
                                           rdst);                              \
            return;                                                            \
        }                                                                      \
        uint64_t addr = vm->registers.regs[rdst].raw();                        \
        mem_tbl[instr.flags_info.mode](vm, addr, imm,                          \
                                       instr.flags_info._signed_instruct);     \
    }

#define DEFINE_SIB_EXEC(n, Op)                                                 \
    static constexpr SIBFn n##_sib_reg_dst[] = {                               \
        &sib_reg_dst_wrapper<uint8_t, Op>, &sib_reg_dst_wrapper<uint16_t, Op>, \
        &sib_reg_dst_wrapper<uint32_t, Op>,                                    \
        &sib_reg_dst_wrapper<uint64_t, Op>};                                   \
    static constexpr SIBFn n##_sib_mem_dst[] = {                               \
        &sib_mem_dst_wrapper<uint8_t, Op>, &sib_mem_dst_wrapper<uint16_t, Op>, \
        &sib_mem_dst_wrapper<uint32_t, Op>,                                    \
        &sib_mem_dst_wrapper<uint64_t, Op>};                                   \
    void exec_instr_##n##_sib(ProcessVM *vm, const DecodedInstr &instr) {      \
        exec_sib_generic<Op>(vm, instr, n##_sib_reg_dst, n##_sib_mem_dst);     \
    }

DECL_BIN_TABLE(mod, ModOp);
DECL_IMM_TABLES(mod, ModOp);
DEFINE_SIB_EXEC(mod, ModOp)
DEFINE_REG_EXEC(mod)
DEFINE_IMM_EXEC(mod, mod_imm_table, mod_mem_imm_table)

#undef DEFINE_REG_EXEC
#undef DEFINE_IMM_EXEC
#undef DEFINE_SIB_EXEC
#undef DECL_BIN_TABLE
#undef DECL_IMM_TABLES

// =========================================================================
// SETCC -- almacena el resultado de una condicion de flags en un registro
//
// Encoding FIXED_4: [0x00][0x43][ctrl][0x00]
//   ctrl = (cond<<4) | dst_reg    (cond: mismo codigo que JCC)
// El registro destino recibe 1 si la condicion es verdadera, 0 si no.
// =========================================================================

/**
 * @brief Ejecuta SETCC r_dst, cond: escribe 0 o 1 segun la condicion de flags.
 *
 * Usa el mismo codigo de condicion que JCC (0x00 = JO, 0x01 = JNO, ..., 0x0E =
 * JLE, 0x0F = JMP/true).
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Instruccion descodificada; cond en reg1>>4, dst en reg1&0xF (o
 * via byte2).
 */
void exec_instr_setcc(ProcessVM *vm, const DecodedInstr &instr) {
    // byte2: bits[7:4] = condicion, bits[3:0] = registro destino
    const uint8_t cond = (instr.data_instruction.reg_data.reg1 >> 4) &
                         0xF; // codigo de condicion
    const uint8_t dst_reg = instr.data_instruction.reg_data.reg1 &
                            0xF; // indice del registro destino

    auto &f = vm->registers.flags.bits;
    bool taken = false; // resultado de la condicion

    switch (cond) {
    case 0x00: taken = f.OF; break;           // JO
    case 0x01: taken = !f.OF; break;          // JNO
    case 0x02: taken = f.CF; break;           // JB/JNAE
    case 0x03: taken = !f.CF; break;          // JNB/JAE
    case 0x04: taken = f.ZF; break;           // JE/JZ
    case 0x05: taken = !f.ZF; break;          // JNE/JNZ
    case 0x06: taken = f.CF || f.ZF; break;   // JBE/JNA
    case 0x07: taken = !f.CF && !f.ZF; break; // JNBE/JA
    case 0x08: taken = f.SF; break;           // JS
    case 0x09: taken = !f.SF; break;          // JNS
    case 0x0A:
        taken = f.ZF && !(f.SF ^ f.OF);
        break;                       // JE y sin desbordamiento con signo
    case 0x0B: taken = !f.ZF; break; // JNE (alias JNLE)
    case 0x0C: taken = (f.SF ^ f.OF); break;         // JL/JNGE
    case 0x0D: taken = !(f.SF ^ f.OF); break;        // JNL/JGE
    case 0x0E: taken = f.ZF || (f.SF ^ f.OF); break; // JLE/JNG
    case 0x0F: taken = true; break;                  // siempre verdadero
    default: taken = false; break;
    }

    vm->registers.regs[dst_reg].qword(
        taken ? 1 : 0); // escribir resultado booleano en el registro
}

/**
 * @brief SEXT r_dst, N: sign-extiende r_dst desde N bits (8/16/32) a 64.
 *
 * b2 (reg1) = r_dst en el nibble bajo; b3 (reg2) = N (ancho fuente en bits).
 * Equivale a `shl r_dst, 64-N; sar r_dst, 64-N` (replica el bit de signo) pero
 * en una sola instruccion, sin quemar un scratch para el conteo de shift.  El
 * IR emitter lo emite donde antes ponia mov+shl+sar para el ensanchamiento con
 * signo de i8/i16/i32 a i64.
 */
void exec_instr_sext(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t dst_reg =
        instr.data_instruction.reg_data.reg1 & 0xF; // r_dst (nibble bajo)
    const uint8_t width = instr.data_instruction.reg_data.reg2; // N bits
    const uint64_t v = vm->registers.regs[dst_reg].qword();
    uint64_t res;
    switch (width) {
    case 8:
        res =
            static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(v)));
        break;
    case 16:
        res = static_cast<uint64_t>(
            static_cast<int64_t>(static_cast<int16_t>(v)));
        break;
    case 32:
        res = static_cast<uint64_t>(
            static_cast<int64_t>(static_cast<int32_t>(v)));
        break;
    default: {
        // Ancho arbitrario < 64: shl + sar aritmetico (enmascara el shift).
        const uint32_t sh = (64u - (static_cast<uint32_t>(width) & 63u)) & 63u;
        res = static_cast<uint64_t>(static_cast<int64_t>(v << sh) >> sh);
        break;
    }
    }
    vm->registers.regs[dst_reg].qword(res);
}

// =========================================================================
// CMPJMP / CMPJMPU / DECJNZ -- fusion de cmp+jcc / dec+jnz (mejora hot loops)
// =========================================================================

/**
 * @brief Helper interno: evalua el cond_byte (0x00..0x0D) contra los flags.
 *
 * Usa el mismo set que @c exec_instr_jmp y @c jmp.j*.  cond_byte > 0x0D
 * cae al default = true (incondicional).  Sin syscalls; pure CPU work.
 */
// El tipo del campo flags::bits es interno; declaramos el helper como
// template para deducir el tipo automaticamente sin requerir -fconcepts-ts.
template <typename FlagsBits>
static inline bool eval_jmp_cond(uint8_t cond, const FlagsBits &fl) noexcept {
    switch (cond) {
    case 0x00: return COND_EQ(fl);                    // ZF==1
    case 0x01: return COND_NE(fl);                    // ZF==0
    case 0x02: return COND_CS(fl);                    // CF==1
    case 0x03: return COND_CC(fl);                    // CF==0
    case 0x04: return COND_MI(fl);                    // SF==1
    case 0x05: return COND_PL(fl);                    // SF==0
    case 0x06: return COND_VS(fl);                    // OF==1
    case 0x07: return COND_VC(fl);                    // OF==0
    case 0x08: return COND_HI(fl);                    // CF==0 && ZF==0
    case 0x09: return COND_LS(fl);                    // CF==1 || ZF==1
    case 0x0A: return COND_GE(fl);                    // SF==OF
    case 0x0B: return COND_LT(fl);                    // SF!=OF
    case 0x0C: return (fl.ZF == 0 && fl.SF == fl.OF); // GT
    case 0x0D: return (fl.ZF == 1 || fl.SF != fl.OF); // LE
    default: return true;
    }
}

/**
 * @brief Helper interno: hace cmp (a-b) + setea flags ZF/SF/CF/OF segun
 *        signo, sin escribir resultado.  Reusa @c compute_with_flags +
 *        @c CmpOp para mantener exactamente la misma semantica que las
 *        instrucciones @c cmps / @c cmpu separadas.
 */
static inline void cmpjmp_set_flags(ProcessVM *vm, uint64_t a, uint64_t b,
                                    bool is_signed) {
    (void)compute_with_flags<uint64_t, CmpOp>(vm, a, b, is_signed);
}

/**
 * @brief Implementacion de @c cmpjmp r_a, r_b, target (signed).
 *
 * Equivalente atomic a:
 *   cmps r_a, r_b
 *   jmp.cond target
 * en una sola instruccion VM (reduce 2 instr -> 1 por comparacion).
 */
void exec_instr_cmpjmp(ProcessVM *vm, const DecodedInstr &instr) {
    const auto &sd = instr.data_instruction.static_data;
    const uint64_t a = vm->registers.regs[sd.r0].qword();
    const uint64_t b = vm->registers.regs[sd.r1].qword();
    cmpjmp_set_flags(vm, a, b, /*is_signed=*/true);
    const bool taken =
        eval_jmp_cond(static_cast<uint8_t>(sd._pad), vm->registers.flags.bits);
    // Sprint D.6: profile counter para branches fusionados.
    {
        const uint64_t bpc = vm->registers.rip.raw();
        runtime::profile::lite_profile_branch(bpc, taken);
        if (__builtin_expect(runtime::profile::g_profile.active.load(
                                 std::memory_order_relaxed),
                             0)) {
            runtime::profile::profile_branch(bpc, taken);
        }
    }
    if (taken) {
        write_rip(vm, static_cast<uint64_t>(sd.offset)); // salto absoluto u32
    }
}

/**
 * @brief Implementacion de @c cmpjmpu r_a, r_b, target (unsigned).
 *
 * Identica a @c exec_instr_cmpjmp pero con semantica unsigned (CmpOp con
 * is_signed=false: CF se setea segun a<b unsigned, OF queda en 0).
 */
void exec_instr_cmpjmpu(ProcessVM *vm, const DecodedInstr &instr) {
    const auto &sd = instr.data_instruction.static_data;
    const uint64_t a = vm->registers.regs[sd.r0].qword();
    const uint64_t b = vm->registers.regs[sd.r1].qword();
    cmpjmp_set_flags(vm, a, b, /*is_signed=*/false);
    const bool taken =
        eval_jmp_cond(static_cast<uint8_t>(sd._pad), vm->registers.flags.bits);
    // Sprint D.6: profile counter para branches fusionados unsigned.
    {
        const uint64_t bpc = vm->registers.rip.raw();
        runtime::profile::lite_profile_branch(bpc, taken);
        if (__builtin_expect(runtime::profile::g_profile.active.load(
                                 std::memory_order_relaxed),
                             0)) {
            runtime::profile::profile_branch(bpc, taken);
        }
    }
    if (taken) {
        write_rip(vm, static_cast<uint64_t>(sd.offset));
    }
}

/**
 * @brief Implementacion de @c decjnz r_counter, target.
 *
 * Equivalente atomic a:
 *   subs r_counter, 1   ; r_counter -= 1, setea flags
 *   jmp.jne target      ; salta si ZF==0 (resultado != 0)
 * en una sola instruccion VM.  Reduce 2-3 instr -> 1 por iteracion en
 * loops contadores.  Tambien ahorra el `mov r14, 1` necesario para subs
 * (que requiere reg, no imm).
 */
void exec_instr_decjnz(ProcessVM *vm, const DecodedInstr &instr) {
    const auto &sd = instr.data_instruction.static_data;
    const int reg_idx = sd.r0;
    const uint64_t old_val = vm->registers.regs[reg_idx].qword();
    // dec = a - 1.  Reusa SubOp para flags consistentes con `subs r, 1`.
    const uint64_t new_val = compute_with_flags<uint64_t, SubOp>(
        vm, old_val, /*b=*/1ULL, /*is_signed=*/true);
    vm->registers.regs[reg_idx].qword(new_val);
    // Saltar si new_val != 0 (equivale a jmp.jne post-subs).
    const bool taken = (new_val != 0ULL);
    // Sprint D.6: profile counter para decjnz (loop counter).
    {
        const uint64_t bpc = vm->registers.rip.raw();
        runtime::profile::lite_profile_branch(bpc, taken);
        if (__builtin_expect(runtime::profile::g_profile.active.load(
                                 std::memory_order_relaxed),
                             0)) {
            runtime::profile::profile_branch(bpc, taken);
        }
    }
    if (taken) {
        write_rip(vm, static_cast<uint64_t>(sd.offset));
    }
}

/**
 * @brief Ejecuta @c fastpush <mask16>: empuja a la pila N registros marcados
 *        en el bitmask en una sola instruccion.
 *
 * Estrategia hardware-aware:
 *   1. @c __builtin_popcount calcula N en 1 ciclo (POPCNT instr en x86-64).
 *   2. Decrementa RSP por (N*8) en una sola escritura al registro.
 *   3. @c __builtin_ctz extrae el indice del bit set mas bajo en O(1) por
 *      iteracion (TZCNT/BSF), evitando un loop de 16 iteraciones con if.
 *   4. @c mask &= mask - 1 limpia el bit set mas bajo en 1 ciclo.
 *   5. Las escrituras se hacen lineales en memoria, lo que la CPU prefetch
 *      detecta y optimiza con write-combining + cache line filling.
 *
 * Convencion: r0 es el PRIMER push (mayor offset relativo a rsp final),
 * r_max_set es el ULTIMO push (rsp final).  Esto permite que @c fastpop
 * con el mismo mask restaure los valores exactamente.
 */
void exec_instr_fastpush(ProcessVM *vm, const DecodedInstr &instr) {
    uint16_t mask = instr.data_instruction.mask_data.mask;
    if (mask == 0) return; // no-op: ningun bit puesto

    const int count = __builtin_popcount(static_cast<unsigned int>(mask));
    const uint64_t old_rsp = vm->registers.stack_pointer.qword();
    const uint64_t new_rsp = old_rsp - static_cast<uint64_t>(count) * 8ULL;
    vm->registers.stack_pointer.qword(new_rsp);

    // r0 se empuja primero (queda en el offset MAS alto del nuevo frame).
    // Iteramos los bits ascendentes y escribimos a offsets descendentes.
    uint64_t slot = new_rsp + static_cast<uint64_t>(count - 1) * 8ULL;
    while (mask) {
        const int r = __builtin_ctz(static_cast<unsigned int>(mask));
        const uint64_t val = vm->registers.regs[r].qword();
        // write_u64_fast: los slots del frame caen todos en la MISMA pagina
        // (el stack es contiguo), asi que el page-cache acierta tras el primer
        // acceso -> memcpy directo (~1 ns) en vez de un TLB walk completo por
        // registro (~50 ns).  fastpush/pop envuelven CADA calln (save/restore
        // de regs vivos), asi que este era el grueso del coste de las llamadas
        // nativas en el interp.
        vm->vm_mem.write_u64_fast(slot, val);
        slot -= 8;
        mask &= static_cast<uint16_t>(mask - 1); // limpiar bit mas bajo
    }
}

/**
 * @brief Ejecuta @c fastpop <mask16>: desempila N registros del bitmask en
 *        orden simetrico a @c fastpush.
 *
 * Misma estrategia hardware (POPCNT + TZCNT + bit clearing).  Las lecturas
 * son lineales en memoria, optimas para prefetch.
 *
 * Para un mismo mask, @c fastpop revierte exactamente el efecto de
 * @c fastpush: lee del slot de cada registro y avanza RSP por N*8 al final.
 */
void exec_instr_fastpop(ProcessVM *vm, const DecodedInstr &instr) {
    uint16_t mask = instr.data_instruction.mask_data.mask;
    if (mask == 0) return;

    const int count = __builtin_popcount(static_cast<unsigned int>(mask));
    const uint64_t rsp = vm->registers.stack_pointer.qword();

    // Mismo orden de iteracion que fastpush, lectura desde offsets
    // descendentes -> los valores se restauran a los registros correctos.
    uint64_t slot = rsp + static_cast<uint64_t>(count - 1) * 8ULL;
    while (mask) {
        const int r = __builtin_ctz(static_cast<unsigned int>(mask));
        // read_u64_fast: mismo page-cache que fastpush (frame contiguo).
        const uint64_t val = vm->vm_mem.read_u64_fast(slot);
        vm->registers.regs[r].qword(val);
        slot -= 8;
        mask &= static_cast<uint16_t>(mask - 1);
    }

    vm->registers.stack_pointer.qword(rsp +
                                      static_cast<uint64_t>(count) * 8ULL);
}

// =========================================================================
// SUPER-INSTRUCCIONES ALU 3-OPERANDOS (0x73-0x7B)
//
// Combinan el patron `mov rd, rs1; OP rd, rs2` en una sola instruccion VM.
// Eliminacion del MOV intermedio cuando el regalloc no puede coalescer dst
// con src1 (caso comun del 2-address codegen del IR emitter).
//
// Encoding FIXED_4: [0x00][opcode2][byte2][byte3]
//   byte2 = (r_src1 << 4) | r_dst       (Convention B: decode_instr_raw_bytes
//                                         deja byte2 en reg1, byte3 en reg2)
//   byte3 = (r_src2 << 4) | flags_low   (flags reservados, low nibble = 0)
//
// La operacion se identifica por @c flags_info.opcode_index:
//   0x73 adds3, 0x74 subs3, 0x75 muls3,
//   0x76 addu3, 0x77 subu3, 0x78 mulu3,
//   0x79 and3,  0x7A or3,   0x7B xor3.
//
// Flags actualizados igual que las variantes 2-op tradicionales (ZF/SF/CF/OF).
// =========================================================================

/**
 * @brief Ejecuta una super-instruccion ALU 3-operandos.
 *
 * Lee r_src1 y r_src2 (de byte2 y byte3 respectivamente, despues de
 * decode_instr_raw_bytes), realiza la operacion identificada por opcode_index,
 * y almacena el resultado en r_dst.  Actualiza flags ZF/SF/CF/OF segun la
 * semantica de la operacion (signed vs unsigned).
 *
 * @param vm    Puntero a la maquina virtual.
 * @param instr Instruccion descodificada con byte2 en reg1, byte3 en reg2.
 */
void exec_instr_alu3(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t b2 = instr.data_instruction.reg_data.reg1;
    const uint8_t b3 = instr.data_instruction.reg_data.reg2;
    const uint8_t r_dst = b2 & 0x0F;
    const uint8_t r_src1 = (b2 >> 4) & 0x0F;
    const uint8_t r_src2 = (b3 >> 4) & 0x0F;
    const uint8_t opc = instr.flags_info.opcode_index;

    auto &regs = vm->registers.regs;
    const uint64_t a = regs[r_src1].qword();
    const uint64_t b = regs[r_src2].qword();
    uint64_t res = 0;

    /* Cada caso produce el resultado y SOLO sus bits CF/OF; ZF y SF son iguales
     * en las nueve variantes, asi que se calculan una vez al salir y todo se
     * escribe de UNA vez.
     *
     * Antes cada rama hacia cuatro asignaciones a campos de bits del mismo
     * byte, o sea cuatro lee-modifica-escribe encadenados.  Aparte del coste,
     * eso hacia que el derivador de efectos viera `adds3` LEYENDO las
     * banderas, cuando no las lee: la explicacion larga esta en
     * `include/runtime/rflags.h`.  Importa mas aqui que en `adds` normal,
     * porque estas son las que emite el IR cuando el asignador de registros no
     * pudo coalescer -- o sea, camino caliente. */
    uint8_t cf_of = 0;

    switch (opc) {
    case 0x73:
    case 0x76: // adds3 / addu3
        res = a + b;
        if (opc == 0x73) {
            if (((static_cast<int64_t>(a) ^ static_cast<int64_t>(res)) &
                 (static_cast<int64_t>(b) ^ static_cast<int64_t>(res))) < 0)
                cf_of = RF_OF; // con signo: desborda, y no toca CF
        } else if (res < a) {
            cf_of = RF_CF; // sin signo: acarreo, y no toca OF
        }
        break;
    case 0x74:
    case 0x77: // subs3 / subu3
        res = a - b;
        if (opc == 0x74) {
            if (((static_cast<int64_t>(a) ^ static_cast<int64_t>(b)) &
                 (static_cast<int64_t>(a) ^ static_cast<int64_t>(res))) < 0)
                cf_of = RF_OF;
        } else if (a < b) {
            cf_of = RF_CF;
        }
        break;
    case 0x75: // muls3
        res = static_cast<uint64_t>(static_cast<int64_t>(a) *
                                    static_cast<int64_t>(b));
        break;
    case 0x78: res = a * b; break; // mulu3
    case 0x79: res = a & b; break; // and3
    case 0x7A: res = a | b; break; // or3
    case 0x7B: res = a ^ b; break; // xor3
    default: return;               // opcode que no es de esta familia
    }

    regs[r_dst].qword(res);
    uint8_t nf = cf_of;
    if (res == 0) nf |= RF_ZF;
    if (static_cast<int64_t>(res) < 0) nf |= RF_SF;
    vm->registers.flags.arith = nf; // store PURO, sin leer el valor anterior
}

// =========================================================================
// LOADZ / LOADZH (0x7C / 0x7D): super-instr LOAD con zero-extend a 64-bit
//
// Combina @c mov rd,0 + @c mov rd_sized,[rs] en una sola instruccion VM.
// La VM no zero-extiende implicitamente al escribir bytes parciales en un
// reg (a diferencia de x86-64); por eso el IR emitter tipicamente emite el
// @c mov rd,0 previo cuando carga i8/i16/i32 desde memoria.  loadz/loadzh
// elimina esa instruccion adicional cargando el valor con zero-extend en
// un solo paso.
//
// Encoding (FIXED_4, ya decoded por decode_instr_simple_mov):
//   ctrl bits 7-6 = mode (0=8b, 1=16b, 2=32b, 3=64b)  -> @c flags_info.mode
//   ctrl bit  5   = is_host  -> @c flags_info._signed_instruct
//   regs:  reg1 (low nibble)  = r_dst
//          reg2 (high nibble) = r_src (puntero base 64-bit)
// =========================================================================
void exec_instr_loadz(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_src = instr.data_instruction.reg_data.reg2;
    const uint8_t mode = instr.flags_info.mode;
    const bool is_host = (instr.flags_info._signed_instruct != 0);
    const uint64_t addr = vm->registers.regs[r_src].qword();

    uint64_t val;
    if (is_host) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(addr);
        switch (mode) {
        case 0: val = *p; break;
        case 1: val = *reinterpret_cast<const uint16_t *>(p); break;
        case 2: val = *reinterpret_cast<const uint32_t *>(p); break;
        default: val = *reinterpret_cast<const uint64_t *>(p); break;
        }
    } else {
        switch (mode) {
        case 0: val = vm->vm_mem.read_u8(addr); break;
        case 1: val = vm->vm_mem.read_u16(addr); break;
        case 2: val = vm->vm_mem.read_u32(addr); break;
        default: val = vm->vm_mem.read_u64(addr); break;
        }
    }
    vm->registers.regs[r_dst].qword(
        val); // qword() escribe 64 bits = zero-extend implicito
}

} // namespace runtime
