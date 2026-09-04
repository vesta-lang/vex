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
 * @file vm_registers.h                                                        \
 * @brief Definicion del banco de registros de la maquina virtual de VestaVM.  \
 *                                                                             \
 * Define @c VMRegisters: los 16 registros de proposito general (R00-R15),     \
 * los registros especiales PC, SP, BP, el registro de flags @c RFlags         \
 * y el modo de operacion (ancho de operando).                                 \
 */                                                                            \
#ifndef VM_REGISTERS_H
#define VM_REGISTERS_H

#include <string>

#include "rflags.h"
#include "cli/sync_io.h"

namespace runtime {

/**
 * @brief Identificadores de los registros de proposito general.
 *
 * Los valores R00..R15 indexan el array regs[] de context_registers_vm.
 * COUNT indica cuantos registros de proposito general existen (16).
 */
enum RegID {
    R00,
    R01,
    R02,
    R03, ///< Registros de proposito general 0 a 3
    R04,
    R05,
    R06,
    R07, ///< Registros de proposito general 4 a 7
    R08,
    R09,
    R10,
    R11, ///< Registros de proposito general 8 a 11
    R12,
    R13,
    R14,
    R15,  ///< Registros de proposito general 12 a 15
    COUNT ///< Numero total de registros de proposito general
};

/**
 * @class GeneralRegister
 * @brief Registro de 64 bits con acceso tipado a sus partes.
 *
 * Encapsula un entero de 64 bits y expone metodos de lectura/escritura
 * para cada subdivision estandar:
 *   - byte_lo / byte_hi  -- byte bajo/alto de los 16 bits inferiores
 *   - word_lo / word_hi  -- word de 16 bits inferior/superior
 *   - dword_lo / dword_hi -- dword de 32 bits inferior/superior
 *   - qword              -- valor completo de 64 bits
 *
 * Todas las escrituras usan zero-extension automatica para no modificar
 * las partes del registro que no se especifican.
 */
class GeneralRegister {
  private:
    uint64_t data = 0; ///< Valor interno del registro (64 bits)

  public:
    /**
     * @brief Lee el byte bajo (bits 7:0) con zero-extension.
     * @return Byte menos significativo del registro.
     */
    [[nodiscard]] uint8_t byte_lo() const {
        return static_cast<uint8_t>(data & 0xFF); // enmascarar bits 7:0
    }

    /**
     * @brief Lee el byte alto de los 16 bits bajos (bits 15:8).
     * @return Byte en la posicion bits 15:8.
     */
    [[nodiscard]] uint8_t byte_hi() const {
        return static_cast<uint8_t>((data >> 8) &
                                    0xFF); // desplazar y enmascarar bits 15:8
    }

    /**
     * @brief Lee los 16 bits bajos (bits 15:0) con zero-extension.
     * @return Word menos significativo del registro.
     */
    [[nodiscard]] uint16_t word_lo() const {
        return static_cast<uint16_t>(data & 0xFFFF); // enmascarar bits 15:0
    }

    /**
     * @brief Lee los 16 bits mas altos (bits 63:48).
     * @return Word en la posicion bits 63:48.
     */
    [[nodiscard]] uint16_t word_hi() const {
        return static_cast<uint16_t>(
            (data >> 48) & 0xFFFF); // desplazar y enmascarar bits 63:48
    }

    /**
     * @brief Lee los 32 bits bajos (bits 31:0) con zero-extension.
     * @return Dword menos significativo del registro.
     */
    [[nodiscard]] uint32_t dword_lo() const {
        return static_cast<uint32_t>(data & 0xFFFFFFFF); // enmascarar bits 31:0
    }

    /**
     * @brief Lee los 32 bits altos (bits 63:32).
     * @return Dword en la posicion bits 63:32.
     */
    [[nodiscard]] uint32_t dword_hi() const {
        return static_cast<uint32_t>(
            (data >> 32) & 0xFFFFFFFF); // desplazar y enmascarar bits 63:32
    }

    /**
     * @brief Lee el valor completo de 64 bits del registro.
     * @return Valor de 64 bits.
     */
    [[nodiscard]] uint64_t qword() const {
        return data; // devolver el valor completo sin mascara
    }

    /**
     * @brief Escribe el byte bajo (bits 7:0) sin modificar el resto.
     * @param v Nuevo valor del byte bajo.
     * @return Referencia al propio registro para encadenamiento.
     */
    GeneralRegister &byte_lo(const uint8_t v) {
        data =
            (data & ~0xFFULL) | v; // limpiar bits 7:0 e insertar el nuevo valor
        return *this;
    }

    /**
     * @brief Escribe el byte alto de los 16 bits bajos (bits 15:8) sin
     * modificar el resto.
     * @param v Nuevo valor del byte.
     * @return Referencia al propio registro para encadenamiento.
     */
    GeneralRegister &byte_hi(const uint8_t v) {
        data = (data & ~0xFF00ULL) |
               (static_cast<uint64_t>(v) << 8); // insertar en bits 15:8
        return *this;
    }

    /**
     * @brief Escribe los 16 bits bajos (bits 15:0) sin modificar el resto.
     * @param v Nuevo valor del word bajo.
     * @return Referencia al propio registro para encadenamiento.
     */
    GeneralRegister &word_lo(const uint16_t v) {
        data = (data & ~0xFFFFULL) |
               v; // limpiar bits 15:0 e insertar el nuevo valor
        return *this;
    }

    /**
     * @brief Escribe los 16 bits mas altos (bits 63:48) sin modificar el resto.
     * @param v Nuevo valor del word alto.
     * @return Referencia al propio registro para encadenamiento.
     */
    GeneralRegister &word_hi(const uint16_t v) {
        data = (data & ~0xFFFF000000000000ULL) |
               (static_cast<uint64_t>(v) << 48); // insertar en bits 63:48
        return *this;
    }

    /**
     * @brief Escribe los 32 bits bajos (bits 31:0) sin modificar el resto.
     * @param v Nuevo valor del dword bajo.
     * @return Referencia al propio registro para encadenamiento.
     */
    GeneralRegister &dword_lo(const uint32_t v) {
        data = (data & 0xFFFFFFFF00000000ULL) |
               v; // conservar bits 63:32 e insertar bits 31:0
        return *this;
    }

    /**
     * @brief Escribe los 32 bits altos (bits 63:32) sin modificar el resto.
     * @param v Nuevo valor del dword alto.
     * @return Referencia al propio registro para encadenamiento.
     */
    GeneralRegister &dword_hi(const uint32_t v) {
        data = (data & 0xFFFFFFFFULL) |
               (static_cast<uint64_t>(v)
                << 32); // conservar bits 31:0 e insertar bits 63:32
        return *this;
    }

    /**
     * @brief Escribe el valor completo de 64 bits del registro.
     * @param v Nuevo valor de 64 bits.
     * @return Referencia al propio registro para encadenamiento.
     */
    GeneralRegister &qword(const uint64_t v) {
        data = v; // sobreescribir el valor completo
        return *this;
    }

    /**
     * @brief Lee el valor interno sin conversion (acceso directo al raw).
     * @return Valor de 64 bits tal como se almacena.
     */
    [[nodiscard]] uint64_t raw() const {
        return data; // acceso directo sin mascara ni conversion
    }

    /**
     * @brief Escribe el valor interno directamente (acceso raw).
     * @param v Nuevo valor de 64 bits.
     */
    void raw(const uint64_t v) {
        data = v; // asignacion directa sin mascaras
    }

    /**
     * @brief Genera una representacion textual del valor del registro.
     * @return Cadena con el valor en decimal.
     */
    [[nodiscard]] std::string to_string() const {
        std::ostringstream oss;
        oss << data; // convertir a decimal
        return oss.str();
    }
};

/**
 * @brief Registro vectorial de 512 bits con aliasing jerarquico ZMM/YMM/XMM/F.
 *
 * Almacena 64 bytes alineados a 64 bytes.  Modelo de aliasing identico a
 * AVX-512:
 *   - Escritura F   (64  bits): pone a cero bytes [8..63].
 *   - Escritura XMM (128 bits): pone a cero bytes [16..63].
 *   - Escritura YMM (256 bits): pone a cero bytes [32..63].
 *   - Escritura ZMM (512 bits): sobreescribe todos los bytes.
 *
 * ZMM0-ZMM15 se indexan igual que los registros generales R00-R15.
 */
struct ZmmRegister {
    alignas(64) uint8_t data[64] =
        {}; ///< Almacenamiento de 512 bits alineado a cache line

    /** @brief Lee el escalar double (IEEE 754 f64) de los bytes [0..7]. */
    [[nodiscard]] double read_f64() const {
        double v;
        __builtin_memcpy(&v, data, 8);
        return v;
    }

    /** @brief Escribe double y pone a cero bytes [8..63] (zeroing upper). */
    void write_f64(double v) {
        __builtin_memcpy(data, &v, 8);
        __builtin_memset(data + 8, 0, 56);
    }

    /**
     * @brief Escribe el escalar double SIN tocar los bytes [8..63].
     *
     * Es lo que usa la ARITMETICA escalar (`fadd`, `fsub`, `fmul`, `fdiv`), y
     * coincide con lo que hace el procesador: `ADDSD` de x86 escribe los ocho
     * bytes bajos y PRESERVA el resto del registro.  Solo `fmov` zerifica, que
     * es lo documentado para el.
     *
     * Antes toda escritura escalar zerificaba, y salia caro por partida doble:
     * `ZmmRegister::write_f64` aparecia como simbolo propio con el 11% del
     * banco de coma flotante, y el `memset` de 56 bytes chocaba con la lectura
     * de la instruccion siguiente -- Machine Clears al 11,5%, medido con VTune
     * y descartadas las asistencias de coma flotante, que salian a cero.
     *
     * `always_inline` porque son ocho bytes: sin el, GCC decidia por tamano y
     * dejaba una llamada donde tiene que haber un store.
     */
    [[gnu::always_inline]] inline void write_f64_keep(double v) {
        __builtin_memcpy(data, &v, 8);
    }

    /** @brief Lee el escalar float (IEEE 754 f32) de los bytes [0..3]. */
    [[nodiscard]] float read_f32() const {
        float v;
        __builtin_memcpy(&v, data, 4);
        return v;
    }

    /** @brief Escribe float y pone a cero bytes [4..63]. */
    void write_f32(float v) {
        __builtin_memcpy(data, &v, 4);
        __builtin_memset(data + 4, 0, 60);
    }

    /// @brief Escribe el escalar float SIN tocar los bytes [4..63].
    ///        Ver @ref write_f64_keep para el porque.
    [[gnu::always_inline]] inline void write_f32_keep(float v) {
        __builtin_memcpy(data, &v, 4);
    }

    /** @brief Lee 128 bits (XMM) al buffer @p dst (>= 16 bytes). */
    void read_xmm(void *dst) const { __builtin_memcpy(dst, data, 16); }

    /** @brief Escribe 128 bits y pone a cero bytes [16..63]. */
    void write_xmm(const void *src) {
        __builtin_memcpy(data, src, 16);
        __builtin_memset(data + 16, 0, 48);
    }

    /** @brief Lee 256 bits (YMM) al buffer @p dst (>= 32 bytes). */
    void read_ymm(void *dst) const { __builtin_memcpy(dst, data, 32); }

    /** @brief Escribe 256 bits y pone a cero bytes [32..63]. */
    void write_ymm(const void *src) {
        __builtin_memcpy(data, src, 32);
        __builtin_memset(data + 32, 0, 32);
    }

    /** @brief Lee 512 bits (ZMM) al buffer @p dst (>= 64 bytes). */
    void read_zmm(void *dst) const { __builtin_memcpy(dst, data, 64); }

    /** @brief Escribe 512 bits completos sin zeroing. */
    void write_zmm(const void *src) { __builtin_memcpy(data, src, 64); }

    /** @brief Puntero mutable al almacenamiento raw. */
    uint8_t *raw() { return data; }

    /** @brief Puntero constante al almacenamiento raw. */
    const uint8_t *raw() const { return data; }
};

/**
 * @brief Contexto completo de registros de un proceso virtual.
 *
 * Agrupa todos los registros que definen el estado de ejecucion de un
 * proceso:
 *   - stack_pointer: puntero al tope de la pila (SP).
 *   - base_pointer:  puntero a la base de la pila (BP).
 *   - rip:           contador de programa (PC/IP).
 *   - flags:         registro de banderas (RFlags_t).
 *   - regs[16]:      registros de proposito general R00..R15.
 *   - cur[4]:        registros cursor cur0..cur3 para uso interno.
 */
typedef struct context_registers_vm {
    GeneralRegister stack_pointer{}; ///< Puntero al tope de la pila (SP)
    GeneralRegister base_pointer{};  ///< Puntero a la base de la pila (BP)

    GeneralRegister
        rip{};        ///< Contador de programa / puntero de instruccion (PC)
    RFlags_t flags{}; ///< Registro de banderas de condicion

    GeneralRegister regs[16]; ///< Registros de proposito general R00..R15

    GeneralRegister cur[4]; ///< Registros cursor cur0..cur3 para uso interno

    ZmmRegister zmm[16]; ///< Banco vectorial ZMM0..ZMM15 (512 bits cada uno,
                         ///< aliasing YMM/XMM/F)
} context_registers_vm;

} // namespace runtime

#endif // VM_REGISTERS_H
