/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/target_reginfo.h
 * @brief Descriptor de registros por arquitectura para el register allocator
 *        ( D.7).  Capa 2 del diseno (ver doc/REGALLOC.md).
 *
 * Esta es la UNICA pieza que cambia por arquitectura desde el punto de vista
 * del allocator.  El allocator CORE es generico: lee de aqui que registros
 * hay en cada clase, cuales son scratch (caller-saved) vs preservados
 * (callee-saved), cuales estan reservados, la convencion de llamada y el
 * ancho de puntero.  Nunca usa literales @c MReg::* .
 *
 * Portar a x86-32 / ARMv7 / AArch64 / RISC-V = añadir una funcion
 * @c target_<arch>() que devuelva su @c TargetRegInfo (mas su selector y
 * encoder, que son independientes del allocator).
 */

#ifndef VESTA_JIT_TARGET_REGINFO_H
#define VESTA_JIT_TARGET_REGINFO_H

#include "jit/machine_ir.h"

#include <cstdint>
#include <vector>

namespace jit {

/**
 * @struct TargetRegInfo
 * @brief Descripcion completa del banco de registros de un target.
 *
 * Todas las tablas estan indexadas por @c (size_t)RegClass (0=GP, 1=FP),
 * con @c RegClass::COUNT entradas.  Los valores son ids fisicos (el
 * mismo espacio que @c MReg en x86; otro target usa su propia numeracion
 * pero el allocator los trata como @c uint8_t opacos).
 */
struct TargetRegInfo {
    /// Ancho de puntero/registro en bytes: 8 (x86-64/AArch64) o 4
    /// (x86-32/ARMv7).  De aqui derivan el tamano de los spill slots.
    uint8_t pointer_size = 8;

    /// True si la ISA es de DOS operandos (x86: `add rd, rs` -> rd=rd+rs)
    /// y por tanto necesita el pase de two-address legalization.  ARM,
    /// AArch64 y RISC-V son de tres operandos -> false.
    bool is_two_address = true;

    /// True si el backend sabe emitir un salto DIRECTO a una direccion
    /// absoluta que solo se conoce al colocar el codigo.
    ///
    /// Lo usa la cola de una llamada a otra funcion.  Poder hacerlo ahorra la
    /// mitad de los bytes y un registro frente a materializar la direccion y
    /// saltar a traves de el, pero exige que el codificador deje un hueco y
    /// alguien lo rellene con la DISTANCIA cuando ya hay direccion.
    ///
    /// Se PREGUNTA en vez de darlo por hecho porque el reescritor que decide la
    /// forma es COMUN a todos los objetivos, mientras que saber emitirla es de
    /// cada uno.  Sin esta pregunta, el reescritor emitia una forma que solo el
    /// codificador de x86 entiende, y el de arm64 -- que asume que el operando
    /// de un salto es una etiqueta -- habria emitido un salto a un sitio
    /// inventado.  Falso por defecto: quien lo sepa hacer, que lo diga.
    bool can_jump_to_abs_addr = false;

    static constexpr size_t NCLASS = static_cast<size_t>(RegClass::COUNT);

    /// Registros ASIGNABLES por clase (excluye reservados).  El orden
    /// es la preferencia de asignacion del allocator.
    std::vector<uint8_t> allocatable[NCLASS];
    /// Subconjunto caller-saved (scratch): se PIERDEN al cruzar un CALL.
    /// El allocator los prefiere para valores de vida corta.
    std::vector<uint8_t> caller_saved[NCLASS];
    /// Subconjunto callee-saved: hay que push/pop en prologue/epilogue
    /// si se usan.  El allocator los prefiere para valores que cruzan
    /// llamadas (evita salvarlos alrededor de cada CALL).
    std::vector<uint8_t> callee_saved[NCLASS];
    /// Registros SCRATCH reservados para el rewrite (materializar
    /// spills / legalizacion two-address).  NUNCA asignados por el
    /// allocator (excluidos de @c allocatable).  Solo viven dentro de
    /// una instruccion, nunca a traves de un CALL -> caller-saved es ok.
    std::vector<uint8_t> scratch[NCLASS];
    /// Orden de registros para pasar argumentos (convencion de llamada
    /// del host) por clase.
    std::vector<uint8_t> arg_regs[NCLASS];
    /// Registro donde queda el valor de retorno por clase.
    uint8_t ret_reg[NCLASS] = {0, 0};
    /// Registros reservados que el allocator NUNCA asigna (frame +
    /// punteros fijos del ABI de la VM).
    std::vector<uint8_t> reserved;

    /// El registro de PILA.
    ///
    /// No aparece en ninguna de las listas de arriba -- no es asignable, asi
    /// que no esta ni en @c allocatable ni en las particiones -- y sin embargo
    /// hace falta nombrarlo: lo leen `push`, `pop`, `call` y `ret`.  Se declara
    /// aqui para que se PREGUNTE en vez de adivinarlo, que es como acababa
    /// escrito `isa == ARM64 ? 31 : RSP` -- una expresion que le da a arm32 y a
    /// riscv el registro de otra arquitectura.
    uint8_t stack_reg = 0;

    /** @brief True si @p r es asignable en la clase @p cls. */
    bool is_allocatable(RegClass cls, uint8_t r) const noexcept {
        const auto &v = allocatable[static_cast<size_t>(cls)];
        for (uint8_t x : v)
            if (x == r) return true;
        return false;
    }
    /** @brief True si @p r es callee-saved en la clase @p cls. */
    bool is_callee_saved(RegClass cls, uint8_t r) const noexcept {
        const auto &v = callee_saved[static_cast<size_t>(cls)];
        for (uint8_t x : v)
            if (x == r) return true;
        return false;
    }
    /** @brief Numero de fisicos asignables de la clase @p cls. */
    size_t num_allocatable(RegClass cls) const noexcept {
        return allocatable[static_cast<size_t>(cls)].size();
    }
};

/**
 * @brief Descriptor del target x86-64 con la VM_ABI de VestaVM.
 *
 * Convencion VM_ABI: @c RBX = ProcessVM* (fijo durante toda la funcion
 * JIT) -> RESERVADO.  @c RSP/@c RBP = frame -> reservados.  El resto de
 * GP son asignables.  La clase FP (XMM) se describe COMPLETA aunque el
 * allocator v1 no la use todavia (camino preparado para la fase XMM).
 *
 * Los @c arg_regs siguen el ABI nativo del host (SysV en POSIX, Win64 en
 * Windows) porque los CALL a runtime entries (@c vrt_*) usan @c extern
 * "C" con esa convencion.
 *
 * @return Referencia a una instancia construida una sola vez (thread-safe
 *         por inicializacion de static local en C++11).
 */
/**
 * @brief Construye el @c TargetRegInfo x86-64 para el ABI dado.
 * @param sysv  true = System V AMD64 (Linux/ELF); false = Win64 (Windows/PE).
 *
 * IMPORTANTE (AOT cross-target): el ABI es del TARGET (formato de salida),
 * NO del host.  Un @c .so/.dll o @c .o que exporta funciones invocadas
 * externamente DEBE usar el ABI de su plataforma (SysV para ELF/Linux, Win64
 * para PE/Windows): los @c arg_regs y la particion caller/callee-saved
 * difieren.  El JIT en proceso usa el ABI del host (ver
 * @c target_x86_64_vm_abi).
 */
inline TargetRegInfo build_x86_64_target(bool sysv, bool reserve_vec_acc = true,
                                         bool reserve_fp_scratch = true,
                                         bool wide512 = false) {
    TargetRegInfo t;
    t.pointer_size = 8;
    t.is_two_address = true;
    // El codificador de x86 sabe dejar el hueco de un `jmp rel32` y que se
    // rellene luego con la distancia.  Ver @c can_jump_to_abs_addr.
    t.can_jump_to_abs_addr = true;
    t.stack_reg = reg_id(MReg::RSP);

    const size_t GP = static_cast<size_t>(RegClass::GP);
    const size_t FP = static_cast<size_t>(RegClass::FP);
    auto id = [](MReg r) { return reg_id(r); };

    /* R10/R11 reservados como SCRATCH del rewrite (no asignables). */
    t.scratch[GP] = {id(MReg::R10), id(MReg::R11)};
    if (!sysv) {
        /* Win64 volatiles: RAX RCX RDX R8 R9. */
        t.caller_saved[GP] = {id(MReg::RAX), id(MReg::RCX), id(MReg::RDX),
                              id(MReg::R8), id(MReg::R9)};
        /* Win64 no-volatiles asignables: RSI RDI R12-R15. */
        t.callee_saved[GP] = {id(MReg::RSI), id(MReg::RDI), id(MReg::R12),
                              id(MReg::R13), id(MReg::R14), id(MReg::R15)};
    } else {
        /* SysV volatiles: RAX RCX RDX RSI RDI R8 R9. */
        t.caller_saved[GP] = {id(MReg::RAX), id(MReg::RCX), id(MReg::RDX),
                              id(MReg::RSI), id(MReg::RDI), id(MReg::R8),
                              id(MReg::R9)};
        /* SysV no-volatiles asignables: R12-R15. */
        t.callee_saved[GP] = {id(MReg::R12), id(MReg::R13), id(MReg::R14),
                              id(MReg::R15)};
    }
    t.allocatable[GP] = t.caller_saved[GP];
    t.allocatable[GP].insert(t.allocatable[GP].end(),
                             t.callee_saved[GP].begin(),
                             t.callee_saved[GP].end());
    t.ret_reg[GP] = id(MReg::RAX);

    /* FP-regalloc ( AOT C1 float): XMM14/XMM15 RESERVADOS como scratch
     * del rewrite (materializar spills FP + two-address legalization de
     * ADDSD/etc), analogo a R10/R11 en GP.  Asignables: XMM0..XMM13.
     * En SysV todos los XMM son caller-saved (volatiles).  En Win64 XMM6-15
     * son callee-saved; el codegen FP v1 (HOST_LEAF) los marca caller-saved
     * por simplicidad: las funciones leaf float no mantienen un XMM vivo a
     * traves de un CALL todavia (cuando lo hagan, habra que salvarlos -- TODO
     * cross-call FP). */
    t.scratch[FP] = {id(MReg::XMM14), id(MReg::XMM15)};
    /* XMM10..XMM13 (ids 26..29): los U=4 acumuladores vectoriales de las
     * reducciones/FMA (VEC_ACC_*), que deben sobrevivir TODO el bucle en
     * registros (no en memoria) y ser INDEPENDIENTES (unroll -> oculta la
     * latencia de la cadena vaddpd).  Reserva DEMAND-DRIVEN: solo se excluyen
     * de allocatable en funciones que USAN el path de reduccion (@p
     * reserve_vec_acc = true); en las que NO lo usan (la gran mayoria) XMM10-13
     * son asignables para FP escalar -> 14 lanes en vez de 10.  El selector
     * solo fija XMM13-idx cuando hay ops VEC_ACC_*, asi que la MISMA condicion
     * decide reserva Y uso
     * -> coherente (nadie pisa un acumulador vivo).  acc_idx 0..3 -> XMM13..10.
     */
    /* XMM14/15 son el scratch del reescritor (materializar derrames FP,
     * legalizar las operaciones de dos operandos, romper ciclos al permutar).
     * Una funcion que NO hace nada de eso -- porque su unico uso del banco
     * ancho son los operandos de un bloque asm -- no los necesita, y
     * reservarlos le quita dos ranuras de las 16 sin motivo.  Misma reserva
     * DEMAND-DRIVEN que la de los acumuladores, decidida por el llamante. */
    /* Y el banco EXTENDIDO de AVX-512 (zmm16..31, ids 32..47) cuando el
     * llamante dice que se puede: hacen falta las dos condiciones -- que el
     * procesador los tenga y que la funcion no vaya a emitir instrucciones de
     * coma flotante propias, porque esos registros solo se codifican con EVEX
     * y el codificador de esas no sabe.  Los operandos de un bloque asm si
     * pueden usarlos: ese texto lo ensambla otro que si sabe. */
    const int fp_hi =
        reserve_vec_acc ? 25 : (reserve_fp_scratch ? 29 : (wide512 ? 47 : 31));
    for (int i = 16; i <= fp_hi; ++i) {
        t.allocatable[FP].push_back(static_cast<uint8_t>(i));
        t.caller_saved[FP].push_back(static_cast<uint8_t>(i));
    }
    t.ret_reg[FP] = id(MReg::XMM0);
    t.reserved = {id(MReg::RSP), id(MReg::RBP), id(MReg::RBX)};

    if (!sysv) {
        /* Win64: args enteros en RCX RDX R8 R9; float en XMM0..3. */
        t.arg_regs[GP] = {id(MReg::RCX), id(MReg::RDX), id(MReg::R8),
                          id(MReg::R9)};
        t.arg_regs[FP] = {id(MReg::XMM0), id(MReg::XMM1), id(MReg::XMM2),
                          id(MReg::XMM3)};
    } else {
        /* SysV AMD64: args enteros en RDI RSI RDX RCX R8 R9; float XMM0..7. */
        t.arg_regs[GP] = {id(MReg::RDI), id(MReg::RSI), id(MReg::RDX),
                          id(MReg::RCX), id(MReg::R8),  id(MReg::R9)};
        t.arg_regs[FP] = {id(MReg::XMM0), id(MReg::XMM1), id(MReg::XMM2),
                          id(MReg::XMM3), id(MReg::XMM4), id(MReg::XMM5),
                          id(MReg::XMM6), id(MReg::XMM7)};
    }
    return t;
}

/**
 * @brief Construye el @c TargetRegInfo x86-32 (modo protegido, kernels).
 *
 * Solo 8 GP (eax=0..edi=7; no hay r8-r15) -> pointer_size=4.  Convencion
 * REGPARM(3) (estilo GCC @c -mregparm=3): args enteros en EAX, EDX, ECX;
 * retorno en EAX; callee-saved EBX, ESI, EDI, EBP.  Se elige regparm (no
 * cdecl con args en pila) para reusar el modelo de @c arg_regs del selector
 * HOST_LEAF sin implementar paso por pila -> cubre kernel freestanding con
 * funciones leaf + llamadas internas (las externas/BIOS van por asm).
 *
 * ESP/EBP reservados (frame).  ESI/EDI reservados como SCRATCH del rewrite
 * (materializar spills + two-address).  Asignables: EAX ECX EDX EBX (4).
 * FP (XMM) vacio en v1: el subset 32-bit es entero (i32/u32/ptr32); las ops
 * float no aparecen.
 */
inline TargetRegInfo build_x86_32_target() {
    TargetRegInfo t;
    t.pointer_size = 4;
    t.stack_reg = reg_id(MReg::RSP); // ESP: el mismo id, otro ancho
    t.is_two_address = true;

    const size_t GP = static_cast<size_t>(RegClass::GP);
    auto id = [](MReg r) { return reg_id(r); };

    /* ESI/EDI = scratch del rewrite (no asignables). */
    t.scratch[GP] = {id(MReg::RSI), id(MReg::RDI)};
    /* Volatiles regparm: EAX ECX EDX. */
    t.caller_saved[GP] = {id(MReg::RAX), id(MReg::RCX), id(MReg::RDX)};
    /* No-volatiles asignables: EBX. */
    t.callee_saved[GP] = {id(MReg::RBX)};
    t.allocatable[GP] = t.caller_saved[GP];
    t.allocatable[GP].insert(t.allocatable[GP].end(),
                             t.callee_saved[GP].begin(),
                             t.callee_saved[GP].end());
    t.ret_reg[GP] = id(MReg::RAX);

    /* FP vacio (sin float en v1). */
    t.reserved = {id(MReg::RSP), id(MReg::RBP)};

    /* regparm(3): EAX, EDX, ECX. */
    t.arg_regs[GP] = {id(MReg::RAX), id(MReg::RDX), id(MReg::RCX)};
    return t;
}

/** @brief @c TargetRegInfo x86-32 (cacheado). */
inline const TargetRegInfo &target_x86_32() {
    static const TargetRegInfo info = build_x86_32_target();
    return info;
}

/**
 * @brief @c TargetRegInfo x86-64 para el ABI @p sysv (cacheado por ABI x
 * reserva).
 * @param reserve_vec_acc  true (defecto) = XMM10-13 reservados para VEC_ACC
 *        (funciones con reduccion vectorial); false = XMM10-13 asignables para
 * FP escalar (funciones sin reduccion).  La reserva es DEMAND-DRIVEN.
 */
inline const TargetRegInfo &target_x86_64_abi(bool sysv,
                                              bool reserve_vec_acc = true,
                                              bool reserve_fp_scratch = true,
                                              bool wide512 = false) {
    static const TargetRegInfo t[16] = {
        build_x86_64_target(true, true, true, false),
        build_x86_64_target(false, true, true, false),
        build_x86_64_target(true, false, true, false),
        build_x86_64_target(false, false, true, false),
        build_x86_64_target(true, true, false, false),
        build_x86_64_target(false, true, false, false),
        build_x86_64_target(true, false, false, false),
        build_x86_64_target(false, false, false, false),
        build_x86_64_target(true, true, true, true),
        build_x86_64_target(false, true, true, true),
        build_x86_64_target(true, false, true, true),
        build_x86_64_target(false, false, true, true),
        build_x86_64_target(true, true, false, true),
        build_x86_64_target(false, true, false, true),
        build_x86_64_target(true, false, false, true),
        build_x86_64_target(false, false, false, true),
    };
    const size_t i = (wide512 ? 8u : 0u) + (reserve_fp_scratch ? 0u : 4u) +
                     (reserve_vec_acc ? 0u : 2u) + (sysv ? 0u : 1u);
    return t[i];
}

/**
 * @brief ¿El ABI de ESTA maquina es el de System V?
 *
 * UNICO sitio donde se mira en que sistema se esta compilando.  Solo vale para
 * el JIT, que compila para la maquina en la que corre; el camino nativo NO
 * puede preguntarse esto -- desde Windows se generan binarios de Linux y al
 * reves -- y por eso recibe el ABI de su objetivo (@c target_x86_64_abi).
 */
inline constexpr bool host_is_sysv() noexcept {
#if defined(_WIN32)
    return false;
#else
    return true;
#endif
}

/**
 * @brief @c TargetRegInfo del ABI del HOST (para el JIT en proceso).
 * @param reserve_vec_acc  ver @c target_x86_64_abi.
 * @param reserve_fp_scratch  ver @c target_x86_64_abi.
 */
inline const TargetRegInfo &target_x86_64_vm_abi(bool reserve_vec_acc = true,
                                                 bool reserve_fp_scratch = true,
                                                 bool wide512 = false) {
    return target_x86_64_abi(host_is_sysv(), reserve_vec_acc,
                             reserve_fp_scratch, wide512);
}

/*
 * Numeracion de registros arm64 (AArch64) para el pipeline vreg.  El allocator
 * los trata como @c uint8_t opacos (no son @c MReg, que es x86); el encoder
 * arm64 los traduce a "x0".."x30" / "v0".."v31".  GP x_n = n (0-30); el banco
 * FP/SIMD v_n = 32 + n (32-63).  sp/x29/x30 no son registros-valor asignables.
 */
enum : uint8_t {
    A64_X0 = 0,
    A64_X8 = 8,
    A64_X15 = 15,
    A64_X16 = 16,
    A64_X17 = 17,
    A64_X18 = 18,
    A64_X19 = 19,
    A64_X28 = 28,
    A64_X29_FP = 29,
    A64_X30_LR = 30,
    A64_SP = 31,
    A64_V0 = 32,
    A64_V7 = 39,
    A64_V8 = 40,
    A64_V15 = 47,
    A64_V16 = 48,
    A64_V29 = 61,
    A64_V30 = 62,
    A64_V31 = 63,
};

/**
 * @brief Construye el @c TargetRegInfo AArch64 (AAPCS64), 3-operandos.
 *
 * GP x0-x30: x0-x7 args (x0 = retorno); x8 (XR) + x9-x15 caller-saved;
 * x16/x17 (IP0/IP1) SCRATCH del rewrite; x18 (plataforma) reservado por
 * portabilidad (Win/Darwin lo usan); x19-x28 callee-saved; x29(FP)/x30(LR)/sp
 * reservados.  FP/SIMD v0-v31: v0-v7 args (v0 = retorno); v8-v15 callee-saved;
 * v16-v29 caller-saved; v30/v31 SCRATCH del rewrite.
 */
inline TargetRegInfo build_arm64_target() {
    TargetRegInfo t;
    t.pointer_size = 8;
    t.is_two_address = false; // AArch64 es de 3 operandos: rd = rn OP rm.
    t.stack_reg = A64_SP;
    // El codificador de arm64 asume que el operando de un salto es una
    // ETIQUETA, asi que NO sabe saltar a una direccion absoluta.  Ver
    // @c can_jump_to_abs_addr: quien lo sepa hacer, que lo diga.

    const size_t GP = static_cast<size_t>(RegClass::GP);
    const size_t FP = static_cast<size_t>(RegClass::FP);

    /* --- GP --- */
    t.scratch[GP] = {A64_X16, A64_X17}; // IP0/IP1: temporales del rewrite.
    /* Caller-saved asignables: x0..x15 (args + temporales). */
    for (uint8_t r = A64_X0; r <= A64_X15; ++r)
        t.caller_saved[GP].push_back(r);
    /* Callee-saved asignables: x19..x28. */
    for (uint8_t r = A64_X19; r <= A64_X28; ++r)
        t.callee_saved[GP].push_back(r);
    t.allocatable[GP] = t.caller_saved[GP];
    t.allocatable[GP].insert(t.allocatable[GP].end(),
                             t.callee_saved[GP].begin(),
                             t.callee_saved[GP].end());
    t.ret_reg[GP] = A64_X0;
    for (uint8_t r = A64_X0; r <= 7; ++r)
        t.arg_regs[GP].push_back(r); // x0-x7
    t.reserved = {A64_X18, A64_X29_FP, A64_X30_LR, A64_SP};

    /* --- FP/SIMD --- */
    t.scratch[FP] = {A64_V30, A64_V31};
    /* Caller-saved: v0..v7 (args) + v16..v29. */
    for (uint8_t r = A64_V0; r <= A64_V7; ++r)
        t.caller_saved[FP].push_back(r);
    for (uint8_t r = A64_V16; r <= A64_V29; ++r)
        t.caller_saved[FP].push_back(r);
    /* Callee-saved: v8..v15. */
    for (uint8_t r = A64_V8; r <= A64_V15; ++r)
        t.callee_saved[FP].push_back(r);
    t.allocatable[FP] = t.caller_saved[FP];
    t.allocatable[FP].insert(t.allocatable[FP].end(),
                             t.callee_saved[FP].begin(),
                             t.callee_saved[FP].end());
    t.ret_reg[FP] = A64_V0;
    for (uint8_t r = A64_V0; r <= A64_V7; ++r)
        t.arg_regs[FP].push_back(r);

    return t;
}

/** @brief @c TargetRegInfo AArch64 (cacheado). */
inline const TargetRegInfo &target_arm64() {
    static const TargetRegInfo info = build_arm64_target();
    return info;
}

} // namespace jit

#endif // VESTA_JIT_TARGET_REGINFO_H
