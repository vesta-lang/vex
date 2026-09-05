/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/exec_instruction_fused.h
 * @brief Instrucciones FUSIONADAS: las que no existen en el bytecode.
 *
 * QUE SON
 * -------
 * Una instruccion fusionada hace el trabajo de dos, y solo existe DENTRO de un
 * paquete, ya descodificada.  Nadie la escribe, nadie la ensambla y nadie la
 * lee de un fichero: la construye el fusionador al formar el paquete y muere
 * con el.
 *
 * DE AHI QUE NO NECESITE UN OPCODE
 * --------------------------------
 * No hay bytes que codificar, asi que no hay ranura de la tabla extendida que
 * gastar, ni ensamblador que ensenar, ni version del `.velb` que subir, ni base
 * de instrucciones que regenerar.  Y al no haber codificacion que respetar, los
 * operandos se colocan como salga mas barato de leer -- registros en BYTES
 * sueltos, sin nibbles que empacar --, que en el bytecode de verdad no cabria.
 *
 * POR QUE ESTAN AQUI Y NO CON EL FUSIONADOR
 * -----------------------------------------
 * Porque son INSTRUCCIONES.  Esto es QUE HACEN y COMO SE EJECUTAN; CUANDO
 * conviene crear una es politica del fusionador y vive en `bundle_fuse.cpp`.
 * Mezclarlo ataria la semantica de una instruccion a la heuristica que la crea,
 * y el dia que haya un segundo creador -- el JIT, por ejemplo -- habria que
 * separarlo a la fuerza.
 *
 * POR QUE EN CABECERA Y NO EN UN `.cpp`
 * -------------------------------------
 * `make_alu2x` corre en el camino de FORMACION, una vez por par fusionado, y
 * ahi una llamada entre unidades de traduccion no se puede plegar: el
 * compilador no ve que casi todo son constantes.  En cabecera desaparece.
 *
 * Los MANEJADORES son otra cosa: se llega a ellos por PUNTERO (`exec_cached`),
 * asi que no se inlinan nunca y no tiene sentido pedirlo.  Lo que los hace
 * rapidos no es el inline, es estar especializados por plantilla -- con las dos
 * operaciones fijadas al compilar, el `switch` de `alu3_apply` se pliega y
 * queda literalmente un `add` y un `xor`.
 *
 * LO QUE HAY QUE RESPETAR AL ANADIR UNA
 * -------------------------------------
 *   - `metadata` tiene que apuntar a un @c InstrFormat valido, con nombre y con
 *     un `exec` correcto: lo leen el camino lento, el depurador y la traza de
 *     un fallo.  Y ese `exec` generico tiene que hacer LO MISMO que la
 *     especializacion, o el mismo programa dara un resultado bajo el depurador
 *     y otro sin el.
 *   - `size_instr` es la SUMA de las que sustituye.  `exec_bundle` avanza `rip`
 *     sumandolo, y quedarse corto no da un error: deja `rip` corrido y el salto
 *     siguiente va a otro sitio.
 *   - `absorbed` cuenta cuantas del PROGRAMA representa, menos una.  Sin eso la
 *     maquina retira una donde el programa tiene dos y los MIPS bajan cuanto
 *     mejor fusione.
 *   - los campos de OPCODE dejan de describirla.  Nadie debe preguntarle a la
 *     base por ellos, y por eso hay que anadirla a `fused_touch`: si no, quien
 *     reordene la tratara como barrera y no se movera nunca.
 *
 * LO QUE SE PIERDE.  El desensamblado de un volcado de paquetes muestra los
 * bytes de la PRIMERA, porque el `pc` de la fusionada es el suyo.  Es cosmetico
 * y queda apuntado para que no sorprenda.
 *
 * DOS CLASES DE FUSIONADA, Y LA DIFERENCIA IMPORTA PARA EL FUERA DE ORDEN
 * ----------------------------------------------------------------------
 * No todas se parecen, aunque compartan mecanismo:
 *
 *   - **CADENA** (`alu2x`, `ldop`, `alui`).  La segunda consume lo que produce
 *     la primera: son una dependencia por construccion.  Fusionarlas ES
 *     colapsar la cadena, y dentro no queda nada que solapar.  Sus operandos se
 *     FUNDEN en una sola operacion porque ya no hay dos.
 *
 *   - **TANDA** (`movn`, y las de memoria).  Las partes son INDEPENDIENTES
 *     entre si; lo unico que hay que respetar es el orden.  Son justo las que
 *     un planificador fuera de orden querria solapar, asi que sus operandos se
 *     guardan POR SEPARADO -- uno por parte -- en vez de fundirse.  Esa
 *     decision no cuesta nada hoy y es la que deja la puerta abierta.
 *
 * Y LAS DOS SE PUEDEN MOVER.  Una fusionada declara lo que toca por si misma
 * (`fused_touch`, al final de este fichero), asi que el reordenador la trata
 * como a cualquier otra en vez de como una barrera.  Antes no: se daba por
 * "no se, no la muevas", que era seguro y las dejaba inmoviles -- ni se
 * reordenan ni podrian solaparse cuando la ejecucion sea de verdad fuera de
 * orden, que es lo contrario de lo que se busca.
 *
 * Se resuelve por FORMATO y no guardando mascaras dentro de la instruccion,
 * porque no siempre hay sitio: `mem2` llena sus dieciseis bytes de operandos con
 * los dos bloques de direccionamiento.
 */

#ifndef VESTA_RUNTIME_EXEC_INSTRUCTION_FUSED_H
#define VESTA_RUNTIME_EXEC_INSTRUCTION_FUSED_H

#include <cstdint>
#include <cstring> // memcpy: los operandos, sin suponer alineacion
#include <utility> // integer_sequence: desenrollar la tabla de manejadores

#include "runtime/bundle/alu3_semantics.h"
#include "runtime/decode_table.h"
#include "runtime/effects_decode.h"
#include "runtime/mem_full_semantics.h"
#include "runtime/proceso_runtime.h"

namespace runtime {

/**
 * @brief Los registros de una fusionada de dos ALU, en bytes sueltos.
 *
 * Sin empacar: leer un byte es una instruccion, desempacar un nibble son tres.
 * Se puede porque esto no es un formato de bytecode -- nadie lo escribe en un
 * fichero --, asi que no hay que meterlo en cuatro bits.
 */
struct Alu2xOperands {
    uint8_t dst;  ///< donde va el resultado final
    uint8_t src1; ///< primera fuente de la PRIMERA operacion
    uint8_t src2; ///< segunda fuente de la primera
    uint8_t src3; ///< la otra fuente de la SEGUNDA (el temporal es implicito)
};

static_assert(sizeof(Alu2xOperands) <= sizeof(uint64_t),
              "los operandos de una fusionada tienen que caber en raw1");

/* Las dos operaciones y el lado van detras de los registros, en el mismo hueco
 * de 16 bytes.  Solo los lee el manejador GENERICO: el especializado los tiene
 * fijados al compilar. */
constexpr unsigned kAlu2xOp1Shift = 32;
constexpr unsigned kAlu2xOp2Shift = 40;
constexpr unsigned kAlu2xSideShift = 48;

[[gnu::always_inline]] inline Alu2xOperands
alu2x_operands(const DecodedInstr &d) {
    Alu2xOperands ops;
    std::memcpy(&ops, &d.data_instruction.raw_data.raw1, sizeof(ops));
    return ops;
}

/**
 * @brief `dst = (src1 OP1 src2) OP2 src3`, con las dos operaciones fijadas AL
 *        COMPILAR.
 *
 * @tparam Op1     Opcode de la primera (0x73-0x7B).
 * @tparam Op2     Opcode de la segunda.
 * @tparam RtRight El temporal entra como operando DERECHO de la segunda.
 */
template <uint8_t Op1, uint8_t Op2, bool RtRight>
void exec_alu2x(ProcessVM *vm, const DecodedInstr &d) {
    const Alu2xOperands ops = alu2x_operands(d);
    auto &regs = vm->registers.regs;

    /* La PRIMERA no deja banderas: las suyas las pisaria la segunda de todas
     * formas, que es justo lo que pasaba sin fusionar. */
    uint8_t cf_of = 0;
    const uint64_t rt =
        alu3_apply(Op1, regs[ops.src1].qword(), regs[ops.src2].qword(), cf_of);
    const uint64_t other = regs[ops.src3].qword();
    const uint64_t res = RtRight ? alu3_apply(Op2, other, rt, cf_of)
                                 : alu3_apply(Op2, rt, other, cf_of);
    regs[ops.dst].qword(res);
    vm->registers.flags.arith = alu3_flags(res, cf_of);
}

/**
 * @brief El manejador GENERICO, con las operaciones leidas del operando.
 *
 * Existe para que `metadata->exec` sea correcto: lo usan el camino lento
 * (`execute_instruction`) y el depurador.  Desde el paquete nunca se llama --
 * ahi se entra por `exec_cached` --, pero tiene que hacer LO MISMO.
 */
inline void exec_alu2x_generic(ProcessVM *vm, const DecodedInstr &d) {
    const Alu2xOperands ops = alu2x_operands(d);
    const uint64_t packed = d.data_instruction.raw_data.raw1;
    const uint8_t op1 = (uint8_t)(packed >> kAlu2xOp1Shift);
    const uint8_t op2 = (uint8_t)(packed >> kAlu2xOp2Shift);
    const bool rt_right = ((packed >> kAlu2xSideShift) & 1u) != 0;

    auto &regs = vm->registers.regs;
    uint8_t cf_of = 0;
    const uint64_t rt =
        alu3_apply(op1, regs[ops.src1].qword(), regs[ops.src2].qword(), cf_of);
    const uint64_t other = regs[ops.src3].qword();
    const uint64_t res = rt_right ? alu3_apply(op2, other, rt, cf_of)
                                  : alu3_apply(op2, rt, other, cf_of);
    regs[ops.dst].qword(res);
    vm->registers.flags.arith = alu3_flags(res, cf_of);
}

/// El descriptor al que apuntan todas las fusionadas de dos ALU.  `size` es
/// FIXED_1 porque el tamano real va en `size_instr` y nadie vuelve a
/// descodificar esto.
inline InstrFormat g_alu2x_format = {
    "alu2x",
    Assembly::Bytecode::AddressingMode::REG,
    Assembly::Bytecode::InstrSizeMode::FIXED_1,
    &exec_alu2x_generic,
    nullptr,
};

using Alu2xFn = void (*)(ProcessVM *, const DecodedInstr &);

/* La tabla de manejadores se desenrolla con plantillas porque no hay `for` que
 * valga a nivel de tipos: cada celda es una instanciacion DISTINTA y el indice
 * tiene que ser constante.  Nueve por nueve por dos lados: 162 funciones
 * diminutas, unos 2 KB de codigo, y una tabla que se indexa UNA vez por fusion
 * -- nunca en ejecucion. */
template <uint8_t Op1, uint8_t Op2>
constexpr void alu2x_fill_cell(Alu2xFn (&t)[kAlu3Count][kAlu3Count][2]) {
    t[Op1 - kAlu3First][Op2 - kAlu3First][0] = &exec_alu2x<Op1, Op2, false>;
    t[Op1 - kAlu3First][Op2 - kAlu3First][1] = &exec_alu2x<Op1, Op2, true>;
}

template <uint8_t Op1, uint8_t... Op2s>
constexpr void alu2x_fill_row(Alu2xFn (&t)[kAlu3Count][kAlu3Count][2],
                              std::integer_sequence<uint8_t, Op2s...>) {
    (alu2x_fill_cell<Op1, (uint8_t)(kAlu3First + Op2s)>(t), ...);
}

template <uint8_t... Op1s>
constexpr void alu2x_fill_all(Alu2xFn (&t)[kAlu3Count][kAlu3Count][2],
                              std::integer_sequence<uint8_t, Op1s...>) {
    (alu2x_fill_row<(uint8_t)(kAlu3First + Op1s)>(
         t, std::make_integer_sequence<uint8_t, kAlu3Count>{}),
     ...);
}

struct Alu2xTable {
    Alu2xFn fn[kAlu3Count][kAlu3Count][2] = {};
    constexpr Alu2xTable() {
        alu2x_fill_all(fn, std::make_integer_sequence<uint8_t, kAlu3Count>{});
    }
};

inline constexpr Alu2xTable kAlu2x{};

/* =========================================================================
 * CARGAR Y OPERAR  (`mld` + ALU de tres operandos)
 *
 * La familia con mas peso de las medidas: 9,1 M de ejecuciones en el corpus.
 *
 *     mld   rt, [dir]        ->    ldop rd, [dir], c    con rd = carga OP c
 *     alu3  rd, rt, c
 *
 * Cabe porque `mem_full` mide EXACTAMENTE ocho bytes, asi que ocupa `raw1` y
 * deja `raw2` entero para la parte de la ALU.  Sin esa casualidad habria que
 * recortar el direccionamiento, y recortarlo dejaria fuera justo los accesos
 * con indice, que son los de los arrays.
 * ========================================================================= */

/// La parte ALU de un `ldop`, en el hueco que deja `mem_full`.
struct LdopOperands {
    uint8_t dst;  ///< donde va el resultado final
    uint8_t src;  ///< la fuente de la ALU que NO es lo cargado
    uint8_t op;   ///< opcode de la ALU (0x73-0x7B)
    uint8_t side; ///< 1 = lo cargado entra por la DERECHA de la ALU
};

static_assert(sizeof(LdopOperands) <= sizeof(uint64_t),
              "la parte ALU de un `ldop` tiene que caber en raw2");

/**
 * @brief `dst = carga([dir]) OP src`, con la operacion fijada AL COMPILAR.
 *
 * La carga se hace con `mem_full_load`, que es la MISMA que usa `mld`: los
 * anchos, el signo y el camino anfitrion/VM no se reescriben aqui.
 */
template <uint8_t Op, bool LoadRight>
void exec_ldop(ProcessVM *vm, const DecodedInstr &d) {
    const auto &m = d.data_instruction.mem_full;
    LdopOperands ops;
    std::memcpy(&ops, &d.data_instruction.raw_data.raw2, sizeof(ops));

    const uint64_t addr =
        mem_full_addr(vm, m.base, m.disp, m.flags, m.index, m.scale);
    const uint64_t loaded = mem_full_load(vm, m, addr);
    const uint64_t other = vm->registers.regs[ops.src].qword();

    uint8_t cf_of = 0;
    const uint64_t res = LoadRight ? alu3_apply(Op, other, loaded, cf_of)
                                   : alu3_apply(Op, loaded, other, cf_of);
    vm->registers.regs[ops.dst].qword(res);
    vm->registers.flags.arith = alu3_flags(res, cf_of);
}

/// El generico, para `metadata->exec`.  Tiene que hacer LO MISMO que la
/// especializacion o el programa dara un resultado bajo el depurador y otro
/// sin el.
inline void exec_ldop_generic(ProcessVM *vm, const DecodedInstr &d) {
    const auto &m = d.data_instruction.mem_full;
    LdopOperands ops;
    std::memcpy(&ops, &d.data_instruction.raw_data.raw2, sizeof(ops));

    const uint64_t addr =
        mem_full_addr(vm, m.base, m.disp, m.flags, m.index, m.scale);
    const uint64_t loaded = mem_full_load(vm, m, addr);
    const uint64_t other = vm->registers.regs[ops.src].qword();

    uint8_t cf_of = 0;
    const uint64_t res = ops.side ? alu3_apply(ops.op, other, loaded, cf_of)
                                  : alu3_apply(ops.op, loaded, other, cf_of);
    vm->registers.regs[ops.dst].qword(res);
    vm->registers.flags.arith = alu3_flags(res, cf_of);
}

inline InstrFormat g_ldop_format = {
    "ldop",
    Assembly::Bytecode::AddressingMode::MEM,
    Assembly::Bytecode::InstrSizeMode::FIXED_1,
    &exec_ldop_generic,
    nullptr,
};

/* Nueve operaciones por dos lados.  Mismo desenrollado por plantilla que la
 * tabla de dos ALU, y por la misma razon: cada celda es una instanciacion
 * distinta y el indice tiene que ser constante. */
template <uint8_t Op>
constexpr void ldop_fill_cell(Alu2xFn (&t)[kAlu3Count][2]) {
    t[Op - kAlu3First][0] = &exec_ldop<Op, false>;
    t[Op - kAlu3First][1] = &exec_ldop<Op, true>;
}

template <uint8_t... Ops>
constexpr void ldop_fill_all(Alu2xFn (&t)[kAlu3Count][2],
                             std::integer_sequence<uint8_t, Ops...>) {
    (ldop_fill_cell<(uint8_t)(kAlu3First + Ops)>(t), ...);
}

struct LdopTable {
    Alu2xFn fn[kAlu3Count][2] = {};
    constexpr LdopTable() {
        ldop_fill_all(fn, std::make_integer_sequence<uint8_t, kAlu3Count>{});
    }
};

inline constexpr LdopTable kLdop{};

/**
 * @brief Convierte @p a (un `mld`) en la fusionada que carga y opera.
 *
 * @p a conserva su `mem_full` tal cual -- el direccionamiento no se toca --, y
 * la parte de la ALU se escribe en el hueco de al lado.
 *
 * @param a          El `mld`; sale convertido en la fusionada.
 * @param op         Opcode de la ALU (0x73-0x7B).
 * @param dst        Registro donde va el resultado final.
 * @param src        La fuente de la ALU que NO es lo cargado.
 * @param load_right Lo cargado entra por la DERECHA de la ALU.
 */
[[gnu::always_inline]] inline void make_ldop(DecodedInstr &a, uint8_t op,
                                             uint8_t dst, uint8_t src,
                                             bool load_right) {
    LdopOperands ops;
    ops.dst = dst;
    ops.src = src;
    ops.op = op;
    ops.side = load_right ? 1u : 0u;
    uint64_t packed = 0;
    std::memcpy(&packed, &ops, sizeof(ops));
    a.data_instruction.raw_data.raw2 = packed;

    a.metadata = &g_ldop_format;
    a.exec_cached = kLdop.fn[op - kAlu3First][load_right];
}

/* =========================================================================
 * OPERAR CON UNA CONSTANTE  (`mov` inmediato + ALU de tres operandos)
 *
 * Lo que mas pesa de lo que NO se miraba: `mov`/15 encabeza 6450 pares en el
 * corpus, mas que ninguna otra.
 *
 *     mov  rt, K            ->    alui rd, K, c    con rd = K OP c
 *     alu3 rd, rt, c
 *
 * Es el caso donde tener dieciseis bytes de operandos SIN formato que respetar
 * se nota: la constante de 64 bits viaja entera dentro de la instruccion.  En
 * el bytecode de verdad haria falta un opcode con inmediato y tres registros,
 * que no cabe en cuatro bytes.
 *
 * SOLO CON EL `mov` DE 64 BITS.  Uno de 8 escribe el byte bajo y conserva los
 * otros siete, asi que el valor que la ALU leeria no es la constante: es la
 * constante mezclada con lo que hubiera.  Eso no se puede reproducir sin
 * conocer el pasado del registro.
 * ========================================================================= */

/// La parte no-constante de un `alui`.  La constante ocupa `raw1` entera.
struct AluiOperands {
    uint8_t dst;  ///< donde va el resultado
    uint8_t src;  ///< la fuente de la ALU que NO es la constante
    uint8_t op;   ///< opcode de la ALU (0x73-0x7B)
    uint8_t side; ///< 1 = la constante entra por la DERECHA
};

static_assert(sizeof(AluiOperands) <= sizeof(uint64_t),
              "la parte no-constante de un `alui` tiene que caber en raw2");

/// `dst = K OP src`, con la operacion fijada AL COMPILAR.
template <uint8_t Op, bool ImmRight>
void exec_alui(ProcessVM *vm, const DecodedInstr &d) {
    const uint64_t imm = d.data_instruction.raw_data.raw1;
    AluiOperands ops;
    std::memcpy(&ops, &d.data_instruction.raw_data.raw2, sizeof(ops));

    const uint64_t other = vm->registers.regs[ops.src].qword();
    uint8_t cf_of = 0;
    const uint64_t res = ImmRight ? alu3_apply(Op, other, imm, cf_of)
                                  : alu3_apply(Op, imm, other, cf_of);
    vm->registers.regs[ops.dst].qword(res);
    vm->registers.flags.arith = alu3_flags(res, cf_of);
}

/// El generico, para `metadata->exec`.  Mismo resultado que la especializacion.
inline void exec_alui_generic(ProcessVM *vm, const DecodedInstr &d) {
    const uint64_t imm = d.data_instruction.raw_data.raw1;
    AluiOperands ops;
    std::memcpy(&ops, &d.data_instruction.raw_data.raw2, sizeof(ops));

    const uint64_t other = vm->registers.regs[ops.src].qword();
    uint8_t cf_of = 0;
    const uint64_t res = ops.side ? alu3_apply(ops.op, other, imm, cf_of)
                                  : alu3_apply(ops.op, imm, other, cf_of);
    vm->registers.regs[ops.dst].qword(res);
    vm->registers.flags.arith = alu3_flags(res, cf_of);
}

inline InstrFormat g_alui_format = {
    "alui",
    Assembly::Bytecode::AddressingMode::INMED,
    Assembly::Bytecode::InstrSizeMode::FIXED_1,
    &exec_alui_generic,
    nullptr,
};

template <uint8_t Op>
constexpr void alui_fill_cell(Alu2xFn (&t)[kAlu3Count][2]) {
    t[Op - kAlu3First][0] = &exec_alui<Op, false>;
    t[Op - kAlu3First][1] = &exec_alui<Op, true>;
}

template <uint8_t... Ops>
constexpr void alui_fill_all(Alu2xFn (&t)[kAlu3Count][2],
                             std::integer_sequence<uint8_t, Ops...>) {
    (alui_fill_cell<(uint8_t)(kAlu3First + Ops)>(t), ...);
}

struct AluiTable {
    Alu2xFn fn[kAlu3Count][2] = {};
    constexpr AluiTable() {
        alui_fill_all(fn, std::make_integer_sequence<uint8_t, kAlu3Count>{});
    }
};

inline constexpr AluiTable kAlui{};

/**
 * @brief Convierte @p a (un `mov` inmediato) en la fusionada con constante.
 *
 * @param a         El `mov`; sale convertido en la fusionada.
 * @param imm       La constante, ya de 64 bits.
 * @param op        Opcode de la ALU (0x73-0x7B).
 * @param dst       Registro donde va el resultado.
 * @param src       La fuente de la ALU que NO es la constante.
 * @param imm_right La constante entra por la DERECHA de la ALU.
 */
[[gnu::always_inline]] inline void make_alui(DecodedInstr &a, uint64_t imm,
                                             uint8_t op, uint8_t dst,
                                             uint8_t src, bool imm_right) {
    AluiOperands ops;
    ops.dst = dst;
    ops.src = src;
    ops.op = op;
    ops.side = imm_right ? 1u : 0u;
    uint64_t packed = 0;
    std::memcpy(&packed, &ops, sizeof(ops));
    a.data_instruction.raw_data.raw1 = imm;
    a.data_instruction.raw_data.raw2 = packed;

    a.metadata = &g_alui_format;
    a.exec_cached = kAlui.fn[op - kAlu3First][imm_right];
}

/* =========================================================================
 * MOVER VARIOS DE UNA VEZ  (una tanda de `mov` reg,reg)
 *
 * Distinto de todos los anteriores en lo que importa: NO necesita que nada
 * muera.  Los otros patrones juntan un productor con su consumidor y por eso
 * tienen que demostrar que el temporal no hace falta despues -- que es la
 * pared con la que chocan --.  Una tanda de `mov` no produce ningun temporal:
 * solo hay que ejecutarlos EN EL MISMO ORDEN, y entonces `mov r1,r2; mov r2,r3`
 * sigue significando lo mismo aunque el segundo lea lo que el primero escribio.
 *
 * CUANTOS CABEN, y no es una eleccion: `size_instr` son CUATRO BITS, o sea 15
 * bytes, y cada `mov` reg,reg ocupa 4.  Tres caben (12), cuatro no (16).  Con
 * inmediatos ni dos: son 11 bytes cada uno.  Ese limite no es del patron, es
 * del campo, y quien quiera pasar de ahi tiene que ensancharlo -- hay tres bits
 * libres en `flags_info` -- sabiendo que `exec_bundle` avanza `rip` con el.
 * ========================================================================= */

/// Hasta CUATRO parejas destino/fuente, en bytes sueltos.  Cuatro es lo que
/// admite `absorbed` (dos bits); el tamano ya no aprieta desde que
/// `size_instr` son cinco bits.
struct MovnOperands {
    uint8_t dst[4];
    uint8_t src[4];
};

static_assert(sizeof(MovnOperands) <= sizeof(uint64_t),
              "las parejas de un `movn` tienen que caber en raw1");

/**
 * @brief Copia @p N registros, en orden.
 *
 * @tparam N Cuantas copias, fijado AL COMPILAR: el bucle desaparece y queda una
 *           secuencia recta de N lecturas y N escrituras.
 */
template <uint32_t N>
void exec_movn(ProcessVM *vm, const DecodedInstr &d) {
    MovnOperands ops;
    std::memcpy(&ops, &d.data_instruction.raw_data.raw1, sizeof(ops));
    auto &regs = vm->registers.regs;
    /* EN ORDEN, y de uno en uno: leer todos y despues escribir todos NO es lo
     * mismo.  `mov r1,r2; mov r2,r1` intercambia con la primera version y
     * duplica con la segunda. */
    for (uint32_t i = 0; i < N; ++i)
        regs[ops.dst[i]].qword(regs[ops.src[i]].qword());
}

/// El generico, con la cuenta leida del operando.  Mismo resultado.
inline void exec_movn_generic(ProcessVM *vm, const DecodedInstr &d) {
    MovnOperands ops;
    std::memcpy(&ops, &d.data_instruction.raw_data.raw1, sizeof(ops));
    const uint32_t n = (uint32_t)(d.data_instruction.raw_data.raw2 & 0xFF);
    auto &regs = vm->registers.regs;
    for (uint32_t i = 0; i < n; ++i)
        regs[ops.dst[i]].qword(regs[ops.src[i]].qword());
}

inline InstrFormat g_movn_format = {
    "movn",
    Assembly::Bytecode::AddressingMode::REG,
    Assembly::Bytecode::InstrSizeMode::FIXED_1,
    &exec_movn_generic,
    nullptr,
};

/// Manejador por cuenta.  Solo 2 y 3 tienen sentido: con 1 no hay fusion.
inline constexpr Alu2xFn kMovn[5] = {nullptr, nullptr, &exec_movn<2>,
                                     &exec_movn<3>, &exec_movn<4>};

/**
 * @brief Convierte @p a en la fusionada que copia @p n registros.
 *
 * @param a   Primera de la tanda; sale convertida en la fusionada.
 * @param dst Registros destino, en orden.
 * @param src Registros fuente, en orden.
 * @param n   Cuantas copias (2, 3 o 4).
 */
[[gnu::always_inline]] inline void make_movn(DecodedInstr &a,
                                             const uint8_t *dst,
                                             const uint8_t *src, uint32_t n) {
    MovnOperands ops{};
    for (uint32_t i = 0; i < n; ++i) {
        ops.dst[i] = dst[i];
        ops.src[i] = src[i];
    }
    uint64_t packed = 0;
    std::memcpy(&packed, &ops, sizeof(ops));
    a.data_instruction.raw_data.raw1 = packed;
    a.data_instruction.raw_data.raw2 = n;

    a.metadata = &g_movn_format;
    a.exec_cached = kMovn[n];
}

/* =========================================================================
 * DOS ACCESOS A MEMORIA DE UNA VEZ  (`mld` / `mst` seguidos)
 *
 * TANDA, no cadena: las dos partes son independientes y solo hay que
 * ejecutarlas EN ORDEN.  Eso las hace seguras sin desambiguar direcciones --
 * dos escrituras al mismo sitio, o una escritura y una lectura del mismo sitio,
 * siguen ocurriendo en el mismo orden que antes --, y ademas son las que un
 * planificador fuera de orden querria solapar.
 *
 * SON DOS Y NO MAS, y el limite es el sitio: cada `mem_full` ocupa OCHO bytes y
 * el hueco de operandos son dieciseis.  Tres no caben.  (El tamano ya no
 * aprieta: 8+8 = 16 y `size_instr` admite 63.)
 *
 * La combinacion carga/almacen va en la PLANTILLA y no en un byte de operando,
 * porque ese byte no existe -- los dos `mem_full` llenan el hueco --.  Cuatro
 * instanciaciones y ni una rama en ejecucion.
 * ========================================================================= */

/// El `mem_full` de la segunda parte vive en `raw2`, en el mismo formato.
template <typename MemFull>
[[gnu::always_inline]] inline MemFull mem2_second(const DecodedInstr &d) {
    MemFull m;
    std::memcpy(&m, &d.data_instruction.raw_data.raw2, sizeof(m));
    return m;
}

/// Hace UN acceso: carga a registro o almacen desde registro.
template <bool IsStore, typename MemFull>
[[gnu::always_inline]] inline void mem2_one(ProcessVM *vm, const MemFull &m) {
    const uint64_t addr =
        mem_full_addr(vm, m.base, m.disp, m.flags, m.index, m.scale);
    if (IsStore)
        mem_full_store(vm, m, addr, vm->registers.regs[m.reg].qword());
    else
        vm->registers.regs[m.reg].qword(mem_full_load(vm, m, addr));
}

/// Dos accesos seguidos, con la clase de cada uno fijada AL COMPILAR.
template <bool StoreA, bool StoreB>
void exec_mem2(ProcessVM *vm, const DecodedInstr &d) {
    using MemFull = decltype(d.data_instruction.mem_full);
    mem2_one<StoreA>(vm, d.data_instruction.mem_full);
    mem2_one<StoreB>(vm, mem2_second<MemFull>(d));
}

/**
 * @brief El generico, para `metadata->exec`.
 *
 * La clase de cada acceso NO cabe en los operandos, asi que se recupera de
 * donde si esta: el bit de almacen que el fusionador dejo en `direction` y en
 * `reg_ext`, dos banderas que una fusionada ya no usa para nada.
 */
inline void exec_mem2_generic(ProcessVM *vm, const DecodedInstr &d) {
    using MemFull = decltype(d.data_instruction.mem_full);
    const bool a_store = d.flags_info.direction != 0;
    const bool b_store = d.flags_info.reg_ext;
    if (a_store)
        mem2_one<true>(vm, d.data_instruction.mem_full);
    else
        mem2_one<false>(vm, d.data_instruction.mem_full);
    const MemFull second = mem2_second<MemFull>(d);
    if (b_store)
        mem2_one<true>(vm, second);
    else
        mem2_one<false>(vm, second);
}

inline InstrFormat g_mem2_format = {
    "mem2",
    Assembly::Bytecode::AddressingMode::MEM,
    Assembly::Bytecode::InstrSizeMode::FIXED_1,
    &exec_mem2_generic,
    nullptr,
};

/// `[a_store][b_store]`.  Cuatro instanciaciones, elegidas una vez al fusionar.
inline constexpr Alu2xFn kMem2[2][2] = {
    {&exec_mem2<false, false>, &exec_mem2<false, true>},
    {&exec_mem2<true, false>, &exec_mem2<true, true>}};

/**
 * @brief Convierte @p a en la fusionada que hace los dos accesos.
 *
 * @p a conserva su propio `mem_full`; el de @p second se copia al hueco de al
 * lado.  Las partes quedan SEPARADAS a proposito: ver las dos clases de
 * fusionada en la cabecera del fichero.
 *
 * @param a        Primera; sale convertida en la fusionada.
 * @param second   La segunda instruccion, de la que se copian sus operandos.
 * @param a_store  La primera es un almacen (si no, una carga).
 * @param b_store  La segunda es un almacen.
 */
[[gnu::always_inline]] inline void make_mem2(DecodedInstr &a,
                                             const DecodedInstr &second,
                                             bool a_store, bool b_store) {
    uint64_t packed = 0;
    std::memcpy(&packed, &second.data_instruction.mem_full,
                sizeof(second.data_instruction.mem_full));
    a.data_instruction.raw_data.raw2 = packed;

    /* La clase de cada acceso, para el manejador generico.  `direction` y
     * `reg_ext` ya no significan nada en una fusionada, asi que se reutilizan
     * en vez de robarle un byte a los operandos, que estan llenos. */
    a.flags_info.direction = a_store ? 1 : 0;
    a.flags_info.reg_ext = b_store;

    a.metadata = &g_mem2_format;
    a.exec_cached = kMem2[a_store ? 1 : 0][b_store ? 1 : 0];
}

/**
 * @brief Construye la fusionada de dos ALU de tres operandos sobre @p a.
 *
 * Solo CONSTRUYE.  Que el par cumpla las condiciones -- que el temporal muera,
 * que quepa en los contadores -- lo comprueba quien llama.
 *
 * @param a        Primera del par; sale convertida en la fusionada.
 * @param op1      Opcode de la primera operacion (0x73-0x7B).
 * @param op2      Opcode de la segunda.
 * @param dst      Registro donde va el resultado final.
 * @param src1     Primera fuente de la primera operacion.
 * @param src2     Segunda fuente de la primera.
 * @param src3     La fuente de la segunda que NO es el temporal.
 * @param rt_right El temporal entra como operando DERECHO de la segunda.  Da
 *                 igual en `add`/`and`/`or`/`xor`; en `sub` cambia el resultado.
 */
[[gnu::always_inline]] inline void make_alu2x(DecodedInstr &a, uint8_t op1,
                                              uint8_t op2, uint8_t dst,
                                              uint8_t src1, uint8_t src2,
                                              uint8_t src3, bool rt_right) {
    Alu2xOperands ops;
    ops.dst = dst;
    ops.src1 = src1;
    ops.src2 = src2;
    ops.src3 = src3;

    uint64_t packed = 0;
    std::memcpy(&packed, &ops, sizeof(ops));
    packed |= (uint64_t)op1 << kAlu2xOp1Shift;
    packed |= (uint64_t)op2 << kAlu2xOp2Shift;
    packed |= (uint64_t)(rt_right ? 1u : 0u) << kAlu2xSideShift;
    a.data_instruction.raw_data.raw1 = packed;
    a.data_instruction.raw_data.raw2 = 0;

    a.metadata = &g_alu2x_format;
    a.exec_cached = kAlu2x.fn[op1 - kAlu3First][op2 - kAlu3First][rt_right];
}

/* =========================================================================
 * QUE TOCA UNA FUSIONADA
 *
 * Lo declara ELLA, porque su opcode ya no la describe: lleva el de la primera
 * del par y hace ademas lo de la segunda.  Sin esto, quien reordena tiene que
 * tratarla como barrera, y una barrera ni se mueve ni se solapa -- que es lo
 * contrario de lo que se busca, sobre todo en las TANDAS, cuyas partes son
 * independientes entre si y son las primeras candidatas a lanzarse en paralelo.
 *
 * Se resuelve por FORMATO y no guardando mascaras dentro de la instruccion,
 * porque no siempre hay sitio: `mem2` llena sus dieciseis bytes de operandos
 * con los dos bloques de direccionamiento.  Comparar el puntero de formato son
 * cuatro comparaciones en un camino que ya es frio.
 * ========================================================================= */

/**
 * @brief Rellena @p t con lo que toca la fusionada @p d.
 *
 * @return true si se pudo describir.  Si un formato fusionado no estuviera
 *         contemplado aqui, devuelve false y quien pregunte la tratara como
 *         barrera -- que es la respuesta prudente, no la silenciosa.
 */
template <typename TouchT>
[[gnu::cold]] inline bool fused_touch(const DecodedInstr &d, TouchT &t) {
    t.barrier = false;
    const auto add_read = [&t](uint8_t r) {
        t.reg_read |= (uint16_t)(1u << (r & 0xF));
    };
    const auto add_write = [&t](uint8_t r) {
        t.reg_write |= (uint16_t)(1u << (r & 0xF));
    };
    /// Lo que un `mem_full` toca: la base y el indice se LEEN siempre; el
    /// registro es destino en una carga y fuente en un almacen.
    const auto add_mem = [&](const auto &m, bool is_store) {
        t.mem = true;
        if (m.base < 16) add_read(m.base);
        if (m.flags & kMemHasIndex) add_read(m.index);
        if (is_store)
            add_read(m.reg);
        else
            add_write(m.reg);
    };

    if (d.metadata == &g_movn_format) {
        MovnOperands ops;
        std::memcpy(&ops, &d.data_instruction.raw_data.raw1, sizeof(ops));
        const uint32_t n = (uint32_t)(d.data_instruction.raw_data.raw2 & 0xFF);
        for (uint32_t i = 0; i < n; ++i) {
            add_read(ops.src[i]);
            add_write(ops.dst[i]);
        }
        return true;
    }
    if (d.metadata == &g_alu2x_format) {
        const Alu2xOperands ops = alu2x_operands(d);
        add_read(ops.src1);
        add_read(ops.src2);
        add_read(ops.src3);
        add_write(ops.dst);
        t.field_write |= kFlags;
        return true;
    }
    if (d.metadata == &g_alui_format) {
        AluiOperands ops;
        std::memcpy(&ops, &d.data_instruction.raw_data.raw2, sizeof(ops));
        add_read(ops.src);
        add_write(ops.dst);
        t.field_write |= kFlags;
        return true;
    }
    if (d.metadata == &g_ldop_format) {
        LdopOperands ops;
        std::memcpy(&ops, &d.data_instruction.raw_data.raw2, sizeof(ops));
        const auto &m = d.data_instruction.mem_full;
        t.mem = true;
        if (m.base < 16) add_read(m.base);
        if (m.flags & kMemHasIndex) add_read(m.index);
        add_read(ops.src);
        add_write(ops.dst);
        t.field_write |= kFlags;
        return true;
    }
    if (d.metadata == &g_mem2_format) {
        using MemFull = decltype(d.data_instruction.mem_full);
        add_mem(d.data_instruction.mem_full, d.flags_info.direction != 0);
        add_mem(mem2_second<MemFull>(d), d.flags_info.reg_ext);
        return true;
    }

    // Formato fusionado sin describir: barrera, y que se note.
    t.barrier = true;
    return false;
}

} // namespace runtime

#endif // VESTA_RUNTIME_EXEC_INSTRUCTION_FUSED_H
