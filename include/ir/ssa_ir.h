/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file ssa_ir.h
 * @brief Representacion Intermedia SSA (Static Single Assignment) para VestaVM.
 *
 * Este header define las estructuras de datos de la IR intermedia que un
 * compilador de lenguaje de alto nivel debe producir antes de bajar a
 * bytecode .vel de VestaVM.
 *
 * La IR usa la forma SSA: cada variable se asigna exactamente una vez.
 * Los puntos de union de flujo de control usan instrucciones Phi para
 * seleccionar el valor correcto segun el bloque predecesor.
 *
 * Pipeline tipico de un compilador HLL sobre VestaVM:
 *
 *   Fuente HLL -> AST -> Analisis semantico -> SSA IR -> Optimizador -> Emisor
 * .vel
 *
 * La SSA IR de VestaVM es intencional y deliberadamente simple:
 *   - Sin tipos de registro (todos los valores son IrValue de 64 bits).
 *   - Tipos de alto nivel se anotan con IrType para el emisor y la reflexion.
 *   - No hay calculo de liveness ni coloreado de registros en la IR:
 *     el emisor asigna registros VM de forma greedy con pool de 16 (r0-r15).
 *
 * Formato de texto (archivo .ir):  ver doc/VMdoc/IR/SSA.md
 *
 * Ejemplo minimo:
 * @code
 *   @function add(a: i64, b: i64) -> i64 {
 *   entry:
 *       %0 = add.i64 %a, %b
 *       ret.i64 %0
 *   }
 * @endcode
 */

#ifndef SSA_IR_H
#define SSA_IR_H

#include <cstdint>
#include <cstddef>

#include "ir/native_effect_vocab.h" // de quien es lo que sale, y que puede fallar
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>

// Windows (windef.h) define VOID->void, CONST->const, BOOL->int como macros,
// lo que rompe los enumerados de la IR.  Guardamos y anulamos antes de entrar.
#ifdef _WIN32
#pragma push_macro("VOID")
#pragma push_macro("CONST")
#pragma push_macro("BOOL")
#undef VOID
#undef CONST
#undef BOOL
#endif

namespace ir {

// =========================================================================
//  Tipos de la IR
// =========================================================================

/**
 * @brief Tipo de un valor en la SSA IR de VestaVM.
 *
 * Todos los valores se representan como 64 bits en los registros VM.
 * El tipo anotado sirve para:
 *   - Elegir la instruccion correcta al bajar a bytecode (add vs. fadd).
 *   - Generar metadatos de reflexion en ClassInfo/FieldInfo.
 *   - Emitir advertencias de tipo en el optimizador.
 */
enum class IrType : uint8_t {
    VOID = 0,    ///< sin valor (tipo de retorno void)
    I8 = 1,      ///< entero de 8 bits con signo
    I16 = 2,     ///< entero de 16 bits con signo
    I32 = 3,     ///< entero de 32 bits con signo
    I64 = 4,     ///< entero de 64 bits con signo (tipo por defecto)
    U8 = 5,      ///< entero de 8 bits sin signo
    U16 = 6,     ///< entero de 16 bits sin signo
    U32 = 7,     ///< entero de 32 bits sin signo
    U64 = 8,     ///< entero de 64 bits sin signo
    F32 = 9,     ///< float  IEEE 754 de 32 bits
    F64 = 10,    ///< double IEEE 754 de 64 bits (bits almacenados como u64)
    PTR = 11,    ///< puntero host (uint64_t cast)
    HANDLE = 12, ///< GcHandle de 32 bits (almacenado en los 32 bits bajos)
    BOOL = 13,   ///< booleano (0 = false, != 0 = true)
};

/**
 * @brief Convierte un IrType a su nombre en el formato de texto.
 * @param t Tipo a convertir.
 * @return Cadena del tipo ("i64", "f64", "handle", ...).
 */
const char *ir_type_name(IrType t);

/**
 * @brief Parsea el nombre de un tipo del formato de texto.
 * @param name Nombre del tipo ("i64", "u32", ...).
 * @param out  Tipo parseado.
 * @return true si el nombre es valido.
 */
bool ir_type_parse(const char *name, IrType &out);

// =========================================================================
//  Codigos de operacion de la IR
// =========================================================================

/**
 * @brief Codigos de operacion de las instrucciones SSA IR.
 *
 * Nomenclatura: el sufijo del texto (.i64, .f64, .u32) es el IrType
 * del operando/resultado, no del opcode.  El opcode solo indica la
 * operacion; el tipo se anota en IrInstr::type.
 *
 * Grupos:
 *   0x00..0x0F  Constantes y movimiento
 *   0x10..0x1F  Aritmetica entera
 *   0x20..0x2F  Aritmetica flotante
 *   0x30..0x3F  Logica y desplazamientos
 *   0x40..0x4F  Comparaciones
 *   0x50..0x5F  Conversiones de tipo
 *   0x60..0x6F  Flujo de control
 *   0x70..0x7F  SSA / phi
 *   0x80..0x8F  Llamadas (VM, nativas, virtuales)
 *   0x90..0x9F  Memoria
 *   0xA0..0xAF  OOP / GC
 *   0xB0..0xBF  Manejo de excepciones
 *   0xC0..0xCF  Async / futures
 *   0xD0..0xDF  Distribucion (mensajes, spawn remoto)
 *   0xE0..0xEF  Sincronizacion / monitores
 *   0xF0..0xFF  Intrinsics VM (proceso, scheduler, etc.)
 */
enum class IrOp : uint16_t {
    // ---- constantes y movimiento (0x00-0x0F) ----
    CONST = 0x00, ///< %dst = const.T  imm64
    MOV = 0x01,   ///< %dst = mov.T   %src   (copia; eliminada en lowering)
    NOP = 0x02,   ///< nop
    STR_LIT_ADDR =
        0x03, ///< %dst = str_lit_addr.ptr  imm=indice en IrModule::static_data
              ///<   El emisor genera "mov rDst, @Absolute(\"code.s_<imm>\")"
    ///<   resolviendo a la direccion VM del literal en la seccion data
    ///<   adjuntada al final de la seccion "code".  Tipo destino: PTR.
    LABEL_ADDR = 0x04, ///< %dst = label_addr.ptr  func_name=label_name
    ///<   Devuelve la direccion absoluta de un label resuelta por
    ///<   el linker, expresada como @c @Absolute("code.<func_name>").
    ///<   Util para slots estaticos, helpers sintetizados, etc.
    SECTION_REF =
        0x05, ///< %dst = section_ref  func_name=nombre de seccion, imm=kind
              ///<   AOT (dev OS): simbolo de seccion estilo linker.  kind:
    ///<   0=START (void*, base de la seccion), 1=END (void*, base+size),
    ///<   2=SIZE (u64, tamano en bytes).  Lo resuelve el writer AOT tras
    ///<   el layout.  En interp/JIT (sin secciones nativas) -> 0.

    // ---- aritmetica entera (0x10-0x1F) ----
    ADD = 0x10, ///< %dst = add.T    %a, %b
    SUB = 0x11, ///< %dst = sub.T    %a, %b
    MUL = 0x12, ///< %dst = mul.T    %a, %b
    DIV = 0x13, ///< %dst = div.T    %a, %b  (con signo segun T)
    MOD = 0x14, ///< %dst = mod.T    %a, %b
    NEG = 0x15, ///< %dst = neg.T    %a       (negacion entera unaria)

    // ---- aritmetica entera extendida (0x16-0x1F) ----
    // raw_asm-elim wave 4 / Math-IR-promote: ops con instr nativa
    // universal (x86 cmov/sar+xor+sub, ARM csel/abs, RISC-V min/max/abs).
    IABS = 0x16, ///< %dst = iabs.T %a            (|a|; INT_MIN undef en signed)
    IMIN = 0x17, ///< %dst = imin.T %a, %b        (min signed via cmov/csel)
    IMAX = 0x18, ///< %dst = imax.T %a, %b        (max signed via cmov/csel)
    IMINU = 0x19, ///< %dst = iminu.T %a, %b       (min unsigned)
    IMAXU = 0x1A, ///< %dst = imaxu.T %a, %b       (max unsigned)
    ILOG2 =
        0x1B, ///< %dst = ilog2.u32 %a         (highest bit pos; undef si a=0)
              ///<   Equivale a @c (63 - clz(a)) para u64.  Util en allocators,
              ///<   capacity calculations, hashing.  x86: @c bsr (3c) o
              ///<   @c (63 ^ lzcnt) ; ARM: @c clz + sub; RISC-V: @c clz.
    // SELECT: primitiva semantica de seleccion sin salto.  operands = [%cond,
    // %a, %b]; %dst = %cond ? %a : %b.  %cond es un valor booleano (0/1, como
    // el que producen los CMP_*).  Es la forma canonica de un diamante
    // if-convertido (el pase ir_pass_if_conversion la emite) y de min/max/abs.
    // Lowering por backend (NO una instruccion nueva de la VM): x86 @c cmovcc,
    // ARM @c csel, interp secuencia branchless (setcc/mascara xor-and-xor),
    // AVX @c vblendv (vectorizado).  Tipado por @c IrInstr::type (i32/i64/f32/
    // f64/ptr).  Habilita peepholes: select(c,x,x)->x, const-fold del cond,
    // select(c,0,1)->zext(c), select(a<b,a,b)->IMIN, y bool->aritmetica cuando
    // el resultado alimenta una suma (acc+select(c,1,0) -> acc+zext(c)).
    SELECT = 0x1C, ///< %dst = select.T %cond, %a, %b   (%cond ? %a : %b)

    // ADDC / SUBB + CARRYOF: aritmetica multiprecision.
    //
    // Una suma de anchura mayor que la palabra se construye sumando limbs y
    // arrastrando el acarreo.  El acarreo lo produce la CPU en un flag y lo
    // consume la suma siguiente con @c adc, pero el IR es SSA y no tiene donde
    // guardar DOS resultados, asi que se parte en dos nodos ligados por el
    // grafo: @c ADDC produce la suma y @c CARRYOF lee el acarreo DE esa suma
    // concreta (su operando es el valor que ADDC produjo).
    //
    // Que la dependencia sea explicita es justo lo que lo hace robusto: el
    // backend no tiene que RECONOCER un patron -- que cualquier pase podria
    // reordenar sin avisar --, solo seguir el uso.  Cuando el acarreo alimenta
    // otra suma, la pareja baja a @c add + @c adc; si nadie lo usa, ADDC es una
    // suma normal y CARRYOF se elimina como codigo muerto.
    //
    // Sin ellos, el acarreo se calculaba comparando el resultado con un sumando
    // (`suma < a`), lo que cuesta seis instrucciones donde la maquina necesita
    // dos.
    ADDC = 0x1D,    ///< %dst = addc.T   %a, %b   (suma; acarreo via CARRYOF)
    SUBB = 0x1E,    ///< %dst = subb.T   %a, %b   (resta; prestamo via CARRYOF)
    CARRYOF = 0x1F, ///< %dst = carryof.T %suma   (0/1 de la ADDC/SUBB dada)

    // ---- aritmetica flotante (0x20-0x2F) ----
    FADD = 0x20,   ///< %dst = fadd.fN  %a, %b
    FSUB = 0x21,   ///< %dst = fsub.fN  %a, %b
    FMUL = 0x22,   ///< %dst = fmul.fN  %a, %b
    FDIV = 0x23,   ///< %dst = fdiv.fN  %a, %b
    FNEG = 0x24,   ///< %dst = fneg.fN  %a        (negacion flotante unaria)
    FABS = 0x25,   ///< %dst = fabs.fN  %a        (valor absoluto)
    FSQRT = 0x26,  ///< %dst = fsqrt.fN %a        (raiz cuadrada)
    FMIN = 0x27,   ///< %dst = fmin.fN  %a, %b
    FMAX = 0x28,   ///< %dst = fmax.fN  %a, %b
    FFLOOR = 0x29, ///< %dst = ffloor.fN %a        (round toward -inf)
    FCEIL = 0x2A,  ///< %dst = fceil.fN  %a        (round toward +inf)
    FROUND = 0x2B, ///< %dst = fround.fN %a        (round to nearest, banker's)
    FTRUNC = 0x2C, ///< %dst = ftrunc.fN %a        (round toward zero)
                   ///<   raw_asm-elim wave 4: las 4 son single-instr en x86
                   ///<   (@c roundsd con bits 0-1 de imm8 = rounding mode), en
    ///<   ARM (@c frintm/p/n/z), en WASM (@c f64.floor/ceil/nearest/trunc)
    ///<   y en RISC-V (@c fcvt.l.d con rounding mode).  Reactivados.
    // ---- ops VECTORIALES FUSIONADAS (auto-vectorizacion, 0x2D-0x2F) ----
    // Compiler-internas: las emite el matcher de vectorize.cpp para el cuerpo
    // de un loop element-wise (W elementos por iteracion).  Son FUSIONADAS
    // (load+op+store en UNA op) para NO necesitar un "valor vectorial" SSA: el
    // modelo de valores del IR es de 8 bytes (GP) y un vector son 16/32/64B,
    // asi
    // que el vector vive solo TRANSITORIO dentro de la op (zmm0/zmm1 scratch en
    // interp, xmm0/xmm1 en jit).  Operandos = punteros HOST a los elementos i.
    // imm bits 0-7 = ancho en bytes (16/32/64 = 128/256/512b); bits 8-15 =
    // sub-op.
    // Bajada por backend (reusa ops EXISTENTES; cero opcodes VM nuevos):
    //   interp: movh host<->VM-stack scratch + fload/fstore ZMM + f<op>[.ps]
    //           packed.  Roundtrip correcto (interp = oraculo).
    //   jit/aot: MOVUPD [ptr] + <packed op> + MOVUPD (SIMD directo).
    // VEC_UNOP dst[i] = OP a[i]    (subop 0=copy 1=fneg 2=fabs 3=fsqrt)
    // VEC_BINOP dst[i] = a[i] OP b[i] (subop 0=fadd 1=fsub 2=fmul 3=fdiv)
    VEC_UNOP = 0x2D, ///< vec_unop.fN %dst_ptr, %a_ptr imm=(subop<<8)|ancho
    VEC_BINOP =
        0x2E, ///< vec_binop.fN %dst_ptr, %a_ptr, %b_ptr imm=(subop<<8)|ancho
    // VEC_FMA acc[i] += a[i] * b[i]  (dot-product fusionado, 1 redondeo).
    VEC_FMA = 0x2F, ///< vec_fma.fN %acc_ptr, %a_ptr, %b_ptr   imm=ancho

    // ---- logica y desplazamientos (0x30-0x3F) ----
    AND = 0x30, ///< %dst = and.T    %a, %b
    OR = 0x31,  ///< %dst = or.T     %a, %b
    XOR = 0x32, ///< %dst = xor.T    %a, %b
    NOT = 0x33, ///< %dst = not.T    %a
    SHL = 0x34, ///< %dst = shl.T    %a, %n   (desplazamiento a izquierda)
    SHR = 0x35, ///< %dst = shr.T    %a, %n   (logico, sin signo)
    SAR = 0x36, ///< %dst = sar.T    %a, %n   (aritmetico, con signo)
    // ---- bit ops extendidos (0x37-0x3F) ---- raw_asm-elim wave 4 /
    // Math-IR-promote.
    CLZ = 0x37, ///< %dst = clz.u32 %a           (count leading zeros; x86
                ///< lzcnt, ARM clz)
    CTZ =
        0x38, ///< %dst = ctz.u32 %a           (count trailing zeros; x86 tzcnt)
    POPCNT = 0x39, ///< %dst = popcnt.u32 %a        (Hamming weight; x86 popcnt,
                   ///< ARM cnt)
    BYTESWAP =
        0x3A, ///< %dst = byteswap.T %a        (endian swap; x86 bswap, ARM rev)
    ROTL = 0x3B, ///< %dst = rotl.T %a, %n        (rotate left; x86 rol, ARM ror
                 ///< neg)
    ROTR =
        0x3C, ///< %dst = rotr.T %a, %n        (rotate right; x86 ror, ARM ror)

    // ---- comparaciones enteras (0x40-0x47) ----
    CMP_EQ = 0x40,  ///< %dst = cmp.eq.T  %a, %b  -> bool
    CMP_NE = 0x41,  ///< %dst = cmp.ne.T  %a, %b  -> bool
    CMP_LT = 0x42,  ///< %dst = cmp.lt.T  %a, %b  -> bool (con signo)
    CMP_GT = 0x43,  ///< %dst = cmp.gt.T  %a, %b  -> bool
    CMP_LE = 0x44,  ///< %dst = cmp.le.T  %a, %b  -> bool
    CMP_GE = 0x45,  ///< %dst = cmp.ge.T  %a, %b  -> bool
    CMP_ULT = 0x46, ///< %dst = cmp.ult.T %a, %b  -> bool (sin signo)
    CMP_UGT = 0x47, ///< %dst = cmp.ugt.T %a, %b  -> bool
    CMP_ULE = 0x48, ///< %dst = cmp.ule.T %a, %b  -> bool
    CMP_UGE = 0x49, ///< %dst = cmp.uge.T %a, %b  -> bool

    // ---- comparaciones flotantes (0x4A-0x4F) ----
    FCMP_EQ = 0x4A, ///< %dst = fcmp.eq.fN %a, %b -> bool  (ordered)
    FCMP_NE = 0x4B, ///< %dst = fcmp.ne.fN %a, %b -> bool
    FCMP_LT = 0x4C, ///< %dst = fcmp.lt.fN %a, %b -> bool
    FCMP_GT = 0x4D, ///< %dst = fcmp.gt.fN %a, %b -> bool
    FCMP_LE = 0x4E, ///< %dst = fcmp.le.fN %a, %b -> bool
    FCMP_GE = 0x4F, ///< %dst = fcmp.ge.fN %a, %b -> bool

    // ---- conversiones de tipo (0x50-0x5F) ----
    CAST = 0x50,  ///< %dst = cast.T    %src  (truncar/extender/reinterpretar)
    ZEXT = 0x51,  ///< %dst = zext.T    %src  (zero-extend a tipo mayor)
    SEXT = 0x52,  ///< %dst = sext.T    %src  (sign-extend a tipo mayor)
    TRUNC = 0x53, ///< %dst = trunc.T   %src  (truncar a tipo menor)
    ITOF = 0x54,  ///< %dst = itof.fN   %src  (entero con signo a flotante)
    UITOF = 0x55, ///< %dst = uitof.fN  %src  (entero sin signo a flotante)
    FTOI = 0x56,  ///< %dst = ftoi.T    %src  (flotante a entero con signo)
    FTOUI = 0x57, ///< %dst = ftoui.T   %src  (flotante a entero sin signo)
    F32TOF64 = 0x58, ///< %dst = f32tof64  %src  (widening: f32 -> f64)
    F64TOF32 = 0x59, ///< %dst = f64tof32  %src  (narrowing: f64 -> f32)
    BITCAST =
        0x5A,   ///< %dst = bitcast.T %src  (reinterpretar bits sin conversion)
    FMA = 0x5B, ///< %dst = fma.fN  %a, %b, %c   (multiply-add CONTRAIDO: UN
                ///< SOLO redondeo, round(a*b+c) -- NO es fmul+fadd).  Intencion
                ///< matematica (como IMIN/IMAX): interp usa std::fma; JIT/AOT
                ///< VFMADD231 si caps.fma, si no CALL a std::fma.  Lo emite el
                ///< pase fuse_fma solo en funciones @fp(fast).

    // ---- flujo de control (0x60-0x6F) ----
    BR = 0x60,          ///< br  label                    (salto incondicional)
    BR_COND = 0x61,     ///< br.cond %cond, L_true, L_false
    RET = 0x62,         ///< ret.T %val  /  ret.void
    UNREACHABLE = 0x63, ///< unreachable               (codigo inalcanzable)

    // ---- SSA (0x70-0x7F) ----
    PHI = 0x70, ///< %dst = phi.T [%v0, L0], [%v1, L1], ...

    // ---- llamadas (0x80-0x8F) ----
    CALL = 0x80, ///< %dst = call.T    @fn(%a, %b, ...)        (intra-modulo)
    CALLIND =
        0x81, ///< %dst = callind.T %fn_ptr(%a, ...)        (puntero de funcion)
    TAILCALL =
        0x82, ///< tailcall @fn(%a, %b, ...)                (tail-call intra)
    CALLVIRT = 0x83, ///< %dst = callvirt.T %obj, vtbl_idx(%a, ...) (virtual via
                     ///< vtable)
    CALLN =
        0x84, ///< %dst = calln.T   @lib:func(%a, ...)      (nativa FFI calln)
    CALLM = 0x85, ///< %dst = callm.T   %obj, %method(%a, ...)  (dispatch via
                  ///< puntero
    ///< MethodInfo* directo; usado para invocacion polimorfica sobre
    ///< tipo interfaz y para reflexion runtime donde la vtable_idx no
    ///< es conocida en compile time)
    CALLITF = 0x8A, ///< %dst = callitf.T %obj, %params(%a, ...)  (dispatch de
    ///< interfaz via itable).  Reemplaza el findmethod+callm para
    ///< llamadas polimorficas sobre un tipo INTERFAZ estatico.
    ///< El receptor (operands[0]) es el objeto; operands[1] es un
    ///< puntero a un @c ItfCallParams (32 bytes, construido por el
    ///< frontend) usado SOLO por el interp (el JIT lo ignora y usa
    ///< los campos del IR op directamente).  operands[2..] = args
    ///< (retbuf SRET como operands[2] si aplica).  Campos del IR:
    ///<   @c func_name = "InterfazNombre\x1fmetodoNombre"
    ///<   @c imm = (count << 32) | method_index
    ///< donde method_index es la posicion del metodo en la
    ///< declaracion de la interfaz y count su numero de metodos.
    ///< El interp ejecuta el bytecode @c callitf (dispatch via la
    ///< itable lazy de la clase concreta); el JIT inlinea el scan
    ///< de itables + call directo a method->jit_code.
    CALLCLOSURE = 0x86, ///< %dst = callclosure.T %fn_ptr, %env(%a, ...)
    ///< Llamada a closure inline.  Identico a CALLIND pero ademas
    ///< coloca @c env en R14 antes del @c callvm fn_ptr.  Si la
    ///< lambda no captura nada, env = 0 (sentinela).  El campo
    ///< @c func_ptr lleva el SSA del fn_addr; el primer operando
    ///< es el env_ptr; los restantes son los args declarados.
    ///< Lowering: el frontend Vesta emite un helper sintetico
    ///< @c __lambda_<N> con el cuerpo del lambda y el call site
    ///< usa este opcode pasando fn_addr + env_addr en el slot
    ///< stack del function value (16 bytes inline, cero heap).

    MAKE_VARIANT = 0x88, ///< make_variant @"Enum.Variant", tag=imm,
                         ///< payload=[%p0, %p1, ...]
                         ///< Marker semantico para construccion de un valor
    ///< de tipo ADT (enum variant).  Emitido por
    ///< @c lower_enum_constructor ANTES de la secuencia explicita
    ///< de ALLOCA + STORE tag + STOREs payload.  Permite que C2 haga
    ///< case-splitting eficiente sobre el match downstream + posible
    ///< escape analysis (promover slot a regs si no escapa).
    ///<
    ///< Campos:
    ///<   @c func_name = "<EnumName>.<VariantName>" (ej. "Color.Green")
    ///<   @c imm = tag de la variante (indice 0..N-1)
    ///<   @c operands = SSA values de los M payloads (M >= 0)
    ///<   @c dst = IR_NO_VALUE (marker puro)
    ///<
    ///< El IR emitter actual lo trata como no-op.

    MATCH_VARIANT = 0x89, ///< match_variant %scrutinee, @EnumName, n_arms=imm
                          ///< Marker semantico para el inicio de un @c match.
    ///< Emitido por @c lower_match_expr ANTES de la cadena de
    ///< cmp_eq + br_cond sobre el tag del scrutinee.  Permite que C2
    ///< reconozca el patron y emita dispatch eficiente (jumptable
    ///< si N grande + tags densos, switch tree balanceado si dispersos).
    ///<
    ///< Campos:
    ///<   @c func_name = nombre del enum (ej. "Color")
    ///<   @c imm = numero de arms con variantes concretas (no default)
    ///<   @c operands[0] = SSA value PTR al slot del scrutinee
    ///<   @c dst = IR_NO_VALUE (marker puro)
    ///<
    ///< El IR emitter actual lo trata como no-op.
    SWITCH_DENSE =
        0x8B, ///< switch_dense %tag, min=imm, targets=jump_targets[],
              ///< default=target_block.  Marker (no-op en interp/
              ///< optimizer/ir_emitter) que el backend JIT (vreg)
              ///< baja a un island nativo O(1) (computed-goto):
              ///< idx=tag-min; if idx u>=N -> default; else jmp al
              ///< brazo jump_targets[idx].  Emitido por
              ///< lower_match_expr para match DENSO (rango~=N) tras
              ///< el LOAD del tag y JUNTO al BST (que es el dispatch
              ///< del interp + fallback).  operands[0]=%tag.

    MAKE_CLOSURE =
        0x87, ///< make_closure @helper, env_kind=imm, captures=[%c0, %c1, ...]
              ///<  Marker semantico que identifica la construccion
              ///< completa de una closure.  Emitido por @c lower_lambda_expr
              ///< ANTES de la secuencia explicita de ALLOCA env + STOREs +
              ///< ALLOCA fv + STORE fn_addr + STORE env_addr.  Permite que el
              ///< C2 JIT haga escape analysis sobre el closure
              ///< sin pattern-matching de 14 instrucciones individuales.
              ///<
              ///< Campos:
              ///<   @c func_name = nombre del helper sintetico (__lambda_<N>)
              ///<   @c imm = bit 0: env_kind (0=STACK ALLOCA, 1=GC_HEAP).
    ///<            bits 1..16: mutable_mask (bit i+1 = capture i es by-ref).
    ///<   @c operands = SSA values de las N capturas (en orden de declaracion)
    ///<   @c dst = IR_NO_VALUE (marker puro; la closure se construye via
    ///<            las siguientes instrucciones)
    ///<
    ///< El IR emitter actual trata MAKE_CLOSURE como no-op:
    ///< las instrucciones reales de construccion siguen produciendo
    ///< el bytecode.  El C2 lo usa para identificar y posiblemente
    ///< eliminar/promover la alocacion del env block.

    // ---- memoria (0x90-0x9F) ----
    ALLOCA = 0x90, ///< %dst = alloca.T count       (reservar en pila local)
    LOAD = 0x91,   ///< %dst = load.T  %ptr         (leer; movh si is_host_ptr,
                   ///< mov si no)
    STORE = 0x92,  ///< store.T  %val, %ptr         (escribir; idem LOAD)
    MEMCPY = 0x93, ///< memcpy %dst_ptr, %src_ptr, %len
    /**
     * memset %dst_ptr, %val, %len  -- rellena @c len bytes desde @c dst con el
     * byte bajo de @c val.  Gemelo de @c MEMCPY.
     *
     * POR QUE ES UN OP DEL IR Y NO UNA CADENA DE STORES.  "Esta region se pone
     * a un valor" es un HECHO SEMANTICO, y desplegarlo en el lowering lo
     * DESTRUYE: ningun nivel inferior puede reconstruirlo a partir de N stores
     * sueltos.  Es la regla del optimizer -- cada cosa en el nivel MAS ALTO
     * donde la informacion aun existe. Medido antes de existir este op:
     * `i32[8192] arr;` (una DECLARACION) generaba 16397 instrucciones, 86 KB de
     * codigo y 1,7 s de compilacion, porque el zero-fill se desplegaba a un
     * STORE por cada 8 bytes sin limite.
     *
     * Cada backend lo MATERIALIZA segun su contexto, que es justo lo que un op
     * semantico permite: el interprete un bucle, el JIT/AOT `rep stosb` o SIMD,
     * y un programa sin runtime la rutina que el usuario haya puesto en su
     * lugar (el mecanismo de sobrecarga ya existe: @c vx_memset es Vesta puro,
     * sin libc, y el vectorizador del AOT puede promover su bucle de qwords).
     * Un tamano pequeno y constante lo desenrolla el BACKEND -- ahi la decision
     * ya no pierde nada.
     */
    MEMSET = 0x9F,
    RAW_ALLOC =
        0x94, ///< %dst = raw_alloc.ptr %size  (rawalloc; dst es puntero host)
    RAW_FREE = 0x95,  ///< raw_free %ptr               (rawfree)
    GC_ALLOC = 0x96,  ///< %dst = gc_alloc.ptr %size   (alloc en heap GC, dst es
                      ///< host_ptr al payload).
    MVTAKE_IR = 0x97, ///< mvtake [dst_addr], [src_addr]  (move-and-zero atomic
                      ///< intra-thread)
    GC_SET_FINALIZER = 0xD3, ///< gcfinal %box, imm=kind  (registra/desregistra
                             ///< el finalizador GC de un box con recurso
                             ///< interno; kind 0=desregistrar, 1=UNIQUE,
                             ///< 2=SHARED).  interp/JIT: opcode gcfinal;
                             ///< AOT: CALL vx_gc_register_finalizer.
    GC_COLLECT = 0xD4, ///< gccollect  (fuerza minor+major GC del proceso +
                       ///< drena finalizadores).  Builtin Vesta gc_collect().
    ///< interp/JIT: opcode gccollect; AOT: CALL vx_gc_collect.
    GC_FINALIZE_ALL = 0xD5, ///< gcfinall  (finaliza TODO objeto GC vivo con
                            ///< recurso interno).  Builtin Vesta
                            ///< gc_finalize_all(). interp/JIT: opcode gcfinall;
                            ///< AOT: CALL vx_gc_finalize_all.  Determinista.
    GC_ALLOCP = 0x98,  ///< %dst = gc_allocp.ptr %size  (gcallocp: alloc + deref
                       ///< + xchg en 1 instr)
    GETSTATIC = 0x99,  ///< %dst = getstatic.i64 %cls, imm=offset   (carga campo
                       ///< estatico)
    SETSTATIC = 0x9A,  ///< setstatic.i64 %cls, %val, imm=offset    (almacena
                       ///< campo estatico)
    ATOMIC_LD = 0x9B,  ///< %dst = atomic_ld.i64 [%addr]   (atomic load i64)
    ATOMIC_ST = 0x9C,  ///< atomic_st.i64 [%addr], %val
    ATOMIC_CAS = 0x9D, ///< %dst = atomic_cas.i64 [%addr], %expected, %desired
    ATOMIC_ADD =
        0x9E, ///< %dst = atomic_add.i64 [%addr], %delta (fetch-and-add)
              ///< El bloque queda en HandleTable y participa del mark/sweep.
    ///< Si nada lo referencia (stack/regs/external_refs), se libera en
    ///< major_gc.
    ///< Usado por @c lower_lambda_expr cuando @c env_in_heap=true (closures que
    ///< escapan).

    // ---- OOP / GC (0xA0-0xAF) ----
    NEWOBJ = 0xA0, ///< %dst = newobj  %class_ptr          (allojar objeto GC)
    GETFIELD =
        0xA1, ///< %dst = getfield.T  %obj, field_off (gcderef+addcur+readcur)
    SETFIELD = 0xA2, ///< setfield.T %obj, field_off, %val   (writecur + gcwb si
                     ///< HANDLE)
    INSTANCEOF = 0xA3, ///< %dst = instanceof %obj, %class_ptr -> bool
    CHECKCAST = 0xA4,  ///< checkcast %obj, %class_ptr         (throw si falla)
    ISNULL = 0xA5, ///< %dst = isnull %src                 (r = (src==0)?1:0)
    UNWRAP =
        0xA6, ///< %dst = unwrap %src                 (throw NullPointer si 0)
    SPECIALIZE = 0xA7, ///< %dst = specialize %class, %types, count
    GEP = 0xA8, ///< %ptr = gep.ptr %handle, imm_off    (byte-offset en objeto
                ///< GC via cursor)
    GCWB_IR = 0xA9,     ///< gcwb_ir %handle                    (write barrier
                        ///< explicito al GC)
    ARRAY_ALLOC = 0xAA, ///< %h = array_alloc.T %len            (allojar array
                        ///< tipado; helper nativo)
    ARRAY_LEN = 0xAB, ///< %n = array_len.i64 %arr            (leer campo length
                      ///< del array)
    ARRAY_LOAD = 0xAC,  ///< %v = array_load.T %arr, %idx       (carga con MOVC
                        ///< SIB stride)
    ARRAY_STORE = 0xAD, ///< array_store.T %arr, %idx, %val     (escritura +
                        ///< gcwb si HANDLE)
    GCDEREF_IR =
        0xAE, ///< gcderef_ir %handle                 (gcderef a cur0; ver nota)
    GC_DEREF_HOST = 0xAF, ///< %dst = gc_deref_host.ptr %handle    (GcHandle ->
                          ///< host_ptr al payload)
    ///<   Combina @c gcderef + @c xchg en 1 IR op.  El emisor
    ///<   bytecode genera @c "gcderef cur0, r_src" + @c "xchg cur0, r_dst",
    ///<   2 instr VM como antes (sin nuevo opcode de bytecode), pero
    ///<   el optimizer ahora puede aplicar CSE (deduplicar conversiones
    ///<   del mismo handle dentro de un bloque), DCE (eliminar si
    ///<   dst no se usa), y el Selector JIT no tiene que parsear el
    ///<   patron en raw_asm.  Reemplaza el viejo blob
    ///<   `RAW_ASM "gcderef cur0, {src0}\nxchg cur0, {dst}\n"`.

    // ---- manejo de excepciones (0xB0-0xBF) ----
    THROW = 0xB0, ///< throw %exc_obj                     (lanzar excepcion)
    TRYENTER =
        0xB1, ///< tryenter %handler_pc, %class_ptr   (push ExceptionFrame)
    TRYLEAVE =
        0xB2, ///< tryleave                           (pop ExceptionFrame)
    LANDINGPAD = 0xB3, ///< %exc = landingpad.T                (receptor del
                       ///< objeto en catch)
    // -- operaciones de cadena (0xB4-0xBF): bajan a instrucciones VM
    // strmake..strfinalize --
    STRMAKE = 0xB4,   ///< %h = strmake.handle %buf, %len [enc=imm]
    STRLEN = 0xB5,    ///< %n = strlen.i64 %str_handle
    STRCAT = 0xB6,    ///< %h = strcat.handle %a, %b
    STRCMP = 0xB7,    ///< %r = strcmp.i64 %a, %b   (-1/0/1)
    STRSLICE = 0xB8,  ///< %h = strslice.handle %str, %range
    STRFLAT = 0xB9,   ///< %h = strflat.handle %str
    STRHASH = 0xBA,   ///< %n = strhash.u64 %str
    STRINTERN = 0xBB, ///< %h = strintern.handle %str
    STRRAW =
        0xBC, ///< %p = strraw.ptr %str              (host pointer para FFI)
    STRCONV = 0xBD, ///< %h = strconv.handle %str, enc=imm
    STRRESERVE =
        0xBE, ///< %h = strreserve.handle %cap       (FLAT con capacidad)
    STRFINALIZE =
        0xBF, ///< strfinalize %str, %new_len        (actualizar byte_len+hash)

    // ---- async / futures (0xC0-0xCF) ----
    FUTURE =
        0xC0, ///< %dst = future                    (crear FutureObject PENDING)
    AWAIT =
        0xC1, ///< %dst = await.T %future_handle    (bloquear hasta resolver)
    FULFILL = 0xC2, ///< fulfill  %future_handle, %value  (resolver con valor)
    REJECT = 0xC3,  ///< reject   %future_handle, %error  (rechazar con codigo)
    FULFILL_HLT =
        0xC4, ///< fulfillhlt %fut, %val           (fusion atomica fulfill+hlt)
    STRGETBYTES =
        0xC5, ///< %n = strgetbytes.i64 %str       (byte_len del StringObject)
    RETHROW = 0xC6, ///< rethrow                         (relanza
                    ///< current_exception del handler)
                    ///<   Terminator de bloque sin operandos.  Baja al bytecode
    ///<   @c rethrow (extended NONE).  Solo valido dentro del cuerpo
    ///<   de un catch handler donde la VM tiene @c current_exception
    ///<   seteada; en cualquier otro contexto el runtime lanza
    ///<   FATAL_ILLEGAL_INSTRUCTION.  Reemplaza el viejo
    ///<   RAW_ASM "rethrow\n" usado en synchronized cleanup.
    SHARED_STAT = 0xC7, ///< %dst = shared_stat.T %op_code    ( Z introspect)
    ///<   op_code (i32 imm): 0=live_count (-> u32), 1=bytes (-> u64),
    ///<                       2=gc_collect (-> void).
    ///<   Reemplaza RAW_ASM "sharedstat ..." con un IR op tipado;
    ///<   el bytecode emitido sigue siendo el opcode extended 0xAD.
    READ_VM_REG = 0xC8, ///< %dst = read_vm_reg.T imm=N      (leer @c
                        ///< proc->registers.regs[N])
    ///<   Lectura directa de un VM register por indice (0..15).
    ///<   Util para closure helper prologue (R14 = env_ptr), o
    ///<   cualquier patron donde el frontend necesita acceder a un
    ///<   reg fuera de la calling convention estandar R1..R12.
    ///<   El bytecode emitido es @c "mov {dst}, rN".  Reemplaza
    ///<   RAW_ASM "mov {dst}, r14\n".
    RSPAWN_RETURN = 0xC9, ///< rspawn_return %payload         (mov r0, %payload
                          ///< + hlt fusionado)
    ///<   Terminator de bloque especifico de rspawn bodies.  El runtime
    ///<   distribuido detecta HALT en un proceso con
    ///<   @c rspawn_future_id != 0, captura R0 como payload y envia
    ///<   VDP_FUTURE_FULFILL al nodo origen.  Reemplaza RAW_ASM
    ///<   "mov r0, {src0}\nhlt\n".
    REFLECT_COUNT = 0xCB, ///< %dst = reflect_count.<kind> %cls
    ///<   Reflexion: cuenta methods (kind=0) o fields (kind=1).
    ///<   imm = sub-op.  El emisor bytecode produce
    ///<   @c "methodcount/fieldcount {src0}\nmov {dst}, r0\n".
    ///<   Reemplaza RAW_ASM equivalente.
    MOD_LOAD = 0xCD, ///< %dst = mod_load.<kind> %path_addr, %path_len
    ///<   imm = kind: 0=loadmod, 1=unloadmod.  El emitter genera:
    ///<   @c "<mnem> r_path, r_len\nmov {dst}, r0\n".  loadmod ejecuta el
    ///<   main del modulo cargado (call site), unloadmod marca el slot
    ///<   como libre y devuelve 1/0.  Reemplaza RAW_ASM equivalentes.
    DLOPEN = 0xCE, ///< %dst = dlopen %path_addr, %path_len  (FFI runtime
                   ///< LoadLibrary/dlopen)
    ///<   Devuelve handle i64 a la libreria cargada (o 0 si falla).
    ///<   Reemplaza RAW_ASM "dlopen {dst}, r12, r11".
    DLSYM = 0xCF, ///< %dst = dlsym %handle, %name_addr, %name_len
                  ///<   Devuelve fn_addr i64 del simbolo (o 0 si no existe).
                  ///<   Reemplaza RAW_ASM "dlsym {dst}, r12, r11, r10".
    REFLECT_AT = 0xCC, ///< %dst = reflect_at.<kind> %cls, %idx
                       ///<   Reflexion: devuelve &cls->methods[i] (kind=0) o
    ///<   &cls->fields[i] (kind=1).  imm = sub-op.  El emisor
    ///<   produce @c "getmethat/getfldat {src0}, {src1}\nmov {dst}, r0\n".
    SMARTPTR_FREE =
        0xCA, ///< smartptr_free.<kind> %ptr [, %deleter_addr] [, "label"]
              ///<   Cleanup deterministico de unique<T> con dispatch segun
              ///<   @c imm = kind:
    ///<     0 = SRET_DISPATCH (operands=[ptr, deleter_addr_at_slot+8],
    ///<                       func_name="")
    ///<         si ptr==0 -> skip; si deleter==0 -> free(ptr);
    ///<         si no -> callvmr deleter_addr(ptr).
    ///<     1 = EXTERN_CALLN  (operands=[ptr], func_name="<lib>:<fn>")
    ///<         si ptr==0 -> skip; si no -> calln @Method(...).
    ///<     2 = VESTA_CALLVM  (operands=[ptr], func_name="<fn_label>")
    ///<         si ptr==0 -> skip; si no -> callvm @Absolute("code.<fn>").
    ///<
    ///<   Reemplaza 3 blobs RAW_ASM con cmpu+jmp+mov+call+labels.
    ///<   El emisor bytecode expande a la secuencia equivalente con
    ///<   labels unicos.  Marcado side-effecting (siempre invoca un
    ///<   destructor o free).

    // ---- Meta-OOP / reflexion /  Z extras (0x71-0x7C) ----
    // Movido fuera del 0xA0-0xAF (OOP/GC) y 0x80-0x8F (llamadas) que
    // estaban llenos.  Estos ops bajan a opcodes bytecode extended ya
    // existentes en la VM.
    GC_HANDLE_FOR_PTR =
        0x71, ///< %dst = gchandle.i64 %host_ptr   (host_ptr -> GcHandle uint32)
    GC_PROMOTE =
        0x72,         ///< %dst = gcpromote %host_ptr      (local -> SharedHeap)
    GC_DEMOTE = 0x73, ///< %dst = gcdemote %host_ptr       (SharedHeap -> local)
    FINDCLASS =
        0x74, ///< %dst = findclass %params        (lookup ClassInfo* by name)
    DEFCLASS =
        0x75, ///< %dst = defclass %params         (define clase en runtime)
    DEFFIELD = 0x76, ///< deffield %cls, %params          (añade field a clase)
    DEFMETHOD =
        0x77, ///< defmethod %cls, %params         (añade metodo a clase)
    ADDADVICE =
        0x78, ///< addadvice %target, %advice, kind  (AOP: BEFORE/AFTER/AROUND)
    FINDMETHOD =
        0x79, ///< %dst = findmethod %params       (lookup MethodInfo* by name)
    FINDFIELD =
        0x7A, ///< %dst = findfield %params        (lookup FieldInfo* by name)
    CALLSUPER =
        0x7B,       ///< %dst = callsuper %method, args  (invoca super.method())
    PROCEED = 0x7C, ///< %dst = proceed                  (re-invoca target
                    ///< dentro de @Around)
    SETMETHDBG = 0x7D, ///< setmethdbg %method, %params     (registra debug info
                       ///< file:line de un MethodInfo*)
    NEWOBJS = 0x7E,    ///< %dst = newobjs %class_ptr        (allojar objeto en
                       ///< SharedHeap,  Z.6)

    // ---- distribucion (0xD0-0xDF) ----
    MSGSEND = 0xD0, ///< %dst = msgsend %pid, %buf_addr, %len -> bool (1=ok)
    MSGRECV = 0xD1, ///< %dst = msgrecv.T %max_len, %buf_addr -> bytes (bloquea)
    RSPAWN = 0xD2,  ///< %dst = rspawn   %node_idx, %fn_addr -> future_handle

    // ---- sincronizacion / monitores (0xE0-0xEF) ----
    MONENTER = 0xE0, ///< monenter %obj     (adquirir monitor reentrable)
    MONEXIT = 0xE1,  ///< monexit  %obj     (liberar monitor)
    MONWAIT = 0xE2,  ///< monwait  %obj     (liberar y esperar; re-adquirir al
                     ///< despertar)
    MONNOTI = 0xE3,  ///< monnoti  %obj     (despertar un esperante)
    MONNOTA = 0xE4,  ///< monnota  %obj     (despertar todos los esperantes)

    // ---- acumulador vectorial register-resident (reduccion/dot-product) ----
    // El acumulador de W lanes vive en un XMM/YMM/ZMM DEDICADO (no en memoria)
    // a traves del bucle -> sin round-trip por iteracion.  El interprete
    // (oraculo) usa el acc_slot de memoria (lento pero correcto); el JIT usa el
    // registro y solo vuelca al slot UNA vez (VEC_ACC_STORE) al salir del
    // bucle,
    // donde la reduccion horizontal existente lo consume.  imm = ancho
    // (16/32/64).
    // imm = ancho(bits0-7) | acc_idx(bits8-11) | src_idx(bits12-15, COMBINE).
    // Para ocultar la latencia de la cadena de dependencia, el bucle se
    // desenrolla en U acumuladores INDEPENDIENTES (acc_idx 0..U-1); al final se
    // combinan (VEC_ACC_COMBINE acc0 += acc_j) antes de la reduccion
    // horizontal.
    VEC_ACC_ZERO = 0xE5, ///< vec_acc_zero %slot         (acc[idx] = 0)
    VEC_ACC_ADD = 0xE6,  ///< vec_acc_add  %slot, %a      (acc[idx] += a[chunk])
    VEC_ACC_FMA = 0xE7,  ///< vec_acc_fma  %slot, %a, %b  (acc[idx] += a*b)
    VEC_ACC_STORE =
        0xE8, ///< vec_acc_store %slot         (slot = acc[0]; nop interp)
    VEC_ACC_COMBINE = 0xE9, ///< vec_acc_combine %slot   (acc[dst] += acc[src])

    // VEC_BINOP_S dst[i] = a[i] OP escalar  (escalado/offset element-wise): el
    // escalar (loop-invariante; f64 o entero ya replicado a 64b) se DIFUNDE a
    // todos los lanes.  imm: bits0-7=ancho, bits8-15=subop, bit16=HOISTED (el
    // broadcast esta pre-hecho en XMM13 por un VEC_BCAST en el preheader -> el
    // loop usa VX puro sin re-broadcast ni transicion AVX/SSE).
    VEC_BINOP_S = 0xEA, ///< vec_binop_s.fN %dst, %a, %scalar
    // VEC_BCAST: difunde el escalar (operands[0]) a TODOS los lanes de XMM13
    // (registro reservado) UNA vez en el preheader del loop, para que el
    // VEC_BINOP_S del cuerpo lo reuse sin re-broadcast por iteracion (hoist).
    // No-op en el interprete (su VEC_BINOP_S re-lee el escalar por lane).
    // imm=ancho del chunk.  XMM13 = acc0; scalar-bcast y reduccion no coexisten
    // en un matcher de 1 sentencia, asi que reusar XMM13 es seguro.
    // VEC_FMA_S dst[i] += a[i] * escalar  (element-wise, escalar difundido).
    // Paso "array escalado" de un compound (c[i]=a[i]*k1 + b[i]*k2): c = c +
    // b*k2 en 1 pasada, 1 redondeo (VFMADD231 reg-reg-reg).  El escalar esta
    // pre-difundido en XMM(13-sidx) por un VEC_BCAST (hoisted).  El SUB se
    // maneja negando el escalar en el matcher (c - b*k = c + b*(-k)).  Solo
    // float.  operands = {dst_ptr, a_ptr, scalar_value}; imm = ancho |
    // hoisted<<16 | sidx<<17.
    VEC_FMA_S = 0xEC, ///< vec_fma_s.fN %dst, %a, %scalar  (dst += a*scalar)
    VEC_BCAST = 0xEB, ///< vec_bcast.fN %scalar

    // ---- intrinsics VM (0xF0-0xFF) ----
    GETPROC = 0xF0, ///< %dst = getproc     (ProcessVM* del proceso actual)
    GETVM = 0xF1,   ///< %dst = getvm       (VM* de la instancia)
    GETMGR = 0xF2,  ///< %dst = getmgr      (ManageVM* del gestor global)
    SPAWN = 0xF3,   ///< %dst = spawn    %fn_ptr     (crear proceso hijo)
    RESUME = 0xF4,  ///< resume          %pid         (despertar proceso)
    YIELD = 0xF5, ///< yield                        (ceder quantum al scheduler)
    SWAPCTX =
        0xF6, ///< swapctx %dst_ctx, %src_ctx  (cambio de contexto cooperativo)
    SPAWN_ARGS = 0xF7, ///< %dst = spawn_args %fn_ptr, %arg1, %arg2, ...
    ///<   (Mejora II): crear proceso hijo + copiar R1..R[N] del padre
    ///<   al child (calling convention CALLVM).  Devuelve PID encoded
    ///<   en %dst.  Usa parallel-move correcto del regalloc para evitar
    ///<   conflictos al colocar args en sus regs destino.
    HLT = 0xF8, ///< hlt                            (terminar proceso virtual)
    GETPID = 0xF9, ///< %dst = getpid                  (PID encoded del proceso
                   ///< actual)
    GETARGC =
        0xFA, ///< %dst = getargc                 (numero de args del programa)
    GETARG =
        0xFB, ///< %dst = getarg %idx             (StringObject del arg [i])
    SPAWN_ON =
        0xFC,     ///< %dst = spawnon %fn_ptr, %hint  (spawn con scheduler hint)
    PANIC = 0xFD, ///< panic %msg_addr, %msg_len      (FatalError USER_ABORT)

    // ---- codigo ensamblador incrustado ----
    ASM_MICRO =
        0xEF, ///< una instruccion asm OPACA liftada (ver @ref AsmMicro):
    ///<   imm=indice en IrFunction::asm_micros.  Lleva su identidad en
    ///<   la DB (isa+form_id) de donde se consultan TODOS sus efectos.
    ///<   operands=SSA de entrada (espejo, para que liveness los vea);
    ///<   dst=primera salida.  Multi-arch; JIT/AOT la re-emiten
    ///<   verbatim, el interp NO la soporta (como INLINE_ASM).
    INLINE_ASM = 0xFE, ///< inline_asm host ( AS): func_name=cuerpo NASM Intel,
    ///<   imm=bitfield de calificadores (bit0 volatile, bit1 nomem,
    ///<   bit2 preserves_flags, bit3 pure, bit4 clobbers_memory,
    ///<   bit5 clobbers_flags).  Distinto de RAW_ASM (asm de la VM):
    ///<   este es asm de la CPU host, lo materializan port-C / JIT /
    ///<   AOT.  El backend bytecode/interp NO lo soporta.
    RAW_ASM = 0xFF, ///< raw_asm "texto"  (ensamblador .vel verbatim; nunca
                    ///< optimizado)
};

/**
 * @brief Convierte un IrOp a su nombre en el formato de texto.
 * @param op Operacion a convertir.
 * @return Nombre de texto del opcode.
 */
const char *ir_op_name(IrOp op);

/**
 * @brief Parsea el nombre de un opcode del formato de texto.
 * @param name Nombre del opcode (p.ej. "add", "calln", "monenter").
 * @param out  Opcode parseado.
 * @return true si el nombre es valido.
 */
bool ir_op_parse(const char *name, IrOp &out);

// =========================================================================
//  Valores SSA
// =========================================================================

/**
 * @brief Identificador unico de un valor SSA.
 *
 * Un IrValueId es un indice en el pool de valores de la funcion.
 * El valor 0xFFFFFFFF indica "sin valor" (instrucciones void).
 */
using IrValueId = uint32_t;
static constexpr IrValueId IR_NO_VALUE = 0xFFFFFFFFu;

/**
 * @brief Identificador de un bloque basico.
 */
using IrBlockId = uint32_t;
static constexpr IrBlockId IR_NO_BLOCK = 0xFFFFFFFFu;

/// El valor no vive en ningun registro fisico (murio o se derramo).
static constexpr uint8_t IR_NO_REG = 0xFFu;

/// La instruccion se escribio en la funcion donde esta, no vino de otra.
static constexpr uint32_t IR_NO_INLINE_SITE = 0xFFFFFFFFu;

/**
 * @struct InlineSite
 * @brief Un trozo de funcion que se metio dentro de otra al inlinar.
 *
 * Guarda lo que hace falta para volver a contar la llamada que se aplano: de
 * que funcion vino el codigo y desde donde se la llamaba.  @c parent encadena
 * los inlinados anidados (A inlino a B, que ya tenia dentro a C), asi que una
 * instruccion referencia UN sitio y la cadena entera se recorre desde el.
 */
struct InlineSite {
    std::string callee;  ///< Funcion de la que vino el codigo.
    uint32_t line = 0;   ///< Linea de la llamada, en quien inlino.
    uint32_t column = 0; ///< Columna de la llamada.
    /// Sitio de fuera si la propia llamada tambien venia inlinada.
    uint32_t parent = IR_NO_INLINE_SITE;
};

/**
 * @brief Descriptor de un valor SSA.
 *
 * Cada %nombre en el texto corresponde a un IrValue con un id unico.
 * Los parametros de funcion son valores especiales con is_param=true.
 */
struct IrValue {
    IrValueId id =
        IR_NO_VALUE; ///< identificador unico (indice en IrFunction::values)
    IrType type = IrType::I64; ///< tipo del valor
    std::string name;          ///< nombre legible ("%0", "%result", "%a", ...)
    bool is_param = false;     ///< true si es un parametro de funcion
    bool is_const = false;     ///< true si es una constante literal
    /// Registro fisico donde el asignador dejo el valor, o @c IR_NO_REG si no
    /// vive en uno (murio, o se derramo a la pila).  Lo estampa quien orquesta
    /// la compilacion a partir de @c EmitResult::value_regs, porque hasta
    /// entonces esta informacion se tiraba: al explicar un fallo salia `%8`
    /// por un lado y `r1=0x2a` por otro sin decir que son lo mismo.
    uint8_t reg = 0xFFu;
    /// true si el valor (debe ser PTR) apunta a memoria HOST (e.g. retorno
    /// de @c rawalloc).  Los LOAD/STORE consultan este bit para decidir
    /// entre @c mov [rp] (s=0, memoria VM) y @c movh [rp] (s=1, memoria
    /// host).  La aritmetica de punteros y subscript propagan el bit
    /// desde el operando base.
    bool is_host_ptr = false;
    /// Limitacion A (cerrada): true si el valor es un PTR a memoria VM
    /// (tipicamente la direccion de un slot ALLOCA en el stack del
    /// proceso) cuyo CONTENIDO es a su vez un host_ptr.  Lo setea el
    /// lowering en (a) @c write_local cuando se escribe un valor con
    /// @c is_host_ptr=true a un local address-taken, y (b) en @c &x
    /// cuando @c x es local host-bearing (caso indirecto via address-of).
    /// El emisor IR (case LOAD en @c ir_emitter.cpp) lo consulta para
    /// propagar @c is_host_ptr=true al SSA value resultante del LOAD,
    /// manteniendo la cadena de host_ptr a traves del round-trip
    /// @c i32** pp = &p; **pp = v.  Solo cubre 1 nivel de indireccion;
    /// patrones con mas niveles (e.g. @c &pp) caen al modelo legacy.
    bool pointee_is_host_ptr = false;
    /// true si el valor es un host_ptr a un objeto GESTIONADO por el GC
    /// (instancia de clase Vesta tipicamente).  El emisor IR usa este flag
    /// para que cualquier @c push/@c pop alrededor de un CALL que pueda
    /// disparar GC se haga sobre el GcHandle (estable a traves de la
    /// evacuacion), no sobre el host_ptr crudo (que el collector
    /// generacional puede mover durante un minor o major GC, dejando
    /// el reg salvado apuntando a memoria liberada).
    ///
    /// Patron emitido al spillar:
    /// @code
    ///   gchandle reg, reg     // host_ptr -> GcHandle
    ///   push reg
    ///   ... call ...
    ///   pop reg
    ///   gcderef cur0, reg     // GcHandle -> host_ptr (refrescado tras GC)
    ///   xchg cur0, reg
    /// @endcode
    ///
    /// Coste: 4 instrucciones extra por spill, solo cuando aplica.
    /// Sin esto, ctors que invocan otra alocacion intermedia (e.g.
    /// @c this.field = new Inner(x)) ven @c this como host_ptr stale
    /// tras un minor GC -> escritura en memoria liberada -> segfault.
    bool is_gc_object = false;
    /// Optimizacion: si true, el resultado de un LOAD i8/i16/i32 NO necesita
    /// sign-extension manual porque todos sus usos transitivos son operaciones
    /// que preservan correctamente los bits bajos (ADD/SUB/MUL/AND/OR/XOR) y
    /// terminan en STORE/RET del mismo ancho.  Lo marca @c ir_pass_load_narrow.
    /// El emisor IR (case LOAD) consulta el flag para saltar el patron
    /// @c shl/sar de 64-N bits, ahorrando 3 instrucciones VM por LOAD.
    /// Bench struct_field: ~9 instr/iter menos = 270M instr ahorradas en 30M
    /// iter del loop principal.
    bool narrow_only = false;
    uint64_t const_val = 0; ///< valor si is_const == true
};

// =========================================================================
//  Instrucciones SSA
// =========================================================================

/**
 * @brief Par (valor, bloque) para los argumentos de una instruccion Phi.
 */
struct IrPhiArg {
    IrValueId value; ///< valor que llega desde el bloque predecesor
    IrBlockId block; ///< bloque predecesor
};

/**
 * @brief Una instruccion SSA.
 *
 * Representacion plana: todos los campos de todas las instrucciones posibles.
 * La seleccion de campos activos depende de IrOp:
 *
 *   CONST:         dst, type, imm
 *   ADD..SAR:      dst, type, operands[0], operands[1]
 *   NEG/NOT/FNEG/FABS/FSQRT: dst, type, operands[0]
 *   CMP_*:         dst, type=BOOL, operands[0], operands[1]
 *   FCMP_*:        dst, type=BOOL, operands[0], operands[1]
 *   CAST/ZEXT/SEXT/TRUNC/ITOF/UITOF/FTOI/FTOUI/F32TOF64/F64TOF32/BITCAST:
 *                  dst, type, operands[0]
 *   BR:            target_block
 *   BR_COND:       operands[0]=cond, target_block=true_bb, false_block
 *   RET:           operands[0] si no es void
 *   PHI:           dst, type, phi_args[]
 *   CALL/TAILCALL: dst, func_name, operands[]
 *   CALLIND:       dst, func_ptr, operands[]
 *   CALLVIRT:      dst, operands[0]=obj, imm=vtbl_idx, operands[1..]=args
 *   CALLITF:       dst, operands[0]=obj, operands[1]=params_ptr,
 * operands[2..]=args, func_name="Iface\x1fmetodo", imm=(count<<32)|method_index
 *   CALLN:         dst, func_name (formato "lib:func"), operands[]
 *   ALLOCA:        dst, type, imm=count
 *   LOAD:          dst, type, operands[0]=ptr
 *   STORE:         operands[0]=val, operands[1]=ptr
 *   MEMCPY:        operands[0]=dst_ptr, operands[1]=src_ptr, operands[2]=len
 *   NEWOBJ:        dst, operands[0]=class_ptr
 *   GETFIELD:      dst, type, operands[0]=obj, imm=field_idx
 *   SETFIELD:      operands[0]=obj, imm=field_idx, operands[1]=val
 *   INSTANCEOF/CHECKCAST: dst, operands[0]=obj, operands[1]=class_ptr
 *   ISNULL/UNWRAP: dst, operands[0]=src
 *   SPECIALIZE:    dst, operands[0]=class_ptr, operands[1]=types_arr, imm=count
 *   GEP:           dst(marker), operands[0]=handle, imm=byte_offset (cur0
 * apunta al campo) GCWB_IR:       operands[0]=handle ARRAY_ALLOC:   dst,
 * type=elem_type, operands[0]=len ARRAY_LEN:     dst, operands[0]=arr_vm_addr
 *   ARRAY_LOAD:    dst, type=elem_type, operands[0]=arr_vm_addr,
 * operands[1]=idx ARRAY_STORE:   type=elem_type, operands[0]=arr_vm_addr,
 * operands[1]=idx, operands[2]=val GCDEREF_IR:    operands[0]=handle (gcderef a
 * cur0; usar solo seguido de readcur/writecur) STRMAKE:       dst,
 * operands[0]=buf_vm_addr, operands[1]=len, imm=enc STRLEN:        dst,
 * operands[0]=str_handle STRCAT:        dst, operands[0]=a_handle,
 * operands[1]=b_handle STRCMP:        dst, operands[0]=a, operands[1]=b
 *   STRSLICE:      dst, operands[0]=str, operands[1]=range
 *   STRFLAT:       dst, operands[0]=str
 *   STRHASH:       dst, operands[0]=str
 *   STRINTERN:     dst, operands[0]=str
 *   STRRAW:        dst, operands[0]=str
 *   STRCONV:       dst, operands[0]=str, imm=enc
 *   STRRESERVE:    dst, operands[0]=cap_bytes
 *   STRFINALIZE:   operands[0]=str, operands[1]=new_len
 *   THROW:         operands[0]=exc_obj
 *   TRYENTER:      operands[0]=handler_pc, operands[1]=class_ptr
 *   TRYLEAVE:      (sin operandos)
 *   LANDINGPAD:    dst, type
 *   FUTURE:        dst
 *   AWAIT:         dst, type, operands[0]=future_handle
 *   FULFILL:       operands[0]=future_handle, operands[1]=value
 *   REJECT:        operands[0]=future_handle, operands[1]=error_code
 *   MSGSEND:       dst, operands[0]=pid, operands[1]=buf_addr, operands[2]=len
 *   MSGRECV:       dst, type, operands[0]=max_len, operands[1]=buf_addr
 *   RSPAWN:        dst, operands[0]=node_idx, operands[1]=fn_addr
 *   MONENTER/MONEXIT/MONWAIT/MONNOTI/MONNOTA: operands[0]=obj
 *   GETPROC/GETVM/GETMGR: dst
 *   SPAWN:         dst, operands[0]=fn_ptr
 *   RESUME:        operands[0]=pid
 *   SWAPCTX:       operands[0]=dst_ctx, operands[1]=src_ctx
 *   RAW_ASM:       func_name=texto_ensamblador (sin dst, sin operandos, nunca
 * optimizado)
 */
struct IrInstr {
    IrOp op;       ///< operacion
    IrType type;   ///< tipo del resultado (VOID si sin resultado)
    IrValueId dst; ///< registro destino (IR_NO_VALUE si sin resultado)

    std::vector<IrValueId> operands; ///< operandos de la instruccion

    uint64_t imm; ///< literal para CONST, ALLOCA, GETFIELD, SETFIELD, CALLVIRT

    std::string func_name; ///< para CALL/CALLN/TAILCALL: nombre de la funcion
    IrValueId
        func_ptr; ///< para CALLIND: id del valor con el puntero de funcion

    /// ABI custom del CALLIND: registro fisico por argumento, tomado del TIPO
    /// del puntero (cfn con abi_regs).  Vacio = ABI estandar.  Necesario porque
    /// un CALLIND no tiene nombre resoluble -> la ABI no puede buscarse por
    /// IrFunction; viaja aqui, fijada en compile-time desde el tipo (aunque el
    /// valor del puntero cambie en runtime).  Para CALL directo NO se usa (el
    /// codegen resuelve la ABI por nombre via IrFunction::param_abi_regs).
    /// Se serializa (cross-module).
    std::vector<std::string> call_abi_regs;

    IrBlockId target_block; ///< destino de BR o rama true de BR_COND
    IrBlockId false_block;  ///< rama false de BR_COND

    std::vector<IrPhiArg> phi_args; ///< para PHI

    /// Tabla de bloques destino para SWITCH_DENSE (jump table denso O(1)):
    /// jump_targets[idx] = bloque del valor (imm_min + idx); idx fuera de
    /// rango -> target_block (default).  Vacio para el resto de ops.  El
    /// backend JIT (vreg) lo baja a un island nativo (computed-goto); el
    /// interp usa el BST que el frontend emite junto al marker.
    std::vector<uint32_t> jump_targets;

    uint32_t
        source_line; ///< numero de linea del fuente original (0 = desconocido)
    /// Columna del fuente (0 = desconocida).  Con la linea sola no se puede
    /// senalar cual de las cosas que caben en ella fallo.
    uint32_t source_column;

    /// De donde vino esta instruccion si NO se escribio aqui: indice en
    /// @c IrFunction::inline_sites, o @c IR_NO_INLINE_SITE si es de la propia
    /// funcion.  Al inlinar, el codigo del llamado pasa a vivir dentro del que
    /// llama pero conserva las lineas de SU fuente, con lo que la traza
    /// atribuia a `main` una linea que es de otro sitio -- no perdia marcos,
    /// mentia.  Con esto se pueden reconstruir los que se aplanaron.
    uint32_t inline_site = IR_NO_INLINE_SITE;

    /// Longitud en caracteres del trozo de fuente que produjo la instruccion
    /// (0 = desconocida).  Con la columna sola se sabe donde empieza pero no
    /// donde acaba, y sin eso no se puede recortar el texto para NOMBRAR un
    /// operando: decir "el divisor es this.valor" en vez de "%2".
    uint32_t source_len = 0;

    /// Si true, esta instruccion NO debe ser eliminada por copy_prop
    /// ni DCE.  Util para barreras de codegen como los MOVs que el
    /// lower_for/lower_while inserta antes del back-edge para
    /// proteger los SSA values de loop-carry contra el "live hole"
    /// del linear scan (ver lower_for / lower_while).
    bool preserve = false;

    /// @Naked: si true en un IrOp::RET, este RET es el SINTETICO de
    /// caida-al-final (fallthrough) que el lowering inserta cuando la funcion
    /// no termina en un `return` explicito -- NO proviene de un `return` del
    /// usuario.  El codegen nativo lo usa para @Naked: una funcion @Naked NO
    /// emite el `ret` implicito (para no pisar el `iretq`/`ret` que el propio
    /// asm provee en un ISR o bootloader), pero SI materializa un `return`
    /// explicito (read-back + `ret`, sin epilogo de frame).  Mirar solo si el
    /// RET porta operando NO basta: el implicito de una fn con retorno no-void
    /// lleva un `0` sintetico.  Se serializa (el AOT consume el @ir del
    /// .velb/.vxir).
    bool ret_implicit = false;

    /// @fp(strict) bajo inlining: cuando el inliner copia el cuerpo de un
    /// callee STRICT (fp_contract=false) dentro de un caller FAST, marca las
    /// ops float copiadas con este flag para que @c ir_pass_fuse_fma NO las
    /// contraiga a FMA (preservar la semantica IEEE de 2 redondeos del callee).
    /// Marcador TRANSITORIO de compile-time (el fuse corre en O2 ANTES de
    /// serializar el
    /// @ir post-opt) -> NO se serializa; el JIT/AOT consumen el IR ya
    /// fusionado.
    bool no_fp_contract = false;

    /// AOT: STR_LIT_ADDR sobre la plantilla de un `thread_local` (TLS).  Solo
    /// en memoria (NO serializado): el driver AOT lo DERIVA tras parsear,
    /// consultando SD_FLAG_TLS de la entrada static_data @c imm.  El codegen
    /// emite el acceso por thread pointer (fs/gs + TPOFF) en vez de lineal.
    bool is_tls = false;

    /// Si true para una RAW_ASM, el emitter envuelve el bloque con
    /// emit_save_live_regs / emit_restore_live_regs.  Necesario cuando
    /// el RAW_ASM internamente dispara una llamada que clobreara los
    /// registros caller-saved (e.g. `loadmod`, que ejecuta el main del
    /// plugin antes de retornar).  Sin esto, el regalloc no sabe que
    /// el RAW_ASM es un "call site" y los locales vivos quedan
    /// invalidados cuando la callee corre.
    ///
    /// SOLO se lee para RAW_ASM, y no es un descuido: en un CALL, un CALLN o
    /// un SPAWN el asignador YA sabe que hay una llamada -- se lo dice el
    /// propio opcode -- y preserva lo que esta vivo por su cuenta.  Este campo
    /// existe justamente para el caso en que eso no se ve: un bloque de
    /// ensamblador no parece una llamada y por dentro lo es.
    ///
    /// Hay codigo que lo pone en instrucciones que no son RAW_ASM.  Ahi no
    /// hace nada -- ni bien ni mal --, pero induce a pensar que si, y a
    /// copiarlo "por si acaso".  No hace falta.
    bool is_call_site = false;

    ///  D.jit-mem-model AUTO-PROMOTE: si true en un IrOp::ALLOCA,
    /// el JIT emite ese ALLOCA en host stack (en lugar de VM-stack).
    /// El ptr resultante es directamente dereferenciable por code C
    /// nativo (e.g. para `&local` pasado a Win API).  Lo marca el IR
    /// pass `ir_pass_promote_callned_allocas` cuando el dst del ALLOCA
    /// fluye a un arg de CALLN.  El bytecode emit del interp lo
    /// IGNORA (sigue emitiendo `subsp` VM-stack) -- en interp, el
    /// patron `&local -> CALLN` requiere JIT activo o malloc explicito.
    bool host_alloca = false;

    /// Sprint mem-loop-fix (2026-06-02): si true en un ALLOCA con
    /// `host_alloca=true`, indica que el RAW_FREE original SE
    /// PRESERVO en el IR (no fue eliminado por el promote pass).
    /// El bytecode emit del interp NO debe llamar @c htrack para
    /// no acumular en el vector @c host_allocas del frame -- el
    /// RAW_FREE preservado libera explicitamente el ptr en su
    /// posicion correcta (al fin de cada iteracion, no al RET).
    /// Resuelve el bottleneck del bench @c mem_malloc_free donde
    /// 5M iter acumulaban 5M ptrs tracked sin liberar.
    bool host_alloca_explicit_free = false;

    IrInstr()
        : op(IrOp::NOP), type(IrType::VOID), dst(IR_NO_VALUE), imm(0),
          func_ptr(IR_NO_VALUE), target_block(IR_NO_BLOCK),
          false_block(IR_NO_BLOCK), source_line(0), source_column(0) {}
};

// =========================================================================
//  Bloque basico
// =========================================================================

/**
 * @brief @c true si @p op cierra un bloque: detras de ella no va nada.
 *
 * Son de dos clases y conviene no confundirlas.  Unas dicen A DONDE se sigue
 * -- saltar, saltar segun una condicion, volver de la funcion --; las otras
 * dicen que NO se sigue: reventar con un mensaje, relanzar la excepcion que
 * venia, resolver la promesa y acabar el proceso, parar.  Para el grafo las
 * segundas son bloques SIN salidas, que es distinto de un bloque al que le
 * falta el final.
 *
 * Existe porque la lista estaba escrita en dos sitios que no coincidian: el
 * verificador solo conocia las primeras (mas @c THROW) y daba por incompleto
 * todo bloque que acabara en un `panic` o en un `hlt` -- veintiocho ejemplos
 * de los que ninguno tenia nada malo --.  Un verificador que grita sin motivo
 * es peor que no tenerlo: nadie lo mira.
 */
inline bool ir_op_ends_block(IrOp op) noexcept {
    switch (op) {
    // Dicen a donde se sigue.
    case IrOp::BR:
    case IrOp::BR_COND:
    case IrOp::RET:
    case IrOp::TAILCALL:
    // Dicen que no se sigue.
    case IrOp::UNREACHABLE:
    case IrOp::THROW:
    case IrOp::RETHROW:
    case IrOp::PANIC:
    case IrOp::HLT:
    case IrOp::FULFILL_HLT:
    case IrOp::RSPAWN_RETURN: return true;
    default: return false;
    }
}

/**
 * @brief Bloque basico de la CFG (Control Flow Graph).
 *
 * Un bloque basico es una secuencia lineal de instrucciones con una
 * sola entrada y una sola salida.  La ultima instruccion es siempre
 * un terminador (@ref ir_op_ends_block).
 */
struct IrBlock {
    IrBlockId id;     ///< identificador unico (indice en IrFunction::blocks)
    std::string name; ///< nombre legible ("entry", "loop_body", ...)
    std::vector<IrInstr> instrs; ///< instrucciones en orden
    std::vector<IrBlockId>
        preds; ///< bloques predecesores (para consistencia de Phi)
    std::vector<IrBlockId> succs; ///< bloques sucesores
    /// Marcador transitorio (no serializado): el unroller lo pone en el header
    /// del REMAINDER y del bucle unrollado para no re-desenrollarlos.
    bool no_unroll = false;
};

// =========================================================================
//  Funcion SSA
// =========================================================================

/**
 * @brief Candidato de devirtualizacion especulativa (TAREA 2 / C2).
 *
 * Describe uno de los <=K tipos concretos que el pase
 * @c ir_pass_spec_devirt convierte en una rama del guard-chain que
 * reemplaza un dispatch dinamico (CALLITF/CALLVIRT/CALLM):
 *
 *     cls = load[obj]
 *     if (cls == cls_value) r = call callee_ir_name(obj, args...)  // fast
 *     ... (mas candidatos) ...
 *     else                  r = <dispatch original>                // fallback
 *
 * El lowering (que conoce los implementors via el type checker) crea
 * un candidato por implementor inlineable y lo registra en
 * @c IrFunction::spec_devirt_sites, keyed por el @c dst del call.  El
 * @c cls_value es un SSA value loop-invariante definido en el entry
 * (resuelto via slot-cache lazy con @c findclass); el guard compara el
 * class_ptr del objeto contra el.
 */
struct DevirtCandidate {
    IrValueId cls_value; ///< SSA value con el ClassInfo* del tipo.
    std::string
        callee_ir_name; ///< nombre IR del metodo concreto a llamar
                        ///< directo en el fast path (e.g. "Circle__area").
};

/**
 * @brief  AS inc.3: variable Vesta con storage-class register("reg").
 *
 * El lowering fuerza estas variables a un slot ALLOCA estable (para que
 * sobrevivan al optimizer y tengan identidad) y registra aqui la
 * asociacion @c alloca_value -> registro fisico.  El backend port-C
 * (c_backend) las materializa como variables C locales con register-pin
 * de GCC (@c "register T __asmreg_N asm(\"reg\")") y traduce los
 * LOAD/STORE de ese ALLOCA a accesos directos a la variable (no puede
 * tomar la direccion de un registro en C).  El JIT (inc.5) las usara para
 * forzar el valor al registro fisico.
 */
struct AsmRegBinding {
    IrValueId alloca_value; ///< dst del ALLOCA del var register-bound
    std::string
        reg;        ///< nombre del registro RAW (eax/rax/xmm0...); vacio
                    ///< si @c reg_auto (el fisico lo elige el RA post-regalloc)
    IrType type;    ///< tipo escalar del var (para el ctype en C)
    bool is_vector; ///< true si reg es xmm/ymm/zmm (constraint "x")
    std::string name; ///< nombre Vesta de la variable (para filtrar
                      ///< por scope activo en lower_asm)
    /// operando `reg` (AUTO) de un @c asm ( ... ): el RA ELIGE el
    /// registro (constraint register-required, no un pin) y el ensamblado se
    /// aplaza a post-regalloc.  El cuerpo lo referencia por el placeholder
    /// @c $ph_index.  false = pin fijo clasico (register("rax") / `rax a`).
    bool reg_auto = false;
    int ph_index = -1; ///< indice $N del placeholder en el cuerpo (reg_auto)
    /**
     * @brief CLASE con la que se declaro el operando, tal como se escribio:
     *        @c "reg" / @c "xmm" / @c "ymm" / @c "zmm" (el compilador elige el
     *        registro) o el nombre del registro concreto (@c "rax", @c "eax").
     *
     * Es lo que dice cuanto MIDE el operando, y hace falta porque el cuerpo ya
     * no lo dice: tras la sustitucion, `movdqa [$0], $1` no permite a nadie
     * saber que `$1` es un registro de 128 bits.  Y ese ancho es lo que decide
     * dos cosas distintas -- cuanta memoria toca el acceso y cuanta alineacion
     * EXIGE la instruccion --, asi que sin el la comprobacion no se puede
     * hacer y un programa que revienta pasa el compilador.
     *
     * Es el dato PRIMARIO, no @ref reg: ese registro es el que se eligio a la
     * primera para que el interprete pueda sustituir algo, y el dia que lo
     * decida el asignador deja de haberlo.  La clase la escribio el
     * programador y no cambia.
     */
    std::string reg_class;
};

/**
 * @brief Flags de ROL de un operando @c ASM_MICRO (bitmask, NO exclusivos).
 *
 * Reflejan EXACTAMENTE los flags de la base de datos (@c DbOperand.flags:
 * bit0 read, bit1 write, bit2 implicit, bit3 suppressed) mas @c CLOBBER para la
 * destruccion sin valor observable.  Un operando @c RW es @c READ|WRITE (p.ej.
 * @c EAX de @c cpuid); un implicito @c RW es @c READ|WRITE|IMPLICIT (p.ej.
 * @c RAX de @c mul).
 */
enum AsmOperandFlag : uint8_t {
    ASM_OP_READ = 1u << 0,  ///< el operando se LEE
    ASM_OP_WRITE = 1u << 1, ///< el operando se ESCRIBE
    ASM_OP_IMPLICIT =
        1u << 2, ///< implicito (no aparece en la sintaxis textual)
    ASM_OP_SUPPRESSED = 1u << 3, ///< leido/escrito pero fuera del encoding
    ASM_OP_CLOBBER = 1u << 4,    ///< destruido sin valor observable
};

/**
 * @brief TIPO de un operando @c ASM_MICRO.  La memoria NO es una clase de
 *        registro: es un tipo de operando propio con su base/index.
 */
enum class AsmOperandKind : uint8_t {
    REG = 0, ///< registro (clase en @c regclass, fisico en @c fixed_phys)
    MEM =
        1, ///< memoria (base/index en @c value; @c regclass del registro base)
    IMM = 2, ///< inmediato (valor en @c imm)
};

/**
 * @brief Un operando de una instruccion @c ASM_MICRO (asm opaca liftada).
 *
 * Modelo de LISTA PLANA en ORDEN TEXTUAL (como LLVM MC / GCC RTL / uops.info):
 * la instruccion tiene UNA lista de operandos, y cada uno lleva su rol como
 * @c flags (no dos listas ins/outs).  @c $0,$1,... de @c AsmMicro::tmpl
 * referencian esta lista por indice.
 *
 * @c regclass es ARCH-NEUTRA (misma para x86, arm64, riscv): el ancho y la
 * sintaxis concreta los da la forma de la base de datos (@ref
 * AsmMicro::form_id).
 * @c fixed_phys fija el operando a un registro fisico REQUERIDO (p.ej. @c cpuid
 * escribe eax/ebx/ecx/edx); -1 = libre, lo elige el asignador de registros.
 */
struct AsmMicroOperand {
    AsmOperandKind kind = AsmOperandKind::REG; ///< REG / MEM / IMM
    uint8_t flags = 0; ///< @ref AsmOperandFlag (READ|WRITE|IMPLICIT|...)
    uint8_t regclass =
        0; ///< clase del REG / base de MEM: 0=GP 1=FP 2=VEC 3=PRED 4=FLAGS
    uint16_t width =
        0; ///< ancho en BITS del operando (de la forma DB); nombra el reg
    int16_t fixed_phys = -1; ///< reg fisico fijo (-1 = libre, lo asigna el RA)
    IrValueId value =
        0;           ///< SSA leido/definido (REG/MEM base); IR_NO_VALUE si no
    int64_t imm = 0; ///< inmediato (solo @c kind==IMM)

    bool reads() const { return (flags & ASM_OP_READ) != 0; }
    bool writes() const { return (flags & ASM_OP_WRITE) != 0; }
};

/**
 * @brief Una instruccion de asm OPACA liftada a IR (@ref IrOp::ASM_MICRO).
 *
 * El lifter general convierte el subconjunto COMPUTACIONAL del asm a ops IR
 * tipadas (ADD, LOAD...); todo lo demas (SIMD, cpuid, mfence, syscall...) se
 * modela como una @c ASM_MICRO: una unica instruccion asm que LLEVA su
 * identidad en la base de datos (@c isa + @c form_id) de donde se CONSULTAN
 * todos los efectos (lee/escribe/flags/mem/barrera/latencia/puertos) sin
 * duplicarlos.  El bloque asm entero pasa a ser IR: el optimizador reordena/
 * elimina/programa alrededor con precision, y el backend (JIT/AOT) la re-emite
 * verbatim rellenando la plantilla con los registros que asigno el regalloc.
 *
 * Es MULTI-ARCH: @c isa identifica la ISA (misma codificacion que
 * @c instr_db::Isa) y @c form_id es el indice de la forma en la base de datos
 * de ESA ISA.  El interprete NO ejecuta @c ASM_MICRO (no se emula cpuid): solo
 * lo materializan JIT/AOT (nativos); lo liftado a ops tipadas SI corre en
 * interp.
 */
struct AsmMicro {
    uint8_t isa =
        0; ///< ISA (== instr_db::Isa: 0=x86_64,1=x86,2=x86_16,3=arm64,...)
    uint32_t form_id =
        0; ///< indice de la forma en la DB de @c isa (efectos/timing)
    std::string
        tmpl; ///< plantilla NASM con placeholders $0,$1,... por operando
    std::vector<AsmMicroOperand>
        operands; ///< lista PLANA en ORDEN TEXTUAL (roles en flags)
    uint8_t eff =
        0; ///< cache: bit0 mem, bit1 flags_r, bit2 flags_w, bit3 barrera,
           ///<   bit4 call (la DB es la verdad; esto es solo un atajo)
};

/**
 * @brief Funcion completa en forma SSA.
 *
 * Contiene el grafo de bloques basicos y el pool de valores.
 * El primer bloque (id=0) es siempre el bloque de entrada "entry".
 */
struct IrFunction {
    std::string name; ///< nombre calificado ("com.pkg.Foo.add")
    /**
     * @brief Cuantas veces se ha MODIFICADO esta funcion.
     *
     * No describe la funcion: identifica su ESTADO.  Un analisis cacheado se
     * sella con el valor que tenia al calcularse, y pedirlo con otro distinto
     * lo recalcula.  Asi un resultado viejo no se puede entregar aunque nadie
     * se haya acordado de invalidarlo.
     *
     * Hace falta porque los hechos guardan PUNTEROS a instrucciones: usarlos
     * despues de mutar la funcion no es dar una respuesta imprecisa, es leer
     * memoria liberada.  Lo avanza quien aplica un pase que dice haber
     * cambiado algo -- un solo sitio, no cada mutacion.
     */
    uint64_t version = 0;
    IrType ret_type = IrType::VOID; ///< tipo de retorno
    std::vector<IrValueId> params;  ///< IDs de los valores parametro
    /// ABI custom por funcion: registro fisico de entrada por parametro,
    /// indexado igual que @c params.  Cadena vacia = ABI estandar del target
    /// (i-esimo arg-reg SysV/Win64).  "rax".."r15".  Lo llena el lowering desde
    /// @c ParamDecl::abi_reg; lo consumen el codegen del CALLEE (el param llega
    /// en ese registro, sin el load estandar) y del CALLER (coloca el arg ahi).
    /// Se serializa (cross-module via .vxir/.velb @ir) y viaja en el .vxi.
    /// Vacio TAMBIEN cuando NINGUN param tiene ABI custom (caso comun -> no
    /// ocupa espacio en el 99% de funciones).
    std::vector<std::string> param_abi_regs;
    std::vector<IrValue> values; ///< pool de todos los valores SSA
    std::vector<IrBlock> blocks; ///< bloques basicos (bloques[0] = entry)
    /// Llamadas que se aplanaron aqui al inlinar.  Las instrucciones apuntan a
    /// una entrada por indice (@c IrInstr::inline_site); vacio si no se inlino
    /// nada, que es lo comun.
    std::vector<InlineSite> inline_sites;
    bool is_native = false;   ///< true si es stub para funcion nativa
    bool is_variadic = false; ///< true si acepta argc variable
    /**
     * @brief Alcanzable desde FUERA del modulo (lo que el fuente declara como
     *        publico; sin palabra clave, en Vesta lo es).
     *
     * Decide hasta donde llega lo que se puede afirmar de ella.  Un resumen
     * interprocedural -- de que valores recibe un parametro, que rango tienen,
     * como estan alineados -- junta lo que aportan los sitios de llamada QUE SE
     * VEN, y eso solo vale si no hay otros.  Con una funcion privada, el modulo
     * los tiene todos; con una publica, cualquiera puede llamarla desde otro
     * lado y "no he visto llamadas" deja de significar "no las hay".
     *
     * Sin este dato la unica salida era suponer, y la suposicion se rompe justo
     * donde mas duele: al compilar por modulos con cache, el mismo fichero
     * daria una respuesta u otra segun se recompilara solo o junto al programa.
     */
    bool is_public = true;

    /**
     * @brief Contract de monomorphizacion: provenance de
     *        funciones generadas a partir de una clase / funcion
     *        generica.
     *
     * Para una funcion que es una instanciacion concreta de un
     * template generico, estos campos identifican:
     *   - @c generic_template_name: nombre del template original
     *     (e.g., "Box", "List", "Pair").  Vacio si NO es una
     *     monomorphizacion (funcion normal o template raw).
     *   - @c generic_type_args: nombres legibles de los tipos
     *     concretos sustituidos (e.g., ["i32"], ["i64", "string"]).
     *     Paralelo a los @c type_params del template original.
     *
     * Usado por:
     *   - C2 JIT: identifica especializaciones para
     *     dedup/sharing across modules.
     *   - AOT cache: invalidar selectivamente solo
     *     las instanciaciones afectadas cuando el template cambia,
     *     en vez de recompilar todo.
     *   - Tools (debuggers, profilers): mostrar el nombre legible
     *     del template + tipos en stack traces ("Box<i32>" en vez
     *     de "Box_i32").
     *   - PGO: agrupar metricas de instanciaciones del mismo
     *     template para decisiones de inlining cross-instantiation.
     *
     * Para funciones que NO son instanciaciones, ambos campos
     * quedan vacios.  En  A esto es metadata pura (no afecta
     * compilacion); en  D+ los pases del JIT/AOT lo consumen.
     *
     * El printer del IR emite @c "@template_of <Name>" y
     * @c "@type_args [t1, t2, ...]" como anotaciones de la
     * funcion; el parser las acepta para round-trip.
     */
    std::string generic_template_name; ///< vacio si no es monomorphizacion
    std::vector<std::string>
        generic_type_args; ///< concretos sustituidos (paralelo a type_params)

    /**
     * @brief  MC.1: marca esta IrFunction como derivada del
     * body de un `@Macro`.  El nombre suele ser `__macro_<original>`.
     * El TypeChecker mantiene un mapa name -> IrFunction* para
     * recuperarla al ejecutar el macro via la ComptimeVM ( MC.2+).
     *
     * NO afecta el codegen ni la ejecucion runtime: estas funciones
     * NO son linkeadas desde call sites de codigo runtime; solo
     * existen como bytecode invocable desde el TypeChecker durante
     * compile-time evaluation.
     *
     * @c false para todas las IrFunctions regulares.
     */
    bool is_macro_compiled = false;

    /**
     * @brief Politica de coma flotante de la funcion (@c \@fp).  Si true
     * (default = fast), el pase @c fuse_fma puede contraer @c fmul+fadd en un
     * @c FMA (round(a*b+c), 1 redondeo).  @c \@fp(strict) lo pone false ->
     * semantica IEEE estricta (2 redondeos, sin contraccion).  Selectivo por
     * funcion; el global @c -ffp-contract=off lo fuerza a false en todas.
     */
    bool fp_contract = true;

    /**
     * @brief TAREA 2 (C2): sitios de devirtualizacion especulativa.
     *
     * Mapa keyed por el @c dst (SSA, unico y estable) de un call
     * dinamico (CALLITF/CALLVIRT/CALLM) -> lista de candidatos de tipo
     * a especular (<=K).  Lo rellena el lowering (que conoce los
     * implementors via el type checker) y lo CONSUME el pase
     * @c ir_pass_spec_devirt durante @c ir_optimize (@O2), que
     * reescribe el call en un guard-chain + fallback.
     *
     * Es metadata EFIMERA del pase: se consume antes de serializar la
     * seccion @c @ir del .velb, por lo que NO se serializa.  Mapa
     * lateral (en vez de un campo en cada @c IrInstr) para no engordar
     * la estructura caliente: solo los pocos call sites especulables
     * tienen entrada.
     */
    std::unordered_map<IrValueId, std::vector<DevirtCandidate>>
        spec_devirt_sites;

    /**
     * @brief  AS inc.2: storage-class @c register("reg") de
     *        var-decls dentro de esta funcion.
     *
     * Mapea el nombre de la variable Vesta -> nombre del registro fisico
     * solicitado (tal cual lo escribio el usuario: eax/rax/xmm0/...).  El
     * backend port-C (inc.3) lo materializa como
     * @c "register T x __asm__(\"rax\")"; el JIT (inc.5) lo usa para
     * forzar el SSA value al registro fisico y excluirlo del pool.
     *
     * Tabla lateral por @c alloca_value (en vez de un campo en cada
     * IrInstr) para no engordar la estructura caliente: solo las funciones
     * con inline asm + register() tienen entradas.  Vacio en el resto.
     */
    std::vector<AsmRegBinding> asm_reg_bindings;

    /**
     * @brief Prestamos vivos en esta funcion, como HECHOS del IR.
     *
     * Un `borrow<T>` / `borrow_mut<T>` no deja rastro en el IR: `lend` no emite
     * instruccion, devuelve el mismo puntero.  Asi que lo que el borrow checker
     * demuestra -- y en particular que un prestamo MUTABLE es EXCLUSIVO -- se
     * queda hoy dentro del type checker y no cruza al analisis, que es justo lo
     * que impide componerlo con regiones, rangos y efectos.
     *
     * Esta tabla lateral (misma forma que @c asm_reg_bindings: vacia en las
     * funciones que no prestan) lo hace cruzar.  Lleva la PROCEDENCIA --
     * fichero y linea del `lend`, y el nombre que el usuario escribio -- porque
     * un veredicto sin su origen no se puede explicar: al bajar la comprobacion
     * al IR se pierden los nombres, y el diagnostico no debe perderse con
     * ellos.
     */
    /**
     * @brief De que NATURALEZA es lo que se presto.
     *
     * No se mezclan: cada una tiene su regimen y su grado de libertad.  Un
     * `borrow` esta sujeto a las reglas del borrow checker; un puntero crudo al
     * estilo C es LIBRE de ellas a proposito, y un `unique`/`shared` responde a
     * propiedad y movimiento, no a prestamo.  Lo que ASA aporta es que ser
     * libre no signifique quedar sin analizar: sobre los tres se razona igual
     * en regiones y lifetime -- seguridad SIN perder libertad.
     *
     * Va en el hecho para que ningun consumidor extrapole: la exclusividad de
     * un `borrow_mut` NO se puede trasladar a un puntero crudo sacado del mismo
     * objeto ni al interior de un `unique`.
     */
    enum class BorrowOwnerKind : uint8_t {
        Plain = 0, ///< Local corriente cuya direccion se tomo.
        Unique,    ///< `unique<T>`: propiedad, no prestamo.
        Shared,    ///< `shared<T>`: propiedad compartida con recuento.
        Reborrow,  ///< Otro prestamo (cadena de represtamos).
    };

    struct BorrowFact {
        IrValueId value = IR_NO_VALUE; ///< El puntero que ES el prestamo.
        IrValueId owner = IR_NO_VALUE; ///< De donde se presto (su valor SSA).
        bool mutable_ = false;         ///< `lend_mut` (exclusivo) vs `lend`.
        BorrowOwnerKind owner_kind = BorrowOwnerKind::Plain;
        uint32_t line = 0;      ///< Linea del `lend` (procedencia).
        std::string owner_name; ///< Nombre escrito por el usuario.
    };
    std::vector<BorrowFact> borrow_facts;

    /**
     * @brief  AS inc.3: listas de clobbers EXPLICITOS por bloque
     *        @c INLINE_ASM de esta funcion.
     *
     * Indexadas por el "asm-id" que el @c INLINE_ASM lleva empaquetado en
     * los bits altos de @c imm (bits 8..31; los bits 0..5 son los
     * calificadores/efectos quals).  Cada entrada es la lista de registros
     * que el usuario declaro en @c clobbers("...") (sin "memory"/"flags",
     * que viajan en @c imm bits 4/5).  La inferencia automatica (inc.4) la
     * AMPLIA; aqui solo van los explicitos.  El backend port-C los emite en
     * la clobber-list de GCC.
     */
    std::vector<std::vector<std::string>> asm_clobber_lists;

    /**
     * @brief Lo que el cuerpo de cada bloque de `asm` LEE, por el mismo asm-id.
     *
     * El gemelo de @c asm_clobber_lists.  Hacia falta porque un cuerpo puede
     * nombrar un registro DIRECTAMENTE sin declararlo como operando -- `asm
     * { div rsi }` lee rsi, y ademas RDX:RAX, que ni siquiera se escriben en
     * la linea --, y quien razone despues sobre lo que sigue vivo no tiene de
     * donde sacarlo: en los operandos no esta.
     *
     * Sin esto, una escritura que alimenta al bloque parece muerta.
     *
     * Lo llena la MISMA inferencia que los clobbers y de la misma fuente (lo
     * que la base de instrucciones dice de cada linea); antes se calculaba y
     * se tiraba.  @c asm_reads_completos dice si la lista lo cubre todo.
     */
    std::vector<std::vector<std::string>> asm_read_lists;
    /// Por asm-id: @c false si alguna linea del cuerpo no se pudo emparejar, y
    /// entonces su lista de lecturas esta INCOMPLETA.  Se dice aparte para no
    /// confundir "no lee nada mas" con "no se sabe si lee algo mas".
    std::vector<uint8_t> asm_reads_completos;

    /**
     * @brief Instrucciones @c ASM_MICRO de esta funcion (asm opaco liftado).
     *
     * Indexadas por el @c imm de cada @c IrInstr con @c op==ASM_MICRO.  Tabla
     * lateral (en vez de engordar @c IrInstr) porque solo las funciones con asm
     * inline no-liftable a ops tipadas tienen entradas.  Ver @ref AsmMicro.
     * Efimera del pipeline de codegen: hoy NO se serializa en la seccion @c @ir
     * (el asm inline vive en el .vx, no viaja en el .velb como IR liftado).
     */
    std::vector<AsmMicro> asm_micros;

    /**
     * @brief  AOT.3 2b: seccion de salida del CODIGO de esta funcion
     *        (dev OS: `@section(".name")`).  Vacio => default `.text`.
     *
     * @c section_perms son los permisos explicitos del usuario
     * (`@section(".boot","rwx")`): subconjunto de "rwx".  Vacio => permisos
     * por CONVENCION del nombre (.text*->rx, .rodata*->r, .data*->rw,
     * .bss*->rw, otro-codigo->rx).  Solo lo consume el codegen AOT; el
     * JIT/interp lo ignoran.
     */
    std::string section;
    std::string section_perms;
    /**
     * @brief  NR: `@Naked` -- funcion sin prologo/epilogo NI ret
     *        implicito (dev OS: ISRs, stubs de entry/cambio de modo).
     *
     * El cuerpo (tipicamente inline `asm { ... }`) se emite verbatim; el
     * programador es responsable del control de flujo de salida
     * (`ret`/`iretq`/`iret`) y de no usar locales/spills que requieran
     * frame (igual semantica que `__attribute__((naked))` de GCC).  Solo
     * lo consume el codegen (AOT/JIT); el interprete lo ignora (un cuerpo
     * naked con asm puro no tiene representacion en bytecode VM).
     */
    bool is_naked = false;
    /// @NoIdiom: los pases que reconocen idiomas (un bucle de copia ->
    /// `memcpy`) no se aplican a esta funcion.  Lo llevan las primitivas de
    /// memoria: reescribir el bucle de `memcpy` a `memcpy` seria convertirlo
    /// en una llamada a si mismo.
    bool no_idiom = false;
    int64_t section_at = -1; ///< @at(N): offset/VA fijo (AOT .bin); -1 = auto
    int32_t section_order =
        0x7fffffff; ///< @order(N): orden de seccion; max = creacion

    /**
     * @brief Subsistema de coste (modo --analyze): contrato @complexity
     *        declarado por el usuario en el fuente Vesta.
     *
     * Metadata PURA, propagada desde @c ast::FunctionDecl por el lowering.
     * NO afecta el codegen (interp/JIT/AOT la ignoran por completo).  La
     * consume el analizador estatico @c analyze::bigo (modo --analyze)
     * como contrato a validar contra la complejidad inferida.
     *
     *   - @c complexity_expr: la sub-expresion de coste tal cual la
     *     escribio el usuario, normalizada (e.g. "O(n^2)", "O(n log n)",
     *     "O(1)").  Vacio => la funcion no declara @complexity.
     *   - @c complexity_vars: bindings opcionales `n = <expr>` que indican
     *     que variable es el tamano del input (necesarios para --measure
     *     en niveles superiores).  Cada entrada es el texto raw del binding.
     *   - @c complexity_partial_pre / @c complexity_partial_post /
     *     @c complexity_total_pre / @c complexity_total_post: contratos por
     *     DIMENSION (PARCIAL/TOTAL x PRE-opt/POST-opt).  Cada uno se valida
     *     contra su coste inferido correspondiente.  @c complexity_total_post
     *     equivale a la forma posicional @complexity(O(...)).  Vacio => esa
     *     dimension no se declara (no se valida).
     */
    std::string complexity_expr;
    std::vector<std::string> complexity_vars;
    std::string complexity_partial_pre;
    std::string complexity_partial_post;
    std::string complexity_total_pre;
    std::string complexity_total_post;
    // Nota de diseno: los contratos de huella (@pure/@alloc/@stack/...) NO
    // viven aqui.  Se llevan en CompileResult (indexados por nombre) porque
    // son metadata puramente de compile-time (modo --analyze) que ni el JIT ni
    // el AOT ni la serializacion del IR necesitan; mantener IrFunction esbelto
    // evita hincharlo con campos que no se usan en el hot path del backend.

    /**
     * @brief Crea un nuevo valor SSA en el pool.
     * @param type Tipo del valor.
     * @param name Nombre opcional (si vacio se genera "%%N").
     * @return ID del nuevo valor.
     */
    IrValueId new_value(IrType type, const std::string &name = "");

    /**
     * @brief Crea un nuevo bloque basico.
     * @param name Nombre del bloque (si vacio se genera "bbN").
     * @return ID del bloque.
     */
    IrBlockId new_block(const std::string &name = "");

    /**
     * @brief Rehace las aristas del grafo (@c succs / @c preds) a partir de los
     *        TERMINADORES.
     *
     * Las aristas son informacion DERIVADA: quien salta a donde ya lo dice el
     * terminador de cada bloque.  Mantenerlas ademas a mano, en cada sitio que
     * construye control de flujo, garantiza que antes o despues una se quede
     * sin poner -- y quien las lea vera un bloque aislado sin manera de notar
     * que le falta algo.
     *
     * Eso ya paso: el elevado de un `asm` fijaba los terminadores y no tocaba
     * las aristas, asi que un bucle escrito en ensamblador quedaba invisible
     * para todo analisis que camina el grafo, y el coste de una funcion cuyo
     * cuerpo entero es ese bucle salia O(1).  El sintoma no fue un error: fue
     * una respuesta tranquila y equivocada.
     *
     * Llamalo tras construir o reestructurar los bloques de una funcion.
     */
    void recompute_edges();

    /**
     * @brief Anade una instruccion al bloque indicado.
     * @param block_id Bloque destino.
     * @param instr    Instruccion a anadir.
     */
    void append(IrBlockId block_id, IrInstr instr);
};

// =========================================================================
//  Modulo IR
// =========================================================================

/**
 * @brief Modulo IR: coleccion de funciones con declaraciones globales.
 *
 * Unidad de compilacion de la SSA IR.  Corresponde a un archivo fuente
 * del HLL o a un modulo de VestaVM (@Module).
 */

/**
 * @brief Definicion de un espacio de direcciones para el modulo .vel generado.
 *
 * Corresponde a la directiva `@space` del formato .ir, que el emisor
 * traduce a `@SpaceAddress { @Name, @IniAddress, @EndAddress }` en el .vel.
 */
struct IrSpaceDef {
    std::string name;     ///< nombre del espacio (p.ej. "anonymous")
    uint64_t ini_address; ///< direccion inicial
    uint64_t end_address; ///< direccion final
};

/**
 * @brief Definicion de una seccion para el modulo .vel generado.
 *
 * Corresponde a la directiva `@section` del formato .ir, que el emisor
 * traduce a `@Section { @Name, @SpaceAddress, @Align }` en el .vel.
 */
struct IrSectionDef {
    std::string name;       ///< nombre de la seccion (p.ej. "code")
    std::string space_name; ///< espacio de direcciones al que pertenece
    uint64_t align;         ///< alineacion en bytes (p.ej. 0x1000)
};

/**
 * @brief Importacion de una funcion nativa desde una libreria dinamica.
 *
 * Corresponde a un bloque @c "@Method { @Lib(\"...\") @Name(\"...\") }" dentro
 * del bloque @c @Import del .vel.  El frontend (Vesta u otro) registra una
 * IrNativeImport por cada funcion nativa que sus llamadas (CALLN) van a
 * usar.  El emisor agrupa todas en un unico bloque @Import.
 */
/**
 * @brief Lo que hace una funcion nativa, DICHO por quien la importa.
 *
 * Una nativa es codigo que no esta en el programa: no se puede analizar, asi
 * que sin esto lo unico honesto es suponer que hace cualquier cosa -- y eso
 * convierte cada llamada en una barrera para todo lo que la rodea.
 *
 * La salida no es una tabla de nativas conocidas dentro del analizador (seria
 * dar por supuestas las capacidades de algo ajeno, y quedaria desfasada en
 * cuanto la nativa cambiara): es una DECLARACION, y vive donde se declara la
 * importacion.  Hoy la rellena el lowering para las nativas que el propio
 * compilador sintetiza -- el que emite la llamada es quien sabe lo que hace --;
 * manana la rellenara el lenguaje desde las `extern` y las syscall.
 *
 * Sin declarar (@c declarados == false) el comportamiento es el de siempre:
 * efecto maximo, y el nombre sale en el informe para que se pueda cerrar.
 */
struct IrNativeEffects {
    bool declared = false; ///< false = nadie ha dicho nada -> opaca.
    /// Operandos del CALLN cuyo APUNTADO se lee / escribe (bit i = operando i).
    /// Es un bitmask sobre los argumentos, no sobre memoria concreta: el
    /// analizador resuelve cada uno a su localizacion en el sitio de llamada,
    /// con lo que "escribe su segundo argumento" acaba diciendo `stack#3` y no
    /// "algun sitio".
    uint32_t reads_pointee = 0;
    uint32_t writes_pointee = 0;
    bool reads_global = false;  ///< Lee estado global (estatico del proceso).
    bool writes_global = false; ///< Lo escribe.
    bool io = false;            ///< E/S observable (consola, fichero, puerto).
    bool may_throw = false;     ///< Puede lanzar una excepcion capturable.
    bool nondeterministic = false; ///< Dos llamadas iguales pueden diferir.
    /**
     * @brief Puede ABORTAR el programa (panic), que no es lanzar.
     *
     * Ejes distintos en todo el compilador: un `throw` se captura y un panic
     * corta.  Sin este campo, respetar una declaracion dejaba `panics` en falso
     * por omision, y entonces un `@nopanic` sobre algo que llama a `abort` se
     * daba por bueno -- una promesa aprobada justo por lo que no se dijo.
     */
    bool may_panic = false;
    /**
     * @brief Puede RESERVAR memoria del monton.
     *
     * Un booleano y no una cuenta a proposito: nadie puede saber cuantas veces
     * reserva algo que no se ve, y prometer un numero seria inventarlo.  Con
     * esto, un `@alloc(0)` sobre quien llame a un `malloc` declarado se
     * INCUMPLE -- que es lo correcto -- y un `@alloc(3)` se queda en
     * indecidible, que es lo honesto.
     *
     * Sin el campo, una nativa declarada aportaba CERO reservas y `@alloc(0)`
     * pasaba: el silencio se leia como una demostracion.
     */
    bool allocates = false;
    /**
     * @brief Puede BLOQUEAR: esperar a otro, a un cerrojo o a la E/S.
     *
     * Eje propio y no una variante de E/S porque lo que decide es distinto:
     * bloquear no cambia ningun valor, pero impide mover la llamada a donde el
     * que espera no pueda ser despertado, y en un planificador cooperativo
     * decide si hay que ceder el turno.  El modelo interno lo tenia
     * (@c SemanticEffects::may_block) y una `extern` no podia decirlo, asi que
     * cualquier `WaitForSingleObject` entraba como "no bloquea".
     */
    bool may_block = false;
    /**
     * @brief De QUIEN es la excepcion, y de quien el aborto.
     *
     * Refinan a `may_throw` y `may_panic`; no los sustituyen.  Sin ellos, una
     * externa que lanza una excepcion de C++ y una que lanza una de Vesta
     * decian lo MISMO, y son cosas distintas: la segunda la recoge un `catch`
     * y la primera no.  Modelar solo el lenguaje deja fuera justo la frontera
     * donde el lenguaje se acaba.
     */
    UnwindOrigin throw_origin = UnwindOrigin::Any;
    UnwindOrigin panic_origin = UnwindOrigin::Any;
    /// Que fallos del PROCESADOR puede provocar.  Cero = no se acoto.
    TrapKinds trap_kinds = TRAP_NONE;
    /**
     * @brief Que PARTES del mundo de fuera lee y escribe.
     *
     * Refinan a `reads_global`/`writes_global`.  Dos llamadas que tocan partes
     * DISJUNTAS no se estorban; con un solo booleano, cualquier par choca.
     */
    WorldKinds reads_world = WORLD_NONE;
    WorldKinds writes_world = WORLD_NONE;
    /**
     * @brief Es un ASIGNADOR: lo que devuelve es memoria FRESCA.
     *
     * Distinto de `allocates`, y la diferencia es la que hay entre un coste y
     * una garantia.  `allocates` dice que PUEDE reservar -- y con eso se cae
     * `heap_free` --; esto dice que lo que devuelve no lo apunta NADIE MAS y
     * que quien llama se queda con ello.
     *
     * Lo que compra: el resultado deja de ser "puede apuntar a cualquier cosa"
     * y pasa a ser una localizacion propia, como la de un `malloc` nuestro.  A
     * partir de ahi, todo lo que el llamante haga con ese puntero deja de
     * estorbar a lo demas.  Sin esto, describir `VirtualAlloc` no servia de
     * nada: se sabia que costaba y no que daba.
     */
    bool returns_fresh = false;
    /// Que argumentos LIBERA (bit i = argumento i).  Tras la llamada, lo que
    /// apuntaban ya no vale: leerlo es un fallo, y quien lo sepa puede decirlo.
    uint32_t frees_pointee = 0;
    /**
     * @brief Puede provocar un fallo del PROCESADOR: division entre cero,
     *        acceso invalido.
     *
     * Distinto de lanzar y de abortar: un fallo del procesador no lo produce el
     * programa, lo produce la maquina, y en nativo ni siquiera se convierte
     * todavia en excepcion capturable.  Lo que aporta es que el optimizador no
     * puede ADELANTAR la llamada a un camino donde antes no se ejecutaba --
     * eso convertiria un programa que funciona en uno que revienta --.
     */
    bool may_trap = false;
    /// Corre AL COMPILAR, no en ejecucion.  Sus efectos son sobre la propia
    /// compilacion, no sobre el programa compilado.
    bool comptime = false;

    /// Igualdad campo a campo.  Sirve para detectar que DOS declaraciones de la
    /// misma nativa dicen cosas distintas; sin esto, la segunda se descartaba
    /// en silencio y el programa se compilaba con una de las dos elegida por el
    /// ORDEN en que se emitieron las llamadas.
    bool operator==(const IrNativeEffects &o) const noexcept {
        return declared == o.declared && reads_pointee == o.reads_pointee &&
               writes_pointee == o.writes_pointee &&
               reads_global == o.reads_global &&
               writes_global == o.writes_global && io == o.io &&
               may_throw == o.may_throw &&
               nondeterministic == o.nondeterministic &&
               may_panic == o.may_panic && allocates == o.allocates &&
               may_block == o.may_block && may_trap == o.may_trap &&
               throw_origin == o.throw_origin &&
               panic_origin == o.panic_origin &&
               trap_kinds == o.trap_kinds &&
               reads_world == o.reads_world &&
               writes_world == o.writes_world &&
               returns_fresh == o.returns_fresh &&
               frees_pointee == o.frees_pointee &&
               comptime == o.comptime;
    }
    bool operator!=(const IrNativeEffects &o) const noexcept {
        return !(*this == o);
    }
};

struct IrNativeImport {
    std::string
        lib; ///< Ruta logica de la libreria (p.ej. "stdlib/native/io/vesta_io")
    std::string name; ///< Nombre de la funcion nativa (p.ej. "vio_println")
    IrNativeEffects effects; ///< Lo que hace, si alguien lo ha dicho.

    /// DOS declaraciones de esta misma nativa dijeron cosas distintas.
    ///
    /// No es un caso raro: la misma funcion del sistema puede declararse en dos
    /// modulos, y al fusionarlos las dos llegan aqui.  Antes ganaba la primera
    /// y la otra desaparecia sin dejar rastro, asi que el programa se compilaba
    /// segun el ORDEN en que se emitieron las llamadas -- que no es una
    /// propiedad del programa.
    ///
    /// Cuando pasa, @c effects se queda con la union de lo PEOR de las dos: el
    /// compilador puede perder precision sin equivocarse, pero no al reves.  Y
    /// se marca aqui para que quien tenga un canal de diagnostico lo diga; este
    /// tipo no lo tiene, y ponerselo lo ataria al frontend.
    bool effects_conflict = false;
};

// =========================================================================
//  Metadata de POO (clases, interfaces, fields, metodos)
//
//  Estos tipos hacen al @c IrModule auto-suficiente para que el port
//  transpiler (C, Java, JS, ...) emita codigo POO eficiente sin tener
//  que parsear @c __module_init (defclass/deffield/defmethod runtime
//  calls).
//
//  El @c IR emitter convencional NO consume esta info -- la deja pasar
//  para el transpiler.  Mantiene compatibilidad backwards: modulos sin
//  classes (e.g. solo funciones libres) tienen los vectores vacios.
//
//  Origen: el frontend Vesta (TypeChecker::class_layouts_) lo llena
//  durante el lowering.  Otros frontends pueden hacer lo mismo.
// =========================================================================

/**
 * @brief Campo de instancia (o estatico) de una clase Vesta.
 */
struct IrField {
    std::string name;    ///< Nombre del campo.
    IrType type;         ///< Tipo del campo.
    uint32_t offset = 0; ///< Offset en bytes desde el inicio del payload
                         ///< (excluye @c ObjectHeader; el lowering lo suma).
    uint32_t size_bytes = 0; ///< Tamano en bytes del campo (sizeof).
    bool is_static = false;  ///< Field estatico (compartido a nivel de clase).
    /// Field es tipo CLASS de una clase nombrada (string vacio si no).
    /// Util para el transpiler: emite punteros a struct anidados o
    /// inline el struct completo segun escape analysis.
    std::string class_type_name;
};

/**
 * @brief Metodo de una clase Vesta (incluyendo ctor/dtor).
 */
struct IrMethod {
    std::string name; ///< Nombre legible del metodo ("inc", "ctor", "dtor").
    std::string
        ir_fn_name; ///< Nombre cualificado de la @c IrFunction asociada
                    ///< (e.g. "Counter__inc"; vacio para metodos abstractos).
    IrType return_type = IrType::VOID;
    std::vector<IrType> param_types; ///< Sin contar @c this.
    int32_t vtable_index =
        -1; ///< Indice en la vtable; -1 si static o no virtual.
    bool is_static = false;
    bool is_final = false; ///< No puede ser overrideado.
    bool is_constructor = false;
    bool is_destructor = false;
    bool is_inline = false; ///< Marcado @c @Inline; lowering inlinea.
    /// Nombre de la clase donde este metodo esta DEFINIDO realmente.
    /// Para metodos heredados sin override, @c defining_class apunta a
    /// la superclase original.  El transpiler usa esto para decidir
    /// si emitir el metodo o reusar la definicion del padre.
    std::string defining_class;
};

/**
 * @brief Descriptor completo de una clase / interface Vesta.
 */
struct IrClass {
    std::string name;       ///< Nombre simple ("Counter", "Animal").
    std::string super_name; ///< "" si no hay super (o == "Object").
    std::vector<std::string>
        interfaces;              ///< Nombres de interfaces implementadas.
    std::vector<IrField> fields; ///< Campos de instancia (incluye heredados).
    std::vector<IrField> static_fields; ///< Campos estaticos.
    std::vector<IrMethod> methods; ///< Todos los metodos (incl. heredados).

    uint32_t size_bytes = 0;  ///< Tamano del payload (sin ObjectHeader).
    uint32_t align_bytes = 8; ///< Alineamiento requerido del struct.

    bool is_final = false; ///< No puede ser heredada.  Permite mode TRIVIAL.
    bool is_interface =
        false;              ///< Sin fields ni cuerpos; solo metodos abstractos.
    bool is_aspect = false; ///< @Aspect class: el modulo USA AOP.  El pase
                            ///< @c ir_pass_devirt_monomorphic debe skip-ear
                            ///< porque CALLVIRTs disparan advice chains.
    bool has_destructor = false; ///< Declara @c ~ClassName().
    /// El destructor (auto-sintetizado o explicito) tiene que recorrer
    /// fields tipo CLASS para llamar sus destructores tambien.  Set
    /// por el frontend tras analisis de fields transitivo.
    bool has_destructible_field = false;
    /// La clase ya esta registrada en el runtime (FatalError, etc.).
    /// El transpiler NO emite struct ni vtable; usa los del runtime.
    bool is_runtime_predefined = false;
};

struct IrModule {
    std::string name;                  ///< nombre del modulo (@module)
    std::vector<IrFunction> functions; ///< funciones definidas
    std::vector<std::string>
        imports; ///< nombres de funciones importadas (@import)
    std::unordered_map<std::string, IrValueId> globals; ///< variables globales
    std::vector<std::string> native_libs; ///< libs nativas (@native_lib)

    /**
     * @brief Que funcion reserva y cual libera en este programa.
     *
     * Quien marque una funcion con @c @AllocatorOverride es el asignador de su
     * programa; el de la biblioteca solo se usa cuando nadie lo hace.  Va aqui
     * para que la maquina lo sepa: escribir un nombre concreto en el backend
     * ataria el JIT al asignador por defecto y se saltaria justo el mecanismo
     * que permite sustituirlo -- un programa con el suyo acabaria usandolo a
     * medias, que es peor que no usarlo.
     *
     * Vacios = ninguno declarado.
     */
    std::string alloc_sym;
    std::string free_sym;

    /// Metadata de clases + interfaces declaradas en el modulo.  Llena
    /// por el frontend (Vesta TypeChecker) en lowering.  Consumida por
    /// el port transpiler (C/Java/JS) para emitir POO eficiente.
    /// Vacio en modulos sin POO -- el transpiler entonces opera solo
    /// sobre funciones libres.  El IR emitter (a .vel) la ignora.
    std::vector<IrClass> classes;

    /**
     * @brief La CADENA de aspectos de cada metodo, por su nombre IR.
     *
     * A un metodo con aspectos NO se le puede llamar directo tal cual: el
     * advice se recorre en el despacho, asi que convertir su @c callvirt en un
     * @c call se lo saltaria.  Estar en el mapa es lo que dice que un metodo
     * los lleva; la lista, EN ORDEN, es lo que hace falta para tejer la cadena
     * en el sitio de llamada en vez de renunciar a optimizarlo.
     *
     * Antes bastaba con que el modulo tuviera UN aspecto para apagar la
     * devirtualizacion ENTERA -- y el modulo aqui es el programa entero.  Un
     * aspecto de registro en un rincon dejaba sin devirtualizar todo lo demas,
     * y eso cuesta entre 1,2x y 9,5x medido en los bancos de despacho.
     *
     * Con la lista, cada sitio de llamada se mira por separado: se salta el que
     * apunta a un metodo de aqui y se devirtualiza el resto.  El pointcut es
     * @c Clase.metodo exacto (no hay comodines), asi que la lista es exacta.
     *
     * Se compara por NOMBRE IR y no por clase, que es justo lo que hace falta
     * con herencia: si la derivada no redefine el metodo, la llamada acaba en
     * el mismo @c Base__m -- el mismo MethodInfo que lleva la cadena --, y el
     * nombre lo recoge; si lo redefine, es otro nombre y otro MethodInfo, que
     * es tambien lo correcto.
     */
    struct ChainedAdvice {
        uint8_t kind;               ///< ADVICE_* de @c loader/oop_types.h
        std::string method_ir_name; ///< nombre IR del advice (`Aspecto__m`)
    };
    std::unordered_map<std::string, std::vector<ChainedAdvice>> advice_chains;

    /**
     * @brief Los aspectos del modulo estan TODOS en @c advice_chains.
     *
     * Falso mientras haya alguno que no se pueda atribuir a un metodo concreto
     * -- hoy, un @c addadvice escrito a mano en ensamblador --, y entonces se
     * vuelve a apagar la devirtualizacion del modulo entero.  Sin esta
     * distincion, un mapa vacio significaria las dos cosas opuestas: que no hay
     * aspectos, o que no se sabe cuales son.
     */
    bool all_advices_attributed = true;

    /**
     * @brief v4: metadatos de cada entrada en @c static_data.
     *
     * Permite al JIT/AOT/PGO consumir hints sobre cada entrada:
     *   - inmutabilidad para inlinear el ptr directo (JIT C2 opt).
     *   - alignment para emitir loads alineados.
     *   - source_module_idx para patch tables (loadmodule rebase).
     *   - hot_hint para layout en .rodata segregado (AOT).
     */
    struct StaticDataMeta {
        uint64_t content_hash = 0; ///< FNV-1a 64 sobre bytes; 0 = no calculado
        uint16_t alignment = 1;    ///< multiplo potencia de 2
        uint8_t flags =
            0; ///< bit0=immutable, bit1=imported, bit2=hot, bit3=cold
        uint16_t source_module_idx = 0; ///< 0 = local; !=0 = imported (futuro)
        std::string section_name;       ///< vacio = default; usado por AOT
        std::string
            section_perms; ///< permisos explicitos "rwx" (vacio = convencion)
        int64_t section_at =
            -1; ///< @at(N): offset/VA fijo (AOT .bin); -1 = auto
        int32_t section_order =
            0x7fffffff; ///< @order(N): orden de seccion; max = creacion
        /// Referencia a simbolo dentro de los bytes (AOT): un campo del blob
        /// que apunta a la direccion de una funcion/dato (p.ej. `dq main` en
        /// un bloque @c bytes -> tabla de saltos, vtable, GDT).  El emisor AOT
        /// las traduce a relocs.
        struct SymRef {
            uint32_t offset = 0; ///< offset del campo dentro del blob.
            std::string sym;     ///< nombre del simbolo referenciado.
            uint8_t width = 8;   ///< 8 (dq->ABS64) u 4 (dd->ABS32/REL32).
            uint8_t is_rel = 0;  ///< 1 = PC-relativo; 0 = absoluto.
        };
        std::vector<SymRef> sym_refs; ///< vacio = sin refs (caso comun).
        ///  NR / dev-OS: nombre EXPORTADO de este bloque de datos para
        /// que OTROS bloques lo referencien por simbolo (cross-block).  Lo
        /// fija el lowering para bloques `asm name {}` y `bytes name {}`: su
        /// `name` se vuelve un simbolo resoluble por el emisor AOT (un `dd
        /// gdt` / `jmp other_block` en otro bloque resuelve a la ubicacion de
        /// ESTE).  Vacio => bloque anonimo (literal de cadena, etc.) sin
        /// simbolo.  Para que la ubicacion sea estable, un bloque con
        /// symbol_name se marca FORCE_EMIT + NON_DEDUP.
        std::string symbol_name;
        /// Clave de global compartido a nivel de PROGRAMA: cuando no esta
        /// vacia, este slot es un unico global identificado por la clave en
        /// todo el binario (aunque sea NON_DEDUP).  El merge cross-module
        /// (compile_vx_project) unifica todas las entries con la misma
        /// shared_key en UN solo slot.  Usado por los globals del CPU
        /// dispatch (__vx_cpu_features, __vx_memcpy_fp, etc.) que deben
        /// ser program-globales para que el init del root inicialice el slot
        /// que leen las funciones de los modulos dependientes.
        std::string shared_key;
    };

    /**
     * @brief Datos estaticos del modulo: cada entrada es la imagen de bytes
     *        de un literal de cadena u otro blob inmutable.
     *
     * **M.staticdata-pool full**: storage unificado en un solo
     * @c vector<uint8_t> con entries que apuntan a (offset, len).
     * Beneficios concretos:
     *   - Cache locality al iterar (1 alocacion vs N).
     *   - mmap shared cross-process (1 mapping vs N).
     *   - Port-to-C trivial (1 array global vs N variables).
     *   - JIT/AOT pueden cargar el pool tal cual a @c .rodata sin reasamblaje.
     *
     * Cada entry arranca en multiplo de @c alignment_default (8 por
     * defecto); si @c StaticDataMeta::alignment de una entry es mayor,
     * recibe padding adicional para respetar ese alineamiento local.
     *
     * Garantia de offsets: el orden de @c push_back determina el orden
     * de las entries; dos builds del mismo source producen el mismo
     * pool byte-a-byte (estable cross-build) tras el dedup deterministico
     * en @c compile_vx_project.
     */
    struct StaticDataStore {
        /// Pool contiguo: todos los blobs concatenados con padding.
        std::vector<uint8_t> bytes;
        /// Entries que indican rangos dentro de @c bytes + meta.
        struct Entry {
            uint32_t byte_offset; ///< offset dentro de bytes[]
            uint32_t byte_len;
            StaticDataMeta meta;
        };
        std::vector<Entry> entries;
        /// Alineamiento global por defecto (entries individuales con
        /// @c meta.alignment mayor reciben padding adicional).
        uint8_t alignment_default = 8;

        /* ---- Accesores de tamano ---- */
        size_t size() const noexcept { return entries.size(); }
        bool empty() const noexcept { return entries.empty(); }

        /* ---- Lectura de bytes ---- */
        const uint8_t *data(size_t i) const noexcept {
            return bytes.data() + entries[i].byte_offset;
        }
        size_t len(size_t i) const noexcept { return entries[i].byte_len; }
        std::pair<const uint8_t *, size_t> bytes_at(size_t i) const noexcept {
            return {data(i), len(i)};
        }

        /* ---- Lectura/escritura de meta ---- */
        const StaticDataMeta &meta_at(size_t i) const noexcept {
            return entries[i].meta;
        }
        StaticDataMeta &meta_at(size_t i) noexcept { return entries[i].meta; }

        /* ---- Comparacion de bytes ---- */
        bool equals(size_t i, const uint8_t *p, size_t n) const noexcept {
            if (entries[i].byte_len != n) return false;
            if (n == 0) return true;
            return std::memcmp(data(i), p, n) == 0;
        }
        bool equals(size_t i, const std::vector<uint8_t> &v) const noexcept {
            return equals(i, v.data(), v.size());
        }

        /* ---- Mutaciones: añadir entries ---- */
        /// añade bytes al pool con padding de alineamiento.  Devuelve
        /// el indice de la nueva entry.  La @c meta queda con defaults;
        /// llamar @c meta_at(i) para ajustarla.
        size_t push_back(const uint8_t *p, size_t n);
        size_t push_back(const std::vector<uint8_t> &v) {
            return push_back(v.data(), v.size());
        }
        size_t push_back(std::vector<uint8_t> &&v);

        /// Append directo del backing pool (sin dedup).  Usado por el
        /// merge cross-module.  Toma ownership.
        void append_raw_entries(StaticDataStore &&other);

        /* ---- Helpers ---- */
        void clear() {
            bytes.clear();
            entries.clear();
        }
        void reserve(size_t n) { entries.reserve(n); }

        /// Copia los bytes de la entry @c i a un @c vector<uint8_t>
        /// (helper para call sites que necesitan ownership).
        std::vector<uint8_t> to_vector(size_t i) const {
            return std::vector<uint8_t>(data(i), data(i) + len(i));
        }
    };

    /// Storage canonico de los datos estaticos.  Reemplaza los antiguos
    /// pares @c static_data + @c static_data_meta a partir de
    /// M.staticdata-pool full.
    StaticDataStore static_data;

    /// Flags para @c StaticDataMeta::flags.
    static constexpr uint8_t SD_FLAG_IMMUTABLE = 1 << 0;
    static constexpr uint8_t SD_FLAG_IMPORTED = 1 << 1;
    static constexpr uint8_t SD_FLAG_HOT = 1 << 2;
    static constexpr uint8_t SD_FLAG_COLD = 1 << 3;
    /// Marca el slot como storage mutable: el dedup post-merge NO
    /// debe colapsarlo aunque dos slots tengan los mismos bytes
    /// iniciales (caso comun: globals `i64 g = 0;` empiezan en 0
    /// pero deben tener storage independiente).
    static constexpr uint8_t SD_FLAG_NON_DEDUP = 1 << 4;
    /// AOT: emite el slot en su seccion AUNQUE ningun reloc lo
    /// referencie (caso: bloques @c bytes para firmas, tablas,
    /// boot sectors).  El emisor AOT lo coloca siempre.
    static constexpr uint8_t SD_FLAG_FORCE_EMIT = 1 << 5;
    /// AOT: el slot es la PLANTILLA de una variable `thread_local` (TLS).
    /// Va a una seccion SHF_TLS (.tdata) y su acceso usa el thread pointer
    /// (fs/gs + TPOFF en ELF; TLS directory en PE), no una direccion lineal.
    static constexpr uint8_t SD_FLAG_TLS = 1 << 6;

    /**
     * @brief Funciones nativas que el modulo declara importar.
     *
     * Cada una corresponde a un @c @Method dentro del bloque @c @Import
     * del .vel emitido.  El emisor las agrupa en un unico bloque para
     * evitar declaraciones redundantes; el frontend solo debe garantizar
     * que cada par (lib, name) usado por un CALLN aparece aqui al menos
     * una vez (los duplicados los filtra el emisor).
     */
    std::vector<IrNativeImport> native_imports;

    // Metadatos de compilacion (opcionales; el emisor genera valores por
    // defecto si estan vacios)
    std::string format; ///< formato de salida: "velb" (defecto) u otro
    std::vector<IrSpaceDef> spaces;     ///< espacios de direcciones (@space)
    std::vector<IrSectionDef> sections; ///< secciones de codigo (@section)

    /**
     * @brief Anade una funcion al modulo.
     * @param fn Funcion a anadir.
     * @return Indice de la funcion en el modulo.
     */
    size_t add_function(IrFunction fn);

    /**
     * @brief Registra un literal de cadena en static_data.
     *
     * Si el contenido ya existe lo deduplica devolviendo el indice
     * existente, evitando datos duplicados en el binario final.
     *
     * @param bytes Contenido literal (puede contener nuls intermedios).
     * @return Indice estable que el lowering puede pasar a STR_LIT_ADDR.
     */
    uint64_t intern_static_data(std::vector<uint8_t> bytes);

    /**
     * @brief Registra una importacion nativa, deduplicando.
     *
     * Si la pareja (lib, name) ya esta en native_imports no se añade
     * de nuevo; el lowering puede llamarlo libremente desde cualquier
     * punto sin preocuparse de duplicados.
     */
    void register_native_import(std::string lib, std::string name);

    /**
     * @brief Registra una importacion nativa DICIENDO lo que hace.
     *
     * Misma deduplicacion; si la pareja ya estaba sin declarar, la declaracion
     * la completa (el orden en que se emiten las llamadas no deberia decidir
     * cuanto se sabe de la funcion).
     */
    void register_native_import(std::string lib, std::string name,
                                const IrNativeEffects &effects);

    /// Devuelve lo declarado para @p lib_dos_puntos_fn ("lib:fn"), o nullptr si
    /// esa nativa no se importa aqui o nadie ha dicho lo que hace.
    const IrNativeEffects *native_effects_of(const std::string &lib_fn) const;
};

// =========================================================================
//  Serializado / deserializado de texto
// =========================================================================

/**
 * @brief Imprime un IrModule al formato de texto SSA IR.
 *
 * @param mod Modulo a serializar.
 * @param out Stream de salida.
 */
void ir_print(const IrModule &mod, std::ostream &out);

/**
 * @brief Parsea un archivo .ir y construye un IrModule.
 *
 * @param text  Contenido del archivo .ir como cadena.
 * @param out   Modulo de salida.
 * @param error Mensaje de error (vacio si no hay error).
 * @return true si el parseo fue exitoso.
 */
bool ir_parse(const std::string &text, IrModule &out, std::string &error);

// =========================================================================
//  Verificador
// =========================================================================

/**
 * @brief Verifica que el modulo esta en forma SSA correcta.
 *
 * Comprueba:
 *   - Cada valor se define exactamente una vez.
 *   - Cada bloque termina en un terminador.
 *   - Los tipos de los operandos son consistentes con el opcode.
 *   - Los operandos referenciados existen en el pool.
 *
 * @param mod    Modulo a verificar.
 * @param errors Vector de mensajes de error encontrados.
 * @return true si el modulo es valido.
 */
bool ir_verify(const IrModule &mod, std::vector<std::string> &errors);

/**
 * @brief Escribe UNA instruccion en el mismo formato que el volcado completo.
 *
 * Se expone para que quien explique un fallo ensene la instruccion ENTERA --
 * destino, operandos, tipos -- y no solo el nombre de la operacion, que por si
 * solo no dice nada.  Es la MISMA funcion que usa el volcado: escribir una
 * segunda daria dos formatos que se irian separando en cuanto uno cambiara.
 *
 * @param o Donde escribir.
 * @param fn Funcion a la que pertenece (hace falta para nombrar los valores).
 * @param ins La instruccion.
 */
void print_instr(std::ostream &o, const IrFunction &fn, const IrInstr &ins);

/**
 * @brief @c true si @p nombre es el cuerpo de una funcion de COMPILACION.
 *
 * Las macros y las funciones comptime se emiten con el prefijo @c __macro_ y
 * corren AL COMPILAR: no llegan al programa emitido, y lo que tocan son datos
 * de la propia compilacion.  Quien razona sobre el programa que se ejecuta
 * tiene que saltarselas -- juzgarlas es juzgar otro programa.
 *
 * Vive aqui porque es el IR quien sabe que significan los nombres de sus
 * funciones.  La comprobacion estaba escrita a pelo en varios sitios, y una
 * regla repetida son varias reglas en cuanto una cambia.
 *
 * @param nombre Nombre de la funcion.
 * @return true si es un cuerpo comptime.
 */
inline bool es_cuerpo_comptime(const std::string &nombre) {
    return nombre.rfind("__macro_", 0) == 0;
}
/**
 * @brief Corre los indices de datos de unas funciones que se traen a otro
 * modulo.
 *
 * Cada modulo numera sus ranuras desde cero.  Al concatenar los datos, las del
 * modulo que llega se van al final y CAMBIAN de indice, pero sus instrucciones
 * siguen pidiendo el numero viejo -- que ahora es otra cosa.  Ademas de leer lo
 * que no es, se pierde la naturaleza: una ranura de variable global vive en
 * memoria del host y el resto en la de la maquina, asi que el codigo traido
 * acaba usando una direccion de la maquina como si fuera del host.
 *
 * Esto ya costo un fallo que tardo en encontrarse, y estaba escrito DOS veces
 * -- una por cada sitio que fusiona --, asi que la tercera copia habria sido el
 * mismo fallo otra vez.  Vive aqui, con la operacion a la que pertenece.
 *
 * Corre las referencias por indice y tambien las TEXTUALES (@c "code.s_N"),
 * que aparecen en el ensamblador embebido y en las etiquetas.
 *
 * @param fns Funciones que se traen (se modifican).
 * @param desplazamiento Cuantas ranuras habia ya en el modulo destino.
 */
void ir_correr_indices_de_datos(std::vector<IrFunction> &fns,
                                uint64_t desplazamiento);

/// @copydoc ir_correr_indices_de_datos
/// Sobre UNA funcion, para quien las trae de una en una.
void ir_correr_indices_de_datos(IrFunction &fn, uint64_t desplazamiento);

} // namespace ir

// Restaurar las macros de Windows que anulamos al principio del header.
#ifdef _WIN32
#pragma pop_macro("VOID")
#pragma pop_macro("CONST")
#pragma pop_macro("BOOL")
#endif

#endif /* SSA_IR_H */
