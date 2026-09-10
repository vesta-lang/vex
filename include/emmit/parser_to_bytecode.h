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
 * @file parser_to_bytecode.h
 * @brief Ensamblador de 3 fases: convierte un AST generado por el parser en
 * bytecode ejecutable.
 *
 * Contiene:
 *  - @c PseudoInstructions : conjunto de directivas de preprocesado (global,
 * extern, bits, align, org).
 *  - @c InstrTable         : tabla completa de instrucciones con sus variantes
 * de codificacion.
 *  - @c Assembler          : clase principal del ensamblador (3 fases).
 *  - @c resolve_imports()  : funcion estatica que expande recursivamente los
 * nodos @c ImportNode.
 *
 * Proceso de ensamblado (3 fases):
 *  1. Primera pasada  (@c first_pass)  : recoleccion de simbolos, labels y
 * calculo de offsets.
 *  2. Segunda pasada  (@c emit_pass)   : emision de datos y evaluacion de
 * expresiones.
 *  3. Tercera pasada  (fusionada en 2) : emision de instrucciones y resolucion
 * de saltos.
 */

#ifndef PARSER_TO_BYTECODE_H
#define PARSER_TO_BYTECODE_H

#include <filesystem>

#include "emmit_decl.h"
#include "annotations.h"

namespace Assembly::Bytecode {

/**
 * @brief Conjunto de pseudo-instrucciones (directivas de preprocesado).
 *
 * Estas directivas deben aparecer siempre al inicio del programa, antes de
 * cualquier instruccion ejecutable.  El ensamblador las procesa en la primera
 * pasada y no generan bytecode directo.
 *
 * Directivas soportadas:
 *  - @c global : exporta un simbolo al scope global.
 *  - @c extern : declara un simbolo externo (importado).
 *  - @c bits   : establece el ancho de los operandos (8, 16, 32, 64).
 *  - @c align  : alinea el offset actual a un multiplo de N bytes.
 *  - @c org    : fija la direccion base del ensamblado.
 */
static const std::unordered_set<std::string> PseudoInstructions = {
    "global", "extern", "bits", "align", "org"};

/**
 * @brief Tabla de instrucciones: mapea cada mnemotecnico a sus variantes de
 * codificacion.
 *
 * Cada entrada asocia un nombre de instruccion con un vector de @c InstrInfo.
 * Cuando una instruccion tiene multiples variantes (por ejemplo, ADD con
 * reg+reg, reg+inmediato o reg+SIB), el ensamblador llama a @c select_variant()
 * para elegir la correcta segun los operandos del nodo AST.
 *
 * Grupos de instrucciones:
 *  - Informacion de VM      : vminfo, vminfomanager.
 *  - Aritmetica con/sin signo: adds/addu, subs/subu, muls/mulu, divs/divu,
 * cmps/cmpu.
 *  - Transferencia          : mov (reg/inmed/SIB), movc, movch.
 *  - Logica                 : and, or, xor, not, shl, shr, sar.
 *  - Saltos absolutos       : jmp (incondicional + 14 condicionales), jmpr.
 *  - Saltos relativos       : jrel (incondicional + 14 condicionales).
 *  - Pila                   : push, pop, xchg.
 *  - Llamadas               : callvm, callvmr, calln, callnr.
 *  - Control de flujo       : enter, leave, ret, loop.
 *  - GC generacional        : newobj, gcrun, gcconfig, drop, gcwb, gcalloc.
 *  - Asignador raw          : alloc, free, realloc.
 *  - Cursores               : readcur, writecur, gcderef.
 *  - OOP                    : newobjraw, callvirt, callsuper, throw, rethrow,
 *                             getclass, instanceof, checkcast, getfield,
 * getmethod, fieldcount, methodcount, classname.
 *  - Reflexion/doc OOP      : classdoc, classattrcount, classattrkey,
 * classattrval, methodname, methoddoc, methoddesc, methodattrcount,
 *                             methodattrkey, methodattrval, fieldname,
 * fielddoc, fieldattrcount, fieldattrkey, fieldattrval.
 *  - NOP                    : nop1 (1 byte), nop2 (2 bytes).
 *  - Protocolo distribuido  : edmw4, edmw6, edm, hlt.
 *
 * Formato de cada variante (@c InstrInfo):
 * @code
 * { opcode1, opcode2, InstrSizeMode, AddressingMode, emit_fn }
 * @endcode
 * Si opcode1 == 0x00 la instruccion es extendida (2 bytes de opcode).
 */
/* UNA definicion, no una por fichero que incluya esta cabecera.
 *
 * Esto era `static`, que a nivel de espacio de nombres significa enlace
 * INTERNO: cada unidad de traduccion se llevaba su propia copia de la tabla
 * entera.  Medido sobre el binario de Profile: 23 objetos con ~58 KB de
 * constructores globales cada uno -- 1,27 MB --, de los que 848 KB sobrevivian
 * al enlace, el 4,1% de todo el codigo del ejecutable.
 *
 * Y no es solo tamano: son 323 mnemonicos con su `std::string` y su
 * `std::vector`, construidos por INICIALIZACION DINAMICA, o sea ANTES de
 * `main`, una vez por copia.
 *
 * Con `extern` la declaracion vive aqui y la definicion en UN sitio
 * (`parser_to_bytecode.cpp`, que define la macro de abajo antes de incluir).
 * El cuerpo NO se ha tocado ni se ha movido: sigue donde estaba, palabra por
 * palabra, para que este cambio no pueda alterar que opcode emite un
 * mnemonico -- que es un fallo que no daria error, daria otro programa.
 *
 * PENDIENTE: pasarla a `inline constexpr` indexada por `Mnemonic`.  La busqueda
 * nombre->enum ya existe (`mnemonic_from_text`, binaria y perezosa), asi que
 * seria O(1) por indice y sin ninguna inicializacion dinamica.  Es la regla del
 * proyecto -- tablas de despacho como arrays planos indexados por enum -- y
 * ademas cerraria la duplicacion que `instr_list.h` existe para cerrar.
 */
extern const std::unordered_map<std::string, std::vector<InstrInfo>> InstrTable;

#ifdef VESTA_DEFINE_INSTR_TABLE
const std::unordered_map<std::string, std::vector<InstrInfo>>
    InstrTable = {
        /* --- Informacion de VM --- */
        {"vminfo",
         {{0x01, 0x00, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},
        {"vminfomanager",
         {{0x02, 0x00, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},

        /* INC y DEC usan la misma subrutina de emision porque se codifican
           igual, cambiando solo el segundo byte. */
        {"inc",
         {{0x04, 0x00, InstrSizeMode::FIXED_2, AddressingMode::REG,
           emit_inc_dec}}},
        {"dec",
         {{0x04, 0x00, InstrSizeMode::FIXED_2, AddressingMode::REG,
           emit_inc_dec}}},

        /* callvm <label|addr>  - llama a funcion interna empujando retorno en
           pila. */
        {"callvm",
         {{0x10, 0x00, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        /* callvmr <reg>        - igual que callvm pero la direccion viene de un
           registro. */
        {"callvmr",
         {{0x16, 0x00, InstrSizeMode::FIXED_2, AddressingMode::REG,
           emit_pop_push}}},

        /* --- Saltos absolutos (opcode1 = 0x11) --- */
        /* jmp incondicional: opcode2 = 0x0F */
        {"jmp",
         {{0x11, 0x0F, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        /* jmp condicionales: sufijo determina la condicion, opcode2 = codigo de
           condicion. */
        {"jmp.je",
         {{0x11, 0x00, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jz",
         {{0x11, 0x00, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jne",
         {{0x11, 0x01, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jnz",
         {{0x11, 0x01, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        /* jcs/jb (jump if below)        : CF==1 -> cond 0x02 */
        {"jmp.jcs",
         {{0x11, 0x02, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jb",
         {{0x11, 0x02, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        /* jcc/jae (jump if above-or-equal) : CF==0 -> cond 0x03 */
        {"jmp.jcc",
         {{0x11, 0x03, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jae",
         {{0x11, 0x03, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jmi",
         {{0x11, 0x04, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jpl",
         {{0x11, 0x05, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jvs",
         {{0x11, 0x06, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jvc",
         {{0x11, 0x07, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jhi",
         {{0x11, 0x08, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jls",
         {{0x11, 0x09, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jge",
         {{0x11, 0x0A, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jlt",
         {{0x11, 0x0B, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jgt",
         {{0x11, 0x0C, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        {"jmp.jle",
         {{0x11, 0x0D, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},

        /* jmpr <reg>  - salto incondicional por registro. */
        {"jmpr",
         {{0x15, 0x00, InstrSizeMode::FIXED_2, AddressingMode::REG,
           emit_pop_push}}},

        /* --- Saltos relativos con desplazamiento de 32 bits (opcode extendido
           0x00 0x2D) --- */
        {"jrel",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.je",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jz",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jne",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jnz",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jcs",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jae",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jcc",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jb",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jmi",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jpl",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jvs",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jvc",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jhi",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jls",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jge",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jlt",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jgt",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},
        {"jrel.jle",
         {{0x00, 0x2D, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_jrel}}},

        /* enter <frame_size> - crea stack frame reservando N bytes para
           variables locales. */
        {"enter",
         {{0x28, 0x00, InstrSizeMode::FIXED_10, AddressingMode::INMED,
           emit_instr_abs64}}},
        /* leave - destruye el frame actual (sin operandos). */
        {"leave",
         {{0x29, 0x00, InstrSizeMode::FIXED_1, AddressingMode::NONE, nullptr}}},

        /* --- Pila --- */
        {"push",
         {{0x12, 0x00, InstrSizeMode::FIXED_2, AddressingMode::REG,
           emit_pop_push}}},
        {"pop",
         {{0x13, 0x00, InstrSizeMode::FIXED_2, AddressingMode::REG,
           emit_pop_push}}},
        {"xchg",
         {{0x14, 0x00, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_xchg}}},

        /* --- GC generacional (opcode extendido 0x00 0xA0..0xA5) --- */
        {"newobj",
         {{0x00, 0xA0, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"gcrun",
         {{0x00, 0xA1, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},
        {"gcconfig",
         {{0x00, 0xA2, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"drop",
         {{0x00, 0xA3, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"gcwb",
         {{0x00, 0xA4, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"gcalloc",
         {{0x00, 0xA5, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Asignador raw (opcode extendido 0x00 0xB0..0xB2) --- */
        {"alloc",
         {{0x00, 0xB0, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"free",
         {{0x00, 0xB1, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"realloc",
         {{0x00, 0xB2, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- Cursores: acceso a memoria real (opcode extendido 0x00
           0xC0..0xC5) --- */
        {"readcur",
         {{0x00, 0xC0, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_cursor_rw}}},
        {"writecur",
         {{0x00, 0xC1, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_cursor_rw}}},
        {"gcderef",
         {{0x00, 0xC2, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_gcderef}}},
        {"addcur",
         {{0x00, 0xC3, InstrSizeMode::FIXED_6, AddressingMode::INMED,
           emit_addcur}}},
        {"vmcopy",
         {{0x00, 0xC4, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_vmcopy}}},
        {"vcopyh",
         {{0x00, 0xC5, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_vcopyh}}},
        /* --- Consulta de entorno de ejecucion (opcode extendido 0x00
           0xC6..0xC8) --- */
        {"getproc",
         {{0x00, 0xC6, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"getvm",
         {{0x00, 0xC7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"getmgr",
         {{0x00, 0xC8, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- OOP: sistema de objetos (opcode extendido 0x00 0xD0..0xDC) --- */
        {"newobjraw",
         {{0x00, 0xD0, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"callvirt",
         {{0x00, 0xD1, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"callsuper",
         {{0x00, 0xD2, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"throw",
         {{0x00, 0xD3, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"rethrow",
         {{0x00, 0xD4, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},
        {"getclass",
         {{0x00, 0xD5, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"instanceof",
         {{0x00, 0xD6, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"checkcast",
         {{0x00, 0xD7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"getfield",
         {{0x00, 0xD8, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"getmethod",
         {{0x00, 0xD9, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"fieldcount",
         {{0x00, 0xDA, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"methodcount",
         {{0x00, 0xDB, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"classname",
         {{0x00, 0xDC, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Reflexion/documentacion OOP (opcode extendido 0x00 0xDD..0xEB)
           --- */
        {"classdoc",
         {{0x00, 0xDD, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"classattrcount",
         {{0x00, 0xDE, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"classattrkey",
         {{0x00, 0xDF, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"classattrval",
         {{0x00, 0xE0, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"methodname",
         {{0x00, 0xE1, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"methoddoc",
         {{0x00, 0xE2, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"methoddesc",
         {{0x00, 0xE3, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"methodattrcount",
         {{0x00, 0xE4, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"methodattrkey",
         {{0x00, 0xE5, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"methodattrval",
         {{0x00, 0xE6, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"fieldname",
         {{0x00, 0xE7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"fielddoc",
         {{0x00, 0xE8, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"fieldattrcount",
         {{0x00, 0xE9, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"fieldattrkey",
         {{0x00, 0xEA, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},
        {"fieldattrval",
         {{0x00, 0xEB, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_reg_imm8}}},

        /* --- Corutinas y fibras (0xEC-0xEF) --- */
        {"yield",
         {{0x00, 0xEC, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},
        {"resume",
         {{0x00, 0xED, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"spawn",
         {{0x00, 0xEE, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        // spawnon r_fn, r_hint
        // - r_hint = -1 (interpretado como int64): Here (mismo scheduler).
        // - r_hint = 0..num_schedulers-1: Pinned al scheduler indicado.
        // Encoding REG (FIXED_4) con 2 registros en byte2 = (reg2<<4)|reg1.
        {"spawnon",
         {{0x00, 0x58, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        // loadmod r_path_addr, r_path_len -- carga dinamica de .velb.
        // Lee path_len bytes desde vm_mem[path_addr] (string utf-8), abre
        // el archivo, lo carga via Loader::load_module_dynamic, y deja en r0:
        //   - 0 si failure (file no existe o vacio o parse error)
        //   - init_pc (>0) del modulo cargado en exito.
        // El caller debe invocar `callvmr r0` para que el prologo de main
        // del nuevo modulo llame __module_init y registre las clases.
        {"loadmod",
         {{0x00, 0x59, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        // unloadmod r_path_addr, r_path_len -- descarga modulo cargado
        // dinamicamente (builtin Vesta `unloadmodule(path) -> i32`).  Mismo
        // formato de operandos que loadmod; R0 = 1 si descargado, 0 si no.
        {"unloadmod",
         {{0x00, 0x6D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        // getmethat / getfldat r_class, r_idx -- variantes reg-reg de
        // getmethod / getfield para iteracion dinamica.  R00 =
        // &cls->methods[idx] o &cls->fields[idx] respectivamente, o 0 si fuera
        // de rango. Builtins Vesta: getMethodAt(cls, i), getFieldAt(cls, i).
        {"getmethat",
         {{0x00, 0x6E, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"getfldat",
         {{0x00, 0x6F, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        // panic r_msg_addr, r_msg_len -- lanza FatalError USER_ABORT con el
        // mensaje leido desde vm_mem.  Capturable via try/catch FatalError.
        {"panic",
         {{0x00, 0x5A, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        // setmethdbg r_method, r_params -- registra debug info para el
        // MethodInfo* (file + start_line).  Consumido por build_stack_trace
        // para mostrar @file:line en cada frame del stack trace de errores.
        {"setmethdbg",
         {{0x00, 0x5B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"swapctx",
         {{0x00, 0xEF, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- Closures GC (0x20-0x21): mkclosure / callclosure ---
         *  mkclosure    r_method, r_env  -> aloca ClosureObject GC y retorna
         * handle en R0 callclosure  r_closure        -> invoca el closure a
         * traves del MethodInfo capturado
         */
        {"mkclosure",
         {{0x00, 0x20, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"callclosure",
         {{0x00, 0x21, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Closures raw / FFI (0x22-0x23): mkrawclosure / callrawclosure ---
         *  mkrawclosure    r_fn, r_env  -> aloca RawClosureObject sin GC y
         * retorna puntero en R0 callrawclosure  r_closure    -> invoca la
         * funcion nativa del RawClosureObject
         */
        {"mkrawclosure",
         {{0x00, 0x22, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"callrawclosure",
         {{0x00, 0x23, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- TCO: tailcall (0x24) ---
         *  tailcall r_fn  -> salto en posicion de cola; reutiliza el frame
         * actual sin crecer la pila
         */
        {"tailcall",
         {{0x00, 0x24, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Nullable: isnull / unwrap (0x25-0x26) ---
         *  isnull r_dst, r_src  -> r_dst = (r_src == 0) ? 1 : 0
         *  unwrap r_dst, r_src  -> r_dst = r_src si no nulo; throw
         * NullPointerException si nulo
         */
        {"isnull",
         {{0x00, 0x25, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"unwrap",
         {{0x00, 0x26, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- Tabla de saltos O(1) (0x27) y cambio de tipo O(n) (0x28) ---
         *  jumptable  r_val, r_table, count  -> salta a table[r_val] si r_val <
         * count typeswitch r_obj, r_table, count  -> salta al handler de la
         * clase de r_obj
         */
        {"jumptable",
         {{0x00, 0x27, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_jumptable}}},
        {"typeswitch",
         {{0x00, 0x28, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_jumptable}}},

        /* --- Async/await nativo (0x29-0x2C) ---
         *  future           -> R0 = GcHandle del FutureObject creado (PENDING)
         *  await   r_fut    -> bloquea el proceso hasta que r_fut sea RESOLVED
         * o REJECTED fulfill r_fut, r_val  -> resuelve r_fut con r_val
         * (RESOLVED) reject  r_fut, r_err  -> rechaza r_fut con r_err
         * (REJECTED)
         */
        {"future",
         {{0x00, 0x29, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},
        {"await",
         {{0x00, 0x2A, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"fulfill",
         {{0x00, 0x2B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"reject",
         {{0x00, 0x2C, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- Aritmetica de puntero de pila (0x2E-0x2F) ---
         *  subsp rsp|rbp, imm  -> RSP/RBP -= imm (reserva frame)
         *  addsp rsp|rbp, imm  -> RSP/RBP += imm (libera frame)
         */
        {"subsp",
         {{0x00, 0x2E, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_spimm}}},
        {"addsp",
         {{0x00, 0x2F, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_spimm}}},

        /* --- Referencias debiles (0x30, 0x32, 0x34) ---
         *  weakref   r_handle  -> R0 = indice opaco en la tabla de weak refs
         *  deref_weak r_dst, r_idx -> r_dst = GcHandle si el objeto sigue vivo,
         * 0 si fue recolectado free_weak r_idx     -> libera la entrada weak en
         * la tabla
         */
        {"weakref",
         {{0x00, 0x30, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"deref_weak",
         {{0x00, 0x32, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"free_weak",
         {{0x00, 0x34, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Lookup inverso ptr -> handle (opcode 0x56) ---
         *  gchandle r_dst, r_src  -> r_dst = GcHandle(host_ptr) o
         * GC_NULL_HANDLE Es el inverso de gcderef.  O(1) via hash map en
         * GcHeap.  Usado por Vesta synchronized(obj) para obtener el handle
         * desde el host_ptr.
         */
        {"gchandle",
         {{0x00, 0x56, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- PID del proceso actual (opcode 0x57) ---
         *  getpid r_dst -> r_dst = (scheduler_id<<32) | (local_pid &
         * 0xFFFFFFFF)
         */
        {"getpid",
         {{0x00, 0x57, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- argv del script (opcodes 0x6B y 0x6C) ---
         *  getargc r_dst         -> r_dst = numero de args del script
         *  getarg  r_dst, r_idx  -> r_dst = GcHandle de StringObject con
         * args[idx] (0 si idx fuera de rango) Builtins Vesta: args_count() y
         * args_get(i).
         */
        {"getargc",
         {{0x00, 0x6B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"getarg",
         {{0x00, 0x6C, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- Move-and-take (0x72) --- primitivo de move-ownership para smart
         * pointers. mvtake r_dst_addr, r_src_addr
         *    -> *(u64*)dst = *(u64*)src; *(u64*)src = 0
         *  Una sola instruccion VM que evita la secuencia LOAD + STORE + CONST
         * 0 + STORE necesaria para implementar move semantics sin overhead.
         */
        {"mvtake",
         {{0x00, 0x72, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- Sprint MMM-ext leak-fix: htrack r_ptr (FIXED_4, REG, 1 operando)
           --- */
        {"htrack",
         {{0x00, 0x7E, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Finalizadores GC: gcfinal r_box, kind (FIXED_4, reg + nibble) ---
         */
        {"gcfinal",
         {{0x00, 0x7F, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_gcfinal}}},

        /* --- gcfinalc / gcfinalu r_box, r_target (FIXED_4, dos regs):
               registran un finalizador diciendo A QUIEN llamar -- el destructor
               de la clase, o el liberador del `unique` --.  Mismo opcode, se
               distinguen por los dos bits altos del byte de control (igual que
               `mods` y `modu`). --- */
        {"gcfinalc",
         {{0x00, 0x8D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_gcfinalc}}},
        {"gcfinalu",
         {{0x00, 0x8D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_gcfinalc}}},

        /* --- gccollect (ZERO, FIXED_2): fuerza minor+major GC del proceso ---
         */
        {"gccollect",
         {{0x00, 0x8C, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},

        /* --- gcfinall (ZERO, FIXED_2): finaliza todo objeto vivo con recurso
         */
        {"gcfinall",
         {{0x00, 0x8E, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},

        /* ---  Z: memoria compartida cross-process (0xA6-0xAD) ---
         *  Stubs registrados para que el assembler acepte estos mnemonicos
         *  emitidos por el lowering  Z.  El runtime ejecuta versiones
         *  simplificadas (no thread-safe cross-process aun) hasta que el
         *  mark/sweep del SharedHeap aterrice.
         */
        {"newobjs",
         {{0x00, 0xA6, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"gcpromote",
         {{0x00, 0xA7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"gcdemote",
         {{0x00, 0xA8, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"atomicld",
         {{0x00, 0xA9, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_atomic_ld}}},
        {"atomicst",
         {{0x00, 0xAA, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_atomic_st}}},
        {"atomiccas",
         {{0x00, 0xAB, InstrSizeMode::FIXED_6, AddressingMode::REG,
           emit_instr_atomic_cas}}},
        {"csel", // dst=cond?a:b (super-instruccion del IrOp::SELECT, interp)
         {{0x00, 0x8F, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_four_reg}}},
        {"mld", // load universal: dst = [base +/- index*scale +/- disp]
         {{0x00, 0x90, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_mem_full}}},
        {"mst", // store universal: [base +/- index*scale +/- disp] = src
         {{0x00, 0x91, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_mem_full}}},
        {"atomicadd",
         {{0x00, 0xAC, InstrSizeMode::FIXED_6, AddressingMode::REG,
           emit_instr_atomic_add}}},
        {"sharedstat",
         {{0x00, 0xAD, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},

        /* --- Super-instrucciones ALU 3-operandos (0x73-0x7B) ---
         *  Combinan `mov rd, rs1; OP rd, rs2` en una sola instruccion VM.
         *  Reduce dispatch + decode para el patron mas frecuente del 2-address
         *  codegen cuando el regalloc no puede coalescer dst con src1.
         *
         *  Encoding FIXED_4: [0x00][opcode2][byte2][byte3]
         *      byte2 = (r_src1 << 4) | r_dst
         *      byte3 = (r_src2 << 4) | 0  (flags reservados)
         *
         *  Opcodes 0x73-0x75: signed (adds3, subs3, muls3).
         *  Opcodes 0x76-0x78: unsigned (addu3, subu3, mulu3).
         *  Opcodes 0x79-0x7B: bitwise (and3, or3, xor3) -- sin signo.
         */
        // Memoria masiva (0xB6-0xB9).  Reusan emit_instr_alu3: su formato
        // fisico ES "3 registros" con el layout de nibbles estandar
        // (byte2=(rB<<4)|rA, byte3=(rC<<4)), identico al que necesitan.
        {"memset",
         {{0x00, 0xB6, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"memseth",
         {{0x00, 0xB7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"memcpy",
         {{0x00, 0xB8, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"memcpyh",
         {{0x00, 0xB9, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"adds3",
         {{0x00, 0x73, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"subs3",
         {{0x00, 0x74, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"muls3",
         {{0x00, 0x75, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"addu3",
         {{0x00, 0x76, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"subu3",
         {{0x00, 0x77, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"mulu3",
         {{0x00, 0x78, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"and3",
         {{0x00, 0x79, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"or3",
         {{0x00, 0x7A, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},
        {"xor3",
         {{0x00, 0x7B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_alu3}}},

        /* --- Super-instruccion LOAD zero-extend (0x7C VM, 0x7D HOST) ---
         *  loadz  rd_sized, r_src_ptr   - carga N-bit desde vm_mem,
         * zero-extiende a 64b. loadzh rd_sized, r_src_ptr   - igual pero desde
         * memoria HOST. Sustituye el patron `mov rd,0 + mov rd_sized,[rs]` (10
         * bytes -> 4 bytes, 2 instrucciones VM -> 1).  N se infiere del tamano
         * del registro destino (r11=64b, r11d=32b, r11w=16b, r11b=8b).
         */
        {"loadz",
         {{0x00, 0x7C, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_loadz}}},
        {"loadzh",
         {{0x00, 0x7D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_loadz}}},

        /* --- Monitor / sincronizacion (0x35-0x39) ---
         *  monenter r_handle  -> adquiere el monitor del objeto GC
         *  monexit  r_handle  -> libera el monitor del objeto GC
         *  monwait  r_handle  -> libera el monitor y suspende el proceso
         *  monnoti  r_handle  -> despierta un proceso de la cola de espera
         *  monnota  r_handle  -> despierta todos los procesos de la cola
         */
        {"monenter",
         {{0x00, 0x35, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"monexit",
         {{0x00, 0x36, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"monwait",
         {{0x00, 0x37, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"monnoti",
         {{0x00, 0x38, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"monnota",
         {{0x00, 0x39, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Genericos en tiempo de ejecucion (0x3A) ---
         *  specialize r_dst, r_class, r_types
         *  byte2 = (r_dst<<4)|r_class,  byte3 = (r_types<<4)|count
         *  count se pasa como tercer operando inmediato (0-15)
         */
        {"specialize",
         {{0x00, 0x3A, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_jumptable}}},

        /* --- Instrucciones distribuidas VDP (0x3B-0x3E) ---
         *  rspawn  r_fn, r_node  -> R0 = GcHandle del FutureObject
         *  msgsend r_pid, r_addr, r_len
         *  msgrecv r_buf, r_max  -> R0 = bytes recibidos
         *  memsync r_params
         */
        {"rspawn",
         {{0x00, 0x3B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"msgsend",
         {{0x00, 0x3C, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_three_reg}}},
        {"msgrecv",
         {{0x00, 0x3D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"memsync",
         {{0x00, 0x3E, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},

        /* --- Punto flotante escalar y vectorial (0xF0-0xFC) --- */
        {"fmov",
         {{0x00, 0xF0, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fadd",
         {{0x00, 0xF1, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fadd.pd",
         {{0x00, 0xF1, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fadd.ps",
         {{0x00, 0xF1, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fsub",
         {{0x00, 0xF2, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fsub.pd",
         {{0x00, 0xF2, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fsub.ps",
         {{0x00, 0xF2, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fmul",
         {{0x00, 0xF3, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fmul.pd",
         {{0x00, 0xF3, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fmul.ps",
         {{0x00, 0xF3, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fdiv",
         {{0x00, 0xF4, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fdiv.pd",
         {{0x00, 0xF4, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fdiv.ps",
         {{0x00, 0xF4, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fcmp",
         {{0x00, 0xF5, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fcmp.pd",
         {{0x00, 0xF5, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fcmp.ps",
         {{0x00, 0xF5, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fsqrt",
         {{0x00, 0xF6, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fsqrt.pd",
         {{0x00, 0xF6, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fsqrt.ps",
         {{0x00, 0xF6, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fabs",
         {{0x00, 0xF7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fabs.pd",
         {{0x00, 0xF7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fabs.ps",
         {{0x00, 0xF7, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fneg",
         {{0x00, 0xF8, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fneg.pd",
         {{0x00, 0xF8, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fneg.ps",
         {{0x00, 0xF8, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fcvt",
         {{0x00, 0xF9, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_fcvt}}},
        {"fcvt.ps",
         {{0x00, 0xF9, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_fcvt}}},
        {"fextend",
         {{0x00, 0x5C, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fnarrow",
         {{0x00, 0x5D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fmadd",
         {{0x00, 0x5F, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_fmadd}}},
        {"fmadd.ps",
         {{0x00, 0x5F, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_fmadd}}},
        /* Sprint string-perf-5: FP ops escalares nativas en interp. */
        {"fmin",
         {{0x00, 0x80, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fmin.ps",
         {{0x00, 0x80, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fmax",
         {{0x00, 0x81, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fmax.ps",
         {{0x00, 0x81, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"ffloor",
         {{0x00, 0x82, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"ffloor.ps",
         {{0x00, 0x82, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fceil",
         {{0x00, 0x83, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fceil.ps",
         {{0x00, 0x83, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fround",
         {{0x00, 0x84, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"fround.ps",
         {{0x00, 0x84, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"ftrunc",
         {{0x00, 0x85, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        {"ftrunc.ps",
         {{0x00, 0x85, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_freg}}},
        /* Sprint string-perf-5: bitcast GP<->ZMM directo (sin memoria). */
        {"bitg2z",
         {{0x00, 0x86, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_bitcast_zg}}},
        {"bitz2g",
         {{0x00, 0x87, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_bitcast_zg}}},
        {"fmowi",
         {{0x00, 0xFA, InstrSizeMode::FIXED_11, AddressingMode::INMED,
           emit_instr_fmowi}}},
        {"fload",
         {{0x00, 0xFB, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_fmem}}},
        {"fstore",
         {{0x00, 0xFC, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_fmem}}},

        /* --- NOP --- */
        {"nop1",
         {{0x33, 0x00, InstrSizeMode::FIXED_1, AddressingMode::NONE, nullptr}}},
        {"nop2",
         {{0x00, 0x33, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},

        /* callnr <reg>  - llamada nativa por registro (sin retorno). */
        {"callnr",
         {{0x55, 0x00, InstrSizeMode::FIXED_1, AddressingMode::REG, nullptr}}},

        /* ret - retorna de una subrutina. */
        {"ret",
         {{0xC3, 0x00, InstrSizeMode::FIXED_1, AddressingMode::NONE, nullptr}}},

        /* --- Protocolo distribuido (opcode extendido 0x00 0x00..0x03) --- */
        {"edmw4",
         {{0x00, 0x00, InstrSizeMode::FIXED_4, AddressingMode::NONE, nullptr}}},
        {"edmw6",
         {{0x00, 0x01, InstrSizeMode::FIXED_4, AddressingMode::NONE, nullptr}}},
        {"edm",
         {{0x00, 0x02, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},
        {"hlt",
         {{0x00, 0x03, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},

        /*
         * Instrucciones aritmeticas con multiples variantes.
         * Ejemplo de busqueda de variante:
         *
         *   auto& variants = InstrTable["adds"];
         *   for (auto& v : variants) {
         *       if (matches_operands(v.sizeMode, operands))
         *           return v;
         *   }
         *
         * Cada grupo expone 3 variantes:
         *   1. reg, reg    -> FIXED_4 / REG
         *   2. reg, [mem]  -> MIXED_SIZE / INMED
         *   3. reg, SIB    -> FIXED_6 / SIB
         */

        /* --- ADDS / ADDU (suma con/sin signo) --- */
        {"adds",
         {{0x00, 0x05, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x06, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x07, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},
        {"addu",
         {{0x00, 0x05, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x06, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x07, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},

        /* --- SUBS / SUBU (resta con/sin signo) --- */
        {"subu",
         {{0x00, 0x08, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x09, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x0A, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},
        {"subs",
         {{0x00, 0x08, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x09, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x0A, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},

        /* --- MULS / MULU (multiplicacion con/sin signo) --- */
        {"muls",
         {{0x00, 0x0B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x0C, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x0D, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},
        {"mulu",
         {{0x00, 0x0B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x0C, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x0D, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},

        /* --- DIVS / DIVU (division con/sin signo) --- */
        {"divu",
         {{0x00, 0x0E, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x0F, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x10, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},
        {"divs",
         {{0x00, 0x0E, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x0F, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x10, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},

        /* --- CMPS / CMPU (comparacion con/sin signo) --- */
        {
            "cmpu",
            {
                {0x00, 0x11, InstrSizeMode::FIXED_4, AddressingMode::REG,
                 emit_instr_reg},
                {0x00, 0x12, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
                 emit_instr_inmed},
                {0x00, 0x13, InstrSizeMode::FIXED_6, AddressingMode::SIB,
                 emit_instr_sib},
            },
        },
        {
            "cmps",
            {
                {0x00, 0x11, InstrSizeMode::FIXED_4, AddressingMode::REG,
                 emit_instr_reg},
                {0x00, 0x12, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
                 emit_instr_inmed},
                {0x00, 0x13, InstrSizeMode::FIXED_6, AddressingMode::SIB,
                 emit_instr_sib},
            },
        },

        /* --- MODS / MODU (modulo con/sin signo) --- */
        {"modu",
         {{0x00, 0x40, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x41, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x42, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},
        {"mods",
         {{0x00, 0x40, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x00, 0x41, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
           emit_instr_inmed},
          {0x00, 0x42, InstrSizeMode::FIXED_6, AddressingMode::SIB,
           emit_instr_sib}}},

        /* --- SETCC r_dst, cond_literal: escribir condicion de flags como 0 o 1
           --- */
        {"setcc",
         {{0x00, 0x43, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_setcc}}},

        /* --- SEXT r_dst, N: sign-extiende r_dst desde N bits (8/16/32) a 64.
           1 instr en vez de mov+shl+sar.  b2=r_dst, b3=N. --- */
        {"sext",
         {{0x00, 0x92, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_sext}}},

        /* --- TRYENTER / TRYLEAVE: frames de excepcion dinamicos --- */
        {"tryenter",
         {{0x00, 0x44, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"tryleave",
         {{0x00, 0x45, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},

        /* --- STRMAKE / STRLEN / STRCAT / STRCMP / STRCONV / STRRAW:
           instrucciones de string --- */
        {"strmake",
         {{0x00, 0x46, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_three_reg}}},
        {// strmake_h: variante de strmake que lee de memoria HOST (puntero
         // crudo de malloc/str_cstr/etc.) en lugar de memoria VM.  Mismo
         // encoding que strmake; cambia solo la semantica del read en runtime.
         "strmake_h",
         {{0x00, 0x5E, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_three_reg}}},
        {"strlen",
         {{0x00, 0x47, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strcat",
         {{0x00, 0x48, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_three_reg}}},
        {"strcmp",
         {{0x00, 0x49, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_three_reg}}},
        {"strconv",
         {{0x00, 0x4A, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_strconv}}},
        {"strraw",
         {{0x00, 0x4B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strslice",
         {{0x00, 0x4C, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_three_reg}}},
        {"strflat",
         {{0x00, 0x4D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strhash",
         {{0x00, 0x4E, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strintern",
         {{0x00, 0x4F, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strgetenc",
         {{0x00, 0x50, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strgetbytes",
         {{0x00, 0x51, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strgetkind",
         {{0x00, 0x52, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strreserve",
         {{0x00, 0x53, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},
        {"strfinalize",
         {{0x00, 0x54, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_str_two_reg}}},

        /* --- MOV: transferencia de datos --- */
        {
            "mov",
            {
                {0x00, 0x14, InstrSizeMode::FIXED_4, AddressingMode::REG,
                 emit_instr_mov_reg},
                {0x00, 0x15, InstrSizeMode::MIXED_SIZE, AddressingMode::INMED,
                 emit_instr_mov_inmed},
                {0x00, 0x16, InstrSizeMode::FIXED_6, AddressingMode::SIB,
                 emit_instr_mov_sib},
            },
        },

        /* --- MOVH: variante SIB que accede a memoria HOST.
         *
         * Usa el mismo opcode que MOV SIB (0x00 0x16); el bit s del ctrl
         * byte (encolado por is_host_sib() en emit_instr_sib) selecciona
         * el modo MOVH en el ejecutor.  Solo se admite en modo SIB
         * (con [reg]); registro-registro o inmediato directos siguen
         * usando 'mov'.  Lo emite el frontend Vesta para LOAD/STORE de
         * punteros marcados is_host_ptr (e.g. resultado de malloc).
         */
        {
            "movh",
            {
                {0x00, 0x16, InstrSizeMode::FIXED_6, AddressingMode::SIB,
                 emit_instr_mov_sib},
            },
        },

        /* --- MOVC / MOVCH: movimiento con bandera de modo (VM mem / host mem)
           --- */
        {"movc",
         {
             /* movc reg1, [reg2], flag  ||  movc [reg1], reg2, flag -> acceso
                memoria VM */
             {0x00, 0x1E, InstrSizeMode::FIXED_4, AddressingMode::MEM,
              emit_instr_movc},
             /* movc reg1, reg2, flag -> modo registro a registro */
             {0x00, 0x1F, InstrSizeMode::FIXED_4, AddressingMode::REG,
              emit_instr_movc},
         }},
        {"movch",
         {
             /* movch reg1, [reg2], flag  ||  movch [reg1], reg2, flag -> acceso
                memoria host */
             {0x00, 0x1E, InstrSizeMode::FIXED_4, AddressingMode::MEM,
              emit_instr_movc},
         }},

        /* --- Logica bit a bit --- */

        /* Cada una con DOS variantes: registro-registro en la tabla extendida,
         * como siempre, y memoria SIB en la PRIMARIA (0x60-0x65).
         *
         * La forma con memoria cubre las dos direcciones con el mismo opcode,
         * porque el bit 4 del ctrl las distingue y `emit_instr_sib` lo pone
         * segun cual de los dos operandos sea la memoria:
         *
         *     and r1, [r2 + r3*4]      ->  r1 &= [mem]      (direction = 0)
         *     and [r2 + r3*4], r1      ->  [mem] &= r1      (direction = 1)
         *
         * La segunda es leer-modificar-escribir en UNA instruccion: hoy son
         * tres (cargar, operar, guardar). */
        {"and",
         {{0x00, 0x17, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x60, 0x00, InstrSizeMode::FIXED_4, AddressingMode::SIB,
           emit_instr_sib}}},
        {"or",
         {{0x00, 0x18, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x61, 0x00, InstrSizeMode::FIXED_4, AddressingMode::SIB,
           emit_instr_sib}}},
        {"xor",
         {{0x00, 0x19, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x62, 0x00, InstrSizeMode::FIXED_4, AddressingMode::SIB,
           emit_instr_sib}}},
        {"not",
         {{0x00, 0x1A, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_one_reg}}},
        {"shl",
         {{0x00, 0x1B, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x63, 0x00, InstrSizeMode::FIXED_4, AddressingMode::SIB,
           emit_instr_sib}}},
        {"shr",
         {{0x00, 0x1C, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x64, 0x00, InstrSizeMode::FIXED_4, AddressingMode::SIB,
           emit_instr_sib}}},
        {"sar",
         {{0x00, 0x1D, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg},
          {0x65, 0x00, InstrSizeMode::FIXED_4, AddressingMode::SIB,
           emit_instr_sib}}},

        /* loop <label>  - decrementa contador y salta si != 0. */
        {
            "loop",
            {
                {0x00, 0x31, InstrSizeMode::FIXED_8, AddressingMode::INMED,
                 nullptr},
            },
        },

        /* calln <addr>  - llamada a funcion nativa por direccion inmediata. */
        {
            "calln",
            {
                {0x00, 0x55, InstrSizeMode::FIXED_10, AddressingMode::INMED,
                 emit_instr_calln_inmmed},
            },
        },

        /* --- Meta-programacion OOP (clases en runtime) ---
         *
         * Cada instruccion toma (r_arg, r_params): el primero es el destino
         * del resultado o la clase a modificar, el segundo apunta a una
         * struct DefXxxParams en memoria VM.  El ejecutor lee la struct y
         * delega al ClassRegistry del Loader.  Encoding FIXED_4 / REG mode
         * compartido con el resto de instrucciones two-reg.
         */
        {"defclass",
         {{0x00, 0xC9, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"deffield",
         {{0x00, 0xCA, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"defmethod",
         {{0x00, 0xCB, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"findclass",
         {{0x00, 0xCC, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"findmethod",
         {{0x00, 0xCD, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"findfield",
         {{0x00, 0xCF, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"callm",
         {{0x00, 0xFD, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"callitf",
         {{0x00, 0xAE, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_reg}}},
        {"proceed",
         {{0x00, 0xFE, InstrSizeMode::FIXED_2, AddressingMode::NONE, nullptr}}},
        // addadvice: 3 operandos (r_target, r_advice, kind imm).  Usa
        // emit_instr_addadvice (mismo patron que jumptable: byte2 con dos
        // registros + byte3 con un valor inmediato pequeno).
        {"addadvice",
         {{0x00, 0xCE, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_addadvice}}},
        // getstatic / setstatic: 3 operandos (2 regs + offset_u32).  FIXED_8.
        // Encoding fisico [0x00][opcode2][regs_byte][_pad8][offset_u32_LE]
        // donde regs_byte = (r0<<4) | r1.  Ver exec_instr_getstatic /
        // exec_instr_setstatic en src/runtime/exec_instruction_meta.cpp.
        {"getstatic",
         {{0x00, 0x60, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_static}}},
        {"setstatic",
         {{0x00, 0x61, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_static}}},
        // FFI runtime dinamico: dlopen / dlsym / callni (FIXED_4).
        // Encoding [0x00][opcode2][b2][b3] con regs empaquetados por nibble.
        // Ver emit_instr_dlopen / emit_instr_dlsym / emit_instr_callni.
        {"dlopen",
         {{0x00, 0x62, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_dlopen}}},
        {"dlsym",
         {{0x00, 0x63, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_dlsym}}},
        {"callni",
         {{0x00, 0x64, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_callni}}},

        // Optimizaciones del frontend Vesta (slots reservados 0x65-0x67):
        //   gcallocp   = GC alloc + host_ptr en 1 instr (closure env heap).
        //   spawnargs  = spawn que copia R1..R[R15] del padre al child.
        //   fulfillhlt = fulfill + hlt fusionados (path critico @Async helper).
        {"gcallocp",
         {{0x00, 0x65, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_gcallocp}}},
        {"spawnargs",
         {{0x00, 0x66, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_spawnargs}}},
        {"fulfillhlt",
         {{0x00, 0x67, InstrSizeMode::FIXED_4, AddressingMode::REG,
           emit_instr_fulfillhlt}}},

        // Optimizaciones hot loops (slots 0x68-0x6A):
        //   cmpjmp.cc r_a, r_b, label   = cmps + jmp.cc fusionados (signed).
        //   cmpjmpu.cc r_a, r_b, label  = cmpu + jmp.cc fusionados (unsigned).
        //   decjnz r_counter, label     = decremento + branch-if-not-zero.
        // Encoding FIXED_8: [0x00][opcode2][b2][cond/_pad][target_u32_LE].
        // El emitter usa el sufijo .jX del mnemonic para determinar @c cond.
        // Todas las variantes de cmpjmp.cc / cmpjmpu.cc comparten opcode2.
        {"cmpjmp.je",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jz",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jne",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jnz",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jcs",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jb",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jcc",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jae",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jmi",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jpl",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jvs",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jvc",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jhi",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jls",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jge",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jlt",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jgt",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},
        {"cmpjmp.jle",
         {{0x00, 0x68, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_signed}}},

        {"cmpjmpu.je",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jz",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jne",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jnz",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jcs",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jb",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jcc",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jae",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jmi",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jpl",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jvs",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jvc",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jhi",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jls",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jge",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jlt",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jgt",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},
        {"cmpjmpu.jle",
         {{0x00, 0x69, InstrSizeMode::FIXED_8, AddressingMode::REG,
           emit_instr_cmpjmp_unsigned}}},

        // decjnz: 2 operandos (reg, label).  El select_variant detecta
        // ops[0]=reg + ops[1]=AnnotationNode como modo INMED, NO REG.
        {"decjnz",
         {{0x00, 0x6A, InstrSizeMode::FIXED_8, AddressingMode::INMED,
           emit_instr_decjnz}}},

        // fastpush <mask16> / fastpop <mask16>: empuja/desempila multiples regs
        // en una sola instruccion segun el bitmask de 16 bits (bit r =
        // r0..r15).
        // Encoding FIXED_4: [0x00][opcode2][mask_lo][mask_hi].
        {"fastpush",
         {{0x00, 0x70, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_fastmask}}},
        {"fastpop",
         {{0x00, 0x71, InstrSizeMode::FIXED_4, AddressingMode::INMED,
           emit_instr_fastmask}}},
};
#endif // VESTA_DEFINE_INSTR_TABLE

/**
 * @class Assembler
 * @brief Convierte un AST generado por el parser en bytecode ejecutable para la
 * VM.
 *
 * El ensamblado se realiza en 3 fases conceptuales (la 2.a y 3.a estan
 * fusionadas):
 *  1. Primera pasada  (@c first_pass)  : recorre el AST para registrar todos
 * los simbolos (labels, secciones, directivas @e global / @e extern) y calcular
 *     sus offsets definitivos.  Sin esta fase no es posible resolver saltos
 * forward.
 *  2. Segunda+tercera pasada (@c emit_pass) : emite datos (directivas @e
 * db/dw/dd/dq) e instrucciones en el mismo recorrido, ahora que los simbolos ya
 * tienen direccion conocida.
 *
 * Las relocalizaciones pendientes (saltos a simbolos de otros espacios) se
 * registran en @c ctx y se resuelven durante el enlazado posterior.
 *
 * @note El ensamblador genera un unico buffer de bytecode secuencial.  El
 * linker es responsable de combinar multiples buffers en un ejecutable final.
 */
class Assembler {
  public:
    /// Tabla de simbolos construida en la primera pasada: nombre -> puntero a
    /// Label.
    std::unordered_map<std::string, Label *> symbol_table;

    /// Buffer de salida donde se escribe el bytecode final byte a byte.
    ByteWriter output;

    /// Contexto global del ensamblador: espacios, secciones, labels y
    /// relocalizaciones.
    Context ctx{};

    /// Seccion actualmente activa; cambia al procesar directivas @e @Section.
    Section *current_section = nullptr;

    /// Label actualmente analizada; se usa como cursor interno durante la
    /// emision.
    Label *current_label = nullptr;

    /**
     * @brief Constructor del ensamblador.
     *
     * Inicializa las estructuras internas, vacia el buffer de salida y
     * establece la direccion base por defecto (0x0000).
     */
    Assembler();

    /**
     * @brief Calcula el tamano final de cada label tras la primera pasada.
     *
     * Debe llamarse despues de @c first_pass y antes de @c emit_pass para
     * que cada label conozca cuantos bytes ocupa en el bytecode.
     */
    void compute_label_sizes();

    /**
     * @brief Ensambla un AST completo y devuelve el bytecode resultante.
     *
     * Ejecuta las 3 fases en orden:
     *  1. @c first_pass  sobre cada nodo raiz.
     *  2. @c compute_label_sizes.
     *  3. @c emit_pass sobre cada nodo raiz.
     *
     * @param ast Lista de nodos raiz del AST generado por el parser.
     * @return Vector de bytes con el bytecode listo para enlazar o ejecutar.
     */
    std::vector<uint8_t>
    assemble(const std::vector<std::unique_ptr<vm::ASTNode>> &ast);

    /**
     * @brief Segunda+tercera pasada: emite datos e instrucciones en el buffer.
     *
     * La segunda y tercera fase estan fusionadas porque, una vez que todos los
     * simbolos tienen offsets definitivos (tras @c first_pass), datos e
     * instrucciones pueden emitirse en un unico recorrido.
     *
     * @param node Nodo actual del AST a procesar.
     */
    void emit_pass(const vm::ASTNode *node);

    /**
     * @brief Devuelve el tamano en bytes de una directiva de datos.
     *
     * @param dir Nombre de la directiva: "db" (1), "dw" (2), "dd" (4), "dq"
     * (8), "ptr" (8).
     * @return Numero de bytes que ocupa un elemento de esa directiva.
     */
    size_t size_of_directive(const std::string &dir) const;

    /**
     * @brief Emite un valor numerico segun la directiva indicada.
     *
     * El valor se escribe en formato little-endian en el buffer de salida
     * y se avanza el offset interno del ensamblador.
     *
     * @param dir   Directiva de datos ("db", "dw", "dd", "dq", "ptr").
     * @param value Valor numerico ya evaluado que se escribira.
     */
    void emit_directive(const std::string &dir, uint64_t value);

    /**
     * @brief Emite los datos de un nodo @c DataDecl del AST.
     *
     * Las cadenas de texto se emiten caracter a caracter (sin nulo terminal
     * a menos que sea explicito).  Las expresiones numericas se evaluan con
     * @c eval_expr y se pasan a @c emit_directive.
     *
     * @param data Nodo @c DataDecl del AST con la lista de valores a emitir.
     */
    void emit_data(const vm::DataDecl *data);

    /**
     * @brief Selecciona la variante correcta de una instruccion segun sus
     * operandos.
     *
     * Varias instrucciones (mov, add, sub...) tienen multiples codificaciones.
     * Esta funcion recorre el vector de variantes en @c InstrTable y elige la
     * que coincide con el modo de direccionamiento de los operandos
     * proporcionados.
     *
     * @param mnemonic Nombre de la instruccion (p.ej. "adds", "mov", "jmp").
     * @param ops      Lista de operandos del nodo instruccion en el AST.
     * @return Referencia constante a la @c InstrInfo de la variante
     * seleccionada.
     * @throws std::runtime_error si no existe ninguna variante compatible.
     */
    const InstrInfo &
    select_variant(const std::string &mnemonic,
                   const std::vector<std::unique_ptr<vm::ASTNode>> &ops) const;

    /**
     * @brief Emite una instruccion completa al buffer de salida.
     *
     * Escribe opcode1, luego opcode2 si la instruccion es extendida
     * (opcode1==0x00), y a continuacion los operandos segun el formato definido
     * en @c InstrInfo.
     *
     * @param instr Nodo @c Instruction del AST con mnemotecnico y operandos.
     */
    void emit_instruction(const vm::Instruction *instr);

    /**
     * @brief Evalua un operando del AST y devuelve su valor numerico de 64
     * bits.
     *
     * Resuelve registros, inmediatos, referencias a labels y expresiones
     * compuestas delegando en @c eval_expr cuando el operando es un @c
     * ExprNode.
     *
     * @param op Nodo operando del AST.
     * @return Valor numerico de 64 bits sin signo del operando evaluado.
     */
    uint64_t eval_operand(const vm::ASTNode *op);

    /**
     * @brief Evalua una expresion del AST y devuelve su valor numerico.
     *
     * Soporta:
     *  - Literales numericos enteros y hexadecimales.
     *  - Referencias a labels (se sustituyen por su offset).
     *  - Expresiones binarias con operadores: +, -, *, /.
     *
     * @param expr Nodo @c ExprNode del AST que representa la expresion.
     * @return Valor numerico de 64 bits resultado de la evaluacion.
     * @throws std::runtime_error si la expresion contiene un operador no
     * soportado.
     */
    uint64_t eval_expr(vm::ExprNode *expr);

    /**
     * @brief Primera pasada: recoleccion de simbolos y calculo de offsets.
     *
     * Recorre el AST y registra en @c ctx todas las labels, secciones y
     * espacios, asignando a cada uno su offset definitivo en el bytecode.
     * Tambien procesa directivas pseudo-instruccion (@e global, @e extern,
     * etc.).
     *
     * @param node   Nodo actual del AST a analizar.
     * @param offset Offset acumulado (se actualiza en cada llamada recursiva).
     */
    void first_pass(const vm::ASTNode *node, uint64_t &offset);

    /**
     * @brief Cierra el tramo de flujo de la seccion activa (primera pasada).
     *
     * Fija @c size_real de @c current_section como el numero de bytes emitidos
     * mientras esa seccion estuvo activa.  Debe llamarse ANTES de alinear el
     * flujo para la siguiente seccion, de modo que el relleno de alineacion no
     * se contabilice como contenido de la seccion que termina.
     *
     * @param offset Offset actual dentro del flujo de bytecode del modulo.
     */
    void close_section_layout(uint64_t offset);

    /**
     * @brief Abre el tramo de flujo de la seccion activa (primera pasada).
     *
     * Alinea @p offset a la alineacion de @c current_section y registra ahi su
     * @c stream_offset.  El relleno introducido debe reproducirlo despues
     * @c emit_pass como bytes reales, ya que la imagen .velb es plana y el
     * offset del flujo es la direccion virtual de la seccion.
     *
     * @param offset Offset dentro del flujo; se avanza hasta quedar alineado.
     */
    void begin_section_layout(uint64_t &offset);

    /**
     * @brief Aplica una anotacion del AST al contexto del ensamblador.
     *
     * Despacha el procesado de la anotacion a traves de @c annotation_handlers,
     * que modifica @c ctx segun la directiva anotacion (@e @SpaceAddress,
     * @e @Section, @e @Format, @e @InitPc, @e @Import...).
     *
     * @param annotation Nodo @c AnnotationNode del AST con nombre y argumentos.
     */
    void apply_annotation(const vm::AnnotationNode *annotation);

    /**
     * @brief Procesa una directiva pseudo-instruccion (global, extern,
     * bits...).
     *
     * Interpreta el nodo instruccion como una directiva de control del
     * ensamblador en lugar de una instruccion ejecutable y actualiza el estado
     * interno del ensamblador en consecuencia.
     *
     * @param instr Nodo @c Instruction del AST cuyo mnemotecnico esta en
     *              @c PseudoInstructions.
     */
    void apply_directive(const vm::Instruction *instr);

  private:
};

/**
 * @brief Expande recursivamente los nodos @c ImportNode de un AST,
 * sustituyendolos por los nodos del archivo importado.
 *
 * Algoritmo (solo movimientos, sin copias ni duplicacion de nodos):
 *  1. Recorre @p ast nodo a nodo.
 *  2. Si encuentra un @c ImportNode cuyo archivo no ha sido procesado todavia:
 *     a. Lee el archivo fuente.
 *     b. Lo lexifica y parsea obteniendo un nuevo AST.
 *     c. Llama a @c resolve_imports recursivamente sobre el AST importado
 *        (para resolver imports anidados).
 *     d. Inserta todos los nodos resultantes en el AST final.
 *  3. Si el archivo ya fue importado (@p imported contiene su ruta), lo ignora
 *     para evitar inclusiones multiples e importaciones ciclicas.
 *  4. Los nodos que no son @c ImportNode se copian directamente al resultado.
 *  5. Al terminar, @p ast es reemplazado por el vector resultado fusionado.
 *
 * Ejemplo:
 * @verbatim
 *   AST original : [A, B, import C, D]
 *   AST de C     : [X, Y, Z]
 *   AST final    : [A, B, X, Y, Z, D]
 * @endverbatim
 *
 * @warning Si algun nodo guarda punteros laterales a otros nodos del mismo AST
 *          (no solo a sus hijos), esas referencias quedaran invalidadas tras el
 *          movimiento.  En un AST puramente jerarquico esto no supone ningun
 * problema.
 *
 * @param ast      AST original que puede contener nodos @c ImportNode; se
 * modifica in-place reemplazando su contenido por el AST expandido.
 * @param imported Conjunto de rutas de archivo ya procesadas; se actualiza
 * durante la recursion para evitar importaciones duplicadas.
 */
/**
 * @brief Expande recursivamente los nodos ImportNode de un AST.
 *
 * Orden de busqueda para cada import relativo:
 *  1. @p base_dir : directorio del archivo fuente que contiene el import.
 *  2. @p search_paths : lista adicional de directorios (CWD, dir del
 * ejecutable, etc.).
 *  3. La ruta tal cual (si es absoluta o el CWD ya la contiene).
 *
 * @param ast          AST a expandir; se modifica en el lugar.
 * @param imported     Rutas ya procesadas (evita reimportaciones y ciclos).
 * @param base_dir     Directorio del archivo que contiene este AST.
 * @param search_paths Directorios adicionales donde buscar los imports.
 */
static void resolve_imports(std::vector<std::unique_ptr<vm::ASTNode>> &ast,
                            std::unordered_set<std::string> &imported,
                            const std::string &base_dir = "",
                            const std::vector<std::string> &search_paths = {}) {
    std::vector<std::unique_ptr<vm::ASTNode>> result;

    for (auto &node : ast) {
        if (auto imp = vm::node_as<vm::ImportNode>(node.get())) {
            const std::string &raw = imp->filename;

            // resolver la ruta del archivo importado con orden de busqueda:
            std::string resolved;
            auto try_path = [&](const std::string &dir) {
                if (!resolved.empty()) return;
                std::filesystem::path p =
                    (std::filesystem::path(dir) / raw).lexically_normal();
                if (std::filesystem::exists(p)) resolved = p.string();
            };

            // 1. directorio del archivo fuente actual
            if (!base_dir.empty()) try_path(base_dir);
            // 2. rutas de busqueda adicionales (CWD, dir del ejecutable, etc.)
            for (auto &sp : search_paths)
                try_path(sp);
            // 3. la ruta tal cual (absoluta o relativa al CWD vigente)
            if (resolved.empty() && std::filesystem::exists(raw))
                resolved = raw;

            if (resolved.empty()) {
                std::string searched = base_dir.empty() ? "." : base_dir;
                for (auto &sp : search_paths)
                    searched += ", " + sp;
                throw std::runtime_error(
                    "No se pudo encontrar el archivo importado: '" + raw +
                    "'\n  Directorios buscados: " + searched);
            }

            /* evitar importaciones multiples del mismo archivo */
            if (imported.find(resolved) != imported.end()) continue;
            imported.insert(resolved);

            /* leer archivo fuente importado */
            std::ifstream f(resolved);
            if (!f.is_open()) {
                throw std::runtime_error(
                    "No se pudo abrir el archivo importado: " + resolved);
            }
            std::string code((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());

            /* lex + parse del codigo importado */
            vm::Lexer lx(code);
            vm::Parser px(lx);
            auto imported_ast = px.parse();

            /* directorio del archivo importado como base para sus propios
             * imports */
            std::string imported_base =
                std::filesystem::path(resolved).parent_path().string();

            /* expandir imports anidados con la misma lista de search_paths */
            resolve_imports(imported_ast, imported, imported_base,
                            search_paths);

            /* insertar nodos del archivo importado en el resultado */
            for (auto &n : imported_ast)
                result.push_back(std::move(n));
        } else {
            /* nodo normal: copiar directamente al resultado */
            result.push_back(std::move(node));
        }
    }

    /* sustituir el AST original por el resultado expandido */
    ast = std::move(result);
}

/**
 * @brief Los mnemonicos que el codificador sabe convertir a bytes.
 *
 * Existe para lo mismo que @ref vm::instruction_set_names: poder comparar las
 * tres listas que tienen que decir lo mismo.
 *
 * @return Nombres, sin orden garantizado.
 */
inline std::vector<std::string> instr_table_names() {
    std::vector<std::string> v;
    v.reserve(InstrTable.size());
    for (const auto &e : InstrTable)
        v.push_back(e.first);
    return v;
}
} // namespace Assembly::Bytecode

#endif // PARSER_TO_BYTECODE_H
