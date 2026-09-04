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
 * @file disasm.cpp
 * @brief Implementacion del desensamblador de bytecode VestaVM.
 *
 * Implementa las tres funciones publicas del modulo disasm:
 *   - disasm_velb():   carga un .velb mediante el Loader y desensambla desde el
 * entrypoint.
 *   - disasm_bytes():  desensambla un buffer de bytes en memoria sin necesitar
 * la VM.
 *   - print_instruction(): formatea e imprime una instruccion decodificada con
 * colores opcionales.
 *
 * Codificaciones soportadas:
 *   - Tabla primaria (1 byte): inc/dec (0x04), callvm (0x10), jmp (0x11), push
 * (0x12), pop (0x13), xchg (0x14), jmpr (0x15), callvmr (0x16).
 *   - Tabla extendida (prefijo 0x00): MOV reg-reg (0x14), MOV imm (0x15), MOV
 * SIB (0x16), ALU con tres modos (0x05-0x13), logica (0x17-0x1D), MOVC/MOVCH
 * (0x1E-0x1F), HLT (0x03), corutinas yield/resume/spawn/swapctx (0xEC-0xEF),
 *     flotante ZMM:
 * fmow/fmov/fadd/fsub/fmul/fdiv/fcmp/fsqrt/fabs/fneg/fcvt/fmowi/fload/fstore
 *     (0xF0-0xFC).
 *
 * Codificacion XCHG (primario 0x14):
 *   byte[2] y byte[3] codifican cada operando:
 *     - bit 6 del byte = tipo (0=general, 1=especial)
 *     - Si especial: bits 5-0 = codigo de registro especial (ver
 * special_reg_encoding)
 *     - Si general:  bits 7-4 = modo de acceso (0=b,1=w,2=d,3=q), bits 3-0 =
 * numero de registro
 */

#include "disasm/disasm.h"

#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "runtime/decode_table.h"
#include "emmit/emmit_decl.h"
#include "util/ansi.h"

#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>

using namespace Assembly::Bytecode;

namespace disasm {

/* Sufijo de ancho, indexado por modo 0-3.
 *
 * El ancho va PEGADO AL REGISTRO -- `r9w`, `r8d` -- que es la sintaxis del
 * lenguaje: el lexer acepta `r0..r15` con sufijo opcional `b`/`w`/`d`, y sin
 * sufijo es de 64 bits.  El desensamblador escribia `r1, r2 [w]`, que no es
 * sintaxis de Vesta y ni siquiera se puede volver a ensamblar.
 *
 * El modo 3 (q) no lleva sufijo: `r9` YA es el registro entero. */
static const char *mode_sfx[] = {"b", "w", "d", ""};

/**
 * @brief Nombre de un registro general con su ancho: `r9`, `r9d`, `r9w`, `r9b`.
 *
 * @param dst  Buffer del llamante (basta con 8 bytes).
 * @param idx  Numero de registro 0-15.
 * @param mode Modo de ancho 0-3; cualquier otro valor se trata como 64 bits.
 */
static const char *reg_nombre(char (&dst)[8], unsigned idx, unsigned mode) {
    snprintf(dst, sizeof(dst), "r%u%s", idx & 0x0F,
             mode_sfx[mode < 4 ? mode : 3]);
    return dst;
}
// multiplicadores de escala SIB
// nombres de las condiciones de salto (indice 16 = salto incondicional).
// Vive a nivel de fichero porque la usan los dos formateadores de operandos.
// Los nombres SALEN del orden real que evalua la VM (eval_jmp_cond, en
// exec_instruction_alu.cpp).  La tabla anterior estaba en otro orden, asi que
// el desensamblador atribuia a cada salto una condicion que no era la suya --
// leer un volcado llevaba a conclusiones equivocadas.
// `setcc` NO comparte la tabla de los saltos: tiene la suya, al estilo x86
// (ver exec_instr_setcc).  Interpretar una con la otra hace que el volcado
// atribuya a cada comparacion una condicion que no es la suya -- basta para
// dar por bueno un bug que no existe.
static const char *cc_setcc[] = {"jo",  "jno", "jb",  "jae", "je", "jne",
                                 "jbe", "ja",  "js",  "jns", "jp", "jne",
                                 "jl",  "jge", "jle", "jg"};

static const char *cc[] = {"je",  "jne", "jcs", "jcc", "jmi", "jpl",
                           "jvs", "jvc", "jhi", "jls", "jge", "jlt",
                           "jgt", "jle", "j?e", "j?f", "jmp"};
static const int scale_val[] = {1, 2, 4, 8};

/**
 * @brief Traduce un codigo de registro especial (6 bits) a su nombre de texto.
 *
 * Los registros especiales (rip, rsp, rbp, rflags, cur0-cur3) tienen codigos
 * distintos a los registros generales R00-R15.
 *
 * @param code Codigo de 6 bits del registro especial.
 * @return Nombre del registro o "?" si el codigo es desconocido.
 */
static const char *special_reg_name(uint8_t code) {
    static const char *tbl[64] = {};
    static bool ready = false;
    if (!ready) {
        tbl[0] = "cur0";
        tbl[1] = "cur1";
        tbl[2] = "cur2";
        tbl[3] = "cur3";
        tbl[8] = "rip";
        tbl[9] = "rbp";
        tbl[10] = "rsp";
        tbl[11] = "rflags";
        ready = true;
    }
    return (code < 64 && tbl[code]) ? tbl[code] : "?";
}

/**
 * @brief Formatea un operando XCHG a texto.
 *
 * Codificacion de cada byte de operando:
 *   - bit 6 = tipo: 0=registro general, 1=registro especial
 *   - Si especial: bits 5-0 = codigo de registro especial
 *   - Si general:  bits 7-4 = modo (0=b,1=w,2=d,3=q), bits 3-0 = numero de
 * registro
 *
 * @param b Byte del operando (raw[2] o raw[3]).
 * @return Cadena de texto del operando formateado.
 */
static std::string fmt_xchg_operand(uint8_t b) {
    char buf[32] = {};
    uint8_t is_special = (b >> 6) & 0x1; // bit 6 = tipo de registro
    uint8_t code = b & 0x3F;             // bits 5-0 = codigo

    if (is_special) {
        // registro especial: codigo referencia directamente al registro
        return special_reg_name(code);
    } else {
        // registro general: nibble alto = modo de acceso, nibble bajo = numero
        uint8_t mode = code >> 4; // modo de tamano (0=b, 1=w, 2=d, 3=q)
        uint8_t reg = code & 0xF; // numero de registro 0-15
        char rb[8];
        snprintf(buf, sizeof(buf), "%s", reg_nombre(rb, reg, mode));
        return buf;
    }
}

/**
 * @brief Devuelve true si el opcode extendido es una instruccion ZMM-ZMM
 * binaria.
 *
 * Instrucciones binarias ZMM: fmov (0xF0), fadd (0xF1), fsub (0xF2),
 * fmul (0xF3), fdiv (0xF4), fcmp (0xF5).
 *
 * @param opc Segundo byte del opcode extendido.
 * @return true si la instruccion opera sobre dos registros ZMM.
 */
static bool is_zmm_binary(uint8_t opc) {
    return opc >= 0xF0 && opc <= 0xF5;
}

/**
 * @brief Devuelve true si el opcode extendido es una instruccion ZMM unaria.
 *
 * Instrucciones unarias ZMM: fsqrt (0xF6), fabs (0xF7), fneg (0xF8).
 *
 * @param opc Segundo byte del opcode extendido.
 * @return true si la instruccion opera sobre un unico registro ZMM.
 */
static bool is_zmm_unary(uint8_t opc) {
    return opc >= 0xF6 && opc <= 0xF8;
}

/**
 * @brief Formatea los operandos de una instruccion extendida (prefijo 0x00).
 *
 * Cubre todas las instrucciones de la tabla extendida, incluyendo:
 *   - ALU/MOV/MOVC (opcodes 0x03..0x1F)
 *   - GETPROC/GETVM/GETMGR (0xC6..0xC8)
 *   - Corutinas Modelo A: yield (0xEC), resume (0xED), spawn (0xEE)
 *   - Fibras: swapctx (0xEF)
 *   - Flotante ZMM-ZMM: fmov (0xF0), fadd-fcmp (0xF1..0xF5)
 *   - Flotante unario:   fsqrt/fabs/fneg (0xF6..0xF8)
 *   - Conversion:        fcvt/fcvt.ps (0xF9)
 *   - Inmediato ZMM:     fmowi (0xFA, FIXED_11)
 *   - Memoria ZMM:       fload (0xFB), fstore (0xFC)
 *
 * @param opc  Segundo byte de la instruccion (opcode extendido).
 * @param fmt  Descriptor del formato de instruccion.
 * @param raw  Buffer con los bytes crudos de la instruccion (hasta 12).
 * @param isz  Tamano total de la instruccion en bytes.
 * @return Cadena de texto con los operandos formateados.
 */
/**
 * @brief Anota un registro nombrado por la instruccion.
 *
 * Se llama junto a cada sitio que imprime un `r%u` o un `f%u`, con el mismo
 * valor: la version estructurada y la de texto salen del mismo dato, asi que no
 * se pueden desincronizar.  @p dest marca la posicion de destino.
 */
static void anota(std::vector<RegOperand> *out, unsigned idx, bool dest,
                  bool floating = false) {
    if (out == nullptr) return;
    out->push_back(
        RegOperand{static_cast<uint8_t>(idx & 0x0F), floating, dest});
}

static std::string fmt_ext_operands(uint8_t opc,
                                    const runtime::InstrFormat *fmt,
                                    const uint8_t *raw, size_t isz,
                                    const runtime::DecodedInstr &d,
                                    std::vector<RegOperand> *out = nullptr) {
    char buf[128] = {};

    switch (fmt->mode) {
    case AddressingMode::NONE:
        break; // instrucciones sin operandos (yield, hlt, nop...)

    case AddressingMode::INMED:
        // fmowi: FIXED_11 = [0x00][0xFA][ctrl][imm64 LE (8 bytes)]
        // ctrl (raw[2]): bits 7-6 = mode, bit 5 = is_f32, bits 3-0 = zmm_idx
        // bytes raw[3..10] = bits IEEE 754 del double en little-endian
        if (opc == 0xFA && isz >= 11) {
            uint8_t zmm_dst = raw[2] & 0x0F; // nibble bajo de ctrl = indice ZMM
            uint64_t bits = 0;
            __builtin_memcpy(&bits, raw + 3,
                             8); // inmediato de 64 bits a partir de raw[3]
            double dval = 0.0;
            __builtin_memcpy(&dval, &bits,
                             8); // reinterpretar como double IEEE 754
            snprintf(buf, sizeof(buf), "f%u, 0x%016llx  ; %.17g", zmm_dst,
                     (unsigned long long)bits, dval);
            anota(out, zmm_dst, true, true);
        } else if (opc == 0x55 && isz >= 10) {
            // calln <addr_nativa>: el inmediato de 64 bits empieza en raw[2].
            uint64_t fn = 0;
            memcpy(&fn, raw + 2, 8);
            snprintf(buf, sizeof(buf), "0x%016llx", (unsigned long long)fn);
        } else if ((opc == 0x70 || opc == 0x71) && isz >= 4) {
            // fastpush/fastpop <mask16>: se listan los registros marcados, que
            // es lo que hace falta para seguir un valor a traves de una
            // llamada.  Sin esto la instruccion salia sin operando alguno.
            const uint16_t mask = static_cast<uint16_t>(raw[2] | (raw[3] << 8));
            char regs[96];
            size_t n = 0;
            regs[0] = '\0';
            for (int r = 0; r < 16; ++r) {
                if (!(mask & (1u << r))) continue;
                n += static_cast<size_t>(snprintf(regs + n, sizeof(regs) - n,
                                                  "%sr%d", (n ? " " : ""), r));
                // fastpop los restaura (escribe); fastpush los guarda (lee).
                anota(out, static_cast<unsigned>(r), opc == 0x71);
                if (n >= sizeof(regs) - 8) break;
            }
            snprintf(buf, sizeof(buf), "0x%04x {%s}", mask, regs);
        }
        break;

    case AddressingMode::REG:
        if (opc == 0x8F && isz >= 4) {
            // csel r_dst, r_cond, r_a, r_b: cuatro registros repartidos en dos
            // bytes (ver decode_instr_four_reg).  Salia mostrando solo dos, y
            // se perdia justo lo que decide la seleccion -- que es lo que hace
            // falta para seguir de donde sale un valor.
            const unsigned rd = (raw[2] >> 4) & 0x0F;
            const unsigned rc = raw[2] & 0x0F;
            const unsigned ra2 = (raw[3] >> 4) & 0x0F;
            const unsigned rb2 = raw[3] & 0x0F;
            snprintf(buf, sizeof(buf), "r%u, r%u ? r%u : r%u", rd, rc, ra2,
                     rb2);
            anota(out, rd, true);
            anota(out, rc, false);
            anota(out, ra2, false);
            anota(out, rb2, false);
        } else if (opc == 0x92 && isz >= 4) {
            // sext r_dst, N: el segundo campo NO es un registro, es el ancho
            // en bits desde el que se extiende el signo (8/16/32).  Salia como
            // `r2` -- un registro que no interviene --, que manda a mirar donde
            // no toca.
            snprintf(buf, sizeof(buf), "r%u, %u", (unsigned)(raw[2] & 0x0F),
                     (unsigned)raw[3]);
            anota(out, raw[2] & 0x0F, true);
        } else if (opc == 0x43 && isz >= 4) {
            // setcc r_dst, cond: byte2 = (cond << 4) | registro.  La condicion
            // es justo el dato que interesa al leer una comparacion, y salia
            // sin mostrar.
            const unsigned cond = (raw[2] >> 4) & 0x0F;
            const unsigned reg = raw[2] & 0x0F;
            snprintf(buf, sizeof(buf), "r%u, %s", reg, cc_setcc[cond]);
            anota(out, reg, true);
        } else if ((opc == 0x68 || opc == 0x69) && isz >= 8) {
            // cmpjmp/cmpjmpu: comparacion y salto fusionados.  Se leen igual
            // que decode_instr_cmpjmp: registros en b2, condicion en b3 y el
            // destino en los cuatro bytes siguientes.
            const unsigned ra = (raw[2] >> 4) & 0x0F;
            const unsigned rb = raw[2] & 0x0F;
            const unsigned cond = raw[3];
            uint32_t target = 0;
            memcpy(&target, raw + 4, 4);
            const int ci = (cond < 0x10) ? (int)cond : 16;
            snprintf(buf, sizeof(buf), "r%u, r%u, %s 0x%08x", ra, rb, cc[ci],
                     (unsigned)target);
            anota(out, ra, false);
            anota(out, rb, false);
        } else if ((opc == 0x90 || opc == 0x91) && isz >= 8) {
            // mld/mst: se leen los campos IGUAL que decode_instr_mem_full, en
            // vez de reinterpretar los bytes por cuenta propia.
            const uint8_t ctrl = raw[2];
            const uint8_t basef = raw[3];
            const uint8_t regs = raw[4];
            const int16_t disp = static_cast<int16_t>(raw[5] | (raw[6] << 8));
            const unsigned width = 1u << ((ctrl >> 4) & 0x07);
            const unsigned scale = ctrl & 0x07;
            const unsigned base = basef & 0x1F;
            const unsigned index = regs & 0x0F;
            const unsigned reg = (regs >> 4) & 0x0F;
            const bool host = (ctrl & 0x80) != 0;
            const bool has_index = (ctrl & 0x08) != 0;
            const bool sign_ext = (basef & 0x20) != 0;
            /* BANCO del registro que se carga o se guarda.  `mld`/`mst` sirven
             * a los dos: con este bit el destino es `zmm[N]`, sin el es
             * `regs[N]`.  Ver `exec_instr_mld` (flag 0x10 ya decodificado).
             *
             * Sin mirarlo, el desensamblador nombraba `r10` donde la
             * instruccion escribe `f10`, y eso no es solo un texto equivocado:
             * quien deriva dependencias de aqui -- el reordenador de paquetes
             * -- veia la escritura en el banco que NO es, no encontraba la
             * dependencia real y movia instrucciones que si dependian.  Daba
             * otro resultado en `bench_array_sum`. */
            const bool fp_bank = (basef & 0x80) != 0;
            char bs[8];
            if (base == 16)
                snprintf(bs, sizeof(bs), "rbp");
            else if (base == 17)
                snprintf(bs, sizeof(bs), "rsp");
            else
                snprintf(bs, sizeof(bs), "r%u", base);
            char addr[64];
            int n = snprintf(addr, sizeof(addr), "%s", bs);
            if (has_index)
                n += snprintf(addr + n, sizeof(addr) - n, " + r%u*%u", index,
                              1u << scale);
            if (disp)
                n += snprintf(addr + n, sizeof(addr) - n, " %c %d",
                              (disp < 0 ? '-' : '+'),
                              (disp < 0 ? -(int)disp : (int)disp));
            // `h` a secas se pasaba por alto.  La diferencia entre tocar
            // memoria de la VM y un puntero del host merece leerse.
            const char *mark = host ? "host" : "vm";
            const char rb = fp_bank ? 'f' : 'r';
            if (opc == 0x90)
                snprintf(buf, sizeof(buf), "%c%u, %s[%s] (%u bytes%s)", rb, reg,
                         mark, addr, width, sign_ext ? ", con signo" : "");
            else
                snprintf(buf, sizeof(buf), "%s[%s], %c%u (%u bytes)", mark, addr,
                         rb, reg, width);
            // mld escribe el registro y lee la direccion; mst al reves.
            anota(out, reg, opc == 0x90, fp_bank);
            if (base < 16) anota(out, base, false);
            if (has_index) anota(out, index, false);
        } else if (opc == 0x1F || opc == 0x1E) {
            // MOVC/MOVCH: ctrl[2], datos[3]
            uint8_t ctrl = raw[2], b4 = raw[3];
            uint8_t dir = (ctrl >> 5) & 0x1; // direccion del movimiento
            uint8_t r1 = ctrl & 0xF;         // registro fuente/destino
            uint8_t flag = (b4 >> 5) & 0x7;  // bandera de condicion
            uint8_t r2 = b4 & 0x1F;          // registro de memoria
            /* MOVC y MOVCH comparten opcode Y NOMBRE en la tabla: lo unico que
             * las separa son los bits 7-6 del ctrl (0b10 = host), igual que lo
             * lee `decode_instr_movc`.  Sin mostrarlo, el volcado ensena `movc`
             * para las dos y no se puede saber cual toca memoria de la VM y
             * cual un puntero del HOST -- que es justo la diferencia que decide
             * si el acceso se puede razonar o no. */
            const char *donde = (((ctrl >> 6) & 0x3) == 0x2) ? "host" : "vm";
            if (dir == 0)
                snprintf(buf, sizeof(buf), "r%u, %s[r%u], flag=%u", r1, donde,
                         r2, flag);
            else
                snprintf(buf, sizeof(buf), "%s[r%u], r%u, flag=%u", donde, r2,
                         r1, flag);
            anota(out, r1, dir == 0);
            anota(out, r2, false);
        } else if (is_zmm_binary(opc) && isz == 4) {
            // fmov, fadd, fsub, fmul, fdiv, fcmp: dos registros ZMM
            // nibble bajo de raw[3] = ZMM destino
            // nibble alto de raw[3] = ZMM fuente
            uint8_t zmm_dst = raw[3] & 0xF;
            uint8_t zmm_src = raw[3] >> 4;
            snprintf(buf, sizeof(buf), "f%u, f%u", zmm_dst, zmm_src);
            anota(out, zmm_dst, true, true);
            anota(out, zmm_src, false, true);
        } else if (is_zmm_unary(opc) && isz == 4) {
            // fsqrt fDst, fSrc / fabs fDst, fSrc / fneg fDst, fSrc
            // nibble bajo de raw[3] = ZMM destino, nibble alto = ZMM fuente
            uint8_t zmm_dst = raw[3] & 0xF;
            uint8_t zmm_src = raw[3] >> 4;
            snprintf(buf, sizeof(buf), "f%u, f%u", zmm_dst, zmm_src);
            anota(out, zmm_dst, true, true);
            anota(out, zmm_src, false, true);
        } else if (opc == 0xF9 && isz == 4) {
            // fcvt / fcvt.ps: conversion GP<->ZMM
            // bit 2 de ctrl (raw[2]) = s: 0=GP->ZMM, 1=ZMM->GP
            // nibble bajo  de raw[3] = ZMM
            // nibble alto  de raw[3] = GP
            uint8_t s = (raw[2] >> 2) & 0x1;
            uint8_t zmm_reg = raw[3] & 0xF;
            uint8_t gp_reg = raw[3] >> 4;
            if (s == 0)
                snprintf(buf, sizeof(buf), "f%u, r%u", zmm_reg, gp_reg);
            else
                snprintf(buf, sizeof(buf), "r%u, f%u", gp_reg, zmm_reg);
            anota(out, s == 0 ? zmm_reg : gp_reg, true, s == 0);
            anota(out, s == 0 ? gp_reg : zmm_reg, false, s != 0);
        } else if (opc == 0xFB && isz == 4) {
            // fload fDst, rAddr: ZMM nibble bajo, GP nibble alto
            uint8_t zmm_dst = raw[3] & 0xF;
            uint8_t gp_addr = raw[3] >> 4;
            snprintf(buf, sizeof(buf), "f%u, r%u", zmm_dst, gp_addr);
            anota(out, zmm_dst, true, true);
            anota(out, gp_addr, false);
        } else if (opc == 0xFC && isz == 4) {
            // fstore rAddr, fSrc: GP nibble alto, ZMM nibble bajo
            uint8_t zmm_src = raw[3] & 0xF;
            uint8_t gp_addr = raw[3] >> 4;
            snprintf(buf, sizeof(buf), "r%u, f%u", gp_addr, zmm_src);
            anota(out, gp_addr, false);
            anota(out, zmm_src, false, true);
        } else if ((opc == 0xED || opc == 0xEE) && isz == 4) {
            // resume rPID / spawn rAddr: un solo registro GP en nibble bajo
            uint8_t r1 = raw[3] & 0xF;
            snprintf(buf, sizeof(buf), "r%u", r1);
            anota(out, r1, false);
        } else if (opc == 0xEF && isz == 4) {
            // swapctx rDst, rSrc: nibble alto = destino, nibble bajo = origen
            uint8_t r_src = raw[3] & 0xF;
            uint8_t r_dst = raw[3] >> 4;
            snprintf(buf, sizeof(buf), "r%u, r%u", r_dst, r_src);
            anota(out, r_dst, true);
            anota(out, r_src, false);
        } else if (fmt->decode == &runtime::decode_instr_raw_bytes) {
            /* Familia "convencion B": los registros van en BYTE2, no en byte3.
             *
             * Esto salia por la rama generica de abajo, que lee los nibbles de
             * `raw[3]`.  Para estas instrucciones eso son los registros
             * EQUIVOCADOS: `strcat r_dst, r_a, r_b` se enseñaba como dos
             * registros sacados de byte3, uno de los cuales ni interviene.  34
             * opcodes afectados.
             *
             * El reparto de nibbles se saco de los MANEJADORES, que son quienes
             * deciden que registro usan, y hay dos convenciones opuestas que
             * conviene no mezclar:
             *
             *   strings  (0x46-0x54, 0x5E): dst = b2hi, src = b2lo, [b3hi]
             *   ALU3/mem/fmadd:             dst = b2lo, src = b2hi,  b3hi
             *
             * Vive aqui y no en `InstrFormat` por decision explicita.  El
             * riesgo conocido es que se quede vieja: si alguien anade un opcode
             * con `decode_instr_raw_bytes` y no lo mete en estas listas, saldra
             * con la forma de dos registros por defecto. */
            const uint8_t b2 = raw[2], b3 = raw[3];
            const unsigned n_hi = (b2 >> 4) & 0x0F; // nibble alto de byte2
            const unsigned n_lo = b2 & 0x0F;        // nibble bajo de byte2
            const unsigned n_b3 = (b3 >> 4) & 0x0F; // nibble alto de byte3

            // Los que ademas usan un tercer registro en b3hi.
            const bool tres_str = (opc == 0x46 || opc == 0x48 || opc == 0x49 ||
                                   opc == 0x4A || opc == 0x4C || opc == 0x5E);
            // ALU 3-operandos, fmadd y la familia de memoria en bloque.
            const bool alu3 = (opc >= 0x73 && opc <= 0x7B);
            const bool bloque = (opc >= 0xB6 && opc <= 0xB9);

            if (alu3 || bloque || opc == 0x5F) {
                // dst = b2lo, luego b2hi y b3hi.  `fmadd` opera sobre el banco
                // ZMM, asi que se nombra con `f`.
                const bool fp = (opc == 0x5F);
                snprintf(buf, sizeof(buf), "%c%u, %c%u, %c%u", fp ? 'f' : 'r',
                         n_lo, fp ? 'f' : 'r', n_hi, fp ? 'f' : 'r', n_b3);
                anota(out, n_lo, true, fp);
                anota(out, n_hi, false, fp);
                anota(out, n_b3, false, fp);
            } else if (opc == 0xCE) {
                // addadvice: byte2 = (r_advice << 4) | r_target, byte3 = kind
                // (no es un registro).
                snprintf(buf, sizeof(buf), "r%u, r%u, kind=%u", n_hi, n_lo,
                         (unsigned)b3);
                anota(out, n_hi, false);
                anota(out, n_lo, false);
            } else if (tres_str) {
                snprintf(buf, sizeof(buf), "r%u, r%u, r%u", n_hi, n_lo, n_b3);
                anota(out, n_hi, true);
                anota(out, n_lo, false);
                anota(out, n_b3, false);
            } else {
                snprintf(buf, sizeof(buf), "r%u, r%u", n_hi, n_lo);
                anota(out, n_hi, true);
                anota(out, n_lo, false);
            }
        } else if (fmt->decode == &runtime::decode_instr_dlopen_dlsym) {
            /* dlopen/dlsym: TRES o CUATRO registros, no dos.  El decoder los
             * deja en `mem_data`, y la rama generica solo enseñaba dos.
             *   dlopen: r_dst, r_path_addr, r_path_len
             *   dlsym:  r_dst, r_handle, r_name_addr, r_name_len */
            const auto &m = d.data_instruction.mem_data;
            if (opc == 0x63)
                snprintf(buf, sizeof(buf), "r%u, r%u, r%u, r%u", m.reg_base,
                         m.reg_index, m.reg_final, m.scale);
            else
                snprintf(buf, sizeof(buf), "r%u, r%u, r%u", m.reg_base,
                         m.reg_index, m.reg_final);
            anota(out, m.reg_base, true);
            anota(out, m.reg_index, false);
            anota(out, m.reg_final, false);
            if (opc == 0x63) anota(out, m.scale, false);
        } else if (fmt->decode == &runtime::decode_instr_three_reg) {
            // msgsend: r_pid, r_addr, r_len.  Los tres se leen.
            const auto &m = d.data_instruction.mem_data;
            snprintf(buf, sizeof(buf), "r%u, r%u, r%u", m.reg_base, m.reg_index,
                     m.reg_final);
            anota(out, m.reg_base, false);
            anota(out, m.reg_index, false);
            anota(out, m.reg_final, false);
        } else if (fmt->decode == &runtime::decode_instr_atomic_rmw) {
            // Cuatro registros empaquetados en dos bytes.
            const auto &m = d.data_instruction.mem_data;
            snprintf(buf, sizeof(buf), "r%u, r%u, r%u, r%u", m.reg_base,
                     m.reg_index, m.reg_final, m.scale);
            anota(out, m.reg_base, true);
            anota(out, m.reg_index, false);
            anota(out, m.reg_final, false);
            anota(out, m.scale, false);
        } else if (fmt->decode == &runtime::decode_instr_vmcopy) {
            // vmcopy/vcopyh: copia entre memoria de VM y del host.
            const auto &m = d.data_instruction.mem_data;
            snprintf(buf, sizeof(buf), "r%u, r%u, r%u", m.reg_base, m.reg_index,
                     m.reg_final);
            anota(out, m.reg_base, false);
            anota(out, m.reg_index, false);
            anota(out, m.reg_final, false);
        } else if (fmt->decode == &runtime::decode_instr_static_offset) {
            /* getstatic/setstatic: dos registros MAS el offset, que se perdia.
             * El papel de cada uno cambia con el opcode:
             *   getstatic: r0 = destino, r1 = clase
             *   setstatic: r0 = clase,   r1 = valor  (no escribe registro) */
            const auto &s = d.data_instruction.static_data;
            snprintf(buf, sizeof(buf), "r%u, r%u, +%u", s.r0, s.r1, s.offset);
            anota(out, s.r0, opc == 0x60);
            anota(out, s.r1, false);
        } else if (fmt->decode == &runtime::decode_instr_decjnz) {
            // decjnz r_counter, target: decrementa y salta si no es cero.
            const auto &s = d.data_instruction.static_data;
            snprintf(buf, sizeof(buf), "r%u, 0x%08x", s.r0, (unsigned)s.offset);
            anota(out, s.r0, true); // lo lee y lo escribe
        } else if (fmt->decode == &runtime::decode_instr_oop_reg_imm8) {
            // [reg, imm8]: el segundo operando NO es un registro.  La rama
            // generica lo enseñaba como `rN`, mandando a mirar donde no toca.
            const auto &r = d.data_instruction.reg_data;
            snprintf(buf, sizeof(buf), "r%u, %u", r.reg1, (unsigned)r.reg2);
            anota(out, r.reg1, true);
        } else if (fmt->decode == &runtime::decode_instr_callni) {
            // callni r_fn: un solo registro; reg2 queda sin uso.
            snprintf(buf, sizeof(buf), "r%u", d.data_instruction.reg_data.reg1);
            anota(out, d.data_instruction.reg_data.reg1, false);
        } else if (fmt->decode == &runtime::decode_instr_gcallocp) {
            // gcallocp r_dst, r_size
            const auto &r = d.data_instruction.reg_data;
            snprintf(buf, sizeof(buf), "r%u, r%u", r.reg1, r.reg2);
            anota(out, r.reg1, true);
            anota(out, r.reg2, false);
        } else if (fmt->decode == &runtime::decode_instr_addcur) {
            // addcur: el decoder solo rellena reg2; reg1 no interviene.
            snprintf(buf, sizeof(buf), "r%u", d.data_instruction.reg_data.reg2);
            anota(out, d.data_instruction.reg_data.reg2, true);
        } else if (fmt->decode == &runtime::decode_instr_jumptable) {
            // jumptable/typeswitch: r_val y r_table en byte2; `count` es el
            // numero de entradas, no un registro.
            const auto &m = d.data_instruction.mem_data;
            snprintf(buf, sizeof(buf), "r%u, r%u, count=%u", m.reg_base,
                     m.reg_index, (unsigned)m.scale);
            anota(out, m.reg_base, false);
            anota(out, m.reg_index, false);
        } else if (fmt->decode == &runtime::decode_instr_cursor_rw) {
            /* Lectura/escritura via cursor: `reg2` NO es un registro general,
             * es el indice del cursor (0-3), que sale del byte de control.  La
             * rama generica lo enseñaba como `rN` -- un registro que no existe
             * -- y ademas se perdia de vista cual es el cursor. */
            const auto &r = d.data_instruction.reg_data;
            snprintf(buf, sizeof(buf), "r%u, cur%u", r.reg1, (unsigned)r.reg2);
            anota(out, r.reg1, true);
        } else if (fmt->decode == &runtime::decode_instr_spawnargs) {
            // spawnargs r_pc: un solo registro (argc va en R15, implicito).
            snprintf(buf, sizeof(buf), "r%u", d.data_instruction.reg_data.reg1);
            anota(out, d.data_instruction.reg_data.reg1, false);
        } else if (fmt->decode == &runtime::decode_instr_fulfillhlt) {
            // fulfillhlt r_fut, r_value: los dos en byte2.
            const auto &r = d.data_instruction.reg_data;
            snprintf(buf, sizeof(buf), "r%u, r%u", r.reg1, r.reg2);
            anota(out, r.reg1, false);
            anota(out, r.reg2, false);
        } else if (isz == 4) {
            // instruccion reg-reg generica: ctrl[2] (mode 7-6), regs[3]
            uint8_t ctrl = raw[2], regs = raw[3];
            uint8_t mode = (ctrl >> 6) & 0x3;
            uint8_t r1 = regs & 0xF, r2 = regs >> 4;
            char n1[8], n2[8];
            snprintf(buf, sizeof(buf), "%s, %s", reg_nombre(n1, r1, mode),
                     reg_nombre(n2, r2, mode));
            anota(out, r1, true);
            anota(out, r2, false);
        }
        break;

    case AddressingMode::MEM: {
        // instrucciones con inmediato (MIXED_SIZE): ctrl[2] codifica mode,
        // sign, dir, reg
        uint8_t ctrl = raw[2];
        uint8_t mode = (ctrl >> 6) &
                       0x3; // tamano del inmediato: 0=8b, 1=16b, 2=32b, 3=64b
        uint8_t sign = (ctrl >> 5) & 0x1; // bit de signo
        uint8_t dir = (ctrl >> 4) & 0x1;  // 0=reg<-imm, 1=[reg]<-imm
        uint8_t reg = ctrl & 0xF;         // numero de registro

        if (dir == 1 && sign == 1) {
            // caso especial: mov a registro especial; codigo = mode<<4|reg;
            // imm64 en [3..10]
            uint64_t imm = 0;
            memcpy(&imm, raw + 3, 8);
            uint8_t code = (uint8_t)((mode << 4) | reg);
            snprintf(buf, sizeof(buf), "%s, 0x%016llx", special_reg_name(code),
                     (unsigned long long)imm);
        } else {
            // operando reg/[reg] con inmediato de tamano variable
            uint64_t imm = 0;
            int nb = mode_to_bytes(mode); // numero de bytes del inmediato
            memcpy(&imm, raw + 3, nb);
            // enmascarar bits superiores para el tamano efectivo
            if (mode == 0)
                imm &= 0xFFu;
            else if (mode == 1)
                imm &= 0xFFFFu;
            else if (mode == 2)
                imm &= 0xFFFFFFFFu;
            char rn[8];
            reg_nombre(rn, reg, mode);
            if (dir == 0)
                snprintf(buf, sizeof(buf), "%s, 0x%llx", rn,
                         (unsigned long long)imm);
            else
                snprintf(buf, sizeof(buf), "[%s], 0x%llx", rn,
                         (unsigned long long)imm);
            anota(out, reg, dir == 0);
        }
        break;
    }

    case AddressingMode::SIB: {
        // instruccion SIB FIXED_6: ctrl[2], regs[3], idx[4]
        uint8_t ctrl = raw[2], regs = raw[3], idx = raw[4];
        uint8_t mode = (ctrl >> 6) & 0x3;  // tamano del acceso
        uint8_t dir = (ctrl >> 4) & 0x1;   // 0=reg<-[...], 1=[...]<-reg
        uint8_t scale = (ctrl >> 2) & 0x3; // indice en scale_val[]
        uint8_t hasi = (ctrl >> 1) & 0x1;  // 1=hay registro indice
        uint8_t rfin = regs >> 4;          // registro final
        uint8_t rbase = regs & 0xF;        // registro base
        uint8_t ridx = idx & 0xF;          // registro indice
        /* El ancho es el del ACCESO, asi que lo lleva el registro de datos.
         * La base y el indice forman una direccion: van enteros, sin sufijo. */
        char rf[8];
        reg_nombre(rf, rfin, mode);
        if (dir == 0) {
            if (hasi)
                snprintf(buf, sizeof(buf), "%s, [r%u+r%u*%d]", rf, rbase, ridx,
                         scale_val[scale]);
            else
                snprintf(buf, sizeof(buf), "%s, [r%u]", rf, rbase);
        } else {
            if (hasi)
                snprintf(buf, sizeof(buf), "[r%u+r%u*%d], %s", rbase, ridx,
                         scale_val[scale], rf);
            else
                snprintf(buf, sizeof(buf), "[r%u], %s", rbase, rf);
        }
        // rfin es destino solo cuando el movimiento va hacia el registro; la
        // base y el indice se leen siempre, porque forman la direccion.
        anota(out, rfin, dir == 0);
        anota(out, rbase, false);
        if (hasi) anota(out, ridx, false);
        break;
    }

    default: break;
    }
    return buf;
}

/**
 * @brief Formatea los operandos de una instruccion primaria (opcode de 1 byte).
 *
 * @param opc Primer byte de la instruccion (opcode primario).
 * @param fmt Descriptor del formato de instruccion.
 * @param raw Buffer con los bytes crudos de la instruccion (hasta 12).
 * @return Cadena de texto con los operandos formateados.
 */
static std::string
fmt_primary_operands(uint8_t opc, const runtime::InstrFormat *fmt,
                     const uint8_t *raw, const runtime::DecodedInstr &d,
                     std::vector<RegOperand> *out = nullptr) {
    char buf[128] = {};

    // tabla de mnemoticos de condicion de salto (indice = byte de condicion)
    switch (fmt->mode) {
    case AddressingMode::NONE: break;

    case AddressingMode::REG: {
        uint8_t data = raw[1];
        uint8_t reg = data & 0xF; // numero de registro en nibble bajo
        if (opc == 0x04) {
            // inc/dec: bit6=variante (0=inc, 1=dec), bits5-4=modo de tamano
            uint8_t mode = (data >> 4) & 0x3;
            uint8_t var = (data >> 6) & 0x1;
            char rn[8];
            snprintf(buf, sizeof(buf), "%s %s", (var ? "dec" : "inc"),
                     reg_nombre(rn, reg, mode));
            anota(out, reg, true); // inc/dec lo lee y lo escribe
        } else if (opc == 0x14) {
            // XCHG: byte[2] y byte[3] codifican dos operandos mixtos
            // (general/especial)
            // - bit 6 de cada byte: 0=general, 1=especial
            // - general: nibble alto = modo, nibble bajo = numero de registro
            // - especial: bits 5-0 = codigo de registro especial
            std::string op1 = fmt_xchg_operand(raw[2]);
            std::string op2 = fmt_xchg_operand(raw[3]);
            snprintf(buf, sizeof(buf), "%s, %s", op1.c_str(), op2.c_str());
            // xchg escribe LOS DOS: es un intercambio.  Los especiales (bit 6)
            // no son generales y no se anotan como tales.
            if (((raw[2] >> 6) & 1) == 0) anota(out, raw[2] & 0xF, true);
            if (((raw[3] >> 6) & 1) == 0) anota(out, raw[3] & 0xF, true);
        } else {
            // push, pop, jmpr, callvmr: un solo registro en nibble bajo de
            // raw[1].  `pop` lo ESCRIBE; los demas solo lo leen.
            snprintf(buf, sizeof(buf), "r%u", reg);
            anota(out, reg, opc == 0x13);
        }
        break;
    }

    case AddressingMode::INMED: {
        // JMP/CALLVM FIXED_10: [opc][cond][addr 8 bytes LE]
        uint8_t cond = raw[1];
        uint64_t addr = 0;
        memcpy(&addr, raw + 2, 8);
        // No todo lo que va con inmediato es un salto.  `enter` lleva el
        // tamano del marco y `fastpush`/`fastpop` una mascara de registros;
        // leerlos como salto imprimia una condicion inexistente en el primero
        // y nada en los otros dos.
        if (opc == 0x28 || opc == 0x29) {
            // enter/leave <frame_size>: el inmediato empieza en raw[1].
            uint64_t fsz = 0;
            memcpy(&fsz, raw + 1, 8);
            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)fsz);
        } else if (opc == 0x70 || opc == 0x71) {
            // fastpush/fastpop <mask16>: los registros marcados, uno a uno,
            // que es lo que interesa al seguir un valor entre llamadas.
            const uint16_t mask = static_cast<uint16_t>(raw[2] | (raw[3] << 8));
            char regs[96];
            size_t n = 0;
            regs[0] = '\0';
            for (int r = 0; r < 16; ++r) {
                if (!(mask & (1u << r))) continue;
                n += static_cast<size_t>(snprintf(regs + n, sizeof(regs) - n,
                                                  "%sr%d", (n ? " " : ""), r));
                // fastpop los restaura (escribe); fastpush los guarda (lee).
                anota(out, static_cast<unsigned>(r), opc == 0x71);
                if (n >= sizeof(regs) - 8) break;
            }
            snprintf(buf, sizeof(buf), "0x%04x {%s}", mask, regs);
        } else if (opc == 0x10) {
            // callvm: salto incondicional con direccion absoluta
            snprintf(buf, sizeof(buf), "0x%016llx", (unsigned long long)addr);
        } else {
            // jmp con condicion; indice 16 = jmp incondicional
            int ci = (cond < 0x10) ? (int)cond : 16;
            snprintf(buf, sizeof(buf), "%s 0x%016llx", cc[ci],
                     (unsigned long long)addr);
        }
        break;
    }

    default: break;
    }
    return buf;
}

/**
 * @brief Construye la cadena hexadecimal coloreada de los bytes de una
 * instruccion.
 *
 * Cada byte recibe un color ANSI deterministico basado en su valor, de forma
 * que el mismo byte siempre aparece con el mismo color.  Muestra como maximo 10
 * bytes.
 *
 * @param raw    Buffer con los bytes crudos.
 * @param isz    Numero de bytes validos en @p raw.
 * @param color  Si es true aplica colores ANSI por byte.
 * @return Cadena con los bytes hex separados por espacio, con o sin codigos
 * ANSI.
 */
static std::string build_hex_string(const uint8_t *raw, size_t isz,
                                    bool color) {
    std::ostringstream hs;
    /* Se ensenan TODOS los bytes que ocupa la instruccion.  Estaban cortados a
     * 10 y las hay de 11 -- un `mov reg, imm64` son 3 + 8 --, con lo que el
     * ultimo byte desaparecia sin decirlo: quien leia el volcado creia estar
     * viendo la instruccion entera y le faltaba un trozo del inmediato.  El
     * tope es el del buffer de bytes crudos. */
    size_t shown = (isz < 12) ? isz : 12;
    for (size_t i = 0; i < shown; ++i) {
        if (i) hs << " ";
        char hb[4];
        snprintf(hb, sizeof(hb), "%02x", raw[i]);
        if (color) {
            hs << ansi::byte_color(raw[i]) << hb << ansi::RESET;
        } else {
            hs << hb;
        }
    }
    return hs.str();
}

// ---- API publica ----

void print_instruction(std::ostream &out, const DisasmResult &instr,
                       const DisasmOptions &opts) {
    bool col = opts.use_color && ansi::is_enabled();

    // columna de direccion en gris atenuado
    char addr_buf[20];
    snprintf(addr_buf, sizeof(addr_buf), "%016llx",
             (unsigned long long)instr.address);
    if (col) out << ansi::DIM;
    out << "  " << addr_buf << "  ";
    if (col) out << ansi::RESET;

    if (opts.show_hex) {
        // columna de bytes hex (ya coloreados si opts.use_color)
        // padding a 30 caracteres: necesario aunque haya codigos ANSI
        // los codigos ANSI no son caracteres visibles, asi que se calcula
        // el numero de bytes visibles para alinear correctamente
        out << instr.hex;
        // calcular cuantos bytes visibles se imprimieron para el padding
        size_t shown = (instr.size < 10) ? instr.size : 10;
        // cada byte visible ocupa 3 chars ("xx ") excepto el ultimo (2 chars)
        // formula: shown*3-1 = chars visibles; se rellena hasta 32 para alinear
        // el mnemotecnico
        size_t visible_chars = shown > 0 ? (shown * 3 - 1) : 0;
        size_t pad = (visible_chars < 32) ? (32 - visible_chars) : 1;
        for (size_t i = 0; i < pad; ++i)
            out << ' ';
    }

    // columna de mnemotecnico con color segun tipo
    if (col) out << ansi::mnem_color(instr.mnemonic.c_str());
    out << std::setw(10) << std::left << instr.mnemonic;
    if (col) out << ansi::RESET;

    // operandos en blanco normal
    out << instr.operands << "\n";
}

/**
 * @brief Pasa la condicion del OPERANDO al mnemonico, que es donde vive.
 *
 * `jmp.jne 0x...` es UN mnemonico con sufijo, no un `jmp` cuyo primer operando
 * sea `jne`: asi se escribe en el `.vel` y asi lo lee el ensamblador.  Salia
 * partido porque quien formatea los operandos no puede tocar el mnemonico --
 * devuelve una cadena --, y el resultado era `jmp      jne 0x...`, que ademas
 * de leerse mal no se puede copiar a un fuente.
 *
 * Vale para las tres formas condicionales: `jmp.cc`, `cmpjmp.cc` y
 * `cmpjmpu.cc`.  En el `jmp` incondicional la tabla repite `jmp` como
 * condicion, y ahi solo se quita.
 *
 * @param r Resultado a normalizar en el sitio.
 */
static void merge_cond_into_mnemonic(DisasmResult &r) {
    const bool is_jmp = (r.mnemonic == "jmp");
    const bool is_cmpjmp = (r.mnemonic == "cmpjmp" || r.mnemonic == "cmpjmpu");
    if (!is_jmp && !is_cmpjmp) return;

    // En `jmp` la condicion abre los operandos; en `cmpjmp` va tras los dos
    // registros, o sea detras del ultimo ", ".
    const size_t start = is_jmp ? 0 : (r.operands.rfind(", j") + 2);
    if (!is_jmp && r.operands.rfind(", j") == std::string::npos) return;
    if (start >= r.operands.size() || r.operands[start] != 'j') return;

    const size_t sp = r.operands.find(' ', start);
    if (sp == std::string::npos) return;
    const std::string cond = r.operands.substr(start, sp - start);
    // `jmp jmp` es el incondicional: no se le pone sufijo.
    if (!(is_jmp && cond == "jmp")) r.mnemonic += "." + cond;
    r.operands = r.operands.substr(0, start) + r.operands.substr(sp + 1);
}

std::vector<DisasmResult> disasm_bytes(const uint8_t *data, size_t len,
                                       uint64_t base_addr,
                                       const DisasmOptions &opts) {
    std::vector<DisasmResult> out;
    size_t off = 0; // desplazamiento actual en el buffer

    while (off < len && off < opts.max_bytes) {
        uint8_t b0 = data[off];
        bool ext = (b0 == 0x00); // prefijo extendido
        uint8_t opc;
        const runtime::InstrFormat *fmt;

        if (ext) {
            if (off + 1 >= len) break; // no hay segundo byte
            opc = data[off + 1];
            fmt = &runtime::decode_table_extended[opc];
        } else {
            opc = b0;
            fmt = &runtime::decode_table_primary[b0];
        }

        DisasmResult r{};
        r.address = base_addr + off;

        // opcode desconocido: volcar como .db
        if (fmt->mode == AddressingMode::COUNT || !fmt->name || !fmt->name[0] ||
            fmt->decode == nullptr) {
            char hb[8];
            snprintf(hb, sizeof(hb), "%02x", b0);
            r.size = 1;
            r.mnemonic = ".db";
            r.operands = std::string("0x") + hb;
            if (opts.show_hex)
                r.hex = build_hex_string(&b0, 1,
                                         opts.use_color && ansi::is_enabled());
            out.push_back(r);
            off++;
            continue;
        }

        /* Se descodifica con EL DECODER DE LA VM, no reinterpretando los
         * bytes por cuenta propia.  Antes el desensamblador calculaba el
         * tamano de las MIXED_SIZE a mano, repitiendo lo que ya hace el
         * decoder; cualquier cambio de formato habia que acordarse de
         * copiarlo aqui.  Ahora `size_instr` sale del propio decoder. */
        runtime::DecodedInstr d{};
        d.metadata = const_cast<runtime::InstrFormat *>(fmt);
        d.exec_cached = fmt->exec;
        d.pc = r.address;
        d.flags_info.is_not_extended = ext ? 0x00 : b0;
        d.flags_info.opcode_index = opc;
        const size_t queda = len - off;
        fmt->decode(runtime::InstrCursor{data + off, queda, r.address}, d);

        size_t isz = d.flags_info.size_instr;
        if (isz == 0) isz = instr_size(fmt->size); // formatos sin size propio
        if (isz > queda) isz = queda;              // truncar si pasa el limite

        uint8_t raw[12] = {};
        memcpy(raw, data + off, (isz < 12) ? isz : 12);

        r.size = isz;
        r.mnemonic = fmt->name;
        r.operands = ext ? fmt_ext_operands(opc, fmt, raw, isz, d, &r.regs)
                         : fmt_primary_operands(opc, fmt, raw, d, &r.regs);
        merge_cond_into_mnemonic(r);
        if (opts.show_hex)
            r.hex = build_hex_string(raw, isz,
                                     opts.use_color && ansi::is_enabled());

        bool is_hlt = (ext && opc == 0x03);
        out.push_back(r);
        off += isz;

        if (opts.stop_at_hlt && is_hlt) break;
    }
    return out;
}

void disasm_velb(const std::string &file, std::ostream &out,
                 const DisasmOptions &opts) {
    ansi::init(); // habilitar colores si el terminal lo soporta
    bool col = opts.use_color && ansi::is_enabled();

    // crear VM temporal solo para el Loader; no se llama a start()
    runtime::ManageVM tmp(nullptr, 0);
    runtime::VM *vm_inst = tmp.loader.create_vm_instance(1);
    if (!vm_inst) {
        out << "[disasm] error: no se pudo crear VM\n";
        return;
    }

    runtime::ProcessVM *proc = tmp.loader.load_executable(*vm_inst, file);
    if (!proc) {
        vm_inst->stop(); // seguro aunque start() no fue llamado
        out << "[disasm] error: no se pudo cargar el archivo\n";
        return;
    }

    uint64_t ip = proc->registers.rip.raw(); // entrypoint segun cabecera .velb
    uint64_t limit = ip + opts.max_bytes;

    // cabecera del listado con color
    char ep_buf[24];
    snprintf(ep_buf, sizeof(ep_buf), "0x%016llx", (unsigned long long)ip);
    if (col) out << ansi::DIM;
    out << "; VestaVM disasm: " << file << "\n"
        << "; entrypoint: " << ep_buf << "\n\n";
    if (col) out << ansi::RESET;

    bool done = false;
    while (!done && ip < limit) {
        uint8_t raw[12] = {};
        uint8_t b0;

        try {
            b0 = proc->vm_mem[ip];
        } catch (...) {
            break;
        }

        bool ext = (b0 == 0x00);
        uint8_t opc;
        const runtime::InstrFormat *fmt;

        if (ext) {
            try {
                opc = proc->vm_mem[ip + 1];
            } catch (...) {
                break;
            }
            fmt = &runtime::decode_table_extended[opc];
        } else {
            opc = b0;
            fmt = &runtime::decode_table_primary[b0];
        }

        // opcode desconocido: volcar como .db y avanzar un byte
        if (fmt->mode == AddressingMode::COUNT || !fmt->name || !fmt->name[0] ||
            fmt->decode == nullptr) {
            if (col) out << ansi::DIM;
            char line[96];
            snprintf(line, sizeof(line), "  %016llx   ",
                     (unsigned long long)ip);
            out << line;
            if (col) {
                out << ansi::RESET;
                out << ansi::byte_color(b0);
            }
            char hb[4];
            snprintf(hb, sizeof(hb), "%02x", b0);
            out << hb;
            if (col) out << ansi::RESET;
            out << "                             ";
            if (col) out << ansi::c(ansi::BR_BLACK);
            out << ".db       ";
            if (col) out << ansi::RESET;
            char op[8];
            snprintf(op, sizeof(op), "0x%02x", b0);
            out << op << "\n";
            ip++;
            continue;
        }

        // calcular tamano de la instruccion
        size_t isz;
        if (fmt->size == InstrSizeMode::MIXED_SIZE) {
            uint8_t ctrl;
            try {
                ctrl = proc->vm_mem[ip + 2];
            } catch (...) {
                break;
            }
            (void)ctrl; // el tamano lo dara el decoder, no este calculo
        }

        // copiar bytes al buffer local
        for (size_t i = 0; i < sizeof(raw); ++i) {
            try {
                raw[i] = proc->vm_mem[ip + i];
            } catch (...) {
                // Fin de la memoria mapeada: lo leido hasta aqui basta para
                // las instrucciones cortas.
                break;
            }
        }

        /* Igual que en `disasm_bytes`: descodifica EL DECODER DE LA VM.  El
         * calculo de tamano a mano que habia aqui era una copia del que hace
         * el decoder, y se quedaba viejo por su cuenta. */
        runtime::DecodedInstr d{};
        d.metadata = const_cast<runtime::InstrFormat *>(fmt);
        d.exec_cached = fmt->exec;
        d.pc = ip;
        d.flags_info.is_not_extended = ext ? 0x00 : b0;
        d.flags_info.opcode_index = opc;
        fmt->decode(runtime::InstrCursor{raw, sizeof(raw), ip}, d);

        isz = d.flags_info.size_instr;
        if (isz == 0) isz = instr_size(fmt->size);

        // construir y delegar en print_instruction
        DisasmResult r{};
        r.address = ip;
        r.size = isz;
        r.mnemonic = fmt->name;
        r.operands = ext ? fmt_ext_operands(opc, fmt, raw, isz, d, &r.regs)
                         : fmt_primary_operands(opc, fmt, raw, d, &r.regs);
        merge_cond_into_mnemonic(r);
        if (opts.show_hex) r.hex = build_hex_string(raw, isz, col);

        print_instruction(out, r, opts);

        if (opts.stop_at_hlt && ext && opc == 0x03) done = true;
        ip += isz;
    }

    vm_inst->stop(); // seguro: scheduler_futures vacio porque start() no fue
                     // llamado
}

} // namespace disasm
