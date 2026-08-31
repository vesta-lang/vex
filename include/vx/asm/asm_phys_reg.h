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
 * @file vx/asm/asm_phys_reg.h
 * @brief Nombres de registro FiSICO por (clase, indice, ancho) + sustitucion de
 *        placeholders @c $N de una @c ASM_MICRO.
 *
 * Header-only: lo comparten el LIFTER (vx_lib: nombre -> indice fisico) y el
 * BACKEND JIT/AOT (vm/vesta_ffi: indice fisico -> nombre, sustituye @c $N en la
 * plantilla NASM) sin dependencia de enlace entre libs.  Cubre x86 GP
 * (rax..r15 en ORDEN DE ENCODING, igual que @c MReg y el encoder); las demas
 * clases (FP/VEC) y arch (arm64) llegan despues.
 */
#ifndef VX_ASM_PHYS_REG_H
#define VX_ASM_PHYS_REG_H

#include "ir/ssa_ir.h"

#include <cctype>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace vx {

/**
 * @name ABI del paso de valores de un bloque asm
 *
 * Lo comparten el EMISOR, que escribe la tabla, y el runtime, que la lee.  Vive
 * aqui porque son dos lados de un mismo acuerdo: si cada uno llevara sus
 * numeros podrian separarse sin que nada fallara al compilar, y el fallo
 * saldria como valores movidos de sitio -- basura, no un error.
 * @{
 */

/// Bytes de cada ranura de la tabla.  Fija y del ancho MAYOR, no ajustada a
/// cada operando: con ranuras variables el desplazamiento de la ranura `i`
/// depende de todas las anteriores, y ese calculo tendria que salir igual en
/// los dos lados.  Fija, el desplazamiento es `i * 64` y no hay nada que
/// cuadrar.  Cuesta pila en un sitio donde no es escasa -- un bloque asm usa
/// unos pocos operandos y no esta en un bucle cerrado.
static constexpr uint32_t kAsmSlotBytes = 64;

/**
 * @brief Lo que hay que saber de un operando para moverlo, EN MEMORIA.
 *
 * Estaba empaquetado en un entero de 64 bits, a unos pocos bits por operando, y
 * eso le ponia presupuesto de bits a algo que crece con cada ISA y cada
 * extension.  Las cuentas no salian ya: clase (GP, FP, VEC, predicados de SVE,
 * mascaras de AVX-512...), ranura (32 hoy, mas los 16 predicados de SVE) y
 * ancho (8 a 64 bytes hoy, 256 en SVE, variable en RVV) piden trece bits por
 * operando cuando habia ocho -- y ensanchar el campo solo cambiaba el problema
 * de sitio: a dieciseis bits, en un descriptor de 64 caben cuatro operandos,
 * menos de los ocho de antes.
 *
 * Y el que faltaba era el peor: sin campo de CLASE, el receptor deducia el
 * banco del ancho, asi que un `double` en `xmm0` -- ocho bytes en el banco
 * ancho -- acababa en el general.
 *
 * Aqui no hay presupuesto que agotar.  La tabla de valores ya vivia en memoria;
 * el descriptor vive al lado, con campos nombrados y de dieciseis bits, que dan
 * sitio de sobra para lo que venga sin volver a reencajar nada.  Anadir un
 * banco nuevo es un campo, no un reparto de bits en dos ficheros a la vez.
 *
 * Ocho bytes por operando, y el numero de operandos deja de tener tope
 * artificial: los ocho de antes tampoco eran una decision, eran los 64 bits.
 */
struct AsmOperandDesc {
    uint16_t clase;  ///< @ref ASM_RC_GP, @ref ASM_RC_VEC, ...
    uint16_t ranura; ///< indice fisico dentro de su banco.
    uint16_t bytes;  ///< cuantos bytes mover (no se deduce del registro:
                     ///< `xmm3`, `ymm3` y `zmm3` son la MISMA ranura).
    uint16_t flags;  ///< reservado (lee/escribe y lo que haga falta).
};

/// Bytes de una entrada de la tabla de descriptores.
static constexpr uint32_t kAsmDescBytes = 8;

/**
 * @brief Donde esta el valor de un operando: en un REGISTRO de la VM.
 *
 * La via de la tabla mueve los valores a la pila para que el runtime los lea de
 * ahi, y de vuelta al terminar.  Eso son dos copias por operando y por bloque,
 * y no compran nada: el valor ya esta en un registro de la VM, y la VM tiene
 * los dos bancos -- `regs[16]` y `zmm[16]` -- asi que el runtime puede leerlo
 * donde ya esta.
 *
 * Un bloque `asm` no es una frontera que haya que cruzar copiando: es codigo
 * dentro del codigo, y sus operandos son valores como cualquier otro.
 *
 * Con esto desaparecen, por bloque: la reserva de pila, los almacenamientos de
 * ida, las cargas de vuelta y el descriptor de ancho -- el ancho lo dice el
 * banco.
 */
/**
 * @brief La posicion de un operando, empaquetada en 16 bits.
 *
 * Va en los ARGUMENTOS de la llamada, no en una tabla: cuatro operandos caben
 * en un entero de 64 bits y ocho en dos, que es mas de lo que un bloque `asm`
 * usa.
 *
 * Sin tabla desaparecen la reserva de pila, los almacenamientos y -- lo que de
 * verdad costo -- la necesidad de un registro para direccionarla.  El primer
 * intento uso los scratch del emisor para eso, y cada carga de un operando
 * pisaba el puntero: 105 casos rotos.  Un dato que se conoce al compilar no
 * necesita memoria ni registro; viaja como inmediato.
 *
 *     bits 0-3   registro de la VM (0..15)
 *     bits 4-8   ranura fisica en el asm (0..31)
 *     bit  9     banco: 0 general, 1 ancho
 *     bits 10-11 lee / escribe
 */
inline constexpr uint16_t asm_pack_loc(uint8_t vm_reg, uint8_t phys,
                                       uint8_t bank, uint8_t flags) {
    return (uint16_t)((vm_reg & 0xF) | ((phys & 0x1F) << 4) |
                      ((bank & 1) << 9) | ((flags & 0x3) << 10));
}

inline constexpr uint8_t asm_loc_vm_reg(uint16_t p) {
    return (uint8_t)(p & 0xF);
}
inline constexpr uint8_t asm_loc_phys(uint16_t p) {
    return (uint8_t)((p >> 4) & 0x1F);
}
inline constexpr uint8_t asm_loc_bank(uint16_t p) {
    return (uint8_t)((p >> 9) & 1);
}
inline constexpr uint8_t asm_loc_flags(uint16_t p) {
    return (uint8_t)((p >> 10) & 0x3);
}

/// Cuantas posiciones caben en cada entero que se pasa como argumento.
static constexpr uint32_t kAsmLocsPerWord = 4;

/// @name Bancos de @ref AsmOperandLoc::bank
/// @{
static constexpr uint8_t kAsmBankGp = 0;
static constexpr uint8_t kAsmBankWide = 1;
/// @}

/// @name Banderas de @ref AsmOperandLoc::flags
/// @{
static constexpr uint8_t kAsmLocReads = 1u;
static constexpr uint8_t kAsmLocWrites = 2u;
/// @}

/// Tope de operandos con valor.  Ya no lo impone el formato -- es una cota de
/// cordura para no reservar pila sin limite por un bloque asm.
static constexpr uint32_t kAsmMaxOps = 16;

/**
 * @name Contexto que recibe el trampolin
 *
 * Ranuras generales primero y banco ancho detras.  Los tamanos son el MAYOR de
 * los objetivos que se soportan, no los de uno:
 *
 *   - generales: 16 en x86-64, 31 en arm64.
 *   - banco ancho: 16 con AVX, 32 con AVX-512F, 32 en arm64.
 *
 * Estaba escrito `16 + 16*8`, que es x86-con-AVX y nada mas.  Con arm64 o
 * AVX-512 el registro 20 caia fuera del contexto: no da error, escribe pasado
 * el final -- justo el fallo que no se encuentra probando si funciona.
 *
 * El ancho de ranura son 64 bytes (512 bits), que cubre zmm y los vectores de
 * arm64.  SVE y RVV son de longitud variable y no caben en una ranura fija;
 * cuando entren, esto deja de ser una constante y pasa a salir del objetivo.
 * @{
 */
static constexpr uint32_t kAsmCtxGpSlots = 32;  ///< ranuras del banco general.
static constexpr uint32_t kAsmCtxVecSlots = 32; ///< ranuras del banco ancho.
static constexpr uint32_t kAsmCtxVecQwords = 8; ///< 64 bytes por ranura ancha.

/// Bits que cabe en una ranura ancha.  512 es lo que miden zmm y los vectores
/// fijos de arm64, y NO es "el maximo": SVE llega a 2048 y RVV no tiene tope
/// fijo.  Subirlo es cambiar este numero -- cuesta memoria por proceso y nada
/// mas -- y para los de longitud variable el contexto tiene que dejar de ser un
/// array fijo y pasar a salir del objetivo.
///
/// Lo que NO puede pasar entre tanto es que un registro mas ancho se mueva a
/// medias: eso no da error, deja medio valor.  Por eso @ref asm_cabe_en_ranura
/// existe y quien vaya a mover algo pregunta ANTES.
static constexpr uint32_t kAsmSlotBits = kAsmCtxVecQwords * 64;

/**
 * @brief Si un valor de @p bits se puede mover entero por el contexto.
 *
 * Preguntar y quedarse fuera cuesta que ese bloque siga opaco, con su motivo
 * dicho.  No preguntar cuesta medio registro, sin aviso ninguno.
 */
inline bool asm_cabe_en_ranura(unsigned bits) {
    return bits <= kAsmSlotBits;
}
/// Qwords totales del contexto.
static constexpr uint32_t kAsmCtxQwords =
    kAsmCtxGpSlots + kAsmCtxVecSlots * kAsmCtxVecQwords;
/** @} */

/// Codigo de ancho del descriptor (3 bits) -> bytes a mover.
///
/// Se codifica el ancho y no se deduce del registro porque son cosas distintas:
/// `xmm3`, `ymm3` y `zmm3` son la MISMA ranura, y lo unico que dice cuantos
/// bytes hay que mover es esto.
inline unsigned asm_ancho_de_codigo(unsigned codigo) {
    switch (codigo & 0x7u) {
    case 0: return 8;  // banco general
    case 1: return 16; // 128 bits (xmm / NEON)
    case 2: return 32; // 256 bits (ymm)
    case 3: return 64; // 512 bits (zmm)
    default: return 8; // desconocido -> lo estrecho, que nunca pisa de mas
    }
}

/// El inverso: bits de un operando -> codigo de 3 bits del descriptor.
inline unsigned asm_codigo_de_ancho(unsigned bits) {
    switch (bits) {
    case 128: return 1;
    case 256: return 2;
    case 512: return 3;
    default: return 0;
    }
}
/** @} */

/**
 * @brief Cuantos BYTES ocupa un valor de la clase @p clase.
 *
 * El tamano de un operando lo dice su clase, no su tipo Vesta: una variable
 * ligada a `xmm` mide 16 bytes aunque su tipo sea de 8.  Reservarle el del tipo
 * la deja a la mitad, y entonces el valor solo conserva su parte baja al cruzar
 * de un bloque asm a otro -- la alta pasa a ser lo que hubiera en la pila.  No
 * da error: da un resultado con basura dentro.
 *
 * @param isa ISA del bloque.
 * @param clase Clase tal como se escribio.
 * @return Bytes, o 0 si la clase no es de un banco ancho (entonces manda el
 *         tipo, como siempre).
 */
/**
 * @brief Ranura del banco ancho que ocupa @p clase dentro de SU banco.
 *
 * `xmm3`, `ymm3` y `zmm3` son la MISMA ranura: lo que cambia entre ellos es
 * cuantos bytes hay que mover, y eso lo dice @ref asm_bytes_de_clase.  Por eso
 * son dos preguntas y no una.
 *
 * Vive aqui, con el resto de lo que sabe de registros por ISA, y no en quien
 * emite: leer un nombre de registro es conocimiento del objetivo, y repetido en
 * cada emisor son varias reglas en cuanto entre una ISA.
 *
 * @param isa ISA del bloque.
 * @param clase Clase tal como se escribio.
 * @return Indice dentro del banco ancho, o -1 si no es de un banco ancho o el
 *         nombre no se entiende.
 */
inline int asm_slot_of_class(uint8_t isa, const std::string &clase) {
    if (clase.empty()) return -1;
    std::string c;
    c.reserve(clase.size());
    for (char ch : clase)
        c += static_cast<char>(std::tolower((unsigned char)ch));
    size_t digits = 0;
    if (isa <= 2) { // familia x86: tres letras de prefijo
        if (c.size() < 4) return -1;
        if (c.compare(0, 3, "xmm") != 0 && c.compare(0, 3, "ymm") != 0 &&
            c.compare(0, 3, "zmm") != 0)
            return -1;
        digits = 3;
    } else { // arm64: una letra
        if (c.size() < 2) return -1;
        if (c[0] != 'q' && c[0] != 'v') return -1; // `z` es de largo variable
        digits = 1;
    }
    int n = 0;
    for (size_t i = digits; i < c.size(); ++i) {
        if (c[i] < '0' || c[i] > '9') return -1;
        n = n * 10 + (c[i] - '0');
    }
    return n;
}

inline uint32_t asm_bytes_de_clase(uint8_t isa, const std::string &clase) {
    if (clase.empty()) return 0;
    std::string c;
    c.reserve(clase.size());
    for (char ch : clase)
        c += static_cast<char>(std::tolower((unsigned char)ch));
    if (isa <= 2) { // familia x86: el prefijo dice el ancho
        if (c.rfind("xmm", 0) == 0) return 16;
        if (c.rfind("ymm", 0) == 0) return 32;
        if (c.rfind("zmm", 0) == 0) return 64;
        return 0;
    }
    /* arm64: `q` son 128 bits, `d` 64 y `s` 32; `v` es el registro completo,
     * que son 128 en NEON.  SVE (`z`) es de longitud variable y no cabe en una
     * ranura fija -- ver @ref asm_cabe_en_ranura. */
    if (c[0] == 'q' || c[0] == 'v') return 16;
    if (c[0] == 'z') return 0; // longitud variable: no se promete un tamano
    return 0;
}

/// Clases de registro arch-neutras (== @c AsmMicroOperand::regclass).
enum : uint8_t {
    ASM_RC_GP = 0,
    ASM_RC_FP = 1,
    ASM_RC_VEC = 2,
    ASM_RC_PRED = 3,
    ASM_RC_FLAGS = 4,
};

/**
 * @brief De que BANCO es la clase que escribio el programador.
 *
 * `xmm v0` en x86 y `v0` en arm64 son el mismo banco con dos nombres, y quien
 * lo sabe es este modulo, que ya lleva los nombres de registro por ISA.  Antes
 * se decidia comparando cadenas en el lowering, que es escribir una
 * arquitectura concreta en un sitio que no es de ninguna.
 *
 * Se pregunta por la CLASE DECLARADA y no por el registro asignado: cuando la
 * ligadura es automatica, el registro es uno elegido a la primera para tener
 * algo que sustituir, y deducir de el la clase da la respuesta contraria.  Ese
 * fue un fallo real, y ademas silencioso -- cada capa quedaba coherente consigo
 * misma y el valor acababa en el banco equivocado sin una sola queja.
 *
 * @param isa ISA del bloque.
 * @param clase Clase tal como se escribio (@c "xmm", @c "reg", @c "v", ...).
 * @return @ref ASM_RC_VEC, @ref ASM_RC_GP, ...  Vacia -> @ref ASM_RC_GP, que es
 *         lo estrecho: equivocarse hacia ancho mueve mas bytes de los que hay.
 */
inline uint8_t asm_clase_de_banco(uint8_t isa, const std::string &clase) {
    if (clase.empty()) return ASM_RC_GP;
    std::string c;
    c.reserve(clase.size());
    for (char ch : clase)
        c += static_cast<char>(std::tolower((unsigned char)ch));
    if (isa <= 2) { // familia x86
        if (c.rfind("xmm", 0) == 0 || c.rfind("ymm", 0) == 0 ||
            c.rfind("zmm", 0) == 0)
            return ASM_RC_VEC;
        if (c.rfind("st", 0) == 0) return ASM_RC_FP; // pila x87
        if (c.rfind("k", 0) == 0 && c.size() <= 2)
            return ASM_RC_PRED; // AVX-512
        return ASM_RC_GP;
    }
    /* arm64 / arm32: el banco ancho se escribe `v`/`q`/`d`/`s` (NEON, SVE usa
     * `z` y sus predicados `p`).  RISC-V vectorial usa `v`. */
    if (c[0] == 'v' || c[0] == 'q' || c[0] == 'z') return ASM_RC_VEC;
    if (c[0] == 'p') return ASM_RC_PRED;
    return ASM_RC_GP;
}

/**
 * @brief Nombre del GPR x86 @p phys (0..15, ORDEN DE ENCODING) al ancho
 *        @p width_bits (64/32/16/8).  @c nullptr si fuera de rango.
 */
inline const char *asm_x86_gp_name(int phys, uint16_t width_bits) {
    if (phys < 0 || phys > 15) return nullptr;
    static const char *k64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                  "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                  "r12", "r13", "r14", "r15"};
    static const char *k32[16] = {"eax",  "ecx",  "edx",  "ebx", "esp",  "ebp",
                                  "esi",  "edi",  "r8d",  "r9d", "r10d", "r11d",
                                  "r12d", "r13d", "r14d", "r15d"};
    static const char *k16[16] = {"ax",   "cx",   "dx",   "bx",  "sp",   "bp",
                                  "si",   "di",   "r8w",  "r9w", "r10w", "r11w",
                                  "r12w", "r13w", "r14w", "r15w"};
    static const char *k8[16] = {"al",   "cl",   "dl",   "bl",  "spl",  "bpl",
                                 "sil",  "dil",  "r8b",  "r9b", "r10b", "r11b",
                                 "r12b", "r13b", "r14b", "r15b"};
    switch (width_bits) {
    case 64: return k64[phys];
    case 32: return k32[phys];
    case 16: return k16[phys];
    case 8: return k8[phys];
    default: return k64[phys]; // 0/desconocido -> 64-bit (caso comun)
    }
}

/**
 * @brief indice fisico de un nombre de registro del banco ANCHO de x86
 *        (@c xmmN / @c ymmN / @c zmmN).  Rellena @p out_width con el ancho en
 *        bits.  -1 si no es uno de esos.
 *
 * Es el inverso de @ref asm_phys_reg_name para la clase vectorial: el numero es
 * el mismo en los tres anchos porque son la misma ranura vista a 128, 256 o 512
 * bits, asi que solo el prefijo dice el ancho.
 */
inline int asm_x86_vec_index(const std::string &tok, uint16_t *out_width) {
    std::string s;
    s.reserve(tok.size());
    for (char c : tok)
        s += static_cast<char>(std::tolower((unsigned char)c));
    uint16_t w = 0;
    size_t pos = 0;
    if (s.rfind("xmm", 0) == 0) {
        w = 128;
        pos = 3;
    } else if (s.rfind("ymm", 0) == 0) {
        w = 256;
        pos = 3;
    } else if (s.rfind("zmm", 0) == 0) {
        w = 512;
        pos = 3;
    } else
        return -1;
    if (pos >= s.size()) return -1;
    int n = 0;
    for (size_t i = pos; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return -1;
        n = n * 10 + (s[i] - '0');
        if (n > 31) return -1;
    }
    if (out_width) *out_width = w;
    return n;
}

/**
 * @brief indice fisico (0..15, orden de encoding) de un nombre de GPR x86.
 *        Rellena @p out_width con el ancho en bits.  -1 si no es un GPR.
 */
inline int asm_x86_gp_index(const std::string &tok, uint16_t *out_width) {
    std::string s;
    s.reserve(tok.size());
    for (char c : tok)
        s += static_cast<char>(std::tolower((unsigned char)c));
    for (uint16_t w : {(uint16_t)64, (uint16_t)32, (uint16_t)16, (uint16_t)8})
        for (int i = 0; i < 16; ++i)
            if (s == asm_x86_gp_name(i, w)) {
                if (out_width) *out_width = w;
                return i;
            }
    return -1;
}

/**
 * @brief Nombre de un operando REG por su (clase, indice fisico, ancho).  @c ""
 *        si la clase no esta soportada o el operando no es fisico.
 */
/**
 * @brief Numero de ranura de un registro del banco ancho x86 por su nombre.
 *
 * `xmm3`, `ymm3` y `zmm3` son la MISMA ranura vista a distinto ancho, asi que
 * las tres formas devuelven 3.
 *
 * @param nombre Nombre del registro.
 * @return La ranura (0..31), o -1 si no es del banco ancho.
 */
inline int asm_vec_reg_index(const std::string &nombre) {
    if (nombre.size() < 4) return -1;
    const std::string pref = nombre.substr(0, 3);
    if (pref != "xmm" && pref != "ymm" && pref != "zmm") return -1;
    int n = 0;
    for (size_t i = 3; i < nombre.size(); ++i) {
        if (nombre[i] < '0' || nombre[i] > '9') return -1;
        n = n * 10 + (nombre[i] - '0');
    }
    return (n >= 0 && n <= 31) ? n : -1;
}

inline std::string asm_phys_reg_name(uint8_t isa, uint8_t regclass, int phys,
                                     uint16_t width_bits) {
    // x86 (isa 0/1/2) GP.  arm64 pendiente.
    if (regclass == ASM_RC_GP && isa <= 2) {
        const char *n = asm_x86_gp_name(phys, width_bits);
        return n ? std::string(n) : std::string();
    }
    /* Banco ancho de x86: el numero es el mismo y solo cambia el prefijo con
     * el ancho, porque xmmN, ymmN y zmmN son la misma ranura vista a 128, 256
     * o 512 bits.  Por eso basta con el ancho para nombrarla. */
    if ((regclass == ASM_RC_VEC || regclass == ASM_RC_FP) && isa <= 2) {
        if (phys < 0 || phys > 31) return std::string();
        const char *pref = nullptr;
        switch (width_bits) {
        case 128: pref = "xmm"; break;
        case 256: pref = "ymm"; break;
        case 512: pref = "zmm"; break;
        default: return std::string();
        }
        return std::string(pref) + std::to_string(phys);
    }
    return std::string();
}

/**
 * @brief Como se escribe "base mas desplazamiento" en esta ISA.
 *
 * La sintaxis de una direccion no es la misma en todas partes: x86 la escribe
 * @c "[rax + 8]" y arm64 @c "[x0, #8]".  Componerla a mano donde haga falta es
 * escribir una arquitectura concreta en un sitio que no es de ninguna, asi que
 * vive aqui, junto al resto de nombres por ISA.
 *
 * @param isa ISA (== @c instr_db::Isa).
 * @param base Nombre ya resuelto del registro base.
 * @param disp Desplazamiento con signo.
 * @return El operando completo, o @c "" si esa ISA no esta descrita todavia --
 *         en cuyo caso el bloque se queda opaco, que es lo correcto: mejor sin
 *         elevar que elevado a una sintaxis inventada.
 */
inline std::string asm_mem_operando(uint8_t isa, const std::string &base,
                                    int64_t disp) {
    if (base.empty()) return std::string();
    if (isa <= 2) { // x86-64 / x86-32 / x86-16
        std::string s = "[" + base;
        if (disp != 0) {
            s += (disp > 0 ? " + " : " - ");
            /* En HEXADECIMAL y con prefijo, no en decimal.  El ensamblador se
             * abre en modo NASM, y en ese modo Keystone lee un numero SIN
             * prefijo como hexadecimal: un `[rdx + 32]` acababa siendo
             * `[rdx + 0x32]`, o sea 50.  Con un `vmovdqu` eso escribe donde no
             * toca -- `memcpy` de `std.memory` entregaba una copia a medias --
             * y con un `vmovdqa`, que EXIGE alineacion, mata el proceso.
             *
             * Escribirlo con `0x` lo hace inequivoco lea quien lo lea y en la
             * base que sea, que es lo que tiene que hacer un texto que se
             * genera: no depender de como este configurado el que lo parsea. */
            const uint64_t mag = static_cast<uint64_t>(disp > 0 ? disp : -disp);
            char buf[24];
            std::snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)mag);
            s += buf;
        }
        return s + "]";
    }
    return std::string();
}

/**
 * @brief Un registro CUALQUIERA de esa clase y ancho, para preguntarle a la
 * base de instrucciones por una linea equivalente.
 *
 * La forma de una instruccion depende de la CLASE del operando, no de que
 * registro concreto sea, asi que para clasificar una linea que todavia lleva
 * marcadores sirve cualquiera.  El de verdad lo elige el asignador despues.
 */
inline std::string asm_reg_muestra(uint8_t isa, uint8_t regclass,
                                   uint16_t width_bits) {
    return asm_phys_reg_name(isa, regclass, 0, width_bits);
}

/**
 * @brief La instruccion con su FORMA completa, para quien la analice leyendo
 *        el texto.
 *
 * La plantilla lleva los marcadores pelados porque como se escribe una
 * direccion depende de la ISA y eso lo pone el que resuelve.  Pero quien
 * analiza el texto -- la comprobacion de alineacion, por ejemplo -- necesita
 * ver que ese operando ES una direccion: sin los corchetes no hay acceso a
 * memoria que ver, y la comprobacion se apaga sin decir nada.
 *
 * @param am Ficha del micro asm.
 * @return El texto con las direcciones escritas al completo.
 */
inline std::string asm_micro_texto_con_forma(const ir::AsmMicro &am) {
    std::string out;
    out.reserve(am.tmpl.size() + 16);
    for (size_t i = 0; i < am.tmpl.size();) {
        if (am.tmpl[i] != '$') {
            out += am.tmpl[i++];
            continue;
        }
        size_t j = i + 1;
        uint32_t idx = 0;
        bool any = false;
        while (j < am.tmpl.size() && std::isdigit((unsigned char)am.tmpl[j])) {
            idx = idx * 10 + (uint32_t)(am.tmpl[j] - '0');
            ++j;
            any = true;
        }
        if (!any || idx >= am.operands.size()) {
            out += am.tmpl[i++];
            continue;
        }
        const ir::AsmMicroOperand &op = am.operands[idx];
        const std::string marca = "$" + std::to_string(idx);
        if (op.kind == ir::AsmOperandKind::MEM) {
            const std::string dir = asm_mem_operando(am.isa, marca, op.imm);
            out += dir.empty() ? marca : dir;
        } else {
            out += marca;
        }
        i = j;
    }
    return out;
}

/**
 * @brief Registros FiSICOS que una @c ASM_MICRO destruye, como pares
 *        (clase, indice).
 *
 * Una instruccion de ensamblador que escribe en un registro lo destruye, y el
 * asignador tiene que saberlo o pondra ahi un valor que la instruccion pisa.
 * La ficha ya lo dice -- cada operando lleva su rol -- pero nadie se lo estaba
 * preguntando, asi que el asignador trataba el micro asm como si no tocara
 * ningun registro.
 *
 * Cuenta tanto lo que la instruccion escribe por nombre como lo que escribe
 * por convencion (@c ASM_OP_IMPLICIT): para el que asigna registros, un
 * registro destruido lo esta igual aparezca o no escrito en el texto.
 *
 * @param am Ficha del micro asm.
 * @param out Recibe los pares (clase de registro, indice fisico).
 */
inline void asm_micro_clobbers(const ir::AsmMicro &am,
                               std::vector<std::pair<uint8_t, int>> &out) {
    out.clear();
    for (const ir::AsmMicroOperand &op : am.operands) {
        if (!op.writes() || op.fixed_phys < 0) continue;
        if (op.kind != ir::AsmOperandKind::REG) continue;
        out.emplace_back(op.regclass, (int)op.fixed_phys);
    }
}

/**
 * @brief Sustituye @c $0,$1,... de @c am.tmpl por el nombre fisico de cada
 *        operando (indexado por posicion en @c am.operands).  Devuelve @c false
 *        si algun @c $N referenciado no es nombrable (operando no fisico o
 * clase no soportada) -> el llamador hace fallback.
 *
 * todos los operandos son de FiSICO FIJO (@c fixed_phys >= 0).  El
 * threading SSA + asignador (@c fixed_phys == -1) llega despues.
 */
inline bool asm_micro_subst_phys(const ir::AsmMicro &am, std::string &out) {
    out.clear();
    out.reserve(am.tmpl.size() + 16);
    for (size_t i = 0; i < am.tmpl.size();) {
        char c = am.tmpl[i];
        if (c != '$') {
            out += c;
            ++i;
            continue;
        }
        // Leer el indice decimal tras '$'.
        size_t j = i + 1;
        uint32_t idx = 0;
        bool any = false;
        while (j < am.tmpl.size() && std::isdigit((unsigned char)am.tmpl[j])) {
            idx = idx * 10 + (uint32_t)(am.tmpl[j] - '0');
            ++j;
            any = true;
        }
        if (!any || idx >= am.operands.size()) return false; // $ suelto / fuera
        const ir::AsmMicroOperand &op = am.operands[idx];
        // Un inmediato es el numero: no hay registro que poner.
        if (op.kind == ir::AsmOperandKind::IMM) {
            out += std::to_string(op.imm);
            i = j;
            continue;
        }
        if (op.fixed_phys < 0)
            return false; // lo elige el asignador, aqui no hay
        std::string name =
            asm_phys_reg_name(am.isa, op.regclass, op.fixed_phys, op.width);
        if (name.empty()) return false;
        /* Una direccion se escribe entera y aqui: la plantilla lleva el
         * marcador pelado porque como se escribe una direccion depende de la
         * ISA. */
        if (op.kind == ir::AsmOperandKind::MEM) {
            const std::string dir = asm_mem_operando(am.isa, name, op.imm);
            if (dir.empty()) return false;
            out += dir;
            i = j;
            continue;
        }
        out += name;
        i = j;
    }
    return true;
}

/**
 * @brief Pone registros a los operandos que no tienen, de forma DETERMINISTA.
 *
 * El interprete no reparte registros, asi que alguien tiene que elegirlos, y lo
 * hacen dos sitios distintos: el que emite el codigo y el que prepara la
 * instruccion para ejecutarla.  Si eligieran distinto, el texto no coincidiria
 * y no se encontrarian -- se buscan por el hash de ese texto.  Por eso eligen
 * aqui, una sola vez.
 *
 * Se reparte por orden, saltando los que ya estan pedidos por nombre y los que
 * no son del programa (la pila y el marco).
 *
 * @param am Ficha del micro asm.
 * @param out Recibe el texto con los registros puestos.
 * @param phys Recibe el registro de cada operando, en el orden de la ficha
 *        (-1 para los inmediatos, que no llevan).
 * @return @c false si algun operando no se pudo resolver -- solo la clase
 *         general entra aqui: el banco ancho no viaja por esta via.
 */
/**
 * @brief Cuantas ranuras reparte @p rc en @p isa, tirando por lo bajo.
 *
 * El numero no es de la ISA sola: el banco ancho de x86 mide 16 con AVX, pero
 * AVX-512F lo sube a 32 (`zmm0-31`), y eso depende de las CAPACIDADES del
 * objetivo, no de si es x86.  Quien tiene el dato completo -- clases, anchuras,
 * solapes y caps -- es el banco fisico de @c codegen::rbank, que ya cubre
 * x86-64, x86-32 y arm64 y esta preparado para SVE, RVV y las mascaras.
 *
 * Aqui se devuelve el SUELO seguro de cada clase, no el maximo, y el motivo es
 * la direccion del error.  Este reparto elige siempre la ranura libre mas baja
 * para un bloque `asm` suelto, que usa unos pocos registros: quedarse corto
 * deja sin usar las altas -- se pierde holgura, nada mas --, mientras que
 * pasarse nombraria un registro que el objetivo no tiene, y eso no se queda en
 * peor: no ensambla, o ensambla otra cosa.
 *
 * Cuando las caps lleguen hasta aqui, esto pasa a preguntarle al banco y
 * desaparece.  Mientras tanto es un suelo, y esta dicho que lo es.
 *
 * @param isa Identificador de ISA del bloque (0-2 = familia x86).
 * @param rc  Clase de registro (@ref ASM_RC_GP, @ref ASM_RC_VEC, ...).
 * @return Ranuras utilizables con seguridad, o 0 si la ISA no se conoce.
 */
inline size_t asm_lanes_por_clase(uint8_t isa, int rc) {
    if (isa <= 2) return 16; // x86: 16 generales; el ancho es 16 sin AVX-512F
    /* arm64: 31 generales utiles (x31 se lee como sp o zr segun la forma, asi
     * que no se reparte) y 32 vectoriales, que ahi no dependen de caps. */
    return (rc == ASM_RC_GP) ? 31 : 32;
}

inline bool asm_micro_subst_greedy(const ir::AsmMicro &am, std::string &out,
                                   std::vector<int> &phys) {
    phys.assign(am.operands.size(), -1);
    /* Un juego POR CLASE, no uno solo.  Los bancos son independientes: `rax` y
     * `xmm0` son la ranura 0 de dos sitios distintos y no se estorban.  Con un
     * unico juego, dar `xmm0` marcaba `rax` como ocupado -- y sobre todo
     * obligaba a rechazar el banco ancho entero para no repartir de mas, que
     * es lo que dejaba opaco cualquier bloque con un operando vectorial.
     *
     * CUANTAS ranuras tiene cada clase NO se escribe aqui: lo dice el banco
     * fisico del objetivo (@c codegen::rbank), que ya modela clases, anchuras y
     * solapes para x86-64, x86-32 y arm64 -- y esta preparado para SVE, RVV y
     * las mascaras de AVX-512.  Poner un 16 a mano habria funcionado en x86 y
     * habria desaprovechado la mitad del banco en arm64, que tiene 31 generales
     * y 32 vectoriales.  El numero se pregunta, no se supone. */
    /* Por clase, porque no todas miden lo mismo: en arm64 hay 31 generales y
     * 32 vectoriales.  Un solo numero para todas habria recortado la mayor al
     * tamano de la menor. */
    size_t n_lanes[ASM_RC_FLAGS + 1];
    for (int rc = 0; rc <= (int)ASM_RC_FLAGS; ++rc) {
        n_lanes[rc] = asm_lanes_por_clase(am.isa, rc);
        if (n_lanes[rc] == 0 || n_lanes[rc] > 32) return false;
    }
    bool usado[ASM_RC_FLAGS + 1][32] = {{false}};
    // La pila y el marco no se reparten; eso es de la clase general.
    usado[ASM_RC_GP][4] = usado[ASM_RC_GP][5] = true;
    auto clase_de = [](const ir::AsmMicroOperand &o) -> int {
        /* Una direccion se forma SIEMPRE con la clase general, aunque el dato
         * que se mueva sea ancho: `movdqa xmm0, [rax]` toca los dos bancos. */
        if (o.kind == ir::AsmOperandKind::MEM) return ASM_RC_GP;
        return (o.regclass <= ASM_RC_FLAGS) ? (int)o.regclass : (int)ASM_RC_GP;
    };
    for (size_t i = 0; i < am.operands.size(); ++i) {
        const ir::AsmMicroOperand &op = am.operands[i];
        if (op.kind == ir::AsmOperandKind::IMM) continue;
        if (op.regclass > ASM_RC_FLAGS) return false; // clase que no se conoce
        if (op.fixed_phys >= 0 &&
            (size_t)op.fixed_phys < n_lanes[clase_de(op)]) {
            phys[i] = op.fixed_phys;
            usado[clase_de(op)][op.fixed_phys] = true;
        }
    }
    for (size_t i = 0; i < am.operands.size(); ++i) {
        const ir::AsmMicroOperand &op = am.operands[i];
        if (op.kind == ir::AsmOperandKind::IMM || phys[i] >= 0) continue;
        const int rc = clase_de(op);
        /* Dos apariciones del MISMO valor son el mismo registro.
         *
         * `pxor v0, v0` lleva `v0` dos veces, y repartiendo por APARICIoN cada
         * una se llevaba una ranura distinta: salia `pxor xmm0, xmm1`, que no
         * pone a cero nada.  El bloque se ensamblaba, corria y devolvia un
         * resultado equivocado sin una queja.
         *
         * La identidad de un operando es su VALOR, no el sitio del texto donde
         * aparece. */
        int elegido = -1;
        if (op.value != ir::IR_NO_VALUE) {
            for (size_t j = 0; j < i; ++j) {
                const ir::AsmMicroOperand &o = am.operands[j];
                if (o.value == op.value && clase_de(o) == rc && phys[j] >= 0) {
                    elegido = phys[j];
                    break;
                }
            }
        }
        for (size_t r = 0; elegido < 0 && r < n_lanes[rc]; ++r)
            if (!usado[rc][r]) {
                elegido = (int)r;
                break;
            }
        if (elegido < 0) return false;
        usado[rc][elegido] = true;
        phys[i] = elegido;
    }
    // Y ahora el texto, con la misma maquinaria de siempre.
    ir::AsmMicro copia = am;
    for (size_t i = 0; i < copia.operands.size(); ++i)
        if (phys[i] >= 0) copia.operands[i].fixed_phys = (int16_t)phys[i];
    return asm_micro_subst_phys(copia, out);
}

/**
 * @brief Sustituye @c $0,$1,... por el registro GREEDY (por defecto) del
 * binding
 *        @c reg_auto con ese @c ph_index.  Para el INTERP, que no tiene RA: usa
 *        el pick greedy guardado en @c AsmRegBinding::reg (nombre de 64 bits).
 *        Los @c $N sin binding correspondiente quedan verbatim.
 *
 * El JIT/AOT NO usan esto: rellenan @c $N con el registro OPTIMO del asignador
 * via el ensamblado diferido (@c AsmBlob::deferred).  Este helper mantiene el
 * interp correcto (aunque no optimo) con el MISMO cuerpo $N.
 */
inline std::string
asm_body_subst_greedy(const std::string &body,
                      const std::vector<ir::AsmRegBinding> &binds) {
    std::string out;
    out.reserve(body.size() + 16);
    for (size_t i = 0; i < body.size();) {
        if (body[i] != '$') {
            out += body[i++];
            continue;
        }
        size_t j = i + 1;
        int idx = 0;
        bool any = false;
        while (j < body.size() && std::isdigit((unsigned char)body[j])) {
            idx = idx * 10 + (body[j] - '0');
            ++j;
            any = true;
        }
        if (!any) {
            out += body[i++];
            continue;
        }
        std::string reg;
        for (const ir::AsmRegBinding &b : binds)
            if (b.reg_auto && b.ph_index == idx) {
                reg = b.reg;
                break;
            }
        if (reg.empty()) {
            out += body[i];
            ++i;
            continue;
        } // $N sin binding
        out += reg;
        i = j;
    }
    return out;
}

} // namespace vx

#endif // VX_ASM_PHYS_REG_H
