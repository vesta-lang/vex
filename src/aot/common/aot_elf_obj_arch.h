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
 * @file aot/common/aot_elf_obj_arch.h
 * @brief Lo UNICO que distingue a una arquitectura al emitir un objeto ELF64.
 *
 * El layout de un ELF64 reubicable -- cabecera, tabla de secciones, simbolos,
 * cadenas, secciones de reubicacion -- es el mismo para x86-64 y para AArch64.
 * Lo unico que cambia son SEIS datos: la marca de maquina y el numero de tipo
 * de cada clase de reubicacion.
 *
 * De ahi que exista esta ficha en vez de un emisor por arquitectura: duplicar
 * trescientas lineas de layout para cambiar seis numeros deja dos copias que
 * divergen, y la que se quede corta lo hara en silencio.  Cada arquitectura
 * aporta su ficha; el emisor es uno.
 */

#ifndef AOT_COMMON_AOT_ELF_OBJ_ARCH_H
#define AOT_COMMON_AOT_ELF_OBJ_ARCH_H

#include <stddef.h>
#include <stdint.h>

/* Los tipos del objeto (AotSection/AotReloc/AotSym) son typedefs de structs
 * anonimos, asi que no se pueden declarar por adelantado: hay que traerlos. */
#include "aot/aot_emit_shim.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Los numeros de una arquitectura para el emisor de objetos ELF64.
 *
 * Un tipo a 0 significa "esta arquitectura no lo admite", y el emisor lo
 * rechaza DICIENDOLO en vez de escribir una reubicacion que el enlazador no
 * sabria interpretar.
 */
typedef struct {
    /** @c e_machine de la cabecera ELF: @c EM_X86_64 (62), @c EM_AARCH64 (183). */
    uint16_t e_machine;
    /** Llamada a un simbolo INDEFINIDO (libc y demas). */
    uint32_t r_call_extern;
    /** Llamada a una funcion del MISMO objeto, contra simbolo de seccion. */
    uint32_t r_call_local;
    /** Referencia PC-relativa de 32 bits a datos. */
    uint32_t r_pcrel32;
    /** Direccion absoluta de 64 bits. */
    uint32_t r_abs64;
    /** TLS local-exec de 32 bits; 0 si la arquitectura no lo trae aqui. */
    uint32_t r_tpoff32;
    /**
     * @brief Cuanto hay que restarle al addend de una referencia PC-relativa.
     *
     * En x86-64 el desplazamiento se cuenta desde el FINAL de la instruccion,
     * asi que hay que compensar sus cuatro bytes de campo; en AArch64 se
     * cuenta desde el principio y no se compensa nada.  Es un numero y no un
     * `if` por arquitectura repartido por el emisor.
     */
    int32_t pcrel_bias;
} AotElfObjArch;

/** @brief La ficha de x86-64.  Definida en @c x86_64/aot_emit_x86_64.c. */
const AotElfObjArch *aot_elf_obj_arch_x86_64(void);

/** @brief La ficha de AArch64.  Definida en @c arm64/aot_emit_arm64.c. */
const AotElfObjArch *aot_elf_obj_arch_arm64(void);

/**
 * @brief Escribe un objeto ELF64 reubicable con la ficha que se le pase.
 *
 * El emisor de verdad, compartido: cada arquitectura solo aporta su @p A.
 * Declarado aparte del header publico porque los envoltorios por arquitectura
 * son la puerta de fuera; esto es la maquinaria de dentro.
 *
 * @param A Ficha de la arquitectura de destino.  No puede ser nula.
 * @return 1 si se escribio; 0 si no, con @p err puesto.
 */
int aot_emit_elf_obj_arch(const char *path, const AotSection *secs,
                          int num_secs, const AotReloc *relocs, int num_relocs,
                          const AotSym *syms, int num_syms,
                          const AotElfObjArch *A, char *err, size_t err_cap);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AOT_COMMON_AOT_ELF_OBJ_ARCH_H */
