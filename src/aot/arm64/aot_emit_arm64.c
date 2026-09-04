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
 * @file aot/arm64/aot_emit_arm64.c
 * @brief Lo propio de AArch64 al emitir objetos: su marca y sus reubicaciones.
 *
 * El layout de un ELF64 reubicable vive en @c common/aot_emit_elf_obj.c y es
 * el mismo para todas las arquitecturas de 64 bits.  Aqui solo estan los seis
 * numeros que cambian, mas el envoltorio que los pone.
 *
 * Antes esto no existia: el emisor de objetos estaba dentro del de x86-64 con
 * la maquina clavada, asi que un objeto de ARM salia rotulado como de otra
 * arquitectura y una llamada `bl` a otra funcion se rechazaba con "reloc kind
 * no soportado".  El efecto era que NINGUN programa de ARM con llamadas entre
 * funciones se podia escribir a un `.o` -- ni siquiera dos funciones que se
 * llamaran la una a la otra.
 */

#include "aot/aot_emit_shim.h"

#include "../common/aot_elf_obj_arch.h"
#include "../common/aot_emit_internal.h"

/* LibPEparse trae los tipos ELF genericos, pero no siempre los numeros de
 * AArch64.  Se definen aqui, que es donde corresponde: son de esta
 * arquitectura y de ninguna otra.  Valores de la especificacion "ELF for the
 * Arm 64-bit Architecture (AArch64)". */
#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif
#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64 257
#endif
#ifndef R_AARCH64_PREL32
#define R_AARCH64_PREL32 261
#endif
#ifndef R_AARCH64_TLSLE_ADD_TPREL_HI12
#define R_AARCH64_TLSLE_ADD_TPREL_HI12 549
#endif
/* `bl` y `b` a una etiqueta: el enlazador parchea el campo imm26 de la propia
 * instruccion de 32 bits.  Es el tipo que faltaba y sin el no habia manera de
 * escribir una llamada entre funciones. */
#ifndef R_AARCH64_CALL26
#define R_AARCH64_CALL26 283
#endif

/**
 * @copydoc aot_elf_obj_arch_arm64
 */
const AotElfObjArch *aot_elf_obj_arch_arm64(void) {
    static const AotElfObjArch A = {
        EM_AARCH64,
        R_AARCH64_CALL26, /* llamada a simbolo indefinido */
        R_AARCH64_CALL26, /* llamada dentro del propio objeto */
        R_AARCH64_PREL32, /* referencia PC-relativa de 32 bits */
        R_AARCH64_ABS64,  /* direccion absoluta de 64 bits */
        /* TLS local-exec: la secuencia de AArch64 no es un solo campo de 32
         * bits como en x86, asi que no se admite todavia.  A cero, que es como
         * la ficha dice "esto no lo traigo": el emisor lo RECHAZA en vez de
         * escribir una reubicacion que el enlazador interpretaria de otra
         * forma. */
        0,
        /* El desplazamiento se cuenta desde el principio de la instruccion, no
         * desde su final: aqui no hay nada que descontar. */
        0,
    };
    return &A;
}

/**
 * @brief Emite un objeto ELF64 reubicable de AArch64.
 *
 * Misma firma que @c aot_emit_elf_obj (la de x86-64); lo unico distinto es la
 * ficha que se le pasa al emisor compartido.
 *
 * @param path       Fichero a escribir.
 * @param secs       Secciones del objeto.
 * @param num_secs   Cuantas.
 * @param relocs     Reubicaciones pendientes.
 * @param num_relocs Cuantas.
 * @param syms       Simbolos a exportar.
 * @param num_syms   Cuantos.
 * @param err        Buffer donde dejar el motivo si falla.
 * @param err_cap    Su tamano.
 * @return 1 si se escribio; 0 si no, con @p err puesto.
 */
int aot_emit_elf_obj_arm64(const char *path, const AotSection *secs,
                           int num_secs, const AotReloc *relocs,
                           int num_relocs, const AotSym *syms, int num_syms,
                           char *err, size_t err_cap) {
    return aot_emit_elf_obj_arch(path, secs, num_secs, relocs, num_relocs, syms,
                                 num_syms, aot_elf_obj_arch_arm64(), err,
                                 err_cap);
}
