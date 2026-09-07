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
 * @file aot/common/aot_emit_internal.h
 * @brief Cabecera INTERNA del emisor AOT (frontera con LibPEparse) COMPARTIDA
 *        por los emisores por-arquitectura.
 *
 * Parte del desacople multi-arch: la emision de objetos se parte en
 * @c aot/common/ (arch-neutral) + @c aot/x86_64/ + @c aot/x86_32/ +
 * @c aot/x86_16/ + @c aot/arm64/.  Este header reune lo COMPARTIDO por todos
 * los .c de emision: las cabeceras C de LibPEparse (que solo compilan como C) y
 * los helpers arch-neutrales pequenos (escritura LE, aplicacion de reloc ya
 * resuelta, tamano de seccion, buffer de salida con append).  Se compila SOLO
 * desde los .c de emision (todos C); el lado C++ del compilador no lo ve.
 *
 * Los helpers pequenos son @c static @c inline: cada TU de emision recibe su
 * propia copia sin conflicto de enlace.  Los grandes compartidos (tabla hash
 * ELF, impl COFF, ...) se DECLARAN aqui y se DEFINEN en @c aot_emit_common.c.
 */

#ifndef AOT_COMMON_AOT_EMIT_INTERNAL_H
#define AOT_COMMON_AOT_EMIT_INTERNAL_H

#include "aot/aot_emit_shim.h" // ABI C plana del emisor (AotSection, AotReloc...)

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CreatePe.h"
#include "CreateELF.h"
#include "LibELFparse.h"
#include "LibCOFFparse.h"
#include "LibPEparse.h" // lectura de exports de DLL (aot_pe_export_names)

/* Constante de ELF a secas -- no de una arquitectura concreta -- que no trae
 * CreateELF.h del submodulo.  Vive aqui, con el resto de lo comun, porque la
 * usan tanto el emisor de ejecutables como el de objetos; tenerla dentro del
 * fichero de x86-64 obligaba a los demas a ir a buscarla alli. */
#ifndef SHF_TLS
#define SHF_TLS 0x400u /* la seccion contiene almacenamiento thread-local */
#endif

/* -------------------------------------------------------------------------
 *  Helpers arch-neutrales pequenos (static inline: copia por TU, sin ODR).
 * ------------------------------------------------------------------------- */

/* Copia segura del mensaje de error al buffer del llamador. */
static inline void set_err(char *err, size_t cap, const char *msg) {
    if (!err || cap == 0) return;
    size_t n = strlen(msg);
    if (n >= cap) n = cap - 1;
    memcpy(err, msg, n);
    err[n] = '\0';
}

/* Escritura little-endian de 2/4/8 bytes en un buffer. */
static inline void wr16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static inline void wr32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
/* Alias historico de wr32le (mismo comportamiento; ambos nombres en uso). */
static inline void wr32(uint8_t *p, uint32_t v) {
    wr32le(p, v);
}
static inline void wr64le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = (uint8_t)(v >> (i * 8));
}

/* "Aqui no hay base de imagen", para los emisores de ELF y de objetos.
 *
 * No vale pasar 0: en un binario plano la base 0 es legitima, asi que un cero
 * no distingue "carga en 0" de "no aplica".  Con el centinela, una RVA32 que
 * llegue a un emisor que no puede resolverla FALLA -- que es lo correcto: son
 * relocs de PE y no tienen sentido en un ELF --, en vez de escribir la
 * direccion entera creyendo que es un desplazamiento. */
#define AOT_NO_IMAGE_BASE UINT64_MAX

/* Aplica UNA relocation ya resuelta: @p target_value es la direccion (ADDR) o
 * el tamano (SIZE) del objetivo + addend; @p site_va es la VA del sitio (para
 * el rel32 PC-relativo); @p image_base es la base de carga, que solo mira
 * @c AOT_RELOC_RVA32 -- se pasa aqui, y no se resta antes de llamar, para que
 * como se calcula un RVA este escrito en UN sitio y no en los ocho que llaman;
 * @p site escribe en el buffer de la seccion del sitio en su offset.  Devuelve
 * 0 en error de tamano/kind.  ARCH-NEUTRAL: escribe el valor crudo
 * (rel32/abs64/imm); el encoding de instruccion especifico de cada ISA para
 * relocs de CODIGO no se aplica aqui (esas se emiten como registros o las
 * resuelve el ensamblado whole-program). */
static inline int apply_reloc(uint8_t *site, uint64_t site_va,
                              uint64_t target_value, int kind,
                              uint64_t image_base) {
    switch (kind) {
    case AOT_RELOC_REL32: {
        int64_t rel = (int64_t)target_value - (int64_t)(site_va + 4);
        wr32le(site, (uint32_t)(int32_t)rel);
        return 1;
    }
    case AOT_RELOC_IMM32: wr32le(site, (uint32_t)target_value); return 1;
    case AOT_RELOC_RVA32: {
        /* Se RECHAZA en vez de truncar.  Un objetivo por debajo de la base, o a
         * mas de 4 GiB de ella, no tiene RVA; escribir los 32 bits bajos daria
         * una tabla bien formada que apunta a cualquier sitio, y el sistema la
         * seguiria.  Fallar aqui es lo unico util que se puede hacer. */
        if (image_base == AOT_NO_IMAGE_BASE) return 0; // no aplica a este formato
        if (target_value < image_base) return 0;
        const uint64_t rva = target_value - image_base;
        if (rva > 0xFFFFFFFFull) return 0;
        wr32le(site, (uint32_t)rva);
        return 1;
    }
    case AOT_RELOC_ABS64:
    case AOT_RELOC_IMM64: wr64le(site, target_value); return 1;
    case AOT_RELOC_ARM64_CALL26: {
        /* AArch64 BL/B: instruccion de 32 bits con imm26 = (target-site)>>2 en
         * los bits [25:0]; se conservan los 6 bits altos del opcode. */
        int64_t off = (int64_t)target_value - (int64_t)site_va;
        uint32_t ins = (uint32_t)site[0] | ((uint32_t)site[1] << 8) |
                       ((uint32_t)site[2] << 16) | ((uint32_t)site[3] << 24);
        uint32_t imm26 = (uint32_t)((off >> 2) & 0x03FFFFFF);
        ins = (ins & 0xFC000000u) | imm26;
        wr32le(site, ins);
        return 1;
    }
    default: return 0;
    }
}

/* Tamano "logico" de una seccion (datos inicializados o BSS). */
static inline uint64_t aot_sec_size(const AotSection *s) {
    return (s->flags & AOT_SEC_BSS) ? s->bss_size : s->size;
}

/* Alinea x hacia arriba a un multiplo de a (potencia de 2). */
static inline uint32_t aot_dyn_align_u32(uint32_t x, uint32_t a) {
    return (x + (a - 1)) & ~(a - 1);
}

/* Version macro de 64 bits (usada por los dynexec 64/32). */
#ifndef AOT_DYN_ALIGN
#define AOT_DYN_ALIGN(x, a) (((x) + ((a) - 1)) & ~((uint64_t)(a) - 1))
#endif

/* Constantes ELF dinamicas compartidas por los dynexec 64/32 (las estandar --
 * PF_*, STB_*, STT_*, DT_NEEDED/HASH/STRTAB/... -- vienen de LibELFparse.h /
 * CreateELF.h; aqui solo las que esos headers no traen). */
#ifndef AOT_ELF_PAGE
#define AOT_ELF_PAGE 0x1000ull
#endif
#ifndef DT_NULL
#define DT_NULL 0
#endif
#ifndef DT_FLAGS_1
#define DT_FLAGS_1 0x6ffffffbULL
#endif
#ifndef DF_BIND_NOW
#define DF_BIND_NOW 0x8
#endif
#ifndef DF_1_NOW
#define DF_1_NOW 0x1
#endif

/* Buffer de salida con append + alineacion (compartido por dynexec + .o). */
typedef struct {
    uint8_t *p;
    size_t len, cap;
} OBuf;
static inline int ob_reserve(OBuf *o, size_t extra) {
    if (o->len + extra <= o->cap) return 1;
    size_t nc = o->cap ? o->cap * 2 : 4096;
    while (nc < o->len + extra)
        nc *= 2;
    uint8_t *np = (uint8_t *)realloc(o->p, nc);
    if (!np) return 0;
    o->p = np;
    o->cap = nc;
    return 1;
}
static inline int ob_put(OBuf *o, const void *data, size_t n) {
    if (!ob_reserve(o, n)) return 0;
    if (n) {
        if (data)
            memcpy(o->p + o->len, data, n);
        else
            memset(o->p + o->len, 0, n);
    }
    o->len += n;
    return 1;
}
static inline int ob_align(OBuf *o, size_t a) {
    while (o->len % a) {
        uint8_t z = 0;
        if (!ob_put(o, &z, 1)) return 0;
    }
    return 1;
}

/* -------------------------------------------------------------------------
 *  Estado compartido definido en aot_emit_common.c.
 * ------------------------------------------------------------------------- */

/* Simbolos de depuracion (nivel 1) fijados por el driver antes de emitir un
 * EXEC (ver aot_set_debug_symbols).  n=0 -> sin simbolos (cero coste).  Los
 * emisores de EXEC por-arch los leen; definidos en aot_emit_common.c. */
extern const AotSym *g_aot_dbg_syms;
extern int g_aot_dbg_n;

/* Hash SysV de ELF (para .hash / DT_HASH).  Usado por los dynexec 64/32
 * (aun en los emisores por-arch); definido en aot_emit_common.c. */
/* 32 bits FIJOS: el hash esta definido asi y se apoya en salirse por arriba.
 * Con `unsigned long` salia distinto en Linux (64 bits) que en Windows (32), y
 * la tabla `.hash` que emitiamos no la sabia recorrer el enlazador dinamico.
 * Ver la nota completa en la definicion. */
uint32_t aot_elf_hash(const char *name);

#endif /* AOT_COMMON_AOT_EMIT_INTERNAL_H */
