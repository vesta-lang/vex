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
 * @file aot/x86_64/aot_emit_x86_64.c
 * @brief Emisores de objetos AOT para x86-64 (AMD64): PE/ELF64 EXEC + dynexec +
 *        .o (ELF/COFF) + .so + .dll sobre LibPEparse.
 *
 * Parte del desacople multi-arch (aot/common + aot/x86_64 + aot/x86_32 +
 * aot/x86_16 + aot/arm64).  Aqui viven SOLO los emisores de 64 bits; los de 32
 * bits estan en aot/x86_32, y los helpers arch-neutrales + la frontera con
 * LibPEparse en aot/common.  Se compila como C.
 */

#include "aot/aot_emit_shim.h"

/* Helpers arch-neutrales + cabeceras C de LibPEparse (frontera compartida).
 * Include RELATIVO al fichero: no se toca el include-path global (la regla de
 * estructura prohibe meter src/ en el path). */
#include "../common/aot_elf_obj_arch.h" // la ficha de esta arquitectura
#include "../common/aot_emit_internal.h"

/* aot_set_debug_symbols + g_aot_dbg_syms/n -> movidos a
 * common/aot_emit_common.c (arch-neutral); se leen aqui via las declaraciones
 * extern del header interno.
 *
 * =========================================================================
 *  PE32+
 * ========================================================================= */

/* Traduce flags genericos AOT_SEC_* a Characteristics de seccion PE. */
static _DWORD pe_section_chars(uint32_t flags) {
    _DWORD c = 0;
    if (flags & AOT_SEC_CODE) c |= ___IMAGE_SCN_CNT_CODE;
    if (flags & AOT_SEC_DATA) c |= ___IMAGE_SCN_CNT_INITIALIZED_DATA;
    if (flags & AOT_SEC_BSS) c |= ___IMAGE_SCN_CNT_UNINITIALIZED_DATA;
    if (flags & AOT_SEC_EXEC) c |= ___IMAGE_SCN_MEM_EXECUTE;
    if (flags & AOT_SEC_READ) c |= ___IMAGE_SCN_MEM_READ;
    if (flags & AOT_SEC_WRITE) c |= ___IMAGE_SCN_MEM_WRITE;
    return c;
}

/* Compara dos nombres de DLL ignorando mayusculas/minusculas (ASCII).  Windows
 * resuelve los imports case-insensitive, asi que "KERNEL32.dll" y
 * "kernel32.dll" son la MISMA libreria y deben agruparse en un solo
 * descriptor de import. */
static int aot_dll_name_eq(const char *a, const char *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    for (; *a && *b; ++a, ++b) {
        int ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}

/* TLS (thread_local) PE: si alguna seccion de usuario es SHF_TLS, sintetiza la
 * infraestructura TLS NATIVA de Windows -- una seccion `.tls$d` con _tls_index
 * (lo rellena el cargador con el indice del slot), un array de callbacks vacio,
 * y el IMAGE_TLS_DIRECTORY -- y pone DataDirectory[9] (TLS) apuntando ahi.  El
 * acceso (mov gs:[0x58] -> [_tls_index] -> bloque -> +offset) lo emite el
 * codegen; el reloc al simbolo `__vx_tls_index` se resuelve a la VA que
 * devuelve esta funcion.  Compartido por aot_emit_pe (.exe) y aot_emit_pe_dll
 * (.dll): el cargador procesa el directorio TLS en ambos (Vista+).
 * @return VA de _tls_index, o 0 si el modulo no tiene TLS. */
static uint64_t aot_pe_synth_tls(PE64FILE_struct *pe, const AotSection *secs,
                                 int num_secs, int is_dll, int cb_section,
                                 uint32_t cb_off) {
    int tls_sec = -1;
    for (int i = 0; i < num_secs; ++i)
        if (secs[i].flags & AOT_SEC_TLS) {
            tls_sec = i;
            break;
        }
    if (tls_sec < 0) return 0;
    const uint64_t image_base = pe->ntHeaders.OptionalHeader.ImageBase;
    /* Layout de .tls$d (64 B): [0]=_tls_index(4) [4]=pad
     * [8]=array de callbacks [&__vx_tls_init, NULL] (16 B)
     * [24]=IMAGE_TLS_DIRECTORY64(40). */
    _BYTE tlsd[64];
    memset(tlsd, 0, sizeof(tlsd));
    int tlsd_idx =
        addSection(pe, ".tls$d",
                   ___IMAGE_SCN_CNT_INITIALIZED_DATA | ___IMAGE_SCN_MEM_READ |
                       ___IMAGE_SCN_MEM_WRITE,
                   tlsd, (_DWORD)sizeof(tlsd));
    const uint32_t tls_rva = pe->sectionHeaders[tls_sec].VirtualAddress;
    const uint32_t tlsd_rva = pe->sectionHeaders[tlsd_idx].VirtualAddress;
    _BYTE *sd = pe->sectionData[tlsd_idx];
    /* Array de callbacks en +8: [&__vx_tls_init, NULL].  El callback aplica la
     * plantilla por-hilo (el cargador no siempre la copia para el TLS de una
     * .dll en un consumidor minimal). */
    int have_cb = (cb_section >= 0 && cb_section < pe->numberOfSections);
    if (have_cb) {
        uint64_t cb_va =
            image_base + pe->sectionHeaders[cb_section].VirtualAddress + cb_off;
        memcpy(sd + 8, &cb_va, 8); /* [+8] = &__vx_tls_init ; [+16] = NULL */
    }
    _BYTE *db = sd + 24; /* IMAGE_TLS_DIRECTORY */
    uint64_t start = image_base + tls_rva;
    uint64_t end = image_base + tls_rva + secs[tls_sec].size;
    uint64_t idx_va = image_base + tlsd_rva + 0;   /* &_tls_index */
    uint64_t cbarr_va = image_base + tlsd_rva + 8; /* &array de callbacks */
    memcpy(db + 0, &start, 8);
    memcpy(db + 8, &end, 8);
    memcpy(db + 16, &idx_va, 8);
    memcpy(db + 24, &cbarr_va, 8);
    uint32_t zfill = (uint32_t)secs[tls_sec].bss_size;
    memcpy(db + 32, &zfill, 4);      /* SizeOfZeroFill */
    uint32_t tls_char = 0x00400000u; /* IMAGE_SCN_ALIGN_8BYTES */
    memcpy(db + 36, &tls_char, 4);   /* Characteristics (alineamiento) */
    pe->ntHeaders.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_TLS]
        .VirtualAddress = tlsd_rva + 24;
    pe->ntHeaders.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_TLS]
        .Size = 40;
    /* Campos VA ABSOLUTOS: el callback (+8) y los 4 del directorio (Start/End/
     * Index/Callbacks en +24/+32/+40/+48).  En un EXE fijamos la base (sin
     * ASLR); en una DLL -- que el cargador reubica -- emitimos una .reloc
     * (IMAGE_REL_BASED_DIR64) para que el loader los fije al relocar. */
    if (is_dll) {
        const uint32_t page = tlsd_rva & ~0xFFFu;
        _BYTE rel[24];
        uint32_t nrelocs = 4 + (have_cb ? 1 : 0);
        uint32_t blksz = 8u + nrelocs * 2u;
        if (blksz & 3u) blksz += 2u; /* bloques .reloc alineados a 4 (pad 0) */
        memset(rel, 0, sizeof(rel));
        memcpy(rel + 0, &page, 4);
        memcpy(rel + 4, &blksz, 4);
        uint32_t voff[5];
        int nv = 0;
        if (have_cb) voff[nv++] = tlsd_rva + 8; /* callback */
        voff[nv++] = tlsd_rva + 24;             /* Start */
        voff[nv++] = tlsd_rva + 32;             /* End */
        voff[nv++] = tlsd_rva + 40;             /* Index */
        voff[nv++] = tlsd_rva + 48;             /* Callbacks */
        for (int k = 0; k < nv; ++k) {
            uint16_t e = (uint16_t)((10u << 12) | ((voff[k] - page) & 0xFFFu));
            memcpy(rel + 8 + k * 2, &e, 2);
        }
        int rel_idx = addSection(pe, ".reloc",
                                 ___IMAGE_SCN_CNT_INITIALIZED_DATA |
                                     ___IMAGE_SCN_MEM_READ |
                                     0x02000000u /* DISCARDABLE */,
                                 rel, blksz);
        const uint32_t rel_rva = pe->sectionHeaders[rel_idx].VirtualAddress;
        pe->ntHeaders.OptionalHeader
            .DataDirectory[___IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress = rel_rva;
        pe->ntHeaders.OptionalHeader
            .DataDirectory[___IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .Size = blksz;
    } else {
        pe->ntHeaders.OptionalHeader.DllCharacteristics &=
            (uint16_t)~___IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }
    return idx_va;
}

/* TLS PE: resuelve un reloc al simbolo `__vx_tls_index` (RIP-relativo) o un
 * SECREL32 (offset del var dentro de su seccion .tls).  @return 1 si lo manejo
 * (el caller debe `continue`), 0 si no es un reloc TLS. */
static int aot_pe_apply_tls_reloc(PE64FILE_struct *pe, const AotSection *secs,
                                  int num_secs, const AotReloc *rl,
                                  uint64_t tls_index_va) {
    const uint64_t image_base = pe->ntHeaders.OptionalHeader.ImageBase;
    if (rl->extern_name && strcmp(rl->extern_name, "__vx_tls_index") == 0) {
        if (tls_index_va == 0 || rl->site_section < 0 ||
            rl->site_section >= num_secs)
            return 1; /* manejado (silenciosamente no-op si malformado) */
        (void)secs;
        uint64_t sva = image_base +
                       pe->sectionHeaders[rl->site_section].VirtualAddress +
                       rl->site_off;
        int32_t disp =
            (int32_t)((int64_t)tls_index_va - (int64_t)(sva + 4) + rl->addend);
        memcpy(pe->sectionData[rl->site_section] + rl->site_off, &disp, 4);
        return 1;
    }
    if (rl->kind == AOT_RELOC_SECREL32) {
        if (rl->site_section < 0 || rl->site_section >= num_secs) return 1;
        int32_t off = (int32_t)((int64_t)rl->target_off + rl->addend);
        memcpy(pe->sectionData[rl->site_section] + rl->site_off, &off, 4);
        return 1;
    }
    return 0;
}

/* --aot-debug=1 (PE): apende una tabla de simbolos COFF al final del .exe/.dll
 * ya escrito y parchea el IMAGE_FILE_HEADER (PointerToSymbolTable +
 * NumberOfSymbols) para exponerla.  gdb/WinDbg/objdump leen los IMAGE_SYMBOL
 * (18 bytes:
 * Name(8)/Value(4)/SectionNumber(2)/Type(2)/StorageClass(1)/NumAux(1)). Value =
 * RVA (sec_rva[seccion] + offset): gdb calcula image_base + Value.  El symtab
 * va TRAS todas las secciones -> no afecta la ejecucion.  Best-effort: ante
 * cualquier fallo deja el fichero intacto (sin simbolos).  Los @p sec_rva son
 * las RVAs finales de cada seccion (pe.sectionHeaders[i].VirtualAddress). */
static void aot_pe_append_coff_symtab(const char *path, const AotSym *syms,
                                      int n, const uint32_t *sec_rva) {
    if (n <= 0 || !syms || !sec_rva) return;
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz < 0x40) {
        fclose(f);
        return;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
    if (!buf) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)fsz, f) != (size_t)fsz) {
        free(buf);
        fclose(f);
        return;
    }
    fclose(f);
    uint32_t e_lfanew = 0;
    memcpy(&e_lfanew, buf + 0x3c, 4);
    if ((size_t)e_lfanew + 24 > (size_t)fsz) {
        free(buf);
        return;
    }
    /* symtab COFF (18 bytes/sym, empaquetado a mano) + string table. */
    uint8_t *symtab = (uint8_t *)calloc((size_t)n, 18);
    uint32_t strtab_sz = 4; /* los primeros 4 bytes son el tamano */
    char *strtab = (char *)malloc(4);
    if (!symtab || !strtab) {
        free(buf);
        free(symtab);
        free(strtab);
        return;
    }
    for (int i = 0; i < n; ++i) {
        uint8_t *s = symtab + (size_t)i * 18;
        const char *nm = syms[i].name;
        size_t l = strlen(nm);
        if (l <= 8) {
            memcpy(s, nm, l); /* nombre inline en Name[8] (resto ya a 0) */
        } else {
            uint32_t zero = 0;
            memcpy(s, &zero, 4);          /* Name.Zeroes = 0 */
            memcpy(s + 4, &strtab_sz, 4); /* Name.Offset */
            char *ns = (char *)realloc(strtab, strtab_sz + l + 1);
            if (!ns) break;
            strtab = ns;
            memcpy(strtab + strtab_sz, nm, l + 1);
            strtab_sz += (uint32_t)(l + 1);
        }
        uint32_t rva = sec_rva[syms[i].section] + (uint32_t)syms[i].offset;
        memcpy(s + 8, &rva, 4); /* Value = RVA */
        int16_t sn = (int16_t)(syms[i].section + 1);
        memcpy(s + 12, &sn, 2);                   /* SectionNumber (1-based) */
        uint16_t ty = syms[i].is_func ? 0x20 : 0; /* 0x20 = funcion */
        memcpy(s + 14, &ty, 2);
        s[16] = 2; /* IMAGE_SYM_CLASS_EXTERNAL */
        s[17] = 0; /* sin aux */
    }
    memcpy(strtab, &strtab_sz, 4); /* el tamano al inicio del strtab */
    /* Parchear el IMAGE_FILE_HEADER: PointerToSymbolTable (+8) y
     * NumberOfSymbols (+12) tras la firma "PE\0\0" (e_lfanew + 4). */
    uint32_t symtab_off = (uint32_t)fsz;
    uint32_t nsyms = (uint32_t)n;
    memcpy(buf + e_lfanew + 4 + 8, &symtab_off, 4);
    memcpy(buf + e_lfanew + 4 + 12, &nsyms, 4);
    FILE *o = fopen(path, "wb");
    if (o) {
        fwrite(buf, 1, (size_t)fsz, o);
        fwrite(symtab, 1, (size_t)n * 18, o);
        fwrite(strtab, 1, strtab_sz, o);
        fclose(o);
    }
    free(buf);
    free(symtab);
    free(strtab);
}

/* Apunta DataDirectory[EXCEPTION] a la seccion `.pdata`, si la hay.
 *
 * Sin este directorio la tabla NO EXISTE para el sistema: `.pdata` seria una
 * seccion de datos mas.  `RtlLookupFunctionEntry` la busca aqui, nunca por
 * nombre, y la funcion que no aparece la trata como hoja -- con lo que el
 * desenrollado se detiene en el primer marco.  El sintoma no es un error: es un
 * proceso que muere sin manejador y sin traza, que es justo lo que la tabla
 * viene a evitar.
 *
 * Se localiza por NOMBRE, y no por un indice que pase el driver, igual que
 * `.reloc` y `.tls` aqui al lado.  Asi un guion de enlazado puede colocar la
 * seccion donde quiera y el directorio la sigue sin tocar nada mas.  El indice
 * PE coincide con el indice AOT porque las secciones se anaden en orden.
 *
 * @return 1 si quedo puesto, y tambien si no hay `.pdata` -- no todos los
 *         binarios la llevan, y no llevarla es legitimo; 0 si la seccion existe
 *         pero su tamano no puede describir una tabla.
 */
static int aot_pe_set_exception_dir(PE64FILE_struct *pe, const AotSection *secs,
                                    int num_secs, char *err, size_t err_cap) {
    for (int i = 0; i < num_secs; ++i) {
        if (!secs[i].name || strcmp(secs[i].name, ".pdata") != 0) continue;

        const uint64_t size = aot_sec_size(&secs[i]);
        if (size == 0) return 1; /* declarada pero vacia: nada que anunciar */

        /* Cada RUNTIME_FUNCTION son TRES RVA de 4 bytes.  Un tamano que no sea
         * multiplo de 12 deja una entrada a medias al final, y el sistema la
         * leeria igual: recorre el directorio por su tamano, con busqueda
         * binaria, y no hay centinela que marque el final. */
        if (size % 12u != 0) {
            /* Se devuelve el CODIGO, no la frase.  Este fichero es C y no
             * alcanza el catalogo de diagnosticos; quien lo renderiza en el
             * idioma que toque es la frontera C++ del emisor.  Un error lo lee
             * una persona, y dejarlo escrito aqui lo fijaria a un idioma. */
            set_err(err, err_cap, "VX9252");
            return 0;
        }
        if (size > 0xFFFFFFFFull) {
            set_err(err, err_cap, "VX9253");
            return 0;
        }

        pe->ntHeaders.OptionalHeader
            .DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .VirtualAddress = pe->sectionHeaders[i].VirtualAddress;
        pe->ntHeaders.OptionalHeader
            .DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .Size = (uint32_t)size;
        return 1;
    }
    return 1;
}

/* Comparador de RUNTIME_FUNCTION por su RVA de inicio (little endian). */
static int aot_pe_cmp_runtime_function(const void *a, const void *b) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    const uint32_t bx = (uint32_t)x[0] | ((uint32_t)x[1] << 8) |
                        ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
    const uint32_t by = (uint32_t)y[0] | ((uint32_t)y[1] << 8) |
                        ((uint32_t)y[2] << 16) | ((uint32_t)y[3] << 24);
    if (bx < by) return -1;
    return (bx > by) ? 1 : 0;
}

/* Deja `.pdata` como el sistema la espera: compactada, ORDENADA y anunciada
 * con su tamano real.  Corre con las RVA ya escritas, que es el unico momento
 * en que existen.
 *
 * SE ORDENA, no se comprueba y ya esta.  Cuando la tabla la producia solo
 * nuestro driver bastaba con verificar que salia ordenada, porque el la
 * construia en orden.  Pero al enlazar, esta seccion es la CONCATENACION de las
 * tablas de cada objeto, y pegar dos tablas ordenadas da una desordenada: el
 * orden final depende de donde caiga el codigo de cada objeto, cosa que ningun
 * productor sabe por separado.  Ordenar aqui es lo unico que funciona para los
 * dos casos.
 *
 * Y hace falta porque el fallo no se manifiesta: el sistema busca en esta tabla
 * por BISECCION.  Una tabla desordenada no da error al consultarla -- devuelve
 * la entrada equivocada, o ninguna, para una direccion que si esta --, asi que
 * el desenrollado fallaria solo a veces y solo para algunas funciones.
 *
 * Las entradas a cero se COMPACTAN fuera y el directorio se reajusta al tamano
 * que queda.  Una entrada a cero no es una funcion en la RVA 0: es relleno de
 * alineamiento, o un hueco que ninguna reloc llego a tocar.  Dejarla dentro
 * seria peor que ignorarla, porque al ordenar se iria al principio y la
 * biseccion la encontraria antes que a ninguna otra.
 *
 * @return 1 si quedo bien, o si no hay `.pdata`; 0 con el motivo si alguna
 *         entrada es imposible.
 */
static int aot_pe_finish_pdata(PE64FILE_struct *pe, const AotSection *secs,
                               int num_secs, char *err, size_t err_cap) {
    for (int i = 0; i < num_secs; ++i) {
        if (!secs[i].name || strcmp(secs[i].name, ".pdata") != 0) continue;
        uint8_t *p = (uint8_t *)pe->sectionData[i];
        if (!p) return 1;

        const uint64_t size = aot_sec_size(&secs[i]);
        const uint64_t total = size / 12;

        /* Compactar: mover las entradas live al principio, conservando su
         * orden relativo (que aun no importa, pero mantenerlo hace que el
         * resultado sea reproducible). */
        uint64_t live = 0;
        for (uint64_t k = 0; k < total; ++k) {
            const uint8_t *e = p + k * 12;
            int all_zero = 1;
            for (int j = 0; j < 12; ++j)
                if (e[j]) {
                    all_zero = 0;
                    break;
                }
            if (all_zero) continue;
            if (live != k) memcpy(p + live * 12, e, 12);
            ++live;
        }
        // Lo que quedo detras ya no describe nada: a cero, para no confundir.
        if (live < total)
            memset(p + live * 12, 0, (size_t)((total - live) * 12));

        if (live > 1)
            qsort(p, (size_t)live, 12, aot_pe_cmp_runtime_function);

        /* Ya ordenada, se valida lo que el orden no arregla. */
        uint32_t prev_begin = 0;
        int has_prev = 0;
        for (uint64_t k = 0; k < live; ++k) {
            const uint8_t *e = p + k * 12;
            const uint32_t begin = (uint32_t)e[0] | ((uint32_t)e[1] << 8) |
                                   ((uint32_t)e[2] << 16) |
                                   ((uint32_t)e[3] << 24);
            const uint32_t end = (uint32_t)e[4] | ((uint32_t)e[5] << 8) |
                                 ((uint32_t)e[6] << 16) | ((uint32_t)e[7] << 24);
            if (end <= begin) {
                set_err(err, err_cap, "VX9254");
                return 0;
            }
            /* Dos funciones no pueden empezar en la misma direccion.  Si pasa,
             * es que la misma tabla entro dos veces o que una reloc se quedo
             * sin resolver, y la biseccion devolveria una de las dos al azar. */
            if (has_prev && begin == prev_begin) {
                set_err(err, err_cap, "VX9255");
                return 0;
            }
            prev_begin = begin;
            has_prev = 1;
        }

        /* El directorio se anuncio antes con el tamano de la seccion; ahora se
         * ajusta a lo que de verdad hay, que es lo que recorre la biseccion. */
        pe->ntHeaders.OptionalHeader
            .DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .Size = (uint32_t)(live * 12);
        return 1;
    }
    return 1;
}

int aot_emit_pe(const char *path, const AotLayoutCfg *cfg,
                const AotSection *secs, int num_secs, int entry_sec,
                uint64_t entry_off, const AotImport *imps, int num_imps,
                const AotReloc *relocs, int num_relocs, char *err,
                size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_pe: sin secciones");
        return 0;
    }
    if (entry_sec < 0 || entry_sec >= num_secs) {
        set_err(err, err_cap, "aot_emit_pe: entry_sec fuera de rango");
        return 0;
    }

    PE64FILE_struct pe;
    initializePE64File(&pe);

    /* Aplicar configuracion de layout (campos en 0 => se deja el default). */
    if (cfg) {
        if (cfg->image_base)
            pe.ntHeaders.OptionalHeader.ImageBase = cfg->image_base;
        if (cfg->section_align)
            pe.ntHeaders.OptionalHeader.SectionAlignment = cfg->section_align;
        if (cfg->file_align)
            pe.ntHeaders.OptionalHeader.FileAlignment = cfg->file_align;
        if (cfg->stack_reserve)
            pe.ntHeaders.OptionalHeader.SizeOfStackReserve = cfg->stack_reserve;
        if (cfg->stack_commit)
            pe.ntHeaders.OptionalHeader.SizeOfStackCommit = cfg->stack_commit;
        if (cfg->heap_reserve)
            pe.ntHeaders.OptionalHeader.SizeOfHeapReserve = cfg->heap_reserve;
        if (cfg->heap_commit)
            pe.ntHeaders.OptionalHeader.SizeOfHeapCommit = cfg->heap_commit;
        if (cfg->pe_subsystem > 0)
            pe.ntHeaders.OptionalHeader.Subsystem = (uint16_t)cfg->pe_subsystem;
    }

    /* Agregar las secciones del usuario en orden (indice PE == indice AOT). */
    for (int i = 0; i < num_secs; ++i) {
        const AotSection *s = &secs[i];
        if (s->flags & AOT_SEC_BSS) {
            addBssSection(&pe, s->name, s->bss_size);
        } else {
            addSection(&pe, s->name, pe_section_chars(s->flags),
                       (_BYTE *)s->data, s->size);
        }
    }

    /* Desenrollado: anunciar `.pdata` en el directorio de excepciones.  Va justo
     * detras del bucle porque es donde addSection ya ha asignado las
     * VirtualAddress de todas las secciones del usuario, que es lo unico que
     * hace falta; lo que se anada despues (una `.reloc` del TLS, por ejemplo)
     * se coloca al final y no mueve a las anteriores. */
    if (!aot_pe_set_exception_dir(&pe, secs, num_secs, err, err_cap)) {
        freePE64File(&pe); /* addSection copia los datos: liberar aqui es seguro */
        return 0;
    }

    /* TLS (thread_local): sintetizar el IMAGE_TLS_DIRECTORY + _tls_index si hay
     * seccion SHF_TLS (devuelve la VA de _tls_index para resolver los relocs).
     */
    uint64_t tls_index_va = aot_pe_synth_tls(
        &pe, secs, num_secs, 0, cfg ? cfg->tls_callback_section : -1,
        cfg ? cfg->tls_callback_off : 0);

    /* Relocations cross-seccion: resolver AHORA que addSection ya asigno las
     * VirtualAddress de todas las secciones del usuario (igual que el parcheo
     * de imports, pero generico).  ImageBase + sectionHeaders[i].VirtualAddress
     * es la VA de la seccion i; pe.sectionData[i] es su buffer mutable. */
    if (relocs && num_relocs > 0) {
        const uint64_t image_base = pe.ntHeaders.OptionalHeader.ImageBase;
        /* Si hay refs ABSOLUTAS (ABS64/IMM64, p.ej. --no-pie), la imagen DEBE
         * cargar en su ImageBase: sin tabla .reloc, el loader no puede
         * reubicar. Limpiamos DYNAMIC_BASE (ASLR) -> base fija (semantica
         * -no-pie).  Las refs RIP-relativas (DATA_REL32) no lo necesitan
         * (position-independent). */
        for (int r = 0; r < num_relocs; ++r) {
            if (relocs[r].kind == AOT_RELOC_ABS64 ||
                relocs[r].kind == AOT_RELOC_IMM64) {
                pe.ntHeaders.OptionalHeader.DllCharacteristics &=
                    (uint16_t)~___IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
                break;
            }
        }
        for (int r = 0; r < num_relocs; ++r) {
            const AotReloc *rl = &relocs[r];
            /* TLS PE: `__vx_tls_index` (RIP-rel al slot) + SECREL32 (offset del
             * var en .tls).  Manejados por el helper compartido. */
            if (aot_pe_apply_tls_reloc(&pe, secs, num_secs, rl, tls_index_va))
                continue;
            if (rl->site_section < 0 || rl->site_section >= num_secs ||
                rl->target_section < 0 || rl->target_section >= num_secs) {
                set_err(err, err_cap,
                        "aot_emit_pe: reloc con seccion fuera de rango");
                freePE64File(&pe);
                return 0;
            }
            uint64_t target_value;
            if (rl->target_is_imagebase) {
                /* `__ImageBase`: la base, tal cual.  Aqui es trivial porque es
                 * este mismo emisor quien la escribe en la cabecera. */
                target_value = image_base;
            } else if (rl->target_is_size) {
                target_value = aot_sec_size(&secs[rl->target_section]);
            } else {
                target_value =
                    image_base +
                    pe.sectionHeaders[rl->target_section].VirtualAddress;
                if (rl->target_is_end)
                    target_value += aot_sec_size(&secs[rl->target_section]);
                else
                    target_value += rl->target_off;
            }
            target_value = (uint64_t)((int64_t)target_value + rl->addend);
            uint64_t site_va =
                image_base +
                pe.sectionHeaders[rl->site_section].VirtualAddress +
                rl->site_off;
            uint32_t width =
                (rl->kind == AOT_RELOC_ABS64 || rl->kind == AOT_RELOC_IMM64)
                    ? 8u
                    : 4u;
            if (rl->site_off + width > secs[rl->site_section].size) {
                set_err(err, err_cap,
                        "aot_emit_pe: reloc fuera de la seccion del sitio");
                freePE64File(&pe);
                return 0;
            }
            if (!apply_reloc(pe.sectionData[rl->site_section] + rl->site_off,
                             site_va, target_value, rl->kind, image_base)) {
                set_err(err, err_cap, "aot_emit_pe: reloc kind invalido");
                freePE64File(&pe);
                return 0;
            }
        }
    }

    /* Imports -> .idata + IAT + parcheo de los call. */
    if (imps && num_imps > 0) {
        const ___IMAGE_SECTION_HEADER *last =
            &pe.sectionHeaders[pe.numberOfSections - 1];
        _DWORD idataRVA = align(last->VirtualAddress + last->Misc.VirtualSize,
                                pe.ntHeaders.OptionalHeader.SectionAlignment);

        /* Agrupar por DLL preservando orden + dedup de funciones. */
        int max_libs = num_imps;
        const char **lib_names =
            (const char **)calloc(max_libs, sizeof(char *));
        const char ***lib_funcs =
            (const char ***)calloc(max_libs, sizeof(char **));
        int *lib_nfuncs = (int *)calloc(max_libs, sizeof(int));
        int num_libs = 0;
        for (int k = 0; k < num_imps; ++k) {
            int di = -1;
            for (int j = 0; j < num_libs; ++j)
                /* DLL names case-insensitive (Windows): el stub usa
                 * "KERNEL32.dll" y un FFI extern puede usar "kernel32.dll" ->
                 * deben fundirse en UN solo descriptor de import. */
                if (aot_dll_name_eq(lib_names[j], imps[k].dll)) {
                    di = j;
                    break;
                }
            if (di < 0) {
                di = num_libs++;
                lib_names[di] = imps[k].dll;
                lib_funcs[di] = (const char **)calloc(num_imps, sizeof(char *));
                lib_nfuncs[di] = 0;
            }
            int dup = 0;
            for (int j = 0; j < lib_nfuncs[di]; ++j)
                if (strcmp(lib_funcs[di][j], imps[k].func) == 0) {
                    dup = 1;
                    break;
                }
            if (!dup) lib_funcs[di][lib_nfuncs[di]++] = imps[k].func;
        }

        ImportLibrary *libs =
            (ImportLibrary *)calloc(num_libs, sizeof(ImportLibrary));
        for (int j = 0; j < num_libs; ++j) {
            libs[j].dllName = lib_names[j];
            libs[j].functions = lib_funcs[j];
            libs[j].numFunctions = lib_nfuncs[j];
        }

        _DWORD idata_size = 0;
        ImportOffsetEntry *off_entries = NULL;
        int num_off = 0;
        _BYTE *idata_buf = buildMultiIdataSectionWithOffsets(
            libs, num_libs, idataRVA, &idata_size, &off_entries, &num_off);

        int idata_idx = -1;
        if (idata_buf) {
            idata_idx =
                addSection(&pe, ".idata",
                           ___IMAGE_SCN_CNT_INITIALIZED_DATA |
                               ___IMAGE_SCN_MEM_READ | ___IMAGE_SCN_MEM_WRITE,
                           idata_buf, idata_size);

            pe.ntHeaders.OptionalHeader
                .DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT]
                .VirtualAddress = idataRVA;
            pe.ntHeaders.OptionalHeader
                .DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT]
                .Size =
                (_DWORD)(sizeof(___IMAGE_IMPORT_DESCRIPTOR) * (num_libs + 1));
            if (num_off > 0) {
                pe.ntHeaders.OptionalHeader
                    .DataDirectory[___IMAGE_DIRECTORY_ENTRY_IAT]
                    .VirtualAddress = idataRVA + (_DWORD)off_entries[0].offset;
                pe.ntHeaders.OptionalHeader
                    .DataDirectory[___IMAGE_DIRECTORY_ENTRY_IAT]
                    .Size = (_DWORD)(sizeof(_QWORD) * num_off);
            }

            /* Parchear cada call importado.  El offset_iat es relativo a
             * idataRVA, asi que la base que se pasa es la VA de .idata. */
            uint64_t idata_base =
                pe.ntHeaders.OptionalHeader.ImageBase + idataRVA;
            FunctionOffset *fix =
                (FunctionOffset *)calloc(num_imps, sizeof(FunctionOffset));
            int nfix = 0;
            int ok = 1;
            for (int k = 0; k < num_imps && ok; ++k) {
                if (imps[k].call_section < 0 ||
                    imps[k].call_section >= num_secs) {
                    set_err(err, err_cap, "aot_emit_pe: call_section invalido");
                    ok = 0;
                    break;
                }
                int iat_off = -1;
                for (int e = 0; e < num_off; ++e)
                    if (strcmp(imps[k].func, off_entries[e].functionName) ==
                            0 &&
                        /* DLL case-insensitive: el grouping fundio KERNEL32.dll
                         * y kernel32.dll en un descriptor; el lookup debe
                         * coincidir igual aunque difiera el case. */
                        aot_dll_name_eq(imps[k].dll, off_entries[e].dllName)) {
                        iat_off = off_entries[e].offset;
                        break;
                    }
                if (iat_off < 0) {
                    set_err(err, err_cap, "aot_emit_pe: import no resuelto");
                    ok = 0;
                    break;
                }
                /* Parchear inmediatamente (cada call puede estar en una seccion
                 * distinta -> base de codigo propia). */
                int cs = imps[k].call_section;
                uint64_t code_vaddr = pe.sectionHeaders[cs].VirtualAddress +
                                      pe.ntHeaders.OptionalHeader.ImageBase;
                FunctionOffset fo;
                fo.offset_iat = iat_off;
                fo.offset_code = (uint32_t)imps[k].call_off;
                fo.name = imps[k].func;
                parchearDesplazamientosPorOffset(
                    pe.sectionData[cs], pe.sectionHeaders[cs].Misc.VirtualSize,
                    code_vaddr, idata_base, &fo, 1);
                fix[nfix++] = fo;
            }
            free(fix);
            free(idata_buf);
            free(off_entries);
            if (!ok) {
                for (int j = 0; j < num_libs; ++j)
                    free(lib_funcs[j]);
                free(lib_names);
                free(lib_funcs);
                free(lib_nfuncs);
                free(libs);
                freePE64File(&pe);
                return 0;
            }
            (void)idata_idx;
        } else {
            set_err(err, err_cap, "aot_emit_pe: fallo construyendo .idata");
            for (int j = 0; j < num_libs; ++j)
                free(lib_funcs[j]);
            free(lib_names);
            free(lib_funcs);
            free(lib_nfuncs);
            free(libs);
            freePE64File(&pe);
            return 0;
        }

        for (int j = 0; j < num_libs; ++j)
            free(lib_funcs[j]);
        free(lib_names);
        free(lib_funcs);
        free(lib_nfuncs);
        free(libs);
    }

    finalizePE64File(&pe);
    pe.ntHeaders.OptionalHeader.AddressOfEntryPoint =
        (_DWORD)(pe.sectionHeaders[entry_sec].VirtualAddress + entry_off);

    /* --aot-debug: capturar las RVAs de las secciones ANTES de free para el
     * symtab COFF (post-proceso tras writePE64File). */
    uint32_t *dbg_rva = NULL;
    if (g_aot_dbg_n > 0) {
        dbg_rva = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
        if (dbg_rva)
            for (int i = 0; i < num_secs; ++i)
                dbg_rva[i] = (uint32_t)pe.sectionHeaders[i].VirtualAddress;
    }

    /* Ultimo momento en que las RVA existen y todavia no se ha escrito nada. */
    if (!aot_pe_finish_pdata(&pe, secs, num_secs, err, err_cap)) {
        freePE64File(&pe);
        free(dbg_rva);
        return 0;
    }

    writePE64File(&pe, path);
    freePE64File(&pe);

    if (dbg_rva) {
        aot_pe_append_coff_symtab(path, g_aot_dbg_syms, g_aot_dbg_n, dbg_rva);
        free(dbg_rva);
    }
    return 1;
}

/* =========================================================================
 *  ELF64 (freestanding)
 * ========================================================================= */

#define AOT_ELF_PAGE 0x1000ull

int aot_emit_elf(const char *path, const AotLayoutCfg *cfg,
                 const AotSection *secs, int num_secs, int entry_sec,
                 uint64_t entry_off, const AotReloc *relocs, int num_relocs,
                 char *err, size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_elf: sin secciones");
        return 0;
    }
    if (entry_sec < 0 || entry_sec >= num_secs) {
        set_err(err, err_cap, "aot_emit_elf: entry_sec fuera de rango");
        return 0;
    }

    uint64_t base = (cfg && cfg->image_base) ? cfg->image_base : 0x400000ull;
    uint64_t stack_vaddr =
        (cfg && cfg->elf_stack_vaddr) ? cfg->elf_stack_vaddr : 0x70000000ull;
    uint64_t stack_size =
        (cfg && cfg->elf_stack_size) ? cfg->elf_stack_size : 0x10000ull;

    size_t total_data = 0;
    for (int i = 0; i < num_secs; ++i)
        total_data += secs[i].size;
    /* Si hay secciones con VA fija (place_section del link-script), el fichero
     * se rellena hasta vaddr-base; ampliar la capacidad para cubrir el span. */
    uint64_t span = total_data;
    for (int i = 0; i < num_secs; ++i)
        if (secs[i].vaddr && secs[i].vaddr >= base) {
            uint64_t end = (secs[i].vaddr - base) + secs[i].size;
            if (end > span) span = end;
        }
    size_t capacity =
        (span + 64 * AOT_ELF_PAGE + AOT_ELF_PAGE) & ~(AOT_ELF_PAGE - 1);

    /* 3 phdrs: PT_LOAD R+X (codigo/rodata), PT_LOAD R+W (.data), PT_GNU_STACK
     * (stack RW).  El R+W puede quedar vacio (filesz 0) si no hay writable. */
    ElfBuilder *b = elf_builder_create_exec64(capacity, /*num_phdrs=*/3);
    if (!b) {
        set_err(err, err_cap, "aot_emit_elf: create_exec64 fallo");
        return 0;
    }
    /* Arquitectura del ELF: por defecto x86-64; si el driver pide otra (p.ej.
     * EM_AARCH64) se la pasamos a LibPEparse.  El layout ELF64 (ehdr/phdr/
     * secciones) es arch-neutral; solo cambia e_machine (y, para relocs de
     * CODIGO, su encoding -- que en el EXEC whole-program ya viene resuelto).
     */
    if (cfg && cfg->machine) elf_builder_set_machine(b, cfg->machine);
    Elf64_Phdr *phdr = (Elf64_Phdr *)b->phdr;

    uint64_t entry_vaddr = 0;

    /* Para resolver relocations tras el layout: VA + offset-en-fichero de cada
     * seccion (indexado por el indice de usuario).  Solo si hay relocs. */
    uint64_t *sec_va = NULL;
    uint64_t *sec_foff = NULL;
    uint8_t *sec_seen = NULL;
    if (relocs && num_relocs > 0) {
        sec_va = (uint64_t *)calloc((size_t)num_secs, sizeof(uint64_t));
        sec_foff = (uint64_t *)calloc((size_t)num_secs, sizeof(uint64_t));
        sec_seen = (uint8_t *)calloc((size_t)num_secs, sizeof(uint8_t));
    }

    /* Agregar las secciones con datos en DOS pasadas para separar permisos:
     * (1) el segmento ejecutable: TODO lo que tenga EXEC (codigo, incluido
     * `.boot` rwx) MAS el rodata no-writable, y (2) un segmento R+W aparte
     * para los datos writable NO-ejecutables (`.data` puro).  Sin esta
     * separacion, un STORE a un global writable (e.g. __vx_cpu_features)
     * caeria en una pagina R-X y segfaultearia; e inversamente, mandar una
     * seccion rwx al segmento R+W (sin X) haria segfaultear su EJECUCION.
     * El criterio de particion es EXEC (no WRITE): el grupo 1 puede contener
     * secciones writable (rwx) -> en ese caso el segmento toma tambien W.
     * El emisor pone vaddr = base + file_off, asi que basta con alinear a
     * pagina entre las dos pasadas para que cada region empiece en un limite
     * de pagina (requisito de mmap del loader del kernel). */
    uint64_t rx_end_off = 0;   /* fin (offset-en-fichero) del segmento exec */
    uint64_t rw_start_off = 0; /* inicio del segmento R+W (0 = sin datos rw) */
    uint64_t rw_end_off = 0;   /* fin del segmento R+W */
    int exec_seg_writable = 0; /* alguna seccion exec es tambien writable? */
    for (int pass = 0; pass < 2; ++pass) {
        /* Pasada 0 = grupo EXEC (+ rodata); pasada 1 = data writable no-exec.
         */
        const int want_rwseg = (pass == 1);
        if (want_rwseg) {
            /* Cerrar el segmento exec y abrir el R+W en un limite de pagina. */
            rx_end_off = b->size;
            if (b->size % AOT_ELF_PAGE != 0) {
                size_t pad = AOT_ELF_PAGE - (b->size % AOT_ELF_PAGE);
                memset(b->mem + b->size, 0, pad);
                b->size += pad;
            }
            rw_start_off = b->size;
        }
        for (int i = 0; i < num_secs; ++i) {
            const AotSection *s = &secs[i];
            if ((s->flags & AOT_SEC_BSS) || s->size == 0) {
                /* BSS en ELF freestanding v1 no soportado (ver doc). */
                continue;
            }
            const int is_exec = (s->flags & AOT_SEC_EXEC) ? 1 : 0;
            const int is_write = (s->flags & AOT_SEC_WRITE) ? 1 : 0;
            /* El grupo 1 (segmento exec) recibe TODO lo no-writable (rodata)
             * Y todo lo ejecutable (aunque sea writable: rwx).  El grupo 2
             * (R+W) recibe solo lo writable NO-ejecutable. */
            const int goes_rwseg = (is_write && !is_exec);
            if (goes_rwseg != want_rwseg) continue;
            if (!want_rwseg && is_write) exec_seg_writable = 1;
            if (b->size % AOT_ELF_PAGE != 0) {
                size_t pad = AOT_ELF_PAGE - (b->size % AOT_ELF_PAGE);
                memset(b->mem + b->size, 0, pad);
                b->size += pad;
            }
            uint64_t sh_flags = SHF_ALLOC;
            if (s->flags & AOT_SEC_EXEC) sh_flags |= SHF_EXECINSTR;
            if (s->flags & AOT_SEC_WRITE) sh_flags |= SHF_WRITE;
            uint64_t align_use = s->align ? s->align : AOT_ELF_PAGE;
            /* VA fija (place_section): rellenar el fichero hasta vaddr-base
             * para que vaddr = base + offset de exactamente lo pedido.  El gap
             * se rellena con ceros (un PT_LOAD lo cubre).  Va en orden de VA:
             * una VA fija por DEBAJO de la posicion actual es inalcanzable. */
            if (s->vaddr != 0) {
                if (s->vaddr < base || (s->vaddr - base) < (uint64_t)b->size) {
                    free(sec_va);
                    free(sec_foff);
                    free(sec_seen);
                    elf_builder_free(b);
                    set_err(err, err_cap,
                            "aot_emit_elf: VA fija de seccion inalcanzable "
                            "(menor que base o que la posicion actual; coloca "
                            "las secciones en orden de direccion ascendente)");
                    return 0;
                }
                uint64_t want_off = s->vaddr - base;
                if (want_off > (uint64_t)b->size) {
                    memset(b->mem + b->size, 0, want_off - b->size);
                    b->size = want_off;
                }
                align_use = 1; // la VA ya esta fijada; no realinear
            }
            size_t off_out = 0;
            uint64_t vaddr_out = 0;
            size_t idx = elf_builder_add_section_ex(
                b, s->name, SHT_PROGBITS, sh_flags, s->data, s->size,
                base + b->size, align_use, &off_out, &vaddr_out, 0, 0, 0);
            if (idx == 0) {
                free(sec_va);
                free(sec_foff);
                free(sec_seen);
                elf_builder_free(b);
                set_err(err, err_cap, "aot_emit_elf: fallo añadiendo seccion");
                return 0;
            }
            if (sec_va) {
                sec_va[i] = vaddr_out;
                sec_foff[i] = off_out;
                sec_seen[i] = 1;
            }
            if (i == entry_sec) entry_vaddr = vaddr_out;
        }
    }
    rw_end_off = b->size;
    if (rx_end_off == 0) rx_end_off = b->size; /* no hubo seccion writable */

    /* BSS (SHT_NOBITS): secciones con AOT_SEC_BSS -> VA en el segmento R+W, SIN
     * contenido en fichero.  Van DESPUES de .data en el espacio de direcciones
     * (base + rw_end_off + ...); el loader las zerifica via p_memsz > p_filesz.
     * Solo son TARGET de relocs (nunca SITE), asi que sec_foff queda en 0.
     * Necesario para dev-OS: cualquier global sin inicializar (Vesta o un .o de
     * C) cae en .bss. */
    uint64_t bss_total = 0;
    {
        uint64_t bss_off = rw_end_off;
        for (int i = 0; i < num_secs; ++i) {
            const AotSection *s = &secs[i];
            if (!(s->flags & AOT_SEC_BSS)) continue;
            uint64_t sz = aot_sec_size(s); /* = bss_size para BSS */
            if (sz == 0) continue;
            uint64_t align_use = s->align ? s->align : 8;
            bss_off = (bss_off + align_use - 1) & ~(align_use - 1);
            if (sec_va) {
                sec_va[i] = base + bss_off;
                sec_foff[i] = 0;
                sec_seen[i] = 1;
            }
            bss_off += sz;
        }
        bss_total = bss_off - rw_end_off;
    }
    if (entry_vaddr == 0) {
        free(sec_va);
        free(sec_foff);
        free(sec_seen);
        elf_builder_free(b);
        set_err(err, err_cap,
                "aot_emit_elf: la seccion de entrada no tiene datos");
        return 0;
    }

    /* Resolver relocations cross-seccion (mismo modelo que PE): el layout ya
     * fijo VA + offset-en-fichero de cada seccion -> parcheamos b->mem. */
    if (relocs && num_relocs > 0) {
        for (int r = 0; r < num_relocs; ++r) {
            const AotReloc *rl = &relocs[r];
            if (rl->site_section < 0 || rl->site_section >= num_secs ||
                rl->target_section < 0 || rl->target_section >= num_secs ||
                !sec_seen[rl->site_section] ||
                (!rl->target_is_size && !sec_seen[rl->target_section])) {
                free(sec_va);
                free(sec_foff);
                free(sec_seen);
                elf_builder_free(b);
                set_err(err, err_cap,
                        "aot_emit_elf: reloc con seccion invalida");
                return 0;
            }
            uint64_t target_value;
            if (rl->target_is_imagebase) {
                /* En ELF no existe `__ImageBase`, pero la nocion si: es la
                 * direccion de CARGA, la misma que va en el primer segmento.
                 * Se contesta con ella para que la marca signifique lo mismo en
                 * los dos formatos y el emisor no tenga un caso sin cubrir. */
                target_value = base;
            } else if (rl->target_is_size) {
                target_value = aot_sec_size(&secs[rl->target_section]);
            } else {
                target_value = sec_va[rl->target_section];
                if (rl->target_is_end)
                    target_value += aot_sec_size(&secs[rl->target_section]);
                else
                    target_value += rl->target_off;
            }
            target_value = (uint64_t)((int64_t)target_value + rl->addend);
            uint64_t site_va = sec_va[rl->site_section] + rl->site_off;
            uint32_t width =
                (rl->kind == AOT_RELOC_ABS64 || rl->kind == AOT_RELOC_IMM64)
                    ? 8u
                    : 4u;
            if (rl->site_off + width > secs[rl->site_section].size) {
                free(sec_va);
                free(sec_foff);
                free(sec_seen);
                elf_builder_free(b);
                set_err(err, err_cap,
                        "aot_emit_elf: reloc fuera de la seccion del sitio");
                return 0;
            }
            if (!apply_reloc(b->mem + sec_foff[rl->site_section] + rl->site_off,
                             site_va, target_value, rl->kind,
                             AOT_NO_IMAGE_BASE)) {
                free(sec_va);
                free(sec_foff);
                free(sec_seen);
                elf_builder_free(b);
                set_err(err, err_cap, "aot_emit_elf: reloc kind invalido");
                return 0;
            }
        }
    }
    free(sec_foff);
    free(sec_seen);
    sec_foff = NULL;
    sec_seen = NULL;
    /* sec_va se libera DESPUES del symtab (los simbolos de debug calculan su
     * st_value con sec_va[section]). */

    /* .strtab + .symtab.  Siempre incluye _start; con --aot-debug=1 incluye
     * ademas un STT_FUNC por cada funcion (nombre -> VA) para que gdb/lldb
     * muestren nombres en los backtraces.  st_value = sec_va[sym.section] +
     * offset (VA absoluta ya conocida tras el layout). */
    {
        const int ndbg = g_aot_dbg_n;
        const AotSym *dsyms = g_aot_dbg_syms;
        /* strtab: \0 + "_start\0" + nombres de debug. */
        size_t strcap = 1 + 7; /* "\0" + "_start\0" */
        for (int i = 0; i < ndbg; ++i)
            strcap += strlen(dsyms[i].name) + 1;
        char *strtab = (char *)calloc(1, strcap);
        Elf64_Sym *symtab =
            (Elf64_Sym *)calloc((size_t)(ndbg + 2), sizeof(Elf64_Sym));
        if (strtab && symtab) {
            size_t sp = 1;
            /* _start (indice 1). */
            memcpy(strtab + sp, "_start", 7);
            symtab[1].st_name = (uint32_t)sp;
            symtab[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
            symtab[1].st_shndx = (uint16_t)(entry_sec + 1);
            symtab[1].st_value = entry_vaddr + entry_off;
            /* st_size=0 (simbolo puntual): con varios simbolos en .text, un
             * size que abarque toda la seccion haria que _start "engulla" a
             * main y gdb resolveria como "_start+N"; con 0, gdb resuelve por el
             * simbolo de mayor VA <= pc (el correcto). */
            symtab[1].st_size = 0;
            sp += 7;
            /* funciones de debug (indices 2..). */
            for (int i = 0; i < ndbg; ++i) {
                size_t l = strlen(dsyms[i].name);
                memcpy(strtab + sp, dsyms[i].name, l + 1);
                Elf64_Sym *s = &symtab[2 + i];
                s->st_name = (uint32_t)sp;
                s->st_info = ELF64_ST_INFO(
                    STB_GLOBAL, dsyms[i].is_func ? STT_FUNC : STT_OBJECT);
                s->st_shndx = (uint16_t)(dsyms[i].section + 1);
                s->st_value =
                    (sec_va ? sec_va[dsyms[i].section] : 0) + dsyms[i].offset;
                s->st_size = 0; /* se calcula abajo */
                sp += l + 1;
            }
            /* st_size = distancia al siguiente simbolo de la misma seccion (o
             * al fin de seccion) -> valgrind resuelve por RANGO (gdb por
             * valor). Cubre _start (indice 1, seccion entry_sec) + funciones
             * (2..). */
            for (int k = 1; k <= ndbg + 1; ++k) {
                int ksec = (k == 1) ? entry_sec : dsyms[k - 2].section;
                uint64_t v = symtab[k].st_value;
                uint64_t nxt = (sec_va ? sec_va[ksec] : 0) + secs[ksec].size;
                for (int m = 1; m <= ndbg + 1; ++m) {
                    if (m == k) continue;
                    int msec = (m == 1) ? entry_sec : dsyms[m - 2].section;
                    if (msec != ksec) continue;
                    uint64_t vm = symtab[m].st_value;
                    if (vm > v && vm < nxt) nxt = vm;
                }
                symtab[k].st_size = nxt - v;
            }
            size_t st_off = 0;
            uint64_t st_va = 0;
            size_t idx_strtab = elf_builder_add_section_ex(
                b, ".strtab", SHT_STRTAB, 0, strtab, strcap, 0, 1, &st_off,
                &st_va, 0, 0, 0);
            size_t sy_off = 0;
            uint64_t sy_va = 0;
            elf_builder_add_section_ex(
                b, ".symtab", SHT_SYMTAB, 0, symtab,
                (size_t)(ndbg + 2) * sizeof(Elf64_Sym), 0, 8, &sy_off, &sy_va,
                (uint32_t)idx_strtab, 1, sizeof(Elf64_Sym));
        }
        free(strtab);
        free(symtab);
    }
    free(sec_va);
    sec_va = NULL;

    /* Program headers.  Los filesz usan rx_end_off / rw_end_off (capturados
     * ANTES de .strtab/.symtab, que no son ALLOC y no se mapean).  El
     * .symtab/.strtab quedan al final del fichero, fuera de todo PT_LOAD. */
    const int has_rw = (rw_end_off > rw_start_off) || (bss_total > 0);

    /* PT_LOAD ejecutable: codigo + rodata.  R+X, y ademas W si contiene alguna
     * seccion rwx (e.g. `.boot` de un kernel/bootloader que se auto-modifica).
     */
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R | PF_X | (exec_seg_writable ? PF_W : 0);
    phdr[0].p_offset = 0;
    phdr[0].p_vaddr = base;
    phdr[0].p_paddr = base;
    phdr[0].p_filesz = rx_end_off;
    phdr[0].p_memsz = (rx_end_off + AOT_ELF_PAGE - 1) & ~(AOT_ELF_PAGE - 1);
    phdr[0].p_align = AOT_ELF_PAGE;

    /* PT_LOAD R+W: secciones writable (.data).  Si no hay, este phdr describe
     * el stack RW (filesz 0) para no desperdiciar la entrada. */
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W;
    if (has_rw) {
        phdr[1].p_offset = rw_start_off;
        phdr[1].p_vaddr = base + rw_start_off;
        phdr[1].p_paddr = base + rw_start_off;
        phdr[1].p_filesz =
            rw_end_off - rw_start_off; /* solo .data en fichero */
        /* p_memsz cubre .data + .bss (el loader zerifica [filesz, memsz)). */
        phdr[1].p_memsz = (rw_end_off - rw_start_off) + bss_total;
        phdr[1].p_align = AOT_ELF_PAGE;
    } else {
        phdr[1].p_offset = 0;
        phdr[1].p_vaddr = stack_vaddr;
        phdr[1].p_paddr = stack_vaddr;
        phdr[1].p_filesz = 0;
        phdr[1].p_memsz = stack_size;
        phdr[1].p_align = AOT_ELF_PAGE;
    }

    /* PT_GNU_STACK: pila RW no-ejecutable.  Si el R+W ya describio .data,
     * aqui reservamos ademas el stack como un PT_LOAD RW separado. */
    phdr[2].p_type = PT_LOAD;
    phdr[2].p_flags = PF_R | PF_W;
    phdr[2].p_offset = 0;
    phdr[2].p_vaddr = stack_vaddr;
    phdr[2].p_paddr = stack_vaddr;
    phdr[2].p_filesz = 0;
    phdr[2].p_memsz = has_rw ? stack_size : 0;
    phdr[2].p_align = AOT_ELF_PAGE;

    elf_builder_finalize_exec64(b, entry_vaddr + entry_off);

    FILE *f = fopen(path, "wb");
    if (!f) {
        elf_builder_free(b);
        set_err(err, err_cap, "aot_emit_elf: fopen fallo");
        return 0;
    }
    size_t written = fwrite(b->mem, 1, b->size, f);
    fclose(f);
    int ok = (written == b->size);
    if (!ok) set_err(err, err_cap, "aot_emit_elf: escritura incompleta");
    elf_builder_free(b);
    return ok;
}

/* aot_emit_pe32 + build_idata32 -> movidos a x86_32/aot_emit_x86_32.c. */

/* aot_emit_elf32 -> movido a x86_32/aot_emit_x86_32.c. */

/* =========================================================================
 *  ELF64 EJECUTABLE DINaMICO (PIE ET_DYN) con imports libc via eager-GOT
 *  -- hand-rolled (sin tocar el submodulo).  AOT.2.exec slice 2.
 *
 *  Modelo (mas simple que PLT lazy): por cada simbolo externo una entrada
 *  GOT (8B, .got writable) + reloc R_X86_64_GLOB_DAT contra un dynsym UND;
 *  el thunk `FF 25 disp32` (jmp [rip+GOT]) que ya emitio el driver salta por
 *  la GOT.  El linker dinamico (DT_NEEDED libc.so.6 + DF_BIND_NOW) resuelve
 *  las GOT al cargar.  PT_INTERP -> ld.so.  vaddr == file offset (PIE base 0).
 * ========================================================================= */

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

/* aot_elf_hash -> movido a common/aot_emit_common.c (compartido por dynexec
 * 64/32); se usa aqui via la declaracion del header interno. */

#define AOT_DYN_ALIGN(x, a) (((x) + ((a) - 1)) & ~((uint64_t)(a) - 1))

int aot_emit_elf_dynexec(const char *path, const AotLayoutCfg *cfg,
                         const AotSection *secs, int num_secs, int entry_sec,
                         uint64_t entry_off, const AotReloc *relocs,
                         int num_relocs, const AotImport *imps, int num_imps,
                         char *err, size_t err_cap) {
    (void)cfg;
    if (num_secs <= 0) {
        set_err(err, err_cap, "elf_dynexec: sin secciones");
        return 0;
    }
    if (entry_sec < 0 || entry_sec >= num_secs) {
        set_err(err, err_cap, "elf_dynexec: entry_sec fuera de rango");
        return 0;
    }
    if (num_imps < 0) num_imps = 0;
    /* num_imps == 0 es valido: un EXEC dinamico sin imports de libc pero con
     * TLS (necesita el cargador para montar el bloque thread-local) o con
     * relocs RELATIVE.  GOT vacia + dynsym de 1 entrada (null). */

    const uint64_t PAGE = AOT_ELF_PAGE;
    /* Seccion TLS (plantilla thread_local): si existe, anyade un PT_TLS. */
    int tls_sec = -1;
    for (int i = 0; i < num_secs; ++i)
        if (secs[i].flags & AOT_SEC_TLS) {
            tls_sec = i;
            break;
        }
    const int NPH = 6 + (tls_sec >= 0 ? 1 : 0); /* +PT_TLS si hay TLS */
    const int nsym = 1 + num_imps; /* [0]=null + 1 UND por import */
    const char interp[] = "/lib64/ld-linux-x86-64.so.2";
    const size_t interp_len = sizeof(interp); /* incluye el nul */

    /* Sonames DISTINTOS de los imports -> un DT_NEEDED por libreria (el campo
     * dll de cada AotImport es el soname; un import sin dll va a libc.so.6). */
    const int scap = num_imps > 0 ? num_imps : 1;
    const char **sonames = (const char **)calloc((size_t)scap, sizeof(char *));
    uint32_t *soname_off = (uint32_t *)calloc((size_t)scap, sizeof(uint32_t));
    int num_sonames = 0;
    for (int i = 0; i < num_imps; ++i) {
        const char *so =
            (imps[i].dll && imps[i].dll[0]) ? imps[i].dll : "libc.so.6";
        int found = 0;
        for (int j = 0; j < num_sonames; ++j)
            if (strcmp(sonames[j], so) == 0) {
                found = 1;
                break;
            }
        if (!found) sonames[num_sonames++] = so;
    }
    if (num_sonames == 0) sonames[num_sonames++] = "libc.so.6";

    /* --- .dynstr: "\0" + nombres de import + sonames --- */
    OBuf dynstr;
    memset(&dynstr, 0, sizeof(dynstr));
    {
        uint8_t z = 0;
        ob_put(&dynstr, &z, 1);
    }
    uint32_t *name_off = (uint32_t *)calloc((size_t)num_imps, sizeof(uint32_t));
    for (int i = 0; i < num_imps; ++i) {
        name_off[i] = (uint32_t)dynstr.len;
        ob_put(&dynstr, imps[i].func, strlen(imps[i].func) + 1);
    }
    for (int s = 0; s < num_sonames; ++s) {
        soname_off[s] = (uint32_t)dynstr.len;
        ob_put(&dynstr, sonames[s], strlen(sonames[s]) + 1);
    }

    /* --- .hash SysV: nbucket, nchain(=nsym), buckets[], chains[] --- */
    uint32_t nbucket = (uint32_t)(nsym < 1 ? 1 : nsym);
    uint32_t nchain = (uint32_t)nsym;
    uint32_t *bucket = (uint32_t *)calloc(nbucket, sizeof(uint32_t));
    uint32_t *chain = (uint32_t *)calloc(nchain, sizeof(uint32_t));
    for (int i = 0; i < num_imps; ++i) {
        uint32_t si = (uint32_t)(1 + i);
        uint32_t b = (uint32_t)(aot_elf_hash(imps[i].func) % nbucket);
        chain[si] = bucket[b];
        bucket[b] = si;
    }
    size_t hash_size = (size_t)(2 + nbucket + nchain) * 4u;

    /* ================= PASO 1: layout (vaddr == file offset) =================
     */
    uint64_t off = 0;
    uint64_t ehdr_off = off;
    off += sizeof(Elf64_Ehdr);
    uint64_t phdr_off = off;
    off += (uint64_t)NPH * sizeof(Elf64_Phdr);
    uint64_t interp_off = off;
    off += interp_len;
    off = AOT_DYN_ALIGN(off, 8);
    uint64_t dynsym_off = off;
    off += (uint64_t)nsym * sizeof(Elf64_Sym);
    uint64_t dynstr_off = off;
    off += dynstr.len;
    off = AOT_DYN_ALIGN(off, 4);
    uint64_t hash_off = off;
    off += hash_size;
    off = AOT_DYN_ALIGN(off, 8);
    uint64_t rela_off = off;
    /* Las relocs ABS64 del driver (p.ej. las entradas de la .got que el linker
     * construye para los GOTPCREL) no caben tal cual en un PIE (base
     * aleatoria): se materializan como R_X86_64_RELATIVE en .rela.dyn (el
     * cargador escribe base + addend).  Se cuentan aqui para dimensionar
     * .rela.dyn. */
    int num_abs64 = 0;
    for (int r = 0; r < num_relocs; ++r)
        if (relocs[r].kind == AOT_RELOC_ABS64) ++num_abs64;
    const int n_dynrela = num_imps + num_abs64;
    off += (uint64_t)n_dynrela * sizeof(Elf64_Rela);
    off = AOT_DYN_ALIGN(off, 16);

    /* Secciones de codigo/rodata (NO-WRITE) en el segmento R+X. */
    uint64_t *sec_va = (uint64_t *)calloc((size_t)num_secs, sizeof(uint64_t));
    uint8_t *sec_seen = (uint8_t *)calloc((size_t)num_secs, sizeof(uint8_t));
    for (int i = 0; i < num_secs; ++i) {
        if ((secs[i].flags & AOT_SEC_WRITE) || (secs[i].flags & AOT_SEC_BSS))
            continue;
        if (secs[i].size == 0) continue;
        uint64_t a = secs[i].align ? secs[i].align : 16;
        off = AOT_DYN_ALIGN(off, a);
        sec_va[i] = off;
        sec_seen[i] = 1;
        off += secs[i].size;
    }
    uint64_t region1_end = off;
    off = AOT_DYN_ALIGN(off, PAGE);
    uint64_t region2_start = off;

    uint64_t got_off = off;
    off += (uint64_t)num_imps * 8u;

    /* Secciones WRITE (.data) en el segmento R+W. */
    for (int i = 0; i < num_secs; ++i) {
        if (!(secs[i].flags & AOT_SEC_WRITE)) continue;
        if (secs[i].flags & AOT_SEC_BSS) continue; /* bss v1: omitido */
        if (secs[i].size == 0) continue;
        uint64_t a = secs[i].align ? secs[i].align : 8;
        off = AOT_DYN_ALIGN(off, a);
        sec_va[i] = off;
        sec_seen[i] = 1;
        off += secs[i].size;
    }
    off = AOT_DYN_ALIGN(off, 8);
    uint64_t dynamic_off = off;
    /* 11 entradas fijas (HASH/STRTAB/SYMTAB/STRSZ/SYMENT/RELA/RELASZ/RELAENT/
     * FLAGS/FLAGS_1/NULL) + un DT_NEEDED por soname. */
    const int ndyn = 11 + num_sonames;
    off += (uint64_t)ndyn * sizeof(Elf64_Dyn);
    uint64_t region2_end = off; /* fin del contenido en FICHERO */
    uint64_t total = off;       /* tamano del fichero (sin BSS) */

    /* BSS (secciones NOBITS): reciben VAs en memoria TRAS el contenido del
     * fichero pero NO ocupan bytes en el (memsz > filesz).  El cargador las
     * pone a cero. */
    uint64_t bss_mem = region2_end;
    for (int i = 0; i < num_secs; ++i) {
        if (!(secs[i].flags & AOT_SEC_BSS)) continue;
        uint64_t bsz = secs[i].bss_size ? secs[i].bss_size : secs[i].size;
        if (bsz == 0) continue;
        uint64_t a = secs[i].align ? secs[i].align : 8;
        bss_mem = AOT_DYN_ALIGN(bss_mem, a);
        sec_va[i] = bss_mem;
        sec_seen[i] = 1; /* visible para relocs; NO se copia al fichero */
        bss_mem += bsz;
    }
    uint64_t region2_mem_end = bss_mem; /* fin en MEMORIA (incluye BSS) */

    uint64_t entry_vaddr = sec_va[entry_sec] + entry_off;

    /* ================= PASO 2: emitir la imagen ================= */
    uint8_t *img = (uint8_t *)calloc(1, (size_t)total);
    if (!img) {
        set_err(err, err_cap, "elf_dynexec: OOM");
        free(name_off);
        free(sonames);
        free(soname_off);
        free(bucket);
        free(chain);
        free(dynstr.p);
        free(sec_va);
        free(sec_seen);
        return 0;
    }

    /* Ehdr. */
    Elf64_Ehdr *eh = (Elf64_Ehdr *)(img + ehdr_off);
    eh->e_ident[0] = 0x7f;
    eh->e_ident[1] = 'E';
    eh->e_ident[2] = 'L';
    eh->e_ident[3] = 'F';
    eh->e_ident[4] = ELFCLASS64;
    eh->e_ident[5] = 1 /*LSB*/;
    eh->e_ident[6] = 1 /*EV_CURRENT*/;
    eh->e_type = ET_DYN;
    eh->e_machine = EM_X86_64;
    eh->e_version = 1;
    eh->e_entry = entry_vaddr;
    eh->e_phoff = phdr_off;
    eh->e_shoff = 0;
    eh->e_flags = 0;
    eh->e_ehsize = (uint16_t)sizeof(Elf64_Ehdr);
    eh->e_phentsize = (uint16_t)sizeof(Elf64_Phdr);
    eh->e_phnum = (uint16_t)NPH;
    eh->e_shentsize = 0;
    eh->e_shnum = 0;
    eh->e_shstrndx = 0;

    /* Phdrs. */
    Elf64_Phdr *ph = (Elf64_Phdr *)(img + phdr_off);
    memset(ph, 0, (size_t)NPH * sizeof(Elf64_Phdr));
    ph[0].p_type = PT_PHDR;
    ph[0].p_flags = PF_R;
    ph[0].p_offset = phdr_off;
    ph[0].p_vaddr = phdr_off;
    ph[0].p_paddr = phdr_off;
    ph[0].p_filesz = (uint64_t)NPH * sizeof(Elf64_Phdr);
    ph[0].p_memsz = ph[0].p_filesz;
    ph[0].p_align = 8;
    ph[1].p_type = PT_INTERP;
    ph[1].p_flags = PF_R;
    ph[1].p_offset = interp_off;
    ph[1].p_vaddr = interp_off;
    ph[1].p_paddr = interp_off;
    ph[1].p_filesz = interp_len;
    ph[1].p_memsz = interp_len;
    ph[1].p_align = 1;
    ph[2].p_type = PT_LOAD;
    ph[2].p_flags = PF_R | PF_X;
    ph[2].p_offset = 0;
    ph[2].p_vaddr = 0;
    ph[2].p_paddr = 0;
    ph[2].p_filesz = region1_end;
    ph[2].p_memsz = region1_end;
    ph[2].p_align = PAGE;
    ph[3].p_type = PT_LOAD;
    ph[3].p_flags = PF_R | PF_W;
    ph[3].p_offset = region2_start;
    ph[3].p_vaddr = region2_start;
    ph[3].p_paddr = region2_start;
    ph[3].p_filesz = region2_end - region2_start;
    ph[3].p_memsz = region2_mem_end - region2_start; /* incluye BSS */
    ph[3].p_align = PAGE;
    ph[4].p_type = PT_DYNAMIC;
    ph[4].p_flags = PF_R | PF_W;
    ph[4].p_offset = dynamic_off;
    ph[4].p_vaddr = dynamic_off;
    ph[4].p_paddr = dynamic_off;
    ph[4].p_filesz = (uint64_t)ndyn * sizeof(Elf64_Dyn);
    ph[4].p_memsz = ph[4].p_filesz;
    ph[4].p_align = 8;
    ph[5].p_type = PT_GNU_STACK;
    ph[5].p_flags = PF_R | PF_W;
    ph[5].p_align = 0x10;

    /* PT_TLS: plantilla thread_local (local-exec).  El cargador la copia por
     * hilo; las variables se acceden TP-relativas (offsets ya calculados por el
     * linker como TPOFF).  p_filesz = parte .tdata (en fichero), p_memsz =
     * .tdata + .tbss (el cargador alinea via p_align). */
    if (tls_sec >= 0) {
        ph[6].p_type = PT_TLS;
        ph[6].p_flags = PF_R;
        ph[6].p_offset =
            sec_va[tls_sec]; /* file offset == vaddr (PIE base 0) */
        ph[6].p_vaddr = sec_va[tls_sec];
        ph[6].p_paddr = sec_va[tls_sec];
        ph[6].p_filesz = secs[tls_sec].size;
        ph[6].p_memsz = secs[tls_sec].size + secs[tls_sec].bss_size;
        ph[6].p_align = secs[tls_sec].align ? secs[tls_sec].align : 8;
    }

    /* .interp */
    memcpy(img + interp_off, interp, interp_len);

    /* .dynsym */
    Elf64_Sym *dsym = (Elf64_Sym *)(img + dynsym_off);
    memset(dsym, 0, (size_t)nsym * sizeof(Elf64_Sym));
    for (int i = 0; i < num_imps; ++i) {
        Elf64_Sym *s = &dsym[1 + i];
        s->st_name = name_off[i];
        s->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
        s->st_other = 0;
        s->st_shndx = SHN_UNDEF;
        s->st_value = 0;
        s->st_size = 0;
    }
    /* .dynstr */
    memcpy(img + dynstr_off, dynstr.p, dynstr.len);
    /* .hash */
    {
        uint32_t *h = (uint32_t *)(img + hash_off);
        h[0] = nbucket;
        h[1] = nchain;
        for (uint32_t i = 0; i < nbucket; ++i)
            h[2 + i] = bucket[i];
        for (uint32_t i = 0; i < nchain; ++i)
            h[2 + nbucket + i] = chain[i];
    }
    /* .rela.dyn (R_X86_64_GLOB_DAT por entrada GOT) */
    Elf64_Rela *rela = (Elf64_Rela *)(img + rela_off);
    for (int i = 0; i < num_imps; ++i) {
        rela[i].r_offset = got_off + (uint64_t)i * 8u;
        rela[i].r_info = ELF64_R_INFO((uint64_t)(1 + i), R_X86_64_GLOB_DAT);
        rela[i].r_addend = 0;
    }
    /* Secciones de usuario (codigo/rodata + data).  BSS no tiene datos en el
     * fichero (su VA cae mas alla de 'total') -> se omite del memcpy. */
    for (int i = 0; i < num_secs; ++i)
        if (sec_seen[i] && !(secs[i].flags & AOT_SEC_BSS) && secs[i].data)
            memcpy(img + sec_va[i], secs[i].data, secs[i].size);

    /* .dynamic */
    {
        Elf64_Dyn *d = (Elf64_Dyn *)(img + dynamic_off);
        int k = 0;
        for (int s = 0; s < num_sonames; ++s) {
            d[k].d_tag = DT_NEEDED;
            d[k++].d_un.d_val = soname_off[s];
        }
        d[k].d_tag = DT_HASH;
        d[k++].d_un.d_ptr = hash_off;
        d[k].d_tag = DT_STRTAB;
        d[k++].d_un.d_ptr = dynstr_off;
        d[k].d_tag = DT_SYMTAB;
        d[k++].d_un.d_ptr = dynsym_off;
        d[k].d_tag = DT_STRSZ;
        d[k++].d_un.d_val = dynstr.len;
        d[k].d_tag = DT_SYMENT;
        d[k++].d_un.d_val = sizeof(Elf64_Sym);
        d[k].d_tag = DT_RELA;
        d[k++].d_un.d_ptr = rela_off;
        d[k].d_tag = DT_RELASZ;
        d[k++].d_un.d_val = (uint64_t)n_dynrela * sizeof(Elf64_Rela);
        d[k].d_tag = DT_RELAENT;
        d[k++].d_un.d_val = sizeof(Elf64_Rela);
        d[k].d_tag = DT_FLAGS;
        d[k++].d_un.d_val = DF_BIND_NOW;
        d[k].d_tag = (Elf64_Sxword)DT_FLAGS_1;
        d[k++].d_un.d_val = DF_1_NOW;
        d[k].d_tag = DT_NULL;
        d[k++].d_un.d_val = 0;
    }

    /* --- Relocs cross-seccion del driver (data refs / section syms).  PIE:
     * solo PC-relativo (REL32) + inmediatos (IMM32/IMM64=size); ABS64 NO va en
     *     PIE (necesitaria R_X86_64_RELATIVE) -> error claro. --- */
    int ok = 1;
    int n_rel_emitted = 0; /* contador de R_X86_64_RELATIVE ya escritas */
    Elf64_Rela *dynrela = (Elf64_Rela *)(img + rela_off);
    for (int r = 0; r < num_relocs && ok; ++r) {
        const AotReloc *rl = &relocs[r];
        if (rl->site_section < 0 || rl->site_section >= num_secs ||
            !sec_seen[rl->site_section] ||
            (!rl->target_is_size &&
             (rl->target_section < 0 || rl->target_section >= num_secs ||
              !sec_seen[rl->target_section]))) {
            {
                char m[160];
                snprintf(
                    m, sizeof(m),
                    "elf_dynexec: reloc con seccion invalida "
                    "(kind=%d site_sec=%d seen=%d target_sec=%d seen=%d "
                    "is_size=%d num_secs=%d)",
                    rl->kind, rl->site_section,
                    (rl->site_section >= 0 && rl->site_section < num_secs)
                        ? sec_seen[rl->site_section]
                        : -1,
                    rl->target_section,
                    (rl->target_section >= 0 && rl->target_section < num_secs)
                        ? sec_seen[rl->target_section]
                        : -1,
                    rl->target_is_size, num_secs);
                set_err(err, err_cap, m);
            }
            ok = 0;
            break;
        }
        uint64_t tv;
        if (rl->target_is_size)
            tv = aot_sec_size(&secs[rl->target_section]);
        else {
            tv = sec_va[rl->target_section];
            tv += rl->target_is_end ? aot_sec_size(&secs[rl->target_section])
                                    : rl->target_off;
        }
        tv = (uint64_t)((int64_t)tv + rl->addend);
        uint64_t site_va = sec_va[rl->site_section] + rl->site_off;
        if (rl->kind == AOT_RELOC_TPOFF32) {
            /* TLS local-exec: tpoff = offset_en_el_bloque - aligned_total
             * (variante II: TP al final del bloque TLS, offset negativo).  Es
             * una CONSTANTE de enlace (no depende de la base de carga): se
             * escribe directa, sin reloc dinamica.  El cargador monta el bloque
             * TLS desde PT_TLS antes del entry. */
            if (tls_sec < 0) {
                set_err(err, err_cap,
                        "elf_dynexec: reloc TPOFF32 sin seccion TLS");
                ok = 0;
                break;
            }
            uint64_t talign = secs[tls_sec].align ? secs[tls_sec].align : 8;
            uint64_t tls_total = secs[tls_sec].size + secs[tls_sec].bss_size;
            uint64_t aligned_total = (tls_total + talign - 1) & ~(talign - 1);
            /* tv = VA del simbolo TLS; el offset en el bloque = tv -
             * sec_va[tls_sec] (el bloque empieza en la 1a seccion SHF_TLS). */
            int32_t tpoff = (int32_t)((int64_t)(tv - sec_va[tls_sec]) -
                                      (int64_t)aligned_total);
            memcpy(img + site_va, &tpoff, 4);
            continue;
        }
        if (rl->kind == AOT_RELOC_ABS64) {
            /* PIE: el valor absoluto se resuelve en carga.  R_X86_64_RELATIVE
             * con r_addend = tv (relativo a la imagen, base 0) -> el cargador
             * escribe base + tv.  El campo se deja con tv (el cargador lo
             * sobreescribe). */
            memcpy(img + site_va, &tv, 8);
            Elf64_Rela *e = &dynrela[num_imps + n_rel_emitted++];
            e->r_offset = site_va;
            e->r_info = ELF64_R_INFO(0, R_X86_64_RELATIVE);
            e->r_addend = (int64_t)tv;
            continue;
        }
        if (!apply_reloc(img + site_va, site_va, tv, rl->kind,
                         AOT_NO_IMAGE_BASE)) {
            set_err(err, err_cap, "elf_dynexec: reloc kind invalido");
            ok = 0;
            break;
        }
    }

    /* --- Parchear cada thunk (FF 25 disp32) -> su entrada GOT.  imps[i] <->
     * got[i]. disp32 = got_va - (thunk_va + 6); el FF 25 esta en
     * call_section:call_off. --- */
    for (int i = 0; i < num_imps && ok; ++i) {
        int cs = imps[i].call_section;
        if (cs < 0 || cs >= num_secs || !sec_seen[cs]) {
            set_err(err, err_cap,
                    "elf_dynexec: call_section del thunk invalido");
            ok = 0;
            break;
        }
        uint64_t thunk_va = sec_va[cs] + imps[i].call_off;
        uint64_t got_va = got_off + (uint64_t)i * 8u;
        int32_t disp = (int32_t)((int64_t)got_va - (int64_t)(thunk_va + 6));
        memcpy(img + thunk_va + 2, &disp, 4);
    }

    /* --aot-debug=1: apendir .symtab/.strtab + tabla de section headers TRAS la
     * imagen cargable (fuera de todo PT_LOAD -> no afecta la ejecucion; solo lo
     * leen gdb/valgrind/lldb/...).  Simbolos section-relative (gdb usa mst_text
     * para resolver PC->funcion; SHN_ABS no vale).  SHT: [0]NULL + secciones
     * cargables + .symtab + .strtab + .shstrtab. */
    uint8_t *final_buf = img;
    size_t final_size = (size_t)total;
    int final_owns = 0;
    if (ok && g_aot_dbg_n > 0 && sec_va) {
        const int n = g_aot_dbg_n;
        const int nsec = num_secs;
        /* shstrtab: "\0" + nombres de seccion + ".symtab" + ".strtab" +
         * ".shstrtab". */
        size_t shstr_cap = 1 + 8 + 8 + 10;
        for (int i = 0; i < nsec; ++i)
            shstr_cap += strlen(secs[i].name ? secs[i].name : ".sec") + 1;
        char *shstr = (char *)calloc(1, shstr_cap);
        uint32_t *sec_name_off = (uint32_t *)calloc((size_t)nsec, 4);
        /* strtab: "\0" + nombres de simbolo. */
        size_t strtab_sz = 1;
        for (int i = 0; i < n; ++i)
            strtab_sz += strlen(g_aot_dbg_syms[i].name) + 1;
        char *strtab = (char *)calloc(1, strtab_sz);
        Elf64_Sym *symtab =
            (Elf64_Sym *)calloc((size_t)(n + 1), sizeof(Elf64_Sym));
        const int nsh = 1 + nsec + 3; /* NULL + secs + symtab+strtab+shstrtab */
        Elf64_Shdr *sht = (Elf64_Shdr *)calloc((size_t)nsh, sizeof(Elf64_Shdr));
        if (shstr && sec_name_off && strtab && symtab && sht) {
            /* shstrtab */
            size_t p = 1;
            for (int i = 0; i < nsec; ++i) {
                const char *nm = secs[i].name ? secs[i].name : ".sec";
                sec_name_off[i] = (uint32_t)p;
                size_t l = strlen(nm);
                memcpy(shstr + p, nm, l + 1);
                p += l + 1;
            }
            uint32_t nm_symtab = (uint32_t)p;
            memcpy(shstr + p, ".symtab", 8);
            p += 8;
            uint32_t nm_strtab = (uint32_t)p;
            memcpy(shstr + p, ".strtab", 8);
            p += 8;
            uint32_t nm_shstr = (uint32_t)p;
            memcpy(shstr + p, ".shstrtab", 10);
            p += 10;
            size_t shstr_sz = p;
            /* strtab + symtab */
            size_t sp = 1;
            for (int i = 0; i < n; ++i) {
                const AotSym *ds = &g_aot_dbg_syms[i];
                size_t l = strlen(ds->name);
                memcpy(strtab + sp, ds->name, l + 1);
                Elf64_Sym *s = &symtab[1 + i];
                s->st_name = (uint32_t)sp;
                s->st_info = ELF64_ST_INFO(STB_GLOBAL,
                                           ds->is_func ? STT_FUNC : STT_OBJECT);
                s->st_shndx =
                    (uint16_t)(1 + ds->section); /* seccion en la SHT */
                s->st_value = sec_va[ds->section] + ds->offset;
                s->st_size = 0; /* se calcula abajo */
                sp += l + 1;
            }
            /* st_size = distancia al siguiente simbolo de la MISMA seccion (o
             * al fin de la seccion).  valgrind resuelve PC->funcion por RANGO
             * [value, value+size); con size 0 no cubre ningun PC (gdb si, por
             * valor-mas-cercano).  O(n^2) pero n = numero de funciones. */
            for (int i = 0; i < n; ++i) {
                Elf64_Sym *s = &symtab[1 + i];
                int sec = g_aot_dbg_syms[i].section;
                uint64_t v = s->st_value;
                uint64_t nxt = sec_va[sec] + aot_sec_size(&secs[sec]);
                for (int j = 0; j < n; ++j) {
                    if (j == i || g_aot_dbg_syms[j].section != sec) continue;
                    uint64_t vj = symtab[1 + j].st_value;
                    if (vj > v && vj < nxt) nxt = vj;
                }
                s->st_size = nxt - v;
            }
            /* layout apendido (8-aligned). */
            size_t off = (size_t)total;
            size_t strtab_off = (off + 7) & ~(size_t)7;
            size_t symtab_off = (strtab_off + strtab_sz + 7) & ~(size_t)7;
            size_t shstr_off = symtab_off + (size_t)(n + 1) * sizeof(Elf64_Sym);
            size_t sht_off = (shstr_off + shstr_sz + 7) & ~(size_t)7;
            final_size = sht_off + (size_t)nsh * sizeof(Elf64_Shdr);
            final_buf = (uint8_t *)calloc(1, final_size);
            if (final_buf) {
                final_owns = 1;
                memcpy(final_buf, img, (size_t)total);
                memcpy(final_buf + strtab_off, strtab, strtab_sz);
                memcpy(final_buf + symtab_off, symtab,
                       (size_t)(n + 1) * sizeof(Elf64_Sym));
                memcpy(final_buf + shstr_off, shstr, shstr_sz);
                /* SHT: NULL + secciones cargables + symtab/strtab/shstrtab. */
                Elf64_Shdr *sh = (Elf64_Shdr *)(final_buf + sht_off);
                for (int i = 0; i < nsec; ++i) {
                    Elf64_Shdr *e = &sh[1 + i];
                    e->sh_name = sec_name_off[i];
                    int is_bss = (secs[i].flags & AOT_SEC_BSS) ? 1 : 0;
                    e->sh_type = is_bss ? SHT_NOBITS : SHT_PROGBITS;
                    e->sh_flags = SHF_ALLOC;
                    if (secs[i].flags & AOT_SEC_EXEC)
                        e->sh_flags |= SHF_EXECINSTR;
                    if (secs[i].flags & AOT_SEC_WRITE) e->sh_flags |= SHF_WRITE;
                    e->sh_addr = sec_va[i];
                    e->sh_offset = is_bss ? 0 : sec_va[i]; /* PIE base 0 */
                    e->sh_size = aot_sec_size(&secs[i]);
                    e->sh_addralign = secs[i].align ? secs[i].align : 8;
                }
                Elf64_Shdr *shsym = &sh[1 + nsec];
                shsym->sh_name = nm_symtab;
                shsym->sh_type = SHT_SYMTAB;
                shsym->sh_offset = symtab_off;
                shsym->sh_size = (uint64_t)(n + 1) * sizeof(Elf64_Sym);
                shsym->sh_link = (uint32_t)(1 + nsec + 1); /* -> .strtab */
                shsym->sh_info = 1;                        /* primer global */
                shsym->sh_addralign = 8;
                shsym->sh_entsize = sizeof(Elf64_Sym);
                Elf64_Shdr *shstr_sh = &sh[1 + nsec + 1];
                shstr_sh->sh_name = nm_strtab;
                shstr_sh->sh_type = SHT_STRTAB;
                shstr_sh->sh_offset = strtab_off;
                shstr_sh->sh_size = strtab_sz;
                shstr_sh->sh_addralign = 1;
                Elf64_Shdr *shshstr = &sh[1 + nsec + 2];
                shshstr->sh_name = nm_shstr;
                shshstr->sh_type = SHT_STRTAB;
                shshstr->sh_offset = shstr_off;
                shshstr->sh_size = shstr_sz;
                shshstr->sh_addralign = 1;
                /* Parchear la cabecera ELF para exponer la SHT. */
                Elf64_Ehdr *neh = (Elf64_Ehdr *)final_buf;
                neh->e_shoff = sht_off;
                neh->e_shnum = (uint16_t)nsh;
                neh->e_shstrndx = (uint16_t)(1 + nsec + 2);
                neh->e_shentsize = sizeof(Elf64_Shdr);
            }
        }
        free(shstr);
        free(sec_name_off);
        free(strtab);
        free(symtab);
        free(sht);
    }

    if (ok) {
        FILE *f = fopen(path, "wb");
        if (!f) {
            set_err(err, err_cap, "elf_dynexec: fopen fallo");
            ok = 0;
        } else {
            size_t w = fwrite(final_buf, 1, final_size, f);
            fclose(f);
            if (w != final_size) {
                set_err(err, err_cap, "elf_dynexec: escritura incompleta");
                ok = 0;
            }
        }
    }

    if (final_owns) free(final_buf);
    free(img);
    free(name_off);
    free(sonames);
    free(soname_off);
    free(bucket);
    free(chain);
    free(dynstr.p);
    free(sec_va);
    free(sec_seen);
    return ok;
}

/* aot_emit_elf32_dynexec -> movido a x86_32/aot_emit_x86_32.c. */

/* =========================================================================
 *  ELF64 RELOCATABLE (.o, ET_REL) -- hand-rolled (sin _start ni phdrs)
 * ========================================================================= */

/* Constantes ELF para TLS no presentes en CreateELF.h (submodulo): se definen
 * localmente para no tocar el submodulo.  `SHF_TLS` es de ELF a secas y se fue
 * al header interno comun; aqui queda solo lo que es de x86-64. */
#ifndef R_X86_64_TPOFF32
#define R_X86_64_TPOFF32 23 /* TLS local-exec: offset TP-relativo (32-bit) */
#endif


/* aot_emit_elf32_obj (+ e32_push16/32) -> movidos a x86_32/aot_emit_x86_32.c.
 */

/* El emisor de objetos ELF64 se fue a common/aot_emit_elf_obj.c: su layout es
 * el mismo para toda arquitectura de 64 bits y lo unico propio de esta son los
 * seis numeros de abajo.  Mientras vivio aqui, la marca de maquina iba clavada
 * a x86-64 y un objeto de ARM salia rotulado como ajeno, con sus llamadas
 * imposibles de reubicar. */
const AotElfObjArch *aot_elf_obj_arch_x86_64(void) {
    static const AotElfObjArch A = {
        EM_X86_64,
        R_X86_64_PLT32,  /* llamada a simbolo indefinido */
        R_X86_64_PLT32,  /* llamada dentro del propio objeto */
        R_X86_64_PC32,   /* referencia PC-relativa de 32 bits */
        R_X86_64_64,     /* direccion absoluta de 64 bits */
        R_X86_64_TPOFF32,/* TLS local-exec */
        /* El desplazamiento se cuenta desde el FINAL de la instruccion, asi
         * que hay que descontar los cuatro bytes del propio campo. */
        -4,
    };
    return &A;
}

/**
 * @copydoc aot_emit_elf_obj
 *
 * Envoltorio: pone la ficha de x86-64 y delega en el emisor compartido.
 */
int aot_emit_elf_obj(const char *path, const AotSection *secs, int num_secs,
                     const AotReloc *relocs, int num_relocs, const AotSym *syms,
                     int num_syms, char *err, size_t err_cap) {
    return aot_emit_elf_obj_arch(path, secs, num_secs, relocs, num_relocs, syms,
                                 num_syms, aot_elf_obj_arch_x86_64(), err,
                                 err_cap);
}

/* =========================================================================
 *  COFF RELOCATABLE (.obj Windows) -- movido a common/aot_emit_common.c
 *  (coff_obj_impl + aot_emit_coff_obj + aot_emit_coff32_obj; el layout del
 *  .obj es arch-neutral, la ISA solo cambia Machine + tipos de reloc via is32).
 * ========================================================================= */
/* =========================================================================
 *  ELF .so (ET_DYN) -- via CreateELF::elf_create_shared64
 * ========================================================================= */

int aot_emit_elf_so(const char *path, const AotSection *secs, int num_secs,
                    const AotReloc *relocs, int num_relocs, const AotSym *syms,
                    int num_syms, char *err, size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_elf_so: sin secciones");
        return 0;
    }

    ElfSharedSection *es =
        (ElfSharedSection *)calloc((size_t)num_secs, sizeof(ElfSharedSection));
    for (int i = 0; i < num_secs; ++i) {
        uint64_t f = SHF_ALLOC;
        if (secs[i].flags & AOT_SEC_EXEC) f |= SHF_EXECINSTR;
        if (secs[i].flags & AOT_SEC_WRITE) f |= SHF_WRITE;
        es[i].name = secs[i].name;
        es[i].sh_flags = f;
        es[i].data = secs[i].data;
        es[i].size = secs[i].size;
    }
    ElfSharedReloc *er = NULL;
    if (num_relocs > 0)
        er = (ElfSharedReloc *)calloc((size_t)num_relocs,
                                      sizeof(ElfSharedReloc));
    for (int r = 0; r < num_relocs; ++r) {
        if (relocs[r].target_is_size || relocs[r].target_is_end) {
            free(es);
            free(er);
            set_err(err, err_cap,
                    "aot_emit_elf_so: SIZE/END no soportado en .so (v1)");
            return 0;
        }
        er[r].site_sec = relocs[r].site_section;
        er[r].site_off = relocs[r].site_off;
        er[r].target_sec = relocs[r].target_section;
        er[r].target_off = relocs[r].target_off + (uint64_t)relocs[r].addend;
        er[r].is_abs64 = (relocs[r].kind == AOT_RELOC_ABS64 ||
                          relocs[r].kind == AOT_RELOC_IMM64)
                             ? 1
                             : 0;
    }
    ElfSharedExport *ex = NULL;
    if (num_syms > 0)
        ex = (ElfSharedExport *)calloc((size_t)num_syms,
                                       sizeof(ElfSharedExport));
    for (int g = 0; g < num_syms; ++g) {
        ex[g].name = syms[g].name;
        ex[g].sec = syms[g].section;
        ex[g].off = syms[g].offset;
        ex[g].is_func = syms[g].is_func;
    }

    int ok = elf_create_shared64(path, es, num_secs, er, num_relocs, ex,
                                 num_syms, err, err_cap);
    free(es);
    free(er);
    free(ex);
    return ok;
}

/* =========================================================================
 *  PE DLL (.dll) -- via CreatePe + tabla de exports (.edata) hand-rolled
 * ========================================================================= */

int aot_emit_pe_dll(const char *path, const AotLayoutCfg *cfg,
                    const AotSection *secs, int num_secs,
                    const AotReloc *relocs, int num_relocs, const AotSym *syms,
                    int num_syms, char *err, size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_pe_dll: sin secciones");
        return 0;
    }
    if (num_syms <= 0) {
        set_err(err, err_cap, "aot_emit_pe_dll: sin simbolos a exportar");
        return 0;
    }

    PE64FILE_struct pe;
    initializePE64File(&pe);
    /* Base de carga: por defecto 0x10000000 (base clasica de DLL, libre); el
     * usuario puede fijar otra.  Codigo PIC -> sin .reloc -> base fija. */
    pe.ntHeaders.OptionalHeader.ImageBase =
        (cfg && cfg->image_base) ? cfg->image_base : 0x10000000ull;
    if (cfg) {
        if (cfg->section_align)
            pe.ntHeaders.OptionalHeader.SectionAlignment = cfg->section_align;
        if (cfg->file_align)
            pe.ntHeaders.OptionalHeader.FileAlignment = cfg->file_align;
    }

    /* Secciones de usuario. */
    for (int i = 0; i < num_secs; ++i) {
        if (secs[i].flags & AOT_SEC_BSS)
            addBssSection(&pe, secs[i].name, secs[i].bss_size);
        else
            addSection(&pe, secs[i].name, pe_section_chars(secs[i].flags),
                       (_BYTE *)secs[i].data, secs[i].size);
    }

    /* Desenrollado: la .dll lo necesita igual que el .exe.  De hecho mas: el
     * codigo de una biblioteca aparece en las pilas de quien la llama, y sin su
     * `.pdata` el desenrollado se corta AL ENTRAR en ella, llevandose por
     * delante el manejador del programa que la cargo. */
    if (!aot_pe_set_exception_dir(&pe, secs, num_secs, err, err_cap)) {
        freePE64File(&pe);
        return 0;
    }

    /* TLS (thread_local) en la .dll: sintetizar el IMAGE_TLS_DIRECTORY +
     * _tls_index igual que en el .exe.  El cargador de Windows procesa el
     * directorio TLS tambien para DLLs (Vista+: tambien las cargadas con
     * LoadLibrary), montando el bloque por-hilo. */
    uint64_t tls_index_va = aot_pe_synth_tls(
        &pe, secs, num_secs, 1, cfg ? cfg->tls_callback_section : -1,
        cfg ? cfg->tls_callback_off : 0);

    /* TLS .dll: el cargador de Windows aplica la plantilla del TLS de una .dll
     * a traves de su DllMain (no la copia sin un entry que dispare su init).
     * El AddressOfEntryPoint -> __vx_tls_init se fija tras finalizePE64File
     * (que lo recomputa), mas abajo. */

    /* Aplicar relocs (PIC: REL32 internas).  Mismo patron que aot_emit_pe. */
    {
        const uint64_t image_base = pe.ntHeaders.OptionalHeader.ImageBase;
        for (int r = 0; r < num_relocs; ++r) {
            const AotReloc *rl = &relocs[r];
            /* TLS PE: __vx_tls_index (RIP-rel) + SECREL32 (offset en .tls). */
            if (aot_pe_apply_tls_reloc(&pe, secs, num_secs, rl, tls_index_va))
                continue;
            if (rl->target_is_size || rl->target_is_end) {
                set_err(err, err_cap, "aot_emit_pe_dll: SIZE/END no soportado");
                freePE64File(&pe);
                return 0;
            }
            if (rl->site_section < 0 || rl->site_section >= num_secs ||
                rl->target_section < 0 || rl->target_section >= num_secs) {
                set_err(err, err_cap,
                        "aot_emit_pe_dll: reloc con seccion fuera de rango");
                freePE64File(&pe);
                return 0;
            }
            uint64_t target_value =
                image_base +
                pe.sectionHeaders[rl->target_section].VirtualAddress +
                rl->target_off;
            target_value = (uint64_t)((int64_t)target_value + rl->addend);
            uint64_t site_va =
                image_base +
                pe.sectionHeaders[rl->site_section].VirtualAddress +
                rl->site_off;
            uint32_t width =
                (rl->kind == AOT_RELOC_ABS64 || rl->kind == AOT_RELOC_IMM64)
                    ? 8u
                    : 4u;
            if (rl->site_off + width > secs[rl->site_section].size) {
                set_err(err, err_cap,
                        "aot_emit_pe_dll: reloc fuera de la seccion del sitio");
                freePE64File(&pe);
                return 0;
            }
            apply_reloc(pe.sectionData[rl->site_section] + rl->site_off,
                        site_va, target_value, rl->kind, image_base);
        }
    }

    /* Tabla de exports (.edata).  Predecir su RVA (siguiente seccion). */
    const ___IMAGE_SECTION_HEADER *last =
        &pe.sectionHeaders[pe.numberOfSections - 1];
    _DWORD edataRVA = align(last->VirtualAddress + last->Misc.VirtualSize,
                            pe.ntHeaders.OptionalHeader.SectionAlignment);

    /* Orden de exports por nombre (GetProcAddress hace busqueda binaria: la
     * name pointer table DEBE estar ordenada ascendente). */
    int *order = (int *)malloc((size_t)num_syms * sizeof(int));
    for (int i = 0; i < num_syms; ++i)
        order[i] = i;
    for (int i = 0; i < num_syms; ++i)
        for (int j = i + 1; j < num_syms; ++j)
            if (strcmp(syms[order[j]].name, syms[order[i]].name) < 0) {
                int t = order[i];
                order[i] = order[j];
                order[j] = t;
            }

    /* Layout del blob .edata: dir(40) + EAT + name_ptr + ordinals + strings. */
    const uint32_t n = (uint32_t)num_syms;
    const uint32_t off_eat = 40;
    const uint32_t off_names = off_eat + 4u * n;
    const uint32_t off_ord = off_names + 4u * n;
    const uint32_t off_str = off_ord + 2u * n;

    OBuf ed;
    memset(&ed, 0, sizeof(ed));
    /* strings (calculados aparte para conocer offsets), luego ensamblamos. */
    const char *dllname = strrchr(path, '/');
    const char *dllbk = strrchr(path, '\\');
    if (dllbk > dllname) dllname = dllbk;
    dllname = dllname ? dllname + 1 : path;

    /* Construir la tabla de strings y registrar offsets. */
    OBuf strs;
    memset(&strs, 0, sizeof(strs));
    uint32_t dllname_soff = (uint32_t)strs.len;
    ob_put(&strs, dllname, strlen(dllname) + 1);
    uint32_t *name_soff =
        (uint32_t *)malloc((size_t)num_syms * sizeof(uint32_t));
    for (int i = 0; i < num_syms; ++i) {
        name_soff[i] = (uint32_t)strs.len;
        ob_put(&strs, syms[order[i]].name, strlen(syms[order[i]].name) + 1);
    }

    /* Export directory (40 bytes). */
    uint8_t dir[40];
    memset(dir, 0, sizeof(dir));
    wr32le(dir + 12, edataRVA + off_str + dllname_soff); /* Name */
    wr32le(dir + 16, 1);                                 /* Base (ordinal) */
    wr32le(dir + 20, n);                                 /* NumberOfFunctions */
    wr32le(dir + 24, n);                                 /* NumberOfNames */
    wr32le(dir + 28, edataRVA + off_eat);   /* AddressOfFunctions */
    wr32le(dir + 32, edataRVA + off_names); /* AddressOfNames */
    wr32le(dir + 36, edataRVA + off_ord);   /* AddressOfNameOrdinals */
    ob_put(&ed, dir, 40);

    /* EAT: RVA de cada funcion (en orden ordenado -> ordinal i = i). */
    for (int i = 0; i < num_syms; ++i) {
        const AotSym *s = &syms[order[i]];
        uint32_t rva =
            pe.sectionHeaders[s->section].VirtualAddress + (uint32_t)s->offset;
        uint8_t b[4];
        wr32le(b, rva);
        ob_put(&ed, b, 4);
    }
    /* Name pointer table (RVA de cada nombre, ordenado). */
    for (int i = 0; i < num_syms; ++i) {
        uint8_t b[4];
        wr32le(b, edataRVA + off_str + name_soff[i]);
        ob_put(&ed, b, 4);
    }
    /* Ordinal table (u16): ordinal[i] = i (EAT en mismo orden). */
    for (int i = 0; i < num_syms; ++i) {
        uint8_t b[2];
        b[0] = (uint8_t)i;
        b[1] = (uint8_t)(i >> 8);
        ob_put(&ed, b, 2);
    }
    /* Strings. */
    ob_put(&ed, strs.p, strs.len);

    addSection(&pe, ".edata",
               ___IMAGE_SCN_CNT_INITIALIZED_DATA | ___IMAGE_SCN_MEM_READ,
               (_BYTE *)ed.p, (_DWORD)ed.len);
    pe.ntHeaders.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXPORT]
        .VirtualAddress = edataRVA;
    pe.ntHeaders.OptionalHeader.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXPORT]
        .Size = (_DWORD)ed.len;

    /* Marcar como DLL + base fija (sin .reloc, codigo PIC carga en ImageBase).
     */
    pe.ntHeaders.FileHeader.Characteristics |= ___IMAGE_FILE_DLL;
    pe.ntHeaders.OptionalHeader.DllCharacteristics &=
        (uint16_t)~___IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    finalizePE64File(&pe);
    /* finalizePE64File recomputa el entry; lo re-fijamos.  Con TLS el entry
     * apunta a __vx_tls_init (DllMain que aplica la plantilla por-hilo y
     * devuelve TRUE); sin TLS no hay DllMain (entry=0). */
    if (tls_index_va != 0 && cfg && cfg->tls_callback_section >= 0 &&
        cfg->tls_callback_section < pe.numberOfSections) {
        pe.ntHeaders.OptionalHeader.AddressOfEntryPoint =
            pe.sectionHeaders[cfg->tls_callback_section].VirtualAddress +
            cfg->tls_callback_off;
    } else {
        pe.ntHeaders.OptionalHeader.AddressOfEntryPoint = 0; /* sin DllMain */
    }
    /* --aot-debug: symtab COFF con las RVAs de seccion (post-proceso). */
    uint32_t *dbg_rva_dll = NULL;
    if (g_aot_dbg_n > 0) {
        dbg_rva_dll = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
        if (dbg_rva_dll)
            for (int i = 0; i < num_secs; ++i)
                dbg_rva_dll[i] = (uint32_t)pe.sectionHeaders[i].VirtualAddress;
    }
    if (!aot_pe_finish_pdata(&pe, secs, num_secs, err, err_cap)) {
        freePE64File(&pe);
        free(dbg_rva_dll);
        return 0;
    }
    writePE64File(&pe, path);
    freePE64File(&pe);
    if (dbg_rva_dll) {
        aot_pe_append_coff_symtab(path, g_aot_dbg_syms, g_aot_dbg_n,
                                  dbg_rva_dll);
        free(dbg_rva_dll);
    }

    free(order);
    free(name_soff);
    free(strs.p);
    free(ed.p);
    return 1;
}

/* aot_emit_flat_bin + aot_pe_export_names + aot_free_pe_export_names +
 * aot_elf_export_names -> movidos a common/aot_emit_common.c (arch-neutral). */
