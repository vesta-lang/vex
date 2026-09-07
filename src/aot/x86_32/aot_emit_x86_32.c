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
 * @file aot/x86_32/aot_emit_x86_32.c
 * @brief Emisores de objetos AOT para x86-32 (i386): PE32 EXEC + ELF32 EXEC
 *        estatico + ELF32 dynexec (PIE) + ELF32 .o relocatable.
 *
 * Parte del desacople multi-arch (aot/common + aot/x86_64 + aot/x86_32 +
 * aot/x86_16 + aot/arm64).  Aqui viven SOLO los emisores de 32 bits (EM_386,
 * structs Elf32 / PE32); los de 64 bits estan en aot/x86_64 y los helpers
 * arch-neutrales + la frontera con LibPEparse en aot/common.  Se compila como
 * C. El wrapper COFF de 32 bits (aot_emit_coff32_obj) vive en aot/common porque
 * comparte coff_obj_impl con la variante de 64 bits (solo cambia is32).
 */

#include "aot/aot_emit_shim.h"

/* Helpers arch-neutrales + cabeceras C de LibPEparse (frontera compartida).
 * Include RELATIVO al fichero: no se toca el include-path global. */
#include "../common/aot_emit_internal.h"

/* =========================================================================
 *  PE32 EJECUTABLE (i386, .exe Windows 32-bit) -- hand-rolled.
 *
 *  Minimo: secciones de usuario (RVA por pagina) + .idata sintetizada con UN
 *  import (kernel32!ExitProcess, el _start sale por ahi).  Parchea el `call
 *  main` (REL32) + intra-imagen + el `FF 15` del stub (abs32 a la IAT).  v1:
 *  EXEC self-contained (sin libc); llamadas a externos = follow-up (thunks
 * 32b).
 * ========================================================================= */
/* Construye la seccion .idata de un PE32 con N imports agrupados por DLL.
 * @p idata_rva: RVA donde vivira .idata (para los RVAs internos).
 * Devuelve buffer malloc'd (caller libera) + *size_out.  Rellena
 * @p iat_off_out[k] = offset DENTRO de .idata de la entrada IAT del import k
 * (para parchear su thunk: abs = ImageBase + idata_rva + iat_off_out[k]).
 * *impdir_size_out, *iat_rva0_out, *iat_total_out para los DataDirectory. */
static uint8_t *build_idata32(const AotImport *imps, int n, uint32_t idata_rva,
                              uint32_t *size_out, uint32_t *impdir_size_out,
                              uint32_t *iat_rva0_out, uint32_t *iat_total_out,
                              uint32_t *iat_off_out) {
    /* DLLs unicas (orden de aparicion) + funcs por DLL. */
    const char **dlls = (const char **)calloc((size_t)n, sizeof(char *));
    int *fcount = (int *)calloc((size_t)n, sizeof(int));
    /* func[d] = lista de nombres (punteros) por DLL d. */
    const char ***funcs = (const char ***)calloc((size_t)n, sizeof(char **));
    int ndll = 0;
    for (int k = 0; k < n; ++k) {
        int d = -1;
        for (int j = 0; j < ndll; ++j)
            if (strcmp(dlls[j], imps[k].dll) == 0) {
                d = j;
                break;
            }
        if (d < 0) {
            d = ndll++;
            dlls[d] = imps[k].dll;
            funcs[d] = (const char **)calloc((size_t)n, sizeof(char *));
        }
        int dup = 0;
        for (int j = 0; j < fcount[d]; ++j)
            if (strcmp(funcs[d][j], imps[k].func) == 0) {
                dup = 1;
                break;
            }
        if (!dup) funcs[d][fcount[d]++] = imps[k].func;
    }
    /* Layout. */
    uint32_t impdir = 0, impdir_sz = (uint32_t)(ndll + 1) * 20;
    uint32_t *ilt_off = (uint32_t *)calloc((size_t)ndll, sizeof(uint32_t));
    uint32_t *iat_off = (uint32_t *)calloc((size_t)ndll, sizeof(uint32_t));
    uint32_t cur = impdir + impdir_sz;
    for (int d = 0; d < ndll; ++d) {
        ilt_off[d] = cur;
        cur += (uint32_t)(fcount[d] + 1) * 4;
    }
    for (int d = 0; d < ndll; ++d) {
        iat_off[d] = cur;
        cur += (uint32_t)(fcount[d] + 1) * 4;
    }
    /* hint/name por (dll,func) unica + dll names; recordar offsets. */
    uint32_t **hint_off = (uint32_t **)calloc((size_t)ndll, sizeof(uint32_t *));
    for (int d = 0; d < ndll; ++d)
        hint_off[d] = (uint32_t *)calloc((size_t)fcount[d], sizeof(uint32_t));
    for (int d = 0; d < ndll; ++d)
        for (int i = 0; i < fcount[d]; ++i) {
            hint_off[d][i] = cur;
            uint32_t hl = 2 + (uint32_t)strlen(funcs[d][i]) + 1;
            if (hl & 1) ++hl;
            cur += hl;
        }
    uint32_t *dll_off = (uint32_t *)calloc((size_t)ndll, sizeof(uint32_t));
    for (int d = 0; d < ndll; ++d) {
        dll_off[d] = cur;
        cur += (uint32_t)strlen(dlls[d]) + 1;
    }
    uint32_t size = cur;

    uint8_t *buf = (uint8_t *)calloc(1, size);
    for (int d = 0; d < ndll; ++d) {
        uint8_t *e = buf + impdir + (uint32_t)d * 20;
        wr32(e + 0, idata_rva + ilt_off[d]);  /* OriginalFirstThunk */
        wr32(e + 12, idata_rva + dll_off[d]); /* Name */
        wr32(e + 16, idata_rva + iat_off[d]); /* FirstThunk (IAT) */
        for (int i = 0; i < fcount[d]; ++i) {
            wr32(buf + ilt_off[d] + (uint32_t)i * 4,
                 idata_rva + hint_off[d][i]);
            wr32(buf + iat_off[d] + (uint32_t)i * 4,
                 idata_rva + hint_off[d][i]);
            memcpy(buf + hint_off[d][i] + 2, funcs[d][i], strlen(funcs[d][i]));
        }
        memcpy(buf + dll_off[d], dlls[d], strlen(dlls[d]));
    }
    /* iat_off_out[k] para cada import original. */
    for (int k = 0; k < n; ++k) {
        int d = -1;
        for (int j = 0; j < ndll; ++j)
            if (strcmp(dlls[j], imps[k].dll) == 0) {
                d = j;
                break;
            }
        int fi = 0;
        for (int i = 0; i < fcount[d]; ++i)
            if (strcmp(funcs[d][i], imps[k].func) == 0) {
                fi = i;
                break;
            }
        iat_off_out[k] = iat_off[d] + (uint32_t)fi * 4;
    }
    *size_out = size;
    *impdir_size_out = impdir_sz;
    *iat_rva0_out = idata_rva + iat_off[0];
    *iat_total_out = (uint32_t)(cur > 0 ? 0 : 0); /* no usado finamente */
    /* IAT total range: desde iat_off[0] hasta fin del ultimo IAT. */
    *iat_total_out =
        (iat_off[ndll - 1] + (uint32_t)(fcount[ndll - 1] + 1) * 4) - iat_off[0];

    for (int d = 0; d < ndll; ++d) {
        free(funcs[d]);
        free(hint_off[d]);
    }
    free(dlls);
    free(fcount);
    free(funcs);
    free(ilt_off);
    free(iat_off);
    free(hint_off);
    free(dll_off);
    return buf;
}

int aot_emit_pe32(const char *path, const AotLayoutCfg *cfg,
                  const AotSection *secs, int num_secs, int entry_sec,
                  uint64_t entry_off, const AotImport *imps, int num_imps,
                  const AotReloc *relocs, int num_relocs, char *err,
                  size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "pe32: sin secciones");
        return 0;
    }
    if (num_imps <= 0) {
        set_err(err, err_cap, "pe32: sin imports (falta el _start)");
        return 0;
    }
    if (entry_sec < 0 || entry_sec >= num_secs) {
        set_err(err, err_cap, "pe32: entry_sec fuera de rango");
        return 0;
    }

    const uint32_t IMGBASE =
        (cfg && cfg->image_base) ? (uint32_t)cfg->image_base : 0x00400000u;
    const uint32_t SECALIGN = 0x1000u, FILEALIGN = 0x200u;
    const uint32_t HDR_RVA = 0; /* headers en RVA 0 */

    /* Numero de secciones del PE = secciones de usuario con datos + .idata. */
    int n_user = 0;
    for (int i = 0; i < num_secs; ++i)
        if (!(secs[i].flags & AOT_SEC_BSS) && secs[i].size > 0) ++n_user;
    const int n_pe_sec = n_user + 1; /* + .idata */

    /* Tamano de cabeceras: DOS(0x40) + "PE\0\0"(4) + COFF(20) + OptHdr32(224)
     * + section headers (40 c/u), alineado a FILEALIGN. */
    const uint32_t opt_size = 224; /* 96 estandar+win + 128 data dirs */
    uint32_t hdr_raw = 0x40 + 4 + 20 + opt_size + (uint32_t)n_pe_sec * 40;
    uint32_t size_headers = aot_dyn_align_u32(hdr_raw, FILEALIGN);

    /* Layout de secciones: RVA por pagina (SECALIGN), file offset por
     * FILEALIGN. sec_rva/sec_foff por seccion de usuario; luego .idata. */
    uint32_t *sec_rva = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    uint32_t *sec_foff = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    uint32_t *sec_vsz = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    uint8_t *sec_seen = (uint8_t *)calloc((size_t)num_secs, sizeof(uint8_t));
    uint32_t rva = aot_dyn_align_u32(size_headers, SECALIGN); /* primera secc */
    uint32_t foff = size_headers;
    for (int i = 0; i < num_secs; ++i) {
        if ((secs[i].flags & AOT_SEC_BSS) || secs[i].size == 0) continue;
        sec_rva[i] = rva;
        sec_foff[i] = foff;
        sec_vsz[i] = (uint32_t)secs[i].size;
        sec_seen[i] = 1;
        rva = aot_dyn_align_u32(rva + (uint32_t)secs[i].size, SECALIGN);
        foff = aot_dyn_align_u32(foff + (uint32_t)secs[i].size, FILEALIGN);
    }
    if (!sec_seen[entry_sec]) {
        free(sec_rva);
        free(sec_foff);
        free(sec_vsz);
        free(sec_seen);
        set_err(err, err_cap, "pe32: la seccion de entrada no tiene datos");
        return 0;
    }

    /* .idata multi-DLL (kernel32!ExitProcess del stub + libc de los thunks). */
    uint32_t idata_rva = rva, idata_foff = foff;
    uint32_t idata_size = 0, impdir_size = 0, iat_rva0 = 0, iat_total = 0;
    uint32_t *imp_iat_off =
        (uint32_t *)calloc((size_t)num_imps, sizeof(uint32_t));
    uint8_t *idata_buf =
        build_idata32(imps, num_imps, idata_rva, &idata_size, &impdir_size,
                      &iat_rva0, &iat_total, imp_iat_off);
    uint32_t idata_vsz = idata_size;
    uint32_t idata_fsz = aot_dyn_align_u32(idata_size, FILEALIGN);

    uint32_t total = idata_foff + idata_fsz;
    uint32_t size_image = aot_dyn_align_u32(idata_rva + idata_vsz, SECALIGN);

    uint8_t *img = (uint8_t *)calloc(1, total);
    if (!img) {
        free(sec_rva);
        free(sec_foff);
        free(sec_vsz);
        free(sec_seen);
        set_err(err, err_cap, "pe32: OOM");
        return 0;
    }

    uint32_t entry_rva = sec_rva[entry_sec] + (uint32_t)entry_off;

    /* DOS header. */
    img[0] = 'M';
    img[1] = 'Z';
    wr32(img + 0x3C, 0x40); /* e_lfanew */

    /* PE signature + COFF header (en 0x40). */
    uint8_t *pe = img + 0x40;
    pe[0] = 'P';
    pe[1] = 'E';
    pe[2] = 0;
    pe[3] = 0;
    uint8_t *coff = pe + 4;
    coff[0] = 0x4C;
    coff[1] = 0x01; /* Machine = 0x14C (i386) */
    coff[2] = (uint8_t)n_pe_sec;
    coff[3] = (uint8_t)(n_pe_sec >> 8); /* NumberOfSections */
    /* TimeDateStamp/PtrSym/NumSym = 0 (coff+4..15) */
    coff[16] = (uint8_t)opt_size;
    coff[17] = (uint8_t)(opt_size >> 8); /* SizeOfOptionalHeader */
    /* Characteristics: EXECUTABLE_IMAGE(0x2) | 32BIT_MACHINE(0x100) |
     * RELOCS_STRIPPED(0x1) */
    uint16_t chars = 0x0002 | 0x0100 | 0x0001;
    coff[18] = (uint8_t)chars;
    coff[19] = (uint8_t)(chars >> 8);

    /* Optional header PE32 (magic 0x10B). */
    uint8_t *oh = coff + 20;
    oh[0] = 0x0B;
    oh[1] = 0x01; /* Magic = 0x10B (PE32) */
    oh[2] = 1;
    oh[3] = 0;                         /* Linker version */
    wr32(oh + 16, entry_rva);          /* AddressOfEntryPoint */
    wr32(oh + 20, sec_rva[entry_sec]); /* BaseOfCode */
    wr32(oh + 24, idata_rva);          /* BaseOfData (PE32-only) */
    wr32(oh + 28, IMGBASE);            /* ImageBase (32-bit) */
    wr32(oh + 32, SECALIGN);           /* SectionAlignment */
    wr32(oh + 36, FILEALIGN);          /* FileAlignment */
    oh[40] = 4;
    oh[41] = 0;
    oh[44] = 0;
    oh[45] = 0; /* OS ver 4.0 */
    oh[48] = 4;
    oh[49] = 0;                  /* Subsystem ver 4.0 */
    wr32(oh + 56, size_image);   /* SizeOfImage */
    wr32(oh + 60, size_headers); /* SizeOfHeaders */
    oh[68] = 3;
    oh[69] = 0; /* Subsystem = CONSOLE(3) */
    /* DllCharacteristics = 0 (sin DYNAMIC_BASE -> base fija; sin .reloc). */
    wr32(oh + 72, 0x100000);
    wr32(oh + 76, 0x1000); /* StackReserve/Commit */
    wr32(oh + 80, 0x100000);
    wr32(oh + 84, 0x1000); /* HeapReserve/Commit */
    wr32(oh + 92, 16);     /* NumberOfRvaAndSizes */
    /* Data directories (offset 96), 16 * 8.  [1]=Import, [12]=IAT. */
    uint8_t *dd = oh + 96;
    wr32(dd + 1 * 8 + 0, idata_rva);   /* Import dir RVA */
    wr32(dd + 1 * 8 + 4, impdir_size); /* Import dir size */
    wr32(dd + 12 * 8 + 0, iat_rva0);   /* IAT RVA (1er IAT) */
    wr32(dd + 12 * 8 + 4, iat_total);  /* IAT size total */

    /* Section headers (tras el optional header). */
    uint8_t *sh = oh + opt_size;
    int shi = 0;
    for (int i = 0; i < num_secs; ++i) {
        if (!sec_seen[i]) continue;
        uint8_t *e = sh + shi * 40;
        const char *nm = secs[i].name ? secs[i].name : ".text";
        for (int j = 0; j < 8 && nm[j]; ++j)
            e[j] = (uint8_t)nm[j];
        wr32(e + 8, sec_vsz[i]);  /* VirtualSize */
        wr32(e + 12, sec_rva[i]); /* VirtualAddress */
        wr32(e + 16,
             aot_dyn_align_u32(sec_vsz[i], FILEALIGN)); /* SizeOfRawData */
        wr32(e + 20, sec_foff[i]);                      /* PointerToRawData */
        uint32_t c = (secs[i].flags & AOT_SEC_EXEC) ? 0x60000020u : 0x40000040u;
        if (secs[i].flags & AOT_SEC_WRITE) c |= 0x80000000u;
        wr32(e + 36, c); /* Characteristics */
        ++shi;
    }
    /* .idata section header. */
    {
        uint8_t *e = sh + shi * 40;
        memcpy(e, ".idata", 6);
        wr32(e + 8, idata_vsz);
        wr32(e + 12, idata_rva);
        wr32(e + 16, idata_fsz);
        wr32(e + 20, idata_foff);
        wr32(e + 36, 0xC0000040u); /* INITIALIZED_DATA|READ|WRITE */
    }

    /* Datos de las secciones de usuario. */
    for (int i = 0; i < num_secs; ++i)
        if (sec_seen[i]) memcpy(img + sec_foff[i], secs[i].data, secs[i].size);

    /* .idata: el buffer multi-DLL construido por build_idata32. */
    memcpy(img + idata_foff, idata_buf, idata_size);

    /* Relocs intra-imagen del driver (REL32 a funciones; ABS no en v1). */
    int ok = 1;
    for (int r = 0; r < num_relocs && ok; ++r) {
        const AotReloc *rl = &relocs[r];
        if (rl->kind != AOT_RELOC_REL32) {
            set_err(err, err_cap,
                    "pe32: solo REL32 intra-imagen en v1 (ABS32 follow-up)");
            ok = 0;
            break;
        }
        if (rl->site_section < 0 || rl->site_section >= num_secs ||
            !sec_seen[rl->site_section] ||
            (!rl->target_is_size &&
             (rl->target_section < 0 || rl->target_section >= num_secs ||
              !sec_seen[rl->target_section]))) {
            set_err(err, err_cap, "pe32: reloc con seccion invalida");
            ok = 0;
            break;
        }
        uint64_t tv = rl->target_is_imagebase
                          ? (uint64_t)IMGBASE // `__ImageBase`: la base, tal cual
                          : (IMGBASE + sec_rva[rl->target_section] +
                             rl->target_off);
        tv = (uint64_t)((int64_t)tv + rl->addend);
        uint64_t site_va = IMGBASE + sec_rva[rl->site_section] + rl->site_off;
        if (!apply_reloc(img + sec_foff[rl->site_section] + rl->site_off,
                         site_va, tv, rl->kind, (uint64_t)IMGBASE)) {
            set_err(err, err_cap, "pe32: reloc kind invalido");
            ok = 0;
            break;
        }
    }

    /* Parchear cada import: el FF 15/FF 25 disp32 = abs de SU entrada IAT.
     * (FF 15 = call del stub ExitProcess; FF 25 = jmp del thunk de un libc).
     * imp_iat_off[k] = offset dentro de .idata de la entrada IAT del import k.
     */
    for (int k = 0; k < num_imps && ok; ++k) {
        int cs = imps[k].call_section;
        if (cs < 0 || cs >= num_secs || !sec_seen[cs]) {
            set_err(err, err_cap, "pe32: call_section del import invalido");
            ok = 0;
            break;
        }
        uint32_t disp = IMGBASE + idata_rva + imp_iat_off[k];
        wr32(img + sec_foff[cs] + imps[k].call_off + 2, disp);
    }

    if (ok) {
        FILE *f = fopen(path, "wb");
        if (!f) {
            set_err(err, err_cap, "pe32: fopen fallo");
            ok = 0;
        } else {
            size_t w = fwrite(img, 1, total, f);
            fclose(f);
            if (w != total) {
                set_err(err, err_cap, "pe32: escritura incompleta");
                ok = 0;
            }
        }
    }
    free(img);
    free(sec_rva);
    free(sec_foff);
    free(sec_vsz);
    free(sec_seen);
    free(idata_buf);
    free(imp_iat_off);
    return ok;
}

/* =========================================================================
 *  ELF32 EJECUTABLE ESTaTICO (ET_EXEC, EM_386) -- modo protegido / kernels.
 *  Hand-rolled (sin structs Elf32: el orden de campos del phdr ELF32 difiere
 *  del ELF64).  1 PT_LOAD R+X cubriendo ehdr+phdr+codigo; entry = _start;
 *  salida via int 0x80 (el stub).  Freestanding: sin dynamic ni libc.  Solo
 *  relocs PC-relativas (CALL_REL32, invariantes de la base) + inmediatos; el
 *  x86-32 no tiene RIP-relativo -> refs a datos absolutas (ABS32) son
 * follow-up.
 * ========================================================================= */
int aot_emit_elf32(const char *path, const AotLayoutCfg *cfg,
                   const AotSection *secs, int num_secs, int entry_sec,
                   uint64_t entry_off, const AotReloc *relocs, int num_relocs,
                   char *err, size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "elf32: sin secciones");
        return 0;
    }
    if (entry_sec < 0 || entry_sec >= num_secs) {
        set_err(err, err_cap, "elf32: entry_sec fuera de rango");
        return 0;
    }

    const uint32_t base =
        (cfg && cfg->image_base) ? (uint32_t)cfg->image_base : 0x08048000u;
    const uint32_t EHDR = 52, PHDR = 32;

    /* Layout: ehdr + phdr + secciones (vaddr = base + file offset). */
    uint32_t *sec_va = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    uint32_t *sec_fo = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    uint8_t *sec_seen = (uint8_t *)calloc((size_t)num_secs, sizeof(uint8_t));
    uint32_t off = EHDR + PHDR;
    for (int i = 0; i < num_secs; ++i) {
        if ((secs[i].flags & AOT_SEC_BSS) || secs[i].size == 0) continue;
        uint32_t a = secs[i].align ? (uint32_t)secs[i].align : 16u;
        while (off % a)
            ++off;
        sec_fo[i] = off;
        sec_va[i] = base + off;
        sec_seen[i] = 1;
        off += (uint32_t)secs[i].size;
    }
    uint32_t total = off;
    if (!sec_seen[entry_sec]) {
        free(sec_va);
        free(sec_fo);
        free(sec_seen);
        set_err(err, err_cap, "elf32: la seccion de entrada no tiene datos");
        return 0;
    }
    uint32_t entry_va = sec_va[entry_sec] + (uint32_t)entry_off;

    uint8_t *img = (uint8_t *)calloc(1, total);
    if (!img) {
        free(sec_va);
        free(sec_fo);
        free(sec_seen);
        set_err(err, err_cap, "elf32: OOM");
        return 0;
    }

    /* Ehdr (52 bytes). */
    img[0] = 0x7f;
    img[1] = 'E';
    img[2] = 'L';
    img[3] = 'F';
    img[4] = 1 /*ELFCLASS32*/;
    img[5] = 1 /*LSB*/;
    img[6] = 1 /*EV_CURRENT*/;
    img[16] = 2;
    img[17] = 0; /* e_type = ET_EXEC */
    img[18] = 3;
    img[19] = 0;              /* e_machine = EM_386 */
    wr32(img + 20, 1);        /* e_version */
    wr32(img + 24, entry_va); /* e_entry */
    wr32(img + 28, EHDR);     /* e_phoff = 52 */
    wr32(img + 32, 0);        /* e_shoff */
    wr32(img + 36, 0);        /* e_flags */
    img[40] = (uint8_t)EHDR;
    img[41] = 0; /* e_ehsize */
    img[42] = (uint8_t)PHDR;
    img[43] = 0; /* e_phentsize */
    img[44] = 1;
    img[45] = 0; /* e_phnum */
    img[46] = 0;
    img[47] = 0; /* e_shentsize */
    img[48] = 0;
    img[49] = 0; /* e_shnum */
    img[50] = 0;
    img[51] = 0; /* e_shstrndx */

    /* Phdr ELF32 (PT_LOAD R+X):
     * type,offset,vaddr,paddr,filesz,memsz,flags,align. */
    uint8_t *ph = img + EHDR;
    wr32(ph + 0, 1);       /* p_type = PT_LOAD */
    wr32(ph + 4, 0);       /* p_offset */
    wr32(ph + 8, base);    /* p_vaddr */
    wr32(ph + 12, base);   /* p_paddr */
    wr32(ph + 16, total);  /* p_filesz */
    wr32(ph + 20, total);  /* p_memsz */
    wr32(ph + 24, 7);      /* p_flags = R+W+X (freestanding: el gdata mutable
                            * -- guards de static locals, campos de un static
                            * ctx -- vive en este mismo segmento y el
                            * __module_init lo ESCRIBE; sin W el store crashea.
                            * MEJORA: dos PT_LOAD (R+X code, R+W data) para
                            * respetar W^X, como el emisor ELF64). */
    wr32(ph + 28, 0x1000); /* p_align */

    /* Datos de las secciones. */
    for (int i = 0; i < num_secs; ++i)
        if (sec_seen[i]) memcpy(img + sec_fo[i], secs[i].data, secs[i].size);

    /* Relocs (solo PC-relativas + inmediatos en x86-32 v1). */
    int ok = 1;
    for (int r = 0; r < num_relocs && ok; ++r) {
        const AotReloc *rl = &relocs[r];
        if (rl->kind == AOT_RELOC_ABS64 || rl->kind == AOT_RELOC_IMM64) {
            set_err(err, err_cap, "elf32: ABS64/IMM64 no aplica en 32-bit");
            ok = 0;
            break;
        }
        if (rl->site_section < 0 || rl->site_section >= num_secs ||
            !sec_seen[rl->site_section] ||
            (!rl->target_is_size &&
             (rl->target_section < 0 || rl->target_section >= num_secs ||
              !sec_seen[rl->target_section]))) {
            set_err(err, err_cap, "elf32: reloc con seccion invalida");
            ok = 0;
            break;
        }
        uint64_t tv;
        if (rl->target_is_imagebase)
            tv = base; // la direccion de CARGA; ver el emisor de 64 bits
        else if (rl->target_is_size)
            tv = aot_sec_size(&secs[rl->target_section]);
        else {
            tv = sec_va[rl->target_section];
            tv += rl->target_is_end ? aot_sec_size(&secs[rl->target_section])
                                    : rl->target_off;
        }
        tv = (uint64_t)((int64_t)tv + rl->addend);
        uint64_t site_va = sec_va[rl->site_section] + rl->site_off;
        if (!apply_reloc(img + sec_fo[rl->site_section] + rl->site_off, site_va,
                         tv, rl->kind, AOT_NO_IMAGE_BASE)) {
            set_err(err, err_cap, "elf32: reloc kind invalido");
            ok = 0;
            break;
        }
    }

    if (ok) {
        FILE *f = fopen(path, "wb");
        if (!f) {
            set_err(err, err_cap, "elf32: fopen fallo");
            ok = 0;
        } else {
            size_t w = fwrite(img, 1, total, f);
            fclose(f);
            if (w != total) {
                set_err(err, err_cap, "elf32: escritura incompleta");
                ok = 0;
            }
        }
    }
    free(img);
    free(sec_va);
    free(sec_fo);
    free(sec_seen);
    return ok;
}

/* =========================================================================
 *  ELF32 EJECUTABLE DINaMICO (PIE ET_DYN, EM_386) con imports libc via
 *  eager-GOT -- hand-rolled.  Variante 32-bit de aot_emit_elf_dynexec:
 *  enlaza contra libc.so.6 de i386.  Difs 32-bit: Ehdr 52B, Phdr 32B (orden
 *  distinto), Elf32_Sym 16B (info/other/shndx AL FINAL), Elf32_Rel 8B SIN
 *  addend (R_386_GLOB_DAT=6, .rel.dyn -> DT_REL/RELSZ/RELENT), Elf32_Dyn 8B,
 *  interp /lib/ld-linux.so.2, GOT 4B, thunk FF25 disp32 ABSOLUTO (i386 sin
 *  rip-rel; PIE base 0 -> vaddr==file off).
 * ========================================================================= */
#ifndef R_386_GLOB_DAT
#define R_386_GLOB_DAT 6
#endif
#define AOT_ELF32_ST_INFO(b, t) (((b) << 4) | ((t) & 0xf))
#define AOT_ELF32_R_INFO(s, t) (((uint32_t)(s) << 8) | ((t) & 0xff))

int aot_emit_elf32_dynexec(const char *path, const AotLayoutCfg *cfg,
                           const AotSection *secs, int num_secs, int entry_sec,
                           uint64_t entry_off, const AotReloc *relocs,
                           int num_relocs, const AotImport *imps, int num_imps,
                           char *err, size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "elf32_dynexec: sin secciones");
        return 0;
    }
    if (entry_sec < 0 || entry_sec >= num_secs) {
        set_err(err, err_cap, "elf32_dynexec: entry_sec fuera de rango");
        return 0;
    }
    if (num_imps < 0) num_imps = 0;
    /* num_imps == 0 es valido: un EXEC dinamico sin imports de libc pero con
     * TLS (necesita el cargador para montar el bloque thread-local).  GOT vacia
     * + dynsym de 1 entrada (null) + DT_NEEDED libc.so.6 (monta el TLS
     * estatico). */

    const uint32_t PAGE = (uint32_t)AOT_ELF_PAGE;
    /* Seccion TLS (plantilla thread_local local-exec): si existe, anyade un
     * PT_TLS para que el cargador monte el bloque TLS por-hilo. */
    int tls_sec = -1;
    for (int i = 0; i < num_secs; ++i)
        if (secs[i].flags & AOT_SEC_TLS) {
            tls_sec = i;
            break;
        }
    const int NPH = 6 + (tls_sec >= 0 ? 1 : 0);
    const int nsym = 1 + num_imps;
    const char interp[] = "/lib/ld-linux.so.2";
    const uint32_t interp_len = (uint32_t)sizeof(interp);

    const uint32_t EHDR32 = 52, PHDR32 = 32, SYM32 = 16, REL32SZ = 8, DYN32 = 8;
    /* x86-32 NO tiene rip-relativo -> el thunk usa direccionamiento ABSOLUTO.
     * Un PIE (ET_DYN) se carga en base aleatoria -> el absoluto fallaria.  Por
     * eso este es un ET_EXEC con BASE FIJA (modelo clasico de 32-bit dinamico):
     * vaddr = BASE + file_offset.  Los offsets en disco siguen siendo file
     * offsets (indexan img); las VADDR (e_entry, p_vaddr, DT_*, r_offset, el
     * disp32 del thunk) llevan +BASE. */
    const uint32_t BASE =
        (cfg && cfg->image_base) ? (uint32_t)cfg->image_base : 0x08048000u;

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
    uint32_t libc_off = (uint32_t)dynstr.len;
    ob_put(&dynstr, "libc.so.6", 10);

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
    uint32_t hash_size = (uint32_t)(2 + nbucket + nchain) * 4u;

    uint32_t off = 0;
    uint32_t ehdr_off = off;
    off += EHDR32;
    uint32_t phdr_off = off;
    off += (uint32_t)NPH * PHDR32;
    uint32_t interp_off = off;
    off += interp_len;
    off = aot_dyn_align_u32(off, 4);
    uint32_t dynsym_off = off;
    off += (uint32_t)nsym * SYM32;
    uint32_t dynstr_off = off;
    off += (uint32_t)dynstr.len;
    off = aot_dyn_align_u32(off, 4);
    uint32_t hash_off = off;
    off += hash_size;
    off = aot_dyn_align_u32(off, 4);
    uint32_t rel_off = off;
    off += (uint32_t)num_imps * REL32SZ;
    off = aot_dyn_align_u32(off, 16);

    uint32_t *sec_va = (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    uint8_t *sec_seen = (uint8_t *)calloc((size_t)num_secs, sizeof(uint8_t));
    for (int i = 0; i < num_secs; ++i) {
        if ((secs[i].flags & AOT_SEC_WRITE) || (secs[i].flags & AOT_SEC_BSS))
            continue;
        if (secs[i].size == 0) continue;
        uint32_t a = secs[i].align ? (uint32_t)secs[i].align : 16u;
        off = aot_dyn_align_u32(off, a);
        sec_va[i] = off;
        sec_seen[i] = 1;
        off += (uint32_t)secs[i].size;
    }
    uint32_t region1_end = off;
    off = aot_dyn_align_u32(off, PAGE);
    uint32_t region2_start = off;

    uint32_t got_off = off;
    off += (uint32_t)num_imps * 4u;

    for (int i = 0; i < num_secs; ++i) {
        if (!(secs[i].flags & AOT_SEC_WRITE)) continue;
        if (secs[i].flags & AOT_SEC_BSS) continue;
        if (secs[i].size == 0) continue;
        uint32_t a = secs[i].align ? (uint32_t)secs[i].align : 8u;
        off = aot_dyn_align_u32(off, a);
        sec_va[i] = off;
        sec_seen[i] = 1;
        off += (uint32_t)secs[i].size;
    }
    off = aot_dyn_align_u32(off, 4);
    uint32_t dynamic_off = off;
    const int ndyn = 13;
    off += (uint32_t)ndyn * DYN32;
    uint32_t region2_end = off;
    uint32_t total = off;

    uint32_t entry_vaddr = sec_va[entry_sec] + (uint32_t)entry_off;

    uint8_t *img = (uint8_t *)calloc(1, (size_t)total);
    if (!img) {
        set_err(err, err_cap, "elf32_dynexec: OOM");
        free(name_off);
        free(bucket);
        free(chain);
        free(dynstr.p);
        free(sec_va);
        free(sec_seen);
        return 0;
    }

    img[ehdr_off + 0] = 0x7f;
    img[ehdr_off + 1] = 'E';
    img[ehdr_off + 2] = 'L';
    img[ehdr_off + 3] = 'F';
    img[ehdr_off + 4] = 1;
    img[ehdr_off + 5] = 1;
    img[ehdr_off + 6] = 1;
    img[ehdr_off + 16] = 2;
    img[ehdr_off + 17] = 0; /* e_type = ET_EXEC */
    img[ehdr_off + 18] = 3;
    img[ehdr_off + 19] = 0; /* e_machine = EM_386 */
    wr32(img + ehdr_off + 20, 1);
    wr32(img + ehdr_off + 24, BASE + entry_vaddr);
    wr32(img + ehdr_off + 28, phdr_off);
    wr32(img + ehdr_off + 32, 0);
    wr32(img + ehdr_off + 36, 0);
    img[ehdr_off + 40] = (uint8_t)EHDR32;
    img[ehdr_off + 41] = 0;
    img[ehdr_off + 42] = (uint8_t)PHDR32;
    img[ehdr_off + 43] = 0;
    img[ehdr_off + 44] = (uint8_t)NPH;
    img[ehdr_off + 45] = 0;
    img[ehdr_off + 46] = 0;
    img[ehdr_off + 47] = 0;
    img[ehdr_off + 48] = 0;
    img[ehdr_off + 49] = 0;
    img[ehdr_off + 50] = 0;
    img[ehdr_off + 51] = 0;

    {
        uint8_t *ph;
        ph = img + phdr_off + 0 * PHDR32;
        wr32(ph + 0, 6);
        wr32(ph + 4, phdr_off);
        wr32(ph + 8, BASE + phdr_off);
        wr32(ph + 12, BASE + phdr_off);
        wr32(ph + 16, (uint32_t)NPH * PHDR32);
        wr32(ph + 20, (uint32_t)NPH * PHDR32);
        wr32(ph + 24, PF_R);
        wr32(ph + 28, 4);
        ph = img + phdr_off + 1 * PHDR32;
        wr32(ph + 0, 3);
        wr32(ph + 4, interp_off);
        wr32(ph + 8, BASE + interp_off);
        wr32(ph + 12, BASE + interp_off);
        wr32(ph + 16, interp_len);
        wr32(ph + 20, interp_len);
        wr32(ph + 24, PF_R);
        wr32(ph + 28, 1);
        ph = img + phdr_off + 2 * PHDR32;
        wr32(ph + 0, 1);
        wr32(ph + 4, 0);
        wr32(ph + 8, BASE + 0);
        wr32(ph + 12, BASE + 0);
        wr32(ph + 16, region1_end);
        wr32(ph + 20, region1_end);
        wr32(ph + 24, PF_R | PF_X);
        wr32(ph + 28, PAGE);
        ph = img + phdr_off + 3 * PHDR32;
        wr32(ph + 0, 1);
        wr32(ph + 4, region2_start);
        wr32(ph + 8, BASE + region2_start);
        wr32(ph + 12, BASE + region2_start);
        wr32(ph + 16, region2_end - region2_start);
        wr32(ph + 20, region2_end - region2_start);
        wr32(ph + 24, PF_R | PF_W);
        wr32(ph + 28, PAGE);
        ph = img + phdr_off + 4 * PHDR32;
        wr32(ph + 0, 2);
        wr32(ph + 4, dynamic_off);
        wr32(ph + 8, BASE + dynamic_off);
        wr32(ph + 12, BASE + dynamic_off);
        wr32(ph + 16, (uint32_t)ndyn * DYN32);
        wr32(ph + 20, (uint32_t)ndyn * DYN32);
        wr32(ph + 24, PF_R | PF_W);
        wr32(ph + 28, 4);
        ph = img + phdr_off + 5 * PHDR32;
        wr32(ph + 0, 0x6474e551u);
        wr32(ph + 4, 0);
        wr32(ph + 8, 0);
        wr32(ph + 12, 0);
        wr32(ph + 16, 0);
        wr32(ph + 20, 0);
        wr32(ph + 24, PF_R | PF_W);
        wr32(ph + 28, 0x10);
        if (tls_sec >= 0) {
            /* PT_TLS: plantilla .tdata (filesz) + .tbss (memsz extra).  El
             * cargador la copia por-hilo bajo el thread pointer (gs). */
            ph = img + phdr_off + 6 * PHDR32;
            wr32(ph + 0, 7); /* PT_TLS */
            wr32(ph + 4, sec_va[tls_sec]);
            wr32(ph + 8, BASE + sec_va[tls_sec]);
            wr32(ph + 12, BASE + sec_va[tls_sec]);
            wr32(ph + 16, (uint32_t)secs[tls_sec].size);
            wr32(ph + 20,
                 (uint32_t)(secs[tls_sec].size + secs[tls_sec].bss_size));
            wr32(ph + 24, PF_R);
            wr32(ph + 28,
                 secs[tls_sec].align ? (uint32_t)secs[tls_sec].align : 4u);
        }
    }

    memcpy(img + interp_off, interp, interp_len);

    for (int i = 0; i < num_imps; ++i) {
        uint8_t *s = img + dynsym_off + (uint32_t)(1 + i) * SYM32;
        wr32(s + 0, name_off[i]);
        wr32(s + 4, 0);
        wr32(s + 8, 0);
        s[12] = (uint8_t)AOT_ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
        s[13] = 0;
        s[14] = (uint8_t)SHN_UNDEF;
        s[15] = 0;
    }
    memcpy(img + dynstr_off, dynstr.p, dynstr.len);
    {
        uint8_t *h = img + hash_off;
        wr32(h + 0, nbucket);
        wr32(h + 4, nchain);
        for (uint32_t i = 0; i < nbucket; ++i)
            wr32(h + 8 + i * 4, bucket[i]);
        for (uint32_t i = 0; i < nchain; ++i)
            wr32(h + 8 + (nbucket + i) * 4, chain[i]);
    }
    for (int i = 0; i < num_imps; ++i) {
        uint8_t *re = img + rel_off + (uint32_t)i * REL32SZ;
        wr32(re + 0,
             BASE + got_off + (uint32_t)i * 4u); /* r_offset = vaddr GOT */
        wr32(re + 4, AOT_ELF32_R_INFO((uint32_t)(1 + i), R_386_GLOB_DAT));
    }
    for (int i = 0; i < num_secs; ++i)
        if (sec_seen[i]) memcpy(img + sec_va[i], secs[i].data, secs[i].size);

    {
        uint8_t *d = img + dynamic_off;
        int k = 0;
        wr32(d + k * DYN32 + 0, DT_NEEDED);
        wr32(d + k * DYN32 + 4, libc_off);
        ++k;
        wr32(d + k * DYN32 + 0, DT_HASH);
        wr32(d + k * DYN32 + 4, BASE + hash_off);
        ++k;
        wr32(d + k * DYN32 + 0, DT_STRTAB);
        wr32(d + k * DYN32 + 4, BASE + dynstr_off);
        ++k;
        wr32(d + k * DYN32 + 0, DT_SYMTAB);
        wr32(d + k * DYN32 + 4, BASE + dynsym_off);
        ++k;
        wr32(d + k * DYN32 + 0, DT_STRSZ);
        wr32(d + k * DYN32 + 4, (uint32_t)dynstr.len);
        ++k;
        wr32(d + k * DYN32 + 0, DT_SYMENT);
        wr32(d + k * DYN32 + 4, SYM32);
        ++k;
        wr32(d + k * DYN32 + 0, DT_REL);
        wr32(d + k * DYN32 + 4, BASE + rel_off);
        ++k;
        wr32(d + k * DYN32 + 0, DT_RELSZ);
        wr32(d + k * DYN32 + 4, (uint32_t)num_imps * REL32SZ);
        ++k;
        wr32(d + k * DYN32 + 0, DT_RELENT);
        wr32(d + k * DYN32 + 4, REL32SZ);
        ++k;
        wr32(d + k * DYN32 + 0, DT_FLAGS);
        wr32(d + k * DYN32 + 4, (uint32_t)DF_BIND_NOW);
        ++k;
        wr32(d + k * DYN32 + 0, (uint32_t)DT_FLAGS_1);
        wr32(d + k * DYN32 + 4, (uint32_t)DF_1_NOW);
        ++k;
        wr32(d + k * DYN32 + 0, DT_NULL);
        wr32(d + k * DYN32 + 4, 0);
        ++k;
        wr32(d + k * DYN32 + 0, DT_NULL);
        wr32(d + k * DYN32 + 4, 0);
        ++k;
    }

    int ok = 1;
    for (int r = 0; r < num_relocs && ok; ++r) {
        const AotReloc *rl = &relocs[r];
        if (rl->kind == AOT_RELOC_ABS64 || rl->kind == AOT_RELOC_IMM64) {
            set_err(err, err_cap,
                    "elf32_dynexec: ABS64/IMM64 no aplica en 32-bit");
            ok = 0;
            break;
        }
        if (rl->site_section < 0 || rl->site_section >= num_secs ||
            !sec_seen[rl->site_section] ||
            (!rl->target_is_size &&
             (rl->target_section < 0 || rl->target_section >= num_secs ||
              !sec_seen[rl->target_section]))) {
            set_err(err, err_cap, "elf32_dynexec: reloc con seccion invalida");
            ok = 0;
            break;
        }
        uint64_t tv;
        if (rl->target_is_imagebase)
            tv = BASE; // la direccion de CARGA; ver el emisor de 64 bits
        else if (rl->target_is_size)
            tv = aot_sec_size(&secs[rl->target_section]);
        else {
            tv = sec_va[rl->target_section];
            tv += rl->target_is_end ? aot_sec_size(&secs[rl->target_section])
                                    : rl->target_off;
        }
        tv = (uint64_t)((int64_t)tv + rl->addend);
        uint64_t site_va = sec_va[rl->site_section] + rl->site_off;
        if (!apply_reloc(img + site_va, site_va, tv, rl->kind,
                         AOT_NO_IMAGE_BASE)) {
            set_err(err, err_cap, "elf32_dynexec: reloc kind invalido");
            ok = 0;
            break;
        }
    }

    for (int i = 0; i < num_imps && ok; ++i) {
        int cs = imps[i].call_section;
        if (cs < 0 || cs >= num_secs || !sec_seen[cs]) {
            set_err(err, err_cap,
                    "elf32_dynexec: call_section del thunk invalido");
            ok = 0;
            break;
        }
        uint32_t thunk_fo =
            sec_va[cs] + (uint32_t)imps[i].call_off;         /* file off */
        uint32_t got_va = BASE + got_off + (uint32_t)i * 4u; /* vaddr GOT */
        wr32(img + thunk_fo + 2, got_va); /* disp32 absoluto (base fija) */
    }

    if (ok) {
        FILE *f = fopen(path, "wb");
        if (!f) {
            set_err(err, err_cap, "elf32_dynexec: fopen fallo");
            ok = 0;
        } else {
            size_t w = fwrite(img, 1, (size_t)total, f);
            fclose(f);
            if (w != total) {
                set_err(err, err_cap, "elf32_dynexec: escritura incompleta");
                ok = 0;
            }
        }
    }

    free(img);
    free(name_off);
    free(bucket);
    free(chain);
    free(dynstr.p);
    free(sec_va);
    free(sec_seen);
    return ok;
}

/* =========================================================================
 *  ELF32 RELOCATABLE (.o i386) -- para enlazar con gcc -m32 / ld
 *  Difs vs ELF64: ELFCLASS32, EM_386, structs Elf32 (Ehdr 52 / Shdr 40 /
 *  Sym 16 / Rel 8), y usa SHT_REL (sin addend en el registro: el addend vive
 *  EN el campo de la seccion -- como COFF).  Relocs R_386_PC32 (2) / R_386_32
 *  (1).  Se construye a mano con OBuf (sin depender de structs Elf32).
 * ========================================================================= */
#define R_386_32 1
#define R_386_PC32 2

static void e32_push16(OBuf *o, uint16_t v) {
    uint8_t b[2];
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    ob_put(o, b, 2);
}
static void e32_push32(OBuf *o, uint32_t v) {
    uint8_t b[4];
    wr32(b, v);
    ob_put(o, b, 4);
}

int aot_emit_elf32_obj(const char *path, const AotSection *secs, int num_secs,
                       const AotReloc *relocs, int num_relocs,
                       const AotSym *syms, int num_syms, char *err,
                       size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_elf32_obj: sin secciones");
        return 0;
    }
    for (int r = 0; r < num_relocs; ++r) {
        if (relocs[r].target_is_imagebase) {
            /* La base no existe todavia en un objeto suelto: la fija quien
             * enlaza.  Se dice, en vez de emitir un cero. */
            set_err(err, err_cap,
                    "aot_emit_elf32_obj: __ImageBase no se puede resolver en "
                    "un .o -- la base la fija el enlace final");
            return 0;
        }
        if (relocs[r].target_is_size || relocs[r].target_is_end) {
            set_err(err, err_cap, "aot_emit_elf32_obj: SIZE/END no soportado");
            return 0;
        }
        if (relocs[r].kind != AOT_RELOC_REL32 &&
            relocs[r].kind != AOT_RELOC_IMM32) {
            set_err(err, err_cap,
                    "aot_emit_elf32_obj: reloc kind no soportado (32-bit usa "
                    "REL32/ABS32, no ABS64)");
            return 0;
        }
        if (relocs[r].site_section < 0 || relocs[r].site_section >= num_secs) {
            set_err(err, err_cap, "aot_emit_elf32_obj: site_section invalido");
            return 0;
        }
    }
    /* Indices de section headers: 0=NULL, 1..N=user, sym, str, rel[i], shstr.
     */
    int *sec_nrel = (int *)calloc((size_t)num_secs, sizeof(int));
    for (int r = 0; r < num_relocs; ++r)
        sec_nrel[relocs[r].site_section]++;
    const int sym_sh = 1 + num_secs;
    const int str_sh = sym_sh + 1;
    int *rel_sh = (int *)calloc((size_t)num_secs, sizeof(int));
    int next_sh = str_sh + 1;
    for (int i = 0; i < num_secs; ++i)
        if (sec_nrel[i] > 0) rel_sh[i] = next_sh++;
    const int shstr_sh = next_sh++;
    const int shnum = next_sh;

    /* Externos dedup. */
    const char **extn =
        (const char **)calloc((size_t)num_relocs + 1, sizeof(char *));
    int n_extn = 0;
    for (int r = 0; r < num_relocs; ++r) {
        const char *e = relocs[r].extern_name;
        if (!e) continue;
        int found = 0;
        for (int k = 0; k < n_extn; ++k)
            if (strcmp(extn[k], e) == 0) {
                found = 1;
                break;
            }
        if (!found) extn[n_extn++] = e;
    }
    const int extn_base = 1 + num_secs + num_syms;

    /* .strtab + symtab (16 bytes/sym, construido en OBuf). */
    OBuf strtab;
    memset(&strtab, 0, sizeof(strtab));
    {
        uint8_t z = 0;
        ob_put(&strtab, &z, 1);
    }
    const int nsym = 1 + num_secs + num_syms + n_extn;
    OBuf symtab;
    memset(&symtab, 0, sizeof(symtab));
    ob_put(&symtab, NULL, 16); /* sym[0] = null */
    for (int i = 0; i < num_secs; ++i) {
        e32_push32(&symtab, 0); /* st_name */
        e32_push32(&symtab, 0); /* st_value */
        e32_push32(&symtab, 0); /* st_size */
        uint8_t info = (uint8_t)((STB_LOCAL << 4) | STT_SECTION);
        ob_put(&symtab, &info, 1); /* st_info */
        uint8_t other = 0;
        ob_put(&symtab, &other, 1);             /* st_other */
        e32_push16(&symtab, (uint16_t)(1 + i)); /* st_shndx */
    }
    for (int g = 0; g < num_syms; ++g) {
        e32_push32(&symtab, (uint32_t)strtab.len);
        ob_put(&strtab, syms[g].name, strlen(syms[g].name) + 1);
        e32_push32(&symtab, (uint32_t)syms[g].offset); /* st_value */
        e32_push32(&symtab, 0);                        /* st_size */
        uint8_t info = (uint8_t)((STB_GLOBAL << 4) |
                                 (syms[g].is_func ? STT_FUNC : STT_OBJECT));
        ob_put(&symtab, &info, 1);
        uint8_t other = 0;
        ob_put(&symtab, &other, 1);
        e32_push16(&symtab, (uint16_t)(1 + syms[g].section));
    }
    for (int e = 0; e < n_extn; ++e) {
        e32_push32(&symtab, (uint32_t)strtab.len);
        ob_put(&strtab, extn[e], strlen(extn[e]) + 1);
        e32_push32(&symtab, 0); /* st_value */
        e32_push32(&symtab, 0); /* st_size */
        uint8_t info = (uint8_t)((STB_GLOBAL << 4) | STT_NOTYPE);
        ob_put(&symtab, &info, 1);
        uint8_t other = 0;
        ob_put(&symtab, &other, 1);
        e32_push16(&symtab, (uint16_t)SHN_UNDEF);
    }
    const int first_global = 1 + num_secs;

    /* .shstrtab. */
    OBuf shstr;
    memset(&shstr, 0, sizeof(shstr));
    {
        uint8_t z = 0;
        ob_put(&shstr, &z, 1);
    }
    uint32_t *sec_nameoff = (uint32_t *)calloc((size_t)num_secs, 4);
    uint32_t *rel_nameoff = (uint32_t *)calloc((size_t)num_secs, 4);
    for (int i = 0; i < num_secs; ++i) {
        sec_nameoff[i] = (uint32_t)shstr.len;
        ob_put(&shstr, secs[i].name, strlen(secs[i].name) + 1);
    }
    uint32_t no_symtab = (uint32_t)shstr.len;
    ob_put(&shstr, ".symtab", 8);
    uint32_t no_strtab = (uint32_t)shstr.len;
    ob_put(&shstr, ".strtab", 8);
    for (int i = 0; i < num_secs; ++i) {
        if (!rel_sh[i]) continue;
        rel_nameoff[i] = (uint32_t)shstr.len;
        ob_put(&shstr, ".rel", 4);
        ob_put(&shstr, secs[i].name, strlen(secs[i].name) + 1);
    }
    uint32_t no_shstr = (uint32_t)shstr.len;
    ob_put(&shstr, ".shstrtab", 10);

    /* Construir el fichero. */
    OBuf out;
    memset(&out, 0, sizeof(out));
    /* Elf32_Ehdr (52). */
    uint8_t eh[52];
    memset(eh, 0, sizeof(eh));
    eh[0] = 0x7f;
    eh[1] = 'E';
    eh[2] = 'L';
    eh[3] = 'F';
    eh[4] = 1; /* ELFCLASS32 */
    eh[5] = 1; /* LSB */
    eh[6] = 1; /* version */
    wr16le(eh + 16, ET_REL);
    wr16le(eh + 18, 3 /* EM_386 */);
    wr32(eh + 20, 1);    /* e_version */
    wr16le(eh + 40, 52); /* e_ehsize */
    wr16le(eh + 46, 40); /* e_shentsize */
    wr16le(eh + 48, (uint16_t)shnum);
    wr16le(eh + 50, (uint16_t)shstr_sh);
    ob_put(&out, eh, 52);

    uint32_t *sec_off = (uint32_t *)calloc((size_t)num_secs, 4);
    for (int i = 0; i < num_secs; ++i) {
        ob_align(&out, 16);
        sec_off[i] = (uint32_t)out.len;
        ob_put(&out, secs[i].data, secs[i].size);
    }
    /* Pre-escribir el addend EN el campo de cada sitio (REL i386 sin addend en
     * el registro).  REL32: A = target_off + addend - 4.  ABS32: A =
     * target_off + addend.  Extern (REL32): A = addend - 4. */
    for (int r = 0; r < num_relocs; ++r) {
        const AotReloc *rl = &relocs[r];
        int64_t A;
        if (rl->extern_name)
            A = rl->addend - 4;
        else if (rl->kind == AOT_RELOC_REL32)
            A = (int64_t)rl->target_off + rl->addend - 4;
        else /* IMM32 -> ABS32 */
            A = (int64_t)rl->target_off + rl->addend;
        wr32(out.p + sec_off[rl->site_section] + rl->site_off, (uint32_t)A);
    }
    ob_align(&out, 4);
    uint32_t symtab_off = (uint32_t)out.len;
    ob_put(&out, symtab.p, symtab.len);
    uint32_t strtab_off = (uint32_t)out.len;
    ob_put(&out, strtab.p, strtab.len);
    uint32_t *rel_off = (uint32_t *)calloc((size_t)num_secs, 4);
    int *rel_cnt = (int *)calloc((size_t)num_secs, sizeof(int));
    for (int i = 0; i < num_secs; ++i) {
        if (!rel_sh[i]) continue;
        ob_align(&out, 4);
        rel_off[i] = (uint32_t)out.len;
        /* Emitir los Elf32_Rel de esta seccion en orden. */
        for (int r = 0; r < num_relocs; ++r) {
            const AotReloc *rl = &relocs[r];
            if (rl->site_section != i) continue;
            uint32_t sym_idx;
            uint32_t type;
            if (rl->extern_name) {
                sym_idx = 0;
                for (int k = 0; k < n_extn; ++k)
                    if (strcmp(extn[k], rl->extern_name) == 0) {
                        sym_idx = (uint32_t)(extn_base + k);
                        break;
                    }
                type = R_386_PC32;
            } else {
                sym_idx = (uint32_t)(1 + rl->target_section); /* section sym */
                type = (rl->kind == AOT_RELOC_REL32) ? R_386_PC32 : R_386_32;
            }
            e32_push32(&out, (uint32_t)rl->site_off);         /* r_offset */
            e32_push32(&out, (sym_idx << 8) | (type & 0xff)); /* r_info */
            rel_cnt[i]++;
        }
    }
    uint32_t shstr_off = (uint32_t)out.len;
    ob_put(&out, shstr.p, shstr.len);
    ob_align(&out, 4);
    uint32_t shoff = (uint32_t)out.len;

    /* Section headers (40 bytes c/u). */
    /* helper para empujar un Elf32_Shdr. */
#define E32_SHDR(name, type, flags, off, size, link, info, align, entsz)       \
    do {                                                                       \
        e32_push32(&out, (name));                                              \
        e32_push32(&out, (type));                                              \
        e32_push32(&out, (flags));                                             \
        e32_push32(&out, 0); /* sh_addr */                                     \
        e32_push32(&out, (off));                                               \
        e32_push32(&out, (size));                                              \
        e32_push32(&out, (link));                                              \
        e32_push32(&out, (info));                                              \
        e32_push32(&out, (align));                                             \
        e32_push32(&out, (entsz));                                             \
    } while (0)
    /* indice 0: NULL */
    E32_SHDR(0, 0, 0, 0, 0, 0, 0, 0, 0);
    for (int i = 0; i < num_secs; ++i) {
        uint32_t fl = SHF_ALLOC;
        if (secs[i].flags & AOT_SEC_EXEC) fl |= SHF_EXECINSTR;
        if (secs[i].flags & AOT_SEC_WRITE) fl |= SHF_WRITE;
        uint32_t al = (secs[i].flags & AOT_SEC_EXEC) ? 16 : 8;
        E32_SHDR(sec_nameoff[i], SHT_PROGBITS, fl, sec_off[i],
                 (uint32_t)secs[i].size, 0, 0, al, 0);
    }
    E32_SHDR(no_symtab, SHT_SYMTAB, 0, symtab_off, (uint32_t)symtab.len,
             (uint32_t)str_sh, (uint32_t)first_global, 4, 16);
    E32_SHDR(no_strtab, SHT_STRTAB, 0, strtab_off, (uint32_t)strtab.len, 0, 0,
             1, 0);
    for (int i = 0; i < num_secs; ++i) {
        if (!rel_sh[i]) continue;
        E32_SHDR(rel_nameoff[i], 9 /* SHT_REL */, 0, rel_off[i],
                 (uint32_t)(rel_cnt[i] * 8), (uint32_t)sym_sh,
                 (uint32_t)(1 + i), 4, 8);
    }
    E32_SHDR(no_shstr, SHT_STRTAB, 0, shstr_off, (uint32_t)shstr.len, 0, 0, 1,
             0);
#undef E32_SHDR

    wr32(out.p + 32, shoff); /* e_shoff */

    int ok = 1;
    FILE *f = fopen(path, "wb");
    if (!f) {
        set_err(err, err_cap, "aot_emit_elf32_obj: fopen fallo");
        ok = 0;
    } else {
        size_t w = fwrite(out.p, 1, out.len, f);
        fclose(f);
        if (w != out.len) {
            set_err(err, err_cap, "aot_emit_elf32_obj: escritura incompleta");
            ok = 0;
        }
    }
    free(sec_nrel);
    free(rel_sh);
    free(extn);
    free(strtab.p);
    free(symtab.p);
    free(shstr.p);
    free(sec_nameoff);
    free(rel_nameoff);
    free(sec_off);
    free(rel_off);
    free(rel_cnt);
    free(out.p);
    return ok;
}
