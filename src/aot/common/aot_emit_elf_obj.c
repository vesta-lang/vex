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
 * @file aot/common/aot_emit_elf_obj.c
 * @brief Emisor de objetos ELF64 reubicables, COMPARTIDO por arquitecturas.
 *
 * Vivia dentro del emisor de x86-64 con la marca de maquina clavada, y por eso
 * un objeto de ARM salia rotulado como de otra arquitectura y sus llamadas no
 * se podian reubicar: `bl` a otra funcion se rechazaba con "reloc kind no
 * soportado" y NINGUN programa de ARM con llamadas entre funciones se podia
 * escribir a un `.o`.
 *
 * El layout de un ELF64 reubicable no depende de la arquitectura -- ya lo
 * decia el comentario de aquel fichero --: cabecera, secciones, simbolos,
 * cadenas y tablas de reubicacion son los mismos.  Lo que cambia son SEIS
 * numeros, y de eso se encarga la ficha @ref AotElfObjArch que cada
 * arquitectura aporta desde su propio directorio.
 */

#include "aot/aot_emit_shim.h"

#include "aot_elf_obj_arch.h"
#include "aot_emit_internal.h"

int aot_emit_elf_obj_arch(const char *path, const AotSection *secs,
                          int num_secs, const AotReloc *relocs, int num_relocs,
                          const AotSym *syms, int num_syms,
                          const AotElfObjArch *A, char *err, size_t err_cap) {
    if (!A) {
        set_err(err, err_cap, "aot_emit_elf_obj: sin ficha de arquitectura");
        return 0;
    }
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_elf_obj: sin secciones");
        return 0;
    }

    /* v1: solo refs ADDR (datos/llamadas).  SIZE/END (simbolos de seccion)
     * no se soportan en .o todavia. */
    for (int r = 0; r < num_relocs; ++r) {
        if (relocs[r].target_is_imagebase) {
            /* La base de la imagen NO existe todavia en un objeto suelto: la
             * fija quien enlaza.  Se dice aqui en vez de emitir un cero, que es
             * la clase de valor por defecto que convierte un error en otro
             * resultado. */
            set_err(err, err_cap,
                    "aot_emit_elf_obj: __ImageBase no se puede resolver en un "
                    ".o -- la base la fija el enlace final");
            return 0;
        }
        if (relocs[r].target_is_size || relocs[r].target_is_end) {
            set_err(err, err_cap,
                    "aot_emit_elf_obj: SIZE/END no soportado en .o (v1)");
            return 0;
        }
        /* Se pregunta a la ficha en vez de enumerar tipos aqui: una
         * arquitectura que no traiga un tipo lo deja a cero, y entonces es que
         * NO lo admite.  Asi anadir una no obliga a tocar esta lista. */
        const int k = relocs[r].kind;
        const int accepted =
            (k == AOT_RELOC_REL32 && A->r_pcrel32 != 0) ||
            (k == AOT_RELOC_ABS64 && A->r_abs64 != 0) ||
            (k == AOT_RELOC_TPOFF32 && A->r_tpoff32 != 0) ||
            (k == AOT_RELOC_ARM64_CALL26 && A->r_call_local != 0);
        if (!accepted) {
            set_err(err, err_cap,
                    "aot_emit_elf_obj: reloc kind no soportado en .o");
            return 0;
        }
    }

    /* Indices de section headers:
     *   0            = NULL
     *   1..num_secs  = secciones de usuario (PROGBITS)
     *   sym_sh       = .symtab
     *   str_sh       = .strtab
     *   rela_sh[i]   = .rela de la seccion de usuario i (si tiene relocs)
     *   shstr_sh     = .shstrtab
     */
    int *sec_nrel = (int *)calloc((size_t)num_secs, sizeof(int));
    if (!sec_nrel) {
        set_err(err, err_cap, "oom");
        return 0;
    }
    for (int r = 0; r < num_relocs; ++r) {
        int s = relocs[r].site_section;
        if (s < 0 || s >= num_secs) {
            free(sec_nrel);
            set_err(err, err_cap, "aot_emit_elf_obj: site_section invalido");
            return 0;
        }
        sec_nrel[s]++;
    }
    const int sym_sh = 1 + num_secs;
    const int str_sh = sym_sh + 1;
    int *rela_sh = (int *)calloc((size_t)num_secs, sizeof(int));
    if (!rela_sh) {
        free(sec_nrel);
        set_err(err, err_cap, "oom");
        return 0;
    }
    int next_sh = str_sh + 1;
    for (int i = 0; i < num_secs; ++i)
        if (sec_nrel[i] > 0) rela_sh[i] = next_sh++;
    const int shstr_sh = next_sh++;
    const int shnum = next_sh;

    /* Simbolos EXTERNOS indefinidos (convencion libc: malloc/free/abort, pero
     * los resuelve el LINKER -> el .o NO depende de libc).  Dedup lineal. */
    const char **extn =
        (const char **)calloc((size_t)num_relocs + 1, sizeof(char *));
    int n_extn = 0;
    if (!extn) {
        free(sec_nrel);
        free(rela_sh);
        set_err(err, err_cap, "oom");
        return 0;
    }
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
    const int extn_base = 1 + num_secs + num_syms; /* indice del 1er externo */

    /* .strtab (nombres de simbolos) + symtab.  Simbolos:
     *   [0]            null
     *   [1..num_secs]  STT_SECTION (LOCAL) por seccion de usuario
     *   [globales...]  STB_GLOBAL (syms[])  -- DESPUES de los locales
     *   [externos...]  STB_GLOBAL indefinidos (SHN_UNDEF) -- al final. */
    OBuf strtab;
    memset(&strtab, 0, sizeof(strtab));
    {
        uint8_t z = 0;
        ob_put(&strtab, &z, 1);
    } /* [0] = "" */
    const int nsym = 1 + num_secs + num_syms + n_extn;
    Elf64_Sym *symtab = (Elf64_Sym *)calloc((size_t)nsym, sizeof(Elf64_Sym));
    if (!symtab) {
        free(sec_nrel);
        free(rela_sh);
        free(strtab.p);
        free(extn);
        set_err(err, err_cap, "oom");
        return 0;
    }
    for (int i = 0; i < num_secs; ++i) {
        symtab[1 + i].st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
        symtab[1 + i].st_shndx = (Elf64_Half)(1 + i);
    }
    for (int g = 0; g < num_syms; ++g) {
        Elf64_Sym *s = &symtab[1 + num_secs + g];
        s->st_name = (Elf64_Word)strtab.len;
        ob_put(&strtab, syms[g].name, strlen(syms[g].name) + 1);
        s->st_info =
            ELF64_ST_INFO(STB_GLOBAL, syms[g].is_func ? STT_FUNC : STT_OBJECT);
        s->st_shndx = (Elf64_Half)(1 + syms[g].section);
        s->st_value = syms[g].offset;
    }
    /* Externos: indefinidos (SHN_UNDEF), STB_GLOBAL -> el linker los resuelve.
     */
    for (int e = 0; e < n_extn; ++e) {
        Elf64_Sym *s = &symtab[extn_base + e];
        s->st_name = (Elf64_Word)strtab.len;
        ob_put(&strtab, extn[e], strlen(extn[e]) + 1);
        s->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
        s->st_shndx = SHN_UNDEF;
        s->st_value = 0;
    }
    const int first_global = 1 + num_secs; /* symtab sh_info */

    /* .rela arrays por seccion. */
    Elf64_Rela **rela =
        (Elf64_Rela **)calloc((size_t)num_secs, sizeof(Elf64_Rela *));
    int *rela_n = (int *)calloc((size_t)num_secs, sizeof(int));
    if (!rela || !rela_n) {
        free(sec_nrel);
        free(rela_sh);
        free(strtab.p);
        free(symtab);
        free(extn);
        free(rela);
        free(rela_n);
        set_err(err, err_cap, "oom");
        return 0;
    }
    for (int i = 0; i < num_secs; ++i)
        if (sec_nrel[i] > 0)
            rela[i] =
                (Elf64_Rela *)calloc((size_t)sec_nrel[i], sizeof(Elf64_Rela));
    for (int r = 0; r < num_relocs; ++r) {
        const AotReloc *rl = &relocs[r];
        Elf64_Rela *re = &rela[rl->site_section][rela_n[rl->site_section]++];
        re->r_offset = rl->site_off;
        if (rl->extern_name) {
            /* Llamada a simbolo externo: PLT32 contra el simbolo indefinido. */
            uint32_t si = 0;
            for (int k = 0; k < n_extn; ++k)
                if (strcmp(extn[k], rl->extern_name) == 0) {
                    si = (uint32_t)(extn_base + k);
                    break;
                }
            re->r_info = ELF64_R_INFO(si, A->r_call_extern);
            re->r_addend = (Elf64_Sxword)A->pcrel_bias + rl->addend;
            continue;
        }
        const uint32_t sym_idx =
            (uint32_t)(1 + rl->target_section); /* section symbol */
        if (rl->kind == AOT_RELOC_ARM64_CALL26) {
            /* Llamada a una funcion del MISMO objeto: mismo tipo que la
             * externa, pero contra el simbolo de la seccion que la contiene. */
            re->r_info = ELF64_R_INFO(sym_idx, A->r_call_local);
            re->r_addend = (Elf64_Sxword)rl->target_off + rl->addend;
        } else if (rl->kind == AOT_RELOC_REL32) {
            re->r_info = ELF64_R_INFO(sym_idx, A->r_pcrel32);
            re->r_addend =
                (Elf64_Sxword)rl->target_off + A->pcrel_bias + rl->addend;
        } else if (rl->kind == AOT_RELOC_TPOFF32) {
            /* TLS local-exec: R_X86_64_TPOFF32 contra el simbolo de seccion de
             * .tdata (SHF_TLS) + addend = offset.  El --link calcula el TPOFF
             * TP-relativo a partir de tls_off[.tdata] + addend. */
            re->r_info = ELF64_R_INFO(sym_idx, A->r_tpoff32);
            re->r_addend = (Elf64_Sxword)rl->target_off + rl->addend;
        } else { /* ABS64 */
            re->r_info = ELF64_R_INFO(sym_idx, A->r_abs64);
            re->r_addend = (Elf64_Sxword)rl->target_off + rl->addend;
        }
    }

    /* .shstrtab + nombres de seccion. */
    OBuf shstr;
    memset(&shstr, 0, sizeof(shstr));
    {
        uint8_t z = 0;
        ob_put(&shstr, &z, 1);
    }
    uint32_t *sec_nameoff =
        (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    uint32_t *rela_nameoff =
        (uint32_t *)calloc((size_t)num_secs, sizeof(uint32_t));
    for (int i = 0; i < num_secs; ++i) {
        sec_nameoff[i] = (uint32_t)shstr.len;
        ob_put(&shstr, secs[i].name, strlen(secs[i].name) + 1);
    }
    uint32_t no_symtab = (uint32_t)shstr.len;
    ob_put(&shstr, ".symtab", 8);
    uint32_t no_strtab = (uint32_t)shstr.len;
    ob_put(&shstr, ".strtab", 8);
    for (int i = 0; i < num_secs; ++i) {
        if (!rela_sh[i]) continue;
        rela_nameoff[i] = (uint32_t)shstr.len;
        ob_put(&shstr, ".rela", 5);
        ob_put(&shstr, secs[i].name, strlen(secs[i].name) + 1);
    }
    uint32_t no_shstr = (uint32_t)shstr.len;
    ob_put(&shstr, ".shstrtab", 10);

    /* Construir el fichero:
     * [ehdr][secs][symtab][strtab][rela...][shstrtab][shdrs]. */
    OBuf out;
    memset(&out, 0, sizeof(out));
    Elf64_Ehdr eh;
    memset(&eh, 0, sizeof(eh));
    eh.e_ident[0] = 0x7f;
    eh.e_ident[1] = 'E';
    eh.e_ident[2] = 'L';
    eh.e_ident[3] = 'F';
    eh.e_ident[4] = 2;
    eh.e_ident[5] = 1;
    eh.e_ident[6] = 1; /* ELF64, LSB, version 1 */
    eh.e_type = ET_REL;
    eh.e_machine = A->e_machine;
    eh.e_version = 1;
    eh.e_ehsize = (Elf64_Half)sizeof(Elf64_Ehdr);
    eh.e_shentsize = (Elf64_Half)sizeof(Elf64_Shdr);
    eh.e_shnum = (Elf64_Half)shnum;
    eh.e_shstrndx = (Elf64_Half)shstr_sh;
    ob_put(&out, &eh, sizeof(eh));

    uint64_t *sec_off = (uint64_t *)calloc((size_t)num_secs, sizeof(uint64_t));
    for (int i = 0; i < num_secs; ++i) {
        ob_align(&out, 16);
        sec_off[i] = out.len;
        ob_put(&out, secs[i].data, secs[i].size);
    }
    ob_align(&out, 8);
    uint64_t symtab_off = out.len;
    ob_put(&out, symtab, (size_t)nsym * sizeof(Elf64_Sym));
    uint64_t strtab_off = out.len;
    ob_put(&out, strtab.p, strtab.len);
    uint64_t *rela_off = (uint64_t *)calloc((size_t)num_secs, sizeof(uint64_t));
    for (int i = 0; i < num_secs; ++i) {
        if (!rela_sh[i]) continue;
        ob_align(&out, 8);
        rela_off[i] = out.len;
        ob_put(&out, rela[i], (size_t)rela_n[i] * sizeof(Elf64_Rela));
    }
    uint64_t shstr_off = out.len;
    ob_put(&out, shstr.p, shstr.len);

    ob_align(&out, 8);
    uint64_t shoff = out.len;
    Elf64_Shdr *shdr = (Elf64_Shdr *)calloc((size_t)shnum, sizeof(Elf64_Shdr));
    for (int i = 0; i < num_secs; ++i) {
        Elf64_Shdr *s = &shdr[1 + i];
        s->sh_name = sec_nameoff[i];
        s->sh_type = SHT_PROGBITS;
        s->sh_flags = SHF_ALLOC;
        if (secs[i].flags & AOT_SEC_EXEC) s->sh_flags |= SHF_EXECINSTR;
        if (secs[i].flags & AOT_SEC_WRITE) s->sh_flags |= SHF_WRITE;
        if (secs[i].flags & AOT_SEC_TLS) s->sh_flags |= SHF_TLS; /* .tdata */
        s->sh_offset = sec_off[i];
        s->sh_size = secs[i].size;
        s->sh_addralign = (secs[i].flags & AOT_SEC_EXEC) ? 16 : 8;
    }
    {
        Elf64_Shdr *s = &shdr[sym_sh];
        s->sh_name = no_symtab;
        s->sh_type = SHT_SYMTAB;
        s->sh_offset = symtab_off;
        s->sh_size = (uint64_t)nsym * sizeof(Elf64_Sym);
        s->sh_link = (Elf64_Word)str_sh;
        s->sh_info = (Elf64_Word)first_global;
        s->sh_addralign = 8;
        s->sh_entsize = sizeof(Elf64_Sym);
    }
    {
        Elf64_Shdr *s = &shdr[str_sh];
        s->sh_name = no_strtab;
        s->sh_type = SHT_STRTAB;
        s->sh_offset = strtab_off;
        s->sh_size = strtab.len;
        s->sh_addralign = 1;
    }
    for (int i = 0; i < num_secs; ++i) {
        if (!rela_sh[i]) continue;
        Elf64_Shdr *s = &shdr[rela_sh[i]];
        s->sh_name = rela_nameoff[i];
        s->sh_type = SHT_RELA;
        s->sh_offset = rela_off[i];
        s->sh_size = (uint64_t)rela_n[i] * sizeof(Elf64_Rela);
        s->sh_link = (Elf64_Word)sym_sh;  /* simbolos */
        s->sh_info = (Elf64_Word)(1 + i); /* seccion a la que aplica */
        s->sh_addralign = 8;
        s->sh_entsize = sizeof(Elf64_Rela);
    }
    {
        Elf64_Shdr *s = &shdr[shstr_sh];
        s->sh_name = no_shstr;
        s->sh_type = SHT_STRTAB;
        s->sh_offset = shstr_off;
        s->sh_size = shstr.len;
        s->sh_addralign = 1;
    }
    ob_put(&out, shdr, (size_t)shnum * sizeof(Elf64_Shdr));

    ((Elf64_Ehdr *)out.p)->e_shoff = shoff;

    int ok = 1;
    FILE *f = fopen(path, "wb");
    if (!f) {
        set_err(err, err_cap, "aot_emit_elf_obj: fopen fallo");
        ok = 0;
    } else {
        size_t w = fwrite(out.p, 1, out.len, f);
        fclose(f);
        if (w != out.len) {
            set_err(err, err_cap, "aot_emit_elf_obj: escritura incompleta");
            ok = 0;
        }
    }

    free(sec_nrel);
    free(rela_sh);
    free(strtab.p);
    free(symtab);
    free(extn);
    for (int i = 0; i < num_secs; ++i)
        free(rela[i]);
    free(rela);
    free(rela_n);
    free(shstr.p);
    free(sec_nameoff);
    free(rela_nameoff);
    free(sec_off);
    free(rela_off);
    free(shdr);
    free(out.p);
    return ok;
}
