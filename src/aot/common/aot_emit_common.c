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
 * @file aot/common/aot_emit_common.c
 * @brief Emision AOT: piezas ARCH-NEUTRALES compartidas por todos los emisores.
 *
 * Parte del desacople multi-arch (aot/common + aot/x86_64 + aot/x86_32 +
 * aot/x86_16 + aot/arm64).  Aqui viven los simbolos que NO dependen de la ISA
 * de destino:
 *   - el estado global de simbolos de depuracion (fijado por el driver),
 *   - el emisor de BINARIO PLANO (.bin): concatena secciones + resuelve relocs
 *     contra una base fija (sin cabecera de formato -> arch-neutral),
 *   - los lectores de exports de DLL/PE y de .so/ELF (delegan en LibPEparse /
 *     LibELFparse; los usa el linker para resolver imports leyendo lo que la
 *     libreria REALMENTE exporta).
 */

#include "aot_emit_internal.h"

/* ------------------------------------------------------------------------
 * Simbolos de DEPURACION (nivel 1): estado global fijado por el driver antes
 * de emitir un EXEC (ver aot_set_debug_symbols en el header).  n=0 -> no hay
 * simbolos (cero coste).  El emit es single-thread por llamada.  Definidos
 * aqui (no static) y declarados extern en aot_emit_internal.h para que los
 * emisores por-arch los lean.
 * ------------------------------------------------------------------------ */
const AotSym *g_aot_dbg_syms = NULL;
int g_aot_dbg_n = 0;

void aot_set_debug_symbols(const AotSym *syms, int n) {
    g_aot_dbg_syms = (n > 0) ? syms : NULL;
    g_aot_dbg_n = (n > 0) ? n : 0;
}

/* Hash SysV de ELF (para .hash / DT_HASH).  Compartido por los dynexec 64/32.
 *
 * `uint32_t` y no `unsigned long`, y no es cosmetico: el hash esta DEFINIDO a
 * 32 bits, y esta forma de escribirlo se apoya en que `h << 4` se salga por
 * arriba.  Con `unsigned long` eso solo pasa donde mide 32 bits (Windows); en
 * Linux mide 64, los bits por encima de 32 se acumulan y la mascara
 * `0xf0000000` no los limpia nunca, asi que el hash sale DISTINTO.
 *
 * Lo que costaba: la tabla `.hash` la lee el enlazador dinamico del sistema,
 * que calcula el hash de 32 bits del estandar.  Un Vesta construido en Linux
 * emitia una tabla que ld.so no sabe recorrer -- y el sintoma no es un error
 * del emisor, es un simbolo que "no existe" al cargar --.  Mismo fallo de
 * fondo que el umbral del JIT: ancho que depende de la plataforma.  Ver la
 * nota en `src/jit/auto_jit.cpp`.
 */
uint32_t aot_elf_hash(const char *name) {
    uint32_t h = 0, g;
    while (*name) {
        h = (h << 4) + (unsigned char)*name++;
        g = h & 0xf0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/* =========================================================================
 *  COFF RELOCATABLE (.obj Windows) -- via LibCOFFparse.  Machine + tipos de
 *  reloc se seleccionan con is32; arch-neutral en cuanto al layout del .obj.
 * ========================================================================= */

/* Storage classes / tipos COFF (PE/COFF spec). */
#define AOT_COFF_SYM_EXTERNAL 2
#define AOT_COFF_SYM_STATIC 3
#define AOT_COFF_SYM_FUNC 0x20 /* DTYPE function << 4 */

/* Impl comun COFF .obj para AMD64 (is32=0) e i386 (is32=1).  Difs: Machine,
 * tipos de reloc, y que i386 NO tiene ABS64 (usa DIR32 para datos abs32). */
static int coff_obj_impl(const char *path, const AotSection *secs, int num_secs,
                         const AotReloc *relocs, int num_relocs,
                         const AotSym *syms, int num_syms, char *err,
                         size_t err_cap, int is32) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_coff_obj: sin secciones");
        return 0;
    }
    for (int r = 0; r < num_relocs; ++r) {
        if (relocs[r].target_is_imagebase) {
            /* La base de la imagen NO existe todavia en un objeto suelto: la
             * fija quien enlaza.  Se dice aqui en vez de emitir un cero, que es
             * la clase de valor por defecto que convierte un error en otro
             * resultado. */
            set_err(err, err_cap,
                    "aot_emit_coff_obj: __ImageBase no se puede resolver en un "
                    ".obj -- la base la fija el enlace final");
            return 0;
        }
        if (relocs[r].target_is_size || relocs[r].target_is_end) {
            set_err(err, err_cap,
                    "aot_emit_coff_obj: SIZE/END no soportado en .obj (v1)");
            return 0;
        }
        const int kind_ok =
            relocs[r].kind == AOT_RELOC_REL32 ||
            relocs[r].kind == AOT_RELOC_SECREL32 || /* TLS (thread_local) */
            (is32 ? relocs[r].kind == AOT_RELOC_IMM32
                  : relocs[r].kind == AOT_RELOC_ABS64);
        if (!kind_ok) {
            set_err(err, err_cap,
                    "aot_emit_coff_obj: reloc kind no soportado en .obj");
            return 0;
        }
        if (relocs[r].site_section < 0 || relocs[r].site_section >= num_secs) {
            set_err(err, err_cap,
                    "aot_emit_coff_obj: site_section fuera de rango");
            return 0;
        }
        /* Los externos no tienen target_section (lo resuelve el linker). */
        if (!relocs[r].extern_name && (relocs[r].target_section < 0 ||
                                       relocs[r].target_section >= num_secs)) {
            set_err(err, err_cap,
                    "aot_emit_coff_obj: target_section fuera de rango");
            return 0;
        }
    }

    /* Copias mutables de los datos de cada seccion: COFF lleva el ADDEND en el
     * campo (no en un record aparte), asi que pre-escribimos target_off en el
     * sitio de cada reloc (4 bytes REL32 / 8 bytes ABS64). */
    uint8_t **data = (uint8_t **)calloc((size_t)num_secs, sizeof(uint8_t *));
    if (!data) {
        set_err(err, err_cap, "oom");
        return 0;
    }
    for (int i = 0; i < num_secs; ++i) {
        data[i] = (uint8_t *)malloc(secs[i].size ? secs[i].size : 1);
        if (secs[i].size) memcpy(data[i], secs[i].data, secs[i].size);
    }
    for (int r = 0; r < num_relocs; ++r) {
        const AotReloc *rl = &relocs[r];
        const uint32_t width = (rl->kind == AOT_RELOC_ABS64) ? 8u : 4u;
        if (rl->site_off + width > secs[rl->site_section].size) {
            for (int i = 0; i < num_secs; ++i)
                free(data[i]);
            free(data);
            set_err(err, err_cap,
                    "aot_emit_coff_obj: reloc fuera de la seccion del sitio");
            return 0;
        }
        /* Externo (call a simbolo indefinido): IMAGE_REL_AMD64_REL32 ya es
         * relativo al byte siguiente; el campo se deja en 0 (sin pre-escribir
         * addend) -> el linker calcula sym - (site+4). */
        if (rl->extern_name) continue;
        const uint64_t addend =
            (uint64_t)((int64_t)rl->target_off + rl->addend);
        uint8_t *p = data[rl->site_section] + rl->site_off;
        if (width == 8)
            wr64le(p, addend);
        else
            wr32le(p, (uint32_t)addend);
    }

    /* Externos unicos (convencion libc; los resuelve el linker). */
    const char **extn =
        (const char **)calloc((size_t)num_relocs + 1, sizeof(char *));
    int n_extn = 0;
    if (extn)
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

    /* Secciones COFF (las relocs se añaden con add_relocation). */
    NewSection *ns = (NewSection *)calloc((size_t)num_secs, sizeof(NewSection));
    for (int i = 0; i < num_secs; ++i) {
        uint32_t chars = 0;
        if (secs[i].flags & AOT_SEC_CODE) chars |= IMAGE_SCN_CNT_CODE;
        if (secs[i].flags & AOT_SEC_DATA)
            chars |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        if (secs[i].flags & AOT_SEC_EXEC) chars |= IMAGE_SCN_MEM_EXECUTE;
        if (secs[i].flags & AOT_SEC_READ) chars |= IMAGE_SCN_MEM_READ;
        if (secs[i].flags & AOT_SEC_WRITE) chars |= IMAGE_SCN_MEM_WRITE;
        ns[i] = create_section(secs[i].name, chars, data[i],
                               secs[i].size ? secs[i].size : 0, NULL, 0);
    }
    /* Relocs -> registros COFF.  Internos: contra el simbolo de SECCION del
     * target (indices 0..num_secs-1).  Externos: contra el simbolo externo
     * (indices num_secs+num_syms..) con REL32. */
    for (int r = 0; r < num_relocs; ++r) {
        const AotReloc *rl = &relocs[r];
        uint32_t sym_idx;
        uint16_t type;
        if (rl->extern_name) {
            int k = 0;
            for (; k < n_extn; ++k)
                if (strcmp(extn[k], rl->extern_name) == 0) break;
            sym_idx = (uint32_t)(num_secs + num_syms + k);
            type = is32 ? (uint16_t)IMAGE_REL_I386_REL32
                        : (uint16_t)IMAGE_REL_AMD64_REL32;
        } else {
            sym_idx = (uint32_t)rl->target_section;
            if (is32)
                type = (rl->kind == AOT_RELOC_SECREL32)
                           ? (uint16_t)IMAGE_REL_I386_SECREL
                       : (rl->kind == AOT_RELOC_REL32)
                           ? (uint16_t)IMAGE_REL_I386_REL32
                           : (uint16_t)IMAGE_REL_I386_DIR32;
            else
                type = (rl->kind == AOT_RELOC_SECREL32)
                           ? (uint16_t)IMAGE_REL_AMD64_SECREL
                       : (rl->kind == AOT_RELOC_ABS64)
                           ? (uint16_t)IMAGE_REL_AMD64_ADDR64
                           : (uint16_t)IMAGE_REL_AMD64_REL32;
        }
        add_relocation(
            &ns[rl->site_section],
            create_relocation((uint32_t)rl->site_off, sym_idx, type));
    }

    SECTION_HEADER *sh =
        (SECTION_HEADER *)calloc((size_t)num_secs, sizeof(SECTION_HEADER));
    setup_sections(sh, ns, num_secs);
    /* En un .obj la VirtualAddress de cada seccion es 0 (la fija el linker). */
    for (int i = 0; i < num_secs; ++i)
        sh[i].VirtualAddress = 0;

    /* Simbolos: [0..num_secs-1] seccion (STATIC), [globales], [externos]. */
    const int nsym = num_secs + num_syms + n_extn;
    COFF_SYMBOL *symtab =
        (COFF_SYMBOL *)calloc((size_t)nsym, sizeof(COFF_SYMBOL));
    /* String table: 4 bytes de tamano + nombres > 8 chars. */
    char *strtab = (char *)calloc(1, 4);
    uint32_t strtab_size = 4;
/* Helper inline: setear nombre (inline si <=8, si no offset a string table). */
#define AOT_COFF_SET_NAME(SYM, NM)                                             \
    do {                                                                       \
        const char *nm_ = (NM);                                                \
        size_t ln_ = strlen(nm_);                                              \
        if (ln_ <= 8) {                                                        \
            memset((SYM).Name.ShortName, 0, 8);                                \
            memcpy((SYM).Name.ShortName, nm_, ln_);                            \
        } else {                                                               \
            (SYM).Name.LongName.Zero = 0;                                      \
            (SYM).Name.LongName.Offset = strtab_size;                          \
            strtab = (char *)realloc(strtab, strtab_size + ln_ + 1);           \
            memcpy(strtab + strtab_size, nm_, ln_ + 1);                        \
            strtab_size += (uint32_t)(ln_ + 1);                                \
        }                                                                      \
    } while (0)

    for (int i = 0; i < num_secs; ++i) {
        AOT_COFF_SET_NAME(symtab[i], secs[i].name);
        symtab[i].Value = 0;
        symtab[i].SectionNumber = (int16_t)(i + 1);
        symtab[i].Type = 0;
        symtab[i].StorageClass = AOT_COFF_SYM_STATIC;
        symtab[i].NumberOfAuxSymbols = 0;
    }

    /* Nombres de seccion de mas de ocho caracteres.
     *
     * La cabecera de seccion reserva ocho bytes justos para el nombre, asi que
     * `.eh_frame` -- que tiene nueve -- no cabe.  En un OBJETO el formato da
     * salida: se escribe `/N`, donde N es en decimal el desplazamiento del
     * nombre completo dentro de la tabla de cadenas.  (En una imagen ya no vale,
     * y por eso alli la seccion aparece recortada; es lo que hacen todos.)
     *
     * Sin esto el nombre se truncaba, y el fallo es de los que no avisan: `gcc`
     * emite `.eh_frame` con el nombre completo, nosotros emitiriamos
     * `.eh_fram`, y al enlazar los dos objetos las dos tablas irian a SECCIONES
     * DISTINTAS.  Cada una queda bien formada por su cuenta, el binario corre,
     * y el desenrollado solo funciona para la mitad del programa.
     *
     * Se hace despues de los simbolos porque comparten tabla de cadenas: ahi ya
     * estan los nombres largos de simbolo y esto se anade detras. */
    for (int i = 0; i < num_secs; ++i) {
        const char *nm = secs[i].name ? secs[i].name : "";
        const size_t ln = strlen(nm);
        if (ln <= 8) continue;

        const uint32_t off = strtab_size;
        char *grown = (char *)realloc(strtab, strtab_size + ln + 1);
        if (!grown) {
            set_err(err, err_cap, "VX9256"); // lo renderiza la frontera C++
            free(strtab);
            free(symtab);
            free(sh);
            return 0;
        }
        strtab = grown;
        memcpy(strtab + strtab_size, nm, ln + 1);
        strtab_size += (uint32_t)(ln + 1);

        /* "/" + hasta siete digitos entra en los ocho bytes; una tabla de
         * cadenas que llegara a 10 millones no cabria, y eso no puede pasar
         * con nombres de seccion. */
        char short_name[16];
        snprintf(short_name, sizeof(short_name), "/%u", (unsigned)off);
        const size_t sn = strlen(short_name);
        memset(sh[i].Name, 0, 8);
        memcpy(sh[i].Name, short_name, sn < 8 ? sn : 8);
    }
    for (int g = 0; g < num_syms; ++g) {
        COFF_SYMBOL *s = &symtab[num_secs + g];
        AOT_COFF_SET_NAME(*s, syms[g].name);
        s->Value = (uint32_t)syms[g].offset;
        s->SectionNumber = (int16_t)(syms[g].section + 1);
        s->Type = syms[g].is_func ? AOT_COFF_SYM_FUNC : 0;
        s->StorageClass = AOT_COFF_SYM_EXTERNAL;
        s->NumberOfAuxSymbols = 0;
    }
    /* Externos: indefinidos (SectionNumber=0), EXTERNAL -> el linker resuelve.
     */
    for (int e = 0; e < n_extn; ++e) {
        COFF_SYMBOL *s = &symtab[num_secs + num_syms + e];
        AOT_COFF_SET_NAME(*s, extn[e]);
        s->Value = 0;
        s->SectionNumber = 0; /* IMAGE_SYM_UNDEFINED */
        s->Type = AOT_COFF_SYM_FUNC;
        s->StorageClass = AOT_COFF_SYM_EXTERNAL;
        s->NumberOfAuxSymbols = 0;
    }
#undef AOT_COFF_SET_NAME

    COFF_HEADER header;
    memset(&header, 0, sizeof(header));
    header.Machine = is32 ? 0x14c /* I386 */ : 0x8664 /* AMD64 */;
    header.NumberOfSections = (uint16_t)num_secs;
    header.NumberOfSymbols = (uint32_t)nsym;
    header.SizeOfOptionalHeader = 0;
    header.Characteristics = 0;
    header.PointerToSymbolTable = calculate_symbol_table_offset(sh, num_secs);

    int rc = create_coff_file(path, &header, sh, ns, num_secs, symtab,
                              (uint32_t)nsym, strtab, strtab_size);
    int ok = (rc == 0);
    if (!ok) set_err(err, err_cap, "aot_emit_coff_obj: create_coff_file fallo");

    cleanup_resources(ns, num_secs); /* libera ns[i].data + relocations */
    free(ns);
    free(sh);
    free(symtab);
    free(strtab);
    free(extn);
    for (int i = 0; i < num_secs; ++i)
        free(data[i]);
    free(data);
    return ok;
}

/* COFF .obj AMD64 (64-bit). */
int aot_emit_coff_obj(const char *path, const AotSection *secs, int num_secs,
                      const AotReloc *relocs, int num_relocs,
                      const AotSym *syms, int num_syms, char *err,
                      size_t err_cap) {
    return coff_obj_impl(path, secs, num_secs, relocs, num_relocs, syms,
                         num_syms, err, err_cap, /*is32=*/0);
}

/* COFF .obj i386 (32-bit). */
int aot_emit_coff32_obj(const char *path, const AotSection *secs, int num_secs,
                        const AotReloc *relocs, int num_relocs,
                        const AotSym *syms, int num_syms, char *err,
                        size_t err_cap) {
    return coff_obj_impl(path, secs, num_secs, relocs, num_relocs, syms,
                         num_syms, err, err_cap, /*is32=*/1);
}

/* =========================================================================
 *  BINARIO PLANO (.bin) -- arch-neutral: solo bytes de secciones + relocs
 *  contra base fija, sin cabecera de formato.
 * ========================================================================= */
int aot_emit_flat_bin(const char *path, uint64_t base, const AotSection *secs,
                      int num_secs, const AotReloc *relocs, int num_relocs,
                      char *err, size_t err_cap) {
    if (num_secs <= 0) {
        set_err(err, err_cap, "aot_emit_flat_bin: sin secciones");
        return 0;
    }

    /* Offset en la imagen de cada seccion (tras la colocacion). */
    uint64_t *sec_off = (uint64_t *)calloc((size_t)num_secs, sizeof(uint64_t));
    int *flow = (int *)malloc((size_t)num_secs * sizeof(int));
    int *fixd = (int *)malloc((size_t)num_secs * sizeof(int));
    if (!sec_off || !flow || !fixd) {
        set_err(err, err_cap, "aot_emit_flat_bin: OOM");
        free(sec_off);
        free(flow);
        free(fixd);
        return 0;
    }
    OBuf out;
    out.p = NULL;
    out.len = 0;
    out.cap = 0;

    /* Particionar: FLUYENTES (at<0, se colocan secuencialmente por @order) y
     * FIJAS (at>=0, ancladas a su offset).  El offset 0 = punto de entrada. */
    int nflow = 0, nfixd = 0;
    for (int i = 0; i < num_secs; ++i) {
        if (secs[i].at >= 0)
            fixd[nfixd++] = i;
        else
            flow[nflow++] = i;
    }
    /* Orden estable de las FLUYENTES por (order asc, indice asc) -- insertion
     * sort (N de secciones es pequeno). */
    for (int a = 1; a < nflow; ++a) {
        int key = flow[a];
        int b = a - 1;
        while (b >= 0 && secs[flow[b]].order > secs[key].order) {
            flow[b + 1] = flow[b];
            --b;
        }
        flow[b + 1] = key;
    }
    /* FIJAS por @at ascendente. */
    for (int a = 1; a < nfixd; ++a) {
        int key = fixd[a];
        int b = a - 1;
        while (b >= 0 && secs[fixd[b]].at > secs[key].at) {
            fixd[b + 1] = fixd[b];
            --b;
        }
        fixd[b + 1] = key;
    }

    /* Pre-chequeo: dos secciones FIJAS (@at) cuyos rangos se solapan son una
     * contradiccion que el emisor NO puede resolver (el usuario las anclo a
     * offsets incompatibles).  Lo detectamos ANTES del merge y damos un error
     * PRECISO -- nombres + offsets + cuantos bytes solapan -- para que re-
     * espaciar sea trivial en vez de adivinar. */
    for (int a = 0; a + 1 < nfixd; ++a) {
        const AotSection *cur = &secs[fixd[a]];
        const AotSection *nxt = &secs[fixd[a + 1]];
        uint64_t cur_at = (uint64_t)cur->at;
        uint64_t cur_end = cur_at + aot_sec_size(cur);
        uint64_t nxt_at = (uint64_t)nxt->at;
        if (cur_end > nxt_at) {
            char b[256];
            snprintf(
                b, sizeof(b),
                "aot_emit_flat_bin: solape @at -- la seccion '%s' "
                "(@0x%llX..0x%llX) se solapa con '%s' (@0x%llX) por 0x%llX "
                "bytes; sube su @at a 0x%llX o reduce '%s'",
                cur->name ? cur->name : "?", (unsigned long long)cur_at,
                (unsigned long long)cur_end, nxt->name ? nxt->name : "?",
                (unsigned long long)nxt_at,
                (unsigned long long)(cur_end - nxt_at),
                (unsigned long long)cur_end, cur->name ? cur->name : "?");
            set_err(err, err_cap, b);
            goto fail;
        }
    }

    /* Merge greedy: coloca FLUYENTES secuencialmente hasta que la siguiente no
     * cabe antes del proximo ancla FIJO; entonces rellena con ceros hasta el
     * ancla y coloca la seccion FIJA.  Las secciones FLUYENTES grandes (p.ej.
     * la .text del kernel) que no caben en ningun hueco se difieren tras el
     * ultimo ancla FIJO automaticamente (nunca se incrustan entre anclas, asi
     * no colisionan con el layout @at por mucho que crezcan). */
    {
        uint64_t cursor = 0;
        int qi = 0, fi = 0;
        const char *prev_name = "(inicio)"; /* quien avanzo el cursor */
        while (qi < nflow || fi < nfixd) {
            int take_fixed = 0;
            uint64_t aligned = cursor;
            if (qi < nflow) {
                size_t al =
                    secs[flow[qi]].align ? (size_t)secs[flow[qi]].align : 1u;
                while (aligned % al)
                    ++aligned;
            }
            if (fi < nfixd) {
                uint64_t fa = (uint64_t)secs[fixd[fi]].at;
                if (qi >= nflow)
                    take_fixed = 1;
                else if (aligned + aot_sec_size(&secs[flow[qi]]) > fa)
                    take_fixed = 1;
            }
            if (take_fixed) {
                uint64_t fa = (uint64_t)secs[fixd[fi]].at;
                if (cursor > fa) {
                    /* Una FLUYENTE colocada antes empujo el cursor sobre este
                     * ancla.  Con el diferido esto no deberia ocurrir, pero si
                     * pasa, reportamos quien y por cuanto. */
                    char b[256];
                    snprintf(b, sizeof(b),
                             "aot_emit_flat_bin: solape -- '%s' (termina en "
                             "0x%llX) invade la seccion @at '%s' (@0x%llX) por "
                             "0x%llX bytes",
                             prev_name, (unsigned long long)cursor,
                             secs[fixd[fi]].name ? secs[fixd[fi]].name : "?",
                             (unsigned long long)fa,
                             (unsigned long long)(cursor - fa));
                    set_err(err, err_cap, b);
                    goto fail;
                }
                sec_off[fixd[fi]] = fa;
                cursor = fa + aot_sec_size(&secs[fixd[fi]]);
                prev_name = secs[fixd[fi]].name ? secs[fixd[fi]].name : "?";
                ++fi;
            } else {
                sec_off[flow[qi]] = aligned;
                cursor = aligned + aot_sec_size(&secs[flow[qi]]);
                prev_name = secs[flow[qi]].name ? secs[flow[qi]].name : "?";
                ++qi;
            }
        }
        /* Construir la imagen (ceros) del tamano total y volcar cada seccion.
         */
        if (!ob_put(&out, NULL, (size_t)cursor)) {
            set_err(err, err_cap, "aot_emit_flat_bin: OOM imagen");
            goto fail;
        }
        for (int i = 0; i < num_secs; ++i) {
            if (secs[i].flags & AOT_SEC_BSS) continue; /* ya es cero */
            uint64_t sz = aot_sec_size(&secs[i]);
            if (sz && secs[i].data)
                memcpy(out.p + sec_off[i], secs[i].data, (size_t)sz);
        }
    }

    /* Resolver relocs contra la base fija (REL32 es invariante a la base). */
    for (int r = 0; r < num_relocs; ++r) {
        const AotReloc *rl = &relocs[r];
        if (rl->site_section < 0 || rl->site_section >= num_secs ||
            rl->target_section < 0 || rl->target_section >= num_secs) {
            set_err(err, err_cap,
                    "aot_emit_flat_bin: indice de seccion invalido en reloc");
            goto fail;
        }
        uint64_t site_image_off = sec_off[rl->site_section] + rl->site_off;
        uint64_t target_value;
        if (rl->target_is_imagebase) {
            target_value = base; // en un binario plano, la base ES la imagen
        } else if (rl->target_is_size) {
            target_value = aot_sec_size(&secs[rl->target_section]);
        } else if (rl->target_is_end) {
            target_value = base + sec_off[rl->target_section] +
                           aot_sec_size(&secs[rl->target_section]);
        } else {
            target_value = base + sec_off[rl->target_section] + rl->target_off;
        }
        target_value += (uint64_t)rl->addend;
        uint32_t width =
            (rl->kind == AOT_RELOC_ABS64 || rl->kind == AOT_RELOC_IMM64) ? 8u
                                                                         : 4u;
        if (site_image_off + width > out.len) {
            set_err(err, err_cap, "aot_emit_flat_bin: reloc fuera de rango");
            goto fail;
        }
        if (!apply_reloc(out.p + site_image_off, base + site_image_off,
                         target_value, rl->kind, base)) {
            set_err(err, err_cap,
                    "aot_emit_flat_bin: kind de reloc no soportado");
            goto fail;
        }
    }

    {
        FILE *f = fopen(path, "wb");
        if (!f) {
            set_err(err, err_cap, "aot_emit_flat_bin: fopen fallo");
            goto fail;
        }
        size_t w = out.len ? fwrite(out.p, 1, out.len, f) : 0;
        fclose(f);
        if (w != out.len) {
            set_err(err, err_cap, "aot_emit_flat_bin: fwrite incompleto");
            goto fail;
        }
    }

    free(sec_off);
    free(flow);
    free(fixd);
    free(out.p);
    return 1;

fail:
    free(sec_off);
    free(flow);
    free(fixd);
    free(out.p);
    return 0;
}

/* --- Lectura de exports de DLL/PE (delega en LibPEparse) ----------------- */
int aot_pe_export_names(const char *path, char ***out_names, int *out_count) {
    if (out_names) *out_names = NULL;
    if (out_count) *out_count = 0;
    if (path == NULL || out_names == NULL || out_count == NULL) return 1;
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 1;
    /* Parse MINIMO suficiente para los exports: DOS header (e_lfanew) + NT
     * headers (RVA del directorio de exports) + section headers (necesarios
     * para resolve64 RVA->offset).  Se EVITA el ParseFile64 completo, que
     * ademas parsea imports / base-relocs / rich-header -- innecesarios para
     * exports y costosos/fragiles en DLLs del sistema grandes (kernel32). */
    PE64FILE pe;
    PE64FILE_Initialize(&pe);
    pe.NAME = (char *)path;
    pe.Ppefile = f;
    ParseDOSHeader64(&pe);
    ParseNTHeaders64(&pe);
    ParseSectionHeaders64(&pe);
    int n = 0;
    char **names = ParseExportNames64(&pe, &n);
    if (pe.PEFILE_SECTION_HEADERS != NULL) free(pe.PEFILE_SECTION_HEADERS);
    fclose(f);
    *out_names = names;
    *out_count = n;
    return 0; /* 0 exports tambien es exito */
}

void aot_free_pe_export_names(char **names, int count) {
    FreeExportNames64(names, count);
}

/* --- Lectura de exports de una .so/ELF (dynsym, delega en LibELFparse) ---- */
int aot_elf_export_names(const char *path, char ***out_names, int *out_count) {
    if (out_names) *out_names = NULL;
    if (out_count) *out_count = 0;
    if (path == NULL || out_names == NULL || out_count == NULL) return 1;
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        return 1;
    }
    void *buf = malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);
    ElfFile elf;
    if (!elf_mem_parse(&elf, buf, (size_t)sz)) {
        free(buf);
        return 1;
    }
    int n = 0;
    /* elf_dynsym_export_names COPIA cada nombre -> el buffer se puede liberar.
     */
    char **names = elf_dynsym_export_names(&elf, &n);
    free(buf);
    *out_names = names;
    *out_count = n;
    return 0;
}
