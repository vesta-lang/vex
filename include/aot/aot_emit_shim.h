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
 * @file aot/aot_emit_shim.h
 * @brief  AOT.4 -- ABI C plana para emitir ejecutables PE/ELF.
 *
 * Frontera limpia entre el compilador AOT (C++) y LibPEparse (C).  Este header
 * NO expone ningun tipo de LibPEparse: solo @c structs C planos y funciones.
 * El .c que lo implementa (@c aot_emit_shim.c) se compila como C -- donde las
 * cabeceras de LibPEparse (con uniones anonimas, macros ELF, etc.) compilan sin
 * problemas -- y el lado C++ incluye SOLO este header.  Asi:
 *
 *   - LibPEparse permanece como libreria C generica, sin cambios por VestaVM.
 *   - El C++ no sufre las incompatibilidades C/C++ de las cabeceras C.
 *   - La API es CONFIGURABLE: el usuario define sus propias secciones, tamanos,
 *     alineamientos, base de imagen, entradas de import, pila, subsistema, etc.
 */

#ifndef AOT_AOT_EMIT_SHIM_H
#define AOT_AOT_EMIT_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 *  Flags genericos de seccion (independientes del formato).
 * ------------------------------------------------------------------------- */
#define AOT_SEC_READ 0x01u  /* legible */
#define AOT_SEC_WRITE 0x02u /* escribible */
#define AOT_SEC_EXEC 0x04u  /* ejecutable */
#define AOT_SEC_CODE 0x08u  /* contiene codigo */
#define AOT_SEC_DATA 0x10u  /* datos inicializados */
#define AOT_SEC_BSS 0x20u   /* datos sin inicializar (no ocupan fichero) */
#define AOT_SEC_TLS                                                            \
    0x40u /* plantilla TLS (thread_local): se describe con un                  \
             segmento PT_TLS; el cargador la copia por-hilo.                   \
             data = parte .tdata (en fichero), bss_size =                      \
             parte .tbss (solo memsz). */

/**
 * @brief Una seccion definida por el usuario.
 *
 * @c vaddr / @c align en 0 => el emisor elige (layout secuencial por pagina).
 * Para BSS, @c data=NULL/@c size=0 y @c bss_size>0.
 */
typedef struct {
    const char *name;    /* nombre (".text", ".rodata", o propio del usuario) */
    uint32_t flags;      /* AOT_SEC_* */
    const uint8_t *data; /* bytes (NULL para BSS) */
    uint32_t size;       /* tamano de @c data */
    uint32_t bss_size;   /* tamano BSS si AOT_SEC_BSS */
    uint64_t vaddr;      /* VA fija (0 = auto) */
    uint64_t align;      /* alineamiento (0 = default del formato) */
    int64_t at;          /* @at(N): offset fijo en .bin (-1 = auto) */
    int32_t order; /* @order(N): orden de seccion en .bin (max = creacion) */
} AotSection;

/**
 * @brief Una llamada a funcion importada a resolver (solo PE).
 *
 * El emisor agrupa por DLL, construye la @c .idata + IAT y parchea el @c disp32
 * del @c call indirecto (@c FF 15) en @c call_off de la seccion @c
 * call_section.
 */
typedef struct {
    const char *dll;   /* "KERNEL32.dll" */
    const char *func;  /* "ExitProcess" */
    int call_section;  /* indice de seccion donde esta el call */
    uint64_t call_off; /* offset del FF 15 dentro de esa seccion */
} AotImport;

/* -------------------------------------------------------------------------
 *  Relocations cross-seccion (resueltas por el emisor TRAS el layout).
 *  El emisor conoce VA + tamano de cada seccion cuando ya las coloco, asi
 *  que es quien puede parchear refs a datos (.rodata), simbolos de seccion
 *  (start/end/size), etc.  ARCH-agnostico: site + target + como escribir.
 * ------------------------------------------------------------------------- */
#define AOT_RELOC_REL32                                                        \
    0 /* *(int32*)site  = (target_value) - (site_va + 4)                       \
       */
#define AOT_RELOC_ABS64                                                        \
    1 /* *(uint64*)site = target_value (direccion absoluta) */
#define AOT_RELOC_IMM32                                                        \
    2 /* *(uint32*)site = target_value (inmediato, e.g. SIZE) */
#define AOT_RELOC_IMM64 3 /* *(uint64*)site = target_value */
#define AOT_RELOC_TPOFF32                                                      \
    4 /* TLS local-exec (ELF .o): R_X86_64_TPOFF32 contra el simbolo de        \
       * seccion de .tdata + addend = offset; el sitio queda SIN resolver en   \
       * el .o (el --link calcula el TPOFF TP-relativo). */
#define AOT_RELOC_SECREL32                                                     \
    5 /* TLS PE (Windows): *(int32*)site = offset del target dentro de su      \
       * seccion (.tls), no la VA.  El emisor PE escribe target_off. */
#define AOT_RELOC_ARM64_CALL26                                                 \
    6 /* AArch64 BL/B (R_AARCH64_CALL26/JUMP26): parchea el campo imm26 de la  \
       * instruccion de 32 bits en el sitio con ((target - site) >> 2).  Para  \
       * el `bl main` del _start arm64 y llamadas cross-funcion arm64. */
#define AOT_RELOC_RVA32                                                        \
    7 /* *(uint32*)site = target_value - base de imagen.  Es la unica que      \
       * necesita la base, y por eso `apply_reloc` la recibe: dejar la resta   \
       * a quien llama repartiria por ocho sitios lo que es una sola regla.    \
       *                                                                       \
       * Hace falta para `.pdata`: un RUNTIME_FUNCTION son TRES campos y los   \
       * tres son RVA, asi que sin esto no se puede escribir ni una entrada.   \
       * Es tambien la que le falta al enlazador de objetos COFF              \
       * (IMAGE_REL_AMD64_ADDR32NB) para conservar la `.pdata` ajena: el mismo \
       * concepto, en las dos direcciones.                                     \
       *                                                                       \
       * Solo tiene sentido produciendo una IMAGEN con base conocida.  Un RVA  \
       * que no cabe en 32 bits -- objetivo por debajo de la base, o a mas de  \
       * 4 GiB -- se rechaza en vez de truncarse: una tabla de desenrollado    \
       * que apunta a cualquier sitio es peor que no tenerla, porque el        \
       * sistema la sigue. */

/**
 * @brief Una relocation a resolver tras el layout.
 *
 * @c target_value = @c target_is_size ? tamano(@c target_section)
 *                                     : VA(@c target_section) + @c target_off;
 * luego se le suma @c addend.  Se escribe en @c secs[@c site_section] en
 * @c site_off segun @c kind (rel32 PC-relativo, abs64, o inmediato).
 */
typedef struct {
    int site_section;    /* seccion donde parchear */
    uint64_t site_off;   /* offset del campo a parchear dentro de la seccion */
    int target_section;  /* seccion objetivo */
    uint64_t target_off; /* offset dentro del target (modo ADDR) */
    int target_is_size;  /* 1 => target_value = tamano de target_section */
    int target_is_end;   /* 1 => target_value = VA(target_section)+tamano */
    /* 1 => target_value = la BASE DE LA IMAGEN, y `target_section`/`target_off`
     * se ignoran.
     *
     * Es lo que hace falta para publicar `__ImageBase`, el simbolo que en PE
     * NO define ningun fichero fuente sino el enlazador, y cuya direccion es el
     * primer byte de la imagen cargada -- la cabecera `MZ` --.  El codigo lo
     * usa como forma barata de saber donde esta cargado su modulo, sin llamar a
     * `GetModuleHandle`; el simbolizador lo necesita para restarselo a una
     * direccion de retorno y quedarse con el desplazamiento dentro del modulo.
     *
     * No cabe como seccion+offset: ninguna seccion empieza en la base (ahi
     * viven las cabeceras), asi que hace falta decirlo aparte.  Solo tiene
     * sentido al producir una IMAGEN (exe / .bin): en un objeto suelto la base
     * todavia no existe, y ahi se rechaza diciendolo. */
    int target_is_imagebase;
    int kind;            /* AOT_RELOC_* */
    int64_t addend;      /* desplazamiento adicional */
    /* Reloc a un SIMBOLO EXTERNO (libc: malloc/free/abort...): si != NULL, el
     * target NO es una seccion sino un simbolo indefinido que resuelve el
     * linker del sistema.  target_section/off se ignoran.  Solo .o/.obj. */
    const char *extern_name;
} AotReloc;

/**
 * @brief Configuracion de layout / linker.  Campos en 0 => default del formato.
 *
 * Permite al usuario controlar base de imagen, alineamientos, pila/heap,
 * subsistema (PE) y direccion de pila (ELF) sin tocar el emisor.
 */
typedef struct {
    uint64_t image_base; /* base de carga (PE/ELF). 0 => 0x400000 */
    uint32_t
        section_align;   /* alineamiento de seccion en memoria. 0 => default */
    uint32_t file_align; /* alineamiento en fichero (PE). 0 => 0x200 */
    uint64_t stack_reserve;   /* PE SizeOfStackReserve. 0 => 0x100000 */
    uint64_t stack_commit;    /* PE SizeOfStackCommit.  0 => 0x1000 */
    uint64_t heap_reserve;    /* PE SizeOfHeapReserve.  0 => 0x100000 */
    uint64_t heap_commit;     /* PE SizeOfHeapCommit.   0 => 0x1000 */
    int pe_subsystem;         /* PE Subsystem. <=0 => CUI (consola) */
    uint64_t elf_stack_vaddr; /* ELF: VA sugerida de la pila. 0 => 0x70000000 */
    uint64_t
        elf_stack_size; /* ELF: tamano del segmento de pila. 0 => 0x10000 */
    /* TLS PE: seccion+offset de __vx_tls_init (el TLS callback que aplica la
     * plantilla por-hilo).  <0 = sin callback.  El emisor sintetiza el
     * IMAGE_TLS_DIRECTORY y registra este callback en AddressOfCallBacks. */
    int tls_callback_section;
    uint32_t tls_callback_off;
    /* Arquitectura de destino (e_machine ELF / Machine PE): 0 => x86-64 por
     * defecto.  EM_AARCH64 (183) para ARM 64-bit; el emisor lo propaga a
     * LibPEparse (elf_builder_set_machine) en lugar de hardcodear x86-64.  Asi
     * el MISMO emisor produce ELF/PE de x86-64 o AArch64 segun este campo. */
    uint16_t machine;
} AotLayoutCfg;

/**
 * @brief Emite un ejecutable PE32+ (Windows) a disco.
 *
 * @param path        ruta del fichero de salida.
 * @param cfg         configuracion de layout (NULL => defaults).
 * @param secs        array de secciones (la entrada @c entry_section debe ser
 * codigo).
 * @param num_secs    numero de secciones.
 * @param entry_sec   indice de la seccion del punto de entrada.
 * @param entry_off   offset dentro de esa seccion del @c _start.
 * @param imps        array de imports a resolver (NULL si num_imps=0).
 * @param num_imps    numero de imports.
 * @param err         buffer para el mensaje de error (puede ser NULL).
 * @param err_cap     capacidad de @c err.
 * @return 1 en exito, 0 en error (con @c err relleno).
 */
int aot_emit_pe(const char *path, const AotLayoutCfg *cfg,
                const AotSection *secs, int num_secs, int entry_sec,
                uint64_t entry_off, const AotImport *imps, int num_imps,
                const AotReloc *relocs, int num_relocs, char *err,
                size_t err_cap);

/**
 * @brief Emite un ejecutable ELF64 (Linux) freestanding a disco.
 *
 * La salida del proceso es responsabilidad del codigo (syscall @c exit_group):
 * el ELF no lleva imports.  Genera dos PT_LOAD (codigo R+X, pila R+W) + symtab
 * minima con @c _start.
 *
 * @param path        ruta del fichero de salida.
 * @param cfg         configuracion de layout (NULL => defaults).
 * @param secs        array de secciones.
 * @param num_secs    numero de secciones.
 * @param entry_sec   indice de la seccion del punto de entrada.
 * @param entry_off   offset dentro de esa seccion del @c _start.
 * @param err         buffer para el mensaje de error (puede ser NULL).
 * @param err_cap     capacidad de @c err.
 * @return 1 en exito, 0 en error.
 */
int aot_emit_elf(const char *path, const AotLayoutCfg *cfg,
                 const AotSection *secs, int num_secs, int entry_sec,
                 uint64_t entry_off, const AotReloc *relocs, int num_relocs,
                 char *err, size_t err_cap);

/**
 * @brief Emite un EJECUTABLE ELF32 estatico (ET_EXEC, EM_386) -- modo
 *        protegido / kernels.  1 PT_LOAD R+X, entry = _start, salida via
 *        @c int @c 0x80 (el stub).  Freestanding (sin dynamic/libc).  Solo
 *        relocs PC-relativas (x86-32 no tiene RIP-relativo; refs a datos
 *        absolutas ABS32 son follow-up).  @c image_base default 0x08048000.
 * @return 1 en exito, 0 en error.
 */
int aot_emit_elf32(const char *path, const AotLayoutCfg *cfg,
                   const AotSection *secs, int num_secs, int entry_sec,
                   uint64_t entry_off, const AotReloc *relocs, int num_relocs,
                   char *err, size_t err_cap);

/**
 * @brief Emite un EJECUTABLE PE32 (i386, .exe Windows 32-bit) -- hand-rolled.
 *        Minimo: secciones de usuario + .idata con UN import (kernel32!
 *        ExitProcess, el _start sale por ahi).  @p imps trae ese import (para
 *        parchear el @c FF @c 15 del stub).  Aplica relocs REL32 intra-imagen.
 *        v1: EXEC self-contained (sin libc); externos = follow-up.  @c
 * image_base default 0x00400000.
 * @return 1 en exito, 0 en error.
 */
int aot_emit_pe32(const char *path, const AotLayoutCfg *cfg,
                  const AotSection *secs, int num_secs, int entry_sec,
                  uint64_t entry_off, const AotImport *imps, int num_imps,
                  const AotReloc *relocs, int num_relocs, char *err,
                  size_t err_cap);

/**
 * @brief Emite un EJECUTABLE ELF64 DINaMICO (PIE ET_DYN) que importa simbolos
 *        externos (libc malloc/free/abort...) via eager-GOT.  AOT.2.exec
 * slice 2.
 *
 * A diferencia de @c aot_emit_elf (estatico freestanding, syscall exit), este
 * lleva PT_INTERP (-> ld.so), .dynsym/.dynstr/.hash, .rela.dyn con
 * R_X86_64_GLOB_DAT por entrada GOT, y .dynamic (DT_NEEDED libc.so.6 +
 * DF_BIND_NOW).  Cada @p imps[i] (su @c func + @c call_section/@c call_off del
 * thunk @c FF @c 25 que emitio el driver) recibe una entrada GOT; el thunk se
 * parchea para saltar por ella.  PIE: vaddr == file offset; solo relocs
 * PC-relativas (ABS64/--no-pie NO soportado).  El campo @c dll de @c AotImport
 * se ignora (todo va a libc.so.6 via DT_NEEDED).
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_elf_dynexec(const char *path, const AotLayoutCfg *cfg,
                         const AotSection *secs, int num_secs, int entry_sec,
                         uint64_t entry_off, const AotReloc *relocs,
                         int num_relocs, const AotImport *imps, int num_imps,
                         char *err, size_t err_cap);

/**
 * @brief Variante x86-32 de @c aot_emit_elf_dynexec: EJECUTABLE ELF32 DINaMICO
 *        (PIE ET_DYN, EM_386) que importa libc.so.6 (i386) via eager-GOT.
 *        PT_INTERP -> /lib/ld-linux.so.2; .rel.dyn con R_386_GLOB_DAT
 * (Elf32_Rel SIN addend); .dynamic con DT_REL/RELSZ/RELENT + DF_BIND_NOW.  Cada
 *        thunk @c FF @c 25 @c disp32 lleva la direccion ABSOLUTA de su GOT
 * entry (i386 no tiene RIP-rel; PIE base 0 -> vaddr == file offset).
 * @return 1 en exito, 0 en error.
 */
int aot_emit_elf32_dynexec(const char *path, const AotLayoutCfg *cfg,
                           const AotSection *secs, int num_secs, int entry_sec,
                           uint64_t entry_off, const AotReloc *relocs,
                           int num_relocs, const AotImport *imps, int num_imps,
                           char *err, size_t err_cap);

/**
 * @brief Un simbolo GLOBAL exportado en un objeto relocatable.
 */
typedef struct {
    const char *name; /* nombre del simbolo (e.g. "main") */
    int section;      /* seccion donde vive */
    uint64_t offset;  /* offset dentro de la seccion */
    int is_func;      /* 1 = STT_FUNC, 0 = STT_OBJECT */
} AotSym;

/**
 * @brief Fija los simbolos de DEPURACION (nivel 1) para los EJECUTABLES.
 *
 * Los emisores de EXEC (aot_emit_elf / aot_emit_elf_dynexec / PE) consultan
 * esta lista global y, si no es vacia, embeben un @c .symtab (ELF) / symtab
 * COFF (PE) con los simbolos de funcion -> gdb/WinDbg/lldb muestran nombres en
 * backtraces. Estado global (el emit es single-thread por llamada); el driver
 * lo fija antes de emitir y lo resetea (n=0) despues.  n=0 -> sin simbolos
 * (cero coste, binario identico al modo release).  Los @c section/@c offset son
 * los mismos que en un
 * @c AotSym de export; @c st_value se calcula con la VA final de cada seccion.
 */
void aot_set_debug_symbols(const AotSym *syms, int n);

/**
 * @brief Emite un objeto RELOCATABLE ELF64 (ET_REL, .o) a disco.
 *
 * A diferencia de @c aot_emit_elf (ejecutable: aplica relocs + _start), este
 * NO lleva _start ni program headers: emite las secciones del usuario + una
 * @c .symtab (simbolos de seccion locales + @p syms globales) + una @c
 * .rela.<s> por seccion con relocs.  Las @c AotReloc se emiten como REGISTROS
 * de relocation (no se aplican): un linker externo (ld/gcc/link) las resuelve.
 * Cada reloc referencia el simbolo de SECCION de su @c target_section + addend
 * (REL32 -> R_X86_64_PC32 con addend @c target_off-4; ABS64 -> R_X86_64_64 con
 * addend @c target_off).  No soporta @c target_is_size/@c target_is_end (v1).
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_elf_obj(const char *path, const AotSection *secs, int num_secs,
                     const AotReloc *relocs, int num_relocs, const AotSym *syms,
                     int num_syms, char *err, size_t err_cap);

/**
 * @brief Emite un objeto ELF64 reubicable de AArch64 (.o arm64).
 *
 * Misma firma y mismo layout que @c aot_emit_elf_obj -- de hecho es el mismo
 * emisor: un ELF64 reubicable se escribe igual en las dos arquitecturas --,
 * cambiando solo la marca de maquina y los tipos de reubicacion.  Existe
 * porque, mientras no existio, una llamada `bl` entre funciones no se podia
 * escribir a un objeto de ARM.
 */
int aot_emit_elf_obj_arm64(const char *path, const AotSection *secs,
                           int num_secs, const AotReloc *relocs,
                           int num_relocs, const AotSym *syms, int num_syms,
                           char *err, size_t err_cap);

/**
 * @brief Emite un objeto RELOCATABLE ELF32 (.o i386) a disco.
 *
 * Variante de 32-bit de @c aot_emit_elf_obj: ELFCLASS32 + EM_386 + structs
 * Elf32 + @c SHT_REL (i386 usa REL, sin addend en el registro: el addend vive
 * EN el campo de la seccion).  Relocs @c REL32 -> @c R_386_PC32, @c IMM32
 * (ABS32 a datos) -> @c R_386_32.  No soporta @c ABS64 (no aplica en 32-bit).
 * Linkable con @c gcc @c -m32 / @c ld.  Conserva la extension @c .o.
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_elf32_obj(const char *path, const AotSection *secs, int num_secs,
                       const AotReloc *relocs, int num_relocs,
                       const AotSym *syms, int num_syms, char *err,
                       size_t err_cap);

/**
 * @brief Emite un objeto RELOCATABLE COFF (.obj Windows) a disco.
 *
 * Analogo a @c aot_emit_elf_obj pero en formato COFF (Machine AMD64), linkable
 * con @c link.exe / @c lld-link / @c gcc (MinGW).  Las @c AotReloc se emiten
 * como registros de relocation COFF contra el simbolo de SECCION del @c
 * target_section (REL32 -> IMAGE_REL_AMD64_REL32, ABS64 ->
 * IMAGE_REL_AMD64_ADDR64).  COFF lleva el addend EN el campo (no en un record
 * aparte): el emisor pre-escribe
 * @c target_off en el sitio.  No soporta @c target_is_size/@c target_is_end
 * (v1).
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_coff_obj(const char *path, const AotSection *secs, int num_secs,
                      const AotReloc *relocs, int num_relocs,
                      const AotSym *syms, int num_syms, char *err,
                      size_t err_cap);

/**
 * @brief Variante COFF i386 (.obj de 32-bit) de @c aot_emit_coff_obj.
 *
 * Machine @c IMAGE_FILE_MACHINE_I386 (0x14c); relocs @c IMAGE_REL_I386_REL32
 * (pc-rel) / @c IMAGE_REL_I386_DIR32 (abs32, para @c IMM32).  Sin @c ABS64.
 * Linkable con @c gcc @c -m32 / @c link.exe.  Conserva la extension @c .obj.
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_coff32_obj(const char *path, const AotSection *secs, int num_secs,
                        const AotReloc *relocs, int num_relocs,
                        const AotSym *syms, int num_syms, char *err,
                        size_t err_cap);

/**
 * @brief Emite una libreria compartida ELF64 (.so, ET_DYN) a disco.
 *
 * PIC: el codigo usa refs RIP-relativas (internas) -> las @c AotReloc se
 * APLICAN al emitir (PC-relativo, invariante bajo la base de carga), sin relocs
 * dinamicas. Exporta @p syms como simbolos GLOBALES en una @c .dynsym + @c
 * .hash + @c .dynamic, de forma que @c dlopen + @c dlsym los resuelvan.  Mapeo
 * vaddr=offset (identidad) + un PT_LOAD (R+W+X) + PT_DYNAMIC.  ABS64 (no-pie)
 * NO se soporta en .so (requeriria relocs dinamicas R_X86_64_RELATIVE) ->
 * error.
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_elf_so(const char *path, const AotSection *secs, int num_secs,
                    const AotReloc *relocs, int num_relocs, const AotSym *syms,
                    int num_syms, char *err, size_t err_cap);

/**
 * @brief Emite una DLL PE32+ (Windows) a disco.
 *
 * Analogo a @c aot_emit_elf_so pero en PE: marca @c IMAGE_FILE_DLL, construye
 * una tabla de exports (@c .edata: export directory + EAT + name pointer table
 * ordenada + ordinal table) para que @c LoadLibrary + @c GetProcAddress
 * resuelvan
 * @p syms.  Codigo PIC (RIP-rel) -> las relocs internas se APLICAN; sin @c
 * .reloc, se limpia @c DYNAMIC_BASE para cargar en la @c ImageBase (base fija).
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_pe_dll(const char *path, const AotLayoutCfg *cfg,
                    const AotSection *secs, int num_secs,
                    const AotReloc *relocs, int num_relocs, const AotSym *syms,
                    int num_syms, char *err, size_t err_cap);

/**
 * @brief Emite un BINARIO PLANO (flat binary, .bin) a disco.
 *
 * Sin ninguna cabecera (ni PE ni ELF): solo los bytes de las secciones
 * concatenadas, en orden, cada una alineada a su @c align (1 por defecto =
 * empaquetado denso).  Es el formato de un bootloader BIOS, una ROM, un
 * payload de firmware o una imagen cargada en una direccion fija.
 *
 * El layout arranca en el offset 0 del fichero y se carga en @p base (la
 * direccion fisica/virtual donde el cargador externo lo deposita, p.ej.
 * @c 0x7C00 para un boot sector).  El punto de entrada es el offset 0 (la
 * primera seccion, normalmente @c .text).  Las relocs se resuelven contra
 * @p base: @c ABS64 = @p base + offset_en_imagen; @c REL32 es invariante a
 * la base (PC-relativo dentro de la imagen).  Las secciones @c BSS no ocupan
 * bytes en el fichero (se omiten; un flat binary no lleva ceros implicitos
 * salvo que el usuario los escriba con @c bytes/times).
 *
 * @return 1 en exito, 0 en error.
 */
int aot_emit_flat_bin(const char *path, uint64_t base, const AotSection *secs,
                      int num_secs, const AotReloc *relocs, int num_relocs,
                      char *err, size_t err_cap);

/**
 * @brief Lee los NOMBRES exportados de una DLL/PE (delega en LibPEparse).
 *
 * El linker lo usa para resolver imports leyendo lo que la DLL REALMENTE
 * exporta, en vez de una lista de simbolos embebida.  Es parte del shim, el
 * unico punto que toca LibPEparse (frontera C/C++ del proyecto).
 *
 * @param path       Ruta de la DLL/PE.
 * @param out_names  [out] array char** (calloc'd) con los nombres; liberar con
 *                   @c aot_free_pe_export_names.
 * @param out_count  [out] numero de nombres.
 * @return 0 en exito (incluido un PE sin exports -> count=0); !=0 si el fichero
 *         no se pudo abrir/parsear.
 */
int aot_pe_export_names(const char *path, char ***out_names, int *out_count);

/** @brief Libera el array devuelto por @c aot_pe_export_names. */
void aot_free_pe_export_names(char **names, int count);

/**
 * @brief Lee los NOMBRES exportados por la tabla dinamica de una @c .so / ELF
 *        (delega en LibELFparse; analogo a @c aot_pe_export_names para PE).
 *        Solo ELF64.  Liberar con @c aot_free_pe_export_names.
 * @return 0 en exito (incluido sin dynsym -> count=0); !=0 si no se pudo
 *         abrir/parsear.
 */
int aot_elf_export_names(const char *path, char ***out_names, int *out_count);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AOT_AOT_EMIT_SHIM_H */
