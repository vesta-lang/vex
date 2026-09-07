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
 * @file aot/object_writer.h
 * @brief  AOT.4 -- emisor de ejecutables nativos (fachada C++ del shim).
 *
 * @c ObjectWriter es una fachada C++ CONFIGURABLE sobre la ABI C
 * @c aot_emit_shim.h (que a su vez usa LibPEparse).  El usuario define sus
 * propias secciones (nombre, flags, datos, tamano, alineamiento), la
 * configuracion de layout (base de imagen, alineamientos, pila/heap,
 * subsistema), el punto de entrada y las entradas de import.  El @c write()
 * despacha al emisor PE o ELF segun el formato.
 *
 * El header es C++ puro y solo incluye la ABI C plana del shim: NO arrastra
 * ningun tipo de LibPEparse al resto del compilador.
 *
 * = Conveniencias =
 *   @c add_text() / @c add_rodata() crean las secciones tipicas y, en el caso
 *   de @c add_text(), fijan el punto de entrada al inicio de esa seccion.  El
 *   usuario que necesite control total usa @c add_section() + @c set_entry() +
 *   @c set_config() directamente.
 */

#ifndef AOT_OBJECT_WRITER_H
#define AOT_OBJECT_WRITER_H

#include "aot/aot_emit_shim.h" // ABI C plana (AOT_SEC_*, AotLayoutCfg, ...)

#include <cstdint>
#include <string>
#include <vector>

namespace aot {

/**
 * @brief Formato del ejecutable de salida.
 */
enum class ObjFormat : uint8_t {
    PE = 0,  ///< PE32+ (Windows).
    ELF = 1, ///< ELF64 (Linux).
};

/**
 * @brief Tipo de artefacto de salida.
 */
enum class OutputKind : uint8_t {
    EXEC = 0,     ///< ejecutable standalone (con _start; relocs aplicadas).
    OBJECT = 1,   ///< objeto relocatable (.o/.obj; SIN _start; relocs como
                  ///< registros + symtab -> linkable con ld/gcc/link).
    SHARED = 2,   ///< libreria compartida (.so/.dll): exporta simbolos
                  ///< (dynsym/export table); PIC, relocs internas aplicadas.
    FLAT_BIN = 3, ///< binario plano (.bin): sin cabecera, solo bytes de las
                  ///< secciones; entry en offset 0; relocs contra base fija.
};

/**
 * @brief Simbolo exportado en un objeto relocatable (OBJECT).
 */
struct ExportSym {
    std::string name; ///< nombre del simbolo (e.g. "main").
    int section;      ///< seccion donde vive.
    uint64_t offset;  ///< offset dentro de la seccion.
    bool is_func;     ///< true = STT_FUNC, false = STT_OBJECT.
};

/// Flags de seccion (alias C++ de los AOT_SEC_* de la ABI).
namespace SecFlag {
constexpr uint32_t READ = AOT_SEC_READ;
constexpr uint32_t WRITE = AOT_SEC_WRITE;
constexpr uint32_t EXEC = AOT_SEC_EXEC;
constexpr uint32_t CODE = AOT_SEC_CODE;
constexpr uint32_t DATA = AOT_SEC_DATA;
constexpr uint32_t BSS = AOT_SEC_BSS;
constexpr uint32_t TLS = AOT_SEC_TLS;
} // namespace SecFlag

/**
 * @brief Una seccion definida por el usuario.
 */
struct WriterSection {
    std::string name;          ///< ".text", ".rodata", o propio.
    uint32_t flags = 0;        ///< SecFlag::*
    std::vector<uint8_t> data; ///< bytes (vacio para BSS).
    uint32_t bss_size = 0;     ///< tamano BSS si SecFlag::BSS.
    uint64_t vaddr = 0;        ///< VA fija (0 = auto).
    uint64_t align = 0;        ///< alineamiento (0 = default).
    int64_t at = -1;           ///< @at(N): offset fijo en .bin; -1 = auto.
    int32_t order =
        0x7fffffff; ///< @order(N): orden de seccion (.bin); max = creacion.
};

/**
 * @brief Configuracion de layout / linker (campos en 0 => default).
 */
struct LayoutConfig {
    uint64_t image_base = 0;      ///< base de carga (0 => 0x400000).
    uint32_t section_align = 0;   ///< alineamiento de seccion en memoria.
    uint32_t file_align = 0;      ///< alineamiento en fichero (PE; 0 => 0x200).
    uint64_t stack_reserve = 0;   ///< PE SizeOfStackReserve.
    uint64_t stack_commit = 0;    ///< PE SizeOfStackCommit.
    uint64_t heap_reserve = 0;    ///< PE SizeOfHeapReserve.
    uint64_t heap_commit = 0;     ///< PE SizeOfHeapCommit.
    int pe_subsystem = -1;        ///< PE Subsystem (<=0 => CUI).
    uint64_t elf_stack_vaddr = 0; ///< ELF: VA sugerida de la pila.
    uint64_t elf_stack_size = 0;  ///< ELF: tamano del segmento de pila.
    /// TLS PE: seccion+offset de @c __vx_tls_init (el TLS callback que aplica
    /// la plantilla por-hilo).  -1 = sin callback.  El emisor lo registra en
    /// @c AddressOfCallBacks del IMAGE_TLS_DIRECTORY.
    int tls_callback_section = -1;
    uint32_t tls_callback_off = 0;
    /// Arquitectura de destino (e_machine ELF / Machine PE): 0 => x86-64.
    /// EM_AARCH64 (183) para ARM 64-bit; el emisor lo propaga a LibPEparse.
    uint16_t machine = 0;
};

/**
 * @brief Llamada a funcion importada a resolver (solo PE).
 */
struct ImportCall {
    std::string dll;   ///< "KERNEL32.dll".
    std::string func;  ///< "ExitProcess".
    int call_section;  ///< indice de la seccion con el call.
    uint64_t call_off; ///< offset del @c FF 15 dentro de la seccion.
};

/**
 * @brief Como escribir el valor resuelto de una relocation.
 */
enum class RelocKind : uint8_t {
    REL32 = 0, ///< rel32 PC-relativo: *(int32*)site = target - (site_va+4).
    ABS64 = 1, ///< direccion absoluta 64-bit.
    IMM32 = 2, ///< inmediato 32-bit (p.ej. tamano de seccion).
    IMM64 = 3, ///< inmediato 64-bit.
    TPOFF32 =
        4, ///< TLS local-exec (ELF .o): R_X86_64_TPOFF32 contra un simbolo
           ///< STT_TLS de la seccion .tdata + addend = offset.  El sitio queda
           ///< SIN resolver en el .o; el `--link` calcula el TPOFF.
    SECREL32 =
        5, ///< TLS PE (Windows): *(int32*)site = offset del target DENTRO de su
           ///< seccion (.tls), no la VA.  El acceso suma este offset a la base
           ///< del bloque TLS (cargada desde el TEB en runtime).
    ARM64_CALL26 =
        6, ///< AArch64 BL/B: parchea imm26 = (target - site) >> 2 en la
           ///< instruccion de 32 bits del sitio (R_AARCH64_CALL26/JUMP26).
};

/**
 * @brief Objetivo de una relocation: la DIRECCION de una seccion+offset, o
 *        el TAMANO de una seccion (para simbolos de seccion estilo
 *        @c __start_/@c __stop_ del linker).
 */
struct RelocTarget {
    int section = 0;         ///< seccion objetivo.
    uint64_t offset = 0;     ///< offset dentro de la seccion (modo ADDR).
    bool is_size = false;    ///< true => el valor es el TAMANO de la seccion.
    bool is_end = false;     ///< true => el valor es VA(seccion)+tamano (fin).
    /// true => el valor es la BASE DE LA IMAGEN (`__ImageBase` en PE).
    bool is_imagebase = false;
    std::string extern_name; ///< no vacio => simbolo EXTERNO (libc); resuelve
                             ///< el linker.

    static RelocTarget addr(int sec, uint64_t off = 0) {
        RelocTarget t;
        t.section = sec;
        t.offset = off;
        return t;
    }
    /**
     * @brief La base de la imagen -- el simbolo `__ImageBase` de PE.
     *
     * No es una seccion: la base es donde empiezan las CABECERAS, antes de
     * cualquier seccion, asi que no se puede expresar como seccion+offset.  Lo
     * resuelve el emisor, que es quien la escribe en la cabecera.
     */
    static RelocTarget image_base() {
        RelocTarget t;
        t.is_imagebase = true;
        return t;
    }
    static RelocTarget size(int sec) {
        RelocTarget t;
        t.section = sec;
        t.is_size = true;
        return t;
    }
    /// Direccion del FINAL de la seccion (base + tamano) -- @c __stop_NAME.
    static RelocTarget end(int sec) {
        RelocTarget t;
        t.section = sec;
        t.is_end = true;
        return t;
    }
    /// Simbolo EXTERNO indefinido (malloc/free/abort...) -- solo .o/.obj.
    static RelocTarget extern_sym(const std::string &name) {
        RelocTarget t;
        t.extern_name = name;
        return t;
    }
};

/**
 * @brief Una relocation a resolver tras el layout (el writer conoce VA +
 *        tamano de cada seccion).
 */
struct AbsReloc {
    int site_section = 0;
    uint64_t site_off = 0;
    RelocTarget target;
    RelocKind kind = RelocKind::REL32;
    int64_t addend = 0;
};

/**
 * @class ObjectWriter
 * @brief Emisor configurable de ejecutables nativos (PE/ELF).
 */
class ObjectWriter {
  public:
    explicit ObjectWriter(ObjFormat fmt) : fmt_(fmt) {}

    /**
     * @brief Agrega una seccion definida por el usuario.
     * @param s Descriptor de la seccion.
     * @return Indice de la seccion (0-based).
     */
    int add_section(WriterSection s);

    /**
     * @brief Conveniencia: agrega @c .text (CODE|EXEC|READ) y fija la
     *        entrada al inicio de esa seccion.
     * @param code Bytes del codigo (incluye @c _start en offset 0).
     * @return Indice de la seccion.
     */
    int add_text(std::vector<uint8_t> code);

    /**
     * @brief Conveniencia: agrega @c .rodata (DATA|READ).
     * @param data Bytes inmutables.
     * @return Indice de la seccion.
     */
    int add_rodata(std::vector<uint8_t> data);

    /// Fija la configuracion de layout.
    void set_config(const LayoutConfig &c) { cfg_ = c; }

    /// TLS PE: ubicacion de @c __vx_tls_init (el callback que aplica la
    /// plantilla por-hilo).  El emisor lo registra en @c AddressOfCallBacks.
    void set_tls_callback(int section, uint32_t off) {
        cfg_.tls_callback_section = section;
        cfg_.tls_callback_off = off;
    }

    /// Fija el tipo de artefacto (EXEC por defecto, OBJECT relocatable).
    void set_output_kind(OutputKind k) { kind_ = k; }

    /// Fija la arquitectura (e_machine ELF / Machine PE): 0 => x86-64,
    /// 183 => AArch64.  El MISMO emisor produce x86-64 o ARM segun esto.
    void set_machine(uint16_t machine) { cfg_.machine = machine; }

    /// Fija la base de carga (image_base) del EXEC.  0 => default del formato.
    void set_image_base(uint64_t base) { cfg_.image_base = base; }

    /// Activa la emision de simbolos de DEPURACION (--aot-debug=1): en un EXEC,
    /// los @c add_symbol registrados se embeben ademas como @c .symtab / COFF
    /// symtab -> gdb/WinDbg/lldb muestran nombres en los backtraces.  OBJECT y
    /// SHARED ya llevan symtab por diseno; esto solo afecta a EXEC.
    void set_debug(bool on) { debug_ = on; }

    /// AOT x86-32: emite ELF32 (ET_EXEC, EM_386) en lugar de ELF64 para el
    /// EXEC.  El codegen (mode32) ya produjo bytes i386; esto solo cambia el
    /// contenedor.  Solo afecta a ELF EXEC (los .bin son crudos; PE32/.o32
    /// son follow-ups).
    void set_mode32(bool m) { mode32_ = m; }

    /// Fija la base de carga de un binario plano (.bin); solo afecta a las
    /// relocs ABS64 (REL32 es invariante a la base).
    void set_flat_base(uint64_t base) { flat_base_ = base; }

    /// Registra un simbolo exportado (solo OBJECT): nombre global en la
    /// tabla de simbolos del objeto, para que el linker externo lo resuelva.
    void add_symbol(const std::string &name, int section, uint64_t offset,
                    bool is_func = true) {
        ExportSym s;
        s.name = name;
        s.section = section;
        s.offset = offset;
        s.is_func = is_func;
        symbols_.push_back(std::move(s));
    }

    /// Fija el punto de entrada: seccion + offset.
    void set_entry(int section, uint64_t off) {
        entry_sec_ = section;
        entry_off_ = off;
    }

    /// Registra una llamada importada a parchear (solo PE).
    void add_import_call(ImportCall ic) { imports_.push_back(std::move(ic)); }

    /**
     * @brief Registra una relocation cross-seccion que el writer resuelve
     *        tras el layout (refs a datos, simbolos de seccion start/end/size).
     * @param site_section  seccion donde esta el campo a parchear.
     * @param site_off      offset del campo dentro de esa seccion.
     * @param target        objetivo (ADDR(sec,off) o SIZE(sec)).
     * @param kind          como escribir el valor (REL32/ABS64/IMM32/IMM64).
     * @param addend        desplazamiento adicional.
     */
    void add_reloc(int site_section, uint64_t site_off, RelocTarget target,
                   RelocKind kind, int64_t addend = 0) {
        AbsReloc r;
        r.site_section = site_section;
        r.site_off = site_off;
        r.target = target;
        r.kind = kind;
        r.addend = addend;
        relocs_.push_back(r);
    }

    /**
     * @brief Escribe el ejecutable a disco.
     * @param path Ruta de salida.
     * @param err  Recibe el mensaje de error si falla.
     * @return true en exito.
     */
    bool write(const std::string &path, std::string &err);

  private:
    ObjFormat fmt_;
    std::vector<WriterSection> sections_;
    LayoutConfig cfg_;
    int entry_sec_ = 0;
    uint64_t entry_off_ = 0;
    std::vector<ImportCall> imports_;
    std::vector<AbsReloc> relocs_;
    OutputKind kind_ = OutputKind::EXEC;
    std::vector<ExportSym> symbols_;
    uint64_t flat_base_ = 0; ///< base de carga (.bin)
    bool mode32_ = false;    ///< AOT x86-32 -> ELF32 EXEC
    bool debug_ = false;     ///< --aot-debug: symtab en el EXEC
};

} // namespace aot

#endif // AOT_OBJECT_WRITER_H
