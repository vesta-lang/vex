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
 * @file aot/object_writer.cpp
 * @brief  AOT.4 -- fachada C++ del emisor de ejecutables (sobre el shim
 * C).
 *
 * Convierte las estructuras C++ (@c WriterSection, @c LayoutConfig,
 * @c ImportCall) en los structs C planos de @c aot_emit_shim.h y despacha al
 * emisor PE o ELF.  No incluye LibPEparse: el shim es la unica frontera.
 */

#include "aot/object_writer.h"

#include <utility>

namespace aot {

int ObjectWriter::add_section(WriterSection s) {
    sections_.push_back(std::move(s));
    return static_cast<int>(sections_.size()) - 1;
}

int ObjectWriter::add_text(std::vector<uint8_t> code) {
    WriterSection s;
    s.name = ".text";
    s.flags = SecFlag::CODE | SecFlag::EXEC | SecFlag::READ;
    s.data = std::move(code);
    const int idx = add_section(std::move(s));
    set_entry(idx, 0); // por defecto el _start esta al inicio de .text
    return idx;
}

int ObjectWriter::add_rodata(std::vector<uint8_t> data) {
    WriterSection s;
    s.name = ".rodata";
    s.flags = SecFlag::DATA | SecFlag::READ;
    s.data = std::move(data);
    return add_section(std::move(s));
}

bool ObjectWriter::write(const std::string &path, std::string &err) {
    if (sections_.empty()) {
        err = "ObjectWriter: sin secciones";
        return false;
    }

    // Construir los AotSection (los punteros apuntan a los buffers de
    // sections_, que viven mientras dure esta llamada).
    std::vector<AotSection> csecs(sections_.size());
    for (size_t i = 0; i < sections_.size(); ++i) {
        const WriterSection &w = sections_[i];
        AotSection &c = csecs[i];
        c.name = w.name.c_str();
        c.flags = w.flags;
        c.data = w.data.empty() ? nullptr : w.data.data();
        c.size = static_cast<uint32_t>(w.data.size());
        c.bss_size = w.bss_size;
        c.vaddr = w.vaddr;
        c.align = w.align;
        c.at = w.at;
        c.order = w.order;
    }

    AotLayoutCfg ccfg;
    ccfg.image_base = cfg_.image_base;
    ccfg.section_align = cfg_.section_align;
    ccfg.file_align = cfg_.file_align;
    ccfg.stack_reserve = cfg_.stack_reserve;
    ccfg.stack_commit = cfg_.stack_commit;
    ccfg.heap_reserve = cfg_.heap_reserve;
    ccfg.heap_commit = cfg_.heap_commit;
    ccfg.pe_subsystem = cfg_.pe_subsystem;
    ccfg.elf_stack_vaddr = cfg_.elf_stack_vaddr;
    ccfg.elf_stack_size = cfg_.elf_stack_size;
    ccfg.tls_callback_section = cfg_.tls_callback_section;
    ccfg.tls_callback_off = cfg_.tls_callback_off;
    ccfg.machine = cfg_.machine;

    // TLS (thread_local): si hay una seccion TLS hace falta el cargador
    // dinamico (monta el bloque TLS + el thread pointer antes del entry) ->
    // forzar la ruta ELF dinamica aunque no haya imports de libc.
    bool has_tls = false;
    for (const AotSection &s : csecs)
        if (s.flags & AOT_SEC_TLS) {
            has_tls = true;
            break;
        }

    // Relocations cross-seccion (refs a datos / simbolos de seccion).  El
    // shim las resuelve tras el layout.
    std::vector<AotReloc> crelocs(relocs_.size());
    for (size_t i = 0; i < relocs_.size(); ++i) {
        const AbsReloc &r = relocs_[i];
        AotReloc &c = crelocs[i];
        c.site_section = r.site_section;
        c.site_off = r.site_off;
        c.target_section = r.target.section;
        c.target_off = r.target.offset;
        c.target_is_size = r.target.is_size ? 1 : 0;
        c.target_is_end = r.target.is_end ? 1 : 0;
        c.kind = static_cast<int>(r.kind); // espejo de AOT_RELOC_*
        c.addend = r.addend;
        // El puntero apunta al std::string en relocs_ (vive durante write()).
        c.extern_name = r.target.extern_name.empty()
                            ? nullptr
                            : r.target.extern_name.c_str();
    }
    const AotReloc *crel_ptr = crelocs.empty() ? nullptr : crelocs.data();
    const int crel_n = static_cast<int>(crelocs.size());

    char errbuf[256] = {0};
    int ok = 0;

    // --aot-debug=1: fija los simbolos de funcion (nombre->VA) para que el
    // emisor de EXEC (ELF/PE) y de SHARED (.dll) embeban un .symtab ELF /
    // symtab COFF. Se declara aqui (scope de la funcion) para sobrevivir a
    // TODOS los caminos de emit (incluidos los early-return de
    // SHARED/OBJECT/FLAT_BIN).  Se llama SIEMPRE (con nullptr si no aplica)
    // para no arrastrar estado de un emit anterior.  OBJECT ya lleva symtab por
    // diseno -> no se le fija aqui.
    std::vector<AotSym> dbg_csyms;
    std::vector<std::string> dbg_hold;
    if (debug_ && (kind_ == OutputKind::EXEC || kind_ == OutputKind::SHARED) &&
        !symbols_.empty()) {
        dbg_csyms.resize(symbols_.size());
        dbg_hold.resize(symbols_.size());
        for (size_t i = 0; i < symbols_.size(); ++i) {
            dbg_hold[i] = symbols_[i].name;
            dbg_csyms[i].name = dbg_hold[i].c_str();
            dbg_csyms[i].section = symbols_[i].section;
            dbg_csyms[i].offset = symbols_[i].offset;
            dbg_csyms[i].is_func = symbols_[i].is_func ? 1 : 0;
        }
        aot_set_debug_symbols(dbg_csyms.data(),
                              static_cast<int>(dbg_csyms.size()));
    } else {
        aot_set_debug_symbols(nullptr, 0);
    }

    // OBJECT relocatable: sin _start, sin imports; relocs como REGISTROS +
    // symtab.  v1: solo ELF (.o).  COFF (.obj) pendiente.
    if (kind_ == OutputKind::OBJECT) {
        std::vector<AotSym> csyms(symbols_.size());
        std::vector<std::string> hold(symbols_.size());
        for (size_t i = 0; i < symbols_.size(); ++i) {
            hold[i] = symbols_[i].name;
            csyms[i].name = hold[i].c_str();
            csyms[i].section = symbols_[i].section;
            csyms[i].offset = symbols_[i].offset;
            csyms[i].is_func = symbols_[i].is_func ? 1 : 0;
        }
        const AotSym *sym_ptr = csyms.empty() ? nullptr : csyms.data();
        const int sym_n = static_cast<int>(csyms.size());
        if (fmt_ == ObjFormat::ELF)
            ok = mode32_ ? aot_emit_elf32_obj(path.c_str(), csecs.data(),
                                              static_cast<int>(csecs.size()),
                                              crel_ptr, crel_n, sym_ptr, sym_n,
                                              errbuf, sizeof(errbuf))
                         : (cfg_.machine == 183 /* EM_AARCH64 */
                                ? aot_emit_elf_obj_arm64(
                                      path.c_str(), csecs.data(),
                                      static_cast<int>(csecs.size()), crel_ptr,
                                      crel_n, sym_ptr, sym_n, errbuf,
                                      sizeof(errbuf))
                                : aot_emit_elf_obj(path.c_str(), csecs.data(),
                                                   static_cast<int>(
                                                       csecs.size()),
                                                   crel_ptr, crel_n, sym_ptr,
                                                   sym_n, errbuf,
                                                   sizeof(errbuf)));
        else /* PE -> COFF .obj (AMD64 o i386 segun mode32) */
            ok = mode32_ ? aot_emit_coff32_obj(path.c_str(), csecs.data(),
                                               static_cast<int>(csecs.size()),
                                               crel_ptr, crel_n, sym_ptr, sym_n,
                                               errbuf, sizeof(errbuf))
                         : aot_emit_coff_obj(path.c_str(), csecs.data(),
                                             static_cast<int>(csecs.size()),
                                             crel_ptr, crel_n, sym_ptr, sym_n,
                                             errbuf, sizeof(errbuf));
        if (!ok) {
            err = errbuf[0] ? errbuf : "ObjectWriter: error obj";
            return false;
        }
        return true;
    }

    // FLAT_BIN: binario plano sin cabecera (bootloader/ROM/firmware).
    // Format-agnostico: solo concatena secciones + resuelve relocs contra
    // la base fija.  No usa _start/imports/symtab.
    if (kind_ == OutputKind::FLAT_BIN) {
        ok = aot_emit_flat_bin(path.c_str(), flat_base_, csecs.data(),
                               static_cast<int>(csecs.size()), crel_ptr, crel_n,
                               errbuf, sizeof(errbuf));
        if (!ok) {
            err = errbuf[0] ? errbuf : "ObjectWriter: error flat bin";
            return false;
        }
        return true;
    }

    // SHARED: libreria compartida (.so ELF / .dll PE).
    if (kind_ == OutputKind::SHARED) {
        std::vector<AotSym> csyms(symbols_.size());
        std::vector<std::string> hold(symbols_.size());
        for (size_t i = 0; i < symbols_.size(); ++i) {
            hold[i] = symbols_[i].name;
            csyms[i].name = hold[i].c_str();
            csyms[i].section = symbols_[i].section;
            csyms[i].offset = symbols_[i].offset;
            csyms[i].is_func = symbols_[i].is_func ? 1 : 0;
        }
        const AotSym *sym_ptr = csyms.empty() ? nullptr : csyms.data();
        const int sym_n = static_cast<int>(csyms.size());
        if (fmt_ == ObjFormat::ELF)
            ok = aot_emit_elf_so(
                path.c_str(), csecs.data(), static_cast<int>(csecs.size()),
                crel_ptr, crel_n, sym_ptr, sym_n, errbuf, sizeof(errbuf));
        else /* PE -> .dll */
            ok =
                aot_emit_pe_dll(path.c_str(), &ccfg, csecs.data(),
                                static_cast<int>(csecs.size()), crel_ptr,
                                crel_n, sym_ptr, sym_n, errbuf, sizeof(errbuf));
        if (!ok) {
            err = errbuf[0] ? errbuf : "ObjectWriter: error shared";
            return false;
        }
        return true;
    }

    if (fmt_ == ObjFormat::PE) {
        std::vector<AotImport> cimps(imports_.size());
        for (size_t i = 0; i < imports_.size(); ++i) {
            const ImportCall &ic = imports_[i];
            cimps[i].dll = ic.dll.c_str();
            cimps[i].func = ic.func.c_str();
            cimps[i].call_section = ic.call_section;
            cimps[i].call_off = ic.call_off;
        }
        if (mode32_) {
            // AOT x86-32: EXEC PE32 (i386) en lugar de PE32+.
            ok = aot_emit_pe32(path.c_str(), &ccfg, csecs.data(),
                               static_cast<int>(csecs.size()), entry_sec_,
                               entry_off_,
                               cimps.empty() ? nullptr : cimps.data(),
                               static_cast<int>(cimps.size()), crel_ptr, crel_n,
                               errbuf, sizeof(errbuf));
        } else {
            ok = aot_emit_pe(path.c_str(), &ccfg, csecs.data(),
                             static_cast<int>(csecs.size()), entry_sec_,
                             entry_off_, cimps.empty() ? nullptr : cimps.data(),
                             static_cast<int>(cimps.size()), crel_ptr, crel_n,
                             errbuf, sizeof(errbuf));
        }
    } else if (mode32_ && (!imports_.empty() || has_tls)) {
        // AOT x86-32 dinamico: ELF32 EXEC (EM_386) con interp -> el cargador
        // monta el bloque TLS y resuelve los imports de libc.so.6 (i386).  Se
        // toma esta ruta tambien sin imports cuando hay TLS (necesita el
        // cargador para montar el bloque thread-local antes del entry).
        std::vector<AotImport> cimps(imports_.size());
        for (size_t i = 0; i < imports_.size(); ++i) {
            const ImportCall &ic = imports_[i];
            cimps[i].dll = ic.dll.c_str();
            cimps[i].func = ic.func.c_str();
            cimps[i].call_section = ic.call_section;
            cimps[i].call_off = ic.call_off;
        }
        ok = aot_emit_elf32_dynexec(
            path.c_str(), &ccfg, csecs.data(), static_cast<int>(csecs.size()),
            entry_sec_, entry_off_, crel_ptr, crel_n, cimps.data(),
            static_cast<int>(cimps.size()), errbuf, sizeof(errbuf));
    } else if (!mode32_ && (!imports_.empty() || has_tls)) {
        // AOT.2.exec slice 2: ELF EXEC (64-bit) PIE dinamico -- cuando importa
        // libc (eager-GOT) o cuando usa TLS (necesita el cargador dinamico para
        // montar el bloque thread-local).  (el caso 32-bit lo cubre arriba)
        std::vector<AotImport> cimps(imports_.size());
        for (size_t i = 0; i < imports_.size(); ++i) {
            const ImportCall &ic = imports_[i];
            cimps[i].dll = ic.dll.c_str(); // ignorado (libc.so.6)
            cimps[i].func = ic.func.c_str();
            cimps[i].call_section = ic.call_section;
            cimps[i].call_off = ic.call_off;
        }
        ok = aot_emit_elf_dynexec(
            path.c_str(), &ccfg, csecs.data(), static_cast<int>(csecs.size()),
            entry_sec_, entry_off_, crel_ptr, crel_n, cimps.data(),
            static_cast<int>(cimps.size()), errbuf, sizeof(errbuf));
    } else if (mode32_) {
        // AOT x86-32: EXEC ELF32 estatico (ET_EXEC, EM_386).  El codegen ya
        // produjo bytes i386; el stub _start sale via int 0x80.
        ok = aot_emit_elf32(
            path.c_str(), &ccfg, csecs.data(), static_cast<int>(csecs.size()),
            entry_sec_, entry_off_, crel_ptr, crel_n, errbuf, sizeof(errbuf));
    } else {
        ok = aot_emit_elf(path.c_str(), &ccfg, csecs.data(),
                          static_cast<int>(csecs.size()), entry_sec_,
                          entry_off_, crel_ptr, crel_n, errbuf, sizeof(errbuf));
    }

    // Reset del estado global de simbolos de debug (el emit ya termino).
    aot_set_debug_symbols(nullptr, 0);

    if (!ok) {
        err = errbuf[0] ? errbuf : "ObjectWriter: error desconocido";
        return false;
    }
    return true;
}

} // namespace aot
