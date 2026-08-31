/**
 * @file loader.cpp
 * @brief Implementacion del loader de ejecutables VELB para VestaVM.
 *
 * Implementa @c loader::Loader: @c parse_velb_header(), @c
 * parse_table_spaces(),
 * @c parser_table_sections(), @c parser_import_table(), @c parse_velb(),
 * @c load_executable() y @c create_vm_instance().
 * Valida el header, reserva memoria en el @c ArenaManager y crea el @c
 * ProcessVM con el PC inicializado segun @c init_pc del ejecutable.
 */
#include "util/env_flags.h"
#include "util/file_read.h"
#include "loader/loader.h"
#include <algorithm> // UCRT64: no transitivo

#include <cstdio>
#include <cstdlib>

#include "analysis/facts/alignment.h"
#include <cstring>
#include "debug/debug_info.h"
#include "ir/ssa_ir_serialize.h"
#include "emmit/bytereader.h"
#include "emmit/struct_context.h"
#include "ffi/virtual_lib_registry.h"
#include "runtime/manager_runtime.h"
#include "runtime/decode_table.h" // rebase_bytecode_addresses usa decode tables
#include "runtime/decode_instruction.h" // InstrFormat para size_from_mode
#include "ffi/vesta_plugin.h"
#include "cli/sync_io.h"
#include "jit/auto_jit.h"            // eager-compile main + jit_entry_fn
#include "jit/jit_compile_options.h" // CompileResult
#include "jit/jit_facts.h"           // base de hechos compartida por el modulo
#include "jit/inline_asm_trampoline.h" // inc.6: trampolines de inline-asm para interp

/*
 *  Loader
 *  ??? load_executable(path)
 *  ?     ??? parse_velb_header()
 *  ?     ??? load_spaces()
 *  ?     ??? load_sections()
 *  ?     ??? resolve_labels()
 *  ?     ??? build_runtime_context()
 *  ??? create_vm_instance()
 */
namespace loader {
Loader::Loader(runtime::ManageVM &instance_manager)
    : instance_manager(instance_manager) {}

std::string Loader::read_string_at(const std::vector<uint8_t> &blob,
                                   uint64_t offset) {
    std::string result;

    while (offset < blob.size() && blob[offset] != 0) {
        result.push_back(static_cast<char>(blob[offset]));
        offset++;
    }

    return result;
}

std::vector<std::string>
Loader::read_all_strings(const std::vector<uint8_t> &blob) {
    std::vector<std::string> result;
    uint64_t i = 0;

    while (i < blob.size()) {
        std::string s;

        while (i < blob.size() && blob[i] != 0) {
            s.push_back(static_cast<char>(blob[i]));
            i++;
        }

        result.push_back(s);

        // saltar el '\0'
        i++;
    }

    return result;
}

std::string Loader::read_string_at(ByteReader &reader, uint64_t offset) {
    // Guardamos el offset original
    uint64_t original = reader.offset;

    // Nos movemos al offset solicitado
    reader.seek(offset);

    // Leemos la cadena
    std::string result;
    while (!reader.eof() && reader.input[reader.offset] != 0) {
        result.push_back(static_cast<char>(reader.input[reader.offset]));
        reader.offset++;
    }

    // Restauramos el offset original
    reader.offset = original;

    return result;
}

void Loader::parse_velb_header(Executable &exe, ByteReader &reader) {
    if (reader.input.size() < sizeof(HeaderVELB)) {
        throw_error_at(
            ErrorKind::TruncatedHeader,
            "El ejecutable es demasiado pequeno para contener un header VELB",
            reader);
    }

    exe.header.magic.firma = reader.read32();
    if (exe.header.magic.firma != MAGIC_NUMBER_VELB) {
        throw_error_at(ErrorKind::InvalidMagic, "Magic number VELB invalido",
                       reader);
    }

    exe.header.format_v = reader.read32();
    if (VERSION_VELB != exe.header.format_v) {
        throw_error_at(ErrorKind::InvalidVersion,
                       "Vesrion invalida de bytecode, la version actual es " +
                           std::to_string(VERSION_VELB) +
                           " pero la encontrada fue: " +
                           std::to_string(exe.header.format_v),
                       reader);
    }

    // La version de la VM debe estar dentro del rango [min_v, max_v] exigido
    // por el ejecutable.
    exe.header.max_v = reader.read32();
    exe.header.min_v = reader.read32();
    if (exe.header.max_v < VERSION_VM || exe.header.min_v > VERSION_VM) {
        throw_error_at(
            ErrorKind::InvalidVersion,
            "Vesrion invalida de maquina virtual, la version actual es " +
                std::to_string(VERSION_VM) +
                " pero la encontrada exigida por el codigo es: " +
                std::to_string(exe.header.min_v) + " - " +
                std::to_string(exe.header.max_v),
            reader);
    }

    exe.header.checksum = reader.read64();
    exe.header.flags = reader.read64();
    exe.header.timestamp = reader.read64();
    exe.header.arch = reader.read32();

    // cantidad de espacios de direcciones
    exe.header.count = reader.read32();

    // offset a la tabla de secciones
    exe.header.table_offset = reader.read64();

    // cantidad de espacios de direcciones que viene despues del header.
    exe.header.n_spaces = reader.read64();
    if (exe.header.n_spaces == 0) {
        throw_error_at(
            ErrorKind::NotFoundSpacesAddress,
            "no se a definido la cantidad de espacios de direcciones.", reader);
    }
    exe.header.address_spaces = new table_spaces_address[exe.header.count];

    // offset a la tabla de strings
    exe.header.offset_section_strings = reader.read64();

    // PC por el que empezar la ejecuccion
    exe.init_pc = exe.header.start_pc = reader.read64();

    // offset a la tabla de importacion
    exe.header.offset_import_table = reader.read64();

    // offset a la tabla de etiquetas o labels
    exe.header.offset_label_table = reader.read64();

    // obtener cuantas entradas tiene la tabla de importacion
    exe.header.size_import_table = reader.read32();

    // obtener cuantas labels tiene la tabla de labels
    exe.header.size_label_table = reader.read32();

    // campos de depuracion (deben leerse para mantener sincronizacion con el
    // writer)
    exe.header.offset_debug_section = reader.read64();
    exe.header.size_debug_section = reader.read32();
    exe.header.debug_level = reader.read8();
    (void)reader.read8(); // _debug_pad[0]
    (void)reader.read8(); // _debug_pad[1]
    (void)reader.read8(); // _debug_pad[2]

    // campos nuevos de la tabla de relocations.  Bumped VERSION_VELB
    // a 0x2 para indicar el cambio de layout.  Si VERSION_VELB esta en
    // este file ya cumple, podemos leer estos campos sin riesgo.
    exe.header.offset_reloc_table = reader.read64();
    exe.header.size_reloc_table = reader.read32();
    /* VERSION_VELB 0x3 añade offset_ir_section + size_ir_section
     * en los mismos 12 bytes que antes eran _reloc_pad.  En binarios
     * v2 (donde _reloc_pad era zero-init) estos campos quedan a 0
     * -> no IR section, JIT deshabilitado para ese modulo.  Forward
     * compatible. */
    exe.header.offset_ir_section = reader.read64();
    exe.header.size_ir_section = reader.read32();

    /*  E.1 (VERSION_VELB 0x4): offset_stackmap_section +
     * size_stackmap_section.  Contienen la seccion VSMP con los stackmaps
     * precisos del interprete.  0 = sin stackmaps (GC preciso no-op). */
    exe.header.offset_stackmap_section = reader.read64();
    exe.header.size_stackmap_section = reader.read32();
    (void)reader.read32(); // _stackmap_pad (mantiene el header en 160 bytes)

    // el header siempre debe estar alineado a 16 bytes
    while (reader.offset % 16 != 0) {
        (void)reader.read8();
    }
}

void Loader::parse_table_spaces(Executable &exe, ByteReader &reader) {
    for (size_t i = 0; i < exe.header.n_spaces; i++) {
        if (exe.header.address_spaces == nullptr) {
            throw_error_at(ErrorKind::InvalidFormat,
                           "No se a podido encontrar los espacios de "
                           "direcciones por algun motivo desconocido.",
                           reader);
        }

        // direccion de inicio del espacio de direcciones
        exe.header.address_spaces[i].address.address_init = reader.read64();

        // direccion final del espacio de direcciones
        exe.header.address_spaces[i].address.address_final = reader.read64();

        // offser a la seccion metada de strings
        exe.header.address_spaces[i].offset_section_strings = reader.read64();

        // offset al bytecode para el espacio de direcciones
        exe.header.address_spaces[i].offset_bytecode = reader.read64();

        Space space{};

        // indicamos el espacio de direcciones
        space.range.address_init =
            exe.header.address_spaces[i].address.address_init;
        space.range.address_final =
            exe.header.address_spaces[i].address.address_final;

        // offset en el bytecode
        space.file_offset = exe.header.address_spaces[i].offset_bytecode;

        // obtenemos el nombre del espacio de direcciones:
        space.name_section = read_string_at(
            reader, exe.header.address_spaces[i].offset_section_strings);

        exe.spaces.push_back(space);
    }

    // la tabla de espacios siempre debe estar alineado a 16 bytes para que se
    // pueda encontrar la tabla de secciones.
    while (reader.offset % 16 != 0) {
        (void)reader.read8();
    }
}

Space *Loader::find_space_for_section(Executable &exe, const Section &sec) {
    for (auto &space : exe.spaces) {
        if (sec.memory.address_init >= space.range.address_init &&
            sec.memory.address_final <= space.range.address_final) {
            return &space;
        }
    }
    return nullptr;
}

void Loader::parser_table_sections(Executable &exe, ByteReader &reader) {
    // realizamos un punto de control completo para parsear la tabla de
    // secciones.
    ByteReader reader_child =
        reader.subreader(exe.header.count * sizeof(section_range_memory));

    // mover el cursor a la tabla de secciones
    reader_child.seek(exe.header.table_offset);

    for (size_t i = 0; i < exe.header.count; i++) {
        Section sec;
        sec.memory.address_init = reader_child.read64();
        sec.memory.address_final = reader_child.read64();
        uint64_t offset_string = reader_child.read64();
        try {
            // aqui usamos al padre, por que el offset de la tabla de strings no
            // puede accederse con el cursor hijo, ya que el cursor hijo solo
            // puede acceder a la tabla de seeciones mientras que el cursor
            // padre puede acceder a cualquier parte del bytecode
            sec.name = read_string_at(reader, offset_string);
        } catch (const ByteReaderError &e) {
            throw_error_at(ErrorKind::InvalidFormat,
                           std::string("Ha ocurrido un error de lectura al "
                                       "leer la tabla de strings: '") +
                               e.what() + "'",
                           reader_child);
        }
        sec.size_real = sec.memory.address_final - sec.memory.address_init;

        // Buscar el espacio al que pertenece
        Space *space = find_space_for_section(exe, sec);

        if (!space) {
            throw_error_at(ErrorKind::InvalidFormat,
                           "La seccion '" + sec.name +
                               "' no pertenece a ningun espacio de direcciones",
                           reader_child);
        }

        // calcular file offset de la seccion
        sec.file_offset = space->file_offset +
                          (sec.memory.address_init - space->range.address_init);

        // Insertar la seccion en el espacio correspondiente
        space->add_section(sec);
        exe.sections.push_back(&space->table_section[sec.name]);
    }

    // es muy importante saber donde empieza el bytecode real generado por el
    // ensamblador para que el loader pueda parchearlo y cargarlo de forma
    // correcta.
    exe.offset_real_bytecode =
        (exe.header.table_offset +
         exe.sections.size() * sizeof(section_range_memory)
         // debemos calcular el final de la tabla de secciones que es
         // donde empieza el bytecode real dentro del archivo
        );
}

void Loader::parser_import_table(Executable &exe, ByteReader &reader) {
    /**
     * Si el offset es 0 entonces no hay tabla de importacion.
     */
    if (exe.header.offset_import_table == 0) {
        return;
    }

    // nos desplazamos hasta la tabla de importacion moviendo el cursor
    // al offset indicado
    reader.seek(exe.header.offset_import_table);

    std::vector<entry_import_table> import_table_from_file;

    // obtener la tabla de importacion del archivo:
    for (size_t i = 0; i < exe.header.size_import_table; i++) {
        entry_import_table entry;
        entry.offset_module_string = reader.read32();
        entry.offset_function_string = reader.read32();
        entry.offset_signature_string = reader.read32();
        entry.offset_bytecode = reader.read32();
        import_table_from_file.push_back(entry);
    }

    // BUG fix: solo patchear los call sites de ESTE modulo, no los
    // acumulados de modulos previos.  ffi_loader.imports es un map
    // global que persiste entre cargas; si simplemente llamamos
    // resolve_all() tras cada parser_import_table, el bytecode del
    // modulo NUEVO se patchea en TODOS los offsets registrados
    // (incluidos los del CALLER previo), corrompiendo bytes
    // arbitrarios.  Sintoma: plugin halt mid-instruccion porque
    // un callsite de caller (e.g. offset 0x4D para vio_print)
    // sobreescribe la imm de algun mov en el plugin con un host
    // pointer (la addr resuelta de vio_print).
    //
    // Fix: separar registro (acumular import key + symbolos) de
    // parcheo (solo en los offsets DE ESTE modulo).  Recolectamos
    // los pares (key, offset_bytecode) en un vector local, y al
    // final iteramos resolviendo y parcheando solo esos.  Las
    // entradas del global imports quedan como cache de simbolos
    // resueltos para que no haya que volver a llamar dlsym.
    struct LocalPatchSite {
        ffi::NativeImportKey key;
        uint32_t offset_bytecode;
    };
    std::vector<LocalPatchSite> local_sites;
    local_sites.reserve(import_table_from_file.size());
    for (auto &imp : import_table_from_file) {
        uint32_t module_idx = ffi_loader.intern_module(
            read_string_at(reader, imp.offset_module_string));
        uint32_t function_idx = ffi_loader.intern_function(
            read_string_at(reader, imp.offset_function_string));

        // si el metodo no tiene firma no se usa firma
        std::string sig = "";
        uint32_t sig_idx = ffi_loader.intern_signature(sig);

        ffi::NativeImportKey key{module_idx, function_idx, sig_idx};

        auto &entry = ffi_loader.imports[key]; // crea si no existe
        if (entry.patch_sites.empty()) {
            entry.key.module_idx = module_idx;
            entry.key.function_idx = function_idx;
            entry.key.signature_idx = sig_idx;
        }
        entry.patch_sites.push_back(imp.offset_bytecode);
        local_sites.push_back({key, imp.offset_bytecode});
    }

    // Resolver simbolos para CADA key (carga modulo nativo si no esta
    // ya cargado, dlsym del simbolo) y patchear en bytecode SOLO los
    // offsets de ESTE modulo.
    for (const auto &site : local_sites) {
        auto it = ffi_loader.imports.find(site.key);
        if (it == ffi_loader.imports.end()) continue;
        auto &entry = it->second;
        if (entry.resolved_ptr == nullptr) {
            const std::string &mod_name =
                ffi_loader.modules[site.key.module_idx];
            const std::string &func_name =
                ffi_loader.functions[site.key.function_idx];
            /* Sprint MC.20 / B.1: virtual lib registry FIRST.  Permite
             * que libs como "vesta_runtime" y "vesta_comptime" sean
             * resueltas via punteros C registrados in-process sin
             * pasar por LoadLibrary. */
            void *fn = ffi::lookup_virtual_fn(mod_name, func_name);
            if (!fn) {
                void *mod = ffi_loader.load_native_module(mod_name);
                fn = ffi_loader.resolve_native_symbol(mod, func_name);
            }
            entry.resolved_ptr = fn;
        }
        const uint64_t real_offset =
            static_cast<uint64_t>(site.offset_bytecode) +
            exe.offset_real_bytecode;
        ffi::patch_call(exe.bytecode.data(), static_cast<uint32_t>(real_offset),
                        entry.resolved_ptr);
    }

    // construir la tabla de callbacks de la API del plugin y notificar
    // a los modulos que exporten "vesta_init".
    this->plugin_api = {};
    this->plugin_api.api_version = VESTA_PLUGIN_API_VERSION;
    this->plugin_api.manager = static_cast<VestaManager *>(&instance_manager);

    this->plugin_api.create_vm = [](VestaManager *mgr, uint32_t n) -> uint64_t {
        return static_cast<runtime::ManageVM *>(mgr)->create_vm(
            static_cast<size_t>(n));
    };
    this->plugin_api.destroy_vm = [](VestaManager *mgr, uint64_t vm_id) -> int {
        return static_cast<runtime::ManageVM *>(mgr)->destroy_vm(vm_id) ? 1 : 0;
    };
    this->plugin_api.get_vm = [](VestaManager *mgr,
                                 uint64_t vm_id) -> VestaVM_t * {
        return static_cast<VestaVM_t *>(
            static_cast<runtime::ManageVM *>(mgr)->get_vm(vm_id));
    };
    this->plugin_api.has_vm = [](VestaManager *mgr, uint64_t vm_id) -> int {
        return static_cast<runtime::ManageVM *>(mgr)->has_vm(vm_id) ? 1 : 0;
    };
    this->plugin_api.vm_count = [](VestaManager *mgr) -> uint64_t {
        return static_cast<uint64_t>(
            static_cast<runtime::ManageVM *>(mgr)->vm_count());
    };
    this->plugin_api.start_vm = [](VestaVM_t *vm) {
        static_cast<runtime::VM *>(vm)->start();
    };
    this->plugin_api.stop_vm = [](VestaVM_t *vm) {
        static_cast<runtime::VM *>(vm)->stop();
    };
    this->plugin_api.wait_vm = [](VestaVM_t *vm) {
        static_cast<runtime::VM *>(vm)->wait();
    };
    this->plugin_api.spawn_process = [](VestaVM_t *vm, uint32_t *out_sched,
                                        uint64_t *out_pid) {
        GlobalPID gid = static_cast<runtime::VM *>(vm)->spawn_process();
        if (out_sched) *out_sched = gid.scheduler_id;
        if (out_pid) *out_pid = gid.local_pid;
    };
    this->plugin_api.make_ready = [](VestaVM_t *vm, uint32_t sched_id,
                                     uint64_t local_pid) {
        GlobalPID pid{sched_id, local_pid};
        static_cast<runtime::VM *>(vm)->make_ready(pid);
    };
    this->plugin_api.vm_read_bytes = [](uint64_t proc_ptr, uint64_t vm_addr,
                                        void *dst, uint64_t len) -> uint64_t {
        auto *proc = reinterpret_cast<runtime::ProcessVM *>(proc_ptr);
        proc->vm_mem.read_bytes(vm_addr, dst, static_cast<size_t>(len));
        return len;
    };
    this->plugin_api.vm_write_bytes = [](uint64_t proc_ptr, uint64_t vm_addr,
                                         const void *src,
                                         uint64_t len) -> uint64_t {
        auto *proc = reinterpret_cast<runtime::ProcessVM *>(proc_ptr);
        proc->vm_mem.write_bytes(vm_addr, src, static_cast<size_t>(len));
        return len;
    };
    this->plugin_api.log = [](const char *msg) {
        vesta::print_threadsafe(std::string(msg));
    };

    // GC roots externos via write-barrier.  Las colecciones nativas
    // que retienen GcHandles (e.g. ArrayList<string>) llaman a estas
    // APIs para que el GC del proceso activo no colecte los objetos
    // referenciados desde fuera de su HandleTable de bytecode.
    this->plugin_api.gc_addref = [](uint64_t proc_ptr, uint64_t gc_handle) {
        if (proc_ptr == 0 || gc_handle == 0) return;
        auto *proc = reinterpret_cast<runtime::ProcessVM *>(proc_ptr);
        proc->gc_heap.gc_addref(static_cast<gc::GcHandle>(gc_handle));
    };
    this->plugin_api.gc_release = [](uint64_t proc_ptr, uint64_t gc_handle) {
        if (proc_ptr == 0 || gc_handle == 0) return;
        auto *proc = reinterpret_cast<runtime::ProcessVM *>(proc_ptr);
        proc->gc_heap.gc_release(static_cast<gc::GcHandle>(gc_handle));
    };
    this->plugin_api.api_version = VESTA_PLUGIN_API_VERSION;

    this->ffi_loader.call_plugin_inits(&this->plugin_api);
}

std::unique_ptr<Executable> Loader::parse_velb(std::vector<uint8_t> bytecode) {
    auto exe = std::make_unique<Executable>();
    exe->bytecode = bytecode;

    ByteReader reader(exe->bytecode);

    // parseamos el header
    parse_velb_header(*exe, reader);

    // parseamos la tabla de espacio de direcciones que siempre va despues del
    // header
    parse_table_spaces(*exe, reader);

    // parseamos la tabla de secciones, requiere haber parseado previamente la
    // tabla de espacios de direcciones, ya que se va a anadir a estos.
    parser_table_sections(*exe, reader);

    // parseamos la tabla de importacion.
    parser_import_table(*exe, reader);

    // Cargar la seccion debug (DVBG) si esta presente.  El header
    // del .velb tiene `offset_debug_section` + `size_debug_section`
    // emitidos por el linker cuando se compila con --vx-debug.
    // Construimos un DebugInfo a partir del blob; el debugger
    // accede luego via Executable::debug_info para resolver
    // breakpoints por (file, line) o devolver line info de un PC.
    if (exe->header.offset_debug_section != 0 &&
        exe->header.size_debug_section > 0 &&
        exe->header.offset_debug_section + exe->header.size_debug_section <=
            exe->bytecode.size()) {
        const uint8_t *blob =
            exe->bytecode.data() + exe->header.offset_debug_section;
        const size_t blob_size = exe->header.size_debug_section;
        exe->debug_info = std::make_unique<debug::DebugInfo>(blob, blob_size);
        if (!exe->debug_info->valid()) {
            // Magic/version invalido: descartar para no confundir al
            // debugger.  Si esto ocurre, el linker emitio mal la
            // seccion -- bug a investigar.
            exe->debug_info.reset();
        }
    }

    //  E.1: cargar la seccion VSMP (stackmaps precisos del interprete)
    // si esta presente.  Formato: magic "VSMP" + version + count + entries.
    // Si el magic/version es invalido, dejamos la tabla vacia (GC preciso
    // no-op, fallback al conservador -- backward compatible).
    if (exe->header.offset_stackmap_section != 0 &&
        exe->header.size_stackmap_section >= 12 &&
        static_cast<size_t>(exe->header.offset_stackmap_section) +
                exe->header.size_stackmap_section <=
            exe->bytecode.size()) {
        const size_t base =
            static_cast<size_t>(exe->header.offset_stackmap_section);
        const size_t end = base + exe->header.size_stackmap_section;
        const auto &bc = exe->bytecode;
        auto rd16 = [&](size_t off) {
            return static_cast<uint16_t>(bc[off]) |
                   (static_cast<uint16_t>(bc[off + 1]) << 8);
        };
        auto rd32 = [&](size_t off) {
            return static_cast<uint32_t>(bc[off]) |
                   (static_cast<uint32_t>(bc[off + 1]) << 8) |
                   (static_cast<uint32_t>(bc[off + 2]) << 16) |
                   (static_cast<uint32_t>(bc[off + 3]) << 24);
        };
        // Validar magic "VSMP" + version.
        if (bc[base] == 'V' && bc[base + 1] == 'S' && bc[base + 2] == 'M' &&
            bc[base + 3] == 'P' &&
            rd16(base + 4) == loader::INTERP_STACKMAP_VERSION) {
            const uint32_t entry_count = rd32(base + 8);
            if (entry_count <= 10'000'000u) { /* sanity */
                size_t cur = base + 12;
                for (uint32_t k = 0; k < entry_count; ++k) {
                    if (cur + 6 > end) break; /* pc(4) + slot_count(2) */
                    loader::InterpStackmap sm;
                    sm.pc_offset = rd32(cur);
                    cur += 4;
                    const uint16_t slot_count = rd16(cur);
                    cur += 2;
                    if (cur + static_cast<size_t>(slot_count) * 2 > end) break;
                    sm.slots.reserve(slot_count);
                    for (uint16_t s = 0; s < slot_count; ++s) {
                        loader::InterpStackmapSlot sl;
                        sl.location = bc[cur++];
                        sl.gc_kind =
                            static_cast<jit::StackmapGcKind>(bc[cur++]);
                        sm.slots.push_back(sl);
                    }
                    exe->interp_stackmaps.add(std::move(sm));
                }
                exe->interp_stackmaps.finalize();
            }
        }
    }

    // parsear la tabla de relocations al final del archivo (si existe).
    // Cada entry son 24 bytes packed: bytecode_offset (u64) + target_value
    // (u64) + type (u8) + pad (u8x7).  El header indica offset y count.
    if (exe->header.offset_reloc_table != 0 &&
        exe->header.size_reloc_table > 0 &&
        exe->header.offset_reloc_table + 24ULL * exe->header.size_reloc_table <=
            exe->bytecode.size()) {
        const size_t off = exe->header.offset_reloc_table;
        const size_t count = exe->header.size_reloc_table;
        exe->velb_relocations.reserve(count);
        ByteReader rr(exe->bytecode);
        rr.seek(off);
        for (size_t i = 0; i < count; ++i) {
            entry_relocation_table e{};
            e.bytecode_offset = rr.read64();
            e.target_value = rr.read64();
            e.type = rr.read8();
            for (int p = 0; p < 7; ++p)
                e._pad[p] = rr.read8();
            exe->velb_relocations.push_back(e);
        }
    }

    // parsear la seccion @c @ir si existe.  El header
    // tiene offset_ir_section + size_ir_section (post bump VERSION_VELB
    // a 0x3).  Si offset == 0 o size == 0, el .velb no tiene IR
    // embebido (build sin frontend Vesta o version antigua) -> se queda
    // ir_functions vacio y el auto-JIT no se dispara para este modulo.
    if (exe->header.offset_ir_section != 0 && exe->header.size_ir_section > 0 &&
        static_cast<size_t>(exe->header.offset_ir_section) +
                exe->header.size_ir_section <=
            exe->bytecode.size()) {
        const size_t ir_off =
            static_cast<size_t>(exe->header.offset_ir_section);
        const size_t ir_size = exe->header.size_ir_section;
        std::vector<ir::IrFunction> fns;
        /* parse_ir_section lee desde ir_off hasta el final del @ir
         * subsection (no consume bytes mas alla del VEIR + functions).
         * Si tras @ir hay un @sym section, parse_ir_section retornara
         * exitosamente y los bytes adicionales quedaran disponibles. */
        const bool ok =
            ir::parse_ir_section(exe->bytecode, ir_off, ir_size, fns);
        if (ok) {
            exe->ir_functions = std::move(fns);
            /* Poblar lookup por nombre para O(1) dispatch JIT. */
            exe->ir_lookup.reserve(exe->ir_functions.size());
            for (size_t i = 0; i < exe->ir_functions.size(); ++i) {
                exe->ir_lookup[exe->ir_functions[i].name] = i;
            }
            /*  AS inc.6: ensamblar + registrar el trampoline de cada
             * bloque inline-asm (indexado por hash del NASM).  Permite que
             * el interprete (modo -m vm, SIN JIT) ejecute inline-asm via el
             * helper vrt:inline_asm_exec.  Usa solo el ENSAMBLADOR
             * (g_asm_backend), no el compilador JIT. */
            jit::build_and_register_inline_asm_trampolines(exe->ir_functions);
        }
        /* Si !ok, ignoramos silenciosamente (graceful degradation).
         * El bytecode sigue siendo ejecutable via interp. */

        /* parsear @sym section (symbol table del linker)
         * que vive RIGHT AFTER el @ir.  Magic "VSYM" + version + count
         * + entries.  Si no aparece o esta corrupta, dejamos el
         * symbol_table vacio y el JIT mini-parser cae a unsupported
         * para @Absolute refs (backward compatible). */
        const size_t section_end = ir_off + ir_size;
        /* Buscar VSYM scanneando desde algun offset razonable dentro
         * de la region.  Como ir::parse_ir_section termino su lectura
         * en algun byte interno, scaneamos los ultimos N bytes para
         * encontrar el VSYM (heuristica simple). */
        for (size_t scan = ir_off + 12; scan + 12 <= section_end; ++scan) {
            if (exe->bytecode[scan] == 'V' && exe->bytecode[scan + 1] == 'S' &&
                exe->bytecode[scan + 2] == 'Y' &&
                exe->bytecode[scan + 3] == 'M') {
                /* Parsear VSYM header. */
                auto rd16 = [&](size_t off) {
                    return static_cast<uint16_t>(exe->bytecode[off]) |
                           (static_cast<uint16_t>(exe->bytecode[off + 1]) << 8);
                };
                auto rd32 = [&](size_t off) {
                    return static_cast<uint32_t>(exe->bytecode[off]) |
                           (static_cast<uint32_t>(exe->bytecode[off + 1])
                            << 8) |
                           (static_cast<uint32_t>(exe->bytecode[off + 2])
                            << 16) |
                           (static_cast<uint32_t>(exe->bytecode[off + 3])
                            << 24);
                };
                auto rd64 = [&](size_t off) {
                    uint64_t v = 0;
                    for (int i = 0; i < 8; ++i)
                        v |= static_cast<uint64_t>(exe->bytecode[off + i])
                             << (i * 8);
                    return v;
                };
                const uint16_t version = rd16(scan + 4);
                if (version != 1) break; /* version desconocida */
                const uint32_t count = rd32(scan + 8);
                if (count > 1'000'000) break; /* sanity check */
                size_t cur = scan + 12;
                exe->symbol_table.reserve(count);
                for (uint32_t k = 0; k < count; ++k) {
                    if (cur + 2 > section_end) break;
                    const uint16_t nlen = rd16(cur);
                    cur += 2;
                    if (cur + nlen + 8 > section_end) break;
                    std::string name(
                        reinterpret_cast<const char *>(&exe->bytecode[cur]),
                        nlen);
                    cur += nlen;
                    const uint64_t addr = rd64(cur);
                    cur += 8;
                    exe->symbol_table[std::move(name)] = addr;
                }
                break;
            }
        }
    }

    return exe;
}

/// Definida mas abajo, junto a las demas rutinas de relocations; la usa
/// load_executable, que va antes.
static void materialize_gdata_host(Executable &exe);

/// Alineacion del bloque de globales: una linea de cache.  Es lo que permite
/// DEMOSTRAR la alineacion de un dato estatico en vez de solo no poder
/// desmentirla (ver `Executable::gdata_host`).
static constexpr size_t kGdataAlign = analysis::kAlineacionBloqueGlobales;

/* Que la reserva y el analisis usen el MISMO numero no puede quedar en la
 * confianza: si alguien bajara uno de los dos, el analisis seguiria afirmando
 * una alineacion que la memoria ya no tiene, y eso no falla -- lee mal.  Aqui
 * no compila. */
static_assert(kGdataAlign >= 8 && (kGdataAlign & (kGdataAlign - 1)) == 0,
              "la alineacion del bloque de globales debe ser potencia de dos");

void Executable::BorrarAlineado::operator()(uint8_t *p) const noexcept {
    if (p == nullptr) return;
#ifdef _WIN32
    _aligned_free(p);
#else
    std::free(p);
#endif
}

runtime::ProcessVM *Loader::load_executable(runtime::VM &vm, std::string path) {
    /* El artefacto, de una vez y por la llamada del sistema.
     *
     * Antes se leia con `std::istreambuf_iterator`, que es la forma mas lenta
     * de leer un fichero en C++: va byte a byte por el bufer del flujo y hace
     * crecer el vector a base de reasignaciones.  Medido con VTune al ejecutar
     * un artefacto de 2,8 MiB, eso ponia 25,8 ms en el `read` de msvcrt mas
     * 14,9 en `memcpy` -- de unos 55 ms de CPU de toda la ejecucion.
     *
     * Aqui el tamano se sabe de antemano, se reserva una vez y se lee de una
     * tacada.  Es lo mismo que ya se hace para leer los paquetes del almacen.
     */
    std::vector<uint8_t> bytecode;
    if (!util::read_whole_file(path, bytecode)) {
        throw std::runtime_error("No se pudo abrir el ejecutable: " + path);
    }

    // Delegar en la version bytecode
    runtime::ProcessVM *proc = load_executable(vm, std::move(bytecode));
    // Se recuerda de que fichero salio.  Antes se dejaba vacio para el
    // ejecutable principal -- solo lo rellenaban los modulos cargados sobre la
    // marcha -- y sin el, al fallar algo, no habia forma de saber que programa
    // se estaba ejecutando ni de pedir la informacion que lo explica.
    if (!executables.empty() && executables.back()->source_path.empty())
        executables.back()->source_path = path;
    return proc;
}

runtime::ProcessVM *
Loader::load_executable(runtime::VM &vm,
                        std::vector<uint8_t> raw_bytecode_file) {
    if (raw_bytecode_file.empty()) {
        throw std::runtime_error("Loader::load_executable: Se intento cargar "
                                 "un ejecutable con raw_bytecode_file vacio");
    }
    auto exe = parse_velb(std::move(raw_bytecode_file));

    GlobalPID pid = vm.spawn_process();
    runtime::ProcessVM *proccess = vm.get_process(pid);

    // configuramos RIP (PC tambien llamado)
    proccess->registers.rip.qword(exe->init_pc);
    // Fondo de su cadena de llamadas: por aqui arranco (ver entry_pc).
    proccess->entry_pc = exe->init_pc;

    // Inicializar RSP/RBP del proceso main al stack base convencional
    // (mismo esquema que exec_instr_spawn para procesos hijo: 0x10000000
    // + (local_pid % 0x1000) * 0x100000).  Sin esta inicializacion el
    // primer `enter N` con RSP=0 hace `push rbp` -> escribir en VA
    // 0xFFFFFFFFFFFFFFF8 -> mapeo de pagina enorme y segfault.  La
    // pila crece hacia abajo desde stack_base.
    //
    // Sentinel HLT para entry-points con TCO: si main termina con
    // `leave; tailcall X` y la funcion final hace `leave; ret`, el ret
    // pop'eara la cima de la pila esperando una direccion de retorno
    // del caller.  Como main no tiene caller, escribimos un par de
    // bytes HLT (0x00 0x03 = extended hlt) en una VA fija, y empujamos
    // esa VA inicialmente como "direccion de retorno" de main.  El ret
    // saltara a ese HLT y la VM terminara limpiamente.  El sentinel
    // vive justo por encima del stack_base (la pila crece hacia abajo,
    // asi que el espacio por encima esta libre).
    const uint64_t stack_base_main =
        0x10000000ULL + (pid.local_pid % 0x1000ULL) * 0x100000ULL;
    const uint64_t hlt_sentinel_va = stack_base_main + 16;
    const uint8_t hlt_bytes[2] = {0x00, 0x03};
    proccess->vm_mem.vm_to_host_memcpy(hlt_sentinel_va, hlt_bytes,
                                       sizeof(hlt_bytes));
    // Empujar el sentinel como retorno inicial de main.
    const uint64_t initial_rsp = stack_base_main - 8;
    proccess->vm_mem.vm_to_host_memcpy(initial_rsp, &hlt_sentinel_va,
                                       sizeof(hlt_sentinel_va));
    proccess->registers.stack_pointer.qword(initial_rsp);
    proccess->registers.base_pointer.qword(initial_rsp);
    // fix8 - el GC stack scan necesita conocer el limite superior
    // del stack (stack_high) para iterar [rsp, stack_high) buscando
    // handles vivos.  stack_low_water arranca igual a stack_high (no
    // hay slot usado todavia).  Se actualiza en subsp; reset post-GC.
    proccess->stack_high = initial_rsp;
    proccess->stack_low_water = initial_rsp;

    // `gdata` (storage de las variables globales) NO va a memoria de la VM:
    // va a un bloque HOST.  Ver Executable::gdata_host para el porque.
    materialize_gdata_host(*exe);

    // copiamos cada seccion del ejecutable a la memoria virtual
    // de la VM
    for (auto *sec : exe->sections) {
        // `gdata` ya vive en el bloque host; copiarla tambien a vm_mem seria
        // una copia muerta que ademas confundiria (dos storages para el mismo
        // global, y el que el programa usa es el host).
        if (sec->name == "gdata") continue;
        uint64_t vm_addr = sec->memory.address_init;
        uint64_t offset = sec->file_offset;

        // no se debe usar raw_bytecode_file ya que no contiene simbolos
        // resueltos; usar exe->bytecode que contiene los mismos datos
        // pero con las instrucciones parcheadas.
        //
        // sec->file_offset YA es absoluto al inicio del archivo (lo
        // computa parser_table_sections como
        // space->file_offset + delta_va, y space->file_offset =
        // address_spaces[i].offset_bytecode que el linker patchea con
        // base_bytecode_offset absoluto).  Por tanto NO sumar
        // exe->offset_real_bytecode (tambien absoluto), o se produce
        // double-counting + lectura OOB del vector exe->bytecode.
        // Bug introducido en a0e3098; logica correcta original en
        // commit dff2bc7 (`bytecode.data() + offset`).
        if (offset >= exe->bytecode.size()) continue;
        const uint8_t *src = exe->bytecode.data() + offset;
        const size_t avail = exe->bytecode.size() - offset;
        proccess->vm_mem.vm_to_host_memcpy(vm_addr, src, avail);
    }
    // poner ejecutable a la pila de ejecutuables
    executables.push_back(std::move(exe));

    // ---- Eager JIT compile de `main` REACTIVADO (2026-05-16) ----
    //
    // Bugs cerrados que bloqueaban este flow:
    //   (a) enum mismatch VESTA_FATAL_* <-> FatalKind alineado.
    //   (b) vrt_callm tiene fallback a bytecode interp sincronico
    //       cuando JIT compile falla -- no devuelve 0 silente.
    //   (c) wrappers dual VM/HOST en vrt_findclass/findmethod/findfield
    //       detectan ptrs > 4GB como host ptrs (ALLOCA del JIT) y
    //       leen via memcpy en lugar de vm_mem.read_bytes.
    //   (d) bug clobber RDX en CALLM fix con R10/R11 scratch.
    //
    // Si el JIT main compila exitosamente, se ejecuta nativo via
    // enter_jit en el scheduler.  Si falla parcialmente (algun raw_asm
    // complejo no soportado), unsupported=true y caemos a interp.
    // SEGURIDAD (sandbox bajo JIT): no eager-compile main si hay un sandbox
    // activo -- el JIT-eated main emitiria CALLN/spawn/etc. sin el check de
    // capabilities (check_cap_at_pc).  El interp enforcea el sandbox.  Cero
    // overhead default (sandbox_active = false).  Mismo guard que
    // maybe_compile_method.
    if (jit::g_jit_threshold != UINT32_MAX && !executables.empty() &&
        !sandbox_active) {
        auto &last_exe = executables.back();
        /* AOP fix 2026-05-16: si el programa tiene CUALQUIER metodo con
         * advice_chain != null (i.e. usa @Before/@After/@Around), no
         * eager-compile main.  El JIT-eated main hace CALLVIRT inline
         * que no aplica advices, y el fallback a vrt_callvirt+interp
         * tampoco los aplica correctamente (ejecuta solo el body sin
         * setup de la cadena).  Resultado: doblar(21)=0 + advice no
         * dispara.  Workaround: main siempre via interp cuando hay AOP. */
        /* Detectar AOP y closures escaneando el IR (no ClassRegistry
         * porque __module_init aun no se ejecuto).  Si el programa
         * usa aspectos (addadvice) o closures (make_closure /
         * callclosure), NO eager-compile main porque:
         *   - AOP: el JIT inline dispatch no aplica advices, y el
         *     fallback tampoco los aplica desde dentro de un JIT frame.
         *   - Closures: el frontend emite VM bytecode vaddr para
         *     __lambda_<N> que vrt_callclosure no puede saltar
         *     correctamente con env_addr como host ptr (el lambda
         *     bytecode interpreta R14 como VM vaddr). */
        bool skip_main_jit = false;
        bool has_closures = false;
        bool main_has_try = false;
        /* Recorrer SOLO la funcion 'main' para detectar try/catch raw_asm:
         * el cross-boundary throw (JIT main + interp callee que throw)
         * salta a handler_pc en bytecode VM address, lo cual NO funciona
         * desde dentro del host frame del JIT main.  Workaround v1: si
         * main tiene tryenter, skip eager-compile (su interp dispatch
         * maneja el throw correctamente).   D.13 (native unwinding)
         * eliminara esta restriccion. */
        /* Sprint JIT-cross-fn 2026-06-01: relajamos la restriccion de
         * closures.  Antes desactivabamos TODO el JIT (set_jit_threshold
         * UINT32_MAX) cuando el modulo tenia MAKE_CLOSURE/CALLCLOSURE.
         * Ahora solo desactivamos el eager-compile de main + flag
         * has_closures para que el cascade resolver evite compilar
         * lambdas problematicas, pero el resto de fns (callvirt
         * counters, fns ordinarias) sigue compilando.  El runtime
         * `vrt_callclosure` ya tiene heuristica VM-vs-host PC para
         * dispatchar correctamente.
         *
         * MAIN tiene closures: skip main eager (interp maneja
         *   CALLCLOSURE con env en VM stack sin issue).
         * OTRAS fns con closures: cascade resolver puede saltarse
         *   esas fns specificas si fallan; resto compila.
         */
        bool main_has_closure = false;
        for (const auto &irf : last_exe->ir_functions) {
            for (const auto &block : irf.blocks) {
                for (const auto &ins : block.instrs) {
                    if (ins.op == ir::IrOp::RAW_ASM &&
                        ins.func_name.find("addadvice") != std::string::npos) {
                        skip_main_jit = true;
                        break;
                    }
                    if (ins.op == ir::IrOp::MAKE_CLOSURE ||
                        ins.op == ir::IrOp::CALLCLOSURE) {
                        has_closures = true;
                        if (irf.name == "main") {
                            main_has_closure = true;
                            skip_main_jit = true;
                        }
                    }
                    /* Detectar tryenter en main especificamente. */
                    if (irf.name == "main" && ins.op == ir::IrOp::RAW_ASM &&
                        ins.func_name.find("tryenter") != std::string::npos) {
                        main_has_try = true;
                    }
                }
                if (skip_main_jit) break;
            }
            if (skip_main_jit) break;
        }
        const bool has_aop = skip_main_jit;
        (void)main_has_closure;
        (void)has_closures;
        /* JIT global SIGUE activo aunque haya closures.  Fns sin
         * closures compilan normal; con closures, el cascade resolver
         * puede saltar la fn problematica. */
        if (false) { /* preservar bloque para futuro deopt selectivo */
            jit::set_jit_threshold(UINT32_MAX);
            if (jit::g_jit_warn_unsupported) {
                std::fprintf(stderr, "[jit] desactivado para este programa\n");
            }
        }
        auto it = last_exe->ir_lookup.find("main");
        if (!has_aop && !main_has_try && it != last_exe->ir_lookup.end() &&
            it->second < last_exe->ir_functions.size()) {
            const ir::IrFunction &ir_main = last_exe->ir_functions[it->second];
            /* Resolver native fn (CALLN handler en Selector):
             * dado "lib:func", carga la DLL via FFI y resuelve el simbolo
             * a un host fn_ptr.  El Selector embebe el ptr como imm64
             * + emite CALL nativo.  Cero overhead runtime vs llamada
             * directa de C. */
            ffi::FFI *ffi_ptr = &ffi_loader;
            auto resolve_native =
                [ffi_ptr](const std::string &name) -> uint64_t {
                size_t colon = name.find(':');
                if (colon == std::string::npos) return 0;
                std::string lib = name.substr(0, colon);
                std::string func = name.substr(colon + 1);
                /* Sprint JIT-cross-fn: virtual lib registry FIRST. */
                void *vfn = ffi::lookup_virtual_fn(lib, func);
                if (vfn != nullptr) {
                    return reinterpret_cast<uint64_t>(vfn);
                }
                try {
                    void *mod = ffi_ptr->load_native_module(lib);
                    if (!mod) return 0;
                    void *fn = ffi_ptr->resolve_native_symbol(mod, func);
                    return reinterpret_cast<uint64_t>(fn);
                } catch (...) {
                    return 0;
                }
            };
            /* lectura compile-time de vm_mem.  El proceso
             * @c proccess ya tiene static_data del .velb cargado por
             * el linker; @c __module_init aun no corrio, pero los
             * literales del data section (e.g. name strings,
             * placeholders de @c s_<X>) si estan disponibles.  El
             * inlining espera por @c __module_init para tener los
             * @c ClassInfo* cacheados -- usualmente el eager-compile
             * de main happens DESPUES de __module_init en runtime.  */
            runtime::ProcessVM *proc_for_read = proccess;
            auto read_vmem_cb = [proc_for_read](uint64_t vaddr) -> uint64_t {
                try {
                    return proc_for_read->vm_mem.read_u64(vaddr);
                } catch (...) {
                    return 0;
                }
            };
            /* Computar offsets de exc_frame_stack + exc_free_list para
             * inline tryleave en codigo JIT-eated (7 instr sin leak,
             * vs runtime call de ~25 instr). */
            int32_t exc_off = 0, exc_free_off = 0;
            {
                const int64_t off64 =
                    reinterpret_cast<int64_t>(&proccess->exc_frame_stack) -
                    reinterpret_cast<int64_t>(proccess);
                const int64_t free64 =
                    reinterpret_cast<int64_t>(&proccess->exc_free_list) -
                    reinterpret_cast<int64_t>(proccess);
                if (off64 >= INT32_MIN && off64 <= INT32_MAX) {
                    exc_off = static_cast<int32_t>(off64);
                }
                if (free64 >= INT32_MIN && free64 <= INT32_MAX) {
                    exc_free_off = static_cast<int32_t>(free64);
                }
            }
            const uint64_t jit_counter_addr = reinterpret_cast<uint64_t>(
                &proccess->scheduler.profiler_jit_instr_counter);
            /* Lo que se sabe de ESTE modulo, en un solo sitio.
             *
             * Aqui se compilan varias funciones del mismo programa -- los
             * cuerpos de fibra, el asignador, main, y en cascada sus llamadas
             * --, asi que el conocimiento se calcula una vez y lo reciben
             * todas.  Antes cada compilacion se construia el suyo, y la misma
             * funcion lo pagaba de nuevo cada vez que se pedia.
             *
             * Vive lo que dura la compilacion de este modulo: dentro de el un
             * nombre identifica una funcion, que es lo que hace legitimo
             * cachear por nombre. */
            jit::JitFactBase hechos_del_modulo;
            // FN.3: force-eager del grafo de fibra ANTES de compilar main.
            // Si algun IR usa el opcode SWAPCTX (fibras via `fiber_swapctx`),
            // (1) materializamos `__vx_swapctx` nativo (deja
            // g_vx_swapctx_native, que el vreg lee para emitir el CALL nativo
            // del SWAPCTX) y (2) eager-compilamos cada CUERPO de fibra por
            // vreg, para que `fiber_entry(fn)` (LABEL_ADDR) resuelva a su
            // jit_code nativo (pieza 1) -- el ctx.r12 de la fibra debe apuntar
            // a codigo nativo VM_ABI, no a una VA.  Los cuerpos se referencian
            // solo via LABEL_ADDR (no CALL), asi que el cascade resolver no los
            // tocaria.
            {
                auto ir_uses_swapctx = [](const ir::IrFunction &f) {
                    for (const auto &blk : f.blocks)
                        for (const auto &ins : blk.instrs)
                            if (ins.op == ir::IrOp::SWAPCTX) return true;
                    return false;
                };
                bool any_swapctx = false;
                for (const auto &irf : last_exe->ir_functions)
                    if (ir_uses_swapctx(irf)) {
                        any_swapctx = true;
                        break;
                    }
                if (any_swapctx) {
                    const uint64_t sc = jit::ensure_vx_swapctx_native(proccess);
                    if (sc == 0) {
                        std::fprintf(
                            stderr,
                            "[jit] context-switch de fibra sin backend nativo "
                            "en esta arquitectura; el grafo de fibra corre en "
                            "el interprete\n");
                    } else {
                        for (const auto &irf : last_exe->ir_functions) {
                            if (irf.name == "main") continue;
                            if (!ir_uses_swapctx(irf)) continue;
                            try {
                                jit::CompileResult fr =
                                    jit::eager_compile_function(
                                        irf, &last_exe->ir_lookup,
                                        &last_exe->ir_functions,
                                        &last_exe->symbol_table, resolve_native,
                                        read_vmem_cb, exc_off, exc_free_off,
                                        jit_counter_addr, &hechos_del_modulo);
                                /* Registrar pc -> jit_code: el path vreg
                                 * top-level NO lo hace por si mismo, y
                                 * `fiber_entry(cuerpo)` (LABEL_ADDR, pieza 1)
                                 * necesita hallar esta direccion nativa para
                                 * que el ctx.r12 de la fibra apunte a codigo
                                 * nativo VM_ABI (no a una VA de bytecode). */
                                if (fr.fn != nullptr) {
                                    auto sit = last_exe->symbol_table.find(
                                        "code." + irf.name);
                                    if (sit != last_exe->symbol_table.end() &&
                                        sit->second != 0)
                                        jit::register_jit_code_at_pc(
                                            sit->second,
                                            reinterpret_cast<void *>(fr.fn));
                                }
                            } catch (...) {
                            }
                        }
                    }
                }
            }
            /* El asignador, ANTES que nada.
             *
             * Si la primera reserva del programa lo encuentra ya compilado, no
             * hay un tramo inicial en el que el codigo compilado use un
             * asignador y el resto otro -- y ese tramo es justo lo que corrompe
             * el monton, porque quien reserva por uno acaba soltando por el
             * otro.  No es una optimizacion: es lo que hace que no haya dos.
             *
             * Se compila el punto de entrada de nombre conocido, que lleva al
             * asignador de ESTE programa (el suyo si lo declaro, el de la
             * biblioteca si no). */
            /* El asignador del programa, compilado ANTES de arrancar.
             *
             * Si la primera reserva ya lo encuentra compilado, no hay un tramo
             * inicial en el que el codigo compilado use un asignador y el resto
             * otro -- y ese tramo es lo que corrompe el monton, porque quien
             * pide por uno acaba soltando por el otro.
             *
             * Se compila el punto de entrada de nombre conocido, que lleva al
             * asignador de ESTE programa: el suyo si lo declaro con
             * @AllocatorOverride, el de la biblioteca si no. */
            static const char *const kPuntos[2] = {"__vx_alloc_entry",
                                                   "__vx_free_entry"};
            const size_t n_puntos =
                util::flag_on(util::FlagId::AsignadorMaquina) ? 0u : 2u;
            for (size_t ip = 0; ip < n_puntos; ++ip) {
                const char *punto = kPuntos[ip];
                /* El nombre convenido es un ALIAS -- una etiqueta mas sobre la
                 * misma direccion --, no una funcion aparte, asi que no aparece
                 * en la tabla de funciones.  Lo que comparten es la DIRECCION:
                 * se busca ahi y se compila la funcion que vive en ella. */
                /* Los simbolos van con el nombre de su seccion delante
                 * ("code.etiqueta"), asi que se busca de las dos formas. */
                auto ial = last_exe->symbol_table.find(punto);
                if (ial == last_exe->symbol_table.end())
                    ial = last_exe->symbol_table.find(std::string("code.") +
                                                      punto);
                if (ial == last_exe->symbol_table.end()) {
                    continue;
                }
                const uint64_t dir_alias = ial->second;
                auto ita = last_exe->ir_lookup.end();
                for (const auto &sim : last_exe->symbol_table) {
                    if (sim.second != dir_alias) continue;
                    /* Los simbolos van con su seccion delante y la tabla de
                     * funciones no, asi que se compara por el nombre pelado --
                     * sin copiarlo: basta una vista sobre el que ya existe. */
                    const size_t sep = sim.first.rfind('.');
                    const char *pelado =
                        sim.first.c_str() +
                        (sep == std::string::npos ? 0 : sep + 1);
                    if (std::strcmp(pelado, punto) == 0)
                        continue; // el alias, no el de verdad
                    auto cand = last_exe->ir_lookup.find(pelado);
                    if (cand != last_exe->ir_lookup.end()) {
                        ita = cand;
                        break;
                    }
                }
                if (ita == last_exe->ir_lookup.end() ||
                    ita->second >= last_exe->ir_functions.size())
                    continue;
                try {
                    jit::CompileResult ra = jit::eager_compile_function(
                        last_exe->ir_functions[ita->second],
                        &last_exe->ir_lookup, &last_exe->ir_functions,
                        &last_exe->symbol_table, resolve_native, read_vmem_cb,
                        exc_off, exc_free_off, jit_counter_addr,
                        &hechos_del_modulo);
                    /* Y se le dice a la maquina donde esta, para que su
                     * instruccion reserve en el MISMO monton que el codigo
                     * compilado.  Cada uno llega por su mecanismo; el monton es
                     * uno. */
                    if (ra.fn != nullptr) {
                        const uint64_t dir = reinterpret_cast<uint64_t>(ra.fn);
                        if (std::strcmp(punto, "__vx_alloc_entry") == 0) {
                            proccess->alloc_del_programa = dir;
                            /* Y que el selector lo sepa: con el monton del
                             * programa, el atajo que replica el de la maquina
                             * repartiria del monton equivocado. */
                            jit::g_alloc_del_programa = dir;
                        } else {
                            proccess->free_del_programa = dir;
                            jit::g_free_del_programa = dir;
                        }
                    }
                } catch (...) {
                    // Sin el, el JIT se queda con el asignador de la maquina:
                    // mas lento y sin compartir camino con el binario nativo,
                    // pero correcto.
                }
            }
            try {
                jit::CompileResult res = jit::eager_compile_function(
                    ir_main, &last_exe->ir_lookup, &last_exe->ir_functions,
                    &last_exe->symbol_table, resolve_native, read_vmem_cb,
                    exc_off, exc_free_off, jit_counter_addr,
                    &hechos_del_modulo);
                if (res.fn != nullptr) {
                    proccess->jit_entry_fn = reinterpret_cast<void *>(res.fn);
                    if (jit::g_jit_warn_unsupported) {
                        std::fprintf(stderr,
                                     "[jit] eager-compiled main (%zu bytes, "
                                     "%zu MInstrs)\n",
                                     res.code_size, res.instr_count);
                    }
                } else if (jit::g_jit_warn_unsupported) {
                    std::fprintf(stderr,
                                 "[jit] main no se eager-compilo "
                                 "(unsupported=%d) -- fallback a interp\n",
                                 res.unsupported ? 1 : 0);
                }
            } catch (...) {
                /* Cualquier excepcion en la compilacion eager se ignora. */
            }
        }
    }

    // vm->vm_mem[0x10] = 1;
    return proccess;
}

// ---------------------------------------------------------------------
// rebase preciso usando la tabla de relocations.
//
// Para cada entry de la tabla de relocations del .velb:
//   - bytecode_offset apunta al slot DENTRO del bytecode (relativo a
//     bytecode start, no a archivo).
//   - target_value es la direccion absoluta original escrita por el
//     linker.
//   - Si target_value esta en el rango [orig_base, orig_end) (es decir,
//     apunta al code section del modulo), reescribimos el slot a
//     (target_value - orig_base + new_base).
//   - Si esta fuera (e.g. apunta a static_data en otra seccion o a
//     codigo importado), no se patchea.
//
// La gran ventaja vs scan brute-force: NO false positives.  El linker
// sabe exactamente que slots son addresses; los datos numericos
// (frame sizes en `enter`, constantes literales en `mov reg, N`, etc.)
// NO aparecen en la tabla de relocations.
/**
 * @brief Materializa la seccion `gdata` en un bloque HOST y fija sus refs.
 *
 * El storage de las variables globales pasa de la memoria de la VM a memoria
 * host: se copia a un bloque contiguo propiedad del @ref Executable y toda
 * referencia a el se reescribe con la direccion host real.
 *
 * No hace falta un tipo de relocation nuevo: cada `@Absolute("gdata.s_N")` ya
 * dejo su entrada en la tabla de relocations del .velb, asi que basta con
 * quedarse con las que apuntan al rango de `gdata`.  La tabla de simbolos se
 * reescribe igual, porque es la que consulta el JIT para resolver `gdata.s_N`
 * en compile-time.
 *
 * Se parchea sobre @c exe.bytecode ANTES de mapear las secciones, de modo que
 * la imagen que se copia a `vm_mem` (y la que `copy_executables_to` replica en
 * cada proceso hijo) ya lleva las direcciones host definitivas -> todos los
 * actores comparten los mismos globales.
 *
 * @param exe Ejecutable ya parseado, con secciones y relocations.
 */
static void materialize_gdata_host(Executable &exe) {
    const Assembly::Bytecode::Section *gsec = nullptr;
    for (const auto *sec : exe.sections)
        if (sec->name == "gdata") {
            gsec = sec;
            break;
        }
    if (gsec == nullptr) return; // modulo sin variables globales

    const uint64_t va = gsec->memory.address_init;
    const uint64_t end = gsec->memory.address_final;
    if (end <= va) return; // seccion declarada pero vacia
    const size_t size = static_cast<size_t>(end - va);

    /* Alineado a linea de cache: ver `Executable::gdata_host`.  El tamano se
     * redondea al multiplo, que es lo que exigen las reservas alineadas. */
    const size_t redondeado =
        (size + kGdataAlign - 1) & ~(size_t)(kGdataAlign - 1);
    uint8_t *bloque = nullptr;
#if defined(_WIN32)
    bloque = static_cast<uint8_t *>(_aligned_malloc(redondeado, kGdataAlign));
#else
    /* `posix_memalign` y no `aligned_alloc`: el segundo es de C11 y falta en
     * varias plataformas que si se soportan (Android viejo, macOS anterior a
     * 10.15), mientras que el primero esta en cualquier sistema POSIX desde
     * hace dos decadas.  La alternativa era compilar en unos sitios y no en
     * otros por una reserva. */
    void *tmp = nullptr;
    if (posix_memalign(&tmp, kGdataAlign, redondeado) != 0) tmp = nullptr;
    bloque = static_cast<uint8_t *>(tmp);
#endif
    if (bloque == nullptr)
        return; // sin bloque no hay globales que materializar
    std::memset(bloque, 0, redondeado);
    exe.gdata_host.reset(bloque);
    exe.gdata_size = size;
    exe.gdata_va = va;

    // Valores iniciales: estan en la imagen, en el file_offset de la seccion.
    const uint64_t foff = gsec->file_offset;
    if (foff < exe.bytecode.size()) {
        const size_t avail =
            std::min(size, static_cast<size_t>(exe.bytecode.size() - foff));
        std::memcpy(exe.gdata_host.get(), exe.bytecode.data() + foff, avail);
    }

    const uint64_t host_base = reinterpret_cast<uint64_t>(exe.gdata_host.get());

    // 1. Referencias en el codigo: las entradas de la tabla de relocations cuyo
    //    target cae en el rango de `gdata`.
    for (const auto &rel : exe.velb_relocations) {
        if (rel.type != static_cast<uint8_t>(RelocTypeVELB::ABSOLUTE64))
            continue;
        if (rel.target_value < va || rel.target_value >= end) continue;
        const uint64_t host = host_base + (rel.target_value - va);
        const size_t site =
            static_cast<size_t>(exe.offset_real_bytecode + rel.bytecode_offset);
        if (site + sizeof(uint64_t) > exe.bytecode.size())
            continue; // defensivo
        std::memcpy(&exe.bytecode[site], &host, sizeof(uint64_t));
    }

    // 2. Tabla de simbolos: el JIT resuelve `gdata.s_N` por aqui y debe obtener
    //    la direccion host, no la virtual.
    for (auto &kv : exe.symbol_table) {
        if (kv.second < va || kv.second >= end) continue;
        kv.second = host_base + (kv.second - va);
    }
}

static void apply_relocations_for_rebase(
    std::vector<uint8_t> &data,
    size_t bytecode_base_in_file, // exe->offset_real_bytecode
    const std::vector<entry_relocation_table> &relocs, uint64_t orig_base,
    uint64_t orig_end, uint64_t new_base) {
    if (orig_base == new_base) return;
    const int64_t delta =
        static_cast<int64_t>(new_base) - static_cast<int64_t>(orig_base);
    for (const auto &rel : relocs) {
        const bool is_abs64 =
            (rel.type == static_cast<uint8_t>(RelocTypeVELB::ABSOLUTE64));
        const bool is_abs32 =
            (rel.type == static_cast<uint8_t>(RelocTypeVELB::ABSOLUTE32));
        if (!is_abs64 && !is_abs32) continue; // solo Absolute64 / Absolute32
        // Solo reescribir si target original esta en el rango del code
        // section que estamos relocando.
        if (rel.target_value < orig_base || rel.target_value >= orig_end)
            continue;
        const uint64_t patched = static_cast<uint64_t>(
            static_cast<int64_t>(rel.target_value) + delta);
        const size_t file_off = bytecode_base_in_file + rel.bytecode_offset;
        if (is_abs64) {
            if (file_off + 8 > data.size()) continue; // safety
            std::memcpy(&data[file_off], &patched, 8);
        } else {
            // ABSOLUTE32: truncar la nueva direccion.  Si el rebase
            // empuja el target fuera del rango u32 lo dejamos igual y
            // fallamos en runtime con error claro (caso muy raro).
            if (file_off + 4 > data.size()) continue;
            if (patched > 0xFFFFFFFFULL)
                continue; // mantener el valor ya patcheado en cmpjmp
            uint32_t patched32 = static_cast<uint32_t>(patched);
            std::memcpy(&data[file_off], &patched32, 4);
        }
    }
}

// ---------------------------------------------------------------------
// helper: parchea el PRIMER `hlt` (extended `0x00 0x03`) que
// aparezca en el code section del modulo, reemplazandolo por `ret`
// (`0xC3`) seguido de un byte de relleno (0x00).  Esto convierte el
// epilogo de `main_ret` (default `leave hlt` para Vesta standalone) en
// `leave ret`, haciendo el main LLAMABLE via CALLVM desde loadmod del
// caller.  Para plugins que no usan spawn, el primer hlt es siempre
// el de main; plugins con spawn helpers tendrian otros hlts mas
// adelante (no afectados, solo el PRIMERO se patchea).
static void patch_first_hlt_to_ret(std::vector<uint8_t> &data,
                                   size_t code_offset, size_t code_size) {
    if (code_offset + code_size > data.size()) return;
    for (size_t i = code_offset; i + 1 < code_offset + code_size; ++i) {
        if (data[i] == 0x00 && data[i + 1] == 0x03) {
            data[i] = 0xC3;     // RET (primary FIXED_1)
            data[i + 1] = 0x00; // padding (no se ejecuta tras el RET)
            return;
        }
    }
}

// carga dinamica de un modulo (.velb) en una VM ya corriendo.
// Si la VA original del modulo solapa con executables ya cargados,
// reasigna a `next_dyn_base` y reescribe direcciones absolutas en el
// bytecode (rebase automatico).  Tambien convierte el `hlt` final del
// main del modulo en `ret` para que sea callable via CALLVM.  El caller
// (instruccion bytecode loadmod) salta a init_pc tras push de return
// address; el main del modulo ejecuta __module_init en su prologo,
// registra clases en el ClassRegistry global y RETs de vuelta al caller.
uint64_t Loader::load_module_dynamic(runtime::VM &vm,
                                     std::vector<uint8_t> raw_bytecode_file) {
    if (raw_bytecode_file.empty()) {
        return 0; // archivo vacio -> failure
    }
    auto exe = parse_velb(std::move(raw_bytecode_file));
    if (!exe) return 0;

    // ---- Detectar solapamiento de VA y reasignar si es necesario ----
    // Encontrar el code section.  Conviccion del emisor Vesta: la primera
    // seccion en el .velb es siempre "code".  El emisor (annotations.cpp)
    // deja sec->memory.address_init/final = 0 -> sec->size_real = 0, asi
    // que NO podemos descartar secciones vacias; tomamos directamente la
    // primera seccion (la convencion).
    Section *code_sec = nullptr;
    for (auto *sec : exe->sections) {
        if (sec && sec->name == "code") {
            code_sec = sec;
            break;
        }
    }
    if (!code_sec) {
        // fallback: primera seccion existente
        for (auto *sec : exe->sections) {
            if (sec) {
                code_sec = sec;
                break;
            }
        }
    }
    // Si no hay code section, no hay nada que cargar; devolver el init_pc
    // tal cual (puede ser 0).
    uint64_t init_pc = exe->init_pc;
    if (code_sec) {
        const uint64_t orig_base = code_sec->memory.address_init;
        // Como sec->size_real esta a 0 con el formato actual, derivar
        // code_size del tamano efectivo del bytecode en el archivo.
        // Tomamos desde el inicio de la seccion (file_offset) hasta el
        // final del area de bytecode, que es:
        //   - el inicio de la tabla de relocations si existe
        //   - o el inicio de la tabla de imports si existe
        //   - o el final del archivo
        uint64_t bytecode_end = exe->bytecode.size();
        if (exe->header.offset_reloc_table != 0 &&
            exe->header.offset_reloc_table < bytecode_end) {
            bytecode_end = exe->header.offset_reloc_table;
        }
        if (exe->header.offset_import_table != 0 &&
            exe->header.size_import_table > 0 &&
            exe->header.offset_import_table < bytecode_end) {
            bytecode_end = exe->header.offset_import_table;
        }
        const uint64_t code_size = (code_sec->file_offset < bytecode_end)
                                       ? (bytecode_end - code_sec->file_offset)
                                       : 0;

        // Comprobar overlap contra todos los executables ya cargados.
        // size_real esta a 0 con el formato actual: derivar el tamano
        // efectivo de cada seccion existente con el mismo razonamiento
        // (file_offset hasta el primer end-of-bytecode marker).
        bool conflict = false;
        for (const auto &existing : executables) {
            if (!existing) continue;
            // calcular bytecode_end del executable existente
            uint64_t e_bc_end = existing->bytecode.size();
            if (existing->header.offset_reloc_table != 0 &&
                existing->header.offset_reloc_table < e_bc_end) {
                e_bc_end = existing->header.offset_reloc_table;
            }
            if (existing->header.offset_import_table != 0 &&
                existing->header.size_import_table > 0 &&
                existing->header.offset_import_table < e_bc_end) {
                e_bc_end = existing->header.offset_import_table;
            }
            for (const auto *esec : existing->sections) {
                if (!esec) continue;
                const uint64_t e_start = esec->memory.address_init;
                const uint64_t e_size_eff =
                    esec->size_real ? esec->size_real
                                    : (esec->file_offset < e_bc_end
                                           ? (e_bc_end - esec->file_offset)
                                           : 0);
                if (e_size_eff == 0) continue;
                const uint64_t e_end = e_start + e_size_eff;
                if (orig_base < e_end && (orig_base + code_size) > e_start) {
                    conflict = true;
                    break;
                }
            }
            if (conflict) break;
        }

        //  M.dyn fix (2026-06-05): ademas del overlap contra las
        // secciones de modulos ya cargados, forzar rebase si el orig_base
        // cae en la region RESERVADA [0, next_dyn_base).  Esa region baja
        // contiene el codigo (VA 0), el stack (stack_base = 0x10000000 +
        // local_pid*...) y el heap del programa principal y sus procesos.
        // Los modulos dinamicos SIEMPRE deben vivir en la region dinamica
        // alta [next_dyn_base=0x80000000, ...).  Sin esto, un plugin
        // compilado con `--vx-base 0x10000000` (== stack_base del main)
        // se copiaba ENCIMA del stack de main y lo corrompia -> el segundo
        // loadmodule del hot-reload devolvia basura (M.dyn -> -4).  La
        // deteccion por secciones no lo cubre porque el code section de
        // main esta en VA 0, no en su stack_base.
        if (!conflict && orig_base < next_dyn_base) {
            conflict = true;
        }

        if (conflict) {
            // solapamiento detectado.  Si el .velb tiene tabla de
            // relocations (formato VERSION_VELB >= 2), podemos hacer
            // rebase preciso a una VA libre sin necesitar flags.  Si
            // no hay tabla, reportamos error.
            if (exe->velb_relocations.empty()) {
                std::fprintf(
                    stderr,
                    "[loadmodule] error: la VA del modulo (0x%llX..0x%llX) "
                    "solapa con codigo ya cargado y el .velb no contiene "
                    "tabla de relocations (compilado con linker viejo).  "
                    "Recompila para que el rebase transparente funcione.\n",
                    (unsigned long long)orig_base,
                    (unsigned long long)(orig_base + code_size));
                std::fflush(stderr);
                return 0;
            }
            // Asignar nueva VA alineada a 4 KiB.
            const uint64_t aligned_size = (code_size + 0xFFFULL) & ~0xFFFULL;
            const uint64_t new_base = next_dyn_base;
            next_dyn_base += aligned_size;
            // Rebase preciso: aplicar las relocations a la nueva VA.
            apply_relocations_for_rebase(
                exe->bytecode,
                exe->offset_real_bytecode, // base de bytecode dentro del .velb
                exe->velb_relocations, orig_base, orig_base + code_size,
                new_base);

            // Patch init_pc al nuevo base.
            init_pc = init_pc - orig_base + new_base;

            // Reasignar la VA de TODAS las secciones cuyo rango
            // [address_init, address_init + size_eff) cae dentro del
            // bloque rebaseado [orig_base, orig_base + code_size).
            // Sin esto las secciones secundarias (e.g. "strings"
            // sintetica del MetaSpace, mapeada a VA 0) seguirian
            // copiandose a VA 0 y machacarian el code section del
            // caller en su mismo VA.
            for (auto *sec : exe->sections) {
                if (!sec) continue;
                const uint64_t s_va_orig = sec->memory.address_init;
                if (s_va_orig >= orig_base &&
                    s_va_orig < orig_base + code_size) {
                    const uint64_t delta = new_base - orig_base;
                    sec->memory.address_init = s_va_orig + delta;
                    sec->memory.address_final =
                        sec->memory.address_final + delta;
                } else if (s_va_orig == 0 && sec != code_sec) {
                    // Caso comun: secciones MetaSpace o auxiliares con
                    // address_init=0 (no fueron asignadas al rango
                    // original del code).  Las re-mapeamos al inicio
                    // del nuevo bloque para evitar colision con VA 0
                    // del caller.  Como su size_real==0 y solo se
                    // copian si tienen contenido, esto es seguro: si
                    // estan vacias no destruyen nada, y si tienen
                    // datos los datos van a una VA libre.
                    sec->memory.address_init = new_base;
                    sec->memory.address_final = new_base;
                }
            }
        }

        // (ya NO patcheamos el HLT del main del plugin a RET en bytes:
        // el viejo `patch_first_hlt_to_ret` hacia search textual de la
        // secuencia 0x00 0x03 y podia false-match con imm de mov/callvm
        // que contienen esos bytes adyacentes por casualidad.  Ahora el
        // runtime maneja HLT-during-loadmod via
        // `ProcessVM::loadmod_call_depth`: si el contador > 0 al
        // ejecutar HLT, lo tratamos como RET y decrementamos.  El plugin
        // sigue siendo standalone-runnable; al ejecutarlo via `--run`
        // directo, loadmod_call_depth queda en 0 y HLT halta normal.)
        (void)code_size;
    }

    // Replicar la copia de secciones a TODOS los procesos vivos de la
    // VM (cada ProcessVM tiene vm_mem privado).  Iteramos schedulers y
    // procesos.  Procesos creados DESPUES heredan el codigo via
    // copy_executables_to invocado en exec_instr_spawn.
    //
    // BUG fix (load_module_dynamic): el plugin tiene multiples secciones
    // (code + auxiliar metaspace).  La auxiliar tiene size_real=0 (no
    // populado por el linker) y address_init=0.  Tras la remap a
    // new_base (para evitar colision con VA 0 del caller), la
    // auxiliar termina con address_init = new_base = MISMA VA que la
    // seccion code.  Si copiamos avail bytes para size_real=0, la
    // auxiliar SOBREESCRIBE la code recien copiada en new_base.
    // Sintoma: el plugin halt en bytes 0x00 0x00 mid-instruccion
    // dentro de __module_init porque parte de su bytecode fue
    // aplastado por la auxiliar.
    //
    // Fix: SOLO copiar la seccion principal "code" (la unica que
    // realmente contiene bytecode ejecutable).  Las auxiliares
    // (MetaSpace etc.) son metadata que el loader ya extrajo durante
    // parse_velb (strings, imports, relocs); no necesitan estar en
    // vm_mem para que la VM ejecute el plugin.
    for (auto &sched : vm.schedulers) {
        for (auto &proc : sched->processes) {
            if (!proc) continue;
            for (const auto *sec : exe->sections) {
                if (!sec) continue;
                if (sec != code_sec) continue; // solo la seccion ejecutable
                const uint64_t vm_addr = sec->memory.address_init;
                const uint64_t offset = sec->file_offset;
                if (offset >= exe->bytecode.size()) continue;
                const uint8_t *src = exe->bytecode.data() + offset;
                const size_t avail = exe->bytecode.size() - offset;
                // Si la seccion declara un tamano (size_real > 0), respetarlo.
                // Si size_real == 0 (formato actual), tomar avail.  Para code
                // section es seguro porque es la primera y unica que copiamos.
                const size_t sec_size =
                    sec->size_real ? std::min<size_t>(sec->size_real, avail)
                                   : avail;
                proc->vm_mem.vm_to_host_memcpy(vm_addr, src, sec_size);
            }
        }
    }

    // Anadir al pool de executables; copy_executables_to se encarga de
    // los procesos futuros (e.g. spawn).
    executables.push_back(std::move(exe));
    return init_pc;
}

// Variante con path: registra el source_path en el Executable creado.
// Mismo flujo interno que load_module_dynamic; pasa por load_module_dynamic
// para evitar duplicacion de logica, luego patchea el campo source_path
// del ultimo Executable agregado.
uint64_t
Loader::load_module_dynamic_with_path(runtime::VM &vm,
                                      std::vector<uint8_t> raw_bytecode_file,
                                      const std::string &source_path) {
    const size_t before = executables.size();
    const uint64_t init_pc =
        load_module_dynamic(vm, std::move(raw_bytecode_file));
    if (init_pc == 0) return 0;
    // Si load_module_dynamic anadio un executable (en raros casos podria
    // no anadirlo, e.g. parse_velb falla), patcheamos su source_path.
    if (executables.size() > before && executables.back()) {
        executables.back()->source_path = source_path;
    }
    return init_pc;
}

bool Loader::unload_module_dynamic(runtime::VM &vm, const std::string &path) {
    (void)vm; // por ahora no necesitamos tocar el vm directamente.
    // Buscar de atras hacia adelante (mas probable encontrar el ultimo
    // cargado, reduce iteraciones tipicas).
    for (auto it = executables.rbegin(); it != executables.rend(); ++it) {
        if (!*it) continue;
        if ((*it)->source_path == path) {
            // Si este modulo fue el ultimo en `next_dyn_base`, retroceder
            // el contador para reutilizar la VA.  Solo seguro si su VA
            // de inicio es < next_dyn_base actual (caso conflict-rebase).
            Section *code_sec = nullptr;
            for (auto *sec : (*it)->sections) {
                if (sec && sec->name == "code") {
                    code_sec = sec;
                    break;
                }
            }
            if (code_sec) {
                const uint64_t va = code_sec->memory.address_init;
                // Calcular tamano efectivo del code section (mismo razonamiento
                // que en load_module_dynamic).
                uint64_t bc_end = (*it)->bytecode.size();
                if ((*it)->header.offset_reloc_table != 0 &&
                    (*it)->header.offset_reloc_table < bc_end) {
                    bc_end = (*it)->header.offset_reloc_table;
                }
                if ((*it)->header.offset_import_table != 0 &&
                    (*it)->header.size_import_table > 0 &&
                    (*it)->header.offset_import_table < bc_end) {
                    bc_end = (*it)->header.offset_import_table;
                }
                const uint64_t code_size =
                    (code_sec->file_offset < bc_end)
                        ? (bc_end - code_sec->file_offset)
                        : 0;
                const uint64_t aligned_size =
                    (code_size + 0xFFFULL) & ~0xFFFULL;
                // Solo retroceder si esta VA fue la ultima asignada.
                if (va + aligned_size == next_dyn_base) {
                    next_dyn_base = va;
                }
            }
            // Convertir reverse_iterator a forward_iterator para erase.
            executables.erase(std::next(it).base());
            return true;
        }
    }
    return false;
}

bool Loader::check_cap_at_pc(uint64_t pc, uint32_t required) const noexcept {
    // Fast path zero-overhead: si ningun modulo tiene sandbox activo
    // (caso default), permitir sin iterar.  1 branch predicho not-taken.
    if (__builtin_expect(!sandbox_active, 1)) return true;
    // Recorrer los modulos cargados.  Solo los que tienen un sandbox
    // activo (caps restringidas) pueden denegar; el resto se saltan con
    // un branch predicho (unrestricted() == true en el caso default).
    for (const auto &exe : executables) {
        if (!exe) continue;
        if (exe->caps.unrestricted()) continue; // sin sandbox -> permitir
        // Localizar la seccion cuyo rango VA contiene @c pc.  Mismo
        // razonamiento de tamano efectivo que load_module_dynamic
        // (size_real puede ser 0 con el formato actual; derivar del
        // bytecode hasta la primera tabla reloc/imports).
        uint64_t bc_end = exe->bytecode.size();
        if (exe->header.offset_reloc_table != 0 &&
            exe->header.offset_reloc_table < bc_end) {
            bc_end = exe->header.offset_reloc_table;
        }
        if (exe->header.offset_import_table != 0 &&
            exe->header.size_import_table > 0 &&
            exe->header.offset_import_table < bc_end) {
            bc_end = exe->header.offset_import_table;
        }
        for (const auto *sec : exe->sections) {
            if (!sec) continue;
            const uint64_t start = sec->memory.address_init;
            const uint64_t size_eff =
                sec->size_real
                    ? sec->size_real
                    : (sec->file_offset < bc_end ? (bc_end - sec->file_offset)
                                                 : 0);
            if (size_eff == 0) continue;
            if (pc >= start && pc < start + size_eff) {
                // @c pc pertenece a este modulo sandboxed: decidir por
                // sus caps.
                return exe->caps.has(required);
            }
        }
    }
    // @c pc no pertenece a ningun modulo sandboxed -> permitir.
    return true;
}

void Loader::copy_executables_to(runtime::ProcessVM &dest,
                                 runtime::ProcessVM *parent) {
    // Replica la copia que hace load_executable() pero apuntando al
    // vm_mem del proceso destino.  Itera todos los executables cargados
    // (puede ser >1 si se usa loadmodule) y todas sus secciones.
    //
    // Bug fix Z.3 (2026-05-23): si @c parent != nullptr, copiamos el
    // estado ACTUAL del @c vm_mem del padre (que ya contiene los stores
    // de @c __module_init: cache slots con @c ClassInfo*, etc.) en
    // lugar del bytecode original (que tiene esos slots a cero).  Sin
    // este fix, @c findclass cacheado en el child devolvia 0 y
    // @c newobj fallaba silenciosamente (host_ptr a header sin
    // class_ptr -> SEGFAULT al primer field access).
    for (const auto &exe_ptr : executables) {
        const Executable *exe = exe_ptr.get();
        if (!exe) continue;
        for (const auto *sec : exe->sections) {
            if (!sec) continue;
            const uint64_t vm_addr = sec->memory.address_init;
            const uint64_t offset = sec->file_offset;
            if (offset >= exe->bytecode.size()) continue;
            const size_t avail = exe->bytecode.size() - offset;
            const size_t sec_size =
                sec->size_real ? std::min<size_t>(sec->size_real, avail)
                               : avail;
            if (parent) {
                // Copia desde el vm_mem actual del padre, qword a qword
                // (preserva cualquier modificacion runtime: cache slots
                // de __module_init, datos globales modificados, etc.).
                // Limitamos a chunks de 8 bytes alineados; el resto se
                // cubre con el fallback del bytecode original.
                constexpr size_t CHUNK = 8;
                size_t i = 0;
                for (; i + CHUNK <= sec_size; i += CHUNK) {
                    uint64_t v = parent->vm_mem.read_u64(vm_addr + i);
                    dest.vm_mem.write_u64(vm_addr + i, v);
                }
                // Bytes residuales (< 8): copiar uno por uno.
                for (; i < sec_size; ++i) {
                    uint8_t b = parent->vm_mem.read_u8(vm_addr + i);
                    dest.vm_mem.write_u8(vm_addr + i, b);
                }
            } else {
                // Fallback: copia desde el bytecode crudo (caso load_module).
                const uint8_t *src = exe->bytecode.data() + offset;
                dest.vm_mem.vm_to_host_memcpy(vm_addr, src, sec_size);
            }
        }
    }
}

void Loader::resolve_labels(Assembly::Bytecode::Section &section) {}

void Loader::load_sections(Assembly::Bytecode::Label &label) {}

void Loader::load_spaces(Assembly::Bytecode::Space &space) {}

void Loader::build_runtime_context() {}

Executable &Loader::get_last_instance_unlocked() {
    return *executables.back();
}

Executable &Loader::get_last_instance() {
    std::lock_guard lock(loader_mutex);
    return get_last_instance_unlocked();
}

runtime::VM *Loader::create_vm_instance(size_t num_schedulers) {
    // bloqueamos el acceso si otro hilo intenta entrar
    std::lock_guard lock(loader_mutex);

    // cramos una instancia VM y configuramos el PC
    uint64_t id = instance_manager.create_vm(num_schedulers);
    runtime::VM *vm = instance_manager.get_vm(id);

    return vm;
}

/**
 * @brief Resuelve los campos de un FieldInfo[] clonado sustituyendo parametros
 * de tipo.
 *
 * Para cada FieldInfo con is_type_param == true, busca el tipo concreto en
 * params[type_param_idx].concrete y lo asigna a type_class, marcando el campo
 * como resuelto (is_type_param = false).
 *
 * @param fields  Array de FieldInfo clonado; modificado en sitio.
 * @param count   Numero de entradas en fields.
 * @param params  Array de GenericParam con los tipos concretos ya asignados.
 * @param np      Numero de parametros de tipo.
 */
static void resolve_generic_fields(FieldInfo *fields, size_t count,
                                   const GenericParam *params, size_t np) {
    for (size_t i = 0; i < count; i++) {
        if (!fields[i].is_type_param) continue; // tipo ya concreto, no tocar
        uint16_t idx = fields[i].type_param_idx;
        if (static_cast<size_t>(idx) < np && params[idx].concrete != nullptr) {
            fields[i].type_class = params[idx].concrete; // sustituir tipo
            fields[i].is_type_param = false;             // marcar resuelto
        }
    }
}

/**
 * @brief Instancia una clase generica con tipos concretos (monomorphization en
 * runtime).
 *
 * Construye la clave "ClassName<T1,T2,...>" y busca en generic_cache_.  Si no
 * existe, clona el ClassInfo original y realiza resolucion completa de tipos:
 *
 *   1. GenericParam[].concrete = tipo concreto (constraint se preserva para
 * bounds).
 *   2. FieldInfo[] de campos de instancia: type_class resuelto via
 * type_param_idx.
 *   3. MethodInfo[].args y .return_type: misma resolucion para cada metodo.
 *
 * Toda la memoria auxiliar se almacena en generic_store_* para duracion de vida
 * automatica: se libera al destruir el Loader.
 *
 * Thread-safe: protegido por loader_mutex.
 *
 * @param generic    ClassInfo de la clase generica (CLASS_FLAG_GENERIC).
 * @param type_args  Array de ClassInfo* con los tipos concretos.
 * @param count      Numero de elementos en type_args.
 * @return Puntero al ClassInfo especializado (valido de por vida del Loader).
 */
ClassInfo *Loader::specialize_class(ClassInfo *generic, ClassInfo **type_args,
                                    size_t count) {
    if (generic == nullptr || type_args == nullptr || count == 0)
        return generic;

    // --- construir clave de cache: "ClassName<T1,T2,...>" ---
    std::string key(reinterpret_cast<const char *>(generic->name.data),
                    generic->name.size);
    key += '<';
    for (size_t i = 0; i < count; i++) {
        if (i > 0) key += ',';
        if (type_args[i] != nullptr) {
            key.append(reinterpret_cast<const char *>(type_args[i]->name.data),
                       type_args[i]->name.size);
        } else {
            key += '?'; // tipo desconocido: clave degenerada
        }
    }
    key += '>';

    std::lock_guard<std::mutex> lock(loader_mutex);

    // camino rapido: especializacion ya cacheada
    auto it = generic_cache_.find(key);
    if (it != generic_cache_.end()) return it->second;

    // --- clonar ClassInfo base ---
    auto clone = std::make_unique<ClassInfo>(*generic);

    // guardar nombre especializado con gestion de vida automatica
    auto name_buf = std::make_unique<char[]>(key.size() + 1);
    std::memcpy(name_buf.get(), key.c_str(), key.size() + 1);
    clone->name.data = reinterpret_cast<uint8_t *>(name_buf.get());
    clone->name.size = static_cast<uint32_t>(key.size());
    generic_store_names_.push_back(std::move(name_buf));

    // vincular plantilla original (para instanceof, reflexion y diagnosticos)
    clone->generic_parent = generic;

    // limpiar CLASS_FLAG_GENERIC: la especializacion es clase concreta
    clone->flags &= ~CLASS_FLAG_GENERIC;

    // --- clonar y rellenar GenericParam[].concrete ---
    // constraint se preserva intacto para validar bounds en tiempo de carga
    GenericParam *new_params = nullptr;
    size_t np = generic->type_param_count;
    if (np > 0 && generic->type_params != nullptr) {
        auto pbuf = std::make_unique<GenericParam[]>(np);
        std::memcpy(pbuf.get(), generic->type_params,
                    np * sizeof(GenericParam));
        for (size_t i = 0; i < count && i < np; i++) {
            pbuf[i].concrete =
                type_args[i]; // asignar concreto; constraint intacto
        }
        new_params = pbuf.get();
        clone->type_params = new_params;
        generic_store_params_.push_back(std::move(pbuf));
    }

    // --- resolver FieldInfo[] de campos de instancia ---
    if (generic->fields != nullptr && generic->field_count > 0) {
        size_t fc = generic->field_count;
        auto fbuf = std::make_unique<FieldInfo[]>(fc);
        std::memcpy(fbuf.get(), generic->fields, fc * sizeof(FieldInfo));
        if (new_params != nullptr) {
            resolve_generic_fields(fbuf.get(), fc, new_params, np);
        }
        clone->fields = fbuf.get();
        generic_store_fields_.push_back(std::move(fbuf));
    }

    // --- resolver MethodInfo[]: argumentos y tipo de retorno ---
    if (generic->methods != nullptr && generic->method_count > 0) {
        size_t mc = generic->method_count;
        auto mbuf = std::make_unique<MethodInfo[]>(mc);
        std::memcpy(mbuf.get(), generic->methods, mc * sizeof(MethodInfo));

        for (size_t mi = 0; mi < mc; mi++) {
            // resolver argumentos del metodo
            if (new_params != nullptr && mbuf[mi].args != nullptr &&
                mbuf[mi].arg_count > 0) {
                size_t ac = mbuf[mi].arg_count;
                auto abuf = std::make_unique<FieldInfo[]>(ac);
                std::memcpy(abuf.get(), mbuf[mi].args, ac * sizeof(FieldInfo));
                resolve_generic_fields(abuf.get(), ac, new_params, np);
                mbuf[mi].args = abuf.get();
                generic_store_fields_.push_back(std::move(abuf));
            }
            // resolver tipo de retorno si es un parametro de tipo
            if (new_params != nullptr && mbuf[mi].return_type != nullptr &&
                mbuf[mi].return_type->is_type_param) {
                auto rbuf = std::make_unique<FieldInfo[]>(1);
                std::memcpy(rbuf.get(), mbuf[mi].return_type,
                            sizeof(FieldInfo));
                resolve_generic_fields(rbuf.get(), 1, new_params, np);
                mbuf[mi].return_type = rbuf.get();
                generic_store_fields_.push_back(std::move(rbuf));
            }
        }
        clone->methods = mbuf.get();
        generic_store_methods_.push_back(std::move(mbuf));
    }

    ClassInfo *raw = clone.get();
    generic_store_.push_back(std::move(clone)); // transferir propiedad
    generic_cache_.emplace(std::move(key), raw);
    return raw;
}

} // namespace loader
