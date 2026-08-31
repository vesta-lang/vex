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
 * @file aot/link_script.cpp
 * @brief  AOT.5 -- runner del script de enlace Vesta.
 *
 * Construye un programa Vesta completo a partir del script del usuario (que
 * solo define @c fn link()): le antepone los @c extern "vxlink" de los builtins
 * + unos wrappers que pasan los strings via @c str_cstr (host ptr), y le anyade
 * un @c main que llama a @c link().  Compila ese programa a @c .velb in-process
 * (frontend Vesta + ensamblador) y lo ejecuta en una VM con los builtins de
 * configuracion registrados via @c ffi::register_virtual_fn.  Los builtins
 * escriben en una @c LinkScriptConfig apuntada por un puntero file-static
 * (la ejecucion del script es single-thread, una vez por enlace).
 */

#include "aot/link_script.h"
#include <algorithm> // UCRT64: no transitivo

#include "ffi/virtual_lib_registry.h"
#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "runtime/runtime.h"
#include "util/assembler_multiprocess.h"
#include "vx/compiler.h"
#include "vx/diag/diag_format.h" // render_diagnostics: el guion dice POR QUE no compila

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>

namespace {
/// RAII: silencia std::cout mientras vive (el ensamblador in-process emite
/// __VESTA_TIMES__ a stdout; no queremos ese ruido en la salida del linker).
struct CoutSilencer {
    std::streambuf *prev;
    std::ostringstream sink;
    CoutSilencer() : prev(std::cout.rdbuf(sink.rdbuf())) {}
    ~CoutSilencer() { std::cout.rdbuf(prev); }
};
} // namespace

namespace aot {
namespace {

// Estado del enlace en curso (la ejecucion del script es single-thread).
LinkScriptConfig *g_cfg = nullptr;
const std::unordered_map<std::string, uint64_t> *g_sizes = nullptr;
bool g_dbg = false;

// --- Builtins nativos (firma u64(u64,...) que espera invoke_native_unchecked).
//     Los punteros de string llegan como u64 (host ptr de str_cstr). ---
uint64_t vxlink_base(uint64_t a) {
    if (g_cfg) {
        g_cfg->base = a;
        g_cfg->has_base = true;
    }
    return 0;
}
uint64_t vxlink_stack(uint64_t n) {
    if (g_cfg) {
        g_cfg->stack = n;
        g_cfg->has_stack = true;
    }
    return 0;
}
uint64_t vxlink_entry_raw(uint64_t p) {
    if (g_cfg && p) {
        g_cfg->entry = reinterpret_cast<const char *>(p);
        g_cfg->has_entry = true;
    }
    return 0;
}
uint64_t vxlink_section_raw(uint64_t p, uint64_t a) {
    if (g_cfg && p) g_cfg->sections[reinterpret_cast<const char *>(p)] = a;
    return 0;
}
uint64_t vxlink_section_size_raw(uint64_t p) {
    if (g_sizes && p) {
        auto it = g_sizes->find(reinterpret_cast<const char *>(p));
        if (it != g_sizes->end()) return it->second;
    }
    return 0;
}
uint64_t vxlink_align_up(uint64_t v, uint64_t a) {
    if (a == 0) return v;
    return ((v + a - 1) / a) * a;
}
uint64_t vxlink_debug_build(void) {
    return g_dbg ? 1u : 0u;
}

void register_builtins_once() {
    static std::atomic<bool> done{false};
    bool expected = false;
    if (!done.compare_exchange_strong(expected, true)) return;
    // Nombres elegidos para NO colisionar con builtins existentes
    // (section_size/start/end del AOT; 'stack' reservado).
    ffi::register_virtual_fn("vxlink", "base", (void *)&vxlink_base);
    ffi::register_virtual_fn("vxlink", "stack_size", (void *)&vxlink_stack);
    ffi::register_virtual_fn("vxlink", "entry_raw", (void *)&vxlink_entry_raw);
    ffi::register_virtual_fn("vxlink", "place_raw",
                             (void *)&vxlink_section_raw);
    ffi::register_virtual_fn("vxlink", "secbytes_raw",
                             (void *)&vxlink_section_size_raw);
    ffi::register_virtual_fn("vxlink", "align_up", (void *)&vxlink_align_up);
    ffi::register_virtual_fn("vxlink", "debug_build",
                             (void *)&vxlink_debug_build);
}

// Prelude inyectado: declara los externs + wrappers ergonomicos (los que
// reciben nombre usan str_cstr para pasar un host ptr nul-terminado).
const char *kPrelude =
    "extern \"vxlink\" {\n"
    "    fn base(u64 a) -> void;\n"
    "    fn stack_size(u64 n) -> void;\n"
    "    fn entry_raw(char* p) -> void;\n"
    "    fn place_raw(char* p, u64 a) -> void;\n"
    "    fn secbytes_raw(char* p) -> u64;\n"
    "    fn align_up(u64 v, u64 a) -> u64;\n"
    "    fn debug_build() -> bool;\n"
    "}\n"
    // Las operaciones de cadena son METODOS.  Esto decia `str_cstr(s)`, la
    // forma de funcion libre que se retiro del lenguaje, y el guion de enlazado
    // dejo de compilar sin que se notara: el error se tragaba y solo salia
    // "error de compilacion Vesta".
    "void entry(string s) { entry_raw(s.cstr()); }\n"
    "void place_section(string nm, u64 a) { place_raw(nm.cstr(), a); }\n"
    "u64 section_bytes(string nm) { return secbytes_raw(nm.cstr()); }\n";

const char *kMainWrapper = "\ni32 main() { link(); return 0; }\n";

bool read_text(const std::string &path, std::string &out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

bool read_file_bytes_local(const std::string &path, std::vector<uint8_t> &out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize n = f.tellg();
    if (n < 0) return false;
    f.seekg(0);
    out.resize((size_t)n);
    if (n > 0) f.read(reinterpret_cast<char *>(out.data()), n);
    return (bool)f;
}

// Compila la fuente Vesta combinada a bytes .velb (frontend + ensamblador).
bool compile_to_velb(const std::string &src, std::vector<uint8_t> &out,
                     std::string &err) {
    vx::CompileOptions copts;
    copts.module_name = "linkscript";
    vx::CompileResult cr = vx::compile_vx_source(src, "linkscript.vx", copts);
    if (!cr.ok || cr.diagnostics.has_errors()) {
        /* Se ENSENA lo que dijo el compilador.  Antes solo salia "error de
         * compilacion Vesta", que dice que fallo y no dice nada de por que: un
         * guion de enlazado con una linea mal quedaba sin enlazar y sin pista,
         * y encima el fichero que se compila es una COMBINACION (el guion del
         * usuario mas el preludio con `base`, `entry` y demas), asi que ni
         * mirando su fuente se veian las lineas de verdad. */
        std::ostringstream ds;
        vx::render_diagnostics(ds, cr.diagnostics, vx::DiagFormat::Text);
        err = "link-script: no compila\n" + ds.str();
        return false;
    }
    // Ensamblar el .vel a .velb via run_worker (opera sobre ficheros).
    std::string prefix;
    {
        std::ostringstream ss;
        ss << (std::getenv("TEMP")
                   ? std::getenv("TEMP")
                   : (std::getenv("TMP") ? std::getenv("TMP") : "/tmp"))
           << "/vxlink_" << (void *)&src;
        prefix = ss.str();
    }
    const std::string vel_path = prefix + ".vel";
    const std::string velb_path = prefix + ".velb";
    {
        std::ofstream ofs(vel_path);
        if (!ofs) {
            err = "link-script: no se pudo crear temporal " + vel_path;
            return false;
        }
        ofs << cr.vel_text;
    }
    int rc;
    {
        CoutSilencer silence; // ocultar __VESTA_TIMES__ del ensamblador
        rc = asm_multi_process::run_worker(vel_path, prefix,
                                           /*skip_preprocessor=*/true,
                                           /*keep_labels=*/false,
                                           &cr.ir_section_bytes,
                                           /*emit_map=*/false);
    }
    std::remove(vel_path.c_str());
    if (rc != 0) {
        std::remove(velb_path.c_str());
        err = "link-script: fallo al ensamblar (rc=" + std::to_string(rc) + ")";
        return false;
    }
    bool ok = read_file_bytes_local(velb_path, out);
    std::remove(velb_path.c_str());
    if (!ok || out.empty()) {
        err = "link-script: .velb vacio o ilegible";
        return false;
    }
    return true;
}

} // namespace

bool aot_run_link_script(
    const std::string &script_path,
    const std::unordered_map<std::string, uint64_t> &sec_sizes,
    bool debug_build, LinkScriptConfig &out, std::string &err) {
    std::string user_src;
    if (!read_text(script_path, user_src)) {
        err = "link-script: no se puede abrir " + script_path;
        return false;
    }
    register_builtins_once();

    std::string full = std::string(kPrelude) + user_src + kMainWrapper;

    std::vector<uint8_t> velb;
    if (!compile_to_velb(full, velb, err)) return false;

    // Ejecutar el .velb con los builtins apuntando a 'out'.
    g_cfg = &out;
    g_sizes = &sec_sizes;
    g_dbg = debug_build;

    bool run_ok = true;
    {
        runtime::ManageVM mgr(nullptr, 0);
        runtime::VM *vm = mgr.loader.create_vm_instance(/*num_schedulers=*/1);
        if (!vm) {
            err = "link-script: no se pudo crear la VM";
            run_ok = false;
        } else {
            runtime::ProcessVM *proc =
                mgr.loader.load_executable(*vm, std::move(velb));
            if (!proc) {
                err = "link-script: no se pudo cargar el .velb del script";
                run_ok = false;
            } else {
                vm->make_ready(proc->pid);
                vm->start();
                {
                    std::unique_lock<std::mutex> lk(vm->done_mtx);
                    vm->done_cv.wait(lk, [&] {
                        return !vm->vm_running.load(std::memory_order_acquire);
                    });
                }
                vm->stop();
            }
        }
    }
    g_cfg = nullptr;
    g_sizes = nullptr;
    return run_ok;
}

} // namespace aot
