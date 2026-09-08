/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/naked_native.cpp
 * @brief Implementacion del dispatcher @c vrt_naked_dispatch para inline-asm
 *        @Naked que referencia simbolos propios (bug/feature 198).  Ver
 *        naked_native.h.
 */

#include "util/env_flags.h"
#include "jit/naked_native.h"

#include "jit/code_cache.h"
#include "jit/vreg_pipeline.h"
#include "jit/auto_jit.h" // FN.3: lookup/compile/get_or_init_code_cache
#include "jit/interp_jit_bridge.h" // FN.3: enter_jit (VM_ABI dispatch)
#include "ffi/virtual_lib_registry.h"
#include "ffi/native_ffi.h"
#include "runtime/proceso_runtime.h"
#include "runtime/runtime.h"
#include "runtime/scheduler.h"
#include "runtime/native_invoke.h" // invoke_native_unchecked (CALLIND naked)
#include "runtime/exception_runtime.h" // throw_fatal (CALLIND null)
#include "vesta_rt/public.h"           // vrt_call_bc_function (CALLIND VA)
#include "vesta_rt/abi.h"              // VESTA_FATAL_* codes
#include "loader/loader.h"
#include "ir/ssa_ir.h"

#include <cstdlib> // getenv (VESTA_NAKED_DEBUG)

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace jit {

namespace {

/// Entrada nativa cacheada de una funcion @Naked (o de una callee alcanzable).
struct NakedEntry {
    uint8_t *code = nullptr; ///< direccion nativa en el code cache.
};

/// Estado global del dispatcher: code cache de vida-proceso + cache
/// nombre -> entrada nativa.  Protegido por mutex (compilacion es cold path).
struct NakedState {
    CodeCache cc;
    std::unordered_map<std::string, NakedEntry> by_name; ///< label -> entrada
    std::mutex mtx;
};

NakedState &state() {
    static NakedState s;
    return s;
}

/**
 * @brief Traduce una direccion VM (@p vaddr) a su puntero HOST usando el
 *        page-cache de @c VirtualMemory.  Warmea la pagina con un
 *        @c read_u64_fast y compone host_base + offset.  Suficiente para un
 *        slot de global (<= 8 bytes, dentro de una pagina).
 * @return host_ptr, o 0 si la traduccion fallo.
 */
uint64_t vm_addr_to_host(runtime::ProcessVM *vm, uint64_t vaddr) {
    if (vm == nullptr) return 0;
    // Warm de la pagina: cualquier lectura hace que el page-cache apunte a la
    // pagina de vaddr; luego jit_cached_page_host + off da el host_ptr.
    (void)vm->vm_mem.read_u64_fast(vaddr & ~7ULL);
    const uint64_t page = vaddr & ~0xFFFULL;
    if (vm->vm_mem.jit_cached_page_vaddr() != page) return 0;
    uint8_t *host = vm->vm_mem.jit_cached_page_host();
    if (host == nullptr) return 0;
    return reinterpret_cast<uint64_t>(host) +
           static_cast<uint64_t>(vaddr & 0xFFFULL);
}

/// Busca el Executable cargado que contiene la funcion @p name en su IR.
loader::Executable *find_exe_with_fn(runtime::ProcessVM *vm,
                                     const std::string &name, size_t &out_idx) {
    if (vm == nullptr) return nullptr;
    auto &loader = vm->scheduler.vm_reference.loader_public;
    for (auto &exe : loader.executables) {
        if (!exe) continue;
        auto it = exe->ir_lookup.find(name);
        if (it != exe->ir_lookup.end() &&
            it->second < exe->ir_functions.size()) {
            out_idx = it->second;
            return exe.get();
        }
    }
    return nullptr;
}

/// Resuelve una direccion NATIVA para un simbolo referenciado desde el asm de
/// una funcion @Naked.  Devuelve 0 si no resuelve (el caller aborta).
/// Compila recursivamente las callees Vesta (naked o no) como HOST_LEAF.
uint64_t compile_native_fn(runtime::ProcessVM *vm, const std::string &name,
                           bool debug);

/**
 * @brief Resuelve el simbolo @p sym (de un @c NativeReloc) a una direccion
 *        viva.  Casos:
 *   - "fnsym:<label>" / bare (CALL_REL32): direccion NATIVA de una funcion
 *     del modulo (compilada al vuelo) o de un extern (FFI).
 *   - "rodata.<slot>": direccion HOST del slot, este en `gdata` (bloque host,
 *     donde vive el storage de las variables globales) o en `code` (memoria de
 *     la VM, donde viven los literales).
 */
uint64_t resolve_naked_symbol(runtime::ProcessVM *vm, const std::string &sym,
                              bool is_call, bool debug) {
    // Global (slot de static_data): rodata.<slot> -> direccion HOST del slot.
    if (sym.rfind("rodata.", 0) == 0) {
        const std::string slot_str = sym.substr(7);
        // El slot idx <slot> es la etiqueta `<seccion>.s_<slot>` que el linker
        // resolvio en el symbol_table del Executable.  Dos secciones posibles:
        //   - `gdata`: storage de una variable global.  El loader la
        //     materializa en un bloque HOST y ya reescribio su entrada del
        //     symbol_table con la direccion host -> se usa TAL CUAL.
        //   - `code`: literal en memoria de la VM -> hay que traducir.
        auto &loader = vm->scheduler.vm_reference.loader_public;
        for (auto &exe : loader.executables) {
            if (!exe) continue;
            auto it = exe->symbol_table.find("gdata.s_" + slot_str);
            if (it != exe->symbol_table.end()) {
                if (debug)
                    std::fprintf(stderr, "[naked] global %s -> host=0x%llx\n",
                                 sym.c_str(), (unsigned long long)it->second);
                return it->second;
            }
            it = exe->symbol_table.find("code.s_" + slot_str);
            if (it != exe->symbol_table.end()) {
                const uint64_t host = vm_addr_to_host(vm, it->second);
                if (debug)
                    std::fprintf(stderr,
                                 "[naked] global %s -> va=0x%llx host=0x%llx\n",
                                 sym.c_str(), (unsigned long long)it->second,
                                 (unsigned long long)host);
                return host;
            }
        }
        if (debug)
            std::fprintf(stderr,
                         "[naked] global %s: ni 'gdata.s_%s' ni 'code.s_%s' en "
                         "symbol_table\n",
                         sym.c_str(), slot_str.c_str(), slot_str.c_str());
        return 0;
    }
    // Referencia a la DIRECCION de una funcion (fnsym:) o CALL directo (bare).
    std::string fn = sym;
    if (fn.rfind("fnsym:", 0) == 0) fn = fn.substr(6);
    // Funcion del modulo -> compilar al vuelo.
    size_t idx;
    if (find_exe_with_fn(vm, fn, idx) != nullptr) {
        return compile_native_fn(vm, fn, debug);
    }
    // Externo: FFI (libc / runtime).  Intentar via el registro virtual y el
    // loader nativo del propio proceso.
    void *nf = ffi::lookup_virtual_fn("vrt", fn);
    if (nf) return reinterpret_cast<uint64_t>(nf);
    if (debug)
        std::fprintf(stderr, "[naked] simbolo externo '%s' no resuelto\n",
                     fn.c_str());
    (void)is_call;
    return 0;
}

/**
 * @brief Compila (o recupera de cache) la funcion Vesta @p name como una
 * entrada NATIVA (ABI HOST_LEAF, respetando @c is_naked) con TODOS sus relocs
 *        resueltos a direcciones vivas.  Devuelve la direccion, o 0 si falla.
 */
uint64_t compile_native_fn(runtime::ProcessVM *vm, const std::string &name,
                           bool debug) {
    // GUARD DE ARQUITECTURA (bug/feature 198): el inline-asm con simbolos
    // propios se apoya en el backend nativo x86-64 (@c vreg_compile_native +
    // @c x86_encoder).  Donde ese backend NO existe (futuro ARM/RISC-V sin
    // encoder) NO podemos native-compilar la funcion @Naked -> emitimos un
    // error CLARO en vez de ensamblar codigo x86 en una CPU que no lo ejecuta
    // (lo que produciria una instruccion ilegal / crash).  El interprete de
    // bytecode NORMAL sigue siendo 100% portable: este path SOLO se alcanza
    // desde inline-asm @Naked, nunca desde un programa Vesta corriente.
#if !(defined(__x86_64__) || defined(_M_X64) || defined(__amd64__))
    (void)vm;
    (void)debug;
    std::fprintf(stderr,
                 "[naked] inline asm con simbolos propios (funcion '%s'): no "
                 "soportado en esta arquitectura (requiere backend nativo "
                 "x86-64)\n",
                 name.c_str());
    return 0;
#else
    NakedState &st = state();
    // Cache hit.
    auto cit = st.by_name.find(name);
    if (cit != st.by_name.end())
        return reinterpret_cast<uint64_t>(cit->second.code);

    size_t idx;
    loader::Executable *exe = find_exe_with_fn(vm, name, idx);
    if (exe == nullptr) {
        if (debug)
            std::fprintf(stderr, "[naked] fn '%s' sin IR en executables\n",
                         name.c_str());
        return 0;
    }
    const ir::IrFunction &fn = exe->ir_functions[idx];

    // Placeholder ANTES de recursar (corta ciclos de mutua recursion: una
    // callee que llama de vuelta al caller ve la entrada en-progreso).  La
    // direccion todavia no es valida; el codegen produce una CALL_REL32 con
    // un placeholder que parcheamos DESPUES de conocer la direccion real.
    // Para no complicar, compilamos primero los bytes, colocamos, y luego
    // resolvemos los relocs (que pueden re-entrar a compile_native_fn).

    // Codegen HOST_LEAF con el ABI del HOST (Win64 en Windows, SysV en POSIX)
    // -- el asm @Naked del usuario asume el ABI nativo del host donde corre el
    // interp/JIT.  PIC=false: los datos (globales) se referencian por su
    // direccion absoluta (ABS64), que apunta al slot en vm_mem.  Sin embargo
    // el selector emite `[rel sym]` (DATA_REL32) por defecto; lo resolvemos
    // rip-relativo tras colocar el codigo.
    std::vector<NativeReloc> relocs;
    std::vector<uint8_t> bytes = jit::vreg_compile_native(
        fn, /*resolve_call=*/{}, /*ent=*/{}, /*resolve_native=*/{},
        /*resolve_symbol=*/{}, &relocs, /*pic=*/true,
#if defined(_WIN32)
        /*target_sysv=*/false
#else
        /*target_sysv=*/true
#endif
    );
    if (bytes.empty()) {
        if (debug)
            std::fprintf(stderr,
                         "[naked] vreg_compile_native fallo para '%s'\n",
                         name.c_str());
        return 0;
    }

    /* ANTES de reservar: decirle al cache DONDE conviene poner el codigo.
     *
     * Lo que se emite alcanza los globales del modulo con desplazamientos
     * relativos a RIP de 32 bits, o sea +-2 GB.  El primer `gdata.s_*` de la
     * tabla de simbolos del cargador es una direccion representativa de esa
     * zona, y esta disponible ya -- no hay que compilar nada para saberla --,
     * asi que sirve de ancla.  Sin esto el sistema elegia y la distancia era
     * cosa del azar: funciono mientras codigo y datos salian del mismo
     * asignador, y dejo de funcionar en cuanto se separaron. */
    for (auto &exe : vm->scheduler.vm_reference.loader_public.executables) {
        if (!exe) continue;
        bool puesto = false;
        for (const auto &s : exe->symbol_table) {
            if (s.first.rfind("gdata.s_", 0) != 0) continue;
            st.cc.set_anchor(static_cast<uintptr_t>(s.second));
            puesto = true;
            break;
        }
        if (puesto) break;
    }

    // Colocar en el code cache (direccion estable).
    uint8_t *code = st.cc.alloc(bytes.size(), 16);
    if (code == nullptr) return 0;
    /* Donde acabo el codigo respecto al ancla.  Sin esto, "rel32 fuera de
     * rango" dice QUE no alcanza pero no si el ancla se puso, si la reserva
     * cercana se intento o si fallo -- que son tres arreglos distintos.  La
     * distancia con signo es el dato: si sale menor de 2 GB, el problema no es
     * la colocacion sino otro. */
    if (debug) {
        const int64_t dist = static_cast<int64_t>(reinterpret_cast<uint64_t>(
                                 code)) -
                             static_cast<int64_t>(st.cc.anchor());
        std::fprintf(
            stderr,
            "[naked] ancla=0x%llx codigo=%p distancia=%lld (%lld MiB) %s\n",
            (unsigned long long)st.cc.anchor(), (void *)code, (long long)dist,
            (long long)(dist / (1024 * 1024)),
            st.cc.anchored() ? "colocado cerca del ancla"
                             : "SIN hueco cerca: lo eligio el sistema");
        if (!st.cc.anchored())
            std::fprintf(stderr,
                         "[naked]   el barrido vio %zu regiones, hueco mayor "
                         "%zu KiB\n",
                         st.cc.scan_regions(),
                         st.cc.scan_largest_free() / 1024);
    }
    std::memcpy(code, bytes.data(), bytes.size());
    // Registrar YA en cache (por direccion) para cortar recursion de callees
    // que se llaman entre si.
    st.by_name[name] = NakedEntry{code};

    // Resolver + aplicar cada reloc en el code cache (RWX).
    bool ok = true;
    for (const NativeReloc &r : relocs) {
        const bool is_call = (r.kind == NativeReloc::Kind::CALL_REL32);
        uint64_t target = resolve_naked_symbol(vm, r.symbol, is_call, debug);
        if (target == 0) {
            ok = false;
            break;
        }
        target += static_cast<uint64_t>(r.addend);
        uint8_t *site = code + r.offset;
        switch (r.kind) {
        case NativeReloc::Kind::CALL_REL32:
        case NativeReloc::Kind::DATA_REL32: {
            // rel32 = target - (site + 4)
            const int64_t rel =
                static_cast<int64_t>(target) -
                static_cast<int64_t>(reinterpret_cast<uint64_t>(site) + 4);
            if (rel < INT32_MIN || rel > INT32_MAX) {
                if (debug)
                    std::fprintf(stderr,
                                 "[naked] rel32 fuera de rango para '%s'\n",
                                 r.symbol.c_str());
                ok = false;
                break;
            }
            const int32_t rel32 = static_cast<int32_t>(rel);
            std::memcpy(site, &rel32, 4);
            break;
        }
        case NativeReloc::Kind::ABS64: std::memcpy(site, &target, 8); break;
        default:
            if (debug)
                std::fprintf(stderr, "[naked] reloc kind %d no soportado\n",
                             static_cast<int>(r.kind));
            ok = false;
            break;
        }
        if (!ok) break;
    }
    if (!ok) {
        // Invalidar la entrada rota (rellenar con INT3) y quitar del cache.
        st.cc.invalidate(code, bytes.size());
        st.by_name.erase(name);
        return 0;
    }
    st.cc.commit(code, bytes.size());
    if (debug) {
        std::fprintf(stderr, "[naked] '%s' compilada nativa @ %p (%zu bytes)\n",
                     name.c_str(), (void *)code, bytes.size());
        std::fprintf(stderr, "[naked]   bytes:");
        for (size_t i = 0; i < bytes.size(); ++i)
            std::fprintf(stderr, " %02x", code[i]);
        std::fprintf(stderr, "\n");
    }
    return reinterpret_cast<uint64_t>(code);
#endif // arquitectura x86-64
}

/**
 * @brief Invoca la entrada nativa @p fn (ABI HOST_LEAF) con @p argc argumentos
 *        ya en @p a[]; devuelve rax.  Reusa el switch por argc (mismo patron
 *        que @c invoke_native_unchecked, pero con args explicitos).
 */
uint64_t invoke_naked(void *fn, int argc, const uint64_t *a) {
    using F0 = uint64_t (*)();
    using F1 = uint64_t (*)(uint64_t);
    using F2 = uint64_t (*)(uint64_t, uint64_t);
    using F3 = uint64_t (*)(uint64_t, uint64_t, uint64_t);
    using F4 = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t);
    using F5 = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    using F6 = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t);
    switch (argc) {
    case 0: return reinterpret_cast<F0>(fn)();
    case 1: return reinterpret_cast<F1>(fn)(a[0]);
    case 2: return reinterpret_cast<F2>(fn)(a[0], a[1]);
    case 3: return reinterpret_cast<F3>(fn)(a[0], a[1], a[2]);
    case 4: return reinterpret_cast<F4>(fn)(a[0], a[1], a[2], a[3]);
    case 5: return reinterpret_cast<F5>(fn)(a[0], a[1], a[2], a[3], a[4]);
    default:
        return reinterpret_cast<F6>(fn)(a[0], a[1], a[2], a[3], a[4], a[5]);
    }
}

} // namespace

/**
 * @brief Helper CALLN: dispatcher de llamadas a funciones @Naked.
 *
 * Convencion (via CALLN, argc marshalizado por el interp/JIT):
 *   arg0 = proc      = ProcessVM* (getproc)
 *   arg1 = name_hash = FNV-1a del nombre de la funcion @Naked
 *   arg2 = argc_real = numero de argumentos reales de la funcion @Naked
 *   arg3..arg8       = los argumentos reales (hasta 6)
 *
 * Localiza (o compila al vuelo) la entrada NATIVA de la funcion @Naked con
 * sus simbolos propios resueltos, la invoca con los args reales (ABI nativo),
 * y devuelve su rax (que el CALLN escribe a R0).
 */
extern "C" uint64_t vrt_naked_dispatch(uint64_t proc, uint64_t name_hash,
                                       uint64_t argc_real, uint64_t a0,
                                       uint64_t a1, uint64_t a2, uint64_t a3,
                                       uint64_t a4, uint64_t a5) {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
    if (vm == nullptr) return 0;
    static const bool debug = util::flag_on(util::FlagId::NakedDebug);

    // Localizar el nombre de la funcion @Naked por hash: escaneamos los IR de
    // los executables cargados buscando el que coincide (barato; solo cold
    // path en la primera llamada, luego cache).
    std::string target_name;
    {
        auto &loader = vm->scheduler.vm_reference.loader_public;
        for (auto &exe : loader.executables) {
            if (!exe) continue;
            for (const auto &f : exe->ir_functions) {
                if (fnv1a64_name(f.name.c_str()) == name_hash) {
                    target_name = f.name;
                    break;
                }
            }
            if (!target_name.empty()) break;
        }
    }
    if (target_name.empty()) {
        std::fprintf(stderr,
                     "[naked] vrt_naked_dispatch: hash 0x%llx sin funcion\n",
                     (unsigned long long)name_hash);
        return 0;
    }

    NakedState &st = state();
    uint64_t entry = 0;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        entry = compile_native_fn(vm, target_name, debug);
    }
    if (entry == 0) {
        std::fprintf(stderr, "[naked] no se pudo compilar nativa '%s'\n",
                     target_name.c_str());
        return 0;
    }

    const uint64_t args[6] = {a0, a1, a2, a3, a4, a5};
    int ac = static_cast<int>(argc_real);
    if (ac < 0) ac = 0;
    if (ac > 6) ac = 6;
    if (debug)
        std::fprintf(stderr,
                     "[naked] invoke '%s' entry=%p argc=%d a0=%llu a1=%llu\n",
                     target_name.c_str(), (void *)entry, ac,
                     (unsigned long long)a0, (unsigned long long)a1);
    uint64_t rv = invoke_naked(reinterpret_cast<void *>(entry), ac, args);
    if (debug)
        std::fprintf(stderr, "[naked] '%s' -> %llu\n", target_name.c_str(),
                     (unsigned long long)rv);
    return rv;
}

void register_naked_dispatch_runner() {
    ffi::register_virtual_fn("vrt", "naked_dispatch",
                             reinterpret_cast<void *>(&vrt_naked_dispatch));
}

bool is_naked_native_addr(uint64_t addr) {
    if (addr == 0) return false;
    NakedState &st = state();
    // El CodeCache expone contains(); protegido por el mutex del estado (el
    // check es cold-ish: solo en callvmr sobre un fp fuera de rango VM).
    std::lock_guard<std::mutex> lk(st.mtx);
    return st.cc.contains(reinterpret_cast<const uint8_t *>(addr));
}

extern "C" uint64_t vrt_naked_fnaddr(uint64_t proc, uint64_t name_hash) {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc);
    if (vm == nullptr) return 0;
    static const bool debug = util::flag_on(util::FlagId::NakedDebug);
    // Localizar el nombre por hash (igual que el dispatcher).
    std::string target_name;
    {
        auto &loader = vm->scheduler.vm_reference.loader_public;
        for (auto &exe : loader.executables) {
            if (!exe) continue;
            for (const auto &f : exe->ir_functions) {
                if (fnv1a64_name(f.name.c_str()) == name_hash) {
                    target_name = f.name;
                    break;
                }
            }
            if (!target_name.empty()) break;
        }
    }
    if (target_name.empty()) {
        /* No es "devuelvo cero y ya": un cero se usa DESPUES como direccion de
         * una funcion -- de hecho como punto de entrada de un hilo --, asi que
         * callarlo convierte un fallo de compilacion en un salto a la direccion
         * cero, tres capas mas abajo y sin ninguna pista.  Eso es exactamente lo
         * que paso: un `vx_thread_spawn` arrancaba un hilo en 0 y el proceso
         * moria con una traza vacia. */
        runtime::throw_fatalf(vm, runtime::FATAL_INVALID_SYSCALL,
                     "(cfn) sobre una funcion que no existe: ninguna funcion "
                     "cargada tiene la huella 0x%llx",
                     (unsigned long long)name_hash);
        return 0;
    }
    NakedState &st = state();
    std::lock_guard<std::mutex> lk(st.mtx);
    uint64_t entry = compile_native_fn(vm, target_name, debug);
    if (debug)
        std::fprintf(stderr, "[naked] fnaddr '%s' -> 0x%llx\n",
                     target_name.c_str(), (unsigned long long)entry);
    if (entry == 0) {
        /* Lo mismo por el otro lado: si la compilacion nativa no sale, hay que
         * DECIRLO aqui.  `compile_native_fn` ya explica el motivo por
         * `VESTA_NAKED_DEBUG`, pero sin la bandera puesta -- que es el caso
         * normal -- devolver cero dejaba el fallo mudo. */
        runtime::throw_fatalf(vm, runtime::FATAL_INVALID_SYSCALL,
                     "no se pudo compilar '%s' a codigo nativo, que es lo que "
                     "exige tomar su direccion con (cfn).  Con "
                     "VESTA_NAKED_DEBUG=1 se dice por que",
                     target_name.c_str());
    }
    return entry;
}

void register_naked_fnaddr_runner() {
    ffi::register_virtual_fn("vrt", "naked_fnaddr",
                             reinterpret_cast<void *>(&vrt_naked_fnaddr));
}

/* ===================================================================== */
/* FN.3: fibras nativas en JIT                                            */
/* ===================================================================== */

uint64_t compile_naked_native(runtime::ProcessVM *vm, const std::string &name) {
    static const bool debug = util::flag_on(util::FlagId::NakedDebug);
    NakedState &st = state();
    std::lock_guard<std::mutex> lk(st.mtx);
    return compile_native_fn(vm, name, debug);
}

extern "C" void vrt_callind(uint64_t proc_u, uint64_t addr) {
    auto *vm = reinterpret_cast<runtime::ProcessVM *>(proc_u);
    if (vm == nullptr) return;
    /* Puntero a funcion nulo: lo delegamos a vrt_call_bc_function(...,0),
     * que lanza un FatalError de null-pointer capturable (mismo trato que
     * el interp al saltar a la VA 0). */
    if (addr == 0) {
        vrt_call_bc_function(reinterpret_cast<vrt_proc *>(vm), 0);
        return;
    }
    /* (a) naked-native (HOST_LEAF): `(cfn)fn` via naked_fnaddr o el thunk
     *     de un extern.  Se invoca con ABI del host, args marshalizados
     *     desde los regs VM (identico a exec_instr_callvmr).  regs[15]=argc. */
    if (is_naked_native_addr(addr)) {
        const uint64_t argc = vm->registers.regs[15].qword();
        const uint64_t r = runtime::invoke_native_unchecked(
            reinterpret_cast<void *>(addr), argc, vm);
        vm->registers.regs[0].qword(r);
        return;
    }
    /* (b) jit_code VM_ABI: `&fn` de una funcion ya compilada (pieza 1 dejo
     *     el puntero de codigo nativo del JIT).  Entramos directo: la fn lee
     *     sus params de proc->registers (ya stagedos) y escribe regs[0]. */
    if (CodeCache *cc = get_or_init_code_cache()) {
        if (cc->contains(reinterpret_cast<const uint8_t *>(addr))) {
            enter_jit(reinterpret_cast<JitFn>(addr),
                      reinterpret_cast<vrt_proc *>(vm));
            return;
        }
    }
    /* (c) VA de bytecode: la fn aun no esta compilada.  Buscamos su jit_code
     *     por VA; si no hay, compile-on-demand; y solo como ultimo recurso
     *     (que el corpus no alcanza) ejecutamos el bytecode -- el resultado
     *     es identico en todo caso, garantizando vm==jit. */
    void *jc = lookup_jit_code_at_pc(addr);
    if (jc == nullptr && g_jit_threshold != UINT32_MAX) {
        maybe_compile_callvm_target(vm, addr);
        jc = lookup_jit_code_at_pc(addr);
    }
    if (jc != nullptr) {
        enter_jit(reinterpret_cast<JitFn>(jc),
                  reinterpret_cast<vrt_proc *>(vm));
        return;
    }
    vrt_call_bc_function(reinterpret_cast<vrt_proc *>(vm), addr);
}

extern "C" int32_t vrt_jit_active(void) {
    /* g_pc_jit_active pasa a true en cuanto se registra la primera funcion
     * JIT (en -m jit el force-eager + el eager-compile de main lo hacen al
     * cargar, antes de que main ejecute).  En -m vm (threshold desactivado)
     * no se compila nada -> sigue false.  Es exactamente la senal que el
     * setup de fibras necesita: main corre nativo (JIT) vs interp. */
    return g_pc_jit_active ? 1 : 0;
}

extern "C" uint64_t vrt_getproc(void) {
    return reinterpret_cast<uint64_t>(runtime::get_current_executing_process());
}

/* Tamano de una pila de fibra en JIT (host).  Fijo, sin guard page (v1). */
static constexpr size_t kFiberJitStackBytes = 65536;
/* Slots del ctx (qwords): PC/SP/BP + 8 callee-saved (rbx,r12..r15,rdi,rsi) +
 * holgura.  152 bytes = 19 qwords; reservamos 20 (160 B) por alineacion. */
static constexpr size_t kFiberJitCtxQwords = 20;

extern "C" uint64_t vrt_fiber_jit_ctx(uint64_t entry) {
    runtime::ProcessVM *vm = runtime::get_current_executing_process();
    if (vm == nullptr) return 0;
    /* Trampolin nativo: pone proc en el arg-reg y salta al entry VM_ABI. */
    const uint64_t tramp = compile_naked_native(vm, "__fiber_trampoline");
    if (tramp == 0) return 0;
    auto *ctx = static_cast<uint64_t *>(std::calloc(kFiberJitCtxQwords, 8));
    auto *stk = static_cast<uint8_t *>(std::malloc(kFiberJitStackBytes));
    if (ctx == nullptr || stk == nullptr) {
        std::free(ctx);
        std::free(stk);
        return 0;
    }
    /* Cima de la pila host, 16-alineada (la pila crece hacia abajo). */
    const uint64_t top =
        (reinterpret_cast<uint64_t>(stk) + kFiberJitStackBytes) & ~15ULL;
    ctx[0] = tramp;                          // PC   (arranque = trampolin)
    ctx[1] = top;                            // SP
    ctx[2] = top;                            // BP
    ctx[3] = reinterpret_cast<uint64_t>(vm); // rbx = proc (VM_ABI del entry)
    ctx[4] = entry;                          // r12 = entry (trampolin: jmp r12)
    /* ctx[5..] (r13,r14,r15,rdi,rsi,...) ya a 0 por calloc. */
    return reinterpret_cast<uint64_t>(ctx);
}

extern "C" uint64_t vrt_fiber_jit_scratch(void) {
    auto *ctx = static_cast<uint64_t *>(std::calloc(kFiberJitCtxQwords, 8));
    return reinterpret_cast<uint64_t>(ctx);
}

void register_fiber_runtime_runner() {
    ffi::register_virtual_fn("vrt", "jit_active",
                             reinterpret_cast<void *>(&vrt_jit_active));
    ffi::register_virtual_fn("vrt", "getproc",
                             reinterpret_cast<void *>(&vrt_getproc));
    ffi::register_virtual_fn("vrt", "fiber_jit_ctx",
                             reinterpret_cast<void *>(&vrt_fiber_jit_ctx));
    ffi::register_virtual_fn("vrt", "fiber_jit_scratch",
                             reinterpret_cast<void *>(&vrt_fiber_jit_scratch));
}

} // namespace jit
