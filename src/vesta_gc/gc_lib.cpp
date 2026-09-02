/**
 * @file vesta_gc/gc_lib.cpp
 * @brief Implementacion de la C-ABI de `libvesta_gc` (GC opt-in de Vesta en
 * AOT).
 *
 * Envuelve un `gc::GcHeap` GLOBAL (singleton) sin `ProcessVM`: el mismo motor
 * generacional mark-sweep del interprete/JIT, pero con un unico heap de
 * proceso. Las raices se descubriran via stackmaps precisos sobre frames
 * nativos (Inc 2); en este Inc 0, `owner_proc_` es nullptr -> `major_gc`
 * conserva todos los handles vivos (no colecta todavia), suficiente para
 * validar alloc/deref.
 *
 * NOTA de enlazado (Inc 0b pendiente): `gc_heap.cpp` aun arrastra
 * `proceso_runtime.h` por los caminos guardados por `owner_proc_ != nullptr`
 * (shared-heap, scan conservativo).  Para un `.o` freestanding linkable sin la
 * VM hay que desacoplar esos sitios via una interfaz RootProvider ( C.3).
 * Hasta entonces esta TU se compila dentro del proyecto (linka la VM) y valida
 * el motor del GC operando ProcessVM-less.
 */

#include "vesta_gc/gc_lib.h"

#include "arena/arena_manager.h"
#include "gc/gc_heap.h"
#include "jit/jit_registry.h" // register_function (frames AOT en el scan preciso)
#include "jit/machine_ir.h"   // Stackmap / StackmapSlot

#include <cstdlib> // free (deleter default UNIQUE / ctrl block SHARED)
#include <cstring>

// Diagnostico: contador de finalizadores nativos ejecutados (verificacion del
// path en tests).  Global de archivo (no anonimo) para que gc_finalizer_run_
// native y el accessor extern "C" compartan el mismo simbolo.
static volatile uint64_t g_vx_gc_fin_count = 0;

namespace {

/**
 * @brief ArenaManager global del GC de AOT (reserva mmap/VirtualAlloc).
 * @return Referencia al manager unico, construido en el primer uso.
 */
vm::ArenaManager &gc_arena() {
    static vm::ArenaManager arena;
    return arena;
}

/**
 * @brief Heap global del GC de AOT.  Mismos parametros que el del ProcessVM
 *        (nursery 2 MiB, umbral old 8 MiB).  `owner_proc_` queda nullptr.
 * @return Referencia al GcHeap unico.
 * @note El static local garantiza orden de construccion: primero @c gc_arena()
 *       (lo invoca el inicializador), luego el GcHeap.
 */
gc::GcHeap &gc_heap() {
    static gc::GcHeap heap(gc_arena(), 2u * 1024u * 1024u, 8u * 1024u * 1024u);
    // Modo AOT: raices SOLO por stackmaps precisos (frames nativos via
    // JitRegistry) + external_refs + pending.  Sin esto el major_gc conservaria
    // todo (no colectaria).  v1 no-moving: vx_gc_alloc usa alloc_pinned ->
    // OldGen, el nursery queda vacio (sin riesgo de interior-ptr stale al
    // mover).  Set idempotente en cada acceso (1 store, a prueba de orden de
    // init de statics).
    heap.set_aot_mode(true);
    return heap;
}

/**
 * @brief Runner NATIVO de finalizadores GC en AOT.
 *
 * Lo instala @c vx_gc_init via @c set_finalizer_runner.  El sweep (major_gc)
 * stagea los datos del box colectado (mismo mecanismo que la VM) y este runner
 * los ejecuta por CALL DIRECTO al deleter/dtor nativo -- cero bytecode (el
 * codigo esta AOT-compilado).  Semantica IDENTICA al runner del interprete
 * (@c gc_finalizer_run en exec_instruction.cpp), pero con llamadas a punteros
 * de funcion nativos en lugar de reentrada al interprete.
 *
 * @param owner Ignorado (no hay ProcessVM en AOT).
 * @param f     Datos stageados del finalizador (kind + a0 + a1).
 */
void gc_finalizer_run_native(void * /*owner*/,
                             const gc::GcPendingFinalizer &f) {
    ++g_vx_gc_fin_count;
    switch (f.kind) {
    case gc::GcFinalizerKind::UNIQUE: {
        // f.a0 = inner_ptr, f.a1 = deleter (func_ptr nativo; 0 = default free).
        const uint64_t inner_ptr = f.a0;
        const uint64_t deleter = f.a1;
        if (inner_ptr == 0) return; // ya movido/zerificado (anti-doble-free).
        if (deleter != 0) {
            // Deleter Vesta AOT-compilado: CALL directo deleter(inner_ptr).
            reinterpret_cast<void (*)(uint64_t)>(deleter)(inner_ptr);
        } else {
            // Default (unique_box): liberar el bloque raw con free (libc).
            std::free(reinterpret_cast<void *>(inner_ptr));
        }
        break;
    }
    case gc::GcFinalizerKind::SHARED: {
        // f.a0 = ctrl_block_ptr.  Refcount puro: decrementar; liberar en 0.
        const uint64_t ctrl = f.a0;
        if (ctrl == 0) return;
        uint64_t *rc = reinterpret_cast<uint64_t *>(ctrl);
        if (*rc > 0) (*rc)--;
        if (*rc == 0) std::free(reinterpret_cast<void *>(ctrl));
        break;
    }
    case gc::GcFinalizerKind::CLASS_DTOR: {
        // f.a0 = dtor func_ptr nativo, f.a1 = obj_host_ptr.  CALL directo
        // dtor(obj).  No se libera memoria (el GC ya reclamo la instancia).
        const uint64_t dtor = f.a0;
        const uint64_t obj = f.a1;
        if (dtor == 0 || obj == 0) return;
        reinterpret_cast<void (*)(uint64_t)>(dtor)(obj);
        break;
    }
    case gc::GcFinalizerKind::NONE:
    default: break;
    }
}

} // namespace

// Captura el frame Vesta LLAMADOR (frontera C<-Vesta) para el WALK POR TAMANO
// DE FRAME del scan preciso de AOT.  Debe expandirse DENTRO de la runtime-entry
// que el codigo Vesta llama directamente, para que:
//   __builtin_return_address(0) = PC de retorno al frame Vesta (dentro de la
//                                 funcion Vesta que hizo `call vx_gc_*`).
//   __builtin_frame_address(0)  = RBP de ESTA entry = RSP_entry - 8, luego el
//                                 RSP del frame Vesta justo antes del `call` es
//                                 frame_addr + 16 (RSP_entry + 8).
// La relacion +16 exige que la entry conserve frame pointer -> se marca con el
// atributo optimize("no-omit-frame-pointer") (ver abajo).  Desde ese par
// (pc, sp) el walk sube por la pila con frame_size (no cadena RBP), saltando
// los frames C++ de esta libreria.
#if defined(__GNUC__)
#define VX_GC_FORCE_FP __attribute__((optimize("no-omit-frame-pointer")))
#else
#define VX_GC_FORCE_FP
#endif
#define VX_GC_CAPTURE_VX_FRAME()                                               \
    gc_heap().set_aot_scan_boundary(                                           \
        reinterpret_cast<uint64_t>(__builtin_return_address(0)),               \
        reinterpret_cast<uint64_t>(__builtin_frame_address(0)) + 16u)

extern "C" {

void vx_gc_init(void) {
    // Forzar la construccion del heap (idempotente: el static local solo se
    // inicializa una vez).
    gc::GcHeap &h = gc_heap();
    // Instalar el runner nativo de finalizadores (idempotente): ejecuta el
    // deleter/dtor concreto por CALL directo cuando el sweep colecte un objeto
    // con recurso interno.  Cierra la fuga del escape en AOT.
    h.set_finalizer_runner(&gc_finalizer_run_native, nullptr);
}

uint32_t vx_gc_alloc(uint64_t size) {
    // v1 no-moving: pinned -> OldGen (el nursery queda vacio).  El GC colecta
    // por mark-sweep con raices precisas; sin compactacion (optimizacion v2).
    gc::GcHeap &h = gc_heap();
    const gc::GcHandle handle = h.alloc_pinned(static_cast<size_t>(size));
    if (handle == gc::GC_NULL_HANDLE)
        return static_cast<uint32_t>(gc::GC_NULL_HANDLE);
    /* BLOQUE CRUDO: el contrato de esta funcion es "size bytes de payload" y
     * no exige forma alguna, asi que obj[0] es lo que el consumidor escriba
     * ahi.  El trazado preciso de AOT lee obj[0] como puntero al descriptor de
     * tipo, y sin esta marca seguia lo que hubiera -- un entero, una cadena,
     * lo que fuera -- y se llevaba el proceso por delante al colectar.
     *
     * Los objetos del frontend NO pasan por aqui: usan vx_gc_alloc_ptr y si
     * escriben descriptor. */
    h.mark_no_type_desc(h.deref(handle));
    return static_cast<uint32_t>(handle);
}

uint8_t *vx_gc_alloc_ptr(uint64_t size) {
    // Aloca + deref en una llamada: devuelve el host_ptr al payload (estable en
    // v1 no-moving).  Lo usa el helper __new_<X>_gc del frontend (gc<T>): el
    // ptr se guarda en el slot del var-decl, marcado HOSTPTR en el stackmap ->
    // handle_for_ptr lo resuelve al handle en la coleccion.
    gc::GcHeap &h = gc_heap();
    const gc::GcHandle handle = h.alloc_pinned(static_cast<size_t>(size));
    if (handle == gc::GC_NULL_HANDLE) return nullptr;
    return h.deref(handle);
}

void vx_gc_register_aot_stackmaps(const uint8_t *sec) {
    // El tamanño total va EMBEBIDO en el header (offset 12) -- no como
    // parametro
    // -- porque section_size seria una reloc SIZE no soportada en .obj/.o.
    if (!sec) return;
    uint32_t total = 0;
    std::memcpy(&total, sec + 12, 4);
    const uint64_t size = total;
    // Parsea la seccion .vxgc_smap emitida por el driver -m aot y registra cada
    // funcion (rango de codigo + stackmaps) en el JitRegistry global, para que
    // scan_jit_roots_precise (el mismo walker del JIT) descubra las raices
    // gc<T> vivas en los frames nativos durante la coleccion.  La llama el
    // arranque del binario (CALL __vxgc_init al inicio de main) antes del
    // primer alloc.
    //
    // Formato (LE), version 2:
    //   header 16B: u32 magic 'VXGM' | u32 version=2 | u32 n_fn | u32
    //   total_size por fn: u64 func_addr | u32 code_size | u32 frame_size | u32
    //   n_safepoints
    //     por safepoint: u32 pc_offset | u32 n_slots
    //       por slot: i16 rbp_offset | u8 gc_kind | u8 _pad
    // frame_size (v2) = RBP - RSP en un safepoint call; lo consume el WALK POR
    // TAMANO DE FRAME (scan_aot_frames) para reconstruir RBP sin cadena RBP. Un
    // .vxgc_smap v1 (sin frame_size) falla el check de version -> recompilar.
    if (!sec || size < 16) return;
    const uint8_t *p = sec;
    const uint8_t *end = sec + size;
    auto rd32 = [&p]() -> uint32_t {
        uint32_t v;
        std::memcpy(&v, p, 4);
        p += 4;
        return v;
    };
    auto rd64 = [&p]() -> uint64_t {
        uint64_t v;
        std::memcpy(&v, p, 8);
        p += 8;
        return v;
    };
    const uint32_t magic = rd32();
    if (magic != 0x4D475856u) return; // 'VXGM'
    const uint32_t version = rd32();
    if (version != 2u) return; // v1 (sin frame_size) -> forzar recompilar
    const uint32_t n_fn = rd32();
    (void)rd32(); // total_size (ya leido del offset 12)
    auto &reg = jit::JitRegistry::instance();
    for (uint32_t f = 0; f < n_fn && p + 20 <= end; ++f) {
        const uint64_t func_addr = rd64();
        const uint32_t code_size = rd32();
        const uint32_t frame_size = rd32(); // v2: RBP - RSP en safepoint call
        const uint32_t n_sp = rd32();
        std::vector<jit::Stackmap> smaps;
        smaps.reserve(n_sp);
        for (uint32_t s = 0; s < n_sp && p + 8 <= end; ++s) {
            jit::Stackmap sm;
            sm.pc_offset = rd32();
            const uint32_t n_slots = rd32();
            for (uint32_t k = 0; k < n_slots && p + 4 <= end; ++k) {
                jit::StackmapSlot slot;
                int16_t off;
                std::memcpy(&off, p, 2);
                p += 2;
                slot.rbp_offset = off;
                slot.gc_kind = static_cast<jit::StackmapGcKind>(*p);
                p += 2; // gc_kind + _pad
                sm.slots.push_back(slot);
            }
            smaps.push_back(std::move(sm));
        }
        if (func_addr != 0)
            reg.register_function(
                reinterpret_cast<const uint8_t *>(func_addr),
                reinterpret_cast<const uint8_t *>(func_addr) + code_size,
                std::move(smaps), /*frame_size=*/frame_size, "aot");
    }
}

void vx_gc_pin(uint32_t handle) {
    gc_heap().gc_addref(static_cast<gc::GcHandle>(handle));
}

void vx_gc_unpin(uint32_t handle) {
    gc_heap().gc_release(static_cast<gc::GcHandle>(handle));
}

uint8_t *vx_gc_deref(uint32_t handle) {
    return gc_heap().deref(static_cast<gc::GcHandle>(handle));
}

VX_GC_FORCE_FP void vx_gc_collect(void) {
    // Capturar el frame Vesta llamador ANTES de colectar: el major_gc de abajo
    // arranca el scan preciso desde aqui (frontera C<-Vesta).
    VX_GC_CAPTURE_VX_FRAME();
    gc::GcHeap &h = gc_heap();
    h.minor_gc();
    h.major_gc();
    // Drenar los finalizadores stageados por el sweep (CALL directo al
    // deleter/dtor nativo).  En AOT no hay scheduler/safe-point: el drenado
    // corre aqui, tras completar el collect (el sweep ya copio los datos del
    // box, asi que el drenado no toca memoria reclamada).
    h.run_pending_finalizers();
}

void vx_gc_register_finalizer(uint8_t *payload, uint32_t kind, uint64_t aux) {
    gc_heap().register_finalizer(payload,
                                 static_cast<gc::GcFinalizerKind>(kind), aux);
}

void vx_gc_unregister_finalizer(uint8_t *payload) {
    gc_heap().unregister_finalizer(payload);
}

VX_GC_FORCE_FP void vx_gc_finalize_all(void) {
    // Capturar el frame Vesta llamador por si finalize_all_live disparara un
    // scan de raices en el futuro (hoy solo corre finalizadores, sin
    // mark/sweep; capturar es defensivo y mantiene el boundary fresco).
    VX_GC_CAPTURE_VX_FRAME();
    // Shutdown-time: finalizar todo objeto vivo con recurso interno (cubre los
    // escapados que el sweep no colecto todavia).  Cero fuga antes del exit.
    gc_heap().finalize_all_live();
}

uint64_t vx_gc_fin_count(void) {
    return g_vx_gc_fin_count;
}

uint64_t vx_gc_live_count(void) {
    // No hay accesor directo de "handles vivos"; lo contamos sobre la tabla
    // (O(N), solo para introspeccion/diagnostico, no es hot path).
    gc::GcHeap &h = gc_heap();
    uint64_t n = 0;
    const size_t cap = h.handle_table_size();
    for (size_t i = 0; i < cap; ++i)
        if (h.is_handle_live(static_cast<gc::GcHandle>(i))) ++n;
    return n;
}

} // extern "C"
