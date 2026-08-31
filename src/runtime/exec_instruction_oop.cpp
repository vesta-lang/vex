/*
#include <cstdlib>
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file exec_instruction_oop.cpp
 * @brief Implementacion de instrucciones del sistema de objetos (0x00
 * 0xD0..0xEB).
 *
 * Convencion de punteros en registros:
 *   - Todos los punteros a ClassInfo*, MethodInfo*, FieldInfo* y al
 * ObjectHeader de un objeto son PUNTEROS HOST (uint64_t casteado) almacenados
 * en registros de proposito general.
 *   - Para objetos GC: se debe hacer GCDEREF primero para obtener el host_ptr
 *     al ObjectHeader, y luego usar ese puntero con CALLVIRT/THROW/etc.
 *   - Para objetos raw (NEWOBJRAW): el puntero al ObjectHeader se obtiene
 *     directamente de R00 tras la instruccion.
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/exception_runtime.h"
#include "runtime/host_alloca_tracker.h"
#include "gc/gc_heap.h"
#include <cstdio>
#include "gc/raw_allocator.h"
#include "loader/oop_types.h"
#include "loader/loader.h"
#include "loader/class_registry.h"

/* hook JIT en CALLVIRT fast path. */
#include "jit/interp_jit_bridge.h"
#include "jit/auto_jit.h" // auto-PGO tier-2: maybe_tier2_method + threshold
#include "jit/jit_branch_prof.h" // jit_branch_prof_emit_enabled

/* Sprint D.6 (2026-06-03): profile counters runtime. */
#include "runtime/profile.h"
#include "vesta_rt/public.h"

#include <time.h>

/* Helper local de timing para el JIT path.  Duplicado de @c now_ns en
 * decode_instruction.cpp (no expuesto en header); medir con CLOCK_MONOTONIC
 * para que cuente wall time real del JIT execution.  Solo se invoca cuando
 * @c has_hooks esta activo (modo --stats), zero overhead sin profiler. */
static inline uint64_t jit_now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

namespace runtime {

// =========================================================================
//  Helpers internos
// =========================================================================

/**
 * @brief Comprueba si @p obj_class es igual a @p target o hereda de el.
 *
 * Realiza una busqueda BFS recursiva sobre la cadena de superclases e
 * interfaces.  La recursion es aceptable porque las jerarquias suelen
 * ser cortas en la practica.
 *
 * @param obj_class Clase del objeto a comprobar.
 * @param target    Clase objetivo de la comprobacion.
 * @return true si obj_class es target o hereda de el.
 */
static bool is_instance_of(const loader::ClassInfo *obj_class,
                           const loader::ClassInfo *target) {
    if (obj_class == nullptr || target == nullptr)
        return false;                     // punteros nulos -> falso
    if (obj_class == target) return true; // coincidencia directa

    // comprobar superclases
    for (size_t i = 0; i < obj_class->super_count; ++i) {
        if (is_instance_of(obj_class->supers[i], target)) return true;
    }
    // comprobar interfaces implementadas
    for (size_t i = 0; i < obj_class->interface_count; ++i) {
        if (is_instance_of(obj_class->interfaces[i], target)) return true;
    }
    return false; // no encontrado en toda la jerarquia
}

/**
 * @brief Implementacion comun de THROW y RETHROW.
 *
 * Recorre la cadena de frames buscando un handler compatible con la clase
 * de la excepcion lanzada:
 *   - Si encuentra handler: restaura frame_stack, pone el puntero en R00 y
 * salta.
 *   - Si no encuentra handler: mata el proceso con EVT_ERROR.
 *
 * @param vm            Proceso virtual sobre el que se lanza la excepcion.
 * @param exception_ptr Puntero host al ObjectHeader de la excepcion (0 =
 * invalido).
 */
void do_throw(ProcessVM *vm, uint64_t exception_ptr) {
    if (exception_ptr == 0) {
        // excepcion nula -> error de segmentacion
        vm->err_thread = THREAD_SEGMENTATION_FAULT;
        vm->scheduler.on_event(EVT_ERROR);
        return;
    }

    auto *exc_hdr = reinterpret_cast<loader::ObjectHeader *>(exception_ptr);
    loader::ClassInfo *exc_class = exc_hdr->class_ptr; // clase de la excepcion

    // guardar la excepcion activa para que RETHROW pueda relanzarla
    vm->current_exception = exception_ptr;

    // --- comprobar primero la pila de frames TRYENTER (frames ligeros de alto
    // nivel) ---
    ProcessVM::ExceptionFrame *ef = vm->exc_frame_stack;
    while (ef != nullptr) {
        bool matches =
            (ef->type == nullptr) || is_instance_of(exc_class, ef->type);
        if (matches) {
            uint64_t handler_addr = ef->handler_pc; // guardar antes de liberar
            uint64_t saved_rsp = ef->saved_rsp;
            uint64_t saved_rbp = ef->saved_rbp;
            // Excepciones in-JIT (Opcion B): si el frame es JIT, capturar la
            // direccion nativa del catch + rsp/rbp host ANTES de reciclar ef.
            const uint64_t native_catch = ef->native_catch_addr;
            const uint64_t native_rsp = ef->native_rsp;
            const uint64_t native_rbp = ef->native_rbp;
            auto *saved_fs =
                (loader::FrameHeader *)(uintptr_t)ef->saved_frame_stack;
            // Snapshot de R0..R15 que el tryenter capturo.  Restauramos
            // antes de saltar al handler para que las variables vivas
            // del catch (incluido `this` y parametros del metodo) tengan
            // los valores correctos -- mismo estado que el try entry.
            // Sin esto, los regs corruptos por el try-body dejaban
            // las vars con valores stale (caso clasico: catch que
            // hace `this.foo()` -> CALLVIRT null porque r1 era stale).
            uint64_t saved_regs[16];
            for (int i = 0; i < 16; ++i)
                saved_regs[i] = ef->saved_regs[i];

            // desapilar todos los frames TRYENTER hasta el handler encontrado.
            // Reciclar a free list en lugar de delete (mismo patron que
            // tryleave).
            while (vm->exc_frame_stack != nullptr &&
                   vm->exc_frame_stack != ef) {
                ProcessVM::ExceptionFrame *tmp = vm->exc_frame_stack;
                vm->exc_frame_stack = tmp->prev;
                tmp->prev = vm->exc_free_list;
                vm->exc_free_list = tmp;
            }
            vm->exc_frame_stack = ef->prev; // el handler se consume al saltar
            ef->prev = vm->exc_free_list;
            vm->exc_free_list = ef;

            // Unwind del CPU stack y de frame_stack al estado
            // del tryenter.  Esto descarta:
            //   - Pushes del regalloc dentro del try-body que no
            //     llegaron a sus pop por el throw -> evita corrupcion
            //     de registros vivos al volver al merge.
            //   - Frames de calls anidados (callvirt/callm) que no
            //     retornaron normalmente -> evita stack frame leak
            //     y pop de retorno desde direccion incorrecta.
            vm->registers.stack_pointer.qword(saved_rsp);
            vm->registers.base_pointer.qword(saved_rbp);
            while (vm->frame_stack != nullptr && vm->frame_stack != saved_fs) {
                loader::FrameHeader *tmp = vm->frame_stack;
                vm->frame_stack = tmp->prev;
                // Sprint MMM-ext leak-fix: liberar host_allocas del
                // frame que se descarta durante el unwind del throw.
                host_alloca_release_all(vm, tmp);
                vm->frame_pool.release(tmp); // fix13
            }
            // Restaurar R1..R15 (R0 lo sobreescribimos con la
            // excepcion abajo).  Esto es el cambio CRITICO que hace
            // que las vars del catch vean valores correctos.
            for (int i = 1; i < 16; ++i) {
                vm->registers.regs[i].qword(saved_regs[i]);
            }

            // convencion: R00 contiene el puntero al objeto excepcion
            vm->registers.regs[R00].qword(exception_ptr);
            // Excepciones in-JIT (Opcion B): el catch vive en codigo JIT.  La
            // limpieza VM (rsp/rbp/frame_stack/regs + regs[0]=exc) ya esta
            // hecha arriba; ahora restauramos el frame HOST y saltamos al
            // bloque catch nativo via el primitivo de unwind.  NUNCA retorna
            // (abandona los frames nativos intermedios reseteando rsp).  El
            // catch lee la excepcion via LANDINGPAD (proc->registers[0]) y sus
            // demas valores via LOAD de los slots VM (force-spill garantiza
            // que sobrevivieron al throw).
            if (native_catch != 0) {
                vrt_resume_jit(native_catch, native_rsp, native_rbp,
                               reinterpret_cast<uint64_t>(vm));
                // unreachable
            }
            vm->registers.rip.qword(handler_addr); // saltar al handler (interp)
            // did_jump solo lo consume el loop del interprete (dispatch_table:
            // `if (!decoded_ptr->did_jump)`).  Cuando do_throw corre desde un
            // frame JIT (vrt_throw_user/vrt_unwrap_throw), decoded_ptr puede
            // ser NULL -> el redirect lo detecta enter_jit comparando rip,
            // asi que aqui basta con guardar el deref (path frio).
            if (vm->decoded_ptr) vm->decoded_ptr->flags_info.did_jump = true;
            return;
        }
        ef = ef->prev;
    }

    /* La cadena se RECORRE sin tocarla, y solo se desmonta cuando ya se sabe
     * a donde se va.  Antes se liberaba cada marco segun se descartaba, y eso
     * traia dos cosas malas: si el manejador aparecia mas arriba, el desenrollo
     * de abajo volvia a soltar los mismos marcos -- devueltos DOS VECES al
     * almacen --, y si no aparecia ninguno ya no quedaba cadena que contar,
     * que es justo cuando hace falta para la traza. */
    loader::FrameHeader *frame =
        vm->frame_stack; // continuar con la cadena de FrameHeaders

    while (frame != nullptr) {
        loader::MethodInfo *method = frame->method;
        if (method == nullptr) {
            frame = frame->prev; // frame sin metodo, subir al siguiente
            continue;
        }

        // calcular el offset del PC respecto al inicio del metodo
        uint64_t pc_offset = vm->registers.rip.raw() - method->code_vaddr;

        for (size_t i = 0; i < method->handler_count; ++i) {
            const loader::HandlerException &h = method->handlers[i];

            // verificar que el PC esta dentro del rango cubierto por el handler
            if (pc_offset < h.start_pc || pc_offset >= h.end_pc) continue;

            // verificar compatibilidad de tipo (nullptr = catch-all / finally)
            bool matches =
                (h.type == nullptr) || is_instance_of(exc_class, h.type);

            if (matches) {
                // desapilar todos los frames intermedios hasta el handler
                loader::FrameHeader *cur = vm->frame_stack;
                while (cur != nullptr && cur != frame) {
                    loader::FrameHeader *tmp = cur;
                    cur = cur->prev;
                    // Sprint MMM-ext leak-fix.
                    host_alloca_release_all(vm, tmp);
                    vm->frame_pool.release(tmp); // fix13
                }
                vm->frame_stack = frame; // restaurar el frame del handler

                // convencion: R00 contiene el puntero al objeto excepcion
                vm->registers.regs[R00].qword(exception_ptr);

                // saltar al handler dentro del metodo
                vm->registers.rip.qword(method->code_vaddr + h.handler_pc);
                // Guarda decoded_ptr null (throw desde frame JIT); ver nota
                // en el path TRYENTER de arriba.
                if (vm->decoded_ptr)
                    vm->decoded_ptr->flags_info.did_jump =
                        true; // notificar el salto
                return;
            }
        }

        // handler no encontrado en este frame: subir al anterior, sin
        // soltarlo todavia (ver la nota del principio del recorrido).
        frame = frame->prev;
    }

    /* Nadie la recogio.  Se CUENTA antes de desmontar nada -- la traza sale de
     * la cadena de marcos, y despues de soltarla no hay de donde sacarla --, y
     * no se cuentan los fallos del motor: esos ya los conto `throw_fatal` con
     * su propio codigo, y repetirlo imprimiria la misma averia dos veces. */
    if (exc_class != g_fatal_error_class) {
        /* `stringx` NO acaba en nul: se acota por su tamano.  Tomarlo como
         * cadena de C leeria hasta el primer cero que hubiera detras. */
        std::string nombre = "?";
        if (exc_class && exc_class->name.data && exc_class->name.size > 0)
            nombre.assign(reinterpret_cast<const char *>(exc_class->name.data),
                          exc_class->name.size);
        report_uncaught_exception(vm, nombre.c_str());
    }

    // Ahora si: liberar host_allocas de cualquier frame remanente para no
    // leakear al destruir el ProcessVM.
    while (vm->frame_stack != nullptr) {
        loader::FrameHeader *tmp = vm->frame_stack;
        vm->frame_stack = tmp->prev;
        host_alloca_release_all(vm, tmp);
        vm->frame_pool.release(tmp);
    }
    vm->scheduler.on_event(EVT_ERROR);
}

// =========================================================================
//  0xD0 NEWOBJRAW reg_classinfo, reg_size -> R0 = host_ptr
// =========================================================================

/**
 * @brief Ejecuta la instruccion NEWOBJRAW: aloca un objeto raw sin GC.
 *
 * Aloca un bloque de memoria bruta usando el raw_allocator del proceso.
 * El tamano se toma del segundo registro si es distinto de cero; de lo
 * contrario se usa instance_size de la clase.  El ObjectHeader se inicializa
 * con OBJ_FLAG_RAW_OWNED para distinguirlo de los objetos GC.
 *
 * @param vm    Proceso virtual que ejecuta NEWOBJRAW.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*) y
 * reg_data.reg2 (size).
 */
void exec_instr_newobjraw(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data
                              .reg1; // registro con puntero a ClassInfo
    const uint8_t r_sz =
        instr.data_instruction.reg_data
            .reg2; // registro con tamano (0 = usar instance_size)

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());
    if (cls == nullptr) {
        vm->registers.regs[R00].qword(0); // clase nula -> puntero nulo
        return;
    }

    // si r_sz != 0, usar el tamano del registro; si no, usar el de la clase
    size_t alloc_size =
        (r_sz != 0) ? static_cast<size_t>(vm->registers.regs[r_sz].qword())
                    : static_cast<size_t>(cls->instance_size);

    uint64_t ptr =
        vm->raw_alloc.alloc(alloc_size); // alocar con el allocator bruto
    if (ptr != 0) {
        auto *hdr = reinterpret_cast<loader::ObjectHeader *>(ptr);
        hdr->class_ptr = cls;                    // enlazar la clase
        hdr->flags = loader::OBJ_FLAG_RAW_OWNED; // marcar como raw (no GC)
        hdr->hash_code = static_cast<uint32_t>(
            ptr & 0xFFFFFFFF); // hash basado en la direccion
    }

    vm->registers.regs[R00].qword(ptr); // devolver el puntero host en R00
}

// =========================================================================
//  0xD1 CALLVIRT reg_obj, vtable_idx
// =========================================================================

/**
 * @brief Ejecuta la instruccion CALLVIRT: llamada virtual a un metodo de
 * objeto.
 *
 * Resuelve el metodo en tiempo de ejecucion a traves de la vtable de la clase
 * del objeto.  Empuja un FrameHeader en frame_stack para que THROW/RETHROW
 * puedan localizar handlers, y tambien empuja la direccion de retorno en la
 * pila convencional (compatible con RET).
 *
 * @param vm    Proceso virtual que ejecuta CALLVIRT.
 * @param instr Instruccion descodificada con reg_data.reg1 (objeto) y
 * reg_data.reg2 (vtable_idx).
 */
void exec_instr_callvirt(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj = instr.data_instruction.reg_data
                              .reg1; // registro con el puntero al objeto
    const uint8_t vtbl_idx =
        instr.data_instruction.reg_data.reg2; // indice en la vtable

    const uint64_t obj_ptr = vm->registers.regs[r_obj].qword();
    if (__builtin_expect(obj_ptr == 0, 0)) {
        // throw_fatal capturable con try/catch.  Si no hay
        // handler activo, ruta antigua (mata el proceso).
        runtime::throw_fatalf(
            vm, runtime::FATAL_NULL_POINTER,
            "CALLVIRT: deref de objeto null (r%u, vtbl_idx=%u)",
            (unsigned)r_obj, (unsigned)vtbl_idx);
        return;
    }

    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(obj_ptr);
    loader::ClassInfo *cls = hdr->class_ptr; // obtener la clase del objeto

    // Sprint D.6: profile type observation per call site.  Fast path
    // colapsa a 1 atomic load relaxed + branch predicted-not-taken
    // cuando el profiler no esta activo (default).
    if (__builtin_expect(
            runtime::profile::g_profile.active.load(std::memory_order_relaxed),
            0)) {
        runtime::profile::profile_callvirt(vm->registers.rip.raw(), cls);
    }

    // ---------- Inline cache (monomorphic) ----------
    // En la mayoria de programas, el call site siempre ve la MISMA clase.
    // Cacheamos (cls -> method) en el icache entry.  Cache hit = saltar
    // bounds check + indirect load de la vtable.
    loader::MethodInfo *method;
    if (__builtin_expect(
            cls == instr.cached_class && instr.cached_method != nullptr, 1)) {
        method = static_cast<loader::MethodInfo *>(instr.cached_method);
    } else {
        // Cache miss: resolver via vtable y actualizar.  La primera
        // invocacion de cada call site cae aqui; las siguientes son hits.
        if (__builtin_expect(cls == nullptr || vtbl_idx >= cls->vtable_size ||
                                 cls->vtable == nullptr,
                             0)) {
            runtime::throw_fatalf(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                                  "CALLVIRT: clase invalida o vtable_idx fuera "
                                  "de rango (idx=%u, size=%u)",
                                  (unsigned)vtbl_idx,
                                  cls ? (unsigned)cls->vtable_size : 0u);
            return;
        }
        method = cls->vtable[vtbl_idx];
        if (__builtin_expect(method == nullptr || method->code_vaddr == 0, 0)) {
            runtime::throw_fatalf(
                vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                "CALLVIRT: metodo abstracto o sin implementacion (vtbl_idx=%u)",
                (unsigned)vtbl_idx);
            return;
        }
        // Cachear para la proxima invocacion (mutable: const-correct).
        instr.cached_class = cls;
        instr.cached_method = method;
    }

    const uint64_t ret_addr =
        vm->registers.rip.raw() +
        static_cast<uint64_t>(instr.flags_info.size_instr); // PC de retorno

    // -----------------------------------------------------------------
    // AOP: si el metodo tiene cadena de advices, recorrerla y construir
    // la secuencia efectiva [b1, b2, ..., bN, M, a1, a2, ..., aK].  Cada
    // paso se traduce en (a) un FrameHeader empujado (para excepciones),
    // (b) un return_pc empujado en la pila (para que RET salte al
    // siguiente paso), todo en orden inverso al de ejecucion (LIFO).
    // Si advice_chain es NULL o no hay BEFORE/AFTER, fast path identico
    // al original (overhead cero).
    // -----------------------------------------------------------------

    // Helper local para empujar (frame + return_pc) atomicamente.  Se
    // invoca varias veces consecutivas para construir la cadena AOP.
    // El parametro opcional @c around_target marca el frame como un
    // advice AROUND con un target original a invocar via @c proceed.
    //
    // NOTA: NO escribimos ret_to al stack VM.  El slot reservado por
    // `rsp -= 8` queda sin inicializar, lo cual es seguro porque:
    //  (a) RET de este callvirt usa frame->return_pc directo (detectado
    //      por RSP == frame_base - 8), nunca lee del slot.
    //  (b) Si el method body hace un callvm anidado, ese callvm
    //      sobreescribe su propio slot (rsp -= 8 de nuevo + write).  El
    //      RET de ese callvm anidado lee de su slot, no del nuestro.
    // El write_bytes que estaba aqui (~30 ns) era trabajo desperdiciado.
    auto push_step = [&](loader::MethodInfo *m, uint64_t ret_to,
                         loader::MethodInfo *around_target = nullptr,
                         loader::MethodInfo **chain = nullptr,
                         uint32_t chain_len = 0, bool owns_chain = false,
                         bool save_regs = false,
                         uint8_t inject_r0_reg = 0 /* LR3 */) {
        const uint64_t cur_rsp = vm->registers.stack_pointer.qword();
        auto *frame = vm->frame_pool.acquire();
        frame->prev = vm->frame_stack;
        frame->method = m;
        frame->return_pc = ret_to;
        frame->frame_base = cur_rsp;
        frame->proceed_target = around_target;
        frame->around_chain = chain;
        frame->around_chain_len = chain_len;
        frame->around_chain_owns = owns_chain ? 1 : 0;
        frame->has_saved_regs = save_regs ? 1 : 0;
        frame->inject_r0_to_reg = inject_r0_reg;
        // BugFix P0-E2: en advice chain dispatch, los pasos comparten
        // la calling convention del CALLVIRT original (r1=this, r2..rN=args).
        // Un advice puede corromper estos regs (e.g. getstatic r1, ...).
        // Snapshot al push; RET restaura antes del siguiente paso.
        if (save_regs) {
            for (int i = 0; i < 12; ++i) {
                frame->saved_r1_r12[i] = vm->registers.regs[i + 1].qword();
            }
        }
        vm->frame_stack = frame;
        vm->registers.stack_pointer.qword(cur_rsp - 8);
    };

    if (method->advice_chain == nullptr) {
        // Fast path: dispatch directo sin advices, overhead cero.
        //
        // HOT PATH OPT:  si method->jit_code ya esta
        // seteado, salt directo al JIT SIN incrementar counter ni
        // llamar al hook.  Esto ahorra ~2-3 ns por callvirt en hot
        // loops (de los ~10ns totales del fast path).  El counter
        // ya sirvio para disparar la compilacion; tras compile no
        // tiene utilidad (futuras phases podrian usarlo para PGO
        // pero hoy no se consulta).  El hook es no-op cuando
        // jit_code != null, asi que skip es seguro.
        if (__builtin_expect(method->jit_code != nullptr, 1)) {
            /* Auto-PGO tier-2: cuando el auto-PGO esta activo, seguir contando
             * invocaciones tras tier-1; al cruzar el delta DINAMICO
             * (g_jit_threshold + jit_tier2_delta()) recompilar con el perfil
             * medido por el codigo nativo (g_jit_line_ctrs).  Sentinela
             * UINT32_MAX = tier-2 hecho -> deja de contar (coste ~2 ops). */
            /* Auto-PGO tier-2: guard barato inline (2 loads); la logica de
             * conteo + recompilacion vive en jit::tier2_tick (TU separada). */
            if (__builtin_expect(jit::g_jit_tier2_on &&
                                     method->invocation_count != UINT32_MAX,
                                 0)) {
                jit::tier2_tick(vm, method);
            }
            jit::JitFn fn = reinterpret_cast<jit::JitFn>(method->jit_code);
            // Salvar rip antes de entrar al JIT para detectar throw
            // cross-boundary: si do_throw modifico proc->rip (a catch
            // handler), NO debemos sobreescribirlo a ret_addr (eso
            // saltaria el catch).  El JIT body normal NO modifica rip
            // del proceso (la convencion VM_ABI usa solo regs[]), asi
            // que cualquier cambio post-enter_jit indica redirect via
            // throw.
            const uint64_t pre_rip = vm->registers.rip.raw();
            // Timing del JIT execution para --stats.  El CALL_TO_JIT
            // overhead (clock_gettime ~20 ns) se justifica porque la
            // unica forma de saber CUANTO tarda el JIT es medirlo
            // aqui (el interp dispatch loop nunca entra a JIT code).
            // Sin este timing, los stats de wall-time son incorrectos.
            const bool measuring = vm->scheduler.has_hooks;
            const uint64_t t0 = measuring ? jit_now_ns() : 0;
            (void)jit::enter_jit(fn, reinterpret_cast<vrt_proc *>(vm));
            if (measuring) vm->scheduler.time_jit += jit_now_ns() - t0;
            if (vm->registers.rip.raw() == pre_rip) {
                // Sin redirect: avanzar normalmente a ret_addr.
                vm->registers.rip.qword(ret_addr);
            } /* else: throw redirigio rip a handler_pc; respetar. */
            vm->decoded_ptr->flags_info.did_jump = true;
            return;
        }
        // Slow path: jit_code no seteado.  Incrementar counter y
        // disparar auto-JIT si procede.  Tras compile exitoso,
        // siguientes callvirts iran por el fast path.
        ++method->invocation_count;
        if (g_callvirt_post_hook != nullptr) {
            g_callvirt_post_hook(vm, method);
        }
        if (method->jit_code != nullptr) {
            jit::JitFn fn = reinterpret_cast<jit::JitFn>(method->jit_code);
            const uint64_t pre_rip = vm->registers.rip.raw();
            const bool measuring = vm->scheduler.has_hooks;
            const uint64_t t0 = measuring ? jit_now_ns() : 0;
            (void)jit::enter_jit(fn, reinterpret_cast<vrt_proc *>(vm));
            if (measuring) vm->scheduler.time_jit += jit_now_ns() - t0;
            if (vm->registers.rip.raw() == pre_rip) {
                vm->registers.rip.qword(ret_addr);
            }
            vm->decoded_ptr->flags_info.did_jump = true;
            return;
        }
        push_step(method, ret_addr);
        vm->registers.rip.qword(method->code_vaddr);
        vm->decoded_ptr->flags_info.did_jump = true;
        return;
    }

    // B5: Recolectar BEFORE/AFTER/AROUND en orden de declaracion.
    // Multi-AROUND nesting soportado via around_chain en FrameHeader.
    // Bug fix 2026-05-23: AFTER_RETURNING se trata como AFTER (mismo
    // dispatch).  El advice ejecuta tras el target; R0 (return value)
    // sigue en su reg al entrar al advice -- el advice puede leerlo si
    // su primer parametro es i64 (el frontend lowering ya lo bindea).
    loader::MethodInfo *befores[16];
    loader::MethodInfo *afters[16];
    bool afters_is_returning[16] = {0}; // LR3
    loader::MethodInfo *arounds[16];
    size_t n_b = 0, n_a = 0, n_around = 0;
    for (loader::AdviceEntry *e = method->advice_chain; e != nullptr;
         e = e->next) {
        if (e->kind == loader::ADVICE_BEFORE && n_b < 16) {
            befores[n_b++] = e->advice_method;
        } else if ((e->kind == loader::ADVICE_AFTER ||
                    e->kind == loader::ADVICE_AFTER_RETURNING) &&
                   n_a < 16) {
            afters[n_a] = e->advice_method;
            afters_is_returning[n_a] =
                (e->kind == loader::ADVICE_AFTER_RETURNING);
            n_a++;
        } else if (e->kind == loader::ADVICE_AROUND && n_around < 16) {
            arounds[n_around++] = e->advice_method;
        }
    }

    if (n_b == 0 && n_a == 0 && n_around == 0) {
        push_step(method, ret_addr);
        vm->registers.rip.qword(method->code_vaddr);
        vm->decoded_ptr->flags_info.did_jump = true;
        return;
    }

    // Si hay >=1 AROUNDs, m_slot = arounds[0] (outer-most).  Su
    // proceed_target = arounds[1] (o M si solo hay 1 AROUND).  El
    // resto de la cadena vive en around_chain (alocado en heap;
    // se libera en el RET del frame de arounds[0]).
    loader::MethodInfo *m_slot = (n_around > 0) ? arounds[0] : method;
    loader::MethodInfo *proceed_tgt = nullptr;
    loader::MethodInfo **around_chain = nullptr;
    uint32_t chain_len = 0;
    if (n_around > 0) {
        // proceed_target = next layer: arounds[1] o M si solo hay 1.
        proceed_tgt = (n_around > 1) ? arounds[1] : method;
        // around_chain = [arounds[2], arounds[3], ..., arounds[N-1], M]
        // Si n_around == 1, chain queda con solo [M] o vacio segun convencion.
        // Convencion: chain_len es lo QUE QUEDA TRAS proceed_target.
        // Cuando proceed() se ejecuta, lee proceed_target Y avanza la chain.
        //
        // n_around=1: chain = [M], len=1.  proceed invoca arounds[1]=M
        //   (que sera el proceed_target del nuevo frame), chain vacio.
        //   Pero proceed_tgt ya es M; chain debe ser vacio para que
        //   el nuevo frame de M no tenga mas proceed_target (M no es AROUND).
        //   Asi: si proceed_tgt == M (final), chain_len=0.
        //   Si proceed_tgt es otro AROUND, chain trae los siguientes.
        // Implementacion:
        if (n_around == 1) {
            // proceed_tgt = M, no hay mas wrappers.
            around_chain = nullptr;
            chain_len = 0;
        } else {
            // proceed_tgt = arounds[1] (otro AROUND).  chain = arounds[2..N-1]
            // + M. chain_len = (n_around - 2) + 1 = n_around - 1.
            chain_len = static_cast<uint32_t>(n_around - 1);
            // Alocar heap.  Sera liberado en exec_instr_ret cuando el
            // frame de arounds[0] (m_slot) muera.  Convencion: el frame
            // que TIENE around_chain != nullptr es responsable de free().
            around_chain = new loader::MethodInfo *[chain_len];
            for (size_t i = 0; i < n_around - 2; ++i) {
                around_chain[i] = arounds[i + 2];
            }
            around_chain[n_around - 2] = method; // M al final
        }
    }

    loader::MethodInfo *seq[33];
    size_t n_seq = 0;
    for (size_t i = 0; i < n_b; ++i)
        seq[n_seq++] = befores[i];
    seq[n_seq++] = m_slot;
    const size_t m_slot_index = n_seq - 1;
    for (size_t i = 0; i < n_a; ++i)
        seq[n_seq++] = afters[i];

    // Push del ultimo al primero.  Cada paso recibe su own return_pc;
    // el slot de M (o de AROUND) recibe ademas proceed_target + chain.
    // Solo m_slot tiene around_chain_owns=true (alocado en este CALL).
    // BugFix P0-E2: cada paso del chain guarda r1..r12 para que los
    // advices BEFORE/AFTER (que pueden corromper estos regs) no rompan
    // la calling convention vista por los siguientes pasos.
    // LR3: helper para determinar inject_r0_to_reg de cada step.
    // Si seq[k] es un advice AFTER_RETURNING, inject_r0_to_reg = 2
    // (r1 = this implicito del aspect class; r2 = primer arg declarado
    // = result).  El advice method en @Aspect class recibe `this` como
    // r1 igual que cualquier metodo de instancia; el primer parametro
    // del usuario empieza en r2.
    auto inject_for_step = [&](size_t k) -> uint8_t {
        if (k <= m_slot_index) return 0; // before / m_slot
        const size_t after_idx = k - m_slot_index - 1;
        if (after_idx >= n_a) return 0;
        return afters_is_returning[after_idx] ? 2 : 0;
    };
    push_step(seq[n_seq - 1], ret_addr,
              (n_seq - 1 == m_slot_index) ? proceed_tgt : nullptr,
              (n_seq - 1 == m_slot_index) ? around_chain : nullptr,
              (n_seq - 1 == m_slot_index) ? chain_len : 0,
              (n_seq - 1 == m_slot_index) && around_chain != nullptr,
              /*save_regs=*/true, inject_for_step(n_seq - 1));
    for (size_t i = n_seq - 1; i > 0; --i) {
        const size_t idx = i - 1;
        push_step(seq[idx], seq[i]->code_vaddr,
                  (idx == m_slot_index) ? proceed_tgt : nullptr,
                  (idx == m_slot_index) ? around_chain : nullptr,
                  (idx == m_slot_index) ? chain_len : 0,
                  (idx == m_slot_index) && around_chain != nullptr,
                  /*save_regs=*/true, inject_for_step(idx));
    }

    vm->registers.rip.qword(seq[0]->code_vaddr);
    vm->decoded_ptr->flags_info.did_jump = true;
}

// =========================================================================
//  0xFE PROCEED (sin operandos)
//
//  Invoca el target original de un advice AROUND.  Lee el campo
//  @c proceed_target del frame actual (puesto por CALLVIRT/CALLM al
//  detectar AROUND).  Equivale a un @c callm r1, proceed_target con
//  los registros actuales (r1=this, args en r2..rN).
//
//  Si el frame actual no es un AROUND (proceed_target == nullptr),
//  fallamos con THREAD_ILLEGAL_INSTRUCTION (proceed solo es valido
//  dentro del body de un advice AROUND activo).
// =========================================================================

void exec_instr_proceed(ProcessVM *vm, const DecodedInstr &instr) {
    loader::FrameHeader *cur = vm->frame_stack;
    if (cur == nullptr || cur->proceed_target == nullptr) {
        runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                             "PROCEED: instruccion fuera de un frame AROUND");
        return;
    }
    loader::MethodInfo *target = cur->proceed_target;
    if (target->code_vaddr == 0) {
        runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                             "PROCEED: target del AROUND no tiene codigo");
        return;
    }
    const uint64_t ret_addr =
        vm->registers.rip.raw() +
        static_cast<uint64_t>(instr.flags_info.size_instr);

    // B5 multi-AROUND: si la chain del current frame tiene mas
    // entradas, el nuevo frame (que ejecuta `target`) hereda:
    //   proceed_target = chain[0]  (siguiente AROUND o M)
    //   around_chain   = chain + 1
    //   chain_len      = cur->chain_len - 1
    // Si la chain esta vacia, el nuevo frame NO tiene proceed_target
    // (es el ultimo AROUND y target es M, que no es AROUND).
    loader::MethodInfo *next_proceed_target = nullptr;
    loader::MethodInfo **next_chain = nullptr;
    uint32_t next_chain_len = 0;
    if (cur->around_chain_len > 0 && cur->around_chain != nullptr) {
        next_proceed_target = cur->around_chain[0];
        if (cur->around_chain_len > 1) {
            next_chain = cur->around_chain + 1;
            next_chain_len = cur->around_chain_len - 1;
        }
    }

    auto *frame = vm->frame_pool.acquire();
    frame->prev = vm->frame_stack;
    frame->method = target;
    frame->return_pc = ret_addr;
    frame->frame_base = vm->registers.stack_pointer.qword();
    frame->proceed_target = next_proceed_target;
    frame->around_chain = next_chain;
    frame->around_chain_len = next_chain_len;
    frame->around_chain_owns = 0; // proceed() nunca aloca; solo CALLVIRT
    vm->frame_stack = frame;
    vm->registers.stack_pointer.qword(vm->registers.stack_pointer.qword() - 8);
    // Mantener el write para callvm anidado dentro del callee.
    vm->vm_mem.write_bytes(vm->registers.stack_pointer.raw(), &ret_addr, 8);
    vm->registers.rip.qword(target->code_vaddr);
    vm->decoded_ptr->flags_info.did_jump = true;
}

// =========================================================================
//  0xFD CALLM reg_obj, reg_method
//
//  Como CALLVIRT, pero el segundo operando es un MethodInfo* directo
//  (no un vtable_idx).  Util para dispatch dinamico:
//    - Llamadas a traves de un tipo de interfaz (lookup por nombre).
//    - Reflexion: invocar un MethodInfo* obtenido via getMethod.
//    - Callbacks generados por el runtime sin conocer el slot vtable.
//
//  Formato FIXED_4: [0xFD][ctrl][reg_byte][_]
//    reg1 = r_obj (objeto receptor, host_ptr a ObjectHeader)
//    reg2 = r_method (MethodInfo* obtenido via findmethod/getmethod)
//
//  El objeto se valida solo para nullness; el ClassInfo del header NO
//  se consulta porque el method ya viene resuelto.  Esto permite
//  invocar advices, callbacks, lambdas, etc.
//
//  IMPORTANTE: la cadena AOP advice_chain del MethodInfo SI se
//  recorre, igual que en CALLVIRT, para mantener semantica uniforme.
//  Sin esto un dispatcher dinamico se saltaria los aspectos.
// =========================================================================

void exec_instr_callm(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj = instr.data_instruction.reg_data.reg1;
    const uint8_t r_method = instr.data_instruction.reg_data.reg2;

    const uint64_t obj_ptr = vm->registers.regs[r_obj].qword();
    if (__builtin_expect(obj_ptr == 0, 0)) {
        runtime::throw_fatal(vm, runtime::FATAL_NULL_POINTER,
                             "CALLM: deref de objeto null");
        return;
    }
    // Sprint D.6: type observation para CALLM (dispatch dinamico
    // via puntero a MethodInfo; comun en codigo polimorfico tras
    // findmethod cuando el frontend NO puede devirtualizar).
    if (__builtin_expect(
            runtime::profile::g_profile.active.load(std::memory_order_relaxed),
            0)) {
        auto *hdr = reinterpret_cast<loader::ObjectHeader *>(obj_ptr);
        runtime::profile::profile_callvirt(vm->registers.rip.raw(),
                                           hdr->class_ptr);
    }
    auto *method = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[r_method].qword());
    if (__builtin_expect(method == nullptr || method->code_vaddr == 0, 0)) {
        runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                             "CALLM: MethodInfo nulo o sin codigo");
        return;
    }
    const uint64_t ret_addr =
        vm->registers.rip.raw() +
        static_cast<uint64_t>(instr.flags_info.size_instr);

    // Helper local: empuja frame + return_pc (mismo patron que CALLVIRT).
    // Sin write a stack: RET usa frame->return_pc directo (matching por
    // frame_base).  Ver explicacion extendida en CALLVIRT::push_step.
    auto push_step = [&](loader::MethodInfo *m, uint64_t ret_to) {
        const uint64_t cur_rsp = vm->registers.stack_pointer.qword();
        // Pool intrusivo en lugar de new/delete: O(1) acquire/release.
        auto *frame = vm->frame_pool.acquire();
        frame->prev = vm->frame_stack;
        frame->method = m;
        frame->return_pc = ret_to;
        frame->frame_base = cur_rsp;
        frame->proceed_target = nullptr;
        frame->around_chain = nullptr;
        frame->around_chain_len = 0;
        frame->around_chain_owns = 0;
        vm->frame_stack = frame;
        vm->registers.stack_pointer.qword(cur_rsp - 8);
    };

    // Fast path: sin advices, dispatch directo.
    if (method->advice_chain == nullptr) {
        push_step(method, ret_addr);
        vm->registers.rip.qword(method->code_vaddr);
        vm->decoded_ptr->flags_info.did_jump = true;
        return;
    }

    // Slow path: recorrer advice_chain como en CALLVIRT.  Construir
    // [BEFORE..., M, AFTER...] e instalar la cadena en pila.
    loader::MethodInfo *befores[16];
    loader::MethodInfo *afters[16];
    size_t n_b = 0, n_a = 0;
    for (loader::AdviceEntry *e = method->advice_chain; e != nullptr;
         e = e->next) {
        if (e->kind == loader::ADVICE_BEFORE && n_b < 16)
            befores[n_b++] = e->advice_method;
        else if (e->kind == loader::ADVICE_AFTER && n_a < 16)
            afters[n_a++] = e->advice_method;
    }
    if (n_b == 0 && n_a == 0) {
        push_step(method, ret_addr);
        vm->registers.rip.qword(method->code_vaddr);
        vm->decoded_ptr->flags_info.did_jump = true;
        return;
    }
    loader::MethodInfo *seq[33];
    size_t n_seq = 0;
    for (size_t i = 0; i < n_b; ++i)
        seq[n_seq++] = befores[i];
    seq[n_seq++] = method;
    for (size_t i = 0; i < n_a; ++i)
        seq[n_seq++] = afters[i];
    push_step(seq[n_seq - 1], ret_addr);
    for (size_t i = n_seq - 1; i > 0; --i) {
        push_step(seq[i - 1], seq[i]->code_vaddr);
    }
    vm->registers.rip.qword(seq[0]->code_vaddr);
    vm->decoded_ptr->flags_info.did_jump = true;
}

// =========================================================================
//  0xAE CALLITF r_obj, r_params - dispatch de interfaz via itable
// =========================================================================

/**
 * @brief Layout del @c ItfCallParams (32 bytes en vm_mem) que construye el
 *        frontend para CALLITF.
 *
 *   +0  [8] iface_name_addr  -- VM addr del nombre de la interfaz
 *   +8  [4] iface_name_len   -- bytes del nombre de la interfaz
 *   +12 [4] method_index     -- posicion del metodo en la decl. de la interfaz
 *   +16 [8] method_name_addr -- VM addr del nombre del metodo (solo cold fill)
 *   +24 [4] method_name_len  -- bytes del nombre del metodo
 *   +28 [4] count            -- nº de metodos de la interfaz (dimensiona
 * itable)
 */
struct ItfCallParamsLayout {
    uint64_t iface_name_addr;
    uint32_t iface_name_len;
    uint32_t method_index;
    uint64_t method_name_addr;
    uint32_t method_name_len;
    uint32_t count;
};
static_assert(sizeof(ItfCallParamsLayout) == 32, "ItfCallParams ABI");

/**
 * @brief Cache thread_local interfaz_name_addr -> ClassInfo* resuelto.
 *
 * El @c iface_name_addr es estable por call site (es @c @Absolute de un
 * literal interned), asi que cachear por esa direccion evita el
 * @c find_class (lectura de vm_mem + hash) en cada dispatch.  8 entradas
 * round-robin, sin locks (thread_local).  Mismo patron que el cache de
 * @c vrt_findmethod (CALLM 1a fase).
 */
struct ItfIfaceCacheEntry {
    uint64_t name_addr;
    loader::ClassInfo *iface;
};
static thread_local ItfIfaceCacheEntry g_itf_iface_cache[8] = {};
static thread_local uint32_t g_itf_iface_cache_rr = 0;

void exec_instr_callitf(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj = instr.data_instruction.reg_data.reg1;
    const uint8_t r_params = instr.data_instruction.reg_data.reg2;

    const uint64_t obj_ptr = vm->registers.regs[r_obj].qword();
    if (__builtin_expect(obj_ptr == 0, 0)) {
        runtime::throw_fatal(vm, runtime::FATAL_NULL_POINTER,
                             "CALLITF: deref de objeto null");
        return;
    }

    // Leer el ItfCallParams (32 bytes) desde vm_mem.
    ItfCallParamsLayout p;
    vm->vm_mem.read_bytes(vm->registers.regs[r_params].qword(), &p, sizeof(p));

    // Sprint D.6: type observation (mismo punto que CALLM/CALLVIRT).
    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(obj_ptr);
    if (__builtin_expect(
            runtime::profile::g_profile.active.load(std::memory_order_relaxed),
            0)) {
        runtime::profile::profile_callvirt(vm->registers.rip.raw(),
                                           hdr->class_ptr);
    }
    loader::ClassInfo *cls = hdr->class_ptr;
    if (__builtin_expect(cls == nullptr, 0)) {
        runtime::throw_fatal(vm, runtime::FATAL_NULL_POINTER,
                             "CALLITF: objeto sin class_ptr");
        return;
    }

    // Resolver la interfaz (cache thread_local por name_addr; cold ->
    // find_class leyendo el nombre de vm_mem).
    loader::ClassInfo *iface = nullptr;
    for (auto &e : g_itf_iface_cache) {
        if (e.name_addr == p.iface_name_addr && e.iface != nullptr) {
            iface = e.iface;
            break;
        }
    }
    loader::ClassRegistry &registry =
        vm->scheduler.vm_reference.loader_public.class_registry();
    if (__builtin_expect(iface == nullptr, 0)) {
        std::string iname(p.iface_name_len, '\0');
        if (p.iface_name_len > 0) {
            vm->vm_mem.read_bytes(p.iface_name_addr, &iname[0],
                                  p.iface_name_len);
        }
        iface = registry.find_class(iname);
        if (iface != nullptr) {
            auto &slot = g_itf_iface_cache[g_itf_iface_cache_rr & 7];
            slot.name_addr = p.iface_name_addr;
            slot.iface = iface;
            ++g_itf_iface_cache_rr;
        }
    }
    if (__builtin_expect(iface == nullptr, 0)) {
        runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                             "CALLITF: interfaz no encontrada en el registry");
        return;
    }

    // Resolver el metodo concreto via la itable.  Warm path: la entry ya
    // existe y el slot esta resuelto -> indice puro, sin leer el nombre del
    // metodo.  Cold path: rellenar por nombre (lee method_name de vm_mem).
    loader::MethodInfo *method = nullptr;
    loader::ItableEntry *entry =
        registry.get_or_build_itable(cls, iface, p.count);
    if (entry != nullptr && p.method_index < entry->count && entry->methods) {
        method = entry->methods[p.method_index];
    }
    if (__builtin_expect(method == nullptr, 0)) {
        // Cold: leer el nombre del metodo y resolver+cachear.
        std::string mname(p.method_name_len, '\0');
        if (p.method_name_len > 0) {
            vm->vm_mem.read_bytes(p.method_name_addr, &mname[0],
                                  p.method_name_len);
        }
        method = registry.resolve_itable_method(
            cls, iface, p.count, p.method_index, mname.data(), mname.size());
    }
    if (__builtin_expect(method == nullptr || method->code_vaddr == 0, 0)) {
        runtime::throw_fatal(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                             "CALLITF: metodo de interfaz sin implementacion");
        return;
    }

    const uint64_t ret_addr =
        vm->registers.rip.raw() +
        static_cast<uint64_t>(instr.flags_info.size_instr);

    // Dispatch identico a CALLM (push_step + advice_chain).
    auto push_step = [&](loader::MethodInfo *m, uint64_t ret_to) {
        const uint64_t cur_rsp = vm->registers.stack_pointer.qword();
        auto *frame = vm->frame_pool.acquire();
        frame->prev = vm->frame_stack;
        frame->method = m;
        frame->return_pc = ret_to;
        frame->frame_base = cur_rsp;
        frame->proceed_target = nullptr;
        frame->around_chain = nullptr;
        frame->around_chain_len = 0;
        frame->around_chain_owns = 0;
        vm->frame_stack = frame;
        vm->registers.stack_pointer.qword(cur_rsp - 8);
    };

    if (method->advice_chain == nullptr) {
        push_step(method, ret_addr);
        vm->registers.rip.qword(method->code_vaddr);
        vm->decoded_ptr->flags_info.did_jump = true;
        return;
    }

    // Slow path con advices (igual que CALLM).
    loader::MethodInfo *befores[16];
    loader::MethodInfo *afters[16];
    size_t n_b = 0, n_a = 0;
    for (loader::AdviceEntry *e = method->advice_chain; e != nullptr;
         e = e->next) {
        if (e->kind == loader::ADVICE_BEFORE && n_b < 16)
            befores[n_b++] = e->advice_method;
        else if (e->kind == loader::ADVICE_AFTER && n_a < 16)
            afters[n_a++] = e->advice_method;
    }
    if (n_b == 0 && n_a == 0) {
        push_step(method, ret_addr);
        vm->registers.rip.qword(method->code_vaddr);
        vm->decoded_ptr->flags_info.did_jump = true;
        return;
    }
    loader::MethodInfo *seq[33];
    size_t n_seq = 0;
    for (size_t i = 0; i < n_b; ++i)
        seq[n_seq++] = befores[i];
    seq[n_seq++] = method;
    for (size_t i = 0; i < n_a; ++i)
        seq[n_seq++] = afters[i];
    push_step(seq[n_seq - 1], ret_addr);
    for (size_t i = n_seq - 1; i > 0; --i) {
        push_step(seq[i - 1], seq[i]->code_vaddr);
    }
    vm->registers.rip.qword(seq[0]->code_vaddr);
    vm->decoded_ptr->flags_info.did_jump = true;
}

// =========================================================================
//  0xD2 CALLSUPER reg_classinfo, vtable_idx
// =========================================================================

/**
 * @brief Ejecuta la instruccion CALLSUPER: llamada a un metodo de la
 * superclase.
 *
 * Similar a CALLVIRT pero resuelve el metodo en la vtable de la clase
 * indicada por el registro (no la del objeto receptor), permitiendo
 * llamadas super() explicitas.
 *
 * @param vm    Proceso virtual que ejecuta CALLSUPER.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*) y
 * reg_data.reg2 (vtable_idx).
 */
void exec_instr_callsuper(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data
                              .reg1; // registro con puntero a ClassInfo
    const uint8_t vtbl_idx =
        instr.data_instruction.reg_data.reg2; // indice en la vtable

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());
    if (cls == nullptr || vtbl_idx >= cls->vtable_size ||
        cls->vtable == nullptr) {
        runtime::throw_fatalf(vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
                              "CALLSUPER: ClassInfo invalido o vtable_idx "
                              "fuera de rango (idx=%u)",
                              (unsigned)vtbl_idx);
        return;
    }

    loader::MethodInfo *method =
        cls->vtable[vtbl_idx]; // resolver metodo en la clase indicada
    if (method == nullptr || method->code_vaddr == 0) {
        runtime::throw_fatal(
            vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
            "CALLSUPER: metodo abstracto o sin implementacion");
        return;
    }

    uint64_t ret_addr = vm->registers.rip.raw() +
                        static_cast<uint64_t>(instr.flags_info.size_instr);

    // crear FrameHeader para soporte de excepciones
    const uint64_t cur_rsp = vm->registers.stack_pointer.qword();
    // Pool intrusivo en lugar de new/delete: O(1) acquire/release.
    auto *frame = vm->frame_pool.acquire();
    frame->prev = vm->frame_stack;
    frame->method = method;
    frame->return_pc = ret_addr;
    frame->frame_base = cur_rsp;
    frame->proceed_target = nullptr;
    frame->around_chain = nullptr;
    frame->around_chain_len = 0;
    frame->around_chain_owns = 0;
    vm->frame_stack = frame;

    // RSP -= 8 (reserva slot).  No escribimos ret_addr: RET de este
    // callsuper usa frame->return_pc directo (mismo patron que callvirt).
    vm->registers.stack_pointer.qword(cur_rsp - 8);

    // saltar al metodo de la superclase
    vm->registers.rip.qword(method->code_vaddr);
    vm->decoded_ptr->flags_info.did_jump = true;
}

// =========================================================================
//  0xD3 THROW reg_obj
// =========================================================================

/**
 * @brief Ejecuta la instruccion THROW: lanza una excepcion con el objeto
 * indicado.
 *
 * @param vm    Proceso virtual que ejecuta THROW.
 * @param instr Instruccion descodificada con reg_data.reg1 (objeto excepcion).
 */
void exec_instr_throw(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj = instr.data_instruction.reg_data.reg1;
    uint64_t exception_ptr = vm->registers.regs[r_obj].qword();
    do_throw(vm, exception_ptr);
}

// =========================================================================
//  0xD4 RETHROW
// =========================================================================

/**
 * @brief Ejecuta la instruccion RETHROW: relanza la excepcion activa.
 *
 * Usa el campo current_exception del proceso para relanzar la ultima excepcion
 * capturada, permitiendo propagacion desde handlers catch.
 *
 * @param vm    Proceso virtual que ejecuta RETHROW.
 * @param instr Instruccion descodificada (no se usan sus campos).
 */
void exec_instr_rethrow(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;                         // sin operandos
    do_throw(vm, vm->current_exception); // relanzar la excepcion activa
}

// =========================================================================
//  0xD5 GETCLASS reg_obj -> R0 = ClassInfo*
// =========================================================================

/**
 * @brief Ejecuta la instruccion GETCLASS: obtiene el puntero a la clase de un
 * objeto.
 *
 * Lee el ObjectHeader del objeto y devuelve en R00 el puntero host a su
 * ClassInfo. Si el objeto es nulo devuelve 0.
 *
 * @param vm    Proceso virtual que ejecuta GETCLASS.
 * @param instr Instruccion descodificada con reg_data.reg1 (objeto).
 */
void exec_instr_getclass(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj = instr.data_instruction.reg_data.reg1;
    uint64_t obj_ptr = vm->registers.regs[r_obj].qword();

    if (obj_ptr == 0) {
        vm->registers.regs[R00].qword(0); // objeto nulo -> ClassInfo nula
        return;
    }

    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(obj_ptr);
    vm->registers.regs[R00].qword(reinterpret_cast<uint64_t>(hdr->class_ptr));
}

// =========================================================================
//  0xD6 INSTANCEOF reg_obj, reg_classinfo -> R0 = bool
// =========================================================================

/**
 * @brief Ejecuta la instruccion INSTANCEOF: comprueba si un objeto es de una
 * clase.
 *
 * Devuelve 1 en R00 si el objeto es instancia de la clase indicada o de una
 * subclase de ella; 0 en caso contrario o si alguno de los operandos es nulo.
 *
 * @param vm    Proceso virtual que ejecuta INSTANCEOF.
 * @param instr Instruccion descodificada con reg_data.reg1 (obj) y
 * reg_data.reg2 (ClassInfo*).
 */
void exec_instr_instanceof(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj = instr.data_instruction.reg_data.reg1;
    const uint8_t r_cls = instr.data_instruction.reg_data.reg2;

    uint64_t obj_ptr = vm->registers.regs[r_obj].qword();
    auto *target_cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());

    if (obj_ptr == 0 || target_cls == nullptr) {
        vm->registers.regs[R00].qword(0); // operandos nulos -> falso
        return;
    }

    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(obj_ptr);
    bool result =
        is_instance_of(hdr->class_ptr, target_cls); // comprobar jerarquia
    vm->registers.regs[R00].qword(result ? 1ULL : 0ULL);
}

// =========================================================================
//  0xD7 CHECKCAST reg_obj, reg_classinfo -> R0 = obj_ptr o THROW
// =========================================================================

/**
 * @brief Ejecuta la instruccion CHECKCAST: verifica y proyecta el tipo de un
 * objeto.
 *
 * Si el objeto es compatible con la clase indicada devuelve el puntero en R00.
 * Si no es compatible notifica EVT_ERROR con THREAD_ILLEGAL_INSTRUCTION.
 * El puntero nulo siempre supera la comprobacion (convencion JVM).
 *
 * @param vm    Proceso virtual que ejecuta CHECKCAST.
 * @param instr Instruccion descodificada con reg_data.reg1 (obj) y
 * reg_data.reg2 (ClassInfo*).
 */
void exec_instr_checkcast(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_obj = instr.data_instruction.reg_data.reg1;
    const uint8_t r_cls = instr.data_instruction.reg_data.reg2;

    uint64_t obj_ptr = vm->registers.regs[r_obj].qword();
    auto *target_cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());

    if (obj_ptr == 0) {
        // null siempre supera el cast (convencion JVM-compatible)
        vm->registers.regs[R00].qword(0);
        return;
    }

    auto *hdr = reinterpret_cast<loader::ObjectHeader *>(obj_ptr);
    bool ok = is_instance_of(hdr->class_ptr, target_cls);

    if (ok) {
        vm->registers.regs[R00].qword(
            obj_ptr); // cast correcto: devolver el puntero
    } else {
        // tipo incompatible: ClassCastException via FatalError
        runtime::throw_fatal(
            vm, runtime::FATAL_ILLEGAL_INSTRUCTION,
            "CHECKCAST: tipo incompatible (ClassCastException)");
    }
}

// =========================================================================
//  0xD8 GETFIELD reg_classinfo, field_idx -> R0 = FieldInfo*
// =========================================================================

/**
 * @brief Ejecuta la instruccion GETFIELD: obtiene el puntero a un descriptor de
 * campo.
 *
 * Devuelve en R00 el puntero host a FieldInfo en el array fields[] de la clase.
 * Devuelve 0 si la clase es nula o el indice esta fuera de rango.
 *
 * @param vm    Proceso virtual que ejecuta GETFIELD.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*) y
 * reg_data.reg2 (field_idx).
 */
void exec_instr_getfield(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1; // ClassInfo*
    const uint8_t field_idx =
        instr.data_instruction.reg_data.reg2; // indice del campo

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());
    if (cls == nullptr || field_idx >= cls->field_count) {
        vm->registers.regs[R00].qword(0); // indice invalido -> puntero nulo
        return;
    }

    vm->registers.regs[R00].qword(
        reinterpret_cast<uint64_t>(&cls->fields[field_idx]));
}

// =========================================================================
//  0xD9 GETMETHOD reg_classinfo, method_idx -> R0 = MethodInfo*
// =========================================================================

/**
 * @brief Ejecuta la instruccion GETMETHOD: obtiene el puntero a un descriptor
 * de metodo.
 *
 * Devuelve en R00 el puntero host a MethodInfo en el array methods[] de la
 * clase. Devuelve 0 si la clase es nula o el indice esta fuera de rango.
 *
 * @param vm    Proceso virtual que ejecuta GETMETHOD.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*) y
 * reg_data.reg2 (method_idx).
 */
void exec_instr_getmethod(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1;
    const uint8_t method_idx = instr.data_instruction.reg_data.reg2;

    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());
    if (cls == nullptr || method_idx >= cls->method_count) {
        vm->registers.regs[R00].qword(0);
        return;
    }

    vm->registers.regs[R00].qword(
        reinterpret_cast<uint64_t>(&cls->methods[method_idx]));
}

// =========================================================================
//  0xDA FIELDCOUNT reg_classinfo -> R0 = uint64
// =========================================================================

/**
 * @brief Ejecuta la instruccion FIELDCOUNT: devuelve el numero de campos de una
 * clase.
 *
 * @param vm    Proceso virtual que ejecuta FIELDCOUNT.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*).
 */
void exec_instr_fieldcount(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1;
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());

    vm->registers.regs[R00].qword(cls ? static_cast<uint64_t>(cls->field_count)
                                      : 0ULL);
}

// =========================================================================
//  0xDB METHODCOUNT reg_classinfo -> R0 = uint64
// =========================================================================

/**
 * @brief Ejecuta la instruccion METHODCOUNT: devuelve el numero de metodos de
 * una clase.
 *
 * @param vm    Proceso virtual que ejecuta METHODCOUNT.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*).
 */
void exec_instr_methodcount(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1;
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());

    vm->registers.regs[R00].qword(cls ? static_cast<uint64_t>(cls->method_count)
                                      : 0ULL);
}

// =========================================================================
//  0xDC CLASSNAME reg_classinfo -> R0 = char* (host ptr a name.data)
// =========================================================================

/**
 * @brief Ejecuta la instruccion CLASSNAME: devuelve el nombre de una clase.
 *
 * Escribe en R00 el puntero host al buffer de caracteres del nombre de la
 * clase. Devuelve 0 si la clase es nula o su nombre no tiene datos.
 *
 * @param vm    Proceso virtual que ejecuta CLASSNAME.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*).
 */
void exec_instr_classname(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1;
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());

    if (cls == nullptr || cls->name.data == nullptr) {
        vm->registers.regs[R00].qword(0); // clase sin nombre -> puntero nulo
        return;
    }

    vm->registers.regs[R00].qword(reinterpret_cast<uint64_t>(cls->name.data));
}

// =========================================================================
//  Helpers para acceso a doc/attrs
// =========================================================================

/**
 * @brief Devuelve el puntero host al buffer de una cadena stringx.
 * @param s Referencia a la cadena stringx.
 * @return Puntero host al buffer de caracteres, o 0 si es nulo.
 */
static inline uint64_t str_ptr(const loader::stringx &s) {
    return reinterpret_cast<uint64_t>(s.data); // puntero al buffer de la cadena
}

/**
 * @brief Devuelve el puntero host a la clave del atributo indicado.
 * @tparam T Tipo que contiene attrs[] y attr_count (ClassInfo, MethodInfo,
 * FieldInfo).
 * @param obj Puntero al objeto con atributos.
 * @param idx Indice del atributo.
 * @return Puntero host a la clave, o 0 si es invalido.
 */
template <typename T> static inline uint64_t attr_key(T *obj, uint8_t idx) {
    if (obj == nullptr || idx >= obj->attr_count || obj->attrs == nullptr)
        return 0; // parametros invalidos
    return reinterpret_cast<uint64_t>(obj->attrs[idx].key.data);
}

/**
 * @brief Devuelve el puntero host al valor del atributo indicado.
 * @tparam T Tipo que contiene attrs[] y attr_count (ClassInfo, MethodInfo,
 * FieldInfo).
 * @param obj Puntero al objeto con atributos.
 * @param idx Indice del atributo.
 * @return Puntero host al valor, o 0 si es invalido.
 */
template <typename T> static inline uint64_t attr_val(T *obj, uint8_t idx) {
    if (obj == nullptr || idx >= obj->attr_count || obj->attrs == nullptr)
        return 0; // parametros invalidos
    return reinterpret_cast<uint64_t>(obj->attrs[idx].value.data);
}

// =========================================================================
//  0xDD CLASSDOC -> R0 = char* (host ptr a doc.data)
// =========================================================================

/**
 * @brief Ejecuta CLASSDOC: devuelve el puntero al texto de documentacion de la
 * clase.
 * @param vm    Proceso virtual que ejecuta CLASSDOC.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*).
 */
void exec_instr_classdoc(ProcessVM *vm, const DecodedInstr &instr) {
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(cls ? str_ptr(cls->doc) : 0ULL);
}

// =========================================================================
//  0xDE CLASSATTRCOUNT -> R0 = uint64
// =========================================================================

/**
 * @brief Ejecuta CLASSATTRCOUNT: devuelve el numero de atributos de una clase.
 * @param vm    Proceso virtual que ejecuta CLASSATTRCOUNT.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*).
 */
void exec_instr_classattrcount(ProcessVM *vm, const DecodedInstr &instr) {
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(cls ? static_cast<uint64_t>(cls->attr_count)
                                      : 0ULL);
}

// =========================================================================
//  0xDF CLASSATTRKEY -> R0 = char* (key del atributo)
// =========================================================================

/**
 * @brief Ejecuta CLASSATTRKEY: devuelve la clave del atributo indicado de una
 * clase.
 * @param vm    Proceso virtual que ejecuta CLASSATTRKEY.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*) y
 * reg_data.reg2 (idx).
 */
void exec_instr_classattrkey(ProcessVM *vm, const DecodedInstr &instr) {
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(
        attr_key(cls, instr.data_instruction.reg_data.reg2));
}

// =========================================================================
//  0xE0 CLASSATTRVAL -> R0 = char* (valor del atributo)
// =========================================================================

/**
 * @brief Ejecuta CLASSATTRVAL: devuelve el valor del atributo indicado de una
 * clase.
 * @param vm    Proceso virtual que ejecuta CLASSATTRVAL.
 * @param instr Instruccion descodificada con reg_data.reg1 (ClassInfo*) y
 * reg_data.reg2 (idx).
 */
void exec_instr_classattrval(ProcessVM *vm, const DecodedInstr &instr) {
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(
        attr_val(cls, instr.data_instruction.reg_data.reg2));
}

// =========================================================================
//  0xE1 METHODNAME -> R0 = char* (nombre del metodo)
// =========================================================================

/**
 * @brief Ejecuta METHODNAME: devuelve el puntero al nombre de un MethodInfo.
 * @param vm    Proceso virtual que ejecuta METHODNAME.
 * @param instr Instruccion descodificada con reg_data.reg1 (MethodInfo*).
 */
void exec_instr_methodname(ProcessVM *vm, const DecodedInstr &instr) {
    auto *m = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(m ? str_ptr(m->name) : 0ULL);
}

// =========================================================================
//  0xE2 METHODDOC -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta METHODDOC: devuelve el puntero a la documentacion de un
 * metodo.
 * @param vm    Proceso virtual que ejecuta METHODDOC.
 * @param instr Instruccion descodificada con reg_data.reg1 (MethodInfo*).
 */
void exec_instr_methoddoc(ProcessVM *vm, const DecodedInstr &instr) {
    auto *m = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(m ? str_ptr(m->doc) : 0ULL);
}

// =========================================================================
//  0xE3 METHODDESC -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta METHODDESC: devuelve el puntero al descriptor de tipo de un
 * metodo.
 * @param vm    Proceso virtual que ejecuta METHODDESC.
 * @param instr Instruccion descodificada con reg_data.reg1 (MethodInfo*).
 */
void exec_instr_methoddesc(ProcessVM *vm, const DecodedInstr &instr) {
    auto *m = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(m ? str_ptr(m->descriptor) : 0ULL);
}

// =========================================================================
//  0xE4 METHODATTRCOUNT -> R0 = uint64
// =========================================================================

/**
 * @brief Ejecuta METHODATTRCOUNT: devuelve el numero de atributos de un metodo.
 * @param vm    Proceso virtual que ejecuta METHODATTRCOUNT.
 * @param instr Instruccion descodificada con reg_data.reg1 (MethodInfo*).
 */
void exec_instr_methodattrcount(ProcessVM *vm, const DecodedInstr &instr) {
    auto *m = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(m ? static_cast<uint64_t>(m->attr_count)
                                    : 0ULL);
}

// =========================================================================
//  0xE5 METHODATTRKEY -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta METHODATTRKEY: devuelve la clave del atributo indicado de un
 * metodo.
 * @param vm    Proceso virtual que ejecuta METHODATTRKEY.
 * @param instr Instruccion descodificada con reg_data.reg1 (MethodInfo*) y
 * reg_data.reg2 (idx).
 */
void exec_instr_methodattrkey(ProcessVM *vm, const DecodedInstr &instr) {
    auto *m = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(
        attr_key(m, instr.data_instruction.reg_data.reg2));
}

// =========================================================================
//  0xE6 METHODATTRVAL -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta METHODATTRVAL: devuelve el valor del atributo indicado de un
 * metodo.
 * @param vm    Proceso virtual que ejecuta METHODATTRVAL.
 * @param instr Instruccion descodificada con reg_data.reg1 (MethodInfo*) y
 * reg_data.reg2 (idx).
 */
void exec_instr_methodattrval(ProcessVM *vm, const DecodedInstr &instr) {
    auto *m = reinterpret_cast<loader::MethodInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(
        attr_val(m, instr.data_instruction.reg_data.reg2));
}

// =========================================================================
//  0xE7 FIELDNAME -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta FIELDNAME: devuelve el puntero al nombre de un FieldInfo.
 * @param vm    Proceso virtual que ejecuta FIELDNAME.
 * @param instr Instruccion descodificada con reg_data.reg1 (FieldInfo*).
 */
void exec_instr_fieldname(ProcessVM *vm, const DecodedInstr &instr) {
    auto *f = reinterpret_cast<loader::FieldInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(f ? str_ptr(f->name) : 0ULL);
}

// =========================================================================
//  0xE8 FIELDDOC -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta FIELDDOC: devuelve el puntero a la documentacion de un campo.
 * @param vm    Proceso virtual que ejecuta FIELDDOC.
 * @param instr Instruccion descodificada con reg_data.reg1 (FieldInfo*).
 */
void exec_instr_fielddoc(ProcessVM *vm, const DecodedInstr &instr) {
    auto *f = reinterpret_cast<loader::FieldInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(f ? str_ptr(f->doc) : 0ULL);
}

// =========================================================================
//  0xE9 FIELDATTRCOUNT -> R0 = uint64
// =========================================================================

/**
 * @brief Ejecuta FIELDATTRCOUNT: devuelve el numero de atributos de un campo.
 * @param vm    Proceso virtual que ejecuta FIELDATTRCOUNT.
 * @param instr Instruccion descodificada con reg_data.reg1 (FieldInfo*).
 */
void exec_instr_fieldattrcount(ProcessVM *vm, const DecodedInstr &instr) {
    auto *f = reinterpret_cast<loader::FieldInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(f ? static_cast<uint64_t>(f->attr_count)
                                    : 0ULL);
}

// =========================================================================
//  0xEA FIELDATTRKEY -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta FIELDATTRKEY: devuelve la clave del atributo indicado de un
 * campo.
 * @param vm    Proceso virtual que ejecuta FIELDATTRKEY.
 * @param instr Instruccion descodificada con reg_data.reg1 (FieldInfo*) y
 * reg_data.reg2 (idx).
 */
void exec_instr_fieldattrkey(ProcessVM *vm, const DecodedInstr &instr) {
    auto *f = reinterpret_cast<loader::FieldInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(
        attr_key(f, instr.data_instruction.reg_data.reg2));
}

// =========================================================================
//  0xEB FIELDATTRVAL -> R0 = char*
// =========================================================================

/**
 * @brief Ejecuta FIELDATTRVAL: devuelve el valor del atributo indicado de un
 * campo.
 * @param vm    Proceso virtual que ejecuta FIELDATTRVAL.
 * @param instr Instruccion descodificada con reg_data.reg1 (FieldInfo*) y
 * reg_data.reg2 (idx).
 */
void exec_instr_fieldattrval(ProcessVM *vm, const DecodedInstr &instr) {
    auto *f = reinterpret_cast<loader::FieldInfo *>(
        vm->registers.regs[instr.data_instruction.reg_data.reg1].qword());
    vm->registers.regs[R00].qword(
        attr_val(f, instr.data_instruction.reg_data.reg2));
}

} // namespace runtime
