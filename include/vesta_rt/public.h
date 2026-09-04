/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file vesta_rt/public.h
 * @brief API estable C ABI de @c libvesta_rt para codigo generado (JIT/AOT).
 *
 * Este header expone los runtime entries necesarios para que codigo
 * generado por el JIT ( D) o el AOT ( F) pueda llamar al
 * runtime sin depender del frontend del lenguaje ni de las cabeceras
 * C++ internas.  Toda la API es @c extern "C" con punteros opacos
 * para que sea linkable desde cualquier toolchain (Cranelift, MachineIR
 * propio, ensamblador a mano, plugins de terceros, etc.).
 *
 * = Diseno (snapshot 2026-05-13) =
 *
 * - Los tipos @c vrt_proc / @c vrt_vm / @c vrt_class son punteros opacos
 *   (forward decls).  El consumidor jamas debe asumir layout interno;
 *   en su lugar usa @c vesta_rt/abi.h para offsets explicitos.
 *
 * - Los handles GC son @c uint32_t crudos (mismo modelo que el bytecode
 *   usa hoy).  El sentinela @c VRT_NULL_HANDLE = UINT32_MAX representa
 *   nulo/invalido.
 *
 * - Errores fatales no se propagan via codigo de retorno: invocan
 *   @c vrt_throw_fatal que aborta la ejecucion o salta al handler
 *   activo (@c tryenter del bytecode).  El codigo generado nunca
 *   necesita verificar retornos de error.
 *
 * - Ningun simbolo aqui puede cambiar de signatura sin bumpear el
 *   @c VRT_API_VERSION_MAJOR.  Bumps minor permiten añaDIR funciones
 *   nuevas al final, jamas mutar las existentes.
 *
 * = Uso desde el JIT =
 *
 * El emisor de codigo nativo resuelve las direcciones de estas
 * funciones via la tabla en @c jit/runtime_entries.h al inicio de cada
 * compile job y las emite como @c call rel32 (PC-relative) o como
 * indirect call via slot fijo del code cache.  Cero overhead vs llamar
 * a C++ directamente (es C++ por dentro, solo el wrapper externo es C).
 */

#ifndef VESTA_RT_PUBLIC_H
#define VESTA_RT_PUBLIC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Version                                                                    */
/* ========================================================================= */

#define VRT_API_VERSION_MAJOR 0
#define VRT_API_VERSION_MINOR 1
#define VRT_API_VERSION_PATCH 0

/* ========================================================================= */
/* Tipos opacos                                                               */
/* ========================================================================= */

/** @brief Puntero opaco a un ProcessVM (un proceso del runtime). */
typedef struct vrt_proc vrt_proc;

/** @brief Puntero opaco a una VM (contenedor de procesos / scheduler). */
typedef struct vrt_vm vrt_vm;

/** @brief Puntero opaco a un ClassInfo (metadatos de clase OOP). */
typedef struct vrt_class vrt_class;

/** @brief Puntero opaco a un MethodInfo (metadatos de metodo OOP). */
typedef struct vrt_method vrt_method;

/** @brief Handle GC opaco (indice en HandleTable per-process). */
typedef uint32_t vrt_handle;

/** @brief Sentinela: handle invalido o nulo. */
#define VRT_NULL_HANDLE UINT32_MAX

/* ========================================================================= */
/* GC                                                                         */
/* ========================================================================= */

/**
 * @brief Aloca un objeto en el heap del proceso (Nursery por defecto).
 * @param proc proceso destino; su GcHeap es donde se aloca.
 * @param size tamano total en bytes (incluye ObjectHeader).
 * @return handle al objeto; @c VRT_NULL_HANDLE si OOM.
 *
 * El objeto sale con header zero-init.  El consumidor debe escribir
 * @c class_ptr antes de exponerlo al GC (la siguiente alocacion podria
 * disparar minor_gc y escanear stack roots).
 */
vrt_handle vrt_gc_alloc(vrt_proc *proc, size_t size);

/**
 * @brief Aloca un objeto NO-MOVING directamente en OldGen.
 * @return handle estable: @c vrt_gc_deref devuelve siempre la misma
 *         direccion host hasta @c vrt_gc_drop.
 *
 * Usado por strings inmutables, buffers FFI y cualquier caso que
 * necesite estabilidad de @c host_ptr a traves del ciclo GC.
 */
vrt_handle vrt_gc_alloc_pinned(vrt_proc *proc, size_t size);

/**
 * @brief Aloca un bloque de memoria HOST cruda (no GC-managed).
 *
 * Equivalente a @c malloc(size) del C runtime: devuelve un puntero
 * dereferenciable directamente por codigo C nativo (Win32, POSIX, etc).
 * El bloque vive hasta que se invoca @c vrt_raw_free.  No participa
 * del GC: el caller es responsable de liberarlo.
 *
 * Usado por callbacks Vesta que necesitan alocar structs (WNDCLASSEXW,
 * MSG, etc) o buffers para pasar a APIs nativas que esperan host_ptr.
 *
 * @return Puntero host dereferenciable, o @c NULL si OOM.
 */
uint8_t *vrt_raw_alloc(vrt_proc *proc, size_t size);

/**
 * @brief Libera un bloque previamente alocalizado con @c vrt_raw_alloc.
 *
 * Idempotente para ptr=NULL (no-op).  Doble free es undefined behavior.
 */
void vrt_raw_free(vrt_proc *proc, uint8_t *ptr);

/**
 * @brief Resuelve un handle a su puntero host actual.
 * @return @c NULL si el handle es invalido o ya colectado.
 *
 * @warning El puntero es valido solo hasta la siguiente operacion que
 *          pueda mover objetos (alloc, llamada al runtime, safepoint).
 *          Codigo generado debe re-deref tras cualquier safepoint.
 */
uint8_t *vrt_gc_deref(vrt_proc *proc, vrt_handle h);

/**
 * @brief Lookup inverso: payload host_ptr -> handle.
 * @return @c VRT_NULL_HANDLE si el puntero no es payload-start de un
 *         objeto vivo en este heap.
 */
vrt_handle vrt_gc_handle_for_ptr(vrt_proc *proc, const uint8_t *payload);

/**
 * @brief Libera explicitamente un handle (drop manual).
 *
 * El objeto fisico permanece hasta el siguiente GC.  Hace el slot
 * disponible para reciclar (free_handles_).  Cero overhead vs el GC
 * automatico; es solo un hint deterministico.
 */
void vrt_gc_drop(vrt_proc *proc, vrt_handle h);

/**
 * @brief Pin externo del handle (refcount externo).
 *
 * Usado por colecciones nativas que retienen GcHandles fuera del heap
 * (e.g. plugin de colecciones).  Mientras refcount > 0, el GC NO
 * colectara el objeto aunque no haya referencias en el bytecode.
 */
void vrt_gc_addref(vrt_proc *proc, vrt_handle h);

/** @brief Unpin externo (decrementa refcount). */
void vrt_gc_release(vrt_proc *proc, vrt_handle h);

/**
 * @brief Write barrier para referencia old -> young.
 *
 * Debe llamarse DESPUES de escribir un campo de un objeto OLD que
 * apunta a un objeto YOUNG.  Sin esto, el minor_gc puede liberar el
 * young aunque haya una referencia viva desde old.
 */
void vrt_gc_write_barrier(vrt_proc *proc, vrt_handle old_handle);

/* ========================================================================= */
/* Monitores (synchronized / wait / notify)                                   */
/* ========================================================================= */

/**
 * @brief Adquiere monitor reentrant del objeto.
 * @return 1 si adquirido inmediatamente, 0 si esta en espera (la VM
 *         registra el proceso en la cola del monitor; cuando se libere,
 *         el scheduler lo despierta).
 */
int32_t vrt_monitor_enter(vrt_proc *proc, vrt_handle obj);

/**
 * @brief Libera el monitor (decrementa lock_depth).
 *
 * Cuando lock_depth llega a 0, se publica el next waiter de la cola
 * via vm.make_ready (despierta otro proceso esperando).
 */
void vrt_monitor_exit(vrt_proc *proc, vrt_handle obj);

/**
 * @brief Suspende el proceso liberando el monitor por completo.
 *
 * Equivalente a Object.wait() de Java.  El proceso queda en WAIT_IO
 * hasta que otro hilo invoque @c vrt_monitor_notify o @c
 * vrt_monitor_notify_all. Tras el wake debe re-adquirir el monitor.
 */
void vrt_monitor_wait(vrt_proc *proc, vrt_handle obj);

/** @brief Despierta UN proceso de la cola de espera del monitor. */
void vrt_monitor_notify(vrt_proc *proc, vrt_handle obj);

/** @brief Despierta TODOS los procesos de la cola de espera. */
void vrt_monitor_notify_all(vrt_proc *proc, vrt_handle obj);

/* ========================================================================= */
/* Excepciones (FatalError + tryenter/tryleave)                              */
/* ========================================================================= */

/**
 * @brief Lanza un FatalError capturable o aborta.
 * @param kind codigo de error (FATAL_NULL_POINTER=1, FATAL_OOM=2,
 *             FATAL_ILLEGAL_INSTRUCTION=3, FATAL_USER_ABORT=11,
 *             FATAL_SEGMENTATION_FAULT=7, FATAL_NATIVE_EXCEPTION=8,
 *             FATAL_NATIVE_CRASH=9, etc.).
 * @param message string C-style (puede ser NULL).
 *
 * Si hay un @c tryenter activo (cadena @c ExceptionFrame), salta al
 * handler.  Si no, marca el proceso como muerto y dispara EVT_ERROR.
 * Nunca retorna en codigo normal; el caller no debe asumir retorno.
 */
void vrt_throw_fatal(vrt_proc *proc, uint32_t kind, const char *message);

/**
 * @brief Lanza FATAL_NULL_POINTER (unwrap sobre null).  Atajo 1-arg para
 * el chequeo inline de UNWRAP en el JIT vreg VM_ABI: el codegen emite
 * `test v,v; jne ok; call vrt_unwrap_throw(proc); ok:` -> el camino frio
 * (null) llama aqui.  Equivale al throw del bytecode UNWRAP (0x26).
 * Nunca retorna (salta al handler o aborta).
 */
void vrt_unwrap_throw(vrt_proc *proc);

/**
 * @brief Push de un frame de manejo de excepciones.
 *
 * El handler_pc es la direccion absoluta del catch block (en bytecode
 * para codigo interpretado, o en code cache para JIT-eado).  El
 * type_class es el ClassInfo* a matchear; NULL = catch-all.  El RSP/
 * RBP/frame_stack actuales se snapshotean para que el throw los
 * restaure al saltar.
 */
void vrt_tryenter(vrt_proc *proc, uint64_t handler_pc, vrt_class *type_class);

/** @brief Pop del tope del exc_frame_stack (salida normal del try). */
void vrt_tryleave(vrt_proc *proc);

/**
 * @brief Push de un frame de excepcion in-JIT (Opcion B): el handler vive en
 *        codigo JIT-eado, no en bytecode.
 *
 * @param proc              proceso actual.
 * @param type_class        ClassInfo* a matchear; NULL = catch-all.
 * @param native_catch_addr direccion nativa del bloque catch JIT.
 *
 * El RSP/RBP host del frame del try se pasan por handoff transitorio en
 * @c proc->jit_exc_rsp / @c proc->jit_exc_rbp (el JIT los escribe justo antes
 * de llamar aqui), evitando un 5o argumento en pila en Win64.  A diferencia de
 * @c vrt_tryenter (handler en bytecode), un throw que matchee este frame NO
 * resume el interp: @c do_throw llama @c vrt_resume_jit para saltar a
 * @c native_catch_addr con el frame host restaurado.  La excepcion la deja en
 * @c proc->registers[0] (el catch la lee via LANDINGPAD).
 */
void vrt_tryenter_jit(vrt_proc *proc, vrt_class *type_class,
                      uint64_t native_catch_addr);

/**
 * @brief Reanuda un catch in-JIT: restaura el frame host y salta al catch.
 *
 * Stub asm (UNICA pieza arch-especifica del modelo de excepciones JIT/AOT):
 * @c rbp=native_rbp; @c rsp=native_rsp; @c jmp catch_addr.  Abandona los
 * frames nativos intermedios (calls anidados + los frames C de
 * @c vrt_throw_user/@c do_throw) reseteando RSP.  NUNCA retorna.  La excepcion
 * ya esta en @c proc->registers[0] (la puso @c do_throw); el catch la lee via
 * LANDINGPAD.  @c do_throw ya hizo la limpieza VM (host_allocas, frames OOP)
 * antes de llamar aqui.
 */
#if defined(_MSC_VER)
__declspec(noreturn)
#endif
void vrt_resume_jit(uint64_t catch_addr, uint64_t native_rsp,
                    uint64_t native_rbp, uint64_t proc)
#if defined(__GNUC__)
    __attribute__((noreturn))
#endif
    ;

/**
 * @brief Lanza una excepcion user-defined desde codigo JIT.
 *
 * Toma un GcHandle (codificado como i64) de un objeto excepcion previamente
 * construido (typically @c new MyException(...)).  Delega a @c do_throw del
 * runtime que:
 *   1. Recorre @c proc->exc_frame_stack buscando el frame matching por tipo.
 *   2. Si encuentra match: restaura RSP/RBP/regs del snapshot del tryenter
 *      y salta al @c handler_pc del frame.
 *   3. Si no hay handler matching: marca el proceso DEAD y dispara EVT_ERROR.
 *
 * Nunca retorna normalmente.  La calling convention del handler es:
 *   - R0 contiene el GcHandle de la excepcion (replicado por do_throw).
 *
 * @param proc proceso actual.
 * @param exc_handle handle (uint32 zero-extendido a uint64) del objeto
 * excepcion.
 */
void vrt_throw_user(vrt_proc *proc, uint64_t exc_handle);

/**
 * @brief Relanza la excepcion activa (@c proc->current_exception).
 *
 * Equivalente a @c rethrow del bytecode: invoca @c do_throw con el handle
 * de la excepcion que esta actualmente siendo manejada (capturada por el
 * catch enclosing).  Usado tipicamente por synchronized handlers que hacen
 * monexit + rethrow para propagar la excepcion al frame externo.
 *
 * Nunca retorna normalmente (igual que @c vrt_throw_user).
 *
 * @param proc proceso actual.  Debe tener @c current_exception != 0.
 */
void vrt_rethrow(vrt_proc *proc);

/* ========================================================================= */
/* FFI nativo                                                                */
/* ========================================================================= */

/**
 * @brief Invoca una funcion nativa con N argumentos (0..12).
 * @param fn puntero a la funcion nativa (resuelto via dlsym o estatico).
 * @param argc numero de args (max 12).  Cada arg se toma de R1..R12.
 * @param proc proceso actual (para acceder a registers / vm_mem).
 * @return valor retornado por la nativa (0 si void).
 *
 * Misma calling convention que CALLN bytecode.  Cero overhead vs llamar
 * la nativa directamente.  El caller debe garantizar argc <= 12.
 */
uint64_t vrt_invoke_native(void *fn, uint64_t argc, vrt_proc *proc);

/* ========================================================================= */
/* Dispatch dinamico (CALLVIRT desde codigo JIT)                              */
/* ========================================================================= */

/**
 * @brief Dispatch dinamico de un metodo virtual desde codigo JIT.
 *
 * Equivalente runtime del opcode bytecode @c callvirt: dado un objeto
 * (host_ptr al payload) y un indice de vtable, resuelve el MethodInfo
 * via @c obj->class_ptr->vtable[idx] y dispatcha:
 *   - Si @c method->jit_code != nullptr -> @c enter_jit() directo
 *     (codigo nativo, calling convention VM_ABI).
 *   - Si no -> setea @c proc->registers.rip al entry bytecode del
 *     metodo y deja que el interprete lo ejecute.  Para JIT que ya
 *     esta en native, esto implica suspender la ejecucion JIT actual
 *     y volver al scheduler.  Para v1, este path retorna 0 y deja
 *     el dispatch al interpreter via el flag de blocking.
 *
 * Calling convention de la METHOD invocada (igual que CALLVIRT):
 *   - R1 = obj_host_ptr (this).
 *   - R2..R12 = argumentos (max 11 args).
 *   - R15 = argc + 1.
 *   - Resultado en R0 al retornar.
 *
 * @param proc proceso actual.
 * @param obj_payload host_ptr al payload del objeto receiver.
 * @param vtbl_idx indice del slot en @c ClassInfo::vtable.
 * @return valor de retorno del metodo (leido de @c proc->registers.regs[0]).
 *         O 0 si fallo el dispatch (e.g. obj nulo, clase nula, idx fuera de
 * rango).
 *
 * Throws @c FATAL_NULL_POINTER si @c obj_payload es nullptr, o
 * @c FATAL_ILLEGAL_INSTRUCTION si vtbl_idx es invalido / metodo abstracto.
 */
uint64_t vrt_callvirt(vrt_proc *proc, uint8_t *obj_payload, uint32_t vtbl_idx);

/**
 * @brief CALLVIRT con Inline Cache.  Igual que @c vrt_callvirt pero al final
 *        actualiza el slot de cache pasado en @p ic_slot_addr con
 *        (cls, jit_code) para que llamadas futuras al mismo call site
 *        hagan dispatch directo sin pasar por esta funcion.
 *
 * El slot tiene 16 bytes:
 *   - offset 0: cached_class_ptr
 *   - offset 8: cached_jit_code
 *
 * Cuando ic_slot_addr == 0 o el metodo no es JIT-able (advice_chain,
 * raw_asm complejo), NO actualiza el slot -> proximas llamadas seguiran
 * yendo por miss path.
 */
uint64_t vrt_callvirt_ic(vrt_proc *proc, uint8_t *obj_payload,
                         uint32_t vtbl_idx, uint64_t ic_slot_addr);

/**
 * @brief Dispatch dinamico via MethodInfo* (CALLM desde JIT).
 *
 * Equivalente runtime del opcode bytecode @c callm: dado un objeto
 * (host_ptr al payload) y un puntero a @c MethodInfo, dispatcha
 * directo sin usar vtable.  Usado por interfaces y
 * reflexion runtime (Method.invoke).
 *
 * El metodo recibe la misma calling convention que CALLVIRT (R1=this,
 * R2..R12=args, R15=argc+1).  El caller debe staged los args en
 * @c proc->registers.regs[1..N+1] antes de invocar este wrapper.
 *
 * @param proc proceso actual.
 * @param obj_payload host_ptr al payload del objeto receiver.
 * @param method puntero al @c MethodInfo a invocar.
 * @return valor de retorno del metodo (de @c proc->registers.regs[0]).
 */
uint64_t vrt_callm(vrt_proc *proc, uint8_t *obj_payload, void *method);

/**
 * @brief Dispatch de interfaz via itable (CALLITF desde JIT).
 *
 * Lee el @c ItfCallParams (32 bytes en vm_mem en @p params_addr) con el nombre
 * de la interfaz, el nombre del metodo, su indice y el numero de metodos;
 * resuelve la interfaz (find_class) y el @c MethodInfo* concreto via la itable
 * lazy de la clase del receptor (@c ClassRegistry::resolve_itable_method), y
 * despacha (si el metodo tiene @c jit_code -> @c enter_jit; si no ->
 * mini-interp sincronico).  Es el SLOW PATH/fallback del inline de CALLITF en
 * el JIT.
 *
 * Calling convention identica a CALLVIRT/CALLM: el caller staged R1=this,
 * R2..=args, R15=argc+1 en @c proc->registers antes de invocar.
 *
 * @param proc         proceso actual.
 * @param obj_payload  host_ptr al payload del objeto receiver.
 * @param params_addr  VM addr del @c ItfCallParams.
 * @param ic_slot_addr host addr de un slot de 8 bytes (cache del call site); si
 *                     != 0, se escribe ahi el @c ClassInfo* de la interfaz
 *                     resuelto, para que el inline de CALLITF lo lea en los
 *                     dispatch siguientes (0 = sin cache).
 * @return valor de retorno del metodo (de @c proc->registers.regs[0]).
 */
uint64_t vrt_callitf(vrt_proc *proc, uint8_t *obj_payload, uint64_t params_addr,
                     uint64_t ic_slot_addr);

/**
 * @brief Invocacion de closure (CALLCLOSURE desde JIT).
 *
 * Equivalente runtime de @c callclosure / @c callrawclosure: invoca
 * una closure dada como (fn_addr, env_addr).  Identica calling
 * convention que CALLVM (args en R1..R12, argc en R15, env en R14).
 *
 * @param proc proceso actual.
 * @param fn_addr direccion del codigo del cuerpo del closure (en bytecode VM).
 * @param env_addr direccion del env block (VM o host, segun closure kind).
 * @return valor de retorno (de @c proc->registers.regs[0]).
 */
uint64_t vrt_callclosure(vrt_proc *proc, uint64_t fn_addr, uint64_t env_addr);

/**
 * @brief Trampoline JIT->interp para llamar a una funcion bytecode
 * user-defined.
 *
 * Cuando codigo JIT necesita invocar una funcion cuyo IR no se pudo
 * JIT-compilar (raw_asm complejo, monenter, synchronized, float arith no
 * soportada, etc.), el selector emite una CALL a este wrapper en lugar
 * de marcar el caller como unsupported.  De esa forma main + helpers
 * basicos pueden JIT-compilar aunque algunas callees caigan a interp.
 *
 * Calling convention identica a CALLVM bytecode:
 *   - args ya en @c proc->registers.regs[1..N] (puestos por el caller JIT
 *     ANTES de invocar este wrapper)
 *   - argc en @c proc->registers.regs[15]
 *   - retorno final en @c proc->registers.regs[0]
 *
 * Internamente:
 *   1. Salva rip/rsp/frame_stack/decoded_ptr del proceso.
 *   2. Push un sentinel ret_addr al stack VM (@c VRT_BYTECODE_RET_SENTINEL).
 *   3. Setea proc->rip = @p bc_entry_va.
 *   4. Mini run-loop: decode + execute hasta que rip == sentinel
 *      (i.e. el RET final del bytecode pop-eo el sentinel y salto a el).
 *   5. Restaura estado y retorna @c proc->registers.regs[0].
 *
 * Limitaciones documentadas:
 *   - Si la funcion lanza una excepcion sin handler interno y la catch
 *     esperada esta en codigo JIT-eated del caller, el unwind cruzaria
 *     la frontera JIT/interp -- comportamiento indefinido en v1.
 *     Solucion futura:  D.13 (native unwinding).
 *   - Si la funcion bloquea por IO/wait, este wrapper aborta con
 *     FATAL_ILLEGAL_INSTRUCTION (no se puede esperar IO sincronicamente
 *     desde dentro de un JIT frame).
 *
 * @param proc proceso actual.
 * @param bc_entry_va direccion VM (entry point) del bytecode de la funcion,
 *        tipicamente resuelta via symbol_table del @c .velb por el JIT
 *        selector (lookup de @c "code.<func_name>").
 * @return valor de @c proc->registers.regs[0] al terminar.
 */
uint64_t vrt_call_bc_function(vrt_proc *proc, uint64_t bc_entry_va);

/**
 * @brief CALLN nativo desde JIT (FFI estatico resuelto en runtime).
 *
 * Equivalente runtime de @c calln @Method("lib:fn"): resuelve el
 * simbolo via Loader::resolve_native_symbol (cached por LibHandle*),
 * setea los args desde @c proc->registers.regs[1..argc] y los pasa
 * al wrapper invoke_native_unchecked.
 *
 * El caller debe colocar los args en @c proc->registers.regs[1..argc]
 * y @c argc en R15 antes de invocar.
 *
 * @param proc proceso actual.
 * @param lib_name nombre de la libreria (sin extension; ASCII).
 * @param fn_name  nombre del simbolo a resolver.
 * @return valor de retorno del wrapper nativo.
 */
uint64_t vrt_calln(vrt_proc *proc, const char *lib_name, const char *fn_name);

/* ========================================================================= */
/* Acceso a memoria VM ( D.3-G: vm_addr -> host_ptr translator)         */
/* ========================================================================= */

/**
 * @brief Lectura de 8 bytes desde memoria VM virtual.
 *
 * Equivalente runtime del bytecode `mov rN, [rM]` cuando la direccion
 * en rM es una VM addr (memoria virtual del proceso, no host).
 * Delega a @c VirtualMemory::read_u64_fast que usa el page cache
 * interno para hits secuenciales (~5 ns hit, ~50 ns miss).
 *
 * @param proc proceso actual.
 * @param vaddr direccion virtual VM (no host).
 * @return los 8 bytes leidos como uint64.
 */
uint64_t vrt_vm_read_u64(vrt_proc *proc, uint64_t vaddr);

/**
 * @brief Escritura de 8 bytes a memoria VM virtual.
 *
 * Equivalente runtime del bytecode `mov [rM], val` cuando la direccion
 * en rM es una VM addr.  Delega a @c VirtualMemory::write_u64_fast.
 *
 * @param proc proceso actual.
 * @param vaddr direccion virtual VM.
 * @param value valor de 8 bytes a escribir.
 */
void vrt_vm_write_u64(vrt_proc *proc, uint64_t vaddr, uint64_t value);

/** @brief Variantes por tamano (necesarias para LOAD/STORE de i8/i16/i32). */
uint32_t vrt_vm_read_u32(vrt_proc *proc, uint64_t vaddr);
uint16_t vrt_vm_read_u16(vrt_proc *proc, uint64_t vaddr);
uint8_t vrt_vm_read_u8(vrt_proc *proc, uint64_t vaddr);
void vrt_vm_write_u32(vrt_proc *proc, uint64_t vaddr, uint32_t value);
void vrt_vm_write_u16(vrt_proc *proc, uint64_t vaddr, uint16_t value);
void vrt_vm_write_u8(vrt_proc *proc, uint64_t vaddr, uint8_t value);

/**
 * @brief Relleno de un bloque de memoria de la MAQUINA.
 *
 * Existe por lo mismo que sus hermanas de un valor: la memoria de la maquina no
 * es contigua -- va por paginas, con traduccion y asignacion perezosa --, asi
 * que una direccion virtual NO vale como puntero del proceso.
 *
 * El codigo compilado tenia las de un valor y le faltaban las de BLOQUE: para
 * @c MEMSET emitia el relleno del anfitrion sobre la direccion en crudo, sin
 * mirar de que memoria era.  Sobre memoria de la maquina eso escribe en otro
 * sitio, y no da un error -- da otro resultado --.  Un programa que registraba
 * sus clases devolvia CERO compilado y su valor correcto interpretado.
 *
 * Aqui NO hay camino rapido en linea, a diferencia de las de un valor: una
 * operacion de bloque ya amortiza la llamada, y el trabajo por pagina lo hace
 * la propia memoria virtual.
 *
 * @param proc  Proceso dueno de la memoria.
 * @param vaddr Primer byte, en direcciones de la maquina.
 * @param value Byte que se repite (solo se usan sus 8 bits bajos).
 * @param len   Cuantos bytes.
 */
void vrt_vm_memset(vrt_proc *proc, uint64_t vaddr, uint64_t value,
                   uint64_t len);

/**
 * @brief Copia de un bloque DENTRO de la memoria de la maquina.
 *
 * Gemela de @ref vrt_vm_memset, y por la misma razon.  Admite solape: se
 * comporta como un movimiento, no como una copia byte a byte hacia delante,
 * porque las dos regiones pueden ser la misma con desplazamiento.
 *
 * @param proc Proceso dueno de la memoria.
 * @param dst  Primer byte del destino, en direcciones de la maquina.
 * @param src  Primer byte del origen, en direcciones de la maquina.
 * @param len  Cuantos bytes.
 */
void vrt_vm_memcpy(vrt_proc *proc, uint64_t dst, uint64_t src, uint64_t len);

/**
 * @brief Traduce una VM-addr a host_ptr via vm_mem.
 *
 *  D.jit-mem-model FULL: usado por el JIT en cada LOAD/STORE
 * cuyo puntero tiene IR is_host_ptr=false (VM-addr semantica).
 * Para is_host_ptr=true el JIT emite native mov directo sin esta
 * llamada.
 *
 * Diseno portable: confia en is_host_ptr del IR (semanticamente
 * preciso, marcado por el frontend) en lugar de range checks
 * arbitrarios que no son portables cross-arch.
 *
 * Delega a @c proc->vm_mem.operator[](vaddr) que fuerza la
 * asignacion perezosa de la pagina si no existe (igual semantica
 * que el interp).  Coste: ~30 ns por call (page cache lookup).
 *
 * @param proc proceso actual.
 * @param vaddr VM-addr.
 * @return host_ptr al byte correspondiente.
 */
uint8_t *vrt_vm_translate(vrt_proc *proc, uint64_t vaddr);

/* ========================================================================= */
/* Class registry runtime entries (defclass/findclass/newobj/etc)            */
/* ========================================================================= */

/**
 * @brief Lookup de clase por nombre (FindClassParams en vm_addr).
 *
 * @c FindClassParams ABI: 16 bytes en VM memory:
 *   +0  [8] name_addr (VM addr)
 *   +8  [4] name_len
 *   +12 [4] _pad
 *
 * @return ClassInfo* o nullptr si no encontrada.
 */
vrt_class *vrt_findclass(vrt_proc *proc, uint64_t params_vaddr);

/**
 * @brief Crea instancia de una clase (newobj bytecode).
 *
 * Alloca un objeto del tamano de la clase via @c gc_heap.alloc,
 * inicializa el header con @c class_ptr = cls.  Devuelve host_ptr
 * al payload (post-header).
 *
 * @param proc proceso actual.
 * @param cls puntero a la clase a instanciar.
 * @return host_ptr al payload del objeto recien creado, o nullptr si OOM.
 */
uint8_t *vrt_newobj(vrt_proc *proc, vrt_class *cls);

/**
 * @brief Aloca un nuevo objeto y devuelve directamente el GcHandle.
 *
 * Combina @c vrt_newobj + @c vrt_gc_handle_for_ptr en una sola llamada,
 * ahorrando una runtime entry call (~30-50 ns por @c new X()).  Util
 * para JIT que necesita el handle (no el host_ptr) para luego pasar a
 * @c gcderef.  Reduce la cadena `newobj + gc_handle_for_ptr` (2 calls)
 * a una sola.
 *
 * @return GcHandle del objeto creado, o @c VRT_NULL_HANDLE si OOM.
 */
vrt_handle vrt_newobj_handle(vrt_proc *proc, vrt_class *cls);

/**
 * @brief NEWOBJS: aloca un objeto de @p cls en el SharedHeap (cross-process)
 *        y devuelve su GcHandle (con SHARED_HANDLE_BIT).  Equivale al opcode
 *        newobjs (0xA6).  GC_NULL_HANDLE si cls es null u OOM.
 */
vrt_handle vrt_newobjs(vrt_proc *proc, vrt_class *cls);

/**
 * @brief DLOPEN: carga una libreria nativa (LoadLibrary/dlopen) cuyo path
 *        (UTF-8) vive en @p path_vaddr (len @p path_len) del vm_mem.
 *        Devuelve el handle host (i64); lanza FatalError si falla.
 */
uint64_t vrt_dlopen(vrt_proc *proc, uint64_t path_vaddr, uint32_t path_len);

/**
 * @brief STRCONV: convierte el StringObject @p src a la codificacion @p enc
 *        (StringEncoding).  Devuelve un GcHandle nuevo (o el mismo si ya esta
 *        en esa codificacion).  Equivale al opcode strconv (0x4A).
 */
vrt_handle vrt_str_conv(vrt_proc *proc, vrt_handle src, uint32_t enc);

/**
 * @brief  D.7.opt: registra un handle para un raw_ptr de objeto ya
 *        alocado por bump-pointer inline en JIT.
 *
 * El JIT-eated codigo emite el bump-pointer + init de @c GcHeader +
 * @c ObjectHeader inline.  Luego llama esta funcion para crear el
 * handle.  Solo hace @c handles_.push_back + @c PtrHandleMap.insert.
 * Coste medido: ~7 ns vs ~25 ns de @c vrt_newobj completo.
 *
 * @param proc ProcessVM cuyo gc_heap se actualiza.
 * @param raw  Puntero host al GcHeader (no al payload) del objeto
 *             recien alocado inline.
 * @return Handle creado.  El JIT generalmente lo descarta porque ya
 *         tiene el host_ptr; el handle se mantiene en la HandleTable
 *         para que @c ptr_to_handle_ + conservative scan funcionen.
 */
uint64_t vrt_register_alloc(vrt_proc *proc, uint8_t *raw);

/**
 * @brief Define una nueva clase via DefClassParams (defclass bytecode).
 *
 * Llama a @c ClassRegistry::define_class con los params en VM memory.
 * @return ClassInfo* recien creado (registrado en el registry).
 */
vrt_class *vrt_defclass(vrt_proc *proc, uint64_t params_vaddr);

/**
 * @brief añade un field a una clase (deffield bytecode).
 *
 * @return 1 si OK, 0 si fallo.
 */
int32_t vrt_deffield(vrt_proc *proc, vrt_class *cls, uint64_t params_vaddr);

/**
 * @brief añade un metodo a una clase (defmethod bytecode).
 *
 * @return vtable_index del metodo recien anadido, o UINT32_MAX si fallo.
 */
uint32_t vrt_defmethod(vrt_proc *proc, vrt_class *cls, uint64_t params_vaddr);

/**
 * @brief añade un advice a un metodo (addadvice bytecode).
 *
 * @return 1 si OK, 0 si fallo.
 */
int32_t vrt_addadvice(vrt_proc *proc, void *target_method, void *advice_method,
                      uint8_t kind);

/**
 * @brief Lookup de metodo por nombre dentro de clase (findmethod).
 *
 * @return MethodInfo* o nullptr.
 */
void *vrt_findmethod(vrt_proc *proc, uint64_t params_vaddr);

/**
 * @brief Lookup de field por nombre dentro de clase (findfield).
 *
 * @return FieldInfo* o nullptr.
 */
void *vrt_findfield(vrt_proc *proc, uint64_t params_vaddr);

/**
 * @brief Registra debug info (file:line) para un metodo (setmethdbg).
 *        Lee @c SetMethDebugParams de vm_mem[params_vaddr].
 */
void vrt_setmethdbg(vrt_proc *proc, uint64_t params_vaddr);

/* ========================================================================= */
/* String operations (Sprint JIT-cobertura 2026-06-01)                       */
/* ========================================================================= */

/**
 * @brief Lanza FatalError(USER_ABORT, msg) leyendo el mensaje de
 *        vm_mem.  Equivalente al opcode PANIC.
 *
 * @param proc      Proceso actual.
 * @param msg_vaddr Direccion VM del mensaje.
 * @param msg_len   Longitud en bytes (cap 511).
 */
void vrt_panic_str(vrt_proc *proc, uint64_t msg_vaddr, uint32_t msg_len);

/**
 * @brief Combinacion atomica GC_ALLOCP: alloc + deref + devuelve
 *        host_ptr al payload.  Mismo path que el opcode gcallocp.
 */
uint8_t *vrt_gc_alloc_payload(vrt_proc *proc, size_t size);

/**
 * @brief Crea un StringObject FLAT desde un buffer en memoria VM.
 *        Equivalente al opcode STRMAKE.  Autodetecta ASCII vs UTF-8.
 */
vrt_handle vrt_str_make(vrt_proc *proc, uint64_t vm_addr, uint32_t byte_len);

/**
 * @brief Crea un StringObject FLAT desde un buffer en memoria HOST
 *        (puntero crudo, no direccion VM).  Equivalente al opcode
 *        STRMAKE_H.  Usado por el path vreg del JIT cuando el buffer
 *        fuente es host (ALLOCA promovido) para evitar caer a slots.
 */
vrt_handle vrt_str_make_h(vrt_proc *proc, uint64_t host_addr,
                          uint32_t byte_len);

/** @brief Devuelve el numero de code-points del string. */
uint64_t vrt_str_len(vrt_proc *proc, vrt_handle h);

/** @brief Devuelve el byte_len del StringObject. */
uint64_t vrt_str_get_bytes(vrt_proc *proc, vrt_handle h);

/** @brief Devuelve host_ptr al buffer de bytes (materializa ROPE/SLICE). */
uint64_t vrt_str_raw(vrt_proc *proc, vrt_handle h);

/** @brief Concatena dos StringObjects en un ROPE O(1). */
vrt_handle vrt_str_cat(vrt_proc *proc, vrt_handle a, vrt_handle b);

/**
 * @brief STRSLICE: vista de una subcadena por puntos de codigo.
 * @param proc  Proceso propietario del heap.
 * @param src   Cadena de la que se toma la vista.
 * @param range (cp_start << 32) | cp_len.
 * @return Handle del SLICE (el padre si la vista lo abarca entero).
 */
vrt_handle vrt_str_slice(vrt_proc *proc, vrt_handle src, uint64_t range);

/** @brief Comparacion lexicografica.  Returns -1/0/1. */
int64_t vrt_str_cmp(vrt_proc *proc, vrt_handle a, vrt_handle b);

/* ========================================================================= */
/* Safepoint ( E - infrastructure stub)                                  */
/* ========================================================================= */

/**
 * @brief Check de safepoint: si el flag global esta activo, bloquea
 *        hasta que el GC complete su fase.
 *
 * Codigo JIT emite un @c vrt_safepoint_poll en cada loop back-edge y
 * cada call site para garantizar que el GC pueda pausar el thread en
 * tiempo limitado.  Coste fast path: ~2ns (cmp byte + jne).
 *
 * @note Stub en v1: la implementacion real llega en  E (D.2).
 *       Hoy es no-op para no romper builds.
 */
void vrt_safepoint_poll(vrt_proc *proc);

/**
 * @brief Handler de safepoint invocado por codigo JIT-eado cuando
 *        @c proc->safepoint_flag != 0.
 *
 * Es la rama lenta del poll.  El JIT emite:
 *
 *     cmp byte [rbx + 0], 0     ; safepoint_flag offset 0
 *     je   continue
 *     mov  rdi, rbx              ; (SysV) proc en rdi
 *     call vrt_safepoint_handler
 *   continue:
 *
 * Esta funcion:
 *   1. Captura RBP del thread (frame pointer).
 *   2. Marca el proceso como SAFEPOINT_ENTERED para que el GC sepa
 *      que esta thread esta pausado en un punto seguro.
 *   3. Wait sobre la condvar hasta que el GC termine y limpie el flag.
 *   4. Retorna; el codigo JIT continua su ejecucion normal.
 *
 * Cero overhead en fast path (flag=0).  Coste solo cuando el GC
 * realmente quiere pausar (typically 1 GC cycle de varios cientos
 * de microsegundos).
 *
 * @note En  D.2-foundation es stub: solo limpia el flag y retorna
 *       (sin coordinacion real con GC).  La integracion completa con
 *       gc_heap.cpp::major_gc llega en D.2-integration.
 */
void vrt_safepoint_handler(vrt_proc *proc);

/* ========================================================================= */
/* Introspeccion / debug                                                      */
/* ========================================================================= */

/** @brief Version actual de la API (para checks runtime). */
uint32_t vrt_api_version(void);

/** @brief Obtiene la VM owner del proceso. */
vrt_vm *vrt_proc_vm(vrt_proc *proc);

/** @brief Obtiene el PID encoded del proceso (scheduler_id<<32 | local_pid). */
uint64_t vrt_proc_pid(vrt_proc *proc);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VESTA_RT_PUBLIC_H */
