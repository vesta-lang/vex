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
/**                                                                            \
 * @file exec_instruction_gc.cpp                                               \
 * @brief Implementacion de las instrucciones de gestion de memoria del GC de  \
 * VestaVM.                                                                    \
 *                                                                             \
 * Implementa las instrucciones ALLOC, FREE, REALLOC, NEWOBJ, DROP, GCRUN,     \
 * GCWB, GCCONFIG, GCALLOC, GCDEREF y las operaciones de cursor (READCUR,      \
 * WRITECUR).                                                                  \
 */                                                                            \
#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/host_alloca_tracker.h"
#include "gc/gc_heap.h"
#include <cstdlib>
#include "gc/raw_allocator.h"
#include "loader/oop_types.h"
#include "util/simd_copy.h"
#include "runtime/profile.h"

namespace runtime {

// -------------------------------------------------------------------------
// Cursor - acceso a memoria real del host - opcodes 0x00 0xC0 .. 0xC2
// Los registros cursor (CUR0-CUR3) contienen punteros host directos.
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta la instruccion READCUR: lee de la memoria host apuntada por un
 * cursor.
 *
 * Obtiene la direccion host almacenada en el registro cursor indicado y lee
 * 1, 2, 4 u 8 bytes segun el modo codificado.  El resultado se almacena en
 * el registro general destino extendido a 64 bits.
 *
 * @param vm    Proceso virtual que ejecuta READCUR.
 * @param instr Instruccion descodificada con reg_data.reg2 (cursor) y
 * reg_data.reg1 (destino).
 */
void exec_instr_readcur(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cur_idx =
        instr.data_instruction.reg_data.reg2; // indice del cursor (0-3)
    const uint8_t dst =
        instr.data_instruction.reg_data.reg1; // registro general destino
    const uint64_t addr =
        vm->registers.cur[cur_idx].qword(); // puntero host del cursor

    // leer segun el modo: 8, 16, 32 o 64 bits
    switch (instr.flags_info.mode) {
    case 0b00:
        vm->registers.regs[dst].qword(*reinterpret_cast<const uint8_t *>(addr));
        break; //  8 bits
    case 0b01:
        vm->registers.regs[dst].qword(
            *reinterpret_cast<const uint16_t *>(addr));
        break; // 16 bits
    case 0b10:
        vm->registers.regs[dst].qword(
            *reinterpret_cast<const uint32_t *>(addr));
        break; // 32 bits
    default:
        vm->registers.regs[dst].qword(
            *reinterpret_cast<const uint64_t *>(addr));
        break; // 64 bits
    }
}

/**
 * @brief Ejecuta la instruccion WRITECUR: escribe en la memoria host apuntada
 * por un cursor.
 *
 * Obtiene la direccion host del cursor indicado y escribe el valor del registro
 * fuente truncado al tamano indicado por el modo (1, 2, 4 u 8 bytes).
 *
 * @param vm    Proceso virtual que ejecuta WRITECUR.
 * @param instr Instruccion descodificada con reg_data.reg2 (cursor) y
 * reg_data.reg1 (fuente).
 */
void exec_instr_writecur(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cur_idx =
        instr.data_instruction.reg_data.reg2; // indice del cursor (0-3)
    const uint8_t src =
        instr.data_instruction.reg_data.reg1; // registro general fuente
    const uint64_t addr =
        vm->registers.cur[cur_idx].qword(); // puntero host del cursor
    const uint64_t val = vm->registers.regs[src].qword(); // valor a escribir

    // escribir segun el modo: 8, 16, 32 o 64 bits
    switch (instr.flags_info.mode) {
    case 0b00:
        *reinterpret_cast<uint8_t *>(addr) = static_cast<uint8_t>(val);
        break; //  8 bits
    case 0b01:
        *reinterpret_cast<uint16_t *>(addr) = static_cast<uint16_t>(val);
        break; // 16 bits
    case 0b10:
        *reinterpret_cast<uint32_t *>(addr) = static_cast<uint32_t>(val);
        break;                                                 // 32 bits
    default: *reinterpret_cast<uint64_t *>(addr) = val; break; // 64 bits
    }
}

/**
 * @brief Ejecuta la instruccion GCDEREF: desreferencia un handle GC en un
 * cursor.
 *
 * Convierte el handle GC almacenado en el registro indicado en un puntero
 * host al payload del objeto y lo escribe en el registro cursor destino.
 * El cursor queda listo para accesos directos con READCUR/WRITECUR.
 *
 * @param vm    Proceso virtual que ejecuta GCDEREF.
 * @param instr Instruccion descodificada con reg_data.reg2 (cursor) y
 * reg_data.reg1 (handle).
 */
/**
 * @brief Ejecuta ADDCUR: suma un inmediato con signo al registro cursor curN.
 *
 * Lee el inmediato de 16 bits almacenado en los bytes 2-3 de raw_data.raw1
 * (colocado alli por decode_instr_addcur) y lo suma con extension de signo
 * al valor de 64 bits del cursor.  Permite avanzar (imm > 0) y retroceder
 * (imm < 0) sin el patron xchg/adds/xchg de tres instrucciones.
 *
 * @param vm    Proceso virtual que ejecuta ADDCUR.
 * @param instr Instruccion descodificada: reg2=cur_idx, raw1[2..3]=imm16.
 */
void exec_instr_addcur(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cur_idx =
        instr.data_instruction.reg_data.reg2 & 0x3; // cursor 0-3

    // recuperar imm16 de los bytes 2-3 de raw_data.raw1 (ver
    // decode_instr_addcur)
    const auto *raw = reinterpret_cast<const uint8_t *>(
        &instr.data_instruction.raw_data.raw1);
    const int16_t imm16 = static_cast<int16_t>(
        static_cast<uint16_t>(raw[2]) | (static_cast<uint16_t>(raw[3]) << 8));

    // sumar con extension de signo a 64 bits para que el retroceso funcione
    const uint64_t old_val = vm->registers.cur[cur_idx].qword();
    vm->registers.cur[cur_idx].qword(
        static_cast<uint64_t>(static_cast<int64_t>(old_val) + imm16));
}

/**
 * @brief Ejecuta VMCOPY: copia bytes desde VM memory a host memory (cursor).
 *
 * Lee rLen bytes desde VM memory a partir de la direccion virtual almacenada
 * en el registro rSrc y los escribe en la memoria host apuntada por curN.
 * Usa la funcion simd_copy::fast_copy para elegir en tiempo de ejecucion la
 * ruta SIMD mas rapida (AVX-512, AVX2, SSE2 o memcpy escalar).
 *
 * Tras la copia avanza automaticamente:
 *   - curN  += rLen  (cursor host apunta al byte siguiente al ultimo copiado)
 *   - rSrc  += rLen  (puntero VM avanza para copias secuenciales)
 *
 * @param vm    Proceso virtual que ejecuta VMCOPY.
 * @param instr Instruccion descodificada: mem_data.reg_final=cur_idx,
 *              mem_data.reg_base=rSrc, mem_data.reg_index=rLen.
 */
void exec_instr_vmcopy(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cur_idx =
        instr.data_instruction.mem_data.reg_final & 0x3; // cursor 0-3
    const uint8_t r_src =
        instr.data_instruction.mem_data.reg_base; // reg VM src
    const uint8_t r_len =
        instr.data_instruction.mem_data.reg_index; // reg longitud

    const uint64_t vm_addr = vm->registers.regs[r_src].qword(); // dir. virtual
    const uint64_t len = vm->registers.regs[r_len].qword(); // bytes a copiar
    uint8_t *const dst =
        reinterpret_cast<uint8_t *>(vm->registers.cur[cur_idx].qword());

    if (len == 0) return; // copia vacia: no modificar nada

    // leer bytes desde VM memory al buffer host apuntado por el cursor;
    // read_bytes maneja cruces de pagina y lazy allocation internamente
    // se usa un buffer temporal solo si dst no es valido, pero aqui dst es host
    // ptr
    vm->vm_mem.read_bytes(vm_addr, dst, static_cast<size_t>(len));

    // avanzar cursor host y puntero VM para facilitar copias secuenciales
    vm->registers.cur[cur_idx].qword(vm->registers.cur[cur_idx].qword() + len);
    vm->registers.regs[r_src].qword(vm_addr + len);
}

/**
 * @brief Ejecuta VCOPYH: copia bytes desde host memory (cursor) a VM memory.
 *
 * Inverso de VMCOPY: lee rLen bytes del buffer host apuntado por curN y los
 * escribe en VM memory a partir de la direccion virtual almacenada en rDst.
 * Avanza curN y rDst en rLen bytes tras la copia.
 *
 * @param vm    Proceso virtual que ejecuta VCOPYH.
 * @param instr Instruccion descodificada: mem_data.reg_final=cur_idx,
 *              mem_data.reg_base=rDst, mem_data.reg_index=rLen.
 */
void exec_instr_vcopyh(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cur_idx =
        instr.data_instruction.mem_data.reg_final & 0x3; // cursor 0-3
    const uint8_t r_dst =
        instr.data_instruction.mem_data.reg_base; // reg VM dst
    const uint8_t r_len =
        instr.data_instruction.mem_data.reg_index; // reg longitud

    const uint64_t vm_addr = vm->registers.regs[r_dst].qword(); // dir. virtual
    const uint64_t len = vm->registers.regs[r_len].qword(); // bytes a copiar
    const uint8_t *src =
        reinterpret_cast<const uint8_t *>(vm->registers.cur[cur_idx].qword());

    if (len == 0) return;

    // escribir desde host memory al espacio virtual de la VM
    vm->vm_mem.write_bytes(vm_addr, src, static_cast<size_t>(len));

    // avanzar cursor host y puntero VM
    vm->registers.cur[cur_idx].qword(vm->registers.cur[cur_idx].qword() + len);
    vm->registers.regs[r_dst].qword(vm_addr + len);
}

// -------------------------------------------------------------------------
// Consulta de entorno de ejecucion - opcodes 0x00 0xC6..0xC8
// Exponen punteros del entorno como uint64_t para pasarlos a funciones
// nativas via calln sin modificar la convencion de llamada existente.
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta GETPROC: carga el puntero al ProcessVM actual en el registro
 * destino.
 */
void exec_instr_getproc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst =
        instr.data_instruction.reg_data.reg1; // registro destino
    vm->registers.regs[rdst].qword(reinterpret_cast<uint64_t>(vm));
}

/**
 * @brief Ejecuta GETVM: carga el puntero a la instancia VM propietaria en el
 * registro destino.
 */
void exec_instr_getvm(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.reg_data.reg1;
    // sigue la cadena: proceso -> scheduler -> vm_reference (VM&)
    vm->registers.regs[rdst].qword(
        reinterpret_cast<uint64_t>(&vm->scheduler.vm_reference));
}

/**
 * @brief Ejecuta GETMGR: carga el puntero al ManageVM del gestor en el registro
 * destino.
 */
void exec_instr_getmgr(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.reg_data.reg1;
    // sigue la cadena: proceso -> scheduler -> vm_reference -> mgr_vm
    // (ManageVM&)
    vm->registers.regs[rdst].qword(
        reinterpret_cast<uint64_t>(&vm->scheduler.vm_reference.mgr_vm));
}

void exec_instr_gcderef(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t cur_idx =
        instr.data_instruction.reg_data.reg2; // cursor destino (0-3)
    const uint8_t handle_reg =
        instr.data_instruction.reg_data.reg1; // registro con el handle GC
    const uint64_t raw_handle =
        vm->registers.regs[handle_reg].qword(); // valor del handle

    // desreferenciar el handle para obtener el puntero host al payload
    uint8_t *payload = vm->gc_heap.deref(static_cast<gc::GcHandle>(raw_handle));
    vm->registers.cur[cur_idx].qword(
        reinterpret_cast<uint64_t>(payload)); // guardar puntero en cursor
}

/**
 * @brief Devuelve el PID encoded del proceso actual en r_dst.
 *
 * Formato: (scheduler_id << 32) | (local_pid & 0xFFFFFFFF).  Mismo
 * encoding que SPAWN deposita en R0 al crear un hijo.  Util para
 * que el proceso pueda enviarse a si mismo via mailbox o registrar
 * su PID en estructuras compartidas.
 */
void exec_instr_getpid(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint64_t encoded =
        (static_cast<uint64_t>(vm->pid.scheduler_id) << 32) |
        static_cast<uint64_t>(vm->pid.local_pid & 0xFFFFFFFFu);
    vm->registers.regs[r_dst].qword(encoded);
}

/**
 * @brief Inverso de GCDEREF: dado un puntero host al payload, devuelve el
 * GcHandle.
 *
 * Lee el host_ptr del registro reg2 (operando 2: source) y consulta el mapa
 * inverso del GcHeap.  Escribe el resultado (GcHandle uint32, o GC_NULL_HANDLE
 * si el puntero no corresponde a un objeto vivo) en reg1 (operando 1: dest).
 */
void exec_instr_gchandle(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1; // dest reg
    const uint8_t r_src =
        instr.data_instruction.reg_data.reg2; // src reg con host_ptr
    const auto ptr_val =
        static_cast<uintptr_t>(vm->registers.regs[r_src].qword());
    const auto *payload = reinterpret_cast<const uint8_t *>(ptr_val);
    // handle_for_ptr es O(1): mira ptr_to_handle_ local + lee
    // ObjectHeader.hash_code (lleva SHARED_HANDLE_BIT | shared_idx
    // para objetos del SharedHeap, escrito por newobjs/gcpromote).
    gc::GcHandle h = vm->gc_heap.handle_for_ptr(payload);
    vm->registers.regs[r_dst].qword(
        static_cast<uint64_t>(h)); // GC_NULL_HANDLE si no encontrado
}

/**
 * @brief Ejecuta MVTAKE: copia qword src->dst y zerifica src.
 *
 * Primitivo de move ownership para smart pointers.  En 1 instr VM
 * realiza la secuencia que de otra forma requeriria 4 instrucciones
 * (LOAD + STORE + CONST 0 + STORE).  El compilador host puede
 * inlinarlo a 3 instrucciones x86-64 (mov rax,[src]; mov [dst],rax;
 * mov qword [src],0) cuando el JIT lo recoja.
 */
void exec_instr_mvtake(ProcessVM *vm, const DecodedInstr &instr) {
    // reg1 = r_dst_addr (destino), reg2 = r_src_addr (fuente)
    const uint8_t r_dst = instr.data_instruction.reg_data.reg1;
    const uint8_t r_src = instr.data_instruction.reg_data.reg2;
    const uint64_t dst_addr = vm->registers.regs[r_dst].qword();
    const uint64_t src_addr = vm->registers.regs[r_src].qword();

    // Si las direcciones coinciden, mvtake equivale a zerificar el slot.
    // Aprovechamos un load + dos stores (LD + ST dst + ST 0 src).
    // No usamos atomic por diseno: move es siempre intra-thread.
    const uint64_t tmp = vm->vm_mem.read_u64(src_addr);
    vm->vm_mem.write_u64(dst_addr, tmp);
    // Si dst == src, este store final deja el slot a cero (semantica
    // correcta para move-to-self: el ownership "vuelve a si mismo"
    // pero el slot original queda invalidado).
    vm->vm_mem.write_u64(src_addr, 0ULL);
}

/**
 * @brief Registra el host_ptr en r_ptr para cleanup automatico
 * cuando el frame actual se destruye (RET / do_throw / TAILCALL).
 *
 * Sprint MMM-ext leak-fix (opcode 0x7E, FIXED_4).  Emitido por el
 * bytecode emit del interp tras un `alloc` cuyo IR ALLOCA lleva
 * flag `host_alloca=true`.  Si no hay frame activo (codigo
 * top-level), el ptr queda sin tracking y debe liberarse
 * manualmente (caso raro).
 *
 * encoding: [0x00][0x7E][byte2][0x00], byte2 = (r_ptr<<4) | 0.
 * El decode_instr_two_op_reg pone reg1=r_ptr.
 */
void exec_instr_htrack(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_ptr = instr.data_instruction.reg_data.reg1;
    const uint64_t ptr = vm->registers.regs[r_ptr].qword();
    if (vm->frame_stack != nullptr && ptr != 0) {
        host_alloca_track(vm->frame_stack, reinterpret_cast<uint8_t *>(ptr));
    }
}

/**
 * @brief GCFINAL r_box, kind (opcode 0x7F, FIXED_4): registra un finalizador
 *        GC para el box (objeto GC con recurso interno) en r_box.
 *
 * Marca el bit @c has_finalizer + @c finalizer_kind en el GcHeader del objeto.
 * Cuando el sweep del GC colecte el box (WHITE, inalcanzable), correra su
 * finalizador (el deleter/dtor customizable) en el safe point post-collect.
 * Lo emite el lowering de @c gc_box(unique_with(...)/shared(...)) tras el
 * GC_ALLOCP, y el cleanup determinista de scope (caso no-escape) lo desregistra
 * con kind=0 para evitar doble-free.
 *
 * encoding: [0x00][0x7F][0x00][n2], n2 = (kind<<4) | r_box.
 * decode_instr_two_op_reg: reg1 = r_box, reg2 = kind.
 */
void exec_instr_gcfinal(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_box = instr.data_instruction.reg_data.reg1;
    const uint8_t kind = instr.data_instruction.reg_data.reg2;
    const uint64_t box = vm->registers.regs[r_box].qword();
    if (box == 0) return;
    auto *payload = reinterpret_cast<uint8_t *>(box);
    if (kind == 0) {
        // Desregistrar (anti-doble-free desde el cleanup determinista).
        vm->gc_heap.unregister_finalizer(payload);
    } else {
        vm->gc_heap.register_finalizer(payload,
                                       static_cast<gc::GcFinalizerKind>(kind));
    }
}

/**
 * @brief GCFINALC r_box, r_dtor (opcode 0x8D, FIXED_4): registra un finalizador
 *        CLASS_DTOR para el objeto GC gc<Clase> con ~Clase() en r_box.
 *
 * A diferencia de @c gcfinal (UNIQUE/SHARED, cuyo deleter vive DENTRO del box),
 * un gc<Clase> es la instancia misma y el vaddr del dtor concreto no viaja
 * inline -> se pasa en @c r_dtor (dispatch ESTATICO: el lowering resuelve
 * <Clase>____dtor en compile-time, CALL directo, sin vtable).  El finalizador,
 * cuando el sweep colecte el objeto, invoca dtor(obj_host_ptr) por bytecode
 * reentrante (portable en interp).
 *
 * encoding: [0x00][0x8D][0x00][n2], n2 = (r_dtor<<4)|r_box.
 * decode_instr_two_op_reg: reg1 = r_box (nibble bajo), reg2 = r_dtor (alto).
 */
void exec_instr_gcfinalc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_box = instr.data_instruction.reg_data.reg1;
    const uint8_t r_dtor = instr.data_instruction.reg_data.reg2;
    const uint64_t box = vm->registers.regs[r_box].qword();
    if (box == 0) return;
    const uint64_t dtor_vaddr = vm->registers.regs[r_dtor].qword();
    auto *payload = reinterpret_cast<uint8_t *>(box);
    /* A QUIEN se llama al finalizar lo dicen los dos bits altos del byte de
     * control: el destructor de la clase, o el liberador de un `unique`.  El
     * cero es el destructor porque es lo que ese byte significaba cuando no se
     * usaba, asi que el bytecode anterior sigue diciendo lo mismo. */
    const gc::GcFinalizerKind kind = (instr.flags_info.mode == 1)
                                         ? gc::GcFinalizerKind::UNIQUE
                                         : gc::GcFinalizerKind::CLASS_DTOR;
    vm->gc_heap.register_finalizer(payload, kind, dtor_vaddr);
}

/**
 * @brief GCCOLLECT (opcode 0x8C, ZERO, FIXED_2): fuerza un ciclo de GC del
 *        proceso (minor + major) + drena finalizadores.
 *
 * Builtin Vesta @c gc_collect().  Util para pruebas de finalizacion (observar
 * el finalizador de un objeto que escapo y murio sin esperar a la presion de
 * memoria) y para liberacion deterministica de recursos GC cuando el programa
 * lo desea explicitamente.  Los finalizadores encolados por el sweep se
 * ejecutan en el safe point dentro de minor_gc/major_gc (reentrada al interp).
 */
void exec_instr_gccollect(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;
    vm->gc_heap.minor_gc(); // evacua/mata YOUNG; puede encadenar major_gc
    vm->gc_heap.major_gc(); // barre OLD (colecta boxes escapados y muertos)
    // NO se drenan los finalizadores aqui: el scheduler los drena en un safe
    // point tras avanzar el PC (la instruccion decodificada `d` ya no se usa),
    // evitando que el re-decode del deleter corrompa la instruccion en curso.
}

/**
 * @brief GCFINALL (opcode 0x8E, ZERO, FIXED_2): finaliza TODO objeto GC vivo
 *        con recurso interno (deleter/dtor).  Builtin Vesta gc_finalize_all().
 *
 * A diferencia de gccollect (que solo finaliza lo INALCANZABLE), este stagea el
 * finalizador de CADA objeto vivo con has_finalizer y lo drena.  Determinista:
 * no depende del scan de raices -> observa la finalizacion de objetos escapados
 * sin polling ni interferencia de host_ptrs residuales en regs/slots.  El
 * drenado (reentrada al interp para el deleter/dtor) lo hace el scheduler en un
 * safe point tras avanzar el PC (igual que gccollect); stage_finalizer limpia
 * el bit has_finalizer -> idempotente (nunca doble-free).
 */
void exec_instr_gcfinall(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;
    // Stagea los finalizadores de todos los objetos vivos con recurso interno.
    vm->gc_heap.stage_all_live_finalizers();
    // Drenar SINCRONAMENTE (reentrada al interp para cada deleter/dtor).  A
    // diferencia de gccollect (cuyo drenado difiere al safe point del scheduler
    // para no interferir con el flujo normal), gc_finalize_all es un builtin
    // EXPLICITO del usuario cuyo efecto (el recurso liberado) debe ser visible
    // en la siguiente instruccion (p.ej. `return contador`).  El reentry es
    // seguro aqui: gcfinall es ZERO (sin operandos que preservar) y
    // gc_finalizer_call_bytecode salva/restaura TODO el estado del proceso +
    // invalida el icache al volver (mismo mecanismo probado del drenado del
    // scheduler).  El avance del PC de gcfinall lo hace el caller tras
    // retornar.
    vm->gc_heap.run_pending_finalizers();
}

// -------------------------------------------------------------------------
// GC generacional - opcodes 0x00 0xA0 .. 0xA5
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta la instruccion NEWOBJ: aloca un objeto gestionado por el GC.
 *
 * Lee el puntero a ClassInfo del registro indicado y aloca instance_size bytes
 * en el heap GC.  Si la aloca tiene exito, inicializa el ObjectHeader con el
 * puntero a la clase, el flag GC_OWNED y el handle como hash inicial.
 * El handle resultante (o GC_NULL_HANDLE en caso de fallo) se escribe en R00.
 *
 * @param vm    Proceso virtual que ejecuta NEWOBJ.
 * @param instr Instruccion descodificada con reg_data.reg1 (registro con
 * ClassInfo*).
 */
void exec_instr_newobj(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data
                              .reg1; // registro con el puntero ClassInfo
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());

    // Sprint D.6 (2026-06-03): alloc count para escape analysis en C2.
    if (__builtin_expect(
            profile::g_profile.active.load(std::memory_order_relaxed), 0)) {
        profile::profile_newobj(vm->registers.rip.raw());
    }

    if (cls == nullptr) {
        // clase nula: devolver handle invalido
        vm->registers.regs[R00].qword(
            static_cast<uint64_t>(gc::GC_NULL_HANDLE));
        return;
    }

    gc::GcHandle h = vm->gc_heap.alloc(
        static_cast<size_t>(cls->instance_size)); // alocar en el heap GC

    if (h != gc::GC_NULL_HANDLE) {
        uint8_t *payload =
            vm->gc_heap.deref(h); // obtener puntero host al payload
        if (payload != nullptr) {
            auto *hdr = reinterpret_cast<loader::ObjectHeader *>(payload);
            hdr->class_ptr = cls; // enlazar la clase
            hdr->flags =
                loader::OBJ_FLAG_GC_OWNED; // marcar como gestionado por GC
            hdr->hash_code =
                static_cast<uint32_t>(h); // usar el handle como hash inicial
        }
    }

    vm->registers.regs[R00].qword(
        static_cast<uint64_t>(h)); // devolver el handle en R00
    // Los finalizadores stageados por un GC de este alloc se drenan en el safe
    // point del scheduler (tras avanzar el PC), no aqui.
}

// B4.3: NEWOBJS r_cls -> aloca en SharedHeap ( Z.6).
//
// Variante shared del NEWOBJ: instead of vm->gc_heap, aloca via
// vm_reference.shared_heap (cross-process).  Registra el host_ptr
// en shared_handle_table y escribe el handle (con SHARED_HANDLE_BIT)
// en ObjectHeader.hash_code para que el reverse lookup de gchandle
// sea O(1) (single atomic load del header).  Cero overhead extra
// vs el path local: el coste es 1 alloc + 1 register + 1 init.
void exec_instr_newobjs(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_cls = instr.data_instruction.reg_data.reg1;
    auto *cls = reinterpret_cast<loader::ClassInfo *>(
        vm->registers.regs[r_cls].qword());
    if (cls == nullptr) {
        vm->registers.regs[R00].qword(
            static_cast<uint64_t>(gc::GC_NULL_HANDLE));
        return;
    }

    auto &vmr = vm->scheduler.vm_reference;
    const uint32_t sz = cls->instance_size;
    uint8_t *payload = vmr.shared_heap.alloc(static_cast<size_t>(sz));
    if (!payload) {
        // OOM en SharedHeap -- devolver handle invalido.
        vm->registers.regs[R00].qword(
            static_cast<uint64_t>(gc::GC_NULL_HANDLE));
        return;
    }

    // Registrar en SharedHandleTable (lock-free CAS).  El handle
    // devuelto YA lleva SHARED_HANDLE_BIT (bit 31).
    const uint32_t sh = vmr.shared_handle_table.register_object(payload, sz);
    if (sh == 0) {
        // tabla llena -- liberar payload y devolver invalido.
        vmr.shared_heap.free(payload);
        vm->registers.regs[R00].qword(
            static_cast<uint64_t>(gc::GC_NULL_HANDLE));
        return;
    }

    // Inicializar ObjectHeader.  Placement-new construye el atomic
    // monitor_word a 0 (libre).  hash_code = handle (con bit 31)
    // permite que handle_for_ptr (en gc_heap) lo recupere O(1) con
    // un single load del header -- lock-free total.
    auto *hdr = new (payload) loader::ObjectHeader();
    hdr->class_ptr = cls;
    hdr->flags = loader::OBJ_FLAG_GC_OWNED;
    hdr->hash_code = sh; // SHARED_HANDLE_BIT | shared_idx

    // newobjs convention: devolver el HANDLE (con SHARED_HANDLE_BIT).
    // El frontend lowering hace gcderef post-newobjs para obtener
    // el host_ptr.  Simetrico a newobj que devuelve el local handle.
    vm->registers.regs[R00].qword(static_cast<uint64_t>(sh));
}

/**
 * @brief Ejecuta la instruccion GCRUN: lanza un ciclo de GC menor.
 *
 * Fuerza la recoleccion de basura de la generacion joven.  Puede llamarse
 * desde bytecode para controlar la presion de memoria en puntos conocidos.
 *
 * @param vm    Proceso virtual que ejecuta GCRUN.
 * @param instr Instruccion descodificada (no se usan sus campos).
 */
void exec_instr_gcrun(ProcessVM *vm, const DecodedInstr &instr) {
    (void)instr;            // instruccion sin operandos
    vm->gc_heap.minor_gc(); // ejecutar el GC menor
}

/**
 * @brief Ejecuta la instruccion GCCONFIG: configura el umbral de promocion del
 * GC.
 *
 * Lee el valor del umbral desde el registro fuente segun el modo y llama a
 * set_old_threshold() para ajustar el limite de bytes tras el cual los objetos
 * se promueven a la generacion antigua.
 *
 * @param vm    Proceso virtual que ejecuta GCCONFIG.
 * @param instr Instruccion descodificada con reg_data.reg1 (fuente) y mode.
 */
void exec_instr_gcconfig(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rsrc =
        instr.data_instruction.reg_data.reg1; // registro con el nuevo umbral
    const uint64_t threshold =
        read_reg_table[instr.flags_info.mode](vm, rsrc); // leer segun modo
    vm->gc_heap.set_old_threshold(
        static_cast<size_t>(threshold)); // aplicar la configuracion
}

/**
 * @brief Ejecuta la instruccion GCDROP: libera un objeto del heap GC por
 * handle.
 *
 * Decrementa el contador de referencias o libera el objeto segun la politica
 * del GC.  El handle se lee del registro fuente segun el modo.
 *
 * @param vm    Proceso virtual que ejecuta GCDROP.
 * @param instr Instruccion descodificada con reg_data.reg1 (fuente) y mode.
 */
void exec_instr_gc_drop(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rsrc = instr.data_instruction.reg_data
                             .reg1; // registro con el handle a liberar
    const uint64_t handle = read_reg_table[instr.flags_info.mode](vm, rsrc);
    vm->gc_heap.drop(
        static_cast<gc::GcHandle>(handle)); // liberar el handle en el GC
}

/**
 * @brief Ejecuta la instruccion GCWB: notifica al GC una escritura (write
 * barrier).
 *
 * Debe llamarse antes de sobrescribir un puntero GC para que el GC pueda
 * mantener la consistencia de sus estructuras de rastreo generacional.
 *
 * @param vm    Proceso virtual que ejecuta GCWB.
 * @param instr Instruccion descodificada con reg_data.reg1 (fuente) y mode.
 */
void exec_instr_gcwb(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rsrc =
        instr.data_instruction.reg_data.reg1; // registro con el handle antiguo
    const uint64_t old_handle = read_reg_table[instr.flags_info.mode](vm, rsrc);
    vm->gc_heap.write_barrier(
        static_cast<gc::GcHandle>(old_handle)); // notificar la escritura al GC
}

/**
 * @brief Ejecuta la instruccion GCALLOC: aloca un bloque de bytes en el heap
 * GC.
 *
 * A diferencia de NEWOBJ, no inicializa ninguna cabecera de objeto.  Util para
 * alocar buffers o arreglos gestionados por el GC.  El handle resultante se
 * devuelve en R00.
 *
 * @param vm    Proceso virtual que ejecuta GCALLOC.
 * @param instr Instruccion descodificada con reg_data.reg1 (tamano) y mode.
 */
void exec_instr_gcalloc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rsrc =
        instr.data_instruction.reg_data.reg1; // registro con el tamano en bytes
    const uint64_t size = read_reg_table[instr.flags_info.mode](vm, rsrc);

    gc::GcHandle h =
        vm->gc_heap.alloc(static_cast<size_t>(size)); // alocar en el heap GC
    vm->registers.regs[R00].qword(
        static_cast<uint64_t>(h)); // devolver el handle en R00
}

// -------------------------------------------------------------------------
// Raw allocator - opcodes 0x00 0xB0 .. 0xB2
// Memoria no gestionada por el GC; ciclo de vida manual.
// -------------------------------------------------------------------------

/**
 * @brief Ejecuta la instruccion RAWALLOC: aloca memoria bruta no gestionada por
 * el GC.
 *
 * El tamano se obtiene del registro fuente segun el modo.  El puntero host
 * al bloque alocalizado se escribe en R00 (0 si falla).
 *
 * @param vm    Proceso virtual que ejecuta RAWALLOC.
 * @param instr Instruccion descodificada con reg_data.reg1 (tamano) y mode.
 */
void exec_instr_raw_alloc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rsrc =
        instr.data_instruction.reg_data.reg1; // registro con el tamano
    const uint64_t size = read_reg_table[instr.flags_info.mode](vm, rsrc);

    /* El asignador del PROGRAMA, si lo hay.
     *
     * La instruccion sigue siendo la misma -- este es el mecanismo del
     * interprete y es lo portable --, pero el monton tiene que ser UNO: si el
     * codigo compilado reserva por un sitio y esta instruccion por otro, un
     * bloque acaba pidiendose por un camino y soltandose por el otro, y eso no
     * falla donde se comete.
     *
     * Cuando no lo hay -- un programa que no trae ninguno, o lo que se reserve
     * antes de que este compilado -- se queda el propio, que es el respaldo. */
    if (vm->alloc_del_programa != 0) {
        vm->registers.regs[R01].qword(size); // convencion de llamada de la VM
        auto fn = reinterpret_cast<uint64_t (*)(void *)>(
            static_cast<uintptr_t>(vm->alloc_del_programa));
        fn(vm);
        return; // deja el puntero en R00, como el resto de llamadas
    }
    uint64_t ptr =
        vm->raw_alloc.alloc(static_cast<size_t>(size)); // alocar bloque
    vm->registers.regs[R00].qword(ptr); // devolver puntero host en R00
}

/**
 * @brief Ejecuta la instruccion RAWFREE: libera un bloque de memoria bruta.
 *
 * El registro fuente contiene el puntero host al bloque previamente alocalizado
 * con RAWALLOC o RAWREALLOC.
 *
 * @param vm    Proceso virtual que ejecuta RAWFREE.
 * @param instr Instruccion descodificada con reg_data.reg1 (puntero a liberar).
 */
void exec_instr_raw_free(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rsrc = instr.data_instruction.reg_data
                             .reg1; // registro con el puntero a liberar
    const uint64_t ptr = vm->registers.regs[rsrc].qword();
    // Quien reserva, libera: por el mismo sitio que @ref exec_instr_raw_alloc.
    if (vm->free_del_programa != 0) {
        vm->registers.regs[R01].qword(ptr);
        auto fn = reinterpret_cast<uint64_t (*)(void *)>(
            static_cast<uintptr_t>(vm->free_del_programa));
        fn(vm);
        return;
    }
    vm->raw_alloc.free(ptr); // liberar el bloque
}

/**
 * @brief Ejecuta la instruccion RAWREALLOC: redimensiona un bloque de memoria
 * bruta.
 *
 * Lee el puntero actual del primer registro y el nuevo tamano del segundo.
 * El puntero al bloque redimensionado (que puede diferir del original) se
 * devuelve en R00.
 *
 * @param vm    Proceso virtual que ejecuta RAWREALLOC.
 * @param instr Instruccion descodificada con reg_data.reg1 (ptr) y
 * reg_data.reg2 (size).
 */
void exec_instr_raw_realloc(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rptr = instr.data_instruction.reg_data
                             .reg1; // registro con el puntero original
    const uint8_t rsize =
        instr.data_instruction.reg_data.reg2; // registro con el nuevo tamano
    const uint64_t ptr =
        vm->registers.regs[rptr].qword(); // puntero al bloque original
    const uint64_t size =
        vm->registers.regs[rsize].qword(); // nuevo tamano en bytes

    uint64_t new_ptr =
        vm->raw_alloc.realloc(ptr, static_cast<size_t>(size)); // redimensionar
    vm->registers.regs[R00].qword(new_ptr); // devolver el nuevo puntero en R00
}

// =========================================================================
//   Z - gcpromote / gcdemote: deep-copy local <-> SharedHeap.
// =========================================================================
//
// El host_ptr en el registro apunta al payload (ObjectHeader + fields).
// El @c GcHeader precede al payload por 8 bytes y lleva el tamano total
// del slot.  Para identificar si un objeto es shared, marcamos
// @c ObjectHeader::hash_code con el bit 31 (@c SHARED_HANDLE_BIT).
//
// Promote (local -> shared):
//   1. Lee tamano del GcHeader del src
//   2. Aloca slot en @c vm.shared_heap.alloc(size)
//   3. Copia bytes desde src.payload al nuevo slot
//   4. Registra en @c shared_handle_table.register_object(new_ptr, size)
//   5. Setea bit 31 en hash_code del nuevo header
//   6. r_dst = new_host_ptr
//
// Demote (shared -> local):
//   1. Aloca slot en @c gc_heap del proceso actual
//   2. Copia bytes
//   3. Limpia bit 31 en hash_code
//   4. r_dst = new_host_ptr

void exec_instr_gcpromote(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.reg_data.reg1;
    const uint8_t rsrc = instr.data_instruction.reg_data.reg2;
    const uint64_t src = vm->registers.regs[rsrc].qword();
    if (src == 0) {
        vm->registers.regs[rdst].qword(0);
        return;
    }
    // Si ya es shared (bit 31 en hash_code), idempotente.
    auto *src_hdr = reinterpret_cast<loader::ObjectHeader *>(src);
    if (src_hdr->hash_code & 0x80000000u) {
        vm->registers.regs[rdst].qword(src);
        return;
    }
    // El GcHeader precede al payload por 8 bytes (no usado aqui --
    // estimacion conservadora del tamano via class_ptr si esta presente).
    // Para v1 usamos un tamano fijo de ObjectHeader + N campos heuristico.
    // Mejora futura: leer GcHeader.size para tamano exacto.
    // Tamano conservador: ObjectHeader (24) + class->total_field_size si
    // class_ptr no es null, sino 64 bytes como default.
    size_t total_size = 64;
    if (src_hdr->class_ptr) {
        total_size = src_hdr->class_ptr->instance_size;
    }
    if (total_size < sizeof(loader::ObjectHeader))
        total_size = sizeof(loader::ObjectHeader);

    auto &shared = vm->scheduler.vm_reference.shared_heap;
    uint8_t *new_ptr = shared.alloc(total_size);
    if (!new_ptr) {
        // OOM en SharedHeap: devolver src sin promote (degradado).
        vm->registers.regs[rdst].qword(src);
        return;
    }
    std::memcpy(new_ptr, reinterpret_cast<void *>(src), total_size);
    // Marcar el nuevo header como shared (bit 31 en hash_code).
    auto *new_hdr = reinterpret_cast<loader::ObjectHeader *>(new_ptr);
    new_hdr->hash_code |= 0x80000000u;
    // Registrar en SharedHandleTable.
    vm->scheduler.vm_reference.shared_handle_table.register_object(
        new_ptr, static_cast<uint32_t>(total_size));
    vm->registers.regs[rdst].qword(reinterpret_cast<uint64_t>(new_ptr));
}

void exec_instr_gcdemote(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.reg_data.reg1;
    const uint8_t rsrc = instr.data_instruction.reg_data.reg2;
    const uint64_t src = vm->registers.regs[rsrc].qword();
    if (src == 0) {
        vm->registers.regs[rdst].qword(0);
        return;
    }
    auto *src_hdr = reinterpret_cast<loader::ObjectHeader *>(src);
    // Si no es shared, idempotente.
    if (!(src_hdr->hash_code & 0x80000000u)) {
        vm->registers.regs[rdst].qword(src);
        return;
    }
    size_t total_size = 64;
    if (src_hdr->class_ptr) {
        total_size = src_hdr->class_ptr->instance_size;
    }
    if (total_size < sizeof(loader::ObjectHeader))
        total_size = sizeof(loader::ObjectHeader);
    // Alocar en gc_heap local.  Usamos alloc_pinned para que el sweep
    // local no lo mueva (igual semantica que strings).
    gc::GcHandle h = vm->gc_heap.alloc_pinned(total_size);
    if (h == gc::GC_NULL_HANDLE) {
        vm->registers.regs[rdst].qword(src);
        return;
    }
    uint8_t *new_ptr = vm->gc_heap.deref(h);
    std::memcpy(new_ptr, reinterpret_cast<void *>(src), total_size);
    // Limpiar bit shared.
    auto *new_hdr = reinterpret_cast<loader::ObjectHeader *>(new_ptr);
    new_hdr->hash_code &= 0x7FFFFFFFu;
    vm->registers.regs[rdst].qword(reinterpret_cast<uint64_t>(new_ptr));
}

// =========================================================================
//   Z - Atomics i64 reales sobre host memory.
// =========================================================================
//
// Implementacion sobre memoria HOST (raw pointers).  Los registros llevan
// direcciones host (uint64_t reinterpret_cast'eadas).  Usamos los
// intrinsics @c __atomic_* de GCC/Clang con memory_order seq_cst para
// simplicidad y correctness; un orden mas relajado por op se anadira
// cuando el frontend exponga el parametro de ordering.

// ATOMICLD r_dst, r_addr : r_dst = atomic_load_i64(*(int64_t*)r_addr).
void exec_instr_atomicld(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.reg_data.reg1;
    const uint8_t raddr = instr.data_instruction.reg_data.reg2;
    const uint64_t addr = vm->registers.regs[raddr].qword();
    if (addr == 0) {
        vm->registers.regs[rdst].qword(0);
        return;
    }
    // Ancho del atomico (flags_info.mode: 0=8b 1=16b 2=32b 3=64b).  El load
    // alineado ya es atomico; se zero-extiende al registro de 64b (el frontend
    // sign-extiende si el tipo lo requiere, como loadz).
    uint64_t val = 0;
    switch (instr.flags_info.mode) {
    case 0:
        val = __atomic_load_n(reinterpret_cast<uint8_t *>(addr),
                              __ATOMIC_SEQ_CST);
        break;
    case 1:
        val = __atomic_load_n(reinterpret_cast<uint16_t *>(addr),
                              __ATOMIC_SEQ_CST);
        break;
    case 2:
        val = __atomic_load_n(reinterpret_cast<uint32_t *>(addr),
                              __ATOMIC_SEQ_CST);
        break;
    default:
        val = __atomic_load_n(reinterpret_cast<uint64_t *>(addr),
                              __ATOMIC_SEQ_CST);
        break;
    }
    vm->registers.regs[rdst].qword(val);
}

// ATOMICST r_addr, r_val : atomic_store_i64(*r_addr, r_val).
void exec_instr_atomicst(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t raddr = instr.data_instruction.reg_data.reg1;
    const uint8_t rval = instr.data_instruction.reg_data.reg2;
    const uint64_t addr = vm->registers.regs[raddr].qword();
    if (addr == 0) return;
    const uint64_t val = vm->registers.regs[rval].qword();
    switch (instr.flags_info.mode) { // ancho 8/16/32/64
    case 0:
        __atomic_store_n(reinterpret_cast<uint8_t *>(addr),
                         static_cast<uint8_t>(val), __ATOMIC_SEQ_CST);
        break;
    case 1:
        __atomic_store_n(reinterpret_cast<uint16_t *>(addr),
                         static_cast<uint16_t>(val), __ATOMIC_SEQ_CST);
        break;
    case 2:
        __atomic_store_n(reinterpret_cast<uint32_t *>(addr),
                         static_cast<uint32_t>(val), __ATOMIC_SEQ_CST);
        break;
    default:
        __atomic_store_n(reinterpret_cast<uint64_t *>(addr), val,
                         __ATOMIC_SEQ_CST);
        break;
    }
}

// ATOMICADD r_dst, r_addr, r_delta : r_dst = atomic_fetch_add_i64.
// CSEL r_dst, r_cond, r_a, r_b : dst = (cond != 0) ? a : b  (1 despacho).
// Super-instruccion del IrOp::SELECT para el interp dispatch-bound; evita la
// mascara branchless (~8 ops).  El JIT/AOT bajan el mismo SELECT a cmov.
void exec_instr_csel(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.mem_data.reg_base;
    const uint8_t rcond = instr.data_instruction.mem_data.reg_index;
    const uint8_t ra = instr.data_instruction.mem_data.reg_final;
    const uint8_t rb = instr.data_instruction.mem_data.scale;
    const uint64_t v = (vm->registers.regs[rcond].qword() != 0)
                           ? vm->registers.regs[ra].qword()
                           : vm->registers.regs[rb].qword();
    vm->registers.regs[rdst].qword(v);
}

void exec_instr_atomicadd(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.mem_data.reg_base;
    const uint8_t raddr = instr.data_instruction.mem_data.reg_index;
    const uint8_t rdelta = instr.data_instruction.mem_data.reg_final;
    const uint64_t addr = vm->registers.regs[raddr].qword();
    if (addr == 0) {
        vm->registers.regs[rdst].qword(0);
        return;
    }
    const uint64_t delta = vm->registers.regs[rdelta].qword();
    uint64_t old = 0; // valor ANTERIOR (zero-extendido al reg de 64b)
    switch (instr.flags_info.mode) { // ancho 8/16/32/64
    case 0:
        old = __atomic_fetch_add(reinterpret_cast<uint8_t *>(addr),
                                 static_cast<uint8_t>(delta), __ATOMIC_SEQ_CST);
        break;
    case 1:
        old =
            __atomic_fetch_add(reinterpret_cast<uint16_t *>(addr),
                               static_cast<uint16_t>(delta), __ATOMIC_SEQ_CST);
        break;
    case 2:
        old =
            __atomic_fetch_add(reinterpret_cast<uint32_t *>(addr),
                               static_cast<uint32_t>(delta), __ATOMIC_SEQ_CST);
        break;
    default:
        old = __atomic_fetch_add(reinterpret_cast<uint64_t *>(addr), delta,
                                 __ATOMIC_SEQ_CST);
        break;
    }
    vm->registers.regs[rdst].qword(old);
}

// ATOMICCAS r_dst, r_addr, r_exp, r_des :
//   compare_exchange_strong(*addr, &exp, des).  Devuelve el valor que
//   estaba en *addr ANTES de la operacion (sea hit o miss del CAS).
//   Si quieres saber si el CAS tuvo exito, comparar r_dst con r_exp.
void exec_instr_atomiccas(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.mem_data.reg_base;
    const uint8_t raddr = instr.data_instruction.mem_data.reg_index;
    const uint8_t rexp = instr.data_instruction.mem_data.reg_final;
    const uint8_t rdes = instr.data_instruction.mem_data.scale;
    const uint64_t addr = vm->registers.regs[raddr].qword();
    if (addr == 0) {
        vm->registers.regs[rdst].qword(0);
        return;
    }
    const uint64_t expected = vm->registers.regs[rexp].qword();
    const uint64_t desired = vm->registers.regs[rdes].qword();
    uint64_t prev = 0; // valor que estaba en *addr ANTES (zero-extendido)
    switch (instr.flags_info.mode) { // ancho 8/16/32/64
    case 0: {
        uint8_t e = static_cast<uint8_t>(expected);
        __atomic_compare_exchange_n(reinterpret_cast<uint8_t *>(addr), &e,
                                    static_cast<uint8_t>(desired), false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        prev = e;
        break;
    }
    case 1: {
        uint16_t e = static_cast<uint16_t>(expected);
        __atomic_compare_exchange_n(reinterpret_cast<uint16_t *>(addr), &e,
                                    static_cast<uint16_t>(desired), false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        prev = e;
        break;
    }
    case 2: {
        uint32_t e = static_cast<uint32_t>(expected);
        __atomic_compare_exchange_n(reinterpret_cast<uint32_t *>(addr), &e,
                                    static_cast<uint32_t>(desired), false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        prev = e;
        break;
    }
    default: {
        uint64_t e = expected;
        __atomic_compare_exchange_n(reinterpret_cast<uint64_t *>(addr), &e,
                                    desired, false, __ATOMIC_SEQ_CST,
                                    __ATOMIC_SEQ_CST);
        prev = e;
        break;
    }
    }
    vm->registers.regs[rdst].qword(prev);
}

// SHAREDSTAT r_dst, r_op : introspeccion del SharedHeap.
//   r_op == 0 -> r_dst = live_count (SharedHandleTable)
//   r_op == 1 -> r_dst = total_allocated_bytes
//   r_op == 2 -> r_dst = shared_gc_collect (slots barridos)
//
// Codigos alineados con la convencion del lowering Vesta
// (shared_heap_live_count/bytes/gc_collect en lower_call).
void exec_instr_sharedstat(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t rdst = instr.data_instruction.reg_data.reg1;
    const uint8_t rop = instr.data_instruction.reg_data.reg2;
    const uint64_t op = vm->registers.regs[rop].qword();
    auto &vmr = vm->scheduler.vm_reference;
    uint64_t result = 0;
    switch (op) {
    case 0:
        result = static_cast<uint64_t>(vmr.shared_handle_table.live_count());
        break;
    case 1: result = vmr.shared_heap.total_allocated_bytes(); break;
    case 2: result = vmr.shared_gc_collect(); break;
    default: result = 0; break;
    }
    vm->registers.regs[rdst].qword(result);
}

} // namespace runtime
