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
 * @file exec_instruction_distrib.cpp
 * @brief Ejecutores de instrucciones de programacion distribuida.
 *
 * Implementa las 4 instrucciones distribuidas del conjunto extendido:
 *
 *   0x3B  rspawn   r_fn, r_node   -> R0 = GcHandle de FutureObject
 *   0x3C  msgsend  r_pid, r_addr, r_len
 *   0x3D  msgrecv  r_buf, r_max   -> R0 = bytes recibidos
 *   0x3E  memsync  r_params
 *
 * Todas las operaciones remotas se delegan al DistRuntime del VM propietario,
 * accesible via vm->scheduler.vm_reference.dist_runtime.
 *
 * Encoding FIXED_4 de las instrucciones:
 *   rspawn:  [0x00][0x3B][ctrl: (mode<<6)][regs: (r_node<<4)|r_fn]
 *   msgsend: [0x00][0x3C][(r_pid<<4)|r_addr][(r_len<<4)]
 *   msgrecv: [0x00][0x3D][ctrl: (mode<<6)][regs: (r_max<<4)|r_buf]
 *   memsync: [0x00][0x3E][ctrl: (mode<<6)][r_params]
 */

#include "runtime/exec_instruction.h"
#include "runtime/proceso_runtime.h"
#include "runtime/scheduler.h"
#include "runtime/runtime.h"
#include "distrib/dist_runtime.h"
#include "distrib/mailbox.h"
#include "loader/loader.h"  // Loader::load_module_dynamic
#include "debug/debugger.h" // Debugger::on_message hook (tracing)
#include <fstream>          // leer archivo .velb del filesystem
#include <iterator>         // istreambuf_iterator

namespace runtime {

// =========================================================================
//  0x3B  RSPAWN  r_fn, r_node  ->  R0 = GcHandle del FutureObject
// =========================================================================

/**
 * @brief Ejecuta la instruccion RSPAWN.
 *
 * Crea un proceso en el nodo remoto indicado por r_node y retorna
 * un FutureObject GC cuyo resultado sera el PID remoto del proceso.
 *
 * El proceso se bloquea implicitamente si usa AWAIT sobre el future.
 * Si el nodo no esta conectado o la sesion no esta activa, R0 = 0xFFFFFFFF.
 *
 * @param vm    Proceso que ejecuta la instruccion.
 * @param instr reg1 = r_fn (dir virtual del bytecode), reg2 = r_node (indice en
 * NodeRegistry).
 */
void exec_instr_rspawn(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_fn =
        instr.data_instruction.reg_data.reg1; // registro con fn_addr
    const uint8_t r_node =
        instr.data_instruction.reg_data.reg2; // registro con node_idx

    const uint64_t fn_addr = vm->registers.regs[r_fn].qword();
    const uint32_t node_idx =
        static_cast<uint32_t>(vm->registers.regs[r_node].qword());

    distrib::DistRuntime *dr = vm->scheduler.vm_reference.dist_runtime.get();
    if (!dr) {
        vm->registers.regs[0].qword(0xFFFFFFFF); // R0 = handle invalido
        return;
    }

    uint32_t handle = dr->rspawn(vm, fn_addr, node_idx);
    vm->registers.regs[0].qword(
        static_cast<uint64_t>(handle)); // R0 = GcHandle del future
}

// =========================================================================
//  0x59  LOADMOD  r_path_addr, r_path_len   (carga dinamica de .velb)
// =========================================================================

/**
 * @brief Ejecuta la instruccion LOADMOD: carga dinamica de un .velb.
 *
 * Lee `path_len` bytes desde `vm_mem[path_addr]` (string utf-8 con la ruta
 * al archivo .velb), abre el archivo, llama a `Loader::load_module_dynamic`
 * y deja en R0:
 *   - 0 si el archivo no existe, esta vacio o el parse falla.
 *   - init_pc del modulo cargado (>0) en exito.
 *
 * NO ejecuta automaticamente el modulo: el caller (la builtin Vesta
 * `loadmodule`) usa `callvmr r0` para invocar el main del nuevo modulo,
 * cuyo prologo ejecuta `__module_init` y registra las clases en el
 * ClassRegistry global de la VM.
 *
 * @param vm    Proceso virtual que invoca la carga.
 * @param instr reg1 = registro con direccion VM del buffer del path,
 *              reg2 = registro con longitud en bytes del path.
 */
void exec_instr_loadmod(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_path_addr = instr.data_instruction.reg_data.reg1;
    const uint8_t r_path_len = instr.data_instruction.reg_data.reg2;
    const uint64_t path_addr = vm->registers.regs[r_path_addr].qword();
    const uint64_t path_len = vm->registers.regs[r_path_len].qword();

    // Validacion basica del path.  Limitamos a un tamano razonable para
    // evitar lecturas de buffer arbitrariamente grandes (PATH_MAX en
    // Windows es ~260, en POSIX 4096; ponemos 8192 con margen).
    if (path_len == 0 || path_len > 8192) {
        vm->registers.regs[0].qword(0);
        return;
    }

    std::vector<uint8_t> path_bytes(path_len);
    vm->vm_mem.read_bytes(path_addr, path_bytes.data(),
                          static_cast<size_t>(path_len));
    std::string path(reinterpret_cast<const char *>(path_bytes.data()),
                     static_cast<size_t>(path_len));

    // Leer el archivo .velb completo desde el filesystem del host.
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        vm->registers.regs[0].qword(0); // file not found
        return;
    }
    std::vector<uint8_t> file_bytes((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    if (file_bytes.empty()) {
        vm->registers.regs[0].qword(0);
        return;
    }

    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    const uint64_t init_pc =
        vm_ref.loader_public.load_module_dynamic(vm_ref, std::move(file_bytes));
    // Tras un load exitoso, registrar el source_path en el Executable que
    // acaba de anadirse (sera el ultimo del pool).  Permite que
    // unloadmodule(path) lo localice por path mas tarde.  Si load fallo
    // (init_pc==0), no hay nada que patchar.
    if (init_pc != 0 && !vm_ref.loader_public.executables.empty() &&
        vm_ref.loader_public.executables.back()) {
        vm_ref.loader_public.executables.back()->source_path = path;
    }

    // NOTE: el init_pc puede legitimamente ser 0 (start del code section).
    // No usamos 0 como sentinela de error: el sentinela es file-not-found
    // (manejado arriba) o parse-failure (load_module_dynamic devolveria 0
    // pero tampoco anadiria al pool, asi que distinguimos por el comportamiento
    // del callvm posterior).  Por simplicidad de la API: si
    // @c load_module_dynamic devuelve 0 asumimos failure, ya que el caso
    // "init_pc legitimo == 0" se solapa con el code section del caller
    // (limitacion documentada de la asignacion de VA fija).
    if (init_pc == 0) {
        vm->registers.regs[0].qword(0); // failure
        return;
    }

    // Convencion CALLVM: empujar la direccion de retorno (PC tras esta
    // instruccion) en la pila y saltar al init_pc del modulo cargado.  El
    // main del nuevo modulo termina con RET, lo que pop'eara la direccion
    // y el flujo continuara despues del loadmod.  Su prologo invoca
    // __module_init (que registra clases via defclass/deffield/defmethod),
    // por lo que tras el RET las clases del modulo estaran disponibles via
    // findclass.  Dejamos R0 = init_pc como indicador de exito antes del
    // salto; el main cargado puede sobrescribirlo si quiere devolver algo
    // al caller.
    const uint64_t ret_addr =
        vm->registers.rip.raw() + vm->decoded_ptr->flags_info.size_instr;
    const uint64_t new_sp = vm->registers.stack_pointer.qword() - 8;
    vm->registers.stack_pointer.qword(new_sp);
    vm->vm_mem.write_bytes(new_sp, &ret_addr, 8);
    vm->registers.rip.qword(init_pc);
    vm->decoded_ptr->flags_info.did_jump = true;
    vm->registers.regs[0].qword(
        init_pc); // success indicator (puede ser sobrescrito)
    // BugFix M.dyn (2026-06-05): guardar init_pc en la pila de retorno.  El
    // __module_init del plugin clobbea R0 (su ultimo op deja un valor
    // arbitrario; en un reload, el defclass idempotente sobre una clase ya
    // registrada NO necesariamente deja un non-zero en R0).  Restauramos R0
    // = init_pc cuando el HLT del plugin se intercepta como RET, para que
    // `loadmodule` devuelva un indicador de exito FIABLE.
    vm->loadmod_r0_stack.push_back(init_pc);
    // Incrementar contador para que el HLT del main del plugin se trate
    // como RET (ver exec_instr_hlt + ProcessVM::loadmod_call_depth).
    // Esto reemplaza el viejo `patch_first_hlt_to_ret` que escaneaba bytes
    // y podia false-match con imm de mov/callvm que contengan 0x00 0x03.
    vm->loadmod_call_depth += 1;
}

// =========================================================================
//  0x6D  UNLOADMOD  r_path_addr, r_path_len   (descarga modulo dinamico)
// =========================================================================

/**
 * @brief Ejecuta UNLOADMOD: descarga un modulo cargado dinamicamente.
 *
 * Lee el path del .velb (mismo formato que loadmod) desde memoria VM,
 * y delega en `Loader::unload_module_dynamic(path)`.  Deposita 1 en r_dst
 * (R0 por convencion) si se descargo, 0 si no se encontro.
 *
 * IMPORTANTE: las clases registradas por el modulo permanecen en
 * ClassRegistry (sus ClassInfo* podrian estar referenciados por instancias
 * vivas).  La memoria del bytecode SI se libera.  Para un "reload" efectivo
 * el usuario debe versionar el nombre de la clase (e.g. ExtV1 -> ExtV2).
 *
 * Encoding FIXED_4: [0x00][0x6D][regs][0x00] con
 * regs=(r_path_len<<4)|r_path_addr (mismo formato que loadmod).
 */
void exec_instr_unloadmod(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_path_addr = instr.data_instruction.reg_data.reg1;
    const uint8_t r_path_len = instr.data_instruction.reg_data.reg2;
    const uint64_t path_addr = vm->registers.regs[r_path_addr].qword();
    const uint64_t path_len = vm->registers.regs[r_path_len].qword();

    if (path_len == 0 || path_len > 8192) {
        vm->registers.regs[0].qword(0);
        return;
    }

    std::vector<uint8_t> path_bytes(path_len);
    vm->vm_mem.read_bytes(path_addr, path_bytes.data(),
                          static_cast<size_t>(path_len));
    std::string path(reinterpret_cast<const char *>(path_bytes.data()),
                     static_cast<size_t>(path_len));

    runtime::VM &vm_ref = vm->scheduler.vm_reference;
    const bool ok = vm_ref.loader_public.unload_module_dynamic(vm_ref, path);
    vm->registers.regs[0].qword(ok ? 1 : 0);
}

// =========================================================================
//  0x3C  MSGSEND  r_pid, r_addr, r_len
// =========================================================================

/**
 * @brief Ejecuta la instruccion MSGSEND.
 *
 * Envia un mensaje al proceso indicado por r_pid.
 * El PID puede ser local (bit 63 = 0) o remoto (bit 63 = 1).
 * El mensaje se copia desde la memoria VM del proceso emisor.
 *
 * Para PIDs remotos, el envio es at-least-once: se almacena hasta recibir ACK.
 *
 * Encoding de r_pid:
 *   - Local:  bits 31-0 = local_pid (usa scheduler_id=0 para busqueda global)
 *   - Remoto: bit63=1, bits 62-32 = node_idx, bits 31-0 = remote_local_pid
 *             Construir con vdp_make_remote_pid(node_idx, local_pid) desde
 * bytecode.
 *
 * @param vm    Proceso emisor.
 * @param instr mem_data.reg_base=r_pid, mem_data.reg_index=r_addr,
 * mem_data.reg_final=r_len.
 */
void exec_instr_msgsend(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_pid =
        instr.data_instruction.mem_data.reg_base; // PID del destino
    const uint8_t r_addr =
        instr.data_instruction.mem_data.reg_index; // dir del buffer
    const uint8_t r_len =
        instr.data_instruction.mem_data.reg_final; // longitud en bytes

    const uint64_t target_pid = vm->registers.regs[r_pid].qword();
    const uint64_t vm_addr = vm->registers.regs[r_addr].qword();
    const uint64_t len = vm->registers.regs[r_len].qword();

    distrib::DistRuntime *dr = vm->scheduler.vm_reference.dist_runtime.get();
    if (!dr) {
        vm->registers.regs[0].qword(0); // R0 = 0 si no hay runtime distribuido
        return;
    }

    bool ok = dr->msgsend(vm, target_pid, vm_addr, len);
    vm->registers.regs[0].qword(
        ok ? 1 : 0); // R0 = 1 si enviado/encolado, 0 si error
    // Hook del debugger: tracing de mensajes (sin overhead si no hay tracing).
    if (vm->scheduler.vm_reference.debugger) {
        uint64_t payload64 = 0;
        if (len >= 8) vm->vm_mem.read_bytes(vm_addr, &payload64, 8);
        vm->scheduler.vm_reference.debugger->on_message(vm->pid.local_pid, true,
                                                        target_pid, payload64);
    }
}

// =========================================================================
//  0x3D  MSGRECV  r_buf, r_max_len  ->  R0 = bytes recibidos
// =========================================================================

/**
 * @brief Ejecuta la instruccion MSGRECV.
 *
 * Extrae el primer mensaje del buzon del proceso y lo copia al buffer
 * VM apuntado por r_buf (hasta r_max_len bytes).
 *
 * Si el buzon esta vacio: bloquea el proceso (EVT_IO_WAIT) sin avanzar el PC.
 * El proceso se re-ejecutara desde MSGRECV cuando llegue un mensaje.
 * R0 = bytes copiados (0 si el proceso quedo bloqueado).
 *
 * @param vm    Proceso receptor.
 * @param instr reg1 = r_buf (dir del buffer destino), reg2 = r_max_len.
 */
void exec_instr_msgrecv(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_buf =
        instr.data_instruction.reg_data.reg1; // buffer destino
    const uint8_t r_max = instr.data_instruction.reg_data.reg2; // tamano maximo

    const uint64_t buf_addr = vm->registers.regs[r_buf].qword();
    const uint64_t max_len = vm->registers.regs[r_max].qword();

    distrib::DistRuntime *dr = vm->scheduler.vm_reference.dist_runtime.get();
    if (!dr) {
        vm->registers.regs[0].qword(0);
        return;
    }

    // intentar obtener el mailbox sin crear uno si no existe
    distrib::Mailbox *mb = dr->get_or_create_mailbox(vm);

    if (mb->empty()) {
        // buzon vacio: bloquear el proceso en WAIT_IO para que sea despertado
        // por msgsend cuando llegue un mensaje. El PC no avanza (blocking =
        // true) hace que MSGRECV se re-ejecute en el proximo quantum de este
        // proceso.
        vm->decoded_ptr->flags_info.blocking = true;
        vm->scheduler.on_event(EVT_IO_WAIT); // transicion a WAIT_IO
        vm->registers.regs[0].qword(0);      // R0 = 0 mientras espera
        return;
    }

    uint64_t bytes = dr->msgrecv(vm, buf_addr, max_len);
    vm->registers.regs[0].qword(bytes); // R0 = bytes copiados al buffer
    // Hook del debugger: tracing de mensajes recibidos.
    if (vm->scheduler.vm_reference.debugger) {
        uint64_t payload64 = 0;
        if (bytes >= 8) vm->vm_mem.read_bytes(buf_addr, &payload64, 8);
        vm->scheduler.vm_reference.debugger->on_message(vm->pid.local_pid,
                                                        false, 0, payload64);
    }
    // CRITICO: si la primera llamada a msgrecv (icache miss) seteo
    // blocking=true por mailbox vacio, ese flag queda CACHEADO en la entrada
    // del icache. En la re-ejecucion (post-wake) decode_instruction devuelve
    // cache HIT con el blocking=true viejo; tras leer el mensaje DEBEMOS
    // limpiar el flag para que execute_instruction devuelva EVT_EXEC_DONE y el
    // scheduler continue al siguiente opcode (avanzando el PC).  Sin esto el
    // proceso queda en bucle: msgrecv -> blocking=true sticky -> WAIT_IO de
    // nuevo
    // -> nadie lo despierta -> deadlock.
    vm->decoded_ptr->flags_info.blocking = false;
}

// =========================================================================
//  0x3E  MEMSYNC  r_params
// =========================================================================

/**
 * @brief Ejecuta la instruccion MEMSYNC.
 *
 * Lee la estructura MemsyncParams desde la memoria VM apuntada por r_params,
 * detecta las paginas modificadas de la region indicada y las sincroniza con
 * el nodo remoto usando el protocolo MEMSYNC_HASH/DIFF/DATA/ACK.
 *
 * Algoritmo de deteccion de cambios (3 niveles):
 *   1. Adler-32: filtro rapido por pagina (~1 ns/pagina intacta)
 *   2. BLAKE2s-256: verificacion fuerte (solo para paginas con Adler-32
 * diferente)
 *   3. Transmision: solo las paginas donde BLAKE2s difiere del baseline
 *
 * En esta implementacion v1 la sincronizacion es siempre asincrona.
 * El future_handle en MemsyncParams (si != 0) se resuelve al completar.
 *
 * Layout de MemsyncParams (leido desde VM memory via r_params):
 *   +0   uint64_t local_addr     dir virtual local de inicio
 *   +8   uint64_t len            tamano de la region en bytes
 *   +16  uint32_t node_idx       indice del nodo destino en NodeRegistry
 *   +20  uint32_t _pad
 *   +24  uint64_t remote_addr    dir en el nodo destino
 *   +32  uint32_t future_handle  GcHandle del future a resolver (0=ignorar)
 *   +36  uint32_t _pad2
 *
 * @param vm    Proceso que ejecuta la instruccion.
 * @param instr reg1 = r_params (dir de MemsyncParams en VM memory).
 */
void exec_instr_memsync(ProcessVM *vm, const DecodedInstr &instr) {
    const uint8_t r_params = instr.data_instruction.reg_data.reg1;
    const uint64_t params_addr = vm->registers.regs[r_params].qword();

    distrib::DistRuntime *dr = vm->scheduler.vm_reference.dist_runtime.get();
    if (!dr) return;

    dr->memsync(vm, params_addr);
    // la instruccion no produce un valor de retorno directo;
    // el future_handle dentro de MemsyncParams se resuelve de forma asincrona
}

} // namespace runtime
