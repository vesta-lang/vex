/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/vm_standalone.h
 * @brief Montar un proceso que se pueda EJECUTAR A MANO, fuera del scheduler.
 *
 * Por que existe
 * --------------
 * Tres tests distintos -- `test_icache_real`, `test_bundles` y
 * `test_efectos_opcodes` -- necesitan lo mismo: un `ProcessVM` cargado sobre el
 * que ejecutar instrucciones una a una sin arrancar el planificador.  Los tres
 * lo montaron por su cuenta y los tres fueron descubriendo, a base de
 * reventones, las MISMAS piezas que el interprete da por hechas.  Estan aqui de
 * una vez.
 *
 * Lo que hay que poner, y que pasa si falta
 * -----------------------------------------
 *   - `make_ready`      -- sin esto el proceso no esta en la FSM.
 *   - `scheduler.instance` -- `Scheduler::on_event` lee `instance->state`, asi
 *     que un opcode que senale un error del programa (una division por cero,
 *     por ejemplo) revienta AL NOTIFICARLO, no al fallar.  Con puntero basura:
 *     `this = 0x54c`.
 *   - la ranura por hilo del proceso en ejecucion -- `av_recovery_stub` la
 *     consulta con `get_current_executing_process()` y hace `abort()` si no la
 *     encuentra.  Sin ella `av_recovery_active` esta puesto pero nadie lo mira,
 *     y el arnes de recuperacion no sirve de nada.
 *   - `state = EXECUTE` -- lo hace tambien `ComptimeVM`, que es el otro sitio
 *     del proyecto que ejecuta bytecode fuera del scheduler.
 *
 * El JIT se apaga a proposito: `VESTA_JIT_THRESHOLD` no basta porque el loader
 * compila `main` en eager por un camino que no lo mira, y `g_pc_jit_active` es
 * lo que impide que `callvm` despache al nativo.  Sin esto se mediria el JIT
 * creyendo medir el interprete.
 */

#ifndef VESTA_TESTS_VM_STANDALONE_H
#define VESTA_TESTS_VM_STANDALONE_H

#include <string>
#include <vector>

#include "emmit/parser_to_bytecode.h"
#include "jit/auto_jit.h"
#include "jit/interp_jit_bridge.h"
#include "lexer/lexer.h"
#include "linker/velb_linker_bytecode.h"
#include "parser/parser.h"
#include "runtime/manager_runtime.h"
#include "bytecode/bytecode.h"
#include "runtime/proceso_runtime.h"

namespace tests {

/**
 * @brief Un proceso listo para ejecutarse a mano.
 *
 * Mantiene viva la `ManageVM`: destruirla se lleva el proceso por delante, y
 * mas de un test se dejo eso y obtuvo lecturas de memoria liberada.
 */
struct VmStandalone {
    runtime::ManageVM manager{nullptr, 0};
    runtime::VM *vm = nullptr;
    runtime::ProcessVM *proc = nullptr;
    std::string error;

    bool ok() const { return proc != nullptr; }
};

/**
 * @brief Carga un `.velb` y deja el proceso listo para ejecutarlo a mano.
 *
 * @param path      Fichero a cargar.
 * @param pure_interp  Apaga el JIT.  Por defecto SI: cualquier medida del
 *                     interprete es mentira sin esto.
 */
inline void vm_standalone_open(VmStandalone &s, const std::string &path,
                               bool pure_interp = true) {
    if (pure_interp) {
        jit::g_jit_threshold = UINT32_MAX;
        jit::g_pc_jit_active = false;
    }

    s.vm = s.manager.loader.create_vm_instance(1);
    try {
        s.proc = s.manager.loader.load_executable(*s.vm, path);
    } catch (const std::exception &e) {
        s.error = e.what();
        s.proc = nullptr;
        return;
    }
    if (s.proc == nullptr) {
        s.error = "load_executable devolvio nullptr";
        return;
    }

    // Las cuatro piezas que el interprete da por hechas.  Ver la cabecera del
    // fichero para que pasa si falta cada una.
    s.vm->make_ready(s.proc->pid);
    s.proc->scheduler.instance = s.proc;
    jit::runtime_set_current_executing_process_c(
        reinterpret_cast<vrt_proc *>(s.proc));
    s.proc->state.store(runtime::EXECUTE, std::memory_order_relaxed);
}

/**
 * @brief El programa mas pequeno que produce un proceso ENTERO.
 *
 * No se ejecuta: existe para que el loader deje un `ProcessVM` completo -- con
 * su memoria, su pila y su monton -- sobre el que trabajar.  Un proceso a
 * medias hace fallar a cualquier cosa que toque memoria.
 *
 * Esta aqui, y no en un `.velb` de fuera, porque un test que depende de un
 * fichero que hay que acordarse de generar y de pasarle no es auto contenido.
 * Y tampoco es un blob incrustado: se compila con el formato del dia.
 */
inline const char *PROGRAMA_MINIMO = "@Format(\"raw\")\n"
                                     "@SpaceAddress {\n"
                                     "    @Name(\"anonymous\"),\n"
                                     "    @IniAddress(0x0000000000000000),\n"
                                     "    @EndAddress(0xFFFFFFFFFFFFFFFF)\n"
                                     "}\n"
                                     "@Section {\n"
                                     "    @Name(\"all\"),\n"
                                     "    @SpaceAddress(\"anonymous\")\n"
                                     "    @Align(0x1000)\n"
                                     "}\n"
                                     "code:\n"
                                     "    hlt\n"
                                     "end_code:\n";

/**
 * @brief Igual, pero desde CODIGO FUENTE: sin fichero y sin tocar el disco.
 *
 * Un test que necesita un `.velb` de fuera no es un test, es un test mas un
 * fichero que hay que acordarse de generar y de pasarle.  Y los tres que usan
 * este arnes no quieren un programa concreto: quieren un proceso ENTERO -- con
 * su monton, sus registros y su memoria -- sobre el que ejecutar instrucciones
 * a mano.
 *
 * La cadena entera existe ya en el proyecto y es toda en memoria: `Lexer` ->
 * `Parser` -> `Assembler` -> `Linker::build_executable()` devuelve los bytes, y
 * `load_executable` tiene sobrecarga que los toma.  Nada de ficheros
 * temporales, y el bytecode se regenera con el formato del dia -- no es un
 * blob incrustado que se pudre cuando el formato cambia.
 */
inline void vm_standalone_build(VmStandalone &s, const std::string &source,
                                bool pure_interp = true) {
    if (pure_interp) {
        jit::g_jit_threshold = UINT32_MAX;
        jit::g_pc_jit_active = false;
    }

    std::vector<uint8_t> executable;
    try {
        vm::Lexer lexer(source);
        vm::Parser parser(lexer);
        std::vector<std::unique_ptr<vm::ASTNode>> program = parser.parse();

        Assembly::Bytecode::Assembler asmblr;
        std::vector<uint8_t> bytecode = asmblr.assemble(program);

        namespace lk = Assembly::Bytecode::Linker;
        lk::LinkerOptions opts;
        opts.optimize_bytecode = false;
        opts.generate_map_file = false;
        opts.verbose = false;
        lk::Linker linker(opts);
        linker.add_assembly_unit(bytecode, &asmblr.ctx);
        executable = linker.build_executable();
    } catch (const std::exception &e) {
        s.error = std::string("compilando el programa de apoyo: ") + e.what();
        s.proc = nullptr;
        return;
    }

    s.vm = s.manager.loader.create_vm_instance(1);
    try {
        s.proc = s.manager.loader.load_executable(*s.vm, std::move(executable));
    } catch (const std::exception &e) {
        s.error = e.what();
        s.proc = nullptr;
        return;
    }
    if (s.proc == nullptr) {
        s.error = "load_executable devolvio nullptr";
        return;
    }

    s.vm->make_ready(s.proc->pid);
    s.proc->scheduler.instance = s.proc;
    jit::runtime_set_current_executing_process_c(
        reinterpret_cast<vrt_proc *>(s.proc));
    s.proc->state.store(runtime::EXECUTE, std::memory_order_relaxed);
}


/**
 * @brief Ejecuta el proceso a mano hasta que pare o gaste @p cap despachos.
 *
 * El mismo ciclo que el run_loop: buscar en icache, descodificar si falla,
 * ejecutar.  No mide tiempo ni compara registros -- para eso esta
 * `test_bundles`, que necesita las dos cosas --; aqui solo hace falta que el
 * programa CORRA, para que se formen los paquetes que luego se analizan.
 *
 * `hlt` se cuenta pero no se ejecuta: su manejador vacia los finalizadores del
 * GC y avisa al scheduler, y aqui no hay scheduler corriendo.
 *
 * @return Despachos realizados.
 */
inline uint64_t vm_standalone_run(runtime::ProcessVM *proc, uint64_t cap) {
    uint64_t dispatches = 0;
    proc->scheduler.has_hooks = false;
    while (proc->state != runtime::HALT && proc->state != runtime::DEAD &&
           proc->err_thread == runtime::THREAD_NO_ERROR && dispatches < cap) {
        const uint64_t pc = proc->registers.rip.raw();
        runtime::DecodedInstr *cached = runtime::icache_lookup(proc, pc);
        if (cached != nullptr && proc->decoded_ptr != nullptr)
            proc->decoded_ptr = cached;
        else
            runtime::decode_instruction(proc);
        if (proc->decoded_ptr == nullptr) break;

        if (proc->decoded_ptr->flags_info.is_not_extended == 0x00 &&
            proc->decoded_ptr->flags_info.opcode_index ==
                static_cast<uint16_t>(bytecode::Opcodes::HLT)) {
            ++dispatches;
            break;
        }
        /* El presupuesto de reducciones lo repone el run_loop al cerrar el
         * lote.  Sin imitarlo, el desenrollado de un paquete se queda sin
         * credito a las ~680 vueltas y no vuelve a dispararse. */
        if (proc->reductions_remaining <= 1)
            proc->reductions_remaining = reductions_remaining_default;
        --proc->reductions_remaining;

        const runtime::vm_event ev = runtime::execute_instruction(proc);
        ++dispatches;
        if (ev == runtime::EVT_HALT || ev == runtime::EVT_ERROR ||
            ev == runtime::EVT_IO_WAIT)
            break;
    }
    return dispatches;
}
} // namespace tests

#endif // VESTA_TESTS_VM_STANDALONE_H
