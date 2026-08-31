/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/runtime/test_bundles.cpp
 * @brief Valida los paquetes de instrucciones: que NO cambian el resultado, y
 *        cuantos despachos ahorran.
 *
 * Que valida
 * ----------
 * Ejecuta cada `.velb` DOS veces en el mismo binario -- con los paquetes
 * apagados y encendidos -- y exige que las dos corridas coincidan en:
 *   - el numero de instrucciones de VM ejecutadas,
 *   - el `rip` donde acaban,
 *   - los 16 registros generales.
 *
 * Un paquete que se salte una instruccion, la ejecute dos veces o deje `rip`
 * mal, rompe alguna de las tres.  Es el fallo mas probable de este diseno,
 * porque el manejador tiene que reproducir a mano el avance de `rip` que hace
 * el run_loop -- incluido el caso de que una instruccion de dentro salte o se
 * bloquee.
 *
 * Que mide
 * --------
 * Con `VM_BUNDLE_STATS=1` publica cuantos paquetes se formaron, cuantos
 * despachos se ahorraron y cuantos se abandonaron a mitad.  El ahorro de
 * despachos es la cifra que dice si esto sirve para algo: cada instruccion de
 * mas dentro de un paquete es un salto indirecto que el interprete no hizo.
 *
 * La telemetria NO altera lo que mide: los incrementos solo existen con la
 * bandera puesta, y sin ella el codigo generado es el mismo.  Para verla hay
 * que construir con `-DVM_BUNDLE_STATS=1`; sin eso el test valida igual pero
 * los contadores salen a cero.
 *
 * Por que conduce el interprete a mano
 * ------------------------------------
 * Porque el JIT no se puede apagar desde fuera: el loader compila `main` en
 * eager por un camino que no mira `VESTA_JIT_THRESHOLD`, asi que ejecutar por
 * la CLI mediria el nativo.  Aqui se apaga desde dentro del proceso.
 *
 * Uso:
 *   test_bundles <fichero.velb> [mas.velb ...] [--tope N]
 */

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "bytecode/bytecode.h"
#include "jit/auto_jit.h"
#include "runtime/bundle.h"
#include "runtime/decode_instruction.h"
#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "runtime/vm_registers.h"
#include "runtime/exception_runtime.h" // build_stack_trace
#include "util/fnv.h"

#include <csignal>
#include <cstdlib>

namespace {

constexpr uint64_t kDefaultCap = 20ull * 1000 * 1000;

/// Lo que tiene que salir igual con y sin paquetes.
struct Result {
    uint64_t vm_instrs = 0; ///< instrucciones de VM, no despachos
    uint64_t final_rip = 0;
    uint64_t regs[16] = {};
    bool ok = false;
    /// Si se corto por el tope en vez de terminar el programa.  Importa: un
    /// paquete ejecuta k instrucciones de golpe, asi que puede pasarse del tope
    /// por hasta k-1 y acabar una instruccion mas alla que la corrida sin
    /// paquetes.  Comparar `rip` y registros entre dos corridas cortadas en
    /// puntos distintos no significa nada.
    bool capped = false;
    const char *why = "";

    /* --- Tiempo -------------------------------------------------------------
     *
     * `time_exec` y `time_decode` son los acumuladores que la propia VM lleva
     * cuando `has_hooks` esta puesto -- lo que hace el depurador al engancharse
     * --, y miden SOLO la region de ejecucion y la de descodificacion.  Las
     * llamadas a los hooks quedan FUERA de esas marcas, asi que activarlos no
     * contamina la medida aunque encarezca la corrida.
     *
     * `wall_ns` es el bucle entero de este arnes: incluye la busqueda en icache
     * y el despacho, que es justo lo que los paquetes se ahorran.  Los dos
     * numeros hacen falta: uno dice si el TRABAJO cambio (no deberia) y el otro
     * si el DESPACHO salio mas barato (deberia). */
    uint64_t time_exec = 0;
    uint64_t time_decode = 0;
    uint64_t wall_ns = 0;
};

/**
 * @brief Ejecuta un proceso paso a paso, como el run_loop.
 *
 * Replica el ciclo del scheduler: buscar en icache, descodificar si falla,
 * ejecutar, y avanzar `rip` salvo que la instruccion saltara.  Con los paquetes
 * encendidos, un solo despacho puede ejecutar varias instrucciones -- por eso
 * el recuento sale de la telemetria y no de las vueltas del bucle.
 */
Result run(runtime::ProcessVM *proc, uint64_t cap) {
    Result r;
    uint64_t dispatches = 0;

    // `has_hooks` se queda APAGADO, y esto no es un descuido.
    //
    // Encenderlo activa `measuring` en la VM, que llama a `now_ns()` DOS VECES
    // POR INSTRUCCION.  Con paquetes esas llamadas ocurren dos veces por
    // DESPACHO -- 45 veces menos --, asi que el cronometro desaparece justo en
    // el lado que se quiere favorecer.  Medido asi salia un 90% de mejora que
    // era, en su mayor parte, el propio instrumento evaporandose.
    //
    // El reloj de fuera mide el bucle entero una sola vez y cuesta lo mismo en
    // los dos modos.
    proc->scheduler.has_hooks = false;
    proc->scheduler.time_exec = 0;
    proc->scheduler.time_decode = 0;
    const auto t0 = std::chrono::steady_clock::now();

    // El tope cuenta INSTRUCCIONES DE VM, no despachos.  Con paquetes un
    // despacho ejecuta varias, asi que topar por despachos hacia que las dos
    // corridas recorrieran trozos distintos del programa y compararlas no
    // significaba nada -- salian "distintas" por construccion.
    auto vm_count = [&]() -> uint64_t {
        uint64_t n = dispatches;
#if VM_BUNDLES
        n += proc->bundle_stats.instrs_in_bundles -
             proc->bundle_stats.dispatches;
#endif
        return n;
    };

    while (proc->state != runtime::HALT && proc->state != runtime::DEAD &&
           proc->err_thread == runtime::THREAD_NO_ERROR && vm_count() < cap) {
        const uint64_t pc = proc->registers.rip.raw();
        runtime::DecodedInstr *cached = runtime::icache_lookup(proc, pc);
        if (cached != nullptr && proc->decoded_ptr != nullptr)
            proc->decoded_ptr = cached;
        else
            runtime::decode_instruction(proc);

        if (proc->decoded_ptr == nullptr) {
            r.why = "sin instruccion descodificada";
            break;
        }
        // `hlt` se cuenta pero no se ejecuta: su manejador vacia los
        // finalizadores del GC y avisa al scheduler, y aqui no hay scheduler
        // corriendo.  El programa ya hizo todo su trabajo a esa altura.
        if (proc->decoded_ptr->flags_info.is_not_extended == 0x00 &&
            proc->decoded_ptr->flags_info.opcode_index ==
                static_cast<uint16_t>(bytecode::Opcodes::HLT)) {
            ++dispatches;
            r.why = "hlt";
            break;
        }

        // El presupuesto de reducciones lo lleva el run_loop: descuenta una por
        // despacho y lo repone al cerrar el lote.  Aqui hay que imitarlo, y no
        // por adorno: el desenrollado de un paquete consume reducciones por
        // vuelta, y sin reposicion se quedaba sin credito a las ~680 vueltas y
        // no volvia a dispararse en toda la corrida.  Las cifras salian
        // identicas a las de antes de implementarlo.
        if (proc->reductions_remaining <= 1)
            proc->reductions_remaining = reductions_remaining_default;
        --proc->reductions_remaining;

        const runtime::vm_event ev = runtime::execute_instruction(proc);
        ++dispatches;
        if (ev == runtime::EVT_HALT || ev == runtime::EVT_ERROR ||
            ev == runtime::EVT_IO_WAIT) {
            r.why = "evento de parada";
            break;
        }
    }

    // Instrucciones de VM = despachos, mas las que se ejecutaron DENTRO de
    // paquetes sin gastar un despacho propio.
    r.wall_ns = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
    r.time_exec = proc->scheduler.time_exec;
    r.time_decode = proc->scheduler.time_decode;
    r.vm_instrs = vm_count();
    r.capped = (r.why[0] == '\0');
    r.final_rip = proc->registers.rip.raw();
    for (int i = 0; i < 16; ++i)
        r.regs[i] = proc->registers.regs[i].raw();
    r.ok = true;
    return r;
}

/**
 * @brief Corre el programa con el SCHEDULER de verdad y cronometra.
 *
 * `run()` conduce el interprete a mano y despacha por `execute_instruction`,
 * que es el camino LENTO.  Comparar paquetes contra ese camino infla la
 * ganancia: el hot path real es el computed-goto del run_loop, que por
 * instruccion cuesta bastante menos.
 *
 * Aqui se arranca el scheduler tal cual, asi que lo que se mide es contra el
 * bucle que de verdad se ejecuta.  A cambio no se puede contar instrucciones ni
 * parar en el `hlt`, solo cronometrar de fuera -- que es justo lo que hace
 * falta.
 *
 * @return nanosegundos de pared, o 0 si no llego a terminar.
 */
uint64_t run_scheduled(runtime::VM *vm, runtime::ProcessVM *proc,
                       double seconds, uint64_t *regs_out) {
    const auto t0 = std::chrono::steady_clock::now();
    vm->make_ready(proc->pid);
    vm->start();
    const auto deadline =
        t0 + std::chrono::milliseconds((long long)(seconds * 1000));
    while (proc->state != runtime::HALT && proc->state != runtime::DEAD) {
        if (std::chrono::steady_clock::now() >= deadline) {
            vm->stop();
            return 0; // no termino: cronometrarlo no diria nada
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    const auto t1 = std::chrono::steady_clock::now();
    vm->stop();
    // El estado final tambien por ESTE camino.  Validar solo por el arnes y
    // cronometrar por el scheduler deja sin comprobar justo el bucle que se
    // mide: si el programa termina antes de tiempo aqui, saldria como una
    // mejora espectacular en vez de como el fallo que es.
    for (int i = 0; i < 16; ++i)
        regs_out[i] = proc->registers.regs[i].raw();
    return (uint64_t)
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
}

const char *base(const std::string &path) {
    const size_t p = path.find_last_of("/\\");
    return path.c_str() + (p == std::string::npos ? 0 : p + 1);
}

/* Traza al reventar.  Sin esto, un fallo es un codigo 139 y nada mas, y
 * acorralarlo cuesta ir bajando `--tope` a mano.  Es el mismo patron que ya
 * desatasco el test de icache. */
runtime::ProcessVM *g_proc = nullptr;
const char *g_bench = "?";

extern "C" void al_reventar(int sig) {
    std::printf("\n  == %s reviento (senal %d) ==\n", g_bench, sig);
    if (g_proc != nullptr) {
        std::printf("     pc=0x%llx estado=%d\n",
                    (unsigned long long)g_proc->registers.rip.raw(),
                    (int)g_proc->state);
        if (g_proc->decoded_ptr != nullptr)
            std::printf("     ultima descodificada: pc=0x%llx opcode=%u/%u\n",
                        (unsigned long long)g_proc->decoded_ptr->pc,
                        (unsigned)g_proc->decoded_ptr->flags_info.is_not_extended,
                        (unsigned)g_proc->decoded_ptr->flags_info.opcode_index);
        std::vector<char> buf(16384, '\0');
        if (runtime::build_stack_trace(g_proc, buf.data(), buf.size()) > 0)
            std::printf("     pila:\n%s\n", buf.data());
    }
    std::fflush(stdout);
    std::_Exit(139);
}

int g_pass = 0;
int g_fail = 0;

void check(bool cond, const char *what, const char *bench) {
    if (cond) {
        ++g_pass;
    } else {
        ++g_fail;
        std::printf("  FALLO  %-22s %s\n", bench, what);
    }
}

} // namespace

int main(int argc, char **argv) {
    std::vector<std::string> files;
    uint64_t cap = kDefaultCap;
    bool control = false;
    int modo_unico = -1; ///< -1 = los dos modos; 0/1 = solo ese, con resumen
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--modo") == 0 && i + 1 < argc)
            // Corre UN SOLO modo y publica un resumen.  Comparar los dos modos
            // dentro del mismo proceso no vale: 202 programas del corpus
            // discrepaban CONSIGO MISMOS sin paquetes de por medio, porque la
            // segunda VM hereda estado global de la primera (la cache eager del
            // JIT, los pools de interning...).  Un proceso por modo elimina esa
            // variable entera.
            modo_unico = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--control") == 0)
            // Corre las dos pasadas SIN paquetes.  Es el control del
            // experimento: cualquier reventon que siga apareciendo asi es del
            // arnes -- montar dos VMs en un proceso --, no del mecanismo.  Sin
            // este modo no se puede atribuir un fallo a los paquetes.
            control = true;
        else if (std::strcmp(argv[i], "--tope") == 0 && i + 1 < argc)
            cap = std::strtoull(argv[++i], nullptr, 10);
        else
            files.push_back(argv[i]);
    }
    if (files.empty()) {
        std::fprintf(stderr, "uso: test_bundles <fichero.velb> [...] "
                             "[--tope N]\n");
        return 2;
    }

#if !VM_BUNDLES
    std::printf("VM_BUNDLES=0: no hay paquetes que validar.\n");
    return 0;
#else
    // Interprete puro.  El umbral por si solo no basta: el loader compila
    // `main` en eager sin mirarlo, y `g_pc_jit_active` es lo que impide que
    // `callvm` despache al nativo.
    jit::g_jit_threshold = UINT32_MAX;
    jit::g_pc_jit_active = false;

    std::printf("Paquetes de instrucciones: BUNDLE_MAX=%d  telemetria=%s\n\n",
                BUNDLE_MAX,
                VM_BUNDLE_STATS ? "si"
                                : "no (compila con "
                                  "-DVM_BUNDLE_STATS=1)");
    std::printf("%-22s %12s %10s %10s %9s %8s\n", "bench", "instr VM",
                "formados", "ahorrados", "abandonos", "encadena", "igual?");
    std::printf("%s\n", std::string(78, '-').c_str());
    // Sin esto, si algo revienta se pierde hasta la cabecera y no queda ni
    // rastro de por donde iba.
    std::fflush(stdout);

    uint64_t g_instrs = 0, g_saved = 0, g_formed = 0, g_aborts = 0;

    for (const std::string &f : files) {
        Result out[2];
        uint64_t formed = 0, saved = 0, aborts = 0, turns = 0;

        // En modo unico el programa se ejecuta SOLO en el bloque del scheduler
        // de mas abajo.  Este bucle es el del arnes paso a paso, que ahi no
        // pinta nada: ejecutarlo tambien duplicaba la salida del programa y la
        // hacia inservible para compararla.
        for (int modo = 0; modo < (modo_unico < 0 ? 2 : 0); ++modo) {
            runtime::ManageVM manager(nullptr, 0);
            runtime::VM *vm = manager.loader.create_vm_instance(1);
            runtime::ProcessVM *proc = nullptr;
            try {
                proc = manager.loader.load_executable(*vm, f);
            } catch (const std::exception &e) {
                std::printf("%-22s  no carga: %s\n", base(f), e.what());
                proc = nullptr;
            }
            if (proc == nullptr) break;

            proc->bundles_on = (modo == 1) && !control;
            g_proc = proc;
            g_bench = base(f);
            std::signal(SIGSEGV, al_reventar);
            std::signal(SIGILL, al_reventar);
            vm->make_ready(proc->pid);
            std::printf("  [%s paquetes %s]\n", base(f),
                        proc->bundles_on ? "ON " : "OFF");
            std::fflush(stdout);
            out[modo] = run(proc, cap);

            if (modo == 1) {
                formed = proc->bundle_stats.formed;
                saved = proc->bundle_stats.instrs_in_bundles -
                        proc->bundle_stats.dispatches;
                aborts = proc->bundle_stats.aborts;
                turns = proc->bundle_stats.chained;
            }
            runtime::bundle_release(proc);
        }

        // Modo unico: se publica el resumen y se deja la comparacion a quien
        // lance los dos procesos.  Asi los dos lados arrancan con el estado
        // global limpio y lo unico que los distingue son los paquetes.
        //
        // Y se corre con el SCHEDULER de verdad, no con el bucle a mano.  Dos
        // razones, las dos aprendidas a base de datos malos:
        //   - El bucle a mano no puede ejecutar `hlt` (su manejador vacia los
        //     finalizadores del GC y avisa a un scheduler que ahi no existe).
        //     Sin paquetes eso no se notaba porque `hlt` siempre era la
        //     cabecera y habia una guarda; DENTRO de un paquete la guarda no lo
        //     ve, y el arnes moria en 416 de 481 programas.  Esos muertos eran
        //     del arnes, no del mecanismo.
        //   - Es el camino que de verdad se va a usar.  Validar por uno y
        //     medir por el otro es lo que dejo pasar el fallo del despacho.
        if (modo_unico >= 0) {
            Result r;
            {
                runtime::ManageVM mgr(nullptr, 0);
                runtime::VM *vm = mgr.loader.create_vm_instance(1);
                runtime::ProcessVM *p = nullptr;
                try {
                    p = mgr.loader.load_executable(*vm, f);
                } catch (const std::exception &) {
                    p = nullptr;
                }
                if (p != nullptr) {
                    p->bundles_on = (modo_unico == 1) && !control;
                    g_proc = p;
                    g_bench = base(f);
                    std::signal(SIGSEGV, al_reventar);
                    const uint64_t ns = run_scheduled(vm, p, 20.0, r.regs);
                    r.ok = (ns != 0);
                    r.capped = (ns == 0); // no termino dentro del plazo
                    r.final_rip = p->registers.rip.raw();
                    r.wall_ns = ns;
                    runtime::bundle_release(p);
                }
            }
            uint64_t h = util::kFnvOffset;
            for (int i = 0; i < 16; ++i)
                h = util::fnv_mix(h, r.regs[i]);
            // `fin` distingue el que termino el programa del que se corto por
            // el tope.  Solo los primeros se pueden comparar entre modos: una
            // corrida topada con paquetes se pasa de largo y acaba en otro
            // sitio, asi que su resumen difiere sin que nada este mal.
            std::printf("RESUMEN %s ms=%.3f rip=0x%llx regs=%016llx fin=%s %s\n",
                        base(f), r.wall_ns / 1e6,
                        (unsigned long long)r.final_rip, (unsigned long long)h,
                        r.capped ? "plazo" : "programa",
                        r.ok ? "ok" : "NO-EJECUTA");
            std::fflush(stdout);
            continue;
        }

        if (!out[0].ok || !out[1].ok) continue;

        const char *b = base(f);
        const bool cortado = out[0].capped || out[1].capped;

        // Con el tope de por medio, lo unico exigible es que las dos corridas
        // hayan hecho la MISMA cantidad de trabajo salvo el desbordamiento
        // inherente de un paquete (hasta k-1 instrucciones).  Sin tope, el
        // estado final tiene que ser identico hasta el ultimo registro.
        const uint64_t a = out[0].vm_instrs, c = out[1].vm_instrs;
        const uint64_t diff = a > c ? a - c : c - a;
        // Sin telemetria no hay forma de saber cuantas instrucciones se
        // ejecutaron DENTRO de los paquetes, asi que el recuento de la corrida
        // con paquetes no es comparable.  Se omite esa comprobacion en vez de
        // darla por fallada: un test que falla por el motivo equivocado hace
        // mas dano que no estar.
        // Cuanto se puede pasar del tope una corrida con paquetes: un despacho
        // ejecuta hasta BUNDLE_MAX instrucciones, y encadenando hasta
        // BUNDLE_LOOP_MAX paquetes mas sin soltarlo.  El tope se mira ANTES del
        // despacho, asi que ese es el desbordamiento maximo.
        const uint64_t holgura =
            (uint64_t)BUNDLE_MAX * (BUNDLE_LOOP_MAX + 1);
        const bool mismo_n =
            !VM_BUNDLE_STATS ? true : (cortado ? diff <= holgura : a == c);
        const bool mismo_rip = out[0].final_rip == out[1].final_rip;
        bool mismos_regs = true;
        for (int i = 0; i < 16; ++i)
            if (out[0].regs[i] != out[1].regs[i]) mismos_regs = false;

        check(mismo_n, "distinto numero de instrucciones de VM", b);
        // Con el tope sin telemetria, las dos corridas paran en sitios
        // distintos y comparar su estado final no dice nada.  Sin tope, las dos
        // acabaron el programa: ahi si tiene que salir todo identico, y es la
        // comprobacion que de verdad valida el mecanismo.
        if (!cortado) {
            check(mismo_rip, "distinto rip final", b);
            check(mismos_regs, "distintos registros al terminar", b);
        }

        std::printf("%-22s %12llu %10llu %10llu %9llu %9llu %7s\n", b,
                    (unsigned long long)out[1].vm_instrs,
                    (unsigned long long)formed, (unsigned long long)saved,
                    (unsigned long long)aborts, (unsigned long long)turns,
                    !mismo_n                     ? "NO"
                    : cortado                    ? "si*"
                    : (mismo_rip && mismos_regs) ? "si"
                                                 : "NO");
        std::fflush(stdout);

        // Tiempo: ns por instruccion de VM en cada modo.  Es la unica cifra que
        // convierte "97% menos despachos" en algo que se pueda creer.
        if (out[0].vm_instrs && out[1].vm_instrs) {
            const double sin_p = (double)out[0].wall_ns / out[0].vm_instrs;
            const double con_p = (double)out[1].wall_ns / out[1].vm_instrs;
            std::printf("      tiempo: %6.2f -> %6.2f ns/instr  (%+.1f%%)\n",
                        sin_p, con_p, 100.0 * (con_p - sin_p) / sin_p);
        }

        // Y ahora contra el run_loop de verdad, que es el hot path.
        {
            uint64_t sched_ns[2] = {0, 0};
            uint64_t sched_regs[2][16] = {};
            for (int modo = 0; modo < 2; ++modo) {
                runtime::ManageVM mgr(nullptr, 0);
                runtime::VM *vm = mgr.loader.create_vm_instance(1);
                runtime::ProcessVM *p = nullptr;
                try {
                    p = mgr.loader.load_executable(*vm, f);
                } catch (const std::exception &) {
                    p = nullptr;
                }
                if (p == nullptr) break;
                p->bundles_on = (modo == 1) && !control;
                sched_ns[modo] = run_scheduled(vm, p, 20.0, sched_regs[modo]);
                runtime::bundle_release(p);
            }
            if (sched_ns[0] != 0 && sched_ns[1] != 0) {
                bool iguales = true;
                for (int i = 0; i < 16; ++i)
                    if (sched_regs[0][i] != sched_regs[1][i]) iguales = false;
                check(iguales, "el run_loop real deja OTROS registros", b);
                std::printf("      run_loop real: %8.2f -> %8.2f ms  "
                            "(%+.1f%%)%s\n",
                            sched_ns[0] / 1e6, sched_ns[1] / 1e6,
                            100.0 * ((double)sched_ns[1] - sched_ns[0]) /
                                (double)sched_ns[0],
                            iguales ? "" : "   <-- RESULTADO DISTINTO");
            }
        }

        g_instrs += out[1].vm_instrs;
        g_saved += saved;
        g_formed += formed;
        g_aborts += aborts;
    }

    std::printf("%s\n", std::string(78, '-').c_str());
    if (g_instrs) {
        std::printf("TOTAL: %llu instrucciones de VM, %llu paquetes, "
                    "%llu despachos ahorrados (%.2f%%), %llu abandonos\n",
                    (unsigned long long)g_instrs, (unsigned long long)g_formed,
                    (unsigned long long)g_saved,
                    100.0 * (double)g_saved / (double)g_instrs,
                    (unsigned long long)g_aborts);
    }
    std::printf("comprobaciones: %d pasaron, %d fallaron\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
#endif // VM_BUNDLES
}
