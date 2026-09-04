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
 * Publica cuantos paquetes se formaron, cuantos despachos se ahorraron y
 * cuantos se abandonaron a mitad.  El ahorro de despachos es la cifra que dice
 * si esto sirve para algo: cada instruccion de mas dentro de un paquete es un
 * salto indirecto que el interprete no hizo.
 *
 * La telemetria se PIDE en ejecucion (`ProcessVM::bundle_stats_on`), asi que no
 * hace falta reconstruir nada para verla.  Antes dependia de una bandera de
 * compilacion y eso obligaba a cambiar de binario para tomar la medida -- con
 * lo que se media otro binario --.
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
#include "../util/gen_program.h" // programas propios si no dan ficheros
#include "jit/auto_jit.h"
#include "runtime/bundle.h"
#include "runtime/decode_instruction.h"
#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "runtime/vm_registers.h"
#include "runtime/exception_runtime.h" // build_stack_trace
#include "util/ansi.h"
#include "util/fnv.h"

// La medida de independencia dentro del paquete.  Era un test aparte que
// generaba LOS MISMOS programas, montaba LA MISMA arena y sacaba una tabla
// igual: dos binarios para dos preguntas sobre un solo sujeto.  Aqui va la
// validacion (que los paquetes no cambian el resultado) y detras el analisis.
#include "../util/bundle_ilp.h"

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
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(t1 -
                                                                          t0)
        .count();
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
            std::printf(
                "     ultima descodificada: pc=0x%llx opcode=%u/%u\n",
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
        std::printf("  %sFALLO%s  %-22s %s\n", ansi::c(ansi::BR_RED),
                    ansi::c(ansi::RESET), bench, what);
    }
}

/// Color por PROPORCION: rojo lo que casi no pasa, verde lo que pasa mucho.
/// Da la escala de un vistazo sin tener que dividir de cabeza.
const char *heat(double frac) {
    if (frac >= 0.60) return ansi::c(ansi::BR_GREEN);
    if (frac >= 0.30) return ansi::c(ansi::GREEN);
    if (frac >= 0.10) return ansi::c(ansi::BR_YELLOW);
    if (frac > 0.0) return ansi::c(ansi::YELLOW);
    return ansi::c(ansi::BR_BLACK);
}

/// Los abandonos son lo contrario: cuantos MENOS, mejor.
const char *heat_bad(double frac) {
    if (frac >= 0.20) return ansi::c(ansi::BR_RED);
    if (frac >= 0.05) return ansi::c(ansi::YELLOW);
    return ansi::c(ansi::BR_BLACK);
}

#if VM_BUNDLES
/**
 * @brief Que hay DENTRO de las caches al terminar una corrida.
 *
 * Tres niveles, de menos a mas detalle, porque son tres preguntas distintas:
 *
 *   1. el RESUMEN -- cuanto de la icache se usa, cuantas cabeceras sobreviven,
 *      cuanto ocupa la region viva --, que dice si el mecanismo esta trabajando;
 *   2. las CABECERAS con lo que cada paquete ha hecho (entradas, ejecutadas,
 *      instrucciones por entrada, si se retiro), que es lo que explica POR QUE
 *      un paquete concreto se comporto como se comporto;
 *   3. el ENSAMBLADOR de una cabecera con las DIRECCIONES VIRTUALES, leido de
 *      la memoria de la VM y pasado por el mismo desensamblador que
 *      `--disasm-file`.  Es lo que se contrasta contra el programa cuando lo
 *      que hay en la cache no cuadra con lo que deberia haber.
 *
 * Nada de esto cuenta durante la ejecucion: recorre las estructuras al
 * pedirselo, o sea que el camino caliente no paga.
 *
 * @param proc  Proceso cuya cache se mira.  Tiene que seguir viva: despues de
 *              `bundle_release` no hay nada que ver.
 * @param name  Nombre del programa, para encabezar el volcado.
 */
void dump_caches(runtime::ProcessVM *proc, const char *name) {
    const char *B = ansi::c(ansi::BOLD);
    const char *D = ansi::c(ansi::DIM);
    const char *R = ansi::c(ansi::RESET);

    /* Las cifras se sacan de la propia icache.  `entries` y `executed` los
     * mantiene la logica de retirada, no la telemetria, asi que esto sale con
     * numeros de verdad aunque nadie haya pedido los contadores. */
    uint32_t heads = 0, retired = 0, occupied = 0;
    uint64_t total_k = 0, total_entries = 0, total_exec = 0;
    const runtime::Bundle *sample = nullptr;
    for (uint32_t i = 0; i < runtime::ICACHE_SIZE; ++i) {
        const runtime::DecodedInstr &e = proc->icache[i];
        if (e.exec_cached != nullptr) ++occupied;
        if (e.exec_cached != &runtime::exec_bundle) continue;
        const runtime::Bundle *b = runtime::bundle_of(e);
        if (b == nullptr) continue;
        ++heads;
        if (b->retired) ++retired;
        total_k += b->k;
        total_entries += b->entries;
        total_exec += b->executed;
        // La de MAS entradas es la interesante: es la que de verdad se ejecuta.
        if (sample == nullptr || b->entries > sample->entries) sample = b;
    }

    std::fflush(stdout); // los volcados van por stderr; sin esto se entrelazan
    std::fprintf(stderr, "\n%s--- caches de %s ---%s\n", B, name, R);
    std::fprintf(stderr,
                 "  icache: %s%u/%u%s ocupadas (%.1f%%), de ellas %s%u%s "
                 "cabeceras de paquete (%s%u retiradas%s)\n",
                 ansi::c(ansi::BR_CYAN), occupied,
                 (unsigned)runtime::ICACHE_SIZE, R,
                 100.0 * (double)occupied / (double)runtime::ICACHE_SIZE,
                 ansi::c(ansi::BR_CYAN), heads, R,
                 retired ? ansi::c(ansi::YELLOW) : D, retired, R);
    if (heads != 0)
        std::fprintf(stderr,
                     "  paquetes vivos: k medio %s%.1f%s de %d, %llu entradas, "
                     "%llu instrucciones -> %s%.1f por entrada%s (umbral %u)\n",
                     ansi::c(ansi::BR_CYAN), (double)total_k / (double)heads, R,
                     BUNDLE_MAX, (unsigned long long)total_entries,
                     (unsigned long long)total_exec,
                     total_entries && total_exec / total_entries >=
                                          runtime::Bundle::MIN_PER_ENTRY
                         ? ansi::c(ansi::BR_GREEN)
                         : ansi::c(ansi::BR_RED),
                     total_entries ? (double)total_exec / (double)total_entries
                                   : 0.0,
                     R, runtime::Bundle::MIN_PER_ENTRY);

    // Nivel 1: el estado de la arena de doble region y el histograma.
    runtime::bundle_dump(proc);
    // Nivel 2: unas pocas cabeceras.  Con miles, listarlas todas es ilegible.
    runtime::bundle_dump_heads(proc, 6, /*with_instructions=*/false);
    // Nivel 3: el ensamblador de la mas usada, con sus direcciones virtuales.
    if (sample != nullptr) {
        std::fprintf(stderr, "\n%scabecera mas ejecutada, desensamblada:%s\n", B,
                     R);
        runtime::bundle_dump_one(proc, sample);
    }
    std::fflush(stderr);
}
#endif // VM_BUNDLES

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
    /* SIN ficheros, el test se genera los suyos y corre igual.
     *
     * Antes salia con codigo 2 pidiendo argumentos, y el lanzador de unitarios
     * lo contaba -- correctamente -- como "pide argumentos, no es un fallo".
     * O sea que este test, que es el que valida que los paquetes NO cambian el
     * resultado, no lo ejecutaba nadie salvo a mano.  Es el mismo patron que
     * dejo los veintiseis de `tests/aot/` meses sin correr.
     *
     * Los dos programas generados no son arbitrarios: uno cabe de sobra en la
     * cache y el otro la desborda a proposito, que es lo que hace pasar por el
     * RECOLECTOR.  Sin el segundo, la recoleccion no se ejecutaria nunca aqui. */
    bool generados = false;
    if (files.empty()) {
        files = tests::default_bundle_programs("test_bundles");
        generados = true;
        if (files.empty()) {
            std::fprintf(stderr, "no se pudieron generar los programas\n");
            return 1;
        }
        std::printf("Sin ficheros: se generan %zu programas propios "
                    "(uno desborda la cache, para pasar por el recolector).\n",
                    files.size());
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

    ansi::init();
    const char *B = ansi::c(ansi::BOLD);
    const char *D = ansi::c(ansi::DIM);
    const char *R = ansi::c(ansi::RESET);

    std::printf("%sPaquetes de instrucciones%s  BUNDLE_MAX=%s%d%s  "
                "ICACHE_SIZE=%s%u%s  telemetria=%s%s%s\n",
                B, R, ansi::c(ansi::BR_CYAN), BUNDLE_MAX, R,
                ansi::c(ansi::BR_CYAN), (unsigned)runtime::ICACHE_SIZE, R,
                ansi::c(ansi::BR_GREEN), "si (se pide en ejecucion)", R);

    /* QUE SIGNIFICA CADA COLUMNA.  Sin esto la tabla son seis numeros sin
     * nombre, y el que la lee dentro de tres meses no sabe si "ahorrados" es
     * bueno que suba o que baje. */
    std::printf("\n%sColumnas:%s\n", B, R);
    std::printf(
        "  %sprograma%s   el `.velb`.  Los generados dicen que CLASE de "
        "instruccion llevan dentro.\n",
        D, R);
    std::printf("  %sinstr VM%s   instrucciones de VM ejecutadas.  Tiene que "
                "salir IGUAL con y sin\n"
                "             paquetes: si difiere, un paquete se salto una o "
                "la ejecuto dos veces.\n",
                D, R);
    std::printf("  %spaquetes%s   cabeceras formadas.  Formar cuesta; lo que "
                "compensa es entrar muchas\n"
                "             veces en cada una, no formar muchas.\n",
                D, R);
    std::printf("  %sahorrados%s  despachos que el interprete NO hizo -- cada "
                "instruccion de mas dentro\n"
                "             de un paquete es un salto indirecto que se "
                "evita.  ES LA CIFRA que\n"
                "             dice si esto sirve: %% sobre las instrucciones "
                "de VM.  Cuanto MAS, mejor.\n",
                D, R);
    std::printf("  %sabandonos%s  paquetes cortados a mitad (salto, bloqueo, "
                "instruccion no apta).\n"
                "             Cuanto MENOS, mejor: el trabajo de formar se "
                "tiro.\n",
                D, R);
    std::printf("  %sreentra%s    veces que se volvio a entrar a una cabecera "
                "ya formada.  Es lo que\n"
                "             amortiza el coste de formarla.\n",
                D, R);
    std::printf("  %sidentico%s   si las dos corridas coinciden en instrucciones"
                ", `rip` y los 16\n"
                "             registros.  `si*` = las dos se cortaron en el "
                "tope, no es concluyente.\n",
                D, R);
    std::printf("  %smotivo%s     por que PARO el arnes: `hlt` es que el "
                "programa termino solo.\n"
                "             Cualquier otra cosa dice que se corto antes, y "
                "entonces lo validado\n"
                "             es solo hasta ahi.\n\n",
                D, R);

    std::printf("\n%s%-28s %12s %9s %12s %10s %9s %9s  %s%s\n", B, "programa",
                "instr VM", "paquetes", "ahorrados", "abandonos", "reentra",
                "identico", "motivo", R);
    std::printf("%s%s%s\n", D, std::string(108, '-').c_str(), R);
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
            // Este test IMPRIME los contadores, asi que los pide.  Ya no hace
            // falta reconstruir con una bandera para verlos.
            proc->bundle_stats_on = true;
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
                /* CONTENIDO de las caches, recien terminada la corrida y antes
                 * de soltar la arena.  Aqui es el unico sitio donde se puede
                 * ver: `bundle_release` la destruye.
                 *
                 * Y no depende de que nadie haya pedido la telemetria: lo que
                 * se lee son las propias estructuras -- la icache, las
                 * cabeceras vivas y lo que cada paquete lleva dentro --, no
                 * contadores. */
                dump_caches(proc, base(f));
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
            std::printf(
                "RESUMEN %s ms=%.3f rip=0x%llx regs=%016llx fin=%s %s\n",
                base(f), r.wall_ns / 1e6, (unsigned long long)r.final_rip,
                (unsigned long long)h, r.capped ? "plazo" : "programa",
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
        const uint64_t holgura = (uint64_t)BUNDLE_MAX * (BUNDLE_LOOP_MAX + 1);
        const bool mismo_n = cortado ? diff <= holgura : a == c;
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

        /* La fila.  Los tres numeros que dicen algo van con escala de color:
         * `ahorrados` sobre las instrucciones de VM (mas = mejor) y
         * `abandonos` sobre los paquetes formados (menos = mejor). */
        const double frac_saved =
            out[1].vm_instrs ? (double)saved / (double)out[1].vm_instrs : 0.0;
        const double frac_abort =
            formed ? (double)aborts / (double)formed : 0.0;
        const bool ok = mismo_n && (cortado || (mismo_rip && mismos_regs));

        /* Los cuatro contadores vienen de la telemetria, que este test PIDE al
         * crear el proceso.  Ya no hay caso "sin medir": antes dependia de una
         * bandera de compilacion y habia que escribir `--` en vez de un cero,
         * porque un cero ahi habria dicho que los paquetes no hicieron nada
         * cuando el volcado de la cache ensenaba lo contrario. */
        char c_formed[24], c_saved[24], c_aborts[24], c_turns[24];
        std::snprintf(c_formed, sizeof c_formed, "%llu",
                      (unsigned long long)formed);
        std::snprintf(c_saved, sizeof c_saved, "%llu",
                      (unsigned long long)saved);
        std::snprintf(c_aborts, sizeof c_aborts, "%llu",
                      (unsigned long long)aborts);
        std::snprintf(c_turns, sizeof c_turns, "%llu",
                      (unsigned long long)turns);

        std::printf("%s%-28s%s %s%12llu%s %s%9s%s %s%12s%s %s%10s%s "
                    "%s%9s%s %s%9s%s  %s%s%s\n",
                    ansi::c(ansi::BR_CYAN), b, ansi::c(ansi::RESET),
                    /* El recuento se toma del modo SIN paquetes: ahi cada
                     * instruccion es un despacho, asi que es exacto.  El del
                     * modo con paquetes solo lo es con telemetria -- lo que se
                     * ejecuta DENTRO de un paquete no gasta despacho --, y
                     * ponerlo daba 5.421 donde el programa hace 2,4 millones. */
                    ansi::c(ansi::WHITE), (unsigned long long)out[0].vm_instrs,
                    ansi::c(ansi::RESET),
                    heat(formed ? 1.0 : 0.0), c_formed, ansi::c(ansi::RESET),
                    heat(frac_saved), c_saved, ansi::c(ansi::RESET),
                    heat_bad(frac_abort), c_aborts, ansi::c(ansi::RESET),
                    heat(turns ? 1.0 : 0.0), c_turns, ansi::c(ansi::RESET),
                    ok ? ansi::c(ansi::BR_GREEN) : ansi::c(ansi::BR_RED),
                    !mismo_n ? "NO" : cortado ? "si*" : ok ? "si" : "NO",
                    ansi::c(ansi::RESET),
                    /* POR QUE paro.  Estaba en `Result::why` y no lo imprimia
                     * nadie: el arnes se detenia y el motivo no salia por
                     * ningun sitio, que es justo el fallo mudo que este
                     * proyecto no admite. */
                    ansi::c(ansi::DIM),
                    out[1].why[0] != '\0' ? out[1].why : "tope",
                    ansi::c(ansi::RESET));
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
    /* Aqui habia OTRO volcado de caches, que ademas volvia a cargar y ejecutar
     * el ultimo programa solo para tener una arena que mirar.  Sobra desde que
     * `dump_caches` sale por programa, justo cuando la arena todavia esta viva:
     * eso ensena los siete casos en vez de uno, y sin ejecutar nada de mas. */

    /* Y la segunda pregunta sobre los mismos programas: cuanta independencia
     * hay DENTRO de un paquete, que es lo que decide si reordenar al formar
     * daria algo.  Vuelve a ejecutarlos por su cuenta porque necesita la arena
     * viva, y la de arriba ya se solto. */
    tests::ilp_report(files, /*detalle=*/false, cap);

    std::printf("\ncomprobaciones: %s%d pasaron%s, %s%d fallaron%s\n",
                ansi::c(ansi::BR_GREEN), g_pass, ansi::c(ansi::RESET),
                g_fail ? ansi::c(ansi::BR_RED) : ansi::c(ansi::BR_BLACK),
                g_fail, ansi::c(ansi::RESET));
    return g_fail == 0 ? 0 : 1;
#endif // VM_BUNDLES
}
