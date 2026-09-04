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
 * @file scheduler.h                                                           \
 * @brief Declaracion del planificador de procesos de VestaVM.                 \
 *                                                                             \
 * Declara @c Scheduler: asignacion de @c ProcessVM a hilos nativos,           \
 * bucle de ejecucion con balance de carga, ganchos de temporalizacion         \
 * y transiciones de estado READY -> RUNNING -> BLOCKED/DEAD.                  \
 */                                                                            \
#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <queue>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>

#include "runtime/runtime.h"
#include "runtime/proceso_runtime.h"
#include "vm_state_event.h"
#include "profiler/timer.h"

#include "runtime/pid.h"

namespace runtime {
class ProcessVM;   ///< Proceso virtual (declaracion adelantada)
struct Transition; ///< Transicion de la FSM (declaracion adelantada)
class VM;          ///< Instancia VM (declaracion adelantada)

/**
 * @brief Semaforo binario compatible con GCC < 11.
 *
 * Polyfill de std::counting_semaphore<1> implementado con mutex y
 * condition_variable.  La API es identica a la del estandar C++20:
 *   - release() desbloquea un waiter o incrementa el contador.
 *   - acquire() bloquea hasta que el contador sea > 0.
 *
 * @note Debe reemplazarse por std::counting_semaphore<> al actualizar el
 * compilador a GCC >= 11.
 */
struct BinarySemaphore {
    /**
     * @brief Incrementa el contador y notifica a un waiter bloqueado.
     */
    void release() {
        std::lock_guard lock(mtx_); // proteger el incremento del contador
        ++count_;                   // senyal disponible
        cv_.notify_one();           // despertar a un waiter
    }

    /**
     * @brief Bloquea el hilo hasta que el contador sea > 0 y lo decrementa.
     */
    void acquire() {
        std::unique_lock lock(mtx_);
        cv_.wait(lock,
                 [&] { return count_ > 0; }); // esperar hasta que haya senal
        --count_;                             // consumir la senyal
    }

  private:
    std::mutex mtx_; ///< Mutex que protege count_
    std::condition_variable
        cv_;        ///< Variable de condicion para bloqueo/notificacion
    int count_ = 0; ///< Contador de senales disponibles
};

/**
 * @brief Fases del ciclo de ejecucion en las que se disparan los hooks de
 * depuracion.
 *
 * Cada valor indica el punto del pipeline donde se invoca el DebugHook:
 *   - DecodeBegin / DecodeEnd:   inicio y fin de la fase de descodificacion.
 *   - ExecuteBegin / ExecuteEnd: inicio y fin de la fase de ejecucion.
 *   - OnEventBegin / OnEventEnd: antes y despues del cambio de estado en la
 * FSM.
 */
enum class DebugStage {
    DecodeBegin,  ///< Inicio de la descodificacion de la instruccion actual
    DecodeEnd,    ///< Fin de la descodificacion de la instruccion actual
    ExecuteBegin, ///< Inicio de la ejecucion de la instruccion descodificada
    ExecuteEnd,   ///< Fin de la ejecucion de la instruccion descodificada
    OnEventBegin, ///< Antes del cambio de estado de la FSM
    OnEventEnd,   ///< Despues del cambio de estado de la FSM
};

/** @brief Tipo de callback de depuracion: recibe el proceso y la fase actual.
 */
using DebugHook = void (*)(ProcessVM *vm, DebugStage stage);

/**
 * @class Scheduler
 * @brief Planificador de procesos virtuales sobre un hilo nativo.
 *
 * Cada Scheduler ejecuta un run_loop() en un hilo del ThreadPool de la VM.
 * Implementa un modelo de planificacion cooperativa/preemptiva inspirado en
 * Erlang/BEAM:
 *   - Round-robin con reducciones: cada proceso tiene un numero maximo de
 *     instrucciones por quantum (reductions_remaining_default).
 *   - FSM por proceso: los estados NEW -> READY -> DECODE -> EXECUTE -> ...
 *     se gestionan mediante la tabla de transiciones fsm[][].
 *   - Semaforo de espera: si no hay procesos listos el scheduler duerme con
 *     sem.acquire() y se despierta cuando llega un make_ready().
 */
class Scheduler {
  public:
    /**
     * @brief Identificador unico del scheduler dentro de su VM.
     *
     * Asignado por la VM en el momento de la construccion.
     * El maximo es 2^32-1 schedulers por VM.
     */
    const uint32_t id_scheduler;

    /**
     * @brief Lista de callbacks de depuracion registrados para este scheduler.
     *
     * Cada hook se invoca en los puntos indicados por DebugStage.
     * Los hooks deben ser rapidos y no bloqueantes para no penalizar el
     * rendimiento.
     */
    std::vector<DebugHook> debug_hooks;

    uint64_t next_pid =
        0; ///< Contador monotonico para generar PIDs locales unicos

    ProcessVM *instance =
        nullptr; ///< Puntero al proceso actualmente en ejecucion

    /**
     * @brief Instrucciones ejecutadas por el proceso actual en el quantum en
     * curso.
     *
     * Cuando alcanza reductions_remaining del proceso activo, el scheduler
     * elige el siguiente proceso de la cola ready_queue.
     */
    uint64_t reductions_now = 0;

    /**
     * @brief Tabla de procesos de este scheduler.
     *
     * Cada proceso es propiedad exclusiva del scheduler (unique_ptr).
     * La VM crea y destruye los procesos; ningun otro modulo puede borrarlos.
     */
    std::vector<std::unique_ptr<ProcessVM>> processes;

    std::unordered_map<GlobalPID, ProcessVM *>
        pid_index; ///< Indice PID -> proceso para busqueda O(1)

    Transition fsm[NUM_STATES][NUM_EVENTS]; ///< Tabla de transiciones de la FSM
                                            ///< [estado][evento]

    /**
     * @brief Ejecuta la transicion de estado correspondiente al evento @p e.
     *
     * Consulta la tabla fsm[estado_actual][e] del proceso activo (instance),
     * ejecuta la accion asociada y actualiza el estado del proceso.
     *
     * Ejemplo de flujo:
     *   estado=EXECUTE, evento=EVT_EXEC_DONE -> fsm[EXECUTE][EVT_EXEC_DONE]
     *   -> nuevo estado + accion (p.ej. incrementar PC).
     *
     * @param e Evento que desencadena la transicion.
     */
    void on_event(vm_event e);

    VM &vm_reference; ///< Referencia a la instancia VM que posee este scheduler

    /**
     * @brief Construye el scheduler y lo asocia a la VM indicada.
     * @param id_scheduler Identificador unico dentro de la VM.
     * @param vm_reference Referencia a la instancia VM propietaria.
     */
    Scheduler(uint32_t id_scheduler, VM &vm_reference);

    /**
     * @brief Cola de procesos listos para ejecutarse (FIFO).
     *
     * Usa std::deque por sus garantias de complejidad O(1) para push_back y
     * pop_front, ideales para round-robin.  Almacena punteros directos para
     * evitar el hash lookup en pid_index en cada ciclo.
     *
     * Protegida por queue_mutex: make_ready() puede ser llamado desde hilos
     * externos mientras run_loop() lee la cola desde el hilo del scheduler.
     */
    std::deque<ProcessVM *> ready_queue;

    std::mutex queue_mutex; ///< Mutex que protege ready_queue ante accesos
                            ///< concurrentes

    /**
     * @brief Numero de procesos vivos en este scheduler.
     *
     * Un proceso es "vivo" si su estado no es NEW, DEAD ni HALT.
     * Se incrementa en make_ready() y se decrementa cuando un proceso alcanza
     * DEAD o HALT. Permite implementar has_alive_processes() en O(1).
     */
    std::atomic<int> alive_count{0};

    /**
     * @brief Ejecuta un unico paso de la FSM para el proceso indicado.
     *
     * Implementa la ejecucion atomica de un estado del ciclo de instruccion:
     *   1. Despacha al bloque de codigo del estado actual (tabla de despacho).
     *   2. Ejecuta la accion del estado (DECODE, EXECUTE, WAIT_IO, etc.).
     *   3. Determina el evento resultante (EVT_DECODE_DONE, EVT_EXEC_DONE,
     * ...).
     *   4. Llama a on_event() para actualizar el estado segun la FSM.
     *   5. Retorna inmediatamente al scheduler.
     *
     * Este metodo no contiene bucles; ejecuta exactamente una transicion.
     * La seleccion de procesos y la gestion de reducciones son responsabilidad
     * exclusiva de run_loop().
     *
     * @param process Proceso sobre el que se ejecutara el paso de la FSM.
     */
    void run_fsm_step(ProcessVM *process);

    /**
     * @brief Bucle principal del planificador de procesos.
     *
     * Se ejecuta en un hilo del ThreadPool de la VM e implementa el ciclo
     * de planificacion cooperativa/preemptiva:
     *   1. Llama a schedule_next() para obtener el proximo proceso listo.
     *      Si no hay procesos, duerme en el semaforo sem.acquire().
     *   2. Inicializa el contador de reducciones del proceso.
     *   3. Ejecuta run_fsm_step() hasta agotar las reducciones o que el
     *      proceso entre en un estado bloqueante o terminal.
     *   4. Si el proceso sigue ejecutable, lo reintroduce en ready_queue.
     *   5. Repite hasta que should_kill sea true.
     *
     * @note Debe ejecutarse en un hilo dedicado; no llamar desde el hilo
     * principal.
     */
    void run_loop();

    /**
     * @brief Genera una representacion textual del scheduler para depuracion.
     * @return Cadena con el ID y el numero de procesos.
     */
    std::string to_string() const;

    /**
     * @brief Reinicia el estado interno del scheduler sin destruirlo.
     */
    void reset();

    /**
     * @brief Inicializa la tabla de transiciones de la FSM (fsm[][]).
     *
     * Debe llamarse una vez antes de que el scheduler comience a ejecutar
     * procesos.  Define los pares (nuevo_estado, accion) para cada combinacion
     * de estado x evento posible.
     */
    void init_fsm();

    /**
     * @brief Indica si hay al menos un proceso vivo en este scheduler.
     *
     * Comprueba el contador alive_count en O(1).
     *
     * @return true si alive_count > 0.
     */
    bool has_alive_processes() const;

    /**
     * @brief Selecciona el proximo proceso de la cola ready_queue.
     *
     * Extrae el primer proceso de la cola (FIFO / round-robin) y lo devuelve.
     * Si la cola esta vacia devuelve nullptr y el scheduler deberia esperar.
     *
     * @return Puntero al proximo proceso listo, o nullptr si la cola esta
     * vacia.
     */
    ProcessVM *schedule_next();

    /**
     * @brief Elimina el proceso con el PID indicado de este scheduler.
     *
     * Transiciona el proceso a DEAD, lo elimina de pid_index y del vector
     * processes.  Decrementa alive_count.
     *
     * @param pid PID global del proceso a eliminar.
     */
    void kill(GlobalPID pid);

    /**
     * @brief Crea un nuevo proceso virtual dentro de este scheduler.
     *
     * Asigna un PID local, construye el ProcessVM y lo registra en pid_index.
     * El proceso nace en estado NEW y no es ejecutable hasta llamar a
     * make_ready().
     *
     * @return PID global del nuevo proceso creado.
     */
    GlobalPID spawn();

    /**
     * @brief Pone el proceso con el PID indicado en estado READY.
     *
     * Inserta el proceso en ready_queue y llama a sem.release() para
     * despertar al scheduler si esta esperando.  Es thread-safe.
     *
     * @param pid PID global del proceso que debe pasar a estado READY.
     */
    void make_ready(GlobalPID pid);

    /**
     * @brief Bandera de parada cooperativa del scheduler.
     *
     * Cuando es true el run_loop() termina al final del quantum actual.
     * Se activa desde VM::stop() para un apagado limpio.
     */
    bool should_kill = false;

    /**
     * @brief Registra un hook de depuracion sin ningun mecanismo de
     * sincronizacion.
     *
     * Solo debe usarse antes de que el scheduler comience a ejecutar procesos.
     * Para uso en tiempo de ejecucion usar add_debug_hook() que protege con
     * mutex.
     *
     * @param hook Callback de depuracion a anadir.
     */
    void free_add_debug_hook(DebugHook hook);

    /**
     * @brief Registra un hook de depuracion de forma thread-safe.
     *
     * Usa un mutex interno para que el hook pueda anadirse mientras el
     * scheduler esta en ejecucion sin causar condiciones de carrera.
     *
     * @param hook Callback de depuracion a anadir.
     */
    void add_debug_hook(DebugHook hook);

    /**
     * @brief Habilita o deshabilita la ejecucion de los hooks de depuracion.
     *
     * Se activa automaticamente al registrar el primer hook con
     * add_debug_hook(). Puede desactivarse en cualquier momento para eliminar
     * la penalizacion de rendimiento de los hooks sin necesidad de eliminarlos.
     */
    bool has_hooks = false;

    /** @brief Destructor: libera todos los procesos y recursos del scheduler.
     */
    ~Scheduler();

    Timer debug_timer{}; ///< Temporizador para medir la duracion de cada fase
                         ///< en modo depuracion

    uint64_t time_decode =
        0; ///< Tiempo acumulado en la fase de descodificacion (en ns)
    uint64_t time_event =
        0; ///< Tiempo acumulado en las transiciones de la FSM (en ns)
    uint64_t time_exec =
        0; ///< Tiempo acumulado en la fase de ejecucion (en ns)
    /// Tiempo acumulado dentro de codigo JIT-eated (en ns).  Incrementado
    /// por @c exec_instr_callvirt cuando dispatcha a @c enter_jit; mide
    /// el wall time real del codigo nativo generado para que las metricas
    /// MIPS/wall-time del programa total reflejen JIT execution.
    uint64_t time_jit = 0;

    // --- Contadores del profiler por hilo ---
    uint64_t profiler_sample = 0; ///< Contador de muestras del profiler
    /// Instrucciones bytecode ejecutadas por el INTERPRETE.  Se incrementa de
    /// UNA EN UNA, en los 24 sitios que retiran una instruccion (el camino
    /// rapido del scheduler y @c decode_instruction).  Es exacto, no una
    /// muestra: comprobado contra la cuenta estatica en `test_mips`.
    ///
    /// Decia "se incrementa cada 256 instrucciones", y no era cierto -- nunca
    /// hubo mascara --, asi que los consumidores que multiplicaban por 256
    /// daban MIPS 256 veces mas altos de lo real.  Al no haber ningun test que
    /// mirara la cifra, el error sobrevivio: el numero era absurdo pero
    /// PLAUSIBLE si nadie tenia con que compararlo.
    uint64_t profiler_instr_counter = 0;
    /// Contador de "instrucciones VM equivalentes" ejecutadas en JIT.
    /// El JIT-eated code emite @c add qword [&counter], N al inicio de
    /// cada metodo, donde N es el numero de IR instructions de ese metodo.
    /// Aproxima cuantas instrucciones bytecode habrian corrido si interp
    /// hubiera ejecutado el mismo metodo.  Las dos cuentas estan en la MISMA
    /// unidad -- instrucciones, sin escalar --, asi que el MIPS total es
    /// (interp + jit) / time / 1M.
    uint64_t profiler_jit_instr_counter = 0;

    std::atomic<bool> profiler_running =
        true; ///< true mientras el profiler deba ejecutarse

    std::atomic<bool> is_waiting{
        false}; ///< true mientras el scheduler esta bloqueado en sem.acquire()

    /**
     * @brief Semaforo binario que permite al scheduler dormir cuando no hay
     * procesos listos.
     *
     * API identica a std::counting_semaphore:
     *   - sem.acquire() bloquea hasta recibir una senyal.
     *   - sem.release() despierta al scheduler desde cualquier hilo
     * (make_ready/stop).
     */
    BinarySemaphore sem;

  private:
};

/**
 * @brief Devuelve el nombre legible de una fase de depuracion.
 *
 * Util para imprimir mensajes de traza junto al valor de DebugStage.
 *
 * @param s Fase de depuracion.
 * @return  Cadena con el nombre de la fase.
 */
static const char *debug_stage_name(DebugStage s) {
    switch (s) {
    case DebugStage::DecodeBegin:
        return "DECODE_BEGIN"; // inicio de descodificacion
    case DebugStage::DecodeEnd: return "DECODE_END"; // fin de descodificacion
    case DebugStage::ExecuteBegin: return "EXEC_BEGIN"; // inicio de ejecucion
    case DebugStage::ExecuteEnd: return "EXEC_END";     // fin de ejecucion
    case DebugStage::OnEventBegin:
        return "EVENT_BEGIN"; // antes del cambio de estado
    case DebugStage::OnEventEnd:
        return "EVENT_END";    // despues del cambio de estado
    default: return "UNKNOWN"; // fase desconocida
    }
}

/**
 * @brief Invoca todos los hooks de depuracion registrados en el scheduler del
 * proceso.
 *
 * Se llama en cada punto del pipeline indicado por @p stage.  Permite
 * implementar trazas, breakpoints, stepping e integracion con depuradores
 * externos sin modificar la logica interna del interprete.
 *
 * Cada hook debe ser rapido y no bloqueante para no degradar el rendimiento.
 *
 * @note Cuando PROFILE_FAST esta definido esta funcion se reemplaza por una
 *       macro vacia para eliminar toda penalizacion de rendimiento.
 *
 * @param process Proceso cuyo scheduler contiene los hooks registrados.
 * @param stage   Fase del pipeline en la que se disparan los hooks.
 */
// PROFILE_FAST activado por defecto en builds Release
// (NDEBUG).  Convierte vm_hook en macro vacia para eliminar 4 llamadas
// de funcion por instruccion VM en el hot path (decode begin/end +
// execute begin/end).  Cuando NDEBUG no esta definido se mantiene la
// version normal por si el usuario quiere registrar hooks de debug.
#if defined(NDEBUG) && !defined(PROFILE_FAST)
#define PROFILE_FAST
#endif

#ifdef PROFILE_FAST
#define vm_hook(...)                                                           \
    do {                                                                       \
    } while (0)
#else
void vm_hook(ProcessVM *process, DebugStage stage);
#endif

/**
 * @brief Hilo de perfilado continuo para un scheduler de la VM.
 *
 * Se ejecuta en paralelo al scheduler y calcula:
 *   - Instrucciones por segundo (IPS): delta de profiler_instr_counter por
 * segundo (el contador va de una en una; no lleva factor de escala).
 *   - Porcentaje de CPU: time_exec (ns acumulados) / 1e9 * 100 por segundo.
 *
 * Interpretacion de resultados:
 *   - IPS alto + CPU bajo  -> VM idle o pocas instrucciones por segundo.
 *   - IPS alto + CPU alto  -> bucle caliente (hot loop).
 *   - IPS bajo + CPU alto  -> instrucciones costosas.
 *
 * Se detiene cuando should_kill o !profiler_running son true.
 *
 * Uso tipico:
 * @code{.cpp}
 * std::thread(&runtime::profiler_thread, scheduler).detach();
 * @endcode
 *
 * @param scheduler Puntero al scheduler cuyas estadisticas se van a perfilar.
 */
void profiler_thread(Scheduler *scheduler);

} // namespace runtime

#endif // SCHEDULER_H
