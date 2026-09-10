/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle/ooo.cpp
 * @brief El hilo ayudante: arrancarlo, su bucle y pararlo.
 *
 * Aqui vive SOLO lo que corre una vez.  El traspaso -- que se paga por paquete
 * ejecutado -- esta en la cabecera y en linea: ver `runtime/bundle/ooo.h`.
 */

#include "runtime/bundle/ooo.h"

#include "runtime/bundle/predecode.h"
#include "runtime/decode_instruction.h"
#include "util/cpu_topology.h"

#if VM_BUNDLES

#if !defined(_WIN32)
#include <chrono> // el plazo del ayudante cuando se queda sin encargos
#include <thread> // fuera de Windows no hay capa NT: aqui es la via directa
#endif

#if defined(_WIN32)
#include <windows.h>
#include <winternl.h> // NTSTATUS y NTAPI, como en `util/file_read.cpp`
#endif

#if defined(_WIN32)

/* Se enlazan (ntdll) en vez de resolverse con GetProcAddress, que es como ya lo
 * hace `util::read_whole_file`: nada que resolver al arrancar, ningun puntero
 * que comprobar, y si un simbolo faltase el fallo saldria al cargar el proceso
 * y no a mitad de una ejecucion.
 *
 * Aqui van las DOS que hacen falta, y solo esas: preguntar que procesadores
 * tiene permitidos el proceso y atar el ayudante a uno.  El traspaso en si no
 * llama a nada -- son atomicas --, asi que por debajo de esto no hay mas que
 * quitar. */
/* `NtQueryInformationProcess` ya la declara `winternl.h`, con
 * `PROCESSINFOCLASS` en vez de `ULONG`; volver a declararla choca.  La otra no
 * esta ahi, asi que es la unica que hay que traer. */
extern "C" {
/* Lo mismo que le pasa a `NtQueryInformationProcess` justo arriba, pero solo
 * con el Windows SDK: ahi `NtSetInformationThread` YA esta declarada, y con
 * `THREADINFOCLASS` en vez de `ULONG`, asi que volver a declararla choca.  El
 * `winternl.h` de MinGW no la trae y hay que seguir poniendola. */
#if !defined(_MSC_VER)
NTSTATUS NTAPI NtSetInformationThread(HANDLE ThreadHandle,
                                      ULONG ThreadInformationClass,
                                      PVOID ThreadInformation,
                                      ULONG ThreadInformationLength);
#endif
/* Crear el hilo tambien por la capa NT.  `std::thread` en MinGW pasa por
 * winpthreads, que es otra capa encima de Win32 encima de esto; y `CreateThread`
 * es Win32 encima de esto.  Aqui no se gana tiempo -- el hilo se crea UNA vez --
 * pero se quita una dependencia entera de una biblioteca de hilos para algo que
 * son tres llamadas, y el proyecto ya baja a NT en otros sitios. */
NTSTATUS NTAPI NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes,
                                HANDLE ProcessHandle, PVOID StartRoutine,
                                PVOID Argument, ULONG CreateFlags,
                                SIZE_T ZeroBits, SIZE_T StackSize,
                                SIZE_T MaximumStackSize, PVOID AttributeList);
NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
                                     PLARGE_INTEGER Timeout);
/* Dormir un plazo exacto.  `Sleep` de Win32 es esto con la resolucion del
 * temporizador de por medio y en milisegundos; aqui el plazo son decenas de
 * microsegundos, asi que hace falta la unidad de 100 ns. */
NTSTATUS NTAPI NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER Interval);
NTSTATUS NTAPI NtClose(HANDLE Handle);
}

#endif

namespace runtime {

namespace {

#if defined(_WIN32)
/// `ProcessAffinityMask` y `ThreadAffinityMask`, por su numero: las cabeceras
/// publicas no declaran los enumerados de la capa NT.
constexpr ULONG kProcessAffinityMask = 21;
/* El tipo lo manda QUIEN declara la funcion.  Con el Windows SDK el segundo
 * parametro es `THREADINFOCLASS`, que es un enum y al que un `ULONG` NO
 * convierte solo; con MinGW la declaramos nosotros tomando `ULONG`.  Se ajusta
 * la constante y no el sitio de llamada, que asi se queda igual en los dos. */
#if defined(_MSC_VER)
constexpr THREADINFOCLASS kThreadAffinityMask = static_cast<THREADINFOCLASS>(4);
#else
constexpr ULONG kThreadAffinityMask = 4;
#endif

/// Lo que devuelve `NtQueryInformationProcess` para la clase de afinidad.
struct ProcessBasicAffinity {
    ULONG_PTR mask;
};
#endif

/**
 * @brief Vueltas en caliente antes de soltar el nucleo.
 *
 * El margen que hay que cubrir es el hueco entre dos entregas seguidas, que
 * son ~100 ns -- lo que tarda el principal en ejecutar su propio paquete --.
 * Con 20.000 vueltas de `pause` se cubre de sobra (decenas de microsegundos) y
 * aun asi un programa que no delega nunca deja de girar enseguida.
 */
constexpr uint32_t kOooSpinIdle = 20000;

/**
 * @brief Se duerme hasta que `head` deje de valer @p seen.
 *
 * NO es un plazo.  Dormir un rato corto parece lo simple y no lo es: el plazo
 * de Windows se redondea a la resolucion del temporizador, asi que pedir 50 us
 * duerme ~15 ms de verdad.  Con eso, el primer encargo tras un silencio se
 * quedaba esperando milisegundos, la cola se llenaba entera -- 32.806 rechazos
 * por "cola llena" en 32.821 despachos -- y no se delegaba NADA: 56 MIPS donde
 * habia 454.
 *
 * Esperar sobre la direccion no tiene ese problema y ademas cierra la carrera
 * del aviso perdido el mismo: el sistema comprueba que `head` siga valiendo
 * @p seen ANTES de dormir, asi que un encargo publicado mientras tanto lo
 * despierta aunque el productor no llegara a ver la marca.
 *
 * La marca se publica con orden secuencial -- en x86 es un `xchg`, o sea
 * barrera completa -- para que el productor no pueda leerla vieja Y ademas
 * escaparse de la relectura de `head`.  Es el unico lado que necesita barrera;
 * el productor solo lee.
 */
void ooo_idle_wait(uint32_t seen) {
    g_ooo.parked.store(1, std::memory_order_seq_cst);
#if defined(_WIN32)
    /* El plazo es una RED, no el mecanismo: si algun dia se colara un aviso
     * perdido, esto lo convierte en un retraso y no en un bloqueo. */
    DWORD ms = 20;
    WaitOnAddress(&g_ooo.head, &seen, sizeof(seen), ms);
#else
    /* Fuera de Windows el plazo corto SI es corto -- `nanosleep` tiene
     * resolucion de microsegundos --, asi que aqui basta con dormir poco y
     * volver a mirar; no hace falta ningun aviso. */
    (void)seen;
    std::this_thread::sleep_for(std::chrono::microseconds(50));
#endif
    g_ooo.parked.store(0, std::memory_order_relaxed);
}

/**
 * @brief Girar sobre la cola: coger un encargo, ejecutarlo, avanzar.
 *
 * El indice `tail` se publica DESPUES de ejecutar, nunca antes: es lo que le
 * dice al productor que ese encargo ya termino, y adelantarlo dejaria a
 * `ooo_drain` volviendo con trabajo a medias.
 *
 * Y se avanza de uno en uno aunque haya varios encolados.  Publicar el ultimo y
 * ya seria menos trafico entre nucleos, pero entonces el productor no sabria
 * cuantas ranuras tiene libres hasta el final de la tanda y la cola se
 * comportaria como una sola ranura grande -- que es justo lo que se quiere
 * evitar.
 */
void worker_loop() {
    /* La cache de pagina DE ESTE HILO.
     *
     * Es lo que le permite leer bytecode del proceso -- la fusion mira que
     * registros siguen vivos detras del paquete, y eso descodifica hasta ocho
     * instrucciones mas alla --.  Con la cache del objeto seria una carrera, y
     * de las que no fallan: fusionaba MAL y el programa devolvia 0 donde
     * esperaba 19.  Vive fuera del bucle para que los encargos seguidos
     * aprovechen la pagina del anterior. */
    vm::VirtualMemory::PageView page_view;
    /* La epoca que corresponde a lo que hay cacheado arriba.  Cuando un proceso
     * muere, sus paginas se liberan y el puntero de anfitrion que guarda la
     * cache pasa a ser de otro; ver `ooo_new_epoch`. */
    uint32_t epoch_seen = g_ooo_epoch.load(std::memory_order_acquire);
    /* Vueltas seguidas sin encargo.  Es lo que decide cuando dejar de girar en
     * caliente y CEDER el nucleo -- ver el bloque de abajo. */
    uint32_t idle = 0;
    for (;;) {
        const uint32_t t = g_ooo.tail.load(std::memory_order_relaxed);
        /* `acquire` sobre `head`: si hay encargo nuevo, su ranura tiene que
         * verse ya escrita.  Es el otro lado del `release` de `ooo_push`. */
        const uint32_t h = g_ooo.head.load(std::memory_order_acquire);
        if (t == h) {
            if (__builtin_expect(g_ooo.stop.load(std::memory_order_relaxed) != 0,
                                 0))
                return;
            /* GIRAR EN CALIENTE UN RATO, Y DESPUES SOLTAR EL NUCLEO.
             *
             * Girar sin fin le cuesta al principal aunque no se delegue NADA, y
             * no poco: medido en la mezcla `independiente` con el motor
             * escalar -- que no forma paquetes, o sea que no hay un solo
             * encargo que dar --, 280 MIPS sin ayudante contra 252-263 con el.
             * Entre un 6% y un 10% por un hilo que no hace nada.  El `pause`
             * cede el hermano SMT dentro del nucleo, pero no cede el NUCLEO: el
             * planificador del sistema sigue viendo un hilo listo y le da
             * turno, y donde caiga se lo quita a alguien.
             *
             * Asi que se gira en caliente lo justo para no perder la tuberia
             * -- entre dos entregas seguidas pasan ~100 ns, unas pocas
             * decenas de vueltas -- y pasado ese margen se duerme de verdad.
             *
             * Y se duerme SOBRE `head`, no un plazo: ver `ooo_idle_wait`. */
            /* SIN espaciar las miradas, y se probo.
             *
             * El perfil dice que este bucle se va en un 60% a esperar lineas
             * del otro nucleo: cada lectura de `head` se la trae en compartido
             * y la escritura siguiente del productor tiene que quitarsela.
             * Mirar cada vez menos parecia lo obvio, y medido no compensa:
             * baja la varianza pero se come el mejor caso -- sin espaciar
             * aparecen corridas de 450 y 385 MIPS cuando el sistema separa
             * bien los dos hilos, y con espaciado no pasa de 311, porque
             * recoger el encargo tarde alarga la juntada --. */
            if (++idle < kOooSpinIdle) {
                ooo_pause();
                continue;
            }
            ooo_idle_wait(h);
            continue;
        }
        idle = 0;

        /* SOLTAR la pagina cacheada si de por medio murio un proceso.
         *
         * Una carga relajada por encargo -- no por byte -- de una linea que
         * casi nunca cambia.  Sin esto la cache acierta con un puntero a
         * memoria ya liberada y se descodifica lo que otro haya puesto ahi:
         * ver `ooo_new_epoch`, que cuenta el caso que lo destapo. */
        const uint32_t epoch_now = g_ooo_epoch.load(std::memory_order_acquire);
        if (__builtin_expect(epoch_now != epoch_seen, 0)) {
            epoch_seen = epoch_now;
            page_view = vm::VirtualMemory::PageView{};
        }

        const OooJob &job = g_ooo.job[t & (kOooSlots - 1)];
        ProcessVM *proc = job.proc;
        if (job.kind == OooKind::Execute) {
            /* Lo de este encargo no toca nada de lo que el principal esta
             * haciendo: ni sus registros, ni las banderas, ni su memoria.  Por
             * eso aqui no hay ninguna sincronizacion -- las condiciones estan
             * en la cabecera y las comprueba el productor contra el resumen
             * del paquete antes de encolarlo. */
            const DecodedInstr *p = job.instr;
            const uint32_t n = job.n;
            for (uint32_t i = 0; i < n; ++i) p[i].exec_cached(proc, p[i]);
            /* Nada mas que hacer: el avance de `tail` que hay al final del
             * bucle lo publica con `release`, y ESO es lo que le dice al
             * principal que los registros que se acaban de escribir ya se ven.
             * Antes habia aqui un contador atomico aparte -- una segunda linea
             * disputada y un RMW por entrega -- que decia lo mismo dos veces.
             * Ver `g_ooo_exec_mark`. */
        } else if (job.kind == OooKind::Decode) {
            /* DESCODIFICAR POR ADELANTADO el tramo que viene.
             *
             * Es el encargo mas caro que se puede quitar del camino critico:
             * descodificar es el 5,7% del banco, cinco veces lo que cuesta
             * formar paquetes.  Y es independiente por construccion -- una
             * funcion del bytecode, que ya esta --, asi que no hace falta
             * ninguna condicion sobre registros ni memoria.
             *
             * Se para en cuanto una direccion no se puede leer o el opcode no
             * existe: seguir seria adelantar basura, y adelantar basura no la
             * hace mas util -- el principal la descartaria igual --.
             *
             * NO se sigue a traves de saltos: se avanza secuencialmente.  A
             * donde va un salto depende de banderas que solo existen
             * ejecutando, y aqui no se ejecuta nada. */
            uint64_t pc = job.next_pc;
            for (uint32_t i = 0; i < job.n; ++i) {
                DecodedInstr d;
                if (!decode_peek(proc, pc, d, &page_view)) break;
                const uint32_t size = d.flags_info.size_instr;
                if (size == 0) break; // no avanzaria: parar antes de girar
                predecode_publish(pc, d);
                pc += size;
            }
        } else {
            /* PREPARAR: reordenar y fusionar una copia que nadie mas mira.
             *
             * No depende de ningun registro ni de ninguna memoria del programa
             * -- es una funcion de las instrucciones, y esas ya estan --, asi
             * que puede correr mientras el principal ejecuta el paquete crudo.
             *
             * Al terminar se publica el puntero con `release`: quien ejecuta lo
             * lee con `acquire` y solo entonces mira el contenido, que para
             * entonces ya esta escrito entero. */
            bundle_prepare_worker(proc, *job.scratch, job.next_pc, page_view);
            __atomic_store_n(&job.target->improved, job.scratch,
                             __ATOMIC_RELEASE);
        }

        g_ooo.tail.store(t + 1, std::memory_order_release);
    }
}

#if defined(_WIN32)

/// El hilo, por su handle NT.  Sin `std::thread` ni `CreateThread`.
HANDLE g_worker = nullptr;

/// Punto de entrada, con la convencion que espera el sistema.
DWORD WINAPI worker_entry(LPVOID) {
    worker_loop();
    return 0;
}

/**
 * @brief Ata el ayudante a un procesador lejos del que usa el hilo principal.
 *
 * NO es un afinado fino: es una CONDICION para que la prueba valga.  El
 * ayudante espera GIRANDO, asi que si el sistema lo coloca en el hermano SMT del
 * hilo principal los dos comparten las mismas unidades de ejecucion y van a
 * media velocidad -- y entonces la medida diria que el paralelismo no compensa
 * cuando lo que no compensa es la colocacion.
 *
 * Se ata al procesador permitido MAS ALTO.  El principal suele arrancar en los
 * bajos, asi que el mas alto cae en otro nucleo fisico sin tener que preguntar
 * en cual esta el principal -- que ademas cambiaria en cuanto el sistema lo
 * mueva --.
 *
 * Si algo falla se sigue igual: quedarse sin afinidad empeora la medida, no la
 * rompe, y abortar por esto seria peor.
 */

void pin_worker_high(HANDLE h) {
    ProcessBasicAffinity info{};
    if (NtQueryInformationProcess(GetCurrentProcess(),
                                  (PROCESSINFOCLASS)kProcessAffinityMask, &info,
                                  sizeof(info), nullptr) < 0)
        return;
    if (info.mask == 0) return;

    /* Los rapidos si se puede saber cuales, y solo los que el proceso tenga
     * permitidos.  Si no se sabe, el bit permitido mas alto, que es lo que
     * habia: en una maquina homogenea sigue siendo la eleccion correcta.
     *
     * La clase ENTERA, no uno: clavarlo en un procesador lo pone a pelearse con
     * el hilo principal, que va suelto, y eso se midio -- 265 MIPS de 500 casi
     * siempre, y 457 las veces que el sistema los separaba por suerte --.  Con
     * la clase entera se consigue lo unico que hace falta, que no acabe en un
     * nucleo lento, sin quitarle al sistema lo que sabe hacer: apartarlo de
     * donde ya hay alguien trabajando.
     *
     * Que la topologia la conteste `util::cpu_class_mask` y no este fichero es
     * a proposito: el banco de MIPS necesita el mismo dato para atar sus
     * medidas, y un hecho tiene un solo productor. */
    ULONG_PTR bit =
        (ULONG_PTR)::util::cpu_class_mask(::util::CoreClass::Fast) &
        (ULONG_PTR)info.mask;
    if (bit == 0)
        bit = (ULONG_PTR)1
              << (63 - (unsigned)__builtin_clzll((uint64_t)info.mask));
    NtSetInformationThread(h, kThreadAffinityMask, &bit, sizeof(bit));
}

#else

std::thread g_worker;

/// Fuera de Windows no hay capa NT: aqui `std::thread` es la via directa, no
/// una capa de mas.  La afinidad se deja al sistema.
void pin_worker_high(std::thread &) {}

#endif

} // namespace

void ooo_start() {
    /* UNA sola vez, aunque dos procesos entren a la vez: se compara e
     * intercambia, y el que pierde sigue en serie esta vuelta. */
    bool expected = false;
    if (!g_ooo_started.compare_exchange_strong(expected, true,
                                               std::memory_order_acq_rel))
        return;
#if defined(_WIN32)
    HANDLE h = nullptr;
    if (NtCreateThreadEx(&h, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(),
                         (PVOID)&worker_entry, nullptr, 0, 0, 0, 0,
                         nullptr) < 0) {
        // Sin ayudante se sigue en serie; no es un fallo del programa.
        g_ooo_started.store(false, std::memory_order_release);
        return;
    }
    g_worker = h;
    pin_worker_high(h);
#else
    g_worker = std::thread(&worker_loop);
    pin_worker_high(g_worker);
#endif
}

void ooo_wake() {
#if defined(_WIN32)
    WakeByAddressSingle(&g_ooo.head);
#endif
}

void ooo_shutdown() {
    if (!g_ooo_started.load(std::memory_order_acquire)) return;
    // Primero que acabe lo encolado, y solo despues la senyal de parar: al
    // reves se perderia trabajo ya publicado.
    ooo_drain_all();
    g_ooo.stop.store(1, std::memory_order_release);
    /* Y despertarlo: la senyal de parar se mira al ver la cola vacia, y si esta
     * dormido no la ve.  Sin esto, parar se quedaba esperando al plazo de la
     * red -- que existe justo para que un descuido asi no bloquee, pero
     * depender de el seria dejarlo a proposito. */
    ooo_wake();
#if defined(_WIN32)
    if (g_worker != nullptr) {
        NtWaitForSingleObject(g_worker, FALSE, nullptr);
        NtClose(g_worker);
        g_worker = nullptr;
    }
#else
    if (g_worker.joinable()) g_worker.join();
#endif
    g_ooo_started.store(false, std::memory_order_release);
}

} // namespace runtime

#endif // VM_BUNDLES
