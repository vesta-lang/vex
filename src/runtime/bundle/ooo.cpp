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

#if VM_BUNDLES

#if !defined(_WIN32)
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
NTSTATUS NTAPI NtSetInformationThread(HANDLE ThreadHandle,
                                      ULONG ThreadInformationClass,
                                      PVOID ThreadInformation,
                                      ULONG ThreadInformationLength);
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
NTSTATUS NTAPI NtClose(HANDLE Handle);
}

#endif

namespace runtime {

namespace {

#if defined(_WIN32)
/// `ProcessAffinityMask` y `ThreadAffinityMask`, por su numero: las cabeceras
/// publicas no declaran los enumerados de la capa NT.
constexpr ULONG kProcessAffinityMask = 21;
constexpr ULONG kThreadAffinityMask = 4;

/// Lo que devuelve `NtQueryInformationProcess` para la clase de afinidad.
struct ProcessBasicAffinity {
    ULONG_PTR mask;
};
#endif

/// Girar, coger, ejecutar, avisar.
void worker_loop() {
    for (;;) {
        const uint32_t s = g_ooo.state.load(std::memory_order_acquire);
        if (s == kOooIdle) {
            ooo_pause();
            continue;
        }
        if (s == kOooStop) return;

        /* Las instrucciones de esta mitad no tocan nada de la otra: ni sus
         * registros, ni las banderas, ni la memoria.  Por eso aqui no hay
         * ninguna sincronizacion -- las condiciones estan en la cabecera, y las
         * comprueba `bundle_split_point` al FORMAR. */
        ProcessVM *proc = g_ooo.proc;
        const DecodedInstr *p = g_ooo.instr;
        const uint32_t n = g_ooo.n;
        for (uint32_t i = 0; i < n; ++i) p[i].exec_cached(proc, p[i]);

        g_ooo.state.store(kOooIdle, std::memory_order_release);
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

    // El bit permitido mas alto: 63 - ceros a la izquierda.
    ULONG_PTR bit = (ULONG_PTR)1
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

void ooo_shutdown() {
    if (!g_ooo_started.load(std::memory_order_acquire)) return;
    ooo_join();
    g_ooo.state.store(kOooStop, std::memory_order_release);
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
