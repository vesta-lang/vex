/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/util/cpu_topology.cpp
 * @brief Implementacion de @ref util/cpu_topology.h, una por sistema.
 */

#include "util/cpu_topology.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sched.h>
#endif

namespace util {

namespace {

#if defined(_WIN32)

/**
 * @brief Recorre los nucleos y devuelve la mascara de la clase pedida.
 *
 * La clase la da `EfficiencyClass` del propio sistema -- mayor es mas rapido --
 * y se lee POR POSICION: es el byte que sigue a `Flags` dentro de
 * `PROCESSOR_RELATIONSHIP`.  Las cabeceras de MinGW todavia declaran ese hueco
 * como `Reserved` y el nombre no existe; la posicion si esta documentada y no
 * ha cambiado desde que el campo se anadio.
 *
 * Si el sistema devuelve la misma clase para todos -- maquina homogenea, o
 * Windows anterior a que existiera el campo --, `Fast` sale con todos y `Slow`
 * vacia, que es exactamente lo que promete la cabecera.
 */
uint64_t class_mask_win(CoreClass which) {
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len);
    if (len == 0) return 0;
    /* En la pila y con tope: esto se pregunta una vez, pero reservar aqui
     * meteria al asignador en un camino que no lo necesita. */
    alignas(8) unsigned char buf[8192];
    if (len > sizeof(buf)) return 0;
    auto *first =
        reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf);
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, first, &len))
        return 0;

    /* Dos pasadas sobre el mismo buffer: la primera averigua cual es la clase
     * mas alta y cual la mas baja, la segunda junta a los que toquen.  Con una
     * sola habria que ir descartando lo acumulado cada vez que aparece una
     * clase mejor, que es la misma pasada escrita peor. */
    unsigned best = 0, worst = 255;
    uint64_t acc = 0;
    for (int pass = 0; pass < 2; ++pass) {
        for (DWORD off = 0; off + sizeof(DWORD) * 2 <= len;) {
            auto *info =
                reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf +
                                                                           off);
            if (info->Size == 0) break; // no avanzaria: parar antes de girar
            if (info->Relationship == RelationProcessorCore) {
                const unsigned ec =
                    reinterpret_cast<const unsigned char *>(&info->Processor)[1];
                if (pass == 0) {
                    if (ec > best) best = ec;
                    if (ec < worst) worst = ec;
                } else {
                    const unsigned want =
                        (which == CoreClass::Fast) ? best : worst;
                    if (ec == want)
                        for (WORD g = 0; g < info->Processor.GroupCount; ++g)
                            acc |= (uint64_t)info->Processor.GroupMask[g].Mask;
                }
            }
            off += info->Size;
        }
        /* Homogenea: una sola clase.  `Fast` son todos -- se calcula en la
         * segunda pasada -- y `Slow` se queda vacia, que es lo prometido. */
        if (pass == 0 && best == worst && which == CoreClass::Slow) return 0;
    }
    return acc;
}

#else

/**
 * @brief Lo mismo en Linux, donde el nucleo lo publica como DOS PMU distintas.
 *
 * En las maquinas hibridas de Intel el kernel expone `/sys/devices/cpu_core` y
 * `/sys/devices/cpu_atom`, cada una con la lista de procesadores de su clase.
 * En una homogenea no existen y solo hay `/sys/devices/cpu`, asi que el fichero
 * no abre y la respuesta es "no se" -- que para `Fast` significa "no hace falta
 * elegir" y para `Slow` "no hay" --.
 */
uint64_t class_mask_linux(CoreClass which) {
    const char *ruta = (which == CoreClass::Fast)
                           ? "/sys/devices/cpu_core/cpus"
                           : "/sys/devices/cpu_atom/cpus";
    std::FILE *f = std::fopen(ruta, "r");
    if (f == nullptr) return 0;
    char txt[256] = {};
    const size_t n = std::fread(txt, 1, sizeof(txt) - 1, f);
    std::fclose(f);
    if (n == 0) return 0;

    /* El formato son rangos separados por comas: "0-15" o "0-7,16-19".  Se
     * recorre a mano en vez de con `sscanf` en bucle porque hay que distinguir
     * el rango del suelto, y son cuatro lineas. */
    uint64_t acc = 0;
    const char *p = txt;
    while (*p != '\0') {
        if (*p < '0' || *p > '9') {
            ++p;
            continue;
        }
        unsigned a = 0;
        while (*p >= '0' && *p <= '9') a = a * 10u + (unsigned)(*p++ - '0');
        unsigned b = a;
        if (*p == '-') {
            ++p;
            b = 0;
            while (*p >= '0' && *p <= '9') b = b * 10u + (unsigned)(*p++ - '0');
        }
        for (unsigned c = a; c <= b && c < 64u; ++c) acc |= (uint64_t)1 << c;
    }
    return acc;
}

#endif

} // namespace

uint64_t cpu_class_mask(CoreClass which) {
#if defined(_WIN32)
    return class_mask_win(which);
#else
    return class_mask_linux(which);
#endif
}

bool cpu_is_hybrid() {
    return cpu_class_mask(CoreClass::Slow) != 0;
}

uint64_t cpu_one_of_class(CoreClass which) {
    const uint64_t m = cpu_class_mask(which);
    return m & (~m + 1); // el bit mas bajo, o 0 si no habia ninguno
}

bool pin_process(uint64_t mask) {
    if (mask == 0) return false;
#if defined(_WIN32)
    /* Solo lo que el sistema permite de verdad: pedir un procesador que no
     * esta en la mascara del sistema falla entera y el proceso se queda como
     * estaba, que es un "no se pudo" mudo. */
    DWORD_PTR proc_mask = 0, sys_mask = 0;
    if (GetProcessAffinityMask(GetCurrentProcess(), &proc_mask, &sys_mask) == 0)
        return false;
    const DWORD_PTR want = (DWORD_PTR)mask & sys_mask;
    if (want == 0) return false;
    return SetProcessAffinityMask(GetCurrentProcess(), want) != 0;
#else
    cpu_set_t set;
    CPU_ZERO(&set);
    for (unsigned c = 0; c < 64u; ++c)
        if ((mask >> c) & 1u) CPU_SET(c, &set);
    /* Con pid 0 es "este proceso", y en Linux la afinidad de proceso la
     * heredan los hilos nuevos igual que en Windows. */
    return sched_setaffinity(0, sizeof(set), &set) == 0;
#endif
}

bool pin_current_thread(uint64_t mask) {
    if (mask == 0) return false;
#if defined(_WIN32)
    /* Se cruza con lo que el PROCESO tiene permitido: pedir un procesador que
     * no lo esta falla entera, y entonces el hilo se queda donde estaba sin que
     * nadie se entere. */
    DWORD_PTR proc_mask = 0, sys_mask = 0;
    if (GetProcessAffinityMask(GetCurrentProcess(), &proc_mask, &sys_mask) == 0)
        return false;
    const DWORD_PTR want = (DWORD_PTR)mask & proc_mask;
    if (want == 0) return false;
    return SetThreadAffinityMask(GetCurrentThread(), want) != 0;
#else
    cpu_set_t set;
    CPU_ZERO(&set);
    for (unsigned c = 0; c < 64u; ++c)
        if ((mask >> c) & 1u) CPU_SET(c, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0;
#endif
}

} // namespace util
