/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/predecode.h
 * @brief Instrucciones que el ayudante descodifico POR ADELANTADO.
 *
 * POR QUE
 * -------
 * Descodificar es, con diferencia, lo mas caro que hay fuera de ejecutar.
 * Perfilado con contadores de hardware sobre el banco entero:
 *
 *     decode_impl<true>                 6,25 s de 110   (5,7%)
 *     bundle_try_form                   1,26 s          (1,2%)
 *
 * O sea CINCO VECES lo que cuesta formar paquetes, que es lo que ya se le da al
 * ayudante.  Y es trabajo independiente por construccion, igual que reordenar y
 * fusionar: descodificar es una funcion del bytecode, y el bytecode ya esta.
 *
 * POR QUE UNA TABLA APARTE Y NO LA ICACHE
 * ---------------------------------------
 * Porque la icache la lee el hilo principal en cada instruccion.  Escribir una
 * entrada de 64 bytes desde otro hilo dejaria al lector viendo media entrada
 * vieja y media nueva, y eso no da un error: ejecuta otra cosa.
 *
 * Asi que el ayudante escribe AQUI, y el principal copia de aqui a su icache
 * cuando falla.  Lo que se ahorra es la descodificacion; lo que se paga es una
 * copia de 64 bytes, que es lo mismo que ya hace el camino de fallo.
 *
 * COMO SE PUBLICA SIN CARRERA
 * ---------------------------
 * Con un contador de version por ranura -- par = estable, impar = escribiendose
 * --.  Es el patron clasico de un escritor y varios lectores, y aqui encaja
 * porque el lector puede RENDIRSE: si pilla la ranura a medias, descodifica el
 * mismo, que es lo que hacia antes.  No hay que esperar a nadie.
 *
 *      AYUDANTE                          PRINCIPAL
 *      --------                          ---------
 *      seq++            (impar)
 *      escribe pc + d                    s1 = seq   (si es impar -> fallo)
 *      seq++            (par)            copia d
 *                                        s2 = seq   (si s1 != s2 -> fallo)
 *
 * Un fallo aqui no es un error: es "descodifica tu", que siempre vale.
 */

#ifndef VESTA_RUNTIME_BUNDLE_PREDECODE_H
#define VESTA_RUNTIME_BUNDLE_PREDECODE_H

#include <atomic>
#include <cstdint>
#include <cstring>

#include "runtime/proceso_runtime.h"

#if VM_BUNDLES

namespace runtime {

/// Ranuras de la tabla.  Potencia de dos: el indice es un AND.  512 entradas
/// son ~38 KB, holgado frente a los 256 KB de la icache y suficiente para ir
/// por delante en un tramo recto.
constexpr uint32_t kPreDecodeSlots = 512;

/// Una instruccion adelantada, con su version.
struct PreDecodeSlot {
    /// Par = estable, impar = el ayudante la esta escribiendo.  Empieza en par
    /// con `pc` imposible, o sea vacia.
    std::atomic<uint32_t> seq{0};
    uint64_t pc = UINT64_MAX;
    DecodedInstr d{};
};

/// La tabla.  Una sola, como el ayudante: se esta midiendo si esto compensa.
struct PreDecodeTable {
    PreDecodeSlot slot[kPreDecodeSlots];
};

inline PreDecodeTable g_predecode;

/// Donde cae @p pc.  Por los bits bajos, que es lo que separa instrucciones
/// consecutivas: un tramo recto ocupa ranuras seguidas y no se pisa a si mismo.
[[gnu::always_inline]] inline uint32_t predecode_index(uint64_t pc) {
    return (uint32_t)(pc) & (kPreDecodeSlots - 1);
}

/**
 * @brief El ayudante deja @p d como la instruccion de @p pc.
 *
 * Solo lo llama el ayudante.  Con dos escritores haria falta un candado, y no
 * lo hay: el hilo principal solo LEE de aqui.
 */
inline void predecode_publish(uint64_t pc, const DecodedInstr &d) {
    PreDecodeSlot &s = g_predecode.slot[predecode_index(pc)];
    const uint32_t v = s.seq.load(std::memory_order_relaxed);
    // Impar: "no te fies de lo que leas hasta que vuelva a ser par".
    s.seq.store(v + 1, std::memory_order_release);
    /* El contenido va DESPUES de anunciar que esta cambiando, y antes de
     * anunciar que ya esta.  Las dos barreras hacen falta: sin la primera, el
     * lector podria ver bytes nuevos con la version vieja. */
    std::atomic_thread_fence(std::memory_order_release);
    s.pc = pc;
    s.d = d;
    std::atomic_thread_fence(std::memory_order_release);
    s.seq.store(v + 2, std::memory_order_release);
}

/**
 * @brief El principal busca @p pc.  Copia en @p out y devuelve true si estaba.
 *
 * Se RINDE en cuanto algo no cuadra -- ranura a medias, o cambiada mientras se
 * copiaba --, porque rendirse aqui no cuesta nada: quien llama descodifica, que
 * es lo que hacia antes de que esto existiera.
 */
[[gnu::always_inline]] inline bool predecode_probe(uint64_t pc,
                                                   DecodedInstr &out) {
    PreDecodeSlot &s = g_predecode.slot[predecode_index(pc)];
    const uint32_t v1 = s.seq.load(std::memory_order_acquire);
    if ((v1 & 1u) != 0) return false; // la estan escribiendo
    if (s.pc != pc) return false;     // es de otra direccion
    out = s.d;
    std::atomic_thread_fence(std::memory_order_acquire);
    // Si cambio mientras se copiaba, lo copiado no vale.
    return s.seq.load(std::memory_order_relaxed) == v1;
}

/// Vacia la tabla.  Al morir el proceso: las direcciones de otro no valen, y
/// una entrada vieja con el `pc` de una nueva daria OTRA instruccion.
inline void predecode_clear() {
    for (uint32_t i = 0; i < kPreDecodeSlots; ++i) {
        PreDecodeSlot &s = g_predecode.slot[i];
        const uint32_t v = s.seq.load(std::memory_order_relaxed);
        s.seq.store(v + 1, std::memory_order_release);
        s.pc = UINT64_MAX;
        s.seq.store(v + 2, std::memory_order_release);
    }
}

} // namespace runtime

#endif // VM_BUNDLES
#endif // VESTA_RUNTIME_BUNDLE_PREDECODE_H
