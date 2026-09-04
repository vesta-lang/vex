/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle_reorder_report.cpp
 * @brief Lo OBSERVABLE del reordenamiento: volcado y telemetria.
 *
 * Aqui no se decide nada.  El planificador vive en `bundle_reorder.cpp` y no
 * sabe que existe este fichero: le devuelve un orden y, cuando alguien va a
 * mirar, le pasa el motivo de cada posicion.
 *
 * La frontera esta puesta a proposito y su razon es de rendimiento, no de
 * estilo: mezclados, el bucle caliente llevaba contadores, banderas y un
 * `fprintf`, y un bucle con efectos observables no se puede optimizar como lo
 * que es -- aritmetica sobre mascaras --.  Separados, la instancia caliente del
 * planificador no contiene ni una instruccion de esto.
 *
 * El texto sale del catalogo multi-idioma.  Se pasan DATOS -- direcciones,
 * cuentas, el nombre del criterio --, nunca frases construidas aqui.
 */

#include "runtime/bundle_reorder_report.h"

#if VM_BUNDLES

#include <cstdio>

#include "runtime/proceso_runtime.h"
#include "vx/diag/diag_catalog.h"

namespace runtime {

void reorder_report_dump(const DecodedInstr *before, const DecodedInstr *after,
                         uint32_t k, uint32_t moved, const uint8_t *why) {
    char addr[32], count[16], nmoved[16];
    std::snprintf(addr, sizeof(addr), "0x%08llx",
                  (unsigned long long)before[0].pc);
    std::snprintf(count, sizeof(count), "%u", k);
    std::snprintf(nmoved, sizeof(nmoved), "%u", moved);
    std::fprintf(stderr, "\n[%s]\n",
                 vx::diag::format("VX7029", {addr, count, nmoved}).c_str());

    /* El motivo del CAMBIO se saca una vez, fuera del bucle: es el mismo texto
     * para todas las lineas que cambiaron y formatearlo por linea seria pedirle
     * al catalogo lo mismo k veces. */
    const std::string changed = vx::diag::format("VX7031", {});

    for (uint32_t i = 0; i < k; ++i) {
        char slot[16], pc[32];
        std::snprintf(slot, sizeof(slot), "%2u", i);
        std::snprintf(pc, sizeof(pc), "0x%08llx",
                      (unsigned long long)after[i].pc);
        const char *reason =
            bundle_reorder_criterion(why != nullptr ? why[i] : 0xFF);
        std::fprintf(stderr, "%s\n",
                     vx::diag::format("VX7030",
                                      {slot, pc, reason,
                                       after[i].pc != before[i].pc
                                           ? changed
                                           : std::string()})
                         .c_str());
    }
}

void reorder_report_stats(ProcessVM *process, uint32_t moved,
                          const uint8_t *why, uint32_t k) {
    /* Sin `#if`: los contadores existen SIEMPRE en `ProcessVM` y aqui se suman
     * siempre.  Lo que decide si se paga es quien llama -- solo la
     * instanciacion que explica llega hasta aqui --, y eso se elige en
     * ejecucion.  Atado al perfil de construccion, mirar la telemetria obligaba
     * a reconstruir y a mirar OTRO binario. */
    process->bundle_stats.reordered += moved;
    if (moved != 0) ++process->bundle_stats.reorder_bundles;
    /* Hubo una eleccion por posicion emitida, y cada una la gano el criterio
     * que dice `why`.  Se deriva de ahi en vez de contarlo en el bucle: el
     * bucle ya lo sabia y llevarlo aparte era contar dos veces lo mismo. */
    process->bundle_stats.reorder_choices += k;
    if (why != nullptr)
        for (uint32_t i = 0; i < k; ++i)
            if (why[i] < kBundleReorderCriteria)
                ++process->bundle_stats.reorder_wins[why[i]];
}

} // namespace runtime

#endif // VM_BUNDLES
