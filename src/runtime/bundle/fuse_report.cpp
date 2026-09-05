/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle/fuse_report.cpp
 * @brief Telemetria de la fusion: nombres, sondeo y volcado.
 *
 * Ver `include/runtime/bundle/fuse_report.h` para por que esta separado.
 */

#include "runtime/bundle/fuse_report.h"

#if VM_BUNDLES

#include <cstdio>

#include "runtime/instr_db_vm.h" // el NOMBRE del opcode que falta por cubrir

namespace runtime {

const char *fuse_reject_name(FuseReject r) {
    switch (r) {
    case FuseReject::None: return "se fusiona";
    case FuseReject::NotAMov: return "la 1a no encaja en ningun patron";
    case FuseReject::NoThreeOpForm: return "la 2a no tiene forma de 3 operandos";
    case FuseReject::WidthMismatch: return "no operan a 64 bits";
    case FuseReject::DestMismatch: return "la ALU no escribe el destino del mov";
    case FuseReject::SrcIsDest: return "la 2a fuente ES el destino";
    case FuseReject::TooMany: return "no cabe en `absorbed` o en `size_instr`";
    case FuseReject::CopyMismatch: return "la 2a no consume lo que produjo la 1a";
    case FuseReject::DestLiveOut: return "el temporal sigue VIVO";
    }
    return "?";
}

namespace {

/**
 * @brief Imprime los ocho opcodes con mas peso de un histograma de 512.
 *
 * @param hist  Contadores, indexados por `(extendida ? 256 : 0) + opcode`.
 * @param title Que significa esta lista, para la linea de cabecera.
 */
[[gnu::cold]] void dump_opcode_top(const uint64_t *hist, const char *title) {
    struct Row {
        uint64_t n;
        uint32_t idx;
    };
    Row top[8] = {};
    uint64_t total = 0;
    for (uint32_t i = 0; i < 512; ++i) {
        const uint64_t n = hist[i];
        if (n == 0) continue;
        total += n;
        // Insercion directa en ocho huecos: no hace falta ordenar 512.
        uint32_t worst = 0;
        for (uint32_t k = 1; k < 8; ++k)
            if (top[k].n < top[worst].n) worst = k;
        if (n > top[worst].n) top[worst] = {n, i};
    }
    if (total == 0) return;

    std::fprintf(stderr, "           %s, de %llu:\n", title,
                 (unsigned long long)total);
    for (uint32_t pos = 0; pos < 8; ++pos) {
        // El mayor que quede sin imprimir, para que salgan ordenados.
        uint32_t best = 8;
        for (uint32_t k = 0; k < 8; ++k)
            if (top[k].n != 0 && (best == 8 || top[k].n > top[best].n)) best = k;
        if (best == 8) break;
        const bool ext = top[best].idx >= 256;
        const uint8_t op = (uint8_t)(top[best].idx & 0xFF);
        const vm_isa::VmInstr *v = vm_isa::vm_instr(ext, op);
        std::fprintf(stderr, "             %-12s /%02X  %10llu (%.1f%%)\n",
                     v != nullptr && v->name != nullptr ? v->name : "?",
                     (unsigned)op, (unsigned long long)top[best].n,
                     100.0 * (double)top[best].n / (double)total);
        top[best].n = 0;
    }
}

} // namespace

void probe_new_opcode(const Touch &ta, const Touch &tb, uint16_t live_after,
                      Bundle &b, const FuseTelemetry &tel) {
    if (ta.barrier || tb.barrier) return;
    // La primera tiene que producir UN valor, y la segunda leerlo.
    const uint16_t produced = (uint16_t)(ta.reg_write & ~ta.reg_read);
    const uint16_t passed = (uint16_t)(produced & tb.reg_read);
    if (passed == 0) return;
    /* Se apunta DOS veces a proposito: en el proceso, que da el recuento por
     * pares formados, y en el PAQUETE, que es lo unico que despues se puede
     * multiplicar por las veces que se entra.  Sin la segunda, un sitio
     * caliente y uno de arranque pesan igual. */
    if ((passed & live_after) != 0) {
        *tel.newop_livewall += 1;
        if (b.newop_livewall < 255) ++b.newop_livewall;
    } else {
        *tel.newop_ready += 1;
        if (b.newop_ready < 255) ++b.newop_ready;
    }
}

void fuse_dump(const ProcessVM *process) {
    const auto &s = process->bundle_stats;

    uint64_t rejects = 0;
    for (size_t i = 1; i < kFuseRejectCount; ++i) rejects += s.fuse_reject[i];
    if (rejects != 0) {
        std::fprintf(stderr,
                     "           no fusionados, por que (mirada ciega=%llu de "
                     "%llu formados):\n",
                     (unsigned long long)s.lookahead_blind,
                     (unsigned long long)s.formed);
        for (size_t i = 1; i < kFuseRejectCount; ++i) {
            if (s.fuse_reject[i] == 0) continue;
            std::fprintf(stderr, "             %-38s %10llu (%.1f%%)\n",
                         fuse_reject_name((FuseReject)i),
                         (unsigned long long)s.fuse_reject[i],
                         100.0 * (double)s.fuse_reject[i] / (double)rejects);
        }
    }

    /* Y cuanto capturaria un opcode que NO existe.  Son los dos numeros que
     * deciden si merece la pena gastar una ranura, y hay que leerlos juntos: el
     * segundo es el material que NINGuN opcode rescataria, porque el temporal
     * sigue vivo y habria que escribirlo igual. */
    if (s.newop_ready != 0 || s.newop_livewall != 0)
        std::fprintf(stderr,
                     "           un opcode nuevo cogeria=%llu pares; no "
                     "cogeria=%llu (el temporal sigue vivo)\n",
                     (unsigned long long)s.newop_ready,
                     (unsigned long long)s.newop_livewall);

    /* QUE FALTA POR CUBRIR, por los dos lados y por peso.
     *
     * Los dos buckets grandes -- "la primera no encaja" y "la segunda no vale"
     * -- por si solos no dicen nada: no distinguen "no hay material" de "hay
     * material y no lo miro".  Con el opcode delante se convierten en la lista
     * de trabajo, ordenada, y deja de hacer falta adivinar cual escribir.
     *
     * Y hacen falta LOS DOS: al cubrir un patron nuevo, sus pares se mudan del
     * primer bucket al segundo, asi que con uno solo la lista se queda ciega en
     * cuanto avanzas. */
    dump_opcode_top(s.uncovered,
                    "encabezan un par y no encajan en ningun patron");
    dump_opcode_top(s.unmatched_second,
                    "van SEGUNDAS y no encajan (la primera si)");

    /* Lo mismo PONDERADO POR EJECUCION, que es la cifra que decide.
     *
     * Los recuentos de arriba son por par FORMADO: un paquete de arranque que
     * corre una vez pesa lo mismo que el cuerpo de un bucle que corre un millon
     * de veces.  Multiplicando por las veces que se entra sale lo que de verdad
     * se ahorraria, y eso puede dar la vuelta al orden entero.
     *
     * La suma se hace AL ENTRAR y no aqui, y esa decision costo un reventon:
     * recorrer la icache al final para leer los paquetes NO VALE.  Una entrada
     * puede seguir diciendo "paquete" con el paquete ya recogido -- la arena es
     * copiadora y la region vieja se libera tras el periodo de gracia --, asi
     * que el puntero que guarda ya no apunta a nada.  Por eso el volcado de
     * estado que ya existia cuenta cabeceras pero no desreferencia ninguna: el
     * unico sitio donde un paquete es seguro es mientras se ejecuta. */
    if (s.fused_weighted != 0 || s.newop_ready_weighted != 0 ||
        s.newop_livewall_weighted != 0)
        std::fprintf(stderr,
                     "           por EJECUCION: fusionadas=%llu  cogeria=%llu  "
                     "no cogeria=%llu\n",
                     (unsigned long long)s.fused_weighted,
                     (unsigned long long)s.newop_ready_weighted,
                     (unsigned long long)s.newop_livewall_weighted);
}

} // namespace runtime

#endif // VM_BUNDLES
