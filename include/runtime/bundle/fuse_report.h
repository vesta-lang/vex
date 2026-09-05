/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/fuse_report.h
 * @brief Lo que se MIRA de la fusion, separado de lo que la decide.
 *
 * `bundle_fuse.cpp` no imprime, no formatea y no explora: decide que pares se
 * juntan y devuelve cuantos.  Contar las renuncias, ponerles nombre y sondear
 * cuanto capturaria un opcode que todavia no existe vive detras de esta
 * frontera y en OTRA unidad de traduccion.  Mismo criterio que ya sigue el
 * reordenador con `bundle_reorder_report.h`.
 *
 * No es cosmetica: el sondeo recorre pares que la fusion ya descarto, o sea que
 * es trabajo que el camino normal no debe pagar ni leer.
 *
 * POR QUE HAY UN INFORME
 * ----------------------
 * Un fusionador que solo publica cuantos pares junto es indistinguible de uno
 * roto: con `fusionados=0` no se sabe si es que no habia material, si el patron
 * esta mal escrito o si lo que aprieta es la ventana del paquete.  Es la misma
 * regla que rige los analisis del ASA -- al renunciar, se dice POR QUE --, y es
 * lo unico que permite afinar los patrones mirando datos.
 */

#ifndef VESTA_RUNTIME_BUNDLE_FUSE_REPORT_H
#define VESTA_RUNTIME_BUNDLE_FUSE_REPORT_H

#include "runtime/bundle.h"
#include "runtime/bundle/touch.h"

#if VM_BUNDLES

namespace runtime {

/// Nombre corto de una razon, para informes.  No es un diagnostico de usuario.
const char *fuse_reject_name(FuseReject r);

/**
 * @brief Cuenta si un opcode que NO existe capturaria este par.
 *
 * No cambia nada: MIDE.  Contesta la pregunta que decide si merece la pena
 * gastar una ranura de la tabla extendida, y la parte en dos mitades porque
 * llevan a conclusiones opuestas:
 *
 *   - la primera produce un valor que la segunda consume, y ese valor MUERE:
 *     un opcode nuevo lo convertiria en una instruccion.  Es material real.
 *   - lo mismo, pero el valor sigue VIVO: la fusionada tendria que escribirlo
 *     igual y no ahorraria ni una instruccion.  El opcode no serviria.
 *
 * La segunda mitad es la pared con la que ya choco el patron de redirigir el
 * destino: dinamicamente el temporal muere, pero desde un paquete no se puede
 * DEMOSTRAR.  Medirlo antes de anadir el opcode es la diferencia entre gastar
 * una ranura con datos y gastarla con una corazonada.
 *
 * @param ta         Lo que toca la primera del par.
 * @param tb         Lo que toca la segunda.
 * @param live_after Registros vivos despues del par.
 * @param tel        Donde apuntar el resultado.
 */
void probe_new_opcode(const Touch &ta, const Touch &tb, uint16_t live_after,
                      Bundle &b, const FuseTelemetry &tel);

/**
 * @brief Vuelca las renuncias del fusionador y el sondeo del opcode que falta.
 *
 * @param process Proceso cuyos contadores se imprimen.
 */
void fuse_dump(const ProcessVM *process);

} // namespace runtime

#endif // VM_BUNDLES
#endif // VESTA_RUNTIME_BUNDLE_FUSE_REPORT_H
