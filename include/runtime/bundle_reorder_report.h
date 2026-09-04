/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle_reorder_report.h
 * @brief Lo que se MIRA del reordenamiento, separado de lo que lo decide.
 *
 * El planificador de `bundle_reorder.cpp` no imprime, no cuenta y no formatea:
 * decide un orden y devuelve cuantas movio.  Todo lo observable -- el volcado
 * lado a lado, los contadores de telemetria y el texto multi-idioma -- vive
 * detras de esta frontera y en OTRA unidad de traduccion.
 *
 * No es cosmetica.  Mezclado, el bucle caliente arrastraba tres bloques
 * `#if VM_BUNDLE_STATS`, una variable `need_reason` que decidia en cada paso si
 * habia que averiguar el motivo, y un `fprintf` con el mensaje escrito a mano
 * en el sitio.  Con eso, el codigo que decide y el codigo que cuenta se leen
 * juntos y se optimizan juntos: el compilador no puede tratar el bucle como lo
 * que es -- aritmetica sobre mascaras -- porque tiene efectos de por medio.
 *
 * La consecuencia de diseno es que el planificador se instancia DOS veces desde
 * una sola implementacion (`Explain` como parametro de plantilla): la caliente
 * no contiene ni una instruccion de telemetria, y la que explica se usa solo
 * cuando alguien va a leer el resultado.  Una implementacion, dos formas; no
 * dos copias que acaban separandose.
 */

#ifndef VESTA_RUNTIME_BUNDLE_REORDER_REPORT_H
#define VESTA_RUNTIME_BUNDLE_REORDER_REPORT_H

#include "runtime/bundle.h"

#if VM_BUNDLES

namespace runtime {

struct ProcessVM;

/**
 * @brief Vuelca el paquete ANTES y DESPUES, con el criterio que decidio cada
 *        cambio.
 *
 * Un reordenador que no se puede mirar no se puede depurar: lo que sale de el
 * es el orden en que se va a ejecutar, y si esta mal el sintoma aparece
 * lejisimos -- otro valor en un registro, al final del programa --.
 *
 * El texto sale del catalogo multi-idioma; aqui solo viajan DATOS.
 *
 * @param before Instrucciones en el orden con el que se formo el paquete.
 * @param after  Instrucciones en el orden que decidio el planificador.
 * @param k      Cuantas hay en cada uno.
 * @param moved  Cuantas cambiaron de sitio.
 * @param why    Criterio que eligio cada posicion, o nullptr.
 */
void reorder_report_dump(const DecodedInstr *before, const DecodedInstr *after,
                         uint32_t k, uint32_t moved, const uint8_t *why);

/**
 * @brief Suma al proceso lo que este paquete aporta a la telemetria.
 *
 * Se deriva ENTERO de @p why y @p k: hubo una eleccion por posicion emitida, y
 * cada una la gano el criterio que dice `why`.  Por eso el bucle no necesita
 * llevar contadores -- llevarlos ahi era contar dos veces lo mismo, una en el
 * camino caliente y otra en la telemetria.
 *
 * @param process Proceso al que se le suma.
 * @param moved   Cuantas cambiaron de sitio; 0 = el paquete no se toco.
 * @param why     Criterio que eligio cada posicion.
 * @param k       Cuantas posiciones se emitieron.
 */
void reorder_report_stats(ProcessVM *process, uint32_t moved,
                          const uint8_t *why, uint32_t k);

} // namespace runtime

#endif // VM_BUNDLES

#endif // VESTA_RUNTIME_BUNDLE_REORDER_REPORT_H
