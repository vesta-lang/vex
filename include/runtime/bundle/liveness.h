/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/liveness.h
 * @brief Que registros siguen VIVOS en cada punto de un paquete.
 *
 * QUE RESPONDE, Y POR QUE ES SU PROPIO MODULO
 * -------------------------------------------
 * Un valor esta VIVO si alguien lo va a leer antes de que otro lo pise.  Es la
 * pregunta de la que depende toda la fusion: dos instrucciones solo se pueden
 * convertir en una si el valor intermedio MUERE ahi -- si sigue vivo, la
 * fusionada tendria que escribirlo igual y no ahorraria nada.
 *
 * Va aparte del fusionador porque son dos responsabilidades distintas: esto
 * ANALIZA y no cambia nada; el fusionador DECIDE y reescribe.  Mezclarlas hacia
 * que la unica forma de comprobar el analisis fuera mirar si el fusionador
 * fusionaba, que es medir dos cosas a la vez.
 *
 * TODO LO QUE NO SE SABE, ES VIVO
 * -------------------------------
 * Las tres fuentes de "no se" devuelven "vivo", y las tres son de correctitud:
 *
 *   - lo que pase del paquete hacia fuera, si no se pudo mirar;
 *   - lo que hay detras de algo que transfiere control, porque no se sabe por
 *     donde sigue el flujo;
 *   - lo que tiene efectos de COTA INFERIOR, porque puede leer mas de lo que
 *     dice.
 *
 * Dar por muerto lo que no se ve es justo el fallo que no avisa: se pierde una
 * escritura y el valor equivocado aparece mucho despues.
 */

#ifndef VESTA_RUNTIME_BUNDLE_LIVENESS_H
#define VESTA_RUNTIME_BUNDLE_LIVENESS_H

#include <cstdint>

#include "runtime/bundle.h"
#include "runtime/bundle/bundle_touch_all.h"
#include "runtime/bundle/touch.h"

#if VM_BUNDLES

namespace runtime {

/**
 * @brief Registros vivos DESPUES de cada instruccion del paquete.
 *
 * Una sola pasada HACIA ATRAS, O(k).  Preguntarlo por candidata seria O(k^2)
 * -- mil pasos con k=32 --, y esto se calcula una vez y se consulta con un AND.
 *
 * La recurrencia es la de siempre: lo vivo ANTES de una instruccion es lo vivo
 * despues, menos lo que ella pisa entero, mas lo que lee.
 *
 * @param b          El paquete, ya reordenado.
 * @param t          Lo que toca cada instruccion (`touch_one`, sin la prudencia
 *                   del reordenador: aqui hace falta distinguir pisar de leer).
 * @param live_out   Lo vivo al SALIR del paquete.  0xFFFF si no se sabe.
 * @param out        Sale con `out[j]` = lo vivo justo despues de la j-esima.
 */
void bundle_live_after(const Bundle &b, const Touch *t, uint16_t live_out,
                       uint16_t *out);

/**
 * @brief Que registros siguen vivos a partir de @p pc, mirando un poco mas alla.
 *
 * Sin esto la respuesta al salir del paquete es "todos", y con "todos" no cuaja
 * ningun patron de fusion: al temporal que una ALU produce lo mata la
 * instruccion que vuelve a escribirlo, y esa cae fuera del paquete con
 * facilidad.
 *
 * Es SEGURO porque el paquete se forma siguiendo el flujo SECUENCIAL: lo que
 * hay detras de su ultima instruccion es lo que se ejecuta si no se salta.
 *
 * @param process Proceso del que leer el bytecode.
 * @param pc      Primera direccion DESPUES del paquete.
 * @param view    Cache de pagina del LLAMANTE, o null para el camino normal.
 *                Pasandola, esto se puede llamar desde el hilo ayudante: la
 *                lectura deja de tocar la del objeto, que es lo unico
 *                compartido.  Sin esto hubo que calcularla en el hilo duenyo y
 *                mandarla dentro del encargo, porque hacerlo alli no fallaba
 *                -- fusionaba MAL y el programa devolvia otro valor --.
 * @return Mascara de registros generales vivos; 0xFFFF si no se pudo resolver.
 */
uint16_t live_out_after(ProcessVM *process, uint64_t pc,
                        vm::VirtualMemory::PageView *view = nullptr);

} // namespace runtime

#endif // VM_BUNDLES
#endif // VESTA_RUNTIME_BUNDLE_LIVENESS_H
