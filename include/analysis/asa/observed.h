/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/observed.h
 * @brief Lo que un PASE observa al transformar, dicho en el vocabulario del ASA.
 *
 * Un pase del optimizador sabe cosas que no estan ni antes ni despues de el:
 * el desenrollador SABE cuantas vueltas da un bucle justo antes de deshacerlo,
 * y la devirtualizacion SABE el tipo justo antes de fijarlo.  Ese conocimiento
 * moria con la transformacion que lo producia.
 *
 * Aqui NO hay un vocabulario nuevo: hay UNA funcion por hecho, que construye
 * el mismo `Fact` que construye el productor del dominio.  Es la diferencia
 * entre "una base, varias fuentes" y dos formas de decir lo mismo -- con dos,
 * basta que una se quede atras para que el mismo bucle se cuente distinto
 * segun quien lo mire.
 *
 * Quien lo produce (el productor del dominio o el pase) cambia la PROCEDENCIA
 * y el MOMENTO del hecho, no lo que dice.  Los dos viajan sellados dentro.
 */

#ifndef ANALYSIS_ASA_OBSERVED_H
#define ANALYSIS_ASA_OBSERVED_H

#include "analysis/asa/fact.h"
#include "analysis/asa/fact_base.h" // los NOMBRES de dominio, que son vocabulario
#include "analysis/asa/fact_store.h"
#include "analysis/facts/loop_trip_count.h"
#include "ir/ssa_ir.h"

namespace analysis {
namespace asa {

/**
 * @brief El hecho "este bucle da N vueltas" (o "como mucho N"), sin depositar.
 *
 * Devuelve el @c Fact en vez de guardarlo porque los dos que lo usan lo
 * depositan de forma distinta: el productor del dominio lo cuenta en su
 * resumen, y un pase lo mete directo en el almacen.  Lo que NO puede diferir
 * es lo que el hecho dice, y por eso se arma aqui.
 *
 * "Da N vueltas" y "da como mucho N" salen con CODIGOS distintos, no como el
 * mismo con menos confianza: con el primero se puede quitar una comprobacion,
 * con el segundo solo elegir.  Y la certeza la trae @p trip, no la pone quien
 * publica.
 *
 * @param store  Para internar el nombre de la funcion (el sujeto lo referencia).
 * @param fn     Funcion a la que pertenece el bucle.
 * @param header Bloque cabecera del bucle: es el sujeto del hecho.
 * @param trip   Lo que el analisis averiguo, con su certeza dentro.
 * @param stage  En que MOMENTO vale (@see kStage*).
 * @param source De donde sale: estatico, observado al transformar, medido...
 * @param out    Donde se deja el hecho.  Solo se toca si se devuelve true.
 * @return true si habia algo que afirmar.
 *
 * Devuelve un BOOL y no un hecho "vacio" a proposito: los campos de @c Fact
 * traen `"?"` de fabrica -- ni nulos ni cadena vacia --, asi que cualquier
 * centinela que se mirara despues daria "hay hecho" siempre, y el almacen
 * acabaria lleno de vacios que ademas se cuentan.  Con un bool no hay nada
 * que acordarse de comprobar.
 */
bool loop_trip_fact(FactStore &store, const ir::IrFunction &fn,
                    ir::IrBlockId header, const LoopTripInfo &trip,
                    const char *stage, Source source, Fact &out);

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_OBSERVED_H
