/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file util/alloc_report.h
 * @brief El informe de QUIEN reserva, con nombres.
 */

#ifndef VESTA_UTIL_ALLOC_REPORT_H
#define VESTA_UTIL_ALLOC_REPORT_H

namespace util {

/**
 * @brief Ensena TODOS los sitios que reservan sin declarar su proposito.
 *
 * Todos, no los primeros.  Una lista cortada contesta "quien reserva mas", que
 * es otra pregunta: lo que se viene a buscar aqui es que queda por declarar, y
 * eso son los que faltan -- que por definicion estan en la cola --.  Un corte
 * ademas se lee como final y no hay nada que avise de lo que no salio.
 *
 * No hace NADA si no se pidio con `VESTA_HOST_ALLOC_SITES`.  Se llama al final,
 * cuando ya no queda trabajo: es un informe, no una medida.
 *
 * Los nombres salen de la tabla de simbolos del propio binario.  Si no la hay
 * -- una construccion despojada --, salen los desplazamientos y se DICE que no
 * hay nombres, en vez de dejar la columna vacia.
 */
void report_alloc_sites();

} // namespace util

#endif // VESTA_UTIL_ALLOC_REPORT_H
