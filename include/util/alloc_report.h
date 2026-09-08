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

#include <string>

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

/**
 * @brief Un nombre de C++ decorado, escrito para que lo lea una persona.
 *
 * Desdecora y ademas LIMPIA: quita los valores por defecto -- el mismo tipo
 * escrito largo, que el lenguaje repone solo -- y los detalles de como esta
 * hecha la biblioteca.  Un manglado desdecorado a secas es tecnicamente la
 * respuesta y practicamente ninguna: cuatrocientos caracteres de los que
 * trescientos no distinguen nada.
 *
 * No recorta NUNCA: el nombre que sale sigue nombrando exactamente lo mismo, y
 * por eso se puede buscar en el codigo, pegar en `c++filt` o meter en un
 * `grep`.  Un nombre con puntos suspensivos en medio no sirve para ninguna de
 * las tres.
 *
 * Vive aqui, y no en la libreria del asignador, porque no es de ella: la
 * libreria da direcciones y nombres tal como estan; como se escribe un nombre
 * de C++ para que se lea es de este proyecto.
 *
 * @param mangled El nombre tal como sale de la tabla de simbolos.
 * @return El nombre legible; el original si no habia nada que desdecorar.
 */
std::string readable_symbol(const char *mangled);

} // namespace util

#endif // VESTA_UTIL_ALLOC_REPORT_H
