/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file aot/lower/statics.h
 * @brief Bajar un campo estatico al camino nativo.
 *
 * Cada area de bajada del AOT vive en su fichero y se pregunta por separado.
 * Sin eso, `aot_lower.cpp` acabaria siendo el sitio donde cae TODO -- campos
 * estaticos, cadenas, despacho virtual, arrays --, que es mucho para un solo
 * switch y deja de poderse leer.
 */

#ifndef AOT_LOWER_STATICS_H
#define AOT_LOWER_STATICS_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "ir/ssa_ir.h"

namespace aot {

/**
 * @brief Da (o crea) el hueco global donde vive un campo estatico, por nombre.
 *
 * Uno por nombre: leer y escribir el mismo campo tienen que dar en el mismo
 * sitio, y con dos huecos distintos no habria un error -- habria otro valor.
 */
using StaticSlotFn = std::function<uint64_t(const std::string &)>;

/**
 * @brief Baja @p in si es un acceso a campo estatico; si no, no toca nada.
 *
 * En codigo nativo un campo estatico no vive en ningun registro de clases: es
 * un hueco global y nada mas.  Se baja a decir donde esta y leerlo o
 * escribirlo -- dos instrucciones --, y el nombre del hueco lo trae la propia
 * instruccion desde el intermedio.
 *
 * Que el nombre viaje en el intermedio no lo hace dependiente del backend: es
 * un HECHO del programa.  El interprete lo ignora, porque alli el campo vive
 * en el registro de clases; aqui es lo unico que hace falta.  Mientras no
 * estuvo, el unico que sabia bajar un estatico era el frontend, y por eso
 * emitia un intermedio DISTINTO segun a donde fuera a parar el programa.
 *
 * @param fn       Funcion en curso; de ella salen los valores nuevos.
 * @param in       Instruccion candidata.
 * @param out      Donde dejar lo que se genere.
 * @param slot_for Como conseguir el hueco de un nombre.
 * @return @c true si lo bajo (y entonces @p in NO se conserva); @c false si no
 *         era suyo.
 */
bool lower_static_field(ir::IrFunction &fn, const ir::IrInstr &in,
                        std::vector<ir::IrInstr> &out,
                        const StaticSlotFn &slot_for);

/**
 * @brief Quita lo que se quedo sin duenyo al bajar los campos estaticos.
 *
 * Buscar la clase por su nombre alimentaba al campo, y en nativo el campo es un
 * hueco global: ya no hay ninguna clase que buscar.  Detras de esa busqueda
 * quedan tambien su buffer de pila y la direccion del nombre, que nadie lee.
 *
 * Si se quedan, el analisis dira -- con razon -- que el modulo necesita el
 * registro de clases por una instruccion cuyo resultado ya no lee nadie, y la
 * direccion del nombre acabaria pidiendole al enlazador una FUNCION que no
 * existe.
 *
 * Solo lo llama quien bajo algun estatico: sin eso se recorreria el intermedio
 * de todas las funciones de todos los programas por un caso que casi nunca se
 * da.
 *
 * @param fn Funcion a limpiar (se modifica en el sitio).
 */
void clean_after_static_lowering(ir::IrFunction &fn);

} // namespace aot

#endif // AOT_LOWER_STATICS_H
