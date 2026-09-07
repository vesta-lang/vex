/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/mfunction_unwind.h
 * @brief Lo que anoto el emisor sobre el prologo, dicho como lo espera
 *        cualquier codificador de desenrollado.
 *
 * @c MFunction::UnwindDesc esta escrito en terminos de x86-64 -- `push_rbp`,
 * `push_rbx`, `frame_ptr` -- porque es lo que el emisor tenia a mano.  Los
 * formatos de salida, en cambio, describen un prologo como una SECUENCIA de
 * cosas que paso, y son varios: los codigos de Windows en x86-64 y en ARM64, y
 * las reglas CFI de DWARF.  Esta es la traduccion de lo uno a lo otro, y esta
 * sola para que cada codificador no la repita a su manera.
 *
 * POR QUE VIVE EN @c jit Y NO EN @c codegen, que es donde deberia.  Necesita
 * @c MFunction, que hoy vive aqui aunque el AOT tambien la use.  Cuando el
 * backend compartido salga de @c jit -- que es trabajo previsto --, esto sale
 * con el; ponerlo en @c codegen ahora obligaria a esa capa a depender de
 * @c jit, que es justo lo que no hace ninguno de sus catorce ficheros.
 */

#ifndef VESTA_JIT_MFUNCTION_UNWIND_H
#define VESTA_JIT_MFUNCTION_UNWIND_H

#include "codegen/frame_unwind.h"

namespace jit {

struct MFunction;

/**
 * @brief Describe el prologo de @p fn sin depender de la ISA ni del formato.
 *
 * Las operaciones salen en ORDEN DE EJECUCION del prologo, que es el que
 * emitio el generador:
 *
 *     push rbp ; mov rbp, rsp ; push rbx ; push <callee-saved> ; sub rsp, N
 *
 * Cada codificador lo recorre como pida su formato.  Guardarlo ya invertido
 * ataria la descripcion al unico que hoy la consume.
 *
 * @param fn La funcion, de la que se leen @c unwind, @c prologue_instrs y
 *           @c prologue_bytes.
 * @return La descripcion.  Si el prologo no se midio, @c prologue_bytes sale a
 *         cero, que es como se dice "no hay nada que describir": la suposicion
 *         de hoja que hace un desenrollador sin tabla ES la correcta ahi, y
 *         emitir una descripcion vacia se la quitaria.
 */
codegen::FrameUnwind frame_unwind_of(const MFunction &fn);

} // namespace jit

#endif // VESTA_JIT_MFUNCTION_UNWIND_H
