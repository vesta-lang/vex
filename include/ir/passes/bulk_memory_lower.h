/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir/passes/bulk_memory_lower.h
 * @brief Reduce un bucle que mueve memoria a la operacion de bloque.
 *
 * El pase no reconoce nada por su cuenta: PREGUNTA.  Todo el saber esta en
 * @c analysis::detect_bulk_memory, que responde si un bucle resulta ser un
 * relleno o una copia y sobre que tramo.  Aqui solo se aplica la consecuencia:
 * donde habia n vueltas queda una instruccion.
 *
 * Esa division no es de organizacion, es lo que hace que funcione.  El intento
 * anterior preguntaba por la FORMA del IR -- cuantas instrucciones tiene la
 * cabecera, si el incremento esta en el cuerpo o en su bloque, si el indice
 * empieza en cero -- y cada respuesta dependia de que pases hubieran corrido
 * antes; bastaba con que el desenrollador fuera primero para que no quedara
 * forma que reconocer.  Preguntar por lo que el bucle HACE no depende de como
 * este escrito.
 */

#ifndef VESTA_IR_PASSES_BULK_MEMORY_LOWER_H
#define VESTA_IR_PASSES_BULK_MEMORY_LOWER_H

namespace analysis {
namespace asa {
class FactStore;
} // namespace asa
} // namespace analysis

namespace ir {

struct IrFunction;

/**
 * @brief Sustituye por @c MEMSET / @c MEMCPY los bucles que son eso.
 *
 * Debe correr ANTES del desenrollador: un bucle que se convierte en una sola
 * instruccion no hay nada que desenrollar en el, y desenrollarlo primero solo
 * multiplica el codigo que despues hay que borrar.
 *
 * @param fn Funcion a transformar.
 * @return true si cambio algo.
 */
/**
 * @param facts Almacen donde DECIR lo que se sabe antes de deshacerlo, o nulo.
 *              Que un bucle sea una copia solo se sabe mientras el bucle
 *              existe: en cuanto el pase lo reduce, lo que queda es una
 *              instruccion de bloque y ya no hay nada que reconocer.  Ese
 *              conocimiento se tiraba, y con el la unica forma de saber si el
 *              pase no disparo porque no vio el bucle o porque decidio no
 *              tocarlo.
 */
bool ir_pass_bulk_memory_lower(IrFunction &fn,
                               analysis::asa::FactStore *facts = nullptr);

} // namespace ir

#endif // VESTA_IR_PASSES_BULK_MEMORY_LOWER_H
