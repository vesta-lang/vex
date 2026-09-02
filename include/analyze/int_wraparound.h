/**
 * @file int_wraparound.h
 * @brief Aritmetica entera que se sale de su tipo, con los dos operandos
 *        sabidos.
 *
 * `i8 max = 127; max = max + 1;` no daba -128 por casualidad: daba un valor
 * SIN NORMALIZAR que ni siquiera se compara igual que -128.  Envolver es
 * legitimo -- lo usan las mezclas de un hash, las sumas de comprobacion y los
 * generadores pseudoaleatorios --, pero tiene que DECIRSE: se escribe un cast
 * al tipo, igual que para cualquier otra conversion que pierde informacion.
 * Sin el cast es un error, no un aviso, para que nadie lo haga sin darse
 * cuenta ni pueda ignorarlo entre los avisos.
 *
 * Se mira el intermedio de ANTES de optimizar a proposito: es lo que el
 * usuario escribio, y no depende del nivel de optimizacion -- si dependiera,
 * el mismo programa seria valido o no segun como se compile, que es lo peor
 * que le puede pasar a una regla del lenguaje.
 */
#ifndef VESTA_ANALYZE_INT_WRAPAROUND_H
#define VESTA_ANALYZE_INT_WRAPAROUND_H

#include "ir/ssa_ir.h"

#include <cstdint>
#include <vector>

namespace analyze {

/// Una operacion cuyo resultado no cabe en el tipo que declara.
struct IntWrap {
    uint32_t line = 0;              ///< linea fuente de la operacion.
    int64_t exact = 0;              ///< lo que da la cuenta sin envolver.
    int64_t lo = 0, hi = 0;         ///< lo que el tipo admite.
    ir::IrType type = ir::IrType::VOID; ///< el tipo del resultado.
};

/**
 * @brief Busca las operaciones que se salen de su tipo en una funcion.
 *
 * Solo lo DEMOSTRADO: los dos operandos tienen que ser constantes visibles en
 * el propio intermedio.  Con uno que venga de fuera no se dice nada -- "no
 * poder demostrar que cabe" no es "demostrar que no cabe", y un error falso es
 * mucho peor que un hueco.
 *
 * @param fn La funcion a mirar.
 * @return Las operaciones encontradas, en orden de aparicion.
 */
std::vector<IntWrap> find_int_wraparounds(const ir::IrFunction &fn);

/**
 * @brief Los limites que admite un tipo entero del intermedio.
 * @param t El tipo.
 * @param lo Salida: el menor valor.
 * @param hi Salida: el mayor.
 * @return false si @p t no es un entero de ancho conocido.
 */
bool int_type_bounds(ir::IrType t, int64_t &lo, int64_t &hi);

} // namespace analyze

#endif // VESTA_ANALYZE_INT_WRAPAROUND_H
