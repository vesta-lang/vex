/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/phys_liveness.h
 * @brief Que registros FISICOS estan vivos en cada punto del MachineIR ya
 *        repartido.
 *
 * El hecho que faltaba.  Quien quiera saber si puede tocar un registro despues
 * de repartir -- una mirilla que borre escrituras muertas, un planificador que
 * reordene, un futuro fusionador -- necesita esto, y hasta ahora cada uno se lo
 * deducia por su cuenta.  Deducirlo sale mal: las lecturas que no estan en los
 * operandos (un bloque de `asm`, la base de una direccion, el RDX:RAX de una
 * division) no se ven mirando la instruccion de frente.
 *
 * NIVEL.  Es el hermano FISICO de la liveness que calcula @c build_intervals,
 * que trabaja sobre registros VIRTUALES y antes de repartir.  Son dos dominios
 * distintos y no se cruzan: alli se pregunta por un vreg, aqui por un MReg, y
 * la misma pregunta tiene respuestas distintas porque entre medias hubo un
 * reparto y una legalizacion a dos operandos.
 *
 * DE DONDE SALE LO QUE SABE.  De @ref jit::each_reg (quien lee y quien escribe,
 * con el `asm` y las direcciones dentro) y de @ref jit::clobbers_like_call (lo
 * que toca registros sin nombrarlos).  Ninguna de las dos se reescribe aqui.
 *
 * LO QUE NO SE SABE SE CUENTA.  Donde hay una instruccion que toca registros
 * sin decir cuales, este hecho no adivina: marca ese punto y ahi da TODO por
 * vivo.  @ref PhysLivenessFacts::unknown_points dice cuantos puntos asi hubo,
 * para que
 * quien mire un resultado pobre sepa por que lo es en vez de suponer que no
 * habia nada que sacar.
 */

#ifndef VESTA_ANALYSIS_FACTS_PHYS_LIVENESS_H
#define VESTA_ANALYSIS_FACTS_PHYS_LIVENESS_H

#include "jit/machine_ir.h"

#include <cstdint>
#include <vector>

namespace analysis {
namespace facts {

/**
 * @brief Conjunto de registros fisicos, uno por bit.
 *
 * Caben los 64 que numera @c jit::MReg (enteros, vectoriales y el centinela),
 * asi que una palabra basta y la union de dos conjuntos es un OR.
 */
using PhysRegSet = uint64_t;

/// @brief Todos: lo que se usa donde no se sabe que se toca.
constexpr PhysRegSet kPhysRegAll = ~PhysRegSet{0};

/// @brief El conjunto con solo @p r.
inline PhysRegSet phys_bit(uint8_t r) noexcept {
    return (r < 64) ? (PhysRegSet{1} << r) : PhysRegSet{0};
}

/**
 * @struct PhysLivenessFacts
 * @brief Los registros vivos DESPUES de cada instruccion.
 *
 * "Vivo despues de la instruccion i" quiere decir: alguien lo lee mas adelante
 * sin que nadie lo haya escrito entero entre medias.  Es justo la pregunta que
 * decide si una escritura sobra.
 */
struct PhysLivenessFacts {
    /// Vivos a la salida de cada bloque (indexado por MBlockId).
    std::vector<PhysRegSet> live_out;
    /// Vivos DESPUES de cada instruccion, aplanado: @c off[b] es donde empieza
    /// el bloque b.
    std::vector<PhysRegSet> after;
    std::vector<uint32_t> off; ///< off[b]..off[b+1] = tramo del bloque b.
    /// Cuantos puntos habia donde no se sabia que se tocaba.  Cero = el
    /// resultado es tan preciso como el modelo permite.
    uint32_t unknown_points = 0;

    /// @brief Los vivos justo despues de la instruccion @p i del bloque @p b.
    PhysRegSet live_after(uint32_t b, uint32_t i) const noexcept {
        if (b + 1 >= off.size()) return kPhysRegAll; // fuera: conservador
        const uint32_t base = off[b];
        if (base + i >= off[b + 1]) return kPhysRegAll;
        return after[base + i];
    }

    /// @brief True si @p r esta vivo despues de la instruccion @p i de @p b.
    bool is_live_after(uint32_t b, uint32_t i, uint8_t r) const noexcept {
        return (live_after(b, i) & phys_bit(r)) != 0;
    }
};

/**
 * @brief Calcula @ref PhysLivenessFacts sobre una funcion YA REPARTIDA.
 *
 * @param pf MachineIR fisico (despues de @c rewrite_to_physical).
 * @return El hecho.  Nunca falla: donde no se sabe, da todo por vivo y lo
 *         cuenta en @c unknown_points.
 */
PhysLivenessFacts compute_phys_liveness(const jit::MFunction &pf);

} // namespace facts
} // namespace analysis

#endif // VESTA_ANALYSIS_FACTS_PHYS_LIVENESS_H
