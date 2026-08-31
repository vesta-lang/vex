/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/rbank/machine_snapshot.h
 * @brief El mismo query system, un AMBITO mas abajo: la funcion YA REPARTIDA.
 *
 * `FunctionSnapshot` responde sobre una funcion del IR; hay conocimiento que
 * solo existe DESPUES de seleccionar instrucciones y repartir registros -- que
 * registro fisico sigue vivo, que se derramo y por que --, y ese no cabe ahi:
 * su sujeto es otro.
 *
 * Es exactamente lo que la cabecera de `function_snapshot.h` llama CONTINUIDAD
 * DE ESCALA: el mismo @c query<T>() sirve a cualquier ambito y lo unico que
 * cambia es el alcance del conocimiento.  Por eso esto no trae mecanismo
 * propio: reusa @c LazyFact -- la celda que computa una vez y cachea -- y
 * @c QueryProducer, que ahora lleva el ambito como segundo parametro.  Escribir
 * aqui una segunda copia de `query<T>()` habria sido tener dos motores que un
 * dia responden distinto.
 *
 * QUE GANA UN HECHO CON ENTRAR AQUI, que es la razon de moverlo:
 *
 *   - **Se calcula si se pregunta, y una sola vez.**  `compute_phys_liveness`
 *     se llamaba a mano, y en la mirilla DOS VECES sobre la misma funcion --
 *     una para el informe y otra para la regla --, que es justo la duplicacion
 *     que este sistema existe para impedir.
 *   - **Sus dependencias se resuelven solas.**  Un hecho de maquina que
 * necesite otro lo pide con `s.query<U>()` y el motor sabe producirlo.
 *   - **Anadir uno no toca a nadie**: una celda mas y su productor.
 *
 * NO es thread-safe, igual que `FunctionSnapshot` y por lo mismo: el reparto de
 * registros de una funcion va en un hilo.  La sincronizacion, si hace falta,
 * entra en @c LazyFact sin tocar a los consumidores.
 */

#ifndef VESTA_CODEGEN_RBANK_MACHINE_SNAPSHOT_H
#define VESTA_CODEGEN_RBANK_MACHINE_SNAPSHOT_H

#include "analysis/facts/phys_liveness.h"
#include "codegen/rbank/function_snapshot.h" // LazyFact + QueryProducer

namespace codegen {
namespace rbank {

/**
 * @struct MachineSnapshot
 * @brief Lo que se sabe de una funcion YA REPARTIDA, consultado a demanda.
 *
 * DATO desacoplado de MECANISMO, como su hermano de arriba: aqui viven las
 * celdas y la consulta; el algoritmo vive en @c QueryProducer.
 */
struct MachineSnapshot {
    /// La funcion de la que es foto.  No la posee: vive lo que ella.
    const jit::MFunction *mfn = nullptr;

    explicit MachineSnapshot(const jit::MFunction &f) : mfn(&f) {}

    /// Los registros fisicos vivos tras cada instruccion.
    const analysis::facts::PhysLivenessFacts &phys_liveness() const {
        return query<analysis::facts::PhysLivenessFacts>();
    }

    /**
     * @brief Consulta un hecho @c T: acierto en su celda, o lo PRODUCE.
     *
     * Identico al de `FunctionSnapshot` salvo el ambito, que es lo unico que
     * cambia entre los dos.
     */
    template <typename T> const T &query() const {
        return cell<T>().get(
            [&] { return QueryProducer<T, MachineSnapshot>::produce(*this); });
    }

  private:
    // --- Celdas.  Una por hecho; el mapeo tipo -> celda se especializa abajo.
    mutable LazyFact<analysis::facts::PhysLivenessFacts> live_;

    template <typename T> const LazyFact<T> &cell() const;
};

template <>
inline const LazyFact<analysis::facts::PhysLivenessFacts> &
MachineSnapshot::cell<analysis::facts::PhysLivenessFacts>() const {
    return live_;
}

// ---------------------------------------------------------------------------
//  Productores registrados: AQUI vive el ALGORITMO.  El snapshot no lo conoce.
// ---------------------------------------------------------------------------
template <>
struct QueryProducer<analysis::facts::PhysLivenessFacts, MachineSnapshot> {
    static analysis::facts::PhysLivenessFacts
    produce(const MachineSnapshot &s) {
        return analysis::facts::compute_phys_liveness(*s.mfn);
    }
};

} // namespace rbank
} // namespace codegen

#endif // VESTA_CODEGEN_RBANK_MACHINE_SNAPSHOT_H
