/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir/parallel_for.h
 * @brief Recorrer las funciones de un modulo en paralelo, cuando se puede.
 *
 * Compilar un modulo era ENTERO monohilo: medido con VTune sobre un programa de
 * 24k lineas, 17,21 s de CPU en 17,95 s de reloj y UN solo hilo.  Todo lo que
 * pesa -- comprobar limites, optimizar, emitir -- corre en fila de uno mientras
 * el resto de la maquina mira.
 *
 * Muchos pases del optimizador tienen la misma forma: `for (fn : funciones)
 * pase(fn)`, y cada uno toca SOLO su funcion.  Sin estado compartido y sin
 * orden, eso se reparte sin cambiar el resultado, que es la unica clase de
 * paralelismo que se puede meter en un compilador sin discutir cada caso.
 *
 * Lo que NO vale para esto, y por que se dice aqui: un pase que consulte o
 * mute algo del modulo mas alla de su funcion (una cache global, el registro de
 * clases, un contador), o cuyo resultado dependa del orden de visita.  Ante la
 * duda, secuencial: el coste de equivocarse no es un programa lento, es un
 * programa distinto.
 *
 * `VESTA_PARALELO=0` lo apaga entero.  No es solo un escape: sin poder
 * apagarlo no hay con que comparar, y la unica prueba que vale aqui es que
 * monohilo y multihilo produzcan el MISMO `.velb`.
 */
#ifndef IR_PARALELO_H
#define IR_PARALELO_H

#include "ir/ssa_ir.h"

#include <functional>

/* `ThreadPool.h` NO se incluye aqui: arrastra `windows.h`, que define `VOID`
 * como macro y rompe `enum class PrimitiveKind { VOID }` en cualquier unidad
 * que incluya esto.  Es la misma contaminacion que ya obligo a renombrar
 * ABSOLUTE/RELATIVE.  La implementacion vive en el .cpp, donde esa cabecera no
 * molesta a nadie. */

namespace ir {

/// Cuantos hilos usar al compilar, o 1 para no repartir.  `VESTA_PARALELO=0`
/// lo apaga.  Se decide UNA vez por proceso.
unsigned compile_threads();

/**
 * @brief Aplica @p f a cada funcion del modulo, en paralelo si se puede.
 *
 * @param mod  Modulo cuyas funciones se recorren.
 * @param f    Que hacer con cada una.  DEBE tocar solo la funcion que recibe:
 *             sin estado compartido y sin depender del orden de visita.
 *
 * Cae a secuencial cuando no hay hilos que usar o hay tan pocas funciones que
 * repartirlas cuesta mas que hacerlas.
 */
void for_each_function(IrModule &mod,
                       const std::function<void(IrFunction &)> &f);

/**
 * @brief Cuantos hilos quedan libres AHORA para repartir.
 *
 * Los dos niveles de reparto -- por modulo y por funcion -- comparten la misma
 * maquina, asi que comparten un PRESUPUESTO: quien reparte se queda con los
 * suyos y los siguientes ven lo que sobra.  Nunca menos de uno, que significa
 * "hazlo en fila de uno".
 */
unsigned available_threads();

/**
 * @brief Reserva @p threads del presupuesto mientras vive.
 *
 * Lo declara quien reparte por MODULO, que lanza sus propios hilos y por eso no
 * pasa por @c for_each_function.  Sin el presupuesto, cada uno de esos hilos
 * volvia a repartir en el pool -- que es UNO para todo el proceso --, asi que N
 * modulos por N workers dejaban N*N hilos listos sobre los nucleos que hubiera,
 * y el que espera gira con @c yield() robandole el nucleo al que trabaja.  Con
 * 24 modulos medidos, la maquina se arrastraba.
 *
 * Lo contrario tambien se midio y tambien es malo: prohibir del todo el reparto
 * de dentro dejaba la maquina al 2 % -- 0,5 nucleos de 24 --, porque la fase
 * mas cara trabaja sobre UN modulo y ahi no hay nada que repartir por arriba.
 * El presupuesto da las dos cosas: se llena la maquina y no se pasa.
 *
 * @param threads Cuantos se reservan.  Se recorta a lo que quede libre.
 */
class OuterParallelScope {
  public:
    explicit OuterParallelScope(unsigned threads) noexcept;
    ~OuterParallelScope() noexcept;
    OuterParallelScope(const OuterParallelScope &) = delete;
    OuterParallelScope &operator=(const OuterParallelScope &) = delete;

    /// Lo que realmente se pudo reservar.
    unsigned granted() const noexcept { return taken_; }

  private:
    unsigned taken_; ///< Lo reservado, para devolverlo exacto al salir.
};

} // namespace ir

#endif // IR_PARALELO_H
