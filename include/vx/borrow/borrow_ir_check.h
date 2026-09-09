/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/borrow/borrow_ir_check.h
 * @brief La exclusividad de un prestamo, comprobada CRUZANDO LA LLAMADA.
 *
 * El comprobador de prestamos del AST aplica la exclusividad por NOMBRE y
 * dentro de una funcion.  Pasar el dueno a otra que lo vuelve a prestar es
 * invisible para el, y entonces coexisten dos prestamos exclusivos vivos de la
 * misma region sin que nadie lo vea.  Ese es el agujero que esto cierra.
 *
 * @par Por que aqui y no en el del AST
 * La pregunta "estas dos regiones son la misma?" no se puede contestar mientras
 * se baja: dentro de la funcion sus parametros son dos NOMBRES, y quien sabe
 * que le llega a cada uno es quien la llama.  Hace falta el IR terminado y el
 * modulo entero, o sea justo lo que el comprobador del AST no tiene.
 *
 * @par Esto NO produce conocimiento, lo CONSUME
 * Los dos datos ya existen y cada uno tiene su productor:
 *
 *   - que la region de un parametro no la alcanza ningun otro de la misma
 *     llamada -- la promesa, que sale del tipo `borrow_mut<T>`;
 *   - que en tal llamada dos parametros SI reciben la misma memoria -- el dato,
 *     que sale de mirar los sitios de llamada.
 *
 * Juntarlos es lo que produce el veredicto, y juntar es del consumidor.  Acunar
 * un hecho "promesa incumplida" seria meter el juicio dentro del dato y duplicar
 * lo que esas dos proposiciones ya dicen.
 *
 * @par Y solo acusa con una PRUEBA
 * Un par sobre el que no se pudo decidir no es una violacion: no poder demostrar
 * que dos regiones son disjuntas NO es demostrar que se solapan.  Solo el
 * veredicto demostrado -- con la llamada que lo ensena -- sale de aqui.
 */

#ifndef VX_BORROW_IR_CHECK_H
#define VX_BORROW_IR_CHECK_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ir {
struct IrModule;
}

namespace analysis {
namespace asa {
class FactBase;
}
} // namespace analysis

namespace vx {
namespace borrow {

/**
 * @brief Una promesa de exclusividad que el programa incumple, con su prueba.
 */
struct ExclusiveViolation {
    /// Funcion cuyos parametros prometian no alcanzarse.
    std::string function;
    /// El parametro que lo prometia.
    size_t promised = 0;
    /// El otro, que alcanza su misma region.
    size_t other = 0;
    /// Linea de la LLAMADA donde se ve que son la misma memoria.  Es la prueba:
    /// sin ella el aviso seria una acusacion sin nada detras.
    uint32_t line = 0;
    /// La promesa la ESCRIBIO el programador (la direccion del parametro), en
    /// vez de derivarla el compilador del tipo.  Viaja hasta aqui porque la
    /// salida no es la misma: a quien declaro `out` no se le puede decir que
    /// termine un prestamo que en su programa no existe.
    bool declared = false;
};

/**
 * @brief Busca promesas de exclusividad incumplidas cruzando las llamadas.
 *
 * @param mod  Modulo con el IR ya terminado.
 * @param base La base de hechos: de ahi sale que le llega a cada parametro.
 * @return Las violaciones DEMOSTRADAS, cada una con la llamada que la ensena.
 */
std::vector<ExclusiveViolation>
check_exclusive_across_calls(const ir::IrModule &mod,
                             analysis::asa::FactBase &base);

} // namespace borrow
} // namespace vx

#endif // VX_BORROW_IR_CHECK_H
