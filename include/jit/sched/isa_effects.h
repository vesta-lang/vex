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
 * @file jit/sched/isa_effects.h
 * @brief Lo que de los efectos de una instruccion DEPENDE de la arquitectura.
 *
 * @ref jit::sched::machine_effects sabe recorrer operandos, preguntarle a la
 * base de instrucciones y aplicar la convencion de llamada leyendola del
 * descriptor del objetivo.  Lo que NO sabe -- ni debe -- es que RDX es la parte
 * alta de una division, que las instrucciones de cadena van por RSI/RDI/RCX, o
 * como se llama la pila.  Todo eso vive aqui, una implementacion por ISA.
 *
 * POR QUE ESTA SEPARACION EXISTE.  Antes ese saber estaba dentro del modulo
 * comun, en forma de `if (isa == X86) ... else ...`.  Y @c EffIsa no tiene dos
 * valores: tiene CUATRO (x86, arm64, arm32, riscv).  O sea que cada una de esas
 * preguntas le daba a arm32 y a riscv la respuesta de arm64 -- registros de
 * otra arquitectura -- sin que nada avisara.  Aqui eso no se puede escribir: o
 * la ISA declara lo suyo, o no hay respuesta y se dice.
 *
 * NO HAY RESPUESTA POR DEFECTO.  Si una ISA no ha declarado su tabla, quien
 * pregunte recibe @c nullptr y debe FALLAR, no seguir con una suposicion.  Un
 * "no se sabe" que se traduce en una barrera es la peor salida posible: el
 * codigo emitido sale correcto por casualidad o no sale correcto, y en ninguno
 * de los dos casos se entera nadie.
 */

#ifndef VESTA_JIT_SCHED_ISA_EFFECTS_H
#define VESTA_JIT_SCHED_ISA_EFFECTS_H

#include "jit/machine_ir.h"
#include "jit/target_reginfo.h"
#include "vx/asm/instr_db.h"

#include <cstdint>

namespace jit {
namespace sched {

struct MEffects; // definido en machine_effects.h

/**
 * @struct IsaEffects
 * @brief La parte del saber que cambia con la arquitectura.
 *
 * Son punteros a funcion y no metodos virtuales a proposito: la tabla de cada
 * ISA es un dato constante, se elige una vez por consulta y no hay nada que
 * construir ni destruir.
 */
struct IsaEffects {
    /// Como se llama, tal cual, para los mensajes.
    const char *name;

    /// @brief Como se llama @p op en el ensamblador de esta ISA.
    /// @return El mnemonico, o @c nullptr si es un pseudo de VestaVM que no
    ///         existe como instruccion y hay que preguntarle a @c pseudo.
    const char *(*mnemonic)(MOp op);

    /// @brief Traduce el nombre de un registro de la base de instrucciones a la
    ///        clave de dependencia uniforme.
    /// @param rs   El nombre, tal cual viene de la base.
    /// @param idx  Su indice en el pool de cadenas, para los que no tienen
    ///             hueco propio en el banco (banderas, mascaras, sistema).
    /// @return La clave, o @c UINT32_MAX si no es un registro concreto.
    uint32_t (*regset_key)(const char *rs, uint16_t idx);

    /// @brief El descriptor de registros del objetivo.
    ///
    /// De aqui salen los registros de la convencion de llamada, que es lo unico
    /// que el modulo comun necesita saber del banco.
    const TargetRegInfo &(*reg_info)();

    /// @brief Los registros que un PSEUDO de VestaVM toca sin nombrarlos.
    ///
    /// Solo se llama para lo que @c mnemonic no reconocio.  Si esta ISA no
    /// define ese pseudo, tiene que decirlo devolviendo @c false: eso es un
    /// fallo del compilador y quien pregunta lo hara saltar.
    ///
    /// @return @c false si esta ISA no sabe que hace ese pseudo.
    bool (*pseudo)(const MInstr &mi, MEffects &e);

    /// @brief Si escribir en @p o deja intacto el RESTO del registro.
    ///
    /// En x86 escribir `al` conserva los demas bytes, y un `setcc` escribe uno
    /// solo aunque su operando se nombre entero; en arm64 escribir una `w` pone
    /// a cero la mitad alta, que equivale a escribirlo entero.  Quien lo sabe
    /// es cada arquitectura.
    bool (*is_narrow_write)(const MInstr &mi, const MOperand &o);
};

/**
 * @brief La tabla de @p isa, o @c nullptr si esa ISA no ha declarado la suya.
 *
 * Devolver @c nullptr no es un caso raro que tapar: es la respuesta honesta
 * mientras un objetivo no diga lo suyo, y quien pregunta debe fallar en vez de
 * suponer.  Ver la cabecera del fichero.
 */
const IsaEffects *isa_effects(vx::instr_db::Isa isa);

} // namespace sched
} // namespace jit

#endif // VESTA_JIT_SCHED_ISA_EFFECTS_H
