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
 * @file jit/sched/isa_effects.cpp
 * @brief Que tabla de efectos le toca a cada arquitectura.
 *
 * Un switch sobre @c Isa y nada mas.  Lo unico que importa aqui es que las
 * cuatro arquitecturas esten NOMBRADAS: cuando se anada una quinta, este switch
 * deja de cubrirlas todas y el compilador lo dice.  Antes esto era un `if (isa
 * == X86) ... else ...` metido en el modulo comun, y por eso arm32 y riscv
 * recibian las respuestas de arm64 -- registros de otra arquitectura -- sin que
 * nada avisara.
 */

#include "jit/sched/isa_effects.h"

namespace jit {
namespace sched {

const IsaEffects &isa_effects_x86();
const IsaEffects &isa_effects_arm64();

const IsaEffects *isa_effects(vx::instr_db::Isa isa) {
    switch (isa) {
    case vx::instr_db::Isa::X86: return &isa_effects_x86();
    case vx::instr_db::Isa::ARM64: return &isa_effects_arm64();
    /* Todavia no tienen tabla.  Devolver nullptr NO es un descuido: es la
     * respuesta honesta mientras nadie haya declarado sus registros, y quien
     * pregunta debe fallar en vez de coger la de otra arquitectura.  Cuando
     * alguna estrene la suya, se anade aqui su linea. */
    case vx::instr_db::Isa::ARM32:
    case vx::instr_db::Isa::RISCV: return nullptr;
    }
    return nullptr;
}

} // namespace sched
} // namespace jit
