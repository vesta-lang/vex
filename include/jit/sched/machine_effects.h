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
 * @file jit/sched/machine_effects.h
 * @brief Efectos COMPLETOS de una instruccion MachineIR (para el DAG de
 *        dependencias del scheduler).  Parte del analisis de efectos del ASA.
 *
 * El scheduler solo puede REORDENAR instrucciones que no dependan entre si.
 * Para eso necesita el conjunto EXACTO de lo que cada instruccion lee y
 * escribe -- incluyendo los efectos IMPLICITOS, que son la fuente de casi
 * todos los bugs de un scheduler ingenuo:
 *
 *   - registros implicitos: @c IDIV / @c DIV_U leen y escriben RDX:RAX;
 *     @c CQO lee RAX y escribe RDX; los shifts por CL leen RCX; etc.
 *   - FLAGS (RFLAGS): @c CMP / @c ADD / ... los ESCRIBEN; @c JCC / @c SETCC /
 *     @c CMOVCC / @c ADC / @c SBB los LEEN.  Un flag-consumer no puede subir
 * por encima de su productor, ni meterse un clobber de flags entre ambos.
 *   - MEMORIA: los accesos a memoria se mantienen ORDENADOS de forma
 *     conservadora (sin alias analysis): un load no adelanta a un store previo,
 *     dos stores no se reordenan.
 *   - BARRERAS: @c CALL / @c RET / @c SAFEPOINT no se cruzan.
 *
 * Esto es exactamente el analisis de efectos del ASA (ver @c vx/asm/asm_effects
 * para el nivel de asm-fuente); aqui se expresa sobre el @c MInstr del
 * back-end.
 */

#ifndef VESTA_JIT_SCHED_MACHINE_EFFECTS_H
#define VESTA_JIT_SCHED_MACHINE_EFFECTS_H

#include "jit/machine_ir.h"
#include "vx/asm/instr_db.h"

#include <cstdint>
#include <vector>

namespace jit {
namespace sched {

/// ISA sobre la que se calculan los efectos (elige la DB: x86 / arm64).
using EffIsa = vx::instr_db::Isa;

/**
 * @brief Efectos de una @c MInstr: que registros lee/escribe (explicitos +
 *        implicitos), si toca flags y memoria, y si es una barrera.
 *
 * Los identificadores de registro usan un espacio UNIFORME:
 *   - fisicos (post-regalloc): el id de @c MReg (0..63).
 *   - virtuales (pre-regalloc): @c VREG_BASE + vreg_id.
 * Asi un mismo dependency-DAG sirve antes o despues del register allocator.
 */
struct MEffects {
    static constexpr uint32_t VREG_BASE = 1u
                                          << 20; ///< separa vregs de fisicos.

    std::vector<uint32_t> reads; ///< registros leidos (explicitos + implicitos)
    std::vector<uint32_t>
        writes;                ///< registros escritos (explicitos+implicitos)
    bool reads_flags = false;  ///< lee RFLAGS (Jcc/SETcc/CMOVcc/ADC/SBB)
    bool writes_flags = false; ///< escribe RFLAGS (ALU/CMP/TEST/...)
    bool reads_mem = false;    ///< lee memoria
    bool writes_mem = false;   ///< escribe memoria
    bool is_barrier = false;   ///< CALL/RET/SAFEPOINT: no reordenar a traves
};

/**
 * @brief Anade @p k a @p v si no estaba ya.
 *
 * Las listas son cortisimas -- media docena de registros --, asi que buscar
 * linealmente en un vector contiguo gana a cualquier conjunto: cabe en una
 * linea de cache y no hay nada que reservar.
 *
 * Vive en la cabecera porque lo usan tanto el modulo comun como la tabla de
 * cada ISA, y tener dos copias de algo tan pequeno es justo como se separan.
 *
 * @param v Lista de lecturas o de escrituras.
 * @param k Clave de registro; @c UINT32_MAX quiere decir "no es un registro" y
 *          no se anade.
 */
inline void add_reg(std::vector<uint32_t> &v, uint32_t k) {
    if (k == UINT32_MAX) return;
    for (const uint32_t x : v)
        if (x == k) return;
    v.push_back(k);
}

/**
 * @brief Calcula los efectos completos de @p mi consultando las DBs generadas.
 *
 * Los efectos de las instrucciones REALES de la ISA (add/mov/idiv/addsd/...) se
 * leen de @c vx::instr_db (rmask/wmask/memflags de la forma) + los registros
 * implicitos con nombre de @c vx::asm (implicit_write).  NO se re-derivan a
 * mano: la DB es la fuente de verdad.  Solo los PSEUDOS propios de VestaVM
 * (LOAD_VM, STORE_VM, DIVMOD_V, ALLOCA, SAFEPOINT, ARG, TAILCALL, ...), que no
 * existen en ninguna ISA, se modelan aqui explicitamente.
 *
 * La ISA es OBLIGATORIA y no tiene valor por defecto.  Lo tuvo -- x86 --, y un
 * valor por defecto aqui es una suposicion con permiso: quien olvidara pasarla
 * recibia los efectos de otra arquitectura sin que nada avisara, que es
 * exactamente el fallo que este modulo existe para evitar.  Quien compila para
 * ejecutar AQUI la saca de @c vx::isa_host(); quien genera un binario para otro
 * sitio, del objetivo declarado (@c vx::isa_actual()).
 *
 * @param mi   instruccion maquina.
 * @param isa  ISA de la DB a consultar.
 */
MEffects machine_effects(const MInstr &mi, EffIsa isa);

/**
 * @brief Igual, pero pudiendo llegar al bloque de `asm`.
 *
 * Un `asm` NO es opaco.  Solo el `asm volatile` llega hasta aqui como
 * @c INLINE_ASM_RAW -- un `asm` normal se ELEVA a IR y se optimiza como
 * cualquier otro codigo --, y aun ese conoce sus registros: viven en su
 * @c AsmBlob -- @c in_vregs / @c out_vregs antes de repartir, @c in_phys /
 * @c out_phys despues, mas @c clobbers --.  Lo que pasa es que no estan en los
 * operandos de la instruccion, asi que la version que solo recibe la @c MInstr
 * no puede alcanzarlos y lo degrada a BARRERA: suficiente para no reordenar a
 * traves, insuficiente para saber que sigue vivo.
 *
 * Quien pregunte por liveness necesita esta.  El unico caso que sigue siendo
 * una barrera sin detalle es un bloque al que no se le infirieron los clobbers
 * (@c clobbers_conocidos a false, lo que activa `noinfer`).
 *
 * @param mf  Funcion a la que pertenece @p mi (para llegar a @c asm_blobs).
 * @param mi  Instruccion.
 * @param isa ISA de la DB a consultar.
 */
MEffects machine_effects(const MFunction &mf, const MInstr &mi, EffIsa isa);

/**
 * @brief Mnemonico de la ISA para un @c MOp REAL (o @c nullptr si es un pseudo
 *        de VestaVM sin instruccion equivalente).  Solo el NOMBRE: los efectos
 *        salen de la DB, no de aqui.  @p isa selecciona x86 vs arm64.
 */
const char *mop_mnemonic(MOp op, EffIsa isa);

} // namespace sched
} // namespace jit

#endif // VESTA_JIT_SCHED_MACHINE_EFFECTS_H
