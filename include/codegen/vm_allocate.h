/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/vm_allocate.h
 * @brief La PUERTA del interprete al allocator: vivacidad del IR -> registros.
 *
 * Los tres modos usan el MISMO nucleo (@c rbank_solve) por puertas distintas:
 * el JIT y el AOT entran desde los intervalos del MachineIR
 * (@c rbank_allocate), el interprete desde la vivacidad del IR.  Son espacios
 * de posiciones distintos -- IR = 1 por instruccion, MachineIR = 2 -- y por eso
 * hay dos adaptadores; el asignador, uno.
 *
 * Aqui no se decide nada: se construye el problema y se delega.  Si esta puerta
 * empezara a resolver, el interprete tendria otra vez su propio allocator con
 * otro nombre.
 */

#ifndef VESTA_CODEGEN_VM_ALLOCATE_H
#define VESTA_CODEGEN_VM_ALLOCATE_H

#include "codegen/rbank/allocate.h"
#include "codegen/rbank/physical_bank.h"
#include "codegen/regalloc.h"
#include "codegen/vm_problem.h"
#include "codegen/vm_target.h"
#include "ir/liveness.h"
#include "ir/ssa_ir.h"
#include "jit/backend_caps.h"

#include <cstdint>
#include <vector>

namespace codegen {

/**
 * @brief Asigna los registros del camino del INTERPRETE con @c codegen::rbank
 *        -- el mismo allocator que ya usan el JIT y el AOT.
 *
 * La funcion se limita a construir el problema en el dominio del IR y delegar
 * en
 * @c rbank_solve.  NO reimplementa la secuencia greedy/taxonomia/Recovery: si
 * lo hiciera, el interprete tendria su propia copia del allocator y volveriamos
 * al punto de partida con otro nombre.
 *
 * @param coalesce_remap  congruencias de PHI.  El adaptador las FUNDE al entrar
 *        (congruentes SON el mismo valor) y aqui se REPARTEN al salir: son la
 * ida y la vuelta de la misma transformacion.
 */
inline codegen::RegAlloc
vm_allocate(const ir::IrFunction &fn, const ir::LivenessResult &live,
            const std::vector<uint32_t> *coalesce_remap) {
    const rbank::AbstractProblem p =
        liveness_to_problem(fn, live, coalesce_remap);
    const uint32_t n = static_cast<uint32_t>(fn.values.size());
    if (p.values.empty()) {
        codegen::RegAlloc empty;
        empty.assign.assign(n, codegen::RegAlloc::VAssign{});
        return empty;
    }
    const rbank::PhysicalRegisterBank &bank =
        rbank::physical_bank_x86_64_from_reginfo_cached(
            target_vm(), jit::backend_caps_host());
    codegen::RegAlloc ra = rbank::rbank_solve(
        p, n, bank, /*vec_active=*/false, /*next_use=*/nullptr,
        /*trace=*/nullptr, /*recover=*/true);

    /* Repartir la asignacion del root a los demas miembros de su clase.  El
     * problema tenia UN valor por clase (fundido en el adaptador), asi que sin
     * esto los miembros no-root quedarian sin ubicacion. */
    if (coalesce_remap && !coalesce_remap->empty()) {
        const std::vector<uint32_t> &remap = *coalesce_remap;
        ra.assign.resize(n);
        for (uint32_t v = 0; v < n; ++v) {
            const uint32_t rt = (v < remap.size()) ? remap[v] : v;
            if (rt == v || rt >= ra.assign.size()) continue;
            ra.assign[v] = ra.assign[rt];
        }
    }
    return ra;
}

} // namespace codegen

#endif // VESTA_CODEGEN_VM_ALLOCATE_H
