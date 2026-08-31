/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/phys_liveness.cpp
 * @brief Calculo de @ref analysis::facts::PhysLivenessFacts (ver la cabecera).
 *
 * El algoritmo es el de siempre -- gen/kill por bloque, punto fijo hacia atras,
 * y una pasada dentro de cada bloque -- y esta escrito igual que el de
 * @c build_intervals a proposito: es la misma pregunta en el otro dominio.
 *
 * Lo que NO se escribe aqui es el SABER.  Que lee y que escribe cada
 * instruccion lo contesta @ref jit::sched::machine_effects, que lo saca de la
 * base de instrucciones -- con los registros implicitos, que son justo los que
 * no se ven mirando los operandos: el RDX:RAX de una division, el RCX de un
 * desplazamiento variable -- y del bloque de `asm` cuando lo hay.
 */

#include "analysis/facts/phys_liveness.h"

#include "jit/sched/machine_effects.h" // el saber: la DB es la fuente de verdad
#include "vx/asm/asm_effects.h" // isa_host(): para que ISA se pregunta

namespace analysis {
namespace facts {

namespace {

/// @brief Los registros de @p v que son FISICOS, como conjunto de bits.
///
/// El espacio de ids es uniforme: por debajo de @c VREG_BASE son fisicos, por
/// encima son virtuales.  Aqui solo interesan los primeros; si aparece uno
/// virtual es que se pregunto sobre codigo sin repartir, y quien llama lo cuenta
/// como no saber en vez de mezclar dos dominios.
inline PhysRegSet reg_mask(const std::vector<uint32_t> &v, bool &saw_virtual) {
    PhysRegSet m = 0;
    for (const uint32_t id : v) {
        if (id >= jit::sched::MEffects::VREG_BASE) {
            saw_virtual = true;
            continue;
        }
        m |= phys_bit(static_cast<uint8_t>(id));
    }
    return m;
}

} // namespace

PhysLivenessFacts compute_phys_liveness(const jit::MFunction &pf) {
    PhysLivenessFacts F;
    const size_t NB = pf.blocks.size();
    F.off.assign(NB + 1, 0);
    for (size_t b = 0; b < NB; ++b)
        F.off[b + 1] =
            F.off[b] + static_cast<uint32_t>(pf.blocks[b].instrs.size());
    F.live_out.assign(NB, 0);
    F.after.assign(F.off[NB], kPhysRegAll);
    if (NB == 0) return F;

    const jit::sched::EffIsa isa =
        (vx::isa_host() == vx::instr_db::Isa::ARM64)
                                       ? jit::sched::EffIsa::ARM64
                                       : jit::sched::EffIsa::X86;

    /* Los efectos se calculan UNA vez por instruccion y se guardan: el punto
     * fijo vuelve a pasar por los bloques varias veces, y consultar la base en
     * cada vuelta seria pagar N veces por la misma respuesta. */
    struct Touches {
        PhysRegSet reads = 0, writes = 0;
        bool unknown = false;
    };
    /* UN BLOQUE NO SIEMPRE ES UN BLOQUE BASICO.
     *
     * El recorrido de mas abajo va hacia atras por las instrucciones de un
     * bloque dando por hecho que el control las atraviesa en linea recta.  Eso
     * vale mientras el bloque sea de verdad basico -- se entra por arriba y se
     * sale por abajo --, y aqui NO siempre lo es: hay pasos que dejan islas
     * dentro (una etiqueta a la que se salta desde el propio bloque, un salto
     * que no es el ultimo, la tabla de un `switch` con sus datos detras).
     *
     * Con una isla dentro, ir hacia atras miente en las dos direcciones: cree
     * que una escritura mata lo de arriba cuando el salto se la salta, y cree
     * que lo de abajo viene de arriba cuando puede venir de otro sitio.  Se vio
     * en `346_optional_struct`: un valor se ponia en un registro, mas abajo un
     * `pop` lo restauraba, y por en medio habia un salto que se saltaba el
     * `pop` y llegaba a un uso -- asi que el valor SI hacia falta y el recorrido
     * lo daba por muerto.
     *
     * Aqui NO se modela ese control interno: se DICE que no se sabe, que es lo
     * unico honesto, y quien pregunte se lo encontrara como un punto sin saber.
     * Modelarlo de verdad es construir el grafo dentro del bloque, y eso es
     * arreglar el bloque, no este fichero. */
    const auto has_island = [](const jit::MBlock &blk) {
        const size_t n = blk.instrs.size();
        for (size_t i = 0; i < n; ++i) {
            const jit::MOp op = blk.instrs[i].op;
            // Una etiqueta que no sea la de entrada: se puede llegar ahi.
            if (op == jit::MOp::LABEL_DEF && i != 0) return true;
            // Un salto que no sea el ultimo: se puede salir antes.
            if ((op == jit::MOp::JMP || op == jit::MOp::JCC) && i + 1 != n)
                return true;
        }
        return false;
    };

    std::vector<Touches> touches(F.off[NB]);
    for (size_t b = 0; b < NB; ++b) {
        const auto &is = pf.blocks[b].instrs;
        if (has_island(pf.blocks[b])) {
            for (size_t i = 0; i < is.size(); ++i) {
                touches[F.off[b] + i].unknown = true;
                ++F.unknown_points;
            }
            continue;
        }
        for (size_t i = 0; i < is.size(); ++i) {
            /* Un `asm volatile` dice lo que lee: sus operandos declarados, y
             * ademas lo que su CUERPO nombra o lee sin nombrar, que la
             * inferencia sobre el texto dedujo preguntandole a la base
             * instruccion por instruccion.
             *
             * Lo unico que se da por desconocido es un cuerpo que la
             * inferencia no pudo cubrir entero -- una linea sin emparejar, o
             * un `noinfer` que la desactiva --.  Eso lo dice
             * @c AsmBlob::reads_conocidos, que distingue "no lee nada mas" de
             * "no se sabe si lee algo mas". */
            if (is[i].op == jit::MOp::INLINE_ASM_RAW) {
                Touches &t = touches[F.off[b] + i];
                const uint32_t bi = static_cast<uint32_t>(is[i].src1.value);
                if (bi >= pf.asm_blobs.size() ||
                    !pf.asm_blobs[bi].reads_conocidos) {
                    t.unknown = true;
                    ++F.unknown_points;
                    continue;
                }
                const jit::AsmBlob &blob = pf.asm_blobs[bi];
                for (const uint8_t r : blob.in_phys) t.reads |= phys_bit(r);
                for (const uint8_t r : blob.body_reads) t.reads |= phys_bit(r);
                for (const uint8_t r : blob.out_phys) t.writes |= phys_bit(r);
                for (const uint8_t r : blob.clobbers) t.writes |= phys_bit(r);
                continue;
            }
            const jit::sched::MEffects e =
                jit::sched::machine_effects(pf, is[i], isa);
            Touches &t = touches[F.off[b] + i];
            bool virt = false;
            t.reads = reg_mask(e.reads, virt);
            t.writes = reg_mask(e.writes, virt);
            /* Un id virtual aqui significa que esto no esta repartido, y
             * entonces la respuesta no vale para este dominio.  Se cuenta y se
             * trata como no saber, que es la unica salida honesta. */
            if (virt) {
                t.unknown = true;
                ++F.unknown_points;
            }
        }
    }

    /* 1) gen/kill por bloque.  Una lectura queda expuesta hacia arriba solo si
     *    nadie de este bloque la escribio ya; se mira ANTES de anotar lo que
     *    escribe, para que un `dst op= src` conserve su lectura. */
    std::vector<PhysRegSet> gen(NB, 0), kill(NB, 0);
    for (size_t b = 0; b < NB; ++b) {
        const size_t n = pf.blocks[b].instrs.size();
        for (size_t i = 0; i < n; ++i) {
            const Touches &t = touches[F.off[b] + i];
            if (t.unknown) {
                // No se sabe: lo no escrito aun se da por leido y no se mata
                // nada.
                gen[b] |= (kPhysRegAll & ~kill[b]);
                continue;
            }
            gen[b] |= (t.reads & ~kill[b]);
            kill[b] |= t.writes;
        }
    }

    /* 2) Punto fijo hacia atras: live_out[b] = U live_in[succ].  Se recorre en
     *    orden inverso de indice, que en un CFG reducible converge en pocas
     *    vueltas porque los sucesores suelen ir detras. */
    std::vector<PhysRegSet> live_in(NB, 0);
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = NB; i-- > 0;) {
            const jit::MBlock &blk = pf.blocks[i];
            PhysRegSet out = 0;
            const auto join = [&](jit::MBlockId s) {
                if (s != jit::MBLOCK_INVALID && s < NB) out |= live_in[s];
            };
            join(blk.succ_a);
            join(blk.succ_b);
            for (const jit::MBlockId s : blk.extra_succs) join(s);
            const PhysRegSet in = gen[i] | (out & ~kill[i]);
            if (out != F.live_out[i] || in != live_in[i]) {
                F.live_out[i] = out;
                live_in[i] = in;
                changed = true;
            }
        }
    }

    /* 3) Dentro de cada bloque, hacia atras: lo live DESPUES de cada
     *    instruccion.  Antes de ella = (lo de despues sin lo que escribe) mas
     *    lo que lee; en ese orden, para que un `dst op= src` salga VIVO. */
    for (size_t b = 0; b < NB; ++b) {
        const size_t n = pf.blocks[b].instrs.size();
        PhysRegSet live = F.live_out[b];
        for (size_t i = n; i-- > 0;) {
            F.after[F.off[b] + i] = live;
            const Touches &t = touches[F.off[b] + i];
            live = t.unknown ? kPhysRegAll : ((live & ~t.writes) | t.reads);
        }
    }
    return F;
}

} // namespace facts
} // namespace analysis
