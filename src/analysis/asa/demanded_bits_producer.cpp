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
 * @file analysis/asa/demanded_bits_producer.cpp
 * @brief El dominio `asa.demanded_bits`: cuantos bits de un valor mira alguien.
 *
 * Aqui NO se calcula nada.  El analisis vive en
 * @ref analysis/facts/demanded_bits.h y lo comparte la base, asi que el pase
 * que lo consume y este productor acaban en la MISMA instancia.  Esto solo lo
 * afirma, que es lo que separa un productor de un analisis.
 *
 * Es la pregunta DUAL de los rangos y los KnownBits, y no la contesta ninguno
 * de los dos:
 *
 *     KnownBits          "que bits valen algo AL SALIR"    -> hacia adelante
 *     bits demandados    "que bits llega a leer ALGUIEN"   -> hacia atras
 *
 * Antes vivia dentro de `ir_pass_elide_narrow_norm`, en un punto fijo privado
 * con su lista de consumidores tolerados escrita a mano.  Con eso pasaban las
 * dos cosas que el ASA existe para impedir: se quedaba corto sin que nadie lo
 * notara -- una cadena `trunc` + `bitcast` + `store` cortaba la tolerancia en
 * el bitcast --, y ningun otro consumidor podia preguntarlo, ni el volcado
 * ensenarlo.
 */

#include "analysis/asa/fact_base.h"
#include "analysis/asa/producers.h"
#include "analysis/facts/demanded_bits.h"
#include "ir/ir_type_info.h"
#include "ir/ssa_ir.h"

namespace analysis {
namespace asa {

namespace {

/**
 * @brief Huella de las ENTRADAS del dominio, sin producir nada.
 *
 * Cubre EXACTAMENTE lo que `compute_demanded_bits` mira -- la operacion, su
 * tipo, el destino, los operandos, los argumentos de phi y el tipo de cada
 * valor -- y nada mas.  Ni los nombres, ni las lineas, ni la memoria
 * estatica: cambiar un literal de cadena no puede cambiar que bits se leen de
 * un entero, y si la huella lo incluyera, tirar los hechos guardados por eso
 * seria trabajo repetido sin motivo.
 *
 * Barata a proposito: se llama al LEER el fichero de hechos, cuando todavia no
 * se ha producido nada, para decidir si lo guardado sigue valiendo.
 *
 * @param mod Modulo que se esta compilando.
 * @return La huella; nunca cero -- cero significa "no se decirlo", y aqui si
 *         se sabe.
 */
uint64_t demanded_bits_inputs(const ir::IrModule &mod) {
    uint64_t h = 0xCBF29CE484222325ull; // FNV-1a de 64
    auto mezcla = [&h](uint64_t v) {
        h ^= v;
        h *= 0x100000001B3ull;
    };
    for (const ir::IrFunction &fn : mod.functions) {
        if (fn.is_native) continue;
        mezcla(fn.values.size());
        for (const ir::IrValue &v : fn.values)
            mezcla(static_cast<uint64_t>(v.type));
        for (const ir::IrBlock &bb : fn.blocks) {
            for (const ir::IrInstr &in : bb.instrs) {
                mezcla(static_cast<uint64_t>(in.op));
                mezcla(static_cast<uint64_t>(in.type));
                mezcla(in.dst);
                for (ir::IrValueId o : in.operands)
                    mezcla(o);
                for (const ir::IrPhiArg &pa : in.phi_args)
                    mezcla(pa.value);
                mezcla(in.func_ptr);
            }
        }
    }
    /* Cero esta reservado para "no se decirlo", asi que un modulo que diera
     * cero por casualidad se anunciaria como indecible y lo guardado se
     * aceptaria sin comprobar. */
    return h == 0 ? 1ull : h;
}

} // namespace

/**
 * @brief Afirma, por valor, cuantos bits bajos se leen de el.
 * @param p Lo que el productor recibe (modulo, base y almacen).
 */
void produce_demanded_bits(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const DemandedBits &db = p.base.demanded(fn);
        const Seal s = p.base.seal(kProducerDemandedBits, fn);
        for (ir::IrValueId v = 0; v < fn.values.size(); ++v) {
            const uint8_t leidos = db.at(v);
            const uint8_t promete = type_promised_bits(fn.values[v].type);

            /* El liston son los 64 del REGISTRO, no lo que el tipo promete.
             *
             * Un `i32` vive en un registro de 64, y la normalizacion existe
             * justo para limpiar los bits 32..63; decir "de este i32 se leen
             * 32 bits" es exactamente lo que autoriza a no limpiarlos.
             * Comparado contra el tipo, ese caso -- el unico que importa --
             * salia como "nada que decir": de 4812 valores solo 4 llegaban a
             * afirmarse. */
            if (leidos >= 64) {
                p.say_unknown(value_subject(p, fn, v),
                              UnknownReason::NothingToSay,
                              "demanded_bits.whole_register",
                              kProducerDemandedBits, "", Scope::everywhere());
                continue;
            }

            Fact f;
            f.what.domain = kProducerDemandedBits;
            /* Un valor sin NINGUN uso es otra cosa que uno del que se leen
             * pocos bits, y se dice aparte: al primero le sobra la
             * instruccion entera, al segundo solo la limpieza. */
            f.what.code = leidos == 0 ? "demanded_bits.none" : "demanded_bits.low";
            f.what.a = leidos;
            f.what.b = promete;
            f.about = value_subject(p, fn, v);
            f.seal = s;
            /* La certeza la puso la base al calcularlo (punto fijo cerrado o
             * cortado por la cota); aqui no se re-decide. */
            support_with_structure(p, fn, f, "backward-data-flow");
            p.assert_fact(std::move(f));
        }
    }
}

void register_demanded_bits_producer() {
    register_producer(kProducerDemandedBits, &produce_demanded_bits,
                      &demanded_bits_inputs);
}

} // namespace asa
} // namespace analysis
