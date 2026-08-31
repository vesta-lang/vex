/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/memory_access_producer.cpp
 * @brief El dominio `asa.memory_access`: QUE toca cada instruccion -- que lee,
 *        que escribe y donde --, y de las que no se sabe, por que no.
 *
 * El vocabulario ya existia y es la UNA SOLA VERDAD que consumen los pases
 * sensibles a memoria (@ref analysis::memory_access).  Lo que faltaba es que
 * ese conocimiento llegara al ALMACEN: hoy lo pregunta quien optimiza, cada uno
 * por su cuenta y en su propia pasada, y nadie mas puede consultarlo.
 *
 * La diferencia con el dominio `asa.memory`, que ya estaba: aquel dice a que
 * APUNTA un valor (points-to); este dice que TOCA una instruccion.  Son dos
 * preguntas distintas y la segunda se apoya en la primera -- por eso el
 * productor recibe la tabla ya montada en vez de reconstruirla (Regla 1) --.
 *
 * QUE GANA CON ESTAR AQUI:
 *
 *   - **El editor y el linter pueden preguntarlo.**  "Que escribe esta linea"
 *     es la pregunta de fondo de media docena de avisos, y hoy no hay a quien
 *     hacersela sin volver a montar el analisis entero.
 *   - **Se cuenta lo OPACO, y por que.**  Una instruccion que toca memoria y no
 *     se puede localizar deja un motivo con su codigo, asi que se puede medir
 *     cuanto conocimiento se pierde por ahi en vez de intuirlo.  Es el mismo
 *     dato que necesita quien quiera atacar esas fronteras.
 *   - **Persiste.**  El almacen se guarda entre compilaciones.
 *
 * Lo que NO entra: una llamada.  El efecto de una llamada lo dice
 * `EffectAnalysis`, no este vocabulario, y meterlo aqui seria dar dos
 * respuestas a la misma pregunta.
 */

#include "analysis/asa/producers.h"
#include "analysis/memory/memory_access.h"
#include "analysis/memory/points_to.h"
#include "ir/ssa_ir.h"

#include <sstream>
#include <string>

namespace analysis {
namespace asa {

namespace {

const char *const kProducerMemoryAccess = "asa.memory_access";

/// El sujeto es la INSTRUCCION: lo que se afirma es de ella, no del valor.
Subject instruction_subject(Production &p, const ir::IrFunction &fn,
                            uint32_t pos) {
    Subject s;
    s.kind = Subject::Kind::Instruction;
    s.function = p.store.intern(fn.name);
    s.id = pos;
    return s;
}

/// El NOMBRE de una localizacion: `stack#2+8(4B)`.
///
/// Es un IDENTIFICADOR, no una frase.  La diferencia importa: un hecho del ASA
/// no puede llevar texto en un idioma, porque quien lo pinta -- el volcado, el
/// linter, el editor -- lo hace en el que el usuario tenga puesto y la frase
/// sale del catalogo, no de aqui.  Lo que si puede llevar es como se LLAMA una
/// cosa, y eso no se traduce.
std::string loc_name(const effects::AbstractLoc &l) {
    const char *clase = "?";
    switch (l.kind) {
    case effects::AbstractLoc::Kind::None: clase = "none"; break;
    case effects::AbstractLoc::Kind::Unknown: clase = "unknown"; break;
    case effects::AbstractLoc::Kind::Stack: clase = "stack"; break;
    case effects::AbstractLoc::Kind::Heap: clase = "heap"; break;
    case effects::AbstractLoc::Kind::Global: clase = "global"; break;
    case effects::AbstractLoc::Kind::ArgDerived: clase = "arg"; break;
    }
    std::ostringstream o;
    o << clase;
    /* El centinela dice "toda la clase", no una raiz concreta: ensenarlo como
     * un numero (`unknown#4294967295`) hace pasar por dato lo que es la
     * ausencia de dato. */
    if (l.id != 0 && l.id != effects::LOC_GENERIC) o << "#" << l.id;
    if (l.off != 0) o << (l.off > 0 ? "+" : "") << l.off;
    if (l.width != 0) o << "(" << l.width << "B)";
    return o.str();
}

/// Los nombres de una lista de localizaciones, separados por comas.
std::string loc_list(const std::vector<effects::AbstractLoc> &ls) {
    std::string s;
    for (size_t i = 0; i < ls.size(); ++i) {
        if (i) s += ",";
        s += loc_name(ls[i]);
    }
    return s;
}

void produce_memory_access(Production &p) {
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        /* La tabla points-to se RECIBE de la base comun: reconstruirla aqui
         * seria producir dos veces lo mismo, y las dos copias divergirian en
         * cuanto una se quedara sin actualizar. */
        const PointsTo &pt = p.base.memory(fn);
        const Seal s = p.base.seal(kProducerMemoryAccess, fn);
        uint32_t pos = 0;
        uint32_t tocan = 0;
        for (const ir::IrBlock &bb : fn.blocks) {
            for (const ir::IrInstr &ins : bb.instrs) {
                const uint32_t aqui = pos++;
                const MemoryAccess a = memory_access(ins, pt);
                if (!a.touches) continue; // no accede: no hay nada que decir
                ++tocan;
                const Subject about = instruction_subject(p, fn, aqui);
                if (a.opaque) {
                    /* Toca memoria y no se sabe donde.  Se DICE, con su motivo:
                     * un dominio que se callara aqui pareceria que no hay nada
                     * que tocar, que es lo contrario de lo que pasa. */
                    p.say_unknown(about, UnknownReason::OpaqueBoundary,
                                  "memory_access.not_localizable",
                                  kProducerMemoryAccess, "");
                    continue;
                }
                Fact f;
                f.what.domain = kProducerMemoryAccess;
                f.what.code = a.is_store ? (a.is_load ? "memory_access.rw"
                                                      : "memory_access.write")
                                         : "memory_access.read";
                f.what.a = static_cast<int64_t>(a.reads.size());
                f.what.b = static_cast<int64_t>(a.writes.size());
                /* Cuantas lee y cuantas escribe van en los NUMEROS; el detalle
                 * lleva solo COMO SE LLAMAN, que es lo que no cabe en dos.  La
                 * frase ("lee ...", "escribe ...") la pone quien lo pinta,
                 * desde el catalogo y en el idioma del usuario. */
                std::ostringstream o;
                o << loc_list(a.reads);
                // La flecha solo cuando hay las DOS: separa origen de destino.
                if (!a.reads.empty() && !a.writes.empty()) o << " -> ";
                o << loc_list(a.writes);
                f.what.detail = p.store.intern(o.str());
                f.about = about;
                /* DEMOSTRADO: lo que una instruccion toca sale de su opcode y
                 * de la tabla points-to, no de una suposicion.  Lo que no se
                 * pudo localizar salio arriba como un "no se" con su motivo. */
                f.seal = s;
                f.seal.certainty = Certainty::Proven;
                f.proof.rule = "memory_access.opcode+points-to";
                p.assert_fact(std::move(f));
            }
            if (bb.instrs.empty()) ++pos; // misma linealizacion que liveness
        }
        if (tocan == 0) {
            /* Una funcion que no toca memoria en ninguna instruccion es un
             * HECHO, no un vacio: sin decirlo no habria forma de distinguirlo
             * de que el dominio no llegara a mirarla. */
            Subject sf;
            sf.kind = Subject::Kind::Function;
            sf.function = p.store.intern(fn.name);
            p.say_unknown(sf, UnknownReason::NothingToSay,
                          "memory_access.no_accesses", kProducerMemoryAccess,
                          "");
        }
    }
}

} // namespace

void register_memory_access_producer() {
    register_producer(kProducerMemoryAccess, &produce_memory_access);
}

} // namespace asa
} // namespace analysis
