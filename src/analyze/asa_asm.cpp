/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analyze/asa_asm.cpp
 * @brief El dominio del ASM como productor de hechos del ASA.
 *
 * Responde lo que hay que poder preguntar de un `asm` sin abrir el fuente:
 *
 *   - QUE se elevo a IR y por tanto lo ve el optimizador como cualquier otra
 *     operacion (y lo ejecuta el interprete).
 *   - QUE se quedo como MICRO ASM: una instruccion que no tiene forma tipada en
 *     el IR -- `cpuid`, `mfence`, SIMD -- pero que NO es una caja negra: lleva
 * su identidad en la base de datos de instrucciones, de donde salen sus
 * efectos.
 *   - QUE bloque no se elevo en absoluto y sigue siendo opaco, con cuanto de el
 *     se entiende y que rasgos del procesador exige.
 *   - QUE EFECTOS tiene cada cosa: memoria, banderas, barreras, control.
 *
 * Vive en @c src/analyze y no en la capa de analisis porque usa el informe de
 * bloques asm (@c analyze::analizar_bloques_asm), que conoce la base de datos
 * de instrucciones.  Se da de alta con @c registrar_productor desde quien lo
 * tenga disponible: el registro existe justamente para que un dominio pueda
 * vivir en su capa y aun asi aparecer en el almacen y en el volcado.
 */

#include "analyze/asm_report.h"

#include "vx/asm/asm_lift_registro.h"
#include "vx/asm/instr_db.h"

#include "analysis/asa/producers.h"
#include "analysis/facts/asm_bindings.h" // que valor entra por que registro
#include "ir/ssa_ir.h"

#include <sstream>
#include <unordered_map>

namespace analyze {

namespace {

using analysis::asa::Certainty;
using analysis::asa::Fact;
using analysis::asa::FactId;
using analysis::asa::Production;
using analysis::asa::Subject;

const char *const kProductorAsm = "asa.asm";

/// El mnemonico de una micro-instruccion: la primera palabra de su plantilla.
std::string mnemonico(const std::string &tmpl) {
    size_t i = 0;
    while (i < tmpl.size() && (tmpl[i] == ' ' || tmpl[i] == '\t'))
        ++i;
    const size_t ini = i;
    while (i < tmpl.size() && tmpl[i] != ' ' && tmpl[i] != '\t')
        ++i;
    return tmpl.substr(ini, i - ini);
}

/// Las tablas de la ISA de una micro-instruccion.  @c AsmMicro::isa lleva el
/// mismo numero que @c instr_db::Isa (lo pone el elevado).
const vx::instr_db::IsaData *datos_isa(uint8_t isa) {
    using vx::instr_db::Isa;
    switch (static_cast<Isa>(isa)) {
    case Isa::X86: return &vx::instr_db::db_x86();
    case Isa::ARM64: return &vx::instr_db::db_arm64();
    case Isa::ARM32: return &vx::instr_db::db_arm32();
    case Isa::RISCV: return &vx::instr_db::db_riscv();
    }
    return nullptr;
}

/// Lo que la BASE DE DATOS dice de una forma, y lo que el IR se guardo de ella.
///
/// Se ensenan LOS DOS a proposito.  El campo @c eff de la instruccion es un
/// ATAJO cacheado; la verdad esta en la DB.  Mientras coincidan, el atajo es
/// legitimo; el dia que no, hay un fallo de modelado nuestro -- y esto es lo
/// unico que lo hace visible sin abrir el generador de codigo.
struct EfectosMicro {
    std::string texto;
    bool discrepa = false;
    std::string discrepancia;
};

EfectosMicro efectos_de(const ir::AsmMicro &m) {
    EfectosMicro r;
    std::ostringstream o;

    const vx::instr_db::IsaData *d = datos_isa(m.isa);
    const vx::instr_db::DbForm *forma =
        (d != nullptr && m.form_id < d->form_count) ? &d->forms[m.form_id]
                                                    : nullptr;
    auto cadena = [d](uint32_t idx) -> const char * {
        return (d != nullptr && idx < d->str_count) ? d->str[idx] : "?";
    };

    if (forma != nullptr) {
        o << cadena(forma->iclass);
        const char *conjunto = cadena(forma->isa_set);
        if (conjunto[0] != '\0' && conjunto[0] != '-')
            o << " (" << conjunto << ")";
        /* Se nombra lo que se esta leyendo: la DB marca memoria y banderas, NO
         * barreras ni llamadas.  Decir "DB: sin efectos" de un `mfence` seria
         * falso -- la DB no dice que no sea barrera, dice que no toca memoria
         * ni banderas --, y ese matiz es justo el que hay que ver para saber si
         * el modelado es bueno. */
        o << " | DB(memoria/banderas):";
        const bool db_mem = (forma->memflags & 0x01) != 0;
        const bool db_wf = (forma->memflags & 0x04) != 0;
        const bool db_rf = (forma->memflags & 0x08) != 0;
        if (db_mem) o << " memoria";
        if (db_rf) o << " lee-banderas";
        if (db_wf) o << " escribe-banderas";
        if (!db_mem && !db_rf && !db_wf) o << " sin marcas";
        /* Los operandos con su papel y el conjunto de registros que la DB
         * permite: es lo que hay que mirar para saber si el elevado ato los
         * valores del programa a los sitios correctos. */
        for (uint8_t i = 0; i < forma->ops_count && d != nullptr; ++i) {
            const size_t idx = forma->ops_off + i;
            if (idx >= d->ops_count) break;
            const vx::instr_db::DbOperand &op = d->ops[idx];
            const bool lee = (op.flags & 0x01) != 0;
            const bool esc = (op.flags & 0x02) != 0;
            const bool imp = (op.flags & 0x04) != 0;
            o << " [" << (lee ? "r" : "") << (esc ? "w" : "")
              << (imp ? "!" : "") << " " << cadena(op.regset);
            if (op.width != 0) o << ":" << op.width;
            o << "]";
        }

        /* Y ahora el contraste con lo que el IR cacheo. */
        const bool ir_mem = (m.eff & 0x01) != 0;
        const bool ir_rf = (m.eff & 0x02) != 0;
        const bool ir_wf = (m.eff & 0x04) != 0;
        std::ostringstream dif;
        if (ir_mem != db_mem)
            dif << " memoria(IR=" << ir_mem << ",DB=" << db_mem << ")";
        if (ir_rf != db_rf)
            dif << " lee-banderas(IR=" << ir_rf << ",DB=" << db_rf << ")";
        if (ir_wf != db_wf)
            dif << " escribe-banderas(IR=" << ir_wf << ",DB=" << db_wf << ")";
        if (!dif.str().empty()) {
            r.discrepa = true;
            r.discrepancia = dif.str();
        }
    } else {
        /* Sin forma en la DB no hay verdad contra la que contrastar: lo que se
         * sepa viene solo del atajo, y eso se dice. */
        o << "forma " << m.form_id << " no esta en la base de datos";
    }

    o << " | IR:";
    if (m.eff & 0x01) o << " memoria";
    if (m.eff & 0x02) o << " lee-banderas";
    if (m.eff & 0x04) o << " escribe-banderas";
    if (m.eff & 0x08) o << " barrera";
    if (m.eff & 0x10) o << " llamada";
    uint32_t lee = 0, escribe = 0, vec = 0;
    for (const ir::AsmMicroOperand &op : m.operands) {
        if (op.reads()) ++lee;
        if (op.writes()) ++escribe;
        if (op.regclass == 2) ++vec;
    }
    o << " lee=" << lee << " escribe=" << escribe;
    if (vec != 0) o << " vectoriales=" << vec;
    r.texto = o.str();
    return r;
}

void produce_asm(Production &p) {
    /* 1. Lo que se quedo como MICRO ASM: sigue siendo asm, pero dentro del IR y
     *    con sus efectos consultables.  El optimizador lo reordena y el backend
     *    lo re-emite verbatim. */
    std::unordered_map<std::string, uint32_t> micros_por_funcion;
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        uint32_t n = 0;
        for (const ir::IrBlock &b : fn.blocks)
            for (const ir::IrInstr &in : b.instrs) {
                if (in.op != ir::IrOp::ASM_MICRO) continue;
                const size_t idx = static_cast<size_t>(in.imm);
                if (idx >= fn.asm_micros.size()) continue;
                const ir::AsmMicro &m = fn.asm_micros[idx];
                ++n;
                const EfectosMicro ef = efectos_de(m);
                Fact f;
                f.what.domain = kProductorAsm;
                f.what.code = "asm.micro";
                f.what.a = m.isa;
                f.what.b = m.form_id;
                std::ostringstream o;
                o << mnemonico(m.tmpl) << " -- " << ef.texto;
                f.what.detail = p.store.intern(o.str());
                f.about.kind = Subject::Kind::Instruction;
                f.about.function = p.store.intern(fn.name);
                f.about.id = static_cast<uint32_t>(idx);
                /* La identidad esta en la base de datos y de ahi salen los
                 * efectos: no es una suposicion sobre lo que hara. */
                f.seal.certainty = Certainty::Proven;
                f.seal.origin.producer = kProductorAsm;
                f.seal.origin.function = f.about.function;
                f.proof.rule = "instruction-database";
                const FactId id_micro = p.assert_fact(std::move(f));

                /* Si el atajo cacheado en el IR no dice lo mismo que la DB, eso
                 * es un fallo de modelado NUESTRO, y hay que verlo: el resto
                 * del compilador razona con el atajo.  Es el ASA comprobando al
                 * propio compilador. */
                if (!ef.discrepa) continue;
                Fact g;
                g.what.domain = kProductorAsm;
                g.what.code = "asm.effects_disagree";
                g.what.a = m.isa;
                g.what.b = m.form_id;
                g.what.detail = p.store.intern(
                    "el atajo del IR no coincide con la DB:" + ef.discrepancia);
                g.about = f.about;
                /* Que discrepan esta VISTO, no supuesto: son dos numeros y no
                 * coinciden.  Lo que no se afirma es cual de los dos miente. */
                g.seal.certainty = Certainty::Proven;
                g.seal.origin.producer = kProductorAsm;
                g.seal.origin.function = g.about.function;
                g.proof.rule = "ir-vs-database";
                g.proof.from.push_back(id_micro);
                p.assert_fact(std::move(g));
            }
        micros_por_funcion[fn.name] = n;
    }

    /* 2. El DETALLE de los bloques asm que siguen en el IR -- opacos o micro
     * --: cuanto de ellos entiende la base, que tocan y que exigen del
     *    procesador.  OJO: esto NO dice si se elevaron; el informe ve lo que
     *    queda, y lo que queda incluye las micro.  El destino lo dice quien
     *    elevo (punto 3), que es el unico que lo sabe. */
    const std::vector<AsmBlockReport> bloques = analizar_bloques_asm(p.mod);
    std::unordered_map<std::string, uint32_t> bloques_en_ir_por_funcion;
    for (const AsmBlockReport &b : bloques) {
        ++bloques_en_ir_por_funcion[b.funcion];
        Fact f;
        f.what.domain = kProductorAsm;
        f.what.code =
            b.opacidad_pedida ? "asm.block_opacity_requested" : "asm.block";
        f.what.a = b.instrucciones;
        f.what.b = b.desconocidas;
        std::ostringstream o;
        o << "linea " << b.linea << ": " << b.instrucciones
          << " instrucciones, " << b.conocidas << " entendidas";
        if (b.desconocidas != 0) o << ", " << b.desconocidas << " sin entender";
        if (b.lee_mem || b.escribe_mem)
            o << " | memoria lee=" << b.lee_mem << " escribe=" << b.escribe_mem;
        if (b.escribe_flags) o << " | banderas=" << b.escribe_flags;
        if (b.control) o << " | saltos=" << b.control;
        if (b.barrera) o << " | barrera";
        if (!b.rasgos.empty()) {
            o << " | exige";
            for (const std::string &r : b.rasgos)
                o << " " << r;
        }
        f.what.detail = p.store.intern(o.str());
        f.about.kind = Subject::Kind::Function;
        f.about.function = p.store.intern(b.funcion);
        /* Si la base entiende TODAS sus instrucciones, lo que se dice de sus
         * efectos esta visto entero.  Si queda alguna sin entender, la
         * evidencia apunta pero pudo quedarse algo fuera: eso es inferido, no
         * demostrado. */
        f.seal.certainty =
            b.desconocidas == 0 ? Certainty::Proven : Certainty::Inferred;
        f.seal.origin.producer = kProductorAsm;
        f.seal.origin.function = f.about.function;
        f.proof.rule = "asm-block-read";
        p.assert_fact(std::move(f));
    }

    /* 3. LO QUE SE ELEVO A IR.  No se puede sacar del IR -- una instruccion
     *    elevada es una suma o un almacenamiento como cualquier otro --, asi
     * que lo dice quien lo elevo, que es el unico que lo sabe.  Sin esto, un
     *    programa cuyo asm se elevo entero salia igual que uno sin asm. */
    std::unordered_map<std::string, uint32_t> elevadas_por_funcion;
    std::unordered_map<std::string, uint32_t> sin_elevar_por_funcion;
    std::unordered_map<std::string, uint32_t> bloques_por_funcion;
    for (const vx::BloqueAsmBajado &b : vx::bloques_asm_bajados()) {
        if (!p.mod.functions.empty()) {
            /* Puede ser de otra funcion del mismo proceso (otro modulo, o una
             * que no esta en este IR): no se afirma de lo que no se mira. */
            bool aqui = false;
            for (const ir::IrFunction &fn : p.mod.functions)
                if (fn.name == b.funcion) {
                    aqui = true;
                    break;
                }
            if (!aqui) continue;
        }
        ++bloques_por_funcion[b.funcion];
        if (b.destino == vx::DestinoAsm::ElevadoAIr)
            elevadas_por_funcion[b.funcion] += b.instrucciones;
        else if (b.destino == vx::DestinoAsm::SinElevar)
            ++sin_elevar_por_funcion[b.funcion];
        Fact f;
        f.what.domain = kProductorAsm;
        f.what.code = b.destino == vx::DestinoAsm::ElevadoAIr ? "asm.lifted"
                      : b.destino == vx::DestinoAsm::MicroAsm ? "asm.to_micro"
                                                              : "asm.opaque";
        f.what.a = b.instrucciones;
        f.what.b = b.linea;
        std::ostringstream o;
        o << "linea " << b.linea << ": " << b.instrucciones
          << " instrucciones del fuente -> "
          << vx::nombre_destino_asm(b.destino);
        f.what.detail = p.store.intern(o.str());
        f.about.kind = Subject::Kind::Function;
        f.about.function = p.store.intern(b.funcion);
        /* Lo anoto quien lo hizo, en el momento de hacerlo: esta visto, no
         * deducido. */
        f.seal.certainty = Certainty::Proven;
        f.seal.origin.producer = kProductorAsm;
        f.seal.origin.function = f.about.function;
        f.proof.rule = "recorded-while-lifting";
        p.assert_fact(std::move(f));
    }

    /* 4. El resumen por funcion, que es lo que uno mira primero. */
    for (const ir::IrFunction &fn : p.mod.functions) {
        if (!p.is_interesting(fn)) continue;
        const uint32_t micros = micros_por_funcion[fn.name];
        auto it = sin_elevar_por_funcion.find(fn.name);
        const uint32_t opacos =
            it == sin_elevar_por_funcion.end() ? 0u : it->second;
        auto ite = elevadas_por_funcion.find(fn.name);
        const uint32_t elevadas =
            ite == elevadas_por_funcion.end() ? 0u : ite->second;
        const bool hubo_asm = bloques_por_funcion.count(fn.name) != 0;
        if (micros == 0 && !hubo_asm &&
            bloques_en_ir_por_funcion.count(fn.name) == 0) {
            /* No es ignorancia: se sabe perfectamente que no tiene asm. */
            p.say_unknown({Subject::Kind::Function, p.store.intern(fn.name), 0},
                          analysis::asa::UnknownReason::NothingToSay,
                          "asm.none", kProductorAsm, "no tiene asm");
            continue;
        }
        Fact f;
        f.what.domain = kProductorAsm;
        f.what.code = "asm.summary";
        f.what.a = elevadas;
        f.what.b = micros;
        std::ostringstream o;
        o << elevadas << " instrucciones elevadas a IR, " << micros
          << " como micro asm, " << opacos << " bloques sin elevar";
        f.what.detail = p.store.intern(o.str());
        f.about.kind = Subject::Kind::Function;
        f.about.function = p.store.intern(fn.name);
        f.seal.certainty = Certainty::Proven;
        f.seal.origin.producer = kProductorAsm;
        f.seal.origin.function = f.about.function;
        f.proof.rule = "ir-count-plus-lift-record";
        p.assert_fact(std::move(f));

        /* Si el IR no se genero en este proceso -- viene de la cache -- el
         * elevado no corrio y no hay nada anotado.  Se dice: "no consta" no es
         * "no hubo". */
        if (!hubo_asm)
            /* Y este es el caso puro de "ni se miro": el analisis no llego a
             * correr, asi que no falta conocimiento -- falta haberlo pedido. */
            p.say_unknown(
                {Subject::Kind::Function, f.about.function, 0},
                analysis::asa::UnknownReason::NotAsked, "asm.lift_not_recorded",
                kProductorAsm,
                "su IR vino de cache: el elevado no corrio en este proceso "
                "y no consta que hizo (purga la cache para verlo)");

        /* 4. LAS ATADURAS: por que registro entra y sale cada valor.
         *
         * Es lo que hace que el asm no sea una barrera para quien pregunta por
         * un VALOR.  Sin publicarlo, cualquiera que quiera saber si un
         * parametro se usa tiene que rendirse en cuanto ve un bloque de asm --
         * y rendirse ahi es tratar el asm como opaco, que es justo lo que este
         * compilador no hace --.  El conocimiento ya se calculaba; lo que
         * faltaba era que llegara al almacen.
         *
         * El sujeto es el VALOR y no el bloque, a proposito: la pregunta que
         * esto contesta es "a este valor lo toca el asm?", y se hace desde el
         * valor. */
        const analysis::AsmBindingFacts ligaduras =
            analysis::compute_asm_bindings(fn);
        for (const analysis::LigaduraAsm &l : ligaduras.ligaduras) {
            /* Sin valor resuelto no se afirma que sea ese: mas de una escritura
             * al hueco significa que depende del camino, y decir uno seria
             * elegir. */
            if (l.valor == ir::IR_NO_VALUE) {
                p.say_unknown({Subject::Kind::Function, f.about.function, 0},
                              analysis::asa::UnknownReason::ShapeNotRecognized,
                              "asm.binding_value_unresolved", kProductorAsm,
                              p.store.intern(l.marcador));
                continue;
            }
            Fact b;
            b.what.domain = kProductorAsm;
            b.what.code = "asm.binding";
            b.what.a = static_cast<int64_t>(l.hueco);
            b.what.detail = p.store.intern(l.marcador + " " + l.clase);
            b.about.kind = Subject::Kind::Value;
            b.about.function = f.about.function;
            b.about.id = l.valor;
            b.seal.certainty = Certainty::Proven;
            b.seal.origin.source = analysis::asa::Source::Static;
            b.seal.origin.producer = kProductorAsm;
            b.seal.origin.function = b.about.function;
            b.proof.rule = "asm.bindings-resolved";
            p.assert_fact(std::move(b));
        }
    }
}

} // namespace

void register_asm_producer() {
    analysis::asa::register_producer(kProductorAsm, &produce_asm);
}

} // namespace analyze
