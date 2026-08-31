/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file fn_targets.cpp
 * @brief Implementacion del resolvedor de punteros a funcion (ver
 * fn_targets.h).
 */
#include "analysis/memory/fn_targets.h"

#include "analysis/memory/points_to.h"
#include "ir/ssa_ir.h"

namespace analysis {

namespace {

using ir::IrOp;

/// Profundidad maxima al seguir copias.  Una cadena mas larga que esto es un
/// patron que no se ha previsto, y ahi se para en vez de adivinar.
constexpr int kMaxSaltos = 16;

/// Deja dicho por que se renuncia y devuelve el vacio de siempre.
///
/// Un ayudante y no siete copias: el dia que se anada una renuncia mas, lo que
/// hace falta es que no se pueda escribir sin motivo.
std::string give_up(FnTargetUnknown *why, asa::UnknownReason reason,
                    const char *code) {
    if (why != nullptr) {
        why->reason = reason;
        why->code = code;
    }
    return {};
}

std::string seguir(const ir::IrFunction &fn, const IrFacts &facts,
                   ir::IrValueId v, int saltos, FnTargetUnknown *why) {
    if (saltos > kMaxSaltos)
        /* Ni el programa esta mal ni falta nada por declarar: es NUESTRO
         * limite. Se arregla subiendolo, y decirlo asi evita que alguien busque
         * el problema en su codigo. */
        return give_up(why, asa::UnknownReason::BudgetExceeded,
                       "target.too_many_hops");
    const ir::IrInstr *d = facts.def(v);
    if (d == nullptr)
        /* Sin definicion dentro de la funcion: viene de fuera -- un parametro,
         * un global --, y quien lo pase es quien sabe a donde apunta. */
        return give_up(why, asa::UnknownReason::OpaqueBoundary,
                       "target.comes_from_outside");
    switch (d->op) {
    case IrOp::LABEL_ADDR:
        // Aqui se toma la direccion: es el unico sitio donde nace un destino.
        return d->func_name;
    case IrOp::MOV:
    case IrOp::BITCAST:
        // Copias y reinterpretaciones no cambian a donde apunta.
        return d->operands.empty()
                   ? give_up(why, asa::UnknownReason::ShapeNotRecognized,
                             "target.copy_without_source")
                   : seguir(fn, facts, d->operands[0], saltos + 1, why);
    case IrOp::LOAD: {
        /* Guardado y releido.  Solo vale si el hueco se escribe UNA vez: con
         * dos escrituras el contenido depende del camino, y entonces el destino
         * tambien. */
        if (d->operands.empty())
            return give_up(why, asa::UnknownReason::ShapeNotRecognized,
                           "target.load_without_address");
        const ir::IrValueId guardado = single_value_of_slot(fn, d->operands[0]);
        if (guardado == ir::IR_NO_VALUE)
            /* El hueco se escribe mas de una vez: cual llega depende del camino
             * que se tome.  Eso SI es especulable con una guarda, que es justo
             * lo que se perdia al devolver el mismo vacio que todo lo demas. */
            return give_up(why, asa::UnknownReason::RuntimeDependent,
                           "target.slot_written_many_times");
        return seguir(fn, facts, guardado, saltos + 1, why);
    }
    case IrOp::PHI: {
        // Varios caminos: solo se afirma si todos llevan al mismo sitio.
        std::string comun;
        for (const ir::IrPhiArg &pa : d->phi_args) {
            const std::string n = seguir(fn, facts, pa.value, saltos + 1, why);
            if (n.empty())
                /* Uno de los caminos no se supo, y su motivo ya quedo escrito
                 * por la llamada de dentro: este se apoya en aquel, y eso es lo
                 * que hay que arreglar primero. */
                return give_up(why, asa::UnknownReason::MissingDependency,
                               "target.one_path_unresolved");
            if (comun.empty())
                comun = n;
            else if (comun != n)
                /* Dos caminos con destinos DISTINTOS.  No es ignorancia: se
                 * sabe que son varios, y ahi es donde nace una cache de
                 * llamada con su guarda. */
                return give_up(why, asa::UnknownReason::RuntimeDependent,
                               "target.varies_by_path");
        }
        return comun;
    }
    default:
        /* Una operacion que este resolvedor no modela.  El programa esta bien;
         * lo que hay que ampliar es esto. */
        return give_up(why, asa::UnknownReason::ShapeNotRecognized,
                       "target.unmodelled_op");
    }
}

/// Todos los usos de @p v dentro de @p fn son el puntero de una llamada
/// indirecta.  Cualquier otro uso -- guardarlo, pasarlo, devolverlo, meterlo en
/// una PHI -- lo saca de la vista.
bool usos_solo_en_llamadas(const ir::IrFunction &fn, ir::IrValueId v,
                           std::vector<IndirectSite> &sitios) {
    bool alguno = false;
    for (const ir::IrBlock &b : fn.blocks) {
        for (const ir::IrInstr &in : b.instrs) {
            if (in.op == IrOp::CALLIND && in.func_ptr == v) {
                sitios.push_back({&fn, &in});
                alguno = true;
                // El puntero puede aparecer TAMBIEN entre los argumentos: eso
                // seria pasarselo a otro, y entonces ya no se ve.
                for (ir::IrValueId a : in.operands)
                    if (a == v) return false;
                continue;
            }
            for (ir::IrValueId a : in.operands)
                if (a == v) return false;
            if (in.func_ptr == v)
                return false; // otro tipo de llamada indirecta
            for (const ir::IrPhiArg &pa : in.phi_args)
                if (pa.value == v) return false;
        }
    }
    return alguno;
}

} // namespace

std::string pointed_function(const ir::IrFunction &fn, const IrFacts &facts,
                             ir::IrValueId v, FnTargetUnknown *why) {
    if (v == ir::IR_NO_VALUE)
        return give_up(why, asa::UnknownReason::NothingToSay,
                       "target.no_value");
    return seguir(fn, facts, v, 0, why);
}

namespace {

/// Lo que hay que saber de un nombre mientras se recorre el modulo: su
/// resultado, y si todavia se pueden censar todos sus usos.
struct EnCurso {
    AddressTaken out;
    bool todas = true;
};

/**
 * @brief Aplica a @p e lo que la instruccion @p in dice del nombre que sigue.
 *
 * Es el cuerpo que comparten la version de un nombre y la de muchos.  Va aparte
 * para que no puedan responder cosas distintas: una sola definicion de que
 * significa que una direccion "se vea".
 */
void mirar_instr(const ir::IrFunction &fn, const ir::IrInstr &in,
                 const std::string &nombre, EnCurso &e) {
    if (in.op == IrOp::CALL || in.op == IrOp::TAILCALL)
        return; // llamada directa: se ve sin seguir nada
    e.out.taken = true;
    if (in.op != IrOp::LABEL_ADDR || in.dst == ir::IR_NO_VALUE) {
        // Registrada como metodo, usada de deleter, nombrada por una
        // nativa...: son puertas de entrada que no se pueden censar.
        e.todas = false;
        return;
    }
    (void)nombre;
    if (!usos_solo_en_llamadas(fn, in.dst, e.out.indirect)) e.todas = false;
}

} // namespace

std::unordered_map<std::string, AddressTaken>
follow_addresses(const ir::IrModule &mod,
                 const std::unordered_set<std::string> &nombres) {
    std::unordered_map<std::string, EnCurso> curso;
    curso.reserve(nombres.size() * 2);
    for (const std::string &n : nombres)
        if (!n.empty()) curso.emplace(n, EnCurso{});

    /* UNA pasada.  Cada instruccion se resuelve consultando su propio nombre en
     * la tabla, en vez de compararlo contra cada uno de los que se siguen. */
    for (const ir::IrFunction &fn : mod.functions) {
        for (const ir::IrBlock &b : fn.blocks) {
            for (const ir::IrInstr &in : b.instrs) {
                if (in.op == IrOp::RAW_ASM || in.op == IrOp::INLINE_ASM) {
                    /* Aqui no hay simbolo que consultar, solo texto donde
                     * buscar, asi que toca mirar nombre a nombre.  Son pocos
                     * bloques: el coste es nombres x bloques de asm, no
                     * nombres x modulo. */
                    if (in.func_name.empty()) continue;
                    for (auto &kv : curso)
                        if (in.func_name.find(kv.first) != std::string::npos) {
                            kv.second.out.taken = true;
                            kv.second.todas = false;
                        }
                    continue;
                }
                if (in.func_name.empty()) continue;
                auto it = curso.find(in.func_name);
                if (it == curso.end()) continue;
                mirar_instr(fn, in, it->first, it->second);
            }
        }
    }

    std::unordered_map<std::string, AddressTaken> res;
    res.reserve(curso.size());
    for (auto &kv : curso) {
        kv.second.out.all_visible = kv.second.out.taken && kv.second.todas;
        res.emplace(kv.first, std::move(kv.second.out));
    }
    return res;
}

AddressTaken follow_address(const ir::IrModule &mod,
                            const std::string &nombre) {
    AddressTaken out;
    if (nombre.empty()) return out;
    bool todas = true;
    for (const ir::IrFunction &fn : mod.functions) {
        for (const ir::IrBlock &b : fn.blocks) {
            for (const ir::IrInstr &in : b.instrs) {
                /* Un bloque de ensamblador puede saltar a un simbolo por su
                 * nombre sin que aparezca ninguna instruccion de llamada.  No
                 * se intenta interpretarlo: basta con que lo nombre. */
                if (in.op == IrOp::RAW_ASM || in.op == IrOp::INLINE_ASM) {
                    if (in.func_name.find(nombre) != std::string::npos) {
                        out.taken = true;
                        todas = false;
                    }
                    continue;
                }
                if (in.func_name != nombre) continue;
                if (in.op == IrOp::CALL || in.op == IrOp::TAILCALL)
                    continue; // llamada directa: se ve sin seguir nada
                out.taken = true;
                if (in.op != IrOp::LABEL_ADDR || in.dst == ir::IR_NO_VALUE) {
                    // Registrada como metodo, usada de deleter, nombrada por
                    // una nativa...: son puertas de entrada que no se pueden
                    // censar.
                    todas = false;
                    continue;
                }
                if (!usos_solo_en_llamadas(fn, in.dst, out.indirect))
                    todas = false;
            }
        }
    }
    out.all_visible = out.taken && todas;
    return out;
}

} // namespace analysis
