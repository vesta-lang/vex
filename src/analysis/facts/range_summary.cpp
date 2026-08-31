/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file range_summary.cpp
 * @brief Implementacion de los resumenes de frontera (contrato en
 *        range_summary.h).
 */
#include "analysis/facts/range_summary.h"

#include "analysis/facts/ir_facts.h"
#include "analysis/memory/fn_targets.h"
#include "ir/ssa_ir.h"

#include <deque>
#include <unordered_set>

namespace analysis {

namespace {

using ir::IrOp;

/// Nombres que el programa usa como PUNTO DE ENTRADA: alguien los llama desde
/// fuera del modulo, asi que sus parametros no se pueden estrechar.
bool es_entrada(const std::string &n) {
    return n == "main" || n == "__module_init" ||
           n.size() >= 5 && n.compare(n.size() - 5, 5, ".main") == 0;
}

/**
 * @brief Quien puede llegar a cada funcion.
 *
 * Se cuentan aparte las llamadas DIRECTAS -- que se ven sin esfuerzo -- de las
 * menciones del nombre en cualquier otro sitio.  Y una mencion NO se da por
 * perdida: si es una toma de direccion, se sigue a donde va esa direccion.  La
 * mayoria de las veces la respuesta esta en el modulo (se toma aqui, se llama
 * tres lineas mas abajo) y rendirse ahi obliga a suponer lo peor sobre codigo
 * que se puede leer entero.
 *
 * Solo cuando la direccion se escapa de verdad -- se guarda donde se escribe
 * mas de una vez, se pasa a otro, la registra una tabla de metodos, la nombra
 * un bloque de ensamblador -- la funcion se declara abierta.
 */
struct UsosDeNombre {
    /// Llamadas visibles a cada funcion (directas + indirectas resueltas).
    std::unordered_map<std::string, uint32_t> llamadas;
    /// Funciones cuya direccion se pierde de vista.
    std::unordered_set<std::string> abiertas;

    void recoger(const ir::IrModule &mod) {
        std::unordered_set<std::string> con_nombre_fuera_de_call;
        for (const ir::IrFunction &fn : mod.functions)
            for (const ir::IrBlock &b : fn.blocks)
                for (const ir::IrInstr &in : b.instrs) {
                    if (in.op == IrOp::RAW_ASM || in.op == IrOp::INLINE_ASM)
                        continue; // lo mira `follow_address`, que ve el texto
                    if (in.func_name.empty()) continue;
                    if (in.op == IrOp::CALL || in.op == IrOp::TAILCALL)
                        llamadas[in.func_name]++;
                    else
                        con_nombre_fuera_de_call.insert(in.func_name);
                }
        /* Para cada funcion cuyo nombre aparece fuera de un `call`, se va a
         * mirar QUE se hace con el en vez de suponerlo.
         *
         * Se piden TODOS de una vez.  Preguntar de uno en uno recorria el
         * modulo entero por cada nombre -- medido con VTune, un segundo de los
         * veintitres de compilar un programa de 24k lineas, y creciendo con el
         * producto de las dos cosas. */
        std::unordered_set<std::string> a_seguir;
        for (const ir::IrFunction &fn : mod.functions)
            if (con_nombre_fuera_de_call.count(fn.name) != 0)
                a_seguir.insert(fn.name);
        const auto seguidas = follow_addresses(mod, a_seguir);
        for (const auto &kv : seguidas) {
            if (!kv.second.all_visible) {
                abiertas.insert(kv.first);
                continue;
            }
            llamadas[kv.first] +=
                static_cast<uint32_t>(kv.second.indirect.size());
        }
    }

    /// Se conocen TODOS los sitios desde los que se puede llamar a @p nombre.
    bool cerrada(const std::string &nombre) const {
        if (es_entrada(nombre)) return false;
        if (abiertas.count(nombre) != 0) return false;
        // Sin ninguna llamada visible, lo prudente es suponer que llama alguien
        // a quien no vemos: nunca se estrecha por falta de datos.
        auto it = llamadas.find(nombre);
        return it != llamadas.end() && it->second > 0;
    }
};

} // namespace

RangeSummaries compute_range_summaries(const ir::IrModule &mod,
                                       const RangeOptions &op) {
    RangeSummaries out;
    UsosDeNombre usos;
    usos.recoger(mod);

    // Hechos por funcion: un recorrido, y no se repite en cada visita.
    std::vector<IrFacts> hechos;
    hechos.reserve(mod.functions.size());
    for (const ir::IrFunction &fn : mod.functions)
        hechos.push_back(build_ir_facts(fn));

    /* Arranque optimista: nadie llama a nadie todavia.  Es lo que hace que la
     * recursion converja al MENOR punto fijo en vez de quedarse en "no se".  El
     * suelo de un parametro sale de su TIPO, sin analizar la funcion: pedirle
     * al motor un pase entero solo para eso seria pagar un analisis por un dato
     * que ya esta en la declaracion. */
    std::unordered_map<std::string, size_t> indice_de;
    for (size_t i = 0; i < mod.functions.size(); ++i) {
        const ir::IrFunction &fn = mod.functions[i];
        indice_de[fn.name] = i;
        FnRangeSummary s;
        s.cerrada = usos.cerrada(fn.name);
        s.params.reserve(fn.params.size());
        for (ir::IrValueId p : fn.params) {
            const ValueRange piso = p < fn.values.size()
                                        ? rango_del_tipo(fn.values[p].type)
                                        : ValueRange::top();
            s.params.push_back(s.cerrada ? ValueRange::bottom(piso.t) : piso);
        }
        s.ret = ValueRange::bottom();
        out.por_funcion[fn.name] = std::move(s);
    }

    /* Quien llama a quien: cuando el resumen de G cambia, hay que rehacer a los
     * que dependen de el, y solo a esos.  Rehacer el modulo entero en cada
     * vuelta cuesta funciones x rondas para volver a calcular lo que ya estaba.
     */
    std::vector<std::unordered_set<size_t>> llamantes(mod.functions.size());
    for (size_t i = 0; i < mod.functions.size(); ++i)
        for (const ir::IrBlock &b : mod.functions[i].blocks)
            for (const ir::IrInstr &in : b.instrs) {
                if (in.op != IrOp::CALL && in.op != IrOp::TAILCALL) continue;
                auto it = indice_de.find(in.func_name);
                if (it != indice_de.end()) llamantes[it->second].insert(i);
            }

    std::deque<size_t> cola;
    std::vector<uint8_t> en_cola(mod.functions.size(), 1);
    std::vector<uint32_t> visitas(mod.functions.size(), 0);
    for (size_t i = 0; i < mod.functions.size(); ++i)
        cola.push_back(i);
    auto encolar = [&](size_t i) {
        if (i < en_cola.size() && !en_cola[i]) {
            en_cola[i] = 1;
            cola.push_back(i);
        }
    };

    const uint32_t tope = static_cast<uint32_t>(mod.functions.size()) *
                              (op.retardo_ensanche + 8) +
                          16;
    bool estable = true;
    uint32_t pasos = 0;
    while (!cola.empty()) {
        if (++pasos > tope) {
            estable = false;
            break;
        }
        const size_t i = cola.front();
        cola.pop_front();
        en_cola[i] = 0;
        out.rondas = pasos;
        {
            const ir::IrFunction &fn = mod.functions[i];
            if (fn.blocks.empty()) continue;
            /* Se ensancha cuando una funcion se revisita demasiado, que es lo
             * mismo que pasa dentro de un bucle: la recursion es un ciclo en el
             * grafo de llamadas y sin soltar un extremo no pararia. */
            const bool ensanchando = (visitas[i]++ >= op.retardo_ensanche);
            /* Por PUNTERO: aqui solo se LEEN, y pedirlos por valor copia un
             * rango por cada valor SSA mas el estado de entrada de cada bloque.
             * Esto esta dentro del bucle, asi que la copia se pagaba en CADA
             * vuelta del punto fijo, no una vez por funcion. */
            const std::shared_ptr<const RangeFacts> rf_ptr =
                compute_ranges_ptr(fn, hechos[i], op, &out);
            const RangeFacts &rf = *rf_ptr;

            /* A quien afecta que un rango del resumen crezca.  Son dos cosas
             * distintas y hasta ahora se hacian las dos siempre, que es lo que
             * llevaba a recalcular cada funcion 2,6 veces de media:
             *
             *  - Cambia lo que una funcion DEVUELVE.  Lo notan sus llamantes,
             *    que ven otro valor al llamarla.  Ella misma no: sus rangos
             *    salen de sus parametros y de lo que devuelven SUS llamadas, no
             *    de lo que devuelve ella.  Y si es recursiva, esta entre sus
             *    propios llamantes, asi que tampoco hace falta nombrarla.
             *
             *  - Cambia lo que una funcion RECIBE.  Lo nota ella, porque sus
             *    rangos arrancan de los parametros.  Sus llamantes no: leen lo
             *    que devuelve, no con que se la llamo.  Si estrechar la entrada
             *    acaba estrechando la salida, eso ya lo propaga el otro caso.
             */
            enum class Afecta { Llamantes, Ella };
            auto subir = [&](ValueRange &destino, const ValueRange &aporte,
                             size_t dueno, Afecta a) {
                ValueRange nuevo = destino.unir(aporte);
                if (ensanchando) nuevo = destino.ensanchar(nuevo);
                if (nuevo == destino) return;
                destino = nuevo;
                if (a == Afecta::Ella) {
                    encolar(dueno);
                    return;
                }
                if (dueno < llamantes.size())
                    for (size_t c : llamantes[dueno])
                        encolar(c);
            };

            for (const ir::IrBlock &b : fn.blocks) {
                for (const ir::IrInstr &in : b.instrs) {
                    // Lo que sale: cada RET aporta al resumen de retorno.
                    if (in.op == IrOp::RET) {
                        FnRangeSummary &mio = out.por_funcion[fn.name];
                        if (in.operands.empty())
                            subir(mio.ret, ValueRange::top(), i,
                                  Afecta::Llamantes);
                        else
                            subir(mio.ret, rf.at(in.operands[0]), i,
                                  Afecta::Llamantes);
                        continue;
                    }
                    /* El destino de una llamada indirecta se resuelve cuando se
                     * puede: la direccion se toma en un sitio y se llama en
                     * otro, y las dos cosas estan a la vista. */
                    std::string destino;
                    if (in.op == IrOp::CALL || in.op == IrOp::TAILCALL)
                        destino = in.func_name;
                    else if (in.op == IrOp::CALLIND)
                        destino = pointed_function(fn, hechos[i], in.func_ptr);
                    if (destino.empty()) continue;
                    auto it = out.por_funcion.find(destino);
                    if (it == out.por_funcion.end()) continue;
                    FnRangeSummary &suyo = it->second;
                    const auto id = indice_de.find(destino);
                    const size_t suyo_idx = id == indice_de.end()
                                                ? mod.functions.size()
                                                : id->second;
                    /* Lo que entra: cada argumento aporta al parametro que le
                     * toca.  Solo tiene sentido si se conocen todos los
                     * llamantes; si no, el parametro ya vale lo que su tipo y
                     * sumarle esto no cambiaria nada. */
                    if (suyo.cerrada)
                        for (size_t a = 0;
                             a < in.operands.size() && a < suyo.params.size();
                             ++a)
                            subir(suyo.params[a], rf.at(in.operands[a]),
                                  suyo_idx, Afecta::Ella);
                    /* Una llamada de cola devuelve lo que devuelva el llamado:
                     * su resumen de retorno es tambien el nuestro. */
                    if (in.op == IrOp::TAILCALL)
                        subir(out.por_funcion[fn.name].ret, suyo.ret, i,
                              Afecta::Llamantes);
                }
            }
        }
    }

    out.convergio = estable;
    if (!out.convergio) {
        /* Sin punto fijo no hay resumen que sostener.  Se abren todos: no saber
         * cuesta precision; afirmar de mas puede costar un programa valido
         * rechazado. */
        for (size_t i = 0; i < mod.functions.size(); ++i) {
            const ir::IrFunction &fn = mod.functions[i];
            FnRangeSummary &s = out.por_funcion[fn.name];
            s.cerrada = false;
            for (size_t a = 0; a < fn.params.size() && a < s.params.size();
                 ++a) {
                const ir::IrValueId p = fn.params[a];
                s.params[a] = p < fn.values.size()
                                  ? rango_del_tipo(fn.values[p].type)
                                  : ValueRange::top();
            }
            s.ret = ValueRange::top();
        }
    }
    return out;
}

} // namespace analysis
