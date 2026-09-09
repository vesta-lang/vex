/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/range_summary.h
 * @brief Rangos que CRUZAN la frontera de una funcion: que entra y que sale.
 *
 * Dentro de una funcion se sabe bastante; en cuanto se cruza una llamada, se
 * sabia cero.  Un parametro valia lo que su tipo y el resultado de una llamada
 * tambien, asi que esto no se podia comprobar:
 *
 *     u8 leer(u8[16] buf, u32 i) { return buf[i]; }   // i vale lo que su tipo
 *     ...  leer(b, 3);                                 // aunque aqui vale 3
 *
 * Dos resumenes por funcion, y NO valen lo mismo:
 *
 *   RETORNO     sale del propio cuerpo.  Es cierto para CUALQUIER llamante, asi
 *               que se puede usar siempre.
 *   PARAMETROS  salen de mirar quien llama, y eso solo se puede afirmar si se
 *               conocen TODOS los llamantes.  Un solo llamante que no se vea --
 *               un puntero a funcion, un `asm` que salta al simbolo, el punto
 * de entrada del programa -- y el resumen seria mentira, con lo que un
 *               comprobador podria rechazar codigo perfectamente valido.
 *
 * Por eso el mundo cerrado se COMPRUEBA, no se supone, y ante cualquier duda la
 * funcion se declara abierta: sus parametros valen lo que su tipo.
 *
 * La RECURSION sale sola del metodo: es un punto fijo sobre el grafo de
 * llamadas con el mismo ensanchamiento que dentro de una funcion.  Una funcion
 * que se llama a si misma se estabiliza igual que un bucle.
 */
#ifndef ANALYSIS_FACTS_RANGE_SUMMARY_H
#define ANALYSIS_FACTS_RANGE_SUMMARY_H

#include "analysis/facts/value_range.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace ir {
struct IrModule;
}

namespace analysis {

/// Lo que se sabe de la frontera de una funcion.
struct FnRangeSummary {
    /// Rango de cada parametro, por indice.  Solo se estrecha si @c cerrada.
    std::vector<ValueRange> params;
    /// Rango del valor devuelto.  Cierto para cualquier llamante.
    ValueRange ret = ValueRange::top();
    /// Si se conocen TODOS los sitios desde los que se llama.
    bool cerrada = false;
};

/// Resumen de todas las funciones de un modulo.
struct RangeSummaries {
    std::unordered_map<std::string, FnRangeSummary> por_funcion;
    /// Si el punto fijo del grafo de llamadas se alcanzo.  Sin el, no se afirma
    /// nada: los resumenes quedan en "lo que diga el tipo".
    bool convergio = true;
    uint32_t rondas = 0;

    const FnRangeSummary *lookup(const std::string &nombre) const {
        auto it = por_funcion.find(nombre);
        return it == por_funcion.end() ? nullptr : &it->second;
    }
};

/**
 * @brief Calcula los resumenes de @p mod hasta punto fijo.
 *
 * Empieza optimista -- nadie llama a nadie -- y crece segun descubre llamadas,
 * que es lo que hace que la recursion converja al menor punto fijo en vez de
 * quedarse en "no se".  Si no converge dentro del presupuesto, TODOS los
 * resumenes se abren: mas vale no saber que saber mal.
 */
RangeSummaries compute_range_summaries(const ir::IrModule &mod,
                                       const RangeOptions &op = RangeOptions{});

} // namespace analysis

#endif // ANALYSIS_FACTS_RANGE_SUMMARY_H
