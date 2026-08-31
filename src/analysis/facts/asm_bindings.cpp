/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/asm_bindings.cpp
 * @brief Implementacion del puente entre el texto de un asm y los valores del
 *        programa.  Ver @ref analysis/facts/asm_bindings.h.
 */

#include "analysis/facts/asm_bindings.h"

#include "analysis/memory/points_to.h" // que hay guardado en un hueco
#include "vx/asm/asm_effects.h"        // forma canonica de un registro

#include <algorithm>

namespace analysis {
namespace {

/// El nombre por el que se ordena y se busca.  Las dos formas existen para que
/// el mismo comparador sirva a los dos lados de una busqueda por rango, que es
/// lo que pide @c std::equal_range.
inline const std::string &clave(const LigaduraAsm &l) {
    return l.marcador;
}
inline const std::string &clave(const std::string &s) {
    return s;
}

} // namespace

AsmBindingFacts::Candidatas
AsmBindingFacts::candidatas(const std::string &marcador) const noexcept {
    const auto rango =
        std::equal_range(ligaduras.begin(), ligaduras.end(), marcador,
                         [](const auto &a, const auto &b) {
                             // Comparador heterogeneo: sirve para (LigaduraAsm,
                             // string) y para (string, LigaduraAsm), que es lo
                             // que equal_range necesita.
                             return clave(a) < clave(b);
                         });
    Candidatas c;
    c.n = static_cast<size_t>(rango.second - rango.first);
    if (c.n != 0) c.datos = &*rango.first;
    return c;
}

const LigaduraAsm *
AsmBindingFacts::unica(const std::string &marcador) const noexcept {
    const Candidatas c = candidatas(marcador);
    return c.n == 1 ? c.datos : nullptr;
}

ExtensionResuelta resolver_extension(const AsmBindingFacts &lig,
                                     const RangeFacts &rangos,
                                     const vx::AsmBlockEffects::Extension &ex) {
    ExtensionResuelta r;
    // Sin saber cuanto mide un acceso no hay extension que acotar.
    if (!ex.ancho_conocido()) {
        r.reason = asa::UnknownReason::ShapeNotRecognized;
        r.reason_code = "asm.access_width_unknown";
        return r;
    }

    /* Entre que valores se mueve un operando NOMBRADO.  El nombre se lleva por
     * su ligadura hasta el valor del programa, y de ese se pregunta el rango:
     * es el mismo camino que usa todo lo demas, aqui aplicado a lo que el
     * bloque dijo que no era constante.
     *
     * Y deja dicho POR QUE falla, que son dos cosas muy distintas: sin ligadura
     * se le puede decir al usuario QUE ESCRIBIR -- liga ese registro --, y con
     * ligadura pero sin cota el arreglo esta en el programa. */
    auto rango_de = [&](const std::string &nombre, int64_t &lo,
                        int64_t &hi) -> bool {
        const LigaduraAsm *l = lig.unica(nombre);
        if (l == nullptr || l->valor == ir::IR_NO_VALUE) {
            r.reason = asa::UnknownReason::ShapeNotRecognized;
            r.reason_code = l == nullptr ? "asm.operand_not_bound"
                                         : "asm.binding_without_value";
            return false;
        }
        const ValueRange &vr = rangos.at(l->valor);
        if (!vr.acotada() || !vr.vista_con_signo(lo, hi)) {
            r.reason = asa::UnknownReason::RuntimeDependent;
            r.reason_code = "asm.bound_value_unbounded";
            return false;
        }
        return true;
    };

    int64_t lo = ex.const_off, hi = ex.const_off;
    if (!ex.distancia_constante()) {
        int64_t ilo = 0, ihi = 0;
        if (!rango_de(ex.indice, ilo, ihi)) return r;
        // La escala multiplica los dos extremos; con escala negativa se cruzan.
        int64_t a = ilo * ex.escala, b = ihi * ex.escala;
        if (a > b) std::swap(a, b);
        lo += a;
        hi += b;
    }
    // Un acceso llega hasta donde alcanza su ultimo byte.
    hi += (int64_t)ex.bytes;

    if (!ex.una_vez()) {
        /* Repetido: el ultimo paso empieza (N-1) anchos mas alla.  Se toma el
         * MAXIMO de la cuenta, que es lo que hay que poder afirmar para decir
         * que no se sale: si el mayor numero de vueltas cabe, ninguna se pasa.
         */
        int64_t nlo = 0, nhi = 0;
        if (!rango_de(ex.repeticion, nlo, nhi)) return r;
        if (nhi < 0) {
            /* Una cuenta de vueltas negativa no describe ningun acceso.  No es
             * que no se sepa: es que lo que se sabe no tiene sentido, y eso
             * apunta a un rango mal calculado -- nuestro -- o a un programa que
             * hace algo que no puede querer. */
            r.reason = asa::UnknownReason::ShapeNotRecognized;
            r.reason_code = "asm.negative_repeat_count";
            return r;
        }
        if (nhi > 0) hi += (nhi - 1) * (int64_t)ex.bytes;
    }
    r.desde = lo;
    r.hasta = hi;
    r.acotada = true;
    return r;
}

AsmBindingFacts compute_asm_bindings(const ir::IrFunction &fn) {
    AsmBindingFacts f;
    if (fn.asm_reg_bindings.empty()) return f;
    f.ligaduras.reserve(fn.asm_reg_bindings.size());

    for (const ir::AsmRegBinding &b : fn.asm_reg_bindings) {
        /* Como lo nombra el cuerpo.  El que elige el compilador se escribe
         * `$N`, y ese numero identifica al operando SIN ambiguedad -- no
         * depende de que registro acabe tocandole --.  El fijo se nombra por
         * su registro, y ahi hay que canonicalizar: el cuerpo puede decir
         * `eax` donde la ligadura dice `rax`. */
        std::string marcador;
        if (b.reg_auto && b.ph_index >= 0) {
            marcador = "$" + std::to_string(b.ph_index);
        } else {
            marcador = vx::asm_canonical_reg(b.reg);
            if (marcador.empty()) continue; // registro que no se reconoce.
        }

        LigaduraAsm l;
        l.marcador = std::move(marcador);
        /* La clase declarada.  Si viene vacia -- IR viejo, o una ligadura
         * sintetica que no la anoto -- se cae al registro, que en los fijos ES
         * la clase.  Preferir el campo y no al reves: el registro de un
         * operando automatico es el que se eligio a la primera para que el
         * interprete tenga algo que sustituir, no lo que dijo el programador.
         */
        l.clase = !b.reg_class.empty() ? b.reg_class : b.reg;
        l.hueco = b.alloca_value;
        f.ligaduras.push_back(std::move(l));
    }

    /* Ordenar por marcador: asi las que responden al mismo nombre quedan
     * CONTIGUAS y se devuelven de una pieza.  Que haya varias no invalida a
     * ninguna -- cada una sigue sabiendo su hueco y su contenido --; lo que
     * cambia es que ya no se puede decir cual de ellas es, y eso lo decide
     * quien pregunta. */
    std::sort(f.ligaduras.begin(), f.ligaduras.end(),
              [](const LigaduraAsm &a, const LigaduraAsm &b) {
                  return a.marcador < b.marcador;
              });

    /* Del hueco a lo que contiene.  Es el ultimo tramo del camino: sin el, un
     * operando ligado a un puntero solo puede decir "una variable", no a donde
     * apunta.
     *
     * De todas a la vez, y preguntandolo a quien sabe de huecos.  Hueco a hueco
     * costaba un recorrido de la funcion por cada uno, y esto se consulta una
     * vez por bloque de asm: el trabajo se multiplicaba por dos sitios sin que
     * se vea.  Reescribir aqui la regla del "valor unico" habria sido peor
     * todavia: dos versiones de cuando se puede afirmar lo que hay en un hueco.
     */
    std::vector<ir::IrValueId> huecos;
    huecos.reserve(f.ligaduras.size());
    for (const LigaduraAsm &l : f.ligaduras)
        huecos.push_back(l.hueco);
    const std::vector<ir::IrValueId> vals = single_values_of_slots(fn, huecos);
    for (size_t k = 0; k < f.ligaduras.size(); ++k)
        f.ligaduras[k].valor = vals[k];
    return f;
}

} // namespace analysis
