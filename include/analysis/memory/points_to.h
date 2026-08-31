/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/memory/points_to.h
 * @brief Resolvedor de direcciones COMPARTIDO: para cada valor SSA puntero,
 *        su localizacion abstracta (clase + raiz + offset const).  Es la UNICA
 *        fuente de "a que memoria apunta este puntero" para TODO el compilador
 *        y el tooling: el modelo de efectos (classify_ptr) y las optimizaciones
 *        de memoria (DSE/alias) preguntan aqui, en lugar de tener cada una su
 *        propia resolucion (antes habia dos: la del DSE y la de effects).
 *
 * La resolucion sigue las cadenas de derivacion: ALLOCA/alloc-site/global/param
 * son RAICES; MOV/BITCAST/CAST y equivalentes HEREDAN la raiz; ADD/GEP con
 * offset CONSTANTE acumulan el offset (off_exact); cualquier derivacion con
 * offset NO constante o desconocida degrada a offset inexacto (whole-root) o a
 * Unknown.  Nunca afirma un offset que no puede probar -> sound para el DSE.
 */
#ifndef ANALYSIS_MEMORY_POINTS_TO_H
#define ANALYSIS_MEMORY_POINTS_TO_H

#include "analysis/asa/fact.h"          // UnknownReason: por que no se supo
#include "analysis/effects/effects.h"   // AbstractLoc
#include "analysis/facts/ir_facts.h"    // IrFacts (def_of, param_of)
#include "analysis/facts/value_range.h" // acotar el desplazamiento variable

#include <cstdint>
#include <vector>

namespace ir {
struct IrFunction;
}

namespace analysis {

/// Resultado de resolver un valor SSA a su localizacion.  Interno al
/// resolvedor; los consumidores usan @c AbstractLoc via @c loc_of.
struct PointsToEntry {
    effects::AbstractLoc::Kind kind = effects::AbstractLoc::Kind::Unknown;
    uint32_t root =
        effects::LOC_GENERIC; ///< value-id de la raiz (o indice de param).
    int64_t off = 0;          ///< offset const desde la raiz.
    bool off_exact = false;   ///< false = offset no probado (whole-root).
    /**
     * @brief Valor que aporta la parte NO CONSTANTE del desplazamiento.
     *
     * Un `buf[i]` no tiene offset constante, pero eso no es lo mismo que no
     * saber nada: se sabe QUE valor lo decide.
     *
     * @c IR_NO_VALUE (0xFFFFFFFF) = el desplazamiento no viene de un solo
     * valor.
     */
    ir::IrValueId off_sym = 0xFFFFFFFFu;
    /**
     * @brief ENTRE QUE DOS desplazamientos esta, cuando no es constante.
     *
     * Un valor simbolico suelto solo sirve si quien pregunta sabe acotarlo; el
     * intervalo ya es la respuesta.  Y hace falta el INTERVALO, no un extremo:
     * para afirmar que un acceso se sale tiene que salirse entero, porque un
     * rango es una sobre-aproximacion.
     *
     * Es ademas lo que hara comprobables las vistas dinamicas, cuya geometria
     * se compone de sumas de cotas.
     */
    int64_t off_lo = 0;
    int64_t off_hi = 0;
    bool off_rango = false; ///< true = @c off_lo/off_hi valen.
    /**
     * @brief La parte CONSTANTE del desplazamiento, sin el simbolo.
     *
     * `(buf + 8) + i` se descompone en un 8 que se sabe y una `i` que no.  El
     * intervalo de arriba ya suma las dos cosas, pero con el rango de `i` EN SU
     * DEFINICION, que es lo que hay disponible cuando se resuelve la direccion.
     * Quien pregunte mas tarde -- en el punto del acceso, donde una guarda pudo
     * acotar `i` mucho mas -- necesita la constante aparte para rehacer la suma
     * con el intervalo mejor.
     */
    int64_t off_base = 0;
    /**
     * @brief POR QUE no se localizo.  Solo vale con @c kind == Unknown.
     *
     * El resolvedor tiene TRECE formas de rendirse y todas daban el mismo
     * `Unknown`.  Quien pregunta -- el DSE, el escape analysis, la
     * vectorizacion -- no podia distinguir "la raiz depende del camino"
     * (especulable con guarda) de "esa operacion no la modelamos" (que se
     * arregla ampliando ESTO) ni de "viene de fuera" (que lo sabe el llamante).
     *
     * Ojo: `Unknown` es ademas el valor POR DEFECTO de esta estructura, asi que
     * un valor que nadie resolvio queda con @c NotAsked -- que es justo lo que
     * hay que poder distinguir de una renuncia razonada.
     *
     * Van al FINAL a proposito: media docena de sitios construyen esta
     * estructura con inicializacion posicional (`{kind, root, off, exacto}`), y
     * meter un campo en medio los rompe en silencio -- el compilador solo avisa
     * porque los tipos no encajan; si encajaran, cambiaria el significado de
     * cada uno sin decir nada.
     */
    asa::UnknownReason reason = asa::UnknownReason::NotAsked;
    /// Codigo estable del caso EXACTO, del vocabulario de este dominio.
    const char *reason_code = "";
};

/**
 * @brief Hasta donde llega una region: su EXTENSION desde la raiz.
 *
 * Sin esto se sabe DONDE escribe una operacion pero no si se SALE, que es la
 * mitad que falta para poder decir "fuera de region".  El dato existe en el
 * sitio de asignacion -- `malloc(64)`, `u8[16] a` -- y ahi se recoge.
 *
 * Tres estados a proposito, que son los mismos que la certeza del analisis:
 * tamano constante (demostrable), simbolico (se sabe QUE valor lo da, asi que
 * con un rango se puede acotar) y desconocido (no se afirma nada).
 */
struct RegionExtent {
    int64_t bytes = -1; ///< >= 0: tamano LOGICO del objeto.
    /**
     * @brief Bytes realmente RESERVADOS para el objeto (>= @c bytes).
     *
     * Un objeto no ocupa lo que mide: ocupa su hueco.  Un struct de 3 bytes se
     * reserva alineado a 8, y por eso el compilador lo copia con un movimiento
     * de 8 sin salirse de nada -- el mismo idiom que usan SRET, los objetos,
     * `Optional` y `Result`.
     *
     * La distincion no es un detalle: sin ella, tomar el tamano logico por el
     * limite convierte cada copia de agregado en un falso desbordamiento (26 de
     * 453 programas del corpus).  Con ella, lo que se sale del HUECO sigue
     * siendo un fallo real en cualquier caso.
     */
    int64_t reservado = -1;
    ir::IrValueId sym =
        0xFFFFFFFFu; ///< value-id que da el tamano (IR_NO_VALUE si no).
    bool constante() const { return bytes >= 0; }
    bool simbolica() const { return bytes < 0 && sym != 0xFFFFFFFFu; }
    bool conocida() const { return constante() || simbolica(); }
    /// Limite que se puede afirmar: el hueco, no el tamano logico.
    int64_t limite() const { return reservado > bytes ? reservado : bytes; }
};

/// Tabla points-to de una funcion: value-id -> localizacion resuelta.  O(n).
struct PointsTo {
    std::vector<PointsToEntry> loc; ///< indexada por value-id.
    /// Extension de cada RAIZ, indexada por su value-id (misma indexacion que
    /// @c loc).  Solo las raices tienen entrada util; el resto queda vacia.
    std::vector<RegionExtent> extent;
    const PointsToEntry &at(ir::IrValueId v) const {
        static const PointsToEntry kUnknown{};
        return v < loc.size() ? loc[v] : kUnknown;
    }
    const RegionExtent &extent_of(uint32_t root) const {
        static const RegionExtent kNada{};
        return root < extent.size() ? extent[root] : kNada;
    }
};

/// Construye la tabla points-to de @p fn usando los hechos @p facts (def-use +
/// param-of).  Resolucion recursiva con memoizacion y guardia de ciclos (PHI).
///
/// @p rangos (opcional) permite ACOTAR el desplazamiento cuando no es
/// constante: sin ellos un `buf[i]` solo puede decir "en algun sitio de buf";
/// con ellos dice entre que dos posiciones.  Es informacion, no otra politica:
/// sin rangos la tabla sale exactamente igual que antes.
PointsTo compute_points_to(const ir::IrFunction &fn, const IrFacts &facts,
                           const RangeFacts *rangos = nullptr);

/// Marcador de analisis para el AnalysisManager (cachea la tabla points-to por
/// funcion).  Depende de IRFactsAnalysis.  El resultado (PointsTo) se invalida
/// cuando la funcion muta (la resolucion raiz+offset cambia con el IR).
struct PointsToAnalysis {
    using Result = PointsTo;
    static char ID;
};

/// Proyecta el valor SSA @p ptr a un @c AbstractLoc con el ancho de acceso
/// @p width (bytes; 0 = desconocido).  Si el offset no es exacto, degrada a
/// whole-root (width 0) para no afirmar bytes concretos que no se probaron.
effects::AbstractLoc loc_of(const PointsTo &pt, ir::IrValueId ptr,
                            int32_t width);

/**
 * @brief Valor que contiene el hueco @p slot, si se puede afirmar cual es.
 *
 * Responde a "que hay guardado aqui" cuando la respuesta es UNA sola y
 * segura: exactamente una escritura al hueco en toda la funcion.  Con dos o
 * mas, el contenido depende de por donde se haya pasado y no se afirma nada.
 *
 * Hace falta para llegar de una variable a lo que apunta.  Un `register("rdi")
 * i64* q` deja el PUNTERO en el registro, pero lo que el compilador tiene a
 * mano es el hueco de la variable; sin esta consulta, un `asm` que escribe en
 * `[rdi]` solo puede decir "escribe en algun sitio".
 *
 * @param fn    Funcion.
 * @param slot  Valor del @c ALLOCA.
 * @return El valor guardado, o @c ir::IR_NO_VALUE si no es unico o no se sabe.
 */
ir::IrValueId single_value_of_slot(const ir::IrFunction &fn,
                                   ir::IrValueId slot);

/**
 * @brief Lo mismo para VARIOS huecos, con un solo recorrido de la funcion.
 *
 * Preguntarlo hueco a hueco cuesta un recorrido por cada uno, y quien pregunta
 * suele tener todos a mano a la vez.  La regla es EXACTAMENTE la misma que en
 * @ref single_value_of_slot -- una sola escritura o nada --; esta aqui, y no
 * copiada en quien lo necesite, porque una regla en dos sitios acaba siendo dos
 * reglas.
 *
 * @param fn    Funcion.
 * @param slots Valores de los @c ALLOCA a resolver.
 * @return Un valor por cada entrada de @p slots, en el mismo orden;
 *         @c ir::IR_NO_VALUE donde no se pueda afirmar cual es.
 */
std::vector<ir::IrValueId>
single_values_of_slots(const ir::IrFunction &fn,
                       const std::vector<ir::IrValueId> &slots);

} // namespace analysis

#endif // ANALYSIS_MEMORY_POINTS_TO_H
