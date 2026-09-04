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
 * @file analysis/facts/demanded_bits.h
 * @brief Cuantos bits de un valor LLEGA A MIRAR alguien.  La otra mitad de
 *        @ref value_range.h y de los KnownBits.
 *
 * Los KnownBits van hacia ADELANTE: dicen que bits GARANTIZA quien produce el
 * valor.  Con eso se quita un ensanchado cuando los bits altos ya son cero
 * (@c elim_casts_with_facts).  Pero eso no contesta la pregunta contraria, que
 * es la que hace falta para quitar una normalizacion:
 *
 *     KnownBits          "que bits valen algo AL SALIR"    -> hacia adelante
 *     bits demandados    "que bits llega a leer ALGUIEN"   -> hacia atras
 *
 * Son duales y ninguna implica a la otra.  Un parametro no tiene KnownBits --
 * podria valer cualquier cosa --, asi que por delante no se puede probar nada
 * de sus bits altos; y sin embargo, si lo unico que se hace con el resultado de
 * una cuenta es escribirlo en un campo de cuatro bytes, los bits de arriba no
 * los mira NADIE y limpiarlos es trabajo tirado.
 *
 * Este analisis contesta lo segundo, y lo contesta UNA vez: hasta ahora vivia
 * escrito a mano dentro de @c ir_pass_elide_narrow_norm, con su propia lista de
 * consumidores tolerados -- que se quedaba corta sin que nadie lo notara, y no
 * la podia consultar ningun otro pase ni el volcado del ASA --.
 *
 * SOUND por construccion: se empieza suponiendo que de TODO valor se leen los
 * 64 bits y solo se baja esa cifra cuando se demuestra que ningun consumidor
 * mira por encima.  Cualquier duda -- una llamada, un operando que no se
 * reconoce, un valor que escapa -- deja los 64.  Quedarse corto solo cuesta
 * velocidad; pasarse daria otro resultado.
 */

#ifndef ANALYSIS_FACTS_DEMANDED_BITS_H
#define ANALYSIS_FACTS_DEMANDED_BITS_H

#include <cstdint>
#include <vector>

namespace ir {
struct IrFunction;
enum class IrType : uint8_t;
} // namespace ir

namespace analysis {

/**
 * @brief Cuantos bits promete el tipo @p t, o 64 si ocupa la palabra entera.
 *
 * Se DECLARA aqui y se define una sola vez: el analisis y el productor del
 * dominio necesitan la MISMA respuesta, y con una copia en cada uno bastaria
 * que uno tratara distinto el caso de 64 para que el hecho publicado y la
 * decision del optimizador dejaran de coincidir, sin que nada fallara.
 *
 * Declarada y no `inline` aqui a proposito: definirla en el header obligaria a
 * incluir `ir/ir_type_info.h`, cuyo enum tiene un `VOID` que choca con el
 * `#define VOID void` de las cabeceras de Windows en cuanto alguien incluya
 * este fichero despues de ellas.
 *
 * @param t Tipo del valor.
 * @return Bits significativos, 1..64.
 */
uint8_t type_promised_bits(ir::IrType t);

/**
 * @struct DemandedBits
 * @brief Cuantos bits BAJOS de cada valor SSA llega a leer alguien.
 *
 * Indexado por id de valor.  64 = se leen todos (o no se sabe, que a efectos
 * de quien decide es lo mismo y por eso NO se distingue aqui: el motivo de no
 * saber lo cuenta el productor del ASA, que es a quien le toca).
 */
struct DemandedBits {
    /// Bits leidos de cada valor, 1..64.  Vacio = funcion sin analizar.
    std::vector<uint8_t> bits;
    /// El punto fijo llego al final.  false = se corto por la cota y la tabla
    /// se puso entera a 64.
    ///
    /// Se guarda porque la CERTEZA del hecho sale del analisis y no de quien
    /// pregunta: haber convergido es haber visto todo lo que podia
    /// contradecirlo; pararse por presupuesto sostiene una decision con red
    /// pero no autoriza a quitar una comprobacion.
    bool converged = true;

    /// @brief Cuantos bits se leen del valor @p v.  64 si esta fuera de rango.
    uint8_t at(uint32_t v) const {
        return v < bits.size() ? bits[v] : uint8_t{64};
    }
    /// @brief Nadie mira por encima del bit @p n de @p v.
    bool only_low(uint32_t v, uint32_t n) const { return at(v) <= n; }
};

/**
 * @brief Calcula, para cada valor de @p fn, cuantos bits bajos se leen.
 *
 * Punto fijo hacia atras sobre la funcion entera: un valor demanda como mucho
 * lo que demanden todos sus usos juntos, y un uso demanda segun QUE OPERACION
 * sea y en que posicion este.  Se itera porque un phi -- o una cadena de
 * cuentas del mismo ancho -- se puede referir a si mismo.
 *
 * @param fn Funcion IR a analizar.
 * @return La tabla de bits demandados por valor.
 */
DemandedBits compute_demanded_bits(const ir::IrFunction &fn);

/// Marcador para el AnalysisManager (cachea por funcion), igual que
/// @c RangeAnalysis: asi los tres que preguntan -- el pase, el productor y
/// quien venga -- comparten UNA instancia en vez de recalcularla cada uno.
struct DemandedBitsAnalysis {
    using Result = DemandedBits;
    static char ID;
};

} // namespace analysis

#endif // ANALYSIS_FACTS_DEMANDED_BITS_H
