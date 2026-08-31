/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analyze/asm_report.h
 * @brief Lo que el ASA sabe de cada bloque `asm`, dicho entero.
 *
 * De un bloque de ensamblador se sabe mucho mas de lo que se contaba: de que
 * juegos de instrucciones es cada una, cuantas entiende la base y cuantas no,
 * que registros toca, si lee o escribe memoria, si mueve las flags o el
 * control. Todo eso decide DONDE puede correr la funcion y CUANTO se puede
 * optimizar a su alrededor, y hasta ahora solo salia a trozos y cuando algo
 * fallaba.
 *
 * El dato que manda es la COBERTURA: que parte del bloque se entiende.  No es
 * una curiosidad, es lo que fija cuanto se puede tocar alrededor -- entender el
 * noventa y cinco por ciento no permite lo mismo que entender el cuarenta --, y
 * por eso se dice con su banda y no solo con el porcentaje.
 */

#ifndef VESTA_ANALYZE_ASM_REPORT_H
#define VESTA_ANALYZE_ASM_REPORT_H

#include <cstdint>
#include <map>
#include <ostream>
#include <set>
#include <string>
#include <vector>

#include "ir/ssa_ir.h"

namespace analyze {

/**
 * @brief Cuanto se puede optimizar alrededor de un bloque, segun cuanto de el
 *        se entiende.
 *
 * No es una escala de calidad: es una decision.  Cada banda dice que se
 * permite, y esta aqui -- y no repartida por los pases -- para que todos usen
 * el mismo criterio en vez de cada uno el suyo.
 */
enum class BandaCobertura : uint8_t {
    Total,        ///< se entiende entero: optimizacion normal.
    Conservadora, ///< casi entero: optimizacion conservadora.
    Restringida,  ///< a medias: restricciones adicionales.
    Opaca         ///< se entiende poco: tratarlo como caja negra.
};

/// Nombre legible de la banda (para el informe).
const char *nombre_banda(BandaCobertura b);

/// La banda que corresponde a una cobertura (0..1).
BandaCobertura banda_de(double cobertura);

/**
 * @brief Un bloque `asm` visto por el ASA.
 *
 * Los contadores son de INSTRUCCIONES o de OPERANDOS segun el campo, y solo se
 * cuentan las que la base reconoce: de las que no, precisamente, no se sabe que
 * tocan -- por eso van aparte en @ref desconocidas en vez de sumar cero y
 * hacer creer que no hacen nada.
 */
struct AsmBlockReport {
    std::string funcion; ///< funcion que lo contiene.
    uint32_t linea = 0;  ///< linea del fuente donde empieza el bloque.
    uint32_t indice = 0; ///< numero de bloque dentro del modulo (1, 2, 3...).

    uint32_t instrucciones =
        0;                  ///< instrucciones del usuario (sin las sinteticas).
    uint32_t conocidas = 0; ///< las que la base sabe emparejar.
    uint32_t desconocidas = 0; ///< las que no: de esas no se sabe nada.

    /// Cuantas instrucciones de cada juego.  "UNKNOWN" agrupa las que la base
    /// no conoce; el conjunto base (I86/I386/...) va como "BASE".
    std::map<std::string, uint32_t> por_juego;
    /// Los rasgos que EXIGE el bloque del procesador donde corra.
    std::set<std::string> rasgos;

    uint32_t lee_gpr = 0, escribe_gpr = 0; ///< operandos de registro general.
    uint32_t lee_vec = 0, escribe_vec = 0; ///< operandos de registro vectorial.
    uint32_t lee_mem = 0, escribe_mem = 0; ///< instrucciones que tocan memoria.
    uint32_t escribe_flags = 0;            ///< instrucciones que mueven flags.
    uint32_t control = 0; ///< saltos / ramas dentro del bloque.
    bool barrera = false; ///< alguna atomica o serializante.
    /// El programador PIDIO que no se optimizara (`volatile` / `raw`).
    ///
    /// Se dice porque cambia como leer todo lo demas: un bloque opaco a
    /// proposito no es una laguna del compilador, es una decision.  Y no
    /// significa que no se sepa lo que hace -- los efectos, la memoria y los
    /// rasgos de aqui al lado valen igual --: significa que no se toca.
    bool opacidad_pedida = false;

    /// Cobertura semantica en tanto por uno (conocidas / instrucciones).
    double cobertura() const {
        return instrucciones == 0
                   ? 1.0
                   : static_cast<double>(conocidas) / instrucciones;
    }
};

/// Recorre el modulo y describe cada bloque `asm` que quede en el.
std::vector<AsmBlockReport> analizar_bloques_asm(const ir::IrModule &mod);

/// Escribe el informe (seccion completa, con cabecera).
void print_asm_report(std::ostream &os,
                      const std::vector<AsmBlockReport> &bloques);

/**
 * @brief Da de alta el dominio del ASM como productor de hechos del ASA.
 *
 * Vive aqui y no en la capa de analisis porque necesita la base de datos de
 * instrucciones.  Lo llama quien lo tenga disponible antes de producir: para
 * eso existe el registro de productores.
 */
void register_asm_producer();

/**
 * @brief Da de alta el dominio de la HUELLA como productor de hechos del ASA.
 *
 * Vive aqui por lo mismo que el del asm: necesita la maquinaria de efectos
 * (@c analyze/fingerprint.h), que no esta en el nucleo del ASA.  Lo que produce
 * es la verdad INFERIDA -- si lanza, si es pura, cuanto reserva --, sin mirar
 * ni un contrato: comparar lo demostrado con lo declarado es cosa de un
 * consumidor, no del productor.
 */
void register_fingerprint_producer();

} // namespace analyze

#endif // VESTA_ANALYZE_ASM_REPORT_H
