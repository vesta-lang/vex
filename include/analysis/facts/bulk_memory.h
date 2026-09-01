/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/bulk_memory.h
 * @brief El HECHO de que un bucle mueve un tramo contiguo de memoria.
 *
 * Un bucle que recorre un rango escribiendo el mismo valor, o copiando de un
 * sitio a otro, no es un bucle: es UNA operacion de bloque escrita larga.  La
 * maquina tiene instrucciones para eso, y el procesador tiene formas de
 * hacerlo que ningun bucle escrito a mano alcanza.  Lo que hace falta para
 * llegar a ellas es SABER que el bucle es eso.
 *
 * Este fichero produce ese saber como un HECHO, no como un patron.  La
 * diferencia importa y no es de estilo:
 *
 *   - Un patron pregunta por la FORMA: "la cabecera tiene tres
 *     instrucciones?", "el incremento esta en el cuerpo o en su propio
 *     bloque?", "el indice empieza en cero?".  Cada respuesta depende de como
 *     baje el frontend y de que pases hayan corrido antes, asi que deja de
 *     valer en cuanto algo cambia -- y no avisa: simplemente no reconoce nada.
 *     Se probo, y bastaba con que el desenrollador corriera antes para que no
 *     quedara forma que reconocer.
 *
 *   - Un hecho pregunta por lo que el codigo HACE: que region toca, con que
 *     paso, con que valor, y si hace algo mas.  Eso lo responden los analisis
 *     que ya existen -- estructura del bucle, variable de induccion, accesos a
 *     memoria -- y sobrevive a que el bucle este desenrollado, tenga el
 *     incremento donde sea o recorra de ocho en ocho bytes en vez de uno.
 *
 * Se apoya en la base de hechos compartida y no re-deriva nada: la estructura
 * la da @c detect_loop_structure, la variable de induccion @c detect_loop_iv y
 * los accesos @c memory_access.  Aqui solo se COMPONEN.
 */

#ifndef ANALYSIS_FACTS_BULK_MEMORY_H
#define ANALYSIS_FACTS_BULK_MEMORY_H

#include <cstdint>
#include <vector>

#include "analysis/facts/loop_iv.h"
#include "analysis/facts/loop_structure.h"

namespace ir {
struct IrFunction;
}

namespace analysis {

/**
 * @struct BulkMemoryFact
 * @brief Un bucle que resulta ser un movimiento de memoria en bloque.
 *
 * La longitud se da en ELEMENTOS y en ancho por elemento, no en bytes ya
 * multiplicados, porque el numero de vueltas suele ser un valor del programa y
 * la multiplicacion la tiene que emitir quien transforme.  Separarlos deja el
 * hecho libre de decidir donde va esa cuenta.
 */
struct BulkMemoryFact {
    /// Que hace el bucle.
    enum class Clase : uint8_t {
        Relleno, ///< escribe el mismo valor en todo el tramo.
        Copia,   ///< copia de un tramo a otro.
    };

    Clase clase = Clase::Relleno;
    uint32_t loop_id = 0; ///< bucle del que sale el hecho.

    /// Puntero al principio del tramo que se ESCRIBE.
    ir::IrValueId dst_base = ir::IR_NO_VALUE;
    /// Puntero al principio del tramo que se LEE.  Solo en @c Copia.
    ir::IrValueId src_base = ir::IR_NO_VALUE;
    /// Valor que se escribe.  Solo en @c Relleno, y es invariante del bucle.
    ir::IrValueId valor = ir::IR_NO_VALUE;
    /// Cuantos elementos: la cota del bucle.  Puede no ser constante.
    ir::IrValueId n_elems = ir::IR_NO_VALUE;
    /// Bytes por elemento.  El tramo son @c n_elems * @c ancho bytes.
    int64_t ancho = 0;

    /// Estructura del bucle, para que quien transforme sepa que reemplazar.
    LoopStructure st;
    /// Variable de induccion, por si el transformador la necesita.
    LoopIV iv;
};

/**
 * @brief Un bucle que se MIRO y no resulto ser un movimiento de bloque, con
 *        el motivo.
 *
 * Sin esto el analisis se rendia quince veces en silencio, y un analisis que
 * calla al renunciar parece que funciona: "no hay ningun memcpy en este
 * programa" y "habia uno y me falto un byte para verlo" salian igual.  Es
 * ademas lo que necesita un consumidor de cara al usuario -- "este bucle seria
 * `std.memory.copy` si la base no cambiara dentro" es un consejo; "no se
 * reconocio nada" no lo es.
 */
struct BulkMemoryDecline {
    uint32_t loop_id = 0;
    ir::IrBlockId header = ir::IR_NO_BLOCK;
    /// Codigo estable del caso, del vocabulario de este dominio.
    const char *code = "";
};

/// Lo que el analisis vio: lo que reconocio y lo que no, con su motivo.
struct BulkMemoryReport {
    std::vector<BulkMemoryFact> facts;
    std::vector<BulkMemoryDecline> declines;
};

/**
 * @brief Descubre que bucles de @p fn son movimientos de memoria en bloque.
 *
 * Solo mira bucles MAS INTERNOS: uno que contiene a otro hace mas cosas que
 * mover memoria por definicion.  Ante cualquier duda -- un efecto que no
 * encaja, una direccion que no se resuelve, un paso que no cuadra con el ancho
 * del acceso -- el bucle no produce hecho.  Es la unica direccion segura: de
 * menos se pierde una optimizacion, de mas se cambia lo que el programa hace.
 *
 * Y esa duda se CUENTA, con su codigo: ver @c BulkMemoryReport::declines.
 *
 * @param fn Funcion a examinar.
 * @return Lo reconocido y lo descartado, cada cosa con lo suyo.
 */
BulkMemoryReport analyze_bulk_memory(const ir::IrFunction &fn);

/// Solo lo reconocido, para quien va a TRANSFORMAR y no tiene nada que hacer
/// con los motivos.
std::vector<BulkMemoryFact> detect_bulk_memory(const ir::IrFunction &fn);

} // namespace analysis

#endif // ANALYSIS_FACTS_BULK_MEMORY_H
