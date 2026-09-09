/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/unwind/pe_x86_64.h
 * @brief Escribe un @c FrameUnwind como el @c UNWIND_INFO de x86-64 que pide
 *        el desenrollador de Windows.
 *
 * POR QUE ESTE FORMATO Y NO OTRO, que suele contarse mal.  No es "porque el
 * objetivo sea Windows": una PE puede llevar DWARF perfectamente -- clang y
 * MinGW lo hacen, y el propio lector de simbolos de este proyecto lo lee sobre
 * PE --, y el modelo de excepciones de C++ depende del compilador, no del
 * sistema.
 *
 * Lo que no depende de nadie es el DESENROLLADOR DEL SISTEMA: en Windows x64
 * camina por tablas, buscando la entrada de la funcion en el directorio de
 * excepciones del ejecutable, y no sabe leer DWARF.  Un binario con
 * `.eh_frame` y sin `.pdata` sigue siendo inandable para el.  Y ese
 * desenrollador es el que hace falta para dos cosas que si nos importan:
 * recoger un fallo del procesador sin llevarse el proceso, y sacar una pila de
 * llamadas de una muestra.
 *
 * QUE PRODUCE.  Solo el @c UNWIND_INFO -- cabecera de cuatro bytes mas los
 * codigos --.  La entrada de la tabla (`RUNTIME_FUNCTION`) la monta quien
 * sepa las direcciones: el JIT con la base del codigo que acaba de generar, y
 * el AOT con los RVA que salen de colocar la imagen.  Son datos que esta capa
 * no tiene ni tiene por que tener.
 *
 * SE COMPILA EN CUALQUIER ANFITRION.  No incluye `windows.h` ni depende de
 * ejecutarse en Windows: el AOT genera PE desde Linux, asi que describir un
 * marco de Windows no puede exigir estar en Windows.
 */

#ifndef VESTA_CODEGEN_UNWIND_PE_X86_64_H
#define VESTA_CODEGEN_UNWIND_PE_X86_64_H

#include "codegen/frame_unwind.h"

#include <cstdint>
#include <vector>

namespace codegen {
namespace unwind {

/**
 * @brief Cuantas ranuras de dos bytes caben en un @c UNWIND_INFO nuestro.
 *
 * El formato admite hasta 255, pero el JIT reserva un bufer fijo para la
 * descripcion y este es su tope.  Se nombra aqui, y no dentro del codificador,
 * porque quien reserva ese bufer necesita el mismo numero: dos constantes para
 * un solo limite es como empiezan a separarse.
 */
inline constexpr uint32_t PE_X86_64_MAX_SLOTS = 32;

/**
 * @brief Escribe @p frame como @c UNWIND_INFO de x86-64.
 *
 * @param frame El prologo a describir.
 * @param out   [out] Se SOBRESCRIBE.  Queda con la cabecera de cuatro bytes
 *              seguida de los codigos, listo para copiar a `.xdata` o a
 *              memoria viva.
 * @param why   [out, opcional] Por que no se emitio, cuando devuelve false.
 * @return true si hay descripcion que emitir.
 *
 * DEVOLVER FALSE SIGNIFICA DOS COSAS MUY DISTINTAS, y de ahi el @p why.  Quien
 * las confunda acaba dando un error por una funcion hoja perfectamente normal,
 * o -- peor -- pasando por alto una que si necesitaba entrada:
 *
 *  - @c Nothing, y omitir la entrada es LO CORRECTO: el cuerpo es dueno de la
 *    pila (`owns_stack`, y mentirle al desenrollador es peor que callar), o el
 *    prologo no hizo nada.  En ese segundo caso la funcion no reservo pila, asi
 *    que no pudo llamar a nadie, asi que es hoja de verdad -- y la suposicion
 *    de hoja que hace el sistema cuando no encuentra entrada acierta.
 *  - @c TooComplex, y ahi SI hay un marco que describir pero no cabe: el
 *    prologo pasa de 255 bytes, o la descripcion pasa de
 *    @ref PE_X86_64_MAX_SLOTS ranuras.  Omitir la entrada dejaria al
 *    desenrollador creyendo que es hoja cuando no lo es, asi que esto no se
 *    puede tragar en silencio.
 */
enum class PeUnwindSkip : uint8_t {
    Nothing,    ///< no habia nada que describir; omitir es correcto
    TooComplex, ///< hay marco, pero no cabe en lo que el formato expresa
};

bool build_pe_x86_64(const FrameUnwind &frame, std::vector<uint8_t> &out,
                     PeUnwindSkip *why = nullptr) noexcept;

} // namespace unwind
} // namespace codegen

#endif // VESTA_CODEGEN_UNWIND_PE_X86_64_H
