/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/unwind/dwarf_cfi.h
 * @brief Escribe un @c FrameUnwind como CFI de DWARF, el contenido de
 *        @c .eh_frame.
 *
 * POR QUE HACEN FALTA LOS DOS.  No es que uno sea de Windows y otro de Linux:
 * son ejes distintos, y una misma PE puede llevar los dos.  El desenrollador
 * DEL SISTEMA en Windows x64 solo sabe leer `.pdata`; pero el de C++ que traen
 * los objetos compilados con MinGW, y `gdb`, y `libunwind`, y el lector de
 * simbolos de este proyecto, leen DWARF -- tambien sobre PE.  Un binario
 * nuestro puede enlazar con objetos de cualquiera de los dos mundos, asi que
 * saber describir el marco en los dos formatos no es duplicar: es lo que hace
 * falta para que la pila se pueda recorrer entera y no hasta la primera
 * frontera.
 *
 * QUE PRODUCE.  La CIE -- el preambulo que comparten todas las funciones -- y
 * una FDE por funcion.  Lo que NO produce es la direccion de la funcion: la FDE
 * deja un hueco de cuatro bytes y dice donde esta, para que lo rellene quien
 * sepa las direcciones (el AOT tras colocar la imagen, el JIT con la base del
 * codigo que acaba de generar).  Es la misma division que en
 * @c codegen/unwind/pe_x86_64.h y por el mismo motivo.
 *
 * DONDE SE PARECE A LA VERSION DE PE, Y DONDE NO.
 *
 * Se parece en la fidelidad: las reglas se emiten TODAS en el final del
 * prologo, no en la posicion real de cada instruccion.  Un fallo ocurrido
 * dentro del prologo queda descrito por las reglas iniciales de la CIE -- que
 * son las de la entrada a la funcion -- y no por las finales.  Es la misma
 * decision, con el mismo motivo, que la explicada en @c pe_x86_64.cpp: lo que
 * importa es el fallo en el CUERPO, y dar la posicion de cada instruccion
 * exigiria que el generador de codigo las fuera anotando una a una.
 *
 * NO se parece en que hacer con una hoja sin marco, y la diferencia es
 * importante.  En PE, que el sistema NO encuentre la funcion significa "es
 * hoja", asi que omitir su entrada la describe correctamente.  En DWARF no
 * existe esa convencion: una funcion sin FDE es una funcion de la que no se
 * sabe nada, y el recorrido se para ahi.  Por eso aqui la hoja SI lleva FDE,
 * aunque no anada ni una regla a las de la CIE.
 */

#ifndef VESTA_CODEGEN_UNWIND_DWARF_CFI_H
#define VESTA_CODEGEN_UNWIND_DWARF_CFI_H

#include "codegen/frame_unwind.h"

#include <cstdint>
#include <vector>

namespace codegen {
namespace unwind {

/**
 * @brief Traduce un registro de la codificacion de x86-64 a la de DWARF.
 *
 * Las dos numeraciones EXISTEN Y NO COINCIDEN, y es de los errores mas faciles
 * de cometer aqui porque se parecen lo justo para no notarlo: coinciden en
 * `rax`, `rbx` y en `r8`-`r15`, y se cruzan justo en medio.  En la codificacion
 * de la instruccion 1 es `rcx` y 2 es `rdx`; en DWARF es al reves.  Y 4,5,6,7
 * son `rsp,rbp,rsi,rdi` en la instruccion pero `rsi,rdi,rbp,rsp` en DWARF.
 *
 * Un cruce de estos no rompe nada visible: produce una tabla que dice que se
 * salvo otro registro, y el valor equivocado solo aparece al desenrollar.
 *
 * @param reg Numero en la codificacion de la instruccion (0-15).
 * @return    Numero DWARF, o el mismo valor si esta fuera de rango.
 */
uint32_t dwarf_reg_x86_64(uint32_t reg) noexcept;

/**
 * @brief Escribe la CIE de x86-64 SysV que comparten todas las FDE.
 *
 * Una sola por seccion.  Lleva las reglas de la ENTRADA a cualquier funcion --
 * el CFA es `rsp+8` y la direccion de retorno esta en `CFA-8`, que es lo que
 * deja el `call` -- y la codificacion de punteros que usan las FDE.
 *
 * @param out [out] Se SOBRESCRIBE.
 */
void build_eh_frame_cie_x86_64(std::vector<uint8_t> &out);

/**
 * @brief Escribe la FDE de una funcion.
 *
 * @param frame        El prologo a describir.
 * @param code_size    Tamano de la funcion, en bytes.
 * @param cie_offset   Offset de la CIE dentro de `.eh_frame`.
 * @param fde_offset   Offset donde va a quedar ESTA FDE dentro de `.eh_frame`.
 *                     Hace falta porque el enlace a la CIE se guarda como la
 *                     distancia entre las dos, no como una direccion.
 * @param out          [out] Se SOBRESCRIBE.
 * @param pc_begin_off [out, opcional] Offset, dentro de @p out, del hueco de
 *                     cuatro bytes donde va la direccion de la funcion.  Queda
 *                     a cero; quien sepa direcciones pone ahi su relocation.
 * @return false, dejando @p out vacio, si el cuerpo es dueno de su pila
 *         (`owns_stack`): ahi no hay prologo que describir y describirlo mal
 *         es peor que no hacerlo.  Una hoja sin marco SI devuelve true, con
 *         una FDE que no anade reglas -- ver la nota de la cabecera.
 */
bool build_eh_frame_fde_x86_64(const FrameUnwind &frame, uint32_t code_size,
                               uint32_t cie_offset, uint32_t fde_offset,
                               std::vector<uint8_t> &out,
                               uint32_t *pc_begin_off = nullptr) noexcept;

} // namespace unwind
} // namespace codegen

#endif // VESTA_CODEGEN_UNWIND_DWARF_CFI_H
