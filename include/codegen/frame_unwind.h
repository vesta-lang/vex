/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/frame_unwind.h
 * @brief Que hizo el prologo, dicho sin depender de la ISA ni del formato con
 *        el que se vaya a escribir.
 *
 * POR QUE EXISTE.  Deshacer un marco es la misma pregunta en todas partes --
 * que registros se guardaron, si se establecio un puntero de marco, cuanta
 * pila se reservo -- y solo cambia como se ESCRIBE la respuesta.  Separar las
 * dos cosas es lo que permite que anadir una ISA o un formato sea escribir un
 * codificador, y no volver a derivar la descripcion.
 *
 * Vive en @c codegen y no en @c jit ni en @c aot a proposito: lo produce quien
 * genera codigo -- los dos -- y lo consume quien lo escribe al binario o al
 * sistema.  Ponerlo en cualquiera de los dos lados obligaria al otro a
 * depender de el.
 *
 * QUE NO ES.  No describe el marco COMPLETO ni sabe donde vive cada valor:
 * para eso esta @c codegen/frame_layout.h.  Esto es solo lo que hace falta
 * para DESHACERLO, que es un subconjunto y por eso va aparte.
 *
 * LA NUMERACION DE REGISTRO ES DEL OBJETIVO.  No se traduce a un espacio
 * comun: el codificador de cada ISA ya conoce la suya, y un espacio intermedio
 * seria una tabla mas que mantener sin nadie que la aproveche.
 */

#ifndef VESTA_CODEGEN_FRAME_UNWIND_H
#define VESTA_CODEGEN_FRAME_UNWIND_H

#include <cstdint>
#include <vector>

namespace codegen {

/**
 * @brief Una cosa que hizo el prologo.
 *
 * Las tres cubren lo que los formatos saben expresar -- los codigos de
 * desenrollado de Windows en x86-64 y en ARM64, y las reglas CFI de DWARF --,
 * que no es casualidad: los tres describen un prologo con estas mismas piezas
 * porque un prologo no hace mas cosas.
 */
struct FrameOp {
    enum class Kind : uint8_t {
        SaveReg,         ///< se guardo un registro.
        SetFramePointer, ///< se establecio el puntero de marco.
        AllocStack,      ///< se reservo pila.
    };

    Kind kind = Kind::SaveReg;
    /// Registro implicado, en la numeracion del OBJETIVO.  @c SaveReg y
    /// @c SetFramePointer.
    uint32_t reg = 0;
    /// Bytes reservados.  Solo @c AllocStack.
    uint32_t bytes = 0;
};

/**
 * @brief El prologo de una funcion, listo para que lo escriba un codificador.
 */
struct FrameUnwind {
    /**
     * @brief El cuerpo es dueno de su pila y no hay prologo que describir.
     *
     * Una funcion `@Naked` entra aqui.  No es lo mismo que no tener
     * operaciones: describir mal un marco es peor que no describirlo, porque
     * quien desenrolla se cree la descripcion y sigue por donde no es.
     */
    bool owns_stack = false;

    /**
     * @brief Donde acaba el prologo, en bytes desde el inicio de la funcion.
     *
     * Cero significa que no se midio, y entonces no hay nada que emitir: una
     * hoja sin marco es exactamente lo que un desenrollador supone cuando no
     * encuentra descripcion, asi que callarse es lo correcto.
     */
    uint32_t prologue_bytes = 0;

    /**
     * @brief Las operaciones, en ORDEN DE EJECUCION del prologo.
     *
     * En orden de ejecucion y no en el que pida ningun formato: cada
     * codificador lo recorre como le convenga -- los codigos de Windows van
     * del final al principio, porque se aplican deshaciendo --, y guardarlo ya
     * invertido ataria la descripcion a uno de ellos.
     */
    std::vector<FrameOp> ops;
};

} // namespace codegen

#endif // VESTA_CODEGEN_FRAME_UNWIND_H
