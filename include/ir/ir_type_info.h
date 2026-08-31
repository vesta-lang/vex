/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir/ir_type_info.h
 * @brief Vocabulario UNICO de las propiedades de un @c ir::IrType: anchura
 *        (tres ejes con nombre propio), clase y derivados.
 *
 * POR QUE EXISTE.  La pregunta "cuantos bytes mide este tipo" estaba respondida
 * por DOCE implementaciones repartidas por el arbol (@c ir_type_size,
 * @c sr_type_size, @c memory_access_size, @c type_size_bytes,
 * @c a64_type_bytes, @c ir_bytes, @c ir_type_size_bytes, @c ir_type_bytes,
 * @c bytes_for, @c bytes_of, @c bytes_of_local y dos lambdas @c narrow_bits), y
 * NO daban todas la misma respuesta.  Dos de ellas eran ademas incorrectas --
 * omitian @c F32, que caia en el @c default y valia 8 en vez de 4 -- y no
 * fallaban solo porque la rama en que vivian excluia los flotantes: protegidas
 * por el contexto, no por ser correctas.
 *
 * TRES EJES, PORQUE SON TRES PREGUNTAS.  La divergencia no era toda un error:
 * un @c HANDLE son 32 bits en memoria pero ocupa una ranura de 8, y un @c VOID
 * no ocupa nada en la pila aunque el acceso se trate conservadoramente como 8.
 * Las tres respuestas eran correctas CADA UNA PARA SU PREGUNTA; el defecto era
 * que las tres se llamaban "size" y quien llamaba no podia saber cual
 * necesitaba.  De ahi que aqui cada eje tenga nombre propio y no se pueda coger
 * el que no es:
 *
 * | eje                    | que mide                          | HANDLE | VOID
 * | | :--------------------- | :-------------------------------- | :----: |
 * :--: | | @c type_access_bytes   | bytes TOCADOS en memoria          |   4 |
 * 8   | | @c type_slot_bytes     | ranura / registro / paso de array |   8    |
 * 8   | | @c type_storage_bytes  | ocupacion en el marco de pila     |   4    |
 * 0   |
 *
 * SWITCH EXHAUSTIVO, SIN @c default.  Es deliberado y es la red de seguridad
 * del modulo: anadir un @c IrType nuevo dispara @c -Wswitch AQUI, en un unico
 * sitio, y obliga a decidir que contesta cada eje.  Es exactamente lo que hoy
 * NO pasaba: los doce sitios llevaban @c default, asi que un tipo nuevo se
 * colaba en silencio con la respuesta de 8 bytes.
 *
 * DISCIPLINA.  Aqui viven PROPIEDADES DEL TIPO, nunca politicas de un pase.
 * "Soporta SELECT este tipo" o "es evaluable en tiempo de compilacion" son
 * decisiones de quien pregunta y se quedan en su fichero; lo que se centraliza
 * es el dato del que esas decisiones parten.  Mismo criterio que los
 * adaptadores de @c codegen::rbank (ver @c adapters/type_adapter.h).
 */

#ifndef VESTA_IR_IR_TYPE_INFO_H
#define VESTA_IR_IR_TYPE_INFO_H

#include <cstdint>

#include "ir/ssa_ir.h"

namespace ir {

// =========================================================================
//  Eje 1: bytes TOCADOS en memoria por un acceso de este tipo
// =========================================================================

/**
 * @brief Bytes que un acceso de tipo @p t lee o escribe en memoria.
 *
 * Es el ancho que interesa al analisis de solapamiento (dos accesos chocan si
 * sus rangos de bytes se cruzan) y al codigo que emite la carga o el
 * almacenamiento.  Un @c HANDLE mide 4: es un @c GcHandle de 32 bits, y
 * tratarlo como 8 haria creer que pisa los cuatro bytes siguientes.
 *
 * @c VOID devuelve 8 por conservadurismo: no hay acceso que medir, y quedarse
 * corto perderia dependencias de memoria.  En este eje NUNCA se sub-estima.
 */
inline uint32_t type_access_bytes(IrType t) noexcept {
    switch (t) {
    case IrType::I8:
    case IrType::U8:
    case IrType::BOOL: return 1;
    case IrType::I16:
    case IrType::U16: return 2;
    case IrType::I32:
    case IrType::U32:
    case IrType::F32:
    case IrType::HANDLE: return 4;
    case IrType::I64:
    case IrType::U64:
    case IrType::F64:
    case IrType::PTR:
    case IrType::VOID: return 8;
    }
    return 8; // inalcanzable; calla al compilador sin abrir un agujero
}

// =========================================================================
//  Eje 2: ancho de la ranura donde vive el valor
// =========================================================================

/**
 * @brief Ancho de la ranura que ocupa un valor de tipo @p t: registro, hueco de
 *        pila o paso entre elementos de un array.
 *
 * Difiere del eje de acceso en el @c HANDLE: son 32 bits de dato, pero viven en
 * una ranura de 64 -- el paso de un array de handles es 8, y el registro que lo
 * sostiene es de 64 bits.  Preguntar aqui por el ancho del ACCESO daria un paso
 * de 4 y leeria los elementos desalineados.
 */
inline uint32_t type_slot_bytes(IrType t) noexcept {
    switch (t) {
    case IrType::I8:
    case IrType::U8:
    case IrType::BOOL: return 1;
    case IrType::I16:
    case IrType::U16: return 2;
    case IrType::I32:
    case IrType::U32:
    case IrType::F32: return 4;
    case IrType::I64:
    case IrType::U64:
    case IrType::F64:
    case IrType::PTR:
    case IrType::HANDLE:
    case IrType::VOID: return 8;
    }
    return 8; // inalcanzable
}

// =========================================================================
//  Eje 3: ocupacion en el marco de pila
// =========================================================================

/**
 * @brief Bytes que un valor de tipo @p t ocupa al contarse el marco de pila.
 *
 * Solo se separa del eje de acceso en @c VOID, que ocupa CERO: no hay valor que
 * guardar.  Quien suma bytes reservados (el resumen de una funcion, el coste de
 * un marco) necesita ese cero; cobrarle 8 a un @c void inventaria pila que
 * nadie reserva.
 */
inline uint32_t type_storage_bytes(IrType t) noexcept {
    return t == IrType::VOID ? 0u : type_access_bytes(t);
}

// =========================================================================
//  Clase del tipo
// =========================================================================

/**
 * @brief @c true si @p t es un entero, con o sin signo.  Incluye @c BOOL.
 *
 * NO incluye @c PTR ni @c HANDLE: se representan con enteros, pero preguntar
 * "es un entero" para decidir si se puede sumar, truncar o extender debe decir
 * que no -- son referencias, y tratarlas como aritmetica es como se cuelan los
 * fallos de puntero.
 */
inline bool type_is_integer(IrType t) noexcept {
    switch (t) {
    case IrType::I8:
    case IrType::I16:
    case IrType::I32:
    case IrType::I64:
    case IrType::U8:
    case IrType::U16:
    case IrType::U32:
    case IrType::U64:
    case IrType::BOOL: return true;
    case IrType::F32:
    case IrType::F64:
    case IrType::PTR:
    case IrType::HANDLE:
    case IrType::VOID: return false;
    }
    return false; // inalcanzable
}

/** @brief @c true si @p t es un flotante IEEE 754 (@c F32 o @c F64). */
inline bool type_is_float(IrType t) noexcept {
    return t == IrType::F32 || t == IrType::F64;
}

/**
 * @brief @c true si @p t es un entero CON signo.
 *
 * Es la pregunta que decide entre extension con signo y con ceros, asi que
 * @c BOOL queda fuera a proposito: se extiende con ceros.
 */
inline bool type_is_signed(IrType t) noexcept {
    return t == IrType::I8 || t == IrType::I16 || t == IrType::I32 ||
           t == IrType::I64;
}

// =========================================================================
//  Derivados
// =========================================================================

/**
 * @brief Mascara de bits que deja pasar exactamente la ranura de @p t.
 *
 * Sobre el eje de RANURA, no el de acceso: es la mascara con la que se trunca
 * un valor al escribirlo, y un @c HANDLE se guarda en los 64 bits de su ranura.
 */
inline uint64_t type_mask(IrType t) noexcept {
    const uint32_t bytes = type_slot_bytes(t);
    if (bytes >= 8) return ~static_cast<uint64_t>(0u);
    return (static_cast<uint64_t>(1u) << (bytes * 8u)) - 1u;
}

/**
 * @brief Bits de @p t si es un entero ESTRECHABLE (8/16/32), o 0 si no lo es.
 *
 * El cero significa "no estrechar", y por eso @c BOOL vale 0 aunque mida un
 * byte: no es un entero al que quepa recortarle anchura, es una bandera.  Los
 * flotantes, punteros, handles y los enteros de 64 bits tambien dan 0.
 */
inline uint32_t type_narrow_bits(IrType t) noexcept {
    switch (t) {
    case IrType::I8:
    case IrType::U8: return 8;
    case IrType::I16:
    case IrType::U16: return 16;
    case IrType::I32:
    case IrType::U32: return 32;
    case IrType::I64:
    case IrType::U64:
    case IrType::F32:
    case IrType::F64:
    case IrType::PTR:
    case IrType::HANDLE:
    case IrType::BOOL:
    case IrType::VOID: return 0;
    }
    return 0; // inalcanzable
}

// =========================================================================
//  El eje del VALOR
// =========================================================================

/**
 * @brief Bytes que ocupa el VALOR @p v de la funcion @p fn.
 *
 * Distinta de @c type_slot_bytes(fn.values[v].type) aunque hoy conteste lo
 * mismo, y la diferencia es el motivo de que exista: cuando un valor pueda
 * declarar su propia anchura, la respuesta dejara de estar en la etiqueta del
 * tipo y pasara a estar en el valor.  Quien pregunte por la anchura DE UN VALOR
 * debe llamar aqui; quien pregunte por la de un ACCESO o un ELEMENTO de array
 * -- donde no hay valor que consultar -- se queda en los ejes de arriba.
 *
 * Un identificador fuera de rango contesta 0: no se inventa una anchura para
 * algo que no existe, se dice que no se sabe.
 */
inline uint32_t value_bytes(const IrFunction &fn, IrValueId v) noexcept {
    if (v == IR_NO_VALUE || v >= fn.values.size()) return 0;
    return type_slot_bytes(fn.values[v].type);
}

} // namespace ir

#endif // VESTA_IR_IR_TYPE_INFO_H
