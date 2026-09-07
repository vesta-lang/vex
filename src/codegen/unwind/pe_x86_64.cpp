/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codegen/unwind/pe_x86_64.cpp
 * @brief Implementacion de @ref codegen/unwind/pe_x86_64.h.
 *
 * Sale de `jit/win_unwind.cpp`, donde nacio atado al registro en runtime.  Se
 * separo al necesitarlo tambien el AOT: alli los mismos bytes van a `.xdata`
 * en vez de a `RtlAddFunctionTable`.
 */

#include "codegen/unwind/pe_x86_64.h"

namespace codegen {
namespace unwind {

namespace {

/// Codigos de operacion del desenrollado.  `winnt.h` no los expone como enum,
/// y aqui no se incluye de todas formas: esto compila fuera de Windows.
enum : uint8_t {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE = 1,
    UWOP_ALLOC_SMALL = 2,
    UWOP_SET_FPREG = 3,
};

/// Un codigo del desenrollado, tal como se va a escribir.
struct Code {
    uint8_t offset; ///< donde, dentro del prologo, ya ha surtido efecto.
    uint8_t op;     ///< UWOP_*.
    uint8_t info;   ///< registro, o tamano segun el op.
    uint16_t extra0 = 0;
    uint16_t extra1 = 0;
    uint8_t n_extra = 0; ///< ranuras adicionales que ocupa (0, 1 o 2).
};

} // namespace

bool build_pe_x86_64(const FrameUnwind &frame,
                     std::vector<uint8_t> &out) noexcept {
    out.clear();

    /* Una funcion duena de su pila no tiene prologo que describir; mentirle al
     * desenrollador es peor que no decirle nada. */
    if (frame.owns_stack) return false;
    /* Sin prologo medido no hay nada que decir.  Pasa si la funcion no emitio
     * ninguno (hoja sin marco): ahi la suposicion de hoja del sistema ES la
     * correcta, asi que no describir es lo acertado. */
    if (frame.prologue_bytes == 0) return false;
    if (frame.prologue_bytes > 255)
        return false; // no cabe en el campo del formato

    const uint8_t end = static_cast<uint8_t>(frame.prologue_bytes);

    /* Los codigos van en orden DESCENDENTE de posicion: el desenrollador los
     * aplica de atras hacia delante para deshacer el prologo.  Todos llevan la
     * posicion del FINAL del prologo, no la suya propia.
     *
     * Eso es deliberado y hay que entenderlo: un codigo solo se aplica cuando
     * la ejecucion ya paso su posicion, asi que con esta descripcion un fallo
     * OCURRIDO DENTRO DEL PROLOGO no aplica ninguno -- y el sistema hace
     * exactamente lo mismo que hacia sin tabla, dar el trozo por hoja.  O sea
     * que en ese caso no se gana nada, pero tampoco se pierde; y en el caso que
     * importa -- el fallo en el CUERPO, que es donde ocurre todo -- la
     * descripcion es exacta.  Dar la posicion real de cada instruccion del
     * prologo exigiria que el codificador las fuera anotando una a una; se hara
     * si algun dia hace falta desenrollar desde dentro del prologo. */
    std::vector<Code> codes;
    codes.reserve(frame.ops.size() + 2);

    uint32_t frame_pointer_reg = 0;
    bool has_frame_pointer = false;

    /* Se recorre al reves porque la descripcion va del final del prologo hacia
     * el principio, y `ops` esta en orden de ejecucion.  Es el unico sitio
     * donde este formato impone su orden; la descripcion no lo lleva dentro. */
    for (size_t i = frame.ops.size(); i-- > 0;) {
        const FrameOp &op = frame.ops[i];
        switch (op.kind) {
        case FrameOp::Kind::AllocStack: {
            const uint32_t n = op.bytes;
            if (n == 0) break;
            if (n % 8 == 0 && n / 8 >= 1 && n / 8 <= 16) {
                // Hasta 128 bytes cabe en el propio codigo: info = n/8 - 1.
                codes.push_back(
                    {end, UWOP_ALLOC_SMALL, static_cast<uint8_t>(n / 8 - 1)});
            } else if (n % 8 == 0 && n / 8 < 0x10000u) {
                // Hasta 512 KiB: una ranura mas, con el tamano en ranuras.
                Code c{end, UWOP_ALLOC_LARGE, 0};
                c.extra0 = static_cast<uint16_t>(n / 8);
                c.n_extra = 1;
                codes.push_back(c);
            } else {
                // Cualquier tamano: dos ranuras mas, con el tamano en BYTES.
                Code c{end, UWOP_ALLOC_LARGE, 1};
                c.extra0 = static_cast<uint16_t>(n & 0xFFFFu);
                c.extra1 = static_cast<uint16_t>(n >> 16);
                c.n_extra = 2;
                codes.push_back(c);
            }
            break;
        }
        case FrameOp::Kind::SetFramePointer:
            has_frame_pointer = true;
            frame_pointer_reg = op.reg;
            codes.push_back({end, UWOP_SET_FPREG, 0});
            break;
        case FrameOp::Kind::SaveReg:
            // Solo el banco general: un registro ancho se salva de otra forma.
            if (op.reg > 15) break;
            codes.push_back(
                {end, UWOP_PUSH_NONVOL, static_cast<uint8_t>(op.reg)});
            break;
        }
    }

    if (codes.empty()) return false; // nada que describir

    // Cuantas ranuras de dos bytes ocupan en total.
    uint32_t slots = 0;
    for (const Code &c : codes)
        slots += 1u + c.n_extra;
    if (slots > PE_X86_64_MAX_SLOTS) return false;

    out.resize(4u + 2u * static_cast<size_t>(slots), 0);

    out[0] = 1; // version 1, sin banderas
    out[1] = end;
    out[2] = static_cast<uint8_t>(slots);
    /* El registro de marco, si lo hay: nibble bajo el registro, nibble alto el
     * desplazamiento en unidades de 16 bytes.  Nuestro `mov rbp, rsp` no suma
     * nada, asi que el desplazamiento es 0. */
    out[3] = has_frame_pointer ? static_cast<uint8_t>(frame_pointer_reg) : 0u;

    size_t k = 4;
    for (const Code &c : codes) {
        out[k++] = c.offset;
        out[k++] = static_cast<uint8_t>(c.op | (c.info << 4));
        if (c.n_extra >= 1) {
            out[k++] = static_cast<uint8_t>(c.extra0 & 0xFFu);
            out[k++] = static_cast<uint8_t>(c.extra0 >> 8);
        }
        if (c.n_extra >= 2) {
            out[k++] = static_cast<uint8_t>(c.extra1 & 0xFFu);
            out[k++] = static_cast<uint8_t>(c.extra1 >> 8);
        }
    }
    return true;
}

} // namespace unwind
} // namespace codegen
