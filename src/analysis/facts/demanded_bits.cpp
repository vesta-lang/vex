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
 * @file analysis/facts/demanded_bits.cpp
 * @brief Punto fijo hacia atras: cuantos bits de cada valor mira alguien.
 *
 * Ver @ref analysis/facts/demanded_bits.h para POR QUE existe y por que no lo
 * contestan los KnownBits.
 *
 * El criterio de "que lee cada operacion" vive AQUI y en ningun otro sitio.
 * Estuvo escrito dentro de un pase del optimizador, y esa es exactamente la
 * forma en que se queda corto sin que se note: quien lo escribio enumero los
 * consumidores que tenia delante -- las cuentas y los phis -- y el dia que la
 * cadena real fue `trunc` + `bitcast` + `store`, el bitcast de en medio corto
 * la tolerancia y la normalizacion se pago entera, sin que nada fallara.
 */

#include "analysis/facts/demanded_bits.h"

#include "ir/ir_type_info.h"
#include "ir/ssa_ir.h"

namespace analysis {

uint8_t type_promised_bits(ir::IrType t) {
    const uint32_t n = ir::type_narrow_bits(t);
    return (n == 0 || n >= 64) ? uint8_t{64} : static_cast<uint8_t>(n);
}

namespace {

/**
 * @brief Cuantos bits del operando @p k lee la instruccion @p in.
 *
 * Devuelve 64 para todo lo que no se reconozca: quedarse corto solo cuesta
 * velocidad, pasarse daria otro resultado.
 *
 * @param in     Instruccion que consume.
 * @param k      Posicion del operando.
 * @param fn     Funcion, para mirar el tipo de los valores.
 * @param out_of Bits que ya se sabe que se demandan del RESULTADO de @p in.
 *               Lo necesitan las operaciones que solo TRANSPORTAN -- un phi, un
 *               bitcast del mismo ancho --: no leen nada por su cuenta, asi que
 *               lo que demandan es lo que demande quien las use.
 */
uint8_t reads_from(const ir::IrInstr &in, size_t k, const ir::IrFunction &fn,
                   uint8_t out_of) {
    const auto operand_bits = [&](size_t i) -> uint8_t {
        if (i >= in.operands.size() || in.operands[i] >= fn.values.size())
            return 64;
        return type_promised_bits(fn.values[in.operands[i]].type);
    };
    switch (in.op) {
    /* Escribe N bytes en memoria: de lo que guarda solo mira esos.  La
     * DIRECCION no: ahi los bits de arriba deciden a donde se escribe. */
    case ir::IrOp::STORE: return k == 0 ? type_promised_bits(in.type) : uint8_t{64};
    /* Se queda con los de abajo, tantos como diga su tipo destino. */
    case ir::IrOp::TRUNC: return type_promised_bits(in.type);
    /* Extienden DESDE el ancho de su fuente: leen exactamente eso. */
    case ir::IrOp::SEXT:
    case ir::IrOp::ZEXT: return operand_bits(k);
    /* No miran nada: reinterpretan.  Piden lo que les pidan a ellos, y solo
     * si no cambian de ancho -- pasar de 64 a 32 SI elige cuales. */
    case ir::IrOp::BITCAST:
        return (in.dst < fn.values.size() &&
                type_promised_bits(fn.values[in.dst].type) == operand_bits(k))
                   ? out_of
                   : uint8_t{64};
    /* Tampoco: transportan.  El punto fijo es lo que hace que esto converja
     * cuando el phi se refiere a si mismo a traves del bucle. */
    case ir::IrOp::PHI: return out_of;
    /* Una cuenta produce los bits bajos del resultado SOLO a partir de los
     * bits bajos de sus operandos -- el acarreo va hacia arriba, nunca hacia
     * abajo --, asi que si de su resultado solo se miran N, de sus operandos
     * tambien.  Vale para suma, resta y multiplicacion; NO para division,
     * resto ni desplazamiento a la derecha, donde los bits altos SI bajan. */
    case ir::IrOp::ADD:
    case ir::IrOp::SUB:
    case ir::IrOp::MUL: return out_of;
    /* Y las bit a bit, por lo mismo y aun mas claro: cada bit del resultado
     * sale de los del mismo sitio. */
    case ir::IrOp::AND:
    case ir::IrOp::OR:
    case ir::IrOp::XOR: return out_of;
    /* Desplazar a la IZQUIERDA tambien: el bit j del resultado sale del j-k del
     * operando, que esta MAS ABAJO, asi que para saber los N de abajo bastan
     * los N de abajo.  Su hermano el de la derecha NO -- ahi los altos bajan --
     * y por eso no esta.
     *
     * La CANTIDAD (operando 1) se lee entera: desplazar por un valor sucio da
     * otro numero.  Faltaba, y era justo la forma en que salia una cuenta
     * estrecha en la practica: `(u32)(0x1000 * (i + 1))` baja a un `add`, su
     * normalizacion, y un `shl` -- y el `shl` cortaba la cadena aunque lo unico
     * que se hiciera despues fuera escribir cuatro bytes. */
    case ir::IrOp::SHL: return k == 0 ? out_of : uint8_t{64};
    default: return 64;
    }
}

} // namespace

DemandedBits compute_demanded_bits(const ir::IrFunction &fn) {
    DemandedBits out;
    if (fn.values.empty()) return out;
    /* Se empieza por ABAJO -- nadie mira nada -- y se sube segun aparecen los
     * usos, hasta que deje de cambiar.  Es el menor punto fijo, y es el que
     * toca: lo que se busca es la cota mas PEQUENA que siga siendo cierta.
     * Un valor sin usos se queda en 0, que es correcto y ademas util (lo mira
     * quien busca codigo muerto). */
    out.bits.assign(fn.values.size(), 0);

    /* Cota de vueltas.  El punto fijo es monotono -- los bits solo suben --,
     * asi que termina; la cota esta para que el analisis no se coma el tiempo
     * de compilacion en una funcion enorme.
     *
     * Y si la cota se ALCANZA, la respuesta no es la que haya quedado a medias:
     * seria mas BAJA que la verdadera, y una cota demasiado baja dice "de este
     * valor nadie mira por encima del bit N" cuando si lo miran.  Eso no da un
     * fallo, da otro numero.  Al cortar, se demanda todo. */
    const int kMaxRondas = 64;
    bool changed = true;
    int rondas = 0;
    for (; changed && rondas < kMaxRondas; ++rondas) {
        changed = false;
        for (const ir::IrBlock &bb : fn.blocks) {
            for (const ir::IrInstr &in : bb.instrs) {
                const uint8_t out_of =
                    (in.dst != ir::IR_NO_VALUE && in.dst < out.bits.size())
                        ? out.bits[in.dst]
                        : uint8_t{64};
                for (size_t k = 0; k < in.operands.size(); ++k) {
                    const ir::IrValueId o = in.operands[k];
                    if (o >= out.bits.size()) continue;
                    const uint8_t want = reads_from(in, k, fn, out_of);
                    if (want > out.bits[o]) {
                        out.bits[o] = want;
                        changed = true;
                    }
                }
                /* Los argumentos de un phi viajan aparte de `operands`. */
                for (const ir::IrPhiArg &pa : in.phi_args) {
                    if (pa.value >= out.bits.size()) continue;
                    if (out_of > out.bits[pa.value]) {
                        out.bits[pa.value] = out_of;
                        changed = true;
                    }
                }
                /* Un destino de llamada indirecta se usa ENTERO. */
                if (in.func_ptr != ir::IR_NO_VALUE) {
                    if (in.func_ptr < out.bits.size() &&
                        out.bits[in.func_ptr] != 64) {
                        out.bits[in.func_ptr] = 64;
                        changed = true;
                    }
                }
            }
        }
    }
    /* No convergio dentro de la cota: se contesta lo unico que no puede
     * equivocarse.  Callarse a medias aqui seria peor que no analizar. */
    if (changed && rondas >= kMaxRondas) {
        out.bits.assign(fn.values.size(), 64);
        out.converged = false;
    }
    return out;
}

char DemandedBitsAnalysis::ID = 0;

} // namespace analysis
