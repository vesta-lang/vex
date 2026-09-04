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
 * @file aot/lower/statics.cpp
 * @copydoc aot/lower/statics.h
 */

#include "statics.h"

#include "ir/ir_optimizer.h"

#include <unordered_set>

namespace aot {

bool lower_static_field(ir::IrFunction &fn, const ir::IrInstr &in,
                        std::vector<ir::IrInstr> &out,
                        const StaticSlotFn &slot_for) {
    const bool is_read = (in.op == ir::IrOp::GETSTATIC);
    if (!is_read && in.op != ir::IrOp::SETSTATIC) return false;
    /* Sin nombre no hay hueco que nombrar, y adivinarlo del desplazamiento
     * daria uno distinto para el mismo campo segun por donde se llegara.  Se
     * deja como estaba: quien clasifica las operaciones dira que este modulo
     * no es compilable a nativo, con su motivo. */
    if (in.func_name.empty()) return false;

    const uint64_t slot = slot_for(in.func_name);

    // Donde vive: una direccion del PROCESO, no de la maquina virtual.  Las
    // dos se escriben igual y confundirlas no da un error, da otro valor.
    ir::IrInstr addr{};
    addr.op = ir::IrOp::STR_LIT_ADDR;
    addr.type = ir::IrType::PTR;
    addr.dst = fn.new_value(ir::IrType::PTR);
    addr.imm = slot;
    addr.source_line = in.source_line;
    const ir::IrValueId v_addr = addr.dst;
    fn.values[v_addr].is_host_ptr = true;
    out.push_back(std::move(addr));

    ir::IrInstr acc{};
    acc.source_line = in.source_line;
    if (is_read) {
        acc.op = ir::IrOp::LOAD;
        acc.type = in.type;
        acc.dst = in.dst;
        acc.operands = {v_addr};
    } else {
        /* El valor es el SEGUNDO operando; el primero es la clase, que aqui ya
         * no pinta nada -- si nadie mas la usa, se la lleva la limpieza de
         * codigo muerto. */
        acc.op = ir::IrOp::STORE;
        acc.type = ir::IrType::I64;
        acc.dst = ir::IR_NO_VALUE;
        /* VALOR primero y DIRECCION despues, que es como esta declarada la
         * operacion: `store.T %val, %ptr`.  Al reves no da un error -- las dos
         * son valores del mismo ancho -- : escribe la direccion del hueco
         * dentro de lo que se queria guardar, y el fallo aparece en otro
         * sitio. */
        acc.operands = {in.operands.size() > 1 ? in.operands[1]
                                               : in.operands[0],
                        v_addr};
    }
    out.push_back(std::move(acc));
    return true;
}

void clean_after_static_lowering(ir::IrFunction &fn) {
    /* Buscar una clase por su nombre cuenta como IMPURA -- puede fallar -- asi
     * que la limpieza general nunca la va a quitar, por mucho que su resultado
     * no lo lea nadie.  Aqui si se sabe: al bajar el campo se fue el unico que
     * la leia. */
    std::unordered_set<ir::IrValueId> used;
    for (const auto &bb : fn.blocks)
        for (const auto &in : bb.instrs)
            for (ir::IrValueId v : in.operands) used.insert(v);

    /* Los buffers de pila donde se le dejaban los parametros a esas busquedas.
     * Se apuntan al quitarlas: son lo unico que queda por deshacer. */
    std::unordered_set<ir::IrValueId> buffers;
    for (auto &bb : fn.blocks) {
        std::vector<ir::IrInstr> keep;
        keep.reserve(bb.instrs.size());
        for (auto &in : bb.instrs) {
            const bool orphan = (in.op == ir::IrOp::FINDCLASS) &&
                                in.dst != ir::IR_NO_VALUE &&
                                !used.count(in.dst);
            if (orphan) {
                if (!in.operands.empty()) buffers.insert(in.operands[0]);
            } else {
                keep.push_back(std::move(in));
            }
        }
        bb.instrs.swap(keep);
    }
    if (buffers.empty()) return;

    /* Todo lo que APUNTA a uno de esos buffers, no solo el buffer.  El nombre
     * de la clase se guarda al principio y su longitud ocho bytes mas alla, asi
     * que por medio hay una suma: quien solo mire el valor del hueco vera que
     * su direccion se le pasa a una suma, no sabra a donde va a parar y --
     * correctamente -- se rendira.  Aqui si se sabe. */
    for (bool growing = true; growing;) {
        growing = false;
        for (const auto &bb : fn.blocks)
            for (const auto &in : bb.instrs)
                if (in.op == ir::IrOp::ADD && in.dst != ir::IR_NO_VALUE &&
                    !in.operands.empty() && buffers.count(in.operands[0]) &&
                    buffers.insert(in.dst).second)
                    growing = true;
    }

    /* Y solo se quitan si NADIE mas los toca.  Vale escribir dentro y vale
     * desplazarse por ellos; cualquier otra cosa -- pasarselos a una llamada,
     * leerlos, devolverlos -- significa que el buffer sigue haciendo falta y
     * mas vale dejarlo entero que quitarlo a medias. */
    for (const auto &bb : fn.blocks) {
        for (const auto &in : bb.instrs) {
            for (size_t k = 0; k < in.operands.size(); ++k) {
                if (!buffers.count(in.operands[k])) continue;
                const bool store_into = (in.op == ir::IrOp::STORE && k == 1);
                const bool step_within = (in.op == ir::IrOp::ADD && k == 0 &&
                                          buffers.count(in.dst));
                if (!store_into && !step_within) return;
            }
        }
    }

    for (auto &bb : fn.blocks) {
        std::vector<ir::IrInstr> keep;
        keep.reserve(bb.instrs.size());
        for (auto &in : bb.instrs) {
            const bool is_the_slot =
                in.dst != ir::IR_NO_VALUE && buffers.count(in.dst);
            const bool writes_into = in.op == ir::IrOp::STORE &&
                                     in.operands.size() > 1 &&
                                     buffers.count(in.operands[1]);
            if (!is_the_slot && !writes_into) keep.push_back(std::move(in));
        }
        bb.instrs.swap(keep);
    }

    /* Lo que quedo alimentando a lo que se acaba de ir -- la direccion del
     * nombre, su longitud, el desplazamiento -- lo recoge la limpieza general:
     * son valores que ya no usa nadie, que es justo la pregunta que sabe
     * responder.  Escribirla otra vez aqui seria tener dos respuestas para lo
     * mismo. */
    while (ir::ir_pass_dce(fn)) {
    }
}

} // namespace aot
