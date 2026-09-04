/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_iv_bounds.cpp
 * @brief Implementacion de la cota de las variables de induccion
 *        (loop_iv_bounds.h).
 */

#include "analysis/facts/loop_iv_bounds.h"

#include "analysis/facts/loop_iv.h"
#include "analysis/facts/loop_structure.h"

#include <algorithm>

namespace analysis {

using ir::IR_NO_VALUE;
using ir::IrInstr;
using ir::IrOp;
using ir::IrValueId;

namespace {

/// El valor CONSTANTE de @p v, si lo define un `CONST`.  Solo lo ESCRITO: si
/// hubiera que preguntarle a los rangos, esto dependeria de ellos y ellos de
/// esto.
bool const_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
              IrValueId v, int64_t &out) {
    if (v == IR_NO_VALUE || v >= fn.values.size()) return false;
    const int db = (v < (IrValueId)def_block.size()) ? def_block[v] : -1;
    if (db < 0 || (size_t)db >= fn.blocks.size()) return false;
    for (const IrInstr &in : fn.blocks[db].instrs)
        if (in.dst == v && in.op == IrOp::CONST) {
            out = (int64_t)in.imm;
            return true;
        }
    return false;
}

} // namespace

LoopIvBounds compute_loop_iv_bounds(const ir::IrFunction &fn,
                                    const IrFacts &facts,
                                    const LoopFacts &loops) {
    LoopIvBounds out;
    if (loops.loop_count == 0) return out;
    /* Una por bucle como mucho, y son pocos: se reserva de una vez para no ir
     * creciendo el vector bucle a bucle. */
    out.bounds.reserve(loops.loop_count);

    /* DE FUERA HACIA DENTRO, y no es un detalle de orden: el limite de un
     * bucle anidado suele ser la variable del que lo contiene
     * (`for (j = 0; j < i; j++)`), asi que mirando primero el de fuera se
     * puede acotar el de dentro.  Al reves no se puede.
     *
     * Y esto NO es preguntar a los rangos -- seguirian mordiendose la cola --:
     * es apoyarse en lo que este mismo analisis acaba de establecer. */
    std::vector<uint32_t> orden(loops.loop_count);
    for (uint32_t L = 0; L < loops.loop_count; ++L)
        orden[L] = L;
    std::sort(orden.begin(), orden.end(), [&](uint32_t a, uint32_t b) {
        return loops.depth_of(
                   static_cast<ir::IrBlockId>(loops.header_block_of(a))) <
               loops.depth_of(
                   static_cast<ir::IrBlockId>(loops.header_block_of(b)));
    });

    /// Lo ya establecido para @p v en esta misma pasada, si lo hay.
    auto ya_acotado = [&](ir::IrValueId v, int64_t &lo, int64_t &hi) -> bool {
        for (const IvBound &c : out.bounds)
            if (c.value == v) return c.range.vista_con_signo(lo, hi);
        return false;
    };

    for (uint32_t L : orden) {
        const LoopStructure ls = detect_loop_structure(fn, loops, L);
        /* CONTABLE basta: la cota de la variable sale de la guarda y del paso,
         * y una salida anticipada no la sube -- solo hace que se llegue menos
         * lejos. */
        if (!ls.countable) {
            ++out.not_counted;
            continue;
        }
        LoopIV iv; // los dos sentidos: acotar no es clonar
        if (!detect_counted_iv(fn, facts.def_block, ls.header, ls.preheader,
                               ls.latch, iv)) {
            ++out.no_shape;
            continue;
        }
        int64_t init = 0, bound = 0;
        if (iv.stride <= 0 || !const_of(fn, facts.def_block, iv.init, init)) {
            /* Sin el arranque ESCRITO no se despeja.  Es de proposito que no se
             * pregunte a los rangos: son ellos los que van a recibir esto, y
             * consultarlos aqui cerraria el circulo. */
            ++out.no_shape;
            continue;
        }
        if (!const_of(fn, facts.def_block, iv.bound, bound)) {
            /* El limite tambien vale si es una variable que este mismo
             * analisis ya acoto -- tipicamente la del bucle de fuera, que es
             * como se escribe un recorrido triangular.  Se coge el extremo que
             * da MAS vueltas: subiendo, lo mas alto que puede llegar el
             * limite; bajando, lo mas bajo. */
            int64_t blo = 0, bhi = 0;
            if (!ya_acotado(iv.bound, blo, bhi)) {
                ++out.no_shape;
                continue;
            }
            bound = iv.dir == IvDir::Down ? blo : bhi;
        }
        if (iv.phi == IR_NO_VALUE || iv.phi >= fn.values.size()) continue;

        /* El extremo alto es el valor con el que se SALE, que es una vuelta
         * mas alla de la ultima que paso la guarda: `i + C < N` deja entrar
         * hasta `i = N - C - 1`, y esa vuelta avanza a `i = N - C - 1 + S`.
         *
         * Con `<=` la ultima que entra es `i = N - C`, y sale en `N - C + S`.
         *
         * Todo comprobado contra desbordamiento: la cuenta se hace sobre
         * numeros que salen del programa, y un desbordamiento con signo no da
         * un numero grande, da uno CUALQUIERA -- que aqui se publicaria como
         * cota y estrecharia un rango con un valor inventado. */
        int64_t extremo = 0;
        if (__builtin_sub_overflow(bound, iv.cmp_offset, &extremo)) continue;
        const bool baja = iv.dir == IvDir::Down;
        if (baja) {
            /* Bajando es la imagen especular: `i + C > N` deja entrar hasta
             * `i = N - C + 1`, y esa vuelta baja a `i = N - C + 1 - S`.  Con
             * `>=`, hasta `i = N - C`, que sale en `N - C - S`. */
            if (iv.cmp_op == IrOp::CMP_GT || iv.cmp_op == IrOp::CMP_UGT) {
                if (__builtin_add_overflow(extremo, (int64_t)1, &extremo))
                    continue;
            } else if (iv.cmp_op != IrOp::CMP_GE &&
                       iv.cmp_op != IrOp::CMP_UGE) {
                ++out.no_shape; // guarda que este despeje no cubre
                continue;
            }
            if (__builtin_sub_overflow(extremo, iv.stride, &extremo)) continue;
            /* Un bucle que no entra nunca deja la variable en su valor
             * inicial: la cota no puede pasarse del inicio. */
            if (extremo > init) extremo = init;
        } else {
            if (iv.cmp_op == IrOp::CMP_LT || iv.cmp_op == IrOp::CMP_ULT) {
                if (__builtin_sub_overflow(extremo, (int64_t)1, &extremo))
                    continue;
            } else if (iv.cmp_op != IrOp::CMP_LE &&
                       iv.cmp_op != IrOp::CMP_ULE) {
                ++out.no_shape; // guarda que este despeje no cubre
                continue;
            }
            if (__builtin_add_overflow(extremo, iv.stride, &extremo)) continue;
            if (extremo < init) extremo = init;
        }

        const ValueRange piso = rango_del_tipo(fn.values[iv.phi].type);
        if (!piso.acotada()) continue; // el tipo no es un entero acotable
        const ValueRange cota =
            baja ? ValueRange::de_enteros(piso.t, extremo, init)
                 : ValueRange::de_enteros(piso.t, init, extremo);
        if (!cota.acotada()) continue; // no cabe en el tipo de la variable
        out.bounds.push_back(IvBound{iv.phi, piso.cortar(cota)});
    }
    /* Ordenado por identificador: quien lo consume recorre sus valores en
     * orden, asi que asi los dos van a la par y la busqueda no retrocede.
     * Dos bucles no comparten variable -- cada PHI es de su cabecera --, asi
     * que no hay repetidos que unir. */
    std::sort(
        out.bounds.begin(), out.bounds.end(),
        [](const IvBound &a, const IvBound &b) { return a.value < b.value; });
    return out;
}

} // namespace analysis
