/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_trip_count.cpp
 * @brief Implementacion del hecho trip-count (ver loop_trip_count.h).
 */

#include "analysis/facts/loop_trip_count.h"

namespace analysis {

using ir::IR_NO_VALUE;
using ir::IrInstr;
using ir::IrOp;
using ir::IrValueId;

namespace {

// Resuelve el valor CONSTANTE de @p v (la CONST que lo define en su bloque).
bool const_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
              IrValueId v, int64_t &out) {
    if (v == IR_NO_VALUE || v >= fn.values.size()) return false;
    const int db = (v < def_block.size()) ? def_block[v] : -1;
    if (db < 0 || (size_t)db >= fn.blocks.size()) return false;
    for (const IrInstr &in : fn.blocks[db].instrs)
        if (in.dst == v && in.op == IrOp::CONST) {
            out = (int64_t)in.imm;
            return true;
        }
    return false;
}

} // namespace

/**
 * @brief Vueltas que caben desde @p init hasta @p bound, o -1 si no cabe
 *        ninguna forma reconocida.
 *
 * La formula es la misma para el numero EXACTO y para la COTA; lo unico que
 * cambia son los extremos que se le pasan.  Estaba escrita en linea y habria
 * que haberla duplicado para la cota, que es como se acaba con dos versiones
 * que se separan.
 *
 * @param cmp_op guarda del bucle (`<` o `<=`; otra cosa devuelve -1).
 */
static int64_t trips_between(int64_t init, int64_t bound, int64_t cmp_offset,
                             int64_t stride, ir::IrOp cmp_op) {
    /* Un bucle que BAJA es el mismo problema con los extremos cambiados de
     * sitio: `for (i = I; i > N; i -= S)` recorre el mismo tramo que
     * `for (i = N; i < I; i += S)`.  Se le da la vuelta y se sigue por el
     * mismo camino, en vez de escribir la formula otra vez -- dos copias de
     * una cuenta con extremos cruzados es como se acaba con una bien y la
     * otra desviada en uno. */
    if (cmp_op == ir::IrOp::CMP_GT || cmp_op == ir::IrOp::CMP_UGT) {
        cmp_op = ir::IrOp::CMP_LT;
        const int64_t tmp = init;
        init = bound;
        bound = tmp;
        cmp_offset = -cmp_offset;
    } else if (cmp_op == ir::IrOp::CMP_GE || cmp_op == ir::IrOp::CMP_UGE) {
        cmp_op = ir::IrOp::CMP_LE;
        const int64_t tmp = init;
        init = bound;
        bound = tmp;
        cmp_offset = -cmp_offset;
    }
    /* La resta primero, y COMPROBADA.  Con extremos grandes -- que es
     * justo lo que llega cuando la cota sale de un rango -- desbordaba, y un
     * desbordamiento con signo no da un numero grande: da uno cualquiera, y
     * ese numero se publicaba como si fuera el trip count.  Mejor no afirmar
     * que afirmar de mas. */
    int64_t room = 0;
    if (__builtin_sub_overflow(bound, cmp_offset, &room)) return -1;
    if (__builtin_sub_overflow(room, init, &room)) return -1;
    if (room <= 0) return 0; // no itera (guarda falsa de entrada).
    if (cmp_op == IrOp::CMP_LT || cmp_op == IrOp::CMP_ULT) {
        int64_t techo = 0; // ceil, sin desbordar al redondear hacia arriba
        if (__builtin_add_overflow(room, stride - 1, &techo)) return -1;
        return techo / stride;
    }
    if (cmp_op == IrOp::CMP_LE || cmp_op == IrOp::CMP_ULE) {
        int64_t t = 0; // floor + 1
        if (__builtin_add_overflow(room / stride, (int64_t)1, &t)) return -1;
        return t;
    }
    return -1; // guarda que este analisis no cubre.
}

LoopTripInfo compute_trip_count(const ir::IrFunction &fn,
                                const std::vector<int> &def_block,
                                const LoopIV &iv, const RangeFacts *ranges) {
    LoopTripInfo info;
    int64_t init_v = 0, bound_v = 0;

    /* Los rangos de un valor, si se tienen y dicen algo.  Es la SEGUNDA
     * fuente: se pregunta solo cuando la primera -- lo que el programa dice
     * con un `CONST` -- no llega. */
    auto range_of = [&](ir::IrValueId v, int64_t &lo, int64_t &hi) -> bool {
        if (ranges == nullptr || v >= ranges->r.size()) return false;
        const ValueRange &rg = ranges->r[v];
        if (!rg.acotada()) return false;
        /* El rango ENTERO del tipo no acota nada: es la forma que tiene el
         * analisis de decir "cualquier valor".  Tomarlo por una cota publicaba
         * "el bucle da como mucho 9223372036854775807 vueltas", que es cierto
         * y no significa nada -- y peor, viste de conocimiento lo que es
         * justamente su ausencia, que es como un respaldo permisivo acaba
         * pareciendo que funciona. */
        if (rg.es_todo()) return false;
        return rg.vista_con_signo(lo, hi);
    };
    /* El valor exacto: primero lo escrito, y si no, un rango de un solo punto
     * -- que es un valor igual, pero llegado por aproximaciones sucesivas, y
     * por eso baja la certeza del hecho entero. */
    auto exact_value_of = [&](ir::IrValueId v, int64_t &out) -> bool {
        if (const_of(fn, def_block, v, out)) return true;
        int64_t lo = 0, hi = 0;
        if (!range_of(v, lo, hi) || lo != hi) return false;
        out = lo;
        info.certainty = asa::Certainty::Inferred;
        return true;
    };
    /* Cada renuncia con SU motivo.  No es documentacion: es lo que decide que
     * puede hacer el consumidor.  Un limite que solo existe al ejecutar admite
     * una guarda; una forma que este analisis no cubre, no -- ahi lo que hay
     * que hacer es ampliar el analisis, y por eso se distinguen. */
    if (iv.stride <= 0) {
        /* Sin avance no hay nada que contar: el bucle no termina por esta
         * variable.  El sentido ya no es un problema -- los dos se cuentan --,
         * pero un paso de cero o negativo sigue sin modelarse: `stride` es el
         * TAMANO del paso y tiene que ser positivo. */
        info.reason = asa::UnknownReason::ShapeNotRecognized;
        info.code = "loop.non_increasing_iv";
        return info;
    }
    const bool has_init = exact_value_of(iv.init, init_v);
    const bool has_bound = exact_value_of(iv.bound, bound_v);

    if (has_init && has_bound) {
        const int64_t t = trips_between(init_v, bound_v, iv.cmp_offset,
                                        iv.stride, iv.cmp_op);
        if (t >= 0) {
            info.trip = t;
            return info;
        }
        /* La guarda no es `<` ni `<=`.  Otra FORMA que no se cubre, y no un
         * limite que dependa de la ejecucion: el bucle puede ser perfectamente
         * contado con `!=` y este analisis no sabe leerlo. */
        info.reason = asa::UnknownReason::ShapeNotRecognized;
        info.code = "loop.unsupported_guard";
        return info;
    }

    /* No sale el numero exacto.  Antes se acababa aqui, pero "no se cuantas
     * vueltas da" y "no se nada" no son lo mismo: si el limite esta ACOTADO
     * ARRIBA y el inicio ACOTADO ABAJO, el bucle esta acotado, y con eso ya se
     * puede decidir si compensa desenrollar o acotar un coste.
     *
     * Las vueltas crecen cuando el inicio es lo menor posible y el limite lo
     * mayor posible, asi que la cota sale de esos dos extremos. */
    int64_t init_lo = 0, init_hi = 0, bound_lo = 0, bound_hi = 0;
    const bool init_bounded = has_init
                                  ? (init_lo = init_hi = init_v, true)
                                  : range_of(iv.init, init_lo, init_hi);
    const bool bound_bounded = has_bound
                                   ? (bound_lo = bound_hi = bound_v, true)
                                   : range_of(iv.bound, bound_lo, bound_hi);
    if (init_bounded && bound_bounded) {
        /* Los extremos que dan MAS vueltas, que si el bucle baja son los
         * contrarios: subiendo se dan mas cuanto antes se empieza y mas lejos
         * se llega; bajando, cuanto MAS ALTO se empieza y mas abajo esta el
         * limite.  Coger siempre los mismos daria una "cota" por debajo de la
         * realidad, que es lo peor que puede pasar aqui. */
        const bool baja = iv.dir == IvDir::Down;
        const int64_t desde = baja ? init_hi : init_lo;
        const int64_t hasta = baja ? bound_lo : bound_hi;
        const int64_t t = trips_between(desde, hasta, iv.cmp_offset,
                                        iv.stride, iv.cmp_op);
        if (t >= 0) {
            info.trip_max = t;
            /* Sale de un punto fijo sobre un reticulo, no de lo que el
             * programa dice: sirve para elegir, no para quitar una
             * comprobacion. */
            info.certainty = asa::Certainty::Inferred;
            info.reason = asa::UnknownReason::RuntimeDependent;
            info.code = "loop.trip_bounded";
            return info;
        }
    }

    /* Ni exacto ni acotado.  Se distingue cual de los dos extremos falta,
     * porque no se arreglan igual: un inicio que depende de la ejecucion pide
     * una precondicion, y un limite que depende de ella admite una guarda. */
    info.reason = asa::UnknownReason::RuntimeDependent;
    info.code = has_init ? "loop.non_constant_bound" : "loop.non_constant_init";
    return info;
}

} // namespace analysis
