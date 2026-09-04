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
#include "util/env_flags.h" // para poder MIRAR lo que este analisis no supo

#include <algorithm>
#include <atomic>
#include <cstdio>

namespace analysis {

using ir::IR_NO_VALUE;
using ir::IrInstr;
using ir::IrOp;
using ir::IrValueId;

namespace {

/**
 * @brief Cuanto se deja sin acotar, y por que.  Se cuenta y NO se calla.
 *
 * Este analisis renuncia cuando el arranque o el limite del bucle no es una
 * constante ESCRITA.  Para despejar esos casos harian falta los rangos, y
 * pedirselos cerraria el circulo -- son ellos los que reciben esto --, asi que
 * el corte se paga renunciando.
 *
 * Lo que NO puede pasar es que se pague en silencio: cada variable que se
 * queda sin cota es una optimizacion que no se hace, y sin este recuento no
 * habia forma de saber si eran cuatro o la mitad.  Los contadores existian ya
 * en @c LoopIvBounds; lo que faltaba era que alguien los mirase.
 */
void report_giveups(const LoopIvBounds &out) {
    static const bool on = util::flag_on(util::FlagId::RangeStats);
    if (!on) return;
    static std::atomic<long long> acotadas{0}, no_contados{0}, sin_iv{0},
        sin_init{0}, sin_limite{0}, guarda{0};
    acotadas += static_cast<long long>(out.bounds.size());
    no_contados += out.not_counted;
    sin_iv += out.no_shape_iv;
    sin_init += out.no_const_init;
    sin_limite += out.no_const_bound;
    guarda += out.guard_uncovered;
    static std::atomic<long long> n{0};
    if ((++n % 100) != 0) return;
    std::fprintf(stderr,
                 "[cotas-iv] acotadas=%lld | induccion-no-reconocida=%lld"
                 " | arranque-no-const=%lld | limite-no-const=%lld"
                 " | guarda-no-cubierta=%lld | no-contados=%lld\n",
                 acotadas.load(), sin_iv.load(), sin_init.load(),
                 sin_limite.load(), guarda.load(), no_contados.load());
}

/**
 * @brief El valor CONSTANTE de @p v: lo escrito, o lo que los rangos fijen.
 *
 * Empieza por el `CONST` escrito, que no cuesta nada y cubre el caso facil.
 * Si no lo hay y se traen @p ranges, vale un rango de UN SOLO valor: un
 * `[7,7]` dice lo mismo que un `7` escrito, y negarse a leerlo era lo que
 * dejaba sin cota al 89 % de los bucles contados.
 *
 * Esto NO reabre el circulo, y la diferencia esta en QUIEN los trae: aqui no
 * se piden rangos -- no se puede, son ellos los que reciben esto --, se usan
 * los que el llamante YA tiene de una pasada anterior.  El orden lo impone
 * quien llama (ver @c compute_ranges_ptr): rangos sin cotas, cotas con esos
 * rangos, y rangos otra vez con las cotas.  Cada etapa solo estrecha, asi que
 * el resultado sigue conteniendo al punto fijo real.
 */
bool const_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
              IrValueId v, int64_t &out, const RangeFacts *ranges) {
    if (v == IR_NO_VALUE || v >= fn.values.size()) return false;
    const int db = (v < (IrValueId)def_block.size()) ? def_block[v] : -1;
    if (db >= 0 && (size_t)db < fn.blocks.size())
        for (const IrInstr &in : fn.blocks[db].instrs)
            if (in.dst == v && in.op == IrOp::CONST) {
                out = (int64_t)in.imm;
                return true;
            }
    if (ranges == nullptr) return false;
    const ValueRange &r = ranges->at(v);
    if (!r.es_constante()) return false;
    /* Con signo: quien lo consume despeja con aritmetica con signo (`i +
     * C < N`), y leer un extremo con el otro convenio da OTRO NUMERO. */
    int64_t lo = 0, hi = 0;
    if (!r.vista_con_signo(lo, hi) || lo != hi) return false;
    out = lo;
    return true;
}

} // namespace

LoopIvBounds compute_loop_iv_bounds(const ir::IrFunction &fn,
                                    const IrFacts &facts,
                                    const LoopFacts &loops,
                                    const RangeFacts *ranges) {
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

    /**
     * @brief Entre que dos numeros esta @p v: por esta pasada, o por rangos.
     *
     * Primero lo que este mismo analisis acaba de establecer -- el bucle de
     * fuera en un recorrido triangular --, y si no lo que digan los rangos de
     * una pasada anterior.
     *
     * NO hace falta que sea constante, y ese era el error de la primera
     * version: se exigia un rango de UN SOLO valor y por eso no recuperaba
     * nada.  Un limite que sea un parametro no vale un numero fijo, pero si
     * esta acotado, y con el extremo que da MAS vueltas sale una cota de la
     * variable que sigue conteniendo todos sus valores.  Es la misma regla que
     * ya se aplicaba a lo establecido en la pasada; lo unico nuevo es de donde
     * viene el intervalo.
     */
    auto ya_acotado = [&](ir::IrValueId v, int64_t &lo, int64_t &hi) -> bool {
        for (const IvBound &c : out.bounds)
            if (c.value == v) return c.range.vista_con_signo(lo, hi);
        if (ranges == nullptr) return false;
        const ValueRange &r = ranges->at(v);
        if (!r.acotada()) return false;
        if (!r.vista_con_signo(lo, hi)) return false;
        /* Viene de un RANGO, que es una sobre-aproximacion: la cota que salga
         * de aqui vale para optimizar con guarda, no para acusar. */
        out.any_inferred = true;
        return true;
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
            ++out.no_shape_iv;
            continue;
        }
        int64_t init = 0, bound = 0;
        bool has_init = iv.stride > 0 &&
                        const_of(fn, facts.def_block, iv.init, init, ranges);
        if (!has_init && iv.stride > 0) {
            /* El arranque tampoco necesita ser un numero fijo: con el intervalo
             * en el que esta basta, cogiendo el extremo que hace la cota MAS
             * ANCHA -- el mas bajo si el bucle sube, el mas alto si baja --.
             * Ese es el que la deja conteniendo todos los arranques posibles.
             *
             * Los rangos NO se piden aqui: los trae quien llama, de una pasada
             * anterior hecha sin cotas.  Pedirlos cerraria el circulo. */
            int64_t ilo = 0, ihi = 0;
            if (ya_acotado(iv.init, ilo, ihi)) {
                init = iv.dir == IvDir::Down ? ihi : ilo;
                has_init = true;
            }
        }
        if (!has_init) {
            ++out.no_shape;
            ++out.no_const_init;
            continue;
        }
        if (!const_of(fn, facts.def_block, iv.bound, bound, ranges)) {
            /* El limite tambien vale si es una variable que este mismo
             * analisis ya acoto -- tipicamente la del bucle de fuera, que es
             * como se escribe un recorrido triangular.  Se coge el extremo que
             * da MAS vueltas: subiendo, lo mas alto que puede llegar el
             * limite; bajando, lo mas bajo. */
            int64_t blo = 0, bhi = 0;
            if (!ya_acotado(iv.bound, blo, bhi)) {
                ++out.no_shape;
                ++out.no_const_bound;
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
                ++out.guard_uncovered;
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
                ++out.guard_uncovered;
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
    report_giveups(out);
    return out;
}

} // namespace analysis
