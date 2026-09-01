/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file loop_iv.cpp
 * @brief Implementacion del descubridor de la variable de induccion
 * (loop_iv.h).
 */

#include "analysis/facts/loop_iv.h"

namespace analysis {

using ir::IR_NO_BLOCK;
using ir::IR_NO_VALUE;
using ir::IrBlockId;
using ir::IrInstr;
using ir::IrOp;
using ir::IrValueId;

namespace {

// Guarda creciente reconocida: `iv < N` / `iv <= N` (signed y unsigned).
bool is_lt_cmp(IrOp op) {
    return op == IrOp::CMP_LT || op == IrOp::CMP_LE || op == IrOp::CMP_ULT ||
           op == IrOp::CMP_ULE;
}

// Y la decreciente: `iv > N` / `iv >= N`.  Un bucle que baja esta tan contado
// como uno que sube; lo unico que cambia es hacia donde.
bool is_gt_cmp(IrOp op) {
    return op == IrOp::CMP_GT || op == IrOp::CMP_GE || op == IrOp::CMP_UGT ||
           op == IrOp::CMP_UGE;
}

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

/**
 * @brief El valor del que @p v es una COPIA, siguiendo la cadena de `mov`.
 *
 * Un `mov` es identidad: `%4 = mov %3` significa que %4 ES %3.  Comparar los
 * dos identificadores como si fueran cosas distintas hace que el analisis
 * dependa de que la propagacion de copias haya corrido antes -- y ANTES de
 * optimizar no ha corrido: la construccion de SSA deja una copia del PHI en la
 * cabecera, con lo que el `cmp` compara la copia y no el PHI, y la variable de
 * induccion "no se encuentra" estando delante.
 *
 * El tope de saltos no es por miedo a un ciclo -- en SSA no puede haberlo --,
 * sino por si el IR llega roto: un analisis no debe colgar el compilador.
 */
IrValueId skip_copies(const ir::IrFunction &fn,
                      const std::vector<int> &def_block, IrValueId v) {
    for (int hops = 0; hops < 16; ++hops) {
        if (v == IR_NO_VALUE || v >= fn.values.size()) return v;
        const int db = (v < def_block.size()) ? def_block[v] : -1;
        if (db < 0 || (size_t)db >= fn.blocks.size()) return v;
        IrValueId next = IR_NO_VALUE;
        for (const IrInstr &in : fn.blocks[db].instrs)
            if (in.dst == v && in.op == IrOp::MOV && in.operands.size() == 1) {
                next = in.operands[0];
                break;
            }
        if (next == IR_NO_VALUE) return v;
        v = next;
    }
    return v;
}

// Descompone @p v = ADD(base, const) (en cualquier orden).  Devuelve base y c.
bool add_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
            IrValueId v, IrValueId &base, int64_t &c) {
    const int db =
        (v < def_block.size() && v != IR_NO_VALUE) ? def_block[v] : -1;
    if (db < 0 || (size_t)db >= fn.blocks.size()) return false;
    for (const IrInstr &in : fn.blocks[db].instrs) {
        if (in.dst != v || in.op != IrOp::ADD || in.operands.size() != 2)
            continue;
        int64_t k;
        if (const_of(fn, def_block, in.operands[1], k)) {
            base = in.operands[0];
            c = k;
            return true;
        }
        if (const_of(fn, def_block, in.operands[0], k)) {
            base = in.operands[1];
            c = k;
            return true;
        }
    }
    return false;
}

/**
 * @brief Suma TODA la cadena de `+constante` que separa @p v de @p base.
 *
 * `add_of` mira un solo escalon, y eso deja fuera la forma que el propio
 * compilador genera al DESENROLLAR: el valor que vuelve por el latch no es
 * `phi + 8`, son ocho `+1` encadenados, uno por copia del cuerpo.  Con un solo
 * escalon el analisis no reconocia la induccion y contestaba "no se encontro
 * una variable de induccion contada" sobre un bucle que el compilador acababa
 * de fabricar -- y de ahi el coste heredaba O(n^2) para una funcion constante.
 *
 * Se recorre hacia atras sumando.  El tope es por si el IR llega roto, no por
 * miedo a un ciclo: en SSA no puede haberlo.
 *
 * @param v     valor final de la cadena (el que vuelve por el latch).
 * @param base  donde tiene que terminar (el PHI del header).
 * @param total suma de las constantes, o sea el paso REAL de cada vuelta.
 * @return true si @p v se alcanza desde @p base sumando constantes.
 */
bool chain_add_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
                  IrValueId v, IrValueId base, int64_t &total) {
    total = 0;
    IrValueId cur = v;
    for (int hops = 0; hops < 64; ++hops) {
        if (cur == base) return hops > 0; // al menos un escalon
        IrValueId next = IR_NO_VALUE;
        int64_t c = 0;
        if (!add_of(fn, def_block, cur, next, c)) return false;
        total += c;
        cur = skip_copies(fn, def_block, next);
    }
    return false;
}

/// Descompone @p v = SUB(base, const).  El orden importa: `K - x` no es una
/// induccion decreciente, es otra cosa -- se alterna en vez de bajar.
bool sub_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
            IrValueId v, IrValueId &base, int64_t &c) {
    const int db =
        (v < def_block.size() && v != IR_NO_VALUE) ? def_block[v] : -1;
    if (db < 0 || (size_t)db >= fn.blocks.size()) return false;
    for (const IrInstr &in : fn.blocks[db].instrs) {
        if (in.dst != v || in.op != IrOp::SUB || in.operands.size() != 2)
            continue;
        int64_t k;
        if (const_of(fn, def_block, in.operands[1], k)) {
            base = in.operands[0];
            c = k;
            return true;
        }
    }
    return false;
}

/// Igual que @c chain_add_of pero restando.  Tambien encadena, y por el mismo
/// motivo: al desenrollar, lo que vuelve por el latch son U restas de `-1`.
bool chain_sub_of(const ir::IrFunction &fn, const std::vector<int> &def_block,
                  IrValueId v, IrValueId base, int64_t &total) {
    total = 0;
    IrValueId cur = v;
    for (int hops = 0; hops < 64; ++hops) {
        if (cur == base) return hops > 0;
        IrValueId next = IR_NO_VALUE;
        int64_t c = 0;
        if (!sub_of(fn, def_block, cur, next, c)) return false;
        total += c;
        cur = skip_copies(fn, def_block, next);
    }
    return false;
}

} // namespace

/**
 * @brief El cuerpo comun de los dos sentidos.
 *
 * Un solo recorrido con un parametro, y no dos funciones parecidas: la parte
 * dificil -- seguir las copias, encadenar los pasos que deja el desenrollado,
 * saltarse los acumuladores -- es identica, y duplicarla es como se acaba con
 * una mitad arreglada y la otra no.
 */
static bool detect_iv_impl(const ir::IrFunction &fn,
                           const std::vector<int> &def_block, IrBlockId header,
                           IrBlockId preheader, IrBlockId latch, bool admite_baja,
                           LoopIV &out) {
    out.phi_index = -1;
    if (header == (IrBlockId)IR_NO_BLOCK || header >= fn.blocks.size())
        return false;
    const auto &hins = fn.blocks[header].instrs;
    if (hins.empty()) return false;

    // 1) La guarda: el cmp que define la condicion del BR_COND.
    const IrInstr &term = hins.back();
    if (term.op != IrOp::BR_COND || term.operands.empty()) return false;
    const IrValueId cond = term.operands[0];
    IrOp cmp_op = IrOp::NOP;
    IvDir dir = IvDir::Up;
    IrValueId cmp_a = IR_NO_VALUE, cmp_b = IR_NO_VALUE;
    for (const IrInstr &in : hins) {
        if (in.dst != cond || in.operands.size() != 2) continue;
        const bool sube = is_lt_cmp(in.op);
        const bool baja = admite_baja && is_gt_cmp(in.op);
        if (sube || baja) {
            cmp_op = in.op;
            dir = sube ? IvDir::Up : IvDir::Down;
            /* A traves de las copias: lo que se compara es el VALOR, y un
             * `mov` no cambia el valor.  Sin esto, la copia que la
             * construccion de SSA deja en la cabecera hacia que el IV no se
             * reconociera hasta que otro pase la borrara. */
            cmp_a = skip_copies(fn, def_block, in.operands[0]);
            cmp_b = skip_copies(fn, def_block, in.operands[1]);
            break;
        }
    }
    if (cmp_op == IrOp::NOP) return false;

    /* 2) El IV: PHI del header cuyo valor de retorno (el que llega por el
     *    latch) avanza una constante en el sentido que dice la guarda.  El
     *    `init` es el que llega por el preheader.
     *
     * El paso se guarda siempre POSITIVO -- es el tamano --, y el sentido va
     * en `dir`.  Con un paso negativo, cada consumidor tendria que acordarse
     * del signo, y olvidarse no da un error: da una direccion al reves. */
    int phi_index = -1;
    for (const IrInstr &in : hins) {
        if (in.op != IrOp::PHI) continue;
        ++phi_index; // indice entre las PHIs, en orden de aparicion.
        IrValueId init = IR_NO_VALUE, back = IR_NO_VALUE;
        for (const auto &pa : in.phi_args) {
            if (pa.block == preheader)
                init = pa.value;
            else if (pa.block == latch)
                back = pa.value;
        }
        if (init == IR_NO_VALUE || back == IR_NO_VALUE) continue;
        IrValueId base;
        int64_t s;
        /* Y el valor que vuelve por el latch, tambien a traves de las copias:
         * `%12 = add %11, 1` donde `%11 = mov %phi` es el mismo `phi + 1`. */
        back = skip_copies(fn, def_block, back);
        /* La cadena ENTERA, no un escalon: al desenrollar, el valor que vuelve
         * son U sumas de `+1` en vez de un `+U`, y mirando solo la primera el
         * bucle dejaba de tener induccion. */
        (void)base;
        const bool avanza = dir == IvDir::Up
                                ? chain_add_of(fn, def_block, back, in.dst, s)
                                : chain_sub_of(fn, def_block, back, in.dst, s);
        if (avanza && s > 0) {
            // 3) La cota: el cmp compara `iv` o `iv + c` con N (el otro lado).
            int64_t off = 0;
            IrValueId bound = IR_NO_VALUE;
            if (cmp_a == in.dst) {
                off = 0;
                bound = cmp_b;
            } else {
                IrValueId cb;
                int64_t c;
                if (add_of(fn, def_block, cmp_a, cb, c) &&
                    skip_copies(fn, def_block, cb) == in.dst) {
                    off = c;
                    bound = cmp_b;
                } else {
                    /* Este PHI avanza como un IV pero NO es el que compara la
                     * guarda: se prueba el SIGUIENTE, no se abandona.
                     *
                     * Rendirse aqui hacia que un bucle normal no tuviera
                     * variable de induccion en cuanto llevara un ACUMULADOR
                     * (`t = t + 1`), que es lo mas corriente que hay: `t`
                     * tambien es `phi + constante`, se probaba primero, fallaba
                     * la guarda -- que compara `i` -- y el analisis contestaba
                     * "no se encontro una variable de induccion" sobre un
                     * `for` de manual.  El coste lo heredaba y declaraba O(?)
                     * una funcion que es O(n). */
                    continue;
                }
            }
            out.phi = in.dst;
            out.phi_index = phi_index;
            out.init = init;
            out.stride = s;
            out.dir = dir;
            out.cmp_op = cmp_op;
            out.cmp_offset = off;
            out.bound = bound;
            return true;
        }
    }
    return false;
}

bool detect_loop_iv(const ir::IrFunction &fn, const std::vector<int> &def_block,
                    IrBlockId header, IrBlockId preheader, IrBlockId latch,
                    LoopIV &out) {
    /* SOLO los que suben, y eso no es comodidad: quien pide esto desenrolla,
     * vectoriza o reconoce un recorrido de memoria, y calcula direcciones a
     * partir del paso.  Devolverle uno que baja haria que tocara lo que el
     * bucle no toca. */
    return detect_iv_impl(fn, def_block, header, preheader, latch,
                          /*admite_baja=*/false, out);
}

bool detect_counted_iv(const ir::IrFunction &fn,
                       const std::vector<int> &def_block, IrBlockId header,
                       IrBlockId preheader, IrBlockId latch, LoopIV &out) {
    return detect_iv_impl(fn, def_block, header, preheader, latch,
                          /*admite_baja=*/true, out);
}

bool detect_geometric_iv(const ir::IrFunction &fn,
                         const std::vector<int> &def_block, IrBlockId header,
                         IrBlockId preheader, IrBlockId latch, GeoIV &out) {
    if (header == (IrBlockId)IR_NO_BLOCK || header >= fn.blocks.size())
        return false;
    const auto &hins = fn.blocks[header].instrs;
    if (hins.empty()) return false;

    // 1) La guarda, igual que en la aritmetica: el cmp creciente del BR_COND.
    const IrInstr &term = hins.back();
    if (term.op != IrOp::BR_COND || term.operands.empty()) return false;
    const IrValueId cond = term.operands[0];
    IrOp cmp_op = IrOp::NOP;
    IrValueId cmp_a = IR_NO_VALUE, cmp_b = IR_NO_VALUE;
    for (const IrInstr &in : hins) {
        if (in.dst == cond && is_lt_cmp(in.op) && in.operands.size() == 2) {
            cmp_op = in.op;
            cmp_a = skip_copies(fn, def_block, in.operands[0]);
            cmp_b = skip_copies(fn, def_block, in.operands[1]);
            break;
        }
    }
    if (cmp_op == IrOp::NOP) return false;

    /* 2) El PHI cuyo valor de retorno es `phi * K` o `phi << k`.
     *
     * El desplazamiento no es un extra: es en lo que el propio compilador
     * convierte `* 2`.  Sin el, el mismo bucle seria logaritmico antes de
     * optimizar y lineal despues, que es la clase de incoherencia que este
     * analisis existe para no tener. */
    for (const IrInstr &in : hins) {
        if (in.op != IrOp::PHI) continue;
        IrValueId init = IR_NO_VALUE, back = IR_NO_VALUE;
        for (const auto &pa : in.phi_args) {
            if (pa.block == preheader)
                init = pa.value;
            else if (pa.block == latch)
                back = pa.value;
        }
        if (init == IR_NO_VALUE || back == IR_NO_VALUE) continue;
        back = skip_copies(fn, def_block, back);
        const int db = (back < def_block.size() && back != IR_NO_VALUE)
                           ? def_block[back]
                           : -1;
        if (db < 0 || (size_t)db >= fn.blocks.size()) continue;

        int64_t ratio = 0;
        for (const IrInstr &d : fn.blocks[db].instrs) {
            if (d.dst != back || d.operands.size() != 2) continue;
            int64_t k = 0;
            if (d.op == IrOp::MUL) {
                // `phi * K` en cualquier orden.
                if (skip_copies(fn, def_block, d.operands[0]) == in.dst &&
                    const_of(fn, def_block, d.operands[1], k))
                    ratio = k;
                else if (skip_copies(fn, def_block, d.operands[1]) == in.dst &&
                         const_of(fn, def_block, d.operands[0], k))
                    ratio = k;
            } else if (d.op == IrOp::SHL) {
                // `phi << k` solo en ese orden: el desplazado es el primero.
                if (skip_copies(fn, def_block, d.operands[0]) == in.dst &&
                    const_of(fn, def_block, d.operands[1], k) && k > 0 &&
                    k < 62)
                    ratio = (int64_t)1 << k;
            }
            if (ratio != 0) break;
        }
        /* Con factor 1 el valor no avanza y el bucle no termina; con 0 o
         * negativo esto no lo modela.  Ni una cosa ni la otra es "casi
         * geometrico": no se afirma. */
        if (ratio < 2) continue;
        // 3) Y que la guarda compare ESE valor contra algo.
        if (cmp_a != in.dst) continue;
        out.phi = in.dst;
        out.init = init;
        out.ratio = ratio;
        out.cmp_op = cmp_op;
        out.bound = cmp_b;
        return true;
    }
    return false;
}

} // namespace analysis
