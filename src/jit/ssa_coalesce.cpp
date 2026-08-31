/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file jit/ssa_coalesce.cpp
 * @brief Implementacion del coalescing de PHI basado en SSA (ver
 *        ssa_coalesce.h).
 *
 * Construye liveness PRECISA sobre el IR (single-def -> sin el problema
 * multi-def del post-out-of-SSA) con el esquema de 2 posiciones por instr
 * (use=2*gi, def=2*gi+1) y coalesce las congruencias de PHI cuyos clusters
 * no interfieren.  Espeja @c build_intervals (MachineIR) adaptado al IR +
 * la semantica de PHI (dst def al entrar el bloque; args usados al final del
 * predecesor).
 */

#include "util/env_flags.h"
#include "jit/ssa_coalesce.h"

#include "jit/interval.h" // LiveInterval (add_range, first_overlap_from)

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <unordered_set>
#include <vector>

namespace jit {

/**
 * @brief Que le hace al destino de un binop la ALU de @p isa.
 *
 * En x86 el destino es tambien operando leido -- `add rax, rbx` deja el
 * resultado EN rax, destruyendolo --, asi que un binop de tres operandos del IR
 * se legaliza a `mov dst, op0; OP dst, op1`.  En arm64, arm32 y RISC-V la ALU
 * es de tres direcciones (`add x0, x1, x2` no toca ni x1 ni x2) y esa
 * legalizacion no existe.
 */
DstKind dst_kind_of_isa(sched::EffIsa isa) noexcept {
    return isa == sched::EffIsa::X86 ? DstKind::Destructive
                                     : DstKind::Preserving;
}

namespace {

/// Los binops ALU del IR que se legalizan a dos direcciones donde toca.
bool is_alu_binop(ir::IrOp op) noexcept {
    switch (op) {
    case ir::IrOp::ADD:
    case ir::IrOp::SUB:
    case ir::IrOp::MUL:
    case ir::IrOp::DIV:
    case ir::IrOp::MOD:
    case ir::IrOp::AND:
    case ir::IrOp::OR:
    case ir::IrOp::XOR:
    case ir::IrOp::SHL:
    case ir::IrOp::SHR:
    case ir::IrOp::SAR: return true;
    default: return false;
    }
}

/// True si @p op es un binop ALU two-address (`dst = op0 OP op1` -> se
/// legaliza a `mov dst, op0; OP dst, op1`) EN @p isa.  Para estos, dst NO
/// puede compartir registro con op1 (operands[1]): el `mov dst, op0`
/// clobberearia op1 antes de leerlo.  Donde la ALU es de tres direcciones no
/// hay tal `mov`, y por tanto tampoco la restriccion.
bool is_two_addr_ir(ir::IrOp op, DstKind dst) noexcept {
    return dst == DstKind::Destructive && is_alu_binop(op);
}

} // namespace

std::vector<uint32_t> ssa_phi_coalesce_remap(const ir::IrFunction &fn,
                                             DstKind dst) {
    const uint32_t NV = static_cast<uint32_t>(fn.values.size());
    const uint32_t NB = static_cast<uint32_t>(fn.blocks.size());
    std::vector<uint32_t> remap; // vacio = nada que coalescer
    if (NV == 0 || NB == 0) return remap;

    /* ---- 1) Posiciones lineales por instruccion (use=2gi, def=2gi+1) ----
     * Cada bloque vacio ocupa 1 slot (como build_intervals) para no colapsar
     * posiciones. */
    std::vector<uint32_t> first_gi(NB, 0), block_start(NB, 0), block_end(NB, 0);
    {
        uint32_t gi = 0;
        for (uint32_t b = 0; b < NB; ++b) {
            first_gi[b] = gi;
            block_start[b] = 2u * gi;
            const size_t n = fn.blocks[b].instrs.size();
            gi += static_cast<uint32_t>(n == 0 ? 1 : n);
            block_end[b] = 2u * gi;
        }
    }

    /* Helper: recorre los USOS (IrValueId) de una instr.  Los args de PHI NO
     * son usos en este bloque (se usan al final del predecesor). */
    auto each_use = [](const ir::IrInstr &in, auto &&fn_use) {
        if (in.op == ir::IrOp::PHI) return; // args gestionados aparte
        for (ir::IrValueId u : in.operands)
            if (u != ir::IR_NO_VALUE) fn_use(u);
        if (in.op == ir::IrOp::CALLIND && in.func_ptr != ir::IR_NO_VALUE)
            fn_use(in.func_ptr);
    };

    /* ---- 2) gen/kill por bloque (bitsets de 64 bits) ----
     *
     * Un BIT por valor, no un byte.  Son CUATRO tablas de NB*NV, y el punto
     * fijo las recorre enteras en cada vuelta: en una funcion grande eso son
     * decenas de megabytes moviendose una y otra vez, y este era el mayor coste
     * propio del compilador (1,692 s de 19,4 s).
     *
     * Con palabras de 64 bits se pide ocho veces menos memoria y, sobre todo,
     * las tres operaciones del bucle interno -- unir con los sucesores,
     * comparar con lo anterior, y gen U (out - kill) -- pasan a resolver 64
     * valores por instruccion en vez de uno, y sin ninguna rama. */
    const size_t W = (size_t(NV) + 63) / 64;
    auto row = [W](std::vector<uint64_t> &t, uint32_t b) {
        return t.data() + size_t(b) * W;
    };
    auto crow = [W](const std::vector<uint64_t> &t, uint32_t b) {
        return t.data() + size_t(b) * W;
    };
    auto get_bit = [](const uint64_t *r, uint32_t v) {
        return (r[v >> 6] >> (v & 63)) & 1ull;
    };
    auto set_bit = [](uint64_t *r, uint32_t v) {
        r[v >> 6] |= 1ull << (v & 63);
    };
    auto clr_bit = [](uint64_t *r, uint32_t v) {
        r[v >> 6] &= ~(1ull << (v & 63));
    };

    std::vector<uint64_t> gen(size_t(NB) * W, 0), kill(size_t(NB) * W, 0);
    for (uint32_t b = 0; b < NB; ++b) {
        uint64_t *g = row(gen, b);
        uint64_t *k = row(kill, b);
        for (const ir::IrInstr &in : fn.blocks[b].instrs) {
            each_use(in, [&](ir::IrValueId u) {
                if (u < NV && !get_bit(k, u)) set_bit(g, u);
            });
            if (in.dst != ir::IR_NO_VALUE && in.dst < NV)
                set_bit(k, in.dst); // incluye phi dst
        }
    }

    /* ---- 3) Liveness dataflow PHI-aware a punto fijo ----
     * live_out[b] = U_succ [ (live_in[succ] - phi_defs[succ]) U
     *                        {args de phis de succ que vienen de b} ]
     * live_in[b]  = gen[b] U (live_out[b] - kill[b]). */
    std::vector<uint64_t> live_in(size_t(NB) * W, 0),
        live_out(size_t(NB) * W, 0);
    bool changed = true;
    /* Fuera de los dos bucles: se reutiliza y se limpia, en vez de pedir y
     * devolver memoria por cada bloque de cada vuelta.  El contenido se
     * construye desde cero igual que antes -- se limpia al entrar --, asi que
     * lo unico que desaparece es el ir y venir al asignador. */
    std::vector<uint64_t> nout(W, 0);
    while (changed) {
        changed = false;
        for (uint32_t bi = NB; bi-- > 0;) {
            const ir::IrBlock &blk = fn.blocks[bi];
            /* new_out */
            std::fill(nout.begin(), nout.end(), 0);
            for (ir::IrBlockId s : blk.succs) {
                if (s >= NB) continue;
                const ir::IrBlock &sb = fn.blocks[s];
                /* live_in[s] menos los phi-defs de s */
                const uint64_t *lis = crow(live_in, s);
                for (size_t w = 0; w < W; ++w)
                    nout[w] |= lis[w];
                for (const ir::IrInstr &in : sb.instrs) {
                    if (in.op != ir::IrOp::PHI) continue;
                    if (in.dst < NV)
                        clr_bit(nout.data(), in.dst); // quitar phi-def
                }
                /* mas los args de phis de s que vienen de bi */
                for (const ir::IrInstr &in : sb.instrs) {
                    if (in.op != ir::IrOp::PHI) continue;
                    for (const ir::IrPhiArg &a : in.phi_args)
                        if (a.block == bi && a.value < NV)
                            set_bit(nout.data(), a.value);
                }
            }
            uint64_t *lo = row(live_out, bi);
            for (size_t w = 0; w < W; ++w) {
                if (nout[w] != lo[w]) {
                    lo[w] = nout[w];
                    changed = true;
                }
            }
            /* new_in = gen U (out - kill) */
            const uint64_t *g = crow(gen, bi);
            const uint64_t *k = crow(kill, bi);
            uint64_t *li = row(live_in, bi);
            for (size_t w = 0; w < W; ++w) {
                const uint64_t ni = g[w] | (lo[w] & ~k[w]);
                if (ni != li[w]) {
                    li[w] = ni;
                    changed = true;
                }
            }
        }
    }

    /* ---- 4) Construccion de rangos precisos por valor ---- */
    std::vector<LiveInterval> iv(NV);
    for (uint32_t v = 0; v < NV; ++v)
        iv[v].vreg = v;
    std::vector<uint32_t> b_first(NV, UINT32_MAX), b_first_def(NV, UINT32_MAX),
        b_last_use(NV, 0);
    std::vector<uint8_t> b_used(NV, 0), b_def(NV, 0);
    std::vector<uint32_t> touched;
    for (uint32_t b = 0; b < NB; ++b) {
        const ir::IrBlock &blk = fn.blocks[b];
        const uint32_t bstart = block_start[b], bend = block_end[b];
        for (uint32_t v : touched) {
            b_first[v] = UINT32_MAX;
            b_first_def[v] = UINT32_MAX;
            b_last_use[v] = 0;
            b_used[v] = 0;
            b_def[v] = 0;
        }
        touched.clear();
        auto mark = [&](uint32_t v) {
            if (b_first[v] == UINT32_MAX && b_first_def[v] == UINT32_MAX &&
                !b_used[v] && !b_def[v])
                touched.push_back(v);
        };
        const uint32_t base = first_gi[b];
        for (size_t j = 0; j < blk.instrs.size(); ++j) {
            const ir::IrInstr &in = blk.instrs[j];
            const uint32_t gi = base + static_cast<uint32_t>(j);
            const uint32_t use_pos = 2u * gi, def_pos = 2u * gi + 1u;
            each_use(in, [&](ir::IrValueId u) {
                if (u >= NV) return;
                mark(u);
                b_used[u] = 1;
                b_last_use[u] = use_pos;
                if (use_pos < b_first[u]) b_first[u] = use_pos;
                iv[u].uses.push_back(use_pos);
            });
            if (in.dst != ir::IR_NO_VALUE && in.dst < NV) {
                mark(in.dst);
                b_def[in.dst] = 1;
                if (def_pos < b_first_def[in.dst])
                    b_first_def[in.dst] = def_pos;
                if (def_pos < b_first[in.dst]) b_first[in.dst] = def_pos;
            }
        }
        /* Rango de cada valor relevante en este bloque. */
        const uint64_t *li_b = crow(live_in, b);
        const uint64_t *lo_b = crow(live_out, b);
        for (uint32_t v = 0; v < NV; ++v) {
            const bool in_ = get_bit(li_b, v) != 0;
            const bool out_ = get_bit(lo_b, v) != 0;
            const bool appears = (b_first[v] != UINT32_MAX);
            if (!in_ && !out_ && !appears) continue;
            const uint32_t start =
                in_ ? bstart : (appears ? b_first[v] : bstart);
            uint32_t end;
            if (out_)
                end = bend;
            else if (b_used[v])
                end = b_last_use[v] + 1u;
            else if (b_def[v])
                end = b_first_def[v] + 1u;
            else
                end = bend;
            iv[v].add_range(start, end);
        }
    }
    // (Eliminado el band-aid `non_phi_used`: rechazaba coalescer args con usos
    // no-phi para no depender de la numeracion lineal imprecisa.  El grafo de
    // interferencia PRECISO `interfere()` (live-at-def, mas abajo) + el gate
    // `sibling_dep` cubren la interferencia real -- incluido el caso original
    // de state_machine -- sin perder el coalescing del acumulador
    // loop-carried.)

    /* ---- 5) Coalescing de congruencias de PHI ---- */
    std::vector<uint32_t> parent(NV);
    for (uint32_t v = 0; v < NV; ++v)
        parent[v] = v;
    std::function<uint32_t(uint32_t)> find = [&](uint32_t x) -> uint32_t {
        while (parent[x] != x) {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        return x;
    };
    std::vector<LiveInterval> merged = iv; // clusters (valido en el rep)
    std::vector<std::vector<uint32_t>> members(NV);
    for (uint32_t v = 0; v < NV; ++v)
        members[v].push_back(v);

    /* Pares PROHIBIDOS 2-address: dst<->operands[1]. */
    /* Marca de phi-dsts: un valor definido por un PHI.  Coalescer un phi_dst
     * con un arg que es a su vez un phi_dst forma CADENAS de phis a traves de
     * bloques merge (dispatch con if/else anidado); la liveness de esas
     * cadenas cross-merge tiene sutilezas que producen miscompilaciones.
     * Conservador: NO coalescer si el arg es un phi_dst.  Se conserva el win
     * comun (loop-carried acc/contador, cuyos args son ADD/const, no phis). */
    std::vector<char> is_phi_dst(NV, 0);
    for (uint32_t b = 0; b < NB; ++b)
        for (const ir::IrInstr &in : fn.blocks[b].instrs)
            if (in.op == ir::IrOp::PHI && in.dst != ir::IR_NO_VALUE &&
                in.dst < NV)
                is_phi_dst[in.dst] = 1;

    std::vector<std::vector<uint32_t>> forbidden(NV);
    for (uint32_t b = 0; b < NB; ++b) {
        for (const ir::IrInstr &in : fn.blocks[b].instrs) {
            if (!is_two_addr_ir(in.op, dst)) continue;
            if (in.dst == ir::IR_NO_VALUE || in.operands.size() < 2) continue;
            const ir::IrValueId d = in.dst, o1 = in.operands[1];
            if (d < NV && o1 < NV && d != o1) {
                forbidden[d].push_back(o1);
                forbidden[o1].push_back(d);
            }
        }
    }
    auto has_forbidden = [&](uint32_t ra, uint32_t rb) -> bool {
        const uint32_t small =
            members[ra].size() <= members[rb].size() ? ra : rb;
        const uint32_t other = (small == ra) ? rb : ra;
        for (uint32_t m : members[small])
            for (uint32_t f : forbidden[m])
                if (find(f) == other) return true;
        return false;
    };
    /* ---- Grafo de interferencia PRECISO (live-at-def, Chaitin/Hack) ----
     * El overlap de rangos LINEALES (first_overlap_from) es impreciso en dos
     * clases: (a) hermanos de un if/else -- el diamante `%d=phi[%s,%o]` con
     * `%s=%o+c`: la numeracion lineal no ve que %o esta vivo tras el def de %s;
     * (b) el back-edge del loop, que no se modela como copia paralela.  El test
     * CORRECTO: `a` interfiere `b` sii `a` esta vivo justo tras un DEF de `b`
     * (o viceversa).  La liveness (arriba) ya es phi-aware, asi que distingue
     * el loop (%i muerto tras `%i+1` -> coalesce OK) del diamante (%o vivo tras
     * `%s=%o+c` -> NO coalesce).  Construccion: walk BACKWARD por bloque desde
     * live_out; en cada def, aristas dst<->{vivos-tras-el-def}.  Los phi dsts
     * (def en la entrada, en paralelo) NO interfieren entre si ni con sus args
     * (each_use excluye los phi args) -> se preservan como candidatos a
     * coalescer.  Gated con VESTA_SSA_COALESCE (el flag maestro). */
    /* Listas contiguas, no conjuntos hash.  Eran NV conjuntos, cada uno con sus
     * propios nodos y sus propias peticiones de memoria, y lo unico que se hace
     * con ellos despues es recorrerlos.  Un vector hace eso mejor y sin pedir
     * un nodo por arista.
     *
     * Y se llevan APARTE los valores vivos en cada punto, en vez de barrer los
     * NV de la funcion en cada definicion buscando cuales lo estan.  Eso era
     * instrucciones por valores; ahora es instrucciones por vivos, que es lo
     * que de verdad hay que mirar.  Las aristas que salen son exactamente las
     * mismas. */
    std::vector<std::vector<uint32_t>> adj(NV);
    {
        std::vector<char> liveset(NV, 0);
        std::vector<uint32_t> vivos;        // los que estan vivos, sin repetir
        std::vector<uint32_t> donde(NV, 0); // posicion de cada uno en `vivos`
        for (uint32_t b = 0; b < NB; ++b) {
            for (uint32_t v : vivos)
                liveset[v] = 0;
            vivos.clear();
            /* Solo los bits ENCENDIDOS: los conjuntos vivos son dispersos, asi
             * que preguntar por los NV valores era recorrer sobre todo ceros.
             * Con `ctz` se salta directamente al siguiente vivo. */
            const uint64_t *lo_b = crow(live_out, b);
            for (size_t w = 0; w < W; ++w) {
                uint64_t bits = lo_b[w];
                while (bits) {
                    const uint32_t v =
                        static_cast<uint32_t>(w * 64) +
                        static_cast<uint32_t>(__builtin_ctzll(bits));
                    bits &= bits - 1;
                    liveset[v] = 1;
                    donde[v] = static_cast<uint32_t>(vivos.size());
                    vivos.push_back(v);
                }
            }
            const auto &ins = fn.blocks[b].instrs;
            for (size_t j = ins.size(); j-- > 0;) {
                const ir::IrInstr &in = ins[j];
                if (in.dst != ir::IR_NO_VALUE && in.dst < NV) {
                    const uint32_t d = in.dst;
                    for (uint32_t a : vivos)
                        if (a != d) {
                            adj[d].push_back(a);
                            adj[a].push_back(d);
                        }
                    if (liveset[d]) { // el def mata d hacia atras
                        liveset[d] = 0;
                        const uint32_t p = donde[d];
                        const uint32_t ult = vivos.back();
                        vivos[p] = ult;
                        donde[ult] = p;
                        vivos.pop_back();
                    }
                }
                each_use(in, [&](ir::IrValueId u) {
                    if (u >= NV || liveset[u]) return;
                    liveset[u] = 1; // uso -> vivo antes del def
                    donde[u] = static_cast<uint32_t>(vivos.size());
                    vivos.push_back(u);
                });
            }
        }
    }
    /* Interferencia de CLUSTERS: dos representantes interfieren sii algun par
     * de miembros (uno de cada) tiene una arista.  Static adj sobre vregs
     * originales; correcto porque si dos originales interfieren, sus clusters
     * no pueden fusionarse.  Itera el cluster menor. */
    auto interfere = [&](uint32_t ra, uint32_t rb) -> bool {
        const uint32_t small =
            members[ra].size() <= members[rb].size() ? ra : rb;
        const uint32_t other = (small == ra) ? rb : ra;
        for (uint32_t ma : members[small]) {
            if (ma >= NV) continue;
            for (uint32_t nb : adj[ma])
                if (find(nb) == other) return true;
        }
        return false;
    };

    /* Posiciones de CALL en el IR (use_pos).  Un valor coalescido que cruza
     * un call debe ir a callee-saved; la interaccion del cluster multi-def
     * con esa logica del allocator produce bugs sutiles -> conservador:
     * NO coalescer valores vivos a traves de un call.  Se pierde el win del
     * acumulador cross-call (raro), se conserva el del loop puro (comun). */
    std::vector<uint32_t> call_pos;
    for (uint32_t b = 0; b < NB; ++b) {
        const uint32_t base = first_gi[b];
        for (size_t j = 0; j < fn.blocks[b].instrs.size(); ++j) {
            const ir::IrInstr &in = fn.blocks[b].instrs[j];
            const ir::IrOp op = in.op;
            bool is_call =
                (op == ir::IrOp::CALL || op == ir::IrOp::CALLN ||
                 op == ir::IrOp::CALLIND || op == ir::IrOp::CALLVIRT ||
                 op == ir::IrOp::CALLITF || op == ir::IrOp::CALLM ||
                 op == ir::IrOp::TAILCALL ||
                 /* ops GC con slow-path call inline (clobbean
                  * caller-saved): deref/alloc/promote/etc. */
                 op == ir::IrOp::GC_DEREF_HOST || op == ir::IrOp::GC_ALLOC ||
                 op == ir::IrOp::GC_ALLOCP || op == ir::IrOp::NEWOBJ ||
                 op == ir::IrOp::GC_HANDLE_FOR_PTR ||
                 op == ir::IrOp::GC_PROMOTE || op == ir::IrOp::GC_DEMOTE);
            /* LOAD/STORE sobre memoria VM (puntero NO host) baja a LOAD_VM/
             * STORE_VM, que hace un CALL a vrt_vm_read/write en el page-miss
             * -> clobbea caller-saved.  Se detecta por is_host_ptr del ptr. */
            if (op == ir::IrOp::LOAD && !in.operands.empty()) {
                const ir::IrValueId p = in.operands[0];
                if (p < NV && !fn.values[p].is_host_ptr) is_call = true;
            }
            if (op == ir::IrOp::STORE && in.operands.size() >= 1) {
                const ir::IrValueId p = in.operands[0];
                if (p < NV && !fn.values[p].is_host_ptr) is_call = true;
            }
            if (is_call)
                call_pos.push_back(2u * (base + static_cast<uint32_t>(j)));
        }
    }
    /* Deteccion DIRECTA y robusta de cross-call por valor: un valor cruza un
     * call si (a) se usa en un bloque en una instr posterior a un call de ese
     * bloque (live a traves del call), o (b) es live-in a un bloque que
     * contiene un call y se usa/pasa mas alla.  Se computa por escaneo simple
     * (over-approxima -> conservador/seguro).  Cubre el patron
     * `acc_next = acc + callresult` de un dispatch polimorfico donde el
     * acumulador live-in cruza el callvirt de la rama. */
    std::vector<char> vcross(NV, 0);
    {
        /* Marcar los valores usados tras un call en su bloque. */
        for (uint32_t b = 0; b < NB; ++b) {
            const std::vector<ir::IrInstr> &ins = fn.blocks[b].instrs;
            bool seen_call = false;
            /* first_call_j = indice de la primera instr-call del bloque. */
            for (size_t j = 0; j < ins.size(); ++j) {
                const ir::IrOp op = ins[j].op;
                bool is_c =
                    (op == ir::IrOp::CALL || op == ir::IrOp::CALLN ||
                     op == ir::IrOp::CALLIND || op == ir::IrOp::CALLVIRT ||
                     op == ir::IrOp::CALLITF || op == ir::IrOp::CALLM ||
                     op == ir::IrOp::TAILCALL ||
                     op == ir::IrOp::GC_DEREF_HOST ||
                     op == ir::IrOp::GC_ALLOC || op == ir::IrOp::GC_ALLOCP ||
                     op == ir::IrOp::NEWOBJ ||
                     op == ir::IrOp::GC_HANDLE_FOR_PTR ||
                     op == ir::IrOp::GC_PROMOTE || op == ir::IrOp::GC_DEMOTE ||
                     /* ALLOCA modifica RSP; LOAD/STORE sobre memoria VM bajan a
                      * LOAD_VM/STORE_VM (CALL a vrt_vm_read/write en page-miss)
                      * -> clobbean caller-saved.  Conservador: cualquier
                      * ALLOCA/LOAD/STORE en el bloque cuenta como clobber
                      * (el is_host_ptr no siempre esta poblado a tiempo). */
                     op == ir::IrOp::ALLOCA || op == ir::IrOp::LOAD ||
                     op == ir::IrOp::STORE);
                if (seen_call) {
                    each_use(ins[j], [&](ir::IrValueId u) {
                        if (u < NV) vcross[u] = 1;
                    });
                }
                if (is_c) seen_call = true;
            }
            /* Si el bloque tiene un call, los valores LIVE-IN cruzan ese call
             * (viven desde antes del bloque, atraviesan el call). */
            if (seen_call) {
                const uint64_t *li_b = crow(live_in, b);
                for (size_t w = 0; w < W; ++w) {
                    uint64_t bits = li_b[w];
                    while (bits) {
                        const uint32_t v =
                            static_cast<uint32_t>(w * 64) +
                            static_cast<uint32_t>(__builtin_ctzll(bits));
                        bits &= bits - 1;
                        vcross[v] = 1;
                    }
                }
            }
        }
    }
    auto crosses_call = [&](uint32_t rep) -> bool {
        for (uint32_t m : members[rep])
            if (m < NV && vcross[m]) return true;
        return false;
    };

    static const bool dbg = util::flag_on(util::FlagId::SsaCoalDbg);

    /* Operandos del def (no-phi) de cada valor -- para la regla del diamante.
     */
    std::vector<std::vector<ir::IrValueId>> def_operands(NV);
    for (uint32_t b = 0; b < NB; ++b)
        for (const ir::IrInstr &in : fn.blocks[b].instrs) {
            if (in.op == ir::IrOp::PHI) continue;
            if (in.dst == ir::IR_NO_VALUE || in.dst >= NV) continue;
            for (ir::IrValueId u : in.operands)
                if (u != ir::IR_NO_VALUE && u < NV)
                    def_operands[in.dst].push_back(u);
        }

    /* Back-edges (DFS): una arista u->v es back-edge si v esta GRIS (en la pila
     * del DFS) al visitar u->v.  v es entonces una cabecera de loop.  Sirve
     * para distinguir, en un phi de cabecera `%d = phi[preheader:%init,
     * back:%carry]`, el arg de ENTRADA (init, arista forward que domina) del
     * loop-carried (arista de retorno).  Coalescer el arg de entrada haria el
     * phi trivial
     * (`%d = phi[%d,%d]`) y perderia/pisaria la inicializacion. */
    std::unordered_set<uint64_t> back_edges;
    std::vector<uint8_t> is_loop_header(NB, 0);
    {
        std::vector<uint8_t> color(NB, 0); // 0=white 1=gray 2=black
        std::vector<uint32_t> stk;
        std::vector<size_t> it(NB, 0);
        for (uint32_t root = 0; root < NB; ++root) {
            if (color[root] != 0) continue;
            stk.push_back(root);
            color[root] = 1;
            while (!stk.empty()) {
                const uint32_t u = stk.back();
                if (it[u] < fn.blocks[u].succs.size()) {
                    const ir::IrBlockId v = fn.blocks[u].succs[it[u]++];
                    if (v >= NB) continue;
                    if (color[v] == 1) { // gris -> back-edge u->v
                        back_edges.insert(((uint64_t)u << 32) | (uint64_t)v);
                        is_loop_header[v] = 1;
                    } else if (color[v] == 0) {
                        color[v] = 1;
                        stk.push_back(v);
                    }
                } else {
                    color[u] = 2;
                    stk.pop_back();
                }
            }
        }
    }

    bool any = false;
    for (uint32_t b = 0; b < NB; ++b) {
        for (const ir::IrInstr &in : fn.blocks[b].instrs) {
            if (in.op != ir::IrOp::PHI || in.dst == ir::IR_NO_VALUE) continue;
            for (const ir::IrPhiArg &a : in.phi_args) {
                const ir::IrValueId d = in.dst, s = a.value;
                /* En una cabecera de loop, solo coalescer el arg de la ARISTA
                 * DE RETORNO (loop-carried).  El arg de entrada (init, arista
                 * forward) NO: coalescerlo hace el phi trivial
                 * (`%d=phi[%d,%d]`) y al consumir el remap se perderia la
                 * inicializacion (el reg del init y del phi serian el mismo y
                 * la copia de entrada seria no-op).  Aplica a AMBOS
                 * consumidores del remap (interp allocate_regs + machine
                 * apply_ssa_coalesce).  Los phis de if/else (bloque no-header)
                 * no se afectan. */
                if (is_loop_header[b] && a.block < NB &&
                    !back_edges.count(((uint64_t)a.block << 32) | (uint64_t)b))
                    continue;
                if (d >= NV || s >= NV || d == s) continue;
                if (iv[d].empty() || iv[s].empty()) continue;
                if (is_phi_dst[s]) continue; // no cadenas de phis (cross-merge)
                /* NO coalescer con un arg CONSTANTE ni con un phi cuyo dst sea
                 * const: una const tiene valor FIJO (rematerializable), no
                 * loop-carried.  Si el phi cae en la clase de la const, el
                 * vreg_select del JIT rematerializa el valor como la constante
                 * K en cada uso (p.ej. `mul rng(=7), LCG` -> `imul r, r, 7`),
                 * perdiendo el valor loop-carried.  Se excluye de la DECISION
                 * de congruencia, comun a los dos consumidores del remap. */
                if ((d < fn.values.size() && fn.values[d].is_const) ||
                    (s < fn.values.size() && fn.values[s].is_const))
                    continue;
                /* CONGRUENCIA (no interferencia): rechazar el arg `s` si su
                 * definicion USA otro ARG `o` del MISMO phi (hermano).  Es el
                 * diamante del acumulador condicional `%d=phi[%s=%o+c, %o]`:
                 * %s y %o NO interfieren (ramas distintas) pero NO son el mismo
                 * valor SSA -- unirlos en la clase de %d hace que el reg que
                 * contiene `%o+c` deje de ser distinguible del que contiene %o
                 * -> semantica rota.  Distincion con el loop `%i_next=%i+1`:
                 * ahi %i_next depende del DST %i (loop-carry legitimo), NO de
                 * un hermano arg -> ese SI coalesce.  Solo miramos dependencia
                 * de HERMANOS (otros args del phi), no del dst. */
                {
                    bool sibling_dep = false;
                    for (ir::IrValueId u : def_operands[s]) {
                        if (u == d)
                            continue; // dependencia del DST = loop-carry OK
                        for (const ir::IrPhiArg &sib : in.phi_args)
                            if (sib.value == u && u != s) {
                                sibling_dep = true;
                                break;
                            }
                        if (sibling_dep) break;
                    }
                    if (sibling_dep) {
                        if (dbg)
                            std::fprintf(
                                stderr,
                                "[ssa-coal] %s phi v%u<-v%u SIBLINGDEP\n",
                                fn.name.c_str(), d, s);
                        continue;
                    }
                }
                // (Antes: gate conservador `non_phi_used[s]` -- rechazaba
                // coalescer cualquier arg con usos NO-phi SIN consultar el
                // grafo de interferencia.  Era un band-aid sobre la imprecision
                // de la numeracion lineal; el grafo PRECISO `interfere()`
                // (live-at-def) de abajo ya detecta la interferencia real, asi
                // que el band-aid sobra y ademas perdia el coalescing del
                // acumulador loop-carried
                // -- `acc` cuyo `acc+1` es un uso no-phi legitimo.  La
                // correccion real es confiar en el grafo preciso + sibling_dep,
                // no rodearlo.)
                const uint32_t rd = find(d), rs = find(s);
                if (rd == rs) continue;
                if (crosses_call(rd) || crosses_call(rs)) {
                    if (dbg)
                        std::fprintf(stderr,
                                     "[ssa-coal] %s phi v%u<-v%u CROSSCALL\n",
                                     fn.name.c_str(), d, s);
                    continue;
                }
                const bool itf = interfere(rd, rs);
                const bool fbd = itf ? false : has_forbidden(rd, rs);
                if (itf || fbd) {
                    if (dbg) {
                        /* Localizar la razon: INTERFERE (overlap de rangos
                         * lineales -- el clasico falso-conflicto del back-edge
                         * de loop no modelado como copia paralela) vs FORBIDDEN
                         * (2-address dst<->operands[1]).  Imprimir los rangos
                         * para ver si el overlap es solo la arista de retorno.
                         */
                        std::fprintf(stderr,
                                     "[ssa-coal] %s phi v%u<-v%u REJECT:%s "
                                     "rd[%u,%u) rs[%u,%u)\n",
                                     fn.name.c_str(), d, s,
                                     itf ? "INTERFERE" : "FORBIDDEN",
                                     merged[rd].start(), merged[rd].end(),
                                     merged[rs].start(), merged[rs].end());
                    }
                    continue;
                }
                if (dbg)
                    std::fprintf(stderr, "[ssa-coal] %s phi v%u<-v%u OK\n",
                                 fn.name.c_str(), d, s);
                for (const LiveRange &r : merged[rs].ranges)
                    merged[rd].add_range(r.from, r.to);
                members[rd].insert(members[rd].end(), members[rs].begin(),
                                   members[rs].end());
                parent[rs] = rd;
                any = true;
            }
        }
    }

    if (!any) return remap; // vacio
    remap.resize(NV);
    for (uint32_t v = 0; v < NV; ++v)
        remap[v] = find(v);
    return remap;
}

bool apply_ssa_coalesce(MFunction &mf, const ir::IrFunction &fn, DstKind dst) {
    /* DEFAULT-ON (kill: VESTA_NO_SSA_COALESCE=1).  Coalesce las congruencias de
     * PHI (reduce el trafico de copias de reg en TODO loop con contador/
     * acumulador + if/else/cadenas) usando un GRAFO DE INTERFERENCIA sound
     * (live-at-def, Chaitin/Hack) construido sobre la liveness phi-aware del
     * pase + una regla de CONGRUENCIA (no absorber un arg cuya def usa OTRO arg
     * del mismo phi -- el diamante `%d=phi[%s=%o+c,%o]`).  Las dos clases de
     * miscompile antiguas (el hang del phi de `rng` y el diamante del
     * acumulador de state_machine) estan cerradas por la interferencia real +
     * la regla de congruencia.  Prerequisitos: las copias de PHI se resuelven
     * como PARALLEL MOVE (regalloc_rewrite) y el gen/kill de build_intervals
     * procesa usos-antes-de-defs (sin esto, `add v,v,1` tras coalescing perdia
     * el uso -> rango fragmentado -> corrupcion).  diff_harness: 388 OK / 0
     * VREG_HANG/DIVERGE/CRASH (solo el asm_stack_manip inherente
     * interp-vs-jit). */
    static const bool off = util::flag_on(util::FlagId::NoSsaCoalesce);
    if (off) return false;
    const std::vector<uint32_t> remap = ssa_phi_coalesce_remap(fn, dst);
    if (remap.empty()) return false;
    const uint32_t NVAL = static_cast<uint32_t>(remap.size());
    bool changed = false;
    auto rw = [&](MOperand &o) {
        if (!o.is_vreg()) return;
        const uint32_t vid = o.vreg_id();
        if (vid < NVAL && remap[vid] != vid) {
            o = MOperand::make_vreg(remap[vid], o.vreg_class(), o.width);
            changed = true;
        }
    };
    for (MBlock &b : mf.blocks) {
        for (MInstr &in : b.instrs) {
            rw(in.dst);
            rw(in.src1);
            rw(in.src2);
        }
    }
    /* Eliminar los phi-copies que quedaron self (`MOV vX, vX`) ANTES de
     * reconstruir intervalos: si se dejan, build_intervals ve un def+use de vX
     * al final del bloque (la copia), lo que puede alterar el rango
     * loop-carried y confundir la deteccion cross-call del allocator.  Borrar
     * la copia muerta deja el rango limpio.  (Los self-moves fisicos residuales
     * los pilla el peephole tras el rewrite.) */
    if (changed) {
        for (MBlock &b : mf.blocks) {
            std::vector<MInstr> kept;
            kept.reserve(b.instrs.size());
            for (const MInstr &in : b.instrs) {
                const bool self_move =
                    (in.op == MOp::MOV || in.op == MOp::MOVSD ||
                     in.op == MOp::MOVSS) &&
                    in.dst.is_vreg() && in.src1.is_vreg() &&
                    in.src2.kind == MOperandKind::NONE &&
                    in.dst.vreg_id() == in.src1.vreg_id();
                if (!self_move) kept.push_back(in);
            }
            if (kept.size() != b.instrs.size()) b.instrs = std::move(kept);
        }
    }
    return changed;
}

} // namespace jit
