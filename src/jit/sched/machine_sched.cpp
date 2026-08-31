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
 * @file jit/sched/machine_sched.cpp
 * @brief List scheduler machine-level (C2.15).  Reordena las MInstr de cada
 *        bloque respetando el DAG de dependencias (efectos COMPLETOS de
 *        @ref machine_effects + desambiguacion de memoria real) y priorizando
 *        por camino critico + latencia (@ref SchedCostModel), para ocultar
 *        latencias y exponer ILP.
 *
 * Memoria: NO se serializa a lo bruto.  Cada acceso se resuelve a una
 * referencia @c MemRef (base + desplazamiento + tamano + objeto de procedencia)
 * y dos accesos solo dependen si de verdad pueden SOLAPARSE:
 *   - objetos de procedencia distintos (ALLOCAs diferentes) -> nunca aliasan.
 *   - misma base con rangos [disp,disp+size) disjuntos -> nunca aliasan.
 *   - solo los punteros genuinamente desconocidos (o accesos de ancho opaco:
 *     rep-movs, atomicos, call) se tratan como que aliasan -> eso es la
 *     semantica correcta sin un points-to global, no un atajo.
 */

#include "util/env_flags.h"
#include "jit/sched/machine_sched.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace jit {
namespace sched {

namespace {

// ---------------------------------------------------------------------------
// Desambiguacion de memoria (alias analysis)
// ---------------------------------------------------------------------------

/// Clave de registro uniforme de un operando REG/VREG (o UINT32_MAX si no).
uint32_t op_reg_key(const MOperand &o) {
    if (o.kind == MOperandKind::REG) return o.reg;
    if (o.kind == MOperandKind::VREG)
        return MEffects::VREG_BASE + static_cast<uint32_t>(o.value);
    return UINT32_MAX;
}

/// Objeto de procedencia de una direccion: 0=desconocido, 1=frame (rbp/rsp),
/// >=2 = objetos ALLOCA distintos (regiones disjuntas del frame).
enum : uint32_t { OBJ_UNKNOWN = 0, OBJ_FRAME = 1, OBJ_FIRST_ALLOCA = 2 };

/// Referencia a memoria de una instruccion.
struct MemRef {
    bool touches = false; ///< la instruccion accede a memoria
    bool reads = false;
    bool writes = false;
    uint32_t base = UINT32_MAX;    ///< registro base (reg/vreg) de la direccion
    uint32_t object = OBJ_UNKNOWN; ///< objeto de procedencia del base
    int64_t disp = 0;              ///< desplazamiento constante
    int32_t size = 8;              ///< bytes accedidos
    bool exact = false; ///< disp/size conocidos y sin index -> rango exacto
};

/// Ancho de acceso de un operando MEM en bytes: 1/2/4/8 (escalar) o 16/32/64
/// (SSE/AVX/AVX512: XMM/YMM/ZMM).  0 = DESCONOCIDO -> el llamador marca el
/// rango como NO exacto (aliasa conservador).  IMPRESCINDIBLE: sub-estimar un
/// acceso vectorial de 32 B como 8 perderia el solapamiento con un acceso a
/// offset 8..31 -> dependencia de memoria perdida -> lectura sin inicializar.
int32_t mem_size_bytes(const MOperand &m) {
    const int32_t s = m.flags; // mem_size override (bytes) si != 0
    return (s == 1 || s == 2 || s == 4 || s == 8 || s == 16 || s == 32 ||
            s == 64)
               ? s
               : 0; // desconocido -> el rango no es exacto
}

/// ¿El operando MEM tiene index? (index != NONE en los bits altos de width).
bool mem_has_index(const MOperand &m) {
    return ((m.width >> 2) & 0x3F) != static_cast<uint8_t>(MReg::NONE);
}

/**
 * @brief Extrae la @c MemRef de @p mi usando el mapa de procedencia @p obj_of.
 *        Cubre las tres formas de acceso del MachineIR:
 *          - operando MEM real (base+index*scale+disp).
 *          - pseudos LOAD/STORE(+_VM): la direccion es un vreg (src1).
 *          - accesos de ancho opaco (rep-movs/atomicos): base desconocida.
 */
MemRef extract_memref(const MInstr &mi, const MEffects &e,
                      const std::unordered_map<uint32_t, uint32_t> &obj_of) {
    MemRef r;
    r.touches = e.reads_mem || e.writes_mem;
    if (!r.touches) return r;
    r.reads = e.reads_mem;
    r.writes = e.writes_mem;

    auto obj = [&](uint32_t base) -> uint32_t {
        auto it = obj_of.find(base);
        return it == obj_of.end() ? OBJ_UNKNOWN : it->second;
    };

    // Pseudos con direccion en src1 (vreg): LOAD/STORE/LOAD_VM/STORE_VM.
    switch (mi.op) {
    case MOp::LOAD:
    case MOp::LOAD_VM:
    case MOp::STORE:
    case MOp::STORE_VM: {
        r.base = op_reg_key(mi.src1);
        r.object = obj(r.base);
        r.disp = 0;
        // LOAD: flags=(width<<1)|signed; STORE: flags=width.
        const int w = (mi.op == MOp::LOAD || mi.op == MOp::LOAD_VM)
                          ? (mi.flags >> 1)
                          : mi.flags;
        const bool w_known = (w == 1 || w == 2 || w == 4 || w == 8 || w == 16 ||
                              w == 32 || w == 64);
        r.size = w_known ? w : 8;
        // Rango exacto solo si la base Y el tamano se conocen; si no, aliasa
        // conservador (no sub-estimar).
        r.exact = (r.base != UINT32_MAX) && w_known;
        return r;
    }
    default: break;
    }

    // Operando MEM real (busca en dst/src1/src2).
    for (const MOperand *m : {&mi.dst, &mi.src1, &mi.src2}) {
        if (m->kind != MOperandKind::MEM) continue;
        r.base = m->reg;
        r.object = obj(r.base);
        r.disp = m->value;
        const int32_t sz = mem_size_bytes(*m);
        r.size = sz > 0 ? sz : 8;
        // Exacto solo sin index Y con tamano conocido; si el ancho es
        // desconocido (p.ej. un vector cuyo mem-size no se anoto), NO exacto ->
        // aliasa conservador (no sub-estimar el rango).
        r.exact = !mem_has_index(*m) && sz > 0;
        return r;
    }

    // Toca memoria pero sin referencia identificable (rep-movs, atomicos con
    // direccion fija en un reg, etc.): base desconocida -> aliasa por seguridad
    // semantica (no hay forma de probar disjuncion).
    return r;
}

/// ¿Pueden SOLAPARSE dos referencias a memoria?
bool may_alias(const MemRef &a, const MemRef &b) {
    // Objetos ALLOCA distintos = regiones disjuntas del frame -> nunca aliasan.
    if (a.object >= OBJ_FIRST_ALLOCA && b.object >= OBJ_FIRST_ALLOCA &&
        a.object != b.object)
        return false;
    // Misma base y ambos rangos exactos -> test de solapamiento [d,d+size).
    if (a.base != UINT32_MAX && a.base == b.base && a.exact && b.exact) {
        const int64_t ae = a.disp + a.size, be = b.disp + b.size;
        return a.disp < be && b.disp < ae; // solapan
    }
    // Sin mas informacion, dos direcciones pueden ser iguales -> aliasan.
    return true;
}

// ---------------------------------------------------------------------------
// DAG de dependencias
// ---------------------------------------------------------------------------

/// ¿Comparten alguna clave de registro dos conjuntos (pequenos)?
bool intersects(const std::vector<uint32_t> &a,
                const std::vector<uint32_t> &b) {
    for (uint32_t x : a)
        for (uint32_t y : b)
            if (x == y) return true;
    return false;
}

/**
 * @brief ¿Hay dependencia de @p a (antes) a @p b (despues)?  Modela TODOS los
 *        hazards: RAW/WAR/WAW en registros, dependencias de FLAGS y memoria con
 *        alias analysis (solo dependen si pueden solaparse).
 */
bool depends(const MEffects &ea, const MEffects &eb, const MemRef &ma,
             const MemRef &mb) {
    if (intersects(ea.writes, eb.reads)) return true;  // RAW
    if (intersects(ea.reads, eb.writes)) return true;  // WAR
    if (intersects(ea.writes, eb.writes)) return true; // WAW
    if (ea.writes_flags && eb.reads_flags) return true;
    if (ea.reads_flags && eb.writes_flags) return true;
    if (ea.writes_flags && eb.writes_flags) return true;
    // Memoria: solo si al menos uno ESCRIBE y las referencias pueden solapar.
    if (ma.touches && mb.touches && (ma.writes || mb.writes) &&
        may_alias(ma, mb))
        return true;
    return false;
}

/**
 * @brief Reordena en sitio las instrucciones [lo,hi) de @p ins (una REGION sin
 *        barreras) por list scheduling.
 * @return numero de instrucciones que cambiaron de posicion.
 */
int schedule_region(std::vector<MInstr> &ins, int lo, int hi,
                    const std::vector<MEffects> &eff,
                    const std::vector<MemRef> &refs, const SchedCostModel &cm) {
    const int n = hi - lo;
    if (n <= 1) return 0;

    // DAG: succ[i] = dependientes de i; indeg[i] = num. de predecesores.
    //
    // Se construye por LAST-WRITER / READERS-SINCE en una sola pasada, no
    // comparando los O(n^2) pares.  La clave: solo hacen falta las dependencias
    // DIRECTAS (predecesor inmediato).  Una arista transitiva a->c (con a->b->c
    // ya presente) es redundante -- c no esta "ready" hasta que toda la cadena
    // a..c este colocada, asi que quitarla no cambia ni las alturas (el camino
    // critico pasa por el mismo b) ni el orden que elige el list scheduling.
    // El resultado es identico al DAG completo, verificable con
    // VESTA_SCHED_VERIFY=1 (compara el ORDEN final contra depends() de TODO
    // par, incluidas las transitivas) -> mismo schedule, de O(n^2) a O(n*k +
    // m^2).
    //
    // Para cada clave de registro se guarda quien la escribio por ultima vez
    // (RAW/WAW dependen de el) y quien la ha leido DESDE esa escritura (WAR).
    // Flags igual, con una sola "clave" implicita.  Memoria: comparacion
    // acotada solo entre las instrucciones que TOCAN memoria (m << n), porque
    // el alias parcial (a y c aliasan, b no) rompe el last-writer unico.
    std::vector<std::vector<int>> succ(n);
    std::vector<int> indeg(n, 0);

    std::unordered_map<uint32_t, int> last_write;           // reg -> ultimo def
    std::unordered_map<uint32_t, std::vector<int>> readers; // reg -> lectores
    int last_flag_write = -1;
    std::vector<int> flag_readers;
    std::vector<int> mem_ops; // indices (locales) que tocan memoria, en orden

    // Dedup de aristas por-destino: pred_epoch[a]==j si a ya es predecesor de
    // j.
    std::vector<int> pred_epoch(n, -1);
    auto add_pred = [&](int a, int j) {
        if (a < 0 || a == j || pred_epoch[a] == j) return;
        pred_epoch[a] = j;
        succ[a].push_back(j);
        ++indeg[j];
    };

    for (int j = 0; j < n; ++j) {
        const MEffects &e = eff[lo + j];
        // --- recoger predecesores DIRECTOS de j ---
        for (uint32_t r : e.reads) { // RAW: leo lo ultimo escrito
            auto it = last_write.find(r);
            if (it != last_write.end()) add_pred(it->second, j);
        }
        for (uint32_t r :
             e.writes) { // WAW con el ultimo def + WAR con lectores
            auto it = last_write.find(r);
            if (it != last_write.end()) add_pred(it->second, j);
            auto rd = readers.find(r);
            if (rd != readers.end())
                for (int reader : rd->second)
                    add_pred(reader, j);
        }
        if (e.reads_flags && last_flag_write >= 0) add_pred(last_flag_write, j);
        if (e.writes_flags) {
            if (last_flag_write >= 0) add_pred(last_flag_write, j);
            for (int reader : flag_readers)
                add_pred(reader, j);
        }
        if (refs[lo + j]
                .touches) { // memoria: comparacion acotada a las mem-ops
            const MemRef &mj = refs[lo + j];
            for (int k : mem_ops) {
                const MemRef &mk = refs[lo + k];
                // SOLO el hazard de memoria (los de reg/flags ya salieron por
                // su via); al menos uno escribe y las referencias pueden
                // solapar.
                if ((mk.writes || mj.writes) && may_alias(mk, mj))
                    add_pred(k, j);
            }
        }

        // --- actualizar el estado con j ---
        for (uint32_t r :
             e.writes) { // una escritura CORTA los lectores previos
            last_write[r] = j;
            readers[r].clear();
        }
        for (uint32_t r : e.reads)
            readers[r].push_back(j);
        if (e.writes_flags) {
            last_flag_write = j;
            flag_readers.clear();
        }
        if (e.reads_flags) flag_readers.push_back(j);
        if (refs[lo + j].touches) mem_ops.push_back(j);
    }

    // Coste COMPLETO por nodo (latencia + throughput reciproco + uops + grupos
    // de puertos) del modelo de coste (generico o de la microarquitectura).
    std::vector<InstrCost> ic(n);
    for (int i = 0; i < n; ++i)
        ic[i] = cm.cost(ins[lo + i]);

    // Altura = camino critico (latencia) hasta el final de la region.
    std::vector<float> height(n, 0.0f);
    for (int i = n - 1; i >= 0; --i) {
        float mx = 0.0f;
        for (int s : succ[i])
            mx = std::max(mx, height[s]);
        height[i] = ic[i].latency + mx;
    }

    // Modelo de RECURSOS del core: ancho de emision (uops/ciclo) + capacidad
    // por grupo de puertos.  El scheduler no programa en el mismo ciclo mas
    // uops de los que el core puede emitir ni mas de los que caben en cada
    // grupo de puertos -> modela la contencion superescalar real (no solo la
    // latencia).
    const int np = cm.port_count();
    const int iw = cm.issue_width() > 0 ? cm.issue_width() : 4;
    std::vector<int> pcap(np > 0 ? np : 1, 1);
    for (int g = 0; g < np; ++g)
        pcap[g] = std::max(1, cm.port_capacity(g));

    // Ocupacion por (ciclo, grupo) + uops emitidas por ciclo (creadas lazy).
    std::vector<std::vector<float>> occ; // occ[ciclo][grupo]
    std::vector<float> issued;           // issued[ciclo] = uops emitidas
    auto ensure = [&](int c) {
        while (static_cast<int>(occ.size()) <= c) {
            occ.emplace_back(np > 0 ? np : 0, 0.0f);
            issued.push_back(0.0f);
        }
    };
    // Ciclos que una op ocupa su(s) puerto(s): el throughput reciproco (una op
    // no-pipelined con recip_tp=12 bloquea su puerto 12 ciclos); pipelined (<1)
    // ocupa 1 ciclo y la capacidad del grupo permite varias por ciclo.
    auto rtp_dur = [&](const InstrCost &c) {
        int d = static_cast<int>(c.recip_tp + 0.5f);
        return d < 1 ? 1 : d;
    };
    auto fits = [&](int node, int c) -> bool {
        const InstrCost &cc = ic[node];
        ensure(c);
        if (issued[c] + cc.uops > static_cast<float>(iw) + 0.001f) return false;
        const int dur = rtp_dur(cc);
        for (int p = 0; p < cc.nports; ++p) {
            const int g = cc.ports[p].port;
            if (g < 0 || g >= np) continue;
            for (int k = 0; k < dur; ++k) {
                ensure(c + k);
                if (occ[c + k][g] + cc.ports[p].uops >
                    static_cast<float>(pcap[g]) + 0.001f)
                    return false;
            }
        }
        return true;
    };
    auto place = [&](int node, int c) {
        const InstrCost &cc = ic[node];
        ensure(c);
        issued[c] += cc.uops;
        const int dur = rtp_dur(cc);
        for (int p = 0; p < cc.nports; ++p) {
            const int g = cc.ports[p].port;
            if (g < 0 || g >= np) continue;
            for (int k = 0; k < dur; ++k) {
                ensure(c + k);
                occ[c + k][g] += cc.ports[p].uops;
            }
        }
    };

    // List scheduling con RECURSOS dirigido por ciclos.  Prioridad: entre las
    // ops LISTAS (indeg==0 -> todas sus dependencias colocadas; el orden
    // SIEMPRE respeta el DAG) prefiere las que quepan en el ciclo actual (issue
    // width + puertos), por camino critico.  GARANTIA DE PROGRESO: si ninguna
    // ready-ya cabe (contencion de recursos), FUERZA la de mayor prioridad --
    // nunca se bloquea ni reordena fuera de las dependencias (correccion >
    // calidad).
    std::vector<int> ready_cycle(n, 0);
    std::vector<char> done(n, 0);
    std::vector<int> order;
    order.reserve(n);
    int cur_cycle = 0;
    int placed = 0;
    // Modo STRESS (VESTA_SCHED_STRESS=1): fuzzer de PREVENCION.  En vez de la
    // prioridad optima, adelanta al maximo las instrucciones MAS TARDIAS
    // (mayor indice original) que estan listas -> produce un orden topologico
    // valido MAXIMAMENTE distinto del original.  Correr la suite e2e con este
    // modo destapa cualquier DEPENDENCIA que FALTE en el modelo de efectos (si
    // el reorden agresivo rompe un test, hay un hazard sin modelar).  Sigue
    // respetando el DAG (solo nodos con indeg==0), asi que un fallo == hueco.
    static const bool stress = util::flag_on(util::FlagId::SchedStress);
    // Compara la prioridad de dos nodos (camino critico, luego ready, luego
    // id).
    auto better = [&](int i, int b) -> bool {
        if (stress) return i > b; // adelanta lo mas tardio (reorden maximo)
        if (height[i] != height[b]) return height[i] > height[b];
        if (ready_cycle[i] != ready_cycle[b])
            return ready_cycle[i] < ready_cycle[b];
        return i < b;
    };
    // Conjunto READY = nodos con indeg==0 aun sin colocar.  Antes cada
    // iteracion reescaneaba las n instrucciones para hallar las listas ->
    // O(n^2) aunque solo una lo estuviera (una cadena de dependencias es el
    // peor caso: 1 sola ready por vuelta, pero se escanean n).  Mantener el
    // ready-set explicito hace que cada vuelta mire solo lo que puede colocar.
    // La SELECCION no cambia: @c better desempata por id (determinista), asi
    // que el nodo elegido es el mismo sea cual sea el orden del set -> schedule
    // identico.
    std::vector<int> ready;
    ready.reserve(n);
    for (int i = 0; i < n; ++i)
        if (indeg[i] == 0) ready.push_back(i);

    while (placed < n) {
        if (ready.empty()) break; // ciclo en el DAG (no deberia): salvaguarda
        int best = -1,
            best_now = -1; // mejor que cabe / mejor ignorando recursos
        int best_pos = -1, best_now_pos = -1;
        for (int p = 0; p < static_cast<int>(ready.size()); ++p) {
            const int i = ready[p];
            if (ready_cycle[i] > cur_cycle) continue; // operandos no listos aun
            if (best_now < 0 || better(i, best_now)) {
                best_now = i;
                best_now_pos = p;
            }
            if (fits(i, cur_cycle) && (best < 0 || better(i, best))) {
                best = i;
                best_pos = p;
            }
        }
        if (best < 0 && best_now < 0) {
            ++cur_cycle; // nada listo este ciclo -> avanzar
            continue;
        }
        const int pick = (best >= 0) ? best : best_now; // fuerza si nada cabe
        const int pick_pos = (best >= 0) ? best_pos : best_now_pos;
        done[pick] = 1;
        ++placed;
        order.push_back(pick);
        place(pick, cur_cycle);
        ready[pick_pos] = ready.back(); // swap-remove: sale del ready-set
        ready.pop_back();
        const int finish =
            cur_cycle + static_cast<int>(ic[pick].latency + 0.5f);
        for (int s : succ[pick]) {
            ready_cycle[s] = std::max(ready_cycle[s], finish);
            if (--indeg[s] == 0) ready.push_back(s); // ya colocadas sus deps
        }
    }
    // Salvaguarda (solo si un ciclo del DAG dejo nodos sin colocar): completar
    // en orden estable.  No deberia ocurrir (el DAG es aciclico).
    if (placed < n)
        for (int i = 0; i < n; ++i)
            if (!done[i]) order.push_back(i);

    // AUTO-VERIFICACION opt-in (VESTA_SCHED_VERIFY=1): el orden nuevo DEBE
    // respetar TODA arista del DAG; si se viola, el BUCLE tiene un bug.  NO
    // detecta EFECTOS que FALTEN (para eso: el modo STRESS + la suite e2e).
    // Env-gated (no #ifndef NDEBUG) para que sirva tambien en builds con
    // NDEBUG.
    static const bool verify = util::flag_on(util::FlagId::SchedVerify);
    if (verify) {
        std::vector<int> vpos(n);
        for (int k = 0; k < n; ++k)
            vpos[order[k]] = k;
        for (int i = 0; i < n; ++i)
            for (int j = i + 1; j < n; ++j)
                if (depends(eff[lo + i], eff[lo + j], refs[lo + i],
                            refs[lo + j]) &&
                    vpos[i] >= vpos[j])
                    std::fprintf(
                        stderr,
                        "[sched-BUG] arista DAG violada: op%d debia ir "
                        "antes de op%d\n",
                        (int)ins[lo + i].op, (int)ins[lo + j].op);
    }

    // Reescribe la region con el nuevo orden; cuenta los que se movieron.
    std::vector<MInstr> tmp;
    tmp.reserve(n);
    int moved = 0;
    for (int k = 0; k < n; ++k) {
        if (order[k] != k) ++moved;
        tmp.push_back(ins[lo + order[k]]);
    }
    for (int k = 0; k < n; ++k)
        ins[lo + k] = std::move(tmp[k]);
    return moved;
}

} // namespace

int schedule_function(MFunction &mf, const SchedCostModel &cm, EffIsa isa) {
    int total_moved = 0;
    /* TELEMETRIA DE FORMA (opt-in, VESTA_SCHED_SHAPE=1): tamano de los bloques.
     *
     * El coste del list scheduling crece con el CUADRADO del tamano del bloque,
     * asi que "el scheduler tarda mucho" tiene DOS causas posibles y muy
     * distintas: (a) el algoritmo no escala, o (b) el backend esta metiendo
     * miles de instrucciones en UN bloque, y el CFG deberia haberlo partido
     * antes. Son problemas de dueno distinto -- uno es del scheduler, el otro
     * del generador de bloques -- y arreglar el equivocado no mueve nada.  @c
     * sum_n2 es el predictor directo del coste: si un solo bloque lo domina, el
     * problema es (b). */
    static const bool shape = util::flag_on(util::FlagId::SchedShape);
    if (shape) {
        size_t nb = 0, maxn = 0, sum = 0;
        unsigned long long sum_n2 = 0;
        for (const MBlock &b : mf.blocks) {
            const size_t k = b.instrs.size();
            ++nb;
            sum += k;
            sum_n2 += 1ull * k * k;
            if (k > maxn) maxn = k;
        }
        std::fprintf(
            stderr,
            "[sched-shape] %-34s bloques=%-5zu instrs=%-7zu mayor=%-7zu"
            " sum(n^2)=%llu  (el mayor aporta %.1f%%)\n",
            mf.name.c_str(), nb, sum, maxn, sum_n2,
            sum_n2 ? 100.0 * (1.0 * maxn * maxn) / sum_n2 : 0.0);
    }
    // Objetos ALLOCA unicos a traves de TODA la funcion (dos allocas siempre
    // distintos, aunque esten en bloques distintos).
    uint32_t next_alloca = OBJ_FIRST_ALLOCA;
    for (MBlock &blk : mf.blocks) {
        std::vector<MInstr> &ins = blk.instrs;
        const int n = static_cast<int>(ins.size());
        if (n <= 1) continue;

        // Efectos + referencia de memoria por instruccion (una sola pasada).
        //
        // PROCEDENCIA POSICIONAL: post-regalloc un registro fisico se REUSA
        // para objetos distintos, asi que el objeto de un @c base es el de su
        // definicion MAS RECIENTE antes de la instruccion -- NO un mapa global
        // (que mal-atribuiria y perderia una dependencia de memoria).  El
        // scheduler solo reordena DENTRO del bloque, asi que basta rastrear
        // por-bloque: reset al entrar (salvo RBP/RSP=FRAME; un base de un
        // bloque previo queda UNKNOWN -> aliasa, conservador), extraer la
        // memref ANTES de actualizar el dst, e INVALIDAR el objeto del dst en
        // cualquier escritura que no PROPAGUE procedencia (solo ALLOCA/MOV/LEA
        // lo hacen).
        std::vector<MEffects> eff(n);
        std::vector<MemRef> refs(n);
        std::unordered_map<uint32_t, uint32_t> obj;
        obj[static_cast<uint32_t>(MReg::RBP)] = OBJ_FRAME;
        obj[static_cast<uint32_t>(MReg::RSP)] = OBJ_FRAME;
        for (int i = 0; i < n; ++i) {
            eff[i] = machine_effects(mf, ins[i], isa);
            refs[i] = extract_memref(ins[i], eff[i], obj);
            const uint32_t d = op_reg_key(ins[i].dst);
            if (d == UINT32_MAX) continue; // dst no es un registro
            switch (ins[i].op) {
            case MOp::ALLOCA:
            case MOp::ALLOCA_VM: obj[d] = next_alloca++; break;
            case MOp::MOV:
            case MOp::LEA: {
                uint32_t src = op_reg_key(ins[i].src1);
                if (src == UINT32_MAX && ins[i].src1.kind == MOperandKind::MEM)
                    src = ins[i].src1.reg;
                auto it = obj.find(src);
                if (it != obj.end())
                    obj[d] = it->second;
                else
                    obj.erase(d); // fuente sin objeto -> dst desconocido
                break;
            }
            default:
                // Cualquier otra escritura invalida el objeto del dst (ya no
                // apunta al mismo) -> UNKNOWN (conservador: aliasa).
                obj.erase(d);
                break;
            }
        }

        // Parte el bloque en REGIONES delimitadas por barreras.
        int lo = 0;
        for (int i = 0; i < n; ++i) {
            if (eff[i].is_barrier) {
                total_moved += schedule_region(ins, lo, i, eff, refs, cm);
                lo = i + 1; // la barrera queda en su sitio
            }
        }
        total_moved += schedule_region(ins, lo, n, eff, refs, cm);
    }
    return total_moved;
}

} // namespace sched
} // namespace jit
