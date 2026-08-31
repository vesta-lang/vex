/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file points_to.cpp
 * @brief Implementacion del resolvedor de direcciones compartido.  Unifica la
 *        resolucion (raiz + offset const) que antes vivia duplicada en el DSE
 *        (addr_of, byte-precisa) y en el modelo de efectos (classify_ptr,
 *        base-only).  Ahora hay UNA sola: precisa (offset const) + sound (nunca
 *        afirma un offset no probado).
 */
#include "analysis/memory/points_to.h"
#include "analysis/memory/memory_access.h" // tamano de un tipo (UNICA verdad)
#include "analysis/facts/loop_facts.h"
#include "analysis/facts/loop_iv.h"
#include "analysis/facts/loop_structure.h"
#include "analysis/facts/loop_trip_count.h"

#include "ir/ssa_ir.h"

#include <algorithm> // orden + busqueda binaria del indice de huecos

namespace analysis {

char PointsToAnalysis::ID = 0;

using effects::AbstractLoc;
using K = effects::AbstractLoc::Kind;

namespace {

// Lee una constante entera de un valor SSA (para acumular offsets const).
bool const_val_of(const ir::IrFunction &fn, ir::IrValueId id, int64_t &out) {
    if (id == ir::IR_NO_VALUE ||
        id >= static_cast<ir::IrValueId>(fn.values.size()))
        return false;
    const ir::IrValue &v = fn.values[id];
    if (!v.is_const) return false;
    out = static_cast<int64_t>(v.const_val);
    return true;
}

/**
 * @brief Evalua un desplazamiento que es constante aunque no sea un literal.
 *
 * Indexar con una constante -- `xs[0]`, `xs[1]` -- no baja a un literal: baja a
 * `base + i*8` con `i` constante.  Mirando solo el literal, el desplazamiento
 * mas comun que existe se daba por VARIABLE, y con el se perdia la posicion
 * exacta del acceso: el comprobador de limites veia "en algun sitio de xs"
 * donde el programa dice "el primero".
 *
 * Se pliega el arbol de la expresion mientras sea aritmetica entre constantes.
 * Profundidad acotada: una cadena mas larga es un patron no previsto, y ahi se
 * para en vez de adivinar.
 */
bool const_expr_of(const ir::IrFunction &fn, const IrFacts &facts,
                   ir::IrValueId id, int64_t &out, int hondura = 0) {
    if (const_val_of(fn, id, out)) return true;
    if (hondura > 4) return false;
    const ir::IrInstr *d = facts.def(id);
    if (d == nullptr || d->operands.size() != 2) return false;
    int64_t a = 0, b = 0;
    if (!const_expr_of(fn, facts, d->operands[0], a, hondura + 1) ||
        !const_expr_of(fn, facts, d->operands[1], b, hondura + 1))
        return false;
    switch (d->op) {
    case ir::IrOp::ADD: return !__builtin_add_overflow(a, b, &out);
    case ir::IrOp::SUB: return !__builtin_sub_overflow(a, b, &out);
    case ir::IrOp::MUL: return !__builtin_mul_overflow(a, b, &out);
    case ir::IrOp::SHL:
        if (b < 0 || b > 62) return false;
        return !__builtin_mul_overflow(a, int64_t(1) << b, &out);
    default: return false;
    }
}

// Estado de la resolucion (memoizacion + guardia de ciclos por PHI).
struct Resolver {
    const ir::IrFunction &fn;
    const IrFacts &facts;
    const RangeFacts *rangos = nullptr;
    std::vector<PointsToEntry> memo;
    std::vector<uint8_t> state; // 0=nuevo, 1=en-curso, 2=hecho

    Resolver(const ir::IrFunction &f, const IrFacts &fc, const RangeFacts *rg)
        : fn(f), facts(fc), rangos(rg) {
        const size_t n = facts.def_of.size();
        memo.assign(n, PointsToEntry{});
        state.assign(n, 0);
    }

    // Raiz concreta: kind + root=self, offset 0, exacto.
    static PointsToEntry root_loc(K kind, ir::IrValueId self) {
        return PointsToEntry{kind, self, 0, true};
    }
    /**
     * @brief No se pudo localizar, Y POR QUE.
     *
     * El motivo NO es documentacion: es lo que decide que puede hacer quien
     * pregunta.  Un puntero cuya raiz depende del camino admite una guarda; una
     * operacion que este resolvedor no modela, no -- ahi lo que hay que ampliar
     * es el resolvedor --; y un valor que viene de fuera lo sabe el llamante.
     * Las trece renuncias de este resolvedor daban el MISMO `Unknown`, asi que
     * los tres casos se trataban igual: no optimizar nunca.
     *
     * Va por el helper y no a mano en cada sitio para que no se pueda escribir
     * una renuncia nueva sin decir de que clase es.
     */
    static PointsToEntry unknown(asa::UnknownReason reason, const char *code) {
        PointsToEntry e{K::Unknown, effects::LOC_GENERIC, 0, false};
        e.reason = reason;
        e.reason_code = code;
        return e;
    }

    // Aplica un offset const a una entrada (respeta off_exact).
    static PointsToEntry with_offset(PointsToEntry base, int64_t delta) {
        if (base.kind == K::Unknown) return base;
        base.off += delta;
        return base; // off_exact heredado (se degrada abajo si el delta no era
                     // const)
    }

    // Degrada una entrada concreta a "raiz conocida, offset inexacto".
    //
    // @p sym, si se da, es el valor que aporta el desplazamiento variable: no
    // se sabe CUANTO, pero si QUIEN, y con su rango se puede acotar despues.
    static PointsToEntry inexact(PointsToEntry base,
                                 ir::IrValueId sym = ir::IR_NO_VALUE) {
        if (base.kind == K::Unknown) return base;
        base.off = 0;
        base.off_exact = false;
        base.off_sym = sym;
        return base;
    }

    /**
     * @brief Como @c inexact, pero ACOTANDO el desplazamiento con su rango.
     *
     * `buf + i` no tiene offset constante; con el rango de `i` si tiene
     * INTERVALO, y un intervalo ya es una respuesta: dice entre que dos
     * posiciones cae el acceso.  Sin rangos se comporta igual que antes.
     *
     * Se suma el offset constante que ya llevara la base (`(buf+8) + i`), que
     * es lo que compone la geometria de una vista.
     */
    /// @param resta @c true si @p sym se RESTA de la base en vez de sumarse.
    ///        Un `p - i` esta a la misma distancia que un `p + i`, del otro
    ///        lado; el intervalo se niega y por eso sus extremos se cruzan.
    PointsToEntry con_rango(PointsToEntry base, ir::IrValueId sym,
                            bool resta = false) {
        const int64_t base_off = base.off;
        PointsToEntry e = inexact(base, sym);
        e.off_base = base_off; // la parte que se sabe, aparte de la que no
        if (!rangos) return e;
        const ValueRange &r = rangos->at(sym);
        if (!r.acotada()) return e; // TOP o BOTTOM: no hay intervalo que sumar
        /* Un desplazamiento se mide con signo.  Si el rango no cabe en esa
         * lectura -- un `u64` por encima del mayor entero con signo -- no se
         * afirma: como offset no significaria lo que parece. */
        int64_t rlo, rhi;
        if (!r.vista_con_signo(rlo, rhi)) return e;
        if (resta) {
            // Negar el intervalo cruza sus extremos, y el minimo con signo no
            // tiene opuesto: ahi no se afirma nada.
            if (rlo == INT64_MIN || rhi == INT64_MIN) return e;
            const int64_t nlo = -rhi, nhi = -rlo;
            rlo = nlo;
            rhi = nhi;
        }
        // Con freno: si la suma se desborda, no se afirma el intervalo.
        int64_t lo, hi;
        if (__builtin_add_overflow(base_off, rlo, &lo) ||
            __builtin_add_overflow(base_off, rhi, &hi))
            return e;
        e.off_lo = lo;
        e.off_hi = hi;
        e.off_rango = true;
        return e;
    }

    /**
     * @brief @c true si @p v es una DIRECCION por su tipo.
     *
     * Hace falta para saber, en una suma o una resta, cual de los dos lados es
     * la direccion y cual el desplazamiento.  Preguntarlo por "tiene raiz" no
     * vale: un parametro entero tambien la tiene -- es memoria alcanzable desde
     * el, por si alguien lo convierte --, y con ese criterio `dst + n` parecia
     * la suma de dos direcciones.
     */
    bool es_direccion(ir::IrValueId v) const {
        return v < fn.values.size() && fn.values[v].type == ir::IrType::PTR;
    }

    /// PHI que se esta resolviendo ahora mismo.  Volver a ella por un arg no es
    /// "no se sabe": es el propio bucle, y ese arg simplemente no aporta.
    ir::IrValueId phi_en_curso = ir::IR_NO_VALUE;

    // --- Hechos de bucle, calculados SOLO si aparece un puntero inducido ---
    bool bucles_listos = false;
    LoopFacts lf;
    /* Donde se define cada valor lo trae `facts`, que ya lo tenemos delante:
     * era el mismo doble bucle que hizo `build_ir_facts`, repetido aqui. */
    const std::vector<int32_t> &def_block = facts.def_block;

    void preparar_bucles() {
        if (bucles_listos) return;
        bucles_listos = true;
        lf = compute_loop_facts(fn);
        shape_.assign(lf.loop_count, LoopShape{});
        shape_ready_.assign(lf.loop_count, 0);
    }

    /**
     * @brief Lo que se sabe de un bucle: su forma, su variable de induccion y
     *        cuantas vueltas da.
     *
     * Las tres cosas se preguntan juntas y valen para todo el bucle, asi que
     * viajan juntas y se calculan UNA vez.
     */
    struct LoopShape {
        LoopStructure st;
        LoopIV iv;
        LoopTripInfo trip;
        /// Sirve para acotar: forma valida, induccion encontrada y vueltas
        /// conocidas.  Si es falso, no hay nada que afirmar.
        bool usable = false;
    };
    std::vector<LoopShape> shape_;
    std::vector<uint8_t> shape_ready_;

    /**
     * @brief La forma del bucle @p lid, calculada la primera vez que se pide.
     *
     * Memorizada por id porque quien pregunta es CADA PUNTERO inducido, y
     * todos los de un mismo bucle comparten forma.  Sin esto, un bucle con N
     * punteros reconstruia N veces lo mismo -- el vector de bloques, el
     * conjunto de membresia y los PHIs del header --, y volvia a buscar N
     * veces la misma induccion y las mismas vueltas.
     */
    const LoopShape &shape_of(uint32_t lid) {
        static const LoopShape none;
        if (lid >= shape_.size()) return none;
        if (shape_ready_[lid]) return shape_[lid];
        shape_ready_[lid] = 1;
        LoopShape &s = shape_[lid];
        s.st = detect_loop_structure(fn, lf, lid);
        if (!s.st.valid) return s;
        if (!detect_loop_iv(fn, def_block, s.st.header, s.st.preheader,
                            s.st.latch, s.iv))
            return s;
        s.trip = compute_trip_count(fn, def_block, s.iv);
        s.usable = s.trip.known() && s.trip.trip > 0;
        return s;
    }

    /**
     * @brief Intervalo de desplazamientos de un puntero INDUCIDO.
     *
     * Un `q` que entra valiendo `base` y en cada vuelta hace `q += d` recorre
     * `base + k*d` con `k` de 0 a vueltas-1.  Se necesitan las tres cosas: de
     * donde parte, cuanto avanza y cuantas veces.  Las dos ultimas ya las saben
     * los hechos de bucle; aqui solo se componen.
     *
     * Ante cualquier duda -- no es un bucle contado, el paso no es constante,
     * el numero de vueltas no se conoce -- no se afirma intervalo alguno.  Que
     * el puntero conserve su raiz ya es una mejora; inventarse el intervalo
     * seria lo contrario.
     */
    bool rango_de_progresion(ir::IrValueId phi, const ir::IrInstr &def,
                             const PointsToEntry &base, int64_t &lo,
                             int64_t &hi) {
        if (def.operands.size() != 2) return false;
        preparar_bucles();
        if (phi >= def_block.size() || def_block[phi] < 0) return false;
        const uint32_t bh = static_cast<uint32_t>(def_block[phi]);
        if (bh >= lf.is_loop_header.size() || !lf.is_loop_header[bh])
            return false;
        const uint32_t lid = lf.loop_id[bh];
        if (lid == LoopFacts::NO_LOOP) return false;
        /* La forma del bucle, ya calculada si otro puntero del mismo bucle
         * pregunto antes.  Trae la estructura, la induccion y las vueltas. */
        const LoopShape &shape = shape_of(lid);
        if (!shape.usable) return false;

        // El paso: el arg que vuelve por el latch es `phi + d` con d constante.
        int64_t paso = 0;
        bool hay_paso = false;
        for (ir::IrValueId a : def.operands) {
            const ir::IrInstr *da = facts.def(a);
            if (!da || da->op != Op_ADD() || da->operands.size() != 2) continue;
            int64_t c;
            if (da->operands[0] == phi &&
                const_val_of(fn, da->operands[1], c)) {
                paso = c;
                hay_paso = true;
                break;
            }
            if (da->operands[1] == phi &&
                const_val_of(fn, da->operands[0], c)) {
                paso = c;
                hay_paso = true;
                break;
            }
        }
        if (!hay_paso || paso == 0) return false;

        // Las vueltas: del IV entero del mismo bucle, ya en la forma.
        const LoopTripInfo &tc = shape.trip;

        const int64_t ini = base.off_exact ? base.off : 0;
        if (!base.off_exact && !base.off_rango) return false;
        const int64_t ini_lo = base.off_exact ? ini : base.off_lo;
        const int64_t ini_hi = base.off_exact ? ini : base.off_hi;
        const int64_t avance = paso * (tc.trip - 1);
        // Freno ante desbordamiento: mejor no afirmar que afirmar de mas.
        if (tc.trip > 1 && paso != 0 && avance / (tc.trip - 1) != paso)
            return false;
        lo = paso > 0 ? ini_lo : ini_lo + avance;
        hi = paso > 0 ? ini_hi + avance : ini_hi;
        return true;
    }

    static ir::IrOp Op_ADD() { return ir::IrOp::ADD; }

    const PointsToEntry &resolve(ir::IrValueId v) {
        if (v == ir::IR_NO_VALUE ||
            v >= static_cast<ir::IrValueId>(memo.size())) {
            /* Un id que no existe: no hay nada que localizar, y eso es
             * conocimiento -- no una renuncia del analisis. */
            static const PointsToEntry kUnk =
                unknown(asa::UnknownReason::NothingToSay, "memory.no_value");
            return kUnk;
        }
        if (state[v] == 2) return memo[v];
        if (state[v] == 1) {
            /* Ciclo.  Si es la PHI que estamos resolviendo, se devuelve un
             * "no aporta" (None) SIN memoizar: memoizarlo la dejaria marcada
             * como desconocida para siempre, que es lo que hacia que un puntero
             * inducido -- `q = p; q += 1` en cada vuelta, en lo que el
             * optimizador convierte `p + i` -- perdiera su raiz y con ella toda
             * posibilidad de comprobar el acceso.  Un bucle indexado es justo
             * donde se desborda un buffer. */
            if (v == phi_en_curso) {
                static const PointsToEntry kNoAporta{
                    K::None, effects::LOC_GENERIC, 0, false};
                return kNoAporta;
            }
            /* Un ciclo que no es el PHI en curso: la raiz se define a si misma
             * y este resolvedor no resuelve recurrencias.  Es FORMA, no
             * ejecucion: el puntero puede estar perfectamente acotado. */
            memo[v] = unknown(asa::UnknownReason::ShapeNotRecognized,
                              "memory.unresolved_cycle");
            state[v] = 2;
            return memo[v];
        }
        state[v] = 1;
        memo[v] = compute(v);
        state[v] = 2;
        return memo[v];
    }

    PointsToEntry compute(ir::IrValueId v) {
        // Parametro: memoria alcanzable desde el arg (points-to grueso).
        const int32_t pidx = facts.param_index(v);
        if (pidx >= 0)
            return PointsToEntry{K::ArgDerived, static_cast<uint32_t>(pidx), 0,
                                 true};

        const ir::IrInstr *d = facts.def(v);
        /* Sin definicion dentro de la funcion: viene de fuera.  Quien lo pase
         * es quien sabe a que apunta, y por eso es frontera y no ignorancia. */
        if (!d)
            return unknown(asa::UnknownReason::OpaqueBoundary,
                           "memory.comes_from_outside");

        using Op = ir::IrOp;
        switch (d->op) {
        // --- Raices ---
        case Op::ALLOCA: return root_loc(K::Stack, v);
        case Op::RAW_ALLOC:
        case Op::GC_ALLOC:
        case Op::GC_ALLOCP:
        case Op::NEWOBJ:
        case Op::NEWOBJS:
        case Op::ARRAY_ALLOC:
        case Op::STRMAKE:
        case Op::STRRESERVE: return root_loc(K::Heap, v);
        case Op::GETSTATIC:
        case Op::STR_LIT_ADDR:
        case Op::LABEL_ADDR:
        case Op::SECTION_REF: return root_loc(K::Global, v);

        // --- Derivaciones que preservan raiz Y offset (misma direccion) ---
        case Op::MOV:
        case Op::BITCAST:
        case Op::CAST:
        case Op::GCDEREF_IR:
        case Op::GC_DEREF_HOST:
        case Op::GC_HANDLE_FOR_PTR:
        case Op::UNWRAP:
        case Op::MVTAKE_IR:
            if (!d->operands.empty()) return resolve(d->operands[0]);
            /* Una derivacion sin origen: el IR no tiene esa forma.  Si llega
             * aqui es un fallo NUESTRO al construirlo, no del programa. */
            return unknown(asa::UnknownReason::ShapeNotRecognized,
                           "memory.derivation_without_source");

        // --- ADD con offset const: acumula ---
        case Op::ADD: {
            if (d->operands.size() != 2)
                return unknown(asa::UnknownReason::ShapeNotRecognized,
                               "memory.malformed_addition");
            int64_t c;
            // base + const
            {
                PointsToEntry b = resolve(d->operands[0]);
                if (b.kind != K::Unknown && b.off_exact &&
                    const_expr_of(fn, facts, d->operands[1], c))
                    return with_offset(b, c);
            }
            // const + base
            {
                PointsToEntry b = resolve(d->operands[1]);
                if (b.kind != K::Unknown && b.off_exact &&
                    const_expr_of(fn, facts, d->operands[0], c))
                    return with_offset(b, c);
            }
            /* Desplazamiento NO constante (`buf + i*8`: indexar con una
             * variable).  Se conserva la RAIZ y se marca el offset como no
             * probado -- exactamente lo que hace @c GEP justo debajo.
             *
             * Antes se devolvia "desconocido", que tira la raiz, y con ella
             * toda posibilidad de distinguir dos objetos DISTINTOS.  Como
             * recorrer un buffer con un indice es el caso normal de cualquier
             * bucle, eso dejaba ciega la desambiguacion justo donde mas falta
             * hace: una escritura en un array volvia opaco el bucle entero.
             *
             * Solo cuando UNO de los dos lados tiene raiz conocida: si la
             * tienen los dos (sumar dos punteros) no hay forma de decir cual
             * manda, y si no la tiene ninguno no hay nada que conservar. */
            {
                /* Quien es la DIRECCION y quien el desplazamiento lo dice el
                 * TIPO, no el hecho de tener raiz.  Un parametro entero es
                 * "memoria alcanzable desde el parametro" igual que uno
                 * puntero -- por si alguien lo convierte --, asi que mirar solo
                 * eso hacia que `dst + n` pareciera la suma de DOS direcciones
                 * y se resolviera como desconocida.  Y `p + n` es el caso
                 * normal de recorrer un buffer. */
                const bool a_ptr = es_direccion(d->operands[0]);
                const bool b_ptr = es_direccion(d->operands[1]);
                const PointsToEntry a = resolve(d->operands[0]);
                const PointsToEntry b = resolve(d->operands[1]);
                const bool a_raiz = a.kind != K::Unknown && a.kind != K::None;
                const bool b_raiz = b.kind != K::Unknown && b.kind != K::None;
                if (a_raiz && (a_ptr ? !b_ptr : !b_raiz))
                    return con_rango(a, d->operands[1]);
                if (b_raiz && (b_ptr ? !a_ptr : !a_raiz))
                    return con_rango(b, d->operands[0]);
            }
            /* Se suman dos cosas y ninguna es una raiz reconocible, o las dos
             * lo son.  El valor que resulte depende de lo que traigan en
             * ejecucion, y por eso no es una forma que se pueda ampliar. */
            return unknown(asa::UnknownReason::RuntimeDependent,
                           "memory.addition_without_single_root");
        }

        /* --- RESTA: la misma derivacion, hacia el otro lado ---
         *
         * `p - k` sigue apuntando al objeto de `p`, igual que `p + k`.  Sin
         * esto la resta tiraba la raiz entera, y con ella lo que se supiera de
         * lo demas -- porque lo desconocido ABSORBE el conjunto de efectos.
         *
         * No es un caso raro: `dst + n - ancho` es como TODA la libreria de
         * memoria calcula el segundo tramo de una copia solapada, asi que
         * `memcpy`, `memset` y sus variantes en asm salian como "tocan
         * cualquier cosa" por una resta.
         *
         * Solo cuenta cuando la raiz esta a la IZQUIERDA: `p - q` (restar dos
         * punteros) es una distancia, no una direccion, y `k - p` no es una
         * derivacion de `p`. */
        case Op::SUB: {
            if (d->operands.size() != 2)
                return unknown(asa::UnknownReason::ShapeNotRecognized,
                               "memory.malformed_subtraction");
            int64_t c;
            const PointsToEntry b = resolve(d->operands[0]);
            if (b.kind == K::Unknown || b.kind == K::None)
                /* La izquierda no se supo, asi que esto tampoco.  Se apoya en
                 * otro que falta: arreglar aquel y este cae solo. */
                return unknown(asa::UnknownReason::MissingDependency,
                               "memory.subtraction_base_unresolved");
            // base - const: se acumula el desplazamiento con el signo cambiado.
            if (b.off_exact && const_expr_of(fn, facts, d->operands[1], c)) {
                int64_t neg;
                if (!__builtin_sub_overflow(int64_t(0), c, &neg))
                    return with_offset(b, neg);
                /* El desplazamiento se sale de un entero de 64 bits.  Es un
                 * limite de la representacion, no del programa. */
                return unknown(asa::UnknownReason::BudgetExceeded,
                               "memory.offset_overflows");
            }
            // base - valor: se conserva la raiz y se acota con SU rango.  Lo
            // que descarta es restar otra DIRECCION (eso da una distancia, no
            // una direccion), y eso lo dice el tipo.
            if (es_direccion(d->operands[1]))
                /* Restar dos direcciones da una DISTANCIA, no una direccion.
                 * No es que no se sepa: es que el resultado no es un puntero, y
                 * eso es conocimiento, no ignorancia. */
                return unknown(asa::UnknownReason::NothingToSay,
                               "memory.address_difference_is_a_distance");
            return con_rango(b, d->operands[1], /*resta=*/true);
        }

        // --- GEP: misma raiz, offset NO probado (escala desconocida aqui) ---
        case Op::GEP:
            if (!d->operands.empty()) return inexact(resolve(d->operands[0]));
            return unknown(asa::UnknownReason::ShapeNotRecognized,
                           "memory.index_without_base");

        /* PHI: si todos los caminos que APORTAN traen la misma raiz, la raiz se
         * conserva.  El desplazamiento no -- por eso queda inexacto --, pero la
         * raiz es lo que permite saber DE QUE objeto se habla, y sin ella no
         * hay nada que comprobar.
         *
         * Es el caso de un puntero inducido: `q = buf` al entrar y `q = q + 1`
         * al volver.  El segundo camino vuelve a la propia PHI y no aporta; el
         * primero dice `buf`.  Antes se devolvia "desconocido" y un bucle que
         * recorre un buffer quedaba fuera de todo analisis.
         *
         * Si dos caminos traen raices DISTINTAS no se afirma nada: no hay forma
         * de decir cual manda. */
        case Op::PHI: {
            if (d->operands.empty())
                return unknown(asa::UnknownReason::ShapeNotRecognized,
                               "memory.phi_without_paths");
            const ir::IrValueId marca_previa = phi_en_curso;
            phi_en_curso = v;
            PointsToEntry acc;
            bool primero = true, discrepan = false;
            for (ir::IrValueId a : d->operands) {
                const PointsToEntry e = resolve(a);
                if (e.kind == K::None) continue; // el propio bucle
                if (e.kind == K::Unknown) {
                    discrepan = true;
                    break;
                }
                if (primero) {
                    acc = e;
                    primero = false;
                    continue;
                }
                if (e.kind != acc.kind || e.root != acc.root) {
                    discrepan = true;
                    break;
                }
            }
            phi_en_curso = marca_previa;
            if (discrepan || primero)
                /* Dos caminos con raices DISTINTAS, o ninguno que aporte.  Cual
                 * manda depende del camino que se tome en ejecucion -- y eso es
                 * justo lo que se puede especular con una guarda, en vez de
                 * rendirse como si no se supiera nada. */
                return unknown(asa::UnknownReason::RuntimeDependent,
                               discrepan ? "memory.root_varies_by_path"
                                         : "memory.no_path_contributes");
            /* Puntero INDUCIDO: su desplazamiento no es un valor que acotar,
             * es una PROGRESION -- `q = buf` al entrar y `q = q + d` al volver,
             * en lo que el optimizador convierte `p + i`.  Se acota con las
             * VUELTAS, que es un hecho que ya existe.  Sin esto, el bucle que
             * recorre un buffer -- donde de verdad se desborda -- queda fuera
             * de toda comprobacion. */
            int64_t lo, hi;
            if (rango_de_progresion(v, *d, acc, lo, hi)) {
                PointsToEntry e = inexact(acc);
                e.off_lo = lo;
                e.off_hi = hi;
                e.off_rango = true;
                return e;
            }
            return inexact(acc);
        }

        default:
            /* Cargado de memoria, direccion constante, calculo arbitrario...
             * Una operacion que este resolvedor no modela: el programa esta
             * bien y lo que hay que ampliar es esto.  Es el caso mas frecuente
             * de todos, y por eso importa que no se confunda con los demas. */
            return unknown(asa::UnknownReason::ShapeNotRecognized,
                           "memory.unmodelled_op");
        }
    }
};

} // namespace

/**
 * @brief Extension de la region que crea una instruccion de asignacion.
 *
 * El tamano esta escrito en el sitio de asignacion; aqui solo se lee y se dice
 * con que grado de certeza se sabe.  `alloca.T count` da count * sizeof(T);
 * `raw_alloc %size` da el operando, constante si lo es y simbolico si no --
 * simbolico NO es desconocido: se sabe QUE valor manda, que es lo que permitira
 * acotarlo con un rango.
 */
static RegionExtent extension_de(const ir::IrInstr &d, const IrFacts &facts) {
    RegionExtent ex;
    using Op = ir::IrOp;
    // Redondeo al hueco: un objeto ocupa su slot, no su tamano.  La pila
    // alinea a 8; el allocador del monton, a 16.  Es el limite que se puede
    // AFIRMAR -- por debajo de el, ensanchar un acceso es legitimo.
    auto redondear = [](int64_t n, int64_t a) {
        return n <= 0 ? n : ((n + a - 1) / a) * a;
    };
    if (d.op == Op::ALLOCA) {
        const int32_t elem = analysis::memory_access_size(d.type);
        const int64_t n = static_cast<int64_t>(d.imm);
        if (elem > 0 && n >= 0) {
            ex.bytes = n * elem;
            ex.reservado = redondear(ex.bytes, 8);
        }
        return ex;
    }
    if (d.op == Op::RAW_ALLOC || d.op == Op::GC_ALLOC ||
        d.op == Op::GC_ALLOCP) {
        if (d.operands.empty()) return ex;
        const ir::IrValueId vs = d.operands[0];
        const ir::IrInstr *ds = facts.def(vs);
        if (ds && ds->op == Op::CONST) {
            ex.bytes = static_cast<int64_t>(ds->imm);
            ex.reservado = redondear(ex.bytes, 16);
        } else {
            ex.sym = vs;
        }
    }
    return ex;
}

PointsTo compute_points_to(const ir::IrFunction &fn, const IrFacts &facts,
                           const RangeFacts *rangos) {
    Resolver r(fn, facts, rangos);
    PointsTo out;
    const size_t n = facts.def_of.size();
    out.loc.assign(n, PointsToEntry{});
    out.extent.assign(n, RegionExtent{});
    for (ir::IrValueId v = 0; v < static_cast<ir::IrValueId>(n); ++v) {
        out.loc[v] = r.resolve(v);
        // La extension se guarda en la RAIZ, que es de quien es propiedad.
        if (const ir::IrInstr *d = facts.def(v))
            out.extent[v] = extension_de(*d, facts);
    }
    return out;
}

AbstractLoc loc_of(const PointsTo &pt, ir::IrValueId ptr, int32_t width) {
    const PointsToEntry &e = pt.at(ptr);
    if (e.kind == K::Unknown)
        return AbstractLoc{K::Unknown, effects::LOC_GENERIC, 0, 0};
    if (!e.off_exact) {
        // Raiz conocida pero offset no probado -> objeto entero (width 0):
        // puede solapar cualquier acceso a la misma raiz, disjunto de otras
        // raices.
        return AbstractLoc{e.kind, e.root, 0, 0};
    }
    return AbstractLoc{e.kind, e.root, e.off, width};
}

std::vector<ir::IrValueId>
single_values_of_slots(const ir::IrFunction &fn,
                       const std::vector<ir::IrValueId> &slots) {
    std::vector<ir::IrValueId> out(slots.size(), ir::IR_NO_VALUE);
    if (slots.empty()) return out;

    /* Indice hueco -> posiciones que lo piden.  Ordenado y contiguo: son unos
     * pocos y se consulta en el bucle de instrucciones, que es el caro.  Un
     * mismo hueco puede pedirse varias veces (dos operandos ligados al mismo
     * slot), asi que se guardan TODAS sus posiciones. */
    std::vector<std::pair<ir::IrValueId, size_t>> indice;
    indice.reserve(slots.size());
    for (size_t i = 0; i < slots.size(); ++i)
        if (slots[i] != ir::IR_NO_VALUE) indice.emplace_back(slots[i], i);
    if (indice.empty()) return out;
    std::sort(indice.begin(), indice.end());

    std::vector<uint32_t> escrituras(slots.size(), 0);
    for (const ir::IrBlock &bb : fn.blocks) {
        for (const ir::IrInstr &in : bb.instrs) {
            if (in.op != ir::IrOp::STORE || in.operands.size() < 2) continue;
            const ir::IrValueId slot = in.operands[1];
            auto it = std::lower_bound(indice.begin(), indice.end(),
                                       std::make_pair(slot, (size_t)0));
            for (; it != indice.end() && it->first == slot; ++it) {
                const size_t k = it->second;
                // Una segunda escritura: el contenido ya depende del camino.
                out[k] =
                    (++escrituras[k] == 1) ? in.operands[0] : ir::IR_NO_VALUE;
            }
        }
    }
    return out;
}

ir::IrValueId single_value_of_slot(const ir::IrFunction &fn,
                                   ir::IrValueId slot) {
    if (slot == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    return single_values_of_slots(fn, {slot})[0];
}

} // namespace analysis
