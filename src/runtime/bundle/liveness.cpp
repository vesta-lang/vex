/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle/liveness.cpp
 * @brief Vivacidad de registros dentro y detras de un paquete.
 *
 * Ver `include/runtime/bundle/liveness.h` para el porque y las garantias.
 */

#include "runtime/bundle/liveness.h"

#include "runtime/bundle/bundle_touch_all.h"

#if VM_BUNDLES

#include "runtime/decode_instruction.h"

namespace runtime {

namespace {

/// Ningun registro resuelto: todos vivos.  Es la respuesta a "no se".
constexpr uint16_t kAllLive = 0xFFFF;

/**
 * @brief Cuantas instrucciones se miran mas alla del final del paquete.
 *
 * Ocho, y no mas, porque el matador de un temporal -- cuando existe -- esta
 * cerca: es el siguiente uso de ese registro.  Cuesta descodificar ocho
 * instrucciones UNA vez por sitio, en el camino de formacion, que es el 0,57%
 * de las ejecuciones.
 */
constexpr uint32_t kLookahead = 8;

} // namespace

void bundle_live_after(const Bundle &b, const Touch *t, uint16_t live_out,
                       uint16_t *out) {
    uint16_t live = live_out;
    for (uint32_t j = b.k; j-- > 0;) {
        if (t[j].barrier) {
            /* Una barrera lo revive TODO.  Si el paquete puede irse por ahi, lo
             * de detras no corrio y el registro puede leerse en cualquier otro
             * sitio.  Vale igual para lo que transfiere control y para lo que
             * tiene efectos de cota inferior. */
            out[j] = kAllLive;
            live = kAllLive;
            continue;
        }
        out[j] = live;
        const uint16_t kill = (uint16_t)(t[j].reg_write & ~t[j].reg_read);
        live = (uint16_t)((live & ~kill) | t[j].reg_read);
    }
}

bool bundle_split_point(const Bundle &b, const BundleTouch &tc,
                        uint8_t &begin, uint8_t &end, uint64_t *reject) {
    /// Apunta la razon, si alguien la pidio.  `@see ProcessVM::ooo_reject`.
    const auto no = [reject](uint32_t why) {
        if (reject != nullptr) reject[why] += 1;
        return false;
    };
    /* Se busca el corte MAS EQUILIBRADO que deje dos mitades sin nada en comun.
     *
     * Equilibrado y no el primero que valga: lo que se gana al repartir es el
     * tiempo de la mitad mas corta, asi que un corte en la posicion 1 no ahorra
     * nada y cuesta el traspaso igual.
     *
     * Y hace falta que la SEGUNDA mitad sea especialmente inocua -- ni memoria,
     * ni banderas -- porque es la que se va a otro hilo: los registros son
     * ranuras distintas de un array y no chocan si son disjuntos, pero la
     * memoria de la VM es un solo recurso sin desambiguar y las banderas son un
     * byte compartido.
     */
    begin = 0;
    end = 0;
    if (b.k < 4) return no(0); // partir dos en uno y uno no ahorra nada

    /* Lo que toca cada una viene ya calculado: es la misma pasada que usan el
     * reordenador y el fusionador.  Calcularlo aqui otra vez costaba un 19% en
     * el motor de paquetes -- que ni reordena ni fusiona --, y era el mismo
     * dato tres veces. */
    const Touch *const t = tc.t;
    /* Cuales NO se pueden delegar aunque esten antes de la barrera: las que
     * leen `rip`.  El valor de `rip` a mitad de paquete depende de cuantas se
     * hayan ejecutado ya, y eso lo sabe el hilo que las va ejecutando en orden,
     * no el que recibe un bloque suelto.  Se quedan en el hilo principal.
     *
     * Separarlas de las barreras de verdad importa: `push` lee `rip` y es de
     * las mas frecuentes que hay, asi que tratarla como un salto cortaba el
     * paquete casi siempre. */
    uint32_t pinned = 0; // mascara de indices que no se delegan
    uint32_t last = b.k; // primera barrera: lo que va de ahi no se delega
    for (uint32_t i = 0; i < b.k; ++i) {
        const TouchKind kind = tc.kind[i];
        if (kind == TouchKind::ReadsPc) {
            if (i < 32) pinned |= (1u << i);
            continue;
        }
        if (kind == TouchKind::Barrier) {
            /* Una barrera acota, pero NO lo impide todo.
             *
             * Lo que no se puede es DELEGAR algo que este detras de ella: si
             * salta o aborta, lo de detras no debia ejecutarse y en paralelo ya
             * habria corrido.  Lo de DELANTE si.
             *
             * Antes se abandonaba el paquete entero al ver una, y como casi
             * todos terminan en un salto, el resultado era que NINGUNO era
             * partible -- ni uno en todo el corpus --.  O sea que el motor
             * estaba construido y no llegaba a arrancar nunca. */
            last = i;
            break;
        }
    }
    if (last < 4) return no(1); // lo que queda por delante no da para dos mitades

    /* El corte se busca dentro de lo que hay ANTES de la primera barrera: esa
     * es la parte que se puede repartir.  Lo de la barrera en adelante lo
     * ejecuta el hilo principal, en orden, como siempre. */
    /* PRIMERO se descarta con escalares, y solo despues se construye nada.
     *
     * Casi ningun paquete es partible, asi que lo que hay que hacer barato es
     * decir que NO.  Antes se construian dos tablas de prefijo y sufijo -- 528
     * bytes escritos por formacion -- para acabar rechazando todos los cortes,
     * y eso costaba un 21% en el motor de paquetes aunque el analisis viniera
     * ya dado.  Un analisis que busca una oportunidad no puede costar mas que
     * la oportunidad.
     *
     * La clave es que dos de las tres condiciones son de UN SOLO LADO: los
     * campos implicitos y la memoria valen si todos sus tocamientos caen en la
     * misma mitad.  Eso no necesita uniones acumuladas -- basta el PRIMER y el
     * ULTIMO indice que toca cada recurso --, y con `k <= 32` el conjunto de
     * cortes que sobreviven cabe en un `uint32_t`.
     *
     * Y son las que mandan: practicamente cualquier instruccion de ALU escribe
     * banderas, asi que el primer y el ultimo tocamiento estan en los extremos
     * y no queda ni un corte.  Ese caso -- el comun con diferencia -- se
     * resuelve en una pasada y sin escribir un solo array. */
    uint32_t why[6] = {0};

    /// Los cortes 0..31 que siguen vivos.  Se empieza con los equilibrables.
    uint32_t alive = 0;
    for (uint32_t s = 2; s + 2 <= last; ++s) alive |= (1u << s);
    if (alive == 0) return no(1);

    /// Los cortes que dejan a un lado todo lo que toca un recurso.
    /// @param first Primer indice que lo toca.  @param lastx El ultimo.
    const auto one_side = [](uint32_t first, uint32_t lastx) -> uint32_t {
        /* Vale cortar en `s <= first` (todo queda a la DERECHA) o en
         * `s > lastx` (todo queda a la IZQUIERDA).  Nada en medio. */
        const uint32_t left = (first >= 31) ? 0xFFFFFFFFu
                                            : (uint32_t)((1ull << (first + 1)) - 1);
        const uint32_t right = (lastx >= 31) ? 0u : ~(uint32_t)((1ull << (lastx + 1)) - 1);
        return left | right;
    };

    // Primer y ultimo tocamiento de cada campo implicito, y de la memoria.
    uint32_t field_first[8], field_last[8];
    for (uint32_t f = 0; f < 8; ++f) { field_first[f] = UINT32_MAX; field_last[f] = 0; }
    uint32_t mem_first = UINT32_MAX, mem_last = 0;
    for (uint32_t i = 0; i < last; ++i) {
        uint32_t fields = (uint32_t)(t[i].field_read | t[i].field_write);
        while (fields != 0) {
            const uint32_t f = (uint32_t)__builtin_ctz(fields);
            fields &= fields - 1;
            if (field_first[f] == UINT32_MAX) field_first[f] = i;
            field_last[f] = i;
        }
        if (t[i].mem) {
            if (mem_first == UINT32_MAX) mem_first = i;
            mem_last = i;
        }
    }

    /* Los campos implicitos -- banderas, pila, marco -- son un recurso mas, y
     * la regla es la MISMA que para los registros: que no los compartan.
     *
     * Antes se exigia que la mitad delegada no los tocara EN ABSOLUTO, y eso
     * descartaba casi todo.  Con una sola mitad tocandolos el resultado es el
     * de siempre, porque la otra ni los lee ni los escribe y el orden entre
     * mitades deja de importar. */
    for (uint32_t f = 0; f < 8 && alive != 0; ++f) {
        if (field_first[f] == UINT32_MAX) continue;
        const uint32_t before = alive;
        alive &= one_side(field_first[f], field_last[f]);
        if (alive == 0 && before != 0) ++why[2];
    }
    /* La memoria, igual: como no hay desambiguacion, dos accesos cualesquiera
     * pueden ir al mismo sitio.  Con una sola mitad tocandola no hay con quien
     * solaparse. */
    if (alive != 0 && mem_first != UINT32_MAX) {
        alive &= one_side(mem_first, mem_last);
        if (alive == 0) ++why[3];
    }
    /* Y ninguna de las delegadas puede ser de las que leen `rip`: su valor a
     * mitad de paquete depende de cuantas se hayan ejecutado ya, y eso lo sabe
     * el hilo que las lleva en orden, no el que recibe un bloque suelto. */
    if (alive != 0 && pinned != 0) {
        /* Lo que se delega es la mitad DERECHA, `[s, last)`, asi que ninguna
         * atada puede caer ahi: todas tienen que quedar por debajo del corte,
         * o sea `s > ultima_atada`. */
        const uint32_t ultima = 31u - (uint32_t)__builtin_clz(pinned);
        alive &= (ultima >= 31) ? 0u : ~(uint32_t)((1ull << (ultima + 1)) - 1);
        if (alive == 0) ++why[5];
    }
    if (alive == 0) {
        uint32_t worst = 2;
        for (uint32_t i = 3; i < 6; ++i)
            if (why[i] > why[worst]) worst = i;
        return no(worst);
    }

    /* Aqui ya hay candidatos, y AHORA si compensa acumular.  Los registros no
     * son una condicion de un solo lado -- dos distintos pueden estar cada uno
     * en su mitad --, asi que hacen falta las uniones de prefijo y sufijo.
     *
     * El sufijo se guarda; el prefijo se lleva en marcha dentro del bucle de
     * candidatos, que es la mitad de escrituras. */
    struct Half {
        uint16_t read, write;
    };
    Half suf[BUNDLE_MAX + 1];
    suf[last] = Half{0, 0};
    for (uint32_t i = last; i-- > 0;)
        suf[i] = Half{(uint16_t)(suf[i + 1].read | t[i].reg_read),
                      (uint16_t)(suf[i + 1].write | t[i].reg_write)};

    /* Se busca el corte MAS EQUILIBRADO, no el primero que valga: lo que se
     * gana al repartir es el tiempo de la mitad mas corta, asi que un corte en
     * la posicion 1 no ahorra nada y cuesta el traspaso igual. */
    uint8_t best = 0;
    uint32_t best_balance = 0;
    Half pre = Half{0, 0};
    uint32_t done = 0; // hasta donde llega `pre`
    uint32_t rest = alive;
    while (rest != 0) {
        const uint32_t s = (uint32_t)__builtin_ctz(rest);
        rest &= rest - 1;
        for (; done < s; ++done) {
            pre.read = (uint16_t)(pre.read | t[done].reg_read);
            pre.write = (uint16_t)(pre.write | t[done].reg_write);
        }
        const Half &bb = suf[s]; // lo que toca [s..last)

        // Disjuntas de verdad: ni lectura-escritura ni escritura-escritura.
        if ((pre.write & (bb.read | bb.write)) != 0) { ++why[4]; continue; }
        if ((bb.write & (pre.read | pre.write)) != 0) { ++why[4]; continue; }

        const uint32_t shorter = s < (last - s) ? s : (last - s);
        if (shorter > best_balance) {
            best_balance = shorter;
            best = (uint8_t)s;
        }
    }
    if (best == 0) {
        // El que mas cortes tumbo.
        uint32_t worst = 2;
        for (uint32_t i = 3; i < 6; ++i)
            if (why[i] > why[worst]) worst = i;
        return no(worst);
    }
    begin = best;
    end = (uint8_t)last;
    return true;
}

uint16_t live_out_after(ProcessVM *process, uint64_t pc) {
    uint16_t live = 0;   // lo que LEE lo que viene detras
    uint16_t killed = 0; // lo que ya se piso, y por tanto no puede leerse
    for (uint32_t n = 0; n < kLookahead; ++n) {
        DecodedInstr ins;
        if (!decode_peek(process, pc, ins)) return kAllLive;
        if (ins.exec_cached == nullptr && ins.metadata != nullptr)
            ins.exec_cached = ins.metadata->exec;

        Touch t;
        if (!touch_one(ins, t)) return kAllLive; // barrera: se acaba lo que se sabe

        live |= (uint16_t)(t.reg_read & ~killed);
        killed |= (uint16_t)(t.reg_write & ~t.reg_read);
        if (killed == kAllLive) break; // ya no queda nada por resolver
        pc += ins.flags_info.size_instr;
    }
    /* Lo que ni se leyo ni se piso en la ventana sigue sin resolverse, y sin
     * resolver es VIVO. */
    return (uint16_t)(live | ~killed);
}

} // namespace runtime

#endif // VM_BUNDLES
