/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle_reorder.cpp
 * @brief Reordena las instrucciones DENTRO de un paquete, al formarlo.
 *
 * QUE ES
 * ------
 * Un planificador de lista sobre el grafo de dependencias del paquete.  No es
 * "juntar pares para fusionar": eso es UNO de los criterios, y ni siquiera el
 * unico que interesa.  El orden que sale de aqui alimenta a la vez a:
 *
 *   - la FUSION: un productor pegado a su consumidor deja el par adyacente, y
 *     solo un par adyacente se puede convertir en UNA instruccion.  Es lo unico
 *     que baja el RECUENTO, que hoy es el cuello del interprete;
 *   - la EJECUCION REAL FUERA DE ORDEN: agrupar instrucciones independientes
 *     entre si es lo que permite lanzarlas en paralelo.  Aqui todavia se
 *     ejecutan en serie, pero el orden ya se prepara para cuando no;
 *   - la LOCALIDAD: juntar las que tocan los mismos registros y las que tocan
 *     memoria deja los accesos agrupados en vez de repartidos.
 *
 * Corre UNA vez por sitio, al formar.  Lo que decida se cobra en cada una de
 * las miles de entradas siguientes, asi que aqui se puede pensar; en el bucle
 * de ejecucion no.
 *
 * COMO SE EXTIENDE
 * ----------------
 * Los tres objetivos de arriba no estan cosidos al algoritmo: son entradas de
 * @ref kCriteria, una tabla plana de (nombre, peso, funcion).  Anadir una
 * capacidad nueva -- vectorizar, evitar un puerto del anfitrion, lo que venga
 * -- es anadir una fila, no tocar el planificador.  El bucle no sabe cuantos
 * criterios hay ni que miden.
 *
 * Los pesos deciden que gana cuando dos criterios piden cosas distintas, y
 * estan juntos y a la vista por eso mismo: repartidos por el codigo, ajustar el
 * comportamiento seria ir a buscarlos de uno en uno.
 *
 * DE DONDE SALE LO QUE PUEDE MOVERSE
 * ----------------------------------
 * De dos sitios, y hacen falta los dos:
 *
 *   - los EFECTOS IMPLICITOS -- banderas, pila, marco, contador de programa, si
 *     toca memoria, si transfiere control, si puede abortar -- salen de
 *     `instr_db_vm`, que se DERIVA del codigo maquina de los manejadores;
 *   - los REGISTROS que nombra salen del DESENSAMBLADOR, porque su indice es
 *     variable (`regs[instr.reg1]`) y solo el formato lo sabe.
 *
 * El reparto lo explica la cabecera de `instr_db_vm.h`.  La forma que la base
 * SI trae (`kFormPrimary`) es COTA INFERIOR: si el recorrido no vio un acceso,
 * sale cero, y cero no distingue "no toca registros" de "no se supo".  Una
 * ESCRITURA que falta permite un reorden que rompe el programa, asi que para
 * DECIDIR no vale; sirve para informar.
 *
 * ES CONSERVADOR, Y A PROPOSITO
 * -----------------------------
 *   - Un opcode que no sea movible es BARRERA: no se mueve nada a su alrededor.
 *     Lo decide `vm_instr_movable`, que exige efectos EXACTOS y descarta las
 *     cuatro barreras (control, aborto, destino solo conocido al ejecutar, y
 *     salida a codigo ajeno).
 *   - El DESTINO cuenta tambien como LECTURA.  Distinguir `mov` de `add`
 *     pediria saber si el opcode lee su destino; no saberlo cuesta un reorden
 *     perdido, suponerlo puede costar un resultado.
 *   - Toda la memoria de la VM es UN recurso: sin desambiguacion, dos accesos
 *     cualesquiera se ordenan entre si.
 *   - Si el desensamblador no entiende una instruccion, barrera.
 *
 * POR QUE ES SEGURO REORDENAR AQUI
 * --------------------------------
 * `exec_bundle` para en seco cuando una instruccion salta o se bloquea, y
 * entonces lo que va detras NO se ejecuta.  Adelantar algo por encima de una
 * instruccion que puede parar lo haria correr en un programa que no debia
 * llegar ahi.  Por eso las cuatro barreras no son prudencia: son la condicion
 * que hace que reordenar no se note desde fuera.
 *
 * El `pc` viaja DENTRO de cada instruccion desde que se forma, asi que moverlas
 * no descoloca ninguna direccion: la traza de un fallo sigue senalando la que
 * de verdad se estaba ejecutando.
 */

#include "runtime/bundle.h"

#include <cstdio>
#include <cstring>

#include "disasm/disasm.h"
#include "runtime/instr_db_vm.h"
#include "util/env_flags.h"

#if VM_BUNDLES

namespace runtime {

namespace {

/// Los cuatro campos implicitos, en el orden del derivador.
enum : uint8_t {
    kFlags = 1u << 0,
    kStack = 1u << 1,
    kFrame = 1u << 2,
    kPc = 1u << 3,
};

/// Lo que una instruccion del paquete toca.  Se calcula una vez al formar.
struct Touch {
    uint16_t reg_read = 0;  ///< bit i = lee el registro general i
    uint16_t reg_write = 0; ///< bit i = escribe el registro general i
    uint16_t vec_read = 0;  ///< lo mismo sobre el banco vectorial
    uint16_t vec_write = 0;
    uint8_t field_read = 0;  ///< banderas/pila/marco/pc que lee
    uint8_t field_write = 0; ///< ...y que escribe
    bool mem = false;        ///< toca la memoria de la VM
    bool barrier = true;     ///< ni se mueve ni deja mover
};

/// Los EFECTOS IMPLICITOS de @p d, que salen de la base y no cuestan nada.
[[gnu::always_inline]] inline bool effects_of(const DecodedInstr &d, Touch &t) {
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const uint8_t opcode =
        ext ? (uint8_t)d.flags_info.opcode_index : d.flags_info.is_not_extended;

    /* Se lee de la tabla CALIENTE -- 2 bytes por opcode, 1 KB entre las dos --
     * y no de `VmInstr`, que son 272 bytes por fila: una linea de cache larga
     * por instruccion para usar dos bytes de ella. */
    const uint16_t eff = vm_isa::vm_hot(ext, opcode);
    if (!vm_isa::vm_instr_movable(eff)) return false; // barrera, y ya esta

    /* QUINTA barrera, y esta no sale de la base: la que LEE el contador de
     * programa.
     *
     * `exec_bundle` avanza `rip` despues de CADA instruccion, sumandole su
     * tamano.  O sea que el valor de `rip` a mitad de paquete es funcion del
     * ORDEN en que se ejecutaron las de antes -- es una escritura implicita que
     * hace el bucle, no la instruccion, y por eso ninguna la declara --.  Al
     * final da igual, porque una suma no depende del orden; en medio no.
     *
     * Asi que quien lea `rip` veria otro valor al cambiarla de sitio.  `push`
     * es una de esas, y es de las mas frecuentes que hay.  Se descubrio porque
     * el reorden pasaba los siete programas sinteticos y fallaba tres de los
     * SIETE REALES: los sinteticos no llevan `push`. */
    if ((eff & vm_isa::VE_R_PC) != 0) return false;
    // Deja de serlo POR SUS EFECTOS.  Todavia puede volver a marcarse si el
    // desensamblador no la entiende, que es lo que decide `touch_all`.
    t.barrier = false;

    t.field_write = (uint8_t)(((eff & vm_isa::VE_W_FLAGS) ? kFlags : 0) |
                              ((eff & vm_isa::VE_W_STACK) ? kStack : 0) |
                              ((eff & vm_isa::VE_W_FRAME) ? kFrame : 0) |
                              ((eff & vm_isa::VE_W_PC) ? kPc : 0));
    t.field_read = (uint8_t)(((eff & vm_isa::VE_R_FLAGS) ? kFlags : 0) |
                             ((eff & vm_isa::VE_R_STACK) ? kStack : 0) |
                             ((eff & vm_isa::VE_R_FRAME) ? kFrame : 0) |
                             ((eff & vm_isa::VE_R_PC) ? kPc : 0));
    t.mem = (eff & vm_isa::VE_MEMORY) != 0;
    return true;
}

/**
 * @brief Rellena `t[0..k)` con lo que toca cada instruccion del paquete.
 *
 * Los registros salen del DESENSAMBLADOR porque su indice es variable
 * (`regs[instr.reg1]`) y solo el formato sabe de que campo sale y cual ocupa la
 * posicion de destino.
 *
 * Y se desensambla el paquete ENTERO de una vez, no instruccion a instruccion.
 * Puede hacerse porque un paquete es un tramo RECTO: sus bytes son contiguos en
 * la memoria de la VM.  La diferencia no es de estilo -- `disasm_bytes`
 * devuelve un vector de cadenas, o sea que por instruccion habria 32 reservas
 * de monton y 32 aperturas de Capstone por cada paquete que se forma --.
 *
 * Si el desensamblador parte los bytes de otra forma que el descodificador, las
 * direcciones dejan de casar y esa instruccion queda como BARRERA: es la unica
 * respuesta honesta cuando dos partes no ven lo mismo.
 *
 * @param process Proceso, para leer los bytes.
 * @param b       Paquete recien formado, todavia en orden de direccion.
 * @param t       Salida: que toca cada una.
 */
void touch_all(ProcessVM *process, const Bundle &b, Touch *t) {
    // Los efectos implicitos primero: son los que deciden quien es barrera, y
    // no hacen falta los bytes para saberlo.
    for (uint32_t i = 0; i < b.k; ++i) effects_of(b.instr[i], t[i]);

    // Un paquete lleno son 32 instrucciones de como mucho 16 bytes.
    constexpr uint32_t kMaxBytes = BUNDLE_MAX * 16;
    uint8_t buf[kMaxBytes];
    const uint64_t base = b.instr[0].pc;
    const DecodedInstr &ultima = b.instr[b.k - 1];
    const uint64_t fin = ultima.pc + (ultima.flags_info.size_instr != 0
                                          ? ultima.flags_info.size_instr
                                          : 16u);
    if (fin <= base) return; // sin bytes que mirar: todas quedan barrera
    const uint64_t len = fin - base;
    if (len > kMaxBytes) return; // no cabe: igual
    process->vm_mem.read_bytes(base, buf, (size_t)len);

    disasm::DisasmOptions opts;
    opts.show_hex = false;
    opts.use_color = false;
    // `hlt` no corta el recorrido: aqui se quiere TODO lo que hay en el
    // paquete, y si dentro hubiera un `hlt` sus efectos ya lo hacen barrera.
    opts.stop_at_hlt = false;
    const auto out = disasm::disasm_bytes(buf, (size_t)len, base, opts);

    /* Se casan por DIRECCION y avanzando los dos a la vez: las dos listas van
     * en orden creciente, asi que basta un indice que no retrocede.  Buscar
     * cada una seria cuadratico para nada. */
    size_t n = 0;
    for (uint32_t i = 0; i < b.k; ++i) {
        while (n < out.size() && out[n].address < b.instr[i].pc) ++n;
        if (n >= out.size() || out[n].address != b.instr[i].pc) {
            t[i].barrier = true; // no casa: no se sabe que toca
            continue;
        }
        if (t[i].barrier) { // ya lo era por sus efectos; no hace falta mas
            ++n;
            continue;
        }
        /* SEGUNDA fuente para "toca memoria", y hace falta.
         *
         * El bit de la base es COTA INFERIOR: se deriva de que el manejador
         * toque `proc->vm_mem`, y hay opcodes que llegan a la memoria por un
         * puntero LEIDO de ahi -- `loadz` y `loadzh` --, con lo que el rastro
         * se pierde y salen sin marcar.  Fiarse solo de eso dejaba intercambiar
         * una carga con un almacen: no da un error, da otro resultado.
         *
         * El desensamblador lo sabe por otro camino -- imprime el operando
         * entre corchetes --, asi que se pregunta a los dos y se queda lo mas
         * conservador.  Dos fuentes independientes que se suman, no una que
         * sustituye a la otra.
         *
         * El arreglo de fondo es que el derivador propague que un puntero
         * sacado de `vm_mem` sigue siendo memoria; hasta entonces, esto. */
        if (out[n].operands.find('[') != std::string::npos) t[i].mem = true;

        bool ok = true;
        for (const disasm::RegOperand &r : out[n].regs) {
            if (r.index > 15) { // fuera del banco: no se sabe
                ok = false;
                break;
            }
            const uint16_t bit = (uint16_t)(1u << r.index);
            uint16_t &rd = r.floating ? t[i].vec_read : t[i].reg_read;
            uint16_t &wr = r.floating ? t[i].vec_write : t[i].reg_write;
            /* El destino cuenta como lectura ADEMAS de escritura.  `add rd, rs`
             * lo lee de verdad; `mov rd, rs` no, pero distinguirlos pediria
             * saber por opcode si lee su destino.  Sobrar una lectura cuesta un
             * reorden; faltar una cuesta un resultado. */
            rd |= bit;
            if (r.dest) wr |= bit;
        }
        t[i].barrier = !ok;
        ++n;
    }
}

/// @return true si @p a y @p b NO se pueden intercambiar.
[[gnu::always_inline]] inline bool conflict(const Touch &a, const Touch &b) {
    if (a.barrier || b.barrier) return true;
    // Las tres formas de chocar sobre un recurso: escribe-lee, lee-escribe y
    // escribe-escribe.  Que los dos LEAN no es conflicto.
    if ((a.reg_write & (b.reg_read | b.reg_write)) != 0) return true;
    if ((b.reg_write & a.reg_read) != 0) return true;
    if ((a.vec_write & (b.vec_read | b.vec_write)) != 0) return true;
    if ((b.vec_write & a.vec_read) != 0) return true;
    if ((a.field_write & (b.field_read | b.field_write)) != 0) return true;
    if ((b.field_write & a.field_read) != 0) return true;
    // Sin desambiguacion de memoria, dos accesos cualesquiera se ordenan.
    if (a.mem && b.mem) return true;
    return false;
}

/* -------------------------------------------------------------------------
 * Los CRITERIOS
 *
 * Cada uno puntua a una candidata en el estado actual del planificador.  El
 * bucle suma `peso * puntuacion` de todos y se queda con la mejor: no sabe
 * cuantos hay ni que miden, asi que anadir una capacidad es anadir una fila.
 * ------------------------------------------------------------------------- */

/// Lo que un criterio puede mirar para puntuar.
struct Ctx {
    const Touch *t;         ///< lo que toca cada instruccion, por indice
    uint32_t k;             ///< cuantas hay
    uint32_t pending;       ///< mascara de las que faltan por emitir
    int32_t last;           ///< indice de la ultima emitida, -1 si ninguna
    uint16_t pend_reg_read; ///< registros que leen las que faltan
    uint32_t orden;         ///< cuantas van emitidas (para el sesgo de orden)
};

/**
 * @brief FUSION: la candidata consume un valor que la ultima acaba de producir
 *        y que no quiere nadie mas.
 *
 * Es el unico criterio que baja el RECUENTO de instrucciones, que es el cuello
 * medido, y por eso pesa mas que los demas.  Un temporal que alguien de mas
 * adelante lee no vale: la primera instruccion sigue haciendo falta.
 */
int score_fusion(const Ctx &c, uint32_t i) {
    if (c.last < 0) return 0;
    const Touch &prod = c.t[c.last];
    const Touch &cons = c.t[i];
    const uint16_t pasa = (uint16_t)(prod.reg_write & cons.reg_read);
    if (pasa == 0) return 0;
    // Lo lee alguien mas de los que faltan?  Entonces no es un temporal muerto.
    const uint16_t otros =
        (uint16_t)(c.pend_reg_read & ~cons.reg_read); // sin contar a la propia
    if ((pasa & otros) != 0) return 0;
    return 1;
}

/**
 * @brief INDEPENDENCIA: la candidata NO choca con la ultima emitida.
 *
 * Mira al futuro: cuando la ejecucion sea de verdad fuera de orden, dos
 * instrucciones seguidas que no chocan son dos que pueden lanzarse a la vez.
 * Hoy se ejecutan en serie igual, asi que esto no cambia nada por si solo --
 * pero deja el orden preparado, y cuesta una comparacion.
 *
 * Va por debajo de la fusion a proposito: fusionar quita una instruccion, y
 * quitarla gana siempre mas que poder solaparla.
 */
int score_independence(const Ctx &c, uint32_t i) {
    if (c.last < 0) return 0;
    return conflict(c.t[c.last], c.t[i]) ? 0 : 1;
}

/**
 * @brief LOCALIDAD: la candidata toca lo mismo que la ultima emitida.
 *
 * Agrupar los accesos a memoria y los que comparten registros deja el trabajo
 * junto en vez de repartido.  Es un PROXY, y conviene saberlo: aqui no se
 * conocen las direcciones -- una SIB las calcula con un registro base --, asi
 * que lo que se mide es "tocan los mismos sitios del banco", que es lo que se
 * puede saber sin ejecutar.
 *
 * Cuando exista la desambiguacion de memoria, este criterio es el que la
 * aprovecha: la misma fila, otra funcion.
 */
int score_locality(const Ctx &c, uint32_t i) {
    if (c.last < 0) return 0;
    const Touch &a = c.t[c.last];
    const Touch &b = c.t[i];
    int s = 0;
    if (a.mem && b.mem) s += 1; // dos accesos seguidos, no separados
    const uint16_t comun = (uint16_t)((a.reg_read | a.reg_write) &
                                      (b.reg_read | b.reg_write));
    if (comun != 0) s += 1;
    return s;
}

/**
 * @brief ORDEN: quedarse cerca del orden original si nada mejor lo pide.
 *
 * No es cosmetico.  Mover por mover cambia el paquete sin ganar nada, y un
 * paquete que cambia sin motivo es un paquete que cuesta mas depurar cuando
 * algo va mal.  Ademas el orden original ya suele ser bueno: lo escribio el
 * emisor del intermedio, que sabe mas que este planificador.
 */
int score_order(const Ctx &c, uint32_t i) {
    // Cuanto mas cerca de donde le tocaba, mejor.  Acotado para que nunca gane
    // a un criterio de verdad.
    const int32_t d = (int32_t)i - (int32_t)c.orden;
    const int32_t dist = d < 0 ? -d : d;
    return dist >= 4 ? 0 : 4 - dist;
}

/// Que criterios hay.  Anadir uno son tres lineas: aqui, en @ref kCriteria y
/// un `case` en @ref score_one.
enum CriterionId : uint8_t {
    CR_FUSION,
    CR_INDEPENDENCE,
    CR_LOCALITY,
    CR_ORDER,
    CR_COUNT,
};

/**
 * @brief Puntua a la candidata @p i segun el criterio @p id.
 *
 * El despacho es un `switch` sobre un entero pequeno y denso -- o sea una tabla
 * de saltos -- y no un puntero a funcion, que es lo que habia antes.  La
 * diferencia no es teorica: esto se evalua una vez por criterio, por candidata
 * y por paso, o sea del orden de `k * k * CR_COUNT` veces al formar un paquete.
 * Con puntero a funcion son 4096 llamadas indirectas que el anfitrion no puede
 * predecir ni inlinar; con el `switch`, el compilador ve los cuatro cuerpos y
 * los mete dentro del bucle.
 *
 * Y la tabla sigue estando (@ref kCriteria): lo que se despacha por ella son
 * los PESOS y el nombre, que es lo que se ajusta; el codigo se elige por
 * identificador.
 */
[[gnu::always_inline]] inline int score_one(uint8_t id, const Ctx &c,
                                            uint32_t i) {
    switch (id) {
    case CR_FUSION: return score_fusion(c, i);
    case CR_INDEPENDENCE: return score_independence(c, i);
    case CR_LOCALITY: return score_locality(c, i);
    case CR_ORDER: return score_order(c, i);
    default: return 0;
    }
}

/// Un criterio: como se llama y cuanto pesa.
struct Criterion {
    const char *name;
    int weight;
};

/* La tabla, indexada por @ref CriterionId.  Plana y en el orden del enum, no un
 * mapa: se recorre entera por cada candidata de cada paso.
 *
 * Los PESOS estan aqui juntos porque son lo que decide quien gana cuando dos
 * criterios piden cosas distintas, y ajustarlos es lo que se hace a menudo.  El
 * de fusion domina por diseno: quitar una instruccion vale mas que solapar dos
 * o que agrupar accesos. */
constexpr Criterion kCriteria[CR_COUNT] = {
    {"fusion", 100},
    {"independence", 20},
    {"locality", 8},
    {"order", 1},
};

static_assert(CR_COUNT == kBundleReorderCriteria,
              "la cuenta publicada en bundle.h y la tabla tienen que coincidir: "
              "quien lee `why` indexa por ella");

} // namespace

const char *bundle_reorder_criterion(uint8_t id) {
    return id < CR_COUNT ? kCriteria[id].name : "orden natural";
}

uint32_t bundle_reorder(ProcessVM *process, Bundle &b, uint8_t *why) {
    if (b.k < 3) return 0; // con dos no hay nada que mover

    Touch t[BUNDLE_MAX];
    touch_all(process, b, t);

    /* GRAFO DE DEPENDENCIAS, una mascara de predecesores por instruccion.
     *
     * `dep[i]` lleva un bit por cada j < i con la que i choca.  Con 32 como
     * maximo cabe en un `uint32_t`, asi que preguntar "esta lista?" es un AND
     * contra las que faltan: una instruccion se puede emitir cuando ninguno de
     * sus predecesores sigue pendiente.
     *
     * Se construye una vez -- 496 comparaciones para un paquete lleno, cada una
     * un punado de ANDs -- y despues el planificador no vuelve a mirar el
     * modelo. */
    uint32_t dep[BUNDLE_MAX] = {};
    for (uint32_t i = 0; i < b.k; ++i)
        for (uint32_t j = 0; j < i; ++j)
            if (conflict(t[j], t[i])) dep[i] |= (1u << j);

    DecodedInstr out[BUNDLE_MAX];
    uint32_t pending = (b.k >= 32) ? 0xFFFFFFFFu : ((1u << b.k) - 1u);
    uint32_t emitted = 0, moved = 0;
    int32_t last = -1;

    while (pending != 0) {
        /* Lo que leen las que faltan.  Es lo que permite saber si un valor es
         * un temporal MUERTO sin recorrer la cola por cada candidata.
         *
         * Se recorren SOLO los bits puestos, sacandolos con `ctz` y quitandolos
         * uno a uno.  Barrer de 0 a k daria 32 vueltas siempre, tambien al
         * final cuando quedan dos. */
        uint16_t pend_reg_read = 0;
        for (uint32_t m = pending; m != 0; m &= m - 1)
            pend_reg_read |= t[(uint32_t)__builtin_ctz(m)].reg_read;

        const Ctx c{t, b.k, pending, last, pend_reg_read, emitted};

        int best = 0;
        int32_t pick = -1;
        /* QUE criterio decidio.  Se queda el de mayor peso que puntuo en la
         * elegida: es la respuesta a "por que se movio esta", y sin ella la
         * telemetria solo dice cuanto se movio.  Solo se calcula con la
         * telemetria encendida; sin ella la variable ni existe. */
        uint8_t winner = CR_COUNT;
        // Solo hace falta averiguarlo si alguien lo va a leer.
        const bool need_reason = (why != nullptr) || VM_BUNDLE_STATS;
        for (uint32_t m = pending; m != 0; m &= m - 1) {
            const uint32_t i = (uint32_t)__builtin_ctz(m);
            if ((dep[i] & pending) != 0) continue; // le falta un predecesor
            int s = 0;
            uint8_t top = CR_COUNT;
            for (uint32_t n = 0; n < CR_COUNT; ++n) {
                const int v = score_one((uint8_t)n, c, i);
                s += kCriteria[n].weight * v;
                if (need_reason && v > 0 && top == CR_COUNT)
                    top = (uint8_t)n; // el primero es el de mas peso
            }
            if (pick < 0 || s > best) {
                best = s;
                pick = (int32_t)i;
                winner = top;
            }
        }
#if VM_BUNDLE_STATS
        ++process->bundle_stats.reorder_choices;
        if (winner < CR_COUNT) ++process->bundle_stats.reorder_wins[winner];
#endif
        /* Sin candidata no se puede seguir, y eso solo pasa si el grafo tuviera
         * un ciclo -- imposible, porque solo hay aristas de j < i --.  Se sale
         * dejando el paquete como estaba en vez de emitir medio. */
        if (pick < 0) return 0;

        if ((uint32_t)pick != emitted) ++moved;
        if (why != nullptr) why[emitted] = winner;
        out[emitted] = b.instr[pick];
        pending &= ~(1u << (uint32_t)pick);
        last = pick;
        ++emitted;
    }

    if (moved == 0) return 0; // nada que hacer: no se toca el paquete
#if VM_BUNDLE_STATS
    ++process->bundle_stats.reorder_bundles;
#endif

    /* QUE se movio, cuando se pide.  Un reordenador que no se puede mirar no se
     * puede depurar: lo que sale de aqui es el orden en que se va a ejecutar, y
     * si esta mal el sintoma aparece lejisimos -- otro valor en un registro, al
     * final del programa --.  Aqui se ve el paquete antes y despues.
     *
     * Va detras de la misma bandera que el volcado de caches y no cuesta nada
     * cuando esta apagada: se mira UNA vez por paquete formado, no al
     * ejecutarlo. */
    if (__builtin_expect(::util::flag_on(::util::FlagId::CacheDump), 0)) {
        std::fprintf(stderr, "\n[reorden] paquete en 0x%08llx  k=%u  movidas=%u\n",
                     (unsigned long long)b.instr[0].pc, b.k, moved);
        for (uint32_t i = 0; i < emitted; ++i)
            std::fprintf(stderr, "    %2u: 0x%08llx%s\n", i,
                         (unsigned long long)out[i].pc,
                         out[i].pc != b.instr[i].pc ? "   <- cambia" : "");
    }

    std::memcpy(b.instr, out, (size_t)emitted * sizeof(DecodedInstr));
    return moved;
}

} // namespace runtime

#endif // VM_BUNDLES
