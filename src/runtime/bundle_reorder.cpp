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
 * Los tres objetivos de arriba no estan cosidos al algoritmo: son filas de
 * @ref VM_REORDER_CRITERIA, una lista de (identificador, nombre, peso,
 * funcion).  Anadir una capacidad -- vectorizar, evitar un puerto del
 * anfitrion, lo que venga -- es anadir UNA fila, y de ella salen a la vez el
 * enumerado, la tabla de pesos y el codigo que puntua.  No hay ningun sitio
 * donde acordarse de dar de alta el criterio por segunda vez.
 *
 * Los pesos deciden que gana cuando dos criterios piden cosas distintas, y
 * estan en esa misma fila por eso: repartidos por el codigo, ajustar el
 * comportamiento seria ir a buscarlos de uno en uno.
 *
 * Y NO HAY DESPACHO.  La lista se expande en el sitio, asi que los cuatro
 * cuerpos quedan dentro del bucle: ni tabla de punteros -- que serian miles de
 * llamadas indirectas que el anfitrion no puede predecir ni inlinar -- ni
 * `switch`, que ademas obliga al compilador a mantener los cuerpos como
 * funciones separadas para poder saltar a ellas.
 *
 * DE DONDE SALE LO QUE PUEDE MOVERSE
 * ----------------------------------
 * De dos sitios, y hacen falta los dos:
 *
 *   - los EFECTOS IMPLICITOS -- banderas, pila, marco, contador de programa, si
 *     toca memoria, si transfiere control, si puede abortar -- salen de
 *     `instr_db_vm`, que se DERIVA del codigo maquina de los manejadores;
 *   - los REGISTROS que nombra salen de la FORMA (`kFormPrimary`), que dice
 *     QUE CAMPO del operando lleva el numero -- su indice es variable
 *     (`regs[instr.reg1]`) y solo el formato lo sabe --, y `regs_of_form` lo
 *     resuelve sobre la instancia ya descodificada.
 *
 * Los dos son un indexado en una tabla que cabe en cache.  AQUI NO SE
 * DESENSAMBLA: formar un paquete son 32 instrucciones, y abrir Capstone y
 * reservar 32 cadenas por paquete es carisimo justo donde no se puede pagar.
 *
 * La forma solo se cree cuando `vm_form_exact` lo dice.  Una mascara a cero
 * tiene dos lecturas opuestas -- "no nombra registros" y "no se vio que
 * nombra" -- y confundirlas no cuesta lo mismo en los dos sentidos: una
 * ESCRITURA que falta permite un reorden que rompe el programa.  Ese bit es lo
 * que separa las dos, y sin el la forma solo servia para informar.
 *
 * LOS CORTES, DE MAS BARATO A MAS CARO
 * ------------------------------------
 * El caso comun de un paquete es que NO se pueda reordenar, asi que lo que hay
 * que hacer bien es salir pronto.  En orden, cada uno evita el trabajo del
 * siguiente:
 *
 *   1. menos de tres instrucciones: con dos no hay nada que mover;
 *   2. menos de dos MOVIBLES: una barrera no se mueve y una sola movible no
 *      tiene con quien intercambiarse.  Corta antes de la matriz, que son 496
 *      comparaciones en un paquete lleno;
 *   3. cadena FORZADA: si cada instruccion depende de la anterior, el unico
 *      orden topologico valido es el que ya trae.  Corta antes del
 *      planificador, que es lo caro.
 *
 * ES CONSERVADOR, Y A PROPOSITO
 * -----------------------------
 *   - Un opcode que no sea movible es BARRERA.  Lo decide `vm_instr_movable`,
 *     que exige efectos EXACTOS y descarta las cuatro barreras (control,
 *     aborto, destino solo conocido al ejecutar, y salida a codigo ajeno).
 *   - El DESTINO cuenta tambien como LECTURA.  Distinguir `mov` de `add`
 *     pediria saber si el opcode lee su destino; no saberlo cuesta un reorden
 *     perdido, suponerlo puede costar un resultado.
 *   - Toda la memoria de la VM es UN recurso: sin desambiguacion, dos accesos
 *     cualesquiera se ordenan entre si.
 *   - Si la forma de un opcode no es de fiar, barrera.
 *
 * Barrera NO quiere decir que el paquete se congele.  Una barrera se fija a SI
 * MISMA: lo que queda por encima se sigue reordenando entre si, y lo que queda
 * por debajo tambien.  La matriz de dependencias es por PARES, asi que sale
 * solo; el test lo comprueba, porque un planificador que se rindiera al ver la
 * primera barrera pasaria todas las comprobaciones de correccion sin hacer
 * nada -- no cruzar nada es trivialmente correcto --.
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
 *
 * LO QUE NO ESTA AQUI
 * -------------------
 * Ni el volcado, ni los contadores, ni una sola cadena de texto: eso vive en
 * `bundle_reorder_report.cpp`, detras de `bundle_reorder_report.h`.  El
 * planificador se instancia DOS veces desde esta misma implementacion
 * (`Explain`), y la caliente no contiene ni una instruccion de telemetria.
 */

#include "runtime/bundle.h"

#include <cstring>

#include "runtime/bundle_reorder_report.h"
#include "runtime/effects_decode.h"
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

/// Cuantos registros tiene el banco general.  Sale del ancho de las mascaras.
constexpr uint32_t kRegs = 16;
/// Cuantos campos implicitos hay: banderas, pila, marco y contador.
constexpr uint32_t kFieldCount = 4;

/* PENDIENTE: puntuar con SIMD, y entonces sin ventana.
 *
 * Los cuatro criterios son aritmetica sobre mascaras de dieciseis bits, o sea
 * que ocho candidatas caben en un registro SSE y las 32 de un paquete lleno
 * salen en cuatro pasos.  `score_order` es aritmetica pura sobre indices,
 * `score_independence` un desplazamiento de `clash`, y `fusion` y `locality`
 * ANDs.  Todo con SSE2, que es LINEA BASE de x86-64: sin despacho por CPU y sin
 * subir `-march`, que es la condicion para que entre en este proyecto.
 *
 * Pide un cambio previo: `Touch` tiene que pasar de vector de estructuras a
 * estructura de vectores (`uint16_t reg_read[BUNDLE_MAX]`, `reg_write[...]`,
 * ...), porque hoy los campos de una candidata estan juntos y lo que hace falta
 * es que esten juntos los de TODAS.
 *
 * Y no seria solo mas rapido: puntuar las 32 en cuatro pasos sale mas barato
 * que recorrer ocho dispersas en escalar, asi que @ref kWindow -- que es una
 * aproximacion -- se sustituiria por el calculo exacto.
 *
 * NO SE HA HECHO, y el motivo esta medido, no supuesto: en la carga que se
 * hundia, `fusion` y `locality` ganaron CERO elecciones de ocho millones, y
 * `independence` decidio el 94%.  Vectorizar aqui es acelerar un calculo cuyo
 * resultado es "no muevas nada" ocho millones de veces.  Antes van dos cosas
 * que quitan trabajo en vez de acelerarlo: no analizar los sitios que se
 * forman una vez y mueren -- la icache se desaloja a si misma y se reforman
 * 250.000 paquetes para cambiar UNO --, y saltarse los criterios que no pueden
 * puntuar.  Cuando eso este, esto es lo siguiente.
 */

/**
 * @brief Cuantas candidatas LISTAS mira el planificador en cada paso.
 *
 * Un planificador de lista mira todas las que estan listas y se queda con la
 * mejor.  Eso es `k` pasos por `k` pendientes: mil evaluaciones de los cuatro
 * criterios en un paquete lleno, y medido con VTune era el coste dominante del
 * reordenamiento -- nueve mil millones de instrucciones del anfitrion --.
 *
 * Mirar solo las primeras no pierde casi nada, y no por corazonada: el criterio
 * de orden YA declara que a partir de cierta distancia su aportacion es cero,
 * asi que una candidata lejana solo puede ganar por fusion o por localidad, y
 * para eso tendria que ser la unica lista que consume lo que la ultima acaba de
 * producir -- que es tanto como decir que las de en medio no estaban listas y
 * no gastaron ventana --.
 *
 * Ocho y no cuatro porque el sesgo de orden se apaga a distancia cuatro: con la
 * ventana justo ahi, la unica candidata capaz de desempatar quedaria fuera.
 */
constexpr uint32_t kWindow = 8;

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
    // Deja de serlo POR SUS EFECTOS.  Todavia puede volver a marcarse si su
    // FORMA no es de fiar, que es lo que decide `touch_one`.
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
 * @brief Rellena @p t con lo que toca @p d.
 *
 * SIN DESENSAMBLAR NADA.  Los efectos dicen que toca sin nombrarlo; la forma
 * dice QUE CAMPO del operando lleva el numero de registro, y `regs_of_form` lo
 * resuelve sobre esta instancia.  Dos indexados en tablas de cache y doce
 * iteraciones sin ramas dependientes de datos.
 *
 * @return true si la instruccion se puede mover.
 */
[[gnu::always_inline]] inline bool touch_one(const DecodedInstr &d, Touch &t) {
    if (!effects_of(d, t)) return false;
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const uint8_t op =
        ext ? (uint8_t)d.flags_info.opcode_index : d.flags_info.is_not_extended;
    if (!vm_isa::vm_form_exact(ext, op)) {
        t.barrier = true; // no se sabe que registros nombra
        return false;
    }
    const uint64_t f = vm_isa::vm_form(ext, op);
    t.reg_read = regs_of_form(vm_isa::vm_form_read(f), d);
    t.reg_write = regs_of_form(vm_isa::vm_form_write(f), d);
    t.vec_read = regs_of_form(vm_isa::vm_form_vec_read(f), d);
    t.vec_write = regs_of_form(vm_isa::vm_form_vec_write(f), d);
    /* Lo que se ESCRIBE se lee tambien, salvo que se pise entero.
     *
     * `add rd, rs` lee rd de verdad; `mov rd, rs` no.  La base lo sabe -- es el
     * estrechamiento que ya distingue una escritura parcial de una total --,
     * pero mientras la forma no lo separe por campo, sobrar la lectura es el
     * lado barato de equivocarse. */
    t.reg_read |= t.reg_write;
    t.vec_read |= t.vec_write;
    return true;
}

/* -------------------------------------------------------------------------
 * Los CRITERIOS
 *
 * Cada uno puntua a una candidata en el estado actual del planificador.  El
 * bucle suma `peso * puntuacion` de todos y se queda con la mejor.
 * ------------------------------------------------------------------------- */

/// Lo que un criterio puede mirar para puntuar.
struct Ctx {
    const Touch *t; ///< lo que toca cada instruccion, por indice
    /**
     * @brief Con quien choca cada una, EN LOS DOS SENTIDOS.
     *
     * `clash[i]` lleva un bit por cada j -- anterior o posterior -- que no se
     * puede cruzar con i.  Se calcula una vez, y de ella sale tambien la mitad
     * de abajo, que es la que dice si una candidata esta lista.
     *
     * Estar aqui es lo que quita el coste dominante.  La independencia se
     * preguntaba llamando otra vez a `conflict`, o sea una vez por candidata y
     * por paso: mil largas por paquete, ADEMAS de las 496 de construir la
     * matriz.  Medido con VTune sobre el caso que se hundia, `conflict` se
     * llevaba 0,41 s de los 0,41 s del reordenamiento entero.  Mirar el bit ya
     * calculado es un desplazamiento y un AND.
     */
    const uint32_t *clash;
    uint32_t k;             ///< cuantas hay
    uint32_t pending;       ///< mascara de las que faltan por emitir
    int32_t last;           ///< indice de la ultima emitida, -1 si ninguna
    uint16_t pend_reg_read; ///< registros que leen las que faltan
    uint32_t emitted;       ///< cuantas van emitidas (para el sesgo de orden)
};

/**
 * @brief FUSION: la candidata consume un valor que la ultima acaba de producir
 *        y que no quiere nadie mas.
 *
 * Es el unico criterio que baja el RECUENTO de instrucciones, que es el cuello
 * medido, y por eso pesa mas que los demas.  Un temporal que alguien de mas
 * adelante lee no vale: la primera instruccion sigue haciendo falta.
 */
[[gnu::always_inline]] inline int score_fusion(const Ctx &c, uint32_t i) {
    if (c.last < 0) return 0;
    const Touch &prod = c.t[c.last];
    const Touch &cons = c.t[i];
    const uint16_t forwarded = (uint16_t)(prod.reg_write & cons.reg_read);
    if (forwarded == 0) return 0;
    // Lo lee alguien mas de los que faltan?  Entonces no es un temporal muerto.
    const uint16_t other_readers =
        (uint16_t)(c.pend_reg_read & ~cons.reg_read); // sin contar a la propia
    return (forwarded & other_readers) != 0 ? 0 : 1;
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
[[gnu::always_inline]] inline int score_independence(const Ctx &c, uint32_t i) {
    if (c.last < 0) return 0;
    // Del bit ya calculado, no volviendo a comparar: ver `Ctx::clash`.
    return (int)((c.clash[i] >> (uint32_t)c.last) & 1u) ^ 1;
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
[[gnu::always_inline]] inline int score_locality(const Ctx &c, uint32_t i) {
    if (c.last < 0) return 0;
    const Touch &a = c.t[c.last];
    const Touch &b = c.t[i];
    const uint16_t shared =
        (uint16_t)((a.reg_read | a.reg_write) & (b.reg_read | b.reg_write));
    return (int)(a.mem && b.mem) + (int)(shared != 0);
}

/**
 * @brief ORDEN: quedarse cerca del orden original si nada mejor lo pide.
 *
 * No es cosmetico.  Mover por mover cambia el paquete sin ganar nada, y un
 * paquete que cambia sin motivo es un paquete que cuesta mas depurar cuando
 * algo va mal.  Ademas el orden original ya suele ser bueno: lo escribio el
 * emisor del intermedio, que sabe mas que este planificador.
 */
[[gnu::always_inline]] inline int score_order(const Ctx &c, uint32_t i) {
    // Cuanto mas cerca de donde le tocaba, mejor.  Acotado para que nunca gane
    // a un criterio de verdad.
    const int32_t d = (int32_t)i - (int32_t)c.emitted;
    const int32_t dist = d < 0 ? -d : d;
    return dist >= 4 ? 0 : 4 - dist;
}

/**
 * @brief LA lista de criterios: identificador, nombre, peso y funcion.
 *
 * De ella salen el enumerado, la tabla de nombres y pesos, y el codigo que
 * puntua.  Anadir una capacidad es anadir UNA fila; no hay ningun otro sitio
 * donde darla de alta, que es justo lo que se olvida.
 *
 * El peso de la fusion domina por diseno: quitar una instruccion vale mas que
 * solapar dos o que agrupar accesos.
 */
#define VM_REORDER_CRITERIA(X)                                                 \
    X(FUSION, "fusion", 100, score_fusion)                                     \
    X(INDEPENDENCE, "independence", 20, score_independence)                    \
    X(LOCALITY, "locality", 8, score_locality)                                 \
    X(ORDER, "order", 1, score_order)

/// Que criterios hay.  Se genera de @ref VM_REORDER_CRITERIA.
enum CriterionId : uint8_t {
#define VM_REORDER_ENUM(id, name, weight, fn) CR_##id,
    VM_REORDER_CRITERIA(VM_REORDER_ENUM)
#undef VM_REORDER_ENUM
        CR_COUNT,
};

/// Un criterio: como se llama y cuanto pesa.
struct Criterion {
    const char *name;
    int weight;
};

/// La tabla, indexada por @ref CriterionId.  Solo la lee quien informa: el
/// planificador lleva los pesos DENTRO del codigo, expandidos de la lista.
constexpr Criterion kCriteria[CR_COUNT] = {
#define VM_REORDER_ROW(id, name, weight, fn) {name, weight},
    VM_REORDER_CRITERIA(VM_REORDER_ROW)
#undef VM_REORDER_ROW
};

static_assert(CR_COUNT == kBundleReorderCriteria,
              "la cuenta publicada en bundle.h y la lista tienen que coincidir: "
              "quien lee `why` indexa por ella");

/**
 * @brief Puntua a la candidata @p i con TODOS los criterios.
 *
 * La lista se expande aqui, asi que los cuerpos quedan dentro del bucle: sin
 * despacho, sin llamada y con los pesos como constantes que el compilador
 * puede plegar.  Esto se evalua del orden de `k * k` veces por paquete, que es
 * donde una llamada indirecta por criterio se nota.
 *
 * @tparam Explain Si hay que averiguar QUE criterio decidio.  Con `false` no se
 *                 genera ni una instruccion de eso.
 * @param top      Salida: el criterio de mas peso que puntuo.  Solo con
 *                 @p Explain.
 */
template <bool Explain>
[[gnu::always_inline]] inline int score_all(const Ctx &c, uint32_t i,
                                            int *parts) {
    int s = 0;
#define VM_REORDER_EVAL(id, name, weight, fn)                                  \
    {                                                                          \
        const int v = fn(c, i);                                                \
        s += (weight) * v;                                                     \
        if constexpr (Explain) parts[CR_##id] = v;                             \
    }
    VM_REORDER_CRITERIA(VM_REORDER_EVAL)
#undef VM_REORDER_EVAL
    if constexpr (!Explain) (void)parts;
    return s;
}

/**
 * @brief Que criterio DECIDIO entre la ganadora y la segunda.
 *
 * El que desempata, no "el de mas peso que puntuo".  No es lo mismo y la
 * diferencia enganya: si `independence` puntua en las dos candidatas, sumaba
 * lo mismo a las dos y no decidio nada -- pero se llevaba el credito, y
 * `locality`, que era quien de verdad rompia el empate, salia con CERO
 * victorias en ocho millones de elecciones.  Con ese numero delante se concluye
 * que el criterio es inerte y se le quita peso, o se deja de optimizar por el:
 * un contador mal etiquetado no es un contador de menos, es uno que lleva a la
 * decision contraria.
 *
 * Se recorre de mas peso a menos y gana el primero donde las dos difieren, que
 * es exactamente el que inclina la suma.
 *
 * @param win Puntuaciones por criterio de la elegida.
 * @param run Las de la segunda.  Si no hubo segunda, no hubo desempate.
 * @return El criterio, o `CR_COUNT` si empatan en todos.
 */
[[gnu::always_inline]] inline uint8_t decided_by(const int *win,
                                                 const int *run) {
    for (uint32_t n = 0; n < CR_COUNT; ++n)
        if (win[n] != run[n]) return (uint8_t)n;
    return CR_COUNT;
}

/**
 * @brief El planificador.  Una implementacion, dos instanciaciones.
 *
 * @tparam Explain Genera el rastreo del motivo y llama al informe.  La
 *                 instancia con `false` no lleva NADA de eso: ni la variable,
 *                 ni las ramas, ni las llamadas.
 * @return Cuantas instrucciones cambiaron de sitio; 0 = el paquete no se toco.
 */
template <bool Explain>
uint32_t reorder_impl(ProcessVM *process, Bundle &b, uint8_t *why) {
    // CORTE 1: con dos no hay nada que mover.
    if (b.k < 3) return 0;

    /* Lo que toca cada una, y de paso cuantas se pueden mover.
     *
     * CORTE 2: una barrera no se mueve, y una sola movible no tiene con quien
     * intercambiarse.  Sale antes de la matriz, que son 496 comparaciones en un
     * paquete lleno. */
    Touch t[BUNDLE_MAX];
    uint32_t movable = 0;
    for (uint32_t i = 0; i < b.k; ++i) movable += touch_one(b.instr[i], t[i]);
    if (movable < 2) return 0;

    /* La matriz de choques, en MASCARAS DE BITS y en los DOS sentidos:
     * `clash[i]` lleva un bit por cada j que no se puede cruzar con i.  Con 32
     * como maximo cabe en un `uint32_t`, y de ella salen las DOS preguntas del
     * planificador: "esta lista?" es la mitad de abajo contra las pendientes, y
     * "es independiente de la ultima?" es un bit.
     *
     * Y NO SE CONSTRUYE POR PARES.  Dos instrucciones chocan cuando coinciden
     * en un RECURSO -- un registro, un campo implicito, la memoria --, asi que
     * en vez de preguntar por cada par se apunta, por recurso, QUIEN lo lee y
     * QUIEN lo escribe.  Despues la fila de cada una es la union de los
     * apuntes de los recursos que ella toca.
     *
     * El cambio es de orden: `k*(k-1)/2` comparaciones de ocho pruebas cada una
     * -- 496 pares y casi cuatro mil pruebas en un paquete lleno -- pasan a dos
     * pasadas de `k` por los recursos que cada una toca, que son uno o dos.  El
     * perfilador senalaba `conflict` como el 100% del coste del reordenamiento
     * (0,41 s de 0,41 s); asi no se llama ni una vez.
     *
     * Una BARRERA choca con todas por definicion: va en su propia mascara y no
     * pasa por los recursos.
     *
     * CORTE 3: si cada una depende de la ANTERIOR, el unico orden topologico
     * valido es el que ya trae.  Sale antes del planificador, que es lo caro. */
    const uint32_t all = (b.k >= 32) ? 0xFFFFFFFFu : ((1u << b.k) - 1u);
    uint32_t w_reg[kRegs] = {}, r_reg[kRegs] = {};
    uint32_t w_vec[kRegs] = {}, r_vec[kRegs] = {};
    uint32_t w_fld[kFieldCount] = {}, r_fld[kFieldCount] = {};
    uint32_t mem_mask = 0, barrier_mask = 0;
    for (uint32_t i = 0; i < b.k; ++i) {
        const uint32_t bit = 1u << i;
        if (t[i].barrier) {
            barrier_mask |= bit;
            continue;
        }
        for (uint16_t m = t[i].reg_write; m != 0; m &= (uint16_t)(m - 1))
            w_reg[__builtin_ctz(m)] |= bit;
        for (uint16_t m = t[i].reg_read; m != 0; m &= (uint16_t)(m - 1))
            r_reg[__builtin_ctz(m)] |= bit;
        for (uint16_t m = t[i].vec_write; m != 0; m &= (uint16_t)(m - 1))
            w_vec[__builtin_ctz(m)] |= bit;
        for (uint16_t m = t[i].vec_read; m != 0; m &= (uint16_t)(m - 1))
            r_vec[__builtin_ctz(m)] |= bit;
        for (uint32_t m = t[i].field_write; m != 0; m &= m - 1)
            w_fld[__builtin_ctz(m)] |= bit;
        for (uint32_t m = t[i].field_read; m != 0; m &= m - 1)
            r_fld[__builtin_ctz(m)] |= bit;
        if (t[i].mem) mem_mask |= bit;
    }

    uint32_t clash[BUNDLE_MAX];
    for (uint32_t i = 0; i < b.k; ++i) {
        if (t[i].barrier) {
            clash[i] = all & ~(1u << i);
            continue;
        }
        /* Escribir choca con quien lee Y con quien escribe; leer, solo con
         * quien escribe.  Que dos LEAN no es conflicto, y es justo lo que hace
         * que el orden tenga margen. */
        uint32_t c = barrier_mask;
        for (uint16_t m = t[i].reg_write; m != 0; m &= (uint16_t)(m - 1)) {
            const int r = __builtin_ctz(m);
            c |= w_reg[r] | r_reg[r];
        }
        for (uint16_t m = t[i].reg_read; m != 0; m &= (uint16_t)(m - 1))
            c |= w_reg[__builtin_ctz(m)];
        for (uint16_t m = t[i].vec_write; m != 0; m &= (uint16_t)(m - 1)) {
            const int r = __builtin_ctz(m);
            c |= w_vec[r] | r_vec[r];
        }
        for (uint16_t m = t[i].vec_read; m != 0; m &= (uint16_t)(m - 1))
            c |= w_vec[__builtin_ctz(m)];
        for (uint32_t m = t[i].field_write; m != 0; m &= m - 1) {
            const int f = __builtin_ctz(m);
            c |= w_fld[f] | r_fld[f];
        }
        for (uint32_t m = t[i].field_read; m != 0; m &= m - 1)
            c |= w_fld[__builtin_ctz(m)];
        // Sin desambiguacion de memoria, dos accesos cualesquiera se ordenan.
        if (t[i].mem) c |= mem_mask;
        clash[i] = c & ~(1u << i);
    }

    bool forced = true;
    for (uint32_t i = 1; i < b.k && forced; ++i)
        if ((clash[i] & (1u << (i - 1))) == 0) forced = false;
    if (forced) return 0;

    // Solo las ANTERIORES: es lo que decide si una candidata esta lista.
    uint32_t dep[BUNDLE_MAX];
    for (uint32_t i = 0; i < b.k; ++i)
        dep[i] = clash[i] & ((1u << i) - 1u);

    /* Los registros que leen las que FALTAN, y cuantas los leen.
     *
     * El contador por registro es lo que permite mantenerlo al emitir en vez de
     * recalcularlo: antes se recorrian todas las pendientes en CADA paso, o sea
     * `k*k/2` uniones para un dato que solo cambia en lo que aporta la que se
     * acaba de emitir.  Ahora cuesta lo que lea esa: se decrementa su cuenta y
     * el bit se apaga cuando llega a cero. */
    uint8_t read_count[kRegs] = {};
    uint16_t pend_reg_read = 0;
    for (uint32_t i = 0; i < b.k; ++i) {
        pend_reg_read |= t[i].reg_read;
        for (uint16_t m = t[i].reg_read; m != 0; m &= (uint16_t)(m - 1))
            ++read_count[__builtin_ctz(m)];
    }

    /* CUANTOS predecesores le faltan a cada una, y quienes estan LISTAS.
     *
     * Es lo que quita la otra mitad del coste cuadratico.  Antes, cada paso
     * recorria las pendientes preguntando `dep[i] & pending` -- `k` preguntas
     * por paso, `k*k` en total -- para un dato que solo cambia en las que
     * dependian de la que se acaba de emitir.
     *
     * Emitir una solo puede desbloquear a sus SUCESORAS, y esas se sacan de la
     * matriz que ya esta: `clash[pick]` por encima de `pick`.  A cada una se le
     * baja el contador y entra en `ready` cuando llega a cero.  El recorrido
     * entero pasa a costar los nodos mas las aristas, en vez de los nodos al
     * cuadrado. */
    uint8_t npred[BUNDLE_MAX];
    uint32_t ready = 0;
    for (uint32_t i = 0; i < b.k; ++i) {
        npred[i] = (uint8_t)__builtin_popcount(dep[i]);
        if (npred[i] == 0) ready |= (1u << i);
    }

    DecodedInstr out[BUNDLE_MAX];
    uint32_t pending = all;
    uint32_t emitted = 0, moved = 0;
    int32_t last = -1;

    while (pending != 0) {
        const Ctx c{t, clash, b.k, pending, last, pend_reg_read, emitted};

        int best = 0;
        int32_t pick = -1;
        uint8_t winner = CR_COUNT;
        uint32_t looked = 0;

        /* UNA SOLA LISTA: no hay nada que decidir.
         *
         * Es el caso comun de largo -- una cadena de dependencias no ofrece
         * alternativa en ningun paso --, y ahi puntuar los cuatro criterios es
         * trabajo cuyo resultado no puede cambiar la eleccion.  Se salta
         * entero.
         *
         * El motivo que se apunta es el orden: no se movio porque no habia
         * otra, que es distinto de "gano el sesgo de orden frente a otras". */
        if ((ready & (ready - 1)) == 0) {
            pick = (int32_t)__builtin_ctz(ready);
            winner = CR_ORDER;
        }
        /* Sobre `ready`, que ya son solo las que se pueden emitir: ni una
         * pregunta por candidata descartada.
         *
         * Y de esas, las kWindow primeras.  El criterio de orden ya declara que
         * a partir de cierta distancia no aporta nada, asi que una candidata
         * lejana solo puede ganar por fusion o por localidad -- y para eso
         * tendria que ser la unica lista que consume lo que la ultima acaba de
         * producir, que es tanto como decir que las de en medio no estaban
         * listas y no gastaron ventana --. */
        /* Las puntuaciones por criterio de la mejor y de la SEGUNDA.  Hacen
         * falta las dos para saber quien desempato, que es lo unico que
         * contesta "por que se movio esta"; con la de la mejor sola, el credito
         * se lo lleva el criterio de mas peso que puntuo aunque sumara igual en
         * las dos y no decidiera nada. */
        int win_parts[CR_COUNT] = {}, run_parts[CR_COUNT] = {};
        int parts[CR_COUNT] = {};
        int second = INT32_MIN; ///< puntuacion de la mejor que NO gana
        for (uint32_t m = (pick < 0) ? ready : 0u; m != 0 && looked < kWindow;
             m &= m - 1) {
            const uint32_t i = (uint32_t)__builtin_ctz(m);
            ++looked;
            const int s = score_all<Explain>(c, i, parts);
            if (pick < 0 || s > best) {
                if constexpr (Explain) {
                    // La que reinaba baja a segunda: era la mejor de las que
                    // ahora no ganan, asi que es con quien hay que comparar.
                    if (pick >= 0) {
                        second = best;
                        for (uint32_t n = 0; n < CR_COUNT; ++n)
                            run_parts[n] = win_parts[n];
                    }
                    for (uint32_t n = 0; n < CR_COUNT; ++n)
                        win_parts[n] = parts[n];
                }
                best = s;
                pick = (int32_t)i;
            } else if constexpr (Explain) {
                if (s > second) { // mejor de las que no ganan
                    second = s;
                    for (uint32_t n = 0; n < CR_COUNT; ++n)
                        run_parts[n] = parts[n];
                }
            }
        }
        /* Sin segunda no hubo desempate: no es que ganara el orden, es que no
         * habia con quien competir.  Se apunta como "ninguno" y por eso las
         * victorias NO suman las elecciones -- la diferencia es justo cuantas
         * veces no habia alternativa, que tambien es un dato. */
        if constexpr (Explain)
            winner = (second == INT32_MIN) ? CR_COUNT
                                           : decided_by(win_parts, run_parts);

        /* Sin candidata no se puede seguir, y eso solo pasa si el grafo tuviera
         * un ciclo -- imposible, porque solo hay aristas de j < i --.  Se sale
         * dejando el paquete como estaba en vez de emitir medio. */
        if (pick < 0) return 0;

        if ((uint32_t)pick != emitted) ++moved;
        if constexpr (Explain) why[emitted] = winner;
        out[emitted] = b.instr[pick];
        const uint32_t pick_bit = 1u << (uint32_t)pick;
        pending &= ~pick_bit;
        ready &= ~pick_bit;

        /* A quien acaba de desbloquear.  Solo las de INDICE MAYOR pueden
         * tenerla de predecesora: `dep` solo lleva aristas hacia atras. */
        const uint32_t higher = pending & ~((pick_bit << 1) - 1u);
        for (uint32_t s = clash[pick] & higher; s != 0; s &= s - 1) {
            const uint32_t j = (uint32_t)__builtin_ctz(s);
            if (--npred[j] == 0) ready |= (1u << j);
        }

        // Lo que dejaba de aportar a las pendientes, ahora que ya salio.
        for (uint16_t m = t[pick].reg_read; m != 0; m &= (uint16_t)(m - 1)) {
            const uint32_t r = (uint32_t)__builtin_ctz(m);
            if (--read_count[r] == 0)
                pend_reg_read &= (uint16_t)~(1u << r);
        }
        last = pick;
        ++emitted;
    }

    if constexpr (Explain) {
        reorder_report_stats(process, moved, why, emitted);
        /* El volcado va ANTES de escribir el paquete: necesita los dos ordenes
         * a la vez, y el de partida sigue en `b.instr` hasta la copia. */
        if (moved != 0 &&
            __builtin_expect(::util::flag_on(::util::FlagId::CacheDump), 0))
            reorder_report_dump(b.instr, out, emitted, moved, why);
    } else {
        (void)process;
    }

    if (moved == 0) return 0; // nada que hacer: no se toca el paquete
    std::memcpy(b.instr, out, (size_t)emitted * sizeof(DecodedInstr));
    return moved;
}

} // namespace

const char *bundle_reorder_criterion(uint8_t id) {
    return id < CR_COUNT ? kCriteria[id].name : "natural order";
}

uint32_t bundle_reorder(ProcessVM *process, Bundle &b, uint8_t *why) {
    /* Que instancia toca.  Se decide aqui, UNA vez por paquete formado, y nunca
     * dentro del bucle: la instancia caliente no lleva ni la pregunta.
     *
     * Los tres que piden el motivo -- quien pasa `why` (el test), quien pide la
     * telemetria y quien vuelca las caches -- van por la que explica.  Ninguno
     * depende del perfil de construccion: se piden en EJECUCION, porque atarlo
     * a como se compilo obliga a reconstruir para mirar, y entonces lo que se
     * mira ya no es el binario que se ejecuta. */
    if (__builtin_expect(why != nullptr, 0))
        return reorder_impl<true>(process, b, why);
    if (__builtin_expect(process->bundle_stats_on ||
                             ::util::flag_on(::util::FlagId::BundleStats) ||
                             ::util::flag_on(::util::FlagId::CacheDump),
                         0)) {
        uint8_t local[BUNDLE_MAX];
        return reorder_impl<true>(process, b, local);
    }
    return reorder_impl<false>(process, b, nullptr);
}

} // namespace runtime

#endif // VM_BUNDLES
