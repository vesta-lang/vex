/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/runtime/test_mips.cpp
 * @brief Cuantas instrucciones por segundo ejecuta el INTERPRETE, con guardia.
 *
 * Por que existe
 * --------------
 * Habia un banco de MIPS en C++ -- dentro de `tests/loader/test1.cpp` -- y no
 * servia, por dos motivos a la vez:
 *
 *   1. Estaba detras de `// #define BENCHMARK_VM`, comentado.  No se compilaba.
 *   2. Aunque se compilara, imprime numeros y hace `return 0` pase lo que pase.
 *      No puede fallar.
 *
 * Es el mismo patron que dejo los veintiseis tests de `tests/aot/` meses sin
 * ejecutarse: una prueba que no se ejecuta no es una prueba, y una que no puede
 * fallar tampoco.  La consecuencia se vio al medir con VTune: el interprete se
 * movio un 29% -- inlinar `get_entry` y conectar la cache de pagina en
 * `operator[]` -- y NADA lo noto, ni para bien ni para mal.
 *
 * Una matriz, no un numero
 * ------------------------
 * Los MIPS de un interprete no son UN numero: cambian con tres cosas a la vez,
 * y por eso el banco las recorre las tres.
 *
 *   MEZCLA    aritmetica de 64 bits, la misma en anchos de 8/16/32, accesos a
 *             memoria (que pasan por la traduccion de direcciones), las tres
 *             alternadas, y coma flotante en escalar y empaquetada.  Medir
 *             solo aritmetica entera deja sin vigilar justo los caminos que
 *             mas se han movido -- y la coma flotante es OTRO banco de
 *             registros, otro fichero de manejadores y ninguna ruta rapida.
 *   LONGITUD  cada cuanto hay un salto: 4, 20, 260 y 1204 instrucciones
 *             seguidas.  Un salto no solo se despacha -- cambia el `pc`,
 *             vuelve a consultar la icache y pone a prueba al predictor.
 *   DESPACHO  con bundles (el ILP de la VM) y sin ellos.  Es el mismo
 *             bytecode ejecutado por dos motores distintos, y una regresion en
 *             uno no se ve en el otro.
 *
 * Con un solo caso no se puede saber si una regresion esta en el despacho, en
 * el camino de salto o en la memoria; con la matriz, la forma en que se mueven
 * las filas lo dice.
 *
 * Que se mide, y por que asi
 * --------------------------
 * El programa se GENERA aqui, se ensambla y se enlaza en el propio test.  Nada
 * de ficheros de fuera ni de compilar un `.vx`: si el numero dependiera del
 * compilador de Vesta o de su cache, una regresion del interprete se
 * confundiria con un cambio del frontend.
 *
 * Se ejecuta por el PLANIFICADOR de verdad (`vm->start()`) y se cronometra
 * desde fuera.  Llamar a los manejadores en un bucle propio mediria justo lo
 * que no interesa: lo que se quiere medir ES el despacho.
 *
 * El umbral
 * ---------
 * Holgado, y no por pereza.  Esto corre en una maquina compartida con lo que
 * haya, y el banco de este proyecto tiene +-7% de ruido de por si.  Un umbral
 * ajustado daria rojos que nadie puede reproducir, y un test que falla sin
 * motivo se acaba ignorando -- con lo que volveriamos al punto de partida.  Lo
 * que se busca cazar es una regresion GRANDE, del tipo "alguien saco una
 * funcion caliente de la cabecera".
 *
 * Dos partes, y las dos corren SIN argumentos
 * -------------------------------------------
 *   1. La MATRIZ de regresion: puntos fijos con linea base.  Es la que puede
 *      fallar, y solo significa algo porque se mide siempre en los mismos
 *      sitios.
 *   2. El BARRIDO del techo: recorre longitudes y mezclas buscando el maximo.
 *      No falla nunca -- informa --, porque el maximo no esta en un punto que
 *      se pueda fijar de antemano: se mueve con el tamano de la icache de
 *      instrucciones descodificadas y con el motor de despacho.
 *
 * Las banderas son para iterar mientras se investiga algo, nunca para elegir
 * que se prueba.
 *
 * Uso:
 *   test_mips [--vueltas N] [--repetir N] [--solo mezcla:tramo:despacho]
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "emmit/parser_to_bytecode.h"    // el ensamblador: `.vel` -> bytes
#include "lexer/lexer.h"
#include "linker/velb_linker_bytecode.h" // y el enlazador: bytes -> .velb
#include "loader/loader.h"
#include "parser/parser.h"
#include "runtime/manager_runtime.h"
#include "runtime/proceso_runtime.h"
#include "runtime/runtime.h"
#include "util/ansi.h"
#include "util/reloj.h"

namespace {

/**
 * @brief Que clase de instrucciones lleva el cuerpo.
 *
 * Los MIPS no son un numero del interprete: son un numero POR MEZCLA.  Un
 * `adds r2, 3` y un `mov r1, [r14 + r13*8]` se despachan igual y cuestan cosas
 * muy distintas -- el segundo pasa por la traduccion de direcciones --, asi que
 * medir solo aritmetica de registros deja sin vigilar justo el camino que mas
 * se ha movido.
 */
enum class Mix {
    Alu,     ///< aritmetica y logica de 64 bits entre registros
    Widths,  ///< las mismas, en 8/16/32/64 -- ejercita el despacho por ANCHO
    Memory, ///< cargas y almacenamientos: pasa por la TLB y la cache de pagina
    Mixed,   ///< las tres alternadas, que es a lo que se parece un programa
    /* Las dos siguientes van DESPUES de `Mixed` a proposito: el cuerpo mixto
     * alterna las tres primeras con `i % 3`, asi que meterlas antes las
     * arrastraria ahi dentro. */
    Float,  ///< coma flotante ESCALAR (f64) sobre el banco ZMM
    Vector, ///< las mismas, empaquetadas en 256 bits (ymm)
};

/// @brief Nombre corto de una mezcla, para la columna de la tabla.
const char *mix_name(Mix m) {
    switch (m) {
    case Mix::Alu: return "alu";
    case Mix::Widths: return "anchos";
    case Mix::Memory: return "memoria";
    case Mix::Mixed: return "mixta";
    case Mix::Float: return "float";
    default: return "vector";
    }
}

/// @brief Color de una mezcla.  Sirve para leer la tabla por bloques de un
///        vistazo sin tener que seguir la columna de nombres linea a linea.
const char *mix_color(Mix m) {
    switch (m) {
    case Mix::Alu: return ansi::CYAN;
    case Mix::Widths: return ansi::MAGENTA;
    case Mix::Memory: return ansi::YELLOW;
    case Mix::Mixed: return ansi::BLUE;
    case Mix::Float: return ansi::GREEN;
    default: return ansi::RED;
    }
}

/**
 * @brief Color del motor de despacho.
 *
 * Los dos motores se alternan fila a fila, asi que sin distinguirlos hay que
 * ir leyendo la palabra para saber en cual estas.  Se usan brillos y no dos
 * tonos porque los tonos ya estan cogidos por las mezclas: apagado el motor
 * de siempre, encendido el que anade el ILP.
 */
const char *dispatch_color(bool bundles) {
    return bundles ? ansi::BR_WHITE : ansi::BR_BLACK;
}

/**
 * @brief Los TRES motores de despacho que se miden.
 *
 * Formar paquetes y reordenar dentro de ellos son dos cosas distintas -- uno
 * ahorra despachos, el otro busca fusion, independencia y localidad -- y
 * medirlas juntas no dice cual aporta que.  Con el escalar delante, cada fila
 * contesta las dos preguntas por separado: cuanto da el paquete, y cuanto anade
 * moverle las instrucciones dentro.
 */
enum class Engine : uint8_t {
    Scalar,        ///< sin paquetes, sin reordenar: el interprete de siempre
    ScalarReorder, ///< sin paquetes, con el reorden pedido -- ver abajo
    Bundles,       ///< con paquetes, en el orden del programa
    Reorder,       ///< con paquetes Y reordenados al formar
};
constexpr uint32_t kEngines = 4;

/// Los cuatro, en el orden en que se miden.
constexpr Engine kEngineList[kEngines] = {Engine::Scalar, Engine::ScalarReorder,
                                          Engine::Bundles, Engine::Reorder};

/// @brief Nombre corto del motor, para las tablas.
const char *engine_name(Engine e) {
    switch (e) {
    case Engine::Scalar: return "escalar";
    case Engine::ScalarReorder: return "esc+reord";
    case Engine::Bundles: return "paquetes";
    default: return "paq+reord";
    }
}

/// Cada motor con su brillo: apagado el de siempre, encendido el que anade el
/// ILP, y el intermedio para el paquete sin reordenar.
const char *engine_color(Engine e) {
    switch (e) {
    case Engine::Scalar: return ansi::BR_BLACK;
    case Engine::ScalarReorder: return ansi::BR_BLACK;
    case Engine::Bundles: return ansi::WHITE;
    default: return ansi::BR_WHITE;
    }
}

/**
 * @brief Es este motor el CONTROL del experimento?
 *
 * `esc+reord` pide reordenar sin formar paquetes, y reordenar solo ocurre AL
 * FORMAR uno: sin paquete no hay nada que reordenar.  Asi que tiene que dar lo
 * mismo que `escalar`, y por eso se mide -- es lo que demuestra que el eje del
 * reorden no se filtra al motor que no lo usa.  Si un dia difiere, el que esta
 * mal es el interruptor, no la medida.
 */
bool engine_is_control(Engine e) { return e == Engine::ScalarReorder; }

/**
 * @brief Escala de calor para una cifra de MIPS.
 *
 * En el barrido no hay linea base contra la que comparar -- justamente se
 * barre para descubrir donde esta el techo --, asi que el color tiene que
 * salir del valor ABSOLUTO.  Sin el, la tabla son noventa numeros de cuatro
 * cifras y hay que leerlos uno a uno; con el, el precipicio de la icache se ve
 * como una mancha roja al final de las filas, que es exactamente lo que se
 * viene a buscar.
 *
 * Los cortes salen del propio banco: el techo ronda los 380 MIPS y el suelo
 * medido es 2, asi que las bandas reparten ese rango en algo legible en vez de
 * ser un degradado continuo -- un degradado se ve bonito y no se puede leer.
 */
const char *mips_color(double mips) {
    if (mips >= 350.0) return ansi::BR_GREEN;  // el techo
    if (mips >= 300.0) return ansi::GREEN;     // sano
    if (mips >= 200.0) return ansi::BR_YELLOW; // se nota
    if (mips >= 100.0) return ansi::YELLOW;    // duele
    if (mips >= 50.0) return ansi::BR_RED;     // roto
    return ansi::RED;                          // patologico
}

/// Un caso del banco: una mezcla con una longitud de bloque recto.
struct Case {
    Mix mix;
    const char *shape;  ///< como se llama esta longitud ("apretado", "medio"..)
    uint64_t body;    ///< instrucciones rectas entre dos ramas
    double base_scalar;  ///< linea base sin use_bundles el bytecode
    double base_bundles;    ///< linea base con el optimizador del enlazador
};

/* La matriz: cada mezcla en varias longitudes.
 *
 * La LONGITUD importa por si sola, y no era evidente: un bloque recto largo
 * sale VARIAS VECES mas lento que un bucle apretado.  Al reves de lo que uno
 * diria, y la causa esta medida -- la cache de instrucciones descodificadas es
 * de @ref runtime::ICACHE_SIZE entradas y de MAPEO DIRECTO (`ICACHE_WAYS = 1`),
 * asi que un tramo mas largo que la tabla se desaloja a si mismo y cada
 * instruccion se vuelve a descodificar.  Con las 4096 de hoy, el escalar cae de
 * ~320 MIPS a 116 al pasar de 4096 rectas, y a 63 en 8192.
 *
 * Por eso hay casos a los DOS LADOS del precipicio: uno que cabe (256) y otro
 * que no (8188).  Si alguien toca el tamano o la asociatividad de la icache,
 * los dos se mueven y la forma en que lo hagan dice si mejoro o solo se
 * traslado el precipicio -- que fue lo que paso al subirla de 1024 a 4096.
 *
 * Y el precipicio NO cae en el mismo sitio para todas las mezclas: el barrido
 * lo enseña en 4096 para las enteras y en 2048 para las de coma flotante.  La
 * icache se indexa por PC, o sea por BYTES, asi que su capacidad medida en
 * INSTRUCCIONES depende de lo que ocupe cada una -- y las de coma flotante son
 * mas largas.  Sin la fila de `float` esto no se veia.
 *
 * Y la MEZCLA importa por si sola, tambien de forma no evidente: `mixta` a 260
 * da 243 MIPS, PEOR que cualquiera de sus tres componentes por separado en esa
 * misma longitud (alu 323, memoria 333, anchos 256).  El todo sale peor que la
 * peor de sus partes porque lo que se mide ahi no es el coste de las
 * instrucciones sino el del DESPACHO: con un flujo variado, el salto calculado
 * de la cabecera se vuelve impredecible para el anfitrion.  Es el caso que
 * vigila el trabajo pendiente de "despacho con salto calculado de verdad".
 *
 * Cuando las lineas base cambien de verdad se actualizan AQUI y el commit dice
 * por que: una linea base que se mueve sin explicacion deja de ser una linea
 * base. */
/* Recalibradas el 2026-09-03 tras meter diez rutas rapidas al interprete --
 * `add`/`sub`/`cmp` con inmediato, `mov` SIB, `enter`, `leave`, `push`, `pop`,
 * `fastpush`, `fastpop` y `ret` -- y componer las banderas en un solo store.
 * El escalar subio en torno a un 10%, y unas lineas base que se quedan por
 * debajo de la realidad dejan de avisar: con margen del 25% sobre una cifra un
 * 10% baja, hace falta una regresion del 32% para que salte.
 *
 * Cada valor es el CENTRAL de tres pasadas, no el mejor: una base puesta en el
 * pico da rojos que nadie puede reproducir. */
const Case kCases[] = {
    //                                          cuerpo  escalar  bundles
    {Mix::Alu, "apretado", 0, 347.0, 348.0},
    {Mix::Alu, "medio", 16, 333.0, 393.0},
    {Mix::Alu, "cabe en icache", 256, 328.0, 358.0},
    /* `no cabe` con paquetes pasa de 3,4 a 71 MIPS al mover la comprobacion de
     * arena llena al PRINCIPIO de `bundle_try_form`: estaba al final, despues
     * de descodificar 32 instrucciones por adelantado, asi que con la arena
     * llena se hacia todo ese trabajo para tirarlo.  Cinco millones de veces.
     * Sigue por debajo del resto porque ahi ya no se forma ningun paquete
     * nuevo -- eso lo arregla el reciclado de la arena, que esta pendiente. */
    {Mix::Alu, "no cabe", 8188, 62.0, 70.0},
    {Mix::Widths, "medio", 16, 278.0, 359.0},
    {Mix::Widths, "cabe en icache", 256, 248.0, 314.0},
    {Mix::Memory, "medio", 16, 300.0, 349.0},
    {Mix::Memory, "cabe en icache", 256, 323.0, 314.0},
    {Mix::Mixed, "medio", 16, 312.0, 344.0},
    {Mix::Mixed, "cabe en icache", 256, 252.0, 304.0},
    /* Coma flotante.  `vector` sale un 32% por debajo de `float` en escalar
     * (207 frente a 304): son los mismos mnemonicos sobre cuatro carriles en
     * vez de uno, asi que la diferencia ES el coste de operar empaquetado. */
    {Mix::Float, "medio", 16, 316.0, 446.0},
    /* Recorrido de `vector`, que es donde mas se ha movido todo:
     *
     *            escalar  paquetes
     *   partida      207       232   sin ninguna ruta rapida
     *   +tabla       220       232   entrada en la tabla de despacho
     *   +ISA         260       235   variante por nivel de ISA en la tabla
     *   +decode      240       300   la variante se elige al DESCODIFICAR
     *   +ancho       306       427   ...y tambien por ANCHO
     *
     * El paso de `decode` es el que arregla los paquetes: `exec_bundle` no pasa
     * por la tabla de rutas rapidas -- llama a `exec_cached` --, asi que
     * mientras la especializacion vivio solo en la tabla, el ILP no la veia.
     * Guardarla en `exec_cached` al descodificar la reparte a todos.
     *
     * El de `ancho` es el que remata: con el ancho fijo, el bucle SIMD se
     * convierte en una o dos operaciones rectas y -- con `always_inline` --
     * desaparece tambien la llamada.  De 232 a 427 en total, un +85%. */
    {Mix::Vector, "medio", 16, 306.0, 427.0},
};

/* LA BASE DE `no cabe` CON PAQUETES SON 3,4 MIPS, Y NO ES UNA ERRATA.
 *
 * Es lo que mide hoy, y esta puesto para que el test no de rojo permanente --
 * un test que siempre falla se acaba ignorando, que es como los veintiseis de
 * `tests/aot/` pasaron meses sin ejecutarse.  Pero deja constancia de que ese
 * numero es un FALLO CONOCIDO, no un comportamiento aceptado:
 *
 *   `bundle_try_form` cuelga del camino de FALLO de icache y descodifica por
 *   adelantado hasta `BUNDLE_MAX` (32) instrucciones.  Mientras casi todo
 *   acierta eso se amortiza; en un tramo recto mas largo que la icache no
 *   acierta NADA, asi que esas 32 descodificaciones se pagan por cada
 *   instruccion ejecutada.  Ademas la arena de bundles se vacia entera al
 *   llenarse, con lo que ningun paquete vive lo suficiente para que la
 *   retirada por rentabilidad (`Bundle::JUDGE_AFTER`) llegue a juzgarlo: se
 *   forma, se tira, se vuelve a formar.
 *
 * Subir la icache de 1024 a 4096 NO lo arregla: mueve el precipicio de sitio.
 * Con 1024 el agujero estaba en 1024 rectas; con 4096 esta en 4096.  Importa
 * porque los bundles estan a punto de encenderse por defecto, y "un bloque
 * recto largo" no es un caso rebuscado.
 *
 * Cuando se arregle, esta fila subira muchisimo y el test NO fallara -- solo
 * se pasa de la base por arriba --; hay que venir aqui y actualizarla. */

/// Cuanto puede bajar sin considerarse regresion.  Ver la cabecera.
constexpr double kMargin = 0.75;

/**
 * @brief Linea base de la MEDIA de cada fila del barrido.
 *
 * Las medias tambien vigilan regresiones, y de hecho vigilan MEJOR que los
 * puntos sueltos de la matriz: cada una resume doce medidas, asi que su ruido
 * es una fraccion del de cualquiera de ellas.  Por eso llevan un umbral mas
 * estrecho -- @ref kSweepMargin -- que el de un caso individual.  Un 25% de
 * margen sobre una media de doce puntos dejaria pasar cualquier cosa.
 *
 * Cubren ademas lo que la matriz no ve: la matriz mide cuatro longitudes
 * elegidas, la media recorre las doce, incluidas aquellas donde el interprete
 * se hunde.  Una regresion que solo aparezca en tramos largos no la caza
 * ningun caso de la matriz y si la media.
 *
 * CERO significa SIN CALIBRAR: informa y no falla.  Es lo que evita que una
 * fila recien anadida de rojo antes de tener una medida honesta detras.
 */
struct SweepBase {
    Mix mix;
    double scalar;  ///< media de la fila con despacho escalar
    double bundles; ///< media de la fila con paquetes
};

/* Calibradas de una tanda LIMPIA, con la maquina fria.  Importa decirlo: una
 * tanda con la maquina cargada da la mitad en las ultimas filas y nada mas que
 * en ellas, porque se recorren en orden.  Eso es lo que vigila el testigo. */
const SweepBase kSweepBases[] = {
    {Mix::Alu, 283.0, 325.0},    {Mix::Widths, 225.0, 320.0},
    {Mix::Memory, 266.0, 243.0}, {Mix::Mixed, 205.0, 309.0},
    {Mix::Float, 252.0, 359.0},  {Mix::Vector, 242.0, 334.0},
};

/// Margen de las MEDIAS.  Mas estrecho que @ref kMargin porque promediar doce
/// medidas divide el ruido: lo que en un punto suelto seria temerario, aqui es
/// lo que hace que la guardia sirva de algo.
constexpr double kSweepMargin = 0.90;

/// Linea base de la media GLOBAL del barrido.  Cero = sin calibrar.
constexpr double kGlobalBase = 280.0;

/**
 * @brief Cuanto puede haber caido el TESTIGO sin invalidar la tanda.
 *
 * El testigo es el mismo punto medido antes y despues del barrido.  Si al
 * final rinde menos de esto respecto al principio, la maquina cambio a mitad
 * de medida y lo medido no se puede comparar ni consigo mismo.
 *
 * 0,90 y no mas fino porque el propio banco tiene +-7% de ruido; y no mas
 * grueso porque lo que se vio en la practica fue una caida al 50%, que hay
 * que cazar con holgura.
 */
constexpr double kCanaryMin = 0.90;

/// @brief Base de la media de una fila, o 0 si no esta calibrada.
double sweep_base(Mix m, bool bundles) {
    for (const SweepBase &b : kSweepBases)
        if (b.mix == m) return bundles ? b.bundles : b.scalar;
    return 0.0;
}

/**
 * @brief Genera el programa con @p cuerpo instrucciones rectas por vuelta.
 *
 * Se genera y no se escribe a mano por dos razones: mil lineas no se pueden
 * revisar, y la cuenta de instrucciones que se usa para los MIPS tiene que
 * cuadrar EXACTA con lo que se ejecuta -- generandolo, las dos salen de la
 * misma constante.
 *
 * Se alternan tres opcodes y cuatro registros a proposito.  Mil `adds r0, 1`
 * seguidos medirian una cadena de dependencias serie, no el despacho: cada
 * instruccion tendria que esperar a la anterior.
 */
std::string generate(uint64_t loops, uint64_t body, Mix mix) {
    /* Los registros de trabajo son r2..r5.  `r0` cuenta las loops, `r1` las
     * descuenta y `r14` guarda la base del area de datos que usa la mezcla de
     * memoria; tocarlos rompeia la cuenta o el direccionamiento. */
    std::string straight;
    straight.reserve(body * 24);
    for (uint64_t i = 0; i < body; ++i) {
        const int r = static_cast<int>(i % 4) + 2; // r2..r5
        const std::string rn = std::to_string(r);
        const std::string otro = std::to_string(((r + 1) % 4) + 2);
        Mix m = mix;
        if (mix == Mix::Mixed)
            m = static_cast<Mix>(i % 3); // Alu, Anchos, Memoria por turnos
        switch (m) {
        case Mix::Alu:
            switch (i % 3) {
            case 0: straight += "    adds r" + rn + ", 3\n"; break;
            case 1: straight += "    subs r" + rn + ", 1\n"; break;
            default: straight += "    xor r" + rn + ", r" + otro + "\n";
            }
            break;
        case Mix::Widths: {
            /* Mismo trabajo en los cuatro anchos.  Es lo que ejercita el
             * despacho por ANCHO -- `tabla[flags_info.mode]` --, que con un
             * solo ancho el predictor acierta siempre y no se mide. */
            static const char *kSuf[4] = {"b", "w", "d", ""};
            const std::string s2 = kSuf[i % 4];
            switch (i % 3) {
            case 0: straight += "    adds r" + rn + s2 + ", 3\n"; break;
            case 1: straight += "    subs r" + rn + s2 + ", 1\n"; break;
            default:
                straight +="    xor r" + rn + s2 + ", r" + otro + s2 + "\n";
            }
            break;
        }
        case Mix::Memory:
            /* Cargas y almacenamientos por la memoria de la VM: es el camino
             * que pasa por la traduccion de direcciones y la cache de pagina.
             * El indice se mantiene pequeno para quedarse dentro de una pagina
             * -- lo que se quiere medir es el ACIERTO de cache, que es el caso
             * comun; el fallo tiene su propio coste y otra historia. */
            if (i % 2 == 0)
                straight +="    mov [r14], r" + rn + "\n";
            else
                straight +="    mov r" + rn + ", [r14]\n";
            break;

        case Mix::Float:
        case Mix::Vector: {
            /* Coma flotante, sobre el OTRO banco de registros.
             *
             * Es un camino aparte de verdad, no una variante del entero: los
             * operandos viven en ZMM y no en los registros generales, los
             * despacha `exec_instruction_float.cpp`, y NINGUNA de sus
             * instrucciones tiene ruta rapida en el interprete -- todas pasan
             * por la llamada indirecta.  Sin este caso, una regresion ahi no
             * la ve nadie.
             *
             * `Flotante` usa `fN` (escalar de 64 bits) y `Vectorial` usa
             * `ymmN`, que es el MISMO mnemonico con otro registro: el ancho lo
             * decide el nombre.  Comparar las dos filas dice lo que cuesta
             * operar cuatro carriles en vez de uno.
             *
             * Solo suma, resta y producto: con los registros a 1,0 el valor
             * oscila y se queda acotado.  Una division metida aqui daria 0/0
             * en los carriles altos -- que arrancan a cero -- y lo que se
             * mediria entonces seria el coste de propagar NaN. */
            const std::string b =
                (m == Mix::Vector) ? "ymm" : "f";
            const std::string fr = b + std::to_string((i % 4) + 2);
            const std::string fo = b + std::to_string(((i + 1) % 4) + 2);
            switch (i % 3) {
            case 0: straight += "    fadd " + fr + ", " + fo + "\n"; break;
            case 1: straight += "    fsub " + fr + ", " + fo + "\n"; break;
            default: straight += "    fmul " + fr + ", " + fo + "\n";
            }
            break;
        }
        default: break;
        }
    }
    std::string s = R"VEL(
@Format("velb")

@SpaceAddress {
    @Name("anonymous"),
    @IniAddress(0x0000000000000000),
    @EndAddress(0xFFFFFFFFFFFFFFFF)
}

@Section {
    @Name("code"),
    @SpaceAddress("anonymous"),
    @Align(0x1000)
}

@Module(bench_mips)
@Export(main)

code:
main:
    enter 0
    mov r1, %VUELTAS%
    mov r0, 0
    mov r14, 0x10000
    mov r2, 1
    mov r3, 2
    mov r4, 3
    mov r5, 4
    fmowi f2, 0x3FF0000000000000
    fmowi f3, 0x3FF0000000000000
    fmowi f4, 0x3FF0000000000000
    fmowi f5, 0x3FF0000000000000

vuelta:
%CUERPO%    adds r0, 1
    subs r1, 1
    cmps r1, 0
    jmp.jne @Absolute("code.vuelta")

    leave
    hlt
)VEL";
    const std::string mv = "%VUELTAS%";
    const size_t pv = s.find(mv);
    if (pv != std::string::npos)
        s.replace(pv, mv.size(), std::to_string(loops));
    const std::string mc = "%CUERPO%";
    const size_t pc = s.find(mc);
    if (pc != std::string::npos) s.replace(pc, mc.size(), straight);
    return s;
}

/// Instrucciones de VM que ejecuta el programa: el cuerpo recto mas las cuatro
/// del cierre de vuelta, por vuelta, mas prologo (enter, dos mov) y cierre
/// (leave, hlt).
uint64_t instruction_count(uint64_t loops, uint64_t body) {
    /* Cuatro por vuelta (el cuerpo mas `adds`, `subs`, `cmps` y el salto), mas
     * el prologo -- `enter`, seis `mov` y cuatro `fmowi` -- y el cierre --
     * `leave` y `hlt` --.
     * La cuenta va aqui y no en una constante suelta porque tiene que cambiar
     * con el programa: si alguien anade una linea al prologo y no la suma, los
     * MIPS salen mal y nada lo dice.  Y no se puede olvidar: en modo escalar
     * el test COMPARA esta cuenta con la que da la propia VM y falla si
     * difieren. */
    return loops * (body + 4) + 13;
}

/// Ensambla y enlaza @p fuente en @p salida.  @return true si se pudo.
bool prepare(const std::string &fuente, const std::string &salida) {
    try {
        vm::Lexer lexer(fuente);
        vm::Parser parser(lexer);
        auto programa = parser.parse();
        Assembly::Bytecode::Assembler asmblr;
        std::vector<uint8_t> bytecode = asmblr.assemble(programa);
        if (bytecode.empty()) return false;
        Assembly::Bytecode::Linker::LinkerOptions opts;
        /* El optimizador del ENLAZADOR se deja apagado, y no es la variable
         * que este test recorre.  Hoy `Linker::optimize_modules` es un `TODO`
         * que solo incrementa un contador, asi que encenderlo no cambiaria un
         * byte; y aunque hiciera algo, lo que aqui se mide es el motor de la
         * VM, no el que produce el bytecode.  Apagado, lo que escribe el
         * generador es exactamente lo que se ejecuta.
         *
         * La optimizacion que SI se recorre es la de la maquina virtual --
         * bundles / ILP --, y va en `ejecutar`, no aqui: no toca el bytecode,
         * cambia como se despacha. */
        opts.optimize_bytecode = false;
        opts.generate_map_file = false;
        opts.output_path = salida;
        opts.verbose = false;
        Assembly::Bytecode::Linker::Linker linker(opts);
        linker.add_assembly_unit(bytecode, &asmblr.ctx);
        linker.write_to_file(opts.output_path);
    } catch (const std::exception &e) {
        std::printf("  no se pudo preparar el programa: %s\n", e.what());
        return false;
    }
    return true;
}

/**
 * @brief Ejecuta el programa y devuelve los nanosegundos de pared.
 *
 * @param bundles si la VM forma bundles (ILP).  Es el eje que este test
 *                 recorre: mismo bytecode, dos motores de despacho.
 * @param r0       recibe el valor final de R00 (la cuenta de loops).
 * @param counted recibe las instrucciones que la VM dice haber retirado.
 * @return nanosegundos, o 0 si no llego a terminar dentro del plazo.
 */
uint64_t run_program(const std::string &velb, Engine engine, uint64_t *r0,
                  uint64_t *counted) {
    // Solo los dos motores de paquete los forman.  El control (`esc+reord`)
    // pide reordenar SIN paquetes, que es precisamente lo que no puede pasar.
    const bool bundles =
        (engine == Engine::Bundles || engine == Engine::Reorder);
    runtime::ManageVM manager(nullptr, 0);
    runtime::VM *vm = manager.loader.create_vm_instance(1);
    runtime::ProcessVM *proc = nullptr;
    try {
        proc = manager.loader.load_executable(*vm, velb);
    } catch (const std::exception &e) {
        std::printf("  no carga el ejecutable: %s\n", e.what());
        return 0;
    }
    if (proc == nullptr) return 0;

    for (const auto &s : vm->schedulers) s->has_hooks = false;

    /* El interruptor del ILP.  Apagado por defecto en el binario que se
     * entrega, asi que sin esta linea el test solo mediria un motor de los
     * dos -- y el que se queda sin medir es justo el que esta en obras. */
    proc->bundles_on = bundles;
    /* Y el reordenado, que es el otro eje.  Va por el campo del proceso y no
     * por la variable de entorno porque esa se lee una vez: con ella no se
     * podrian medir los cuatro en la misma ejecucion, y medirlos en ejecuciones
     * distintas mete de por medio el estado de la maquina. */
    proc->bundle_reorder_on =
        (engine == Engine::Reorder || engine == Engine::ScalarReorder);

    /* Y CONTAR lo que hace, que se pide aparte.
     *
     * La telemetria del reordenamiento no viene de serie: el planificador tiene
     * dos instanciaciones y solo la que explica lleva contadores, asi que hay
     * que pedirla o el resumen sale a cero sin que nadie avise.  Aqui se pide
     * porque este test IMPRIME esos numeros; el coste es una rama por paquete
     * formado, no por instruccion ejecutada, y esta prueba mide instrucciones
     * por segundo -- lo que se mide no cambia --. */
    proc->bundle_stats_on = true;

    /* Se cronometra con NUESTRO reloj, no con `steady_clock`.  En Windows ese
     * sale de QueryPerformanceCounter y salta de 100 en 100 ns; aqui se miden
     * decenas de milisegundos, asi que daria igual -- pero el numero que este
     * test defiende es el mismo que la VM publica en `--stats`, y medirlos con
     * dos relojes distintos es como se llega a que no cuadren. */
    const uint64_t t0 = util::reloj::ahora();
    vm->make_ready(proc->pid);
    vm->start();
    /* El plazo, con el mismo reloj que todo lo demas.  La objecion habitual al
     * contador de ciclos -- que no avanza mientras el nucleo duerme -- no
     * aplica aqui: la espera de abajo GIRA, no duerme. */
    const uint64_t plazo_ns = 120ULL * 1000000000ULL;
    /* Se espera GIRANDO, no durmiendo.  Un `sleep_for(200 us)` mete hasta
     * 200 us de tiempo muerto entre que el programa termina y este hilo se
     * entera, y ese hueco entra en el cronometro: sobre los 13 ms del caso mas
     * corto es un 1,5% de MIPS que se pierden por no mirar.  Peor aun, el
     * sesgo NO es constante -- pesa mas cuanto mas rapido va el caso --, o sea
     * que castiga justo lo que se quiere medir.
     *
     * Girar cuesta un nucleo, y aqui sobra: la VM corre en sus propios hilos y
     * la maquina tiene mas de uno.  `yield()` cede el turno por si el
     * planificador del sistema quisiera el nucleo, sin llegar a dormirse.
     *
     * La comprobacion del plazo va cada 4096 loops y no en cada una: leer el
     * reloj del sistema en el bucle de espera es lo unico caro que hay aqui. */
    for (uint64_t giro = 0;
         proc->state != runtime::HALT && proc->state != runtime::DEAD; ++giro) {
        if ((giro & 0xFFF) == 0xFFF &&
            (uint64_t)util::reloj::a_ns(util::reloj::ahora() - t0) >=
                plazo_ns) {
            vm->stop();
            return 0; // no termino: cronometrarlo no diria nada
        }
        std::this_thread::yield();
    }
    const uint64_t t1 = util::reloj::ahora();
    *r0 = proc->registers.regs[0].raw();
    /* Lo que la VM dice haber retirado.  Se lee ANTES de `stop()`, mientras
     * los planificadores siguen vivos. */
    *counted = 0;
    for (const auto &s : vm->schedulers)
        *counted += s->profiler_instr_counter + s->profiler_jit_instr_counter;
    vm->stop();
    return (uint64_t)util::reloj::a_ns(t1 - t0);
}

/**
 * @brief Mide un punto del banco y devuelve sus MIPS (0 si no se pudo).
 *
 * Es lo que comparten la matriz de regresion y el barrido del techo: si cada
 * uno midiera a su manera, sus cifras no se podrian comparar entre si.
 */
double measure(uint64_t loops, uint64_t body, Mix mix, Engine engine,
             int repeats, uint64_t *instrs_out) {
    const uint64_t v =
        body == 0 ? loops : (loops * 4) / (body + 4);
    const std::string velb = "test_mips_bench.velb";
    /* POR QUE fallo, no solo que fallo.
     *
     * Devolver 0.0 desde cuatro sitios distintos ponia un `-` en la tabla y
     * dejaba al que la lee eligiendo entre cuatro causas que llevan a sitios
     * opuestos: no se pudo generar el programa, no arranco, el reloj no midio,
     * o DIO OTRO RESULTADO -- que es un fallo de correccion y no de medida --.
     * Un guion mudo hace perder una tarde distinguiendolas a mano. */
    if (!prepare(generate(v, body, mix), velb)) {
        std::fprintf(stderr, "[medida] no se pudo generar/enlazar el programa "
                             "(mezcla=%s cuerpo=%llu)\n",
                     mix_name(mix), (unsigned long long)body);
        return 0.0;
    }

    uint64_t r0 = 0, counted = 0;
    run_program(velb, engine, &r0, &counted); // calentamiento, se tira

    uint64_t best_ns = UINT64_MAX, instrs = 0;
    for (int i = 0; i < repeats; ++i) {
        const uint64_t ns = run_program(velb, engine, &r0, &counted);
        if (ns == 0) {
            std::fprintf(stderr, "[medida] el programa no llego a ejecutarse "
                                 "(mezcla=%s cuerpo=%llu despacho=%s)\n",
                         mix_name(mix), (unsigned long long)body,
                         engine_name(engine));
            return 0.0;
        }
        if (r0 != v) {
            std::fprintf(stderr,
                         "[medida] RESULTADO DISTINTO: r0=%llu y se esperaba "
                         "%llu (mezcla=%s cuerpo=%llu despacho=%s).  Esto NO "
                         "es ruido de medida\n",
                         (unsigned long long)r0, (unsigned long long)v,
                         mix_name(mix), (unsigned long long)body,
                         engine_name(engine));
            return 0.0;
        }
        if (ns < best_ns) {
            best_ns = ns;
            instrs = counted;
        }
    }
    if (best_ns == UINT64_MAX) return 0.0;
    if (instrs_out != nullptr) *instrs_out = instrs;
    return (double)instrs * 1000.0 / (double)best_ns;
}

/**
 * @brief Barre longitudes y mezclas buscando el TECHO del interprete.
 *
 * La matriz de regresion comprueba puntos FIJOS -- es lo que tiene que hacer,
 * porque una linea base solo significa algo si se mide siempre igual --, pero
 * con eso no se responde "cuantos MIPS alcanza".  El maximo no esta en un
 * punto que se pueda elegir de antemano: depende de donde caiga el precipicio
 * de la icache de instrucciones descodificadas, que se mueve con el tamano y
 * la asociatividad, y del motor de despacho.
 *
 * Este modo no falla nunca: informa.  Es una herramienta de medida, no una
 * guardia, y mezclar las dos cosas es como se acaba con un test que da rojo
 * porque la maquina iba ocupada.
 *
 * LO QUE DESTAPO AL ESCRIBIRLO, y por eso el barrido llega hasta 1024:
 * `memoria` + `bundles` + 1024 instrucciones rectas da **2 MIPS**, cuando el
 * resto de esa fila va a 320.  No es ruido, y el mecanismo se sigue entero:
 *
 *   - La icache de instrucciones descodificadas tiene 1024 entradas y es de
 *     MAPEO DIRECTO, asi que un bloque recto de mas de 1024 falla SIEMPRE.
 *   - `bundle_try_form` cuelga del camino de FALLO de icache, y cada llamada
 *     descodifica por adelantado hasta `BUNDLE_MAX` (32) instrucciones.
 *   - Con todo fallando, esas 32 descodificaciones se pagan por cada
 *     instruccion ejecutada, y no se amortizan nunca.
 *   - La arena de bundles se vacia ENTERA al llenarse, asi que ademas ningun
 *     paquete vive lo bastante como para que la retirada por rentabilidad
 *     (`JUDGE_AFTER`) llegue a juzgarlo.
 *
 * La cabecera de `bundle.h` dice que la formacion "esta acotada por el numero
 * de cabeceras de traza distintas, no por lo que se ejecute".  Es cierto
 * MIENTRAS la icache retenga esas cabeceras -- y este es el caso en que no las
 * retiene.  Importa porque los bundles estan a punto de encenderse por
 * defecto: el caso patologico no es raro, es "un bloque recto largo".
 */
int sweep_peak(uint64_t loops, int repeats) {
    /* Llega hasta 8192 rectas porque el precipicio esta en `ICACHE_SIZE`
     * (4096), y un barrido que se pare antes no lo ve.  Cuando alguien mueva
     * ese valor, el ultimo punto tiene que quedar POR ENCIMA o el barrido deja
     * de medir lo unico que solo el mide. */
    const uint64_t kLengths[] = {0,    4,    12,   28,   60,   124,
                                252,  508,  1020, 2044, 4092, 8188};
    const Mix kMixes[] = {Mix::Alu,      Mix::Widths,
                               Mix::Memory,  Mix::Mixed,
                               Mix::Float, Mix::Vector};

    const char *RESET = ansi::c(ansi::RESET);
    const char *BOLD = ansi::c(ansi::BOLD);
    const char *DIM = ansi::c(ansi::DIM);
    const char *VERDE = ansi::c(ansi::BR_GREEN);
    const char *ROJO = ansi::c(ansi::BR_RED);

    /// Fallos de las MEDIAS.  Los puntos sueltos nunca fallan, y estos solo
    /// cuentan si el testigo dice que la tanda fue comparable.
    int avg_failures = 0;

    std::printf("%s=== test_mips: barrido del techo ===%s\n", BOLD, RESET);
    std::printf("%s  %llu vueltas por punto, mejor de %d (mas una de "
                "calentamiento)%s\n",
                DIM, (unsigned long long)loops, repeats, RESET);
    /* La icache que hay, en la salida.  Es la variable que decide la forma de
     * este barrido -- donde cae el precipicio es donde se acaba la tabla --,
     * asi que sin ella las cifras no se pueden comparar entre dos maquinas ni
     * entre dos configuraciones. */
    std::printf("%s  icache: %u entradas x %zu B = %zu KB por proceso, %d "
                "via(s)%s\n\n",
                DIM, (unsigned)runtime::ICACHE_SIZE,
                sizeof(runtime::DecodedInstr),
                (size_t)runtime::ICACHE_SIZE * sizeof(runtime::DecodedInstr) /
                    1024,
                (int)ICACHE_WAYS, RESET);

    /* Que son los numeros de la cabecera.  Sin esto la tabla es ilegible: son
     * MIPS por longitud, pero de que longitud no lo dice ninguna columna. */
    std::printf("%s  Cada columna es un TRAMO RECTO: cuantas instrucciones "
                "seguidas se ejecutan\n"
                "  sin que haya un salto.  El bucle es siempre el mismo y el "
                "trabajo total\n"
                "  tambien (~%llu instrucciones); lo unico que cambia es cada "
                "cuanto se rompe\n"
                "  la linea recta.  El precipicio cae al pasar de %u, que es "
                "donde se acaba\n"
                "  la icache: a partir de ahi el tramo se desaloja a si mismo "
                "y cada\n"
                "  instruccion se vuelve a descodificar.%s\n\n",
                DIM, (unsigned long long)(loops * 4),
                (unsigned)runtime::ICACHE_SIZE, RESET);
    std::printf("%s  Color de la cifra: %s>=350%s %s>=300%s %s>=200%s "
                "%s>=100%s %s>=50%s %s<50%s   (MIPS)%s\n",
                DIM, ansi::c(ansi::BR_GREEN), DIM, ansi::c(ansi::GREEN), DIM,
                ansi::c(ansi::BR_YELLOW), DIM, ansi::c(ansi::YELLOW), DIM,
                ansi::c(ansi::BR_RED), DIM, ansi::c(ansi::RED), DIM, RESET);

    std::printf("%s  %-8s %-9s", DIM, "mezcla", "despacho");
    for (uint64_t length : kLengths)
        std::printf("%6llu", (unsigned long long)(length + 4));
    std::printf("%s%7s%s\n", BOLD, "media", RESET);
    const size_t kPoints = sizeof(kLengths) / sizeof(kLengths[0]);
    std::printf("%s  %s%s\n", DIM,
                std::string(25 + 6 * kPoints, '-').c_str(), RESET);

    /* TESTIGO.  Se mide el MISMO punto antes y despues del barrido.
     *
     * Hace falta porque el barrido dura minutos de carga sostenida y la
     * maquina no rinde igual al principio que al final: medido aqui, las
     * ultimas filas salian a la MITAD que las primeras -- `vector` con
     * paquetes daba 230 dentro del barrido y 448 medido aparte --.  Como las
     * filas se recorren en orden, eso no se reparte: castiga siempre a las
     * mismas, y sin avisar.
     *
     * Con un testigo el fallo deja de ser silencioso.  Si el segundo se aleja
     * del primero, la tanda entera es incomparable y se dice; las medias no
     * cuentan como regresion en ese caso, porque compararlas con una linea
     * base seria comparar dos maquinas distintas. */
    const double canary_start =
        measure(loops, 16, Mix::Alu, Engine::Scalar, repeats, nullptr);

    double peak = 0.0;
    const char *peak_mix = "?";
    const char *peak_dispatch = "?";
    uint64_t peak_length = 0;

    /* Medias.  El techo dice de cuanto es CAPAZ el interprete en su mejor
     * punto, que es una cifra util pero parcial: se alcanza en una longitud
     * concreta y con un motor concreto.  La media de la fila resume como se
     * comporta esa clase de operaciones a lo largo de TODAS las longitudes,
     * incluidas aquellas en las que se hunde -- que es justo lo que el maximo
     * esconde.  Y la global resume el banco entero en un numero, que es lo que
     * se compara entre dos versiones de un vistazo.
     *
     * Es la media ARITMETICA de los puntos medidos, sin quitar los
     * patologicos: taparlos daria una cifra mas bonita y menos cierta. */
    double global_sum = 0.0;
    int global_n = 0;

    for (Mix m : kMixes)
        for (uint32_t modo = 0; modo < kEngines; ++modo) {
            const Engine engine = kEngineList[modo];
            std::printf("  %s%-8s%s %s%-10s%s", ansi::c(mix_color(m)),
                        modo == 0 ? mix_name(m) : "", RESET,
                        ansi::c(engine_color(engine)), engine_name(engine),
                        RESET);
            double row_sum = 0.0;
            int row_n = 0;
            for (uint64_t length : kLengths) {
                const double mips = measure(loops, length, m, engine, repeats,
                                          nullptr);
                if (mips <= 0.0) {
                    std::printf("%s%6s%s", DIM, "-", RESET);
                    continue;
                }
                std::printf("%s%6.0f%s", ansi::c(mips_color(mips)), mips,
                            RESET);
                row_sum += mips;
                ++row_n;
                if (mips > peak) {
                    peak = mips;
                    peak_mix = mix_name(m);
                    peak_dispatch = engine_name(engine);
                    peak_length = length + 4;
                }
            }
            if (row_n > 0) {
                const double row_avg = row_sum / (double)row_n;
                /* Las lineas base solo existen para los dos motores que habia.
                 * Los dos nuevos -- el control y el reordenado -- se miden y se
                 * ensenan, pero todavia no validan: calibrarlos con una sola
                 * corrida seria fijar como verdad el ruido de esta maquina. */
                const double base =
                    (engine == Engine::Scalar || engine == Engine::Bundles)
                        ? sweep_base(m, engine == Engine::Bundles)
                        : 0.0;
                /* Sin calibrar, la media sale con su color de calor y ya.  Con
                 * base, el color pasa a decir si CUMPLE, que es otra pregunta:
                 * 400 MIPS estan muy bien salvo si ayer eran 500. */
                const char *color = ansi::c(mips_color(row_avg));
                if (base > 0.0)
                    color = ansi::c(row_avg < base * kSweepMargin ? ansi::BR_RED
                                    : row_avg < base ? ansi::BR_YELLOW
                                                     : ansi::BR_GREEN);
                std::printf("%s%s%7.0f%s", BOLD, color, row_avg, RESET);
                if (base > 0.0 && row_avg < base * kSweepMargin) {
                    std::printf("  %sREGRESION: la media cayo de %.0f a %.0f "
                                "(%.0f%% del minimo)%s",
                                ROJO, base, row_avg, kSweepMargin * 100.0,
                                RESET);
                    ++avg_failures;
                }
                global_sum += row_sum;
                global_n += row_n;
            } else {
                std::printf("%s%7s%s", DIM, "-", RESET);
            }
            std::printf("\n");
        }

    std::printf("\n%s%s  TECHO: %.1f MIPS%s  %s(mezcla %s, %llu instrucciones "
                "rectas, despacho %s)%s\n",
                BOLD, VERDE, peak, RESET, DIM, peak_mix,
                (unsigned long long)peak_length, peak_dispatch, RESET);
    if (global_n > 0) {
        const double global_avg = global_sum / (double)global_n;
        const bool mal =
            kGlobalBase > 0.0 && global_avg < kGlobalBase * kSweepMargin;
        std::printf("%s%s  MEDIA:  %.1f MIPS%s  %s(los %d puntos del barrido, "
                    "sin descartar ninguno)%s\n",
                    BOLD, ansi::c(mal ? ansi::BR_RED : mips_color(global_avg)),
                    global_avg, RESET, DIM, global_n, RESET);
        if (mal) {
            std::printf("  %sREGRESION: la media global cayo de %.0f a %.0f%s\n",
                        ROJO, kGlobalBase, global_avg, RESET);
            ++avg_failures;
        }
    }

    /* El testigo, otra vez.  Lo que diga decide si lo de arriba se puede
     * comparar con nada. */
    const double canary_end =
        measure(loops, 16, Mix::Alu, Engine::Scalar, repeats, nullptr);
    const double drift =
        canary_start > 0.0 ? canary_end / canary_start : 0.0;
    std::printf("%s  testigo: %.0f MIPS al empezar, %.0f al terminar "
                "(%+.1f%%)%s\n",
                DIM, canary_start, canary_end, (drift - 1.0) * 100.0, RESET);

    if (drift < kCanaryMin) {
        std::printf(
            "\n  %sLA MAQUINA SE FRENO DURANTE EL BARRIDO.%s  %sEl mismo punto "
            "rinde un\n"
            "  %.0f%% de lo que rendia al empezar, asi que las filas de abajo "
            "de la tabla\n"
            "  midieron una maquina distinta de las de arriba: NO son "
            "comparables entre\n"
            "  si ni con ninguna linea base.  Las medias NO cuentan como "
            "regresion en\n"
            "  esta tanda.  Causa habitual: carga sostenida durante varios "
            "minutos, o\n"
            "  algo mas ocupando la maquina.%s\n",
            ROJO, RESET, DIM, drift * 100.0, RESET);
        return 0; // se informa, pero no se acusa a nadie con datos invalidos
    }
    return avg_failures;
}

} // namespace

int main(int argc, char **argv) {
    uint64_t loops = 2'000'000;
    int repeats = 3;
    const char *solo = nullptr;
    /* Sin argumentos se ejercita ENTERO: la matriz de regresion y el barrido
     * del techo.  Las banderas son para iterar mientras se investiga algo, no
     * para elegir que se prueba -- una prueba que solo hace su trabajo si le
     * pasas el argumento correcto acaba corriendo a medias, que es como los
     * veintiseis de `tests/aot/` pasaron meses sin ejecutarse. */
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--vueltas") == 0 && i + 1 < argc)
            loops = std::strtoull(argv[++i], nullptr, 10);
        else if (std::strcmp(argv[i], "--repetir") == 0 && i + 1 < argc)
            repeats = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--solo") == 0 && i + 1 < argc)
            solo = argv[++i];
        else {
            std::fprintf(stderr,
                         "uso: test_mips [--vueltas N] [--repetir N]\n"
                         "                [--solo <mezcla>:<tramo>:<despacho>]\n"
                         "  mezcla:   alu | anchos | memoria | mixta | float "
                         "| vector\n"
                         "  tramo:    instrucciones seguidas sin salto\n"
                         "  despacho: escalar | esc+reord | paquetes "
                         "| paq+reord\n");
            return 2;
        }
    }

    /* `--solo` mide UN punto y se va.  Existe para poder poner un perfilador
     * encima: el banco entero mezcla veinte configuraciones y, peor aun, las
     * celdas patologicas del barrido -- las de 1 a 3 MIPS -- se llevan la mayor
     * parte del tiempo de pared, con lo que un perfil de la tanda completa
     * describe el caso roto y no el que se quiere mejorar. */
    if (solo != nullptr) {
        char mezcla_txt[32] = "", despacho_txt[32] = "";
        unsigned tramo = 0;
        if (std::sscanf(solo, "%31[^:]:%u:%31s", mezcla_txt, &tramo,
                        despacho_txt) != 3) {
            std::fprintf(stderr, "--solo: se esperaba "
                                 "<mezcla>:<tramo>:<despacho>\n");
            return 2;
        }
        Mix m;
        if (std::strcmp(mezcla_txt, "alu") == 0) m = Mix::Alu;
        else if (std::strcmp(mezcla_txt, "anchos") == 0) m = Mix::Widths;
        else if (std::strcmp(mezcla_txt, "memoria") == 0) m = Mix::Memory;
        else if (std::strcmp(mezcla_txt, "mixta") == 0) m = Mix::Mixed;
        else if (std::strcmp(mezcla_txt, "float") == 0) m = Mix::Float;
        else if (std::strcmp(mezcla_txt, "vector") == 0) m = Mix::Vector;
        else {
            std::fprintf(stderr, "--solo: mezcla '%s' desconocida\n",
                         mezcla_txt);
            return 2;
        }
        // Los cuatro motores por nombre, el mismo que sale en la tabla.
        Engine engine = Engine::Scalar;
        bool engine_ok = false;
        for (Engine e : kEngineList)
            if (std::strcmp(despacho_txt, engine_name(e)) == 0) {
                engine = e;
                engine_ok = true;
            }
        if (!engine_ok) {
            std::fprintf(stderr,
                         "--solo: despacho '%s' desconocido (escalar, "
                         "esc+reord, paquetes, paq+reord)\n",
                         despacho_txt);
            return 2;
        }
        if (tramo < 4) {
            std::fprintf(stderr, "--solo: el tramo minimo es 4 (el propio "
                                 "cierre del bucle)\n");
            return 2;
        }
        uint64_t instrs = 0;
        const double mips =
            measure(loops, tramo - 4, m, engine, repeats, &instrs);
        if (mips <= 0.0) {
            std::fprintf(stderr, "--solo: la medida fallo\n");
            return 1;
        }
        std::printf("%s %u %s -> %.1f MIPS  (%llu instr)\n", mezcla_txt, tramo,
                    despacho_txt, mips, (unsigned long long)instrs);
        return 0;
    }

    ansi::init();
    const char *RESET = ansi::c(ansi::RESET);
    const char *BOLD = ansi::c(ansi::BOLD);
    const char *DIM = ansi::c(ansi::DIM);
    const char *ROJO = ansi::c(ansi::BR_RED);
    const char *VERDE = ansi::c(ansi::BR_GREEN);
    const char *AMBAR = ansi::c(ansi::BR_YELLOW);

    std::printf("%s=== test_mips ===%s\n", BOLD, RESET);
    std::printf("%s  %llu vueltas por caso, mejor de %d pasadas%s\n\n", DIM,
                (unsigned long long)loops, repeats, RESET);

    /* La cabecera y la regla salen atenuadas para que el ojo caiga en los
     * numeros, que es lo que se viene a mirar. */
    std::printf("%s  %-8s %-16s %6s %-10s %9s  %9s  %10s  %9s%s\n", DIM,
                "mezcla", "bloque", "recto", "despacho", "MIPS", "vs base",
                "instr", "ms", RESET);
    std::printf("%s  %s%s\n", DIM, std::string(88, '-').c_str(), RESET);

    int failures = 0;
    for (const Case &c : kCases)
    for (uint32_t modo = 0; modo < kEngines; ++modo) {
        const Engine engine = kEngineList[modo];
        const bool use_bundles = (engine != Engine::Scalar &&
                                  engine != Engine::ScalarReorder);
        const char *mode_name = engine_name(engine);
        /* Solo los dos motores calibrados validan.  Los dos nuevos se miden y
         * se ensenan; ponerles linea base con una sola corrida seria fijar como
         * verdad el ruido de esta maquina. */
        const double base = (engine == Engine::Bundles)  ? c.base_bundles
                            : (engine == Engine::Scalar) ? c.base_scalar
                                                         : 0.0;

        /* Las loops se reparten para que los tres casos ejecuten un numero
         * de instrucciones PARECIDO.  Sin esto, el caso recto haria mil veces
         * mas trabajo y tardaria mil veces mas. */
        const uint64_t v = c.body == 0
                               ? loops
                               : (loops * 4) / (c.body + 4);
        const std::string velb = "test_mips_bench.velb";
        if (!prepare(generate(v, c.body, c.mix), velb)) return 1;
        const uint64_t expected_count = instruction_count(v, c.body);

        /* CALENTAMIENTO, que se tira.  La primera pasada de un caso paga lo
         * que ninguna de las siguientes vuelve a pagar: fallos de pagina al
         * tocar la memoria de la VM por primera vez, la icache de
         * instrucciones descodificadas vacia, el codigo del interprete aun sin
         * subir a la cache del anfitrion y la CPU todavia en frecuencia baja.
         *
         * Se veia: con una sola pasada aparecian caidas del 25% que no se
         * reproducian.  Como aqui se busca el TECHO -- de cuanto es capaz el
         * interprete, no cuanto tarda en arrancar --, la pasada fria no dice
         * nada de lo que se pregunta. */
        {
            uint64_t r0 = 0, counted = 0;
            run_program(velb, engine, &r0, &counted);
        }

        uint64_t best_ns = UINT64_MAX;
        uint64_t instrs = 0;
        for (int i = 0; i < repeats; ++i) {
            uint64_t r0 = 0, counted = 0;
            const uint64_t ns = run_program(velb, engine, &r0, &counted);
            if (ns == 0) {
                std::printf("  %s%-8s %-16s %6s %-10s  FALLO: no termino en el "
                            "plazo%s\n",
                            ROJO, mix_name(c.mix), c.shape, "",
                            mode_name, RESET);
                ++failures;
                break;
            }
            /* Que el resultado sea el esperado importa tanto como el tiempo: un
             * bucle que termina antes de la cuenta saldria como una mejora
             * espectacular en vez de como el fallo que es. */
            if (r0 != v) {
                std::printf("  %s%-8s %-16s %6s %-10s  FALLO: R0 = %llu, se "
                            "esperaba %llu%s\n",
                            ROJO, mix_name(c.mix), c.shape, "",
                            mode_name, (unsigned long long)r0,
                            (unsigned long long)v, RESET);
                ++failures;
                break;
            }
            /* Lo que la VM dice haber retirado tiene que ser EXACTAMENTE lo
             * que el generador escribio, EN LOS DOS MODOS.  Es una
             * comprobacion del contador, no del rendimiento, y aqui sale
             * gratis.
             *
             * Hace falta porque ya fallo dos veces, y de las dos maneras
             * posibles:
             *
             *   - Por ARRIBA: el contador se declaraba como "se incrementa
             *     cada 256 instrucciones" y en realidad iba de una en una, asi
             *     que todo el que multiplicaba por 256 daba MIPS 256 veces mas
             *     altos.
             *   - Por ABAJO: con bundles, `exec_bundle` retiraba N
             *     instrucciones y el planificador contaba UNA, porque el
             *     paquete no tocaba el contador.  Los MIPS bajaban cuanto
             *     MEJOR fuera el ILP.
             *
             * Las dos sobrevivieron por lo mismo: nadie comparaba la cifra con
             * nada.  Comparandola con el generador, cualquiera de las dos sale
             * a la primera. */
            if (counted != expected_count) {
                std::printf("  %s%-8s %-16s %6s %-10s  FALLO: la VM conto %llu "
                            "instrucciones y se generaron %llu%s\n",
                            ROJO, mix_name(c.mix), c.shape, "",
                            mode_name, (unsigned long long)counted,
                            (unsigned long long)expected_count, RESET);
                ++failures;
                break;
            }
            if (ns < best_ns) {
                best_ns = ns;
                instrs = counted;
            }
        }
        if (best_ns == UINT64_MAX) continue;

        /* El MEJOR de varias pasadas, no la media: lo que estorba en una
         * maquina compartida solo puede hacer que tarde MAS, asi que el minimo
         * es la pasada que menos interferencia sufrio. */
        const double mips = (double)instrs * 1000.0 / (double)best_ns;
        const double minimo = base * kMargin;
        const double deviation = (mips / base - 1.0) * 100.0;

        /* Tres estados, no dos.  Por encima de la base es verde; por debajo
         * pero dentro del margen es ambar -- no falla, pero se ve --; por
         * debajo del margen es rojo y cuenta como fallo.  El ambar es lo que
         * permite notar una caida que aun no ha llegado a regresion. */
        const char *color = mips < minimo    ? ROJO
                            : deviation < 0.0   ? AMBAR
                                             : VERDE;

        /* La mezcla y el bloque solo se escriben en la primera de las dos
         * filas: repetirlos convierte la tabla en una pared de texto donde el
         * par de modos deja de leerse como un par. */
        const bool primera = (modo == 0);
        char recto[16] = "";
        if (primera)
            std::snprintf(recto, sizeof(recto), "%llu",
                          (unsigned long long)(c.body + 4));
        /* Sin linea base no hay desviacion que ensenar.  Se imprimia igual, y
         * dividir entre cero daba `+inf%` en toda la columna de los motores sin
         * calibrar -- un numero que no significa nada ocupando el sitio del que
         * si. */
        char vs[16];
        if (base > 0.0)
            std::snprintf(vs, sizeof(vs), "%+7.1f%%", deviation);
        else
            std::snprintf(vs, sizeof(vs), "%8s", "-");

        std::printf("  %s%-8s%s %-16s %6s %s%-10s%s %s%9.1f%s  %s%8s%s  "
                    "%s%10llu  %9.1f%s\n",
                    ansi::c(mix_color(c.mix)), primera ? mix_name(c.mix) : "",
                    RESET, primera ? c.shape : "", recto,
                    ansi::c(engine_color(engine)), mode_name, RESET, color,
                    mips, RESET, color, vs, RESET, DIM,
                    (unsigned long long)instrs, best_ns / 1e6, RESET);

        if (mips < minimo) {
            std::printf("  %s%*s^ REGRESION: por debajo de %.0f MIPS (%.0f%% "
                        "de la base %.0f)%s\n",
                        ROJO, 45, "", minimo, kMargin * 100.0, base, RESET);
            ++failures;
        }
    }

    /* El barrido corre SIEMPRE, tambien cuando la matriz ha fallado: si algo
     * ha caido, la forma del techo es justo lo que dice por donde.
     *
     * Sus MEDIAS si cuentan como fallo -- resumen doce medidas cada una, asi
     * que son mas fiables que cualquier punto suelto --; los puntos
     * individuales no, que ahi el ruido manda. */
    std::printf("\n");
    failures += sweep_peak(loops, repeats);

    if (failures > 0) {
        std::printf(
            "\n%s  Por donde empezar a mirar:\n"
            "    - Caida GENERAL: una funcion caliente dejo de inlinarse (es "
            "lo que\n"
            "      costaba el 29%% antes de arreglarlo), o un opcode se salio "
            "de la\n"
            "      tabla de rutas rapidas del interprete y volvio a la llamada "
            "indirecta.\n"
            "      `VESTA_SLOW_OPS=1` dice CUAL: cuenta lo que pasa por el "
            "camino lento.\n"
            "    - Cae SOLO el apretado: el camino de SALTO.\n"
            "    - Cae solo `memoria`: la traduccion de direcciones.\n"
            "    - Cae solo `no cabe`: el tamano de la icache, o la formacion "
            "de paquetes.%s\n",
            DIM, RESET);
        std::printf("\n%s%s=== test_mips: %d fallidos ===%s\n", BOLD, ROJO,
                    failures, RESET);
        return 1;
    }
    std::printf("\n%s%s=== test_mips: OK ===%s\n", BOLD, VERDE, RESET);
    return 0;
}
