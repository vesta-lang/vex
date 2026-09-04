/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/coste/test_icache_conflictos.cpp
 * @brief Se pisan entre si las instrucciones de un bucle en la icache?
 *        SUPERADO por @c test_icache_real.  Se conserva como registro.
 *
 * SUS RESULTADOS NO VALEN
 * -----------------------
 * Este test da mal el ORDEN.  Marcaba `tight_loop` entre los peores y, medido
 * ejecutando, `tight_loop` no falla NI UNA VEZ.  El fallo no es un despiste en
 * la simulacion: es que la pregunta no se puede contestar sin ejecutar.
 *
 * Mirando el bytecode quieto se puede saber que instrucciones caen en el mismo
 * conjunto, pero no CUANTAS VECES se ejecuta cada bucle -- ni si se ejecuta.
 * Un bucle que se pisa entero y da dos vueltas sale aqui igual de rojo que el
 * bucle caliente que da veinte millones, y el segundo es el unico que cuesta
 * tiempo.  Ponderar por frecuencia es justo lo que un analisis estatico no
 * tiene.
 *
 * Tampoco distinguia entre lo que ejecuta el INTERPRETE y lo que se va al JIT.
 * La icache es del interprete: lo que `callvm` despacha a codigo compilado no
 * pasa por ella, y aqui todo el bytecode contaba por igual.
 *
 * QUE USAR
 * --------
 * @c test_icache_real, que carga el `.velb`, lo ejecuta sobre un `ProcessVM`
 * de verdad y pregunta a la misma @c icache_lookup que usa el scheduler.  Sus
 * numeros son medidos, con la frecuencia real de cada PC, y con el JIT
 * apagado para que el interprete sea quien ejecuta.
 *
 * POR QUE SIGUE AQUI
 * ------------------
 * No estorba a nadie: es un ejecutable de test aparte, no entra en el
 * compilador ni en la VM.  Y deja constancia de un error que es facil repetir
 * -- contar conflictos posibles y llamarlo coste --, con al lado la medida que
 * lo desmiente.  Borrarlo dejaria la conclusion sin el camino que llevo a
 * ella.
 *
 * La pregunta que se hacia
 * ------------------------
 * La icache de instrucciones descodificadas es de mapeo DIRECTO, indexada por
 * `pc & (ICACHE_SIZE-1)` sobre la direccion en BYTES.  Un fallo obliga a
 * redescodificar, y el modelo de coste dice que descodificar cuesta entre 15 y
 * 25 veces mas que ejecutar.
 *
 * Pero eso solo importa si los fallos se REPITEN.  Con mapeo directo, dos PCs
 * cualesquiera dentro de una ventana de ICACHE_SIZE BYTES caen en ranuras
 * distintas: un bucle que no pase de ahi no tiene ni un conflicto y su decode
 * se paga una vez.  El coste del decode solo se sufre si el cuerpo del bucle es
 * mas largo -- y entonces se paga en CADA vuelta.
 *
 * OJO CON LA UNIDAD, que es de donde salen las sorpresas: la ventana se mide en
 * BYTES de bytecode, no en instrucciones.  Con instrucciones de cuatro a once
 * bytes, un paso REGULAR solo alcanza una fraccion de las ranuras, y ahi el
 * conflicto no es por capacidad sino por indice -- la cache puede estar al 9%
 * y colisionar el 100% --.
 *
 * Esa era la idea: contestar si pasa de verdad, y cuanto ganaria cada
 * alternativa.  Contesta lo primero -- si hay bucles que se pisan -- pero no
 * lo segundo, porque para eso hace falta saber cuanto se ejecuta cada uno.
 *
 * Como
 * ----
 * Estatico, sobre el `.velb`: no ejecuta nada y no toca la VM.  Desensambla con
 * el desensamblador del proyecto, busca los saltos hacia ATRAS -- que son los
 * bucles -- y simula la icache sobre cada cuerpo.
 *
 * El modelo de fallos, y por que es este:  en regimen estacionario, si una
 * ranura la comparten K instrucciones del cuerpo y las K se ejecutan en cada
 * vuelta, cada una desaloja a la anterior y las K fallan SIEMPRE.  Una ranura
 * con una sola instruccion acierta siempre despues de la primera vuelta.  Con
 * N vias, una ranura con K <= N tampoco falla.
 *
 * Es una cota OPTIMISTA: supone que todas las instrucciones del cuerpo se
 * ejecutan en cada vuelta.  Un cuerpo con ramas ejecuta menos, asi que los
 * conflictos reales pueden ser menores.  Se dice, no se esconde.
 *
 * Y ahi estaba el agujero, visto en retrospectiva: la salvedad se escribio
 * pensando en un margen de error, cuando en realidad es lo que decide el
 * resultado entero.  Entre "todas las instrucciones se ejecutan siempre" y lo
 * que hace un programa de verdad no hay un margen: hay un orden distinto.
 *
 * TODO LO PROBADO, Y QUE SALIO
 * ============================
 * Esta es la tabla entera, no solo la conclusion.  Se deja porque cada fila
 * cuesta una tarde de reconstruir, y porque varias parecen buenas ideas hasta
 * que se miden -- tres de ellas EMPEORAN --.  Los dos programas son los unicos
 * del corpus que se diferencian entre si (ver "sobre el corpus", abajo):
 *
 *   A = test_mips_bench.velb   2223 instrs en 8529 bytes  (~3,84 B/instr)
 *   B = benchmark1.velb         226 instrs en  354 bytes  (~1,57 B/instr)
 *
 *   variante                        A                B         nota
 *   ------------------------  ------------  ---------------  --------------------
 *   actual (4096, directa)    2091 (94,1%)     0 ( 0,0%)     linea base
 *   4096 con hash              172 ( 7,7%)     0 ( 0,0%)     -92%, pero DISPERSA
 *   4096 hash + 2 vias         129 ( 5,8%)     0 ( 0,0%)     lo mejor con mezcla
 *   4096 hash + 4 vias         215 ( 9,7%)     0 ( 0,0%)     las vias acortan
 *   pc>>2, sin mezclar         155 ( 7,0%)   202 (89,4%)     ROMPE el caso denso
 *   pc>>2 + pliegue alto       155 ( 7,0%)   202 (89,4%)     el pliegue no salva
 *   pc>>3, sin mezclar        2209 (99,4%)      --           peor que la base
 *   pc>>2, 2 vias              195 ( 8,8%)   192 (85,0%)     sigue roto en B
 *   4096, 2 vias (sin mezcla) 2094 (94,2%)     0 ( 0,0%)     +0%: no hace NADA
 *   2048 (la mitad)           2094 (94,2%)     0 ( 0,0%)     +0%: no es capacidad
 *   512 (cabe en L1)          2094 (94,2%)     0 ( 0,0%)     +0%: idem
 *   1024 con hash (64 KB)     2114 (95,1%)     0 ( 0,0%)     +1%: LA PEOR
 *   512 con hash (32 KB)      2114 (95,1%)      --           idem
 *   8192 directa (512 KB)       98 ( 4,4%)     0 ( 0,0%)     dobla la memoria
 *   16384 directa (1 MB)         0 ( 0,0%)     0 ( 0,0%)     x4 la memoria
 *   4 tablas por tamano       2051 (92,3%)     0 ( 0,0%)     -2%: inutil
 *   2 tablas por tamano         44 ( 2,0%)     0 ( 0,0%)     -98%: EL MEJOR
 *   2 tablas + 2 vias           66 ( 3,0%)     0 ( 0,0%)     las vias restan
 *
 * LO QUE SE APRENDE, en orden de importancia:
 *
 *   - NO ES CAPACIDAD.  Achicar la tabla a la mitad, a un octavo o duplicar las
 *     vias da el MISMO numero (2094).  Si fuera capacidad, achicar tendria que
 *     empeorar.  Es el ALCANCE: el indice consume bits de una direccion en
 *     BYTES, asi que la ventana son SETS bytes y no SETS entradas.
 *   - LAS VIAS SOLAS NUNCA AYUDAN, y ademas RESTAN: `ICACHE_SETS = SIZE/WAYS`,
 *     asi que doblar las vias parte los conjuntos y ACORTA la ventana, que es
 *     justo lo que falla.  Solo suman acompanadas de algo que arregle el
 *     alcance -- y pasadas de dos vuelven a restar (129 -> 215).
 *   - NO HAY UN DESPLAZAMIENTO CORRECTO.  `pc>>2` es optimo con instrucciones
 *     de 4 bytes y catastrofico con las de 1-2, porque las colapsa de dos en
 *     dos.  VestaVM tiene opcodes de UN byte: el paso va de 1 a 11 segun el
 *     programa.
 *   - MEZCLAR Y ACHICAR ES LO PEOR.  Con mascara pelada el tamano daba igual
 *     (mandaba el indice); con mezcla, el tamano vuelve a ser el limite real y
 *     2223 instrucciones no caben en 1024 entradas.  Parecia la sintesis de
 *     los dos arreglos y es la unica fila que empeora la linea base.
 *   - LA CONDICION EXACTA es `entradas_clase * paso >= bytes_del_bucle`, y de
 *     ella sale por que 2 tablas ganan y 4 no valen: con 4, la clase dominante
 *     recibe la MISMA ventana que la tabla entera sin partir.
 *
 * Y EL TIEMPO, que es otra cosa (esto cuenta CONFLICTOS).  Medido con
 * `test_mips --solo`, intercalado y en los dos ordenes, con un binario aparte
 * construido con `-DICACHE_HASH=1`:
 *
 *   float:2048:paquetes   42,4 / 45,2  ->  404,4 / 526,2 MIPS   (~10x)
 *   alu:32:escalar       309,6 / 317,2 ->  244,4 / 247,1 MIPS   (-22%)
 *   alu:64:paquetes      336,0 / 348,7 ->  346,5 / 324,5 MIPS   (ruido)
 *
 * El -22% en bucles cortos es lo que mantiene `ICACHE_HASH` en 0, y la
 * sospecha de por que: la tabla son 4096 x 64 B = 256 KB, que no cabe en L1, y
 * la mascara pelada tiene una localidad ACCIDENTAL -- indices contiguos -- que
 * el XOR destruye.  El reparto por TAMANO no tiene ese problema: dentro de una
 * clase el mapeo sigue siendo contiguo.
 *
 * SOBRE EL CORPUS: HOY no se dispara, que no es lo mismo que no pueda pasar
 * -------------------------------------------------------------------------
 * Medido sobre 44 binarios recien compilados (36 ejemplos de
 * `examples_codes_vx/` + los 8 benchmarks): ocho tienen bucle, el mayor mide
 * 966 bytes -- la ventana son 4096 -- y dan CERO conflictos en todas y cada una
 * de las configuraciones de la tabla.
 *
 * El unico programa donde algo cambia es el que genera `test_mips`, y su mezcla
 * no es la que produce el compilador: 92% de instrucciones de 4 bytes, frente a
 * 68% de 1 byte y 26% de 4 en codigo real.
 *
 * PERO ESO ES UN "TODAVIA", NO UN "NUNCA", y de ahi sale la postura:
 *
 *   - La ventana son 4096 BYTES, o sea unas 1700 instrucciones seguidas con la
 *     mezcla real.  Lo alcanza codigo generado, una expansion `comptime` o un
 *     cuerpo grande escrito a mano.  Que el mayor de HOY mida 966 bytes no dice
 *     que nadie pueda escribir uno de 5000.
 *   - Y el que empuja hacia ahi puede ser el propio compilador: el DESENROLLADO
 *     alarga el tramo recto, asi que cuanto mejor desenrolle, mas cerca del
 *     limite.  El corpus de hoy mide el compilador de hoy.
 *   - Cuando se dispara no degrada: cae 10x de golpe (94% de fallos).  Un
 *     acantilado no avisa antes de llegar.
 *
 * Por eso lo que se decide con estos numeros es SOLO el defecto: no se cambia
 * el indice para arreglar un caso que hoy no ocurre, y menos con una variante
 * que cuesta -22% en el caso que SI ocurre (la mezcla).  Lo que si tiene que
 * quedar es esto: la tabla entera medida, los interruptores puestos
 * (`ICACHE_HASH`, `ICACHE_WAYS`) y la herramienta capaz de decir de un programa
 * si su bucle pasa de la ventana.  El dia que un programa real lo cruce, la
 * respuesta ya esta calculada y no hay que rehacer la tarde.
 *
 * Consecuencia aparte, para quien mire el banco: las columnas de tramo grande
 * de las mezclas `float` y `vector` de `test_mips` miden un regimen de
 * conflicto de icache que hoy ningun programa alcanza.  Sirven para estudiar la
 * icache -- para eso salio toda esta tabla -- pero NO para juzgar el
 * interprete.
 *
 * DOS TRAMPAS al reunir un corpus para esto:
 *   - Los `.velb` viejos del arbol son de VERSION 1 y la actual es la 4.  El
 *     desensamblador los parte mal y todo sale de "1 byte": daban un 91% que
 *     no existe.  La version esta en el offset 4 del fichero.
 *   - El detector de bucles miraba mnemonicos que empiezan por `j`, y en esta
 *     ISA `decjnz` -- EL patron del bucle contador -- no empieza por `j`, ni
 *     `cmpjmp.cc` casa con una comparacion exacta.  Un salto que no se
 *     reconoce es un bucle entero invisible, y entonces la herramienta contesta
 *     "aqui no hay conflictos" sobre un programa que no ha mirado.
 */

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "disasm/disasm.h"
/* De aqui salen ICACHE_SIZE, ICACHE_WAYS e ICACHE_HASH.  La configuracion NO se
 * escribe a mano: estaba puesta a 1024 y etiquetada como "actual" cuando la
 * real llevaba tiempo en 4096, asi que la herramienta comparaba alternativas
 * contra una linea base que no existia -- y daba luz verde sobre un caso que se
 * hunde diez veces --.  Una medida que se cree su propia etiqueta es peor que
 * no medir. */
#include "runtime/proceso_runtime.h"
#include "util/ansi.h"

namespace {

/// Una configuracion de icache a comparar.
struct Config {
    const char *nombre;
    uint32_t entradas;
    uint32_t vias;
    bool hash; ///< true = mezcla bits altos en vez de mascara pelada.

    /**
     * @brief Bits bajos que se TIRAN antes de enmascarar.  0 = ninguno.
     *
     * Es la tercera via, y no es un hash.  El problema del indice no es que la
     * direccion sea poco aleatoria: es que sus bits BAJOS son casi constantes
     * -- las instrucciones ocupan de cuatro a once bytes, asi que un paso
     * regular de cuatro deja los dos ultimos bits a cero y solo alcanza una de
     * cada cuatro ranuras --.  Tirarlos usa la tabla ENTERA sin mezclar nada.
     *
     * La diferencia con el hash importa por la LOCALIDAD, no por los
     * conflictos: mezclar dispersa un bucle corto por las 4096 entradas, y la
     * tabla ocupa 256 KB, asi que cada acceso se va a un nivel de cache mas
     * abajo.  Desplazar mantiene juntas las instrucciones que van juntas.
     */
    uint32_t desplaza = 0;

    /// Una sub-tabla por CLASE DE TAMANO, cada una con su desplazamiento.  Ver
    /// `kClases` y `fallos`.
    /// 0 = una sola tabla.  2 o 4 = cuantas sub-tablas por clase de tamano.
    uint32_t por_tamano = 0;

    /* Los MISMOS desplazamientos que `runtime::icache_index`, 12 y 21, y no un
     * `pc ^ (pc >> 10)` parecido: simular otra mezcla contesta por una funcion
     * que nadie ejecuta, y el numero que sale no dice nada de la que corre. */
    uint32_t indice(uint64_t pc) const {
        const uint32_t conjuntos = entradas / vias;
        const uint64_t d = pc >> desplaza;
        const uint64_t v = hash ? (d ^ (d >> 12) ^ (d >> 21)) : d;
        return static_cast<uint32_t>(v & (conjuntos - 1));
    }
    /// Bytes que ocupa.  `DecodedInstr` son 64 bytes exactos -- una linea de
    /// cache --, asi que esto dice si la tabla cabe en la L1 del host.  Una
    /// icache de 64 KB en una L1 de 32 KB convierte cada acierto en un fallo
    /// del nivel de abajo, que es un coste que no se ve en ningun contador.
    uint32_t kib() const { return entradas * 64 / 1024; }
};

/// Un bucle: el tramo entre el destino del salto hacia atras y el propio salto.
struct Bucle {
    uint64_t inicio, fin;
    std::vector<uint64_t> pcs;
    size_t bytes() const { return static_cast<size_t>(fin - inicio); }
};

/// El ultimo `0x...` de los operandos, que es el destino del salto.
/// Formato real: "jge 0x0000000000000063", "r6, r3, jge 0x00000075".
bool destino_de(const std::string &ops, uint64_t &out) {
    const size_t p = ops.rfind("0x");
    if (p == std::string::npos) return false;
    out = std::strtoull(ops.c_str() + p + 2, nullptr, 16);
    return true;
}

/**
 * @brief Es un salto?
 *
 * OJO con los que NO empiezan por `j`, que en esta ISA existen y son justo los
 * de bucle: `decjnz` (decrementa y salta si no es cero) es EL patron del bucle
 * contador, y `cmpjmp.cc` / `cmpjmpu.cc` llevan sufijo de condicion, asi que
 * una comparacion exacta con "cmpjmp" no los ve.
 *
 * Un salto que no se reconoce no es un salto de menos: es un BUCLE ENTERO que
 * no existe para esta herramienta, y entonces contesta "aqui no hay conflictos"
 * sobre un programa que no ha mirado.
 */
bool es_salto(const std::string &m) {
    return m.compare(0, 1, "j") == 0 || m.find("jmp") != std::string::npos ||
           m.compare(0, 6, "decjnz") == 0;
}

/// Fallos por vuelta en regimen estacionario (ver la cabecera del fichero).
/**
 * @brief Clase de tamano de una instruccion, para el reparto por TAMANO.
 *
 * La idea: una tabla por clase, cada una indexada con el desplazamiento que le
 * corresponde a SU paso.  Asi las de 4 bytes usan la tabla entera con `pc>>2` y
 * las de 1-2 bytes no se colapsan, que es lo que hace imposible elegir un
 * desplazamiento unico.
 *
 * El desplazamiento de cada clase es el log2 del tamano MENOR de la clase: con
 * eso, dos instrucciones consecutivas de esa clase caen en ranuras
 * consecutivas y no se pierde ni una.
 *
 * LA CONDICION EXACTA, que es lo que decide cuantas clases conviene tener:
 * una clase no colisiona si `entradas_clase * paso >= bytes_del_bucle`.  De ahi
 * sale que partir tiene un coste y un beneficio que se pelean -- dividir la
 * tabla entre N reduce `entradas_clase`, y el desplazamiento de la clase
 * multiplica por su paso --, asi que MENOS clases es mejor mientras cada una
 * siga cumpliendo la condicion.
 *
 * Medido sobre `test_mips_bench` (2223 instrs en 8529 bytes, casi todas de 4):
 *
 *     4 clases: 1024 * 4 = 4096 de ventana  ->  2051 fallos ( -2%)
 *     2 clases: 2048 * 4 = 8192 de ventana  ->    44 fallos (-98%)
 *
 * Con cuatro, la clase dominante se queda con la MISMA ventana que la tabla
 * entera sin partir, y el reparto no sirve de nada; con dos, la cubre casi
 * entera -- los 44 que quedan son el 4% que le falta a 8192 para llegar a 8529
 * --.  Es el mejor resultado de todo lo probado con 256 KB: mejor que la mezcla
 * (172), que `pc>>2` (155) y que doblar la tabla a 512 KB (98).
 *
 * Y a diferencia de la mezcla, NO DISPERSA: dentro de una clase el mapeo sigue
 * siendo contiguo, asi que no deberia pagar el precio que el XOR cobra en
 * bucles cortos.  En `benchmark1` da cero, o sea que tampoco rompe el caso denso
 * como si hace `pc>>2` a secas.
 *
 * LO QUE FALTA antes de llevarlo al runtime: la clase sale del byte de opcode
 * (`select_metadata` ya da el formato y de ahi el tamano), o sea una lectura de
 * `vm_mem[pc]` mas un indexado en el camino mas caliente que hay.  Eso NO esta
 * medido, y aqui solo se cuentan conflictos.  Ademas el corte (<=2 bytes) y el
 * desplazamiento estan afinados a la distribucion de tamanos de ESTA ISA.
 */
struct ClaseTam {
    uint32_t max_bytes; ///< tope de la clase (inclusive)
    uint32_t desplaza;
};
constexpr ClaseTam kClases4[] = {{2, 0}, {4, 2}, {8, 2}, {0xFFFFFFFFu, 3}};
/* DOS clases, que es la forma fuerte de la idea: cuantas menos clases, mas
 * entradas para la dominante.  La condicion exacta para que una clase no
 * colisione es `entradas_clase * paso >= bytes_del_bucle`, asi que repartir
 * entre menos deja a cada una mas cerca de cumplirla. */
constexpr ClaseTam kClases2[] = {{2, 0}, {0xFFFFFFFFu, 2}};

inline uint32_t clase_de(uint32_t bytes, const ClaseTam *cl, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i)
        if (bytes <= cl[i].max_bytes) return i;
    return n - 1;
}

/**
 * @brief Fallos por vuelta en regimen estacionario (ver la cabecera).
 *
 * Con `por_tamano`, la tabla se PARTE en una sub-tabla por clase y cada una se
 * indexa con su propio desplazamiento.  El tamano se saca de la distancia a la
 * instruccion siguiente, que dentro de un tramo recto ES el tamano.
 */
uint32_t fallos(const Config &c, const std::vector<uint64_t> &pcs) {
    std::map<uint64_t, uint32_t> por_conjunto; // clave: (clase<<32)|conjunto
    const ClaseTam *clases = (c.por_tamano == 2) ? kClases2 : kClases4;
    const uint32_t por_clase =
        c.por_tamano ? (c.entradas / c.vias / c.por_tamano) : 0;
    for (size_t i = 0; i < pcs.size(); ++i) {
        if (!c.por_tamano) {
            por_conjunto[c.indice(pcs[i])]++;
            continue;
        }
        /* La ULTIMA no tiene siguiente de la que sacar el tamano.  Se le da la
         * clase de la anterior en vez de inventarse un numero: una de 2223 no
         * cambia el resultado, y suponerle un tamano si podria. */
        const uint32_t bytes =
            (i + 1 < pcs.size())
                ? (uint32_t)(pcs[i + 1] - pcs[i])
                : (i > 0 ? (uint32_t)(pcs[i] - pcs[i - 1]) : 4u);
        const uint32_t cl = clase_de(bytes, clases, c.por_tamano);
        const uint64_t idx = (pcs[i] >> clases[cl].desplaza) & (por_clase - 1);
        por_conjunto[((uint64_t)cl << 32) | idx]++;
    }
    uint32_t n = 0;
    for (const auto &kv : por_conjunto)
        if (kv.second > c.vias) n += kv.second;
    return n;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        std::printf("uso: %s <fichero.velb> [mas.velb ...]\n", argv[0]);
        return 1;
    }
    const char *R = ansi::c(ansi::RESET), *B = ansi::c(ansi::BOLD);
    const char *D = ansi::c(ansi::DIM), *VE = ansi::c(ansi::GREEN);
    const char *AM = ansi::c(ansi::YELLOW), *RO = ansi::c(ansi::RED);

    /* La ACTUAL va primera, y se lee de las constantes de la VM en vez de
     * escribirse aqui: es la linea base contra la que se compara todo lo demas,
     * asi que si miente, mienten todas las filas. */
    static char etiqueta_actual[64];
    std::snprintf(etiqueta_actual, sizeof(etiqueta_actual),
                  "actual (%u, %s%s)", runtime::ICACHE_SIZE,
                  ICACHE_WAYS == 1 ? "directa"
                                   : (ICACHE_WAYS == 2 ? "2 vias" : "N vias"),
                  ICACHE_HASH ? ", hash" : "");
    static char etiqueta_hash[64], etiqueta_vias[64], etiqueta_mitad[64];
    std::snprintf(etiqueta_hash, sizeof(etiqueta_hash), "%u con hash",
                  runtime::ICACHE_SIZE);
    std::snprintf(etiqueta_vias, sizeof(etiqueta_vias), "%u, 2 vias",
                  runtime::ICACHE_SIZE);
    std::snprintf(etiqueta_mitad, sizeof(etiqueta_mitad), "%u (la mitad)",
                  runtime::ICACHE_SIZE / 2);

    const Config configs[] = {
        {etiqueta_actual, runtime::ICACHE_SIZE, ICACHE_WAYS, ICACHE_HASH != 0, 0},
        {etiqueta_hash, runtime::ICACHE_SIZE, ICACHE_WAYS, true, 0},
        /* Tirar los bits bajos en vez de mezclar: usa la tabla entera Y deja
         * juntas las instrucciones que van juntas.  Dos y tres porque el paso
         * util esta entre cuatro y ocho bytes. */
        {"pc>>2, sin mezclar", runtime::ICACHE_SIZE, ICACHE_WAYS, false, 2},
        /* Las dos ideas JUNTAS: bits bajos utiles y solo los altos plegados.
         * Dentro de una region alineada el XOR es con una CONSTANTE, o sea una
         * permutacion que no rompe la contiguidad; entre regiones lejanas si
         * las separa.  Es lo que hacen las caches de verdad. */
        /* HACIA ARRIBA, que es lo que contesta si el problema es el tamano.
         * Con mascara pelada el alcance son SETS BYTES, asi que doblar la tabla
         * dobla la ventana: si la causa fuera el tamano, aqui tiene que
         * arreglarse solo.  Achicar no lo contestaba -- por debajo del bucle da
         * igual --, y era la unica direccion que se habia mirado. */
        {"8192 directa (512 KB)", 8192, 1, false, 0},
        {"16384 directa (1 MB)", 16384, 1, false, 0},
        /* Y con MEZCLA, el tamano vuelve a ser el limite de verdad: con mascara
         * pelada daba igual porque mandaba el indice.  Una tabla que quepa en
         * la cache del anfitrion gana dos veces, porque `DecodedInstr` son 64
         * bytes y 4096 entradas ya son 256 KB. */
        /* Mezcla Y vias.  Es la combinacion que pide el regimen en el que
         * estamos -- capacidad de sobra, alcance corto --: la mezcla reparte
         * las colisiones y las vias les dan donde caer sin desalojar.  Por
         * separado ninguna de las dos basta, y `ICACHE_SETS = SIZE / WAYS`, asi
         * que las vias ACORTAN el alcance: solo pueden ganar acompanadas. */
        {"4096 hash + 2 vias", 4096, 2, true, 0},
        {"4096 hash + 4 vias", 4096, 4, true, 0},
        /* 4 sub-tablas por CLASE DE TAMANO, cada una con su desplazamiento.  No
         * es gratis en el runtime: la clase sale del byte de opcode, o sea una
         * lectura de `vm_mem[pc]` en el camino MAS caliente de la VM.  Por eso
         * se simula antes de escribir nada. */
        {"4 tablas por tamano", runtime::ICACHE_SIZE, 1, false, 0, 4},
        {"2 tablas por tamano", runtime::ICACHE_SIZE, 1, false, 0, 2},
        {"2 tablas + 2 vias", runtime::ICACHE_SIZE, 2, false, 0, 2},
    };
    const size_t n_cfg = sizeof(configs) / sizeof(configs[0]);

    std::printf("%sConflictos de icache, simulados sobre el bytecode%s\n", B,
                R);
    std::printf("%s  Estatico: no ejecuta nada.  Un bucle de menos de 1 KB de "
                "bytecode no tiene\n  conflictos con la icache actual; el "
                "problema empieza al pasar de ahi.%s\n\n",
                D, R);

    uint64_t tot_bucles = 0, tot_con_conflicto = 0;
    std::vector<uint64_t> suma(n_cfg, 0);

    for (int a = 1; a < argc; ++a) {
        std::FILE *fp = std::fopen(argv[a], "rb");
        if (!fp) {
            std::printf("%s[aviso]%s no pude abrir %s\n", AM, R, argv[a]);
            continue;
        }
        std::fseek(fp, 0, SEEK_END);
        const long n = std::ftell(fp);
        std::fseek(fp, 0, SEEK_SET);
        std::vector<uint8_t> datos(static_cast<size_t>(n < 0 ? 0 : n));
        if (!datos.empty() &&
            std::fread(datos.data(), 1, datos.size(), fp) != datos.size()) {
            std::fclose(fp);
            continue;
        }
        std::fclose(fp);

        disasm::DisasmOptions opts;
        opts.max_bytes = datos.size();
        const auto instrs =
            disasm::disasm_bytes(datos.data(), datos.size(), 0, opts);
        if (instrs.empty()) continue;

        // Saltos hacia ATRAS = bucles.  El cuerpo va del destino al salto.
        std::vector<Bucle> bucles;
        for (const auto &in : instrs) {
            if (!es_salto(in.mnemonic)) continue;
            uint64_t dst = 0;
            if (!destino_de(in.operands, dst)) continue;
            if (dst > in.address) continue; // hacia adelante: no es bucle
            Bucle b;
            b.inicio = dst;
            b.fin = in.address;
            for (const auto &x : instrs)
                if (x.address >= dst && x.address <= in.address)
                    b.pcs.push_back(x.address);
            if (b.pcs.size() > 1) bucles.push_back(std::move(b));
        }
        if (bucles.empty()) continue;

        // Solo se detalla el bucle mas grande de cada fichero: es el unico que
        // puede tener conflictos, y listarlos todos ahoga el informe.
        std::sort(bucles.begin(), bucles.end(),
                  [](const Bucle &x, const Bucle &y) {
                      return x.bytes() > y.bytes();
                  });
        const Bucle &mayor = bucles.front();
        const uint32_t base = fallos(configs[0], mayor.pcs);

        const char *nom = std::strrchr(argv[a], '/');
        const char *nom2 = std::strrchr(argv[a], '\\');
        if (nom2 > nom) nom = nom2;
        nom = nom ? nom + 1 : argv[a];

        std::printf("%s%-28s%s %zu bucles, el mayor: %zu instrs en %zu bytes",
                    B, nom, R, bucles.size(), mayor.pcs.size(), mayor.bytes());
        // El umbral es la VENTANA REAL en bytes, que es el tamano de la tabla:
        // ponerlo en 1 KB fijo daba verde con una icache cuatro veces mayor.
        if (mayor.bytes() >= runtime::ICACHE_SIZE)
            std::printf("  %s(pasa de %u B)%s", RO, runtime::ICACHE_SIZE, R);
        std::printf("\n");

        /* La DISTRIBUCION de tamanos del cuerpo, que es de donde tienen que
         * salir los cortes del reparto por clases.  Deducirlos de la media es
         * lo que hace que 4 clases parezcan razonables: una media de 3,84 no
         * dice que el 95% sean de 4 y que el resto no llene su tabla. */
        {
            std::map<uint32_t, uint32_t> hist;
            for (size_t i = 0; i + 1 < mayor.pcs.size(); ++i)
                hist[(uint32_t)(mayor.pcs[i + 1] - mayor.pcs[i])]++;
            if (!hist.empty()) {
                std::printf("   %stamanos:%s", D, R);
                const double tot = (double)(mayor.pcs.size() - 1);
                for (const auto &kv : hist)
                    std::printf("  %uB=%.0f%%", kv.first,
                                100.0 * kv.second / tot);
                std::printf("\n");
            }
        }

        for (size_t c = 0; c < n_cfg; ++c) {
            const uint32_t f = fallos(configs[c], mayor.pcs);
            suma[c] += f;
            const double pc =
                mayor.pcs.empty()
                    ? 0.0
                    : 100.0 * f / static_cast<double>(mayor.pcs.size());
            const char *col = f == 0 ? VE : (f < base ? AM : (c ? RO : D));
            std::printf("   %s%-24s%s %4u KB  %s%5u fallos/vuelta (%4.1f%%)%s",
                        D, configs[c].nombre, R, configs[c].kib(), col, f, pc,
                        R);
            if (c && base)
                std::printf("  %s%+.0f%%%s", f < base ? VE : RO,
                            100.0 * (double)f / base - 100.0, R);
            std::printf("\n");
        }
        std::printf("\n");
        ++tot_bucles;
        if (base) ++tot_con_conflicto;
    }

    if (!tot_bucles) {
        std::printf("%sNo se detecto ningun bucle.%s  Sin saltos hacia atras "
                    "no hay nada que simular:\nel decode se paga una vez por "
                    "sitio y se amortiza.\n",
                    AM, R);
        return 0;
    }

    std::printf("%s== Resumen%s\n", B, R);
    std::printf("   ficheros con bucle: %llu   con conflictos: %s%llu%s\n",
                (unsigned long long)tot_bucles, tot_con_conflicto ? RO : VE,
                (unsigned long long)tot_con_conflicto, R);
    if (!tot_con_conflicto) {
        std::printf(
            "%s   Ningun bucle se pisa a si mismo en la icache actual: "
            "el coste del decode se\n   amortiza y cambiar el indice no "
            "ganaria nada.  Es el resultado que hay que\n   tener antes "
            "de tocar el bucle de despacho.%s\n",
            VE, R);
    } else {
        std::printf("   fallos/vuelta sumados, por configuracion:\n");
        for (size_t c = 0; c < n_cfg; ++c)
            std::printf("     %s%-24s%s %llu%s\n", c == 0 ? B : D,
                        configs[c].nombre, R, (unsigned long long)suma[c],
                        c && suma[c] < suma[0] ? "  <- mejor" : "");
        std::printf("%s   Ojo con el KB: `DecodedInstr` son 64 bytes, asi que "
                    "la tabla actual ocupa\n   %u KB y no cabe en una L1 de 32."
                    "  "
                    "Una configuracion con menos fallos pero que se\n   salga "
                    "de L1 puede acabar siendo mas lenta: esto cuenta "
                    "conflictos, no tiempo.%s\n",
                    AM, configs[0].kib(), R);
    }
    return 0;
}
