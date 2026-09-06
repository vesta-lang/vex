/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**                                                                            \
 * @file proceso_runtime.h                                                     \
 * @brief Declaracion del contexto de proceso virtual (ProcessVM) de VestaVM.  \
 *                                                                             \
 * Declara @c ProcessVM: registros generales (R00-R15), PC, SP, BP,            \
 * flags de estado, pila de llamadas, estado del proceso y campos del          \
 * planificador.  Unidad minima de ejecucion dentro de la VM.                  \
 */                                                                            \
#ifndef PROCESO_RUNTIME_H
#define PROCESO_RUNTIME_H

#include "vx/asm/asm_phys_reg.h" // ABI del contexto de un bloque asm
#include "scheduler.h"
#include "vm_registers.h"
#include "vm_state_event.h"

#include "runtime/pid.h"
#include "gc/gc_heap.h"
#include "gc/raw_allocator.h"
#include "loader/oop_types.h"

#include <atomic>
#include <csetjmp>
#include <vector>

namespace distrib {
class Mailbox; ///< Declaracion adelantada del buzon de mensajes distribuido
}

namespace runtime {
class StringInternPool; ///< Pool de interning de strings (definicion en
                        ///< string_intern.h)
}

/**
 * @brief Numero de reducciones por defecto que se le asignan a cada proceso al
 * entrar en ejecucion.
 *
 * Una reduccion equivale a ejecutar una instruccion o un paso costoso de la
 * FSM. Cuando el contador llega a cero el scheduler cambia de proceso
 * (round-robin cooperativo).
 */
#define reductions_remaining_default 8192

namespace runtime {
struct InstrFormat; ///< Formato de instruccion con metadatos de
                    ///< descodificacion/ejecucion
class Scheduler;    ///< Gestor de procesos que ejecuta el run_loop

/**
 * @brief Informacion generada durante la descodificacion de una instruccion.
 *
 * Todas las fases de la FSM (DECODE -> EXECUTE) leen y escriben este struct.
 * Contiene flags de control, los operandos descodificados y un puntero al
 * descriptor de la instruccion (InstrFormat).
 */
/* SIN `alignas(64)`, y es una decision medida, no un descuido.
 *
 * Mide 64 bytes exactos, asi que subirle la alineacion parecia gratis y ademas
 * util: cualquier copia que reciba `alignof(DecodedInstr)` como pista tiene que
 * suponer 8 y emitir el prologo que alinea el destino en EJECUCION, que es lo
 * que convierte un tamano constante en variable e impide desenrollar.
 *
 * Se probo, y durante un rato REVENTABA -- violacion de segmento nada mas
 * arrancar --.  La causa no estaba aqui: el asignador del proyecto sustituia
 * `operator new`/`delete` pero no las sobrecargas SOBRE-ALINEADAS de C++17, asi
 * que un tipo con `alignas` mayor que la natural se reservaba con el asignador
 * del sistema y se soltaba por el camino sustituido.  Ya esta arreglado (ver
 * `util::host_alloc_aligned`), asi que hoy se puede alinear sin que pase nada.
 *
 * No se hace porque MIDE PEOR.  Intercalado y en los dos ordenes:
 *
 *     mixta:8192:paquetes      284,5 -> 291,5   (+2,5%)
 *     alu:8192:paquetes        298   -> 299     (igual)
 *     independ:256:paquetes    499   -> 440     (-12%)
 *
 * Y no hace falta para nada: lo unico que necesita estar alineado de verdad es
 * el array de instrucciones de un paquete, y eso lo garantiza el `alignas` de
 * `Bundle::instr` con su `static_assert`.  Alinear el TIPO ademas obliga a
 * todas las demas instrucciones sueltas del programa sin ganar nada. */
typedef struct DecodedInstr {
    /**
     * @brief Campos de control descodificados del prefijo de la instruccion.
     *
     * Todos los campos se inicializan a cero/false en la declaracion del
     * objeto.
     */
    struct {
        uint8_t is_not_extended : 8; ///< opcode1: 0x00 indica tabla extendida;
                                     ///< otro valor indica tabla primaria

        uint8_t opcode_index : 8; ///< opcode2: indice en la tabla de
                                  ///< descodificacion

        uint8_t _signed_instruct : 1; ///< 1 si la instruccion opera con signo;
                                      ///< 0 si es sin signo

        /**
         * @brief Modo de la instruccion (tamanyo del operando).
         *
         * Codifica el tamanyo del operando:
         *   0 -> 8 bits, 1 -> 16 bits, 2 -> 32 bits, 3 -> 64 bits.
         */
        uint8_t mode : 2;

        /**
         * @brief Indica si la instruccion ha modificado el PC manualmente.
         *
         * Las instrucciones de salto (JMP, CALL, RET) deben poner este campo a
         * true. Si es false, la fase EXECUTE incrementa el PC en size_instr
         * bytes al terminar. Si es true, se asume que la instruccion ya
         * actualizo el PC y no se incrementa.
         */
        bool did_jump : 1;

        bool blocking : 1; ///< 1 si la instruccion requiere esperar una
                           ///< operacion de E/S desbloqueante

        /**
         * @brief 1 si la instruccion usa registros extendidos/especiales (rsp,
         * rbp, rip, cur0..cur3).
         */
        bool reg_ext : 1;

        /**
         * @brief Direccion de la operacion de memoria.
         *
         * Para instrucciones con acceso a memoria:
         *   0: destino en registro, fuente en memoria  (ej. add r3, [r1 +
         * r2*8]) 1: destino en memoria, fuente en registro  (ej. add [r1 +
         * r2*8], r3)
         *
         * En instrucciones sin direccionalidad se usa como metadato de
         * seleccion de variante dentro de la misma familia.
         */
        uint8_t direction : 1;

        /**
         * @brief Tamanyo en bytes de la instruccion.  Maximo 63.
         *
         * Eran CUATRO bits -- 15 bytes --, que le sobran a cualquier
         * instruccion del bytecode: la mayor de la ISA es `FIXED_11`.  El que
         * se quedaba fuera era el FUSIONADOR, que tiene que declarar la SUMA de
         * las que sustituye, y con 15 de tope quedaban bloqueadas fusiones que
         * si valen la pena -- dos cargas (8+8), dos `mov` con inmediato
         * (11+11), cuatro `mov` reg,reg (4x4) --.  Y no por su semantica: por
         * un campo.
         *
         * SEIS bits, y el numero no es a ojo.  El techo que hay que cubrir sale
         * de dos hechos:
         *
         *     mayor instruccion de la ISA   = 11 bytes (FIXED_11)
         *     mayor tanda fusionable        =  4       (lo que admite `absorbed`)
         *     techo                         = 44       -> no cabe en 5 bits (31)
         *
         * INVARIANTE: `size_instr` tiene que poder con `11 * (absorbed_max+1)`.
         * El dia que `absorbed` crezca a tres bits -- ocho instrucciones --
         * harian falta 88, o sea siete bits, y en este campo ya no quedan: son
         * 31 de 32 usados.  Ese dia los dos campos se mudan, no se recortan.
         *
         * No es un cambio de formato: esto se rellena al DESCODIFICAR y no se
         * escribe en ningun fichero.  Lo unico que lo lee es el avance de
         * `rip`, y quedarse corto ahi no da un error -- deja `rip` corrido y el
         * salto siguiente va a otro sitio --, asi que el fusionador lo
         * comprueba antes de escribirlo.
         */
        uint8_t size_instr : 6;

        /**
         * @brief Cuantas instrucciones del PROGRAMA representa esta, MENOS una.
         *
         * Vale 0 en todo lo que se descodifica, y 1 en lo que sale de fusionar
         * un par.  Existe porque al fusionar hay DOS cuentas distintas, y
         * confundirlas le cambia el SIGNO a la medida:
         *
         *   - las que la maquina DESPACHA: bajan al fusionar, y esa bajada es
         *     justo la ganancia;
         *   - las que el PROGRAMA tiene: no cambian, porque el programa es el
         *     mismo.
         *
         * Los MIPS son de las segundas.  Contando las primeras, fusionar BIEN
         * se leeria como una regresion proporcional a lo bien que funciona.  Es
         * el mismo fallo que ya mordio con los paquetes encadenados -- un bucle
         * entero recorrido en un despacho contaba como UNA instruccion -- y se
         * arregla igual: se retira lo que el programa dice, no lo que la
         * maquina despacha.
         *
         * Dos bits y no uno: caben en los cinco que sobraban del campo de bits,
         * no agrandan `DecodedInstr` (64 bytes) y dejan sitio para fusionar de
         * tres en tres sin volver a tocar esto.
         */
        uint8_t absorbed : 2;
    } flags_info = {
        0,     0,     0, 0, false,
        false, false, 0, 0, 0}; ///< Campos de control inicializados a cero/false

    /**
     * @brief Operandos descodificados de la instruccion (union de todos los
     * formatos).
     *
     * Solo uno de los campos de la union es valido en cada instruccion; el
     * campo activo depende del tipo de instruccion indicado por flags_info.
     */
    union {
        /**
         * @brief Acceso crudo a los 16 bytes de datos de la instruccion.
         */
        struct {
            uint64_t raw1; ///< Primeros 8 bytes en crudo
            uint64_t raw2; ///< Segundos 8 bytes en crudo
        } raw_data;

        /**
         * @brief Operandos para instrucciones de tipo reg, reg.
         *
         * Ejemplo: add r0, r1
         */
        struct {
            uint8_t reg1; ///< Indice del registro destino (o primer operando)
            uint8_t reg2; ///< Indice del registro fuente (o segundo operando)
        } reg_data;

        /**
         * @brief Operandos para instrucciones con mezcla de registros generales
         * y especiales.
         *
         * Usado por instrucciones como XCHG que pueden operar con registros
         * extendidos y generales en la misma instruccion.  Cada registro tiene
         * un bit de flag que indica si es extendido (1) o general (0).
         */
        struct {
            uint8_t reg1 : 6; ///< Indice del registro 1 (general o extendido)
            uint8_t reg1_flags : 1; ///< 1 si reg1 es extendido/especial
            uint8_t unused1 : 1;    ///< Sin uso por ahora
            uint8_t reg2 : 6; ///< Indice del registro 2 (general o extendido)
            uint8_t reg2_flags : 1; ///< 1 si reg2 es extendido/especial
            uint8_t unused2 : 1;    ///< Sin uso por ahora
        } regs_data_extent;

        /**
         * @brief Operandos para instrucciones de tipo reg, imm o imm, reg.
         *
         * Ejemplo: add r0, 42
         */
        struct {
            uint64_t inmmed; ///< Valor inmediato codificado en la instruccion
            uint8_t reg;     ///< Indice del registro destino o fuente
        } inmmed_data;

        /**
         * @brief Operandos para instrucciones de acceso a memoria con SIB.
         *
         * Codifica la formula de direccion: [reg_base + reg_index * scale].
         * El campo mode en flags_info determina el tamanyo del acceso.
         *
         * Ejemplo: add [r1 + r2 * 2], r3b
         *   reg_base=r1, reg_index=r2, scale=2, reg_final=r3
         */
        struct {
            uint8_t reg_base;  ///< Registro base de la direccion de memoria
            uint8_t reg_index; ///< Registro indice de la formula SIB
            uint8_t reg_final; ///< Registro destino o fuente de la operacion
            uint8_t
                scale; ///< Factor de escala del registro indice (1, 2, 4 u 8)
        } mem_data;

        /**
         * @brief Operandos de mld / mst (load/store universal, opcodes extended
         *        0x90 / 0x91).  Direccionamiento completo en 1 despacho:
         *        @c addr = base +/- (index << scale) +/- disp.  Ver
         *        @c exec_instr_mld / @c exec_instr_mst.  Encoding FIXED_8:
         *        @c [0x00][op2][ctrl][basef][regs][disp16][pad].
         */
        struct {
            uint8_t reg;   ///< dst (mld) o src (mst); banco segun bit bank
            uint8_t base;  ///< base: 0-15=rN, 16=rbp, 17=rsp
            uint8_t index; ///< registro indice (0-15); valido si has_index
            uint8_t scale; ///< shift 0..6 (x1/2/4/8/16/32/64)
            uint8_t width; ///< bytes de acceso: 1/2/4/8/16/32/64
            uint8_t flags; ///< b0=host b1=has_index b2=idx_sub b3=sign_ext
                           ///< b4=bank(FP)
            int16_t disp;  ///< desplazamiento con signo (+/- 32KB)
        } mem_full;

        /**
         * @brief Operandos para instrucciones de acceso a static fields
         *        (getstatic / setstatic, opcodes extended 0x60 / 0x61).
         *
         * Encoding fisico FIXED_8:
         *   [0x00][0x60|0x61][regs_byte][_pad8][offset_u32_LE]
         *     byte2 (regs_byte) = (r0 << 4) | r1
         *     bytes 4-7         = offset uint32 little-endian
         *
         * Para @c getstatic: r0 = r_dst (destino del valor leido),
         *                    r1 = r_class (registro con ClassInfo*).
         * Para @c setstatic: r0 = r_class (registro con ClassInfo*),
         *                    r1 = r_value (valor a almacenar).
         *
         * El opcode siempre opera sobre @c i64 (8 bytes); el frontend
         * Vesta realiza @c truncate post-load para tipos mas pequenos
         * (mismo patron que los accesos a campos de instancia).
         */
        struct {
            uint8_t
                r0; ///< Registro 0 (dst para getstatic, class para setstatic)
            uint8_t
                r1; ///< Registro 1 (class para getstatic, value para setstatic)
            uint16_t _pad; ///< Padding de alineacion
            uint32_t
                offset; ///< Offset dentro de @c ClassInfo::static_data (bytes)
        } static_data;

        /**
         * @brief Operandos para fastpush / fastpop con bitmask de registros.
         *
         * Cada bit del mask representa un registro general (bit 0 = r0, ...,
         * bit 15 = r15). fastpush itera los bits ascendentes y empuja en orden
         * r0, r1, ..., r15 (los que tengan el bit puesto).  fastpop itera los
         * bits ascendentes tambien, leyendo de offsets descendentes (orden
         * inverso al push), lo que restaura los valores exactos.
         *
         * Encoding fisico FIXED_4:
         *   [0x00][opcode2][mask_lo][mask_hi]
         */
        struct {
            uint16_t mask; ///< Bitmask de registros (bit r = r0..r15)
        } mask_data;
    } data_instruction = {
        static_cast<uint64_t>(0),
        static_cast<uint64_t>(0)}; ///< Operandos inicializados a cero

    InstrFormat *metadata = nullptr; ///< Descriptor de la instruccion: funcion
                                     ///< de ejecucion, metadatos, etc.

    /**
     * @brief cache directo del exec function pointer.
     *
     * Antes el hot path del scheduler hacia `decoded_ptr->metadata->exec(...)`
     * que es una doble indireccion (decoded_ptr -> metadata -> exec).
     * Cachear el pointer aqui ahorra una carga por instruccion VM.
     * Lo seteamos junto con metadata en decode_instruction (cache hit y miss).
     */
    void (*exec_cached)(ProcessVM *, const DecodedInstr &) = nullptr;

    uint64_t pc =
        0; ///< Direccion virtual del PC donde se encontro esta instruccion

    /**
     * @brief Inline cache para resolucion virtual (CALLVIRT/CALLM monomorfica).
     *
     * Las llamadas virtuales en la practica son MONOMORFICAS: el receptor
     * suele ser de la misma clase en ejecuciones repetidas del mismo PC.
     * Cachear `cached_class -> cached_method` permite saltarse el bounds
     * check + indirect load de la vtable en el caso comun (cache hit).
     *
     * Invalidacion: si `hdr->class_ptr != cached_class` (cache miss), el
     * exec hace lookup completo y actualiza el cache.  El primer hit tras
     * un miss paga el coste de la resolucion; los hits subsiguientes son
     * O(1) sin indireccion.
     *
     * Cero overhead si el call site nunca se ejecuta (campos a nullptr).
     */
    mutable void *cached_class = nullptr;
    mutable void *cached_method = nullptr;
} DecodedInstr;

/**
 * @brief El tamano de `DecodedInstr` esta VIGILADO, y no por gusto.
 *
 * Cada proceso lleva `icache[ICACHE_SIZE]` de estas, o sea 4096 copias: un
 * byte de mas aqui son 4 KB de mas POR PROCESO, y hoy la tabla ya ocupa
 * 256 KB.  Sin esta guarda, anadir un campo hace crecer la huella de todos los
 * procesos sin que nada lo diga -- y eso no se nota al compilar ni al probar:
 * se nota el dia que alguien lanza muchos procesos.
 *
 * Si esto salta, la pregunta NO es "subo el numero".  Es: cabe el campo nuevo
 * en los huecos que ya hay, o de verdad hace falta pagar 4 KB por proceso.
 * `flags_info` en concreto tiene sitio de sobra -- usa 27 de sus 32 bits.
 *
 * Se pone en 64 porque son 64 los que mide hoy, no porque 64 sea sagrado.
 */
static_assert(sizeof(DecodedInstr) == 64,
              "DecodedInstr dimensiona la icache: 4096 copias por proceso.  "
              "Ver el comentario de arriba antes de cambiar el numero.");

/**
 * @brief Codigos de error que puede almacenar un hilo de proceso virtual.
 *
 * El campo err_thread de ProcessVM guarda el ultimo error ocurrido.
 * Un valor THREAD_NO_ERROR (0) indica que el proceso no ha fallado.
 */
typedef enum state_err_thread {
    THREAD_NO_ERROR = 0,        ///< Sin error
    THREAD_UNKNOWN_ERROR,       ///< Error no clasificado
    THREAD_SEGMENTATION_FAULT,  ///< Acceso a memoria sin permisos suficientes
    THREAD_ILLEGAL_INSTRUCTION, ///< Instruccion no reconocida o prohibida
    THREAD_DIVISION_BY_ZERO,    ///< Division entre cero

    /**
     * @brief El tope de pila (SP) alcanzo el limite inferior del segmento de
     * pila.
     *
     * Ocurre cuando se realiza un PUSH mas alla del limite reservado para la
     * pila.
     */
    THREAD_STACK_OVERFLOW,

    /**
     * @brief Se intento leer de una pila vacia o SP quedo por debajo de BP.
     *
     * El tope de pila siempre debe ser mayor o igual que el puntero de base.
     * Un POP de pila vacia o un decremento ilegal de SP genera este error.
     */
    THREAD_STACK_UNDERFLOW,

    THREAD_INVALID_SYSCALL, ///< Llamada al sistema invalida o no soportada
    THREAD_NULL_POINTER,    ///< UNWRAP encontro un valor nulo
                            ///< (NullPointerException)
} state_err_thread;

/**
 * @brief Numero de entradas de la cache de instrucciones descodificadas.
 *
 * Debe ser potencia de dos para que icache_index() pueda usar una mascara AND.
 *
 * SE PUEDE CAMBIAR AL CONFIGURAR (`-DVESTA_ICACHE_SIZE=N`), y hasta ahora no se
 * podia: era un `constexpr` fijo mientras @ref ICACHE_WAYS si era ajustable,
 * asi que de las dos variables de la icache solo una se podia medir.  Y es la
 * otra la que manda en el caso que duele -- un bloque recto mas largo que la
 * tabla falla SIEMPRE, por muchas vias que tenga.
 *
 * MISMA DISCIPLINA que los interruptores de paquetes de mas abajo, y por la
 * misma razon: esto dimensiona un array DENTRO de `ProcessVM`.  Definirlo para
 * unas unidades de traduccion y no para otras da dos `ProcessVM` de tamanos
 * distintos, que no es un error de compilacion ni de enlazado -- es corrupcion
 * en ejecucion.  Se pone en la configuracion del proyecto, para TODOS los
 * objetivos, o no se pone.
 *
 * Lo que cuesta subirlo: cada entrada es un `DecodedInstr` de 64 bytes, asi
 * que la tabla ocupa `ICACHE_SIZE * 64` bytes **por PROCESO**.  Con 4096
 * entradas son 256 KB, y esa es la variable a vigilar -- no la velocidad --
 * el dia que haya muchos procesos ligeros a la vez.
 *
 * POR QUE 4096 Y NO 1024.  Con 1024 entradas, cualquier bloque de codigo
 * RECTO mas largo que la tabla falla en TODAS sus instrucciones, y un fallo
 * cuesta redescodificar (entre 15 y 25 veces mas que ejecutar).  Medido con
 * `test_mips --pico`, que barre longitudes:
 *
 *                 1024 rectas       1024 entradas   4096 entradas
 *   memoria + paquetes                    2 MIPS         308 MIPS
 *   memoria + escalar                    24                263
 *   alu     + escalar                    105                293
 *   anchos  + escalar                     76                182
 *
 * Los 2 MIPS no son una errata: ahi coinciden el fallo en todas y que
 * `bundle_try_form` cuelga del camino de fallo, con lo que cada instruccion
 * paga hasta `BUNDLE_MAX` descodificaciones por adelantado que no se amortizan
 * nunca.
 *
 * Y el TECHO no se mueve (377 MIPS con 1024, 376 con 4096): subirlo no le
 * quita nada al caso corto, que es donde se temia el precio.  Lo unico que
 * cambia es donde cae el precipicio -- ahora en 4096 en vez de en 1024 --, asi
 * que sigue existiendo; ver `tests/runtime/test_mips.cpp`, que tiene un caso a
 * cada lado a proposito.
 */
/* El MANDO y el NOMBRE van separados a proposito.  El mando es el macro, que
 * es lo unico que se puede fijar desde la linea de configuracion; el nombre
 * sigue siendo una constante de verdad dentro del espacio de nombres, porque
 * hay codigo que la usa cualificada (`runtime::ICACHE_SIZE`) y un macro ahi
 * expande a `runtime::4096`, que no compila. */
#ifndef VESTA_ICACHE_SIZE
#define VESTA_ICACHE_SIZE 4096
#endif
static constexpr uint32_t ICACHE_SIZE = VESTA_ICACHE_SIZE;

/**
 * @brief Vias (asociatividad) de la icache.  1 = mapeo directo, como siempre.
 *
 * Con mapeo directo, dos instrucciones cuyas direcciones difieren en un
 * multiplo de ICACHE_SIZE caen en la misma ranura y se desalojan la una a la
 * otra en CADA vuelta del bucle.  Medido sobre el corpus de benchmarks
 * (tests/coste/test_icache_conflictos.cpp): 15 de 32 programas tienen un
 * bucle que se pisa a si mismo, y en el peor -- 488 instrucciones en 2821
 * bytes -- el 28.9% de sus instrucciones falla en cada vuelta.  Cada fallo
 * obliga a redescodificar, que cuesta entre 15 y 25 veces mas que ejecutar.
 *
 * La misma simulacion dice que 2 vias quitan el 36% de esos conflictos SIN
 * cambiar la huella de memoria.
 *
 * OJO: esas cifras se midieron con @ref ICACHE_SIZE en 1024, que era el valor
 * de entonces.  Hoy son 4096, asi que la tabla es cuatro veces mas grande y
 * los conflictos que contaba esa simulacion han bajado -- cuanto, no se sabe:
 * habria que volver a pasar `tests/coste/test_icache_conflictos.cpp`.  El
 * argumento a favor de dos vias sigue en pie, pero su TAMANO ya no es el que
 * dice el parrafo de arriba.
 *
 * Se queda en 1 POR DEFECTO: con este valor el codigo generado es el de
 * siempre.  Ponerlo a 2 es el experimento, y hay que MEDIRLO con el banco
 * antes de dejarlo: la simulacion cuenta conflictos, no tiempo.
 */
#ifndef ICACHE_WAYS
#define ICACHE_WAYS 1
#endif

/* Los interruptores de PAQUETES (runtime/bundle.h) se definen AQUI y no alli
 * aunque sea alli donde se usan: anaden campos a `ProcessVM`, y si el defecto
 * viviera en `bundle.h` una unidad de traduccion que no lo incluya veria un
 * `ProcessVM` de otro tamano.  Eso es una violacion de ODR que no da error de
 * compilacion ni de enlazado: da corrupcion en ejecucion.
 *
 * Ver `runtime/bundle.h` para que hace cada uno. */
#ifndef VM_BUNDLES
#define VM_BUNDLES 1
#endif
/* `VM_BUNDLE_STATS` YA NO EXISTE.  La telemetria de paquetes se pide en
 * EJECUCION (`ProcessVM::bundle_stats_on` o `VESTA_BUNDLE_STATS`), porque
 * atarla al perfil de construccion obligaba a reconstruir para tomar la medida
 * -- y entonces lo que se mide es otro binario --. */

/// Conjuntos = entradas / vias.  Con 1 via es la tabla entera, como antes.
static constexpr uint32_t ICACHE_SETS = ICACHE_SIZE / ICACHE_WAYS;

static_assert(
    (ICACHE_SIZE & (ICACHE_SIZE - 1)) == 0,
    "ICACHE_SIZE debe ser potencia de dos: el indice usa mascara AND");
static_assert((ICACHE_SETS & (ICACHE_SETS - 1)) == 0,
              "ICACHE_SETS debe ser potencia de dos");

/**
 * @brief Si el indice de la icache DISPERSA la direccion antes de recortarla.
 *
 * 0 = mascara pelada, el comportamiento de siempre.  1 = se pliegan bits altos
 * con un XOR antes de la mascara.
 *
 * POR QUE EXISTE.  Una mascara pelada es maximamente vulnerable a los pasos
 * REGULARES, que es justo lo que produce este interprete.  Medido con
 * `VESTA_CACHE_DUMP=1` sobre un tramo recto de 8192 instrucciones: las
 * cabeceras de paquete caen cada ~160 bytes, y como `gcd(160, 4096) = 32` solo
 * alcanzan 128 indices distintos para 256 cabeceras.  Dos por ranura, mapeo
 * directo, **conflicto del 100% con la cache ocupada al 9,4%**.  No es
 * capacidad: es que el indice tira 256 cosas sobre 128 sitios.
 *
 * Y no se arregla con vias: `ICACHE_SETS = ICACHE_SIZE / ICACHE_WAYS`, asi que
 * pasar a 2 vias PARTE los conjuntos por la mitad y el paso vuelve a colisionar
 * igual -- medido, 74,6 -> 57,5 MIPS, peor que antes por el coste de buscar en
 * dos vias.
 *
 * El XOR mezcla bits que el paso no toca, con lo que un patron regular deja de
 * serlo.  Cuesta dos operaciones en el camino caliente, y por eso va detras de
 * un mando: hay que poder medir si compensa en vez de suponerlo.
 */
#ifndef ICACHE_HASH
#define ICACHE_HASH 0
#endif

/**
 * @brief Si la icache se PARTE en dos mitades por clase de tamano.
 *
 * 0 = una sola tabla, el comportamiento de siempre.  1 = una mitad para las
 * instrucciones de la tabla PRIMARIA (un byte, indexadas por `pc>>0`) y otra
 * para las de la EXTENDIDA (cuatro o mas, por `pc>>2`).  Ver @ref icache_set.
 *
 * POR QUE EXISTE.  El problema del indice es que la ventana son `SETS` BYTES y
 * no `SETS` entradas, asi que un bucle mas largo que eso alias siempre.  Un
 * desplazamiento unico no lo arregla porque el paso VARIA con el programa: con
 * instrucciones de 4 bytes `pc>>2` es optimo y con las de 1 byte las colapsa de
 * dos en dos.  Partiendo, cada mitad usa el suyo.
 *
 * Simulado en `tests/coste/test_icache_conflictos.cpp`: sobre un tramo recto de
 * 8529 bytes los fallos pasan de 2091 (94,1%) a 44 (2,0%), y es lo mejor de
 * todo lo probado sin gastar mas memoria -- mejor que la mezcla (172) y que
 * doblar la tabla a 512 KB (98) --.  A diferencia de la mezcla, NO DISPERSA:
 * dentro de una mitad el mapeo sigue siendo contiguo.
 *
 * Y va detras de un mando porque cuesta LEER `vm_mem[pc]` en el camino mas
 * caliente, y eso la simulacion no lo mide: cuenta conflictos, no tiempo.
 */
#ifndef ICACHE_SIZE_CLASS
#define ICACHE_SIZE_CLASS 0
#endif

/**
 * @brief Si la FORMACION desplaza una cabecera cuya ranura ya ocupa otra.
 *
 * 0 = como siempre.  1 = al formar en `pc`, si esa ranura de icache ya tiene
 * la cabecera de OTRA direccion, no se forma ahi: la cabecera acaba en la
 * instruccion siguiente, que cae en otra ranura.  Ver `bundle_try_form`.
 *
 * Ataca lo mismo que @ref ICACHE_SIZE_CLASS -- que un paso REGULAR solo
 * alcance un punado de ranuras -- pero desde el otro lado: en vez de llevar
 * mas bits del `pc` al indice, hace irregular el espaciado de las cabeceras.
 * Es reactivo (solo donde hay colision) y no toca `k`, asi que no cambia lo
 * que significa un paquete.
 *
 * ENCENDIDO POR DEFECTO, y con la medida delante.  Sobre la mezcla `float` con
 * despacho de paquetes:
 *
 *      tramo    base   desplazando
 *        512   494,2       459,4
 *       1024   476,1       480,1
 *       2048    46,4       352,5   <- 7,6x
 *       8192    46,4       277,4   <- 6,0x
 *
 * Y los contadores dicen por que: a tramo 2048 las formaciones caen de 249.985
 * a 4.033 -- el mismo sitio dejaba de reconstruirse 62 veces de cada 63 -- y la
 * arena deja de necesitar recolecciones (30 -> 0).
 *
 * Lo que lo hace apto para el defecto es que es REACTIVO: a tramo 1024 marca
 * `cabeceras_movidas=0`, o sea que no se dispara donde no hay colision y ahi no
 * cuesta.  La alternativa que arregla lo mismo desde el indice
 * (@ref ICACHE_SIZE_CLASS) es incondicional y se cobra un 14% en todas partes.
 *
 * El mando se queda para poder contrastar el MISMO binario con y sin el: si un
 * programa cambiara de resultado al apagarlo, la culpa es de aqui.
 */
#ifndef ICACHE_HEAD_SHIFT
#define ICACHE_HEAD_SHIFT 1
#endif

/**
 * @brief Conjunto de la icache al que va una direccion PC.
 *
 * @param pc Direccion del contador de programa de la instruccion.
 * @return   Conjunto (0 .. ICACHE_SETS-1).
 */
[[gnu::always_inline]] inline uint32_t icache_index(uint64_t pc) {
#if ICACHE_HASH
    /* Se pliegan dos tramos altos sobre el bajo.  Los desplazamientos no son
     * redondos a proposito: con 12 y 21 los bits que aporta cada uno no se
     * solapan con los que el paso regular deja fijos. */
    const uint64_t mezclado = pc ^ (pc >> 12) ^ (pc >> 21);
    return static_cast<uint32_t>(mezclado & (ICACHE_SETS - 1));
#else
    // Mascara pelada, valida porque ICACHE_SETS es potencia de dos.  Con una
    // via esto es exactamente el indice de siempre.
    return static_cast<uint32_t>(pc & (ICACHE_SETS - 1));
#endif
}

/**
 * @class ProcessVM
 * @brief Proceso virtual de la maquina virtual VestaVM.
 *
 * Cada ProcessVM representa un hilo de ejecucion independiente dentro de
 * la VM.  Contiene su propio:
 *   - Conjunto de registros (context_registers_vm).
 *   - Espacio de memoria privado (ArenaManager + VirtualMemory + TLB).
 *   - Heap de GC y asignador raw.
 *   - Cache de instrucciones descodificadas (icache).
 *   - Estado de la FSM (vm_state).
 *
 * El scheduler propietario gestiona el ciclo de vida del proceso.
 * Para que el proceso sea elegible por el scheduler debe llamarse a
 * vm->make_ready(proc->pid) tras crearlo.
 */

class ProcessVM; // fwd: el provider guarda un ProcessVM* (def mas abajo).

/**
 * @brief Implementacion de @c gc::GcRootProvider sobre un @c ProcessVM.
 *
 * Da al GcHeap acceso al stack/regs del proceso (scan conservativo) y a las
 * tablas shared ( Z, cross-proceso) sin que @c gc_heap.cpp dependa de la
 * VM.  Los cuerpos viven en @c proceso_runtime.cpp (donde @c runtime.h aporta
 * la def completa de la VM); aqui solo las declaraciones.
 */
class ProcessVMRootProvider final : public gc::GcRootProvider {
  public:
    explicit ProcessVMRootProvider(ProcessVM *p) noexcept : proc_(p) {}
    bool vm_stack_regs(uint64_t &rsp, uint64_t &stack_high,
                       uint64_t regs[16]) override;
    uint64_t stack_low_water() const override;
    void set_stack_low_water(uint64_t v) override;
    void write_back_regs(const uint64_t regs[16]) override;
    vm::VirtualMemory *vm_mem() override;
    uint64_t scan_interp_precise_roots(InterpRootCallback cb,
                                       void *cb_ctx) override;
    bool all_interp_frames_have_stackmaps() override;
    bool shared_contains(const uint8_t *ptr) override;
    uint8_t *shared_lookup(gc::GcHandle h) override;
    gc::WaitTable *shared_wait_table() override;

  private:
    ProcessVM *proc_;
};

class ProcessVM {
  public:
    /**
     * @brief Safepoint flag (per-proceso).  PRIMER campo de la
     *        clase a proposito para que el JIT-eado pueda emitir
     *        polls con disp8 (mas compactos que disp32).
     *
     * El JIT mantiene @c ProcessVM* en RBX durante toda la funcion.
     * Cada poll (back-edge / post-call) emite:
     *
     *     cmp byte [rbx], 0      ; 4 bytes (REX + cmp + modrm)
     *     jne handler            ; 6 bytes (0F 85 rel32)
     *
     * Total: 10 bytes por poll, ~2 cycles cuando flag=0 (branch
     * predictor lo aprende inmediatamente).  Esencialmente gratis.
     *
     * El GC del propio proceso setea este byte a 1 cuando quiere
     * pausar al thread para stack scan.  El handler invoca
     * @c vrt_safepoint_handler que captura RIP/RBP y cede el control
     * al GC.
     *
     * NOTE: @c uint8_t (no atomic) para que el poll JIT-eado sea
     * un simple @c cmp byte.  Ordenamiento garantizado porque el
     * setter del GC y el reader del handler coordinan via
     * @c std::atomic<bool> @c safepoint_acked posteriormente.
     */
    uint8_t safepoint_flag = 0;
    /// Watchdog CTPE: el hilo temporizador lo pone a 1 al vencer el
    /// presupuesto; @c vrt_safepoint_handler lo consulta en el proximo poll y
    /// aborta (throw_fatal).  Vive en el ProcessVM (una sola instancia) para
    /// evitar el problema de globales duplicados cross-modulo (vm/DLL/vmcore).
    uint8_t ctpe_abort = 0;
    /// Watchdog CTPE (resultado): 1 = el safepoint hizo longjmp para abortar
    /// la ejecucion precomputada.  Lo lee try_invoke_ctpe: si es 1, NO se
    /// pliega (el resultado seria parcial/incorrecto).  Distinto de ctpe_abort
    /// (peticion).
    uint8_t ctpe_did_abort = 0;
    uint8_t _safepoint_pad[5] = {0}; ///< Alineacion a 8 bytes

    GlobalPID
        pid; ///< Identificador global del proceso (scheduler_id + local_pid)

    /**
     * @brief Contador de reducciones restantes antes del proximo cambio de
     * contexto.
     *
     * Una reduccion equivale normalmente a ejecutar una instruccion.
     * Cuando llega a cero el scheduler elige otro proceso (planificacion
     * round-robin). Se reinicia al valor reductions_remaining_default en cada
     * quantum.
     */
    uint64_t reductions_remaining = reductions_remaining_default;

    context_registers_vm
        registers; ///< Contexto completo de registros del proceso

    /**
     * @brief GC stack scanning conservativo.
     *
     * Limite superior INMUTABLE del stack del proceso, seteado al spawn
     * y al cargar el proceso main.  El stack crece hacia abajo desde
     * @c stack_high hacia @c stack_low_water.  El GC stack scan recorre
     * el rango [stack_low_water, stack_high) para encontrar handles y
     * host_ptrs vivos.
     */
    uint64_t stack_high = 0;

    /**
     * @brief minimo @c rsp visto desde el ultimo GC.
     *
     * Actualizado en @c subsp (1 cmp + cmov, ~1 ns; subsp es raro = 1
     * vez por entry de funcion).  Reseteado al rsp actual tras cada GC.
     * Permite escanear solo el rango realmente usado del stack
     * en lugar del 1 MiB completo.
     */
    uint64_t stack_low_water = 0;

    /**
     * @brief Puntero a codigo JIT a ejecutar al iniciar el proceso.
     *
     * Si != nullptr, el scheduler salta a este codigo nativo ANTES de
     * iniciar el bucle interp.  Util para JIT-ear @c main (que es
     * free function y no se invoca via CALLVIRT, asi que el hook
     * normal no lo dispara).
     *
     * Cuando el JIT-eated @c main retorna, el proceso queda en HALT
     * automaticamente (sin ejecutar el interp).  Se usa una sola vez
     * (el campo se limpia tras la primera invocacion).
     *
     * Set por @c Loader::load_executable cuando JIT esta on y main
     * compila correctamente.
     */
    void *jit_entry_fn = nullptr;

    /**
     * @brief Puntero cacheado a la @c HandleTable del @c gc_heap, para el JIT.
     *
     *  D.7 (principio "JIT inline > runtime"): el codigo JIT-eado
     * inline-a @c GcHeap::deref leyendo @c data_/@c count_ de esta tabla
     * (offsets 0/8) en vez de hacer un CALL a @c vrt_gc_deref (~6x: 30ns
     * -> 5ns).  Se inicializa UNA sola vez en el constructor a
     * @c gc_heap.jit_handle_table_ptr(); la direccion es estable durante
     * toda la vida del proceso (el GcHeap no se mueve).
     *
     * El offset de este campo dentro de ProcessVM esta fijado por
     * @c VESTA_PROC_JIT_HANDLE_TABLE_OFFSET (abi.h) + static_assert en
     * @c abi_checks.cpp; el JIT lo usa como displacement: el inline hace
     * @c mov base, [rbx + JIT_HANDLE_TABLE_OFFSET].
     */
    void *jit_handle_table = nullptr;

    /**
     * @brief Buffer del state-transfer del OSR ( D.8), indexado por IR
     * VID.
     *
     * Cuando un loop caliente en codigo C1 cruza el umbral de iteraciones
     * (contador por back-edge), el trigger escribe los valores vivos del loop
     * header en @c osr_buffer[vid] (1 celda uint64 por IR value id); el
     * OSR-entry del C2 recompilado los lee para reanudar el loop sin repetir
     * el preheader.  El buffer-por-VID es regalloc-independiente: C1 y C2
     * comparten el namespace de IR VIDs (el clon C2 los preserva), asi cada
     * lado usa SU propia asignacion fisica sobre la misma celda.
     *
     * Alocado en el ctor SOLO cuando @c VESTA_OSR_COUNT esta activo
     * (@c nullptr por defecto -> cero coste).  Su offset esta fijado por
     * @c VESTA_PROC_OSR_BUFFER_OFFSET (abi.h) + static_assert; el JIT lo lee
     * con @c mov rax, [rbx + OSR_BUFFER_OFFSET].
     */
    uint64_t *osr_buffer = nullptr;

    /**
     * @brief El asignador de ESTE programa, ya compilado, si lo hay.
     *
     * Cada modo llega a la memoria por su mecanismo -- el interprete por su
     * instruccion, el codigo compilado por una llamada directa, el binario
     * nativo por el enlazado -- pero el monton tiene que ser UNO.  Con dos, un
     * bloque se pide por un camino y se suelta por otro, y eso no falla donde
     * se comete.
     *
     * Aqui viven las direcciones de los puntos de entrada del programa (el
     * suyo si lo declaro con @c @AllocatorOverride, el de la biblioteca si no),
     * que el cargador compila antes de arrancar.  Cuando estan, la instruccion
     * de la maquina las usa; cuando no -- un programa que no trae ninguno, o lo
     * que se reserve antes de que esten listas -- se queda el asignador propio,
     * que sigue siendo el respaldo.
     */
    uint64_t alloc_del_programa = 0;
    uint64_t free_del_programa = 0;

    uint64_t tsc{}; ///< Contador de instrucciones ejecutadas (Time Stamp
                    ///< Counter virtual)

    /**
     * @brief Marca temporal en nanosegundos a la que debe despertar el proceso.
     *
     * Cuando el proceso entra en estado BLOCK (p.ej. por una instruccion
     * sleep), este campo almacena el instante futuro en el que debe pasar a
     * READY. Un valor 0 indica que no hay temporizador activo.
     */
    uint64_t time_sleep{};

    state_err_thread err_thread =
        THREAD_NO_ERROR; ///< Ultimo error ocurrido en el proceso

    /**
     * @brief Estado actual del proceso dentro de la FSM del scheduler.
     *
     * el campo es @c std::atomic<vm_state> para permitir
     * acceso seguro desde varios hilos (scheduler propietario + remoto
     * que invoca @c make_ready desde otro scheduler en escenarios
     * multi-thread real con @c --schedulers N>1).  Los operadores
     * implicitos @c operator T() y @c operator=(T) realizan load/store
     * con memory_order seq_cst por defecto; las rutas calientes que
     * necesitan ordering relajado usan @c .load(...)/.store(...)
     * explicitamente.
     */
    std::atomic<vm_state> state{NEW};

    /**
     * @brief bandera de wake-up pendiente para resolver
     * la race "lost wakeup" en multi-thread.
     *
     * Cuando otro hilo (msgsend cross-scheduler, fulfill, monitor notify,
     * etc.) invoca @c make_ready y observa que el proceso esta en un
     * estado activo (EXECUTE/DECODE/RUNNING/READY), no puede transicionar
     * el state a READY (perderia la ejecucion en curso).  En su lugar
     * pone @c wake_pending=true.  El scheduler propietario, al transicionar
     * EXECUTE -> WAIT_IO por bloqueo, hace exchange(false) sobre este
     * flag.  Si era true, abandona la transicion y vuelve a READY (un
     * mensaje llego mientras el proceso decidia dormirse).
     */
    std::atomic<bool> wake_pending{false};

    /**
     * @brief B4.3: flag de "notify recibido" para que MONWAIT no
     * re-bloquee tras un wake.
     *
     * Set por @c monnoti / @c monnota en el proceso popeado de la cola
     * CONDVAR.  Consumido por @c monwait al re-ejecutar tras wake:
     * si esta set, lo limpia y AVANZA el PC (sin re-bloquear).
     * Lock-free (atomic exchange).
     */
    std::atomic<bool> condvar_notified{false};

    // --- Cache de instrucciones descodificadas (icache) ---
    DecodedInstr icache[ICACHE_SIZE] =
        {}; ///< Tabla de instrucciones descodificadas indexada por
            ///< icache_index(PC).  Con varias vias, el conjunto `s` ocupa las
            ///< entradas [s*ICACHE_WAYS, s*ICACHE_WAYS + ICACHE_WAYS).

#if ICACHE_WAYS > 1
    /// A que via toca desalojar en cada conjunto.  Reemplazo FIFO, no LRU: con
    /// dos vias basta para el caso que se quiere arreglar -- dos direcciones
    /// alternandose en el mismo conjunto, que con FIFO caben las dos y dejan
    /// de fallar -- y cuesta un byte por conjunto en vez de bits de edad.
    uint8_t icache_way[ICACHE_SETS] = {};
#endif

    DecodedInstr *decoded_ptr =
        nullptr; ///< Puntero a la entrada icache activa durante DECODE/EXECUTE

    /// Hueco para descodificar SIN cachear.  Se usa cuando la ranura de icache
    /// que tocaria es la que se esta ejecutando: pisarla dejaria rancio el
    /// puntero que el run_loop sostiene a traves de `exec_cached`.  Ver
    /// `icache_victim`.
    DecodedInstr decoded_scratch = {};

    /// Entrada de icache ANCLADA: no se desaloja aunque toque.  La pone
    /// `exec_bundle` con su cabecera mientras ejecuta, porque ahi
    /// `decoded_ptr` apunta a la arena y no protegeria la entrada por la que
    /// el run_loop entro.  Sin esto no se pueden meter llamadas en un paquete.
    DecodedInstr *icache_pinned = nullptr;

#if VM_BUNDLES
    /// Paquetes formados para este proceso (ver runtime/bundle.h).  El tipo va
    /// borrado a `void*` para que ESTA cabecera, que la incluye medio mundo, no
    /// tenga que conocer `BundleArena`: `bundle.h` incluye a esta, no al reves.
    void *bundle_arena = nullptr;

    /// Si se forman paquetes.  Se mira SOLO en el camino de fallo de icache
    /// (0,57% de las ejecuciones), nunca en el hot path: en el despacho la
    /// diferencia ya esta en a donde apunta `exec_cached`.
    ///
    /// APAGADO por defecto: hasta que este medido, el binario que se entrega se
    /// comporta exactamente como antes.  Encenderlo es esta linea.
    bool bundles_on = false;

    /// Si al formar un paquete se REORDENA su contenido.
    ///
    /// Va aparte de `bundles_on` porque son dos preguntas: formar paquetes
    /// ahorra despachos, reordenar dentro busca fusion, independencia y
    /// localidad.  Medirlas juntas no dice cual aporta que.
    ///
    /// Es un campo del PROCESO y no solo la variable de entorno
    /// `VESTA_NO_BUNDLE_REORDER` porque esa se lee una vez: con ella no se
    /// pueden medir los tres modos -- escalar, paquetes, paquetes+reorden -- en
    /// la misma ejecucion, que es justo lo que hace comparable la medida.  La
    /// variable sigue mandando para apagarlo todo desde fuera.
    ///
    /// Se mira donde `bundles_on`: en el fallo de icache, nunca en el hot path.
    bool bundle_reorder_on = true;

    /// Fusionar pares dentro del paquete, por PROCESO.
    ///
    /// Mismo motivo que el de arriba, y por eso va al lado: la variable de
    /// entorno `VESTA_NO_BUNDLE_FUSE` se lee una vez y no permite medir con y
    /// sin fusion en la MISMA ejecucion, que es lo unico que hace comparables
    /// los dos numeros.  Sin este eje aparte, la fusion quedaba dentro del
    /// motor de paquetes y no se podia decir cuanto aporta.
    ///
    /// Se mira donde los otros dos: en el fallo de icache, nunca en el hot
    /// path.
    bool bundle_fuse_on = true;

    /// Repartir paquetes a un hilo ayudante, por PROCESO.  Apagado por
    /// defecto: mientras sea un experimento no debe cobrarle nada al camino
    /// normal.  Lo enciende `VESTA_BUNDLE_OOO` o quien mida.
    bool bundle_ooo_on = false;

    /**
     * @brief Lo que tocan los paquetes que estan EN VUELO en el ayudante.
     *
     * Es un marcador, y es lo que permite no esperar por paquete: mientras lo
     * que viene no coincida con esto, el hilo principal sigue sin sincronizar
     * con nadie.  Cuando coincide, se vacia la cola y se limpia.
     *
     * Sin el, la unica forma segura de continuar seria esperar despues de cada
     * entrega -- que es lo que hacia la version anterior, y por eso perdia: la
     * barrera estaba en el camino critico SIEMPRE.
     */
    struct OooInflight {
        uint16_t reg_read = 0;
        uint16_t reg_write = 0;
        /// El banco VECTORIAL, aparte del general: son sitios distintos, y
        /// juntarlos inventaria dependencias que no existen.  Sin ellos, dos
        /// paquetes de coma flotante sobre el mismo registro se veian
        /// independientes.
        uint16_t vec_read = 0;
        uint16_t vec_write = 0;
        uint8_t field = 0;
        bool mem = false;
    };
    OooInflight ooo_inflight;

    /**
     * @brief He delegado ejecucion desde la ultima espera?
     *
     * Local al proceso, y por eso existe: sin el, comprobar si queda algo en
     * vuelo obliga a leer una atomica que el AYUDANTE escribe, o sea a traerse
     * su linea de cache en CADA despacho -- aunque no se haya delegado nada en
     * toda la ejecucion --.  Eso es rebote entre nucleos puro y salia en el
     * perfil.
     *
     * Y no es una aproximacion: solo este hilo encola ejecucion, asi que si no
     * ha encolado nada desde la ultima espera, no hay nada que esperar.  Cuando
     * si lo hay, entonces si toca mirar la atomica.
     */
    bool ooo_exec_dirty = false;

    /**
     * @brief Le toca a ESTE hilo el paquete que viene.
     *
     * DELEGAR UNO, EJECUTAR UNO.  Con material del todo independiente, dejar
     * que delegue sin freno hace que el principal delegue TODO y no ejecute
     * nada: se queda de repartidor, el ayudante hace el trabajo en serie y
     * encima se paga el traspaso.  Medido en la mezcla `independiente`: 7.808
     * entregas y 0,62 paradas por entrega -- la tuberia SI se formaba -- y aun
     * asi 366 MIPS contra 490 sin repartir.
     *
     * Repartiendo de uno en uno trabajan los dos nucleos, que es lo unico que
     * puede ganar tiempo.  Y es el limite natural: con UN ayudante, mas de un
     * paquete por delante solo alarga la cola.
     *
     * Vive en el PROCESO y no en el despacho porque un despacho es un paquete
     * de largo salvo que encadene: con la alternancia dentro del despacho se
     * delegaba uno y se ejecutaba lo que quedara de ese mismo, o sea casi nada
     * -- 5,5% del trabajo repartido, cuando el techo de este reparto es la
     * mitad --.
     */
    bool ooo_owner_turn = false;

    /**
     * @brief Se sigue intentando delegar EJECUCION?
     *
     * Delegar la ejecucion de un paquete solo sirve si el siguiente es
     * independiente, y en un bucle no lo es: el cuerpo que viene comparte el
     * acumulador consigo mismo.  Cuando pasa eso, cada entrega obliga a una
     * parada y el reparto es un fork-join con otro nombre -- puro coste --.
     *
     * En vez de decidirlo por adelantado, se MIDE: se prueba durante las
     * primeras `kOooProbe` entregas y, si practicamente todas acabaron en
     * parada, se deja de intentar.  Delegar el ANALISIS sigue igual, que ese no
     * depende de nada y siempre compensa.
     *
     * Y se VUELVE A PROBAR mas adelante, con la espera doblandose cada vez que
     * falla.  Apagarlo para siempre daria por hecho que un programa se comporta
     * igual de principio a fin, y no es cierto: recorre fases, y la respuesta
     * cambia con ellas.  Con el reintento espaciado, uno que nunca gana acaba
     * pagando casi nada y uno que cambia se entera pronto.
     */
    bool ooo_try_exec = true;
    uint32_t ooo_exec_wait = 0;    ///< despachos que faltan para reintentar
    uint32_t ooo_exec_backoff = 0; ///< y cuantos seran la proxima vez
    /// Espera del primer reintento y su tope, en despachos.
    static constexpr uint32_t kOooRetry = 4096;
    static constexpr uint32_t kOooRetryMax = 262144;

    /**
     * @brief Se sigue adelantando la DESCODIFICACION?
     *
     * Adelantarla sale muy a cuenta cuando acierta -- descodificar es el 5,7%
     * del banco, cinco veces lo que cuesta formar paquetes -- y muy cara cuando
     * no: la tabla de adelanto son 38 KB que el ayudante machaca mientras el
     * principal la consulta, y en un programa que YA va justo de cache eso es lo
     * peor que se le puede anadir.  Medido en un tramo recto de 8188
     * instrucciones: 3,4% de aciertos y el caso pasa de 216 a 55 MIPS.
     *
     * Asi que se prueba y se decide con el dato: si en una ventana de
     * `kDecodeProbe` consultas no acierta al menos la mitad, se deja de
     * encargar.
     *
     * Y se VUELVE A PROBAR mas adelante.  Apagarlo para siempre daria por hecho
     * que un programa se comporta igual de principio a fin, y no es cierto:
     * recorre fases -- carga, un bucle que cabe, otro que no --, y la respuesta
     * cambia con ellas.  El reintento se espacia cada vez que vuelve a fallar,
     * asi que un programa que de verdad no gana nunca acaba pagando casi nada,
     * y uno que cambia de fase lo aprovecha en cuanto le toca.
     */
    bool ooo_try_decode = true;
    uint32_t ooo_decode_probe = 0; ///< consultas contadas en esta ventana
    /// ...y cuantas acertaron.  Propio y no el de la telemetria: ese solo
    /// cuenta con las estadisticas pedidas, y entonces la decision dependeria
    /// de si alguien esta mirando.
    uint32_t ooo_decode_hits = 0;
    uint32_t ooo_decode_wait = 0;    ///< consultas que faltan para reintentar
    uint32_t ooo_decode_backoff = 0; ///< y cuantas seran la proxima vez
    /// Cuantas consultas tiene una ventana.  Bastantes para que el porcentaje
    /// signifique algo, pocas para no arrastrar la perdida: en el caso malo
    /// cada consulta fallida cuesta una linea de cache disputada.
    static constexpr uint32_t kDecodeProbe = 128;
    /// Espera del primer reintento, y su tope.  Se dobla en cada fallo: un
    /// programa que nunca gana acaba probando una vez cada 64 mil consultas, o
    /// sea nada; uno que cambia de fase no tarda en enterarse.
    static constexpr uint32_t kDecodeRetry = 1024;
    static constexpr uint32_t kDecodeRetryMax = 65536;
    uint32_t ooo_probe_splits = 0; ///< entregas contadas durante la prueba
    uint32_t ooo_probe_drains = 0; ///< ...y cuantas acabaron en parada
    /// Cuantas entregas se prueban antes de decidir.
    ///
    /// Treinta y dos.  Bastantes para que la proporcion signifique algo -- una
    /// racha de treinta y dos entregas seguidas acabando en parada no es
    /// casualidad -- y pocas para no arrastrar la perdida: la prueba se paga en
    /// CADA proceso, y con 256 los programas cortos se pasaban la vida
    /// probando.
    static constexpr uint32_t kOooProbe = 32;

    /**
     * @brief El `pc` cuya entrada acaba de pisar la CABECERA de otro paquete.
     *
     * Lo pone el camino de fallo justo antes de sobrescribir la entrada, que es
     * el unico momento en que se sabe QUE habia ahi; para cuando forma el
     * paquete, el ocupante anterior ya se perdio.  Vale `UINT64_MAX` cuando no
     * hay ninguno.  Solo con `ICACHE_HEAD_SHIFT`.
     */
    uint64_t icache_head_clash = UINT64_MAX;

    /**
     * @brief Contar lo que hace la maquinaria de paquetes: TODO, no solo el
     *        reordenamiento.
     *
     * Se pide en EJECUCION -- este campo, o `VESTA_BUNDLE_STATS` --, no al
     * compilar.  Atarlo al perfil de construccion obligaba a reconstruir el
     * proyecto para mirar por que un programa forma los paquetes que forma, y
     * entonces lo que se mira ya no es el binario que se ejecuta.
     *
     * Apagado no cuesta: ninguno de estos contadores va por INSTRUCCION -- van
     * por paquete formado, por despacho o por encadenamiento --, asi que es una
     * rama que casi siempre no se toma cada treinta y tantas instrucciones.  Y
     * el reordenador ni eso: tiene dos instanciaciones y esto elige cual se
     * llama, de modo que la de por defecto no lleva ni el contador ni la rama.
     */
    bool bundle_stats_on = false;

    /**
     * @brief Anidamiento actual en paquetes.  Cero = no hay ninguno en curso.
     *
     * CUENTA, no es un booleano, porque se anida: una instruccion de dentro de
     * un paquete puede provocar un fallo de icache que forme otro.
     *
     * Es lo que hace segura la recoleccion de la cache: mientras sea distinta
     * de cero hay un `Bundle*` en manos de alguien y no se puede ni copiar ni
     * reiniciar nada.
     */
    uint32_t bundle_depth = 0;

    /**
     * @brief Hay una region esperando a reiniciarse.
     *
     * Va AQUI y no en la arena a proposito: se mira al salir de CADA paquete,
     * o sea en camino caliente, y asi es una lectura de memoria que ya se esta
     * tocando en vez de una indireccion mas.  Casi siempre es false y la rama
     * se predice sola.
     */
    bool bundle_needs_grace = false;
#endif

#if VM_BUNDLES
    /// Telemetria de paquetes.  Existe siempre y se llena solo cuando se pide
    /// con @ref bundle_stats_on (ver `BSTAT` en bundle.cpp).
    ///
    /// Podria ir tambien bajo la bandera, pero entonces un test compilado con
    /// la telemetria encendida y enlazado contra un `vmcore` sin ella veria un
    /// `ProcessVM` de otro tamano: corrupcion en ejecucion, sin error de
    /// compilacion ni de enlazado.  48 bytes en una estructura que ya lleva
    /// 64 KB de icache no cuestan nada, y con los incrementos fuera el codigo
    /// generado es identico.  Lo que no puede pasar es que MEDIR el coste
    /// cambie lo que se mide, y eso se cumple igual.
    struct {
        uint64_t formed, not_formed, dispatches, instrs_in_bundles, aborts,
            flushes, shrinks, chained, collects;
        /// Cabeceras que NO se formaron porque su ranura de icache ya tenia
        /// otra: la cabecera se corre a la instruccion siguiente.  Solo con
        /// `ICACHE_HEAD_SHIFT`; sin el vale cero y eso es la verdad.
        uint64_t head_shifts;
        /// Pares convertidos en UNA instruccion al formar.  Es la unica cifra
        /// que dice cuanto baja el RECUENTO, que es el cuello del interprete.
        uint64_t fused;
        /// Paquetes ejecutados REPARTIDOS entre dos nucleos.  Dice si el
        /// reparto llega siquiera a intentarse, que es lo primero que hay que
        /// saber antes de mirar si compensa.
        uint64_t ooo_split;
        /**
         * @brief Instrucciones DELEGADAS, sumadas.
         *
         * Dividida por `ooo_split` da el TAMANyO del bocado: cuantas
         * instrucciones se le dan al ayudante en cada entrega.  Es la cifra que
         * decide si el reparto puede compensar, y no estaba.
         *
         * Sin ella se lee mal el perfil: con 0,755 s esperando contra 0,411 s
         * trabajando, la conclusion parece "coordinar es caro" cuando lo que
         * dice de verdad es que el bocado es diminuto.  Un traspaso entre
         * nucleos cuesta cientos de nanosegundos y no se amortiza con media
         * docena de instrucciones, pero eso no es un limite del mecanismo: es
         * un limite de lo que se le esta dando.
         */
        uint64_t ooo_delegated;
        /// Cuantos paquetes se MIRARON buscando corte.  Cero significa que la
        /// busqueda no llego a correr -- va con el reparto, porque cuesta un
        /// 8% --, y sin este contador "partibles=0" se leia como "no hay donde
        /// partir", que es otra cosa muy distinta.
        uint64_t ooo_searched;
        /// Paquetes en los que SI se encontro un corte al formar.  Con este y
        /// `ooo_split` se distingue "no hay donde partir" de "hay donde pero el
        /// ayudante nunca lo coge".
        uint64_t ooo_splittable;
        /**
         * @brief Por que NO se delego un paquete, al EJECUTARLO.
         *
         * 0=tiene una barrera         1=lee rip
         * 2=depende de lo que vuela   3=la cola estaba llena
         * 4=el ayudante lo tiene otro proceso
         *
         * Sin esto, "delegados=0" no dice si es que no hay paralelismo o si es
         * que una condicion mia lo descarta todo.  Ya han fallado dos
         * suposiciones seguidas por no tenerlo.
         */
        uint64_t ooo_reject[6];
        /// Cuantas veces hubo que VACIAR la cola porque lo siguiente dependia
        /// de lo que estaba en vuelo.  Dividido por `ooo_split` dice si esto es
        /// una tuberia o un fork-join disfrazado: uno a uno seria lo segundo.
        uint64_t ooo_drains;
        /// Fallos de icache que el ayudante ya traia DESCODIFICADOS, y los que
        /// no.  Es la medida de si adelantar la descodificacion sirve: llegar
        /// tarde se lee igual que no haberlo intentado, y no es lo mismo.
        uint64_t predecode_hits;
        uint64_t predecode_misses;
        /// Paquetes cuyo ANALISIS se le encargo al ayudante.
        uint64_t ooo_prepares;
        /// ...y los que hubo que preparar AQUI porque no habia sitio en la cola
        /// o en la arena.  Va aparte porque es la medida de si el ayudante da
        /// abasto: si esto domina, el reparto del analisis no esta quitando
        /// nada del camino critico.
        ///
        /// Antes estos paquetes se quedaban CRUDOS -- correctos pero sin
        /// reordenar ni fusionar, y para siempre, porque a un paquete ya
        /// formado no vuelve a preguntarle nadie --.  Eran 32 de 65 en un tramo
        /// recto largo.
        uint64_t ooo_prepares_lost;
        /// Versiones preparadas que el hilo de ejecucion llego a RECOGER.  Con
        /// la de arriba dice si la preparacion llega a tiempo de servir para
        /// algo o el paquete muere antes de estrenarla.
        uint64_t ooo_improved;
        /**
         * @brief Por que NO se fusiono un par, contado por razon.
         *
         * Indexado por @c FuseReject.  Un fusionador que solo publica cuantos
         * pares junto es indistinguible de uno roto: si sale cero, no se sabe
         * si es que no habia material, si el patron esta mal escrito o si lo
         * que aprieta es la ventana del paquete.  Es la misma regla que rige
         * los analisis del ASA -- al renunciar, se dice POR QUE --, y la unica
         * forma de afinar los patrones mirando datos.
         */
        uint64_t fuse_reject[9];
        /// Veces que la mirada mas alla del paquete se quedo CIEGA: lo
        /// primero que hay detras transfiere control o tiene efectos de cota
        /// inferior, asi que todo se supone vivo.  Sin este contador no se
        /// distingue "el temporal sigue vivo de verdad" de "no se pudo mirar".
        uint64_t lookahead_blind;

        /* --- Cuanto capturaria un opcode que NO existe ----------------------
         *
         * Son los dos numeros que deciden si merece la pena gastar una ranura
         * de la tabla extendida, y hay que mirarlos JUNTOS.  Un par en el que
         * la primera produce un valor que la segunda consume es candidato a
         * fusionarse en una instruccion nueva, pero solo si ese valor MUERE:
         * si sigue vivo, la fusionada tendria que escribirlo igual y no
         * ahorraria nada.
         *
         * Separarlos importa porque distinguen dos conclusiones opuestas:
         * "falta el opcode" y "el opcode no serviria de nada porque no se
         * puede demostrar que el temporal muere".  Es la pared con la que ya
         * choco el patron de redirigir el destino. */
        /**
         * @brief Que instruccion encabezaba un par que NINGuN patron miro.
         *
         * Indexado por `(extendida ? 256 : 0) + opcode`.  Es la lista de
         * trabajo del fusionador: mientras el 84% de los rechazos sea "la
         * primera no encaja", lo que falta son PATRONES, y esto dice cuales
         * escribir por peso en vez de a ojo.
         */
        uint64_t uncovered[512];

        /**
         * @brief Que instruccion iba SEGUNDA cuando la primera si encajaba.
         *
         * El companyero del de arriba, y hace falta por lo mismo: al cubrir un
         * patron nuevo, sus pares se mueven de "la primera no encaja" a "la
         * segunda no vale", y sin esto ese bucket tampoco dice cual escribir.
         * Entre los dos, la lista de trabajo esta completa por los dos lados.
         */
        uint64_t unmatched_second[512];

        uint64_t newop_ready;    ///< el temporal muere: un opcode lo capturaria
        uint64_t newop_livewall; ///< el temporal sigue vivo: no lo capturaria

        /* Y los mismos PONDERADOS POR EJECUCION, que es lo que de verdad
         * decide: un paquete de arranque que corre una vez no vale lo que el
         * cuerpo de un bucle que corre un millon.  Se acumulan AL ENTRAR, que
         * es el unico momento en que el paquete es seguro de leer: al final ya
         * puede estar recogido. */
        uint64_t fused_weighted;           ///< instrucciones ahorradas de verdad
        uint64_t newop_ready_weighted;     ///< las que ahorraria un opcode nuevo
        uint64_t newop_livewall_weighted;  ///< las que no rescataria ninguno

        /// Instrucciones que el planificador movio de sitio al formar.  Se
        /// cuenta en UNIDADES, no en veces: lo que interesa es cuanto se
        /// reordena, no cuantos paquetes se tocaron.
        uint64_t reordered;
        /// Paquetes que quedaron distintos.  Con la de arriba da cuanto se
        /// mueve POR paquete, que es lo que dice si el planificador esta
        /// haciendo algo o rozando.
        uint64_t reorder_bundles;
        /// Veces que cada criterio DECIDIO la eleccion, en el orden de
        /// `CriterionId`.  Es lo unico que contesta "por que se movio": con el
        /// total solo se sabe que se movio.
        uint64_t reorder_wins[4];
        /// Candidatas que se puntuaron.  El denominador: sin el, "fusion gano
        /// 20 veces" no dice si fue de 20 ocasiones o de 20.000.
        uint64_t reorder_choices;
    } bundle_stats = {};
#endif

    // --- Memoria privada del proceso ---
    vm::ArenaManager
        manager_mem_priv{}; ///< Gestor de arenas privadas de este proceso

    tlb::LazyHybridTLB tlb{}; ///< TLB privado del proceso
    vm::VirtualMemory
        vm_mem; ///< Interfaz de memoria virtual (combina TLB + ArenaManager)

    // --- Scratch para inline-asm en el interprete ( AS inc.6) ---
    // Buffer host de 16 qwords que el helper @c vrt_inline_asm_exec usa
    // como @c ctx[16] del trampolin (marshalling GP host <-> valores VM).
    // Vive en el ProcessVM (host), no en vm_mem, porque el trampolin
    // nativo lo dereferencia como puntero host crudo.  Sincronico y
    // no-reentrante por proceso (cada bloque asm lo usa secuencialmente).
    /**
     * @brief Estado que el trampolin de ensamblador mete y saca del bloque.
     *
     * Los 16 registros generales primero y, tras ellos, los 16 del banco ancho
     * a 512 bits (8 huecos de 64 bits cada uno).  El banco ancho hace falta
     * porque el micro asm existe justo para las instrucciones que NO tienen
     * representacion fiel en el IR -- y muchas de esas son vectoriales.  Sin
     * sitio donde ponerlas, esos bloques se quedaban sin elevar, y la
     * limitacion no era del lenguaje sino de este array.
     *
     * Alineado a 64 porque las formas de mover 512 bits alineados lo exigen.
     *
     * El tamano NO se escribe aqui: sale del ABI compartido con quien lo llena
     * (@ref vx::kAsmCtxQwords).  Estaba puesto `16 + 16*8`, que describe x86
     * con AVX y nada mas -- en arm64, con 31 generales, o con AVX-512 y sus 32
     * ranuras anchas, el registro alto caia FUERA del array.  Eso no da error:
     * escribe pasado el final.
     */
    alignas(64) uint64_t asm_ctx[vx::kAsmCtxQwords] = {0};

    // --- GC del proceso ---
    gc::GcHeap gc_heap{manager_mem_priv, 2 * 1024 * 1024,
                       8 * 1024 * 1024}; ///< Heap del GC (min 2 MiB, max 8 MiB)
    /// Proveedor de raices del GC sobre este proceso (lo conecta el ctor via
    /// gc_heap.set_root_provider).  Solo guarda `this`; seguro en member-init.
    ProcessVMRootProvider gc_root_provider_{this};
    gc::RawAllocator raw_alloc{}; ///< Asignador raw sin GC

    // --- Sistema de objetos (OOP) ---
    loader::FrameHeader *frame_stack =
        nullptr; ///< Cabeza de la cadena de FrameHeaders activos (push en
                 ///< CALLVIRT, pop en RET/THROW)

    /**
     * @brief Pool de FrameHeader con free list LIFO.
     *
     * Motivacion: la implementacion ingenua hacia `new
     * loader::FrameHeader{}` por cada CALLVIRT/CALLM/CALLVMR/CALLCLOSURE
     * y `delete frame` por cada RET.  En benchmarks con 30M calls eso
     * son 30M malloc + 30M free a ~150 ns cada uno => ~9 segundos solo
     * en el heap del compilador C++.  Era el cuello de botella principal
     * de cualquier programa intensivo en dispatch virtual.
     *
     * El pool reemplaza esa ruta por O(1) acquire/release sobre un free
     * list intrusivo: cuando un frame esta libre, su campo @c prev
     * apunta al siguiente libre (reusamos el campo porque ya esta
     * presente y los frames libres no participan de la cadena de
     * activacion).  La medicion empirica tras este cambio bajo el
     * coste por call/return a ~5 ns (30x mas rapido).
     *
     * Asigna chunks de 256 frames.  Crece bajo demanda.  Los chunks
     * se liberan en el destructor del pool (al morir el ProcessVM).
     */
    struct FrameHeaderPool {
        std::vector<loader::FrameHeader *>
            chunks; ///< Chunks alocados con `new[]`.
        loader::FrameHeader *free_list_head = nullptr;
        static constexpr size_t CHUNK_SIZE = 256;

        /**
         * @brief Saca un FrameHeader libre del pool.  Si el free list
         * esta vacio, aloca un nuevo chunk de @c CHUNK_SIZE frames.
         * El frame devuelto NO esta inicializado: el caller debe
         * setear todos los campos antes de usarlo.
         */
        inline loader::FrameHeader *acquire() {
            if (!free_list_head) {
                auto *chunk = new loader::FrameHeader[CHUNK_SIZE];
                chunks.push_back(chunk);
                // Encadenar el chunk al free list via campo `prev`.
                for (size_t i = 0; i < CHUNK_SIZE; ++i) {
                    chunk[i].prev = free_list_head;
                    free_list_head = &chunk[i];
                }
            }
            loader::FrameHeader *f = free_list_head;
            free_list_head = f->prev;
            /* Sprint MMM-ext leak-fix: garantizar host_allocas=nullptr
             * para todo frame fresco.  Los chunks recien alocados con
             * `new[]` ya cumplen (default-init = zero); los frames
             * reciclados via release() pueden haber tenido un puntero
             * vivo, asi que aqui forzamos el reset.  El release()
             * libera la lista; este reset es defensa contra reuse.
             * Coste: 1 store por acquire (~1 ns), irrelevante vs el
             * coste de un CALLVIRT (~50 ns). */
            f->host_allocas = nullptr;
            return f;
        }

        /**
         * @brief Devuelve un FrameHeader al pool.  El frame puede
         * estar en cualquier estado; lo unico que importa es el
         * campo `prev` que se reusa para el free list.
         */
        inline void release(loader::FrameHeader *f) {
            f->prev = free_list_head;
            free_list_head = f;
        }

        ~FrameHeaderPool() {
            for (auto *c : chunks)
                delete[] c;
        }
    };

    FrameHeaderPool
        frame_pool; ///< Pool de FrameHeader para CALLVIRT/CALLM/CALLVMR/RET.

    /**
     * @brief Contador de llamadas activas a `loadmod` no retornadas.
     *
     * Cada `loadmod` incrementa el contador antes de saltar al main del
     * modulo cargado.  El main del modulo tipicamente termina con `hlt`
     * (porque fue compilado para ejecutarse standalone), pero al ser
     * llamado via loadmod debe regresar al caller via RET.  La solucion
     * es runtime: cuando un `hlt` se ejecuta con `loadmod_call_depth>0`,
     * se trata como un RET (decrementa contador, pop ret_addr del stack,
     * salta a el).  Esto evita patchar bytecode (la solucion anterior
     * `patch_first_hlt_to_ret` era fragil ante secuencias de bytes 0x00 0x03
     * que aparecen en imm de mov/callvm aleatoriamente).  Soporta
     * loadmodule anidado (counter > 1) sin esfuerzo extra.
     */
    uint32_t loadmod_call_depth = 0;

    /**
     * @brief Pila de valores de retorno de @c loadmodule (BugFix M.dyn
     *        2026-06-05).  El opcode @c loadmod pone @c init_pc en R0
     *        como indicador de exito ANTES de saltar al @c __module_init
     *        del plugin, pero el @c __module_init clobbea R0 (su ultimo
     *        op deja un valor arbitrario).  Para que @c loadmodule
     *        devuelva un valor FIABLE (init_pc != 0 = exito) restauramos
     *        R0 desde esta pila cuando el HLT del plugin se intercepta
     *        como RET (ver @c exec_instr_hlt + @c loadmod_call_depth).
     *        Es una pila para soportar loadmodule anidado.
     */
    std::vector<uint64_t> loadmod_r0_stack;

    uint64_t current_exception = 0; ///< Handle de la excepcion activa durante
                                    ///< el unwinding (0 = sin excepcion)

    /**
     * @brief Frame de excepcion ligero apilado por TRYENTER / desapilado por
     * TRYLEAVE.
     *
     * Permite que compiladores de alto nivel instalen handlers de excepcion en
     * tiempo de ejecucion sin necesidad de anotaciones en el bytecode.
     * do_throw comprueba esta pila antes de recorrer MethodInfo.handlers.
     */
    struct ExceptionFrame {
        uint64_t handler_pc;     ///< Direccion absoluta VM del bloque catch
        loader::ClassInfo *type; ///< Tipo capturado (nullptr = catch-all)
        uint64_t saved_rsp;      ///< RSP al momento del tryenter.
                                 ///< @c do_throw lo restaura antes de saltar
                                 ///< al handler para descartar los push del
        ///< regalloc que no llegaron a pop por el throw.
        uint64_t saved_rbp;         ///< Idem para RBP (frame pointer).
        uint64_t saved_frame_stack; ///< Puntero al @c frame_stack al
                                    ///< momento del tryenter; @c do_throw
                                    ///< unwindea hasta este punto antes de
                                    ///< saltar al handler (descarta frames
                                    ///< de calls dentro del try-body que no
                                    ///< retornaron normalmente).
        uint64_t saved_regs[16];    ///< Snapshot de R0..R15 al
                                    ///< momento del tryenter.
                                    ///< @c do_throw los restaura antes de
                                    ///< saltar al handler para que el catch
                                    ///< vea exactamente el mismo estado que
                                    ///< el try entry (igual que C/C++ exc).
                                    ///< Resuelve la limitacion clasica de
                                    ///< que las vars vivas a traves del try
                                    ///< quedaban con valores stale tras
                                    ///< el throw (regalloc no preservaba
                                    ///< los regs en el unwind).
                                    ///< R0 se preserva PERO el catch lo
                                    ///< sobreescribe con la excepcion.
        /// Excepciones in-JIT (Opcion B).  Si != 0, el handler vive en codigo
        /// JIT-eado (no bytecode): @c do_throw resume via @c vrt_resume_jit
        /// (restaura @c native_rsp/@c native_rbp del frame host y salta a
        /// @c native_catch_addr) en lugar de poner rip=handler_pc para el
        /// interp.  0 = frame de interp (ruta clasica intacta).
        uint64_t native_catch_addr = 0; ///< direccion nativa del bloque catch
        uint64_t native_rsp = 0;        ///< RSP host del frame del try
        uint64_t native_rbp = 0;        ///< RBP host del frame del try
        struct ExceptionFrame *prev;    ///< Frame anterior en la pila
    };

    ExceptionFrame *exc_frame_stack =
        nullptr; ///< Pila de frames TRYENTER activos

    /**
     * @brief Free list de @c ExceptionFrames reciclables.
     *
     * Cuando @c tryleave (bytecode o JIT inline) pop-ea un frame del
     * @c exc_frame_stack, en lugar de hacer @c delete (que llama a
     * @c free de libc, ~30-100 ns + fragmentation del heap), lo empuja
     * a este free list via el campo @c prev.  Subsequent @c tryenter
     * busca aqui primero; si esta vacio, hace @c new normal.
     *
     * Beneficios:
     *   - Cero leak: los frames se reusan, no se descartan.
     *   - O(1) per try/tryleave (sin malloc/free amortizado).
     *   - Inline JIT tryleave puede usar este free list directamente
     *     emitiendo solo 2 instrucciones extra (set prev + update head).
     *
     * Los frames del free list se liberan en el destructor del
     * ProcessVM via @c free_exc_pool (en .cpp).
     */
    ExceptionFrame *exc_free_list = nullptr;

    /// Excepciones in-JIT (Opcion B): handoff transitorio de RSP/RBP host del
    /// frame del try.  El codigo JIT los escribe (MOV [rbx+off], rsp/rbp)
    /// justo antes de llamar a @c vrt_tryenter_jit, que los lee y los copia al
    /// @c ExceptionFrame.  Evita un 5o argumento en pila (Win64).  No es
    /// estado persistente: solo vive entre el store del JIT y la lectura del
    /// wrapper (inmediata, sin reentradas en medio incluso con try anidados).
    uint64_t jit_exc_rsp = 0;
    uint64_t jit_exc_rbp = 0;

    /// Slot reusable para FatalError instance.  Aloca lazy en
    /// el primer @c throw_fatal y se reutiliza en throws sucesivos
    /// (evita alocacion en heap durante un error fatal, donde el GC
    /// puede estar en mal estado).  Layout: ObjectHeader (24) + 4
    /// fields qword-aligned (kind/pc/message/trace) = 56 bytes.
    /// El message y trace apuntan a buffers tambien lazy-asignados
    /// (@c fatal_msg_buf y @c fatal_trace_buf) que se reusan.
    void *fatal_slot = nullptr;
    char *fatal_msg_buf = nullptr;   ///< buffer de mensajes (256 bytes)
    char *fatal_trace_buf = nullptr; ///< buffer de stack trace (4096 bytes)

    /// Recovery point para errores fatales de OS-level (access
    /// violation / SIGSEGV cuando el bytecode dereferencia un
    /// puntero host invalido).  El scheduler hace setjmp aqui antes
    /// de cada batch de instrucciones; el VEH (Windows) o el
    /// handler de SIGSEGV (POSIX) hace longjmp si av_recovery_active
    /// esta activo y el proceso tiene un try/catch envolvente
    /// (exc_frame_stack != nullptr).  Tras el longjmp el scheduler
    /// llama @c throw_fatal con FATAL_SEGMENTATION_FAULT y la
    /// direccion del AV; el flujo normal de @c do_throw redirige al
    /// handler `catch (FatalError e)`.
    ///
    /// Sin esta infra, accesos a punteros host invalidos (e.g.
    /// `*(i32*)0`, deref de un host_ptr stale tras free) crashean
    /// el proceso entero de la VM en lugar de ser capturados.
    std::jmp_buf av_recovery_jmpbuf;
    bool av_recovery_active = false;
    uint64_t pending_av_addr = 0; ///< direccion bruta del AV (informativa)
    /// Codigo de fallo que dio el sistema.  Viaja para poder NOMBRAR lo que
    /// paso cuando no es uno de los conocidos: sin el, un fallo fuera de la
    /// lista se cuenta pero no se puede identificar, y quien lee se queda
    /// igual.
    uint64_t pending_av_os_code = 0;
    /// Tipo de excepcion host que disparo el recovery:
    ///   0 = AV (segfault, default), 1 = DIVIDE_BY_ZERO, 2 = INT_OVERFLOW.
    /// El scheduler lo consulta tras el @c longjmp para emitir el
    /// @c FatalError adecuado.
    /// Que fallo del procesador quedo pendiente de contar.  0xFFFFFFFF = no
    /// hay ninguno; 0 = acceso invalido, 1 = division entre cero, 2 =
    /// desbordamiento.  El centinela hace falta porque 0 es un fallo REAL: sin
    /// el no habia forma de distinguir un acceso invalido de no haber fallado.
    uint32_t pending_av_kind = 0xFFFFFFFFu;
    /// El PC del fallo apunta a la instruccion que fallo, sin haber
    /// avanzado.  Pasa con los fallos que captura el sistema (acceso
    /// invalido, division del procesador): la interrumpen a medias.  En el
    /// resto, el PC ya avanzo y hay que mirar el byte anterior.  Sin
    /// distinguirlo, un fallo en la PRIMERA instruccion de una funcion se
    /// atribuye a la ultima de la anterior -- que es otra funcion.
    bool fatal_pc_exact = false;

    /// Direccion del codigo NATIVO donde ocurrio el fallo, o 0.
    ///
    /// El codigo compilado no va actualizando el PC de la maquina virtual --
    /// ese es el punto de compilarlo --, asi que al fallar el PC que se
    /// conserva es de la ultima vez que se sincronizo y la traza senalaba una
    /// funcion que no era.  Lo unico fiable es esta, que el sistema entrega al
    /// avisar del fallo y que hay que guardar ANTES de desviar la ejecucion.
    uint64_t pending_fault_native_pc = 0;

    /// Puntero de pila NATIVO en el momento del fallo, o 0.
    ///
    /// Con el codigo compilado los marcos de la cadena de llamadas viven en la
    /// pila del anfitrion y no en la de la maquina virtual, que es donde mira
    /// el barrido normal; por eso la traza en JIT solo ensenaba el marco de
    /// arriba.  Guardando por donde iba esa pila se puede recorrer igual.
    uint64_t pending_fault_native_sp = 0;

    /// Registros generales del anfitrion en el momento del fallo, en el orden
    /// de la codificacion x86-64 (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
    /// r8..r15).  Solo valen si @c pending_fault_native_regs_ok.
    ///
    /// El sistema entrega el contexto entero al avisar del fallo y se estaba
    /// tirando todo menos el PC: sin ellos, el desensamblado del codigo nativo
    /// dice QUE instruccion revento pero no CON QUE, que es justo lo que
    /// explica el fallo.
    uint64_t pending_fault_native_regs[16] = {};
    bool pending_fault_native_regs_ok = false;

    /// La direccion nativa guardada es una de RETORNO, no la del fallo.
    ///
    /// Pasa con lo que lanza el propio programa -- un `panic` --: ahi no hay
    /// aviso del sistema y lo unico que se sabe es desde donde se llamo al
    /// ayudante, que apunta al byte SIGUIENTE a la llamada.  Al informar hay
    /// que retroceder uno para caer dentro de la instruccion que de verdad
    /// interviene, que es lo que hace cualquier desenrollador; si no, se marca
    /// la de despues y quien lee no reconoce su propio codigo.
    bool pending_fault_native_is_return = false;

    /// Direccion por la que ARRANCO este proceso.
    ///
    /// Es el fondo de su cadena de llamadas y no tiene direccion de retorno
    /// en ninguna parte: nadie lo llamo, lo puso a correr el cargador (el
    /// proceso principal) o un @c spawn (los hijos).  Al reconstruir una
    /// traza a partir de la pila, ese ultimo escalon no se puede deducir --
    /// hay que saberlo --, y sin el la traza no dice de donde venia todo.
    /// Cada proceso guarda el suyo: el de un hijo es su cuerpo, no @c main.
    ///
    /// El valor "sin fijar" es @c UINT64_MAX, no 0: el codigo empieza en la
    /// direccion 0, asi que 0 es una entrada perfectamente valida y usarlo
    /// como vacio descartaba justo el caso normal.
    uint64_t entry_pc = UINT64_MAX;

    StringInternPool *str_intern_pool =
        nullptr; ///< Pool de strings internados (creado bajo demanda)

    Scheduler
        &scheduler; ///< Referencia al scheduler propietario de este proceso

    distrib::Mailbox *mailbox =
        nullptr; ///< Buzon de mensajes distribuido (creado bajo demanda por
                 ///< DistRuntime)

    // --- Campos para procesos creados remotamente via rspawn ---
    uint64_t rspawn_future_id =
        0; ///< future_id en el nodo origen que debe resolverse con r0 al
           ///< terminar (0 = no es rspawn)
    uint32_t rspawn_origin_node =
        0xFFFFFFFFu; ///< node_idx del nodo que envio el rspawn (0xFFFFFFFF = no
                     ///< es rspawn)

    /**
     * @brief Construye un proceso virtual y lo asocia al scheduler indicado.
     * @param scheduler Scheduler que gestionara este proceso.
     * @param pid       Identificador global unico del proceso.
     */
    ProcessVM(Scheduler &scheduler, GlobalPID pid);

    /**
     * @brief Invalida todas las entradas del icache del proceso.
     *
     * Debe llamarse cuando el espacio de codigo del proceso cambia (p.ej.
     * tras JIT o carga dinamica de codigo) para evitar ejecutar instrucciones
     * descodificadas sobre codigo antiguo.
     */
    void reset_cache();

    /**
     * @brief Carga codigo en bruto en la memoria virtual del proceso.
     *
     * Mapea @p code a partir de @p address en el espacio de memoria del
     * proceso y pone su estado a RUNNING para que el scheduler pueda
     * comenzar a ejecutarlo.
     *
     * @param address Direccion virtual donde se escribira el codigo.
     * @param code    Vector de bytes con las instrucciones a cargar.
     */
    void load_raw_code(uint64_t address, const std::vector<uint8_t> &code);

    /**
     * @brief Genera un resumen de estado del proceso en texto.
     * @return Cadena con los valores mas relevantes del proceso.
     */
    std::string vm_summary() const;

    /**
     * @brief Destructor: libera todos los recursos del proceso.
     */
    ~ProcessVM();

    /**
     * @brief Genera una representacion textual detallada del proceso.
     * @return Cadena con el volcado completo del estado del proceso.
     */
    [[nodiscard]] std::string to_string() const;

  private:
};

/**
 * @brief Busca @p pc en la icache.  Devuelve la entrada, o nullptr si falla.
 *
 * Un solo sitio para el chequeo de acierto.  Estaba copiado en cuatro -- el
 * descodificador y tres macros del scheduler -- y con varias vias habria que
 * mantener la misma logica en los cuatro, que es como se separan.
 *
 * Con ICACHE_WAYS == 1 esto es exactamente el codigo de antes: una mascara,
 * una comparacion y el puntero.  El bucle de vias desaparece en compilacion.
 *
 * @param p  Proceso cuyo icache se consulta.
 * @param pc Direccion buscada.
 * @return   La entrada valida, o nullptr si no esta (hay que descodificar).
 */
/**
 * @brief Conjunto de la icache, con la variante que reparte por TAMANO.
 *
 * Con `ICACHE_SIZE_CLASS=0` (el defecto) es exactamente @ref icache_index y el
 * codigo generado no cambia.
 *
 * Con 1, la tabla se parte en DOS mitades y cada una se indexa con el
 * desplazamiento que le toca a su paso: las instrucciones de la tabla PRIMARIA
 * -- de un byte -- con `pc>>0`, y las de la EXTENDIDA -- de cuatro o mas -- con
 * `pc>>2`.  Asi cada mitad alcanza tantos BYTES de programa como su paso, que
 * es la unica forma de que la ventana deje de valer `SETS` bytes.
 *
 * El discriminante no cuesta una tabla: el byte 0x00 ES el prefijo de la tabla
 * extendida, asi que separa las dos familias con una comparacion.  Lo que si
 * cuesta es LEERLO -- `vm_mem[pc]`, en el camino mas caliente que hay --, y
 * medir eso es justo para lo que existe este interruptor: la simulacion de
 * `tests/coste/test_icache_conflictos.cpp` dice que los conflictos caen un 98%,
 * pero cuenta conflictos, no tiempo.
 *
 * @param p  Proceso, para poder leer el byte de opcode.
 * @param pc Direccion del contador de programa.
 */
[[gnu::always_inline]] inline uint32_t icache_set(ProcessVM *p, uint64_t pc) {
#if ICACHE_SIZE_CLASS
    /* Mitad alta = EXTENDIDAS, y esas son las que EMPIEZAN por 0x00 -- ese byte
     * es el prefijo de la tabla extendida, no un opcode --.  Escrito al reves
     * (`!= 0x00`) la mitad de cuatro bytes recibe desplazamiento 0 y la de un
     * byte desplazamiento 2: las dos con el que no les toca, y sale PEOR que no
     * partir.  Medido asi por error: +8% en vez de la mejora esperada.
     *
     * Sin rama: la clase ES el resultado de la comparacion, y el
     * desplazamiento sale de ella con un producto que el compilador convierte
     * en un `shl`. */
    constexpr uint32_t kHalf = ICACHE_SETS / 2;
    const uint32_t cls = (p->vm_mem[pc] == 0x00) ? 1u : 0u;
    return cls * kHalf + (uint32_t)((pc >> (cls * 2u)) & (kHalf - 1));
#else
    (void)p;
    return icache_index(pc);
#endif
}

#if ICACHE_SIZE_CLASS == 2 && ICACHE_WAYS > 1
static_assert(false, "ICACHE_SIZE_CLASS=2 con varias vias no esta escrito: la "
                     "busqueda recorreria las vias de UNA mitad y de la otra "
                     "solo la via 0, o sea que perderia entradas validas sin "
                     "dar ningun error");
#endif

/// El conjunto dentro de la mitad @p cls, sin leer nada de memoria.
[[gnu::always_inline]] inline uint32_t icache_half(uint64_t pc, uint32_t cls) {
    constexpr uint32_t kHalf = ICACHE_SETS / 2;
    return cls * kHalf + (uint32_t)((pc >> (cls * 2u)) & (kHalf - 1));
}

inline DecodedInstr *icache_lookup(ProcessVM *p, uint64_t pc) {
#if ICACHE_SIZE_CLASS == 2
    /* LAS DOS MITADES COMO SI FUERAN DOS VIAS.
     *
     * Colocar bien exige saber el tamano, pero BUSCAR no: la etiqueta -- el
     * `pc` guardado en la entrada -- ya distingue, asi que se puede mirar en
     * las dos mitades y quedarse con la que case.  Una instruccion vive en UNA
     * sola, porque quien inserta si conoce su tamano.
     *
     * Con eso el camino caliente no lee `vm_mem[pc]`.  Y eso importa mas de lo
     * que parece: medido, la lectura en si cuesta poco -- `operator[]` sumaba
     * 51 M --, pero meter un acceso a memoria en el despacho obliga a recargar
     * lo que estaba en registros y `icache_lookup` pasaba de 68 M a 407 M.  El
     * precio no era el byte: era el codigo de alrededor.
     *
     * Se prueba primero la mitad de las PRIMARIAS porque son la mayoria del
     * codigo real (68% de un byte, 26% de cuatro).  Fallar la primera cuesta
     * una comparacion mas, no una descodificacion. */
    DecodedInstr *a = &p->icache[icache_half(pc, 0) * ICACHE_WAYS];
    if (a[0].pc == pc) return &a[0];
    DecodedInstr *v = &p->icache[icache_half(pc, 1) * ICACHE_WAYS];
#else
    DecodedInstr *v = &p->icache[icache_set(p, pc) * ICACHE_WAYS];
#endif
    // La via 0 primero y sin bucle: es el caso comun y tiene que costar una
    // sola comparacion, igual que antes.
    if (v[0].pc == pc) return &v[0];
#if ICACHE_WAYS > 1
    for (uint32_t i = 1; i < ICACHE_WAYS; ++i)
        if (v[i].pc == pc) return &v[i];
#endif
    return nullptr;
}

/**
 * @brief La entrada donde guardar una instruccion recien descodificada.
 *
 * Reemplazo FIFO por conjunto.  Solo se llama en el camino de FALLO, que ya
 * paga la descodificacion entera: el coste de elegir via es irrelevante ahi.
 *
 * @param p  Proceso cuyo icache se escribe.
 * @param pc Direccion de la instruccion que se va a guardar.
 * @return   Entrada a sobrescribir.
 */
inline DecodedInstr *icache_victim(ProcessVM *p, uint64_t pc) {
    const uint32_t s = icache_set(p, pc);
#if ICACHE_WAYS > 1
    const uint8_t v = p->icache_way[s];
    p->icache_way[s] = static_cast<uint8_t>((v + 1u) % ICACHE_WAYS);
    DecodedInstr *victim = &p->icache[s * ICACHE_WAYS + v];
#else
    DecodedInstr *victim = &p->icache[s];
#endif

    /* La entrada que se esta EJECUTANDO no se desaloja.
     *
     * El run_loop sostiene `d = decoded_ptr` a traves de `exec_cached` y, al
     * volver, lee `d->flags_info` para decidir si avanza `rip`.  Si esa misma
     * entrada se desalojo durante la ejecucion -- lo que puede pasar cuando la
     * instruccion REENTRA al interprete: finalizadores del GC, una llamada
     * nativa que vuelve, codigo cargado al vuelo -- esa lectura es de otra
     * instruccion, y el `rip` avanza mal.
     *
     * La icache es de mapeo directo, asi que no hay otra ranura a la que ir:
     * cuando toca la ocupada se devuelve `nullptr` y quien llama descodifica
     * SIN cachear.  Cuesta un fallo de icache -- 0,57% de las ejecuciones, y de
     * esas solo las que colisionan con la que corre -- a cambio de que el
     * puntero que sostiene el run_loop no pueda quedarse rancio.
     *
     * Sin esto no se pueden meter llamadas dentro de un paquete, y sin llamadas
     * dentro no hay inlinado, ni tramos largos, ni ILP que explotar. */
    if (victim == p->decoded_ptr || victim == p->icache_pinned) return nullptr;
    return victim;
}

/**
 * @brief Fase: hook opcional para auto-JIT trigger desde
 *        @c exec_instr_callvirt.
 *
 * Llamado tras incrementar @c MethodInfo::invocation_count en cada
 * dispatch CALLVIRT.  Si nullptr (default), no JIT.  Cuando el main
 * binario inicializa el JIT subsystem registra
 * @c &jit::maybe_compile_method aqui, habilitando el trigger.
 *
 * Por que function pointer: el codigo del auto-JIT depende del IR
 * frontend (Selector, IrFunction) que NO esta en @c vesta_rt.
 * El hook permite que vesta_rt despache al JIT sin acoplarse al
 * frontend.  Coste: 1 cmp + 1 branch predicted = ~1 ns por
 * CALLVIRT en programas sin JIT habilitado.
 */
extern void (*g_callvirt_post_hook)(ProcessVM *vm, loader::MethodInfo *method);

} // namespace runtime

#endif // PROCESO_RUNTIME_H
