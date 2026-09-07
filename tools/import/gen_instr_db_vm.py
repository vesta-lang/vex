#!/usr/bin/env python3
"""Genera la base de datos de instrucciones de la MAQUINA VIRTUAL.

Lo mismo que `gen_cpp_db.py` hace con las instrucciones nativas, pero para la
ISA de la VM, que hasta ahora no tenia ninguna: `instr_db::Isa` conoce X86,
ARM64, ARM32 y RISCV, y la VM es otra arquitectura en la practica --tiene su
banco R00-R15, su juego de instrucciones y su convencion-- sin sitio propio.

De donde sale, y por que de ahi
-------------------------------
De los dos tests que ya DERIVAN esto del codigo, no de una tabla escrita a mano:

  - `test_efectos_opcodes --json`  -> que toca cada opcode sin nombrarlo en un
    operando (banderas, pila, marco, contador de programa), sacado del codigo
    maquina del manejador.
  - `test_coste_opcodes` (escribe `coste_opcodes.json`) -> lo que cuesta, en
    instrucciones y ciclos del anfitrion, por microarquitectura.

Asi que la DB no puede contradecir al codigo: sale de el.  Y no se deriva en
ejecucion porque recorrer los 242 manejadores con Capstone cuesta ~106 ms, y un
programa corriente entero tarda 34.

Uso:
    test_efectos_opcodes --json > efectos.json
    test_coste_opcodes                      # escribe coste_opcodes.json
    python tools/import/gen_instr_db_vm.py efectos.json coste_opcodes.json
"""

import json
import pathlib
import sys

RAIZ = pathlib.Path(__file__).resolve().parent.parent.parent

CABECERA = RAIZ / "include" / "runtime" / "instr_db_vm.h"
FUENTE = RAIZ / "src" / "runtime" / "isa" / "instr_db_vm_gen.cpp"

AVISO = """// GENERADO por tools/import/gen_instr_db_vm.py -- NO editar a mano.
//
// QUE ES
//   La base de datos de la ISA de la MAQUINA VIRTUAL: que toca cada
//   instruccion sin nombrarlo en un operando (banderas, pila, marco, contador
//   de programa) y lo que cuesta en el anfitrion.  Es a las instrucciones de la
//   VM lo que `src/vx/gen/instr_db_*_gen.cpp` es a las nativas.
//
// PARA QUE
//   Para poder afirmar que dos instrucciones son INDEPENDIENTES, que es lo que
//   hace falta para reordenarlas al formar un paquete, fusionarlas o
//   vectorizarlas.  Reordenar dos que si dependian no da un error: da otro
//   resultado.
//
// DE DONDE SALE
//   De los dos tests que DERIVAN estos datos del codigo maquina de los
//   manejadores, no de nadie escribiendolos:
//     test_efectos_opcodes --json > efectos.json
//     test_coste_opcodes                      # escribe coste_opcodes.json
//     python tools/import/gen_instr_db_vm.py efectos.json coste_opcodes.json
//
// CUANDO HAY QUE REGENERARLA
//   Siempre que se anada una instruccion, se quite, o CAMBIE lo que hace su
//   manejador -- aunque el opcode sea el mismo --.  Un manejador que empieza a
//   tocar las banderas y una tabla que dice que no las toca es exactamente el
//   fallo silencioso que esto existe para evitar.
//
//   No hay que acordarse: `test_efectos_opcodes` COMPRUEBA en cada ejecucion
//   que esta tabla sigue coincidiendo con lo derivado, y si no, sale con codigo
//   1 diciendo QUE instruccion difiere.  Por eso se puede tener una tabla
//   aparte sin que envejezca en silencio.
"""
HDR = '''/**
 * @file include/runtime/instr_db_vm.h
 * @brief Base de datos de la ISA de la MAQUINA VIRTUAL: efectos y coste.
 *
 * Que es
 * ------
 * Lo que `src/vx/gen/instr_db_*_gen.cpp` es a las instrucciones NATIVAS, esto
 * es a las de la VM.  `instr_db::Isa` conoce X86, ARM64, ARM32 y RISCV; la VM
 * es otra arquitectura en la practica --su banco R00-R15, su juego de
 * instrucciones, su convencion-- y hasta ahora no tenia sitio propio.
 *
 * Para que
 * --------
 * Para poder afirmar que dos instrucciones son INDEPENDIENTES --lo que permite
 * reordenar al formar un paquete, fusionar y vectorizar-- y para saber CUANTO
 * cuesta cada una, que es lo que decide si una transformacion compensa.
 * Reordenar dos que si dependian no da un error, da OTRO RESULTADO.
 *
 * Lo que hay y lo que NO
 * ---------------------
 * Estan los efectos IMPLICITOS --los que la instruccion no nombra en ningun
 * operando: banderas, pila, marco, contador de programa--, el coste completo y
 * la FORMA.
 *
 * La forma no dice QUE registro se toca --su indice es VARIABLE
 * (`regs[instr.reg1]`) y sale de los bytes de cada instruccion concreta-- sino
 * de QUE CAMPO del operando sale ese indice y en que direccion.  Eso si es
 * propiedad del opcode y si cabe en una tabla, y es la mitad que faltaba: con
 * los efectos solos, `add r2, 3` y `add r3, 1` son indistinguibles y no se
 * puede afirmar que no chocan.  Antes esta mitad habia que sacarla del
 * DESENSAMBLADOR, que al formar un paquete de 32 es carisimo.
 *
 * De donde sale
 * -------------
 * GENERADO.  Sale de los dos tests que DERIVAN estos datos del codigo maquina
 * de los manejadores, no de nadie escribiendolos a mano:
 *
 *     test_efectos_opcodes --json > efectos.json
 *     test_coste_opcodes                      # escribe coste_opcodes.json
 *     python tools/import/gen_instr_db_vm.py efectos.json coste_opcodes.json
 *
 * No se deriva en EJECUCION porque recorrer los 242 manejadores con Capstone
 * cuesta ~106 ms, y un programa corriente entero tarda 34.
 *
 * Cuando hay que regenerarla
 * --------------------------
 * Al anadir una instruccion, al quitarla, y al cambiar lo que hace su
 * MANEJADOR aunque el opcode siga igual.  Un manejador que empieza a tocar las
 * banderas y una tabla que dice que no las toca es justo el fallo silencioso
 * que esto existe para evitar.
 *
 * No hace falta acordarse: `test_efectos_opcodes` comprueba en cada ejecucion
 * que la tabla sigue coincidiendo con lo derivado y sale con codigo 1 diciendo
 * QUE instruccion difiere.  Generada A SECAS envejeceria; generada MAS
 * verificada, no.
 */

#ifndef VESTA_RUNTIME_INSTR_DB_VM_H
#define VESTA_RUNTIME_INSTR_DB_VM_H

#include <cstdint>

namespace runtime {
namespace vm_isa {
'''
HDR2 = '''
/**
 * @brief Que toca una instruccion de la VM SIN nombrarlo en ningun operando.
 *
 * Los cuatro campos van en el orden en que los vigila el derivador: banderas,
 * pila, marco y contador de programa.
 */
enum VmEffect : uint16_t {
    VE_W_FLAGS = 1u << 0,
    VE_W_STACK = 1u << 1,
    VE_W_FRAME = 1u << 2,
    VE_W_PC = 1u << 3,
    VE_R_FLAGS = 1u << 4,
    VE_R_STACK = 1u << 5,
    VE_R_FRAME = 1u << 6,
    VE_R_PC = 1u << 7,
    /// Los efectos son EXACTOS.  Sin este bit son COTA INFERIOR: el manejador
    /// tiene una llamada indirecta que no se pudo seguir, asi que puede tocar
    /// mas de lo que dice.  Quien reordene DEBE tratarlo como barrera.
    VE_EXACT = 1u << 8,
    /// Transfiere control: no se reordena nunca, toque lo que toque.
    VE_CONTROL = 1u << 9,
    /// Toca la memoria de la VM.  Sin desambiguacion, dos de estas se ordenan
    /// entre si.
    VE_MEMORY = 1u << 10,
    /// La ranura tiene `exec` y `decode`.  Sin esto la VM la rechaza, y lo
    /// demas de la fila no significa nada.
    VE_IMPL = 1u << 11,
    /// Los efectos dependen de un valor que solo existe AL EJECUTAR (el destino
    /// de un despacho dinamico).  No es "no se sabe": es "no se sabe todavia".
    /// Se resuelve al formar el paquete observandolo, con guarda y abandono.
    VE_RUNTIME = 1u << 12,
    /**
     * @brief Puede ABORTAR: el manejador llega a `throw_fatal`.
     *
     * Es una BARRERA, y por una razon distinta de la de `VE_CONTROL`: no es que
     * cambie a donde se va, es que si aborta, lo que venga detras NO debe haber
     * corrido.  Adelantar algo por encima de una division que puede lanzar hace
     * que ese algo se ejecute en un programa que ya habia muerto.
     *
     * Existe porque no tenerlo salia carisimo por el otro lado: el derivador
     * SEGUIA la llamada al manejador de errores -- se llega a el con el proceso
     * como argumento, o sea con procedencia legitima -- y le atribuia a la
     * instruccion todo lo que tocan la traza de pila, el formateo del mensaje y
     * el runtime de C++.  `div` y `mod` salian escribiendo Y leyendo los cuatro
     * campos, cuando lo unico que escriben son las BANDERAS.  Eso no es
     * conservador: es declarar ocho efectos falsos que impiden cualquier
     * reordenacion alrededor.
     */
    VE_ABORT = 1u << 13,
    /**
     * @brief PUEDE salir a codigo ajeno: una funcion nativa, una API del
     *        sistema.
     *
     * Dice algo distinto de `VE_RUNTIME`, y por eso NO son excluyentes:
     *
     *   `VE_RUNTIME`  el destino solo se conoce al ejecutar -> se observa al
     *                 formar el paquete, con guarda.
     *   `VE_FOREIGN`  el destino PUEDE estar fuera de nuestro mundo -> aunque
     *                 se observe, sus efectos pueden no ser derivables.
     *
     * Las dos juntas describen `calln` exactamente: el puntero esta en el
     * inmediato, asi que observarlo SI dice a donde va -- y muchas veces va a
     * NUESTRO runtime (`vio_println`, `vmath_sqrt`, las colecciones), cuyos
     * efectos si se conocen --.  Solo cuando cae en una biblioteca ajena hay
     * que tratarlo como barrera.  Marcarlo como barrera SIEMPRE seria renunciar
     * a la mayoria de los casos, que son los nuestros.
     *
     * `VE_FOREIGN` a secas, sin `VE_RUNTIME`, es el otro caso: `dlopen` y
     * `dlsym` llaman a una entrada FIJA del sistema, asi que no hay nada que
     * observar y nunca sera nuestra.
     */
    VE_FOREIGN = 1u << 14,
};

/**
 * @brief De que campo del OPERANDO dependen los efectos.
 *
 * El tercer estado, y el mas barato: hay instrucciones cuyos efectos no son
 * fijos por opcode pero SI quedan determinados por sus operandos, que ya estan
 * descodificados al formar el paquete.  Ni hace falta especular ni hay duda.
 *
 * Por opcode, `mov r_ext, r` tiene que declarar que puede escribir cualquiera
 * de los cuatro campos.  Por INSTANCIA se sabe exactamente cual, porque el
 * codigo del registro especial va en los bytes.  Y `mov` era el 80-100% del
 * peso de lo desconocido.
 */
enum VmNarrow : uint8_t {
    VN_NONE = 0,
    /// El campo sale del codigo de registro especial (`reg2 & 0xF`): 8=pc,
    /// 9=marco, 10=pila, 11=banderas; 0..3 son cursores y no tocan ninguno.
    /// Solo en la variante extendida (s=1); con s=0 no toca nada.
    VN_SPECIAL_REG = 1,
};

/// Cuanto se fia el derivador de un coste.
enum VmCertainty : uint8_t {
    VC_EXACT = 0,   ///< se recorrio todo el manejador
    VC_BOUNDED = 1, ///< hay ramas: el numero depende del camino
    VC_LOWER = 2,   ///< cota INFERIOR: quedo codigo sin mirar.  Sirve para
                    ///< ordenar, no para prometer un numero.
};

/**
 * @brief Coste de una instruccion en UNA microarquitectura del anfitrion.
 *
 * DESCODIFICAR y EJECUTAR van separados, y no es un detalle de presentacion:
 * **una instruccion cuesta distinto una vez ya esta descodificada**.  Un
 * paquete descodifica UNA vez y ejecuta muchas, asi que lo que decide si
 * compensa es @c exec_cycles, no el total.  Sumarlos escondia justo eso.
 */
struct VmMicroCost {
    float decode_cycles;  ///< ciclos de descodificar (se paga una vez)
    float decode_latency; ///< latencia del camino critico al descodificar
    float decode_uops;    ///< uops emitidas al descodificar
    float exec_cycles;    ///< ciclos de ejecutar (se paga CADA vez)
    float exec_latency;   ///< latencia del camino critico al ejecutar
    float exec_uops;      ///< uops emitidas al ejecutar
    uint16_t host_instrs; ///< instrucciones del anfitrion recorridas
    uint16_t host_priced; ///< de esas, cuantas tenian coste conocido.  Si es
                          ///< menor que @c host_instrs el numero es PARCIAL.
};
'''
HDR3 = '''
/**
 * @brief Coste de una instruccion en una ISA del anfitrion.
 *
 * NUNCA MEDIDO no es lo mismo que CERO, y por eso hay un campo para decirlo.
 * El coste se deriva recorriendo el codigo maquina de los manejadores, asi que
 * solo se puede medir la ISA para la que esta compilada la VM que corre el
 * derivador: hoy hay x86-64 y las demas estan sin medir.  Un cero silencioso
 * haria creer que una instruccion es gratis en ARM.
 */
struct VmIsaCost {
    /// nullptr = esta ISA NUNCA SE MIDIO.  Comprobarlo antes de leer nada mas.
    const VmMicroCost *micro;
    /// Nombres de las microarquitecturas, en el mismo orden que @c micro.
    const char *const *micro_names;
    uint8_t micro_count;
    uint8_t certainty_decode; ///< VmCertainty
    uint8_t certainty_exec;   ///< VmCertainty

    /* Resumen sobre las microarquitecturas.  Se guarda calculado porque quien
     * decide una transformacion no quiere recorrer 21 entradas, y se calcula
     * de los datos CRUDOS, no de otro resumen: los campos `minimo_latencia` y
     * `maximo_latencia` del volcado de coste no son el minimo y el maximo de
     * la latencia sino la latencia de la microarquitectura con menos y mas
     * CICLOS, y en 225 de 232 opcodes el "minimo" sale mayor que el "maximo".
     * Leerlos como cotas da el dato al reves. */
    float exec_cycles_min, exec_cycles_avg, exec_cycles_max;
    float total_cycles_min, total_cycles_avg, total_cycles_max;
    float exec_latency_min, exec_latency_avg, exec_latency_max;
    float exec_uops_avg;
};

/// Las ISA del anfitrion, en el mismo orden que `instr_db::Isa`.
enum VmHostIsa : uint8_t {
    VH_X86 = 0,
    VH_ARM64 = 1,
    VH_ARM32 = 2,
    VH_RISCV = 3,
    VH_COUNT = 4,
};

/// Nombre de una ISA, para los informes.
const char *vm_host_isa_name(uint8_t isa);

/// Una instruccion de la ISA de la VM.
struct VmInstr {
    const char *name; ///< nullptr si la ranura no existe
    uint16_t effects; ///< bits de VmEffect
    uint8_t size;     ///< bytes que ocupa
    uint8_t narrow;   ///< VmNarrow: de que operando dependen los efectos
    VmIsaCost cost[VH_COUNT];
};

/// Tabla primaria (opcode 0x00-0xFF) y extendida (prefijo 0x00 + opcode).
extern const VmInstr kPrimary[256];
extern const VmInstr kExtended[256];

/**
 * @brief Lo CALIENTE, aparte y denso: los efectos de cada opcode.
 *
 * `VmInstr` mide 272 bytes -- nombre, tamano y el coste en 21
 * microarquitecturas por cada una de las cuatro ISA --, y el camino caliente
 * lee de ahi DOS: los bits de efectos.  Consultarlo por la tabla grande
 * arrastra una linea de cache por opcode para no usar casi nada de ella, y las
 * dos tablas juntas son 136 KB, o sea que no caben en L1.
 *
 * Aqui van solo los bits, indexados igual.  512 entradas de 2 bytes = 1 KB, que
 * cabe entero y de sobra.  El coste sigue en `VmInstr`, que es FRIO: lo miran
 * los informes y las herramientas, no el que forma un paquete.
 *
 * Las dos representaciones salen del MISMO generador, y `test_efectos_opcodes`
 * comprueba que coinciden: dos copias del mismo hecho que nadie compara acaban
 * separandose.
 *
 * En los bits altos (13-15) va el estrechamiento, que si no ocuparia otro array
 * y otra linea de cache para tres valores posibles.
 */
extern const uint16_t kHotPrimary[256];
extern const uint16_t kHotExtended[256];

/**
 * @brief La FORMA: que campos del operando indexan el banco de registros.
 *
 * Los efectos dicen que toca una instruccion SIN nombrarlo (banderas, pila,
 * marco, pc).  Esto dice lo otro: que registros nombra y en que direccion.
 * Hacen falta los dos para afirmar que dos instrucciones son independientes --
 * con los efectos solos, `add r2, 3` y `add r3, 1` parecen iguales y no se
 * puede decir que no chocan.
 *
 * Un bit por (campo, parte), en cada campo de dieciseis (ver @ref VmForm):
 *
 *     0: reg1 entero    1: reg1 nibble bajo   2: reg1 nibble alto
 *     3: reg2 entero    4: reg2 nibble bajo   5: reg2 nibble alto
 *     6: reg3 entero    7: reg3 nibble bajo   8: reg3 nibble alto
 *     9: regI entero   10: regI nibble bajo  11: regI nibble alto
 *
 * Empaquetado, de bajo a alto: lee del banco general, escribe en el general,
 * lee del vectorial, escribe en el vectorial.
 *
 * CERO NO ES "no toca registros": es que el recorrido no lo vio, igual que en
 * los efectos.  Quien reordene tiene que tratarlo como desconocido, no como
 * vacio -- confundirlos es exactamente el fallo que da otro resultado.
 */
extern const uint64_t kFormPrimary[256];
extern const uint64_t kFormExtended[256];

/**
 * @brief Si la FORMA de cada opcode se puede CREER.  Un bit por opcode.
 *
 * Sin esto, una mascara a cero tiene dos lecturas opuestas -- "no nombra
 * registros" y "no se vio que registros nombra" -- y el que reordena no puede
 * distinguirlas.  Las consecuencias no son simetricas: creerse de mas una
 * lectura cuesta un reordenamiento que no se hace, y creerse de menos una
 * ESCRITURA deja mover por encima a quien leia ese registro, que no da un
 * error sino otro resultado.
 *
 * Vale 1 cuando el recorrido del manejador llego al final Y ni un solo acceso
 * al banco quedo sin atribuir a un campo del operando.  Es la misma disciplina
 * que `VE_EXACT` para los efectos, aplicada a la forma.
 *
 * Va como mapa de bits y no como `uint8_t[256]` porque se consulta una vez por
 * instruccion al formar un paquete: 32 bytes por tabla caben en media linea de
 * cache, y 256 no caben en ninguna.
 */
extern const uint64_t kFormExactPrimary[4];
extern const uint64_t kFormExactExtended[4];

/// @return true si la forma de @p opcode es de fiar (ver @ref kFormExactPrimary).
inline bool vm_form_exact(bool extended, uint8_t opcode) {
    const uint64_t *mapa = extended ? kFormExactExtended : kFormExactPrimary;
    return ((mapa[opcode >> 6] >> (opcode & 63)) & 1u) != 0;
}

/**
 * @brief Opcodes cuyos campos vienen DECLARADOS, no derivados.
 *
 * 1 = los cuatro campos de esta fila los puso una declaracion `fixed` y
 * SUSTITUYEN a lo que el recorrido vio, porque lo que el recorrido ve ahi esta
 * mal: `div` y `mod` llegan al camino de fallo, y por el se les atribuian los
 * efectos de construir la traza y formatear el mensaje.
 *
 * Existe para que la comprobacion de la tabla no acuse un estrechamiento hecho
 * a proposito.  Su regla es "la tabla no puede saber MENOS que el derivador" --
 * un efecto real que la tabla no declare es el fallo silencioso que todo esto
 * previene --, y una declaracion `fixed` es exactamente la excepcion: alguien
 * dijo, mirando el fuente, que lo derivado sobra.  Sin esta marca la
 * comprobacion falla siempre sobre esas filas y deja de guardar las demas.
 */
extern const uint8_t kFixedPrimary[256];
extern const uint8_t kFixedExtended[256];

/**
 * @brief Bits de la forma: uno por cada `RegSlot`, desplazado uno.
 *
 * El bit `i` corresponde a la ranura `i + 1` de `RegSlot`, porque `RS_NONE`
 * es la ranura 0 y no gasta bit.  El nombre de cada una sale de ahi, asi que
 * anadir una ranura es anadir una fila EN LOS DOS SITIOS: aqui y en
 * `kRegSlotDesc` de `effects_decode.h`.
 *
 * Las tres ultimas no son un adorno.  `RS_REG3` es el tercer registro de la
 * forma de MEMORIA, y `RS_REGI` el registro de la forma con INMEDIATO, que
 * vive en el byte 8 detras del inmediato de ocho bytes: es donde `add r, imm`
 * guarda su unico registro.
 */
enum VmForm : uint16_t {
    VF_REG1 = 1u << 0,    ///< reg1 entero
    VF_REG1_LO = 1u << 1, ///< nibble bajo de reg1
    VF_REG1_HI = 1u << 2, ///< nibble alto de reg1
    VF_REG2 = 1u << 3,    ///< reg2 entero
    VF_REG2_LO = 1u << 4, ///< nibble bajo de reg2
    VF_REG2_HI = 1u << 5, ///< nibble alto de reg2
    VF_REG3 = 1u << 6,    ///< reg3 entero (forma de memoria)
    VF_REG3_LO = 1u << 7, ///< nibble bajo de reg3
    VF_REG3_HI = 1u << 8, ///< nibble alto de reg3
    VF_REGI = 1u << 9,     ///< registro de la forma con inmediato
    VF_REGI_LO = 1u << 10, ///< nibble bajo de ese registro
    VF_REGI_HI = 1u << 11, ///< nibble alto de ese registro
};

/**
 * @return La forma empaquetada de @p opcode.
 *
 * Son SESENTA Y CUATRO bits, cuatro campos de dieciseis, y no treinta y dos
 * de a ocho como fue al principio.  Con ocho no cabian las doce ranuras: los
 * bits de `RS_REGI` para arriba se perdian al empaquetar, y lo que se perdia
 * era justo la forma con INMEDIATO de `add`, `sub`, `mul`, `div`, `cmp`,
 * `mov`, `movc` y `mod` -- ocho de los opcodes mas ejecutados que hay --.
 * Truncados, `add r3, 5` declaraba no tocar ningun registro, y un modelo que
 * dice eso deja intercambiar dos instrucciones que si dependian.  No da un
 * error: da otro resultado.
 */
inline uint64_t vm_form(bool extended, uint8_t opcode) {
    return extended ? kFormExtended[opcode] : kFormPrimary[opcode];
}

/// Los cuatro campos de @ref vm_form, por separado.
inline uint16_t vm_form_read(uint64_t f) { return (uint16_t)(f & 0xFFFF); }
inline uint16_t vm_form_write(uint64_t f) {
    return (uint16_t)((f >> 16) & 0xFFFF);
}
inline uint16_t vm_form_vec_read(uint64_t f) {
    return (uint16_t)((f >> 32) & 0xFFFF);
}
inline uint16_t vm_form_vec_write(uint64_t f) {
    return (uint16_t)((f >> 48) & 0xFFFF);
}

/// Desplazamiento del estrechamiento dentro de la palabra caliente.
constexpr uint16_t kNarrowShift = 15;

/// @return Los efectos de @p opcode, con el estrechamiento en los bits altos.
inline uint16_t vm_hot(bool extended, uint8_t opcode) {
    return extended ? kHotExtended[opcode] : kHotPrimary[opcode];
}

/// @return La instruccion, o nullptr si esa ranura no existe.
inline const VmInstr *vm_instr(bool extended, uint8_t opcode) {
    const VmInstr &v = extended ? kExtended[opcode] : kPrimary[opcode];
    return v.name != nullptr ? &v : nullptr;
}

/**
 * @brief Efectos EXACTOS de UNA instancia concreta.
 *
 * El tercer estado, y el mas barato de los tres.  Por OPCODE hay que declarar
 * todo lo que la instruccion PODRIA tocar; por INSTANCIA, los operandos ya
 * descodificados suelen decidirlo sin ninguna duda.  No hay que especular ni
 * poner guardas: la respuesta esta en los bytes.
 *
 * Quien forma un paquete tiene el `DecodedInstr` delante, asi que esto no
 * cuesta nada donde se usa.
 *
 * @param v         La instruccion, de la tabla.
 * @param signed_bit `flags_info._signed_instruct` (el selector `s`).
 * @param direction `flags_info.direction`.
 * @param reg2      `data_instruction.reg_data.reg2`.
 * @return Los efectos ya estrechados.  Si el opcode no tiene regla, los mismos
 *         que trae la tabla.
 */
uint16_t vm_narrow_effects(const VmInstr *v, uint8_t signed_bit,
                           uint8_t direction, uint8_t reg2);

/// @return true si esa ISA se llego a medir para esta instruccion.
inline bool vm_cost_measured(const VmInstr *v, uint8_t isa) {
    return v != nullptr && isa < VH_COUNT && v->cost[isa].micro != nullptr;
}

/// @return true si se puede REORDENAR alrededor de esta instruccion.
/// Exige que exista, que sus efectos sean EXACTOS y que no sea ninguna de las
/// cuatro barreras.  Ante cualquier duda, false.
inline bool vm_instr_movable(uint16_t effects) {
    const uint16_t need = VE_IMPL | VE_EXACT;
    if ((effects & need) != need) return false;
    /* Las CUATRO barreras, y cada una por su motivo:
     *
     *   VE_CONTROL  cambia a donde se va: mover algo a su alrededor lo saca de
     *               su camino.
     *   VE_ABORT    si aborta, lo de detras NO debe haber corrido.  Adelantar
     *               algo por encima de una division que puede lanzar lo ejecuta
     *               en un programa que ya habia muerto.
     *   VE_RUNTIME  los efectos dependen de un destino que solo existe al
     *               ejecutar: aqui todavia no se sabe que toca.
     *   VE_FOREIGN  puede salir a codigo ajeno, cuyos efectos no son derivables
     *               ni observandolo.
     *
     * `VE_ABORT`, `VE_RUNTIME` y `VE_FOREIGN` faltaban, y las tres estan
     * documentadas como barrera en su propio comentario mas arriba: la puerta
     * decia que si a instrucciones que el resto del fichero declara
     * inmovibles. */
    const uint16_t barreras = VE_CONTROL | VE_ABORT | VE_RUNTIME | VE_FOREIGN;
    return (effects & barreras) == 0;
}

/// Misma pregunta desde la fila completa, para quien ya la tiene a mano.
inline bool vm_instr_movable(const VmInstr *v) {
    return v != nullptr && vm_instr_movable(v->effects);
}

} // namespace vm_isa
} // namespace runtime

#endif // VESTA_RUNTIME_INSTR_DB_VM_H
'''


CERTEZA = {"exacto": 0, "acotado": 1, "cota": 2}

# El eje de ISA, en el mismo orden que `instr_db::Isa` y que `VmHostIsa`.
ISAS = ["x86", "arm64", "arm32", "riscv"]


def isa_slot(nombre):
    """La ranura que le toca a la ISA que dice el volcado de coste."""
    n = (nombre or "").lower()
    if n.startswith("x86") or n in ("amd64", "x64"):
        return 0
    if n.startswith("aarch64") or n.startswith("arm64"):
        return 1
    if n.startswith("arm"):
        return 2
    if n.startswith("riscv") or n.startswith("rv"):
        return 3
    return None


def resumen(micros, campo):
    """min, promedio, max de un campo sobre las microarquitecturas.

    Se calcula de los datos CRUDOS a proposito.  El `resumen` del volcado tiene
    `minimo_latencia` y `maximo_latencia`, pero NO son el minimo y el maximo de
    la latencia: son la latencia de la microarquitectura con menos y mas
    CICLOS.  En 225 de 232 opcodes el "minimo" sale mayor que el "maximo".
    """
    vals = [m[campo] for m in micros if campo in m]
    if not vals:
        return (0.0, 0.0, 0.0)
    return (min(vals), sum(vals) / len(vals), max(vals))


DECLARACIONES = RAIZ / "src" / "runtime" / "isa" / "instr_effects_decl.json"

NARROW = {"special_reg": 1}


def leer_declaraciones():
    """Lo que se declara de los opcodes que el derivador no cierra solo.

    No es un parche: es el CONTRATO.  Un opcode cuyos efectos no se derivan y
    tampoco se declaran no puede entrar en la base de datos, porque una entrada
    incompleta en silencio hace que se reordenen instrucciones que si dependian.
    """
    if not DECLARACIONES.is_file():
        return {}
    d = json.loads(DECLARACIONES.read_text(encoding="utf-8"))
    # Las entradas SIN `tabla` son comentarios.  JSON no los tiene, y en un
    # fichero donde cada linea es una renuncia a derivar hace falta poder decir
    # POR QUE ahi mismo: una lista de opcodes sin explicacion no se puede
    # revisar, solo creer.
    fuera = {}
    for o in d.get("opcodes", []):
        if "tabla" not in o:
            continue
        clave = (o["tabla"], o["indice"])
        # DOS declaraciones del mismo opcode es un error, no una sustitucion.
        # Antes ganaba la ultima y nadie se enteraba: declarar las lecturas de
        # `callitf` le quito CALLADAMENTE su clase `runtime`, que es lo que le
        # dice al que forma el paquete que su destino se puede observar.  Un
        # fichero que es el CONTRATO no puede perder una clausula en silencio.
        if clave in fuera:
            raise SystemExit(
                "%s: %s declarado dos veces (%s 0x%02X): '%s' y '%s'.\n"
                "Una sola entrada por opcode; si necesita dos cosas a la vez,\n"
                "usa las banderas (`runtime`, `foreign`) junto a la clase."
                % (DECLARACIONES.name, o.get("nombre", "?"), o["tabla"],
                   o["indice"], fuera[clave].get("clase", "?"),
                   o.get("clase", "?")))
        fuera[clave] = o
    return fuera


def revisar(por_clave, decl):
    """Falla si algun opcode implementado no se deriva NI se declara."""
    faltan = []
    for (tabla, idx), o in sorted(por_clave.items()):
        if o is None or not o["implementada"] or o["exacto"]:
            continue
        if (tabla, idx) not in decl:
            faltan.append((o["nombre"], tabla, idx, o.get("motivo", "")))
    if not faltan:
        return True
    print("\nEFECTOS SIN DERIVAR Y SIN DECLARAR -- no se genera la base de "
          "datos:\n")
    for nombre, tabla, idx, motivo in faltan:
        print("  %-16s %-9s 0x%02X   %s" % (nombre, tabla, idx, motivo))
    print("\n%d opcodes.  En una VM propia no puede haber instrucciones con\n"
          "efectos desconocidos: o el derivador los cierra, o se declaran en\n"
          "  %s\n" % (len(faltan), DECLARACIONES.relative_to(RAIZ)))
    return False


def bits(o, dec=None):
    """Los efectos, empaquetados.  El orden de los campos es el de `kFields`:
    banderas, pila, marco, contador de programa."""
    v = (o["escribe"] & 0xF) | ((o["lee"] & 0xF) << 4)
    if o["exacto"] and o["implementada"]:
        v |= 1 << 8   # solo una ranura CON manejador puede ser exacta
    if o["salta"]:
        v |= 1 << 9
    # TOCA MEMORIA.  Sale de dos sitios, y se quedan los dos porque cada uno
    # ve casos que el otro no:
    #
    #   - DERIVADO: el manejador toca `proc->vm_mem`, que es el quinto campo
    #     vigilado (bit 4 de las mascaras).  Es la senal de verdad.
    #   - por el MODO de direccionamiento del operando.  Era la UNICA antes, y
    #     es un proxy equivocado: dice como estan puestos los operandos, no si
    #     se toca memoria.  `mld`, `mst` y `loadz` codifican en modo REG porque
    #     su direccion viaja en un registro, asi que salian como si no tocaran
    #     memoria -- y con eso una carga y un almacen se podian intercambiar.
    #     Se conserva porque marca de mas, nunca de menos, y aqui pasarse es el
    #     lado seguro: sobrar una dependencia cuesta un reorden, faltar una
    #     cuesta un resultado.
    #
    # El bit no cabe en las mascaras de campo -- son 4 bits cada una y este es
    # el quinto campo --, asi que va donde le toca: VE_MEMORY.
    kMemoria = 1 << 4
    if (o["escribe"] | o["lee"]) & kMemoria:
        v |= 1 << 10
    if o["modo"] not in ("REG", "INMED", "NONE"):
        v |= 1 << 10
    if o["implementada"]:
        v |= 1 << 11
    # Declarado como dependiente de la ejecucion: no es "no se sabe", es "no se
    # sabe todavia", y quien forme el paquete puede resolverlo observando.
    #
    # Se acepta tambien como BANDERA, no solo como clase, por lo mismo que
    # `foreign`: no es excluyente con `fixed`.  `callitf` es las dos cosas --
    # su destino se observa al ejecutar, Y sus lecturas hubo que declararlas a
    # mano --, y con las clases excluyentes declarar lo segundo le quitaba lo
    # primero en silencio.
    if dec is not None and (dec.get("clase") == "runtime" or
                            dec.get("runtime")):
        v |= 1 << 12
    # PUEDE salir a codigo ajeno.  Va como bandera aparte y no como clase
    # porque no es excluyente con `runtime`: `calln` es las dos cosas -- el
    # destino se observa, y a veces resulta ser nuestro y a veces no.  Ver
    # VE_FOREIGN.
    if dec is not None and (dec.get("clase") == "foreign" or
                            dec.get("foreign")):
        v |= 1 << 14
    # Puede ABORTAR: el manejador llega a `throw_fatal`.  Ver VE_ABORT.
    if o.get("puede_abortar"):
        v |= 1 << 13
    # Efectos declarados a mano, leidos del FUENTE del manejador.  Sustituyen a
    # lo derivado, no lo completan: existen justo porque lo derivado esta mal.
    #
    # Las mascaras declaradas usan la MISMA codificacion que las derivadas --
    # bits 0..3 = [banderas, pila, marco, pc], bit 4 = memoria --, y no una
    # propia de cuatro bits.  Con cuatro no se podia declarar que una
    # instruccion toca memoria, y eso deja fuera justo el caso que motivo esto:
    # `fastpush` perdio a la vez la escritura de la pila y el bit de memoria, y
    # arreglar solo la primera lo dejaba diciendo que un push no toca memoria.
    if dec is not None and dec.get("clase") == "fixed":
        d_esc = dec.get("escribe", 0) & 0x1F
        d_lee = dec.get("lee", 0) & 0x1F
        v &= ~0xFF
        v |= (d_esc & 0xF) | ((d_lee & 0xF) << 4)
        # El quinto campo no cabe en los nibbles y va a su bandera, igual que en
        # el camino derivado.  Solo se ANADE: si lo derivado ya decia que toca
        # memoria, una declaracion que no lo mencione no se lo quita -- sobrar
        # una dependencia cuesta un reorden, faltar una cuesta un resultado.
        if (d_esc | d_lee) & kMemoria:
            v |= 1 << 10
        # NO se toca `VE_EXACT`: esa marca dice si el RECORRIDO llego al final,
        # y eso lo sabe el derivador y solo el.  Una declaracion aporta CAMPOS
        # -- lo que el fuente dice que toca --, no una promesa sobre lo que el
        # recorrido alcanzo a ver.  Ponerla aqui haria que la tabla afirmase
        # algo que nadie comprobo.
    return v


def leer(ruta_efectos, rutas_coste):
    """Une los efectos con el coste de CADA ISA medida, por (tabla, opcode)."""
    efectos = json.loads(pathlib.Path(ruta_efectos).read_text(encoding="utf-8"))
    por_clave = {}
    for o in efectos["opcodes"]:
        por_clave[(o["tabla"], o["indice"])] = dict(o, isas={})

    nombres_micro = {}
    for ruta in rutas_coste:
        coste = json.loads(pathlib.Path(ruta).read_text(encoding="utf-8"))
        slot = isa_slot(coste.get("isa"))
        if slot is None:
            print("aviso: ISA desconocida en %s: %r" % (ruta, coste.get("isa")))
            continue
        nombres_micro[slot] = coste.get("microarquitecturas", [])
        for o in coste["opcodes"]:
            k = (o["tabla"], o["indice"])
            if k not in por_clave:
                continue
            por_clave[k]["isas"][slot] = {
                "micro": o.get("coste") or [],
                "cert_decode": CERTEZA.get(o.get("certeza_decode"), 2),
                "cert_exec": CERTEZA.get(o.get("certeza_exec"), 2),
            }
    return por_clave, nombres_micro


NO_MEDIDA = ("{nullptr, nullptr, 0, 2, 2, "
             "0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f}")


def micro_array(nombre, micros):
    """El array de coste por microarquitectura de UNA instruccion."""
    filas = []
    for m in micros:
        filas.append(
            "    {%.2ff, %.2ff, %.2ff, %.2ff, %.2ff, %.2ff, %d, %d},"
            % (m.get("decode_ciclos", 0.0), m.get("decode_latencia", 0.0),
               m.get("decode_uops", 0.0), m.get("exec_ciclos", 0.0),
               m.get("exec_latencia", 0.0), m.get("exec_uops", 0.0),
               int(m.get("instrs", 0) or 0), int(m.get("con_coste", 0) or 0)))
    return ("const VmMicroCost %s[] = {\n%s\n};\n" % (nombre, "\n".join(filas)))


def isa_cost(nombre_array, micros, cert_d, cert_e, nombres_var):
    """La entrada `VmIsaCost`, con el resumen calculado de los datos crudos."""
    ex_c = resumen(micros, "exec_ciclos")
    to_c = resumen(micros, "total_ciclos")
    ex_l = resumen(micros, "exec_latencia")
    ex_u = resumen(micros, "exec_uops")
    return ("{%s, %s, %d, %d, %d, "
            "%.2ff, %.2ff, %.2ff, %.2ff, %.2ff, %.2ff, %.2ff, %.2ff, %.2ff, "
            "%.2ff}"
            % (nombre_array, nombres_var, len(micros), cert_d, cert_e,
               ex_c[0], ex_c[1], ex_c[2], to_c[0], to_c[1], to_c[2],
               ex_l[0], ex_l[1], ex_l[2], ex_u[1]))


def emitir(por_clave, nombres_micro, decl):
    CABECERA.write_text(AVISO + "\n" + HDR + HDR2 + HDR3, encoding="utf-8")

    pre = [AVISO,
           '#include "runtime/instr_db_vm.h"', "",
           "namespace runtime {", "namespace vm_isa {", "",
           "static const char *const kIsaNames[VH_COUNT] = {",
           '    "x86", "arm64", "arm32", "riscv"};', "",
           "const char *vm_host_isa_name(uint8_t isa) {",
           "    return isa < VH_COUNT ? kIsaNames[isa] : \"?\";",
           "}", "", "namespace {", ""]

    # Nombres de microarquitectura, uno por ISA medida.
    var_nombres = {}
    for slot, nombres in sorted(nombres_micro.items()):
        var = "kMicroNames%d" % slot
        var_nombres[slot] = var
        pre.append("const char *const %s[] = {" % var)
        pre.append("    " + ", ".join('"%s"' % n for n in nombres) + "};")
        pre.append("")

    tablas = []
    for nombre_tabla, tabla in (("kPrimary", "primary"),
                                ("kExtended", "extended")):
        filas = ["const VmInstr %s[256] = {" % nombre_tabla]
        for i in range(256):
            o = por_clave.get((tabla, i))
            if o is None:
                filas.append("    {nullptr, 0, 0, 0, {%s}},"
                             % ", ".join([NO_MEDIDA] * 4))
                continue
            costes = []
            for slot in range(4):
                d = o["isas"].get(slot)
                if not d or not d["micro"]:
                    costes.append(NO_MEDIDA)
                    continue
                var = "kM%s%d_%d" % (tabla[0], slot, i)
                pre.append(micro_array(var, d["micro"]))
                costes.append(isa_cost(var, d["micro"], d["cert_decode"],
                                       d["cert_exec"], var_nombres[slot]))
            dec = decl.get((tabla, i))
            nar = NARROW.get((dec or {}).get("regla", ""), 0)
            filas.append('    {"%s", 0x%04X, %d, %d, {%s}},'
                         % (o["nombre"].replace('"', ''), bits(o, dec),
                            o["bytes"], nar, ", ".join(costes)))
        filas.append("};")
        filas.append("")
        tablas.append("\n".join(filas))

    # --- La FORMA, densa: que campos del operando indexan el banco ----------
    #
    # Va aparte de `VmInstr` por lo mismo que los efectos: quien FORMA un
    # paquete necesita esto por cada instruccion, y sacarlo de la tabla grande
    # arrastraria 272 bytes -- una linea de cache larga -- para leer cuatro.
    # 512 entradas de 8 bytes = 4 KB, que caben enteras.
    for nombre_tabla, tabla in (("kFormPrimary", "primary"),
                                ("kFormExtended", "extended")):
        filas = ["const uint64_t %s[256] = {" % nombre_tabla]
        linea = "   "
        for i in range(256):
            o = por_clave.get((tabla, i))
            if o is None:
                v = 0
            else:
                # Una declaracion `fixed` corrige tambien la FORMA, no solo los
                # cuatro campos implicitos.
                #
                # Hace falta porque los dos se pierden por el MISMO motivo.  El
                # derivador atribuye un acceso solo si puede seguir el puntero
                # al proceso hasta el; cuando el compilador lo deja en un
                # registro que el rastro no alcanza, se pierden a la vez la
                # escritura de banderas y la del registro destino.  Corregir
                # solo la primera deja la segunda diciendo que la instruccion
                # no escribe ningun registro, y eso permite mover por encima a
                # quien lo leia -- que es el lado caro de equivocarse.
                dec = decl.get((tabla, i))
                forma = dict(o)
                if dec is not None and dec.get("clase") == "fixed":
                    for clave in ("form_read", "form_write", "form_vec_read",
                                  "form_vec_write"):
                        if clave in dec:
                            forma[clave] = dec[clave]
                # Dieciseis bits por campo: con ocho no cabian las doce
                # ranuras y se perdia la forma con inmediato de los ocho
                # opcodes mas ejecutados.  Se comprueba en vez de recortar:
                # truncar en silencio es lo que lo escondio la primera vez.
                for clave in ("form_read", "form_write", "form_vec_read",
                              "form_vec_write"):
                    if forma.get(clave, 0) & ~0xFFFF:
                        raise SystemExit(
                            "%s de %s no cabe en 16 bits: 0x%X"
                            % (clave, forma.get("nombre", "?"), forma[clave]))
                v = ((forma.get("form_read", 0) & 0xFFFF)
                     | ((forma.get("form_write", 0) & 0xFFFF) << 16)
                     | ((forma.get("form_vec_read", 0) & 0xFFFF) << 32)
                     | ((forma.get("form_vec_write", 0) & 0xFFFF) << 48))
            linea += " 0x%016XULL," % v
            if (i % 2) == 1:
                filas.append(linea)
                linea = "   "
        filas.append("};")
        filas.append("")
        tablas.append("\n".join(filas))

    # --- Si esa forma se puede CREER: un bit por opcode ---------------------
    for nombre_tabla, tabla in (("kFormExactPrimary", "primary"),
                                ("kFormExactExtended", "extended")):
        mapa = [0, 0, 0, 0]
        for i in range(256):
            o = por_clave.get((tabla, i))
            if o is not None and o.get("form_exact"):
                mapa[i >> 6] |= 1 << (i & 63)
        filas = ["const uint64_t %s[4] = {" % nombre_tabla]
        filas.append("    " + " ".join("0x%016XULL," % v for v in mapa))
        filas.append("};")
        filas.append("")
        tablas.append("\n".join(filas))

    # --- Que filas llevan los campos DECLARADOS, no derivados ---------------
    for nombre_tabla, tabla in (("kFixedPrimary", "primary"),
                                ("kFixedExtended", "extended")):
        filas = ["const uint8_t %s[256] = {" % nombre_tabla]
        linea = "   "
        for i in range(256):
            dec = decl.get((tabla, i))
            linea += " %d," % (1 if dec is not None and
                               dec.get("clase") == "fixed" else 0)
            if (i % 16) == 15:
                filas.append(linea)
                linea = "   "
        filas.append("};")
        filas.append("")
        tablas.append("\n".join(filas))

    # --- La tabla CALIENTE, densa: solo los bits, 1 KB en total -------------
    for nombre_tabla, tabla in (("kHotPrimary", "primary"),
                                ("kHotExtended", "extended")):
        filas = ["const uint16_t %s[256] = {" % nombre_tabla]
        linea = "   "
        for i in range(256):
            o = por_clave.get((tabla, i))
            if o is None:
                v = 0
            else:
                dec = decl.get((tabla, i))
                nar = NARROW.get((dec or {}).get("regla", ""), 0)
                v = bits(o, dec) | (nar << 15)
            linea += " 0x%04X," % v
            if (i % 8) == 7:
                filas.append(linea)
                linea = "   "
        filas.append("};")
        filas.append("")
        tablas.append("\n".join(filas))

    pre += ["} // namespace", ""]
    FUENTE.write_text("\n".join(pre) + "\n".join(tablas)
                      + "\n} // namespace vm_isa\n} // namespace runtime\n",
                      encoding="utf-8")

    con = sum(1 for v in por_clave.values() if v)
    exactos = sum(1 for v in por_clave.values() if v and (bits(v) & (1 << 8)))
    declarados = len(decl)
    print("generado %s" % CABECERA.relative_to(RAIZ))
    print("generado %s" % FUENTE.relative_to(RAIZ))
    print("  %d instrucciones, %d con efectos EXACTOS, %d DECLARADAS"
          % (con, exactos, declarados))
    for slot, nom in enumerate(ISAS):
        n = sum(1 for v in por_clave.values()
                if v and v["isas"].get(slot) and v["isas"][slot]["micro"])
        if n:
            print("  ISA %-6s medida: %d instrucciones x %d microarquitecturas"
                  % (nom, n, len(nombres_micro.get(slot, []))))
        else:
            print("  ISA %-6s SIN MEDIR (queda como nula, no como coste cero)"
                  % nom)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    por_clave, nombres_micro = leer(sys.argv[1], sys.argv[2:])
    decl = leer_declaraciones()
    if not revisar(por_clave, decl):
        return 1
    emitir(por_clave, nombres_micro, decl)
    return 0


if __name__ == "__main__":
    sys.exit(main())
