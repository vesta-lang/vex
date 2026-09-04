// GENERADO por tools/import/gen_instr_db_vm.py -- NO editar a mano.
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

/**
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
 * Un bit por (campo, parte), en cada byte:
 *
 *     0: reg1 entero    1: reg1 nibble bajo   2: reg1 nibble alto
 *     3: reg2 entero    4: reg2 nibble bajo   5: reg2 nibble alto
 *
 * Empaquetado: byte 0 = lee del banco general, byte 1 = escribe en el general,
 * byte 2 = lee del vectorial, byte 3 = escribe en el vectorial.
 *
 * CERO NO ES "no toca registros": es que el recorrido no lo vio, igual que en
 * los efectos.  Quien reordene tiene que tratarlo como desconocido, no como
 * vacio -- confundirlos es exactamente el fallo que da otro resultado.
 */
extern const uint32_t kFormPrimary[256];
extern const uint32_t kFormExtended[256];

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

/// Bits de la forma dentro de cada byte de @ref kFormPrimary.
enum VmForm : uint8_t {
    VF_REG1 = 1u << 0,    ///< reg1 entero
    VF_REG1_LO = 1u << 1, ///< nibble bajo de reg1
    VF_REG1_HI = 1u << 2, ///< nibble alto de reg1
    VF_REG2 = 1u << 3,    ///< reg2 entero
    VF_REG2_LO = 1u << 4, ///< nibble bajo de reg2
    VF_REG2_HI = 1u << 5, ///< nibble alto de reg2
};

/// @return La forma empaquetada de @p opcode.
inline uint32_t vm_form(bool extended, uint8_t opcode) {
    return extended ? kFormExtended[opcode] : kFormPrimary[opcode];
}

/// Los cuatro bytes de @ref vm_form, por separado.
inline uint8_t vm_form_read(uint32_t f) { return (uint8_t)(f & 0xFF); }
inline uint8_t vm_form_write(uint32_t f) { return (uint8_t)((f >> 8) & 0xFF); }
inline uint8_t vm_form_vec_read(uint32_t f) {
    return (uint8_t)((f >> 16) & 0xFF);
}
inline uint8_t vm_form_vec_write(uint32_t f) {
    return (uint8_t)((f >> 24) & 0xFF);
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
