/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/effects_decode.h
 * @brief Descodificador de EFECTOS: que toca ESTA instruccion, no este opcode.
 *
 * Que es
 * ------
 * El gemelo del descodificador de instrucciones.  Aquel saca los VALORES de los
 * operandos; este saca lo que la instruccion TOCA: que registros lee, cual
 * escribe y en que campo vive ese destino.
 *
 * Misma forma que el otro, y por la misma razon: una tabla PLANA indexada por
 * opcode con un puntero a funcion por entrada.  Consultarlo es un indexado y un
 * salto.  Ni cadenas, ni buscar en ninguna estructura, ni pasar por el
 * desensamblador -- que construye texto con `snprintf` y no puede estar en un
 * camino que corre en cada fallo de icache.
 *
 * Por INSTANCIA, no por opcode
 * ----------------------------
 * Es la diferencia que lo hace util.  Una tabla por OPCODE tiene que decir todo
 * lo que la instruccion PODRIA tocar; aqui la funcion ve los operandos ya
 * descodificados y responde lo que toca DE VERDAD esta vez.
 *
 * El caso que lo justifica es `mov`: por opcode hay que declarar que puede
 * escribir las banderas, la pila, el marco o el contador de programa, porque
 * segun el registro especial escribe uno u otro.  Por instancia ese codigo esta
 * en `reg2 & 0xF`, asi que no hay ninguna duda, y no hace falta ni especular ni
 * poner guardas.  `mov` era el 80-100% del peso de lo desconocido.
 *
 * Que aporta sobre la base de datos
 * ---------------------------------
 * La base de datos (`instr_db_vm.h`) guarda lo que vale para TODAS las
 * instancias de un opcode, derivado del codigo maquina y verificado.  Esto no la
 * duplica: la lee y le anade las dos cosas que ella no puede tener --
 *
 *   - la FORMA: que registro concreto se lee o se escribe, que depende de los
 *     bytes de esta instruccion;
 *   - el ESTRECHAMIENTO: los campos implicitos que de verdad toca esta vez.
 *
 * Quien anade un opcode lo declara aqui
 * -------------------------------------
 * La entrada de la tabla ES la declaracion, en codigo y comprobada por el
 * compilador.  Y no se queda vieja: `test_efectos_opcodes` DERIVA los efectos
 * del codigo maquina del manejador y comprueba que lo declarado no se quede
 * corto.
 *
 * Lo que no se declara queda como DESCONOCIDO, no como vacio: la entrada por
 * defecto lo dice, y quien reordene o fusione debe negarse.  Un opcode sin
 * escribir simplemente no se optimiza, en vez de optimizarse mal.
 */

#ifndef VESTA_RUNTIME_EFFECTS_DECODE_H
#define VESTA_RUNTIME_EFFECTS_DECODE_H

#include <cstdint>

#include "runtime/decode_instruction.h"

namespace runtime {

/**
 * @brief Los cuatro campos IMPLICITOS, en el orden del derivador.
 *
 * Lo que una instruccion toca sin nombrarlo en ningun operando.  Viven aqui, y
 * no donde se usan, porque los comparten dos que no se pueden incluir entre si:
 * el modelo de "que toca" (`bundle/touch.h`) y las instrucciones FUSIONADAS,
 * que tienen que declarar sus propios efectos.
 */
enum : uint8_t {
    kFlags = 1u << 0,
    kStack = 1u << 1,
    kFrame = 1u << 2,
    kPc = 1u << 3,
};

/**
 * @brief Donde vive un registro dentro de la instruccion ya descodificada.
 *
 * Hace falta para poder REESCRIBIRLO: fusionar dos instrucciones en una pasa
 * por cambiarle el destino a la primera.
 *
 * Los nombres son los del DECODER, no los de los bytes: `decode_instr_raw_bytes`
 * deja byte2 en `reg_data.reg1` y byte3 en `reg_data.reg2`, asi que sacar un
 * nibble es un desplazamiento y una mascara.
 */
enum RegSlot : uint8_t {
    RS_NONE = 0,
    RS_REG1,    ///< `reg_data.reg1` entero
    RS_REG2,    ///< `reg_data.reg2` entero
    RS_REG1_LO, ///< nibble bajo de `reg1`
    RS_REG1_HI, ///< nibble alto de `reg1`
    RS_REG2_LO, ///< nibble bajo de `reg2`
    RS_REG2_HI, ///< nibble alto de `reg2`
    /* Los otros dos sitios donde vive un numero de registro.  La union de
     * operandos empieza en el mismo byte, asi que las formas se solapan: los
     * bytes 0 y 1 son `reg1`/`reg2` y a la vez la base y el indice de la forma
     * de MEMORIA; el 2 es su tercer registro, y el 8 -- detras del inmediato de
     * ocho bytes -- es el registro de la forma con INMEDIATO.
     *
     * Faltaban, y el derivador si los produce: sin ellos ninguna instruccion
     * con inmediato podia declarar que registro toca, y el puente entre lo
     * derivado y lo declarado se quedaba corto justo ahi. */
    RS_REG3,    ///< `mem_data.reg_final` entero
    RS_REG3_LO, ///< nibble bajo de `reg3`
    RS_REG3_HI, ///< nibble alto de `reg3`
    RS_REGI,    ///< `inmmed_data.reg` entero
    RS_REGI_LO, ///< nibble bajo de `regi`
    RS_REGI_HI, ///< nibble alto de `regi`
};

/**
 * @brief QUE BANCO indexa el numero de registro que vive en un `RegSlot`.
 *
 * El `RegSlot` dice DONDE, en los bytes de la instruccion, esta escrito el
 * numero.  No dice a que se refiere ese numero, y la VM tiene dos bancos: los
 * de proposito general (`regs[16]`) y los vectoriales (`zmm[16]`).
 *
 * Son ejes distintos y hace falta separarlos: `fadd f7, f8` y `adds r7, r8`
 * llevan los mismos numeros en los mismos campos y NO se estorban.  Con un solo
 * banco, la aritmetica de coma flotante declararia tocar registros generales --
 * lo que impide reordenar alrededor de ella sin motivo -- o, si se declarase al
 * reves, dejaria pasar dos operaciones flotantes que si dependian.
 */
enum RegBank : uint8_t {
    RB_GP = 0,  ///< `registers.regs[]`, proposito general
    RB_VEC = 1, ///< `registers.zmm[]`, banco vectorial (f/xmm/ymm/zmm)
};

/// Bits de los campos implicitos, en el orden en que los vigila el derivador.
enum EffField : uint8_t {
    EF_FLAGS = 1u << 0,
    EF_STACK = 1u << 1,
    EF_FRAME = 1u << 2,
    EF_PC = 1u << 3,
};

/**
 * @brief Lo que toca UNA instruccion concreta.
 *
 * `exact` es el que manda: sin el, lo de dentro es una COTA INFERIOR y no se
 * puede ni reordenar ni fusionar alrededor.  Empieza en false a proposito, para
 * que un opcode sin entrada en la tabla no se optimice por descuido.
 */
struct InstrEffects {
    uint16_t reg_read = 0;  ///< bit por registro GENERAL leido
    uint16_t reg_write = 0; ///< bit por registro GENERAL escrito
    /// Lo mismo para el banco VECTORIAL.  Va aparte y no mezclado porque son
    /// bancos distintos: `fadd f7, f8` no estorba a `adds r7, r8`.  Ver
    /// @ref RegBank.
    uint16_t vec_read = 0;
    uint16_t vec_write = 0;
    uint8_t field_read = 0; ///< bits de EffField
    uint8_t field_write = 0;
    bool mem_read = false;  ///< toca la memoria de la VM
    bool mem_write = false;
    bool control = false; ///< transfiere control: no se mueve nunca
    bool exact = false;   ///< se sabe TODO lo que toca

    /* El destino, para poder reescribirlo.  `dest_slot == RS_NONE` significa
     * que no hay destino conocido, y entonces no se puede retargetear. */
    uint8_t dest_reg = 0;
    uint8_t dest_slot = RS_NONE;
    /// A que banco pertenece el destino.  Sin esto, reescribir el destino de una
    /// operacion flotante cambiaria un registro general con el mismo numero.
    uint8_t dest_bank = RB_GP;
    /// El destino se pisa ENTERO (no se acumula sobre su valor previo).  Es lo
    /// que decide si una instruccion MATA un temporal o solo lo actualiza.
    bool dest_is_kill = false;
};

/**
 * @brief Como se saca un `RegSlot` de los dos bytes: de cual, cuanto se
 *        desplaza y que mascara lleva.
 *
 * Es una tabla y no un `switch` a proposito.  Leer o escribir un operando pasa
 * a ser un indexado y tres operaciones aritmeticas, sin una sola rama, y sin que
 * el compilador tenga que elegir entre comparar en cadena o montar su propia
 * tabla de saltos.
 *
 * `RS_NONE` lleva mascara 0, que es lo que lo hace inofensivo sin comprobarlo:
 * al leer da 0 y al escribir no cambia nada.
 */
struct RegSlotDesc {
    /* El BYTE dentro de la union de operandos, no un booleano reg1/reg2.
     *
     * Era booleano, y con eso solo se llegaba a los dos primeros.  Los otros
     * dos sitios donde vive un numero de registro quedaban fuera: el byte 2
     * -- tercer registro de la forma de MEMORIA -- y el 8, que es el registro
     * de la forma con INMEDIATO, detras del inmediato de ocho bytes. */
    uint8_t byte;  ///< indice dentro de `data_instruction`
    uint8_t shift; ///< desplazamiento del nibble
    uint8_t mask;  ///< 0x0F un nibble, 0xFF el byte entero, 0 nada
};

/// Indexada por `RegSlot`, en el mismo orden que el enum.
constexpr RegSlotDesc kRegSlotDesc[] = {
    {0, 0, 0x00}, // RS_NONE
    {0, 0, 0xFF}, // RS_REG1
    {1, 0, 0xFF}, // RS_REG2
    {0, 0, 0x0F}, // RS_REG1_LO
    {0, 4, 0x0F}, // RS_REG1_HI
    {1, 0, 0x0F}, // RS_REG2_LO
    {1, 4, 0x0F}, // RS_REG2_HI
    {2, 0, 0xFF}, // RS_REG3
    {2, 0, 0x0F}, // RS_REG3_LO
    {2, 4, 0x0F}, // RS_REG3_HI
    {8, 0, 0xFF}, // RS_REGI
    {8, 0, 0x0F}, // RS_REGI_LO
    {8, 4, 0x0F}, // RS_REGI_HI
};

/// @return El valor del registro que vive en @p slot.
inline uint8_t reg_slot_get(const DecodedInstr &d, uint8_t slot) {
    const RegSlotDesc &s = kRegSlotDesc[slot];
    const uint8_t *base =
        reinterpret_cast<const uint8_t *>(&d.data_instruction);
    return static_cast<uint8_t>((base[s.byte] >> s.shift) & s.mask);
}

/// Escribe @p v en el registro que vive en @p slot.  Es lo que permite
/// retargetear el destino de una instruccion al fusionarla con la siguiente.
inline void reg_slot_set(DecodedInstr &d, uint8_t slot, uint8_t v) {
    const RegSlotDesc &s = kRegSlotDesc[slot];
    uint8_t &dst =
        reinterpret_cast<uint8_t *>(&d.data_instruction)[s.byte];
    const uint8_t hueco = static_cast<uint8_t>(s.mask << s.shift);
    dst = static_cast<uint8_t>((dst & ~hueco) |
                               ((v & s.mask) << s.shift));
}

/**
 * @brief El `RegSlot` de cada bit de la FORMA derivada del codigo maquina.
 *
 * El derivador responde en campos del operando -- reg1 entero, nibble bajo de
 * reg2... -- y el descodificador en `RegSlot`.  Son la misma nocion con dos
 * nombres, y esta tabla es el puente.  El orden es el que produce
 * `operand_field_bit`: campo (reg1, reg2, reg3, regI) por parte (entero, bajo,
 * alto), que es tambien el de `VmForm` en la base generada.
 *
 * Vive aqui, y no en quien la usa, porque la usan DOS: el que reordena dentro
 * de un paquete y el que comprueba que la tabla generada dice lo mismo que el
 * descodificador.  Dos copias de la misma correspondencia acaban separandose,
 * y la que se separa deja de comparar nada.
 */
constexpr RegSlot kFormSlot[12] = {
    RS_REG1, RS_REG1_LO, RS_REG1_HI, RS_REG2, RS_REG2_LO, RS_REG2_HI,
    RS_REG3, RS_REG3_LO, RS_REG3_HI, RS_REGI, RS_REGI_LO, RS_REGI_HI};

/**
 * @brief Los registros del banco a los que apunta @p form sobre @p d.
 *
 * La forma dice QUE CAMPO lleva el numero de registro; la instancia dice que
 * numero es.  Sin las dos no se puede afirmar que dos instrucciones no chocan:
 * con los efectos solos, `add r2, 3` y `add r3, 1` parecen la misma cosa.
 *
 * Recorre SOLO los bits puestos, sacandolos con `ctz` y quitandolos uno a uno.
 * Barrer los doce daba doce vueltas siempre, y la forma tipica tiene uno o dos:
 * con cuatro llamadas por instruccion -- general y vectorial, lectura y
 * escritura -- eran 48 iteraciones para mirar tres campos, y las dos del banco
 * vectorial casi siempre sobre una mascara VACIA.
 *
 * Sin tocar memoria fuera de la propia instruccion, que es lo que permite
 * llamarlo al formar el paquete sin desensamblar nada.
 */
[[gnu::always_inline]] inline uint16_t
regs_of_form(uint16_t form, const DecodedInstr &d) {
    uint16_t m = 0;
    for (uint16_t f = form; f != 0; f &= static_cast<uint16_t>(f - 1)) {
        const int b = __builtin_ctz(f);
        m |= static_cast<uint16_t>(1u << (reg_slot_get(d, kFormSlot[b]) & 0x0F));
    }
    return m;
}

/**
 * @brief Que toca @p d.
 *
 * Un indexado y un salto.  Se llama al formar un paquete, que es el 0,57% de
 * las ejecuciones, pero el coste esta pensado para que tambien valga en un
 * camino mas caliente si algun dia hace falta.
 *
 * @param d   La instruccion ya descodificada.
 * @param out Se rellena por completo; no hace falta limpiarlo antes.
 * @return true si se sabe TODO lo que toca.  Con false, @p out es una COTA
 *         INFERIOR: lo que dice es cierto, pero puede tocar mas.
 *
 * @note El resultado es `[[nodiscard]]` a proposito.  "No lo se" es una
 *       respuesta legitima y frecuente -- un opcode sin forma declarada, o con
 *       efectos que solo se conocen al ejecutar --, pero es exactamente la que
 *       no se puede ignorar: quien reordene o fusione creyendo que sabe lo que
 *       toca cambia el resultado del programa sin que salte ningun error.
 *       Descartarla es un aviso del compilador.
 *
 *       NO se aborta al no saberlo, y no por permisividad: hoy la mayoria de los
 *       opcodes no tienen forma declarada, asi que "no lo se" es el caso comun y
 *       no un fallo.  El sitio donde eso SI tiene que gritar es
 *       `test_efectos_opcodes`, que lista los que faltan y puede actuarse sobre
 *       ellos.  Cuando esten todos declarados, este camino pasa a ser
 *       imposible y se puede convertir en fatal.
 */
[[nodiscard]] bool decode_effects(const DecodedInstr &d, InstrEffects &out);

/**
 * @brief Lo mismo, pero SIN terminar el programa si falta la forma.
 *
 * Existe para hacer INVENTARIO, no para relajar la regla.  `decode_effects`
 * muere ante un opcode sin declarar porque es la unica forma de que se acaben
 * de escribir todos; pero quien quiere saber CUALES faltan no puede permitirse
 * morir en el primero.
 *
 * O sea: el runtime EXIGE, el test INVENTARIA.  Usar esta en un camino de
 * ejecucion seria devolverle el silencio a lo que existe para gritar.
 *
 * @return true si la forma esta declarada.  @p out solo vale si devuelve true.
 */
[[nodiscard]] bool probe_effects(const DecodedInstr &d, InstrEffects &out);

} // namespace runtime

#endif // VESTA_RUNTIME_EFFECTS_DECODE_H
