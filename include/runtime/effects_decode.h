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
    uint16_t reg_read = 0;  ///< bit por registro de VM leido
    uint16_t reg_write = 0; ///< bit por registro escrito
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
    uint8_t use_reg2; ///< 0 = `reg1`, 1 = `reg2`
    uint8_t shift;    ///< desplazamiento del nibble
    uint8_t mask;     ///< 0x0F un nibble, 0xFF el byte entero, 0 nada
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
};

/// @return El valor del registro que vive en @p slot.
inline uint8_t reg_slot_get(const DecodedInstr &d, uint8_t slot) {
    const RegSlotDesc &s = kRegSlotDesc[slot];
    const uint8_t src = s.use_reg2 ? d.data_instruction.reg_data.reg2
                                   : d.data_instruction.reg_data.reg1;
    return static_cast<uint8_t>((src >> s.shift) & s.mask);
}

/// Escribe @p v en el registro que vive en @p slot.  Es lo que permite
/// retargetear el destino de una instruccion al fusionarla con la siguiente.
inline void reg_slot_set(DecodedInstr &d, uint8_t slot, uint8_t v) {
    const RegSlotDesc &s = kRegSlotDesc[slot];
    uint8_t &dst = s.use_reg2 ? d.data_instruction.reg_data.reg2
                              : d.data_instruction.reg_data.reg1;
    const uint8_t hueco = static_cast<uint8_t>(s.mask << s.shift);
    dst = static_cast<uint8_t>((dst & ~hueco) |
                               ((v & s.mask) << s.shift));
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
