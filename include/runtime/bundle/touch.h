/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file include/runtime/bundle/touch.h
 * @brief Que toca una instruccion del paquete: registros, campos implicitos y
 *        memoria, SIN desensamblar nada.
 *
 * POR QUE ESTA AQUI Y NO DENTRO DEL REORDENADOR
 * ---------------------------------------------
 * Lo necesitan los DOS: el reordenador para saber que se puede cruzar con que,
 * y el fusionador para saber si un valor MUERE -- que es lo que decide si un
 * par se puede convertir en una instruccion sola.  Escrito dos veces se
 * separaria en cuanto uno de los dos afinara el modelo, y la forma de fallar es
 * la peor: no da un error, deja de fusionar o -- mucho peor -- fusiona algo que
 * no debia.
 *
 * DE DONDE SALE
 * -------------
 * De la base generada.  Los EFECTOS dicen que toca sin nombrarlo (banderas,
 * pila, marco, contador); la FORMA dice que campo del operando lleva el numero
 * de registro, y `regs_of_form` lo resuelve sobre esta instancia.  Dos
 * indexados en tablas de cache; ni una cadena, ni un desensamblador.
 *
 * LEER Y ESCRIBIR VAN SEPARADOS
 * -----------------------------
 * A proposito, y es la diferencia con lo que habia.  El reordenador trata toda
 * escritura como si fuera tambien lectura -- es el lado barato de equivocarse
 * cuando lo unico que se decide es si dos instrucciones se pueden cruzar --,
 * pero esa mezcla BORRA justo el dato que el fusionador necesita: si una
 * instruccion PISA su destino sin leerlo, mata lo que hubiera.  Aqui salen
 * crudos y cada consumidor aplica su propia prudencia.
 */

#ifndef VESTA_RUNTIME_BUNDLE_TOUCH_H
#define VESTA_RUNTIME_BUNDLE_TOUCH_H

#include <cstdint>

#include "runtime/effects_decode.h"
#include "runtime/exec_instruction_fused.h"
#include "runtime/instr_db_vm.h"
#include "runtime/proceso_runtime.h"

namespace runtime {

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

/// El opcode de @p d en la tabla que le toque.  Una instruccion de la tabla
/// PRIMARIA lleva el suyo en `is_not_extended` y deja `opcode_index` a cero.
[[gnu::always_inline]] inline uint8_t touch_opcode(const DecodedInstr &d) {
    return (d.flags_info.is_not_extended == 0x00)
               ? (uint8_t)d.flags_info.opcode_index
               : d.flags_info.is_not_extended;
}

/**
 * @brief Lee ESTA instruccion el contador de programa?
 *
 * La base dice que opcodes PUEDEN leerlo, y ahi es correcta.  Pero eso no es lo
 * que hace falta: `push r3` y `push rip` son el mismo opcode y solo la segunda
 * lo lee.  El que decide es el OPERANDO, o sea la instancia, y ese dato lo pone
 * el decodificador en `reg_ext` -- "esta nombra un registro especial" --.
 *
 * POR QUE ASI Y NO POR OPCODE.  Con la version gruesa, cualquier `push` o
 * cualquier `mov` era intocable: ni se reordenaban ni se podian repartir entre
 * dos hilos.  Medido, el 75% de los paquetes no se podia repartir porque una de
 * estas aparecia pronto.  Y son de las mas frecuentes que hay, asi que el
 * efecto no es marginal: es el que decide si el reparto existe o no.
 *
 * SEIS opcodes se declaran lectores de `rip` sin transferir control, y se
 * miraron uno a uno:
 *
 *   - `push` y `mov` llegan a `rip` SOLO por un operando especial -- por
 *     `read_special`, bajo `reg_ext` en el primero y bajo el bit de signo en el
 *     segundo, que el decodificador traduce ya a `reg_ext` --;
 *   - `newobj` lo lee para PERFILAR (`profile_newobj`), o sea que moverla no
 *     cambia el programa, solo de donde sale una muestra;
 *   - `getarg`, `strhash` y `rspawn` no lo tocan: su marca sale de que el
 *     derivador sigue las llamadas a ayudantes y les atribuye lo que aquellos
 *     tocan.  Es la misma sobreaproximacion que ya se documento con `div` y
 *     `mod`, que salian leyendo los cuatro campos por alcanzar `throw_fatal`.
 *
 * Los tres ultimos son un HUECO DE LA DERIVACION, no de esta regla; cuando se
 * cierre alli, aqui no habra que tocar nada.
 */
[[gnu::always_inline]] inline bool reads_pc_now(const DecodedInstr &d) {
    return d.flags_info.reg_ext;
}

/// Los EFECTOS IMPLICITOS de @p d, que salen de la base y no cuestan nada.
/// @param pc_is_barrier Si leer `rip` descalifica.  Quien REORDENA dice que si
///        -- mover algo que lo lee cambia el valor que ve --; quien reparte en
///        dos hilos dice que no, porque esa instruccion se queda en su hilo y en
///        su orden, y ahi `rip` vale lo que tiene que valer.
[[gnu::always_inline]] inline bool effects_of(const DecodedInstr &d, Touch &t,
                                              bool pc_is_barrier = true) {
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const uint8_t opcode = touch_opcode(d);

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
    if (pc_is_barrier && (eff & vm_isa::VE_R_PC) != 0 && reads_pc_now(d))
        return false;
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
 * @brief Rellena @p t con lo que toca @p d, con lectura y escritura SEPARADAS.
 *
 * SIN DESENSAMBLAR NADA.  Los efectos dicen que toca sin nombrarlo; la forma
 * dice QUE CAMPO del operando lleva el numero de registro, y `regs_of_form` lo
 * resuelve sobre esta instancia.  Dos indexados en tablas de cache y las
 * iteraciones que hagan falta, sin ramas dependientes de datos.
 *
 * OJO: no aplica la prudencia de "lo que se escribe se lee tambien".  Quien
 * reordena la quiere y la anade (`touch_one_conservative`); quien fusiona la
 * ROMPERIA, porque lo que necesita saber es justo si el destino se pisa sin
 * leerlo.
 *
 * @return true si la instruccion se puede mover.
 */
/// @param pc_is_barrier Ver @ref effects_of.
[[gnu::always_inline]] inline bool touch_one(const DecodedInstr &d, Touch &t,
                                             bool pc_is_barrier = true) {
    /* Una instruccion YA FUSIONADA no se describe por su opcode: lleva escrito
     * el de la primera del par, pero hace ademas lo que hacia la segunda.
     * Preguntarle a la base por ese opcode daria una respuesta INCOMPLETA -- le
     * faltan registros que lee y que escribe --, y actuar sobre ella seria
     * reordenar alrededor de dependencias que no se ven.
     *
     * Asi que lo declara ELLA, no la base.  Antes esto devolvia "no se, no la
     * muevas", y era seguro pero dejaba a las fusionadas INMOVILES: ni se
     * reordenan ni podrian solaparse cuando la ejecucion sea de verdad fuera de
     * orden, que es justo lo contrario de lo que se busca -- las TANDAS son
     * independientes por dentro y son las primeras candidatas a lanzarse en
     * paralelo --. */
    if (d.flags_info.absorbed != 0) return fused_touch(d, t);
    if (!effects_of(d, t, pc_is_barrier)) return false;
    const bool ext = (d.flags_info.is_not_extended == 0x00);
    const uint8_t op = touch_opcode(d);
    if (!vm_isa::vm_form_exact(ext, op)) {
        t.barrier = true; // no se sabe que registros nombra
        return false;
    }
    const uint64_t f = vm_isa::vm_form(ext, op);
    t.reg_read = regs_of_form(vm_isa::vm_form_read(f), d);
    t.reg_write = regs_of_form(vm_isa::vm_form_write(f), d);
    t.vec_read = regs_of_form(vm_isa::vm_form_vec_read(f), d);
    t.vec_write = regs_of_form(vm_isa::vm_form_vec_write(f), d);
    return true;
}

/// En que categoria cae una instruccion para quien quiere MOVERLA o REPARTIRLA.
enum class TouchKind : uint8_t {
    Movable,  ///< se puede mover y se puede delegar a otro hilo
    ReadsPc,  ///< lee el contador de programa: se queda en su hilo, en orden
    Barrier,  ///< transfiere control, puede abortar, o no se sabe que toca
};

/**
 * @brief Como @ref touch_one, pero distinguiendo POR QUE no se puede mover.
 *
 * `touch_one` junta en un solo "no" dos cosas que no son iguales:
 *
 *   - **transferir control** acota de verdad: lo que va detras puede no
 *     ejecutarse, asi que no se puede adelantar ni delegar nada de ahi;
 *   - **leer `rip`** solo obliga a quedarse en su hilo y en su orden.  El valor
 *     de `rip` a mitad de paquete depende de cuantas se hayan ejecutado ya, y
 *     eso lo sabe el hilo que las va ejecutando, no el que recibe un bloque
 *     suelto.
 *
 * Juntarlas hacia que `push` -- que lee `rip` y es de las mas frecuentes que
 * hay -- cortara el paquete como si fuera un salto.  Medido: el 75% de los
 * paquetes no se podian repartir por una barrera temprana, y buena parte de
 * ellas eran de esta clase.
 */
[[gnu::always_inline]] inline TouchKind touch_classify(const DecodedInstr &d,
                                                       Touch &t) {
    /* Se pide SIN la regla de `rip` -- asi se rellena tambien lo que la lee -- y
     * despues se mira si la lleva.  Al reves habria que repetir el relleno. */
    if (!touch_one(d, t, /*pc_is_barrier=*/false)) return TouchKind::Barrier;
    return reads_pc_now(d) ? TouchKind::ReadsPc : TouchKind::Movable;
}

/**
 * @brief Lo mismo, mas la prudencia que necesita quien REORDENA.
 *
 * `add rd, rs` lee rd de verdad; `mov rd, rs` no.  La base lo sabe -- la forma
 * separa las ranuras que lee de las que escribe --, pero para decidir si dos
 * instrucciones se pueden cruzar, sobrar una lectura solo cuesta una
 * reordenacion que no se hace, mientras que faltar una cambia el resultado.
 */
[[gnu::always_inline]] inline bool touch_one_conservative(const DecodedInstr &d,
                                                          Touch &t) {
    if (!touch_one(d, t)) return false;
    t.reg_read |= t.reg_write;
    t.vec_read |= t.vec_write;
    return true;
}

} // namespace runtime

#endif // VESTA_RUNTIME_BUNDLE_TOUCH_H
