/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file src/runtime/bundle_fuse.cpp
 * @brief Convierte pares de instrucciones de un paquete en UNA sola.
 *
 * QUE ES, Y POR QUE VIVE AQUI Y NO EN EL COMPILADOR
 * -------------------------------------------------
 * Es lo unico que baja el RECUENTO de instrucciones, que es el cuello medido
 * del interprete: reordenar prepara el orden y empaquetar ahorra despachos,
 * pero las instrucciones siguen siendo las mismas.  Fusionar las quita.
 *
 * Y va en la VM, no en el emisor de intermedio, aunque el emisor ya sepa
 * hacerlo en algunos casos.  El bytecode le llega a la maquina de sitios que
 * no controla -- `.vel` escrito a mano, modulos cargados con `loadmodule`,
 * otro frontend, una version anterior del compilador --, asi que arreglarlo
 * alli mejora solo lo que produce el nuestro HOY.  Aqui funciona sea quien sea
 * el que lo genero.
 *
 * CUANTO HAY.  Medido con `tests/util/bundle_ilp.h` sobre los benchmarks
 * reales: el **44,6%** de las instrucciones ejecutadas esta en un par ya
 * adyacente cuya primera produce un valor que la segunda consume y que nadie
 * mas quiere.  (Sobre los programas SINTETICOS del banco sale 0%, porque sus
 * cuerpos ciclan tres registros sin temporales muertos -- medir ahi habria
 * dicho que no hay nada que hacer.)
 *
 * QUE SE FUSIONA HOY
 * ------------------
 * Solo con opcodes que YA EXISTEN, o sea sin tocar el ABI del bytecode:
 *
 *     mov rd, rs1        ->   <alu>3 rd, rs1, rs2
 *     <alu> rd, rs2
 *
 * Las nueve variantes de tres operandos (`adds3`..`xor3`, 0x73-0x7B) se
 * anadieron justo para este patron -- es lo que emite un generador cuando el
 * asignador de registros no pudo coalescer --, asi que la instruccion destino
 * ya esta implementada y probada.
 *
 * Los pares que mas pesan en la medida piden opcodes que NO existen (cargar y
 * sumar, multiplicar y sumar, xor y and).  Eso es un cambio del ABI y se
 * acuerda antes de escribirlo; aqui no se toca.
 *
 * POR QUE ES SEGURO
 * -----------------
 * La fusionada tiene que hacer EXACTAMENTE lo que hacian las dos, incluido lo
 * que no se ve:
 *
 *   - **El ancho.**  Solo se fusiona con las dos en 64 bits.  Un `mov` estrecho
 *     escribe media parte del registro y conserva la otra; `alu3` escribe el
 *     registro entero.
 *   - **Las banderas.**  `mov` no las toca y la ALU si; `alu3` las deja como la
 *     ALU.  Coincide.
 *   - **El segundo operando no puede ser el destino.**  `alu3` lee sus DOS
 *     fuentes antes de escribir, asi que `mov rd, rs1; add rd, rd` no es
 *     `adds3 rd, rs1, rd`: la segunda leeria el rd viejo en vez del recien
 *     copiado.  Es el caso que da otro resultado sin dar ningun error.
 *   - **Los registros especiales.**  Un `mov` con `_signed_instruct` puesto
 *     habla con rip/rsp/rbp, no con el banco general.
 *   - **El tamano.**  `exec_bundle` avanza `rip` sumando el tamano de cada
 *     instruccion, asi que la fusionada tiene que declarar la SUMA de los dos.
 *     Sin eso el paquete termina con `rip` corrido y el salto siguiente va a
 *     otro sitio -- otro resultado, no un error --.
 *
 * Y una que no es del par sino del paquete: fusionar cambia `k`, asi que se
 * hace DESPUES de reordenar y ANTES de publicar, mientras el paquete todavia
 * es local.
 */

#include "runtime/bundle.h"

#include <array> // la tabla de ALU de tres operandos

#include "runtime/bundle/bundle_touch_all.h"
#include "runtime/bundle/fuse_report.h"
#include "runtime/bundle/liveness.h"
#include "runtime/bundle/touch.h"
#include "runtime/mem_full_semantics.h"
#include "runtime/decode_table.h"
#include "runtime/exec_instruction.h"
#include "runtime/exec_instruction_fused.h"
#include "util/env_flags.h"

#if VM_BUNDLES

namespace runtime {

namespace {

/// Ancho de 64 bits.  Es el unico con el que se fusiona: ver la cabecera.
constexpr uint8_t kMode64 = 3;

/**
 * @brief Los dos topes de una fusionada, y de donde salen.
 *
 * `absorbed` son dos bits: una fusionada representa como mucho CUATRO
 * instrucciones del programa, o sea tres absorbidas.  `size_instr` son seis, y
 * tiene que poder con la tanda mas larga de las instrucciones mas grandes --
 * cuatro por once bytes, que es `FIXED_11`, la mayor de la ISA --.
 *
 * Se comprueban SIEMPRE antes de escribirlos.  Pasarse de `size_instr` no da
 * un error: deja `rip` corrido y el salto siguiente va a otro sitio.
 */
constexpr uint32_t kFusedMaxAbsorbed = 3;
constexpr uint32_t kFusedMaxSize = 63;
static_assert(kFusedMaxSize >= 11 * (kFusedMaxAbsorbed + 1),
              "`size_instr` tiene que poder con la tanda mas larga de las "
              "instrucciones mas grandes");

/**
 * @brief La variante de TRES operandos de cada ALU de dos, o 0 si no la tiene.
 *
 * TABLA PLANA, no un `switch`, y el indice lleva el signo dentro:
 * `(opcode2 << 1) | con_signo`.  Con eso, saber si un par se puede fusionar es
 * UNA carga y una comparacion contra cero -- sin ramas y sin que el predictor
 * tenga nada que acertar --, en vez de una cadena de casos que ademas el
 * compilador es libre de bajar como comparaciones encadenadas.
 *
 * Y no es solo velocidad: esto es una correspondencia entre opcodes.  Escrita
 * como codigo se separa de la tabla de despacho sin que nadie lo note, que es
 * el modo de fallo que este proyecto persigue en todas las tablas duplicadas.
 *
 * 512 bytes, o sea ocho lineas de cache, y se recorre una vez por paquete
 * FORMADO.  `and`, `or` y `xor` no distinguen signo, asi que sus dos entradas
 * son la misma.
 */
/* Se rellena por indice dentro de una funcion `constexpr` y no con
 * inicializadores designados (`[i] = v`), que son de C99 y C++ no admite: el
 * proyecto compila con `-pedantic-errors`, asi que no era un aviso sino un
 * fallo de compilacion.  La tabla resultante es la misma, y se sigue formando
 * ENTERA al compilar -- no hay ningun relleno en ejecucion. */
constexpr std::array<uint8_t, 512> build_alu3() {
    std::array<uint8_t, 512> t{};
    // add (0x05) -> addu3 / adds3
    t[0x05 * 2 + 0] = 0x76;
    t[0x05 * 2 + 1] = 0x73;
    // sub (0x08) -> subu3 / subs3
    t[0x08 * 2 + 0] = 0x77;
    t[0x08 * 2 + 1] = 0x74;
    // mul (0x0B) -> mulu3 / muls3
    t[0x0B * 2 + 0] = 0x78;
    t[0x0B * 2 + 1] = 0x75;
    // and / or / xor: sin signo que distinguir
    t[0x17 * 2 + 0] = 0x79;
    t[0x17 * 2 + 1] = 0x79;
    t[0x18 * 2 + 0] = 0x7A;
    t[0x18 * 2 + 1] = 0x7A;
    t[0x19 * 2 + 0] = 0x7B;
    t[0x19 * 2 + 1] = 0x7B;
    return t;
}

constexpr std::array<uint8_t, 512> kAlu3 = build_alu3();

/// Es @p d un `mov rd, rs` del banco general y de 64 bits?
[[gnu::always_inline]] inline bool is_plain_mov(const DecodedInstr &d) {
    return d.flags_info.is_not_extended == 0x00 &&
           d.flags_info.opcode_index == 0x14 &&
           d.flags_info._signed_instruct == 0 && // 1 = registro especial
           d.flags_info.mode == kMode64;
}

/**
 * @brief Se puede fusionar el par (@p a, @p b)?  Deja el opcode destino en
 *        @p out_op3.
 *
 * Separado del reescrito a proposito: es la MISMA pregunta que responde el
 * informe de pares (`tests/util/bundle_ilp.h`) cuando dice cuanto material
 * queda al alcance del ABI de hoy.  Si el informe la contestara por su cuenta
 * -- mirando nombres de opcode, que es como se hacia --, las dos respuestas se
 * separarian sin que nadie lo notara: el informe diria que hay trabajo donde el
 * fusionador no ve nada, o al reves.  Un hecho, un productor.
 */
[[gnu::always_inline]] inline FuseReject can_fuse(const DecodedInstr &a,
                                                  const DecodedInstr &b,
                                                  uint8_t &out_op3) {
    /* Las cuatro condiciones del `mov`, SEPARADAS.
     *
     * Juntas en un solo "no encaja" el informe no sirve para nada: dice que no
     * hay material igual cuando de verdad no lo hay que cuando el `mov` esta
     * ahi pero es de 32 bits o habla con un registro especial.  Son
     * conclusiones opuestas -- una cierra el tema y la otra dice donde
     * ampliar -- y costaba una sesion de depuracion distinguirlas. */
    if (a.flags_info.is_not_extended != 0x00 ||
        a.flags_info.opcode_index != 0x14)
        return FuseReject::NotAMov;
    if (a.flags_info._signed_instruct != 0) // habla con rip/rsp/rbp
        return FuseReject::NotAMov;
    if (a.flags_info.mode != kMode64) return FuseReject::WidthMismatch;
    if (b.flags_info.is_not_extended != 0x00) return FuseReject::NoThreeOpForm;
    if (b.flags_info.mode != kMode64) return FuseReject::WidthMismatch;

    const uint8_t op3 =
        kAlu3[((uint32_t)b.flags_info.opcode_index << 1) |
              (b.flags_info._signed_instruct != 0 ? 1u : 0u)];
    if (op3 == 0) return FuseReject::NoThreeOpForm;

    const uint8_t rd = a.data_instruction.reg_data.reg1;
    const uint8_t bd = b.data_instruction.reg_data.reg1;
    const uint8_t rs2 = b.data_instruction.reg_data.reg2;

    // La ALU tiene que escribir justo lo que el `mov` acaba de dejar.
    if (bd != rd) return FuseReject::DestMismatch;
    // Y su segunda fuente no puede ser el destino: ver la cabecera.
    if (rs2 == rd) return FuseReject::SrcIsDest;
    // Y tiene que caber en los dos bits de `absorbed`.
    if ((uint32_t)a.flags_info.absorbed + (uint32_t)b.flags_info.absorbed + 1u >
        3u)
        return FuseReject::TooMany;

    out_op3 = op3;
    return FuseReject::None;
}

/**
 * @brief Intenta fusionar @p a (mov) con @p b (ALU) dejando el resultado en
 *        @p a.
 *
 * @return true si se fusiono.  Si devuelve false, @p a queda INTACTA: un
 *         fusionador que deja el paquete a medias al renunciar es peor que uno
 *         que no lo intenta.
 */
[[gnu::always_inline]] inline void rewrite_mov_alu(DecodedInstr &a,
                                                  const DecodedInstr &b,
                                                  uint8_t op3) {
    const uint8_t rd = a.data_instruction.reg_data.reg1;
    const uint8_t rs1 = a.data_instruction.reg_data.reg2;
    const uint8_t rs2 = b.data_instruction.reg_data.reg2;

    /* Se construye la fusionada SOBRE `a`, que ya lleva el `pc` bueno.  El
     * formato de `alu3` es Convencion B: los dos bytes crudos, no los campos
     * de registro del decodificador. */
    const uint32_t size = (uint32_t)a.flags_info.size_instr +
                          (uint32_t)b.flags_info.size_instr;

    /* Y cuantas instrucciones del PROGRAMA pasa a representar la fusionada.
     * Sin esto, la maquina retiraria UNA donde el programa tiene DOS y los
     * MIPS bajarian cuanto mejor fusionase: la explicacion larga esta en
     * `DecodedInstr::flags_info::absorbed`.  Son dos bits, asi que se
     * comprueba en vez de suponerlo -- una cuenta que se envuelve en silencio
     * no da un error, da otro numero --, y esa comprobacion la hizo ya
     * `can_fuse`, que es donde viven TODAS las condiciones. */
    const uint32_t absorbed = (uint32_t)a.flags_info.absorbed +
                              (uint32_t)b.flags_info.absorbed + 1u;

    a.flags_info.opcode_index = op3;
    a.flags_info._signed_instruct = 0;
    a.flags_info.size_instr = size;
    a.flags_info.absorbed = (uint8_t)absorbed;
    a.data_instruction.reg_data.reg1 = (uint8_t)((rs1 << 4) | rd);
    a.data_instruction.reg_data.reg2 = (uint8_t)(rs2 << 4);
    a.metadata = &decode_table_extended[op3];
    a.exec_cached = decode_table_extended[op3].exec;
}

/**
 * @brief Es @p d una instruccion que PISA su destino entero, sin leerlo?
 *
 * Es la condicion de la que vive el segundo patron: si la primera del par no
 * lee el registro que escribe, se le puede cambiar el destino y lo que hubiera
 * dentro no le importaba a nadie.
 *
 * Se limita a la familia de tres operandos (0x73-0x7B) y a las cargas con
 * extension de cero (0x7C/0x7D), y NO porque la base no sepa distinguirlo -- la
 * forma ya separa las ranuras que lee de las que escribe, y ahi se ve que
 * `adds3` escribe la ranura 1 y no la lee, mientras que `add` escribe y lee la
 * 0 --, sino por una condicion que la forma NO dice: que la escritura sea de 64
 * bits ENTEROS.
 *
 * Un `mov` de 8 bits escribe el byte bajo y conserva los otros siete, asi que
 * cambiarle el destino dejaria la mitad alta del registro nuevo con lo que ya
 * tuviera.  Estas trece son las que siempre escriben el registro completo:
 * `alu3` opera sobre `qword()` pase lo que pase, y `loadz` existe justamente
 * para extender con ceros.  Cuando la base diga "escritura total" por si misma,
 * esto se sustituye por esa consulta.
 */
[[gnu::always_inline]] inline bool kills_dest_whole(const DecodedInstr &d) {
    if (d.flags_info.is_not_extended != 0x00) return false;
    const uint8_t op = (uint8_t)d.flags_info.opcode_index;
    if (op >= 0x73 && op <= 0x7D) return true;
    /* Y `mld`, que tambien pisa el registro ENTERO: escribe con `qword()` pase
     * cual sea el ancho del acceso -- de ahi que un `mld` de un byte deje los
     * otros siete a cero o a signo, nunca a lo que hubiera --.  Queda fuera el
     * banco de coma flotante, donde no escribe un registro general.
     *
     * Lo dijo la medida: `mov`/14 aparecia con 1595 pares como segunda de un
     * par cuya primera SI encajaba, y casi todos son `mld` seguido de copiar lo
     * cargado.  Redirigir el destino del `mld` los quita todos. */
    return op == 0x90 && (d.data_instruction.mem_full.flags & kMemFpBank) == 0;
}

/**
 * @brief Cambia el registro DESTINO de @p a, sea cual sea su convencion.
 *
 * Explicito y no un solo `or` sobre el primer byte, aunque los campos se
 * solapen en la union: que `mem_full.reg` y `reg_data.reg1` empiecen en el
 * mismo sitio es un detalle de disposicion, no un contrato, y apoyarse en el
 * deja una trampa para quien reordene la union.  Lo que se cambia es el
 * DESTINO, y cada convencion lo guarda donde lo guarda.
 */
[[gnu::always_inline]] inline void set_dest_reg(DecodedInstr &a, uint8_t rx) {
    if (a.flags_info.opcode_index == 0x90) { // mld: campo propio
        a.data_instruction.mem_full.reg = rx;
        return;
    }
    /* `alu3` va en bytes crudos y su destino es el nibble BAJO de byte2;
     * `loadz` usa la convencion del `mov` simple, donde `reg1` ES el registro y
     * el nibble alto esta siempre a cero.  Machacar el nibble bajo vale para
     * las dos. */
    a.data_instruction.reg_data.reg1 =
        (uint8_t)((a.data_instruction.reg_data.reg1 & 0xF0) | rx);
}

/**
 * @brief Segundo patron: la ALU escribe en el registro equivocado.
 *
 *     adds3 rd, a, b        ->    adds3 rX, a, b
 *     mov   rX, rd                (el `mov` desaparece)
 *
 * No hace falta NINGuN opcode nuevo: es la misma instruccion apuntando a otro
 * destino.  Lo unico que hay que demostrar es que a `rd` no lo quiere nadie
 * despues, y eso lo trae ya resuelto @p live_after.
 *
 * Que @p a lea `rX` no estorba: las de esta familia leen sus DOS fuentes antes
 * de escribir, asi que `adds3 rX, rX, b` hace lo mismo que hacian las dos.
 *
 * @param a          Primera del par; se reescribe en el sitio si cuaja.
 * @param b          El `mov` que copia el resultado.
 * @param ta         Lo que toca @p a, ya calculado.
 * @param live_after Registros vivos DESPUES del par.
 */
template <typename LiveFn>
[[gnu::always_inline]] inline FuseReject fuse_retarget(DecodedInstr &a,
                                                       const DecodedInstr &b,
                                                       const Touch &ta,
                                                       LiveFn &&live_at) {
    if (!kills_dest_whole(a)) return FuseReject::NotAMov;
    if (!is_plain_mov(b)) return FuseReject::CopyMismatch;

    const uint8_t rx = b.data_instruction.reg_data.reg1; // destino del mov
    const uint8_t rd = b.data_instruction.reg_data.reg2; // fuente del mov

    // El `mov` tiene que copiar justo lo que la primera acaba de producir, y la
    // primera tiene que escribir ESE registro y ninguno mas.
    if (ta.reg_write != (uint16_t)(1u << rd)) return FuseReject::CopyMismatch;
    // Y a `rd` no puede quererlo nadie despues del par.  La vivacidad se pide
    // AQUI y no antes: es lo caro, y hasta este punto ya se descarto casi todo.
    if ((live_at() & (uint16_t)(1u << rd)) != 0)
        return FuseReject::DestLiveOut;

    /* Los dos contadores del paquete son campos de bits ESTRECHOS y se
     * comprueban en vez de suponerlos: `absorbed` son 2 bits y `size_instr`
     * son 4, asi que una cadena larga los desbordaria.  Y desbordar `size_instr`
     * no da un error: deja `rip` corrido y el salto siguiente va a otro sitio. */
    const uint32_t absorbed = (uint32_t)a.flags_info.absorbed + 1u;
    const uint32_t size = (uint32_t)a.flags_info.size_instr +
                          (uint32_t)b.flags_info.size_instr;
    if (absorbed > kFusedMaxAbsorbed || size > kFusedMaxSize)
        return FuseReject::TooMany;

    set_dest_reg(a, rx);
    a.flags_info.size_instr = (uint8_t)size;
    a.flags_info.absorbed = (uint8_t)absorbed;
    return FuseReject::None;
}

/// Es @p d una ALU de tres operandos de las nueve?
[[gnu::always_inline]] inline bool is_alu3(const DecodedInstr &d) {
    return d.flags_info.is_not_extended == 0x00 &&
           d.flags_info.opcode_index >= kAlu3First &&
           d.flags_info.opcode_index <= kAlu3Last;
}

/**
 * @brief Tercer patron: dos ALU encadenadas en una instruccion SINTETICA.
 *
 *     adds3 rt, a, b        ->    alu2x rd, a, b, c    con rd = (a + b) ^ c
 *     xor3  rd, rt, c
 *
 * Sin opcode nuevo: ver el comentario grande de arriba.
 */
template <typename LiveFn>
[[gnu::always_inline]] inline FuseReject fuse_alu2x(DecodedInstr &a,
                                                    const DecodedInstr &b,
                                                    const Touch &ta,
                                                    LiveFn &&live_at) {
    if (!is_alu3(a)) return FuseReject::NotAMov;
    if (!is_alu3(b)) return FuseReject::NoThreeOpForm;

    const uint8_t op1 = (uint8_t)a.flags_info.opcode_index;
    const uint8_t op2 = (uint8_t)b.flags_info.opcode_index;

    const uint8_t rt = a.data_instruction.reg_data.reg1 & 0x0F;
    const uint8_t src1 = (a.data_instruction.reg_data.reg1 >> 4) & 0x0F;
    const uint8_t src2 = (a.data_instruction.reg_data.reg2 >> 4) & 0x0F;

    const uint8_t rd = b.data_instruction.reg_data.reg1 & 0x0F;
    const uint8_t b1 = (b.data_instruction.reg_data.reg1 >> 4) & 0x0F;
    const uint8_t b2 = (b.data_instruction.reg_data.reg2 >> 4) & 0x0F;

    // La primera tiene que escribir SOLO el temporal, y la segunda leerlo.
    if (ta.reg_write != (uint16_t)(1u << rt)) return FuseReject::CopyMismatch;
    const bool rt_left = (b1 == rt);
    const bool rt_right = (b2 == rt);
    if (!rt_left && !rt_right) return FuseReject::CopyMismatch;
    /* Si el temporal entra por LAS DOS fuentes no se puede: la sintetica lo
     * calcula una vez y lo mete por un lado solo. */
    if (rt_left && rt_right) return FuseReject::CopyMismatch;

    // Y a nadie le puede hacer falta despues.  Se pregunta AQUI, que es lo caro
    // y llega despues de haber descartado casi todo.
    if ((live_at() & (uint16_t)(1u << rt)) != 0)
        return FuseReject::DestLiveOut;

    const uint32_t absorbed = (uint32_t)a.flags_info.absorbed +
                              (uint32_t)b.flags_info.absorbed + 1u;
    const uint32_t size = (uint32_t)a.flags_info.size_instr +
                          (uint32_t)b.flags_info.size_instr;
    if (absorbed > kFusedMaxAbsorbed || size > kFusedMaxSize)
        return FuseReject::TooMany;
    /* La construccion la hace `make_alu2x`: aqui se decide QUE se fusiona, no
     * COMO queda.  Ver `runtime/exec_instruction_fused.h`. */
    make_alu2x(a, op1, op2, rd, src1, src2, rt_left ? b2 : b1, rt_right);
    a.flags_info.size_instr = (uint8_t)size;
    a.flags_info.absorbed = (uint8_t)absorbed;
    return FuseReject::None;
}

/**
 * @brief Prueba los patrones sobre el par y, si alguno cuaja, reescribe @p a.
 *
 * Se prueban en orden de coste de DESCARTE, no de rendimiento: el primero se
 * cae con una comparacion de opcode, y solo si la primera del par no es un
 * `mov` se mira el segundo.  Son excluyentes por construccion -- uno pide que
 * la primera SEA un `mov` y el otro que PISE su destino sin leerlo, y `mov`
 * no cumple lo segundo porque sus modos estrechos conservan la mitad alta --,
 * asi que no hay que decidir cual gana.
 *
 * @return @c FuseReject::None si se fusiono; si no, por que no.  La razon es
 *         la del patron que llego mas lejos, que es la util.
 */
/// Es @p d un `mld` que escribe en el banco GENERAL?
///
/// El banco de coma flotante queda fuera: ahi `mld` no produce un valor que la
/// ALU pueda consumir, reinterpreta los bits en un ZMM.  Es otra operacion.
[[gnu::always_inline]] inline bool is_gp_load(const DecodedInstr &d) {
    return d.flags_info.is_not_extended == 0x00 &&
           d.flags_info.opcode_index == 0x90 &&
           (d.data_instruction.mem_full.flags & kMemFpBank) == 0;
}

/**
 * @brief Cuarto patron: CARGAR Y OPERAR.
 *
 *     mld  rt, [dir]        ->    ldop rd, [dir], c
 *     alu3 rd, rt, c
 *
 * Es la familia con mas peso de las medidas (9,1 M de ejecuciones), y no pide
 * opcode nuevo: la fusionada es sintetica y su direccionamiento es el MISMO
 * `mem_full` que traia el `mld`, sin recortar nada.
 *
 * El ancho, el signo y el camino anfitrion/VM no se reescriben: la carga la
 * hace `mem_full_load`, que es la que usa `mld`.
 */
template <typename LiveFn>
[[gnu::always_inline]] inline FuseReject fuse_ldop(DecodedInstr &a,
                                                   const DecodedInstr &b,
                                                   const Touch &ta,
                                                   LiveFn &&live_at) {
    if (!is_gp_load(a)) return FuseReject::NotAMov;
    if (!is_alu3(b)) return FuseReject::NoThreeOpForm;

    const uint8_t rt = a.data_instruction.mem_full.reg;
    const uint8_t rd = b.data_instruction.reg_data.reg1 & 0x0F;
    const uint8_t b1 = (b.data_instruction.reg_data.reg1 >> 4) & 0x0F;
    const uint8_t b2 = (b.data_instruction.reg_data.reg2 >> 4) & 0x0F;

    // El `mld` tiene que producir SOLO el temporal, y la ALU consumirlo.
    if (ta.reg_write != (uint16_t)(1u << rt)) return FuseReject::CopyMismatch;
    const bool rt_left = (b1 == rt);
    const bool rt_right = (b2 == rt);
    if (rt_left == rt_right) return FuseReject::CopyMismatch; // ni una ni las dos

    /* Y el destino de la ALU no puede ser un registro del que dependa la
     * DIRECCION: la fusionada calcula la direccion y escribe el resultado en la
     * misma instruccion, y sin esta guarda escribiria antes de que otra copia
     * leyera la base.  En la version separada eso no pasaba porque el `mld` ya
     * habia terminado. */
    const uint16_t dst_bit = (uint16_t)(1u << rd);
    if ((ta.reg_read & dst_bit) != 0) return FuseReject::SrcIsDest;

    // Y a nadie le puede hacer falta el temporal despues.
    if ((live_at() & (uint16_t)(1u << rt)) != 0)
        return FuseReject::DestLiveOut;

    const uint32_t absorbed = (uint32_t)a.flags_info.absorbed +
                              (uint32_t)b.flags_info.absorbed + 1u;
    const uint32_t size = (uint32_t)a.flags_info.size_instr +
                          (uint32_t)b.flags_info.size_instr;
    if (absorbed > kFusedMaxAbsorbed || size > kFusedMaxSize)
        return FuseReject::TooMany;

    make_ldop(a, (uint8_t)b.flags_info.opcode_index, rd,
              rt_left ? b2 : b1, rt_right);
    a.flags_info.size_instr = (uint8_t)size;
    a.flags_info.absorbed = (uint8_t)absorbed;
    return FuseReject::None;
}

/// Es @p d un `mov rd, K` de 64 bits al banco general?
///
/// Se excluyen las otras dos variantes que comparten opcode: el registro
/// ESPECIAL (`direction` y `signed` a uno) y el `mov [reg], K`, que escribe en
/// memoria y no produce ningun valor en un registro.
[[gnu::always_inline]] inline bool is_mov_imm(const DecodedInstr &d) {
    return d.flags_info.is_not_extended == 0x00 &&
           d.flags_info.opcode_index == 0x15 &&
           d.flags_info.direction == 0 && d.flags_info._signed_instruct == 0 &&
           d.flags_info.mode == kMode64;
}

/**
 * @brief Quinto patron: OPERAR CON UNA CONSTANTE.
 *
 *     mov  rt, K            ->    alui rd, K, c
 *     alu3 rd, rt, c
 *
 * Es la primera de la lista de lo que no se miraba: `mov`/15 encabeza 6450
 * pares del corpus.  Tampoco pide opcode nuevo -- la constante de 64 bits cabe
 * de sobra en los dieciseis bytes de operandos de una sintetica.
 */
template <typename LiveFn>
[[gnu::always_inline]] inline FuseReject fuse_alui(DecodedInstr &a,
                                                   const DecodedInstr &b,
                                                   const Touch &ta,
                                                   LiveFn &&live_at) {
    if (!is_mov_imm(a)) return FuseReject::NotAMov;
    if (!is_alu3(b)) return FuseReject::NoThreeOpForm;

    const uint8_t rt = a.data_instruction.inmmed_data.reg;
    const uint64_t imm = a.data_instruction.inmmed_data.inmmed;
    const uint8_t rd = b.data_instruction.reg_data.reg1 & 0x0F;
    const uint8_t b1 = (b.data_instruction.reg_data.reg1 >> 4) & 0x0F;
    const uint8_t b2 = (b.data_instruction.reg_data.reg2 >> 4) & 0x0F;

    // El `mov` tiene que producir SOLO el temporal, y la ALU consumirlo.
    if (ta.reg_write != (uint16_t)(1u << rt)) return FuseReject::CopyMismatch;
    const bool rt_left = (b1 == rt);
    const bool rt_right = (b2 == rt);
    if (rt_left == rt_right) return FuseReject::CopyMismatch;

    // Y a nadie le puede hacer falta el temporal despues.
    if ((live_at() & (uint16_t)(1u << rt)) != 0)
        return FuseReject::DestLiveOut;

    const uint32_t absorbed = (uint32_t)a.flags_info.absorbed +
                              (uint32_t)b.flags_info.absorbed + 1u;
    const uint32_t size = (uint32_t)a.flags_info.size_instr +
                          (uint32_t)b.flags_info.size_instr;
    if (absorbed > kFusedMaxAbsorbed || size > kFusedMaxSize)
        return FuseReject::TooMany;

    /* La constante va donde estaba el temporal: si el `mov` lo dejaba en la
     * fuente IZQUIERDA de la ALU, la constante entra por la izquierda.  Importa
     * en `sub`, donde el orden es el resultado. */
    make_alui(a, imm, (uint8_t)b.flags_info.opcode_index, rd,
              rt_left ? b2 : b1, rt_left ? false : true);
    a.flags_info.size_instr = (uint8_t)size;
    a.flags_info.absorbed = (uint8_t)absorbed;
    return FuseReject::None;
}

/// Es @p d un `mld` o `mst` sobre el banco GENERAL?
[[gnu::always_inline]] inline bool is_mem_full_op(const DecodedInstr &d) {
    if (d.flags_info.is_not_extended != 0x00) return false;
    const uint8_t op = (uint8_t)d.flags_info.opcode_index;
    if (op != 0x90 && op != 0x91) return false;
    // El banco de coma flotante lee y escribe ZMM, no registros generales.
    return (d.data_instruction.mem_full.flags & kMemFpBank) == 0;
}

/**
 * @brief Septimo patron: DOS ACCESOS A MEMORIA de una vez.
 *
 * Es una TANDA, no una cadena: las dos partes son independientes y lo unico que
 * hay que respetar es el orden.  De ahi que no haga falta desambiguar
 * direcciones -- dos escrituras al mismo sitio, o una escritura y una lectura
 * del mismo sitio, siguen ocurriendo en el mismo orden que antes -- ni
 * demostrar que nada muere.
 *
 * Sirve para las cuatro combinaciones: carga+carga, carga+almacen,
 * almacen+carga y almacen+almacen.
 */
[[gnu::always_inline]] inline FuseReject fuse_mem2(DecodedInstr &a,
                                                   const DecodedInstr &b) {
    if (!is_mem_full_op(a)) return FuseReject::NotAMov;
    if (!is_mem_full_op(b)) return FuseReject::NoThreeOpForm;
    // Una ya fusionada no vuelve a entrar: su hueco de operandos esta ocupado.
    if (a.flags_info.absorbed != 0 || b.flags_info.absorbed != 0)
        return FuseReject::TooMany;

    const uint32_t size = (uint32_t)a.flags_info.size_instr +
                          (uint32_t)b.flags_info.size_instr;
    if (size > kFusedMaxSize) return FuseReject::TooMany;

    make_mem2(a, b, a.flags_info.opcode_index == 0x91,
              b.flags_info.opcode_index == 0x91);
    a.flags_info.size_instr = (uint8_t)size;
    a.flags_info.absorbed = 1;
    return FuseReject::None;
}

/**
 * @brief Cuantos `mov` reg,reg seguidos hay desde @p i, hasta el tope que cabe.
 *
 * Es el UNICO patron que no consume un par sino una TANDA, y el unico que no
 * necesita demostrar que nada muere: no produce ningun temporal, solo copia.
 * Basta con ejecutarlos en el mismo orden.
 *
 * El tope son CUATRO, y quien lo fija es `absorbed`: son dos bits, o sea que
 * una fusionada puede representar como mucho cuatro instrucciones del
 * programa.  El tamano ya no aprieta -- 4x4 = 16 y `size_instr` admite 31 --,
 * pero antes de ensancharlo el tope eran tres.
 *
 * @return 0, o entre 2 y 4.  Uno solo no es fusion.
 */
[[gnu::always_inline]] inline uint32_t mov_run_len(const Bundle &b,
                                                   uint32_t i) {
    constexpr uint32_t kMaxRun = 4;
    uint32_t n = 0;
    while (n < kMaxRun && i + n < b.k) {
        const DecodedInstr &d = b.instr[i + n];
        // Una ya fusionada no vuelve a entrar: sus campos de opcode ya no la
        // describen.
        if (d.flags_info.absorbed != 0) break;
        if (!is_plain_mov(d)) break;
        ++n;
    }
    return n >= 2 ? n : 0;
}

template <typename LiveFn>
[[gnu::always_inline]] inline FuseReject try_fuse(DecodedInstr &a,
                                                  const DecodedInstr &b,
                                                  const Touch &ta,
                                                  LiveFn &&live_at) {
    uint8_t op3 = 0;
    const FuseReject r = can_fuse(a, b, op3);
    if (r != FuseReject::NotAMov) {
        if (r == FuseReject::None) rewrite_mov_alu(a, b, op3);
        return r;
    }
    const FuseReject rr = fuse_retarget(a, b, ta, live_at);
    if (rr != FuseReject::NotAMov) return rr;
    const FuseReject r2 = fuse_alu2x(a, b, ta, live_at);
    if (r2 != FuseReject::NotAMov) return r2;
    const FuseReject r3 = fuse_ldop(a, b, ta, live_at);
    if (r3 != FuseReject::NotAMov) return r3;
    const FuseReject r4 = fuse_alui(a, b, ta, live_at);
    if (r4 != FuseReject::NotAMov) return r4;
    /* La tanda de memoria va la ULTIMA de las de par: `mld` encabeza tambien el
     * patron de cargar-y-operar, y ese es preferible -- colapsa una cadena en
     * vez de solo ahorrar un despacho --.  Aqui llega lo que aquel descarto. */
    return fuse_mem2(a, b);
}


} // namespace

FuseReject fuse_would_apply(const DecodedInstr &a, const DecodedInstr &b) {
    uint8_t op3 = 0;
    return can_fuse(a, b, op3);
}


uint32_t bundle_fuse(Bundle &b, BundleTouch &tc, ProcessVM *process,
                     uint64_t next_pc, vm::VirtualMemory::PageView *view,
                     const FuseTelemetry *tel) {
    if (b.k < 2) return 0;
    if (__builtin_expect(::util::flag_on(::util::FlagId::NoBundleFuse), 0))
        return 0;

    /* Lo que toca cada una viene ya calculado: es el mismo analisis que uso el
     * reordenador, y antes se rehacia entero aqui.  Se usa CRUDO -- la
     * vivacidad necesita distinguir PISAR un registro de leerlo, y la version
     * prudente del reordenador borra justo ese dato. */
    const Touch *const t = tc.t;

    /* Y quien sigue vivo detras de cada una, PEREZOSO.
     *
     * Se calcula la primera vez que un patron lo pregunta, y no antes.  No es
     * recortar posibilidades -- los patrones se prueban todos igual --: es no
     * pagar por adelantado algo que en la mayoria de los paquetes no se llega a
     * mirar.
     *
     * Y lo que se ahorra no es la pasada hacia atras, que son k operaciones
     * sobre datos ya en cache: es `live_out_after`, que DESCODIFICA hasta ocho
     * instrucciones mas alla del paquete.  Medido con los cinco motores del
     * banco, pagarlo siempre costaba un 29% en las mezclas donde no se fusiona
     * nada, y la caida crecia con la longitud del programa -- o sea con la
     * frecuencia de formacion, que es exactamente donde este camino duele. */
    uint16_t live_after[BUNDLE_MAX];
    bool live_ready = false;
    const auto live_at = [&](uint32_t idx) -> uint16_t {
        if (!live_ready) {
            /* Y sigue siendo PEREZOSO aunque esto corra en el ayudante.
             *
             * `live_out_after` descodifica bytecode del proceso, y eso desde
             * otro hilo era una carrera -- no de las que fallan: fusionaba MAL
             * y el programa devolvia 0 donde esperaba 19 --.  Se aparto
             * calculandolo en el hilo duenyo y mandandolo dentro del encargo,
             * pero eso lo volvia ANSIOSO: se pagaba en cada formacion, tambien
             * en las mezclas donde no se fusiona nada, que es justo lo que la
             * pereza evitaba (medido: 29%).
             *
             * Con la cache de pagina del llamante ya no hace falta elegir: el
             * ayudante trae la suya y lo mira aqui, cuando un patron lo pide. */
            const uint16_t live_out = live_out_after(process, next_pc, view);
            if (live_out == 0xFFFF && process->bundle_stats_on)
                ++process->bundle_stats.lookahead_blind;
            bundle_live_after(b, t, live_out, live_after);
            live_ready = true;
        }
        return live_after[idx];
    };

    uint32_t fused = 0, out = 0;
    for (uint32_t i = 0; i < b.k;) {
        /* La TANDA de `mov` va primero porque consume mas de dos, y porque no
         * necesita nada de lo caro: ni vivacidad, ni dependencias.  Si la
         * probaran despues, el patron de par se habria llevado ya las dos
         * primeras y la tanda no llegaria a formarse nunca. */
        const uint32_t run = mov_run_len(b, i);
        if (run >= 2) {
            uint8_t dst[4], src[4];
            uint32_t size = 0;
            for (uint32_t j = 0; j < run; ++j) {
                dst[j] = b.instr[i + j].data_instruction.reg_data.reg1;
                src[j] = b.instr[i + j].data_instruction.reg_data.reg2;
                size += b.instr[i + j].flags_info.size_instr;
            }
            DecodedInstr cand = b.instr[i];
            make_movn(cand, dst, src, run);
            cand.flags_info.size_instr = (uint8_t)size;
            cand.flags_info.absorbed = (uint8_t)(run - 1);
            b.instr[out++] = cand;
            i += run;
            fused += run - 1; // una tanda de tres son DOS uniones
            continue;
        }
        if (i + 1 < b.k) {
            /* Se mira el par (i, i+1) y, si cuaja, la fusionada ocupa el hueco
             * de las dos y se saltan las dos.  Los patrones se prueban del mas
             * barato de descartar al mas caro. */
            DecodedInstr cand = b.instr[i];
            // La vivacidad de ESTE par, atada al indice y sin calcular todavia.
            const auto live_here = [&] { return live_at(i + 1); };
            const FuseReject r =
                try_fuse(cand, b.instr[i + 1], t[i], live_here);
            if (r == FuseReject::None) {
                /* La fusionada describe la union de sus partes -- eso es lo que
                 * dice `fused_touch` --, asi que su entrada se recalcula.  Es
                 * una vez por par fusionado, no una por instruccion. */
                tc.t[out] = Touch{};
                tc.kind[out] = touch_classify(cand, tc.t[out]);
                tc.role[out] = fuse_role(cand);
                b.instr[out++] = cand;
                i += 2;
                ++fused;
                continue;
            }
            /* Por que NO.  Va detras de la rama del caso bueno y solo cuando la
             * telemetria esta pedida: un contador por par renunciado seria una
             * escritura por instruccion del paquete en el camino de formacion,
             * y ese camino ya se paga entero cada fallo de icache. */
            if (__builtin_expect(tel != nullptr, 0)) {
                tel->reject[(size_t)r] += 1;
                /* Y CUAL era la primera, cuando ningun patron la miro.  Sin
                 * esto, "no encaja" es el 84% de los rechazos y no dice nada:
                 * con el opcode delante se convierte en la lista de patrones
                 * que faltan, ordenada por peso. */
                if (r == FuseReject::NotAMov) {
                    const bool ext =
                        (b.instr[i].flags_info.is_not_extended == 0x00);
                    tel->uncovered[(ext ? 256u : 0u) + touch_opcode(b.instr[i])] +=
                        1;
                } else if (r == FuseReject::NoThreeOpForm &&
                           (t[i].reg_write & t[i + 1].reg_read) != 0) {
                    /* La primera SI encajaba: lo que falta es admitir esta como
                     * segunda.
                     *
                     * Se exige que HAYA dependencia -- que la segunda lea lo
                     * que la primera escribe --, porque si no la hay no la
                     * fusionaria ningun patron y la lista senalaria trabajo que
                     * no existe.  Sin este filtro, `mov rt,K1; mov rd,K2`
                     * encabezaba el ranking siendo dos instrucciones
                     * independientes. */
                    const DecodedInstr &sec = b.instr[i + 1];
                    const bool ext = (sec.flags_info.is_not_extended == 0x00);
                    tel->unmatched_second[(ext ? 256u : 0u) +
                                          touch_opcode(sec)] += 1;
                }
                probe_new_opcode(t[i], t[i + 1], live_at(i + 1), b, *tel);
            }
        }
        /* El analisis compartido se COMPACTA con el paquete.  `out <= i` siempre,
         * asi que moverlo en el sitio no se pisa a si mismo. */
        bundle_touch_move(tc, out, tc, i);
        b.instr[out++] = b.instr[i++];
    }
    b.k = out;
    /* Cuantos pares se juntaron AQUI.  Lo guarda el paquete, no un contador
     * global, porque la cifra que importa no es cuantos pares se fusionaron al
     * formar sino cuantas instrucciones se ahorran EJECUTANDO -- y eso es esto
     * por las veces que se entra, que solo se sabe al final.  Cabe en un byte:
     * un paquete tiene como mucho 31 pares. */
    b.fused_pairs = (uint8_t)fused;
    return fused;
}

} // namespace runtime

#endif // VM_BUNDLES
