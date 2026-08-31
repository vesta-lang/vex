/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file ir/native_effect_vocab.h
 * @brief El vocabulario de lo que una funcion AJENA puede hacer.
 *
 * Vive aqui -- en el IR, por debajo del frontend y del analisis -- porque lo
 * usan los TRES: el `extern` de Vesta lo declara, @c IrNativeEffects lo lleva
 * y el motor de efectos lo consume.  Definirlo en cualquiera de ellos obligaria
 * a los otros dos a depender de esa capa, o a tener su copia; y dos copias del
 * mismo vocabulario acaban diciendo cosas distintas.
 *
 * NO es "los efectos": los efectos son las palabras (`io`, `alloc`, ...).  Esto
 * es lo que REFINA a tres de ellas, y son refinamientos de naturaleza distinta:
 * de quien es el mecanismo (lanzar, abortar) y que puede fallar (atrapar).
 */
#ifndef IR_NATIVE_EFFECT_VOCAB_H
#define IR_NATIVE_EFFECT_VOCAB_H

#include <cstdint>

namespace ir {

/**
 * @brief De QUIEN es la excepcion o el aborto que sale de una externa.
 *
 * No es un detalle: son mecanismos distintos y no se recogen igual.
 *
 *   - @c Vesta   lo lanza NUESTRO runtime: un `catch` lo recoge, el
 *                desenrollado es el nuestro y las tablas son las que emitimos.
 *   - @c Native  lo lanza el OTRO LADO -- una excepcion de C++, un SEH de
 *                Windows, un `abort()` de la libreria --.  Nuestro `catch` NO
 *                lo recoge, y desenrollar a traves de nuestros marcos no esta
 *                garantizado: quien llama tiene que tratarlo como una salida
 *                sin retorno, no como algo recuperable.
 *   - @c Any     no se dijo cual.  Es lo CONSERVADOR y lo que vale la palabra
 *                desnuda: se supone lo peor de los dos.
 *
 * El orden importa: `Any` es el peor y va primero, para que el neutro de una
 * union sea el conservador y no el permisivo.
 */
enum class UnwindOrigin : uint8_t {
    Any = 0, ///< no se dijo: se supone lo peor.
    Vesta,   ///< nuestro runtime; capturable.
    Native   ///< el otro lado; NO capturable por nosotros.
};

/**
 * @brief Que fallo del PROCESADOR puede provocar una externa.
 *
 * Bits, no un enum suelto, porque una funcion puede provocar varios y hay que
 * poder decirlos todos.  Cero = no se dijo cual, y entonces vale por todos:
 * quien no lo diga no se beneficia de haberlo acotado.
 *
 * MULTI-ISA A PROPOSITO.  Cual de estos existe de verdad depende del juego de
 * instrucciones: en x86-64 una division entera entre cero atrapa, y en aarch64
 * NO -- devuelve cero --.  Por eso esto no se deduce de la arquitectura: lo
 * DECLARA quien conoce la funcion, y si varia con el objetivo se dice con el
 * `when:` que ya existe:
 *
 *     @traps(div0, when: arch == "x86-64")
 *
 * El vocabulario CRECE: anadir un fallo es anadir un bit y su nombre en la
 * tabla, sin tocar la gramatica ni el formato.
 */
using TrapKinds = uint16_t;

static constexpr TrapKinds TRAP_NONE = 0;       ///< no se acoto: vale por todos
static constexpr TrapKinds TRAP_DIV0 = 1u << 0; ///< division entre cero
static constexpr TrapKinds TRAP_ACCESS = 1u << 1;  ///< acceso invalido
static constexpr TrapKinds TRAP_ALIGN = 1u << 2;   ///< acceso desalineado
static constexpr TrapKinds TRAP_ILLEGAL = 1u << 3; ///< instruccion ilegal
static constexpr TrapKinds TRAP_STACK = 1u << 4;   ///< desbordamiento de pila
static constexpr TrapKinds TRAP_FP = 1u << 5;      ///< excepcion IEEE 754

/**
 * @brief QUE PARTE del mundo de fuera toca una externa.
 *
 * "El mundo del SO" en una sola palabra es un saco: dentro caben el reloj, un
 * fichero, la red y el registro, y no tienen las mismas consecuencias.  Dos
 * llamadas que tocan partes DISJUNTAS no se estorban -- se pueden reordenar, y
 * una que no se usa se puede quitar --; con una sola palabra, cualquier par
 * choca con cualquier par y se pierde todo eso.
 *
 * Y no solo eso: leer el RELOJ o la ENTROPIA no da lo mismo dos veces, y leer
 * la configuracion si.  Con un unico "lee el mundo" hay que suponer lo primero
 * siempre, que es tratar a la mayoria por el peor caso.
 *
 * Bits, como los fallos, y por lo mismo: se pueden decir varios, y cero
 * significa "no se acoto" -- vale por todos --.  El vocabulario CRECE sin
 * tocar la gramatica ni el formato.
 */
using WorldKinds = uint16_t;

static constexpr WorldKinds WORLD_NONE = 0;       ///< sin acotar: vale por todo
static constexpr WorldKinds WORLD_FILE = 1u << 0; ///< ficheros y su metadata
static constexpr WorldKinds WORLD_NET = 1u << 1;  ///< la red
static constexpr WorldKinds WORLD_CLOCK = 1u << 2;   ///< la hora
static constexpr WorldKinds WORLD_RANDOM = 1u << 3;  ///< entropia del sistema
static constexpr WorldKinds WORLD_ENV = 1u << 4;     ///< variables de entorno
static constexpr WorldKinds WORLD_CONFIG = 1u << 5;  ///< registro, /etc
static constexpr WorldKinds WORLD_PROCESS = 1u << 6; ///< pid, manejadores, TLS
static constexpr WorldKinds WORLD_CONSOLE = 1u << 7; ///< terminal
static constexpr WorldKinds WORLD_DEVICE = 1u << 8;  ///< hardware, MMIO

/// @brief Las partes cuyo valor NO se repite entre dos lecturas.
///
/// Leer estas hace la llamada no-determinista; leer las demas, no.  Es la
/// razon principal de partir el saco: con una sola palabra habia que suponer
/// esto de todas.
static constexpr WorldKinds WORLD_CAMBIANTE = WORLD_CLOCK | WORLD_RANDOM;

/// @brief El nombre de una parte del mundo, o nulo si @p b no es una sola.
inline const char *world_kind_name(WorldKinds b) noexcept {
    switch (b) {
    case WORLD_FILE: return "file";
    case WORLD_NET: return "net";
    case WORLD_CLOCK: return "clock";
    case WORLD_RANDOM: return "random";
    case WORLD_ENV: return "env";
    case WORLD_CONFIG: return "config";
    case WORLD_PROCESS: return "process";
    case WORLD_CONSOLE: return "console";
    case WORLD_DEVICE: return "device";
    default: return nullptr;
    }
}

/// @brief El bit de un nombre, o @c WORLD_NONE si no es ninguno.
inline WorldKinds world_kind_from_name(const char *s) noexcept {
    if (s == nullptr) return WORLD_NONE;
    for (WorldKinds b = 1; b != 0; b = static_cast<WorldKinds>(b << 1)) {
        const char *n = world_kind_name(b);
        if (n == nullptr) continue;
        const char *a = n;
        const char *c = s;
        while (*a != '\0' && *a == *c) {
            ++a;
            ++c;
        }
        if (*a == '\0' && *c == '\0') return b;
    }
    return WORLD_NONE;
}

/// @brief El nombre de un fallo, o nulo si @p b no es uno solo conocido.
///
/// UNA tabla para las dos direcciones: lo que el parser acepta es exactamente
/// lo que el volcado ensena, y anadir un fallo es anadir una fila.
inline const char *trap_kind_name(TrapKinds b) noexcept {
    switch (b) {
    case TRAP_DIV0: return "div0";
    case TRAP_ACCESS: return "access";
    case TRAP_ALIGN: return "align";
    case TRAP_ILLEGAL: return "illegal";
    case TRAP_STACK: return "stack_overflow";
    case TRAP_FP: return "fp";
    default: return nullptr;
    }
}

/// @brief El bit de un nombre, o @c TRAP_NONE si no es ninguno.
inline TrapKinds trap_kind_from_name(const char *s) noexcept {
    if (s == nullptr) return TRAP_NONE;
    for (TrapKinds b = 1; b != 0; b = static_cast<TrapKinds>(b << 1)) {
        const char *n = trap_kind_name(b);
        if (n == nullptr) continue;
        const char *a = n;
        const char *c = s;
        while (*a != '\0' && *a == *c) {
            ++a;
            ++c;
        }
        if (*a == '\0' && *c == '\0') return b;
    }
    return TRAP_NONE;
}

} // namespace ir

#endif // IR_NATIVE_EFFECT_VOCAB_H
