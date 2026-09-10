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

/**
 * @file jit_call.h
 * @brief Estructuras basicas para la generacion JIT de shellcode y llamadas a
 * funciones nativas.
 *
 * Define:
 *  - @c err_shellcode : codigos de error del generador de shellcode JIT.
 *  - @c shellcode_t   : buffer dinamico de bytes con funciones de emision y
 * expansion.
 *  - @c PendingCall_t : descriptor de una llamada nativa pendiente de ejecucion
 * asincrona.
 *
 * El modulo JIT genera secuencias de bytes x86_64 que llaman a funciones del
 * host desde codigo VM, usando @c shellcode_t como buffer de construccion
 * incremental.
 * @c PendingCall_t permite encolar esas llamadas para ejecutarlas en un hilo
 * dedicado.
 *
 * @note Este modulo esta en desarrollo activo; la interfaz puede cambiar.
 */

#ifndef JIT_CALL_H
#define JIT_CALL_H

#include <cstdint>
#include <cstddef>
/* Nuestro cerrojo, no `pthread_mutex_t`.  El CRT de MSVC no trae `<pthread.h>`
 * -- era lo unico que ataba esta cabecera a MinGW --, pero la razon de fondo no
 * es esa: en Windows los pthreads son winpthreads, la emulacion que este mismo
 * proyecto evita a proposito en el resto de los sitios (ver la cabecera de
 * `util/shared_mutex.h`, donde esta medido que se rompe con hilos que nacen y
 * mueren).  `util::SharedMutex` es un `SRWLOCK` del sistema: del tamano de un
 * puntero, sin reservar nada y sin destruir nada. */
#include "util/shared_mutex.h"

/**
 * @brief Codigos de error del generador de shellcode JIT.
 *
 * Valores:
 *  - @c NO_ERROR_SC                             : operacion completada sin
 * error.
 *  - @c REALLOC_ERROR                           : fallo al reasignar el buffer
 * del shellcode.
 *  - @c EmitIndirect_ERROR                      : error al emitir una
 * referencia indirecta.
 *  - @c EmitIndirectByteDisplaced_ERROR         : error con desplazamiento de 1
 * byte.
 *  - @c EmitIndirectDisplaced_ERROR             : error con desplazamiento de 4
 * bytes.
 *  - @c EmitIndirectIndexed_ERROR               : error con direccionamiento
 * indexado.
 *  - @c EmitIndirectIndexedDisplaced_ERROR      : error con indexado mas
 * desplazamiento de 4 bytes.
 *  - @c EmitIndirectIndexedByteDisplaced_ERROR  : error con indexado mas
 * desplazamiento de 1 byte.
 */
typedef enum err_shellcode {
    NO_ERROR_SC,                     ///< Sin error.
    REALLOC_ERROR,                   ///< Fallo al expandir el buffer.
    EmitIndirect_ERROR,              ///< Error en emision indirecta basica.
    EmitIndirectByteDisplaced_ERROR, ///< Error en emision indirecta con disp8.
    EmitIndirectDisplaced_ERROR,     ///< Error en emision indirecta con disp32.
    EmitIndirectIndexed_ERROR,       ///< Error en emision indexada.
    EmitIndirectIndexedDisplaced_ERROR,    ///< Error en emision indexada con
                                           ///< disp32.
    EmitIndirectIndexedByteDisplaced_ERROR ///< Error en emision indexada con
                                           ///< disp8.
} err_shellcode;

/**
 * @struct shellcode_t
 * @brief Buffer dinamico de bytes para la construccion incremental de shellcode
 * JIT.
 *
 * Actua como un vector de bytes con capacidad dinamica y funciones de emision
 * accesibles mediante punteros de funcion.  Cada llamada a @c Emit8, @c Emit32
 * o
 * @c Emit64 agrega bytes al buffer; si la capacidad se agota, @c expand duplica
 * el tamano del buffer mediante @c realloc.
 *
 * El campo @c err almacena el primer error ocurrido; las funciones de emision
 * deben verificarlo antes de continuar.
 *
 * Ciclo de vida tipico:
 * @code
 *   shellcode_t sc;
 *   // inicializar con la funcion de inicializacion del modulo JIT
 *   sc.Emit8(&sc, 0x90);          // NOP
 *   sc.Emit32(&sc, 0xDEADBEEF);   // datos de 4 bytes
 *   if (sc.err != NO_ERROR_SC) { ... }
 *   sc.free(&sc);                 // liberar buffer
 * @endcode
 */
typedef struct shellcode_t {
    size_t capacity; ///< Capacidad actual en bytes del buffer @c code.
    size_t size;     ///< Numero de bytes escritos hasta ahora en @c code.

    uint8_t *code; ///< Puntero al buffer de bytes del shellcode.
    err_shellcode
        err; ///< Primer error ocurrido (NO_ERROR_SC si todo fue bien).

    /**
     * @brief Emite un byte al buffer.
     * @param code Puntero al propio @c shellcode_t.
     * @param byte Byte a emitir.
     */
    void (*Emit8)(struct shellcode_t *code, uint8_t byte);

    /**
     * @brief Emite 4 bytes (uint32_t) al buffer en orden little-endian.
     * @param code  Puntero al propio @c shellcode_t.
     * @param bytes Valor de 4 bytes a emitir.
     */
    void (*Emit32)(struct shellcode_t *code, uint32_t bytes);

    /**
     * @brief Emite 8 bytes (uint64_t) al buffer en orden little-endian.
     * @param code  Puntero al propio @c shellcode_t.
     * @param bytes Valor de 8 bytes a emitir.
     */
    void (*Emit64)(struct shellcode_t *code, uint64_t bytes);

    /**
     * @brief Expande la capacidad del buffer duplicando su tamano.
     *
     * Si @c realloc falla establece @c err = @c REALLOC_ERROR.
     *
     * @param code Puntero al propio @c shellcode_t.
     */
    void (*expand)(struct shellcode_t *code);

    /**
     * @brief Libera el buffer @c code y resetea el shellcode.
     * @param code Puntero al propio @c shellcode_t.
     */
    void (*free)(struct shellcode_t *code);

    /**
     * @brief Imprime el contenido del buffer como volcado hexadecimal.
     * @param shell Puntero constante al @c shellcode_t a mostrar.
     */
    void (*dump)(const struct shellcode_t *shell);
} shellcode_t;

/**
 * @struct PendingCall_t
 * @brief Descriptor de una llamada a funcion nativa pendiente de ejecucion
 * asincrona.
 *
 * Permite encolar llamadas a funciones del host para que un hilo dedicado las
 * ejecute de forma ordenada.  El llamante crea un @c PendingCall_t, lo encola y
 * puede esperar a que @c finished sea @c true para leer @c result.
 *
 * El campo @c arg proporciona el shellcode con los argumentos pre-empaquetados
 * en un formato listo para la ABI nativa del sistema.
 *
 * Sincronizacion:
 *  - @c lock protege las escrituras y lecturas de @c finished y @c result.
 *  - El hilo ejecutor adquiere @c lock, ejecuta @c func(arg), guarda @c result,
 *    pone @c finished = @c true y libera @c lock.
 */
typedef struct PendingCall_t {
    void *(*func)(void *arg); ///< Puntero a la funcion nativa que se invocara.
    shellcode_t *arg;         ///< Shellcode con los argumentos empaquetados.
    void *result;             ///< Valor de retorno de la funcion (valido cuando
                              ///< finished==true).
    bool finished; ///< true una vez que la funcion termino de ejecutarse.

    util::SharedMutex lock; ///< Cerrojo que protege el acceso a finished y result.
} PendingCall_t;

#endif // JIT_CALL_H
