/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/cpu_topology.h
 * @brief Que nucleos tiene la maquina y de que clase, para poder elegir.
 *
 * POR QUE EXISTE
 * --------------
 * Porque suponerlo ya costo caro.  El hilo ayudante del reparto de paquetes se
 * ataba "al procesador permitido de numero mas alto", razonando que los
 * hermanos SMT llevan numeros bajos y asi cae en otro nucleo fisico sin tener
 * que preguntar donde esta el principal.  En una maquina homogenea es correcto.
 * En una HIBRIDA es la peor eleccion posible: los nucleos eficientes se
 * enumeran los ULTIMOS, asi que el numero mas alto es siempre uno de ellos.
 *
 * Perfilado con contadores de hardware sobre un i7-13700KF (8 nucleos de
 * rendimiento con SMT = CPU 0..15, 8 eficientes = CPU 16..23):
 *
 *                        sin reparto      con reparto
 *     ciclos en P-core       796 M          1.658 M
 *     ciclos en E-core       3,4 M          1.131 M
 *     CPI                    0,277            1,039
 *     CPI del E-core            --            1,799
 *
 * O sea que la mitad del trabajo se le estaba dando a un nucleo 6,5 veces mas
 * lento por instruccion.  No se veia por ningun sitio: no falla nada, solo
 * rinde menos.
 *
 * Y SIRVE PARA MEDIR, que es el otro uso
 * --------------------------------------
 * En una maquina hibrida, dos ejecuciones del mismo banco pueden diferir un 70%
 * solo por donde decidio ponerlo el sistema.  Atando el hilo de medida a una
 * clase, la cifra deja de depender de esa loteria -- y ademas se puede medir la
 * misma carga en las dos clases, que es un dato por si mismo.
 *
 * SE PREGUNTA, NO SE DEDUCE
 * -------------------------
 * Nada de inferir la clase por el numero de procesador ni por el fabricante: se
 * le pregunta al sistema.  Si no sabe contestar, la respuesta es "no se" -- una
 * mascara vacia -- y quien llama decide, en vez de recibir una suposicion
 * disfrazada de dato.
 */

#ifndef VESTA_UTIL_CPU_TOPOLOGY_H
#define VESTA_UTIL_CPU_TOPOLOGY_H

#include <cstdint>

namespace util {

/// Clase de nucleo por RENDIMIENTO, no por numero ni por nombre comercial.
enum class CoreClass {
    Fast, ///< los de mas rendimiento (P-core en la nomenclatura de Intel)
    Slow  ///< los eficientes (E-core).  En una maquina homogenea, vacio.
};

/**
 * @brief Procesadores logicos de la clase @p which, en mascara de bits.
 *
 * @return La mascara, o 0 si el sistema no sabe decirlo.  En una maquina
 *         HOMOGENEA, @c Fast son todos y @c Slow esta vacia: asi quien
 *         pregunta no tiene que distinguir los dos casos.
 */
uint64_t cpu_class_mask(CoreClass which);

/// @brief La maquina mezcla nucleos de rendimiento distinto?
bool cpu_is_hybrid();

/**
 * @brief Ata el hilo ACTUAL a los procesadores de @p mask.
 *
 * @param mask Los permitidos.  Con 0 no hace nada y devuelve false.
 * @return true si el sistema lo acepto.  Fallar no es grave -- se sigue
 *         corriendo donde toque --, pero quien mide tiene que SABERLO para no
 *         publicar como "en nucleos rapidos" algo que no lo fue.
 */
bool pin_current_thread(uint64_t mask);

/**
 * @brief Ata el PROCESO ENTERO a los procesadores de @p mask.
 *
 * Hace falta cuando el trabajo que se quiere confinar no corre en el hilo que
 * llama: el banco de MIPS, por ejemplo, ejecuta el programa en los hilos del
 * planificador de la VM, asi que atar el hilo que mide no ata nada.  Los hilos
 * que se creen despues lo heredan, y los que ya existen tambien se mueven.
 *
 * @param mask Los permitidos.  Con 0 no hace nada y devuelve false.
 * @return true si el sistema lo acepto.
 */
bool pin_process(uint64_t mask);

/**
 * @brief UN procesador de la clase @p which, o 0 si no hay.
 *
 * El de numero mas bajo.  Con SMT eso es un hermano de un nucleo fisico, y el
 * otro se queda libre: para una medida de un solo hilo es justo lo que se
 * quiere -- el nucleo entero para el, sin compartir la captacion --.
 */
uint64_t cpu_one_of_class(CoreClass which);

} // namespace util

#endif // VESTA_UTIL_CPU_TOPOLOGY_H
