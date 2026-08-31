/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/env_flags.h
 * @brief Los mandos del entorno: declarados en un sitio, leidos una vez,
 *        consultados desde cualquier parte.
 *
 * EL PROBLEMA.  Habia 245 llamadas a `getenv` repartidas por 73 ficheros, 167
 * mandos distintos, y nueve de ellos escondidos detras de ayudantes locales que
 * un barrido por `getenv` ni ve.  Eso costaba tres cosas a la vez:
 *
 *   - CADA sitio decidia por su cuenta que significa "puesto" (unos miran que
 *     exista, otros que no sea "0"), asi que el mismo valor podia activar un
 *     mando y no otro.
 *   - Consultar el entorno recorre su bloque entero.  En un pase que corre por
 *     funcion se paga por funcion, y ya salio en un perfil: `getenv` a un 1 %
 *     del tiempo de compilar para decidir algo que no cambia nunca.  Cada sitio
 *     se defendia con su propio `static const`, o se olvidaba.
 *   - Y lo que de verdad importa: NO SE PODIA SABER de que depende lo
 *     compilado.  Un mando que cambia el codigo emitido y no entra en la clave
 *     de la cache hace que se sirva un artefacto construido con OTRA
 *     configuracion.  No da error: da un binario que no corresponde al fuente.
 *
 * LA FORMA.  Una sola tabla (@c util/env_flags_table.h) de la que salen el
 * enum, los descriptores y las huellas.  Anadir un mando es anadir UNA linea;
 * no hay ningun sitio donde puedas anadirlo y olvidar la huella, porque la
 * huella se deriva de la misma linea.
 *
 * CADA MANDO DICE QUE CAMBIA (@c FlagScope), y de ahi sale si entra en una
 * huella.  Solo @c Emitted entra.  `VESTA_TIMES` no puede invalidar la cache
 * por pedir tiempos, y el reparto por hilos tampoco: que no cambie la salida no
 * es una suposicion, lo sostiene
 * `tests/vx/incremental_identity_test.py`.
 *
 * CUIDADO -- QUIEN NO PUEDE USAR ESTO.  Consultar el registro la primera vez
 * construye la tabla de valores, y esa tabla guarda cadenas: PIDE MEMORIA.  Por
 * eso no lo puede usar nada de lo que dependa una reserva -- el asignador de
 * memoria del host, sin ir mas lejos.  Si lo hace, la peticion reentra mientras
 * el estatico del registro se esta construyendo y el proceso se queda esperando
 * su guarda para siempre: cuelga ANTES de entrar en `main`.  Ya paso; ver el
 * comentario de @c allocator_active en `util/host_allocator.cpp`.  Esos sitios
 * leen el entorno a mano, y sus mandos siguen declarados aqui igual.
 *
 * Y CADA MANDO DICE A QUE PARTE AFECTA (@c FlagDomain), que es la granularidad
 * de la invalidacion: tocar algo del JIT no tiene por que tirar lo que se
 * guardo del optimizador.  Cuanto mas fino el dominio, menos hay que rehacer.
 * Es el mismo reparto que hace el fichero de hechos del ASA, que versiona y
 * valida POR REGISTRO en vez de con una huella global.
 */
#ifndef VESTA_UTIL_ENV_FLAGS_H
#define VESTA_UTIL_ENV_FLAGS_H

#include <cstdint>
#include <string>

namespace util {

/**
 * @brief Que cambia un mando al tocarlo.  Decide si entra en una huella.
 */
enum class FlagScope : uint8_t {
    Emitted,  ///< Cambia el artefacto compilado.  ENTRA en la huella.
    Speed,    ///< Cambia COMO se hace el trabajo, no el resultado.  No entra.
    Report,   ///< Solo imprime o mide.  No entra.
    Runtime,  ///< Cambia la ejecucion, no lo compilado.  No entra.
    Location, ///< Rutas: donde estan las cosas, no que son.  No entra.
    System,   ///< Del sistema operativo, no nuestro.  No entra.
};

/**
 * @brief A que parte del compilador afecta.  Es la unidad de invalidacion.
 */
enum class FlagDomain : uint8_t {
    None,      ///< Transversal, sin dominio propio.
    Optimizer, ///< Nucleo del optimizador de IR.
    Range,     ///< Rangos de valor.
    Alias,     ///< Desambiguacion de memoria y sus consumidores.
    Escape,    ///< Escape analysis y promocion de reservas.
    Loop,      ///< Transformaciones de bucle.
    Vector,    ///< Vectorizacion y memoria en bloque.
    Branch,    ///< SELECT contra salto.
    Asm,       ///< Ensamblador en linea.
    Comptime,  ///< Ejecucion al compilar.
    Scheduler, ///< Planificador de instrucciones.
    RegAlloc,  ///< Asignacion de registros.
    Codegen,   ///< Emision de codigo maquina.
    Jit,       ///< Compilacion al vuelo.
    Gc,        ///< Recoleccion de basura.
    Parallel,  ///< Reparto por hilos.
    Asa,       ///< Conocimiento del programa.
    Cache,     ///< Caches: donde estan y si se usan.
    Paths,     ///< Instalacion.
    Count_     ///< Cuantos hay.  No es un dominio.
};

/**
 * @brief Como se interpreta el valor, incluido SU DEFECTO.
 *
 * El defecto va aqui y no en el sitio que lo lee, porque en el codigo habia las
 * dos convenciones mezcladas -- unos mandos apagados salvo que los enciendas,
 * otros encendidos salvo que pongas "0" -- y desde fuera no habia forma de
 * saber cual era cual.  Quien lea la tabla tiene que poder decir que hace el
 * compilador sin abrir catorce ficheros.
 */
enum class FlagKind : uint8_t {
    Bool,   ///< APAGADO por defecto; lo enciende cualquier valor que no sea
            ///< "0" ni vacio.
    BoolOn, ///< ENCENDIDO por defecto; solo "0" lo apaga.  Son caminos que ya
            ///< son el normal y conservan la salida a mano para comparar.
    Int,    ///< Numero entero.
    Text,   ///< Cadena tal cual, leida una vez al arrancar.
    /**
     * Cadena que se RELEE en cada consulta.
     *
     * Rompe la premisa de todo lo demas -- leer una vez -- y por eso se declara
     * aparte en vez de dejarlo a que cada sitio se acuerde.  Existe porque el
     * compilador usa alguna variable como CANAL entre sus propias fases: la
     * escribe con `putenv` a mitad y la lee despues.  Con el valor cacheado del
     * arranque, la segunda fase leia lo de antes de escribir -- y eso no da
     * error, da 50 programas compilados de otra forma.
     *
     * Usar el entorno para hablar consigo mismo es el problema de fondo; esto
     * solo lo hace visible mientras siga ahi.
     */
    TextLive,
};

/**
 * @brief En que sistemas existe el mando.
 *
 * Los nuestros (@c VESTA_* / @c VX_* ) valen en todos: los definimos nosotros.
 * Los del sistema NO: `APPDATA`, `USERPROFILE`, `TEMP`, `PATHEXT` y
 * `SystemRoot` son de Windows, `HOME` es de POSIX, y solo `PATH` esta en los
 * dos.  Sin este campo la tabla afirmaba que todos existen en todas partes, y
 * quien la leyera para saber de que depende una compilacion se lo creeria.
 */
enum class FlagOs : uint8_t {
    Any,     ///< En cualquier sistema.
    Windows, ///< Solo Windows.
    Posix,   ///< Solo POSIX (Linux, macOS).
};

/// @brief Identificador de cada mando.  Sale de la tabla, no se escribe aqui.
enum class FlagId : uint16_t {
#define VESTA_ENV_FLAG(id, nombre, alcance, dominio, tipo, so) id,
#include "util/env_flags_table.h"
#undef VESTA_ENV_FLAG
    Count_ ///< Cuantos hay.  No es un mando.
};

/// @brief Lo declarado sobre un mando.
struct FlagInfo {
    const char *name;  ///< La variable de entorno.
    FlagScope scope;   ///< Que cambia.
    FlagDomain domain; ///< A que parte afecta.
    FlagKind kind;     ///< Como se lee su valor.
    FlagOs os;         ///< En que sistemas existe.
};

/// @brief @c true si @p os corresponde al sistema en el que corremos.
bool flag_applies_here(FlagOs os);

/// @brief Cuantos mandos hay declarados.
constexpr size_t kFlagCount = static_cast<size_t>(FlagId::Count_);

/// @brief Lo declarado sobre @p id.
const FlagInfo &flag_info(FlagId id);

/**
 * @brief Valor de un mando de tipo @c Bool.
 *
 * Un solo criterio para todos: puesto = existe, no esta vacio y no es "0".
 * Antes lo decidia cada sitio y no todos igual.
 */
bool flag_on(FlagId id);

/**
 * @brief Valor de un mando de tipo @c Int.
 * @param si_falta Lo que se devuelve si no esta puesto o no es un numero.
 */
long flag_int(FlagId id, long si_falta);

/**
 * @brief Valor de un mando de tipo @c Text.  Cadena vacia si no esta puesto.
 *
 * Referencia estable: la lectura se hizo una vez y el texto vive lo que el
 * proceso.
 */
const std::string &flag_text(FlagId id);

/// @brief @c true si el mando esta presente en el entorno, sea cual sea su
///        valor.  Para los pocos sitios donde "definida a 0" no es lo mismo
///        que "no definida".
bool flag_present(FlagId id);

/**
 * @brief Huella de los mandos @c Emitted de UN dominio.
 *
 * Esto es lo que entra en la clave de una cache: dos compilaciones con la misma
 * huella de dominio vieron los mismos mandos de esa parte.  Por dominio y no
 * global a proposito -- con una huella unica, pedir un volcado del JIT tiraria
 * lo que guardo el optimizador.
 *
 * Los mandos que NO son @c Emitted no entran: no cambian lo compilado, asi que
 * meterlos solo serviria para invalidar de mas.
 *
 * @return 0 si ningun mando @c Emitted de ese dominio esta puesto -- el caso
 *         normal, y a proposito: un usuario que no toca nada no arrastra un
 *         numero arbitrario en sus claves.
 */
uint64_t domain_fingerprint(FlagDomain domain);

/**
 * @brief Huella de TODOS los mandos @c Emitted, de cualquier dominio.
 *
 * Para quien cachea el artefacto final, que depende de todas las partes.  Los
 * caches por dominio deben usar @c domain_fingerprint, que invalida menos.
 */
uint64_t emitted_fingerprint();

/**
 * @brief Los mandos @c Emitted que estan puestos, para poder DECIRLO.
 *
 * Un artefacto compilado con mandos raros y otro sin ellos son cosas distintas,
 * y quien mire un informe tiene que poder ver cual tiene delante.  Sale
 * ordenado y estable, apto para comparar dos volcados.
 */
std::string emitted_flags_summary();

/**
 * @brief Relee el entorno.  Solo para los tests.
 *
 * En una ejecucion normal no se llama: los mandos se fijan al arrancar y no
 * cambian durante una compilacion -- de eso depende que leerlos cueste cero.
 * Un test que quiera comprobar que una huella reacciona a un mando necesita
 * poder cambiarlo, y esa es la unica razon de que esto exista.
 */
void reload_flags_for_testing();

} // namespace util

#endif // VESTA_UTIL_ENV_FLAGS_H
