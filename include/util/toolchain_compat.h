/**
 * @file toolchain_compat.h
 * @brief Lo que un compilador trae y otro no, en UN sitio.
 *
 * Este arbol se construye con GCC y con Clang, y Clang con las DOS ABI de
 * Windows.  La de MSVC es la que muerde: ahi no hay cabeceras POSIX, asi que
 * faltan nombres que en MinGW vienen dados y que el codigo portable usa sin
 * pensar -- @c ssize_t y @c getpid son los dos que aparecieron.
 *
 * Va aparte y no repartido por los ficheros que lo necesitan por la misma
 * razon que el resto del proyecto: un remiendo por sitio son N criterios en
 * cuanto alguien toca uno.  Aqui el hecho "en esta plataforma esto no existe"
 * se declara UNA vez.
 *
 * Lo que este fichero NO hace, a proposito: no define @c NOMINMAX ni
 * @c WIN32_LEAN_AND_MEAN.  Esos dos tienen que estar puestos ANTES de que
 * nadie incluya @c windows.h, y una cabecera no puede garantizar el orden --
 * el que llega tarde no hace nada y no avisa.  Se ponen en la linea de
 * ordenes, en @c CMakeLists.txt, que es el unico sitio que los ve todos.
 */

#ifndef VESTA_UTIL_TOOLCHAIN_COMPAT_H
#define VESTA_UTIL_TOOLCHAIN_COMPAT_H

#if defined(_MSC_VER)

#include <BaseTsd.h> // SSIZE_T
#include <process.h> // _getpid

/* `ssize_t` es de POSIX y el CRT de MSVC no lo trae; su equivalente se llama
 * `SSIZE_T` y esta en <BaseTsd.h>.  El guardia `_SSIZE_T_DEFINED` es el que usa
 * el propio CRT, asi que si otra cabecera se adelanta, aqui no se duplica. */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#endif

/**
 * @brief PID del proceso actual.
 *
 * En el CRT de MSVC la funcion se llama @c _getpid.  Se envuelve en una funcion
 * en linea y no en una macro para que `::getpid()` -- que es como esta escrito
 * en varios sitios -- siga resolviendo, y para que no se le cambie el nombre a
 * ningun identificador ajeno que se llame igual.
 *
 * @return Identificador del proceso.
 */
inline int getpid() { return ::_getpid(); }

#endif // _MSC_VER

#endif // VESTA_UTIL_TOOLCHAIN_COMPAT_H
