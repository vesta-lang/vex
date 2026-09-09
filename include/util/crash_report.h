/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/crash_report.h
 * @brief Que hace el PROCESO cuando se cae: contarlo entero antes de morir.
 *
 * No es el manejador de fallos del programa Vesta -- ese vive en
 * `runtime/exception_runtime.h`, convierte un acceso invalido en una excepcion
 * que el programa del usuario puede capturar, y se aparta expresamente cuando
 * no hay proceso Vesta corriendo.  Mientras se COMPILA no lo hay, asi que hasta
 * ahora una caida del compilador moria como decidiera el sistema: sin
 * diagnostico, sin decir que fichero estaba compilando, y con los bufers
 * perdidos -- medido, cero bytes de salida --.
 *
 * Eso choca con la regla del proyecto: nada se calla, NI AL COMPILAR.
 *
 * Lo que se cuenta al caer:
 *   1. La causa (senal o codigo de excepcion) y la direccion que la provoco.
 *   2. QUE se estaba haciendo, si alguien lo dejo dicho (@ref CrashContext).
 *   3. Los registros del procesador en el momento exacto.
 *   4. El desensamblado alrededor de la instruccion que fallo, con ella
 *      senalada.
 *   5. La pila, y cada marco con su funcion -- y su fichero y linea cuando la
 *      construccion lleva informacion de depuracion.
 *
 * @par Por que se puede
 * Las piezas ya estaban sueltas: Capstone para desensamblar, y el resolutor de
 * la libreria del asignador (`util/symbols/self_resolver.h`) para poner nombre
 * a una direccion -- con DWARF si lo hay, con la tabla de simbolos si no, y con
 * `.pdata`/`st_size` en una construccion despojada --.  Aqui solo se juntan.
 */

#ifndef VESTA_UTIL_CRASH_REPORT_H
#define VESTA_UTIL_CRASH_REPORT_H

namespace util {

/**
 * @brief Instala el informe de caidas del proceso.
 *
 * Idempotente: llamarlo dos veces no instala dos.  Se llama lo antes posible en
 * @c main, porque una caida antes de esto no se cuenta.
 *
 * En Windows engancha el filtro de excepciones no capturadas y el manejador de
 * terminacion de C++; en Linux, las senales de fallo del procesador
 * (@c SIGSEGV, @c SIGBUS, @c SIGFPE, @c SIGILL, @c SIGABRT) con pila propia,
 * que es lo unico que permite informar de un desbordamiento de pila.
 */
void install_crash_reporter() noexcept;

/**
 * @brief Provoca una caida A PROPOSITO si `VESTA_CRASH_TEST` lo pide.
 *
 * Existe porque un informe de caidas que solo se ve cuando algo se rompe de
 * verdad no se puede comprobar, y lo que no se comprueba se estropea sin que
 * nadie lo note.  Se llama justo despues de instalar el informe.
 *
 * Sin la variable puesta no hace absolutamente nada -- una consulta a una tabla
 * y vuelve --, asi que no cuesta.
 */
void crash_test_if_asked() noexcept;

/**
 * @brief Cuenta la caida ENTERA para una excepcion que ya tiene otro manejador.
 *
 * El informe se instala como filtro de lo NO capturado, asi que una excepcion
 * que un manejador anterior se queda no llega nunca hasta el.  Eso ya escondio
 * un fallo: una corrupcion de monton (`0xC0000374`) la recogia el manejador de
 * fallos del procesador de la VM, que la desviaba a su punto de rescate, y del
 * suceso quedaba UNA LINEA -- codigo y direccion -- mientras que el informe que
 * si salia era el del salto, cuya pila habla del salto y no de la corrupcion.
 *
 * Esto le da a ese manejador la forma de contarlo antes de decidir que hace.
 *
 * @param platform_exception En Windows, el @c EXCEPTION_POINTERS* que recibe el
 *        manejador.  Nulo no hace nada.  Fuera de Windows todavia no hace nada:
 *        alli el equivalente es el manejador de senal, que ya es el nuestro.
 *
 * @note Informa UNA sola vez por proceso, igual que el filtro: una segunda
 *       caida durante el propio informe no vuelve a entrar.
 */
void crash_report_for(void *platform_exception) noexcept;

/**
 * @brief Deja dicho QUE se esta haciendo, para que el informe lo cuente.
 *
 * Una traza de pila dice donde reviento; esto dice sobre QUE.  "compilando
 * std/memory/x86_64.vx" ahorra mas tiempo que quince marcos de plantillas.
 *
 * No copia nada ni reserva memoria: guarda los punteros tal cual, asi que las
 * cadenas tienen que sobrevivir al ambito.  Es a proposito -- lo que se llama
 * desde un manejador de senal no puede reservar --, y por eso lo normal es
 * pasar literales o cadenas que ya viven en el arbol de compilacion.
 *
 * @param stage  CODIGO del catalogo con la fase (`crash.stage.*`), no un texto:
 *               el informe se escribe en el idioma de quien lo lee, y eso solo
 *               se puede decidir al imprimirlo.
 * @param detail De que, o nulo: la ruta del fichero, el nombre de la funcion.
 *               Va tal cual -- un nombre propio no se traduce.
 */
void crash_context_set(const char *stage, const char *detail) noexcept;

/**
 * @brief Deja el contexto y lo restaura al salir del ambito.
 *
 * Anidar sin dejar rastro: al deshacerse vuelve a poner el que hubiera, asi que
 * el informe siempre cuenta el mas interior de los que siguen vigentes.
 */
class CrashContext {
  public:
    CrashContext(const char *stage, const char *detail) noexcept;
    ~CrashContext() noexcept;
    CrashContext(const CrashContext &) = delete;
    CrashContext &operator=(const CrashContext &) = delete;

  private:
    const char *prev_stage_;
    const char *prev_detail_;
};

} // namespace util

#endif // VESTA_UTIL_CRASH_REPORT_H
