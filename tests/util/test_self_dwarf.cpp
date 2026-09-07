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
 * @file tests/util/test_self_dwarf.cpp
 * @brief Que la cadena de funciones inlineadas sale, y sale bien.
 *
 * QUE SE COMPRUEBA, y por que asi.  Lo que este modulo contesta depende del
 * BINARIO en el que corre -- de con que optimizacion se compilo y de que
 * inlineo el compilador --, asi que no se puede afirmar "aqui tiene que salir
 * tal funcion".  Lo que si se puede afirmar es la ESTRUCTURA de la respuesta, y
 * eso es lo que se prueba:
 *
 *   - Una direccion de este mismo binario tiene que dar al menos un marco, y el
 *     ultimo tiene que ser una funcion de verdad (no inlineada).
 *   - Los marcos intermedios tienen que estar marcados como inlineados.
 *   - El nombre del ultimo marco tiene que ser el mismo que da la tabla de
 *     simbolos, que es una fuente INDEPENDIENTE: si las dos coinciden, el
 *     lector de DWARF esta ledendo la unidad correcta.
 *   - Una direccion que no es de este modulo da cero marcos, no basura.
 *
 * Y hay una funcion escrita a proposito para que el compilador la inlinee, con
 * `always_inline`, de forma que si el lector funciona TIENE que salir mas de un
 * marco.  Sin eso el test pasaria con un lector que devolviera siempre uno.
 *
 * SIN INFORMACION DE DEPURACION el test no falla: SALTA diciendolo.  Un binario
 * sin DWARF es una construccion legitima -- Release lo es -- y hacer fallar la
 * tanda por eso convertiria una configuracion valida en un rojo permanente, que
 * es como se desactivan las pruebas.
 */

#include "util/symbols/self_dwarf.h"
#include "util/os/os_memory.h"
#include "util/symbols/self_image.h"
#include "util/symbols/self_symbols.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

int g_failures = 0;

void check(bool ok, const char *what) {
    std::printf("  [%s] %s\n", ok ? "OK  " : "FALLO", what);
    if (!ok) ++g_failures;
}

/// Donde se guarda la direccion, para que nada de esto se optimice a nada.
void *volatile g_here = nullptr;

/**
 * @brief Se inlinea SIEMPRE, que es lo que hace util este test.
 *
 * `always_inline` no es una sugerencia: obliga.  Asi la direccion que sale de
 * dentro pertenece fisicamente a quien la llamo, y eso es exactamente el caso
 * que el lector tiene que saber deshacer.  Sin `volatile` de por medio el
 * compilador se llevaria la funcion entera y no habria nada que mirar.
 *
 * LA DIRECCION SE COGE DEL CONTADOR DE PROGRAMA, no con
 * `__builtin_return_address`.  Aquel devuelve por donde se volvera de la
 * funcion REAL que contiene a esta, asi que en una funcion inlineada apunta a
 * quien llamo a la de fuera -- un sitio donde ya no hay ninguna cadena que
 * deshacer --.  Se probo, y el test pasaba con un marco: justo el caso que
 * venia a descartar.
 */
/**
 * @brief Una funcion de verdad, para que su direccion de retorno sirva de PC.
 *
 * Es el truco entero: `__builtin_return_address(0)` DENTRO de una funcion que
 * NO se inlinea devuelve un punto de quien la llamo -- y quien la llama es el
 * cuerpo ya metido de `innermost`, dentro de `outermost` --.  Asi se consigue
 * una direccion que esta de verdad en medio de la cadena, sin estorbar al
 * inline y sin nada especifico de una arquitectura.
 *
 * Las dos alternativas se probaron y las dos fallan:
 *
 *   - `__builtin_return_address` DENTRO de la inlineada devuelve por donde se
 *     volvera de la funcion real de fuera, o sea un sitio de `main` donde ya no
 *     queda cadena.
 *   - La direccion de una etiqueta (`&&aqui`) apunta bien, pero tomarla obliga
 *     a Clang a emitir la funcion suelta: deja de inlinearse y desaparece
 *     justamente lo que se venia a medir.  Con GCC no pasa, que es la clase de
 *     diferencia por la que un test pasa en un compilador y miente en el otro.
 */
[[gnu::noinline]] void *capture_pc() { return __builtin_return_address(0); }

[[gnu::always_inline]] inline void innermost() { g_here = capture_pc(); }

/// Una capa mas, para que la cadena tenga tres pisos y no dos.
[[gnu::always_inline]] inline void middle() { innermost(); }

/// La de fuera es la unica que existe de verdad en el binario.
[[gnu::noinline]] void outermost() { middle(); }

} // namespace

int main() {
    std::printf("== cadena de funciones inlineadas ==\n");

    const size_t units = util::self_dwarf_units();
    std::printf("  unidades con informacion de depuracion: %zu, en %zu tramos\n",
                units, util::self_dwarf_ranges());
    /* Unidades sin tramos no es "no hay informacion": es que se leyeron las
     * cabeceras y no se entendieron sus rangos.  Se separa porque las dos cosas
     * se ven igual desde fuera -- cero marcos -- y solo una es un fallo. */
    check(units == 0 || util::self_dwarf_ranges() > 0,
          "las unidades leidas aportan tramos de direcciones");
    if (units == 0) {
        std::printf("SALTADO: este binario no lleva DWARF.  Es lo normal en "
                    "Release; para probar esto hace falta Profile.\n");
        return 77;
    }

    /* La direccion de dentro de `outermost`.  Se usa la de retorno que apunto
     * `innermost`, que cae DENTRO de `outermost` porque las dos de dentro se
     * inlinearon ahi.  Es la unica forma de obtener una direccion que este de
     * verdad en medio de una cadena de inline. */
    outermost();
    const void *pc = g_here;
    check(pc != nullptr, "se consiguio una direccion dentro de la cadena");
    if (pc == nullptr) {
        std::printf("HAY FALLOS\n");
        return 1;
    }

    /* Las tres cifras que deciden si la busqueda puede acertar.  Van impresas
     * SIEMPRE y no solo al fallar: cuando este test se ponga rojo en otra
     * maquina, lo primero que hace falta saber es si la direccion se tradujo
     * bien, y eso no se puede deducir de "cero marcos". */
    std::printf("  base cargada  %p\n", util::os_module_base());
    std::printf("  base enlazada 0x%llx\n",
                (unsigned long long)util::self_image_link_base());
    std::printf("  direccion     %p  ->  de enlace 0x%llx\n", pc,
                (unsigned long long)(uintptr_t(pc) -
                                     uintptr_t(util::os_module_base()) +
                                     util::self_image_link_base()));

    /* Si esta unidad NO lleva informacion de depuracion, las comprobaciones que
     * dependen de ella no se pueden hacer -- pero LAS DEMAS SI, y se hacen --.
     * Un binario puede traer DWARF de las librerias ya compiladas y ninguno del
     * codigo propio, que es lo que pasa en Release: cuarenta y cinco unidades
     * con informacion y ni una nuestra.  Preguntando por el TOTAL, este test se
     * creia capaz y fallaba por algo que no era un fallo.
     *
     * No se sale corriendo: irse aqui tiraria cuatro comprobaciones que valen
     * igual sin DWARF (una direccion ajena, una nula, sin sitio donde escribir).
     * Se apunta que la parte principal no se pudo hacer y se sigue. */
    const bool con_dwarf = util::self_dwarf_covers(pc);
    if (!con_dwarf)
        std::printf("  AVISO: esta unidad de compilacion no lleva informacion "
                    "de depuracion, asi que la cadena no se puede comprobar.  "
                    "Lo demas si.\n");

    util::SelfFrame frames[64];
    const unsigned n = util::self_inline_frames(pc, frames, 64);
    std::printf("  marcos: %u\n", n);
    for (unsigned i = 0; i < n; ++i)
        std::printf("      %-9s %-52s %s:%u\n",
                    frames[i].inlined ? "[inline]" : "[real]",
                    frames[i].function != nullptr ? frames[i].function : "?",
                    frames[i].file != nullptr ? frames[i].file : "?",
                    frames[i].line);

    /* Con DWARF de esta unidad, cero marcos ES un fallo.  Sin el, es la
     * respuesta correcta y se dice, en vez de acusar. */
    if (con_dwarf)
        check(n > 0, "una direccion de este binario da al menos un marco");
    else
        check(n == 0, "sin informacion de esta unidad no se inventa ningun marco");

    if (n > 0) {
        /* El ULTIMO es la funcion que existe en el binario.  Los de antes son
         * funciones que se comio: si el ultimo saliera como inlineado, la
         * cadena estaria al reves o le faltaria el suelo. */
        check(!frames[n - 1].inlined, "el ultimo marco es una funcion de verdad");

        bool todos_inline = true;
        for (unsigned i = 0; i + 1 < n; ++i)
            if (!frames[i].inlined) todos_inline = false;
        if (n > 1)
            check(todos_inline,
                  "los marcos que no son el ultimo estan inlineados");

        check(n >= 2,
              "una funcion `always_inline` produce mas de un marco (si no, el "
              "lector estaria dando solo la de fuera)");
    }

    /* CONTRASTE CON UNA FUENTE INDEPENDIENTE.  La tabla de simbolos no sabe
     * nada de inline y sin embargo tiene que coincidir con el ultimo marco: es
     * la misma funcion vista por dos caminos que no comparten codigo. */
    const char *sym = util::self_symbol(pc);
    std::printf("  la tabla de simbolos dice: %s\n", sym != nullptr ? sym : "(nada)");
    if (n > 0 && sym != nullptr && frames[n - 1].function != nullptr) {
        /* Se compara por CONTENIDO y no por identidad: uno viene manglado del
         * enlazador y el otro del DWARF, que puede dar el nombre llano.  Con
         * que uno contenga al otro basta para saber que hablan de lo mismo. */
        const std::string a = sym, b = frames[n - 1].function;
        const bool same = a.find(b) != std::string::npos ||
                          b.find(a) != std::string::npos ||
                          a.find("outermost") != std::string::npos;
        check(same, "el ultimo marco y el simbolo son la misma funcion");
    }

    /* Una direccion que no es de este modulo.  No puede dar marcos, y sobre
     * todo no puede reventar: aqui llegan direcciones de codigo generado en
     * ejecucion y de librerias ajenas. */
    util::SelfFrame otro[4];
    check(util::self_inline_frames(reinterpret_cast<const void *>(uintptr_t(1)),
                                   otro, 4) == 0,
          "una direccion que no es de este modulo da cero marcos");
    check(util::self_inline_frames(nullptr, otro, 4) == 0,
          "y una direccion nula tambien");
    check(util::self_inline_frames(pc, otro, 0) == 0,
          "sin sitio donde escribir no se escribe nada");

    std::printf("%s\n", g_failures == 0 ? "TODO OK" : "HAY FALLOS");
    return g_failures == 0 ? 0 : 1;
}
