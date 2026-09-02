/**
 * @file tests/vx/target_keys_test.cpp
 * @brief Que el vocabulario de `@Target` sea UNO, y no dos que se parecen.
 *
 * Las claves por las que se puede preguntar (`os`, `arch`, `cpu`, `mode`,
 * `tier`) las necesitan DOS sitios: el evaluador de `@Target` en el parser y
 * el validador del `when:` de los contratos.  Cuando cada uno tenia la suya,
 * divergieron sin que nada fallara: a la lista de los contratos le faltaba
 * `tier`, asi que `@Target("tier:sin_libc")` valia y
 * `@complexity(O(n), when: tier:sin_libc)` se rechazaba por "clave
 * desconocida" -- la misma pregunta contestada de dos formas.
 *
 * Este test las ata: toda clave de la lista tiene que ser entendida por el
 * evaluador, y una inventada tiene que ser rechazada por los dos.  Si alguien
 * anade una clave a un lado y no al otro, esto se pone rojo.
 */

#include "vx/contract_when.h"
#include "vx/parser.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool cond, const std::string &etiqueta) {
    if (cond) {
        ++g_pass;
        std::printf("  PASS  %s\n", etiqueta.c_str());
    } else {
        ++g_fail;
        std::printf("  FAIL  %s\n", etiqueta.c_str());
    }
}

} // namespace

int main() {
    std::printf("=== target_keys: un solo vocabulario ===\n");

    /* El vocabulario esperado, ESCRITO.  Sin esto el test se encoge con la
     * lista: si alguien quita `tier`, el bucle de abajo deja de probarlo y
     * todo sigue verde -- justo la regresion que este fichero existe para
     * impedir.  Anadir o quitar una clave tiene que obligar a tocar AQUI, que
     * es donde se lee que se acordo. */
    const std::vector<std::string> esperadas = {"os", "arch", "cpu", "mode",
                                                "tier"};
    check(vx::cwhen::target_keys() == esperadas,
          "el vocabulario es exactamente {os, arch, cpu, mode, tier}");

    /* Toda clave de la lista tiene que ENTENDERSE.  Que se cumpla o no depende
     * del objetivo con el que se compile este test, y da igual: lo que se mide
     * es que el evaluador no la tome por una errata. */
    for (const std::string &clave : vx::cwhen::target_keys()) {
        const std::string atom = clave + ":loquesea";
        check(vx::target_expr_unknown_atom(atom).empty(),
              "'" + atom + "' se entiende (la clave existe)");
        /* Y el validador de los contratos tiene que decir lo mismo: es un
         * atomo de target, no un predicado de tipo ni un error. */
        check(vx::cwhen::only_target(atom),
              "'" + atom + "' es de target tambien para el `when:`");
    }

    /* Las variables con comparador de version van por otro camino del mismo
     * evaluador, y tambien tienen que entenderse. */
    for (const std::string &var : vx::cwhen::target_vars()) {
        const std::string atom = var + ">=1.0";
        check(vx::target_expr_unknown_atom(atom).empty(),
              "'" + atom + "' se entiende (variable de version)");
    }

    /* Y lo contrario: una clave que no existe se detecta, y se detecta EL
     * ATOMO, que es lo que el mensaje le ensena al usuario. */
    check(vx::target_expr_unknown_atom("so:windows") == "so:windows",
          "'so:windows' se senala entero como desconocido");
    check(!vx::cwhen::only_target("so:windows"),
          "'so:windows' tampoco cuela como `when:` de target");
    check(vx::target_expr_unknown_atom("widows") == "widows",
          "un atomo sin ':' tambien es desconocido");

    /* Una expresion compuesta: basta con que UN atomo no se entienda.  Y se
     * devuelve el primero, no el ultimo, que es el que hay que corregir. */
    check(vx::target_expr_unknown_atom("os:linux && so:windows") ==
              "so:windows",
          "en una expresion compuesta se senala el atomo malo");
    check(vx::target_expr_unknown_atom("os:linux || arch:x86_64").empty(),
          "una expresion entera de claves buenas no senala nada");

    /* Vacio = sin condicion, que es distinto de no entenderse. */
    check(vx::target_expr_unknown_atom("").empty(),
          "una expresion vacia no es una errata");

    std::printf("\n=== target_keys: %d OK, %d fallidos ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
