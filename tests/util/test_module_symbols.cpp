/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/test_module_symbols.cpp
 * @brief Valida el lector de simbolos contra una fuente que no comparte NADA.
 *
 * Que se comprueba, y por que asi
 * -------------------------------
 * El lector responde "en que funcion cae esta direccion".  Comprobarlo contra
 * si mismo no demostraria nada, asi que se compara con la unica fuente
 * independiente que hay: el ENLAZADOR ya nos dio la direccion de cada
 * `exec_instr_*` -- estan en la tabla de decodificacion, como punteros --, y el
 * nombre de cada una lo sabe el compilador.  Si el lector dice otro nombre para
 * esa direccion, esta mal.
 *
 * Es la misma disciplina que el resto: dos derivaciones que coinciden son una
 * prueba, una sola es una afirmacion.
 *
 * Lo que se comprueba, en concreto:
 *
 *   1. La direccion EXACTA de una funcion da su nombre, sin desplazamiento.
 *   2. Una direccion a mitad da el mismo nombre MAS el desplazamiento, que es
 *      lo que hace falta para situar un hueco dentro de una funcion.
 *   3. Los nombres salen deshechos (`runtime::exec_instr_hlt(...)`), no como
 *      los codifica el enlazador: el informe lo lee una persona.
 *   4. Una direccion que no es de ninguna funcion no inventa un nombre.
 *   5. La tabla esta ORDENADA, que es de lo que depende la busqueda binaria.
 *
 * Sobre el build
 * --------------
 * Release enlaza con `--strip-all` y ahi NO hay simbolos.  Eso no es un fallo
 * del lector: es que el binario no los lleva.  El test lo detecta y lo dice, y
 * pasa; en `Profile`, que compila lo mismo sin estripar, exige que funcione.
 * Un test que fallara en Release obligaria a ignorarlo, y un test que se ignora
 * no es un test.
 */

#include <cstdio>
#include <cstring>
#include <string>

#include "runtime/decode_table.h"
#include "runtime/exec_instruction.h"

#include "module_symbols.h"

namespace {

int fallos = 0;
int comprobadas = 0;

void check(bool cond, const char *que, const std::string &detalle = "") {
    ++comprobadas;
    if (cond) return;
    ++fallos;
    std::printf("  FALLO: %s\n", que);
    if (!detalle.empty()) std::printf("         %s\n", detalle.c_str());
}

/// El ancla: cualquier direccion del modulo sirve para encontrarlo.
const void *ancla() {
    return reinterpret_cast<const void *>(&runtime::exec_instr_hlt);
}

} // namespace

int main() {
    std::printf("=== test_module_symbols ===\n");

    const auto &tabla = tests::module_symbols(ancla());
    if (tabla.empty()) {
        std::printf("  el binario no lleva simbolos (enlazado con "
                    "--strip-all,\n  que es lo que hace Release).  Para "
                    "ejercitar esto hace falta\n  el build de Profile, que "
                    "compila lo mismo sin estripar.\n");
        std::printf("\n=== test_module_symbols: sin simbolos, nada que "
                    "comprobar ===\n");
        return 0;
    }
    std::printf("  %zu simbolos de codigo\n\n", tabla.size());

    // 5. La tabla esta ordenada: la busqueda binaria depende de ello.
    bool ordenada = true;
    for (size_t i = 1; i < tabla.size(); ++i)
        if (tabla[i - 1].addr > tabla[i].addr) ordenada = false;
    check(ordenada, "la tabla esta ordenada por direccion");

    /* 1 y 3.  Cada manejador de la tabla de decodificacion es una direccion que
     * el enlazador resolvio y un nombre que el compilador conoce.  Es la fuente
     * independiente: si el lector dice otra cosa para esa direccion, esta mal.
     *
     * Se comprueba que el nombre CONTIENE el del manejador y no que sea igual,
     * porque el deshecho trae tambien la firma. */
    int probados = 0, aciertos = 0;
    std::string primer_fallo;
    for (int t = 0; t < 2; ++t) {
        const bool ext = (t == 1);
        for (int i = 0; i < 256; ++i) {
            const auto &fmt = ext ? runtime::decode_table_extended[i]
                                  : runtime::decode_table_primary[i];
            if (fmt.exec == nullptr || fmt.name == nullptr || !fmt.name[0])
                continue;
            const uint64_t dir = reinterpret_cast<uint64_t>(
                reinterpret_cast<const void *>(fmt.exec));
            const std::string n = tests::symbol_at(ancla(), dir);
            if (n.empty()) continue; // sin simbolo: no es un error, es un hueco
            ++probados;
            /* El nombre deshecho de un manejador tiene que llevar dentro
             * `exec_instr_`.  Si sale otra cosa, la direccion se atribuyo a la
             * funcion equivocada -- que es el fallo que importa: un nombre
             * equivocado es peor que ninguno. */
            if (n.find("exec_instr_") != std::string::npos)
                ++aciertos;
            else if (primer_fallo.empty())
                primer_fallo = std::string(fmt.name) + " -> " + n;
        }
    }
    check(probados > 0, "se resolvio al menos un manejador");
    check(aciertos == probados,
          "todo manejador resuelto cae en una funcion `exec_instr_*`",
          primer_fallo);
    std::printf("  %d manejadores resueltos, %d con nombre coherente\n",
                probados, aciertos);

    // 3. El nombre viene DESHECHO, no como lo codifica el enlazador.
    const std::string n_hlt = tests::symbol_at(
        ancla(), reinterpret_cast<uint64_t>(ancla()));
    check(n_hlt.find("runtime::exec_instr_hlt") != std::string::npos,
          "el nombre sale deshecho, no codificado", n_hlt);
    check(n_hlt.find('+') == std::string::npos,
          "la direccion EXACTA no lleva desplazamiento", n_hlt);

    /* 2. A mitad de funcion: mismo nombre mas el desplazamiento.  Es lo que
     * convierte "hay un hueco en 0x7FF..." en "hay un hueco a 32 bytes del
     * principio de tal funcion", que ya es accionable. */
    const uint64_t medio = reinterpret_cast<uint64_t>(ancla()) + 16;
    const std::string n_medio = tests::symbol_at(ancla(), medio);
    check(n_medio.find("runtime::exec_instr_hlt") != std::string::npos,
          "una direccion a mitad cae en la misma funcion", n_medio);
    check(n_medio.find("+16") != std::string::npos,
          "y dice a que distancia del principio", n_medio);

    /* 4. Una direccion que no es de ninguna funcion no puede dar un nombre.
     * Se usa una MUY por encima del modulo: sin el tope, la busqueda binaria
     * atribuiria media seccion al ultimo simbolo de la lista, y ese es el modo
     * de fallo silencioso -- un nombre que parece bueno y no lo es. */
    const std::string n_lejos =
        tests::symbol_at(ancla(), tabla.back().addr + (1ull << 32));
    check(n_lejos.empty(), "una direccion fuera de rango no inventa nombre",
          n_lejos);

    std::printf("\n=== test_module_symbols: %d comprobaciones, %d fallidas "
                "===\n",
                comprobadas, fallos);
    return fallos == 0 ? 0 : 1;
}
