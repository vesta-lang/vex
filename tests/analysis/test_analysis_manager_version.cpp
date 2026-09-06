/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_analysis_manager_version.cpp
 * @brief Que un analisis cacheado NO se pueda entregar si habla de un estado
 *        que ya no existe.
 *
 * Lo que se comprueba no es que el cache funcione -- eso ya se sabia --, sino
 * que la caducidad sea IMPOSIBLE en vez de depender de que alguien se acuerde
 * de invalidar.  Esa disciplina ya fallaba: prestar al eliminador de codigo
 * muerto unos hechos que el gestor daba por buenos terminaba en fallo de
 * segmentacion en la mitad de las ejecuciones, porque @c IrFacts guarda
 * PUNTEROS a instrucciones y el IR se habia modificado por medio.
 *
 * Por eso el test mira la version, no el contenido: si el sello no se
 * comprueba, el resultado viejo se entrega y el contador de calculos no sube.
 */
#include "analysis/manager/analysis_manager.h"

#include "util/name_pool.h"

#include <cstdio>
#include <string>

namespace {

/// Analisis de mentira: solo necesita una identidad.
struct AnalisisFalso {
    static char ID;
};
char AnalisisFalso::ID = 0;

/// Resultado de mentira: guarda de que estado hablaba, para poder comprobarlo.
struct ResultadoFalso {
    uint64_t estado_visto = 0;
};

int fallos = 0;

void comprueba(bool cond, const char *que) {
    if (cond) {
        std::printf("  ok   %s\n", que);
    } else {
        std::printf("  FALLA %s\n", que);
        ++fallos;
    }
}

} // namespace

int main() {
    std::printf("[gestor de analisis] la caducidad tiene que ser imposible\n");

    analysis::AnalysisManager am;
    /* La unidad se nombra con el puntero internado; quien lo llama de verdad
     * usa `IrFunction::name_key()`. */
    const std::string *const u_fn = util::intern_name(std::string("fn"));
    const std::string *const u_otra = util::intern_name(std::string("otra"));
    long calculos = 0;
    uint64_t version = 1; // el "estado" de la unidad

    auto pedir = [&]() -> const ResultadoFalso & {
        return am.get_or_compute_v<AnalisisFalso, ResultadoFalso>(
            u_fn, version, [&] {
                ++calculos;
                return ResultadoFalso{version};
            });
    };

    // 1. La primera vez se calcula.
    const ResultadoFalso &a = pedir();
    comprueba(calculos == 1, "la primera peticion calcula");
    comprueba(a.estado_visto == 1, "el resultado habla del estado 1");

    // 2. Sin cambios, se reusa: para eso esta el cache.
    pedir();
    pedir();
    comprueba(calculos == 1,
              "sin cambios NO se recalcula (3 peticiones, 1 calculo)");

    // 3. La unidad cambia.  Nadie invalida NADA -- ese es el punto: la
    //    disciplina de acordarse es justo lo que no queremos que haga falta.
    version = 2;
    const ResultadoFalso &b = pedir();
    comprueba(calculos == 2,
              "tras cambiar la unidad SI se recalcula, sin invalidar a mano");
    comprueba(b.estado_visto == 2, "el resultado nuevo habla del estado 2");

    // 4. Y el nuevo tambien se reusa mientras el estado no vuelva a moverse.
    pedir();
    comprueba(calculos == 2, "el resultado nuevo se cachea igual");

    // 5. Volver a un estado anterior tampoco resucita lo viejo: lo que importa
    //    es que el sello COINCIDA, no que sea mayor.  (Los identificadores se
    //    reutilizan; suponer monotonia seria otra forma de confiar.)
    version = 1;
    pedir();
    comprueba(calculos == 3,
              "un estado distinto recalcula aunque sea uno anterior");

    // 6. Sin versionar (0) sigue comportandose como un cache normal: las
    //    unidades que no son funciones IR no tienen por que inventarse un
    //    contador.
    long calculos_sv = 0;
    analysis::AnalysisManager am2;
    for (int i = 0; i < 3; ++i)
        am2.get_or_compute_v<AnalisisFalso, ResultadoFalso>(u_otra, 0, [&] {
            ++calculos_sv;
            return ResultadoFalso{0};
        });
    comprueba(calculos_sv == 1,
              "sin versionar se comporta como un cache normal");

    std::printf(fallos == 0 ? "[gestor de analisis] TODO OK\n"
                            : "[gestor de analisis] %d FALLOS\n",
                fallos);
    return fallos == 0 ? 0 : 1;
}
