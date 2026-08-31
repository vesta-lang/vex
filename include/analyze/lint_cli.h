/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analyze/lint_cli.h
 * @brief La orden `vesta lint` (ver @c analyze/lint_cli.cpp).
 */
#ifndef ANALYZE_LINT_CLI_H
#define ANALYZE_LINT_CLI_H

namespace analyze {
namespace lint_cli {

/**
 * @brief Punto de entrada del subcomando.
 *
 * @param argc Cuantos argumentos, con @c argv[0] = el ejecutable.
 * @param argv Los argumentos YA desplazados (sin la palabra `lint`).
 * @return 0 siempre que se pudiera mirar el fichero; 1 si no se pudo abrir o
 *         compilar; 2 si los argumentos no valen.  Un hallazgo NO es un error:
 *         devolver uno romperia la construccion por una sugerencia.
 */
int run(int argc, char **argv);

} // namespace lint_cli
} // namespace analyze

#endif // ANALYZE_LINT_CLI_H
