/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analyze/linter.h
 * @brief El linter: el primer CONSUMIDOR de verdad del ASA.
 *
 * NO ANALIZA NADA.  Pregunta al almacen de hechos y compara lo que el
 * compilador DEMOSTRO con lo que el programador DECLARo.  Un linter que
 * volviera a deducir lo que el ASA ya sabe no seria un linter mal hecho: seria
 * romper el primer invariante -- un hecho, un productor --, y las dos copias se
 * separarian sin que nadie lo notara.
 *
 *      productores --> [ FactStore ] --> linter --> hallazgos (VXW)
 *                                    \-> optimizador
 *                                    \-> LSP / MCP
 *
 * TRES COSAS QUE LA GENTE LLAMA "LINTER", Y AQUI SON DISTINTAS.  Lo que las
 * separa es una sola pregunta: puede la maquina decidir el arreglo?
 *
 *   - si, y es demostrablemente equivalente -> lo hace el formateador, SIN
 *     mensaje;
 *   - sabe la respuesta pero no puede firmarla por ti -> el compilador la
 *     sugiere con el valor puesto;
 *   - el arreglo exige una decision humana -> ESTO.
 *
 * Que la tercera sea la mas pequena es senal de que el lenguaje esta bien.
 *
 * POSTURA: callado salvo lo que es casi seguro.  Un linter que se equivoca se
 * apaga entero, y apagado no protege de nada.  Por eso cada familia solo habla
 * cuando el hecho en que se apoya esta DEMOSTRADO, y todo hallazgo lleva su
 * prueba (cuarto invariante).
 *
 * MULTI-IDIOMA POR CONSTRUCCION: un hallazgo es un CoDIGO del catalogo mas sus
 * argumentos como DATOS.  Nunca una frase.  Asi el mismo hallazgo sirve al
 * terminal, al LSP y al MCP sin traducirlo tres veces, y anadir un idioma no
 * toca ni una linea de aqui.
 */
#ifndef ANALYZE_LINTER_H
#define ANALYZE_LINTER_H

#include "analysis/asa/fact_store.h"
#include "analyze/fingerprint.h"
#include "vx/diagnostic.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace ir {
struct IrModule;
} // namespace ir

namespace analyze {

/**
 * @brief Lo que el linter necesita para decidir, y nada mas.
 *
 * Agrupado en una estructura y no en seis parametros sueltos porque cada
 * familia usa un subconjunto distinto: con parametros, anadir una familia que
 * necesite un dato nuevo obligaria a cambiar la firma y todos los sitios que
 * llaman.
 */
struct LintInput {
    const ir::IrModule &mod; ///< el codigo que de verdad va a existir.
    const analysis::asa::FactStore &facts; ///< lo que se sabe de el.
    /// Lo que el programador DECLARo, por nombre de funcion.  Vacio si el
    /// camino de compilacion no los recogio.
    const std::unordered_map<std::string, FunctionContracts> &contracts;
    /// Desde donde se pregunta: un hallazgo puede valer en un objetivo y no en
    /// otro, y el hecho ya lo dice.
    analysis::asa::Scope here;
    /// Fichero al que atribuir los hallazgos.  El IR sabe la LINEA de cada
    /// instruccion pero no de que fichero salio, y una posicion sin fichero no
    /// se puede pinchar en un editor.
    std::string file;
};

/**
 * @brief Una familia de hallazgos: un nombre estable y que hacer.
 *
 * Registrables una a una para que anadir la siguiente no toque el motor, igual
 * que los productores del ASA.  El nombre es el que se apaga en `vx.toml`.
 */
struct LintFamily {
    /// Estable, en INGLES y sin traducir: es lo que se escribe en `vx.toml`
    /// para apagarla.  Traducirlo haria que la configuracion de un proyecto
    /// dependiera del idioma de quien lo compile.
    const char *name = "?";
    /// Codigo del catalogo con su descripcion.  Lo que se LEE se traduce; lo
    /// que se ESCRIBE, no.  Sin esto, `vesta lint --help` era la unica parte
    /// del subcomando que solo existia en un idioma.
    const char *doc = "";
    void (*run)(const LintInput &, vx::Diagnostics &) = nullptr;
};

/// Da de alta una familia.  Idempotente por nombre.
///
/// @param name Nombre estable (ingles, no se traduce).
/// @param doc  Codigo del catalogo con su descripcion.
/// @param run  Que hace.
void register_lint_family(const char *name, const char *doc,
                          void (*run)(const LintInput &, vx::Diagnostics &));

/// Las familias dadas de alta, en orden de registro.
std::vector<const LintFamily *> registered_lint_families();

/**
 * @brief Corre las familias pedidas y deja los hallazgos en @p diags.
 *
 * @param in     Lo que hay que mirar.
 * @param diags  Donde se depositan los hallazgos (codigo + argumentos).
 * @param wanted Familias a correr.  Vacio = todas las que esten dadas de alta.
 * @return Cuantos hallazgos se emitieron.
 */
uint32_t run_lint(const LintInput &in, vx::Diagnostics &diags,
                  const std::vector<std::string> &wanted = {});

} // namespace analyze

#endif // ANALYZE_LINTER_H
