/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/comptime/compile_service.h
 * @brief "Compila este IR y damelo LISTO PARA EJECUTAR".
 *
 * EL PROBLEMA QUE RESUELVE.  Esa cadena -- emitir, ensamblar, cargar -- estaba
 * escrita a mano en DOS sitios: el precomputo del arranque (`compiler.cpp`) y
 * el camino de las macros (`main.cpp`).  Dos copias del mismo trabajo
 * significan dos sitios donde arreglar un fallo y dos que se separan solos; y
 * ya hay un tercer consumidor a la vista -- la ejecucion comptime PEREZOSA, que
 * necesita compilar UNA funcion en el momento en que se la llama, que es lo que
 * permitira quitar el tree-walker y con el la doble compilacion.
 *
 * QUE HACE, exactamente lo que hacian las dos copias y nada mas:
 *
 *      modulo IR --(emitir)--> texto .vel --(ensamblar)--> .velb --(cargar)-->
 * runtime
 *
 * QUE NO HACE, y es a proposito: no decide QUE compilar.  Recibe un modulo ya
 * formado.  Quien elige la particion es otro.
 *
 * DEUDA CONOCIDA, dicha y no escondida: el camino pasa por TEXTO.  El emisor
 * serializa el IR a una cadena que el ensamblador vuelve a lexar y parsear acto
 * seguido, y ademas el `.velb` va a disco para volver a leerse.  Se conserva
 * asi a proposito en esta primera version: el objetivo era que las dos copias
 * hagan lo MISMO, comprobable porque el `.velb` sale identico.  Quitar el paso
 * por texto es un cambio aparte -- una emision, dos destinos -- y con este
 * servicio en medio se hace en UN sitio en vez de en dos.
 */
#ifndef VESTA_VX_COMPTIME_COMPILE_SERVICE_H
#define VESTA_VX_COMPTIME_COMPILE_SERVICE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ir {
struct IrModule;
struct EmitOptions;
} // namespace ir

namespace vx {

class ComptimeRuntime;

/**
 * @enum CompileFailure
 * @brief En que fase se quedo sin bytecode.  DATO, no frase.
 *
 * El motivo se cuenta SIEMPRE: quedarse sin bytecode no es un caso raro que se
 * despache con un booleano.  Si una funcion comptime no se pudo compilar, quien
 * la iba a invocar tiene que poder DECIRLO -- callarse y caer a otra via es
 * exactamente como el tree-walker se quedo dentro tantos anyos.
 *
 * Va como codigo estable y no como texto porque el texto sale del CATALOGO
 * multi-idioma (@c vx/diag/diag_catalog.h): los modulos devuelven datos, el
 * formateo ocurre al imprimir y en el idioma activo.
 */
enum class CompileFailure : uint8_t {
    None,     ///< salio bien.
    Emit,     ///< el emisor no produjo codigo.
    Assemble, ///< el ensamblador rechazo el codigo.
    Read,     ///< el bytecode no se pudo leer o salio vacio.
    Load,     ///< el runtime comptime no acepto el bytecode.
};

/// @brief Codigo del catalogo que corresponde a @p f, o @c nullptr si @c None.
const char *compile_failure_code(CompileFailure f);

/**
 * @struct CompiledIr
 * @brief El bytecode de un modulo IR, o el dato de por que no lo hay.
 */
struct CompiledIr {
    std::vector<uint8_t> velb; ///< bytecode listo para cargar; vacio si fallo.
    bool ok = false;           ///< true si @c velb sirve.
    CompileFailure failure = CompileFailure::None; ///< en que fase se quedo.
    /// Sujeto del fallo (el nombre que se le paso al servicio).  Es el ARG
    /// `{0}` del mensaje del catalogo, no parte de una frase.
    std::string subject;
};

/**
 * @brief Emite @p mod y lo ensambla a bytecode.
 *
 * @param mod          Modulo IR ya formado y optimizado.
 * @param emit_opts    Opciones del emisor (nivel, depuracion, ...).
 * @param ir_section   Seccion @c @ir a incrustar en el `.velb`, o @c nullptr.
 *                     La necesita quien vaya a compilar en JIT lo cargado.
 * @param diag_name  Nombre para los diagnosticos y para el fichero temporal.
 *                     NO se abre nada con el: solo distingue un trabajo de
 * otro.
 * @return El bytecode, o el motivo de no tenerlo.
 */
CompiledIr compile_ir_to_bytecode(const ir::IrModule &mod,
                                  const ir::EmitOptions &emit_opts,
                                  const std::vector<uint8_t> *ir_section,
                                  const std::string &diag_name);

/**
 * @brief Lo mismo, y ademas lo deja CARGADO en un runtime nuevo.
 *
 * @param out Si se devuelve @c nullptr, aqui queda el motivo (ver
 *            @c CompiledIr).  Nunca se falla en silencio.
 * @return El runtime con el bytecode dentro, o @c nullptr.
 */
std::unique_ptr<ComptimeRuntime>
compile_ir_and_load(const ir::IrModule &mod, const ir::EmitOptions &emit_opts,
                    const std::vector<uint8_t> *ir_section,
                    const std::string &diag_name, CompiledIr *out = nullptr);

} // namespace vx

#endif // VESTA_VX_COMPTIME_COMPILE_SERVICE_H
