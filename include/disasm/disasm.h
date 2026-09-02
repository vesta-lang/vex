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
 * @file disasm.h
 * @brief Desensamblador de bytecode VestaVM (.velb).
 *
 * Expone una API independiente del REPL para desensamblar bytecode nativo de
 * VestaVM a partir de un archivo .velb o de un buffer de bytes en memoria.
 * Utiliza las tablas de decodificacion internas (decode_table_primary /
 * decode_table_extended) y NO depende de Capstone ni de ningun desensamblador
 * de codigo nativo externo.
 *
 * Uso tipico:
 * @code
 *   disasm::DisasmOptions opts;
 *   opts.stop_at_hlt = true;
 *   disasm::disasm_velb("build/main.velb", std::cout, opts);
 * @endcode
 */

#ifndef DISASM_H
#define DISASM_H

#include <cstdint>
#include <string>
#include <vector>
#include <ostream>

/**
 * @brief Espacio de nombres del modulo desensamblador de VestaVM.
 */
namespace disasm {

/**
 * @brief Opciones que controlan el comportamiento del desensamblador.
 */
struct DisasmOptions {
    uint64_t max_bytes =
        65536; ///< Numero maximo de bytes a desensamblar desde el entrypoint.
    bool show_hex =
        true; ///< Si es true, incluye los bytes hex de cada instruccion.
    bool stop_at_hlt = true; ///< Si es true, detiene el recorrido al encontrar
                             ///< HLT (0x00 0x03).
    bool use_color = true;   ///< Si es true, usa colores ANSI en la salida
                             ///< (requiere terminal con VT).
};

/**
 * @brief Un registro que la instruccion NOMBRA, con su papel.
 *
 * Es la misma informacion que ya se imprime como texto (`r3`, `f0`), pero
 * estructurada.  Existe porque hay analisis que necesitan saber que registros
 * toca una instruccion sin volver a leer el formato de cada opcode: la
 * dependencia entre dos instrucciones dentro de un paquete, por ejemplo, que
 * decide si se pueden reordenar.
 *
 * El desensamblador es el sitio donde vive esto porque es el unico que ya
 * conocia el formato de los 232 opcodes -- no se puede imprimir `r3` sin saber
 * de que campo sale -- y porque nadie puede anadir un opcode sin ensenarselo.
 * Una tabla aparte se quedaria vieja en silencio.
 */
struct RegOperand {
    uint8_t index; ///< 0..15
    bool floating; ///< banco ZMM (`f0`..`f15`) en vez de general
    bool dest;     ///< ocupa la posicion de destino de la instruccion
};


/**
 * @brief Resultado del desensamblado de una sola instruccion.
 */
struct DisasmResult {
    uint64_t address;     ///< Direccion virtual de la instruccion.
    size_t size;          ///< Tamano en bytes de la instruccion.
    std::string hex;      ///< Representacion hexadecimal de los bytes (vacio si
                          ///< show_hex=false).
    std::string mnemonic; ///< Nombre mnemotecnico de la instruccion (p.ej.
                          ///< "add", "mov").
    std::string
        operands; ///< Operandos formateados como texto (p.ej. "r0, r1 [q]").

    /**
     * @brief Los registros nombrados, en el mismo orden en que se imprimen.
     *
     * `dest` marca la posicion de destino, que es lo que el formato distingue.
     * Si el destino ademas se LEE depende de la operacion (`add` lo lee, `mov`
     * no), y eso no lo sabe el formato: quien analice dependencias debe tratar
     * el destino como leido salvo que sepa lo contrario, que es el lado seguro.
     */
    std::vector<RegOperand> regs;
};

/**
 * @brief Desensambla un archivo .velb y escribe el listado en @p out.
 *
 * Carga el binario en una VM temporal usando el Loader de VestaVM, localiza
 * el entrypoint desde el registro RIP del proceso cargado y recorre las
 * instrucciones hasta @c opts.max_bytes o un HLT si @c opts.stop_at_hlt.
 *
 * @param file Ruta al archivo .velb a desensamblar.
 * @param out  Flujo de salida donde se escribe el listado.
 * @param opts Opciones del desensamblador (valor por defecto si se omite).
 */
void disasm_velb(const std::string &file, std::ostream &out,
                 const DisasmOptions &opts = {});

/**
 * @brief Desensambla un buffer de bytes en memoria y devuelve la lista de
 * instrucciones.
 *
 * No requiere cargar ningun archivo; opera directamente sobre @p data.
 * Util para desensamblar fragmentos de bytecode en memoria o en tests.
 *
 * @param data      Puntero al inicio del buffer de bytes.
 * @param len       Numero de bytes validos en @p data.
 * @param base_addr Direccion virtual base que se asigna al primer byte de @p
 * data.
 * @param opts      Opciones del desensamblador.
 * @return Vector de DisasmResult, uno por instruccion decodificada.
 */
std::vector<DisasmResult> disasm_bytes(const uint8_t *data, size_t len,
                                       uint64_t base_addr,
                                       const DisasmOptions &opts = {});

/**
 * @brief Imprime una sola instruccion desensamblada en el formato estandar de
 * VestaVM.
 *
 * Formato de salida:
 * @code
 *   <address>  <hex bytes>  <mnemonic>  <operands>
 * @endcode
 *
 * @param out   Flujo de salida.
 * @param instr Instruccion a imprimir.
 * @param opts  Opciones (controla si se muestra el hex).
 */
void print_instruction(std::ostream &out, const DisasmResult &instr,
                       const DisasmOptions &opts = {});

} // namespace disasm

#endif // DISASM_H
