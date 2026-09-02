/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/lowering_internal.h
 * @brief Lo que las unidades del lowering comparten entre si, y solo entre si.
 *
 * El lowering vivia en UN fichero de mas de cuarenta mil lineas.  Al repartirlo
 * en varias unidades, los helpers que estaban marcados @c static -- visibles
 * solo dentro de aquel fichero -- dejan de alcanzarse desde las demas.  Este
 * cabecero es donde se declaran esos, y NADA MAS: no es la interfaz del
 * lowering (esa es @c vx/lowering.h, la clase), es su cocina.
 *
 * Regla para lo que entra aqui: si algo lo necesita alguien de FUERA del
 * lowering, no es de aqui -- que suba a la interfaz publica.  Si solo lo
 * necesita una unidad, tampoco: que se quede @c static en la suya.
 */

#ifndef VESTA_VX_LOWERING_INTERNAL_H
#define VESTA_VX_LOWERING_INTERNAL_H

#include "ir/ssa_ir.h"
#include "vx/ast.h"
#include "vx/type_checker.h"

#include <cstdint>
#include <cstring> // memcpy: los bits de un flotante
#include <string>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace vx {

/**
 * @brief Deja el nombre de una clase en los datos del modulo y devuelve su
 *        direccion, reutilizandola si ya estaba.
 *
 * La reflexion por nombre (@c forName, @c getClass) necesita el nombre como
 * bytes en memoria del programa, no como cadena del compilador.
 */
uint64_t intern_class_name(ir::IrModule &mod, const std::string &name);

/**
 * @brief Ensambla un bloque @c asm a bytes.
 *
 * Vive con el resto del mini-ensamblador (@c lowering/asm.cpp) y es el unico de
 * su familia que sale de ahi: los bloques @c asm a nivel de DATOS los ensambla
 * @c Lowering::run al montar el modulo, no @c lower_asm.
 *
 * @p sym_refs (opcional) recibe las referencias a simbolos externos -- un
 * @c call o @c jmp a una funcion de Vesta -- para que el driver las resuelva
 * despues; un salto a una etiqueta local lo cierra el propio ensamblador.
 * @return @c false y deja el motivo en @p err si el bloque no ensambla.
 */
bool asmblk_assemble(
    const std::string &body, uint8_t bits, std::vector<uint8_t> &out,
    std::string &err,
    std::vector<ir::IrModule::StaticDataMeta::SymRef> *sym_refs = nullptr);

/**
 * @brief Direccion de un campo: @p base mas el desplazamiento, como valor.
 *
 * Lo usan tanto la bajada de la POO como la de expresiones, asi que no puede
 * quedarse dentro de ninguna de las dos.
 */
ir::IrValueId emit_field_addr(ir::IrFunction *fn, ir::IrBlockId block,
                              ir::IrValueId base, uint32_t offset,
                              uint32_t line);

/**
 * @brief Reserva el hueco donde se recuerda la clase ya resuelta por su nombre.
 *
 * Ocho ceros -- el hueco -- seguidos de un centinela y del nombre.  El
 * centinela es lo que lo distingue de @c intern_class_name, que interna el
 * mismo nombre para otra cosa: sin el, las dos entradas se fundirian en una.
 */
uint64_t intern_class_cache_slot(ir::IrModule &mod, const std::string &name);

/**
 * @brief Reparte la funcion de arranque del modulo en tandas mas pequenas.
 *
 * @c __module_init acababa siendo una funcion enorme -- una tirada por clase y
 * por aspecto --, y se puede partir porque sus bloques forman una cadena lineal
 * que NO se pasa valores: lo que una clase necesita de otra viaja por estado
 * global.  Es conservador a proposito: cualquier forma que no encaje -- un PHI,
 * una rama, un valor que cruce y no sea una reserva de pila -- deja la funcion
 * como estaba, porque partir mal aqui no da un programa mas lento, da uno que
 * registra mal sus clases.
 *
 * @param init La funcion recien generada; queda reescrita a llamadas.
 * @param out  Modulo donde se anaden las tandas.
 * @return @c true si se partio; @c false si se dejo intacta.
 */
bool split_module_init_into_chunks(ir::IrFunction &init, ir::IrModule &out);

/**
 * @brief Recoge los nombres a los que un sub-arbol ASIGNA.
 *
 * Lo necesita quien construye un bucle: una variable que el cuerpo modifica
 * tiene que entrar por una phi en la cabecera, o el bucle leeria siempre el
 * valor de la primera vuelta.  Es deliberadamente generoso -- puede nombrar
 * cosas que no son del ambito --; filtrar es cosa de quien pregunta, que si
 * sabe que hay declarado justo antes del bucle.
 *
 * @param n   Nodo a inspeccionar; @c nullptr no aporta nada.
 * @param out Conjunto al que se anaden los nombres.
 */
void collect_assigned_vars(const ast::Node *n, std::set<std::string> &out);

/**
 * @name Estado del bajado de macros, por hilo
 *
 * Una macro puede llamar a un ayudante que todavia no se ha bajado, y hay que
 * bajarlo aunque nadie mas lo llame.  @c macro_force_lower recoge esos nombres
 * para que el recorrido de arriba los emita; @c macro_visiting es la guarda que
 * impide que una macro que se llama a si misma -- directa o indirectamente --
 * se persiga sin fin.  Nulo significa "no estamos dentro de una macro", que es
 * el caso normal.
 *
 * Es estado POR HILO porque el compilador baja varios modulos a la vez, y va en
 * las ranuras propias del proyecto (@c util/thread_slot.h), NO en
 * @c thread_local.  Se intento lo segundo y rompio el compilador: declaradas
 * @c extern @c thread_local, otra unidad las alcanzaba por la capa emulada de
 * este toolchain y no leia el nulo con el que nacen sino memoria sin sentido --
 * el @c if daba verdadero y se desreferenciaba --, reventando al compilar
 * programas que ni siquiera tienen macros.  Aquella cabecera ya contaba esta
 * misma historia: la via emulada les habia costado antes un cuelgue.
 * @{
 */
std::unordered_set<std::string> *macro_force_lower();
void set_macro_force_lower(std::unordered_set<std::string> *p);
std::unordered_set<std::string> *macro_visiting();
void set_macro_visiting(std::unordered_set<std::string> *p);
/** @} */

/**
 * @name Si el cuerpo de una macro se puede bajar, y que se le pasa
 *
 * Una macro se ejecuta AL COMPILAR, asi que su cuerpo no puede hacer cualquier
 * cosa: hay formas que no tienen sentido ahi -- o que no se sabrian ejecutar --
 * y hay que rechazarlas DICIENDO cual es, no con un "no se puede".  De ahi que
 * estas devuelvan el motivo y no un booleano: la cadena vacia es el si.
 *
 * Las dos de `forwards_expr_capture` responden otra cosa: si el cuerpo se
 * limita a pasar una captura de expresion a otra macro.  Eso permite encadenar
 * macros sin evaluar la expresion por el camino, que es lo que la haria
 * ejecutarse antes de tiempo.
 * @{
 */
std::string macro_body_unsupported_reason(const TypeChecker &tc,
                                          const ast::Stmt *s);
std::string macro_body_unsupported_reason_expr(const TypeChecker &tc,
                                               const ast::Expr *e);
bool macro_body_forwards_expr_capture(const TypeChecker &tc,
                                      const ast::Stmt *s);
bool macro_body_forwards_expr_capture_expr(const TypeChecker &tc,
                                           const ast::Expr *e);

/**
 * @brief Marca en el arbol que ciertos identificadores son parametros de la
 *        macro, y de que tipo.
 *
 * El cuerpo de una macro se clona en cada uso, y al clonarlo sus parametros
 * dejan de tener quien los declare: sin esta anotacion, quien lo baja despues
 * no sabria de que tipo son.
 */
void annotate_macro_param_idents(
    ast::Stmt *s, const std::unordered_map<std::string, Type> &param_types);
/** @} */

/**
 * @brief La biblioteca nativa de entrada y salida de la maquina virtual.
 *
 * Se comparte porque los builtins de impresion la nombran en varios sitios y el
 * nombre tiene que ser EL MISMO en todos: es la clave con la que se registra la
 * importacion nativa, asi que dos escrituras distintas darian dos
 * importaciones.
 */
extern const std::string kVestaIoLib;

/**
 * @brief La biblioteca nativa que instrumenta la entrada y salida de funciones.
 *
 * Igual que @ref kVestaIoLib: el nombre lleva el subdirectorio bajo
 * `stdlib/native/` porque el cargador resuelve la biblioteca por ruta relativa
 * al ejecutable, y ese nombre ES la clave de la importacion.
 */
extern const std::string kVestaTraceLib;

/**
 * @brief @c true si @p fn_name es una funcion que se invento el compilador.
 *
 * Sirve para no ponerles traza: quien la pide quiere ver SU programa.  La
 * lista de prefijos vive en un solo sitio porque estaba en tres y en ninguno
 * completa.
 */
bool is_compiler_generated_fn(const std::string &fn_name);

/**
 * @brief Lee @p n bytes desde @p pos como un entero, el de menor peso primero.
 *
 * Sirve para meter en UNA instruccion lo que si no serian ocho: al copiar una
 * cadena conocida al compilar, sus bytes se agrupan de ocho en ocho y cada
 * grupo se escribe de una vez.  El orden -- el primer byte en la parte baja --
 * es el de la maquina, asi que lo escrito coincide con lo leido sin darle la
 * vuelta a nada.
 *
 * Estaba escrito cuatro veces, y no toca nada del bajador: es aritmetica sobre
 * un vector de bytes, y por eso vive aqui como funcion libre y no como metodo.
 *
 * @param data Los bytes.
 * @param pos  Desde donde.
 * @param n    Cuantos, de 1 a 8.
 * @return El entero formado por esos bytes.
 */
inline uint64_t pack_le(const std::vector<uint8_t> &data, uint64_t pos, int n) {
    uint64_t v = 0;
    for (int k = 0; k < n; ++k)
        v |= static_cast<uint64_t>(data[pos + k]) << (8 * k);
    return v;
}

/**
 * @brief Los BITS de un `double` con el ancho del tipo destino.
 *
 * El intermedio lleva los flotantes como bits, asi que una constante de coma
 * flotante se convierte una sola vez y de una sola forma.  `f32` guarda cuatro
 * bytes y `f64` ocho: hacerlo a ojo en cada sitio es como se separan dos
 * caminos que deberian dar lo mismo.
 *
 * Estaba `static` en el bajado de MODULO, que es quien inicializa los datos
 * estaticos.  Lo necesita tambien quien inlina una constante global en cada
 * uso, y por eso vive aqui: son la misma conversion.
 *
 * @param d Valor.
 * @param is_f32 Si el destino es de 32 bits.
 * @return Los bits, en los 32 o 64 de abajo segun el ancho.
 */
inline uint64_t float_bits_from_double(double d, bool is_f32) {
    uint64_t bits = 0;
    if (is_f32) {
        const float f = static_cast<float>(d);
        uint32_t u32 = 0;
        std::memcpy(&u32, &f, sizeof(u32));
        bits = u32;
    } else {
        std::memcpy(&bits, &d, sizeof(d));
    }
    return bits;
}

} // namespace vx

#endif // VESTA_VX_LOWERING_INTERNAL_H
