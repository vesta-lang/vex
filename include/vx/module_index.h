/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file module_index.h
 * @brief Que declara un modulo, indexado UNA vez.
 *
 * Buscar "la clase que se llama X" o "la global constante Y" se hacia
 * recorriendo `mod.decls` entero, y estaba escrito TREINTA Y TRES veces
 * repartido por el frontend: diez busquedas de clase, siete de global, seis de
 * funcion, cuatro de struct y el resto sueltas.  Cada una de esas lineas es un
 * recorrido del modulo, y varias corren por cada identificador del programa --
 * o sea O(n^2) en tamano del modulo.
 *
 * Medido con VTune sobre un modulo de 24.000 funciones, UNA de esas lineas
 * (la de globales constantes, en `lower_ident`) era el 1,8 % de las
 * instrucciones de todo el proceso.  No es que esa fuera especialmente mala:
 * es que se ejecuta mas veces que las otras.
 *
 * Aqui se recorre una vez y se pregunta por nombre.  Y ademas se deja de
 * repetir la misma busqueda escrita a mano en treinta y tres sitios, que era
 * el problema de fondo: un cambio en como se resuelve un nombre habia que
 * hacerlo treinta y tres veces o no hacerlo.
 *
 * REHACE EL INDICE SOLO si el modulo crecio.  No es una comodidad: la
 * monomorfizacion ANADE declaraciones a mitad de la compilacion, asi que un
 * indice construido antes se quedaria sin las instancias nuevas -- y eso no
 * daria un error, daria una busqueda que no encuentra lo que si existe.
 */
#ifndef VX_MODULE_INDEX_H
#define VX_MODULE_INDEX_H

#include "vx/ast.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace vx {

class ModuleIndex {
  public:
    /// Se construye vacio; el primer acceso lo llena.
    ModuleIndex() = default;

    /// La global `const` que se llame @p name, o nullptr.  Solo las que tienen
    /// inicializador: una `const` sin valor no se puede sustituir por el.
    ast::GlobalVarDecl *const_global(ast::ModuleNode &mod,
                                     const std::string &name);

    /// La clase que se llame @p name, o nullptr.
    ast::ClassDecl *class_decl(ast::ModuleNode &mod, const std::string &name);

    /// El struct que se llame @p name, o nullptr.
    ast::StructDecl *struct_decl(ast::ModuleNode &mod, const std::string &name);

    /// La funcion libre que se llame @p name, o nullptr.  Con sobrecargas se
    /// queda la PRIMERA: quien necesite elegir entre varias no puede
    /// resolverlo por nombre y esta pregunta no le sirve.
    ast::FunctionDecl *function(ast::ModuleNode &mod, const std::string &name);

  private:
    /// Rehace el indice si el modulo crecio desde la ultima vez.
    void ensure(ast::ModuleNode &mod);

    std::unordered_map<std::string, ast::GlobalVarDecl *> const_globals_;
    std::unordered_map<std::string, ast::ClassDecl *> classes_;
    std::unordered_map<std::string, ast::StructDecl *> structs_;
    std::unordered_map<std::string, ast::FunctionDecl *> functions_;

    /// Cuantas declaraciones tenia el modulo cuando se indexo.  Es la marca
    /// que detecta que la monomorfizacion metio mas.
    size_t indexed_decls_ = static_cast<size_t>(-1);
};

} // namespace vx

#endif // VX_MODULE_INDEX_H
