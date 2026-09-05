/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file module_index.cpp
 * @brief Implementacion del indice de declaraciones del modulo
 *        (module_index.h).
 */

#include "vx/module_index.h"

namespace vx {

void ModuleIndex::ensure(ast::ModuleNode &mod) {
    /* Solo se rehace si el modulo CRECIO.  La monomorfizacion anade
     * declaraciones a mitad de la compilacion, y un indice viejo no daria un
     * error: daria "no existe" sobre algo que si existe. */
    if (indexed_decls_ == mod.decls.size()) return;

    const_globals_.clear();
    classes_.clear();
    structs_.clear();
    functions_.clear();

    for (auto &decl : mod.decls) {
        if (!decl) continue;
        switch (decl->kind) {
        case ast::NodeKind::GlobalVarDecl: {
            auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
            /* Solo las CONSTANTES con valor: es lo que se puede sustituir por
             * su literal.  Una global mutable no, y una `const` sin
             * inicializador tampoco tiene nada que poner. */
            if (gv->is_const && gv->init) const_globals_.emplace(gv->name, gv);
            break;
        }
        case ast::NodeKind::ClassDecl: {
            auto *c = static_cast<ast::ClassDecl *>(decl.get());
            classes_.emplace(c->name, c);
            break;
        }
        case ast::NodeKind::StructDecl: {
            auto *s = static_cast<ast::StructDecl *>(decl.get());
            structs_.emplace(s->name, s);
            break;
        }
        case ast::NodeKind::FunctionDecl: {
            auto *f = static_cast<ast::FunctionDecl *>(decl.get());
            /* `emplace` NO pisa: con sobrecargas se queda la primera, que es
             * lo que hacia el recorrido lineal al que sustituye. */
            functions_.emplace(f->name, f);
            break;
        }
        default: break;
        }
    }
    indexed_decls_ = mod.decls.size();
}

ast::GlobalVarDecl *ModuleIndex::const_global(ast::ModuleNode &mod,
                                              const std::string &name) {
    ensure(mod);
    auto it = const_globals_.find(name);
    return it == const_globals_.end() ? nullptr : it->second;
}

ast::ClassDecl *ModuleIndex::class_decl(ast::ModuleNode &mod,
                                        const std::string &name) {
    ensure(mod);
    auto it = classes_.find(name);
    return it == classes_.end() ? nullptr : it->second;
}

ast::StructDecl *ModuleIndex::struct_decl(ast::ModuleNode &mod,
                                          const std::string &name) {
    ensure(mod);
    auto it = structs_.find(name);
    return it == structs_.end() ? nullptr : it->second;
}

ast::FunctionDecl *ModuleIndex::function(ast::ModuleNode &mod,
                                         const std::string &name) {
    ensure(mod);
    auto it = functions_.find(name);
    return it == functions_.end() ? nullptr : it->second;
}

} // namespace vx
