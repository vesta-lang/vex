/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file comptime_collect.cpp
 * @brief Implementacion del recolector del conjunto comptime (P1 fase 1).
 *
 * Analisis puro: recorre el modulo, clasifica las decls comptime y arrastra
 * (BFS) las funciones no-comptime que ese codigo llama, para que el futuro
 * artefacto comptime separado sea auto-suficiente.
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include <cstdio>
#include "vx/comptime/comptime_collect.h"
#include "util/env_flags.h"

#include <algorithm>
#include <functional> // std::function, para el recorrido recursivo de abajo
#include <unordered_map>
#include <unordered_set>

namespace vx {

namespace {

/**
 * @brief Principio REAL de la declaracion que empieza (segun el AST) en @p off.
 *
 * `loc.offset` de una decl apunta a su TIPO DE RETORNO, no a donde empieza de
 * verdad: lo que va delante -- `comptime`, `public`, anotaciones `@Macro` /
 * `@Pure`, el comentario de documentacion -- queda fuera.  Recortar por ahi
 * rompe el texto por los DOS lados: la decl extraida pierde su modificador (un
 * `comptime string f()` sale como `string f()`) y la decl ANTERIOR se queda con
 * ese `comptime` colgando al final, que es codigo invalido.  Se vio como "se
 * esperaba ';' al final de la declaracion" y "se esperaba un tipo al inicio de
 * la declaracion top-level" al compilar el conjunto extraido.
 *
 * Se retrocede hasta el principio de la linea de @p off y, desde ahi, por las
 * lineas anteriores mientras sean parte de la declaracion: anotaciones (`@`),
 * documentacion (`//`, `/*`, `*`) o una linea con solo modificadores.  Se para
 * en cuanto encuentra algo que ya es otra cosa (el `}` de la decl anterior, una
 * linea en blanco no precedida de anotacion, etc.).
 *
 * @param src Fuente completo del modulo.
 * @param off Offset que da el AST para la decl.
 * @return Offset del primer caracter de la declaracion, <= @p off.
 */
uint32_t inicio_real_de_decl(const std::string &src, uint32_t off) {
    if (off > src.size()) return static_cast<uint32_t>(src.size());
    // Principio de la linea de `off`.
    uint32_t ini = off;
    while (ini > 0 && src[ini - 1] != '\n')
        --ini;

    /// @brief Contenido de la linea que TERMINA en @p fin (exclusivo), sin
    ///        espacios de los extremos.
    auto linea_previa = [&src](uint32_t fin, uint32_t &ini_out) -> std::string {
        if (fin == 0) return {};
        uint32_t f = fin - 1; // saltar el '\n' que la cierra
        uint32_t i = f;
        while (i > 0 && src[i - 1] != '\n')
            --i;
        ini_out = i;
        std::string s = src.substr(i, f - i);
        size_t a = s.find_first_not_of(" \t\r");
        if (a == std::string::npos) return {};
        size_t b = s.find_last_not_of(" \t\r");
        return s.substr(a, b - a + 1);
    };

    for (;;) {
        uint32_t ini_prev = 0;
        const std::string prev = linea_previa(ini, ini_prev);
        if (prev.empty()) break; // linea en blanco o principio del fichero
        const bool es_anotacion = prev[0] == '@';
        const bool es_doc = prev.rfind("//", 0) == 0 ||
                            prev.rfind("/*", 0) == 0 || prev[0] == '*';
        /* Una linea que es SOLO modificadores (`public`, `comptime`, ...) sin
         * nada mas: es la cabecera de esta decl partida en dos lineas. */
        const bool es_modificador =
            prev == "comptime" || prev == "public" || prev == "private" ||
            prev == "protected" || prev == "static" || prev == "final" ||
            prev == "extern" || prev == "public comptime" ||
            prev == "private comptime";
        /* Y la CONTINUACION: una declaracion partida en varias lineas.
         *
         * Para un `const`, `loc.offset` apunta al INICIALIZADOR, no al tipo,
         * asi que con
         *
         *     const string VX_LITERAL_VACIO =
         *         "literal entero sin digitos: ...";
         *
         * el retroceso arrancaba en la segunda linea y paraba, porque la
         * primera no es anotacion ni documentacion ni solo-modificadores.  El
         * texto extraido empezaba a mitad de la declaracion y NO COMPILABA:
         * medido, 4 de las 6 unidades reales de `tipos_u128.vx` fallaban asi.
         *
         * Se reconoce por como TERMINA la linea anterior: si acaba en algo que
         * deja una expresion a medias (`=`, `,`, `(`, ...), lo que sigue es la
         * continuacion de esa misma declaracion.
         *
         * Cenido a esas formas A PROPOSITO.  La regla ancha -- "cualquier linea
         * que no acabe en `;`, `{` o `}`" -- parece equivalente y NO lo es: se
         * mete dentro del CUERPO de la funcion anterior y lo parte, y entonces
         * lo extraido falla con "se esperaba '}' al cerrar bloque".  Probado.
         */
        const char ultimo = prev.back();
        const bool es_continuacion =
            ultimo == '=' || ultimo == ',' || ultimo == '(' || ultimo == '[' ||
            ultimo == '<' || ultimo == '+' || ultimo == '|' || ultimo == '&';
        if (!es_anotacion && !es_doc && !es_modificador && !es_continuacion)
            break;
        ini = ini_prev;
    }
    return ini;
}

/// Acumula en @p out los nombres de funcion invocados (callee IdentExpr) dentro
/// de una expresion, recursivamente.  Solo nos interesan las llamadas directas
/// por nombre; las indirectas (punteros a fn) no arrastran una decl concreta.
void collect_calls_expr(const ast::Expr *e,
                        std::unordered_set<std::string> &out) {
    if (!e) return;
    switch (e->kind) {
    case ast::NodeKind::CallExpr: {
        const auto *c = static_cast<const ast::CallExpr *>(e);
        if (c->callee && c->callee->kind == ast::NodeKind::IdentExpr) {
            out.insert(
                static_cast<const ast::IdentExpr *>(c->callee.get())->name);
        }
        collect_calls_expr(c->callee.get(), out);
        for (const auto &a : c->args)
            collect_calls_expr(a.get(), out);
        break;
    }
    case ast::NodeKind::BinaryExpr: {
        const auto *b = static_cast<const ast::BinaryExpr *>(e);
        collect_calls_expr(b->lhs.get(), out);
        collect_calls_expr(b->rhs.get(), out);
        break;
    }
    case ast::NodeKind::UnaryExpr:
        collect_calls_expr(
            static_cast<const ast::UnaryExpr *>(e)->operand.get(), out);
        break;
    case ast::NodeKind::TernaryExpr: {
        const auto *t = static_cast<const ast::TernaryExpr *>(e);
        collect_calls_expr(t->cond.get(), out);
        collect_calls_expr(t->then_expr.get(), out);
        collect_calls_expr(t->else_expr.get(), out);
        break;
    }
    case ast::NodeKind::FieldAccessExpr:
        collect_calls_expr(
            static_cast<const ast::FieldAccessExpr *>(e)->base.get(), out);
        break;
    case ast::NodeKind::IndexExpr: {
        const auto *i = static_cast<const ast::IndexExpr *>(e);
        collect_calls_expr(i->base.get(), out);
        collect_calls_expr(i->index.get(), out);
        break;
    }
    default: break;
    }
}

/// Idem sobre statements (recorre las expresiones contenidas + control de
/// flujo).  Cubre los nodos que aparecen en cuerpos comptime tipicos.
void collect_calls_stmt(const ast::Stmt *s,
                        std::unordered_set<std::string> &out) {
    if (!s) return;
    switch (s->kind) {
    case ast::NodeKind::BlockStmt:
    case ast::NodeKind::ComptimeBlockStmt: {
        const auto *b = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : b->body)
            collect_calls_stmt(st.get(), out);
        break;
    }
    case ast::NodeKind::ExprStmt:
        collect_calls_expr(static_cast<const ast::ExprStmt *>(s)->expr.get(),
                           out);
        break;
    case ast::NodeKind::VarDeclStmt:
        collect_calls_expr(static_cast<const ast::VarDeclStmt *>(s)->init.get(),
                           out);
        break;
    case ast::NodeKind::ReturnStmt:
        collect_calls_expr(static_cast<const ast::ReturnStmt *>(s)->value.get(),
                           out);
        break;
    case ast::NodeKind::IfStmt: {
        const auto *i = static_cast<const ast::IfStmt *>(s);
        collect_calls_expr(i->cond.get(), out);
        collect_calls_stmt(i->then_branch.get(), out);
        collect_calls_stmt(i->else_branch.get(), out);
        break;
    }
    case ast::NodeKind::WhileStmt: {
        const auto *w = static_cast<const ast::WhileStmt *>(s);
        collect_calls_expr(w->cond.get(), out);
        collect_calls_stmt(w->body.get(), out);
        break;
    }
    case ast::NodeKind::DoWhileStmt: {
        const auto *w = static_cast<const ast::DoWhileStmt *>(s);
        collect_calls_expr(w->cond.get(), out);
        collect_calls_stmt(w->body.get(), out);
        break;
    }
    case ast::NodeKind::ForStmt: {
        const auto *f = static_cast<const ast::ForStmt *>(s);
        collect_calls_stmt(f->init.get(), out);
        collect_calls_expr(f->cond.get(), out);
        collect_calls_expr(f->step.get(), out);
        collect_calls_stmt(f->body.get(), out);
        break;
    }
    case ast::NodeKind::ComptimeForStmt: {
        const auto *f = static_cast<const ast::ComptimeForStmt *>(s);
        collect_calls_stmt(f->body.get(), out);
        break;
    }
    default: break;
    }
}

} // namespace

ComptimeUnit
collect_comptime_unit(const ast::ModuleNode &mod, const std::string &source,
                      const std::unordered_set<std::string> *tambien) {
    ComptimeUnit u;

    /* Las decls, incluidas las que estan DENTRO de un `namespace`.
     *
     * Un `namespace a.b;` mete todo lo que sigue dentro de un nodo, asi que
     * mirando solo el nivel superior se ve UNA decl -- el propio namespace -- y
     * el conjunto sale practicamente vacio.  En el flujo de siempre no se
     * notaba porque para cuando se llegaba aqui los namespaces ya estaban
     * aplanados; llamando ANTES (que es lo que permite tener el codigo de
     * compilacion listo antes de compilar nada) no lo estan.
     *
     * Se recorre en el mismo ORDEN en que aparecen en el fuente, que es del
     * que dependen los tramos de texto. */
    std::vector<const ast::Node *> decls;
    decls.reserve(mod.decls.size());
    {
        std::function<void(const std::vector<std::unique_ptr<ast::Node>> &)>
            recoger =
                [&](const std::vector<std::unique_ptr<ast::Node>> &lista) {
                    for (const auto &d : lista) {
                        if (!d) continue;
                        if (d->kind == ast::NodeKind::NamespaceDecl) {
                            const auto *nd =
                                static_cast<const ast::NamespaceDecl *>(
                                    d.get());
                            decls.push_back(d.get()); // el propio `namespace`
                            recoger(nd->decls);
                            continue;
                        }
                        decls.push_back(d.get());
                    }
                };
        recoger(mod.decls);
    }

    // Indice nombre -> FunctionDecl para resolver dependencias.
    std::unordered_map<std::string, const ast::FunctionDecl *> fn_by_name;
    for (const auto *d : decls) {
        if (d && d->kind == ast::NodeKind::FunctionDecl) {
            const auto *fd = static_cast<const ast::FunctionDecl *>(d);
            fn_by_name.emplace(fd->name, fd);
        }
    }

    // Clasificar decls comptime top-level + sembrar el worklist de cuerpos.
    std::unordered_set<std::string> seed_calls; // llamadas del codigo comptime
    for (const auto *d : decls) {
        if (!d) continue;
        if (d->kind == ast::NodeKind::FunctionDecl) {
            const auto *fd = static_cast<const ast::FunctionDecl *>(d);
            if (fd->is_macro) {
                u.macros.push_back(fd->name);
                collect_calls_stmt(fd->body.get(), seed_calls);
            } else if (fd->is_comptime) {
                u.comptime_fns.push_back(fd->name);
                collect_calls_stmt(fd->body.get(), seed_calls);
            }
        } else if (d->kind == ast::NodeKind::GlobalVarDecl) {
            const auto *gv = static_cast<const ast::GlobalVarDecl *>(d);
            if (gv->is_comptime || gv->is_const) {
                u.comptime_consts.push_back(gv->name);
                collect_calls_expr(gv->init.get(), seed_calls);
            }
        } else if (d->kind == ast::NodeKind::ComptimeBlockStmt) {
            // Bloque comptime a nivel modulo: su cuerpo tambien es comptime.
            collect_calls_stmt(static_cast<const ast::Stmt *>(d), seed_calls);
        } else if (d->kind == ast::NodeKind::StructDecl ||
                   d->kind == ast::NodeKind::ClassDecl) {
            /* Lo comptime que vive DENTRO de un tipo.  Este recolector recoge
             * declaraciones de nivel superior, y un metodo no lo es, asi que no
             * se lleva -- pero se APUNTA: un conjunto vacio no puede significar
             * a la vez "aqui no hay comptime" y "aqui hay comptime que no
             * recojo".  Lo segundo deja el artefacto sin algo que hace falta, y
             * no da error: falla mucho despues.
             *
             * Hoy no se nota porque el artefacto es el PROGRAMA ENTERO y el
             * bytecode del metodo esta dentro por eso.  En cuanto el artefacto
             * sea la particion, deja de estarlo. */
            const auto &metodos =
                d->kind == ast::NodeKind::StructDecl
                    ? static_cast<const ast::StructDecl *>(d)->methods
                    : static_cast<const ast::ClassDecl *>(d)->methods;
            const std::string &tipo =
                d->kind == ast::NodeKind::StructDecl
                    ? static_cast<const ast::StructDecl *>(d)->name
                    : static_cast<const ast::ClassDecl *>(d)->name;
            for (const auto &m : metodos) {
                if (!m) continue;
                if (m->is_comptime) {
                    u.not_collected.push_back(tipo + "." + m->name);
                    continue;
                }
                /* Un tipo viaja ENTERO, y un struct con metodos SI es codigo:
                 * sus cuerpos llaman a funciones que tambien tienen que viajar.
                 * Sin sembrar el cierre con ellos, el tipo llegaba y sus
                 * llamadas no ("el modulo 'atomic' no exporta
                 * 'vx_cpu_relax'"). */
                collect_calls_stmt(m->body.get(), seed_calls);
            }
        }
    }

    // Cierre transitivo: cada llamada a una fn NO-comptime del modulo se
    // arrastra como dependencia (debe viajar en el artefacto) y se explora su
    // cuerpo tambien.  Las comptime fn/macro ya estan en sus listas.
    std::unordered_set<std::string> is_comptime_name;
    for (const auto &n : u.comptime_fns)
        is_comptime_name.insert(n);
    for (const auto &n : u.macros)
        is_comptime_name.insert(n);

    std::unordered_set<std::string> visited;
    std::vector<std::string> work(seed_calls.begin(), seed_calls.end());
    std::unordered_set<std::string> dep_set;
    std::unordered_set<std::string> externas;
    while (!work.empty()) {
        const std::string name = work.back();
        work.pop_back();
        if (!visited.insert(name).second) continue;
        auto it = fn_by_name.find(name);
        if (it == fn_by_name.end()) {
            /* No esta en este modulo.  Puede ser un builtin o venir de otro por
             * un `import`; aqui no se puede distinguir, asi que se anota y lo
             * decide quien vea todos los modulos.  Tirarlas era lo que dejaba
             * al modulo que la DEFINE sin incluirla en su conjunto. */
            externas.insert(name);
            continue;
        }
        // Si es comptime, ya esta en su lista; si no, es helper-dep.
        if (!is_comptime_name.count(name)) dep_set.insert(name);
        std::unordered_set<std::string> more;
        collect_calls_stmt(it->second->body.get(), more);
        for (const auto &m : more)
            if (!visited.count(m)) work.push_back(m);
    }
    u.helper_deps.assign(dep_set.begin(), dep_set.end());
    /* Y los nombres que los `import` piden por su nombre.
     *
     * Un `import std.memory only memcpy;` viaja con el conjunto, pero si el
     * modulo de destino sale recortado sin `memcpy`, el import falla y con el
     * todo el modulo ("el modulo 'memory' no exporta 'memcpy'").  El import ya
     * DICE lo que necesita: no hay que deducirlo. */
    for (const auto *d : decls) {
        if (!d || d->kind != ast::NodeKind::ImportDecl) continue;
        const auto *im = static_cast<const ast::ImportDecl *>(d);
        for (const auto &s : im->only_symbols)
            if (!s.name.empty()) externas.insert(s.name);
    }
    u.external_calls.assign(externas.begin(), externas.end());
    std::sort(u.external_calls.begin(), u.external_calls.end());

    // Orden estable para diagnostico reproducible.
    std::sort(u.comptime_fns.begin(), u.comptime_fns.end());
    std::sort(u.macros.begin(), u.macros.end());
    std::sort(u.comptime_consts.begin(), u.comptime_consts.end());
    std::sort(u.helper_deps.begin(), u.helper_deps.end());

    // Clave de cache del artefacto: FNV-1a 64 del texto fuente de las decls del
    // conjunto (spans [decl.offset, siguiente_decl.offset)).  Reproducible e
    // independiente del codigo no-comptime del modulo.
    /* Basta con que haya fuente.  Antes se exigia ademas que el modulo tuviera
     * codigo comptime (`!u.empty()`), y eso dejaba fuera a los que solo aportan
     * TIPOS -- que no ejecutan nada al compilar, pero declaran lo que otros
     * usan.  El de tipos de la arquitectura viajaba con veintidos bytes (solo
     * su linea de `namespace`) y `std.types` no compilaba por un alias cuyo
     * destino se habia quedado por el camino.
     *
     * Lo que no cumpla el criterio no entra igualmente: se decide decl a decl
     * mas abajo.  Esta condicion solo decidia si SE MIRABA. */
    if (!source.empty()) {
        std::unordered_set<std::string> unit_names;
        for (const auto &n : u.comptime_fns)
            unit_names.insert(n);
        for (const auto &n : u.macros)
            unit_names.insert(n);
        for (const auto &n : u.comptime_consts)
            unit_names.insert(n);
        for (const auto &n : u.helper_deps)
            unit_names.insert(n);

        struct Span {
            uint32_t off; ///< primer byte de la decl.
            /// Un byte DESPUES del ultimo, tal como lo dio el parser.  Cero si
            /// no lo dio (decl sintetizada): entonces se usa el inicio de la
            /// siguiente, que es lo que se hacia siempre.
            uint32_t end;
            bool in_unit;   ///< pertenece al conjunto comptime (entra al hash).
            bool is_import; ///< es un `import` (viaja, pero NO entra al hash).
        };
        std::vector<Span> spans;
        spans.reserve(decls.size());
        for (const auto *d : decls) {
            if (!d) continue;
            bool in = false;
            if (d->kind == ast::NodeKind::FunctionDecl)
                in = unit_names.count(
                         static_cast<const ast::FunctionDecl *>(d)->name) > 0;
            else if (d->kind == ast::NodeKind::GlobalVarDecl)
                in = unit_names.count(
                         static_cast<const ast::GlobalVarDecl *>(d)->name) > 0;
            else if (d->kind == ast::NodeKind::ComptimeBlockStmt)
                in = true; // el bloque comptime es parte del conjunto.
            else if (d->kind == ast::NodeKind::ImportDecl)
                /* Los `import` NO son parte del conjunto -- no se ejecutan al
                 * compilar -- pero SI hacen falta para que el texto extraido
                 * compile por si solo: una comptime que usa `string` o llama a
                 * la stdlib necesita las mismas importaciones que su modulo. Se
                 * marcan aparte para no ensuciar el hash: si entrasen en el,
                 * anadir un import que el codigo comptime no usa invalidaria el
                 * cache sin que nada comptime hubiera cambiado. */
                in = false;
            /* Los TIPOS del modulo viajan TODOS.
             *
             * El codigo que se ejecuta al compilar puede nombrar cualquiera --
             * en una firma, en una variable local, en un `sizeof<T>` --, y sin
             * su declaracion el texto extraido no compila ("el operando de '.'
             * debe ser un struct o clase (tipo recibido: void)", "sizeof: tipo
             * no reconocido").
             *
             * TODOS y no solo los referenciados, a proposito: seguir las
             * referencias exige un recorrido de tipos aparte, y una declaracion
             * de tipo no es codigo -- no se ejecuta, no llama a nada, y
             * compilarla cuesta lo que ocupa.  Pagar de mas aqui sale mas
             * barato que un cierre incompleto, que se manifiesta como un
             * conjunto que no compila y deja al codigo de compilacion sin
             * bytecode que ejecutar.
             *
             * Entran al hash: si un struct cambia, lo que el codigo comptime
             * calcule con el puede cambiar tambien. */
            if (d->kind == ast::NodeKind::StructDecl ||
                d->kind == ast::NodeKind::ClassDecl ||
                d->kind == ast::NodeKind::EnumDecl ||
                d->kind == ast::NodeKind::TypeAliasDecl)
                in = true;
            /* Y lo que pida quien orquesta.  Son funciones de ESTE modulo que
             * el codigo comptime de OTRO llama por un `import`: sin esto, el
             * modulo que las define las deja fuera de su conjunto y el otro se
             * queda sin poder llamarlas. */
            if (tambien != nullptr && !in) {
                std::string nom;
                if (d->kind == ast::NodeKind::FunctionDecl)
                    nom = static_cast<const ast::FunctionDecl *>(d)->name;
                else if (d->kind == ast::NodeKind::GlobalVarDecl)
                    nom = static_cast<const ast::GlobalVarDecl *>(d)->name;
                if (!nom.empty() && tambien->count(nom) > 0) in = true;
            }
            const bool es_import = d->kind == ast::NodeKind::ImportDecl;
            /* El principio REAL, no el que da el AST: si no, el recorte pierde
             * el `comptime`/`@Macro` de esta decl y se lo cuelga a la anterior
             * (ver @ref inicio_real_de_decl).
             *
             * PENDIENTE, y es la forma correcta: este span lo sabe EXACTO el
             * parser, que ya lo calcula para exportar plantillas genericas al
             * `.vxi` (`Parser::collect_template_export_`).  Deducirlo del texto
             * es un segundo criterio, peor, para algo ya decidido.  Cambiarlo
             * exige emparejar bien los spans con `decls`, y no es inmediato:
             * el parser inserta ademas las decls sintetizadas
             * (`pending_before_decls_`, `pending_extra_decls_`), asi que el
             * indice no vale como emparejamiento -- probado, y desalinea. */
            /* El tramo tal como lo anoto el parser.  Si no esta (decl
             * sintetizada, que no sale de ningun texto), se cae al respaldo de
             * siempre: deducirlo del fuente. */
            uint32_t ini = d->span_start;
            uint32_t fin = d->span_end;
            /* Sin tramo anotado no hay texto que extraer.  Una decl que el
             * parser no anoto es SINTETIZADA -- no sale de ningun fuente --, y
             * deducirle un tramo del texto era justo lo que cortaba por medio
             * de un token: se colaba la cola de la cadena de al lado y el
             * conjunto extraido no compilaba. */
            if (fin == 0) continue;
            spans.push_back({ini, fin, in, es_import});
        }
        std::sort(spans.begin(), spans.end(),
                  [](const Span &a, const Span &b) { return a.off < b.off; });

        uint64_t h = util::kFnvOffset; // FNV-1a offset basis.
        const uint32_t src_len = static_cast<uint32_t>(source.size());
        for (size_t i = 0; i < spans.size(); ++i) {
            if (!spans[i].in_unit && !spans[i].is_import) continue;
            uint32_t start = spans[i].off;
            /* El fin que dio el PARSER.  Solo si no lo hay se recurre al inicio
             * de la siguiente decl -- que es una aproximacion: arrastra lo que
             * haya en medio (lineas en blanco, comentarios sueltos) y, si el
             * inicio de la siguiente se calculo mal, corta esta por donde no
             * es.  Con el span del parser eso no puede pasar. */
            uint32_t end =
                spans[i].end != 0
                    ? spans[i].end
                    : ((i + 1 < spans.size()) ? spans[i + 1].off : src_len);
            if (start > src_len) start = src_len;
            if (end > src_len) end = src_len;
            /* Y nunca al reves: un `end` menor que `start` daria una longitud
             * negativa, que al restar sin signo se convierte en un numero
             * enorme -- y eso no es un texto mal recortado, es un crash. */
            if (end < start) end = start;
            /* El TEXTO del conjunto, recogido en el MISMO recorrido que ya
             * calculaba el hash: los spans se computaban, se usaban para
             * hashear y se tiraban, y son justo lo que la fase siguiente
             * necesita para poder compilar el conjunto POR SEPARADO. */
            u.unit_source.append(source, start, end - start);
            if (!spans[i].in_unit) continue; // un import viaja, pero no hashea.
            for (uint32_t j = start; j < end; ++j) {
                h ^= static_cast<uint8_t>(source[j]);
                h *= util::kFnvPrime; // FNV-1a prime.
            }
        }
        u.content_hash = h;
    }
    return u;
}

void dump_comptime_unit(const ComptimeUnit &u, std::ostream &os) {
    os << "[comptime-unit] resumen del conjunto comptime del modulo:\n";
    os << "  comptime fns   (" << u.comptime_fns.size() << "):";
    for (const auto &n : u.comptime_fns)
        os << " " << n;
    os << "\n  @Macro         (" << u.macros.size() << "):";
    for (const auto &n : u.macros)
        os << " " << n;
    os << "\n  comptime const (" << u.comptime_consts.size() << "):";
    for (const auto &n : u.comptime_consts)
        os << " " << n;
    os << "\n  helper deps    (" << u.helper_deps.size() << "):";
    for (const auto &n : u.helper_deps)
        os << " " << n;
    /* Lo que se VIO y no se llevo, SIEMPRE que lo haya: sin esta linea, un
     * conjunto vacio se lee igual esten o no esten estas declaraciones, y son
     * cosas opuestas. */
    if (!u.not_collected.empty()) {
        os << "\n  visto y NO recogido (" << u.not_collected.size()
           << ", comptime dentro de un tipo -- hoy lo cubre el artefacto"
              " monolitico):";
        for (const auto &n : u.not_collected)
            os << " " << n;
    }
    os << "\n  content_hash   : 0x" << std::hex << u.content_hash << std::dec
       << "  (clave de cache del artefacto comptime)\n";
}

} // namespace vx
