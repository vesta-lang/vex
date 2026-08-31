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
 * @file mermaid_diagrams.cpp
 * @brief Implementacion de los generadores Mermaid para AST/IR/VEL.
 *
 * Cada generador escribe un sub-bloque ```mermaid ... ``` con los nodos
 * y aristas adecuados para inspeccionar el codigo a esa capa del pipeline.
 * El output esta orientado a debug y traceo, NO a presentacion: prima la
 * informacion sobre la estetica.
 *
 * Convenciones del output:
 *   - Estilo Mermaid: `flowchart TD` (top-down, lectura natural de
 *     secuencias).
 *   - Identificadores de nodo: prefijo por tipo (M_, F_, C_, B_, ...) +
 *     indice unico.  Cero ambiguedad cuando el mismo nombre aparece dos
 *     veces (e.g. dos funciones con el mismo metodo `init`).
 *   - Texto del nodo: encerrado en `["..."]` con `<br/>` para saltos y
 *     escape de `<`, `>`, `"`.
 *   - Estilos: classes Mermaid agrupan nodos por tipo (functions, blocks,
 *     terminators).  Asi se pueden distinguir visualmente sin leer el
 *     texto.
 */

#include "vx/diagram/mermaid_diagrams.h"

#include "analyze/bigo.h"
#include "vx/asm/asm_diagram.h" // expansion del CFG de inline asm con coste
#include "vx/ast.h"
#include "vx/diagram/diagram_labels.h" // como se lee cada cosa
#include "vx/diagram/vel_text_model.h" // que se lee del .vel, comun a los dos
#include "ir/ssa_ir.h"
#include "vx/types.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace vx {

namespace {

// =====================================================================
//  Helpers comunes (escape Mermaid, formateo de tipos, etc.)
// =====================================================================

/**
 * @brief Escapa un string para que sea seguro dentro de un nodo Mermaid.
 *
 * Reemplaza caracteres que romperian la sintaxis de label:
 *   "  -> &quot;
 *   <  -> &lt;
 *   >  -> &gt;
 *   &  -> &amp;
 *   \n -> <br/>
 *   |  -> :   (las pipes son sintaxis Mermaid en edges)
 *
 * Mermaid renderiza HTML entities dentro de labels cuando estan
 * encerrados en `["..."]`, lo que permite mostrar genericos como
 * `Future<i32>` sin romper el parser.
 */
std::string escape_label(const std::string &s_in) {
    // NS: los nombres de un namespace estan mangled con `__` como separador
    // (org__geo__shapes__area).  Para el diagrama los mostramos CUALIFICADOS
    // con puntos (org.geo.shapes.area), mucho mas legibles.  Se preserva un
    // `__` INICIAL (nombres sinteticos: __module_init, __new_X, __lambda_N).
    std::string s;
    s.reserve(s_in.size());
    for (size_t i = 0; i < s_in.size();) {
        if (i > 0 && i + 1 < s_in.size() && s_in[i] == '_' &&
            s_in[i + 1] == '_') {
            s.push_back('.');
            i += 2;
        } else {
            s.push_back(s_in[i]);
            ++i;
        }
    }
    // Mermaid label rules:
    //   - Dentro de `["..."]` o edges `|"..."|` Mermaid acepta
    //     practicamente cualquier carater excepto `"` literal.
    //   - Sin quotes, los caracteres `()[]{}|"<>&` son sintaxis
    //     y rompen el parser.
    //
    // Estrategia: convertir TODO carater problematico a entidad
    // HTML.  Mermaid las renderiza correctamente como el carater
    // visible.  Asi el output es seguro tanto si el caller usa
    // quotes alrededor como si no.
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': out += "&quot;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '&': out += "&amp;"; break;
        case '\n': out += "<br/>"; break;
        case '\r': break;
        case '|': out += "&#124;"; break;
        case '[': out += "&#91;"; break;
        case ']': out += "&#93;"; break;
        case '{': out += "&#123;"; break;
        case '}': out += "&#125;"; break;
        case '(': out += "&#40;"; break;
        case ')': out += "&#41;"; break;
        case '`': out += "&#96;"; break;
        case '#': out += "&#35;"; break;
        default:
            if (static_cast<unsigned char>(c) < 32) {
                // controles invisibles -> espacio
                out += ' ';
            } else {
                out += c;
            }
        }
    }
    return out;
}

/**
 * @brief Imprime un type_to_string sanitizado para Mermaid.
 */

// Helpers comunes usados por varias funciones (forward decls).
void render_function_body_subgraph(std::ostringstream &os,
                                   const std::string &prefix,
                                   const std::string &title,
                                   const ast::BlockStmt *body);

// =====================================================================
//  Resumen breve de expresiones (recursivo con depth limit)
// =====================================================================
//
// Cada Expr se reduce a una linea (~ <80 chars) con info suficiente
// para entender el control flow sin tener que abrir el codigo fuente.
// Los operadores binarios y unarios mantienen su simbologia; las
// llamadas muestran el nombre + aridad; los literales muestran el
// valor.  Profundidad limitada a 3 niveles para evitar explosion.

// Forward decls usadas por fmt_expr_brief.

/**
 * @brief Cuenta total de stmts en un body (recursivo) para info de label.
 */
size_t count_stmts(const ast::Stmt *s) {
    if (!s) return 0;
    if (s->kind == ast::NodeKind::BlockStmt) {
        auto *bs = static_cast<const ast::BlockStmt *>(s);
        size_t total = 0;
        for (const auto &st : bs->body)
            total += count_stmts(st.get());
        return total > 0 ? total : 1; // contar al menos el block en si
    }
    return 1;
}

// =====================================================================
//  GENERADOR 1: AST Vesta -> Mermaid
// =====================================================================

/**
 * @brief Renderiza el AST de un modulo Vesta completo.
 *
 * Topologia del diagrama:
 *   - Module nodo raiz.
 *   - Por cada decl (function, class, struct, enum, global, extern):
 *     un nodo conectado al Module.
 *   - Class y struct expanden fields y methods como subnodos.
 *   - Function expande params y return type.
 *
 * Estilo:
 *   - `funcDecl` / `classDecl` / `structDecl` / `enumDecl` /
 *     `globalDecl` / `externDecl` clases de Mermaid para estilizar.
 */
void render_function_decl(std::ostringstream &os, const ast::FunctionDecl *fd,
                          const std::string &parent_id, size_t idx) {
    const std::string fid = "F_" + std::to_string(idx);
    std::string ret_type = fmt_type(fd->return_type.get());
    // Construir signatura completa con params para que el nodo principal
    // ya muestre toda la info que el usuario querria de un overview.
    std::string title = "fn " + fd->name + "(";
    for (size_t pi = 0; pi < fd->params.size(); ++pi) {
        if (pi) title += ", ";
        title +=
            fmt_type(fd->params[pi]->type.get()) + " " + fd->params[pi]->name;
    }
    title += ") -> " + ret_type;
    if (fd->is_async) title = "@Async " + title;
    std::string body_info;
    if (fd->body) {
        size_t n = count_stmts(fd->body.get());
        body_info = "body: " + std::to_string(n) + " stmts (ver subgraph)";
    } else {
        body_info = "(declaracion sin body)";
    }
    os << "    " << fid << "[\"" << escape_label(title) << "<br/>"
       << escape_label(body_info) << "\"]:::funcDecl\n";
    os << "    " << parent_id << " --> " << fid << "\n";

    // Subgraph con el control flow del body.
    if (fd->body) {
        std::string body_prefix = fid + "_";
        std::string body_title = fd->name + "() body";
        render_function_body_subgraph(os, body_prefix, body_title,
                                      fd->body.get());
        // Edge punteado del nodo de la funcion al subgraph (al entry).
        os << "    " << fid << " -.->|body| " << body_prefix << "entry\n";
    }
}

void render_class_decl(std::ostringstream &os, const ast::ClassDecl *cd,
                       const std::string &parent_id, size_t idx) {
    const std::string cid = "C_" + std::to_string(idx);
    std::string title;
    if (cd->is_interface)
        title = "interface " + cd->name;
    else if (cd->is_aspect)
        title = "@Aspect class " + cd->name;
    else if (cd->is_final)
        title = "final class " + cd->name;
    else
        title = "class " + cd->name;
    if (!cd->type_params.empty()) {
        title += "<";
        for (size_t i = 0; i < cd->type_params.size(); ++i) {
            if (i) title += ",";
            title += cd->type_params[i];
        }
        title += ">";
    }
    std::string sub = std::to_string(cd->fields.size()) + " fields, " +
                      std::to_string(cd->methods.size()) + " methods";
    os << "    " << cid << "[\"" << escape_label(title) << "<br/>"
       << escape_label(sub) << "\"]:::classDecl\n";
    os << "    " << parent_id << " --> " << cid << "\n";

    // Herencia: super -> nodo virtual (no resuelto al modulo)
    if (!cd->super_name.empty()) {
        std::string sid = cid + "_super";
        os << "    " << sid << "[[\"" << escape_label(cd->super_name)
           << "\"]]:::externRef\n";
        os << "    " << cid << " ==>|extends| " << sid << "\n";
    }
    // Interfaces consolidadas en un solo nodo lista (mismo motivo
    // que fields/variants/globals: cada interfaz es un nodo hoja
    // sin estructura propia y su grupo "del mismo tipo" puede
    // colapsarse manteniendo distinguibilidad por linea).
    if (!cd->interface_names.empty()) {
        std::string iid = cid + "_ifaces";
        std::ostringstream lbl;
        lbl << "Interfaces (" << cd->interface_names.size() << ")";
        for (const auto &iname : cd->interface_names) {
            lbl << "<br/>" << escape_label(iname);
        }
        os << "    " << iid << "[[\"" << lbl.str() << "\"]]:::externRef\n";
        os << "    " << cid << " -->|implements| " << iid << "\n";
    }

    // Fields consolidados en un solo nodo lista.  Sin truncamiento:
    // se muestran TODOS los fields para no omitir informacion.
    if (!cd->fields.empty()) {
        std::string fid = cid + "_fields";
        std::ostringstream lbl;
        lbl << "Fields (" << cd->fields.size() << ")";
        for (const auto &f : cd->fields) {
            std::string acc = (f.access == 1)   ? "private "
                              : (f.access == 2) ? "protected "
                                                : "public ";
            std::string mods;
            if (f.is_static) mods += "static ";
            if (f.is_final) mods += "final ";
            std::string line =
                acc + mods + fmt_type(f.type.get()) + " " + f.name;
            lbl << "<br/>" << escape_label(line);
        }
        os << "    " << fid << "[\"" << lbl.str() << "\"]:::fieldNode\n";
        os << "    " << cid << " -.->|fields| " << fid << "\n";
    }
    // Metodos
    for (size_t mi = 0; mi < cd->methods.size(); ++mi) {
        const auto &m = cd->methods[mi];
        std::string mid = cid + "_m" + std::to_string(mi);
        std::string acc = (m->access == 1)   ? "private "
                          : (m->access == 2) ? "protected "
                                             : "public ";
        std::string mods;
        if (m->is_static) mods += "static ";
        if (m->is_final) mods += "final ";
        if (m->is_override) mods += "@Override ";
        if (m->is_constructor) mods += "<ctor> ";
        if (m->is_destructor) mods += "<dtor> ";
        if (m->is_inline) mods += "@Inline ";
        if (m->advice_kind == 1)
            mods += "@Before(\"" + m->advice_target + "\") ";
        if (m->advice_kind == 2)
            mods += "@After(\"" + m->advice_target + "\") ";
        if (m->advice_kind == 3)
            mods += "@Around(\"" + m->advice_target + "\") ";
        std::string ret = m->return_type ? fmt_type(m->return_type.get())
                                         : std::string("void");
        // Signatura completa con tipos y nombres de params (igual
        // que en FunctionDecl).
        std::string sig = acc + mods + ret + " " + m->name + "(";
        for (size_t pi = 0; pi < m->params.size(); ++pi) {
            if (pi) sig += ", ";
            sig +=
                fmt_type(m->params[pi]->type.get()) + " " + m->params[pi]->name;
        }
        sig += ")";
        std::string body_info;
        if (m->body) {
            body_info = std::to_string(count_stmts(m->body.get())) +
                        " stmts (ver subgraph)";
        } else {
            body_info = "(abstract)";
        }
        os << "    " << mid << "[\"" << escape_label(sig) << "<br/>"
           << escape_label(body_info) << "\"]:::methodNode\n";
        os << "    " << cid << " -->|method| " << mid << "\n";

        // Subgraph del body del metodo.
        if (m->body) {
            std::string body_prefix = mid + "_";
            std::string body_title = cd->name + "." + m->name + "() body";
            render_function_body_subgraph(os, body_prefix, body_title,
                                          m->body.get());
            os << "    " << mid << " -.->|body| " << body_prefix << "entry\n";
        }
    }
}

void render_struct_decl(std::ostringstream &os, const ast::StructDecl *sd,
                        const std::string &parent_id, size_t idx) {
    const std::string sid = "S_" + std::to_string(idx);
    std::string title = "struct " + sd->name + " (" +
                        std::to_string(sd->fields.size()) + " fields)";
    os << "    " << sid << "[\"" << escape_label(title) << "\"]:::structDecl\n";
    os << "    " << parent_id << " --> " << sid << "\n";
    // Fields consolidados en un solo nodo lista.  Sin truncamiento.
    if (!sd->fields.empty()) {
        std::string fid = sid + "_fields";
        std::ostringstream lbl;
        lbl << "Fields (" << sd->fields.size() << ")";
        for (const auto &f : sd->fields) {
            std::string line = fmt_type(f.type.get()) + " " + f.name;
            if (f.bit_width > 0) {
                line += " : " + std::to_string(f.bit_width);
            }
            lbl << "<br/>" << escape_label(line);
        }
        os << "    " << fid << "[\"" << lbl.str() << "\"]:::fieldNode\n";
        os << "    " << sid << " -.->|fields| " << fid << "\n";
    }
}

void render_enum_decl(std::ostringstream &os, const ast::EnumDecl *ed,
                      const std::string &parent_id, size_t idx) {
    const std::string eid = "E_" + std::to_string(idx);
    std::string title = "enum " + ed->name + " (" +
                        std::to_string(ed->variants.size()) + " variants)";
    os << "    " << eid << "[\"" << escape_label(title) << "\"]:::enumDecl\n";
    os << "    " << parent_id << " --> " << eid << "\n";
    // Variants consolidados en un solo nodo lista.  Sin truncamiento.
    if (!ed->variants.empty()) {
        std::string vid = eid + "_variants";
        std::ostringstream lbl;
        lbl << "Variants (" << ed->variants.size() << ")";
        for (const auto &v : ed->variants) {
            std::string line = v.name;
            if (!v.field_types.empty()) {
                line += "(";
                for (size_t i = 0; i < v.field_types.size(); ++i) {
                    if (i) line += ", ";
                    line += fmt_type(v.field_types[i].get());
                }
                line += ")";
            }
            lbl << "<br/>" << escape_label(line);
        }
        os << "    " << vid << "[\"" << lbl.str() << "\"]:::variantNode\n";
        os << "    " << eid << " -.->|variants| " << vid << "\n";
    }
}

/**
 * @brief Renderiza TODOS los globals/constants top-level como un solo
 *        nodo con la lista.
 *
 * Antes (un nodo por global) saturaba grafos de modulos con muchas
 * constantes (e.g. `const i32 KEY_X = N;` x 80 en el modulo del
 * editor TUI).  Ahora se acumulan en un unico nodo "Globals (N)" con
 * cada linea = una declaracion.  Const declarations primero (logico
 * para inspeccion humana), luego las var globales mutables.
 *
 * Limite de lineas mostradas: 80 (con "... N mas" si excede).
 */
void render_globals_batch(
    std::ostringstream &os,
    const std::vector<const ast::GlobalVarDecl *> &globals,
    const std::string &parent_id) {
    if (globals.empty()) return;
    const std::string gid = "G_all";
    std::ostringstream lbl;
    lbl << "Globals/Constants (" << globals.size() << ")";
    // Sin truncamiento ni cap: emitimos TODOS los globals con su
    // expresion de inicializacion completa.  Pase 1 const, pase 2
    // var-globals, para agrupar visualmente.
    for (const auto *gv : globals) {
        if (!gv->is_const) continue;
        std::string line =
            std::string("const ") + fmt_type(gv->type.get()) + " " + gv->name;
        if (gv->init) {
            line += " = " + fmt_expr_brief(gv->init.get(), 32);
        }
        lbl << "<br/>" << escape_label(line);
    }
    for (const auto *gv : globals) {
        if (gv->is_const) continue;
        std::string line = fmt_type(gv->type.get()) + " " + gv->name;
        if (gv->init) {
            line += " = " + fmt_expr_brief(gv->init.get(), 32);
        }
        lbl << "<br/>" << escape_label(line);
    }
    os << "    " << gid << "[\"" << lbl.str() << "\"]:::globalDecl\n";
    os << "    " << parent_id << " --> " << gid << "\n";
}

/**
 * @brief Renderiza TODOS los `extern fn` top-level como un solo nodo
 *        con la lista, agrupados por libreria nativa (.dll/.so).
 *
 * Cada extern es un nodo hoja (declaracion FFI sin body), asi que
 * pueden colapsarse igual que globals/constants.  Para preservar
 * la distinguibilidad cuando el modulo importa de varias librerias
 * (e.g. msvcrt + kernel32 + user32), agrupamos por @c lib y emitimos
 * un encabezado por libreria seguido de las funciones de esa lib.
 */
void render_externs_batch(std::ostringstream &os,
                          const std::vector<const ast::ExternFnDecl *> &externs,
                          const std::string &parent_id) {
    if (externs.empty()) return;
    const std::string xid = "X_all";
    // Agrupar por libreria (preservando primer-uso order).
    std::vector<std::string> lib_order;
    std::unordered_map<std::string, std::vector<const ast::ExternFnDecl *>>
        by_lib;
    for (const auto *ef : externs) {
        if (by_lib.find(ef->lib) == by_lib.end()) lib_order.push_back(ef->lib);
        by_lib[ef->lib].push_back(ef);
    }
    std::ostringstream lbl;
    lbl << "Externs (" << externs.size() << ")";
    // Sin truncamiento: emitimos TODOS los externs con sus tipos
    // completos (return + tipos de cada parametro).
    for (const auto &lib : lib_order) {
        lbl << "<br/>--- " << escape_label(lib) << " ---";
        for (const auto *ef : by_lib[lib]) {
            std::string ret = fmt_type(ef->return_type.get());
            std::string line = ret + " " + ef->name + "(";
            for (size_t pi = 0; pi < ef->params.size(); ++pi) {
                if (pi) line += ", ";
                line += fmt_type(ef->params[pi]->type.get()) + " " +
                        ef->params[pi]->name;
            }
            line += ")";
            lbl << "<br/>" << escape_label(line);
        }
    }
    os << "    " << xid << "[\"" << lbl.str() << "\"]:::externDecl\n";
    os << "    " << parent_id << " --> " << xid << "\n";
}

// =====================================================================
//  GENERADOR 2: SSA IR -> Mermaid
// =====================================================================

/**
 * @brief Renderiza un IrBlock como un nodo Mermaid con su contenido.
 */
void render_ir_block(std::ostringstream &os, const ir::IrFunction &fn,
                     const ir::IrBlock &bb, const std::string & /*fn_id*/,
                     const std::string &block_id) {
    std::ostringstream lbl;
    lbl << bb.name << " (#" << bb.id << ", " << bb.instrs.size() << " instrs)";
    // Sin truncamiento: emitimos TODAS las instrucciones.
    for (const auto &ins : bb.instrs) {
        lbl << "<br/>" << escape_label(fmt_instr(fn, ins, fn.blocks));
    }
    // Detectar tipo de terminador para escoger clase visual
    std::string css_class = "irBlock";
    if (!bb.instrs.empty()) {
        ir::IrOp last_op = bb.instrs.back().op;
        if (last_op == ir::IrOp::RET || last_op == ir::IrOp::UNREACHABLE)
            css_class = "irExit";
        else if (last_op == ir::IrOp::BR_COND)
            css_class = "irBranch";
    }
    os << "        " << block_id << "[\"" << lbl.str() << "\"]:::" << css_class
       << "\n";
}

/**
 * @brief Renderiza una IrFunction completa como subgraph con sus bloques.
 */
void render_ir_function(std::ostringstream &os, const ir::IrFunction &fn,
                        size_t fn_idx,
                        std::unordered_set<std::string> &intra_calls_out,
                        const std::string &cost_label = std::string()) {
    const std::string fn_id = "fn" + std::to_string(fn_idx);
    std::string title = fn.name;
    // añadir conteo de bloques + tipo retorno + n params
    title += " (";
    title += std::to_string(fn.blocks.size());
    title += " bb, ";
    title += std::to_string(fn.params.size());
    title += " params, ret ";
    title += ir::ir_type_name(fn.ret_type);
    title += ")";
    // --diagram-cost: anexar el coste Big-O al titulo del subgraph (segunda
    // linea, separada con <br/> para que Mermaid la renderice debajo).
    if (!cost_label.empty()) {
        title += "<br/>";
        title += cost_label;
    }

    os << "    subgraph " << fn_id << " [\"" << escape_label(title) << "\"]\n";
    os << "    direction TB\n";

    // Emit cada bloque
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        std::string bid = fn_id + "_b" + std::to_string(bi);
        render_ir_block(os, fn, fn.blocks[bi], fn_id, bid);
    }

    // Edges dentro del subgraph
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        std::string src = fn_id + "_b" + std::to_string(bi);
        const auto &bb = fn.blocks[bi];
        if (bb.instrs.empty()) continue;
        const auto &term = bb.instrs.back();
        if (term.op == ir::IrOp::BR) {
            if (term.target_block < fn.blocks.size()) {
                std::string dst =
                    fn_id + "_b" + std::to_string(term.target_block);
                os << "        " << src << " --> " << dst << "\n";
            }
        } else if (term.op == ir::IrOp::BR_COND) {
            if (term.target_block < fn.blocks.size()) {
                std::string dst =
                    fn_id + "_b" + std::to_string(term.target_block);
                os << "        " << src << " -->|true| " << dst << "\n";
            }
            if (term.false_block < fn.blocks.size()) {
                std::string dst =
                    fn_id + "_b" + std::to_string(term.false_block);
                os << "        " << src << " -->|false| " << dst << "\n";
            }
        }
        // Detectar llamadas intra-modulo para edges punteados a otras
        // funciones (cross-subgraph).  Las anotamos en intra_calls_out
        // para emitirlas DESPUES del cierre del subgraph.
        for (const auto &ins : bb.instrs) {
            if ((ins.op == ir::IrOp::CALL || ins.op == ir::IrOp::TAILCALL) &&
                !ins.func_name.empty()) {
                // formato fuente -> "fnName" (resolveremos al cierre)
                intra_calls_out.insert(fn_id + ">" + ins.func_name);
            }
        }
    }

    os << "    end\n";
}

// =====================================================================
//  GENERADOR 3: .vel ensamblador -> Mermaid
// =====================================================================

// Lo que se lee del texto .vel -- mnemonico, etiqueta, llamada, destino del
// salto, instruccion fusionada -- vive en vx/diagram/vel_text_model.h, porque
// la respuesta es la misma se dibuje en Mermaid o en DOT.

// is_terminator helper se mantenia para futuras extensiones de tagging
// pero la deteccion de "exit" en render_vel ahora usa solo last mnemonic
// directamente; no hay uso adicional, asi que omitimos definicion para
// evitar warning -Wunused-function.

// =====================================================================
//  Renderer detallado del cuerpo de funciones (control flow)
// =====================================================================
//
// Construye un sub-grafo Mermaid con cada stmt como nodo + edges
// explicitos para los caminos posibles:
//   - Stmts secuenciales: edge solid sin label.
//   - if/else:           cond -->|true| then ; cond -->|false| else
//   - while/do-while:    cond -->|true| body --> back-edge ; cond -->|false|
//   exit
//   - for:               init --> cond -->|true| body --> step --> cond
//   - try/catch/finally: body -->|exception| catch ; body --> finally
//   - return/throw:      nodo terminal (rojo).
//   - break/continue:    edge especial al loop enclosing (mostrado con label).
//   - synchronized:      monenter --> body --> monexit (con catch implicito).
//   - spawn/rspawn:      nodo destacado con edge "spawn" al body inline.
//
// Estado de render: contador de IDs por sub-grafo + stack de loops
// pendientes para break/continue + accumulator de salida.
struct StmtCtx {
    std::ostringstream &os; ///< Stream del sub-grafo.
    std::string prefix;     ///< Prefijo de IDs (e.g. "f0_").
    int next_id = 0;
    // Stack de pares (loop_cond_id, loop_exit_id) para resolver
    // break/continue al loop enclosing.
    struct LoopFrame {
        std::string continue_target;
        std::string break_target;
    };
    std::vector<LoopFrame> loop_stack;
    // Stack de labels resueltos (para goto).
    std::unordered_map<std::string, std::string> labels;

    std::string fresh(const char *kind) {
        return prefix + kind + std::to_string(next_id++);
    }
};

// Forward decls para recursividad mutua.
std::string render_stmt(StmtCtx &ctx, const ast::Stmt *s);
std::string render_block(StmtCtx &ctx, const ast::BlockStmt *bs);

/**
 * @brief Emite un nodo simple con un label dado.  Devuelve el id.
 */
std::string emit_node(StmtCtx &ctx, const std::string &id,
                      const std::string &label, const char *css) {
    ctx.os << "        " << id << "[\"" << escape_label(label)
           << "\"]:::" << css << "\n";
    return id;
}
std::string emit_node(StmtCtx &ctx, const char *kind, const std::string &label,
                      const char *css) {
    std::string id = ctx.fresh(kind);
    return emit_node(ctx, id, label, css);
}
std::string emit_node_round(StmtCtx &ctx, const char *kind,
                            const std::string &label, const char *css) {
    std::string id = ctx.fresh(kind);
    ctx.os << "        " << id << "((\"" << escape_label(label)
           << "\")):::" << css << "\n";
    return id;
}
std::string emit_node_diamond(StmtCtx &ctx, const char *kind,
                              const std::string &label, const char *css) {
    std::string id = ctx.fresh(kind);
    ctx.os << "        " << id << "{\"" << escape_label(label)
           << "\"}:::" << css << "\n";
    return id;
}

// Mermaid no permite caracteres `()[]{}` sin escape dentro de un
// edge label `-->|texto|`.  La forma robusta es encerrar el label
// en comillas dobles: `-->|"texto con (parens) y [brackets]"|`.
// Ya que escape_label sustituye los `"` por &quot;, el texto
// resultante NO contiene comillas literales y el parser Mermaid
// ve el label como una cadena.
void emit_edge(StmtCtx &ctx, const std::string &from, const std::string &to,
               const std::string &label = "") {
    ctx.os << "        " << from;
    if (label.empty()) {
        ctx.os << " --> ";
    } else {
        ctx.os << " -->|\"" << escape_label(label) << "\"| ";
    }
    ctx.os << to << "\n";
}
void emit_dotted(StmtCtx &ctx, const std::string &from, const std::string &to,
                 const std::string &label = "") {
    ctx.os << "        " << from;
    if (label.empty()) {
        ctx.os << " -.-> ";
    } else {
        ctx.os << " -.->|\"" << escape_label(label) << "\"| ";
    }
    ctx.os << to << "\n";
}

/**
 * @brief Clasifica un stmt para fusion en `render_block`.
 *
 * Stmts hoja sin estructura propia (var-decls, expr-stmts) que
 * aparecen consecutivos en un bloque pueden fusionarse en un solo
 * nodo multi-linea para reducir clutter visual.  El @c group
 * agrupa por tipo + sub-estilo: solo stmts con el MISMO @c group
 * pueden fusionar.  Stmts de control (if/while/return/etc.) no
 * son fusables -- @c group queda vacio.
 */
struct StmtFusionInfo {
    std::string group;         // empty = no fusable
    std::string line;          // representacion en una linea
    const char *css = nullptr; // CSS class del nodo fusionado
};

StmtFusionInfo classify_stmt_for_fusion(const ast::Stmt *s) {
    StmtFusionInfo r;
    if (!s) return r;
    switch (s->kind) {
    case ast::NodeKind::VarDeclStmt: {
        auto *v = static_cast<const ast::VarDeclStmt *>(s);
        std::string ty = fmt_type(v->type.get());
        std::string lbl =
            (v->is_const ? "const " : std::string()) + ty + " " + v->name;
        if (v->init) lbl += " = " + fmt_expr(v->init.get());
        r.group = "var";
        r.line = lbl;
        r.css = "stmtVar";
        return r;
    }
    case ast::NodeKind::ExprStmt: {
        auto *e = static_cast<const ast::ExprStmt *>(s);
        if (!e->expr) {
            r.group = "noop";
            r.line = "(no-op)";
            r.css = "stmtAux";
            return r;
        }
        auto *expr = e->expr.get();
        r.line = fmt_expr(expr);
        if (expr->kind == ast::NodeKind::CallExpr ||
            expr->kind == ast::NodeKind::NewExpr) {
            r.group = "call";
            r.css = "stmtCall";
        } else if (expr->kind == ast::NodeKind::SpawnExpr ||
                   expr->kind == ast::NodeKind::RSpawnExpr) {
            r.group = "spawn";
            r.css = "stmtSpawn";
        } else if (expr->kind == ast::NodeKind::AssignExpr) {
            r.group = "assign";
            r.css = "stmtAssign";
        } else {
            r.group = "expr";
            r.css = "stmtExpr";
        }
        return r;
    }
    default: return r;
    }
}

/**
 * @brief Renderiza un BlockStmt: secuencia de stmts encadenados.
 *
 * Devuelve un par (entry_id, exit_id) representado como string
 * "entry|exit".  Si el bloque esta vacio, devuelve un nodo solo.
 *
 * Optimizacion visual: stmts consecutivos del MISMO tipo+sub-estilo
 * (var-decls, calls, assigns, ...) se FUSIONAN en un solo nodo
 * multi-linea distinguible para reducir clutter del grafo.  La
 * fusion preserva el orden y la informacion (cada linea conserva
 * la representacion completa del stmt original).  Stmts de
 * control (if/while/return/etc.) rompen el run -- siguen siendo
 * nodos individuales.
 */
std::string render_block(StmtCtx &ctx, const ast::BlockStmt *bs) {
    if (!bs || bs->body.empty()) {
        std::string nid = emit_node(ctx, "empty", "(empty block)", "stmtAux");
        return nid + "|" + nid;
    }
    std::string entry, prev_exit;
    // prev_terminal indica si el ultimo stmt del flujo fue terminal
    // (return/throw/break/continue/goto).  En ese caso los stmts
    // siguientes son inalcanzables; aparecen como dead code (sin edge).
    bool prev_terminal = false;
    // Acumulador de stmts fusables del run actual.
    std::vector<std::string> run_lines;
    std::string run_group;
    const char *run_css = nullptr;

    // Emite el run acumulado (1 nodo) y lo encadena al flow.
    auto flush_run = [&]() {
        if (run_lines.empty()) return;
        std::string nid;
        if (run_lines.size() == 1) {
            // Un solo elemento: render como nodo simple (mismo
            // aspecto que sin fusion, sin cabecera de grupo).
            nid = emit_node(ctx, run_group.c_str(), run_lines[0], run_css);
        } else {
            // Multi-elemento: nodo fusionado con encabezado de
            // grupo + lista de lineas.  emit_node escapa la label
            // entera, los `\n` se convierten a `<br/>`.
            std::string lbl =
                "[" + run_group + " x" + std::to_string(run_lines.size()) + "]";
            for (const auto &l : run_lines) {
                lbl += "\n";
                lbl += l;
            }
            nid = emit_node(ctx, run_group.c_str(), lbl, run_css);
        }
        if (entry.empty()) entry = nid;
        if (!prev_terminal && !prev_exit.empty()) {
            emit_edge(ctx, prev_exit, nid);
        }
        prev_exit = nid;
        prev_terminal = false;
        run_lines.clear();
        run_group.clear();
        run_css = nullptr;
    };

    for (const auto &s : bs->body) {
        StmtFusionInfo fi = classify_stmt_for_fusion(s.get());
        if (!fi.group.empty()) {
            if (run_group == fi.group) {
                run_lines.push_back(fi.line);
            } else {
                flush_run();
                run_group = fi.group;
                run_css = fi.css;
                run_lines.push_back(fi.line);
            }
            continue;
        }
        // No fusable -> flush + render normal del stmt.
        flush_run();
        std::string node_pair = render_stmt(ctx, s.get());
        std::string sentry = node_pair, sexit = node_pair;
        auto bar = node_pair.find('|');
        if (bar != std::string::npos) {
            sentry = node_pair.substr(0, bar);
            sexit = node_pair.substr(bar + 1);
        }
        if (entry.empty()) entry = sentry;
        if (!prev_terminal && !prev_exit.empty() && !sentry.empty()) {
            emit_edge(ctx, prev_exit, sentry);
        }
        prev_exit = sexit;
        prev_terminal = sexit.empty();
    }
    // Flush final del run pendiente al terminar el bloque.
    flush_run();

    if (entry.empty()) {
        std::string nid = emit_node(ctx, "empty", "(no stmts)", "stmtAux");
        return nid + "|" + nid;
    }
    return entry + "|" + prev_exit;
}

/**
 * @brief Renderiza un Stmt individual.  Devuelve "entry|exit" o
 *        solo un id si entry==exit (stmt simple).  Para stmts
 *        terminales (return, throw, break, continue, goto) el
 *        "exit" es el mismo nodo terminal -- el caller debe
 *        comprobar y NO seguir encadenando edges normales.
 */
std::string render_stmt(StmtCtx &ctx, const ast::Stmt *s) {
    if (!s) {
        return emit_node(ctx, "null", "(null stmt)", "stmtAux");
    }
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        auto *bs = static_cast<const ast::BlockStmt *>(s);
        return render_block(ctx, bs);
    }
    case ast::NodeKind::VarDeclStmt: {
        auto *v = static_cast<const ast::VarDeclStmt *>(s);
        std::string ty = fmt_type(v->type.get());
        std::string lbl = (v->is_const ? "const " : "") + ty + " " + v->name;
        if (v->init) {
            lbl += " = " + fmt_expr(v->init.get());
        }
        return emit_node(ctx, "var", lbl, "stmtVar");
    }
    case ast::NodeKind::ExprStmt: {
        auto *e = static_cast<const ast::ExprStmt *>(s);
        if (!e->expr) return emit_node(ctx, "noop", "(no-op)", "stmtAux");
        // Detectar llamadas para resaltar visualmente.
        const char *css = "stmtExpr";
        auto *expr = e->expr.get();
        if (expr->kind == ast::NodeKind::CallExpr ||
            expr->kind == ast::NodeKind::NewExpr) {
            css = "stmtCall";
        } else if (expr->kind == ast::NodeKind::SpawnExpr ||
                   expr->kind == ast::NodeKind::RSpawnExpr) {
            css = "stmtSpawn";
        } else if (expr->kind == ast::NodeKind::AssignExpr) {
            css = "stmtAssign";
        }
        return emit_node(ctx, "expr", fmt_expr(e->expr.get()), css);
    }
    case ast::NodeKind::IfStmt: {
        auto *iss = static_cast<const ast::IfStmt *>(s);
        std::string cond = emit_node_diamond(
            ctx, "if", "if " + fmt_expr(iss->cond.get()), "stmtIf");
        std::string merge = emit_node(ctx, "ifend", "(merge)", "stmtAux");

        // then branch
        std::string then_pair = render_stmt(ctx, iss->then_branch.get());
        std::string te = then_pair, tx = then_pair;
        auto bar = then_pair.find('|');
        if (bar != std::string::npos) {
            te = then_pair.substr(0, bar);
            tx = then_pair.substr(bar + 1);
        }
        emit_edge(ctx, cond, te, "true");
        // Solo conectar al merge si el then branch NO termina
        // (i.e., su exit no es vacio).  Si termina en return/throw,
        // el flow no llega al merge, y el edge seria visualmente
        // erroneo.
        if (!tx.empty()) emit_edge(ctx, tx, merge);

        if (iss->else_branch) {
            std::string else_pair = render_stmt(ctx, iss->else_branch.get());
            std::string ee = else_pair, ex = else_pair;
            auto ebar = else_pair.find('|');
            if (ebar != std::string::npos) {
                ee = else_pair.substr(0, ebar);
                ex = else_pair.substr(ebar + 1);
            }
            emit_edge(ctx, cond, ee, "false");
            if (!ex.empty()) emit_edge(ctx, ex, merge);
        } else {
            // sin else, la rama false va directa al merge.
            emit_edge(ctx, cond, merge, "false");
        }
        return cond + "|" + merge;
    }
    case ast::NodeKind::WhileStmt: {
        auto *ws = static_cast<const ast::WhileStmt *>(s);
        std::string head = emit_node_diamond(
            ctx, "while", "while " + fmt_expr(ws->cond.get()), "stmtLoop");
        std::string exit_id = emit_node(ctx, "wend", "(loop exit)", "stmtAux");
        ctx.loop_stack.push_back({head, exit_id});
        std::string body_pair = render_stmt(ctx, ws->body.get());
        ctx.loop_stack.pop_back();
        std::string be = body_pair, bx = body_pair;
        auto bar = body_pair.find('|');
        if (bar != std::string::npos) {
            be = body_pair.substr(0, bar);
            bx = body_pair.substr(bar + 1);
        }
        emit_edge(ctx, head, be, "true");
        emit_edge(ctx, head, exit_id, "false");
        if (!bx.empty()) emit_edge(ctx, bx, head, "back");
        return head + "|" + exit_id;
    }
    case ast::NodeKind::DoWhileStmt: {
        auto *dw = static_cast<const ast::DoWhileStmt *>(s);
        std::string entry = emit_node(ctx, "doentry", "do {", "stmtLoop");
        std::string cond = emit_node_diamond(
            ctx, "dowhile", "while " + fmt_expr(dw->cond.get()), "stmtLoop");
        std::string exit_id = emit_node(ctx, "dwend", "(loop exit)", "stmtAux");
        ctx.loop_stack.push_back({cond, exit_id});
        std::string body_pair = render_stmt(ctx, dw->body.get());
        ctx.loop_stack.pop_back();
        std::string be = body_pair, bx = body_pair;
        auto bar = body_pair.find('|');
        if (bar != std::string::npos) {
            be = body_pair.substr(0, bar);
            bx = body_pair.substr(bar + 1);
        }
        emit_edge(ctx, entry, be);
        if (!bx.empty()) emit_edge(ctx, bx, cond);
        emit_edge(ctx, cond, be, "true");
        emit_edge(ctx, cond, exit_id, "false");
        return entry + "|" + exit_id;
    }
    case ast::NodeKind::ForStmt: {
        auto *fs = static_cast<const ast::ForStmt *>(s);
        std::string init_id;
        if (fs->init) {
            std::string ip = render_stmt(ctx, fs->init.get());
            auto bar = ip.find('|');
            init_id = (bar == std::string::npos) ? ip : ip.substr(bar + 1);
        }
        std::string head = emit_node_diamond(
            ctx, "for",
            fs->cond ? ("for " + fmt_expr(fs->cond.get())) : "for (true)",
            "stmtLoop");
        std::string step_id;
        if (fs->step) {
            step_id = emit_node(
                ctx, "step", "step: " + fmt_expr(fs->step.get()), "stmtLoop");
        }
        std::string exit_id = emit_node(ctx, "fend", "(loop exit)", "stmtAux");
        std::string continue_target = step_id.empty() ? head : step_id;
        ctx.loop_stack.push_back({continue_target, exit_id});
        std::string body_pair = render_stmt(ctx, fs->body.get());
        ctx.loop_stack.pop_back();
        std::string be = body_pair, bx = body_pair;
        auto bar = body_pair.find('|');
        if (bar != std::string::npos) {
            be = body_pair.substr(0, bar);
            bx = body_pair.substr(bar + 1);
        }
        if (!init_id.empty()) emit_edge(ctx, init_id, head);
        emit_edge(ctx, head, be, "true");
        emit_edge(ctx, head, exit_id, "false");
        if (!bx.empty()) {
            if (!step_id.empty()) {
                emit_edge(ctx, bx, step_id);
                emit_edge(ctx, step_id, head, "back");
            } else {
                emit_edge(ctx, bx, head, "back");
            }
        } else if (!step_id.empty()) {
            // body termina en return/throw: el step es inalcanzable
            // pero lo dibujamos para reflejar la estructura del AST.
            emit_dotted(ctx, head, step_id, "step (skipped if return)");
            emit_edge(ctx, step_id, head, "back");
        }
        std::string entry = init_id.empty() ? head : init_id;
        return entry + "|" + exit_id;
    }
    case ast::NodeKind::ForEachStmt: {
        auto *fe = static_cast<const ast::ForEachStmt *>(s);
        std::string head = emit_node_diamond(
            ctx, "foreach",
            "for " + fmt_type(fe->iter_type.get()) + " " + fe->iter_name +
                " : " + fmt_expr(fe->iter_expr.get()),
            "stmtLoop");
        std::string exit_id = emit_node(ctx, "feend", "(loop exit)", "stmtAux");
        ctx.loop_stack.push_back({head, exit_id});
        std::string body_pair = render_stmt(ctx, fe->body.get());
        ctx.loop_stack.pop_back();
        std::string be = body_pair, bx = body_pair;
        auto bar = body_pair.find('|');
        if (bar != std::string::npos) {
            be = body_pair.substr(0, bar);
            bx = body_pair.substr(bar + 1);
        }
        emit_edge(ctx, head, be, "next");
        emit_edge(ctx, head, exit_id, "done");
        if (!bx.empty()) emit_edge(ctx, bx, head, "back");
        return head + "|" + exit_id;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *rs = static_cast<const ast::ReturnStmt *>(s);
        std::string lbl = "return";
        if (rs->value) lbl += " " + fmt_expr(rs->value.get());
        // Terminal: el flow NO continua tras return.  Devolvemos
        // "id|" (entry sin exit) para que el caller no encadene
        // edges hacia un merge que jamas se ejecutaria.
        return emit_node_round(ctx, "ret", lbl, "stmtTerminal") + "|";
    }
    case ast::NodeKind::ThrowStmt: {
        auto *ts = static_cast<const ast::ThrowStmt *>(s);
        std::string lbl = "throw";
        if (ts->value) lbl += " " + fmt_expr(ts->value.get());
        // Terminal local: el flow normal no continua aqui (puede
        // ser capturado por un try/catch enclosing, pero ese
        // edge se modela en TryStmt).
        return emit_node_round(ctx, "throw", lbl, "stmtThrow") + "|";
    }
    case ast::NodeKind::BreakStmt: {
        std::string n = emit_node_round(ctx, "brk", "break", "stmtBranch");
        if (!ctx.loop_stack.empty()) {
            emit_edge(ctx, n, ctx.loop_stack.back().break_target, "break");
        }
        // Terminal: tras break no hay flow secuencial al siguiente stmt.
        return n + "|";
    }
    case ast::NodeKind::ContinueStmt: {
        std::string n = emit_node_round(ctx, "cnt", "continue", "stmtBranch");
        if (!ctx.loop_stack.empty()) {
            emit_edge(ctx, n, ctx.loop_stack.back().continue_target,
                      "continue");
        }
        return n + "|";
    }
    case ast::NodeKind::GotoStmt: {
        auto *gs = static_cast<const ast::GotoStmt *>(s);
        std::string n =
            emit_node_round(ctx, "goto", "goto " + gs->label, "stmtBranch");
        auto it = ctx.labels.find(gs->label);
        if (it != ctx.labels.end()) {
            emit_dotted(ctx, n, it->second, "goto");
        }
        return n + "|";
    }
    case ast::NodeKind::LabelStmt: {
        auto *ls = static_cast<const ast::LabelStmt *>(s);
        std::string n = emit_node(ctx, "lbl", ls->name + ":", "stmtLabel");
        ctx.labels[ls->name] = n;
        return n;
    }
    case ast::NodeKind::TryStmt: {
        auto *ts = static_cast<const ast::TryStmt *>(s);
        std::string entry = emit_node(ctx, "try", "try {", "stmtTry");
        std::string merge = emit_node(ctx, "tryend", "(after try)", "stmtAux");
        std::string bp = render_block(ctx, ts->body.get());
        std::string be = bp, bx = bp;
        auto bar = bp.find('|');
        if (bar != std::string::npos) {
            be = bp.substr(0, bar);
            bx = bp.substr(bar + 1);
        }
        emit_edge(ctx, entry, be);
        if (!bx.empty()) emit_edge(ctx, bx, merge);
        for (size_t ci = 0; ci < ts->catches.size(); ++ci) {
            const auto &c = ts->catches[ci];
            std::string cls = c.exc_class_name.empty()
                                  ? std::string("(catch-all)")
                                  : c.exc_class_name;
            std::string handler = emit_node(
                ctx, "catch",
                "catch " + cls + (c.var_name.empty() ? "" : (" " + c.var_name)),
                "stmtCatch");
            std::string cp = render_block(ctx, c.body.get());
            std::string ce = cp, cx = cp;
            auto cbar = cp.find('|');
            if (cbar != std::string::npos) {
                ce = cp.substr(0, cbar);
                cx = cp.substr(cbar + 1);
            }
            emit_dotted(ctx, be, handler, "throw " + cls);
            emit_edge(ctx, handler, ce);
            if (!cx.empty()) emit_edge(ctx, cx, merge);
        }
        if (ts->finally_body) {
            std::string fp = render_block(ctx, ts->finally_body.get());
            std::string fe = fp, fx = fp;
            auto fbar = fp.find('|');
            if (fbar != std::string::npos) {
                fe = fp.substr(0, fbar);
                fx = fp.substr(fbar + 1);
            }
            std::string fnode =
                emit_node(ctx, "finally", "finally", "stmtFinally");
            emit_edge(ctx, merge, fnode);
            emit_edge(ctx, fnode, fe);
            std::string after =
                emit_node(ctx, "tryafter", "(after finally)", "stmtAux");
            if (!fx.empty()) emit_edge(ctx, fx, after);
            return entry + "|" + after;
        }
        return entry + "|" + merge;
    }
    case ast::NodeKind::SynchronizedStmt: {
        auto *ss = static_cast<const ast::SynchronizedStmt *>(s);
        std::string entry = emit_node(
            ctx, "sync", "synchronized (" + fmt_expr(ss->target.get()) + ")",
            "stmtSync");
        std::string bp = render_block(ctx, ss->body.get());
        std::string be = bp, bx = bp;
        auto bar = bp.find('|');
        if (bar != std::string::npos) {
            be = bp.substr(0, bar);
            bx = bp.substr(bar + 1);
        }
        std::string exit_id = emit_node(ctx, "syncend", "monexit", "stmtSync");
        emit_edge(ctx, entry, be);
        if (!bx.empty()) emit_edge(ctx, bx, exit_id);
        return entry + "|" + exit_id;
    }
    default: {
        // Stmts no manejados (raro): emite un nodo generico.
        return emit_node(
            ctx, "stmt",
            "<stmt kind=" + std::to_string(static_cast<int>(s->kind)) + ">",
            "stmtAux");
    }
    }
}

/**
 * @brief Renderiza el body completo de una FunctionDecl o ClassMethodDecl
 *        como un sub-grafo Mermaid.
 *
 * @param prefix     Prefijo de IDs para evitar colisiones (e.g. "fn0_").
 * @param title      Titulo del subgraph.
 * @param body       Cuerpo (puede ser null para metodos abstractos).
 */
void render_function_body_subgraph(std::ostringstream &os,
                                   const std::string &prefix,
                                   const std::string &title,
                                   const ast::BlockStmt *body) {
    os << "    subgraph " << prefix << "body [\"" << escape_label(title)
       << "\"]\n";
    os << "    direction TB\n";
    if (!body) {
        os << "        " << prefix
           << "abstract[\"(metodo abstracto)\"]:::stmtAux\n";
        os << "    end\n";
        return;
    }
    StmtCtx ctx{os, prefix, 0, {}, {}};
    std::string entry_id = prefix + "entry";
    os << "        " << entry_id << "[\"entry\"]:::stmtEntry\n";
    std::string bp = render_block(ctx, body);
    std::string be = bp, bx = bp;
    auto bar = bp.find('|');
    if (bar != std::string::npos) {
        be = bp.substr(0, bar);
        bx = bp.substr(bar + 1);
    }
    emit_edge(ctx, entry_id, be);
    // No emitimos un nodo "exit" porque return/throw ya marcan
    // terminacion explicita; el flow natural cae en el ultimo
    // stmt del bloque sin necesidad de un sink adicional.
    os << "    end\n";
}

} // namespace

// =========================================================================
//  API publica
// =========================================================================

namespace {

/// @brief Simbolo UML del modificador de acceso (0=public, 1=private,
///        2=protected).
const char *access_sym(uint8_t a) {
    switch (a) {
    case 1: return "-";
    case 2: return "#";
    default: return "+";
    }
}

} // namespace

std::string mermaid_types_from_ast(const ast::ModuleNode &mod) {
    std::ostringstream os;
    os << "```mermaid\n";
    os << "%% Diagrama de tipos Vesta (clases, herencia, interfaces, structs, "
          "enums)\n";
    os << "classDiagram\n";

    // Aristas de relacion recolectadas para emitir tras los nodos.
    std::vector<std::string> rels;

    for (const auto &node : mod.decls) {
        if (!node) continue;
        switch (node->kind) {
        case ast::NodeKind::ClassDecl: {
            auto *d = static_cast<const ast::ClassDecl *>(node.get());
            if (d->name.empty()) break;
            os << "    class " << d->name << " {\n";
            if (d->is_final) os << "        <<final>>\n";
            for (const auto &f : d->fields) {
                os << "        " << access_sym(f.access)
                   << fmt_type(f.type.get()) << ' ' << f.name;
                if (f.is_static)
                    os << "$"; // '$' = estatico en mermaid classDiagram.
                os << '\n';
            }
            for (const auto &m : d->methods) {
                if (!m || m->name.empty()) continue;
                os << "        " << access_sym(m->access) << m->name << "(";
                for (size_t i = 0; i < m->params.size(); ++i) {
                    if (i) os << ", ";
                    if (m->params[i]) os << fmt_type(m->params[i]->type.get());
                }
                os << ")";
                if (m->return_type) os << ' ' << fmt_type(m->return_type.get());
                if (m->is_static) os << "$";
                if (m->is_final || m->is_override)
                    os << "*"; // '*' = abstracto/override en mermaid.
                os << '\n';
            }
            os << "    }\n";
            // Herencia (solida) e interfaces (punteada).
            if (!d->super_name.empty())
                rels.push_back("    " + d->super_name + " <|-- " + d->name);
            for (const auto &iface : d->interface_names)
                rels.push_back("    " + iface + " <|.. " + d->name);
            break;
        }
        case ast::NodeKind::StructDecl: {
            auto *d = static_cast<const ast::StructDecl *>(node.get());
            if (d->name.empty()) break;
            os << "    class " << d->name << " {\n";
            os << "        <<struct>>\n";
            for (const auto &f : d->fields)
                os << "        +" << fmt_type(f.type.get()) << ' ' << f.name
                   << '\n';
            for (const auto &m : d->methods) {
                if (!m || m->name.empty()) continue;
                os << "        +" << m->name << "()";
                if (m->return_type) os << ' ' << fmt_type(m->return_type.get());
                os << '\n';
            }
            os << "    }\n";
            break;
        }
        case ast::NodeKind::EnumDecl: {
            auto *d = static_cast<const ast::EnumDecl *>(node.get());
            if (d->name.empty()) break;
            os << "    class " << d->name << " {\n";
            os << "        <<enumeration>>\n";
            if (!d->backing_type.empty())
                os << "        %% base: " << d->backing_type << '\n';
            for (const auto &v : d->variants)
                os << "        " << v.name << '\n';
            os << "    }\n";
            break;
        }
        case ast::NodeKind::ConceptDecl: {
            auto *d = static_cast<const ast::ConceptDecl *>(node.get());
            if (d->name.empty()) break;
            os << "    class " << d->name << " {\n";
            os << "        <<concept>>\n";
            os << "    }\n";
            break;
        }
        default: break;
        }
    }

    for (const auto &r : rels)
        os << r << '\n';

    os << "```\n";
    return os.str();
}

std::string mermaid_from_ast(const ast::ModuleNode &mod) {
    std::ostringstream os;
    os << "```mermaid\n";
    os << "%% Diagrama AST Vesta generado por VestaVM\n";
    os << "%% Cada nodo lleva la info relevante para debug:\n";
    os << "%%   funciones: nombre, return type, conteo de stmts del body\n";
    os << "%%   clases:    super, interfaces, fields, metodos con "
          "modificadores\n";
    os << "%%   structs/enums/globals: tipo y nombre\n";
    os << "flowchart TD\n";

    // Estilos por tipo de nodo (clases Mermaid)
    os << "    classDef moduleRoot "
          "fill:#1e3a8a,color:#fff,stroke:#1e3a8a,font-weight:bold\n";
    os << "    classDef funcDecl   fill:#15803d,color:#fff,stroke:#166534\n";
    os << "    classDef classDecl  fill:#7e22ce,color:#fff,stroke:#581c87\n";
    os << "    classDef structDecl fill:#b45309,color:#fff,stroke:#78350f\n";
    os << "    classDef enumDecl   fill:#0f766e,color:#fff,stroke:#134e4a\n";
    os << "    classDef globalDecl fill:#475569,color:#fff,stroke:#1e293b\n";
    os << "    classDef externDecl fill:#9d174d,color:#fff,stroke:#831843\n";
    os << "    classDef paramNode  fill:#dcfce7,color:#15803d,stroke:#166534\n";
    os << "    classDef fieldNode  fill:#fef3c7,color:#92400e,stroke:#78350f\n";
    os << "    classDef methodNode fill:#f3e8ff,color:#7e22ce,stroke:#581c87\n";
    os << "    classDef variantNode "
          "fill:#ccfbf1,color:#0f766e,stroke:#134e4a\n";
    os << "    classDef externRef  "
          "fill:#fce7f3,color:#9d174d,stroke:#831843,stroke-dasharray:5 5\n";
    // Estilos para nodos del control flow del body de funciones.
    os << "    classDef stmtEntry    "
          "fill:#1e293b,color:#fff,stroke:#0f172a,stroke-width:2px\n";
    os << "    classDef stmtVar      "
          "fill:#fef3c7,color:#92400e,stroke:#92400e\n";
    os << "    classDef stmtExpr     "
          "fill:#e0e7ff,color:#3730a3,stroke:#4338ca\n";
    os << "    classDef stmtCall     "
          "fill:#dbeafe,color:#1e40af,stroke:#1d4ed8,stroke-width:2px\n";
    os << "    classDef stmtAssign   "
          "fill:#fef3c7,color:#854d0e,stroke:#a16207\n";
    os << "    classDef stmtSpawn    "
          "fill:#fae8ff,color:#86198f,stroke:#86198f,stroke-width:2px\n";
    os << "    classDef stmtIf       "
          "fill:#fef9c3,color:#713f12,stroke:#a16207,stroke-width:2px\n";
    os << "    classDef stmtLoop     "
          "fill:#fed7aa,color:#9a3412,stroke:#c2410c,stroke-width:2px\n";
    os << "    classDef stmtTerminal "
          "fill:#dcfce7,color:#166534,stroke:#15803d,stroke-width:2px\n";
    os << "    classDef stmtThrow    "
          "fill:#fecaca,color:#991b1b,stroke:#b91c1c,stroke-width:2px\n";
    os << "    classDef stmtBranch   "
          "fill:#e9d5ff,color:#6b21a8,stroke:#7e22ce\n";
    os << "    classDef stmtLabel    "
          "fill:#cffafe,color:#155e75,stroke:#0e7490\n";
    os << "    classDef stmtTry      "
          "fill:#fde68a,color:#92400e,stroke:#a16207,stroke-width:2px\n";
    os << "    classDef stmtCatch    "
          "fill:#fca5a5,color:#7f1d1d,stroke:#991b1b\n";
    os << "    classDef stmtFinally  "
          "fill:#a7f3d0,color:#065f46,stroke:#047857\n";
    os << "    classDef stmtSync     "
          "fill:#fbcfe8,color:#831843,stroke:#9d174d,stroke-width:2px\n";
    os << "    classDef stmtAux      "
          "fill:#f1f5f9,color:#475569,stroke:#94a3b8,stroke-dasharray:3 3\n";

    os << "    M[\"Module<br/>"
       << escape_label(std::to_string(mod.decls.size()) + " top-level decls")
       << "\"]:::moduleRoot\n";

    // Acumulamos los nodos hoja (globals, externs) para emitirlos
    // consolidados al final.  Las funciones, clases, structs y enums
    // siguen siendo nodos individuales porque tienen estructura interna
    // propia (body subgraph, fields, methods, variants).
    std::vector<const ast::GlobalVarDecl *> globals;
    std::vector<const ast::ExternFnDecl *> externs;
    size_t fcount = 0, ccount = 0, scount = 0, ecount = 0;
    for (const auto &dn : mod.decls) {
        if (!dn) continue;
        switch (dn->kind) {
        case ast::NodeKind::FunctionDecl:
            render_function_decl(os, static_cast<ast::FunctionDecl *>(dn.get()),
                                 "M", fcount++);
            break;
        case ast::NodeKind::ClassDecl:
            render_class_decl(os, static_cast<ast::ClassDecl *>(dn.get()), "M",
                              ccount++);
            break;
        case ast::NodeKind::StructDecl:
            render_struct_decl(os, static_cast<ast::StructDecl *>(dn.get()),
                               "M", scount++);
            break;
        case ast::NodeKind::EnumDecl:
            render_enum_decl(os, static_cast<ast::EnumDecl *>(dn.get()), "M",
                             ecount++);
            break;
        case ast::NodeKind::GlobalVarDecl:
            globals.push_back(static_cast<ast::GlobalVarDecl *>(dn.get()));
            break;
        case ast::NodeKind::ExternFnDecl:
            externs.push_back(static_cast<ast::ExternFnDecl *>(dn.get()));
            break;
        default:
            // Otros tipos top-level no comunes (TypeAliasDecl, etc.):
            // los omitimos del diagrama para no saturarlo.  Si en el
            // futuro se quiere granularidad mayor, añadir aqui.
            break;
        }
    }
    render_globals_batch(os, globals, "M");
    render_externs_batch(os, externs, "M");

    os << "```\n";
    return os.str();
}

std::string mermaid_from_ir_module(const ir::IrModule &mod,
                                   const std::string &title,
                                   const analyze::ModuleCost *cost) {
    std::ostringstream os;
    os << "```mermaid\n";
    os << "%% " << title << "\n";
    os << "%% Modulo: " << mod.name << " (" << mod.functions.size()
       << " funciones)\n";
    os << "%% Cada subgraph = una funcion.  Cada nodo dentro = un IrBlock\n";
    os << "%% con sus instrucciones SSA.  Edges:\n";
    os << "%%   solid (-->)        = control flow incondicional (BR)\n";
    os << "%%   solid label true   = rama true de BR_COND\n";
    os << "%%   solid label false  = rama false de BR_COND\n";
    os << "%%   dotted (-..-)      = call inter-funcion (CALL/CALLN)\n";
    os << "flowchart TD\n";

    os << "    classDef irBlock  fill:#dbeafe,color:#1e3a8a,stroke:#1e40af\n";
    os << "    classDef irBranch fill:#fef9c3,color:#854d0e,stroke:#a16207\n";
    os << "    classDef irExit   fill:#fee2e2,color:#7f1d1d,stroke:#991b1b\n";

    // Mapa nombre_fn -> fn_id para resolver intra-calls al final.
    std::unordered_map<std::string, std::string> fn_id_by_name;
    for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
        fn_id_by_name[mod.functions[fi].name] = "fn" + std::to_string(fi);
    }

    std::unordered_set<std::string>
        intra_calls; // formato: "src_fn_id>callee_name"
    for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
        // --diagram-cost: si hay analisis de coste, anexar la etiqueta al
        // subgraph de cada funcion.
        std::string cost_label = cost ? analyze::cost_label_for_function(
                                            *cost, mod.functions[fi].name)
                                      : std::string();
        render_ir_function(os, mod.functions[fi], fi, intra_calls, cost_label);
    }

    // Edges cross-subgraph para llamadas
    for (const auto &edge : intra_calls) {
        auto pos = edge.find('>');
        if (pos == std::string::npos) continue;
        std::string src_fn = edge.substr(0, pos);
        std::string callee = edge.substr(pos + 1);
        auto it = fn_id_by_name.find(callee);
        if (it == fn_id_by_name.end())
            continue; // funcion externa, no la dibujamos
        // Edge punteado entre el subgraph fuente y el subgraph destino
        os << "    " << src_fn << " -.->|call| " << it->second << "\n";
    }

    // Expandir cada bloque de inline asm en su propio CFG anotado con coste
    // (latencia, throughput superescalar, cuello de botella por puerto, flags y
    // diagnosticos).  El microarq por defecto es el mismo que asume el
    // lowering.
    {
        int32_t ua =
            instr_db::microarch_by_name(instr_db::Isa::X86, "intel-skylake");
        const uint32_t skl = static_cast<uint32_t>(ua < 0 ? 0 : ua);
        for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
            const auto &fn = mod.functions[fi];
            for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
                const auto &bb = fn.blocks[bi];
                for (size_t ii = 0; ii < bb.instrs.size(); ++ii) {
                    const auto &ins = bb.instrs[ii];
                    if (ins.op != ir::IrOp::INLINE_ASM || ins.func_name.empty())
                        continue;
                    AsmDiagramOptions o;
                    o.isa = instr_db::Isa::X86;
                    o.ua_id = skl;
                    o.microarch = "intel-skylake";
                    o.id_prefix = "asmf" + std::to_string(fi) + "b" +
                                  std::to_string(bi) + "i" + std::to_string(ii);
                    o.title = "inline asm";
                    os << asm_cfg_mermaid(ins.func_name, o);
                    os << "    fn" << fi << "_b" << bi << " -.->|asm| "
                       << o.id_prefix << "_b0\n";
                }
            }
        }
    }

    os << "```\n";
    return os.str();
}

std::string mermaid_from_vel_text(const std::string &vel_text) {
    std::ostringstream os;
    os << "```mermaid\n";
    os << "%% Diagrama bytecode .vel (output final del frontend Vesta)\n";
    os << "%% Cada nodo = un label del .vel (bloque basico).\n";
    os << "%% Edges:\n";
    os << "%%   solid                = jmp incondicional al label\n";
    os << "%%   solid label cc       = jmp.cc condicional\n";
    os << "%%   solid label cmpjmp.cc = cmpjmp fusionado (cmps + jmp.cc)\n";
    os << "%%   dotted (call)        = callvm a otra funcion\n";
    os << "%% Opcodes destacados con borde:\n";
    os << "%%   cmpjmp/cmpjmpu/decjnz/gcallocp/spawnargs/fulfillhlt = "
          "optimizaciones recientes\n";
    os << "flowchart TD\n";

    os << "    classDef velBlock   fill:#e0f2fe,color:#075985,stroke:#0369a1\n";
    os << "    classDef velExit    fill:#fee2e2,color:#7f1d1d,stroke:#991b1b\n";
    os << "    classDef velOptInstr "
          "fill:#fef3c7,color:#92400e,stroke:#92400e,stroke-width:2px\n";

    // Parser linear del .vel: itera por lineas, agrupa por label.
    struct Block {
        std::string name;
        std::vector<std::string> instrs;
    };
    std::vector<Block> blocks;
    Block cur;
    bool in_block = false;

    std::istringstream iss(vel_text);
    std::string line;
    while (std::getline(iss, line)) {
        // Eliminar \r al final si viene de archivos Windows
        if (!line.empty() && line.back() == '\r') line.pop_back();

        std::string lbl;
        if (is_label_line(line, lbl)) {
            if (in_block) blocks.push_back(std::move(cur));
            cur = Block{};
            cur.name = lbl;
            in_block = true;
            continue;
        }
        if (!in_block) continue; // ignora directivas pre-modulo
        // Trim leading whitespace
        size_t i = 0;
        while (i < line.size() &&
               std::isspace(static_cast<unsigned char>(line[i])))
            ++i;
        if (i == line.size()) continue;
        if (line[i] == '/' && i + 1 < line.size() && line[i + 1] == '/')
            continue;                 // comentario
        if (line[i] == '@') continue; // directiva
        cur.instrs.push_back(line.substr(i));
    }
    if (in_block) blocks.push_back(std::move(cur));

    // Conjunto de labels existentes (para ignorar edges a externos no
    // presentes)
    std::unordered_set<std::string> known_labels;
    for (const auto &b : blocks)
        known_labels.insert(b.name);

    // Emit nodos sin truncamiento de instrs ni de longitud por linea.
    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        const auto &b = blocks[bi];
        std::ostringstream lbl;
        lbl << b.name << ":  (" << b.instrs.size() << " instrs)";
        bool has_opt = false;
        for (const auto &ins : b.instrs) {
            lbl << "<br/>" << escape_label(ins);
            std::string mn = get_mnemonic(ins);
            if (is_fused_instr(mn)) has_opt = true;
        }
        std::string css = has_opt ? "velOptInstr" : "velBlock";
        // Detectar terminador para clase de exit
        if (!b.instrs.empty()) {
            std::string last_mn = get_mnemonic(b.instrs.back());
            if (last_mn == "ret" || last_mn == "hlt" ||
                last_mn == "fulfillhlt") {
                css = "velExit";
            }
        }
        std::string node_id = "vb" + std::to_string(bi);
        os << "    " << node_id << "[\"" << lbl.str() << "\"]:::" << css
           << "\n";
    }

    // Emit edges segun saltos detectados
    std::unordered_map<std::string, size_t> idx_by_name;
    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        idx_by_name[blocks[bi].name] = bi;
    }

    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        const auto &b = blocks[bi];
        std::string src = "vb" + std::to_string(bi);
        // Recorre instrucciones; cualquiera que tenga @Absolute("code.X")
        // genera un edge.  Distingue por mnemonic el tipo (call vs jmp vs
        // cmpjmp vs decjnz, etc.).
        for (const auto &ins : b.instrs) {
            std::string target = extract_abs_target(ins);
            if (target.empty()) continue;
            auto it = idx_by_name.find(target);
            if (it == idx_by_name.end())
                continue; // target externo (otro modulo)
            std::string dst = "vb" + std::to_string(it->second);
            std::string mn = get_mnemonic(ins);

            // Edge labels en .vel diagram: encerrar en quotes para que
            // mnemonics con caracteres especiales no rompan el parser
            // Mermaid (mismo razonamiento que en emit_edge / emit_dotted).
            if (is_call_mnemonic(mn)) {
                os << "    " << src << " -.->|\"" << escape_label(mn) << "\"| "
                   << dst << "\n";
            } else if (mn == "jmp") {
                os << "    " << src << " --> " << dst << "\n";
            } else if (mn.size() >= 4 && mn.substr(0, 4) == "jmp.") {
                os << "    " << src << " -->|\"" << escape_label(mn) << "\"| "
                   << dst << "\n";
            } else if (mn.size() >= 7 && mn.substr(0, 7) == "cmpjmp.") {
                os << "    " << src << " -->|\"" << escape_label(mn) << "\"| "
                   << dst << "\n";
            } else if (mn.size() >= 8 && mn.substr(0, 8) == "cmpjmpu.") {
                os << "    " << src << " -->|\"" << escape_label(mn) << "\"| "
                   << dst << "\n";
            } else if (mn == "decjnz") {
                os << "    " << src << " -->|decjnz| " << dst << "\n";
            } else {
                // direccion absoluta de uso desconocido (e.g. mov reg,
                // @Absolute("code.s_N") para literales).  Lo dibujamos con
                // label "ref" para no perder la traza.
                if (mn != "mov") {
                    os << "    " << src << " -..->|\"" << escape_label(mn)
                       << "\"| " << dst << "\n";
                }
            }
        }

        // Fall-through: el bloque CAE al siguiente bloque secuencial si su
        // ultima instruccion NO es un terminador incondicional
        // (jmp / ret / hlt / fulfillhlt / tailcall).  Cubre labels de 0
        // instrs (caen al _entry) y saltos condicionales (rama no-tomada).
        if (bi + 1 < blocks.size()) {
            bool falls = true;
            if (!b.instrs.empty()) {
                const std::string last_mn = get_mnemonic(b.instrs.back());
                if (last_mn == "jmp" || last_mn == "ret" || last_mn == "hlt" ||
                    last_mn == "fulfillhlt" || last_mn == "tailcall") {
                    falls = false;
                }
            }
            if (falls) {
                const std::string dst = "vb" + std::to_string(bi + 1);
                os << "    " << src << " -->|fall| " << dst << "\n";
            }
        }
    }

    os << "```\n";
    return os.str();
}

} // namespace vx
