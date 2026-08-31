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
 * @file graphviz_diagrams.cpp
 * @brief Implementacion de los generadores Graphviz (DOT) para AST/IR/VEL.
 *
 * Equivalente al modulo Mermaid pero produciendo DOT.  La logica de
 * traversal del AST/IR/VEL es la misma; lo que cambia es la sintaxis
 * de emision: en lugar de `A["label"]:::class` emitimos
 * `A [label="...", shape=box, fillcolor="#xxx", style=filled];` y en
 * lugar de `subgraph X [...] ... end` emitimos `subgraph cluster_X
 * { label="..."; ... }`.
 *
 * El output esta orientado a debug y traceo, NO a presentacion: prima la
 * informacion sobre la estetica (igual que Mermaid).  La diferencia es
 * que DOT permite atributos arbitrarios (tooltip, URL, fontname, ...) que
 * Mermaid no admite, asi que aprovechamos para emitir tooltips con info
 * extra que en Mermaid quedaria fuera del label.
 */

#include "vx/diagram/graphviz_diagrams.h"

#include "vx/asm/asm_diagram.h" // expansion del CFG de inline asm con coste
#include "vx/diagram/diagram_labels.h" // como se lee cada cosa
#include "vx/diagram/vel_text_model.h" // que se lee del .vel, comun a los dos

#include "analyze/bigo.h"
#include "vx/ast.h"
#include "ir/ssa_ir.h"
#include "vx/types.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace vx {

namespace {

// =====================================================================
//  Helpers comunes
// =====================================================================

/**
 * @brief Escapa un string para que sea seguro dentro de un label DOT.
 *
 * En DOT los labels van entre comillas dobles.  Caracteres a escapar:
 *   "  -> \"
 *   \\ -> \\\\
 *   \n -> \\n  (DOT renderiza \\n como salto)
 *   \r -> (eliminado)
 *
 * Otros caracteres (`<`, `>`, `&`, etc.) se aceptan literales: DOT
 * solo trata como sintaxis los `<` `>` cuando son HTML-like labels
 * (encerrados en angle brackets en lugar de comillas), modo que NO
 * usamos aqui.  Para nuestro caso de labels estandar quoted, no hay
 * que escapar HTML entities.
 */
// NS: convierte el separador de mangling `__` en `.` para mostrar los nombres
// de namespace cualificados (org__geo__shapes__area -> org.geo.shapes.area).
// Preserva un `__` INICIAL (nombres sinteticos: __module_init, __new_X).
static std::string ns_demangle(const std::string &s_in) {
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
    return s;
}

std::string escape_label(const std::string &s_raw) {
    const std::string s = ns_demangle(s_raw);
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': break;
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
 * @brief Escapa un string para usar en un campo de un nodo `record`.
 *
 * Records son nodos con estructura: `label="campo1 | campo2 | { sub1 | sub2
 * }"`. Los caracteres `{`, `}`, `|`, `<`, `>` son sintaxis del record y deben
 * ir escapados con `\` cuando aparecen como contenido literal.
 */
std::string escape_record(const std::string &s_raw) {
    const std::string s = ns_demangle(s_raw);
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\l"; break; // \\l = left-justify newline en records
        case '\r': break;
        case '{': out += "\\{"; break;
        case '}': out += "\\}"; break;
        case '|': out += "\\|"; break;
        case '<': out += "\\<"; break;
        case '>': out += "\\>"; break;
        default:
            if (static_cast<unsigned char>(c) < 32) {
                out += ' ';
            } else {
                out += c;
            }
        }
    }
    return out;
}

// Forward decls.
void render_function_body_subgraph(std::ostringstream &os,
                                   const std::string &cluster_id,
                                   const std::string &title,
                                   const ast::BlockStmt *body);

size_t count_stmts(const ast::Stmt *s) {
    if (!s) return 0;
    if (s->kind == ast::NodeKind::BlockStmt) {
        auto *bs = static_cast<const ast::BlockStmt *>(s);
        size_t total = 0;
        for (const auto &st : bs->body)
            total += count_stmts(st.get());
        return total > 0 ? total : 1;
    }
    return 1;
}

// =====================================================================
//  Atributos por tipo de nodo (estilos visuales)
// =====================================================================
//
// En lugar de classDef/Mermaid usamos atributos directos en cada nodo.
// Estructurados como const-refs para evitar duplicacion en cada call.
// El paleta es CONSISTENTE con la version Mermaid para que un usuario
// que cambie de formato encuentre el mismo lenguaje visual.

struct NodeStyle {
    const char *shape;
    const char *fillcolor;
    const char *fontcolor;
    const char *color; // border color
    const char *style; // filled, rounded, bold, dashed
    int penwidth;
};

// Paleta: usar el mismo color hex que Mermaid donde sea posible.
const NodeStyle ST_MODULE = {"box3d",   "#1e3a8a",     "#ffffff",
                             "#1e3a8a", "filled,bold", 2};
const NodeStyle ST_FUNC = {"box",     "#15803d",        "#ffffff",
                           "#166534", "filled,rounded", 1};
const NodeStyle ST_CLASS = {"box",     "#7e22ce",        "#ffffff",
                            "#581c87", "filled,rounded", 1};
const NodeStyle ST_STRUCT = {"box",     "#b45309",        "#ffffff",
                             "#78350f", "filled,rounded", 1};
const NodeStyle ST_ENUM = {"box",     "#0f766e",        "#ffffff",
                           "#134e4a", "filled,rounded", 1};
const NodeStyle ST_GLOBAL = {"box",     "#475569",        "#ffffff",
                             "#1e293b", "filled,rounded", 1};
const NodeStyle ST_EXTERN = {"box",     "#9d174d",        "#ffffff",
                             "#831843", "filled,rounded", 1};
const NodeStyle ST_PARAM = {"ellipse", "#dcfce7", "#15803d",
                            "#166534", "filled",  1};
const NodeStyle ST_FIELD = {"note",    "#fef3c7", "#92400e",
                            "#78350f", "filled",  1};
const NodeStyle ST_METHOD = {"box",     "#f3e8ff",        "#7e22ce",
                             "#581c87", "filled,rounded", 1};
const NodeStyle ST_VARIANT = {"ellipse", "#ccfbf1", "#0f766e",
                              "#134e4a", "filled",  1};
const NodeStyle ST_EXTREF = {"box",     "#fce7f3",       "#9d174d",
                             "#831843", "filled,dashed", 1};
// Stmts del control flow
const NodeStyle ST_ENTRY = {"circle",  "#1e293b",     "#ffffff",
                            "#0f172a", "filled,bold", 2};
const NodeStyle ST_VAR = {"box",     "#fef3c7",        "#92400e",
                          "#92400e", "filled,rounded", 1};
const NodeStyle ST_EXPR = {"box",     "#e0e7ff",        "#3730a3",
                           "#4338ca", "filled,rounded", 1};
const NodeStyle ST_CALL = {
    "box", "#dbeafe", "#1e40af", "#1d4ed8", "filled,rounded,bold", 2};
const NodeStyle ST_ASSIGN = {"box",     "#fef3c7",        "#854d0e",
                             "#a16207", "filled,rounded", 1};
const NodeStyle ST_SPAWN = {"doubleoctagon", "#fae8ff",     "#86198f",
                            "#86198f",       "filled,bold", 2};
const NodeStyle ST_IF = {"diamond", "#fef9c3",     "#713f12",
                         "#a16207", "filled,bold", 2};
const NodeStyle ST_LOOP = {"diamond", "#fed7aa",     "#9a3412",
                           "#c2410c", "filled,bold", 2};
const NodeStyle ST_LOOP_BODY = {"box",     "#fed7aa",        "#9a3412",
                                "#c2410c", "filled,rounded", 1};
const NodeStyle ST_TERMINAL = {"doublecircle", "#dcfce7",     "#166534",
                               "#15803d",      "filled,bold", 2};
const NodeStyle ST_THROW = {"doublecircle", "#fecaca",     "#991b1b",
                            "#b91c1c",      "filled,bold", 2};
const NodeStyle ST_BRANCH = {"octagon", "#e9d5ff", "#6b21a8",
                             "#7e22ce", "filled",  1};
const NodeStyle ST_LABEL = {"tab",     "#cffafe", "#155e75",
                            "#0e7490", "filled",  1};
const NodeStyle ST_TRY = {
    "box", "#fde68a", "#92400e", "#a16207", "filled,rounded,bold", 2};
const NodeStyle ST_CATCH = {"box",     "#fca5a5",        "#7f1d1d",
                            "#991b1b", "filled,rounded", 1};
const NodeStyle ST_FINALLY = {"box",     "#a7f3d0",        "#065f46",
                              "#047857", "filled,rounded", 1};
const NodeStyle ST_SYNC = {
    "box", "#fbcfe8", "#831843", "#9d174d", "filled,rounded,bold", 2};
const NodeStyle ST_AUX = {
    "box", "#f1f5f9", "#475569", "#94a3b8", "filled,dashed,rounded", 1};
// IR blocks
const NodeStyle ST_IRBLOCK = {"box",     "#dbeafe",        "#1e3a8a",
                              "#1e40af", "filled,rounded", 1};
const NodeStyle ST_IRBRANCH = {"box",     "#fef9c3",        "#854d0e",
                               "#a16207", "filled,rounded", 1};
const NodeStyle ST_IREXIT = {
    "box", "#fee2e2", "#7f1d1d", "#991b1b", "filled,rounded,bold", 2};
// VEL blocks
const NodeStyle ST_VELBLOCK = {"box",     "#e0f2fe",        "#075985",
                               "#0369a1", "filled,rounded", 1};
const NodeStyle ST_VELEXIT = {
    "box", "#fee2e2", "#7f1d1d", "#991b1b", "filled,rounded,bold", 2};
const NodeStyle ST_VELOPT = {
    "box", "#fef3c7", "#92400e", "#92400e", "filled,rounded,bold", 2};

/**
 * @brief Emite un nodo DOT con la NodeStyle dada.
 *
 * Acepta un tooltip opcional con info extra que aparece al hover en
 * herramientas interactivas (xdot, Graphviz Online, browsers SVG).
 */
void emit_node(std::ostringstream &os, const std::string &id,
               const std::string &label, const NodeStyle &st,
               const std::string &tooltip = "") {
    os << "    " << id << " [label=\"" << escape_label(label) << "\"";
    os << ", shape=" << st.shape;
    os << ", fillcolor=\"" << st.fillcolor << "\"";
    os << ", fontcolor=\"" << st.fontcolor << "\"";
    os << ", color=\"" << st.color << "\"";
    os << ", style=\"" << st.style << "\"";
    os << ", penwidth=" << st.penwidth;
    if (!tooltip.empty()) {
        os << ", tooltip=\"" << escape_label(tooltip) << "\"";
    }
    os << "];\n";
}

/**
 * @brief Emite un nodo `record` (multi-celda) con la NodeStyle dada.
 *
 * Records permiten estructurar el contenido en celdas separadas por
 * `|`.  Util para mostrar lista de instrucciones de un IrBlock o
 * de un label .vel.
 */
void emit_record(std::ostringstream &os, const std::string &id,
                 const std::string &record_label, const NodeStyle &st,
                 const std::string &tooltip = "") {
    os << "    " << id << " [label=\"" << record_label << "\"";
    os << ", shape=record";
    os << ", fillcolor=\"" << st.fillcolor << "\"";
    os << ", fontcolor=\"" << st.fontcolor << "\"";
    os << ", color=\"" << st.color << "\"";
    os << ", style=\"" << st.style << "\"";
    os << ", penwidth=" << st.penwidth;
    if (!tooltip.empty()) {
        os << ", tooltip=\"" << escape_label(tooltip) << "\"";
    }
    os << "];\n";
}

/**
 * @brief Emite un edge con label opcional y style segun tipo de flow.
 */
enum class EdgeKind { Solid, Dotted, Dashed, Bold };
void emit_edge(std::ostringstream &os, const std::string &from,
               const std::string &to, const std::string &label = "",
               EdgeKind kind = EdgeKind::Solid, const std::string &color = "") {
    os << "    " << from << " -> " << to;
    std::vector<std::string> attrs;
    if (!label.empty()) {
        attrs.push_back("label=\"" + escape_label(label) + "\"");
    }
    switch (kind) {
    case EdgeKind::Dotted: attrs.push_back("style=\"dotted\""); break;
    case EdgeKind::Dashed: attrs.push_back("style=\"dashed\""); break;
    case EdgeKind::Bold:
        attrs.push_back("style=\"bold\"");
        attrs.push_back("penwidth=2");
        break;
    case EdgeKind::Solid: break;
    }
    if (!color.empty()) {
        attrs.push_back("color=\"" + color + "\"");
    }
    if (!attrs.empty()) {
        os << " [";
        for (size_t i = 0; i < attrs.size(); ++i) {
            if (i) os << ", ";
            os << attrs[i];
        }
        os << "]";
    }
    os << ";\n";
}

// =====================================================================
//  GENERADOR 1: AST Vesta -> Graphviz
// =====================================================================

void render_function_decl(std::ostringstream &os, const ast::FunctionDecl *fd,
                          const std::string &parent_id, size_t idx) {
    const std::string fid = "F_" + std::to_string(idx);
    std::string ret_type = fmt_type(fd->return_type.get());
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
        body_info = "body: " + std::to_string(n) + " stmts";
    } else {
        body_info = "(declaracion sin body)";
    }
    std::string tooltip = title + "\nFile: line " +
                          std::to_string(fd->loc.line) + "\n" + body_info;
    emit_node(os, fid, title + "\n" + body_info, ST_FUNC, tooltip);
    emit_edge(os, parent_id, fid);

    if (fd->body) {
        std::string body_cluster = fid + "_body";
        std::string body_title = fd->name + "() body";
        render_function_body_subgraph(os, body_cluster, body_title,
                                      fd->body.get());
        emit_edge(os, fid, body_cluster + "_entry", "body", EdgeKind::Dotted);
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
    std::string tooltip =
        title + "\n" + sub + "\nLine: " + std::to_string(cd->loc.line);
    emit_node(os, cid, title + "\n" + sub, ST_CLASS, tooltip);
    emit_edge(os, parent_id, cid);

    if (!cd->super_name.empty()) {
        std::string sid = cid + "_super";
        emit_node(os, sid, cd->super_name, ST_EXTREF,
                  "extends " + cd->super_name);
        emit_edge(os, cid, sid, "extends", EdgeKind::Bold);
    }
    // Interfaces consolidadas en un solo nodo lista (el padre tenia
    // multiples hijos del mismo tipo y todos eran nodos hoja sin
    // estructura interna).
    if (!cd->interface_names.empty()) {
        const std::string iid = cid + "_ifaces";
        std::ostringstream lbl;
        lbl << "Interfaces (" << cd->interface_names.size() << ")";
        std::ostringstream tip;
        tip << cd->name << " implements:\n";
        for (const auto &iname : cd->interface_names) {
            lbl << "\n" << iname;
            tip << iname << "\n";
        }
        emit_node(os, iid, lbl.str(), ST_EXTREF, tip.str());
        emit_edge(os, cid, iid, "implements", EdgeKind::Solid, "#9d174d");
    }

    // Fields consolidados en un solo nodo lista.  Sin truncamiento.
    if (!cd->fields.empty()) {
        const std::string fid = cid + "_fields";
        std::ostringstream lbl;
        lbl << "Fields (" << cd->fields.size() << ")";
        std::ostringstream tip;
        tip << cd->name << " fields:\n";
        for (const auto &f : cd->fields) {
            std::string acc = (f.access == 1)   ? "private "
                              : (f.access == 2) ? "protected "
                                                : "public ";
            std::string mods;
            if (f.is_static) mods += "static ";
            if (f.is_final) mods += "final ";
            std::string line =
                acc + mods + fmt_type(f.type.get()) + " " + f.name;
            tip << line << "\n";
            lbl << "\n" << line;
        }
        emit_node(os, fid, lbl.str(), ST_FIELD, tip.str());
        emit_edge(os, cid, fid, "fields", EdgeKind::Dotted);
    }
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
        std::string sig = acc + mods + ret + " " + m->name + "(";
        for (size_t pi = 0; pi < m->params.size(); ++pi) {
            if (pi) sig += ", ";
            sig +=
                fmt_type(m->params[pi]->type.get()) + " " + m->params[pi]->name;
        }
        sig += ")";
        std::string body_info =
            m->body ? (std::to_string(count_stmts(m->body.get())) + " stmts")
                    : std::string("(abstract)");
        std::string tooltip2 =
            sig + "\n" + body_info + "\nLine: " + std::to_string(m->loc.line);
        emit_node(os, mid, sig + "\n" + body_info, ST_METHOD, tooltip2);
        emit_edge(os, cid, mid, "method");

        if (m->body) {
            std::string body_cluster = mid + "_body";
            std::string body_title = cd->name + "." + m->name + "() body";
            render_function_body_subgraph(os, body_cluster, body_title,
                                          m->body.get());
            emit_edge(os, mid, body_cluster + "_entry", "body",
                      EdgeKind::Dotted);
        }
    }
}

void render_struct_decl(std::ostringstream &os, const ast::StructDecl *sd,
                        const std::string &parent_id, size_t idx) {
    const std::string sid = "S_" + std::to_string(idx);
    std::string title = "struct " + sd->name + " (" +
                        std::to_string(sd->fields.size()) + " fields)";
    std::string tooltip = title + "\nLine: " + std::to_string(sd->loc.line);
    emit_node(os, sid, title, ST_STRUCT, tooltip);
    emit_edge(os, parent_id, sid);
    // Fields consolidados en un solo nodo lista.  Sin truncamiento.
    if (!sd->fields.empty()) {
        const std::string fid = sid + "_fields";
        std::ostringstream lbl;
        lbl << "Fields (" << sd->fields.size() << ")";
        std::ostringstream tip;
        tip << sd->name << " fields:\n";
        for (const auto &f : sd->fields) {
            std::string line = fmt_type(f.type.get()) + " " + f.name;
            if (f.bit_width > 0) {
                line += " : " + std::to_string(f.bit_width);
            }
            tip << line << "\n";
            lbl << "\n" << line;
        }
        emit_node(os, fid, lbl.str(), ST_FIELD, tip.str());
        emit_edge(os, sid, fid, "fields", EdgeKind::Dotted);
    }
}

void render_enum_decl(std::ostringstream &os, const ast::EnumDecl *ed,
                      const std::string &parent_id, size_t idx) {
    const std::string eid = "E_" + std::to_string(idx);
    std::string title = "enum " + ed->name + " (" +
                        std::to_string(ed->variants.size()) + " variants)";
    emit_node(os, eid, title, ST_ENUM,
              title + "\nLine: " + std::to_string(ed->loc.line));
    emit_edge(os, parent_id, eid);
    // Variants consolidados en un solo nodo lista.  Sin truncamiento.
    if (!ed->variants.empty()) {
        const std::string vid = eid + "_variants";
        std::ostringstream lbl;
        lbl << "Variants (" << ed->variants.size() << ")";
        std::ostringstream tip;
        tip << ed->name << " variants:\n";
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
            tip << line << "\n";
            lbl << "\n" << line;
        }
        emit_node(os, vid, lbl.str(), ST_VARIANT, tip.str());
        emit_edge(os, eid, vid, "variants", EdgeKind::Dotted);
    }
}

/**
 * @brief Renderiza TODOS los globals/constants top-level como un solo
 *        nodo con la lista (consolidado).  Mismo motivo que en Mermaid:
 *        un nodo por global saturaba grafos de modulos con muchas
 *        constantes (e.g. el editor TUI declara ~80 `const i32 KEY_*`).
 *
 * El tooltip lleva la lista COMPLETA aunque la label solo muestre
 * los primeros N -- asi el usuario puede inspeccionar todos los
 * valores haciendo hover en el SVG sin saturar el layout.
 */
void render_globals_batch(
    std::ostringstream &os,
    const std::vector<const ast::GlobalVarDecl *> &globals,
    const std::string &parent_id) {
    if (globals.empty()) return;
    const std::string gid = "G_all";
    std::ostringstream lbl;
    lbl << "Globals/Constants (" << globals.size() << ")";
    std::ostringstream tip;
    tip << globals.size() << " globals/constants:\n";
    // Sin truncamiento: emitimos TODOS los globals con su expresion
    // completa.  Pase 1 const, pase 2 var-globals.
    for (const auto *gv : globals) {
        if (!gv->is_const) continue;
        std::string line =
            std::string("const ") + fmt_type(gv->type.get()) + " " + gv->name;
        if (gv->init) {
            line += " = " + fmt_expr_brief(gv->init.get(), 32);
        }
        tip << line << "\n";
        lbl << "\n" << line;
    }
    for (const auto *gv : globals) {
        if (gv->is_const) continue;
        std::string line = fmt_type(gv->type.get()) + " " + gv->name;
        if (gv->init) {
            line += " = " + fmt_expr_brief(gv->init.get(), 32);
        }
        tip << line << "\n";
        lbl << "\n" << line;
    }
    emit_node(os, gid, lbl.str(), ST_GLOBAL, tip.str());
    emit_edge(os, parent_id, gid);
}

/**
 * @brief Renderiza TODOS los `extern fn` top-level como un solo nodo
 *        consolidado, agrupados por libreria nativa.
 *
 * Mismo motivo que globals: cada extern es un nodo hoja sin
 * estructura propia.  Para preservar distinguibilidad cuando el
 * modulo importa de varias librerias, agrupamos por @c lib y emitimos
 * un encabezado por libreria seguido de las funciones declaradas.
 */
void render_externs_batch(std::ostringstream &os,
                          const std::vector<const ast::ExternFnDecl *> &externs,
                          const std::string &parent_id) {
    if (externs.empty()) return;
    const std::string xid = "X_all";
    std::vector<std::string> lib_order;
    std::unordered_map<std::string, std::vector<const ast::ExternFnDecl *>>
        by_lib;
    for (const auto *ef : externs) {
        if (by_lib.find(ef->lib) == by_lib.end()) lib_order.push_back(ef->lib);
        by_lib[ef->lib].push_back(ef);
    }
    std::ostringstream lbl;
    lbl << "Externs (" << externs.size() << ")";
    std::ostringstream tip;
    tip << externs.size() << " extern functions:\n";
    // Sin truncamiento: TODOS los externs con sus tipos completos.
    for (const auto &lib : lib_order) {
        lbl << "\n--- " << lib << " ---";
        tip << "--- " << lib << " ---\n";
        for (const auto *ef : by_lib[lib]) {
            std::string ret = fmt_type(ef->return_type.get());
            std::string line = ret + " " + ef->name + "(";
            for (size_t pi = 0; pi < ef->params.size(); ++pi) {
                if (pi) line += ", ";
                line += fmt_type(ef->params[pi]->type.get()) + " " +
                        ef->params[pi]->name;
            }
            line += ")";
            tip << line << "\n";
            lbl << "\n" << line;
        }
    }
    emit_node(os, xid, lbl.str(), ST_EXTERN, tip.str());
    emit_edge(os, parent_id, xid);
}

// =====================================================================
//  Render del cuerpo de funciones (control flow)
// =====================================================================

struct StmtCtx {
    std::ostringstream &os;
    std::string prefix;
    int next_id = 0;
    struct LoopFrame {
        std::string continue_target;
        std::string break_target;
    };
    std::vector<LoopFrame> loop_stack;
    std::unordered_map<std::string, std::string> labels;

    std::string fresh(const char *kind) {
        return prefix + kind + std::to_string(next_id++);
    }
};

std::string render_stmt(StmtCtx &ctx, const ast::Stmt *s);
std::string render_block(StmtCtx &ctx, const ast::BlockStmt *bs);

std::string emit_stmt_node(StmtCtx &ctx, const char *kind,
                           const std::string &label, const NodeStyle &st,
                           const std::string &tooltip = "") {
    std::string id = ctx.fresh(kind);
    emit_node(ctx.os, id, label, st, tooltip);
    return id;
}

/**
 * @brief Clasifica un stmt para fusion en `render_block`.  Misma
 *        semantica que la version Mermaid: stmts hoja consecutivos
 *        del mismo grupo se colapsan en un nodo multi-linea.
 */
struct StmtFusionInfo {
    std::string group; // empty = no fusable
    std::string line;
    const NodeStyle *style = nullptr;
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
        r.style = &ST_VAR;
        return r;
    }
    case ast::NodeKind::ExprStmt: {
        auto *e = static_cast<const ast::ExprStmt *>(s);
        if (!e->expr) {
            r.group = "noop";
            r.line = "(no-op)";
            r.style = &ST_AUX;
            return r;
        }
        auto *expr = e->expr.get();
        r.line = fmt_expr(expr);
        if (expr->kind == ast::NodeKind::CallExpr ||
            expr->kind == ast::NodeKind::NewExpr) {
            r.group = "call";
            r.style = &ST_CALL;
        } else if (expr->kind == ast::NodeKind::SpawnExpr ||
                   expr->kind == ast::NodeKind::RSpawnExpr) {
            r.group = "spawn";
            r.style = &ST_SPAWN;
        } else if (expr->kind == ast::NodeKind::AssignExpr) {
            r.group = "assign";
            r.style = &ST_ASSIGN;
        } else {
            r.group = "expr";
            r.style = &ST_EXPR;
        }
        return r;
    }
    default: return r;
    }
}

std::string render_block(StmtCtx &ctx, const ast::BlockStmt *bs) {
    if (!bs || bs->body.empty()) {
        std::string nid = emit_stmt_node(ctx, "empty", "(empty block)", ST_AUX);
        return nid + "|" + nid;
    }
    std::string entry, prev_exit;
    bool prev_terminal = false;
    // Acumulador de stmts fusables del run actual.
    std::vector<std::string> run_lines;
    std::string run_group;
    const NodeStyle *run_style = nullptr;

    auto flush_run = [&]() {
        if (run_lines.empty()) return;
        std::string nid = ctx.fresh(run_group.c_str());
        if (run_lines.size() == 1) {
            emit_node(ctx.os, nid, run_lines[0], *run_style);
        } else {
            std::string lbl =
                "[" + run_group + " x" + std::to_string(run_lines.size()) + "]";
            for (const auto &l : run_lines) {
                lbl += "\n";
                lbl += l;
            }
            emit_node(ctx.os, nid, lbl, *run_style);
        }
        if (entry.empty()) entry = nid;
        if (!prev_terminal && !prev_exit.empty()) {
            emit_edge(ctx.os, prev_exit, nid);
        }
        prev_exit = nid;
        prev_terminal = false;
        run_lines.clear();
        run_group.clear();
        run_style = nullptr;
    };

    for (const auto &s : bs->body) {
        StmtFusionInfo fi = classify_stmt_for_fusion(s.get());
        if (!fi.group.empty()) {
            if (run_group == fi.group) {
                run_lines.push_back(fi.line);
            } else {
                flush_run();
                run_group = fi.group;
                run_style = fi.style;
                run_lines.push_back(fi.line);
            }
            continue;
        }
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
            emit_edge(ctx.os, prev_exit, sentry);
        }
        prev_exit = sexit;
        prev_terminal = sexit.empty();
    }
    flush_run();

    if (entry.empty()) {
        std::string nid = emit_stmt_node(ctx, "empty", "(no stmts)", ST_AUX);
        return nid + "|" + nid;
    }
    return entry + "|" + prev_exit;
}

std::string render_stmt(StmtCtx &ctx, const ast::Stmt *s) {
    if (!s) {
        return emit_stmt_node(ctx, "null", "(null stmt)", ST_AUX);
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
        return emit_stmt_node(ctx, "var", lbl, ST_VAR,
                              "L" + std::to_string(v->loc.line));
    }
    case ast::NodeKind::ExprStmt: {
        auto *e = static_cast<const ast::ExprStmt *>(s);
        if (!e->expr) return emit_stmt_node(ctx, "noop", "(no-op)", ST_AUX);
        auto *expr = e->expr.get();
        NodeStyle st = ST_EXPR;
        if (expr->kind == ast::NodeKind::CallExpr ||
            expr->kind == ast::NodeKind::NewExpr) {
            st = ST_CALL;
        } else if (expr->kind == ast::NodeKind::SpawnExpr ||
                   expr->kind == ast::NodeKind::RSpawnExpr) {
            st = ST_SPAWN;
        } else if (expr->kind == ast::NodeKind::AssignExpr) {
            st = ST_ASSIGN;
        }
        return emit_stmt_node(ctx, "expr", fmt_expr(e->expr.get()), st,
                              "L" + std::to_string(e->loc.line));
    }
    case ast::NodeKind::IfStmt: {
        auto *iss = static_cast<const ast::IfStmt *>(s);
        std::string cond =
            emit_stmt_node(ctx, "if", "if " + fmt_expr(iss->cond.get()), ST_IF,
                           "L" + std::to_string(iss->loc.line));
        std::string merge = emit_stmt_node(ctx, "ifend", "(merge)", ST_AUX);

        std::string then_pair = render_stmt(ctx, iss->then_branch.get());
        std::string te = then_pair, tx = then_pair;
        auto bar = then_pair.find('|');
        if (bar != std::string::npos) {
            te = then_pair.substr(0, bar);
            tx = then_pair.substr(bar + 1);
        }
        emit_edge(ctx.os, cond, te, "true");
        if (!tx.empty()) emit_edge(ctx.os, tx, merge);

        if (iss->else_branch) {
            std::string else_pair = render_stmt(ctx, iss->else_branch.get());
            std::string ee = else_pair, ex = else_pair;
            auto ebar = else_pair.find('|');
            if (ebar != std::string::npos) {
                ee = else_pair.substr(0, ebar);
                ex = else_pair.substr(ebar + 1);
            }
            emit_edge(ctx.os, cond, ee, "false");
            if (!ex.empty()) emit_edge(ctx.os, ex, merge);
        } else {
            emit_edge(ctx.os, cond, merge, "false");
        }
        return cond + "|" + merge;
    }
    case ast::NodeKind::WhileStmt: {
        auto *ws = static_cast<const ast::WhileStmt *>(s);
        std::string head =
            emit_stmt_node(ctx, "while", "while " + fmt_expr(ws->cond.get()),
                           ST_LOOP, "L" + std::to_string(ws->loc.line));
        std::string exit_id =
            emit_stmt_node(ctx, "wend", "(loop exit)", ST_AUX);
        ctx.loop_stack.push_back({head, exit_id});
        std::string body_pair = render_stmt(ctx, ws->body.get());
        ctx.loop_stack.pop_back();
        std::string be = body_pair, bx = body_pair;
        auto bar = body_pair.find('|');
        if (bar != std::string::npos) {
            be = body_pair.substr(0, bar);
            bx = body_pair.substr(bar + 1);
        }
        emit_edge(ctx.os, head, be, "true");
        emit_edge(ctx.os, head, exit_id, "false");
        if (!bx.empty()) emit_edge(ctx.os, bx, head, "back", EdgeKind::Bold);
        return head + "|" + exit_id;
    }
    case ast::NodeKind::DoWhileStmt: {
        auto *dw = static_cast<const ast::DoWhileStmt *>(s);
        std::string entry =
            emit_stmt_node(ctx, "doentry", "do {", ST_LOOP_BODY);
        std::string cond =
            emit_stmt_node(ctx, "dowhile", "while " + fmt_expr(dw->cond.get()),
                           ST_LOOP, "L" + std::to_string(dw->loc.line));
        std::string exit_id =
            emit_stmt_node(ctx, "dwend", "(loop exit)", ST_AUX);
        ctx.loop_stack.push_back({cond, exit_id});
        std::string body_pair = render_stmt(ctx, dw->body.get());
        ctx.loop_stack.pop_back();
        std::string be = body_pair, bx = body_pair;
        auto bar = body_pair.find('|');
        if (bar != std::string::npos) {
            be = body_pair.substr(0, bar);
            bx = body_pair.substr(bar + 1);
        }
        emit_edge(ctx.os, entry, be);
        if (!bx.empty()) emit_edge(ctx.os, bx, cond);
        emit_edge(ctx.os, cond, be, "true", EdgeKind::Bold);
        emit_edge(ctx.os, cond, exit_id, "false");
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
        std::string head = emit_stmt_node(
            ctx, "for",
            fs->cond ? ("for " + fmt_expr(fs->cond.get())) : "for (true)",
            ST_LOOP, "L" + std::to_string(fs->loc.line));
        std::string step_id;
        if (fs->step) {
            step_id = emit_stmt_node(
                ctx, "step", "step: " + fmt_expr(fs->step.get()), ST_LOOP_BODY);
        }
        std::string exit_id =
            emit_stmt_node(ctx, "fend", "(loop exit)", ST_AUX);
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
        if (!init_id.empty()) emit_edge(ctx.os, init_id, head);
        emit_edge(ctx.os, head, be, "true");
        emit_edge(ctx.os, head, exit_id, "false");
        if (!bx.empty()) {
            if (!step_id.empty()) {
                emit_edge(ctx.os, bx, step_id);
                emit_edge(ctx.os, step_id, head, "back", EdgeKind::Bold);
            } else {
                emit_edge(ctx.os, bx, head, "back", EdgeKind::Bold);
            }
        } else if (!step_id.empty()) {
            emit_edge(ctx.os, head, step_id, "step (skipped)",
                      EdgeKind::Dotted);
            emit_edge(ctx.os, step_id, head, "back", EdgeKind::Bold);
        }
        std::string entry = init_id.empty() ? head : init_id;
        return entry + "|" + exit_id;
    }
    case ast::NodeKind::ForEachStmt: {
        auto *fe = static_cast<const ast::ForEachStmt *>(s);
        std::string head = emit_stmt_node(
            ctx, "foreach",
            "for " + fmt_type(fe->iter_type.get()) + " " + fe->iter_name +
                " : " + fmt_expr(fe->iter_expr.get()),
            ST_LOOP, "L" + std::to_string(fe->loc.line));
        std::string exit_id =
            emit_stmt_node(ctx, "feend", "(loop exit)", ST_AUX);
        ctx.loop_stack.push_back({head, exit_id});
        std::string body_pair = render_stmt(ctx, fe->body.get());
        ctx.loop_stack.pop_back();
        std::string be = body_pair, bx = body_pair;
        auto bar = body_pair.find('|');
        if (bar != std::string::npos) {
            be = body_pair.substr(0, bar);
            bx = body_pair.substr(bar + 1);
        }
        emit_edge(ctx.os, head, be, "next");
        emit_edge(ctx.os, head, exit_id, "done");
        if (!bx.empty()) emit_edge(ctx.os, bx, head, "back", EdgeKind::Bold);
        return head + "|" + exit_id;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *rs = static_cast<const ast::ReturnStmt *>(s);
        std::string lbl = "return";
        if (rs->value) lbl += " " + fmt_expr(rs->value.get());
        return emit_stmt_node(ctx, "ret", lbl, ST_TERMINAL,
                              "L" + std::to_string(rs->loc.line)) +
               "|";
    }
    case ast::NodeKind::ThrowStmt: {
        auto *ts = static_cast<const ast::ThrowStmt *>(s);
        std::string lbl = "throw";
        if (ts->value) lbl += " " + fmt_expr(ts->value.get());
        return emit_stmt_node(ctx, "throw", lbl, ST_THROW,
                              "L" + std::to_string(ts->loc.line)) +
               "|";
    }
    case ast::NodeKind::BreakStmt: {
        std::string n = emit_stmt_node(ctx, "brk", "break", ST_BRANCH);
        if (!ctx.loop_stack.empty()) {
            emit_edge(ctx.os, n, ctx.loop_stack.back().break_target, "break",
                      EdgeKind::Dashed);
        }
        return n + "|";
    }
    case ast::NodeKind::ContinueStmt: {
        std::string n = emit_stmt_node(ctx, "cnt", "continue", ST_BRANCH);
        if (!ctx.loop_stack.empty()) {
            emit_edge(ctx.os, n, ctx.loop_stack.back().continue_target,
                      "continue", EdgeKind::Dashed);
        }
        return n + "|";
    }
    case ast::NodeKind::GotoStmt: {
        auto *gs = static_cast<const ast::GotoStmt *>(s);
        std::string n =
            emit_stmt_node(ctx, "goto", "goto " + gs->label, ST_BRANCH);
        auto it = ctx.labels.find(gs->label);
        if (it != ctx.labels.end()) {
            emit_edge(ctx.os, n, it->second, "goto", EdgeKind::Dotted);
        }
        return n + "|";
    }
    case ast::NodeKind::LabelStmt: {
        auto *ls = static_cast<const ast::LabelStmt *>(s);
        std::string n = emit_stmt_node(ctx, "lbl", ls->name + ":", ST_LABEL);
        ctx.labels[ls->name] = n;
        return n;
    }
    case ast::NodeKind::TryStmt: {
        auto *ts = static_cast<const ast::TryStmt *>(s);
        std::string entry = emit_stmt_node(ctx, "try", "try {", ST_TRY);
        std::string merge =
            emit_stmt_node(ctx, "tryend", "(after try)", ST_AUX);
        std::string bp = render_block(ctx, ts->body.get());
        std::string be = bp, bx = bp;
        auto bar = bp.find('|');
        if (bar != std::string::npos) {
            be = bp.substr(0, bar);
            bx = bp.substr(bar + 1);
        }
        emit_edge(ctx.os, entry, be);
        if (!bx.empty()) emit_edge(ctx.os, bx, merge);
        for (size_t ci = 0; ci < ts->catches.size(); ++ci) {
            const auto &c = ts->catches[ci];
            std::string cls = c.exc_class_name.empty()
                                  ? std::string("(catch-all)")
                                  : c.exc_class_name;
            std::string handler = emit_stmt_node(
                ctx, "catch",
                "catch " + cls + (c.var_name.empty() ? "" : (" " + c.var_name)),
                ST_CATCH);
            std::string cp = render_block(ctx, c.body.get());
            std::string ce = cp, cx = cp;
            auto cbar = cp.find('|');
            if (cbar != std::string::npos) {
                ce = cp.substr(0, cbar);
                cx = cp.substr(cbar + 1);
            }
            emit_edge(ctx.os, be, handler, "throw " + cls, EdgeKind::Dotted,
                      "#b91c1c");
            emit_edge(ctx.os, handler, ce);
            if (!cx.empty()) emit_edge(ctx.os, cx, merge);
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
                emit_stmt_node(ctx, "finally", "finally", ST_FINALLY);
            emit_edge(ctx.os, merge, fnode);
            emit_edge(ctx.os, fnode, fe);
            std::string after =
                emit_stmt_node(ctx, "tryafter", "(after finally)", ST_AUX);
            if (!fx.empty()) emit_edge(ctx.os, fx, after);
            return entry + "|" + after;
        }
        return entry + "|" + merge;
    }
    case ast::NodeKind::SynchronizedStmt: {
        auto *ss = static_cast<const ast::SynchronizedStmt *>(s);
        std::string entry = emit_stmt_node(
            ctx, "sync", "synchronized (" + fmt_expr(ss->target.get()) + ")",
            ST_SYNC);
        std::string bp = render_block(ctx, ss->body.get());
        std::string be = bp, bx = bp;
        auto bar = bp.find('|');
        if (bar != std::string::npos) {
            be = bp.substr(0, bar);
            bx = bp.substr(bar + 1);
        }
        std::string exit_id =
            emit_stmt_node(ctx, "syncend", "monexit", ST_SYNC);
        emit_edge(ctx.os, entry, be);
        if (!bx.empty()) emit_edge(ctx.os, bx, exit_id);
        return entry + "|" + exit_id;
    }
    default: {
        return emit_stmt_node(
            ctx, "stmt",
            "<stmt kind=" + std::to_string(static_cast<int>(s->kind)) + ">",
            ST_AUX);
    }
    }
}

void render_function_body_subgraph(std::ostringstream &os,
                                   const std::string &cluster_id,
                                   const std::string &title,
                                   const ast::BlockStmt *body) {
    os << "    subgraph cluster_" << cluster_id << " {\n";
    os << "        label=\"" << escape_label(title) << "\";\n";
    os << "        style=\"rounded,filled\";\n";
    os << "        fillcolor=\"#fafafa\";\n";
    os << "        color=\"#94a3b8\";\n";
    os << "        fontname=\"sans-serif\";\n";
    if (!body) {
        os << "        " << cluster_id
           << "_abstract [label=\"(metodo abstracto)\","
           << " shape=note, fillcolor=\"#f1f5f9\","
           << " fontcolor=\"#475569\","
           << " style=\"filled,dashed\"];\n";
        os << "    }\n";
        return;
    }
    std::string entry_id = cluster_id + "_entry";
    emit_node(os, entry_id, "entry", ST_ENTRY);
    StmtCtx ctx{os, cluster_id + "_", 0, {}, {}};
    std::string bp = render_block(ctx, body);
    std::string be = bp;
    auto bar = bp.find('|');
    if (bar != std::string::npos) be = bp.substr(0, bar);
    emit_edge(os, entry_id, be);
    os << "    }\n";
}

// =====================================================================
//  GENERADOR 2: SSA IR -> Graphviz
// =====================================================================

/**
 * @brief Renderiza un IrBlock como un nodo `record` con su contenido.
 *
 * Records permiten resaltar visualmente la cabecera del bloque y las
 * instrucciones como celdas separadas.  Mas legible que un label
 * plano para bloques con muchas instrucciones.
 */
void render_ir_block(std::ostringstream &os, const ir::IrFunction &fn,
                     const ir::IrBlock &bb, const std::string &block_id) {
    std::ostringstream lbl;
    const size_t total = bb.instrs.size();
    lbl << "{ "
        << escape_record(bb.name + " (#" + std::to_string(bb.id) + ", " +
                         std::to_string(total) + " instrs)");
    // Sin truncamiento: emitimos TODAS las instrucciones del bloque.
    for (const auto &ins : bb.instrs) {
        lbl << " | " << escape_record(fmt_instr(fn, ins, fn.blocks));
    }
    lbl << " }";

    NodeStyle st = ST_IRBLOCK;
    std::string term_kind = "fallthrough";
    if (!bb.instrs.empty()) {
        ir::IrOp last_op = bb.instrs.back().op;
        if (last_op == ir::IrOp::RET || last_op == ir::IrOp::UNREACHABLE) {
            st = ST_IREXIT;
            term_kind = "exit";
        } else if (last_op == ir::IrOp::BR_COND) {
            st = ST_IRBRANCH;
            term_kind = "branch";
        }
    }
    std::string tooltip = bb.name + ": " + std::to_string(total) +
                          " instrs, terminator=" + term_kind;
    emit_record(os, block_id, lbl.str(), st, tooltip);
}

/**
 * @brief Renderiza una IrFunction completa como cluster con sus bloques.
 */
void render_ir_function(std::ostringstream &os, const ir::IrFunction &fn,
                        size_t fn_idx,
                        std::unordered_set<std::string> &intra_calls_out,
                        const std::string &cost_label = std::string()) {
    const std::string fn_id = "fn" + std::to_string(fn_idx);
    std::string title = fn.name + " (" + std::to_string(fn.blocks.size()) +
                        " bb, " + std::to_string(fn.params.size()) +
                        " params, ret " + ir::ir_type_name(fn.ret_type) + ")";
    // --diagram-cost: anexar el coste Big-O al label en una segunda linea.
    // Usamos un '\n' REAL: escape_label lo convierte al "\\n" que DOT
    // interpreta como salto de linea dentro del label.
    if (!cost_label.empty()) title += "\n" + cost_label;

    os << "    subgraph cluster_" << fn_id << " {\n";
    os << "        label=\"" << escape_label(title) << "\";\n";
    // Tooltip con el coste (visible al hover en herramientas interactivas).
    if (!cost_label.empty())
        os << "        tooltip=\"" << escape_label(cost_label) << "\";\n";
    os << "        style=\"rounded,filled\";\n";
    os << "        fillcolor=\"#f8fafc\";\n";
    os << "        color=\"#475569\";\n";
    os << "        fontname=\"sans-serif\";\n";
    os << "        fontsize=14;\n";

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        std::string bid = fn_id + "_b" + std::to_string(bi);
        render_ir_block(os, fn, fn.blocks[bi], bid);
    }

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        std::string src = fn_id + "_b" + std::to_string(bi);
        const auto &bb = fn.blocks[bi];
        if (bb.instrs.empty()) continue;
        const auto &term = bb.instrs.back();
        if (term.op == ir::IrOp::BR) {
            if (term.target_block < fn.blocks.size()) {
                std::string dst =
                    fn_id + "_b" + std::to_string(term.target_block);
                emit_edge(os, src, dst);
            }
        } else if (term.op == ir::IrOp::BR_COND) {
            if (term.target_block < fn.blocks.size()) {
                std::string dst =
                    fn_id + "_b" + std::to_string(term.target_block);
                emit_edge(os, src, dst, "true", EdgeKind::Solid, "#16a34a");
            }
            if (term.false_block < fn.blocks.size()) {
                std::string dst =
                    fn_id + "_b" + std::to_string(term.false_block);
                emit_edge(os, src, dst, "false", EdgeKind::Solid, "#dc2626");
            }
        }
        for (const auto &ins : bb.instrs) {
            if ((ins.op == ir::IrOp::CALL || ins.op == ir::IrOp::TAILCALL) &&
                !ins.func_name.empty()) {
                intra_calls_out.insert(fn_id + ">" + ins.func_name);
            }
        }
    }

    os << "    }\n";
}

// =====================================================================
//  GENERADOR 3: .vel ensamblador -> Graphviz
// =====================================================================

// Lo que se lee del texto .vel -- mnemonico, etiqueta, llamada, destino del
// salto, instruccion fusionada -- vive en vx/diagram/vel_text_model.h, porque
// la respuesta es la misma se dibuje en DOT o en Mermaid.

} // namespace

// =========================================================================
//  API publica
// =========================================================================

std::string graphviz_types_from_ast(const ast::ModuleNode &mod) {
    // Nodo por tipo (record con campos + metodos); aristas de herencia
    // (solidas) e interfaces (punteadas).
    std::ostringstream os;
    os << "digraph tipos {\n";
    os << "  rankdir=BT;\n"; // subclases abajo, bases arriba.
    os << "  node [shape=record, fontname=\"monospace\", fontsize=10];\n";

    auto acc = [](uint8_t a) -> const char * {
        return a == 1 ? "-" : (a == 2 ? "#" : "+");
    };
    std::vector<std::string> rels;

    for (const auto &node : mod.decls) {
        if (!node) continue;
        if (node->kind == ast::NodeKind::ClassDecl) {
            auto *d = static_cast<const ast::ClassDecl *>(node.get());
            if (d->name.empty()) continue;
            std::string rec = "{" + d->name;
            if (d->is_final) rec += " (final)";
            rec += "|";
            for (const auto &f : d->fields)
                rec += std::string(acc(f.access)) +
                       escape_record(fmt_type(f.type.get()) + " " + f.name) +
                       "\\l";
            rec += "|";
            for (const auto &m : d->methods) {
                if (!m || m->name.empty()) continue;
                rec +=
                    std::string(acc(m->access)) + escape_record(m->name) + "()";
                if (m->return_type)
                    rec += escape_record(" " + fmt_type(m->return_type.get()));
                rec += "\\l";
            }
            rec += "}";
            os << "  " << d->name << " [label=\"" << rec << "\"];\n";
            if (!d->super_name.empty())
                rels.push_back("  " + d->name + " -> " + d->super_name + ";");
            for (const auto &iface : d->interface_names)
                rels.push_back("  " + d->name + " -> " + iface +
                               " [style=dashed];");
        } else if (node->kind == ast::NodeKind::StructDecl) {
            auto *d = static_cast<const ast::StructDecl *>(node.get());
            if (d->name.empty()) continue;
            std::string rec = "{[struct] " + d->name + "|";
            for (const auto &f : d->fields)
                rec += escape_record(fmt_type(f.type.get()) + " " + f.name) +
                       "\\l";
            rec += "}";
            os << "  " << d->name << " [label=\"" << rec
               << "\", style=filled, fillcolor=\"#fef3c7\"];\n";
        } else if (node->kind == ast::NodeKind::EnumDecl) {
            auto *d = static_cast<const ast::EnumDecl *>(node.get());
            if (d->name.empty()) continue;
            std::string rec = "{[enum] " + d->name;
            if (!d->backing_type.empty()) rec += " : " + d->backing_type;
            rec += "|";
            for (const auto &v : d->variants)
                rec += escape_record(v.name) + "\\l";
            rec += "}";
            os << "  " << d->name << " [label=\"" << rec
               << "\", style=filled, fillcolor=\"#ccfbf1\"];\n";
        } else if (node->kind == ast::NodeKind::ConceptDecl) {
            auto *d = static_cast<const ast::ConceptDecl *>(node.get());
            if (d->name.empty()) continue;
            os << "  " << d->name << " [label=\"[concept] " << d->name
               << "\", style=filled, fillcolor=\"#e9d5ff\"];\n";
        }
    }
    for (const auto &r : rels)
        os << r << '\n';
    os << "}\n";
    return os.str();
}

std::string graphviz_from_ast(const ast::ModuleNode &mod) {
    std::ostringstream os;
    os << "// Diagrama AST Vesta (Graphviz DOT)\n";
    os << "// Cada nodo lleva la info relevante para debug:\n";
    os << "//   funciones: nombre, return type, params, body con control "
          "flow\n";
    os << "//   clases:    super, interfaces, fields, metodos con "
          "modificadores\n";
    os << "//   structs/enums/globals: tipo y nombre\n";
    os << "// Tooltips contienen info expandida (line numbers, conteos).\n";
    os << "// Render con: dot -Tsvg <archivo>.dot -o <archivo>.svg\n";
    os << "digraph AST {\n";
    os << "    rankdir=TB;\n";
    os << "    node [fontname=\"sans-serif\", fontsize=11];\n";
    os << "    edge [fontname=\"sans-serif\", fontsize=10];\n";
    os << "    graph [fontname=\"sans-serif\", fontsize=12];\n";
    os << "    compound=true;\n";

    std::string root = "M";
    emit_node(os, root,
              "Module\n" + std::to_string(mod.decls.size()) +
                  " top-level decls",
              ST_MODULE,
              "Module: " + std::to_string(mod.decls.size()) + " declarations");

    // Acumulamos los nodos hoja (globals, externs) para emitirlos
    // consolidados al final.  Funciones, clases, structs y enums siguen
    // siendo nodos individuales porque tienen estructura interna propia.
    std::vector<const ast::GlobalVarDecl *> globals;
    std::vector<const ast::ExternFnDecl *> externs;
    size_t fcount = 0, ccount = 0, scount = 0, ecount = 0;
    for (const auto &dn : mod.decls) {
        if (!dn) continue;
        switch (dn->kind) {
        case ast::NodeKind::FunctionDecl:
            render_function_decl(os, static_cast<ast::FunctionDecl *>(dn.get()),
                                 root, fcount++);
            break;
        case ast::NodeKind::ClassDecl:
            render_class_decl(os, static_cast<ast::ClassDecl *>(dn.get()), root,
                              ccount++);
            break;
        case ast::NodeKind::StructDecl:
            render_struct_decl(os, static_cast<ast::StructDecl *>(dn.get()),
                               root, scount++);
            break;
        case ast::NodeKind::EnumDecl:
            render_enum_decl(os, static_cast<ast::EnumDecl *>(dn.get()), root,
                             ecount++);
            break;
        case ast::NodeKind::GlobalVarDecl:
            globals.push_back(static_cast<ast::GlobalVarDecl *>(dn.get()));
            break;
        case ast::NodeKind::ExternFnDecl:
            externs.push_back(static_cast<ast::ExternFnDecl *>(dn.get()));
            break;
        default: break;
        }
    }
    render_globals_batch(os, globals, root);
    render_externs_batch(os, externs, root);

    os << "}\n";
    return os.str();
}

std::string graphviz_from_ir_module(const ir::IrModule &mod,
                                    const std::string &title,
                                    const analyze::ModuleCost *cost) {
    std::ostringstream os;
    os << "// " << title << "\n";
    os << "// Modulo: " << mod.name << " (" << mod.functions.size()
       << " funciones)\n";
    os << "// Cada cluster = una funcion.  Cada nodo = un IrBlock con sus "
          "instrs SSA.\n";
    os << "// Edges:\n";
    os << "//   solid verde      = rama true de BR_COND\n";
    os << "//   solid rojo       = rama false de BR_COND\n";
    os << "//   solid sin label  = BR incondicional\n";
    os << "//   dotted           = call inter-funcion (CALL/CALLN)\n";
    os << "// Render con: dot -Tsvg <archivo>.dot -o <archivo>.svg\n";
    os << "digraph IR {\n";
    os << "    rankdir=TB;\n";
    os << "    label=\"" << escape_label(title) << "\";\n";
    os << "    labelloc=\"t\";\n";
    os << "    node [fontname=\"sans-serif\", fontsize=10];\n";
    os << "    edge [fontname=\"sans-serif\", fontsize=9];\n";
    os << "    graph [fontname=\"sans-serif\", fontsize=12];\n";
    os << "    compound=true;\n";

    std::unordered_map<std::string, std::string> fn_id_by_name;
    for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
        fn_id_by_name[mod.functions[fi].name] = "fn" + std::to_string(fi);
    }

    std::unordered_set<std::string> intra_calls;
    for (size_t fi = 0; fi < mod.functions.size(); ++fi) {
        // --diagram-cost: si hay analisis de coste, anexarlo al cluster.
        std::string cost_label = cost ? analyze::cost_label_for_function(
                                            *cost, mod.functions[fi].name)
                                      : std::string();
        render_ir_function(os, mod.functions[fi], fi, intra_calls, cost_label);
    }

    // Cross-cluster edges para llamadas: enlazamos un nodo de origen
    // (primer bloque del fn fuente) con el primer bloque del callee,
    // usando ltail/lhead para que el edge visualmente conecte clusters.
    for (const auto &edge : intra_calls) {
        auto pos = edge.find('>');
        if (pos == std::string::npos) continue;
        std::string src_fn = edge.substr(0, pos);
        std::string callee = edge.substr(pos + 1);
        auto it = fn_id_by_name.find(callee);
        if (it == fn_id_by_name.end()) continue;
        os << "    " << src_fn << "_b0 -> " << it->second << "_b0"
           << " [ltail=cluster_" << src_fn << ", lhead=cluster_" << it->second
           << ", style=dotted, color=\"#7e22ce\", label=\"call\"];\n";
    }

    // Expandir cada bloque de inline asm en su propio CFG (cluster) anotado con
    // coste/latencia/cuello de botella/flags/diagnosticos.
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
                    os << asm_cfg_graphviz(ins.func_name, o);
                    os << "    fn" << fi << "_b" << bi << " -> " << o.id_prefix
                       << "_b0 [lhead=cluster_" << o.id_prefix
                       << ", style=dotted, color=\"#3366aa\", "
                          "label=\"asm\"];\n";
                }
            }
        }
    }

    os << "}\n";
    return os.str();
}

std::string graphviz_from_vel_text(const std::string &vel_text) {
    std::ostringstream os;
    os << "// Diagrama bytecode .vel (Graphviz DOT)\n";
    os << "// Cada nodo = un label del .vel (bloque basico).\n";
    os << "// Tooltips contienen TODAS las instrucciones (no solo las primeras "
          "10).\n";
    os << "// Edges:\n";
    os << "//   solid sin label   = jmp incondicional\n";
    os << "//   solid con label cc= jmp.cc condicional\n";
    os << "//   solid con cmpjmp  = cmpjmp fusionado\n";
    os << "//   dotted purpura    = callvm a otra funcion\n";
    os << "// Opcodes destacados "
          "(cmpjmp/cmpjmpu/decjnz/gcallocp/spawnargs/fulfillhlt)\n";
    os << "// llevan borde grueso y color amarillo.\n";
    os << "// Render con: dot -Tsvg <archivo>.dot -o <archivo>.svg\n";
    os << "digraph VEL {\n";
    os << "    rankdir=TB;\n";
    os << "    node [fontname=\"monospace\", fontsize=10];\n";
    os << "    edge [fontname=\"sans-serif\", fontsize=9];\n";
    os << "    graph [fontname=\"sans-serif\", fontsize=12];\n";

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
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string lbl;
        if (is_label_line(line, lbl)) {
            if (in_block) blocks.push_back(std::move(cur));
            cur = Block{};
            cur.name = lbl;
            in_block = true;
            continue;
        }
        if (!in_block) continue;
        size_t i = 0;
        while (i < line.size() &&
               std::isspace(static_cast<unsigned char>(line[i])))
            ++i;
        if (i == line.size()) continue;
        if (line[i] == '/' && i + 1 < line.size() && line[i + 1] == '/')
            continue;
        if (line[i] == '@') continue;
        cur.instrs.push_back(line.substr(i));
    }
    if (in_block) blocks.push_back(std::move(cur));

    std::unordered_set<std::string> known_labels;
    for (const auto &b : blocks)
        known_labels.insert(b.name);

    // Sin truncamiento de instrs ni de longitud por linea: el record
    // muestra TODAS las instrucciones del bloque tal cual fueron
    // emitidas por el assembler.
    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        const auto &b = blocks[bi];
        std::ostringstream record;
        record << "{ "
               << escape_record(b.name + ":  (" +
                                std::to_string(b.instrs.size()) + " instrs)");
        bool has_opt = false;
        for (const auto &ins : b.instrs) {
            record << " | " << escape_record(ins);
            std::string mn = get_mnemonic(ins);
            if (is_fused_instr(mn)) has_opt = true;
        }
        record << " }";

        NodeStyle st = has_opt ? ST_VELOPT : ST_VELBLOCK;
        if (!b.instrs.empty()) {
            std::string last_mn = get_mnemonic(b.instrs.back());
            if (last_mn == "ret" || last_mn == "hlt" ||
                last_mn == "fulfillhlt") {
                st = ST_VELEXIT;
            }
        }

        // Tooltip con TODAS las instrucciones (no truncado).  En SVG
        // interactivo aparece al hover; en PDF/PNG no se ve pero queda
        // como metadata.
        std::ostringstream tooltip;
        tooltip << b.name << ":  (" << b.instrs.size() << " instrs)\n";
        for (const auto &ins : b.instrs) {
            tooltip << ins << "\n";
        }
        std::string node_id = "vb" + std::to_string(bi);
        emit_record(os, node_id, record.str(), st, tooltip.str());
    }

    std::unordered_map<std::string, size_t> idx_by_name;
    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        idx_by_name[blocks[bi].name] = bi;
    }

    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        const auto &b = blocks[bi];
        std::string src = "vb" + std::to_string(bi);
        for (const auto &ins : b.instrs) {
            std::string target = extract_abs_target(ins);
            if (target.empty()) continue;
            auto it = idx_by_name.find(target);
            if (it == idx_by_name.end()) continue;
            std::string dst = "vb" + std::to_string(it->second);
            std::string mn = get_mnemonic(ins);

            if (is_call_mnemonic(mn)) {
                emit_edge(os, src, dst, mn, EdgeKind::Dotted, "#7e22ce");
            } else if (mn == "jmp") {
                emit_edge(os, src, dst);
            } else if (mn.size() >= 4 && mn.substr(0, 4) == "jmp.") {
                emit_edge(os, src, dst, mn);
            } else if (mn.size() >= 7 && mn.substr(0, 7) == "cmpjmp.") {
                emit_edge(os, src, dst, mn, EdgeKind::Solid, "#92400e");
            } else if (mn.size() >= 8 && mn.substr(0, 8) == "cmpjmpu.") {
                emit_edge(os, src, dst, mn, EdgeKind::Solid, "#92400e");
            } else if (mn == "decjnz") {
                emit_edge(os, src, dst, "decjnz", EdgeKind::Solid, "#92400e");
            } else if (mn != "mov") {
                emit_edge(os, src, dst, mn, EdgeKind::Dashed);
            }
        }

        // Fall-through: si el bloque NO termina en un terminador
        // INCONDICIONAL (jmp / ret / hlt / fulfillhlt / tailcall), la
        // ejecucion CAE al siguiente bloque secuencial.  Esto cubre:
        //   - labels de 0 instrucciones (p.ej. `factorial:`) que caen al
        //     `_entry_0` siguiente,
        //   - saltos CONDICIONALES (cmpjmp.cc / cmpjmpu.cc / jmp.cc /
        //     decjnz) cuya rama NO-tomada continua al bloque siguiente,
        //   - bloques que terminan en call/mov/etc (continuan tras la
        //     instruccion).
        // Sin esto el grafo del .vel queda desconectado y no refleja el
        // flujo real que ejecuta la VM.
        if (bi + 1 < blocks.size()) {
            bool falls = true;
            if (!b.instrs.empty()) {
                const std::string last_mn = get_mnemonic(b.instrs.back());
                if (last_mn == "jmp" || last_mn == "ret" || last_mn == "hlt" ||
                    last_mn == "fulfillhlt" || last_mn == "tailcall") {
                    falls = false; // terminador incondicional: sin caida
                }
            }
            if (falls) {
                const std::string dst = "vb" + std::to_string(bi + 1);
                emit_edge(os, src, dst, "fall", EdgeKind::Solid, "#475569");
            }
        }
    }

    os << "}\n";
    return os.str();
}

} // namespace vx
