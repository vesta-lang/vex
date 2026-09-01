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
 * @file symbol_index.cpp
 * @brief Implementacion del indice de simbolos del LSP de Vesta (Fase 4).
 *
 * LIMITACION ACEPTADA v1: la resolucion es POR NOMBRE.  No se modelan scope,
 * shadowing, imports ni sobrecarga: un nombre repetido en varios sitios
 * devolvera varias definiciones/referencias.  Es deliberado para esta version
 * (un LSP util y robusto sin reimplementar el resolvedor del compilador); la
 * resolucion precisa es un refinamiento futuro.
 *
 * Estrategia de @c build_doc_symbols:
 *   1. LEXAR todo el fuente a un vector de tokens (offset/longitud/lexema).
 *      Las REFERENCIAS son todos los tokens @c IDENTIFIER.
 *   2. PARSEAR el fuente (lex+parse independiente) para obtener el AST y, de
 *      el, los NOMBRES + KINDS de cada declaracion (funcion/clase/struct/enum/
 *      typedef/global/metodo/campo/param/variante).  El AST da kinds fiables.
 *   3. Para cada nombre declarado, LOCALIZAR su rango preciso emparejandolo
 *      con el token @c IDENTIFIER homonimo mas cercano a la linea de la
 *      declaracion (el @c .loc del nodo no siempre apunta al nombre).
 */

#include "lsp/symbol_index.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <sstream>

#include "lsp/document_store.h"
#include "vx/ast.h"
#include "vx/diagnostic.h"
#include "vx/lexer.h"
#include "vx/parser.h"
#include "vx/source_text.h" // un solo fin de linea para todo el pipeline
#include "vx/token.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

#include "vx/diag/diag_catalog.h"

namespace lsp {

std::string symbol_kind_name(SymbolKind k) {
    // El texto sale del catalogo, no de aqui: el idioma lo elige el entorno y
    // anadir uno nuevo no debe obligar a tocar este fichero.
    const char *code = "VX9141";
    switch (k) {
    case SymbolKind::Function: code = "VX9130"; break;
    case SymbolKind::Class: code = "VX9131"; break;
    case SymbolKind::Struct: code = "VX9132"; break;
    case SymbolKind::Enum: code = "VX9133"; break;
    case SymbolKind::TypeAlias: code = "VX9134"; break;
    case SymbolKind::Variable: code = "VX9135"; break;
    case SymbolKind::Parameter: code = "VX9136"; break;
    case SymbolKind::Method: code = "VX9137"; break;
    case SymbolKind::Field: code = "VX9138"; break;
    case SymbolKind::EnumVariant: code = "VX9139"; break;
    case SymbolKind::Concept: code = "VX9140"; break;
    case SymbolKind::Unknown:
    default: break;
    }
    return vx::diag::format(code);
}

const SymbolRef *DocSymbols::ref_at(size_t byte_offset) const {
    // Busqueda lineal: el numero de identificadores por fichero es modesto.
    // Se devuelve la referencia cuyo span [offset, offset+length) contiene el
    // byte del cursor.
    for (const auto &r : refs) {
        if (byte_offset >= r.byte_offset &&
            byte_offset < r.byte_offset + r.byte_length)
            return &r;
    }
    return nullptr;
}

namespace {

/// Token "ligero" capturado del lexer: lo justo para localizar nombres.
struct LexTok {
    vx::TokenKind kind = vx::TokenKind::END_OF_FILE;
    std::string lexeme;
    size_t offset = 0;
    size_t length = 0;
    uint32_t line = 0; ///< 1-based, tal como lo da el lexer.
};

/**
 * @brief Lexa el fuente completo a un vector de tokens ligeros.
 *
 * Bajo try/catch: ante un fallo del lexer devuelve lo acumulado.  Aplica un
 * cap defensivo de tokens (1 por byte + holgura) para no colgar ante una
 * entrada patologica.
 */
std::vector<LexTok> lex_all(const std::string &text,
                            const std::string &filename) {
    std::vector<LexTok> out;
    try {
        vx::Diagnostics diags; // descartables.
        vx::Lexer lex(text, filename, diags);
        const size_t kMaxTokens = text.size() + 1024;
        size_t produced = 0;
        for (;;) {
            vx::Token tok = lex.next();
            if (tok.kind == vx::TokenKind::END_OF_FILE) break;
            if (++produced > kMaxTokens) break;
            LexTok t;
            t.kind = tok.kind;
            t.lexeme = std::move(tok.lexeme);
            t.offset = tok.loc.offset;
            t.length = tok.loc.length;
            t.line = tok.loc.line;
            out.push_back(std::move(t));
        }
    } catch (...) {
        // Devolver lo acumulado.
    }
    return out;
}

/**
 * @brief Construye la firma legible de una funcion/metodo: "nombre(p1, p2)".
 *
 * Solo usa los nombres de los parametros (best-effort); el tipo de retorno
 * y los tipos de los parametros se omiten para mantenerlo compacto y robusto
 * frente a TypeNode complejos.
 */
std::string
make_signature(const std::string &name,
               const std::vector<std::unique_ptr<vx::ast::ParamDecl>> &params) {
    std::string sig = name;
    sig += "(";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i) sig += ", ";
        if (params[i]) sig += params[i]->name;
    }
    sig += ")";
    return sig;
}

/// Descriptor intermedio de un nombre declarado encontrado en el AST.
struct DeclName {
    std::string name;
    SymbolKind kind = SymbolKind::Unknown;
    uint32_t line = 0; ///< linea de referencia para emparejar con el token.
    std::string container;
    std::string signature;
};

/**
 * @brief Recorre el AST y recolecta los nombres declarados (con kind, linea,
 *        contenedor y firma) en @p out.
 *
 * Cubre declaraciones top-level y miembros (metodos, campos, parametros,
 * variantes de enum).  Robusto frente a nodos nulos (AST parcial mientras se
 * teclea).
 */
/**
 * @brief Recoge los nombres declarados de una lista de declaraciones.
 *
 * Se separa del modulo porque un @c namespace CONTIENE sus declaraciones, en
 * sus dos formas: tanto @c "namespace a.b.c;" -- que agrupa el resto del
 * fichero -- como @c "namespace a { ... }".  Sin bajar por el, un fichero que
 * empieza declarando su namespace no aportaba NI UN nombre: los campos, los
 * metodos y los parametros dejaban de resolverse, y las funciones parecian
 * funcionar solo porque las rescataba el indice semantico, que no llega a los
 * miembros.  Y casi todo el corpus y toda la biblioteca empiezan asi.
 *
 * @param decls Declaraciones a recorrer.
 * @param out   Nombres encontrados; se anaden al final.
 */
void collect_decls_from(
    const std::vector<std::unique_ptr<vx::ast::Node>> &decls,
    std::vector<DeclName> &out) {
    using namespace vx::ast;

    // Helper: registrar parametros de una lista.
    auto add_params = [&](const std::vector<std::unique_ptr<ParamDecl>> &params,
                          const std::string &owner) {
        for (const auto &p : params) {
            if (!p || p->name.empty()) continue;
            DeclName d;
            d.name = p->name;
            d.kind = SymbolKind::Parameter;
            d.line = p->loc.line;
            d.container = owner;
            out.push_back(std::move(d));
        }
    };

    for (const auto &node : decls) {
        if (!node) continue;
        switch (node->kind) {
        case NodeKind::NamespaceDecl: {
            // Bajar: lo declarado dentro es tan visible como lo de fuera.
            auto *ns = static_cast<const NamespaceDecl *>(node.get());
            collect_decls_from(ns->decls, out);
            break;
        }
        case NodeKind::FunctionDecl: {
            // ClassMethodDecl tambien usa NodeKind::FunctionDecl, pero a nivel
            // top-level solo aparecen FunctionDecl reales.
            auto *d = static_cast<const FunctionDecl *>(node.get());
            if (d->name.empty()) break;
            DeclName dn;
            dn.name = d->name;
            dn.kind = SymbolKind::Function;
            dn.line = d->loc.line;
            dn.signature = make_signature(d->name, d->params);
            out.push_back(std::move(dn));
            add_params(d->params, d->name);
            break;
        }
        case NodeKind::ExternFnDecl: {
            auto *d = static_cast<const ExternFnDecl *>(node.get());
            if (d->name.empty()) break;
            DeclName dn;
            dn.name = d->name;
            dn.kind = SymbolKind::Function;
            dn.line = d->loc.line;
            dn.signature = make_signature(d->name, d->params);
            dn.container = d->lib;
            out.push_back(std::move(dn));
            add_params(d->params, d->name);
            break;
        }
        case NodeKind::GlobalVarDecl: {
            auto *d = static_cast<const GlobalVarDecl *>(node.get());
            if (d->name.empty()) break;
            DeclName dn;
            dn.name = d->name;
            dn.kind = SymbolKind::Variable;
            dn.line = d->loc.line;
            out.push_back(std::move(dn));
            break;
        }
        case NodeKind::TypeAliasDecl: {
            auto *d = static_cast<const TypeAliasDecl *>(node.get());
            if (d->name.empty()) break;
            DeclName dn;
            dn.name = d->name;
            dn.kind = SymbolKind::TypeAlias;
            dn.line = d->loc.line;
            out.push_back(std::move(dn));
            break;
        }
        case NodeKind::StructDecl: {
            auto *d = static_cast<const StructDecl *>(node.get());
            if (!d->name.empty()) {
                DeclName dn;
                dn.name = d->name;
                dn.kind = SymbolKind::Struct;
                dn.line = d->loc.line;
                out.push_back(std::move(dn));
            }
            // Campos del struct.
            for (const auto &f : d->fields) {
                if (f.name.empty()) continue;
                DeclName dn;
                dn.name = f.name;
                dn.kind = SymbolKind::Field;
                dn.line = f.loc.line;
                dn.container = d->name;
                out.push_back(std::move(dn));
            }
            // Metodos del struct.
            for (const auto &m : d->methods) {
                if (!m || m->name.empty()) continue;
                DeclName dn;
                dn.name = m->name;
                dn.kind = SymbolKind::Method;
                dn.line = m->loc.line;
                dn.container = d->name;
                dn.signature = make_signature(m->name, m->params);
                out.push_back(std::move(dn));
                add_params(m->params, d->name + "." + m->name);
            }
            break;
        }
        case NodeKind::EnumDecl: {
            auto *d = static_cast<const EnumDecl *>(node.get());
            if (!d->name.empty()) {
                DeclName dn;
                dn.name = d->name;
                dn.kind = SymbolKind::Enum;
                dn.line = d->loc.line;
                out.push_back(std::move(dn));
            }
            for (const auto &v : d->variants) {
                if (v.name.empty()) continue;
                DeclName dn;
                dn.name = v.name;
                dn.kind = SymbolKind::EnumVariant;
                dn.line = v.loc.line;
                dn.container = d->name;
                out.push_back(std::move(dn));
            }
            break;
        }
        case NodeKind::ClassDecl: {
            auto *d = static_cast<const ClassDecl *>(node.get());
            if (!d->name.empty()) {
                DeclName dn;
                dn.name = d->name;
                dn.kind = SymbolKind::Class;
                dn.line = d->loc.line;
                out.push_back(std::move(dn));
            }
            for (const auto &f : d->fields) {
                if (f.name.empty()) continue;
                DeclName dn;
                dn.name = f.name;
                dn.kind = SymbolKind::Field;
                dn.line = f.loc.line;
                dn.container = d->name;
                out.push_back(std::move(dn));
            }
            for (const auto &m : d->methods) {
                if (!m || m->name.empty()) continue;
                DeclName dn;
                dn.name = m->name;
                dn.kind = SymbolKind::Method;
                dn.line = m->loc.line;
                dn.container = d->name;
                dn.signature = make_signature(m->name, m->params);
                out.push_back(std::move(dn));
                add_params(m->params, d->name + "." + m->name);
            }
            break;
        }
        case NodeKind::ConceptDecl: {
            auto *d = static_cast<const ConceptDecl *>(node.get());
            if (!d->name.empty()) {
                DeclName dn;
                dn.name = d->name;
                dn.kind = SymbolKind::Concept;
                dn.line = d->loc.line;
                // Firma legible: concept N<T> (usable como bound o predicado).
                std::string sig = "concept " + d->name;
                if (!d->type_params.empty()) {
                    sig += "<";
                    for (size_t i = 0; i < d->type_params.size(); ++i) {
                        if (i) sig += ", ";
                        sig += d->type_params[i];
                    }
                    sig += ">";
                }
                dn.signature = std::move(sig);
                out.push_back(std::move(dn));
            }
            break;
        }
        default: break;
        }
    }
}

void collect_decl_names(const vx::ast::ModuleNode &mod,
                        std::vector<DeclName> &out) {
    collect_decls_from(mod.decls, out);
}

} // namespace

DocSymbols build_doc_symbols(const std::string &text,
                             const std::string &filename) {
    DocSymbols out;

    // 1) Lexar: las referencias son todos los IDENTIFIER.
    std::vector<LexTok> toks = lex_all(text, filename);
    for (const auto &t : toks) {
        if (t.kind == vx::TokenKind::IDENTIFIER && t.length > 0) {
            SymbolRef r;
            r.name = t.lexeme;
            r.byte_offset = t.offset;
            r.byte_length = t.length;
            out.refs.push_back(std::move(r));
        }
    }

    // 2) Parsear el AST para nombres + kinds (best-effort, descartando diags).
    std::vector<DeclName> names;
    try {
        vx::Diagnostics diags;
        vx::Lexer lex(text, filename, diags);
        vx::Parser parser(lex, diags);
        std::unique_ptr<vx::ast::ModuleNode> mod = parser.parse_program();
        if (mod) collect_decl_names(*mod, names);
    } catch (...) {
        // AST parcial: seguimos solo con lo recolectado (posiblemente nada).
    }

    // 3) Emparejar cada nombre declarado con el token IDENTIFIER homonimo mas
    //    cercano a la linea de la declaracion.  Marcamos los tokens ya usados
    //    para no asignar dos definiciones al mismo token (p.ej. clase y su
    //    constructor comparten nombre pero en lineas distintas).
    std::vector<char> used(toks.size(), 0);
    for (const auto &dn : names) {
        // Buscar el token con menor |linea_token - linea_decl| cuyo lexema
        // coincida y no este usado.  Empate -> el de offset menor.
        size_t best = toks.size();
        uint32_t best_dist = 0xffffffffu;
        for (size_t i = 0; i < toks.size(); ++i) {
            if (used[i]) continue;
            const LexTok &t = toks[i];
            if (t.kind != vx::TokenKind::IDENTIFIER) continue;
            if (t.lexeme != dn.name) continue;
            uint32_t dist =
                (t.line >= dn.line) ? (t.line - dn.line) : (dn.line - t.line);
            if (dist < best_dist) {
                best_dist = dist;
                best = i;
            }
        }
        if (best >= toks.size())
            continue; // sin token homonimo: no localizable.
        used[best] = 1;
        SymbolDef def;
        def.name = dn.name;
        def.kind = dn.kind;
        def.byte_offset = toks[best].offset;
        def.byte_length = toks[best].length;
        def.container = dn.container;
        def.signature = dn.signature;
        out.defs.push_back(std::move(def));
    }

    return out;
}

// ---------------------------------------------------------------------------
// Helpers URI <-> ruta.
// ---------------------------------------------------------------------------

namespace {

/// Decodifica un nibble hexadecimal (0..15) o -1 si no es valido.
int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

std::string uri_to_fs_path(const std::string &uri) {
    const std::string prefix = "file://";
    if (uri.rfind(prefix, 0) != 0)
        return uri; // no es file://: devolver tal cual.
    std::string rest = uri.substr(prefix.size());
    // Tras file:// puede venir un "host" (normalmente vacio) seguido de /path.
    // En la practica del LSP es file:///C:/... o file:///home/...
    // Decodificar percent-encoding.
    std::string decoded;
    decoded.reserve(rest.size());
    for (size_t i = 0; i < rest.size(); ++i) {
        if (rest[i] == '%' && i + 2 < rest.size()) {
            int hi = hex_nibble(rest[i + 1]);
            int lo = hex_nibble(rest[i + 2]);
            if (hi >= 0 && lo >= 0) {
                decoded += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        decoded += rest[i];
    }
    // Windows: file:///C:/x -> "/C:/x"; quitar la barra inicial sobrante.
#if defined(_WIN32)
    if (decoded.size() >= 3 && decoded[0] == '/' &&
        std::isalpha(static_cast<unsigned char>(decoded[1])) &&
        decoded[2] == ':') {
        decoded.erase(decoded.begin());
    }
#endif
    return decoded;
}

std::string fs_path_to_uri(const std::string &fs_path) {
    // Normalizar barras invertidas a barras.
    std::string p = fs_path;
    for (char &c : p) {
        if (c == '\\') c = '/';
    }
    // Percent-encoding minimo: codificar espacios y unos pocos caracteres
    // problematicos; el resto se deja (suficiente para rutas locales).
    std::string enc;
    enc.reserve(p.size() + 8);
    for (char c : p) {
        unsigned char u = static_cast<unsigned char>(c);
        bool safe = (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') ||
                    (u >= '0' && u <= '9') || c == '/' || c == '.' ||
                    c == '-' || c == '_' || c == ':' || c == '~';
        if (safe) {
            enc += c;
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", u);
            enc += buf;
        }
    }
    // En Windows la ruta empieza por la letra de unidad (C:/...): anteponer
    // la barra para formar file:///C:/...  En POSIX la ruta ya empieza por /.
    if (!enc.empty() && enc[0] == '/') return "file://" + enc;
    return "file:///" + enc;
}

// ---------------------------------------------------------------------------
// WorkspaceIndex.
// ---------------------------------------------------------------------------

namespace {

/// Cap defensivo del numero de ficheros a indexar (evita colgar el server en
/// arboles enormes accidentales).
constexpr size_t kMaxIndexedFiles = 5000;

/// Devuelve true si @p name es un directorio que NO debe recorrerse.
bool is_skipped_dir(const std::string &name) {
    return name == ".git" || name == "build" || name == "node_modules" ||
           name == "_deps" || name == ".vx_cache" || name == ".cache" ||
           name == ".vscode" || name == "out" ||
           // cmake-build* (cmake-build-debug, cmake-build-release, ...).
           name.rfind("cmake-build", 0) == 0;
}

/// Devuelve true si @p name termina en la extension del lenguaje Vesta: `.vx`.
bool has_vx_ext(const std::string &name) {
    const char *ext = ".vx";
    const size_t el = std::strlen(ext);
    return name.size() > el && name.compare(name.size() - el, el, ext) == 0;
}

/**
 * @brief Recorre recursivamente @p dir acumulando rutas de ficheros @c .vx en
 *        @p out, saltando directorios de build/cache y respetando el cap.
 */
void collect_vx_files(const std::string &dir, std::vector<std::string> &out) {
    if (out.size() >= kMaxIndexedFiles) return;
#if defined(_WIN32)
    std::string pattern = dir + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        std::string full = dir + "\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (is_skipped_dir(name)) continue;
            collect_vx_files(full, out);
        } else if (has_vx_ext(name)) {
            out.push_back(full);
        }
        if (out.size() >= kMaxIndexedFiles) break;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir.c_str());
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") continue;
        std::string full = dir + "/" + name;
        struct stat st;
        if (stat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (is_skipped_dir(name)) continue;
            collect_vx_files(full, out);
        } else if (S_ISREG(st.st_mode) && has_vx_ext(name)) {
            out.push_back(full);
        }
        if (out.size() >= kMaxIndexedFiles) break;
    }
    closedir(d);
#endif
}

/// Lee un fichero entero a un std::string; devuelve false si falla.
///
/// Con los fines de linea normalizados, igual que el compilador: si el servidor
/// de lenguaje contara las lineas de otra manera, senalaria a un sitio distinto
/// del que senala el error al compilar.
bool read_file(const std::string &path, std::string &out) {
    return vx::leer_fuente(path, out);
}

} // namespace

void WorkspaceIndex::set_roots(const std::vector<std::string> &roots) {
    roots_ = roots;
    built_ = false;
    defs_.clear();
    refs_.clear();
}

void WorkspaceIndex::erase_uri_entries(const std::string &uri) {
    // Quitar de defs_ y refs_ todas las entradas cuyo uri coincida.
    for (auto &kv : defs_) {
        auto &v = kv.second;
        v.erase(std::remove_if(
                    v.begin(), v.end(),
                    [&](const WorkspaceLocation &l) { return l.uri == uri; }),
                v.end());
    }
    for (auto &kv : refs_) {
        auto &v = kv.second;
        v.erase(std::remove_if(
                    v.begin(), v.end(),
                    [&](const WorkspaceLocation &l) { return l.uri == uri; }),
                v.end());
    }
}

void WorkspaceIndex::index_content(const std::string &uri,
                                   const std::string & /*fs_path*/,
                                   const std::string &text) {
    DocSymbols sym = build_doc_symbols(text, uri);
    // Definiciones.
    for (const auto &d : sym.defs) {
        WorkspaceLocation loc;
        loc.uri = uri;
        byte_offset_to_lsp_position(text, d.byte_offset, loc.start_line,
                                    loc.start_char);
        byte_offset_to_lsp_position(text, d.byte_offset + d.byte_length,
                                    loc.end_line, loc.end_char);
        loc.kind = d.kind;
        loc.container = d.container;
        loc.signature = d.signature;
        defs_[d.name].push_back(std::move(loc));
    }
    // Referencias.
    for (const auto &r : sym.refs) {
        WorkspaceLocation loc;
        loc.uri = uri;
        byte_offset_to_lsp_position(text, r.byte_offset, loc.start_line,
                                    loc.start_char);
        byte_offset_to_lsp_position(text, r.byte_offset + r.byte_length,
                                    loc.end_line, loc.end_char);
        refs_[r.name].push_back(std::move(loc));
    }
}

void WorkspaceIndex::index_path(const std::string &fs_path) {
    std::string text;
    if (!read_file(fs_path, text)) return; // fichero ilegible: saltarlo.
    const std::string uri = fs_path_to_uri(fs_path);
    index_content(uri, fs_path, text);
}

void WorkspaceIndex::ensure_built() {
    /* Bajo cerrojo: quien llegue segundo ESPERA a que el indice este entero.
     *
     * La marca se pone antes de construir -- para que un fallo no reintente en
     * bucle -- asi que sin esperar, el segundo la veia puesta y consultaba un
     * indice a medio hacer.  Y no daba error: contestaba "no lo encuentro",
     * que se lee igual que "no existe".  Se vio con `definition` y
     * `references` pedidos a la vez, que es lo normal en cuanto el editor
     * reparte las consultas entre hilos.
     *
     * Solo cuesta la PRIMERA vez: despues sale por la marca sin pelearse por
     * nada. */
    std::lock_guard<std::mutex> guard(build_mutex_);
    if (built_) return;
    built_ = true; // marcar antes para que un fallo no reintente en bucle.
    std::vector<std::string> files;
    for (const auto &root : roots_) {
        if (root.empty()) continue;
        collect_vx_files(root, files);
    }
    for (const auto &f : files) {
        if (defs_.size() + refs_.size() > 0 && f.empty()) continue;
        try {
            index_path(f);
        } catch (...) {
            // Un fichero que falle no debe abortar el indexado completo.
        }
    }
}

void WorkspaceIndex::update_file(const std::string &uri,
                                 const std::string &text) {
    // Quitar la contribucion previa de este uri (de disco o de una version
    // anterior) y volver a indexar con el texto vivo.
    erase_uri_entries(uri);
    try {
        index_content(uri, uri_to_fs_path(uri), text);
    } catch (...) {
        // Robustez: un fallo deja el fichero sin entradas (no tumba el server).
    }
}

void WorkspaceIndex::remove_file(const std::string &uri) {
    erase_uri_entries(uri);
}

std::vector<WorkspaceLocation>
WorkspaceIndex::defs_for(const std::string &name) const {
    auto it = defs_.find(name);
    if (it == defs_.end()) return {};
    return it->second;
}

std::vector<WorkspaceLocation>
WorkspaceIndex::refs_for(const std::string &name) const {
    auto it = refs_.find(name);
    if (it == refs_.end()) return {};
    return it->second;
}

void WorkspaceIndex::for_each_def_name(
    const std::function<void(const std::string &, SymbolKind,
                             const std::string &)> &fn) const {
    // Recorrer el mapa nombre -> [definiciones] y reportar la PRIMERA
    // definicion de cada nombre (kind + firma).  El kind de un nombre puede
    // variar entre ficheros homonimos; para el completado basta el primero.
    for (const auto &kv : defs_) {
        if (kv.second.empty()) continue;
        const WorkspaceLocation &first = kv.second.front();
        fn(kv.first, first.kind, first.signature);
    }
}

std::vector<std::string> import_search_roots(const std::string &fs_path) {
    std::vector<std::string> raices;
    if (fs_path.empty()) return raices;

    std::string d = fs_path;
    const size_t barra = d.find_last_of("/\\");
    if (barra == std::string::npos) return raices;
    d = d.substr(0, barra);

    /* Acotado a 40 niveles por si la ruta es patologica: nadie anida cuarenta
     * directorios, y una ruta que se repita a si misma colgaria el bucle. */
    for (int nivel = 0; nivel < 40 && !d.empty(); ++nivel) {
        raices.push_back(d);
        // Con manifiesto, aqui empieza el paquete: se incluye y se para.
        if (std::ifstream(d + "/vx.toml").good() ||
            std::ifstream(d + "/vx.json").good())
            break;
        const size_t s = d.find_last_of("/\\");
        // La raiz del sistema de ficheros: POSIX "/" o Windows "C:".
        if (s == std::string::npos || s == 0 || (s == 2 && d[1] == ':')) break;
        d = d.substr(0, s);
    }
    return raices;
}

} // namespace lsp
