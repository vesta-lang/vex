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
 * @file lsp_server.cpp
 * @brief Implementacion del dispatcher y bucle de eventos del LSP de Vesta.
 */

#include "lsp/lsp_server.h"

#include <filesystem>

#include "vx/fmt/fmt.h"
#include "vx/fmt/fmt_driver.h"
#include "vx/diag/diag_catalog.h"
#include "vx/diag/diag_format.h" // formatted_message: el MISMO texto que la CLI
#include "vx/module/namespace_flatten.h" // demangle_symbol: el nombre escrito

#include "lsp/builtin_docs.h"
#include "toolchain/toolchain.h" // vesta::tc::compile (compilar embebido)
#include "util/fs_utils.h"       // fs::get_executable_path (localizar stdlib)

#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <exception>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "lsp/param_hints.h"
#include "lsp/semantic_tokens.h"
#include "lsp/symbol_index.h"
#include "vx/ast.h"
#include "vx/diagnostic.h"
#include "vx/source_text.h" // un solo fin de linea para todo el pipeline

namespace lsp {

namespace {

/**
 * @brief Mapea la severidad del compilador a la del LSP.
 *
 * LSP: 1=Error, 2=Warning, 3=Information, 4=Hint.  Las NOTE del
 * compilador se mapean a Information (3).
 *
 * @param level Nivel del diagnostico Vesta.
 * @return Codigo de severidad LSP.
 */
int diag_severity_to_lsp(vx::DiagLevel level) {
    switch (level) {
    case vx::DiagLevel::ERR: return 1;  // Error
    case vx::DiagLevel::WARN: return 2; // Warning
    case vx::DiagLevel::NOTE: return 3; // Information
    }
    return 1;
}

} // namespace

LspServer::LspServer(JsonRpcTransport transport)
    : transport_(std::move(transport)) {}

void LspServer::send_result(const nlohmann::json &id,
                            const nlohmann::json &result) {
    // Respuesta JSON-RPC 2.0 estandar: jsonrpc + id + result.
    nlohmann::json resp;
    resp["jsonrpc"] = "2.0";
    resp["id"] = id;
    resp["result"] = result;
    transport_.write_message(resp);
}

nlohmann::json LspServer::compile_request(const std::string &method,
                                          const std::string &uri,
                                          const nlohmann::json &params) {
    namespace tc = vesta::tc;
    const std::string fs_path = uri_to_fs_path(uri);
    if (fs_path.empty())
        return {{"ok", false}, {"message", "uri sin ruta de fichero"}};

    tc::CompileRequest req;
    req.input = fs_path;
    // Si el documento esta abierto, usar su buffer (overlay) en vez del disco.
    if (docs_.has(uri)) req.source_overlay = *docs_.text(uri);
    req.output = params.value("output", std::string());
    req.module_name = params.value("moduleName", std::string("main"));
    req.debug = params.value("debug", false);
    // Con que nivel optimizar: -1 = el de por defecto del frontend.
    req.opt_level = params.value("opt", -1);
    req.instrument = params.value("instrument", std::string());
    req.keep_labels = params.value("keepLabels", false);
    req.emit_map = params.value("emitMap", false);
    req.no_preprocessor = params.value("noPreprocessor", false);
    // Critico: silenciar el stdout del ensamblado/linkado; en el LSP el stdout
    // es el canal JSON-RPC y cualquier print de run_worker lo corromperia.
    req.quiet = true;

    // Modo: vm | jit | aot.
    const std::string mode = params.value("mode", std::string("vm"));
    if (mode == "aot") {
        req.mode = tc::ExecMode::AOT;
        // Opciones del emisor nativo (todas opcionales; defaults por
        // host/tier).
        const std::string tier = params.value("tier", std::string("bare"));
        req.aot.tier = (tier == "embed") ? aot::Tier::EMBED
                                         : (tier == "full" ? aot::Tier::FULL
                                                           : aot::Tier::BARE);
        req.aot.freestanding = params.value("freestanding", false);
        req.aot.no_exceptions = params.value("noExceptions", false);
        req.aot.no_io = params.value("noIo", false);
        req.aot.no_mem = params.value("noMem", false);
        req.aot.arch = params.value("arch", std::string("x86-64"));
        req.aot.float_isa = params.value("floatIsa", std::string("sse2"));
        req.aot.format = params.value("format", std::string());
        req.aot.emit = params.value("emit", std::string());
        req.aot.no_pie = params.value("noPie", false);
        req.aot.bin_base = params.value("binBase", std::string());
        req.aot.sysroot = params.value("sysroot", std::string());
        // Para localizar la stdlib (auto-bundle de exc/io): junto al
        // ejecutable.
        req.aot.argv0 = fs::get_executable_path();
    } else if (mode == "jit")
        req.mode = tc::ExecMode::JIT;
    else
        req.mode = tc::ExecMode::VM;

    // Proyecto: explicito por el metodo/param, o auto-detectado si el fuente
    // tiene algun `import "..."`.
    const auto src_ref = docs_.text(uri);
    const std::string &src = *src_ref;
    const bool has_imports = src.find("import \"") != std::string::npos ||
                             src.find("import\t\"") != std::string::npos;
    req.is_project = (method == "vesta/compileProject") ||
                     params.value("project", has_imports);

    // Para proyectos, pasar los directorios ancestros como search paths (igual
    // que el analisis), para resolver imports relativos al root.
    if (req.is_project) {
        for (const auto &d : import_search_roots(fs_path))
            req.search_paths.push_back(d);
    }

    tc::CompileResponse cr = tc::compile(req);

    nlohmann::json diags = nlohmann::json::array();
    for (const auto &d : cr.diagnostics) {
        nlohmann::json jd;
        jd["level"] =
            (d.level == tc::DiagLevel::Error)
                ? "error"
                : (d.level == tc::DiagLevel::Warning ? "warning" : "note");
        jd["line"] = d.line;
        jd["column"] = d.column;
        jd["message"] = d.message;
        jd["file"] = d.file;
        diags.push_back(std::move(jd));
    }

    nlohmann::json out;
    out["ok"] = cr.ok;
    out["output"] = cr.output_path;
    out["diagnostics"] = std::move(diags);
    out["frontend_us"] = cr.frontend_us;
    out["mode"] = mode;
    out["project"] = req.is_project;
    if (!cr.message.empty()) out["message"] = cr.message;
    return out;
}

void LspServer::handle_initialize(const nlohmann::json &msg) {
    // Capturar las raices del workspace (rootUri / rootPath / workspaceFolders)
    // para el indice de simbolos de la Fase 4.  El indexado real es perezoso:
    // solo se construye en la primera peticion de navegacion.
    if (msg.contains("params") && msg.at("params").is_object()) {
        const nlohmann::json &params = msg.at("params");
        std::vector<std::string> roots;
        // workspaceFolders[] (LSP moderno): [{ uri, name }, ...].
        if (params.contains("workspaceFolders") &&
            params.at("workspaceFolders").is_array()) {
            for (const auto &wf : params.at("workspaceFolders")) {
                if (wf.is_object() && wf.contains("uri") &&
                    wf.at("uri").is_string()) {
                    roots.push_back(
                        uri_to_fs_path(wf.at("uri").get<std::string>()));
                }
            }
        }
        // rootUri (deprecado pero comun).
        if (params.contains("rootUri") && params.at("rootUri").is_string()) {
            roots.push_back(
                uri_to_fs_path(params.at("rootUri").get<std::string>()));
        }
        // rootPath (muy antiguo): ya es una ruta de sistema de ficheros.
        if (params.contains("rootPath") && params.at("rootPath").is_string()) {
            roots.push_back(params.at("rootPath").get<std::string>());
        }
        // Para que maquina analizar.  El editor lo manda al arrancar y cada
        // vez que se cambia (@c workspace/didChangeConfiguration).
        apply_target_settings(
            params.value("initializationOptions", nlohmann::json::object()));
        // Deduplicar entradas vacias/repetidas conservando el orden.
        std::vector<std::string> uniq;
        for (const auto &r : roots) {
            if (r.empty()) continue;
            bool dup = false;
            for (const auto &u : uniq) {
                if (u == r) {
                    dup = true;
                    break;
                }
            }
            if (!dup) uniq.push_back(r);
        }
        workspace_.set_roots(uniq);
    }

    // Anunciar las capacidades soportadas en esta fase.  textDocumentSync=1
    // = sincronizacion full (cada cambio envia el texto completo).  Se deja
    // sitio para anunciar capacidades futuras (semanticTokens, hover, etc.).
    nlohmann::json caps;
    caps["textDocumentSync"] = 1; // TextDocumentSyncKind.Full

    // Resaltado semantico (Fase 2): anunciar la leyenda (tokenTypes +
    // tokenModifiers, en orden = indices) y soporte de documento completo.
    // No se anuncia range/delta en esta fase.
    nlohmann::json sem;
    nlohmann::json legend;
    legend["tokenTypes"] = semantic_token_types();
    legend["tokenModifiers"] = semantic_token_modifiers();
    sem["legend"] = std::move(legend);
    sem["full"] = true;
    sem["range"] = false;
    caps["semanticTokensProvider"] = std::move(sem);

    // Navegacion (Fase 4): hover, ir a la definicion y buscar referencias.
    /* Dar formato al fichero entero.  Es lo que enchufa `vesta fmt` al editor:
     * el mismo codigo, el mismo estandar y el mismo resultado que en la linea
     * de ordenes, sin que el editor tenga que saber nada de reglas.
     *
     * Solo el documento COMPLETO (`documentFormattingProvider`), no por rango:
     * la alineacion de un bloque mira a sus vecinas y las columnas de un trozo
     * suelto no significan nada sin el resto. */
    caps["documentFormattingProvider"] = true;
    caps["hoverProvider"] = true;
    caps["definitionProvider"] = true;
    caps["referencesProvider"] = true;
    // Buscar un simbolo por su nombre: es lo que permite ir a una funcion
    // desde un sitio donde solo se la nombra.
    caps["workspaceSymbolProvider"] = true;

    // Autocompletado (Fase 5): se dispara al teclear o tras el punto '.'
    // (acceso a miembros).  No resolvemos detalles diferidos (resolveProvider
    // false): cada item llega ya completo.
    nlohmann::json comp;
    comp["triggerCharacters"] = nlohmann::json::array({"."});
    comp["resolveProvider"] = false;
    caps["completionProvider"] = std::move(comp);

    // Inspector del ecosistema (Fase 3): las peticiones a medida vesta/* no
    // forman parte del LSP estandar, asi que se anuncian bajo el campo
    // experimental para que un cliente que las conozca las descubra.
    nlohmann::json experimental;
    experimental["vestaMethods"] =
        nlohmann::json::array({"vesta/bytecode",       "vesta/ir",
                               "vesta/complexity",     "vesta/diagram",
                               "vesta/functions",      "vesta/aotCompat",
                               "vesta/jitAsm",         "vesta/aotAsm",
                               "vesta/modes",          "vesta/compile",
                               "vesta/compileProject", "vesta/macroExpand",
                               "vesta/comptimeValues", "vesta/asa",
                               "vesta/asaFacts",       "vesta/targets",
                               "vesta/instruction",    "vesta/functionReport",
                               "vesta/asmBlock",       "vesta/asmFlow"});
    caps["experimental"] = std::move(experimental);

    nlohmann::json result;
    result["capabilities"] = caps;
    nlohmann::json server_info;
    server_info["name"] = "vesta-lsp";
    server_info["version"] = "0.1.0";
    result["serverInfo"] = server_info;

    // Responder a la peticion (initialize SIEMPRE lleva id).
    send_result(msg.at("id"), result);
    initialized_ = true;
}

void LspServer::handle_shutdown(const nlohmann::json &msg) {
    // El cliente pide cerrar: responder result null y esperar el exit.
    shutdown_requested_ = true;
    send_result(msg.at("id"), nullptr);
}

void LspServer::handle_did_open(const nlohmann::json &params) {
    // params.textDocument = { uri, languageId, version, text }
    const auto &td = params.at("textDocument");
    const std::string uri = td.at("uri").get<std::string>();
    std::string text = td.value("text", std::string());
    docs_.open(uri, text);
    // Refrescar la entrada de este fichero en el indice con su texto VIVO (el
    // del editor, no el de disco).  Solo si el indice ya se construyo; si no,
    // se hara perezosamente en la primera navegacion.
    workspace_.update_file(uri, text);
    publish_diagnostics(uri);
}

void LspServer::handle_did_change(const nlohmann::json &params) {
    // Sincronizacion full: tomamos el texto del ultimo contentChange.
    const auto &td = params.at("textDocument");
    const std::string uri = td.at("uri").get<std::string>();
    if (!params.contains("contentChanges")) return;
    const auto &changes = params.at("contentChanges");
    if (!changes.is_array() || changes.empty()) return;
    // En modo full sync, el ultimo cambio contiene el documento entero.
    const auto &last = changes.back();
    std::string text = last.value("text", std::string());
    docs_.update(uri, text);
    // Reindexar SOLO este fichero con su texto vivo.
    workspace_.update_file(uri, text);
    publish_diagnostics(uri);
}

void LspServer::handle_did_close(const nlohmann::json &params) {
    const auto &td = params.at("textDocument");
    const std::string uri = td.at("uri").get<std::string>();
    docs_.close(uri);
    engine_.forget(uri);
    // El fichero deja de estar abierto: su contribucion al indice (que usaba el
    // texto vivo) se reemplaza por su version de disco si existe.  Leemos el
    // disco best-effort; si no se puede, quitamos sus entradas.
    {
        const std::string fs_path = uri_to_fs_path(uri);
        std::string texto;
        if (vx::leer_fuente(fs_path, texto)) {
            workspace_.update_file(uri, std::move(texto));
        } else {
            workspace_.remove_file(uri);
        }
    }
    // Publicar una lista de diagnosticos vacia limpia los del editor.
    nlohmann::json note;
    note["jsonrpc"] = "2.0";
    note["method"] = "textDocument/publishDiagnostics";
    nlohmann::json p;
    p["uri"] = uri;
    p["diagnostics"] = nlohmann::json::array();
    note["params"] = p;
    transport_.write_message(note);
}

void LspServer::apply_target_settings(const nlohmann::json &settings) {
    if (!settings.is_object()) return;
    /* Un editor manda su configuracion anidada bajo el nombre de la extension;
     * quien llame al servidor a mano suele mandar el objeto plano.  Se aceptan
     * las dos porque las dos dicen lo mismo. */
    const nlohmann::json *donde = &settings;
    if (settings.contains("vesta") && settings.at("vesta").is_object()) {
        const nlohmann::json &v = settings.at("vesta");
        if (v.contains("inspect") && v.at("inspect").is_object())
            donde = &v.at("inspect");
        else
            donde = &v;
    }
    engine_.set_target(donde->value("os", std::string()),
                       donde->value("arch", std::string()));
}

void LspServer::publish_diagnostics(const std::string &uri) {
    // Compilar (o reusar cache) el documento.
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    const auto an_ref = engine_.analyze_document(uri, text);
    const DocAnalysis &an = *an_ref;

    // Construir el array de diagnosticos LSP a partir de los del compilador.
    nlohmann::json diags = nlohmann::json::array();
    for (const auto &d : an.result.diagnostics.all()) {
        // El compilador da linea/columna 1-based en bytes; el LSP exige
        // 0-based + caracter en UTF-16.  Convertir cada extremo del span.
        const vx::SourceLoc &loc = d.loc;
        // Linea 0-based (proteger contra line==0 hipotetico).
        uint32_t line0 = loc.line > 0 ? loc.line - 1 : 0;
        // Texto de la linea para la conversion de columnas.
        std::string line_text = docs_.line(uri, line0);
        // Span en bytes 0-based dentro de la linea [span_start, span_end).
        uint32_t span_start = loc.column > 0 ? loc.column - 1 : 0;
        uint32_t span_end = span_start + (loc.length > 0 ? loc.length : 1);
        // Si el span es de un solo byte (tipico cuando el diagnostico apunta a
        // un simbolo suelto -- p.ej. el '(' de una llamada como static_assert),
        // ensancharlo al token legible bajo esa posicion para que el subrayado
        // sea visible y util en lugar de marcar un solo caracter.
        if (span_end <= span_start + 1) {
            auto is_ident = [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_';
            };
            const std::string &lt = line_text;
            // Si el punto cae en la indentacion / espacios (diagnostico cuyo
            // loc apunta al inicio de la sentencia), avanzar al primer token
            // real de la linea: un subrayado sobre el hueco en blanco no se
            // entiende.
            while (span_start < lt.size() &&
                   (lt[span_start] == ' ' || lt[span_start] == '\t'))
                ++span_start;
            span_end = span_start + 1;
            if (span_start < lt.size() && is_ident(lt[span_start])) {
                // Identificador bajo la posicion: extender hacia adelante hasta
                // el final del identificador.
                uint32_t e = span_start;
                while (e < lt.size() && is_ident(lt[e]))
                    ++e;
                span_end = e;
            } else if (span_start > 0 && span_start <= lt.size() &&
                       is_ident(lt[span_start - 1])) {
                // Simbolo precedido de un identificador (p.ej.
                // "static_assert("): subrayar ese identificador anterior, que
                // es lo significativo.
                uint32_t s = span_start;
                while (s > 0 && is_ident(lt[s - 1]))
                    --s;
                span_end = span_start;
                span_start = s;
            }
        }
        // Conversion de cada extremo (columna 1-based en bytes) a UTF-16.
        uint32_t start_char = byte_column_to_utf16(line_text, span_start + 1);
        uint32_t end_char = byte_column_to_utf16(line_text, span_end + 1);

        nlohmann::json range;
        range["start"] = {{"line", line0}, {"character", start_char}};
        // El span no cruza lineas en el modelo actual del compilador.
        range["end"] = {{"line", line0}, {"character", end_char}};

        nlohmann::json jd;
        jd["range"] = range;
        jd["severity"] = diag_severity_to_lsp(d.level);
        jd["source"] = "vesta";
        if (!d.code.empty()) jd["code"] = d.code;
        /* El texto se compone AQUI, igual que al imprimirlo por la linea de
         * ordenes: un diagnostico catalogado no lleva la frase escrita, lleva
         * el codigo y los datos.  Publicando el campo crudo salia vacio, y el
         * editor rechaza un diagnostico sin texto -- y con el, la tanda entera:
         * no se veia NINGUNO.
         *
         * Y si aun asi no hubiera texto -- un codigo que no esta en el catalogo
         * y sin mensaje crudo --, se manda el codigo antes que nada: decir poco
         * es mejor que tirar la tanda. */
        std::string texto = vx::formatted_message(d);
        if (texto.empty())
            texto = d.code.empty() ? std::string("(sin texto)") : d.code;
        jd["message"] = std::move(texto);
        diags.push_back(std::move(jd));
    }

    // Emitir la notificacion publishDiagnostics.
    nlohmann::json note;
    note["jsonrpc"] = "2.0";
    note["method"] = "textDocument/publishDiagnostics";
    nlohmann::json p;
    p["uri"] = uri;
    p["diagnostics"] = std::move(diags);
    note["params"] = std::move(p);
    transport_.write_message(note);
}

void LspServer::handle_semantic_tokens_full(const nlohmann::json &msg) {
    // params.textDocument.uri identifica el documento.
    const auto &params = msg.at("params");
    const auto &td = params.at("textDocument");
    const std::string uri = td.at("uri").get<std::string>();

    // Calcular los tokens.  Si el documento no esta abierto, devolvemos una
    // lista vacia (data: []) en lugar de un error: el cliente lo tolera.
    nlohmann::json data = nlohmann::json::array();
    if (docs_.has(uri)) {
        const auto text_ref = docs_.text(uri);
        const std::string &text = *text_ref;
        // Reusar el analisis cacheado (mismo punto que los diagnosticos) para
        // enriquecer los identificadores con los nombres declarados.
        const auto an_ref = engine_.analyze_document(uri, text);
        const DocAnalysis &an = *an_ref;
        std::vector<uint32_t> toks = compute_semantic_tokens(text, uri, &an);
        // Volcar el array plano de uint32 a JSON.
        data = nlohmann::json(toks);
    }

    nlohmann::json result;
    result["data"] = std::move(data);
    send_result(msg.at("id"), result);
}

namespace {

/**
 * @brief Construye el objeto @c Range LSP a partir de coordenadas 0-based.
 */
nlohmann::json make_range(uint32_t sl, uint32_t sc, uint32_t el, uint32_t ec) {
    nlohmann::json r;
    r["start"] = {{"line", sl}, {"character", sc}};
    r["end"] = {{"line", el}, {"character", ec}};
    return r;
}

/**
 * @brief Construye un objeto @c Location LSP a partir de una
 *        @c WorkspaceLocation.
 */
nlohmann::json make_location(const lsp::WorkspaceLocation &l) {
    nlohmann::json j;
    j["uri"] = l.uri;
    j["range"] = make_range(l.start_line, l.start_char, l.end_line, l.end_char);
    return j;
}

// ---------------------------------------------------------------------------
// Soporte de autocompletado (Fase 5).
// ---------------------------------------------------------------------------

/// Codigos @c CompletionItemKind del LSP usados aqui.
enum class CompletionKind : int {
    Method = 2,
    Function = 3,
    Field = 5,
    Variable = 6,
    Class = 7,
    Interface = 8,
    Enum = 13,
    Keyword = 14,
    Struct = 22,
    TypeParameter = 25,
};

/**
 * @brief Construye un @c CompletionItem LSP.
 *
 * @param label  Texto mostrado y a insertar.
 * @param kind   Categoria LSP.
 * @param detail Detalle opcional (firma o tipo); vacio para omitir.
 * @return Objeto JSON del item.
 */
nlohmann::json make_completion_item(const std::string &label,
                                    CompletionKind kind,
                                    const std::string &detail) {
    nlohmann::json it;
    it["label"] = label;
    it["kind"] = static_cast<int>(kind);
    it["insertText"] = label;
    if (!detail.empty()) it["detail"] = detail;
    return it;
}

/**
 * @brief Extrae el comentario de documentacion que PRECEDE a una definicion.
 *
 * Dado el offset de byte del nombre de la definicion, sube por las lineas
 * inmediatamente anteriores recolectando:
 *   - lineas de comentario @c // (se quita el @c // y un espacio inicial),
 *   - lineas de un bloque @c /* ... *\/ (se quitan los delimitadores y un @c *
 *     de continuacion al inicio).
 * Se detiene en la primera linea que no es comentario (codigo o linea en
 * blanco).  Devuelve las lineas en orden natural unidas por @c \n, o "" si no
 * hay comentario.  Tolerante: cualquier caso raro devuelve lo acumulado.
 */
std::string extract_doc_comment(const std::string &text, size_t name_offset) {
    if (name_offset > text.size()) return std::string();
    // Inicio de la linea que contiene el nombre.
    size_t line_start = text.rfind('\n', name_offset ? name_offset - 1 : 0);
    line_start = (line_start == std::string::npos) ? 0 : line_start + 1;

    auto trim = [](const std::string &s) -> std::string {
        size_t a = s.find_first_not_of(" \t\r");
        if (a == std::string::npos) return std::string();
        size_t b = s.find_last_not_of(" \t\r");
        return s.substr(a, b - a + 1);
    };

    std::vector<std::string>
        doc; // de la mas cercana a la mas lejana (luego se invierte)
    size_t pos = line_start;
    int guard = 0;
    /* Balance de parentesis contado HACIA ARRIBA.  Una anotacion puede
     * repartir sus argumentos en varias lineas (`@complexity(O(n),` y en la
     * siguiente `n = len(arg0))`); subiendo, la linea de cierre se reconoce
     * porque cierra mas de lo que abre.  Mientras el balance sea negativo
     * seguimos dentro de esa anotacion. */
    int paren_depth = 0;
    while (pos > 0 && guard++ < 200) {
        // Linea anterior: [prev_start, prev_end) sin el '\n'.
        size_t nl = text.rfind('\n', pos - 2 < text.size() ? pos - 2 : 0);
        size_t prev_start = (pos >= 2 && nl != std::string::npos) ? nl + 1 : 0;
        if (pos < 2) prev_start = 0;
        size_t prev_end = pos - 1; // posicion del '\n' que separa.
        if (prev_end > text.size()) break;
        std::string raw = text.substr(prev_start, prev_end - prev_start);
        std::string t = trim(raw);
        if (t.rfind("//", 0) == 0) {
            std::string c = t.substr(2);
            // Las formas de documentacion `///` y `//!` llevan un tercer
            // caracter que es marca, no texto: sin quitarlo cada linea
            // empezaba por una barra suelta.
            if (!c.empty() && (c[0] == '/' || c[0] == '!')) c = c.substr(1);
            if (!c.empty() && c[0] == ' ') c = c.substr(1);
            // saltar las marcas Doxygen de mero formato (@brief queda visible).
            doc.push_back(c);
            pos = prev_start;
            continue;
        }
        // Linea de bloque: "*/", "* ...", "/** ...", "/* ...".
        if (t == "*/" || t.rfind("* ", 0) == 0 || t == "*" ||
            t.rfind("/**", 0) == 0 || t.rfind("/*", 0) == 0) {
            std::string c = t;
            // Limpiar delimitadores.  El CIERRE va primero: quitandolo despues
            // del asterisco de la izquierda, una linea que solo tiene `*/` se
            // quedaba en una barra suelta que aparecia dentro de la
            // documentacion.
            if (c.size() >= 2 && c.compare(c.size() - 2, 2, "*/") == 0)
                c = c.substr(0, c.size() - 2);
            if (c.rfind("/**", 0) == 0)
                c = c.substr(3);
            else if (c.rfind("/*", 0) == 0)
                c = c.substr(2);
            if (!c.empty() && c[0] == '*') c = c.substr(1);
            c = trim(c);
            if (!c.empty()) doc.push_back(c);
            pos = prev_start;
            // si era la apertura del bloque, ya terminamos.
            if (t.rfind("/*", 0) == 0) break;
            continue;
        }
        /* Entre el comentario y la declaracion caben anotaciones -- @Target,
         * @nothrow, @complexity(...) --, y son lo normal en la biblioteca.  No
         * cortan la documentacion: se saltan.  Sin esto, un comentario perdia
         * a su funcion en cuanto alguien le ponia un atributo delante, y el
         * hover se quedaba mudo sin decir por que. */
        {
            int balance = 0;
            for (char c : t) {
                if (c == '(')
                    ++balance;
                else if (c == ')')
                    --balance;
            }
            const bool es_anotacion = !t.empty() && t[0] == '@';
            // Negativo = esta linea cierra parentesis que abrio otra de mas
            // arriba, luego es la continuacion de una anotacion.
            if (es_anotacion || balance < 0 || paren_depth < 0) {
                paren_depth += balance;
                pos = prev_start;
                continue;
            }
        }
        // Ni comentario, ni continuacion de bloque, ni anotacion: fin de la
        // doc.
        break;
    }
    if (doc.empty()) return std::string();
    std::string out;
    for (auto it = doc.rbegin(); it != doc.rend(); ++it) {
        if (!out.empty()) out += "\n";
        out += *it;
    }
    return out;
}

/**
 * @brief Da forma de markdown a un comentario de documentacion.
 *
 * El comentario se escribe en lineas, pero markdown junta las lineas seguidas
 * en un parrafo: sin dar forma, la descripcion y todos los @param acaban en un
 * bloque corrido donde no se distingue donde empieza cada cosa.
 *
 * Las etiquetas de Doxygen pasan a ser lo que son: los parametros, una lista
 * con su nombre destacado; lo que se devuelve y lo que se lanza, lineas
 * propias.  El texto libre se deja fluir, que es lo que quiere la prosa.
 *
 * @param doc Comentario tal y como se escribio, linea a linea.
 * @return El mismo contenido listo para mostrar.
 */
std::string doc_to_markdown(const std::string &doc) {
    if (doc.empty()) return doc;

    auto trim = [](const std::string &s) -> std::string {
        const size_t a = s.find_first_not_of(" \t\r");
        if (a == std::string::npos) return std::string();
        const size_t b = s.find_last_not_of(" \t\r");
        return s.substr(a, b - a + 1);
    };

    std::string descripcion; ///< texto libre, que fluye.
    std::vector<std::string> parametros;
    std::vector<std::string> otras; ///< devuelve / lanza / ve / nota.
    // A que se le esta anadiendo el texto que continua en la linea siguiente.
    enum class Destino {
        Descripcion,
        Parametro,
        Otra
    } destino = Destino::Descripcion;

    size_t pos = 0;
    while (pos <= doc.size()) {
        const size_t nl = doc.find('\n', pos);
        const std::string linea = trim(doc.substr(
            pos, nl == std::string::npos ? std::string::npos : nl - pos));
        pos = (nl == std::string::npos) ? doc.size() + 1 : nl + 1;

        if (linea.empty()) {
            // Una linea en blanco separa parrafos y corta la continuacion.
            if (destino == Destino::Descripcion && !descripcion.empty() &&
                descripcion.size() >= 2 &&
                descripcion.compare(descripcion.size() - 2, 2, "\n\n") != 0) {
                descripcion += "\n\n";
            }
            destino = Destino::Descripcion;
            continue;
        }

        if (linea[0] == '@') {
            const size_t fin_tag = linea.find_first_of(" \t");
            const std::string tag = linea.substr(
                1, (fin_tag == std::string::npos ? linea.size() : fin_tag) - 1);
            const std::string resto = (fin_tag == std::string::npos)
                                          ? std::string()
                                          : trim(linea.substr(fin_tag));
            if (tag == "param" || tag == "tparam") {
                // El primer termino es el nombre del parametro.
                const size_t fin_nombre = resto.find_first_of(" \t");
                const std::string nombre = (fin_nombre == std::string::npos)
                                               ? resto
                                               : resto.substr(0, fin_nombre);
                const std::string texto = (fin_nombre == std::string::npos)
                                              ? std::string()
                                              : trim(resto.substr(fin_nombre));
                parametros.push_back("- `" + nombre + "`" +
                                     (texto.empty() ? "" : " -- " + texto));
                destino = Destino::Parametro;
                continue;
            }
            if (tag == "brief") {
                // El resumen ES la descripcion; la etiqueta sobra al mostrarlo.
                if (!descripcion.empty()) descripcion += "\n";
                descripcion += resto;
                destino = Destino::Descripcion;
                continue;
            }
            // La etiqueta que ve el lector sale del catalogo; lo que va
            // detras es el texto del autor, que no se traduce.
            static const struct {
                const char *tag;
                const char *code;
            } kNombres[] = {
                {"return", "VX9107"},     {"returns", "VX9107"},
                {"throws", "VX9108"},     {"throw", "VX9108"},
                {"see", "VX9109"},        {"note", "VX9110"},
                {"warning", "VX9111"},    {"since", "VX9112"},
                {"deprecated", "VX9113"}, {"complexity", "VX9114"},
            };
            const char *code = nullptr;
            for (const auto &n : kNombres) {
                if (tag == n.tag) {
                    code = n.code;
                    break;
                }
            }
            if (code != nullptr) {
                otras.push_back(vx::diag::format(code) + " " + resto);
                destino = Destino::Otra;
                continue;
            }
            // Etiqueta que no conocemos: se deja tal cual, sin inventar.
            otras.push_back(linea);
            destino = Destino::Otra;
            continue;
        }

        // Continuacion de lo anterior.
        switch (destino) {
        case Destino::Parametro:
            if (!parametros.empty()) parametros.back() += " " + linea;
            break;
        case Destino::Otra:
            if (!otras.empty()) otras.back() += " " + linea;
            break;
        case Destino::Descripcion:
            if (!descripcion.empty() && descripcion.back() != '\n')
                descripcion += "\n";
            descripcion += linea;
            break;
        }
    }

    std::string out = trim(descripcion);
    if (!parametros.empty()) {
        if (!out.empty()) out += "\n\n";
        out += vx::diag::format("VX9106") + "\n\n";
        for (size_t i = 0; i < parametros.size(); ++i) {
            if (i) out += "\n";
            out += parametros[i];
        }
    }
    for (const auto &o : otras) {
        if (!out.empty()) out += "\n\n";
        out += o;
    }
    return out;
}

/// @brief Palabras clave de Vesta ofrecidas en el completado general (curadas a
///        partir del conjunto @c KW_* del lexer del frontend).
const std::vector<std::string> &vx_keywords() {
    static const std::vector<std::string> kws = {
        // Declaraciones y modificadores.
        "const",
        "static",
        "final",
        "nonnull",
        "typedef",
        "using",
        "namespace",
        "struct",
        "class",
        "interface",
        "enum",
        "fn",
        "public",
        "private",
        "protected",
        "import",
        "extern",
        "get",
        "set",
        "override",
        // Control de flujo.
        "if",
        "else",
        "while",
        "do",
        "for",
        "in",
        "break",
        "continue",
        "goto",
        "return",
        "try",
        "catch",
        "finally",
        "throw",
        "match",
        "case",
        // Objetos / memoria.
        "new",
        "delete",
        "this",
        "super",
        // Concurrencia / distribucion.
        "synchronized",
        "monitor",
        "await",
        "spawn",
        "rspawn",
        "asm",
        // Smart pointers / borrow.
        "unique",
        "shared",
        "borrow",
        "borrow_mut",
        // Literales.
        "true",
        "false",
        "null",
    };
    return kws;
}

/// @brief Tipos (primitivos + alias + colecciones) ofrecidos en el completado.
const std::vector<std::string> &vx_types() {
    static const std::vector<std::string> tys = {
        // Primitivos canonicos.
        "i8",
        "i16",
        "i32",
        "i64",
        "u8",
        "u16",
        "u32",
        "u64",
        "f32",
        "f64",
        "bool",
        "char",
        "void",
        "string",
        // Alias estilo C.
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "float",
        "double",
        // Colecciones (keywords del lenguaje).
        "ArrayList",
        "HashMap",
        "HashSet",
        "Queue",
        "Deque",
        "TreeMap",
        "TreeSet",
        "Stack",
        // Builtins de tipo generico.
        "Optional",
        "Result",
        "Future",
        "Array",
    };
    return tys;
}

/// @brief Builtins de funcion mas comunes (lista curada documentada).
///
/// El registro de builtins del type checker es privado y no se conserva en el
/// analisis cacheado, asi que se ofrece una seleccion curada de los builtins
/// documentados de uso habitual.  Best-effort: no pretende ser exhaustiva.
const std::vector<std::string> &vx_builtins() {
    static const std::vector<std::string> bs = {
        // I/O.
        "print",
        "println",
        "echo",
        "flush",
        "panic",
        // Memoria.
        "malloc",
        "free",
        "sizeof",
        "alignof",
        // Strings.
        "str_length",
        "str_bytes",
        "str_concat",
        "str_equals",
        "str_intern",
        "to_str",
        // Reflexion / introspeccion.
        "forName",
        "getClass",
        "getField",
        "getMethod",
        "newInstance",
        // Concurrencia.
        "pid",
        "msgsend",
        "msgrecv",
        "loadmodule",
        "unloadmodule",
    };
    return bs;
}

/// @brief true si @p name empieza por @p prefix (case-sensitive).  Prefijo
///        vacio coincide con todo.
bool has_prefix(const std::string &name, const std::string &prefix) {
    if (prefix.empty()) return true;
    if (name.size() < prefix.size()) return false;
    return name.compare(0, prefix.size(), prefix) == 0;
}

/// @brief true si @p c es valido dentro de un identificador de Vesta.
bool is_ident_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/**
 * @brief Extrae el prefijo de identificador inmediatamente anterior a
 *        @p byte_off (los caracteres [A-Za-z0-9_] que se estan escribiendo).
 *
 * @param text     Texto completo del documento.
 * @param byte_off Offset de byte del cursor.
 * @return Prefijo (posiblemente vacio) y, por referencia, su offset de inicio.
 */
std::string ident_prefix_before(const std::string &text, size_t byte_off,
                                size_t &out_start) {
    size_t i = byte_off;
    while (i > 0 && is_ident_char(text[i - 1]))
        --i;
    out_start = i;
    return text.substr(i, byte_off - i);
}

/**
 * @brief Resuelve si el contexto del cursor es un acceso a miembro y, si lo es,
 *        devuelve el identificador receptor (el que precede al @c '.').
 *
 * Salta espacios entre el receptor y el punto.  Solo reconoce receptores que
 * son un identificador simple (no cadenas de @c a.b.c ni llamadas); v1
 * pragmatico.
 *
 * @param text         Texto del documento.
 * @param prefix_start Offset de inicio del prefijo que se escribe.
 * @param out_receiver Salida: nombre del receptor si hay acceso a miembro.
 * @return true si hay un @c '.' antes del prefijo con un receptor
 * identificable.
 */
bool member_receiver_before(const std::string &text, size_t prefix_start,
                            std::string &out_receiver) {
    // Saltar espacios/tabuladores entre el prefijo y el posible punto.
    size_t i = prefix_start;
    while (i > 0 && (text[i - 1] == ' ' || text[i - 1] == '\t'))
        --i;
    if (i == 0 || text[i - 1] != '.') return false; // no es acceso a miembro.
    --i;                                            // saltar el punto.
    // Saltar espacios entre el receptor y el punto.
    while (i > 0 && (text[i - 1] == ' ' || text[i - 1] == '\t'))
        --i;
    // El receptor es el identificador que termina en i.
    size_t end = i;
    while (i > 0 && is_ident_char(text[i - 1]))
        --i;
    if (i == end) return false; // sin identificador receptor.
    out_receiver = text.substr(i, end - i);
    return !out_receiver.empty();
}

/**
 * @brief Heuristica best-effort para deducir el tipo (clase/struct) de un
 *        receptor a partir de su declaracion en el texto.
 *
 * Busca un patron de declaracion @c "<Tipo> <receptor>" donde @c <Tipo> es un
 * nombre de clase o struct conocido (de @p known_types).  Recorre todas las
 * apariciones del receptor como palabra completa y, para cada una, mira la
 * palabra anterior: si es un tipo conocido, lo devuelve.  Devuelve cadena vacia
 * si no logra resolverlo.
 *
 * @param text        Texto del documento.
 * @param receiver    Nombre del receptor.
 * @param known_types Conjunto de nombres de tipo (clases + structs).
 * @return Nombre del tipo deducido, o cadena vacia.
 */
std::string
deduce_receiver_type(const std::string &text, const std::string &receiver,
                     const std::unordered_set<std::string> &known_types) {
    const size_t n = text.size();
    const size_t rlen = receiver.size();
    if (rlen == 0) return std::string();
    for (size_t p = 0; p + rlen <= n;) {
        // Localizar la siguiente aparicion del receptor.
        size_t pos = text.find(receiver, p);
        if (pos == std::string::npos) break;
        p = pos + 1; // avanzar para la siguiente busqueda.
        // Exigir limites de palabra: lo anterior y lo posterior no deben ser
        // caracteres de identificador.
        bool left_ok = (pos == 0) || !is_ident_char(text[pos - 1]);
        size_t after = pos + rlen;
        bool right_ok = (after >= n) || !is_ident_char(text[after]);
        if (!left_ok || !right_ok) continue;
        // Retroceder por espacios antes del receptor.
        size_t j = pos;
        while (j > 0 && (text[j - 1] == ' ' || text[j - 1] == '\t'))
            --j;
        // Extraer la palabra anterior (el candidato a tipo).
        size_t word_end = j;
        while (j > 0 && is_ident_char(text[j - 1]))
            --j;
        if (j == word_end) continue; // no hay palabra previa.
        std::string prev = text.substr(j, word_end - j);
        if (known_types.count(prev) != 0) return prev;
    }
    return std::string();
}

} // namespace

bool LspServer::word_under_cursor(const nlohmann::json &params,
                                  std::string &out_uri, std::string &out_word) {
    // params.textDocument.uri + params.position.{line, character}.
    if (!params.contains("textDocument") || !params.contains("position"))
        return false;
    const auto &td = params.at("textDocument");
    out_uri = td.value("uri", std::string());
    if (out_uri.empty() || !docs_.has(out_uri)) return false;
    const auto &pos = params.at("position");
    const uint32_t line = pos.value("line", 0u);
    const uint32_t character = pos.value("character", 0u);

    const auto text_ref = docs_.text(out_uri);
    const std::string &text = *text_ref;
    // Convertir la posicion LSP a un offset de byte para localizar el token.
    const uint32_t byte_off =
        lsp_position_to_byte_offset(text, line, character);

    // Construir (o recomputar barato) el indice por-documento y buscar el
    // identificador que el cursor toca.
    DocSymbols sym = build_doc_symbols(text, out_uri);
    const SymbolRef *ref = sym.ref_at(byte_off);
    if (ref == nullptr) {
        // El cursor puede caer justo al final del identificador (posicion
        // exclusiva): reintentar un byte antes.
        if (byte_off > 0) ref = sym.ref_at(byte_off - 1);
    }
    if (ref == nullptr) return false;
    out_word = ref->name;
    return true;
}

void LspServer::handle_formatting(const nlohmann::json &msg) {
    const auto &params = msg.at("params");
    const std::string uri =
        params.at("textDocument").at("uri").get<std::string>();
    const auto src = docs_.text(uri);
    if (!src) {
        if (msg.contains("id"))
            send_result(msg.at("id"), nlohmann::json::array());
        return;
    }

    /* Los nombres de las funciones que capturan el texto de su argumento
     * (`R110`) no se pueden saber mirando un fichero solo: las importadas se
     * declaran en otro modulo.  El indice de simbolos ya tiene los ficheros
     * del espacio de trabajo, asi que se los pasamos. */
    if (!capture_names_listos_) {
        capture_names_listos_ = true;
        std::vector<std::string> ficheros;
        std::error_code ec;
        for (const std::string &raiz : workspace_.roots()) {
            for (std::filesystem::recursive_directory_iterator it(raiz, ec),
                 fin;
                 it != fin && !ec; it.increment(ec)) {
                if (!it->is_regular_file(ec)) continue;
                if (it->path().extension() == ".vx")
                    ficheros.push_back(it->path().string());
            }
        }
        capture_names_ = vx::fmt::capture_names_in_files(ficheros);
    }
    vx::fmt::FormatOptions options;
    options.raw_capture_names = capture_names_;

    const vx::fmt::FormatResult r = vx::fmt::format(*src, uri, options);
    if (!r.ok || r.text == *src) {
        // No se pudo, o ya estaba formateado: ninguna edicion.  Que el
        // formateador se niegue no es un error del editor.
        if (msg.contains("id"))
            send_result(msg.at("id"), nlohmann::json::array());
        return;
    }

    /* Una sola edicion que sustituye el documento entero.
     *
     * Podria calcularse un diff minimo, y seria mas fino para el historial de
     * deshacer; pero el formateador toca casi todas las lineas de un fichero
     * sin formatear, asi que el diff no seria mucho menor y si mucho mas
     * codigo que mantener en sincronia con el resultado. */
    uint32_t lineas = 0;
    for (const char c : *src)
        if (c == '\n') ++lineas;
    nlohmann::json edit;
    edit["range"] = {{"start", {{"line", 0}, {"character", 0}}},
                     {"end", {{"line", lineas + 1}, {"character", 0}}}};
    edit["newText"] = r.text;
    if (msg.contains("id"))
        send_result(msg.at("id"), nlohmann::json::array({edit}));
}

void LspServer::handle_hover(const nlohmann::json &msg) {
    const auto &params = msg.at("params");

    // (0) ¿El cursor esta sobre un builtin de introspeccion comptime
    // (sizeof<T>, alignof<T>, kind<T>, type_id<T>, typename<T>)?  Mostramos el
    // VALOR que el compilador resolvio, aunque "sizeof" no sea un simbolo
    // declarado.  Va antes del flujo normal porque esos builtins no estan en el
    // indice de simbolos.
    try {
        const std::string huri =
            params.at("textDocument").at("uri").get<std::string>();
        const uint32_t pline = params.at("position").at("line").get<uint32_t>();
        const uint32_t pchar =
            params.at("position").at("character").get<uint32_t>();
        const auto htext_ref = docs_.text(huri);
        const std::string &htext = *htext_ref;
        const auto an_ref = engine_.analyze_document(huri, htext);
        const DocAnalysis &an = *an_ref;
        const std::string line_text = docs_.line(huri, pline);
        for (const auto &cv : an.result.comptime_values) {
            if (cv.loc.line == 0 || cv.builtin_kind.empty()) continue;
            if (cv.loc.line != pline + 1) continue; // 1-based vs 0-based
            const uint32_t s = byte_column_to_utf16(line_text, cv.loc.column);
            const uint32_t e =
                byte_column_to_utf16(line_text, cv.loc.column + cv.loc.length);
            if (pchar >= s && pchar < e) {
                std::string md = "**" + cv.name + "**  _(comptime)_\n\n";
                md +=
                    "= **" + cv.value_str + "**  _(resuelto en compilacion)_\n";
                nlohmann::json result, contents;
                contents["kind"] = "markdown";
                contents["value"] = md;
                result["contents"] = std::move(contents);
                send_result(msg.at("id"), result);
                return;
            }
        }
    } catch (...) {
        // params incompleto: continuar con el flujo normal de hover.
    }

    std::string uri, word;
    if (!word_under_cursor(params, uri, word)) {
        // Sin identificador resoluble: devolver null (el cliente lo tolera).
        send_result(msg.at("id"), nullptr);
        return;
    }

    // Resolver a una definicion: primero las del propio fichero (texto vivo),
    // luego el workspace.  La definicion da el kind + firma; la complejidad
    // sale de la ModuleCost cacheada del propio documento.
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    DocSymbols local = build_doc_symbols(text, uri);

    SymbolKind kind = SymbolKind::Unknown;
    std::string signature;
    std::string container;
    std::string def_uri = uri; ///< fichero donde vive la definicion (Big-O).
    bool resolved = false;
    /// Comentario de documentacion que precede a la declaracion.  Se recoge en
    /// la rama que resuelve, porque cada una tiene a mano un texto distinto
    /// (el del documento, o el del modulo importado).
    std::string doc;
    /// Para la rama del workspace, que da la posicion pero no el texto: se
    /// apunta donde esta y la doc se extrae al cargar el fichero que define.
    bool doc_pendiente = false;
    uint32_t doc_line = 0, doc_char = 0;

    /* Donde esta el cursor, en bytes.  Sirve para desempatar entre
     * definiciones que se llaman igual: dos structs pueden tener un campo con
     * el mismo nombre, y quedarse con la primera hacia que el hover de uno
     * contara el contenedor y la disposicion en memoria del OTRO -- con
     * aplomo, porque los dos existen y la respuesta parecia buena. */
    size_t cursor_off = std::string::npos;
    if (params.contains("position") && params["position"].is_object()) {
        const auto &pos = params["position"];
        cursor_off = lsp_position_to_byte_offset(text, pos.value("line", 0u),
                                                 pos.value("character", 0u));
    }

    // Buscar en las definiciones locales (preferencia por exactitud de scope).
    // Si el cursor cae DENTRO del nombre de una de ellas, es esa: ahi no hay
    // nada que adivinar, se esta senalando la declaracion.
    const SymbolDef *elegida = nullptr;
    for (const auto &d : local.defs) {
        if (d.name != word) continue;
        if (elegida == nullptr) elegida = &d;
        if (cursor_off != std::string::npos && cursor_off >= d.byte_offset &&
            cursor_off < d.byte_offset + d.byte_length) {
            elegida = &d;
            break;
        }
    }
    if (elegida != nullptr) {
        kind = elegida->kind;
        signature = elegida->signature;
        container = elegida->container;
        doc = extract_doc_comment(text, elegida->byte_offset);
        resolved = true;
    }
    // Si no esta en el fichero, mirar el workspace.
    if (!resolved) {
        workspace_.ensure_built();
        std::vector<WorkspaceLocation> wdefs = workspace_.defs_for(word);
        if (!wdefs.empty()) {
            kind = wdefs.front().kind;
            signature = wdefs.front().signature;
            container = wdefs.front().container;
            def_uri =
                wdefs.front().uri; // Big-O sale del fichero que la define.
            doc_pendiente = true;
            doc_line = wdefs.front().start_line;
            doc_char = wdefs.front().start_char;
            resolved = true;
        }
    }

    // NS.4: fallback por indice semantico -- resuelve el acceso CUALIFICADO por
    // namespace (`shapes.area`, cursor sobre `area`) que build_doc_symbols no
    // cubre.  El word es el ULTIMO segmento; el contenedor es el namespace.  La
    // complejidad Big-O de abajo ya encuentra el coste por sufijo `__area`
    // (el nombre mangled `org__geo__shapes__area` termina asi).
    if (!resolved) {
        const auto anx_ref = engine_.analyze_document(uri, text);
        const DocAnalysis &anx = *anx_ref;
        for (const auto &s : anx.sem_index.symbols) {
            const std::string &q = s.name;
            const size_t dot = q.rfind('.');
            const std::string simple =
                (dot == std::string::npos) ? q : q.substr(dot + 1);
            if (simple != word) continue;
            switch (static_cast<vx::ast::NodeKind>(s.kind)) {
            case vx::ast::NodeKind::StructDecl:
                kind = SymbolKind::Struct;
                break;
            case vx::ast::NodeKind::ClassDecl: kind = SymbolKind::Class; break;
            case vx::ast::NodeKind::EnumDecl: kind = SymbolKind::Enum; break;
            case vx::ast::NodeKind::TypeAliasDecl:
                kind = SymbolKind::TypeAlias;
                break;
            case vx::ast::NodeKind::GlobalVarDecl:
                kind = SymbolKind::Variable;
                break;
            default: kind = SymbolKind::Function; break;
            }
            container =
                (dot == std::string::npos) ? std::string() : q.substr(0, dot);
            // Firma = cabecera del decl (primera linea del span, hasta
            // '{'/';').
            const size_t len = std::min<size_t>(s.src_length, 240);
            std::string span = text.substr(s.src_offset, len);
            const size_t cut = span.find_first_of("{;\n");
            signature = (cut == std::string::npos) ? span : span.substr(0, cut);
            // trim trailing spaces.
            while (!signature.empty() &&
                   (signature.back() == ' ' || signature.back() == '\t' ||
                    signature.back() == '\r'))
                signature.pop_back();
            doc = extract_doc_comment(text, s.src_offset);
            resolved = true;
            break;
        }
        // Cross-module: el simbolo puede vivir en un modulo importado.
        if (!resolved) {
            for (const auto &im : anx.imported_sem_indexes) {
                for (const auto &s : im.index.symbols) {
                    if (!s.is_public)
                        continue; // solo public es accesible cross-module.
                    const std::string &q = s.name;
                    const size_t dot = q.rfind('.');
                    const std::string simple =
                        (dot == std::string::npos) ? q : q.substr(dot + 1);
                    if (simple != word) continue;
                    switch (static_cast<vx::ast::NodeKind>(s.kind)) {
                    case vx::ast::NodeKind::StructDecl:
                        kind = SymbolKind::Struct;
                        break;
                    case vx::ast::NodeKind::ClassDecl:
                        kind = SymbolKind::Class;
                        break;
                    case vx::ast::NodeKind::EnumDecl:
                        kind = SymbolKind::Enum;
                        break;
                    case vx::ast::NodeKind::TypeAliasDecl:
                        kind = SymbolKind::TypeAlias;
                        break;
                    case vx::ast::NodeKind::GlobalVarDecl:
                        kind = SymbolKind::Variable;
                        break;
                    default: kind = SymbolKind::Function; break;
                    }
                    container = (dot == std::string::npos) ? std::string()
                                                           : q.substr(0, dot);
                    const size_t len = std::min<size_t>(s.src_length, 240);
                    if (s.src_offset < im.source.size()) {
                        std::string span = im.source.substr(s.src_offset, len);
                        const size_t cut = span.find_first_of("{;\n");
                        signature = (cut == std::string::npos)
                                        ? span
                                        : span.substr(0, cut);
                        while (!signature.empty() &&
                               (signature.back() == ' ' ||
                                signature.back() == '\t' ||
                                signature.back() == '\r'))
                            signature.pop_back();
                        doc = extract_doc_comment(im.source, s.src_offset);
                    }
                    resolved = true;
                    break;
                }
                if (resolved) break;
            }
        }
    }

    if (!resolved) {
        send_result(msg.at("id"), nullptr);
        return;
    }

    // Texto del fichero que DEFINE el simbolo, que puede ser otro modulo.  Se
    // carga UNA vez: lo usan tanto la documentacion como el coste y los
    // contratos.  Si esta abierto en el editor se usa su texto vivo.
    std::string def_text;
    if (def_uri == uri) {
        def_text = text;
    } else if (docs_.has(def_uri)) {
        def_text = *docs_.text(def_uri);
    } else {
        std::ifstream f(uri_to_fs_path(def_uri), std::ios::binary);
        if (f) {
            std::ostringstream ss;
            ss << f.rdbuf();
            def_text = ss.str();
        }
    }
    if (doc_pendiente && !def_text.empty()) {
        doc = extract_doc_comment(def_text, lsp_position_to_byte_offset(
                                                def_text, doc_line, doc_char));
    }
    // Analisis del fichero que define: de ahi salen el coste, los contratos y
    // la disposicion en memoria de los tipos.  Se pide una sola vez.
    const auto def_an_ref = engine_.analyze_document(def_uri, def_text);
    const DocAnalysis &def_an = *def_an_ref;

    // Construir el markdown del hover.
    std::string md;
    md += "**";
    md += word;
    md += "**";
    md += "  _(";
    md += symbol_kind_name(kind);
    md += ")_\n\n";
    if (!container.empty()) {
        md += vx::diag::format("VX9100", {container});
        md += "\n\n";
    }
    if (!signature.empty()) {
        md += "```vx\n";
        md += signature;
        md += "\n```\n";
    }
    // La documentacion que el autor escribio encima de la declaracion, con
    // forma de markdown.  Va detras de la firma, que es donde se lee.
    if (!doc.empty()) {
        md += "\n";
        md += doc_to_markdown(doc);
        md += "\n";
    }
    // Complejidad Big-O si es una funcion (o un metodo) conocida por el
    // analizador de coste.  Buscamos por nombre exacto y, si no, por sufijo
    // (los metodos viven en el IR como `Clase__metodo`).
    if (kind == SymbolKind::Function || kind == SymbolKind::Method) {
        // El coste sale del analisis del fichero que DEFINE la funcion, que
        // puede ser otro modulo; ya se pidio arriba.
        const DocAnalysis &an = def_an;
        const analyze::CostResult *cr = nullptr;
        for (const auto &c : an.cost.functions) {
            if (c.function == word) {
                cr = &c;
                break;
            }
        }
        if (cr == nullptr) {
            // Buscar por sufijo "__<word>" (mangling de metodos) o por
            // contener el nombre como ultimo componente.
            const std::string suffix = "__" + word;
            for (const auto &c : an.cost.functions) {
                if (c.function.size() >= suffix.size() &&
                    c.function.compare(c.function.size() - suffix.size(),
                                       suffix.size(), suffix) == 0) {
                    cr = &c;
                    break;
                }
            }
        }
        if (cr != nullptr) {
            md += "\n";
            md += vx::diag::format("VX9101",
                                   {analyze::cost_class_str(cr->total_class)});
            // Si el coste del cuerpo propio difiere del total, ensenar los dos.
            if (cr->big_o != cr->total_class) {
                md += " ";
                md += vx::diag::format("VX9102",
                                       {analyze::cost_class_str(cr->big_o)});
            }
            md += "\n";

            // Lo DECLARADO con @complexity, junto a lo inferido: verlos a la
            // vez es el motivo de que el contrato exista.
            std::string declarado = cr->declared_expr;
            if (declarado.empty()) {
                // Las cuatro dimensiones crudas, por si el contrato hablaba de
                // una distinta de la que representa este resultado.
                for (const std::string *d :
                     {&cr->decl_total_post, &cr->decl_total_pre,
                      &cr->decl_partial_post, &cr->decl_partial_pre}) {
                    if (!d->empty()) {
                        declarado = *d;
                        break;
                    }
                }
            }
            if (!declarado.empty()) {
                md += "\n";
                md += vx::diag::format("VX9103", {declarado});
                if (cr->contract_mismatch) {
                    md += "  ";
                    md += vx::diag::format("VX9104");
                }
                md += "\n";
            }
        }

        // Contratos de huella declarados sobre la funcion (@pure, @nothrow,
        // @nopanic, @alloc, @stack).  El compilador los verifica contra lo que
        // infiere del IR; aqui se ensena lo que el autor prometio, que es lo
        // que un lector necesita saber antes de llamarla.
        const analyze::FunctionContracts *fc = nullptr;
        {
            auto it = an.result.contracts.find(word);
            if (it != an.result.contracts.end()) {
                fc = &it->second;
            } else {
                // Los metodos viven con el nombre de su clase por delante.
                const std::string suffix = "__" + word;
                for (const auto &entry : an.result.contracts) {
                    const std::string &n = entry.first;
                    if (n.size() >= suffix.size() &&
                        n.compare(n.size() - suffix.size(), suffix.size(),
                                  suffix) == 0) {
                        fc = &entry.second;
                        break;
                    }
                }
            }
        }
        if (fc != nullptr && fc->any()) {
            std::vector<std::string> partes;
            if (fc->pure) partes.push_back("`@pure`");
            if (fc->nothrow) partes.push_back("`@nothrow`");
            if (fc->nopanic) partes.push_back("`@nopanic`");
            // @alloc y @stack tienen dos dimensiones: lo propio de la funcion
            // y el peor caso de toda la cadena de llamadas.
            auto con_dimensiones = [&partes](const char *nombre,
                                             int64_t parcial, int64_t total) {
                if (parcial < 0 && total < 0) return;
                std::string s = "`@";
                s += nombre;
                s += "(";
                if (parcial >= 0) {
                    s += "partial: " + std::to_string(parcial);
                    if (total >= 0) s += ", ";
                }
                if (total >= 0) s += "total: " + std::to_string(total);
                s += ")`";
                partes.push_back(std::move(s));
            };
            con_dimensiones("alloc", fc->alloc_partial, fc->alloc_total);
            con_dimensiones("stack", fc->stack_partial, fc->stack_total);

            std::string lista;
            for (size_t i = 0; i < partes.size(); ++i) {
                if (i) lista += " ";
                lista += partes[i];
            }
            md += "\n";
            md += vx::diag::format("VX9105", {lista});
            md += "\n";
        }
    }

    // Un campo y una variante de enum se leen igual: lo que uno quiere saber es
    // DONDE cae en memoria y QUE valor tiene.  El comprobador de tipos ya lo
    // resolvio -- es el mismo layout que usa el generador de codigo --, asi que
    // aqui solo se busca por nombre de tipo contenedor.
    if ((kind == SymbolKind::Field || kind == SymbolKind::EnumVariant) &&
        !container.empty()) {
        const analyze::TypeFingerprint *tf = nullptr;
        for (const auto &f : def_an.result.type_fingerprints) {
            if (f.type_name == container) {
                tf = &f;
                break;
            }
        }
        if (tf == nullptr) {
            // Dentro de un namespace el tipo lleva su path por delante
            // (`std__syscall__windows__Ctx`), mientras que el contenedor que
            // ve el hover es el nombre a secas.  Se busca por el final.
            const std::string sufijo = "__" + container;
            for (const auto &f : def_an.result.type_fingerprints) {
                if (f.type_name.size() >= sufijo.size() &&
                    f.type_name.compare(f.type_name.size() - sufijo.size(),
                                        sufijo.size(), sufijo) == 0) {
                    tf = &f;
                    break;
                }
            }
        }
        /* Y si no hay huella, se dice por que.  Callarse deja "de este tipo no
         * se sabe la disposicion" indistinguible de "este tipo no tiene
         * ninguna", y lo normal es lo primero: el modulo no compilo para el
         * objetivo con el que se esta mirando -- un fichero de Linux leido
         * desde Windows, por ejemplo -- y sin compilar no hay layout que
         * consultar. */
        if (tf == nullptr && def_an.result.ir_module_cache_bytes.empty()) {
            md += "\n";
            md += vx::diag::format("VX9157", {});
            md += "\n";
        }
        if (tf != nullptr && kind == SymbolKind::EnumVariant) {
            for (size_t i = 0; i < tf->variants.size(); ++i) {
                const analyze::VariantPlacement &v = tf->variants[i];
                if (v.name != word) continue;
                md += "\n";
                md += vx::diag::format("VX9115", {std::to_string(v.int_value)});
                // La etiqueta es lo que se guarda en memoria; solo se ensena
                // cuando NO coincide con el valor, que es cuando confundirlos
                // duele.
                if (static_cast<int64_t>(v.tag) != v.int_value) {
                    md += "  ";
                    md += vx::diag::format("VX9116", {std::to_string(v.tag)});
                }
                md += "\n";
                char hex[32];
                std::snprintf(hex, sizeof(hex), "0x%llX",
                              static_cast<unsigned long long>(v.int_value));
                md += "\n";
                md += vx::diag::format("VX9117", {hex});
                md += "\n";
                if (v.payload_fields > 0) {
                    md += "\n";
                    md += vx::diag::format("VX9118",
                                           {std::to_string(v.payload_fields)});
                    md += "\n";
                }
                md += "\n";
                md += vx::diag::format("VX9119",
                                       {std::to_string(tf->size_bytes)});
                md += "\n";
                break;
            }
        } else if (tf != nullptr) {
            for (size_t i = 0; i < tf->fields.size(); ++i) {
                const analyze::FieldPlacement &f = tf->fields[i];
                if (f.name != word) continue;
                char hex[32];
                std::snprintf(hex, sizeof(hex), "0x%X", f.offset);
                md += "\n";
                md += vx::diag::format("VX9120", {std::to_string(f.offset), hex,
                                                  std::to_string(f.size)});
                md += "\n";
                if (f.bit_width > 0) {
                    // Campo de bits: lo que importa es que trozo de la palabra
                    // ocupa, no el tamano de la palabra entera.
                    md += "\n";
                    md += vx::diag::format(
                        "VX9121",
                        {std::to_string(f.bit_offset),
                         std::to_string(f.bit_offset + f.bit_width - 1),
                         std::to_string(f.offset)});
                    md += "\n";
                }
                // El relleno solo significa algo cuando los campos se colocan
                // en orden: en una union todos empiezan en cero, y en una
                // vista los desplazamientos los fija el autor.
                if (!tf->is_union && !tf->is_overlay) {
                    const uint32_t anterior =
                        (i == 0)
                            ? 0
                            : tf->fields[i - 1].offset + tf->fields[i - 1].size;
                    if (f.offset > anterior) {
                        md += "\n";
                        md += vx::diag::format(
                            "VX9122", {std::to_string(f.offset - anterior)});
                        md += "\n";
                    }
                    if (i + 1 == tf->fields.size()) {
                        const uint64_t fin = f.offset + f.size;
                        if (tf->size_bytes > fin) {
                            md += "\n";
                            md += vx::diag::format(
                                "VX9123",
                                {std::to_string(tf->size_bytes - fin)});
                            md += "\n";
                        }
                    }
                }
                md += "\n";
                md += vx::diag::format(
                    "VX9124", {container, std::to_string(tf->size_bytes),
                               std::to_string(tf->align_bytes)});
                if (tf->is_union) md += ", " + vx::diag::format("VX9125");
                if (tf->is_overlay) md += ", " + vx::diag::format("VX9126");
                if (tf->is_polymorphic) md += ", " + vx::diag::format("VX9127");
                md += "\n";
                break;
            }
        }
    }

    nlohmann::json result;
    nlohmann::json contents;
    contents["kind"] = "markdown";
    contents["value"] = md;
    result["contents"] = std::move(contents);
    send_result(msg.at("id"), result);
}

void LspServer::handle_definition(const nlohmann::json &msg) {
    const auto &params = msg.at("params");
    std::string uri, word;
    if (!word_under_cursor(params, uri, word)) {
        send_result(msg.at("id"), nullptr);
        return;
    }

    // Preferir las definiciones del propio fichero (texto vivo); si no hay,
    // usar el workspace (incluye librerias/modulos importados).
    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    DocSymbols local = build_doc_symbols(text, uri);

    nlohmann::json locs = nlohmann::json::array();
    for (const auto &d : local.defs) {
        if (d.name != word) continue;
        WorkspaceLocation l;
        l.uri = uri;
        byte_offset_to_lsp_position(text, d.byte_offset, l.start_line,
                                    l.start_char);
        byte_offset_to_lsp_position(text, d.byte_offset + d.byte_length,
                                    l.end_line, l.end_char);
        locs.push_back(make_location(l));
    }
    if (locs.empty()) {
        workspace_.ensure_built();
        for (const auto &l : workspace_.defs_for(word))
            locs.push_back(make_location(l));
    }

    // NS.4: fallback por indice semantico -- resuelve el acceso CUALIFICADO por
    // namespace (`shapes.area`, cursor sobre `area`).  El word bajo el cursor
    // es el ULTIMO segmento; buscamos en el indice los simbolos cuyo nombre
    // simple (ultimo segmento del nombre cualificado) coincide y devolvemos su
    // span.
    if (locs.empty()) {
        const auto an_ref = engine_.analyze_document(uri, text);
        const DocAnalysis &an = *an_ref;
        for (const auto &s : an.sem_index.symbols) {
            const std::string &q = s.name;
            const size_t dot = q.rfind('.');
            const std::string simple =
                (dot == std::string::npos) ? q : q.substr(dot + 1);
            if (simple != word) continue;
            WorkspaceLocation l;
            l.uri = uri;
            byte_offset_to_lsp_position(text, s.src_offset, l.start_line,
                                        l.start_char);
            byte_offset_to_lsp_position(text, s.src_offset + s.src_length,
                                        l.end_line, l.end_char);
            locs.push_back(make_location(l));
        }
        // Cross-module: un simbolo cuyo ultimo segmento coincide puede vivir en
        // un modulo importado.  Devolvemos su Location en el fichero de origen.
        if (locs.empty()) {
            for (const auto &im : an.imported_sem_indexes) {
                for (const auto &s : im.index.symbols) {
                    if (!s.is_public)
                        continue; // solo public es accesible cross-module.
                    const std::string &q = s.name;
                    const size_t dot = q.rfind('.');
                    const std::string simple =
                        (dot == std::string::npos) ? q : q.substr(dot + 1);
                    if (simple != word) continue;
                    WorkspaceLocation l;
                    // El frontend entrega la RUTA del modulo; darle forma de
                    // uri es cosa de aqui, que es donde se habla el protocolo.
                    l.uri = fs_path_to_uri(im.path);
                    byte_offset_to_lsp_position(im.source, s.src_offset,
                                                l.start_line, l.start_char);
                    byte_offset_to_lsp_position(im.source,
                                                s.src_offset + s.src_length,
                                                l.end_line, l.end_char);
                    locs.push_back(make_location(l));
                }
            }
        }
    }

    if (locs.empty()) {
        send_result(msg.at("id"), nullptr);
        return;
    }
    send_result(msg.at("id"), locs);
}

/**
 * @brief Traduce el kind propio al numero de @c SymbolKind del protocolo.
 *
 * Los numeros son los del LSP; el editor los usa para el icono de cada
 * resultado.  Lo que no encaje va como Funcion, que es lo mas comun aqui.
 *
 * @param k Kind propio.
 * @return El numero del protocolo.
 */
static int symbol_kind_to_lsp(SymbolKind k) {
    switch (k) {
    case SymbolKind::Struct: return 23;      // Struct
    case SymbolKind::Class: return 5;        // Class
    case SymbolKind::Enum: return 10;        // Enum
    case SymbolKind::EnumVariant: return 22; // EnumMember
    case SymbolKind::TypeAlias: return 26;   // TypeParameter
    case SymbolKind::Variable: return 13;    // Variable
    case SymbolKind::Field: return 8;        // Field
    case SymbolKind::Method: return 6;       // Method
    default: return 12;                      // Function
    }
}

void LspServer::handle_workspace_symbol(const nlohmann::json &msg) {
    const std::string consulta =
        msg.contains("params") && msg.at("params").is_object()
            ? msg.at("params").value("query", std::string())
            : std::string();

    nlohmann::json salida = nlohmann::json::array();
    if (consulta.empty()) {
        send_result(msg.at("id"), std::move(salida));
        return;
    }
    workspace_.ensure_built();

    /* Se busca por el nombre INTERNO y tambien por el ESCRITO.
     *
     * Quien pide esto suele venir de una vista donde se ensena el nombre real
     * -- `std.windows.GetCurrentFiber` --, y en el indice esta el interno
     * (`std__windows__GetCurrentFiber`).  Exigir uno de los dos obligaria a
     * quien pregunta a saber cual, que es justo lo que no tiene por que
     * saber. */
    std::vector<std::string> candidatos;
    candidatos.push_back(consulta);
    {
        // Del nombre escrito al interno: los puntos vuelven a ser separadores.
        std::string interno;
        interno.reserve(consulta.size() + 8);
        for (char c : consulta) {
            if (c == '.')
                interno += "__";
            else
                interno.push_back(c);
        }
        if (interno != consulta) candidatos.push_back(interno);
    }
    /* Y al reves: si lo que llega es el nombre interno, se deshace.  El indice
     * guarda el nombre tal y como esta ESCRITO en el fuente (`MAKELANGID`), no
     * el que el compilador construye (`__macro_std__windows__MAKELANGID`), asi
     * que hay que quedarse con el ultimo segmento. */
    const std::string escrito = vx::demangle_symbol(consulta);
    if (escrito != consulta) candidatos.push_back(escrito);
    for (const std::string &c : {consulta, escrito}) {
        const size_t punto = c.find_last_of('.');
        if (punto != std::string::npos && punto + 1 < c.size())
            candidatos.push_back(c.substr(punto + 1));
    }

    for (const std::string &nombre : candidatos) {
        for (const WorkspaceLocation &def : workspace_.defs_for(nombre)) {
            nlohmann::json s;
            // El nombre que se ensena es el escrito, siempre.
            s["name"] = vx::demangle_symbol(nombre);
            s["kind"] = symbol_kind_to_lsp(def.kind);
            if (!def.container.empty()) s["containerName"] = def.container;
            nlohmann::json rango;
            rango["start"] = {{"line", def.start_line},
                              {"character", def.start_char}};
            rango["end"] = {{"line", def.end_line},
                            {"character", def.end_char}};
            s["location"] = {{"uri", def.uri}, {"range", std::move(rango)}};
            salida.push_back(std::move(s));
        }
        if (!salida.empty()) break; // el primero que encaja manda
    }
    send_result(msg.at("id"), std::move(salida));
}

void LspServer::handle_references(const nlohmann::json &msg) {
    const auto &params = msg.at("params");
    std::string uri, word;
    if (!word_under_cursor(params, uri, word)) {
        send_result(msg.at("id"), nlohmann::json::array());
        return;
    }

    // includeDeclaration: si true, incluir tambien las definiciones.
    bool include_decl = false;
    if (params.contains("context") && params.at("context").is_object())
        include_decl = params.at("context").value("includeDeclaration", false);

    // Todas las referencias del workspace (incluye librerias).
    workspace_.ensure_built();

    nlohmann::json locs = nlohmann::json::array();
    for (const auto &l : workspace_.refs_for(word))
        locs.push_back(make_location(l));
    if (include_decl) {
        for (const auto &l : workspace_.defs_for(word))
            locs.push_back(make_location(l));
    }

    send_result(msg.at("id"), locs);
}

void LspServer::handle_completion(const nlohmann::json &msg) {
    const auto &params = msg.at("params");
    // Validar uri + documento abierto + posicion.  Sin ello respondemos lista
    // vacia (valida para el protocolo).
    if (!params.contains("textDocument") || !params.contains("position")) {
        send_result(msg.at("id"), nlohmann::json::array());
        return;
    }
    const std::string uri =
        params.at("textDocument").value("uri", std::string());
    if (uri.empty() || !docs_.has(uri)) {
        send_result(msg.at("id"), nlohmann::json::array());
        return;
    }
    const auto &pos = params.at("position");
    const uint32_t line = pos.value("line", 0u);
    const uint32_t character = pos.value("character", 0u);

    const auto text_ref = docs_.text(uri);
    const std::string &text = *text_ref;
    // Offset de byte del cursor, prefijo que se esta escribiendo y su inicio.
    const size_t cursor = lsp_position_to_byte_offset(text, line, character);
    size_t prefix_start = cursor;
    const std::string prefix = ident_prefix_before(text, cursor, prefix_start);

    // Tope de resultados para no devolver listas gigantes.
    constexpr size_t kMaxItems = 500;
    nlohmann::json items = nlohmann::json::array();
    std::unordered_set<std::string> seen; // dedup por label.

    auto add_item = [&](const std::string &label, CompletionKind kind,
                        const std::string &detail) {
        if (items.size() >= kMaxItems) return;
        if (label.empty() || seen.count(label) != 0) return;
        seen.insert(label);
        items.push_back(make_completion_item(label, kind, detail));
    };

    // El analisis cacheado da los conjuntos de nombres declarados (clases,
    // structs, enums, alias, funciones) del propio documento.
    const auto an_ref = engine_.analyze_document(uri, text);
    const DocAnalysis &an = *an_ref;

    // -- COMPLETADO DE MIEMBRO tras '.' --------------------------------------
    std::string receiver;
    if (member_receiver_before(text, prefix_start, receiver)) {
        // Resolver el tipo del receptor:
        //  (a) si el receptor ES directamente un nombre de clase/struct
        //      conocido (acceso estilo Tipo.miembro), usar ese tipo;
        //  (b) si no, deducirlo de su declaracion "<Tipo> receptor".
        std::string type_name;
        if (an.class_names.count(receiver) != 0 ||
            an.struct_names.count(receiver) != 0) {
            type_name = receiver;
        } else {
            std::unordered_set<std::string> known_types;
            known_types.insert(an.class_names.begin(), an.class_names.end());
            known_types.insert(an.struct_names.begin(), an.struct_names.end());
            type_name = deduce_receiver_type(text, receiver, known_types);
        }

        if (!type_name.empty()) {
            // Listar metodos y campos cuyo contenedor sea el tipo resuelto.
            DocSymbols sym = build_doc_symbols(text, uri);
            for (const auto &d : sym.defs) {
                if (d.container != type_name) continue;
                if (!has_prefix(d.name, prefix)) continue;
                if (d.kind == SymbolKind::Method) {
                    add_item(d.name, CompletionKind::Method, d.signature);
                } else if (d.kind == SymbolKind::Field) {
                    add_item(d.name, CompletionKind::Field, type_name);
                }
            }
        }
        // NS.4: completado de miembro de NAMESPACE (`ns.simbolo`).  Si el
        // receptor no resolvio a un tipo, puede ser un namespace: ofrecer sus
        // simbolos desde el indice semantico (nombres CUALIFICADOS).  Coincide
        // si el receptor es el PATH completo del namespace o su ULTIMO segmento
        // (short-form), consistente con la resolucion del compilador.
        if (type_name.empty()) {
            // Ofrece los miembros de un namespace desde un conjunto de simbolos
            // (nombres CUALIFICADOS) + su fuente (para extraer la firma).  Se
            // aplica al indice del documento Y a los de los modulos importados
            // (cross-module: `import "lib"; lib.<TAB>`).
            auto offer_ns_members =
                [&](const std::vector<vx::SymbolEntry> &syms,
                    const std::string &src, bool public_only) {
                    for (const auto &s : syms) {
                        // Cross-module: solo los `public` son importables.
                        if (public_only && !s.is_public) continue;
                        const std::string &q = s.name;
                        const size_t dot = q.rfind('.');
                        if (dot == std::string::npos)
                            continue; // simbolo sin namespace.
                        const std::string ns = q.substr(0, dot);
                        const std::string member = q.substr(dot + 1);
                        bool match = (ns == receiver);
                        if (!match) {
                            const size_t nd = ns.rfind('.');
                            const std::string last = (nd == std::string::npos)
                                                         ? ns
                                                         : ns.substr(nd + 1);
                            match = (last == receiver);
                        }
                        if (!match || !has_prefix(member, prefix)) continue;
                        // Mapear el ast::NodeKind (u8) del indice a
                        // CompletionKind.
                        CompletionKind k = CompletionKind::Function;
                        switch (static_cast<vx::ast::NodeKind>(s.kind)) {
                        case vx::ast::NodeKind::StructDecl:
                            k = CompletionKind::Struct;
                            break;
                        case vx::ast::NodeKind::ClassDecl:
                            k = CompletionKind::Class;
                            break;
                        case vx::ast::NodeKind::EnumDecl:
                            k = CompletionKind::Enum;
                            break;
                        case vx::ast::NodeKind::TypeAliasDecl:
                            k = CompletionKind::Class;
                            break;
                        case vx::ast::NodeKind::ConceptDecl:
                            k = CompletionKind::Interface;
                            break;
                        case vx::ast::NodeKind::GlobalVarDecl:
                            k = CompletionKind::Variable;
                            break;
                        default: k = CompletionKind::Function; break;
                        }
                        // Detalle = firma (cabecera del decl) + namespace, como
                        // el hover.
                        std::string detail;
                        {
                            const size_t len =
                                std::min<size_t>(s.src_length, 200);
                            if (s.src_offset < src.size()) {
                                std::string span =
                                    src.substr(s.src_offset, len);
                                const size_t cut = span.find_first_of("{;\n");
                                std::string sig = (cut == std::string::npos)
                                                      ? span
                                                      : span.substr(0, cut);
                                while (!sig.empty() && (sig.back() == ' ' ||
                                                        sig.back() == '\t' ||
                                                        sig.back() == '\r'))
                                    sig.pop_back();
                                detail =
                                    sig.empty() ? ns : (sig + "  (" + ns + ")");
                            } else {
                                detail = ns;
                            }
                        }
                        add_item(member, k, detail);
                    }
                };
            // Namespaces del propio documento (todos, incl. privados de
            // fichero).
            offer_ns_members(an.sem_index.symbols, text, /*public_only=*/false);
            // Namespaces de los modulos importados (solo los public).
            for (const auto &im : an.imported_sem_indexes)
                offer_ns_members(im.index.symbols, im.source,
                                 /*public_only=*/true);
        }
        // Caso miembro: NO mezclamos el completado general (evitar inundar con
        // todo el universo de nombres tras un punto).  Respondemos lo hallado
        // (puede ser vacio si el tipo no se resolvio: best-effort documentado).
        send_result(msg.at("id"), items);
        return;
    }

    // -- COMPLETADO GENERAL (sin '.') ----------------------------------------
    // Palabras clave.
    for (const auto &kw : vx_keywords())
        if (has_prefix(kw, prefix))
            add_item(kw, CompletionKind::Keyword, std::string());
    // Tipos (primitivos + alias + colecciones + genericos builtin).
    for (const auto &ty : vx_types())
        if (has_prefix(ty, prefix)) add_item(ty, CompletionKind::Class, "tipo");
    // Builtins comunes (lista curada, incluye los que no tienen doc formal).
    for (const auto &b : vx_builtins())
        if (has_prefix(b, prefix))
            add_item(b, CompletionKind::Function, "builtin");
    // Builtins documentados (introspeccion, conceptos, overlay, strings, ...):
    // la tabla de docs es la fuente de verdad; el detalle es su firma real.
    for (const auto &b : all_builtin_names())
        if (has_prefix(b, prefix)) {
            const BuiltinDoc *d = lookup_builtin(b);
            // Los conceptos se ofrecen como interfaz/clase (bound o predicado);
            // el resto como funcion builtin.
            bool is_concept =
                d && d->signature.find("<T>()  |  <T:") != std::string::npos;
            add_item(b,
                     is_concept ? CompletionKind::Interface
                                : CompletionKind::Function,
                     d ? d->signature : std::string("builtin"));
        }

    // Simbolos del propio documento (con su firma como detalle cuando exista).
    DocSymbols sym = build_doc_symbols(text, uri);
    for (const auto &d : sym.defs) {
        if (!has_prefix(d.name, prefix)) continue;
        CompletionKind k;
        switch (d.kind) {
        case SymbolKind::Function: k = CompletionKind::Function; break;
        case SymbolKind::Class: k = CompletionKind::Class; break;
        case SymbolKind::Struct: k = CompletionKind::Struct; break;
        case SymbolKind::Enum: k = CompletionKind::Enum; break;
        case SymbolKind::TypeAlias: k = CompletionKind::Class; break;
        case SymbolKind::Variable: k = CompletionKind::Variable; break;
        case SymbolKind::Parameter: k = CompletionKind::Variable; break;
        case SymbolKind::Method: k = CompletionKind::Method; break;
        case SymbolKind::Field: k = CompletionKind::Field; break;
        case SymbolKind::EnumVariant: k = CompletionKind::Enum; break;
        case SymbolKind::Concept: k = CompletionKind::Interface; break;
        default: k = CompletionKind::Variable; break;
        }
        add_item(d.name, k, d.signature);
    }

    // Simbolos del workspace (otros ficheros / librerias importadas).  Solo si
    // las raices estan fijadas; el indice se construye perezosamente.  El
    // dedup por label evita duplicar los que ya aporto el documento.
    if (items.size() < kMaxItems && workspace_.has_roots()) {
        workspace_.ensure_built();
        workspace_.for_each_def_name([&](const std::string &name,
                                         SymbolKind kind,
                                         const std::string &signature) {
            if (!has_prefix(name, prefix)) return;
            CompletionKind k;
            switch (kind) {
            case SymbolKind::Function: k = CompletionKind::Function; break;
            case SymbolKind::Class: k = CompletionKind::Class; break;
            case SymbolKind::Struct: k = CompletionKind::Struct; break;
            case SymbolKind::Enum: k = CompletionKind::Enum; break;
            case SymbolKind::TypeAlias: k = CompletionKind::Class; break;
            case SymbolKind::Variable: k = CompletionKind::Variable; break;
            case SymbolKind::Method: k = CompletionKind::Method; break;
            case SymbolKind::Field: k = CompletionKind::Field; break;
            case SymbolKind::EnumVariant: k = CompletionKind::Enum; break;
            case SymbolKind::Concept: k = CompletionKind::Interface; break;
            default: k = CompletionKind::Variable; break;
            }
            add_item(name, k, signature);
        });
    }

    send_result(msg.at("id"), items);
}

bool LspServer::handle_vesta_request(const std::string &method,
                                     const nlohmann::json &msg) {
    // Toda peticion vesta/* lleva id (es request) y params con el uri.  Si
    // falta algo, respondemos con un error en lugar de crashear.
    if (!msg.contains("id"))
        return false; // sin id no es una peticion: dejar pasar.
    const nlohmann::json &id = msg.at("id");

    // Helper local para responder un error con la forma { error: "..." }.
    auto respond_error = [&](const std::string &what) {
        nlohmann::json r;
        r["error"] = what;
        send_result(id, r);
    };

    try {
        // Extraer params.uri (comun a todas las peticiones del inspector).
        if (!msg.contains("params") || !msg.at("params").is_object()) {
            respond_error("faltan params");
            return true;
        }
        const nlohmann::json &params = msg.at("params");

        // El catalogo de objetivos habla del compilador, no de un documento:
        // se atiende antes de exigir uno.
        if (method == "vesta/targets") {
            send_result(id, inspector_.targets());
            return true;
        }

        // La ficha de una instruccion se pide por su LINEA, no por su texto:
        // asi se responde por lo que el compilador entendio de ella.
        if (method == "vesta/asmFlow") {
            // El flujo de todos los bloques, para pintarlo sobre el codigo.
            send_result(
                id, inspector_.asm_flow(params.value("uri", std::string()),
                                        params.value("arch", std::string())));
            return true;
        }
        if (method == "vesta/asmBlock") {
            // Un bloque de asm entero, con su flujo y lo que se sabe de cada
            // instruccion.
            send_result(
                id, inspector_.asm_block(params.value("uri", std::string()),
                                         params.value("line", 0u),
                                         params.value("cpu", std::string()),
                                         params.value("arch", std::string())));
            return true;
        }
        if (method == "vesta/instruction") {
            send_result(id, inspector_.instruction(
                                params.value("uri", std::string()),
                                params.value("line", 0u),
                                params.value("cpu", std::string()),
                                params.value("arch", std::string())));
            return true;
        }

        const std::string uri = params.value("uri", std::string());
        if (uri.empty()) {
            respond_error("falta params.uri");
            return true;
        }

        // Target OS/arch opcional (vistas por plataforma): params.os /
        // params.arch (vacios = host).  Permite ver el
        // IR/bytecode/asm/JIT/diagrama que el compilador genera para
        // Linux/Windows x x86-64/x86-32.
        lsp::InspectTarget itarget;
        itarget.os = params.value("os", std::string());
        itarget.arch = params.value("arch", std::string());
        // Con que se compila y para que maquina concreta: el nivel de
        // optimizacion, el juego de instrucciones de coma flotante y la
        // microarquitectura cambian lo que sale, asi que son parte de la
        // pregunta.  Sin ellos se responde siempre por el mismo binario.
        itarget.opt = params.value("opt", -1);
        itarget.float_isa = params.value("floatIsa", std::string());
        itarget.cpu = params.value("cpu", std::string());

        nlohmann::json result;
        if (method == "vesta/bytecode") {
            const std::string fn = params.value("function", std::string());
            result = inspector_.bytecode(uri, fn, itarget);
        } else if (method == "vesta/ir") {
            const std::string phase =
                params.value("phase", std::string("post"));
            result = inspector_.ir(uri, phase, itarget);
        } else if (method == "vesta/irDiff") {
            const std::string fn = params.value("function", std::string());
            result = inspector_.ir_diff(uri, fn);
        } else if (method == "vesta/complexity") {
            result = inspector_.complexity(uri);
        } else if (method == "vesta/functionReport") {
            // Lo declarado frente a lo medido, por funcion.
            result = inspector_.function_report(uri);
        } else if (method == "vesta/diagram") {
            const std::string kind =
                params.value("kind", std::string("ir-post"));
            const std::string format =
                params.value("format", std::string("mermaid"));
            const bool cost = params.value("cost", false);
            // 'function' solo lo usa kind="asm" (CFG del codigo nativo).
            const std::string fn = params.value("function", std::string());
            result = inspector_.diagram(uri, kind, format, cost, itarget, fn);
        } else if (method == "vesta/functions") {
            result = inspector_.functions(uri);
        } else if (method == "vesta/aotCompat") {
            const std::string tier = params.value("tier", std::string("bare"));
            result = inspector_.aot_compat(uri, tier);
        } else if (method == "vesta/modes") {
            // Reporte del modulo en interp/JIT/AOT (todos, o el 'mode' pedido).
            const std::string md = params.value("mode", std::string());
            const std::string tier = params.value("tier", std::string("bare"));
            result = inspector_.modes(uri, md, tier);
        } else if (method == "vesta/compile" ||
                   method == "vesta/compileProject") {
            // El LSP embebe el compilador: produce un .velb en disco usando el
            // driver reutilizable (vesta::tc).  No ejecuta nada (eso corre en
            // un proceso aparte: correrlo aqui escribiria en el stdout del LSP
            // y romperia el canal JSON-RPC).
            result = compile_request(method, uri, params);
        } else if (method == "vesta/jitAsm") {
            const std::string fn = params.value("function", std::string());
            result = inspector_.jit_asm(uri, fn, itarget);
        } else if (method == "vesta/aotAsm") {
            const std::string fn = params.value("function", std::string());
            result = inspector_.aot_asm(uri, fn, itarget);
        } else if (method == "vesta/macroExpand") {
            result = inspector_.macro_expand(uri);
        } else if (method == "vesta/comptimeValues") {
            result = inspector_.comptime_values(uri);
        } else if (method == "vesta/asa") {
            // Todo lo que el compilador sabe del modulo, tal y como lo cuenta
            // la linea de ordenes.
            result = inspector_.asa(uri);
        } else if (method == "vesta/asaFacts") {
            // Lo mismo, pero atado a la linea a la que pertenece cada cosa:
            // para ensenarlo EN el codigo mientras se escribe.
            result = inspector_.asa_facts(uri);
        } else if (method == "vesta/paramHints") {
            // Parameter hints (inlay): nombre de cada parametro antes de su
            // argumento en las llamadas a funciones conocidas.
            nlohmann::json arr = nlohmann::json::array();
            if (docs_.has(uri)) {
                const auto text_ref = docs_.text(uri);
                const std::string &text = *text_ref;
                std::vector<ParamHint> ph = compute_param_hints(text, uri);
                for (const auto &h : ph) {
                    nlohmann::json o;
                    o["line"] = h.line;
                    o["character"] = h.character;
                    o["label"] = h.label;
                    arr.push_back(std::move(o));
                }
            }
            result = nlohmann::json::object();
            result["hints"] = std::move(arr);
        } else if (method == "vesta/symbolInfo") {
            // Informacion del simbolo bajo el cursor para el hover rico:
            // nombre + categoria + firma + doc (comentarios precedentes).  Las
            // pestanas IR/bytecode/JIT/AOT las pide el cliente aparte
            // (on-demand) con vesta/ir, vesta/bytecode, vesta/jitAsm,
            // vesta/aotAsm.
            const uint32_t line = params.value("line", 0u);
            const uint32_t character = params.value("character", 0u);
            nlohmann::json info = nlohmann::json::object();
            info["found"] = false;
            if (docs_.has(uri)) {
                // Reusar la extraccion de palabra del hover (maneja UTF-16).
                nlohmann::json hp;
                hp["textDocument"]["uri"] = uri;
                hp["position"]["line"] = line;
                hp["position"]["character"] = character;
                std::string u2, word;
                if (word_under_cursor(hp, u2, word) && !word.empty()) {
                    const auto text_ref = docs_.text(uri);
                    const std::string &text = *text_ref;
                    DocSymbols local = build_doc_symbols(text, uri);
                    const SymbolDef *def = nullptr;
                    for (const auto &d : local.defs)
                        if (d.name == word) {
                            def = &d;
                            break;
                        }
                    info["name"] = word;
                    if (def) {
                        info["found"] = true;
                        info["kind"] = symbol_kind_name(def->kind);
                        info["signature"] = def->signature;
                        info["container"] = def->container;
                        info["doc"] =
                            extract_doc_comment(text, def->byte_offset);
                        const bool callable =
                            def->kind == SymbolKind::Function ||
                            def->kind == SymbolKind::Method;
                        info["callable"] = callable;
                    } else if (const BuiltinDoc *b = lookup_builtin(word)) {
                        // Builtin del lenguaje (print, sizeof, str_*, ...):
                        // doc + firma desde la tabla central.  callable=false
                        // -> el hover solo muestra la pestana Doc (los builtins
                        // no tienen IR/JIT/AOT de usuario que inspeccionar).
                        info["found"] = true;
                        info["kind"] = "builtin";
                        info["signature"] = b->signature;
                        info["container"] = "";
                        info["doc"] = b->doc;
                        info["callable"] = false;
                    } else {
                        // Identificador sin definicion local (var local, tipo
                        // importado): aun util saber el nombre.
                        info["found"] = true;
                        info["kind"] = "unknown";
                        info["signature"] = "";
                        info["doc"] = "";
                        info["callable"] = false;
                    }
                }
            }
            result = std::move(info);
        } else {
            // Metodo vesta/* desconocido: no manejado aqui.
            return false;
        }
        send_result(id, result);
        return true;
    } catch (const std::exception &e) {
        // Cualquier fallo del inspector se convierte en un error de
        // resultado: el servidor sigue sirviendo.
        respond_error(std::string("excepcion en el inspector: ") + e.what());
        return true;
    } catch (...) {
        respond_error("excepcion desconocida en el inspector");
        return true;
    }
}

void LspServer::dispatch(const nlohmann::json &msg) {
    // Todo mensaje LSP valido lleva un campo method (string).  Sin el, lo
    // ignoramos (puede ser una respuesta a una peticion nuestra, etc.).
    if (!msg.contains("method") || !msg.at("method").is_string()) return;
    const std::string method = msg.at("method").get<std::string>();

    // Peticiones (llevan id) y notificaciones (no llevan id) se distinguen
    // por la presencia del campo id.
    if (method == "initialize") {
        handle_initialize(msg);
    } else if (method == "initialized") {
        // Notificacion sin payload relevante: no requiere respuesta.
    } else if (method == "workspace/didChangeConfiguration") {
        // Cambiar el objetivo cambia lo que se compila, asi que hay que
        // reanalizar y volver a publicar: los errores de antes eran los de
        // otra maquina.
        if (msg.contains("params") && msg.at("params").is_object()) {
            apply_target_settings(
                msg.at("params").value("settings", nlohmann::json::object()));
            for (const auto &uri : docs_.open_uris())
                publish_diagnostics(uri);
        }
    } else if (method == "shutdown") {
        handle_shutdown(msg);
    } else if (method == "exit") {
        // exit se maneja en el bucle run(); aqui no hacemos nada.
    } else if (method == "textDocument/didOpen") {
        handle_did_open(msg.at("params"));
    } else if (method == "textDocument/didChange") {
        handle_did_change(msg.at("params"));
    } else if (method == "textDocument/didClose") {
        handle_did_close(msg.at("params"));
    } else if (method == "textDocument/semanticTokens/full") {
        handle_semantic_tokens_full(msg);
    } else if (method == "textDocument/formatting") {
        try {
            handle_formatting(msg);
        } catch (...) {
            // Ante cualquier fallo se responde una lista VACIA de ediciones:
            // el editor deja el fichero como esta, que es lo que hay que hacer
            // cuando no se sabe.  Nunca a medias.
            if (msg.contains("id"))
                send_result(msg.at("id"), nlohmann::json::array());
        }
    } else if (method == "textDocument/hover") {
        // Navegacion (Fase 4): cada handler envuelve su logica de forma que un
        // fallo NO tumba el servidor; ademas respondemos null/[] ante error
        // para cumplir el protocolo (toda peticion debe responderse).
        try {
            handle_hover(msg);
        } catch (...) {
            if (msg.contains("id")) send_result(msg.at("id"), nullptr);
        }
    } else if (method == "textDocument/definition") {
        try {
            handle_definition(msg);
        } catch (...) {
            if (msg.contains("id")) send_result(msg.at("id"), nullptr);
        }
    } else if (method == "workspace/symbol") {
        /* Buscar un simbolo por su NOMBRE, sin tener que saber en que fichero
         * esta.  Hace falta para ir a una funcion desde donde se la nombra --
         * un informe, una vista, un hecho del analisis --, que es sitio donde
         * no hay posicion que dar y por tanto "ir a la definicion" no sirve. */
        try {
            handle_workspace_symbol(msg);
        } catch (...) {
            if (msg.contains("id"))
                send_result(msg.at("id"), nlohmann::json::array());
        }
    } else if (method == "textDocument/references") {
        try {
            handle_references(msg);
        } catch (...) {
            if (msg.contains("id"))
                send_result(msg.at("id"), nlohmann::json::array());
        }
    } else if (method == "textDocument/completion") {
        // Autocompletado (Fase 5): ante un fallo respondemos una lista vacia
        // valida para cumplir el protocolo sin tumbar el servidor.
        try {
            handle_completion(msg);
        } catch (...) {
            if (msg.contains("id"))
                send_result(msg.at("id"), nlohmann::json::array());
        }
    } else if (method.rfind("vesta/", 0) == 0 &&
               handle_vesta_request(method, msg)) {
        // Peticion a medida del inspector (vesta/*) atendida.
    } else if (msg.contains("id")) {
        // Peticion de un metodo no soportado: responder error MethodNotFound
        // para cumplir el protocolo (las peticiones SIEMPRE deben responderse).
        nlohmann::json resp;
        resp["jsonrpc"] = "2.0";
        resp["id"] = msg.at("id");
        resp["error"] = {{"code", -32601}, // MethodNotFound
                         {"message", "metodo no soportado: " + method}};
        transport_.write_message(resp);
    }
    // Notificaciones no soportadas: se ignoran en silencio (permitido).
}

/**
 * @brief Nombre del metodo de un mensaje, o vacio si no lo lleva.
 * @param msg Mensaje JSON-RPC.
 * @return El metodo.
 */
static std::string metodo_de(const nlohmann::json &msg) {
    if (!msg.contains("method") || !msg.at("method").is_string())
        return std::string();
    return msg.at("method").get<std::string>();
}

/**
 * @brief La URI del documento de un mensaje, o vacia.
 * @param msg Mensaje JSON-RPC.
 * @return La URI.
 */
static std::string uri_de(const nlohmann::json &msg) {
    if (!msg.contains("params") || !msg.at("params").is_object())
        return std::string();
    const nlohmann::json &p = msg.at("params");
    if (!p.contains("textDocument") || !p.at("textDocument").is_object())
        return std::string();
    return p.at("textDocument").value("uri", std::string());
}

/**
 * @brief Indica si un mensaje CAMBIA el estado del servidor.
 *
 * Estos van en orden y por un solo hilo; el resto se reparte.  La lista es
 * corta a proposito: en la duda, un mensaje se trata como si cambiara algo,
 * que es lo conservador.
 *
 * @param metodo Nombre del metodo.
 * @return true si hay que atenderlo en orden.
 */
static bool es_mutacion(const std::string &metodo) {
    return metodo == "initialize" || metodo == "initialized" ||
           metodo == "shutdown" || metodo == "textDocument/didOpen" ||
           metodo == "textDocument/didChange" ||
           metodo == "textDocument/didClose" ||
           metodo == "workspace/didChangeConfiguration" ||
           metodo == "workspace/didChangeWatchedFiles" ||
           metodo.rfind("vesta/compile", 0) == 0; // escribe en disco
}

int LspServer::run() {
    /* Leer la entrada NO puede depender de haber terminado lo anterior.
     *
     * Con un solo hilo, mientras se compila no se lee, y compilar un modulo
     * grande son minutos: en ese rato el `exit` del editor se queda en la
     * tuberia sin que nadie lo mire, y el servidor "no se deja cerrar" -- que
     * es exactamente como se ve desde fuera --.  Asi que un hilo lee y encola,
     * y este despacha.  Escribir sigue siendo cosa de uno solo (este), que es
     * lo que evita que dos respuestas se entrelacen. */
    std::mutex m;
    std::condition_variable cv;
    std::deque<nlohmann::json> cola;

    /* Que la entrada se acabo, y con que codigo hay que salir.
     *
     * No se sale desde el lector: cuando llega el `exit` -- o cuando el editor
     * cierra la tuberia -- puede haber mensajes YA LEIDOS y sin atender, y
     * matar el proceso ahi los tira.  Se vio con el banco de pruebas, que
     * manda los cuatro mensajes de golpe: el lector se comia los cuatro,
     * llegaba al `exit` y terminaba antes de que nadie respondiera al
     * `initialize`.  El servidor salia con 1 y sin escribir un byte.
     *
     * Esperar tampoco puede ser lo de antes: lo que NO funcionaba era que el
     * `exit` se quedara sin leer detras de una compilacion larga.  Eso ya no
     * pasa -- leer es de otro hilo --, asi que aqui solo se espera a vaciar lo
     * que ya estaba encolado, que es un trabajo acotado. */
    std::atomic<bool> input_finished{false};
    std::atomic<int> exit_code{0};

    std::thread lector([&] {
        nlohmann::json msg;
        while (transport_.read_message(msg)) {
            const std::string metodo = metodo_de(msg);
            /* Que el editor lo PIDIO se sabe aqui, al leerlo, y no cuando se
             * le conteste: el `exit` puede venir pegado detras y entonces el
             * `shutdown` sigue en la cola.  Quien contesta lo vuelve a marcar,
             * que es idempotente. */
            if (metodo == "shutdown") shutdown_requested_.store(true);
            if (metodo == "exit") {
                /* Se deja DICHO que se acabo, y quien atiende sale cuando no
                 * le queda nada.  Terminar aqui mismo tiraba lo que ya estaba
                 * leido y sin atender.
                 *
                 * El codigo lo manda el protocolo: cero si hubo `shutdown`
                 * antes, uno si no.  Se mira aqui y no al salir porque el
                 * `shutdown` puede estar todavia en la cola -- lo importante
                 * es que el editor lo PIDIO, no que ya se le haya contestado. */
                exit_code.store(shutdown_requested_.load() ? 0 : 1);
                input_finished.store(true);
                cv.notify_all();
                return;
            }
            {
                std::lock_guard<std::mutex> guard(m);
                /* Un cambio de documento SUSTITUYE al anterior del mismo
                 * fichero: la sincronizacion es de texto completo, asi que el
                 * ultimo dice todo lo que hay que saber.  Sin esto, teclear
                 * durante una compilacion larga encola una compilacion por
                 * pulsacion y el servidor se queda minutos por detras
                 * recalculando textos que ya nadie tiene delante. */
                if (metodo == "textDocument/didChange") {
                    const std::string uri = uri_de(msg);
                    if (!uri.empty()) {
                        for (auto it = cola.begin(); it != cola.end();) {
                            if (metodo_de(*it) == "textDocument/didChange" &&
                                uri_de(*it) == uri)
                                it = cola.erase(it);
                            else
                                ++it;
                        }
                    }
                }
                /* Cancelar lo que aun no ha empezado.  El editor cancela en
                 * cuanto el cursor se mueve, y una peticion que ya no le
                 * interesa a nadie no tiene por que costar una compilacion --
                 * ni retrasar a las que vienen detras --.  Lo que YA se esta
                 * atendiendo no se puede parar todavia: eso necesita puntos de
                 * cancelacion dentro del compilador. */
                if (metodo == "$/cancelRequest") {
                    const nlohmann::json &p =
                        msg.value("params", nlohmann::json::object());
                    if (p.contains("id")) {
                        const nlohmann::json &quien = p.at("id");
                        for (auto &encolada : cola) {
                            if (encolada.contains("id") &&
                                encolada.at("id") == quien) {
                                /* Se marca, no se borra: toda peticion tiene
                                 * que recibir respuesta, y quien responde es el
                                 * hilo que despacha -- el unico que escribe --.
                                 * Borrarla dejaria al editor esperando algo que
                                 * no va a llegar. */
                                encolada["__cancelada"] = true;
                            }
                        }
                    }
                    continue; // la cancelacion en si no se despacha
                }
                cola.push_back(std::move(msg));
            }
            cv.notify_one();
        }
        /* El editor cerro la tuberia.  Se deja dicho, igual que con el `exit`:
         * cerrar la entrada no significa que lo ya leido no haya que
         * atenderlo, y terminar aqui lo tiraba.
         *
         * Sin vaciar nada a proposito: `fflush(NULL)` pide el cerrojo de CADA
         * flujo, y el de la salida puede tenerlo el otro hilo escribiendo en
         * una tuberia que ya nadie lee.  Ahi el cierre se quedaba esperando
         * para siempre -- justo lo contrario de lo que se busca --.  Cada
         * respuesta se vacia al escribirse, asi que no hay nada pendiente. */
        exit_code.store(0);
        input_finished.store(true);
        cv.notify_all();
    });
    lector.detach(); // vive lo que el proceso; su final es el del proceso.

    /* La salida es de ESTE hilo, abajo: quien lee sabe que la conversacion se
     * acabo, pero no si queda algo por atender.  Terminar alli tiraba lo ya
     * leido -- y con el banco de pruebas, que manda los cuatro mensajes de
     * golpe, tiraba TODO: el servidor salia con 1 y sin escribir un byte. */

    /* Atender un mensaje.  Lo hace este hilo o uno del grupo, segun el mensaje;
     * la diferencia esta abajo. */
    auto atender = [this](const nlohmann::json &msg) {
        /* Cancelada mientras esperaba: se contesta que se cancelo y no se hace
         * el trabajo.  El codigo -32800 es el que el protocolo reserva para
         * esto, y el editor lo entiende como "no pasa nada". */
        if (msg.value("__cancelada", false) && msg.contains("id")) {
            nlohmann::json resp;
            resp["jsonrpc"] = "2.0";
            resp["id"] = msg.at("id");
            resp["error"] = {{"code", -32800}, // RequestCancelled
                             {"message", "peticion cancelada"}};
            transport_.write_message(resp);
            return;
        }
        // Despachar bajo try/catch: un mensaje malformado (campos ausentes)
        // no debe tumbar el servidor.
        try {
            dispatch(msg);
        } catch (...) {
            // Ignorar errores de un mensaje individual y seguir sirviendo.
        }
    };

    /* El grupo de hilos que atiende las CONSULTAS.
     *
     * Se crean una vez y viven lo que el proceso: crear y destruir hilos por
     * peticion cuesta, y en este toolchain ademas es la situacion en la que la
     * TLS emulada se ha colgado alguna vez (ver util/thread_slot.h).
     *
     * Tantos como nucleos, con techo: el compilador ya reparte SUS modulos
     * entre hilos, asi que poner aqui veinte no compila mas rapido, solo se
     * pelean por los mismos nucleos. */
    unsigned cuantos = std::thread::hardware_concurrency();
    if (cuantos == 0) cuantos = 2;
    if (cuantos > 4) cuantos = 4;

    std::mutex m_trabajo;
    std::condition_variable cv_trabajo;
    std::deque<nlohmann::json> trabajo;
    /// Consultas SACADAS de la cola y aun sin contestar.  Sin esto, "no queda
    /// nada" se leia solo de la cola, y una consulta a medio atender no
    /// contaba: el servidor salia y el editor se quedaba sin respuesta.
    size_t in_flight = 0;
    std::vector<std::thread> grupo;
    grupo.reserve(cuantos);
    for (unsigned i = 0; i < cuantos; ++i) {
        grupo.emplace_back([&] {
            for (;;) {
                nlohmann::json tarea;
                {
                    std::unique_lock<std::mutex> guard(m_trabajo);
                    cv_trabajo.wait(guard, [&] { return !trabajo.empty(); });
                    tarea = std::move(trabajo.front());
                    trabajo.pop_front();
                    /* Se cuenta AQUI, bajo el mismo cerrojo que la saca de la
                     * cola: entre sacarla y marcarla no puede haber un hueco
                     * en el que parezca que no queda nada -- ahi es donde el
                     * hilo principal decidiria salir y se perderia la
                     * respuesta. */
                    ++in_flight;
                }
                atender(tarea);
                {
                    std::lock_guard<std::mutex> guard(m_trabajo);
                    --in_flight;
                }
                /* Puede ser la ultima que quedaba: si el principal esta
                 * esperando para salir, que se entere. */
                cv.notify_all();
            }
        });
    }
    for (auto &h : grupo)
        h.detach(); // viven lo que el proceso, como el lector

    for (;;) {
        nlohmann::json msg;
        {
            std::unique_lock<std::mutex> guard(m);
            /* Queda algo por hacer en el grupo?  Se mira bajo SU cerrojo. */
            const auto pool_busy = [&] {
                std::lock_guard<std::mutex> g(m_trabajo);
                return !trabajo.empty() || in_flight != 0;
            };
            cv.wait(guard, [&] {
                return !cola.empty() ||
                       (input_finished.load() && !pool_busy());
            });
            /* Se acabo la entrada Y no queda nada por atender: AHORA se sale.
             *
             * Este es el unico sitio del que se sale, y a proposito: el hilo
             * que lee sabe que la conversacion termino, pero no si queda
             * trabajo -- y salir con la cola llena es perder respuestas que el
             * editor esta esperando.  `_Exit` no corre destructores: hacerlo
             * con un hilo del grupo dentro del compilador seria peor que no
             * hacerlo, y lo ya respondido esta fuera porque cada escritura
             * hace flush. */
            if (cola.empty()) {
                guard.unlock();
                std::_Exit(exit_code.load());
            }
            msg = std::move(cola.front());
            cola.pop_front();
        }
        /* Lo que CAMBIA el estado se atiende aqui y en orden; lo que solo
         * PREGUNTA se reparte.
         *
         * El orden importa en lo primero y no en lo segundo: abrir, escribir y
         * cerrar un documento tienen que ocurrir en el orden en que se
         * escribieron -- si un cambio adelantara al anterior, el fichero
         * quedaria con un texto que nunca se tecleo --.  Una consulta, en
         * cambio, mira un estado y no lo toca, asi que dos consultas sobre
         * documentos distintos no tienen nada que decirse.
         *
         * Y es justo lo que se queria: mientras una consulta compila un modulo
         * grande, las demas siguen contestando. */
        if (es_mutacion(metodo_de(msg))) {
            atender(msg);
            continue;
        }
        {
            std::lock_guard<std::mutex> guard(m_trabajo);
            trabajo.push_back(std::move(msg));
        }
        cv_trabajo.notify_one();
    }
}

} // namespace lsp
