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
 * @file analysis_engine.cpp
 * @brief Implementacion del motor de analisis de documentos del LSP.
 *
 * RIESGO conocido (fase futura): el frontend del compilador podria llegar
 * a segfaultear con fuente Vesta muy parcial o malformada.  Las excepciones
 * C++ SI se capturan aqui, pero un segfault no.  Una fase futura debe
 * aislar el analisis en un subproceso o thread con sandbox para que un
 * crash del frontend no tumbe el servidor LSP.  De momento se confia en
 * que el frontend reporta errores via diagnosticos y no aborta.
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "lsp/analysis_engine.h"

#include <exception>
#include <fstream>
#include <unordered_map>

#include "analyze/bigo.h"
#include "ir/ssa_ir.h"
#include "ir/ssa_ir_serialize.h"
#include "lsp/symbol_index.h" // uri_to_fs_path (multi-modulo)
#include "vx/ast.h"
#include "vx/compiler.h" // compile_vx_project (multi-modulo)
#include "vx/diagnostic.h"
#include "vx/lexer.h"
#include "vx/parser.h"

namespace lsp {

uint64_t fnv1a_hash(const std::string &s) {
    // FNV-1a 64-bit: rapido, sin dependencias, suficiente para detectar
    // cambios del texto entre peticiones (no es hash criptografico).
    uint64_t h = util::kFnvOffset; // offset basis
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(c);
        h *= util::kFnvPrime; // prime
    }
    return h;
}

namespace {

/**
 * @brief Devuelve la primera linea fuente conocida de una funcion IR.
 *
 * Recorre los bloques y sus instrucciones buscando el primer
 * @c source_line distinto de cero.  Sirve para ubicar de forma
 * best-effort el warning de @c @complexity cuando la cota inferida no
 * coincide con la declarada (el IR no guarda una SourceLoc por funcion).
 *
 * @param fn Funcion IR.
 * @return Linea 1-based, o 0 si ninguna instruccion lleva linea.
 */
uint32_t first_source_line(const ir::IrFunction &fn) {
    for (const auto &blk : fn.blocks) {
        for (const auto &ins : blk.instrs) {
            if (ins.source_line != 0) return ins.source_line;
        }
    }
    return 0;
}

/**
 * @brief Computa el coste/complejidad del modulo y engancha el warning de
 *        discrepancia de @c @complexity.
 *
 * Deserializa el IR del modulo (post-opt) cacheado en el @c CompileResult,
 * corre el analisis de coste interprocedural, GUARDA el resultado en
 * @p out_cost (para que el hover lo reutilice sin recomputar) y, por cada
 * funcion cuyo contrato @c @complexity no coincide de forma confirmada con la
 * cota inferida (@c contract_mismatch), emite un WARNING.
 *
 * Best-effort en la ubicacion: el IR no conserva una SourceLoc por
 * funcion, asi que el warning se situa en la primera linea conocida de la
 * funcion (columna 1).  Si no hay linea, se omite el warning de esa
 * funcion para no apuntar a una posicion enganosa.
 *
 * Robusto: cualquier fallo de deserializacion o analisis se traga en
 * silencio (el warning es informativo, no debe romper los diagnosticos
 * principales).
 *
 * @param result   CompileResult con @c ir_module_cache_bytes; recibe los
 *                 warnings en @c result.diagnostics.
 * @param filename Nombre logico del fichero para la SourceLoc.
 * @param out_cost Destino del coste por funcion (queda vacio si no hubo IR).
 */
void attach_complexity_warnings(vx::CompileResult &result,
                                const std::string &filename,
                                analyze::ModuleCost &out_cost) {
    if (result.ir_module_cache_bytes.empty()) return;
    try {
        ir::IrModule mod;
        if (!ir::parse_ir_module_cache(result.ir_module_cache_bytes, mod))
            return;
        // Coste PARCIAL + composicion interprocedural (coste efectivo real).
        analyze::ModuleCost mc = analyze::analyze_module(mod);
        analyze::compose_interproc(mc);

        // Indexar las funciones IR por nombre para recuperar su linea.
        // mc.functions sigue el orden de mod.functions, asi que un recorrido
        // emparejado es O(n) sin construir mapa.
        for (const auto &cr : mc.functions) {
            if (!cr.contract_mismatch) continue;
            // Localizar la IrFunction homonima para extraer la linea.
            uint32_t line = 0;
            for (const auto &fn : mod.functions) {
                if (fn.name == cr.function) {
                    line = first_source_line(fn);
                    break;
                }
            }
            if (line == 0) continue; // sin linea fiable: no ubicar el warning.

            vx::SourceLoc loc;
            loc.file = filename;
            loc.line = line;
            loc.column = 1;
            loc.length = 1;
            // Mensaje claro: declarada vs inferida (la efectiva post-opt).
            std::string msg = "la complejidad declarada (@complexity ";
            msg += cr.declared_expr;
            msg += ") no coincide con la inferida (";
            msg += analyze::cost_class_str(cr.total_class);
            msg += ")";
            result.diagnostics.warning(loc, msg);
        }
        // Guardar el coste para que el hover lo reutilice sin recomputar.
        out_cost = std::move(mc);
    } catch (...) {
        // El warning de complejidad es opcional: ignorar cualquier fallo.
    }
}

/**
 * @brief Extrae los nombres de tipos/clases/structs/enums/funciones
 *        declarados top-level en el fuente.
 *
 * Hace un lex+parse independiente (descartando los diagnosticos: ya los
 * produce la compilacion principal) y recorre las declaraciones top-level
 * del @c ModuleNode para poblar los sets de @p out.  Se ejecuta bajo
 * try/catch externo en el caller; aqui ademas se ignora cualquier nodo
 * inesperado para ser robusto frente a AST parciales (fuente a medio
 * teclear).
 *
 * Este parse extra es necesario porque @c CompileResult no expone las
 * tablas de tipos del type checker; el coste es pequeno (el lexer es
 * O(N) y solo recorremos las declaraciones de primer nivel).
 *
 * @param text Texto fuente del documento.
 * @param uri  URI logico (nombre del fichero para el lexer).
 * @param out  DocAnalysis cuyos sets de nombres se rellenan.
 */
void extract_declared_names(const std::string &text, const std::string &uri,
                            DocAnalysis &out) {
    // Diagnosticos locales y descartables: solo queremos el AST.
    vx::Diagnostics local_diags;
    vx::Lexer lex(text, uri, local_diags);
    vx::Parser parser(lex, local_diags);
    std::unique_ptr<vx::ast::ModuleNode> mod = parser.parse_program();
    if (!mod) return;
    // Recorrer SOLO las declaraciones top-level: nombres de tipos y funciones
    // visibles para el resaltado.  Los miembros (campos/metodos) se refinaran
    // en una fase futura (parametros/propiedades por posicion).
    for (const auto &node : mod->decls) {
        if (!node) continue;
        switch (node->kind) {
        case vx::ast::NodeKind::ClassDecl: {
            auto *d = static_cast<const vx::ast::ClassDecl *>(node.get());
            if (!d->name.empty()) out.class_names.insert(d->name);
            // Parametros de plantilla de una clase generica (class Box<T>).
            for (const auto &tp : d->type_params)
                if (!tp.empty()) out.type_params.insert(tp);
            break;
        }
        case vx::ast::NodeKind::StructDecl: {
            auto *d = static_cast<const vx::ast::StructDecl *>(node.get());
            if (!d->name.empty()) out.struct_names.insert(d->name);
            break;
        }
        case vx::ast::NodeKind::EnumDecl: {
            auto *d = static_cast<const vx::ast::EnumDecl *>(node.get());
            if (!d->name.empty()) out.enum_names.insert(d->name);
            // Parametros de plantilla de un enum generico (enum Maybe<T>).
            for (const auto &tp : d->type_params)
                if (!tp.empty()) out.type_params.insert(tp);
            break;
        }
        case vx::ast::NodeKind::TypeAliasDecl: {
            auto *d = static_cast<const vx::ast::TypeAliasDecl *>(node.get());
            if (!d->name.empty()) out.type_names.insert(d->name);
            break;
        }
        case vx::ast::NodeKind::ConceptDecl: {
            auto *d = static_cast<const vx::ast::ConceptDecl *>(node.get());
            if (!d->name.empty()) out.concept_names.insert(d->name);
            // Parametros de plantilla del concepto (concept N<T>).
            for (const auto &tp : d->type_params)
                if (!tp.empty()) out.type_params.insert(tp);
            break;
        }
        case vx::ast::NodeKind::FunctionDecl: {
            auto *d = static_cast<const vx::ast::FunctionDecl *>(node.get());
            if (!d->name.empty()) out.function_names.insert(d->name);
            // Parametros de plantilla de una funcion comptime generica
            // (comptime <T> u32 vec_dim()).
            for (const auto &tp : d->type_params)
                if (!tp.empty()) out.type_params.insert(tp);
            break;
        }
        case vx::ast::NodeKind::ExternFnDecl: {
            // Las funciones extern (FFI declarativo) tambien se clasifican
            // como funciones para el resaltado.
            auto *d = static_cast<const vx::ast::ExternFnDecl *>(node.get());
            if (!d->name.empty()) out.function_names.insert(d->name);
            break;
        }
        default: break;
        }
    }
}

} // namespace

std::string norm_target_arch(const std::string &arch) {
    if (arch.empty() || arch == "x86-64" || arch == "x86_64" || arch == "x64")
        return "x86_64";
    if (arch == "x86-32" || arch == "x86_32" || arch == "x86" || arch == "i386")
        return "x86";
    return arch;
}

CondCompTargetGuard::CondCompTargetGuard(const std::string &os,
                                         const std::string &arch) {
    // Sin objetivo pedido no se toca el thread_local: compilar para el
    // anfitrion es lo normal y no tiene que pagar nada.
    if (os.empty() && arch.empty()) return;
    vx::get_aot_condcomp_target(prev_os_, prev_arch_);
    vx::set_aot_condcomp_target(os, norm_target_arch(arch));
    aplicado_ = true;
}

CondCompTargetGuard::~CondCompTargetGuard() {
    if (aplicado_) vx::set_aot_condcomp_target(prev_os_, prev_arch_);
}

void AnalysisEngine::set_target(const std::string &os,
                                const std::string &arch) {
    std::lock_guard<std::mutex> guard(mapa_);
    if (os == target_os_ && arch == target_arch_) return;
    target_os_ = os;
    target_arch_ = arch;
    // Lo analizado respondia a otra pregunta: se tira entero.  Lo que alguien
    // este usando ahora sigue vivo mientras lo use; simplemente ya no se
    // ofrece a nadie mas.
    cache_.clear();
}

std::shared_ptr<const DocAnalysis>
AnalysisEngine::analyze_document(const std::string &uri,
                                 const std::string &text) {
    const uint64_t h = fnv1a_hash(text);

    /* El cerrojo del documento se saca bajo el del mapa y se suelta este
     * enseguida: mientras uno compila `a.vx`, otro puede entrar aqui y ponerse
     * a compilar `b.vx`.  Lo que no puede es compilar `a.vx` otra vez, y para
     * eso espera en el cerrojo de `a.vx`. */
    std::shared_ptr<std::mutex> cerrojo_doc;
    std::string os_ahora, arch_ahora;
    {
        std::lock_guard<std::mutex> guard(mapa_);
        auto it = cache_.find(uri);
        if (it != cache_.end() && it->second->text_hash == h) return it->second;
        auto &slot = por_documento_[uri];
        if (!slot) slot = std::make_shared<std::mutex>();
        cerrojo_doc = slot;
        os_ahora = target_os_;
        arch_ahora = target_arch_;
    }
    std::lock_guard<std::mutex> guard_doc(*cerrojo_doc);
    {
        // Puede que quien iba delante ya lo haya dejado hecho.
        std::lock_guard<std::mutex> guard(mapa_);
        auto it = cache_.find(uri);
        if (it != cache_.end() && it->second->text_hash == h) return it->second;
    }

    // Crear (o reusar el slot de) el analisis para este documento.
    auto analysis = std::make_shared<DocAnalysis>();
    analysis->text_hash = h;

    /* Para que maquina se compila.  Los diagnosticos y todo lo que sale de
     * compilar dependen de esto: las variantes @Target que no encajan con el
     * objetivo no existen, y con ellas se van sus imports y sus tipos.
     *
     * La guarda es POR HILO, asi que se aplica aqui: cada uno fija el suyo y lo
     * restaura al salir. */
    const CondCompTargetGuard tguard(os_ahora, arch_ahora);

    try {
        // Compilar el fuente.  No aplicamos VPP en Fase 1 (el frontend no lo
        // hace por si mismo; integrarlo es trabajo de una fase posterior).
        vx::CompileOptions opts;
        opts.module_name = "main";
        // Capturar los valores comptime (consts + builtins sizeof/kind/...) con
        // su ubicacion, para que el hover y el inspector los muestren.  Coste
        // bajo (un vector pequeno) y solo en el analisis del LSP.
        opts.dump_comptime_values = true;
        // Multi-modulo: si el buffer tiene `import "..."`, compilar el PROYECTO
        // (resuelve los imports del disco) usando el buffer como overlay del
        // root.  Sin esto el analisis single-file reporta "nombre no declarado"
        // para cualquier simbolo de un modulo importado (serial/fb/... de un
        // programa multi-fichero).  El fs_path se deriva del uri file://.
        const std::string fs_path = uri_to_fs_path(uri);
        // Usar el MISMO detector que el compilador (@c vx_source_has_imports):
        // reconoce imports con puntos (`import std.comptime only source;`)
        // igual que los de string (`import "modules/foo";`), ignorando strings
        // y comentarios.  El check anterior solo miraba `import "` -> un
        // fichero con imports DOTTED caia al path single-file, que no resuelve
        // el modulo ni siembra los params `expr` importados (source/inject) ->
        // el parser reportaba errores FALSOS en `source(...)` (raw-capture no
        // reconocido).
        const bool has_imports = vx::vx_source_has_imports(text);
        const bool file_on_disk =
            !fs_path.empty() && std::ifstream(fs_path).good();
        if (has_imports && file_on_disk) {
            std::unordered_map<std::string, std::string> overlay;
            overlay[fs_path] = text;
            // Los directorios de encima, para resolver los imports relativos
            // al root del proyecto cuando el fichero analizado es un modulo
            // que no es la raiz.  La regla de hasta donde subir vive en un
            // solo sitio (@ref lsp::import_search_roots).
            const std::vector<std::string> anc =
                lsp::import_search_roots(fs_path);
            analysis->result =
                vx::compile_vx_project(fs_path, opts, &overlay, &anc);
            // Cross-module: indexar los modulos importados para el completado
            // `lib.<TAB>` y la navegacion cualificada.  Best-effort (misma
            // resolucion de paths que el compile de arriba); un fallo aqui no
            // afecta a los diagnosticos.
            try {
                analysis->imported_sem_indexes =
                    vx::build_imported_sem_indexes(fs_path, text, anc);
            } catch (...) {
                // sin indices importados; el resto del analisis sigue valido.
            }
        } else {
            analysis->result = vx::compile_vx_source(text, uri, opts);
        }
        // Enganchar (best-effort) el warning de discrepancia de @complexity y
        // cachear el coste/complejidad para el hover.
        attach_complexity_warnings(analysis->result, uri, analysis->cost);
        // Poblar los sets de nombres declarados para el resaltado semantico.
        // Best-effort: un fallo del parse extra no debe afectar a los
        // diagnosticos (el catch externo cubre cualquier excepcion).
        extract_declared_names(text, uri, *analysis);
        // NS.4: indice semantico del AST RAW (pre-flatten) -- nombres
        // CUALIFICADOS por namespace, para completado de miembro `ns.simbolo`
        // y resolucion de acceso cualificado.  Parse independiente del compile
        // (que aplana los namespaces); best-effort (sin indice si el parse
        // peta).
        try {
            vx::Diagnostics sidiag;
            vx::Lexer slx(text, uri, sidiag);
            vx::Parser sp(slx, sidiag);
            auto smod = sp.parse_program();
            if (smod)
                analysis->sem_index =
                    vx::build_semantic_index(*smod, text, uri);
        } catch (...) {
            // sin indice; el resto del analisis sigue valido.
        }
    } catch (const std::exception &e) {
        // Un fallo del frontend NO debe tumbar el servidor: convertirlo en un
        // diagnostico de error interno en 0:0 para que el cliente lo vea.
        analysis->result = vx::CompileResult{};
        analysis->result.ok = false;
        vx::SourceLoc loc;
        loc.file = uri;
        loc.line = 1; // LSP es 0-based; el mapeo restara 1 -> linea 0.
        loc.column = 1;
        loc.length = 1;
        std::string msg = "error interno del analizador: ";
        msg += e.what();
        analysis->result.diagnostics.error(loc, msg);
    } catch (...) {
        // Captura de cualquier otra excepcion no estandar.
        analysis->result = vx::CompileResult{};
        analysis->result.ok = false;
        vx::SourceLoc loc;
        loc.file = uri;
        loc.line = 1;
        loc.column = 1;
        loc.length = 1;
        analysis->result.diagnostics.error(
            loc, "error interno del analizador (excepcion desconocida)");
    }

    // Guardar y devolver.  Quien lo recibe conserva el suyo vivo aunque otro
    // lo sustituya aqui dentro un instante despues.
    std::shared_ptr<const DocAnalysis> hecho = std::move(analysis);
    {
        std::lock_guard<std::mutex> guard(mapa_);
        cache_[uri] = hecho;
    }
    return hecho;
}

std::shared_ptr<const DocAnalysis>
AnalysisEngine::cached(const std::string &uri) const {
    std::lock_guard<std::mutex> guard(mapa_);
    auto it = cache_.find(uri);
    return it == cache_.end() ? nullptr : it->second;
}

void AnalysisEngine::forget(const std::string &uri) {
    std::lock_guard<std::mutex> guard(mapa_);
    cache_.erase(uri);
    /* El cerrojo del documento NO se borra: puede haber alguien dentro de el
     * compilando ese mismo fichero ahora mismo.  Son unos pocos bytes por
     * documento abierto en toda la sesion. */
}

} // namespace lsp
