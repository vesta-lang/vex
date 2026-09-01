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
 * @file lsp_server.h
 * @brief Servidor Language Server Protocol para Vesta (Fase 1).
 *
 * Despacha los metodos del LSP que esta fase soporta:
 *   - @c initialize / @c initialized / @c shutdown / @c exit
 *   - @c textDocument/didOpen / didChange / didClose (sincronizacion full)
 *
 * En @c didOpen y @c didChange compila el documento via @c AnalysisEngine y
 * publica @c textDocument/publishDiagnostics con los diagnosticos del
 * compilador mapeados a rangos LSP.  El motor de analisis se disena
 * reutilizable para que fases posteriores (semantic tokens, hover con
 * Big-O, ver IR/bytecode/JIT/AOT, diagramas) cuelguen del mismo punto.
 */

#ifndef VESTA_LSP_SERVER_H
#define VESTA_LSP_SERVER_H

#include "json.hpp"

#include <atomic>

#include "lsp/analysis_engine.h"
#include "lsp/document_store.h"
#include "lsp/inspector.h"
#include "lsp/json_rpc.h"
#include "lsp/symbol_index.h"

namespace lsp {

/**
 * @class LspServer
 * @brief Bucle principal + dispatcher de metodos LSP.
 *
 * Procesa mensajes de forma secuencial sobre un @c JsonRpcTransport.  No
 * es thread-safe por diseno (un solo hilo de eventos).
 */
class LspServer {
  public:
    /**
     * @brief Construye el servidor sobre el transporte dado.
     * @param transport Transporte JSON-RPC (por defecto stdio).
     */
    explicit LspServer(JsonRpcTransport transport);

    /**
     * @brief Ejecuta el bucle de eventos hasta recibir @c exit o EOF.
     * @return Codigo de salida del proceso (0 si fin limpio).
     */
    int run();

  private:
    /**
     * @brief Despacha un mensaje entrante segun su metodo.
     * @param msg Mensaje JSON-RPC ya parseado.
     */
    void dispatch(const nlohmann::json &msg);

    /// --- Handlers de peticiones (responden con result) ---
    void handle_initialize(const nlohmann::json &msg);
    void handle_shutdown(const nlohmann::json &msg);

    /**
     * @brief Responde a @c textDocument/semanticTokens/full.
     *
     * Analiza (o reusa cache) el documento, calcula sus semantic tokens y
     * responde con @c { data: [...] } (array plano de quintetos).  Si el
     * documento no esta abierto, responde con @c data vacio.
     *
     * @param msg Mensaje completo (lleva @c id y @c params.textDocument.uri).
     */
    void handle_semantic_tokens_full(const nlohmann::json &msg);

    /**
     * @brief Despacha una peticion a medida @c vesta/* (inspector del
     *        ecosistema) y responde con su resultado.
     *
     * Cada metodo (bytecode/ir/complexity/diagram/functions/aotCompat/
     * jitAsm/aotAsm) se sirve BAJO DEMANDA: el editor lo llama cuando el
     * usuario pide ver esa fase.  Envuelve la llamada al @c Inspector en
     * try/catch: ante un fallo responde un error JSON-RPC limpio en lugar
     * de tumbar el servidor.
     *
     * @param method Nombre completo del metodo (e.g. "vesta/ir").
     * @param msg    Mensaje completo (lleva @c id y @c params).
     * @return true si @p method era una peticion @c vesta/* (manejada);
     *         false si no lo es (el caller sigue con el dispatch normal).
     */
    bool handle_vesta_request(const std::string &method,
                              const nlohmann::json &msg);

    /**
     * @brief Responde a @c textDocument/hover.
     *
     * Localiza el identificador bajo el cursor, lo resuelve a una definicion
     * (prioridad: definiciones del propio fichero -> workspace) y devuelve un
     * @c MarkupContent markdown con: el kind del simbolo, su firma/tipo
     * best-effort y, si es una funcion, su complejidad Big-O (de la
     * @c ModuleCost cacheada).  Devuelve @c null si no resuelve nada.
     *
     * @param msg Mensaje completo (lleva @c id y @c params.position).
     */
    /// @brief `textDocument/formatting`: da formato al documento entero.
    void handle_formatting(const nlohmann::json &msg);
    void handle_hover(const nlohmann::json &msg);

    /**
     * @brief Responde a @c textDocument/definition.
     *
     * Devuelve la(s) @c Location de la definicion del identificador bajo el
     * cursor (prioriza el propio fichero; si no, el workspace, incluyendo
     * librerias/modulos importados).  Devuelve @c null si no hay ninguna.
     *
     * @param msg Mensaje completo (lleva @c id y @c params.position).
     */
    void handle_definition(const nlohmann::json &msg);

    /**
     * @brief Responde a @c textDocument/references.
     *
     * Devuelve TODAS las referencias del identificador bajo el cursor en el
     * indice de workspace (todos los @c .vx, incluidas librerias).  Si
     * @c context.includeDeclaration es true, anyade tambien las definiciones.
     *
     * @param msg Mensaje completo (lleva @c id y @c params).
     */
    void handle_references(const nlohmann::json &msg);

    /**
     * @brief @c workspace/symbol: buscar un simbolo por su NOMBRE.
     *
     * "Ir a la definicion" necesita una posicion en un fichero, y hay sitios
     * donde se nombra una funcion sin tenerla delante: un informe, una vista
     * del compilador, un hecho del analisis.  Desde ahi, lo unico que se tiene
     * es el nombre, y esto es lo que lo convierte en un sitio al que ir.
     *
     * @param msg Peticion, con @c params.query.
     */
    void handle_workspace_symbol(const nlohmann::json &msg);

    /**
     * @brief Responde a @c textDocument/completion (Fase 5).
     *
     * Ofrece autocompletado pragmatico:
     *   - COMPLETADO DE MIEMBRO tras @c '.': si el receptor (el identificador
     *     antes del punto) es resoluble a un tipo clase/struct conocido (o es
     *     directamente el nombre de un tipo), lista sus METODOS y CAMPOS
     *     (tomados del indice por-documento, @c container == tipo).  Si el tipo
     *     no se resuelve, devuelve lista vacia para el caso miembro (no
     * inunda).
     *   - COMPLETADO GENERAL (sin @c '.'): une palabras clave de Vesta, tipos
     *     primitivos, builtins comunes y simbolos del documento/workspace,
     *     deduplicados por label y filtrados por el prefijo que se esta
     *     escribiendo bajo el cursor.
     *
     * Acota el numero de resultados y, ante cualquier fallo, responde una lista
     * vacia (nunca tumba el servidor).
     *
     * @param msg Mensaje completo (lleva @c id y @c params.position).
     */
    void handle_completion(const nlohmann::json &msg);

    /**
     * @brief Resuelve el identificador bajo el cursor de una peticion de
     *        navegacion.
     *
     * Compartido por hover/definition/references: extrae uri+position, abre
     * (o reusa) el indice por-documento, convierte la posicion a offset de
     * byte y devuelve la referencia que el cursor toca (o nullptr).
     *
     * @param params       params del mensaje (lleva textDocument.uri +
     * position).
     * @param out_uri       Salida: uri del documento.
     * @param out_word      Salida: nombre del identificador bajo el cursor.
     * @return true si se localizo un identificador; false si no (o documento
     *         no abierto / cursor sobre algo que no es identificador).
     */
    bool word_under_cursor(const nlohmann::json &params, std::string &out_uri,
                           std::string &out_word);

    /// --- Handlers de notificaciones (no responden) ---
    void handle_did_open(const nlohmann::json &params);
    void handle_did_change(const nlohmann::json &params);
    void handle_did_close(const nlohmann::json &params);

    /**
     * @brief Compila el documento y publica sus diagnosticos al cliente.
     * @param uri URI del documento abierto/modificado.
     */
    void publish_diagnostics(const std::string &uri);

    /**
     * @brief Lee del editor para que maquina hay que analizar.
     *
     * Acepta tanto @c {"vesta":{"inspect":{"os":...}}} -- la forma en que un
     * editor manda su configuracion -- como el objeto plano @c {"os":...}.
     * Lo que no venga se deja como esta.
     *
     * @param settings Objeto de configuracion recibido.
     */
    void apply_target_settings(const nlohmann::json &settings);

    /**
     * @brief Envia una respuesta de exito (result) a una peticion con id.
     * @param id     Identificador de la peticion (numero o string).
     * @param result Cuerpo del resultado.
     */
    void send_result(const nlohmann::json &id, const nlohmann::json &result);

    /**
     * @brief Atiende @c vesta/compile y @c vesta/compileProject.
     *
     * Compila el documento @p uri a @c .velb usando el compilador embebido
     * (@c vesta::tc::compile).  Si el documento esta abierto usa su buffer como
     * overlay; si no, lee del disco.  NO ejecuta el programa.
     * @param method @c "vesta/compile" (fichero) o @c "vesta/compileProject".
     * @param uri    URI del fichero raiz a compilar.
     * @param params Parametros de la peticion (output, mode, debug, ...).
     * @return JSON con @c {ok, output, diagnostics, frontend_us, message}.
     */
    nlohmann::json compile_request(const std::string &method,
                                   const std::string &uri,
                                   const nlohmann::json &params);

    JsonRpcTransport transport_; ///< Transporte de mensajes.
    DocumentStore docs_;         ///< Documentos abiertos.
    AnalysisEngine engine_;      ///< Motor de analisis reutilizable.
    Inspector inspector_{engine_,
                         docs_}; ///< Inspector del ecosistema (Fase 3).
    WorkspaceIndex workspace_;   ///< Indice de simbolos del workspace (Fase 4).
    /**
     * Nombres de las funciones que capturan el TEXTO de su argumento (`R110`),
     * sacados de todo el workspace.
     *
     * Se guardan porque no cambian de un guardado al siguiente y sacarlos
     * cuesta leer el proyecto entero: hacerlo en cada formateo convertiria una
     * operacion instantanea en una espera.  Vacio = aun no se han buscado.
     */
    std::vector<std::string> capture_names_;
    bool capture_names_listos_ = false;
    bool initialized_ = false; ///< true tras un initialize correcto.
    /**
     * @brief true en cuanto el editor PIDE @c shutdown (espera @c exit).
     *
     * Lo marca quien LEE la entrada, no quien contesta, y la diferencia
     * importa: decide el codigo de salida, y el `exit` puede llegar con el
     * `shutdown` todavia en la cola.  Mirando solo lo contestado, el servidor
     * salia con 1 -- "exit sin shutdown" -- cuando el editor si lo habia
     * pedido.  Lo que cuenta es que lo pidio.
     *
     * Atomico porque lo escribe el hilo lector y lo lee el que despacha.
     */
    std::atomic<bool> shutdown_requested_{false};
};

} // namespace lsp

#endif // VESTA_LSP_SERVER_H
