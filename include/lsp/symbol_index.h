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
 * @file symbol_index.h
 * @brief Indice de simbolos para la navegacion del LSP de Vesta (Fase 4).
 *
 * Provee dos indices complementarios:
 *
 *  - @c DocSymbols: indice POR DOCUMENTO, barato.  De un fuente Vesta extrae,
 *    via un unico recorrido del lexer:
 *      (a) DEFINICIONES: por cada declaracion top-level/miembro reconocida en
 *          el flujo de tokens (funcion, clase, struct, enum, typedef/using,
 *          variable global, parametros, metodos, campos, variantes de enum)
 *          guarda { nombre, kind, rango del nombre }.
 *      (b) REFERENCIAS: por cada token @c IDENTIFIER del fichero guarda
 *          { nombre, rango }.  Es resolucion por NOMBRE (v1): suficiente para
 *          un LSP util sin necesidad del AST completo.
 *
 *  - @c WorkspaceIndex: indice de TODOS los @c .vx bajo la raiz del proyecto
 *    (recursivo y acotado) MAS los directorios de busqueda de modulos de Vesta
 *    que sean faciles de detectar.  Mapea @c nombre -> [definiciones] y
 *    @c nombre -> [referencias] con su fichero y rango.  Esto es lo que
 *    permite "buscar referencias en librerias": una referencia a un simbolo
 *    aparece aunque viva en un modulo importado.
 *
 * LIMITACION ACEPTADA v1 (documentada tambien en symbol_index.cpp): la
 * resolucion es por NOMBRE, no por scope/imports/sobrecarga.  Un nombre
 * repetido en varios sitios devolvera varias definiciones o referencias.  La
 * resolucion precisa (shadowing, imports, overloads) es un refinamiento
 * futuro; para v1 esto ya es un LSP serio y util.
 */

#ifndef VESTA_LSP_SYMBOL_INDEX_H
#define VESTA_LSP_SYMBOL_INDEX_H

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace lsp {

/**
 * @enum SymbolKind
 * @brief Categoria de un simbolo definido (para el hover y la presentacion).
 */
enum class SymbolKind : uint8_t {
    Unknown = 0,
    Function,    ///< funcion top-level o extern.
    Class,       ///< clase.
    Struct,      ///< struct value-type.
    Enum,        ///< enum (ADT).
    TypeAlias,   ///< typedef/using.
    Variable,    ///< variable global (top-level).
    Parameter,   ///< parametro de funcion/metodo.
    Method,      ///< metodo de clase/struct.
    Field,       ///< campo de clase/struct.
    EnumVariant, ///< variante de un enum.
    Concept,     ///< concepto (predicado comptime; bound o predicado).
};

/// @brief Nombre legible de un @c SymbolKind, en el idioma activo.
std::string symbol_kind_name(SymbolKind k);

/**
 * @struct SymbolDef
 * @brief Una definicion de simbolo localizada en el fuente.
 *
 * El rango se expresa en bytes (offset + longitud) sobre el texto del
 * fichero; el caller lo convierte a coordenadas LSP con
 * @c byte_offset_to_lsp_position cuando necesita responder.
 */
struct SymbolDef {
    std::string name;                      ///< Nombre del simbolo.
    SymbolKind kind = SymbolKind::Unknown; ///< Categoria.
    size_t byte_offset = 0; ///< Offset de byte del nombre (inicio).
    size_t byte_length = 0; ///< Longitud en bytes del nombre.
    /// Cualificador opcional para miembros (e.g. clase contenedora).  Vacio
    /// para simbolos top-level.  Informativo para el hover.
    std::string container;
    /// Firma legible best-effort (para funciones/metodos): "nombre(p1, p2)".
    /// Vacio si no aplica o no se pudo construir.
    std::string signature;
};

/**
 * @struct SymbolRef
 * @brief Una referencia (uso) de un identificador en el fuente.
 */
struct SymbolRef {
    std::string name;       ///< Nombre referenciado.
    size_t byte_offset = 0; ///< Offset de byte del identificador.
    size_t byte_length = 0; ///< Longitud en bytes.
};

/**
 * @struct DocSymbols
 * @brief Indice de simbolos de UN documento (definiciones + referencias).
 */
struct DocSymbols {
    std::vector<SymbolDef> defs; ///< Definiciones del fichero.
    std::vector<SymbolRef> refs; ///< Todas las referencias (identificadores).

    /**
     * @brief Devuelve la referencia cuyo span contiene @p byte_offset, o
     *        nullptr si el cursor no esta sobre ningun identificador.
     *
     * Como las referencias incluyen TODOS los identificadores (incluidos los
     * nombres de las definiciones, que tambien son identificadores), este
     * metodo basta para "identificador bajo el cursor".
     *
     * @param byte_offset Offset de byte del cursor en el documento.
     * @return Puntero a la referencia, o nullptr.
     */
    const SymbolRef *ref_at(size_t byte_offset) const;
};

/**
 * @brief Construye el indice de simbolos de un documento a partir de su
 *        fuente.
 *
 * Hace un unico recorrido del lexer de Vesta bajo try/catch: un fallo del
 * lexer devuelve el indice parcial acumulado en lugar de propagar.
 *
 * @param text     Texto fuente del documento.
 * @param filename Nombre logico (para el lexer; no se usa en el indice).
 * @return Indice con definiciones y referencias del fichero.
 */
DocSymbols build_doc_symbols(const std::string &text,
                             const std::string &filename);

/**
 * @struct WorkspaceLocation
 * @brief Localizacion de un simbolo en el workspace (fichero + rango LSP).
 *
 * El rango se guarda YA en coordenadas LSP (linea/caracter 0-based UTF-16)
 * para que responder una peticion no requiera reabrir/re-decodificar el
 * fichero.  El @c uri es la URI @c file:// del fichero.
 */
struct WorkspaceLocation {
    std::string uri; ///< URI file:// del fichero.
    uint32_t start_line = 0;
    uint32_t start_char = 0;
    uint32_t end_line = 0;
    uint32_t end_char = 0;
    SymbolKind kind = SymbolKind::Unknown; ///< Solo relevante en definiciones.
    std::string container;                 ///< Cualificador (miembros).
    std::string signature;                 ///< Firma (funciones/metodos).
};

/**
 * @class WorkspaceIndex
 * @brief Indice de simbolos de TODO el workspace (defs y refs por nombre).
 *
 * Se construye perezosamente la primera vez que se pide navegacion, recorre
 * recursivamente la raiz del proyecto (mas directorios de modulos faciles de
 * detectar) y registra las definiciones y referencias de cada @c .vx.  Para
 * los ficheros abiertos en el editor usa el TEXTO VIVO (no el de disco) y
 * permite refrescar SOLO ese fichero sin reindexar todo.
 *
 * Robusto y acotado: un cap de ficheros + saltar directorios de build/cache
 * evitan que el indexado cuelgue el servidor.  Un fichero que falle al
 * leerse/lexar se salta.
 *
 * La CONSTRUCCION si es segura entre hilos: el servidor reparte las consultas
 * entre un grupo, y `definition` y `references` la piden las dos.  Lo demas
 * sigue sin serlo -- las escrituras (`update_file`, `set_roots`) las hace el
 * hilo que atiende las mutaciones, en orden.
 *
 * El comentario que habia aqui decia lo contrario ("el servidor procesa
 * peticiones secuencialmente") y dejo de ser cierto al repartirlas: entonces
 * dos hilos entraban a construir, el segundo veia la marca ya puesta y
 * consultaba un indice a MEDIO construir.  No fallaba -- contestaba "no lo
 * encuentro" --, que es indistinguible de que el simbolo no exista.
 */
class WorkspaceIndex {
  public:
    /**
     * @brief Fija las raices del workspace (de @c rootUri / @c
     *        workspaceFolders del @c initialize) y marca el indice como no
     *        construido todavia (construccion perezosa).
     *
     * @param roots Rutas de sistema de ficheros de las raices.
     */
    void set_roots(const std::vector<std::string> &roots);

    /**
     * @brief Asegura que el indice de disco esta construido (idempotente).
     *
     * La primera invocacion recorre las raices e indexa todos los @c .vx
     * encontrados.  Invocaciones posteriores no hacen nada (salvo que se
     * llame @c invalidate_all).
     */
    void ensure_built();

    /**
     * @brief Re-indexa un unico fichero con un texto dado (el del editor),
     *        sustituyendo sus entradas anteriores.
     *
     * Usado en didOpen/didChange/didSave: el documento abierto usa su texto
     * vivo, no el de disco.  Si el indice global aun no se construyo, esta
     * llamada NO lo fuerza (se hara perezosamente en la primera navegacion).
     *
     * @param uri  URI file:// del documento.
     * @param text Texto vivo del documento.
     */
    void update_file(const std::string &uri, const std::string &text);

    /**
     * @brief Quita del indice todas las entradas de un fichero (al cerrarlo
     *        sin guardar, su version de disco se re-indexara en la siguiente
     *        construccion; aqui solo se elimina su contribucion vigente).
     *
     * @param uri URI file:// del documento.
     */
    void remove_file(const std::string &uri);

    /**
     * @brief Devuelve las definiciones registradas para un nombre.
     * @param name Nombre del simbolo.
     * @return Vector de localizaciones (vacio si no hay).
     */
    std::vector<WorkspaceLocation> defs_for(const std::string &name) const;

    /**
     * @brief Devuelve las referencias registradas para un nombre.
     * @param name Nombre del simbolo.
     * @return Vector de localizaciones (vacio si no hay).
     */
    std::vector<WorkspaceLocation> refs_for(const std::string &name) const;

    /**
     * @brief Recorre cada nombre definido en el workspace junto con el kind y
     *        la firma de su primera definicion.
     *
     * Pensado para el autocompletado: permite ofrecer los simbolos de otros
     * ficheros/librerias filtrando por prefijo en el caller, sin exponer la
     * estructura interna del indice.  El callback recibe (nombre, kind, firma).
     *
     * @param fn Callback invocado una vez por nombre definido.
     */
    void
    for_each_def_name(const std::function<void(const std::string &, SymbolKind,
                                               const std::string &)> &fn) const;

    /// @brief true si las raices estan fijadas (hay donde indexar).
    bool has_roots() const { return !roots_.empty(); }
    /// @brief Raices del workspace, para quien necesite recorrerlas.
    const std::vector<std::string> &roots() const noexcept { return roots_; }

  private:
    /// Indexa un fichero concreto (lee de disco) y registra sus entradas.
    void index_path(const std::string &fs_path);
    /// Indexa el contenido @p text atribuido a @p uri (texto vivo o de disco).
    void index_content(const std::string &uri, const std::string &fs_path,
                       const std::string &text);
    /// Elimina del indice todas las entradas asociadas a @p uri.
    void erase_uri_entries(const std::string &uri);

    std::vector<std::string> roots_; ///< Raices del workspace (fs paths).
    bool built_ = false; ///< true tras la primera construccion.
    /**
     * @brief Protege la construccion del indice, que ahora piden VARIOS hilos.
     *
     * `definition` y `references` lo necesitan los dos, y el servidor reparte
     * las consultas entre un grupo de hilos: sin esto, el segundo veia la
     * marca ya puesta -- se ponia ANTES de construir, para que un fallo no
     * reintentara en bucle -- y consultaba un indice a MEDIO construir.  No
     * fallaba: devolvia "no lo encuentro", que es indistinguible de que el
     * simbolo no exista.
     */
    mutable std::mutex build_mutex_;

    /// nombre -> definiciones (de todos los ficheros indexados).
    std::unordered_map<std::string, std::vector<WorkspaceLocation>> defs_;
    /// nombre -> referencias (de todos los ficheros indexados).
    std::unordered_map<std::string, std::vector<WorkspaceLocation>> refs_;
};

// ---------------------------------------------------------------------------
// Helpers de URI <-> ruta de sistema de ficheros.
// ---------------------------------------------------------------------------

/**
 * @brief Convierte una URI @c file:// a una ruta de sistema de ficheros.
 *
 * Decodifica el percent-encoding (%20, etc.) y, en Windows, elimina la barra
 * inicial sobrante de @c file:///C:/... dejando @c C:/....  Si @p uri no
 * empieza por @c file:// se devuelve tal cual (best-effort).
 *
 * @param uri URI del documento.
 * @return Ruta de sistema de ficheros.
 */
std::string uri_to_fs_path(const std::string &uri);

/**
 * @brief Convierte una ruta de sistema de ficheros a una URI @c file://.
 *
 * Normaliza las barras invertidas a barras y aplica percent-encoding minimo.
 *
 * @param fs_path Ruta de sistema de ficheros.
 * @return URI @c file://.
 */
std::string fs_path_to_uri(const std::string &fs_path);

/**
 * @brief Los directorios donde buscar los imports de @p fs_path.
 *
 * Un fichero que no es la raiz del proyecto importa relativo a esa raiz, asi
 * que hay que ofrecer los directorios de encima como sitios donde mirar.  Pero
 * SOLO hasta la raiz del paquete: el primer ancestro con manifiesto
 * (@c vx.toml / @c vx.json) es donde el paquete empieza, y por encima ya se
 * esta fuera.
 *
 * Subir mas alla tiene una consecuencia que no se ve venir: esos directorios
 * CONTIENEN al paquete, asi que ofrecen sus mismos namespaces con otra
 * identidad -- una sin manifiesto --, y el resolutor se encuentra el mismo
 * namespace en dos sitios y avisa de que hay dos librerias en disputa.  Es lo
 * que dejaba sin analizar a cualquier fichero de la biblioteca estandar abierto
 * en el editor: 607 diagnosticos y ningun IR, luego ni disposicion de tipos, ni
 * coste, ni nada de lo que se calcula compilando.
 *
 * Si no hay manifiesto en ninguna parte -- un ejemplo suelto -- se sube hasta
 * la raiz, que es lo que se hacia siempre.
 *
 * @param fs_path Fichero que se esta analizando.
 * @return Directorios, del mas cercano al mas lejano.
 */
std::vector<std::string> import_search_roots(const std::string &fs_path);

} // namespace lsp

#endif // VESTA_LSP_SYMBOL_INDEX_H
