/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vxdbg_emit.cpp
 * @brief Traduce las tablas del checker de Vesta a simbolos.
 *
 * Aqui SOLO se dice que existe: los tipos del programa, sus miembros y como se
 * relacionan, nombrando a los demas por su clave.  Ordenarlos, resolver esas
 * claves a huellas y guardarlos es trabajo de @ref vxdbg::emit_semantic_graph,
 * que no sabe -- ni debe saber -- que es un `struct`.
 *
 * Esa separacion es lo que permite que el subsistema sirva a otro lenguaje: un
 * frontend de C o de Lisp escribe su propio traductor contra sus propias
 * tablas y reutiliza todo lo demas.  Si el emisor conociera `StructLayout`,
 * anadir un lenguaje obligaria a tocarlo.
 *
 * Las relaciones van de abajo a arriba: un metodo declara pertenecer a su clase
 * y la clase no lista sus metodos.  Al reves seria un ciclo -- la huella de la
 * clase dependeria de la del metodo y la del metodo de la de la clase -- y
 * ademas ya es la regla del subsistema: la relacion inversa es un indice, no un
 * dato.
 */

#include "util/env_flags.h"
#include "vx/vxdbg_emit.h"

#include "vx/ast.h"
#include "vx/type_checker.h"
#include "vxdbg/codec.h"
#include "vxdbg/pack_store.h"
#include "vxdbg/store.h"
#include "vxdbg/roots.h"
#include "vxdbg/semantic.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <unordered_set>

namespace vx {

namespace {

/**
 * @brief Como llama Vesta a algo, y de que especie es en terminos comunes.
 *
 * Tenerlos juntos evita que se separen: anadir un genero nuevo obliga a decir
 * en el mismo sitio a que especie pertenece, en vez de dejarlo para luego.
 */
struct KindPair {
    vxdbg::EntityKind kind;
    const char *lang; ///< el nombre que le da Vesta
};

/// @name Generos de Vesta
///
/// Uno por cada forma que Vesta distingue de verdad, no por cada palabra
/// clave: `@Abstract` o `@overlay` cambian lo que ES el tipo -- uno no se
/// puede instanciar, el otro no posee su memoria -- y quien lee un error tiene
/// que verlo.  Lo que solo cambia como se genera el codigo no llega aqui.
/// @{
constexpr KindPair K_STRUCT{vxdbg::EntityKind::Type, "struct"};
constexpr KindPair K_UNION{vxdbg::EntityKind::Type, "union"};
/// Vista tipada sobre memoria ajena: un valor de este tipo ES un puntero, no
/// aloca ni copia.  Confundirlo con un struct normal al explicar un fallo
/// llevaria a buscar el problema donde no esta.
constexpr KindPair K_OVERLAY{vxdbg::EntityKind::Type, "overlay"};
/// Solo sirve de base: no se instancia.
constexpr KindPair K_ABSTRACT_STRUCT{vxdbg::EntityKind::Type,
                                     "abstract struct"};
/// Tiene metodos virtuales, asi que lleva puntero a tabla y sus campos no
/// empiezan en cero.
constexpr KindPair K_POLY_STRUCT{vxdbg::EntityKind::Type, "polymorphic struct"};
constexpr KindPair K_CLASS{vxdbg::EntityKind::Type, "class"};
constexpr KindPair K_INTERFACE{vxdbg::EntityKind::Contract, "interface"};
/// Clase de aspecto: sus metodos se ejecutan alrededor de los de otras.
constexpr KindPair K_ASPECT{vxdbg::EntityKind::Type, "aspect"};
/// Predicado sobre tipos, comprobado al compilar.  Se cumple, no se instancia:
/// de ahi que sea un contrato y no un tipo.
constexpr KindPair K_CONCEPT{vxdbg::EntityKind::Contract, "concept"};
constexpr KindPair K_ENUM{vxdbg::EntityKind::Enumeration, "enum"};
/// Enum cuyos casos SON valores de otro tipo (`enum Color : u8`).
constexpr KindPair K_VALUED_ENUM{vxdbg::EntityKind::Enumeration, "valued enum"};
/// Lo que se escribe en el sitio y nadie declara: primitivos, punteros,
/// genericos instanciados sobre la marcha.
constexpr KindPair K_BUILTIN{vxdbg::EntityKind::Type, "type"};
constexpr KindPair K_FIELD{vxdbg::EntityKind::Field, "field"};
constexpr KindPair K_STATIC_FIELD{vxdbg::EntityKind::Field, "static field"};
/// Campo que solo existe mientras se compila: no ocupa nada en la instancia.
constexpr KindPair K_COMPTIME_FIELD{vxdbg::EntityKind::Field, "comptime field"};
constexpr KindPair K_METHOD{vxdbg::EntityKind::Function, "method"};
constexpr KindPair K_CONSTRUCTOR{vxdbg::EntityKind::Function, "constructor"};
constexpr KindPair K_DESTRUCTOR{vxdbg::EntityKind::Function, "destructor"};
constexpr KindPair K_VARIANT{vxdbg::EntityKind::Constant, "variant"};
constexpr KindPair K_NAMESPACE{vxdbg::EntityKind::Module, "namespace"};
/// Funcion libre: no pertenece a ningun tipo.
constexpr KindPair K_FUNCTION{vxdbg::EntityKind::Function, "function"};
/// @}

/**
 * @brief Recolecta los simbolos de un modulo Vesta.
 *
 * Lo unico que hace es LEER las tablas del checker y describir lo que hay.  No
 * guarda nada, no calcula huellas y no decide ordenes: asi se puede anadir un
 * genero de declaracion sin tocar nada de la parte que emite.
 */
class Collector {
  public:
    /**
     * @param tc Checker con las tablas.
     * @param file Fichero al que atribuir las declaraciones.
     */
    Collector(const TypeChecker &tc, vxdbg::FileId file)
        : tc_(tc), file_(file) {}

    /// @brief Recorre todo lo declarado.
    void collect();

    /// @return Los simbolos recolectados.
    std::vector<vxdbg::SemanticNode> take() { return std::move(out_); }

  private:
    /// @name Un recolector por genero de declaracion
    ///
    /// Cada uno sabe leer UNA tabla del checker.  Anadir un genero nuevo -- un
    /// alias, una global, un trait -- es anadir uno mas y llamarlo desde
    /// @ref collect, sin tocar los demas ni la parte que emite.
    /// @{
    void collect_structs();
    void collect_classes();
    void collect_enums();
    void collect_concepts();
    void collect_functions();
    /// @}

    /**
     * @brief Empieza un simbolo con lo comun a todos.
     * @param key Clave del compilador.
     * @param kp Genero.
     * @return El simbolo, aun sin relaciones.
     */
    vxdbg::SemanticNode begin(const std::string &key, const KindPair &kp);

    /**
     * @brief Anade una relacion por clave.
     * @param s Simbolo.
     * @param kind Genero de la relacion.
     * @param target Clave del destino; se ignora si esta vacia.
     */
    static void relate(vxdbg::SemanticNode &s, vxdbg::RelationKind kind,
                       const std::string &target);

    /**
     * @brief Declara la pertenencia a un espacio de nombres, si lo hay.
     * @param s Simbolo.
     * @param key Su clave.
     */
    void relate_namespace(vxdbg::SemanticNode &s, const std::string &key);

    /**
     * @brief Describe un miembro: campo, metodo o variante.
     * @param name Nombre.
     * @param kp Genero.
     * @param owner_key Clave de quien lo declara.
     * @param type_name Tipo al que se refiere, si tiene uno.
     */
    void add_member(const std::string &name, const KindPair &kp,
                    const std::string &owner_key, const std::string &type_name,
                    const std::string &signature = std::string());

    /**
     * @brief Asegura que existe el simbolo de un tipo escrito en el sitio.
     *
     * `i32`, `u8*`, `Array<i64>`: nadie los declara, pero un campo se refiere a
     * ellos y sin simbolo la relacion se perderia.  Salen con la misma huella
     * en todos los modulos que los usen, que es justo lo que se quiere.
     *
     * @param name Texto del tipo.
     */
    void ensure_builtin(const std::string &name);

    /// @brief Asegura que existe el simbolo de un espacio de nombres.
    /// @param path Camino.
    /// @return La clave con la que se le nombra.
    std::string ensure_namespace(const std::string &path);

    /**
     * @brief Nombre visible de una clave del compilador.
     *
     * Lo dice el checker, que es quien manglea: no se puede deducir partiendo
     * la clave por un separador, porque el separador es una convencion que
     * cambia -- hoy `lib__Caja`, manana otra cosa -- y quedaria un nombre roto
     * sin que nadie se enterara.
     *
     * @param key Clave.
     * @return El nombre a ensenar; la clave entera si nadie la registro.
     */
    const std::string &display_name(const std::string &key) const;

    /// @return @c true si la clave no se habia visto todavia.
    bool first_time(const std::string &key) { return seen_.insert(key).second; }

    const TypeChecker &tc_;
    vxdbg::FileId file_;
    std::vector<vxdbg::SemanticNode> out_;
    /// Claves ya descritas, para no repetir un tipo escrito en el sitio que
    /// aparezca en veinte campos.
    std::unordered_set<std::string> seen_;
};

const std::string &Collector::display_name(const std::string &key) const {
    const auto &decl = tc_.declared_ns_symbols();
    auto it = decl.find(key);
    // Lo que no se declaro dentro de un espacio de nombres no lleva prefijo:
    // su clave YA es su nombre.
    if (it == decl.end()) return key;
    return it->second.second;
}

vxdbg::SemanticNode Collector::begin(const std::string &key,
                                     const KindPair &kp) {
    vxdbg::SemanticNode s;
    s.key = key;
    s.name = display_name(key);
    s.kind = kp.kind;
    s.lang_kind = kp.lang;
    s.declared_at.file = file_;
    return s;
}

void Collector::relate(vxdbg::SemanticNode &s, vxdbg::RelationKind kind,
                       const std::string &target) {
    if (target.empty()) return;
    vxdbg::SemanticRelation r;
    r.kind = kind;
    r.target = target;
    s.relations.push_back(std::move(r));
}

std::string Collector::ensure_namespace(const std::string &path) {
    // La clave lleva delante de que es para que un espacio de nombres llamado
    // igual que un tipo no se confunda con el.
    std::string key = "namespace " + path;
    if (first_time(key)) {
        vxdbg::SemanticNode s;
        s.key = key;
        s.name = path;
        s.kind = K_NAMESPACE.kind;
        s.lang_kind = K_NAMESPACE.lang;
        out_.push_back(std::move(s));
    }
    return key;
}

void Collector::relate_namespace(vxdbg::SemanticNode &s,
                                 const std::string &key) {
    const auto &decl = tc_.declared_ns_symbols();
    auto it = decl.find(key);
    if (it == decl.end() || it->second.first.empty()) return;
    // La pertenencia se dice como relacion y no reconstruyendo el prefijo del
    // nombre, que es lo que la hace consultable.
    relate(s, vxdbg::RelationKind::DeclaredIn,
           ensure_namespace(it->second.first));
}

void Collector::ensure_builtin(const std::string &name) {
    if (name.empty() || !first_time(name)) return;
    vxdbg::SemanticNode s;
    s.key = name; // el texto del tipo ya es su identidad
    s.name = name;
    s.kind = K_BUILTIN.kind;
    s.lang_kind = K_BUILTIN.lang;
    // No se declara en ningun fichero, asi que no lleva posicion.
    out_.push_back(std::move(s));
}

void Collector::add_member(const std::string &name, const KindPair &kp,
                           const std::string &owner_key,
                           const std::string &type_name,
                           const std::string &signature) {
    vxdbg::SemanticNode s;
    // Un miembro se identifica por su propietario mas su nombre: dos campos
    // `size` de dos structs distintos no son el mismo campo.
    s.key = owner_key + "::" + name;
    s.name = name;
    s.kind = kp.kind;
    s.lang_kind = kp.lang;
    s.declared_at.file = file_;
    relate(s, vxdbg::RelationKind::DeclaredIn, owner_key);
    if (!type_name.empty()) {
        // Si el tipo no es uno declarado, se describe como escrito en el sitio;
        // la clave es la misma en ambos casos, asi que el emisor la resuelve
        // sin distinguirlos.
        if (tc_.struct_layouts().count(type_name) == 0 &&
            tc_.class_layouts().count(type_name) == 0 &&
            tc_.enum_layouts().count(type_name) == 0)
            ensure_builtin(type_name);
        relate(s, vxdbg::RelationKind::Uses, type_name);
    }
    if (!signature.empty()) {
        // La firma va como atributo y no como relaciones a cada tipo: lo que
        // hace falta al explicar un fallo es LEERLA de un tirón, y un metodo se
        // distingue de sus sobrecargas justo por ella.  Sin esto, una traza
        // dice `ctor_1` -- el nombre con el que se emitio -- que no se parece a
        // nada de lo que hay escrito en el fuente.
        vxdbg::Attribute a;
        a.name = "signature";
        a.kind = vxdbg::AttributeKind::String;
        a.text = signature;
        s.attributes.push_back(std::move(a));
    }
    out_.push_back(std::move(s));
}

/**
 * @brief Firma legible de un metodo, tal como se escribio.
 * @param m Metodo.
 * @return Algo como `(string) -> u128`.
 */
std::string signature_of(const ClassMethodInfo &m) {
    std::string out = "(";
    for (size_t i = 0; i < m.param_types.size(); ++i) {
        if (i) out += ", ";
        out += type_to_string(m.param_types[i]);
    }
    out += ")";
    const std::string ret = type_to_string(m.return_type);
    if (!ret.empty() && ret != "void") out += " -> " + ret;
    return out;
}

void Collector::collect_structs() {
    for (const auto &kv : tc_.struct_layouts()) {
        const StructLayout &lay = kv.second;
        // El orden importa: una vista sobre memoria ajena no es un struct
        // abstracto aunque lleve la marca, y no poder instanciarlo pesa mas
        // que tener metodos virtuales.
        const KindPair &kp = lay.is_overlay       ? K_OVERLAY
                             : lay.is_union       ? K_UNION
                             : lay.is_abstract    ? K_ABSTRACT_STRUCT
                             : lay.is_polymorphic ? K_POLY_STRUCT
                                                  : K_STRUCT;
        vxdbg::SemanticNode s = begin(kv.first, kp);
        s.byte_size = lay.size_bytes;
        s.alignment = lay.align_bytes;
        relate_namespace(s, kv.first);
        relate(s, vxdbg::RelationKind::Derives, lay.super_name);
        // Los conceptos que satisface los sabe el checker de cuando los
        // comprobo; se leen de ahi en lugar de reevaluar los predicados, que
        // seria pagar dos veces por la misma respuesta.
        if (auto it = tc_.impl_conformances().find(kv.first);
            it != tc_.impl_conformances().end())
            for (const auto &c : it->second)
                relate(s, vxdbg::RelationKind::Implements, c);
        out_.push_back(std::move(s));

        for (const auto &f : lay.fields)
            add_member(f.name, K_FIELD, kv.first, type_to_string(f.type));
        for (const auto &f : lay.static_fields)
            add_member(f.name, K_STATIC_FIELD, kv.first,
                       type_to_string(f.type));
        for (const auto &f : lay.comptime_fields)
            add_member(f.name, K_COMPTIME_FIELD, kv.first,
                       type_to_string(f.type));
        for (const auto &m : lay.methods)
            add_member(m.name, m.is_constructor ? K_CONSTRUCTOR : K_METHOD,
                       kv.first, type_to_string(m.return_type),
                       signature_of(m));
    }
}

void Collector::collect_classes() {
    for (const auto &kv : tc_.class_layouts()) {
        const ClassLayout &lay = kv.second;
        const KindPair &kp = lay.is_interface ? K_INTERFACE
                             : lay.is_aspect  ? K_ASPECT
                                              : K_CLASS;
        vxdbg::SemanticNode s = begin(kv.first, kp);
        s.byte_size = lay.size_bytes;
        relate_namespace(s, kv.first);
        relate(s, vxdbg::RelationKind::Derives, lay.super_name);
        for (const auto &iface : lay.interface_names)
            relate(s, vxdbg::RelationKind::Implements, iface);
        if (auto it = tc_.impl_conformances().find(kv.first);
            it != tc_.impl_conformances().end())
            for (const auto &c : it->second)
                relate(s, vxdbg::RelationKind::Implements, c);
        out_.push_back(std::move(s));

        for (const auto &f : lay.fields)
            add_member(f.name, K_FIELD, kv.first, type_to_string(f.type));
        for (const auto &f : lay.static_fields)
            add_member(f.name, K_STATIC_FIELD, kv.first,
                       type_to_string(f.type));
        for (const auto &m : lay.methods) {
            const KindPair &mk = m.is_constructor  ? K_CONSTRUCTOR
                                 : m.is_destructor ? K_DESTRUCTOR
                                                   : K_METHOD;
            add_member(m.name, mk, kv.first, type_to_string(m.return_type),
                       signature_of(m));
        }
    }
}

void Collector::collect_enums() {
    for (const auto &kv : tc_.enum_layouts()) {
        const EnumLayout &lay = kv.second;
        vxdbg::SemanticNode s =
            begin(kv.first, lay.is_valued ? K_VALUED_ENUM : K_ENUM);
        s.byte_size = lay.size_bytes;
        relate_namespace(s, kv.first);
        // Un enum con tipo base ES un valor de ese tipo: la relacion lo dice
        // sin que quien lea tenga que saber como se representa.
        if (!lay.backing_type_name.empty()) {
            if (tc_.struct_layouts().count(lay.backing_type_name) == 0 &&
                tc_.class_layouts().count(lay.backing_type_name) == 0)
                ensure_builtin(lay.backing_type_name);
            relate(s, vxdbg::RelationKind::Uses, lay.backing_type_name);
        }
        out_.push_back(std::move(s));

        for (const auto &v : lay.variants)
            add_member(v.name, K_VARIANT, kv.first, "");
    }
}

void Collector::collect_concepts() {
    for (const auto &kv : tc_.concepts()) {
        // Un concepto no tiene tamano ni instancias: es una condicion sobre
        // tipos que se comprueba al compilar.
        vxdbg::SemanticNode s = begin(kv.first, K_CONCEPT);
        relate_namespace(s, kv.first);
        out_.push_back(std::move(s));
    }
}

void Collector::collect_functions() {
    /* Las funciones libres tambien son declaraciones del programa.  Sin ellas,
     * un fallo dentro de una salia con el nombre a secas y sin fichero: el
     * grafo no sabia nada de ella y no habia de donde sacar ni la firma ni
     * donde estaba escrita. */
    for (const auto &d : tc_.ast_module().decls) {
        if (!d || d->kind != ast::NodeKind::FunctionDecl) continue;
        const auto *fd = static_cast<const ast::FunctionDecl *>(d.get());
        if (fd->name.empty()) continue;
        vxdbg::SemanticNode s = begin(fd->name, K_FUNCTION);
        s.declared_at.begin_line = fd->loc.line;
        s.declared_at.begin_column = static_cast<uint16_t>(fd->loc.column);
        relate_namespace(s, fd->name);
        out_.push_back(std::move(s));
    }
}

void Collector::collect() {
    collect_structs();
    collect_classes();
    collect_enums();
    collect_concepts();
    collect_functions();
}

/**
 * @brief Emite el nodo del fichero.
 * @param store Destino.
 * @param path Ruta del fuente.
 * @param content Su contenido, para resumirlo.
 * @return El identificador del fichero.
 */
vxdbg::FileId emit_file(vxdbg::NodeStore &store, const std::string &path,
                        const std::string &content) {
    vxdbg::FileNode f;
    f.path = path;
    f.language = "vesta";
    f.encoding = "utf-8";
    // El resumen del contenido es lo que permite luego detectar que el fuente
    // ya no es el que se compilo, y no ensenar la linea equivocada.
    /* Se resume el FICHERO DEL DISCO, que es lo que se ensena al explicar un
     * fallo.  Durante un tiempo se resumia el texto ya preprocesado porque sus
     * lineas no coincidian con las del fichero -- el preprocesador se comia
     * los comentarios de bloque sin reponer su sitio -- y asi al menos no se
     * ensenaba una linea equivocada.  Ya no hace falta: el preprocesador
     * mantiene la numeracion, de modo que resumir el fichero vuelve a decir lo
     * que debe (si cambio de verdad) en lugar de fallar siempre.
     *
     * Queda pendiente el codigo EXPANDIDO: cuando una macro genera lineas no
     * existe ninguna del fichero que ensenar, y para eso hace falta que cada
     * linea lleve su procedencia. */
    std::string del_disco;
    {
        std::ifstream fh(path, std::ios::binary);
        if (fh)
            del_disco.assign((std::istreambuf_iterator<char>(fh)),
                             std::istreambuf_iterator<char>());
    }
    const std::string &resumir = del_disco.empty() ? content : del_disco;
    if (!resumir.empty())
        f.checksum = vxdbg::hash_bytes(resumir.data(), resumir.size());
    vxdbg::ContentHash h;
    if (!vxdbg::store_node(store, f, h)) return {};
    return vxdbg::FileId{h};
}

/**
 * @brief Liga los simbolos que emitio el lowering con las entidades del grafo.
 *
 * Los pares (simbolo, declaracion) los anota el LOWERING al crear cada nombre;
 * aqui no se reconstruye ninguno.  Deducirlos desde fuera exigiria replicar el
 * mangling, y esa copia falla en silencio en cuanto cambie: un constructor de
 * clase es `Clase__ctor` y el de un struct `Struct__ctor_<aridad>`, formas que
 * no salen del nombre del metodo.
 *
 * @param links Lo que anoto el lowering.
 * @param ids Entidades emitidas, por clave.
 * @param stats Recibe cuantos simbolos se ligaron y cuantos no.
 * @return El mapa.
 */
vxdbg::ArtifactMap link_symbols(
    const std::vector<std::pair<std::string, std::string>> &links,
    const std::vector<std::pair<std::string, vxdbg::LanguageEntityId>> &ids,
    VxdbgEmitStats &stats) {
    std::unordered_map<std::string, vxdbg::LanguageEntityId> by_key;
    by_key.reserve(ids.size());
    for (const auto &kv : ids)
        by_key.emplace(kv.first, kv.second);

    vxdbg::ArtifactMap map;
    for (const auto &link : links) {
        auto it = by_key.find(link.second);
        if (it == by_key.end()) {
            // La declaracion no llego al grafo.  Se cuenta en vez de callarse:
            // que esto crezca de golpe significa que el grafo dejo de cubrir
            // algo que el compilador si emite.
            ++stats.unlinked;
            continue;
        }
        map.add(link.first, it->second);
        ++stats.linked;
    }
    return map;
}

} // namespace

bool publish_vxdbg_artifact(const std::string &artifact_path,
                            vxdbg::ContentHash map, vxdbg::ContentHash spans,
                            const std::string &out_dir,
                            const std::vector<uint8_t> *artifact_bytes) {
    if (map.empty()) return false;

    /* El identificador se calcula sobre el fichero entero.  Es lo mismo que
     * hara quien lo ejecute para preguntar por el, asi que tiene que salir de
     * los mismos bytes y de nada mas: ni la fecha, ni la ruta, ni quien lo
     * compilo.
     *
     * Pero si quien llama YA los tiene, se usan los suyos.  Al servir desde el
     * cache de proyecto los bytes vienen en memoria y el fichero se acaba de
     * escribir con ellos: releerlo del disco es leer dos veces lo mismo, y
     * medido costaba +87 ms en un proyecto de 6k lineas, mas que el acierto de
     * cache entero. */
    std::string bytes;
    if (artifact_bytes != nullptr) {
        if (artifact_bytes->empty()) return false;
    } else {
        std::FILE *f = std::fopen(artifact_path.c_str(), "rb");
        if (!f) return false;
        char buf[64 * 1024];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
            bytes.append(buf, n);
        std::fclose(f);
        if (bytes.empty()) return false;
    }
    const void *datos = artifact_bytes != nullptr
                            ? static_cast<const void *>(artifact_bytes->data())
                            : static_cast<const void *>(bytes.data());
    const size_t tam =
        artifact_bytes != nullptr ? artifact_bytes->size() : bytes.size();

    const std::string dir = out_dir.empty() ? default_vxdbg_dir() : out_dir;
    vxdbg::FileNodeStore store(dir);
    const vxdbg::CacheRootRepository repo(dir, store);
    const vxdbg::BuildId build{vxdbg::hash_bytes(datos, tam)};
    // La ruta va como pista para saber luego si este apuntador quedo
    // sobrescrito; la identidad sigue saliendo de los bytes de arriba.
    return repo.publish(build, map, spans, artifact_path);
}

std::string default_vxdbg_dir() {
    // La misma valvula que el resto de caches del compilador: si el proyecto
    // los redirige a un sitio comun, este va con ellos y no se queda suelto en
    // la carpeta de trabajo.
    {
        const std::string &v = util::flag_text(util::FlagId::CacheDir);
        if (!v.empty()) return v + "/vxdbg";
    }
    return ".cache/vxdbg";
}

bool emit_vxdbg_source(
    const TypeChecker &tc,
    const std::vector<std::pair<std::string, std::string>> &symbol_links,
    const std::vector<vxdbg::SourceExtent> &spans,
    const std::string &source_path, const std::string &source_text,
    const std::string &out_dir, VxdbgEmitStats &stats, std::string &err) {
    (void)err;
    /* EMPAQUETADO.  Esta emision escribe un nodo por entidad del programa --
     * medido, 2.030 para 2.004 lineas de fuente --, y con un fichero por nodo
     * el 90 % del tiempo de compilar en frio se iba en metadatos del sistema de
     * ficheros.  El almacen empaquetado acumula y publica UN fichero con UN
     * renombrado, reutilizando lo que ya existe.
     *
     * Envuelve al suelto en vez de sustituirlo: lo que ya hay en disco se sigue
     * leyendo igual, y `put` no reescribe lo que el suelto ya tenga.
     *
     * `VESTA_NO_PACK=1` vuelve al comportamiento anterior, para comparar. */
    const std::string dir = out_dir.empty() ? default_vxdbg_dir() : out_dir;
    std::unique_ptr<vxdbg::NodeStore> propietario;
    if (util::flag_on(util::FlagId::NoPack)) {
        propietario.reset(new vxdbg::FileNodeStore(dir));
    } else {
        propietario.reset(new vxdbg::PackNodeStore(
            dir,
            std::unique_ptr<vxdbg::NodeStore>(new vxdbg::FileNodeStore(dir))));
    }
    vxdbg::NodeStore &store = *propietario;

    Collector col(tc, emit_file(store, source_path, source_text));
    col.collect();
    const auto graph = col.take();

    const auto res = vxdbg::emit_semantic_graph(store, graph);
    stats.entities = res.emitted;
    stats.unresolved = res.unresolved;
    stats.duplicates = res.duplicates;
    stats.roots = res.ids;
    for (const auto &s : graph)
        if (s.kind == vxdbg::EntityKind::Field ||
            s.kind == vxdbg::EntityKind::Function ||
            s.kind == vxdbg::EntityKind::Constant)
            ++stats.members;

    // Sin simbolos el grafo queda emitido, pero sin la forma de entrar en el
    // desde una direccion de ejecucion.
    /* EL MAPA DEL MODULO: TODO lo que este modulo emitio, no solo lo que quedo
     * ligado a un simbolo del artefacto.
     *
     * La diferencia no es un matiz.  El mapa del artefacto liga los simbolos
     * EMITIDOS -- lo que tiene codigo --, mientras que la emision guarda ademas
     * los tipos y sus miembros.  Con un `hola mundo` eso eran 5 nodos
     * alcanzables de 29 guardados: el 80% del grafo no colgaba de ninguna raiz,
     * asi que nadie podia llegar a el y una recogida se lo llevaba por delante.
     *
     * `res.ids` es justo esa lista -- los tipos emitidos por su clave -- y
     * hasta ahora no la usaba nadie.  Guardandola como mapa del modulo, el
     * grafo entero queda sostenido por su propio modulo, y su huella viaja al
     * `.vxi` para que una compilacion que lo sirva desde cache lo cite sin
     * re-emitir nada.
     *
     * Se aprovecha el almacen que esta emision ya tiene abierto: con seis mil
     * modulos, abrir uno por modulo serian seis mil aperturas justo en el
     * camino que se quiere barato. */
    if (!res.ids.empty()) {
        vxdbg::ArtifactMap module_map;
        // Con `add` y no asignando la lista de golpe: el mapa se guarda
        // ORDENADO por simbolo a proposito, para que quien lo lea pueda buscar
        // sin construir nada, y saltarse eso al escribir dejaria un nodo que
        // miente sobre su propia forma.
        for (const auto &kv : res.ids)
            module_map.add(kv.first, kv.second);
        vxdbg::ContentHash mh;
        if (vxdbg::store_node(store, module_map, mh)) stats.module_map = mh;
    }

    if (!symbol_links.empty()) {
        vxdbg::ArtifactMap map = link_symbols(symbol_links, res.ids, stats);
        stats.symbol_links = map.symbols;
        /* El mapa del artefacto CITA al del modulo.  Sin esto solo sostiene lo
         * que quedo ligado a un simbolo emitido, y todo lo demas que se guardo
         * -- tipos, miembros -- se queda sin raiz: en un `hola mundo`, 5 nodos
         * de 29.  Hace falta en los dos caminos, el de fichero suelto y el de
         * proyecto, y este es el unico sitio comun a ambos. */
        if (!stats.module_map.empty()) map.modules.push_back(stats.module_map);
        vxdbg::ContentHash h;
        if (vxdbg::store_node(store, map, h)) stats.artifact_map = h;
    }
    // Los tramos de fuente: van en su propio nodo porque cambian con cualquier
    // reformateo mientras que los simbolos no, y compartir nodo obligaria a
    // reescribir los dos por mover una llave de sitio.
    if (!spans.empty()) {
        vxdbg::SpanMap sm;
        for (const auto &e : spans)
            sm.add(e);
        stats.spans = sm.extents;
        vxdbg::ContentHash hs;
        if (vxdbg::store_node(store, sm, hs)) stats.span_map = hs;
    }
    return true;
}

} // namespace vx
