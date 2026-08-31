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
 * @file parser.h
 * @brief Parser recursivo descendente para el lenguaje Vesta.
 *
 * Estrategia:
 *  - Declaraciones, statements y tipos: descenso recursivo clasico.
 *  - Expresiones: cascada de niveles de precedencia (estilo C),
 *    cada nivel implementado como funcion propia.  Esto evita el
 *    coste de hashing/dispatch de un esquema Pratt generico y produce
 *    un binario mas predecible para el branch predictor.
 *  - Errores: sin excepciones.  Los errores se acumulan en Diagnostics
 *    y el parser intenta sincronizar al siguiente ";" o "}" para
 *    seguir reportando.
 *
 * Reglas de precedencia (de menor a mayor):
 *   1.  asignacion         = += -= *= /= %= &= |= ^= <<= >>=  (derecha-asoc)
 *   2.  or logico          ||
 *   3.  and logico         &&
 *   4.  or bit             |
 *   5.  xor bit            ^
 *   6.  and bit            &
 *   7.  igualdad           == !=
 *   8.  relacional         < <= > >=
 *   9.  shift              << >>
 *   10. aditivo            + -
 *   11. multiplicativo     * / %
 *   12. unario prefijo     ! ~ - + ++ --
 *   13. postfijo           ()  ++  --  []  .  ?.  ?.[ ]  ?
 *   14. primaria           literales, identificadores, ( expr )
 */

#ifndef VX_PARSER_H
#define VX_PARSER_H

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "vx/ast.h"
#include "vx/diagnostic.h"
#include "vx/lexer.h"

namespace vx {

/// Fija el TARGET (os, arch) contra el que @c @Target evalua sus atomos
/// `os:`/`arch:` en compilacion AOT cross-target (el binario puede generarse
/// para un os/arch distinto del host de build).  Llamar ANTES de compilar.
/// Strings vacios => usar el host de build (comportamiento normal).
/// os: "windows"/"linux"/"macos".  arch: "x86_64"/"x86"/"arm64".
void set_aot_condcomp_target(const std::string &os,
                             const std::string &arch) noexcept;

/// Lee el override actual del target de @Target (el thread_local).  Usado por
/// el compile paralelo (M8) para propagar el target a los workers, que de otro
/// modo parsearian las variantes @Target contra el host (HALLAZGO-2).
void get_aot_condcomp_target(std::string &os, std::string &arch) noexcept;

/// Fija el CAMINO DE COMPILACION activo ("aot" al generar codigo nativo, vacio
/// en la ruta de bytecode).  Es contra esto que se evalua `@Target("mode:aot")`
/// y `@Target("mode:bytecode")`.
///
/// Este eje separa AOT de bytecode, que son compilaciones distintas.  NO
/// separa interprete de JIT: los dos ejecutan el mismo .velb y lo decide un
/// flag de ejecucion, asi que no es una propiedad del codigo emitido.
void set_aot_condcomp_mode(const std::string &mode) noexcept;
/// Lee el camino de compilacion activo (para propagarlo a los workers del
/// compile paralelo, igual que os/arch).
void get_aot_condcomp_mode(std::string &mode) noexcept;

/// Fija el TIER del binario nativo, contra el que se evalua `@Target("tier:")`.
///
/// Son los tres del proyecto (@c aot::Tier) -- los mismos nombres que toma
/// `--target` -- y dicen QUE hay debajo del binario:
///   - `full`  el runtime completo (libvesta_rt): planificador, async,
///             distribucion, reflexion.
///   - `embed` NINGUN runtime: solo la stdlib escrita en Vesta que el propio
///             AOT fusiona en el objeto (cadenas, excepciones, monitores,
///             I/O, reserva de memoria).
///   - `bare`  solo codigo nativo.  Nucleos, drivers, empotrados.
///
/// El GC no entra en esta escala: en nativo es SIEMPRE opcional y se pide
/// enlazando su libreria, en cualquiera de los tres.  Lo de serie es RAII y el
/// ownership del lenguaje.
///
/// `sin_libc` es OTRA cosa y por eso va aparte, aunque se pregunte con la misma
/// clave: es `--freestanding`, y lo que dice es que reservar memoria y el
/// panico pasan a exigir ganchos del usuario (@c \@AllocatorOverride,
/// @c \@PanicHandler) en vez de resolverse solos.  Se consulta como
/// `tier:sin_libc`.
///
/// Vacio => ruta de bytecode; ahi ningun `tier:` vale, porque no hay binario.
void set_aot_condcomp_tier(const std::string &tier, bool sin_libc) noexcept;
/// Lee el tier activo (para propagarlo a los workers del compile paralelo,
/// igual que os/arch/mode).
void get_aot_condcomp_tier(std::string &tier, bool &sin_libc) noexcept;

/// Evalua una expresion de @c @Target (os/arch/cpu/mode/compiler/vm con
/// &&/||/! y parentesis) contra el target activo.
///
/// Expuesta porque el `when:` de un contrato usa la MISMA gramatica, y el que
/// habla del parametro de tipo lo resuelve el type checker al monomorphizar
/// (donde T es concreto), no el parser.  Una expresion mixta
/// (`arch:x86_64 && is_float<T>()`) se evalua alli, apoyandose en esta para sus
/// atomos de target -- un solo evaluador de target para todo el compilador.
bool target_expr_matches(const std::string &spec) noexcept;

/**
 * @class Parser
 * @brief Construye un AST a partir de los tokens producidos por @c Lexer.
 *
 * Es de un solo uso: una instancia produce un AST llamando a
 * @c parse_program() y luego se descarta.  Mantiene internamente el
 * token actual y acceso al lexer para producir el siguiente.
 */
class Parser {
  public:
    /**
     * @brief Construye el parser sobre un lexer y un sumidero de diagnosticos.
     *
     * @param lex   Lexer del que se consumen tokens.  Debe sobrevivir al
     * parser.
     * @param diags Sumidero de errores.  Debe sobrevivir al parser.
     */
    Parser(Lexer &lex, Diagnostics &diags);

    /**
     * @brief  M.L8: registra un alias de tipo conocido (typedef
     * importado de otro modulo via @c .vxi) ANTES de parsear.  El
     * @c looks_like_cast lo usa para reconocer @c (Name)expr como un
     * cast.  Idempotente: insertar el mismo nombre dos veces es no-op.
     */
    void add_known_alias(const std::string &name) {
        declared_aliases_.insert(name);
    }

    /**
     * @brief Declara un tipo cuyo constructor recibe la expresion sin evaluar.
     *
     * Al ver `T(algo)`, el parser captura el TEXTO de lo que se escribio en
     * lugar de interpretarlo, pero solo si sabe que `T` tiene un constructor
     * de parametro `expr`.  Cuando el tipo se declara en el mismo fichero lo
     * averigua al parsearlo; cuando viene de otro modulo no, porque el
     * parseo ocurre antes de importar nada -- y entonces un numero mas ancho
     * que la palabra se truncaba antes de que nadie pudiera usarlo.
     *
     * El pipeline compila los modulos de los que se depende ANTES, asi que
     * ese dato ya se conoce y basta con darselo aqui.
     *
     * @param name Nombre del tipo.
     * @param positions Indices de los parametros declarados `expr`.
     */
    void add_expr_ctor_type(const std::string &name,
                            std::vector<int> positions) {
        macro_expr_params_[name] = std::move(positions);
    }

    /**
     * @brief Siembra las posiciones de params @c expr de funciones IMPORTADAS
     * de otros modulos, ANTES de parsear.
     *
     * Cross-module expr-capture: el raw-text slicing de un arg @c expr es una
     * decision de PARSEO (el arg puede no ser una expresion valida, p.ej. un
     * bloque @c asm).  Para una fn importada (`source(expr code)` de otro
     * modulo) el parser no conoceria su firma a tiempo.  El @c ModuleGraph
     * resuelve los imports ANTES de parsear el cuerpo (reusando el AST ya
     * parseado del dep -- sin re-parseo) y siembra aqui `nombre -> posiciones`.
     * No sobreescribe las fns declaradas en ESTE fichero (esas se registran
     * durante el parseo).  Idempotente.
     */
    void seed_imported_expr_params(
        const std::unordered_map<std::string, std::vector<int>> &m) {
        for (const auto &kv : m)
            macro_expr_params_.emplace(kv.first, kv.second);
    }

    /**
     * @brief Parsea el programa completo desde el cursor actual del lexer.
     *
     * @return Un ModuleNode con todas las declaraciones top-level encontradas.
     *         Aun en caso de errores, devuelve un AST parcial; el caller debe
     *         consultar @c Diagnostics::has_errors() antes de bajar a IR.
     */
    std::unique_ptr<ast::ModuleNode> parse_program();

    /**
     * @brief parsea UNA expresion sobre el lexer actual.
     *
     * Util para macros estilo Lisp (`comptime_compile(str)`) que
     * construyen codigo a partir de un string en compile-time.  El
     * caller crea un Lexer sobre la cadena, instancia un Parser y
     * llama a este metodo.  Tras el parse el lexer queda en el token
     * que no consumio (tipicamente END_OF_FILE).  Si hay error
     * sintactico, se reporta via @c Diagnostics y devuelve nullptr.
     */
    std::unique_ptr<ast::Expr> parse_one_expr() { return parse_expr(); }

  private:
    // -----------------------------------------------------------------
    // Helpers de gestion de tokens.
    // -----------------------------------------------------------------

    /**
     * @brief Avanza al siguiente token y devuelve el consumido.
     */
    Token consume();

    /**
     * @brief Devuelve el token actual sin consumirlo.
     */
    const Token &peek() const noexcept { return current_; }

    /**
     * @brief @c true si el token actual es del tipo @p k.
     */
    [[nodiscard]] bool check(TokenKind k) const noexcept {
        return current_.kind == k;
    }

    /**
     * @brief Si el token actual es @p k, lo consume y devuelve true.
     */
    bool match(TokenKind k);

    /**
     * @brief Exige un token de tipo @p k.  Si no coincide, emite error y
     * devuelve false.
     *
     * El parser no aborta; intenta seguir parseando para detectar mas errores.
     *
     * @param k   Token esperado.
     * @param msg Mensaje a emitir cuando no coincide.
     * @return    Token consumido si coincidio, o un Token UNKNOWN si no.
     */
    Token expect(TokenKind k, const char *msg);

    /**
     * @brief Cierra un grupo de argumentos de tipo `<...>`.
     *
     * Acepta tanto un solo `>` (token GT) como el primer `>` de un
     * `>>` (token SHR), que se "parte" en dos: consume la mitad
     * izquierda y deja la derecha como nuevo current_ (kind=GT).
     * Esto permite tipos genericos anidados como
     * `VirtualPtr<VirtualPtr<i64>>` sin requerir espacios entre los
     * dos cierres (`> >`).
     */
    Token expect_close_angle(const char *msg);

    /**
     * @brief Avanza tokens hasta hallar un punto de sincronizacion.
     *
     * Sincronizadores: ';', '}', EOF, y el inicio de cualquier
     * keyword de declaracion top-level.  Usado tras un error para
     * limitar la cascada de mensajes.
     */
    void synchronize();

    /**
     * @brief Reporta un error en la posicion del token actual.
     */
    void error_here(const char *msg);

    /**
     * @brief Reporta un error en la posicion de un token dado.
     */
    void error_at(const Token &tok, const char *msg);

    /**
     * @brief True si @p k puede usarse como NOMBRE (de funcion, variable,
     *        parametro, campo, metodo, alias...).
     *
     * Es IDENTIFIER, o uno de los keywords CONTEXTUALES del lenguaje.
     * `get` y `set` solo son palabras clave dentro del cuerpo de una
     * clase y unicamente en la forma de property (`get n => e;` /
     * `set n(T v) {...}`); en cualquier otra posicion son nombres
     * corrientes (`HashMap.get`, `V get(K k)`, `u64 get(i64 x)`).
     */
    static bool is_name_token(TokenKind k) noexcept;

    /**
     * @brief Reporta "se esperaba un nombre" con un mensaje ESPECIFICO
     *        cuando el token actual es una palabra reservada.
     *
     * Sin esto el usuario recibia un generico ("se esperaba un nombre
     * tras el tipo") que no decia el motivo real ni apuntaba al termino
     * culpable, y ademas arrastraba una cascada de errores derivados.
     *
     * @param what        Que se esperaba, para el mensaje especifico
     *                    (p.ej. "nombre de funcion o variable global").
     * @param generic_msg Mensaje a emitir si el token NO es una palabra
     *                    reservada (se preserva el texto historico de
     *                    cada sitio para no cambiar diagnosticos ajenos).
     */
    void error_expected_name(const char *what, const char *generic_msg);

    // -----------------------------------------------------------------
    // Reglas gramaticales: top-level y declaraciones.
    // -----------------------------------------------------------------

    std::unique_ptr<ast::Node> parse_top_level_decl();

    /**
     * @brief parsea @c extern @c "lib.dll" @c { @c fn @c name(params) @c -> @c
     * R; @c ... @c }
     *
     * El bloque produce N decls (uno por funcion); el parser los empuja
     * directamente al modulo via @p mod.  Cada @c ExternFnDecl comparte
     * el campo @c lib del bloque.  Sin parseo de nombre de parametro
     * obligatorio: si no hay identificador tras el tipo, sintetiza
     * @c "__arg<i>" para que el resto del frontend pueda referirlo.
     * El tipo de retorno usa @c PrimitiveKind::VOID si no hay @c "->".
     */
    void parse_extern_block(ast::ModuleNode &mod);
    std::unique_ptr<ast::FunctionDecl>
    parse_function_decl(std::unique_ptr<ast::TypeNode> ret_type,
                        std::string name, SourceLoc loc);
    std::unique_ptr<ast::GlobalVarDecl>
    parse_global_var_decl(std::unique_ptr<ast::TypeNode> type, std::string name,
                          SourceLoc loc, bool is_const);
    std::unique_ptr<ast::ParamDecl> parse_param();

    /**
     * @brief Lee la lista de parametros que va entre parentesis, hasta el
     *        cierre (que NO consume).
     *
     * Lo que hay entre esos parentesis no depende de si lo que se declara es
     * una funcion suelta, un metodo o un constructor: es la MISMA gramatica.  Y
     * no lo era: el cuerpo de este bucle estaba copiado cinco veces para los
     * metodos, identico byte a byte, y era una version pobre que solo aceptaba
     * `tipo nombre`.  Un metodo no podia declarar un variadico `T... xs`, ni un
     * parametro no-nulo `T !!x`, ni un puntero a funcion al estilo de C -- todo
     * eso si valia en una funcion suelta --, y no por ninguna razon: por que la
     * copia no lo sabia leer.
     *
     * @param out  Donde dejar los parametros leidos.
     * @param what Como nombrar lo que se declara en los mensajes de error.
     */
    void parse_param_list(std::vector<std::unique_ptr<ast::ParamDecl>> &out,
                          const char *what);
    std::unique_ptr<ast::TypeAliasDecl> parse_typedef_decl();
    std::unique_ptr<ast::TypeAliasDecl> parse_using_decl();
    /// @brief Parsea @c import "path" [as alias] [only A, B];
    /// @param is_public_reexport @c true si vino precedido de @c public.
    std::unique_ptr<ast::ImportDecl> parse_import_decl(bool is_public_reexport);
    /// @brief Parsea @c "namespace foo { decls }" ( M.7.c).
    std::unique_ptr<ast::NamespaceDecl> parse_namespace_decl();
    /// #cross-module-generics: captura el texto fuente de una
    /// plantilla/concepto (top-level o dentro de un namespace) en @c
    /// generic_template_exports.
    void collect_template_export_(ast::ModuleNode *mod, ast::Node *decl,
                                  uint32_t decl_start_off);
    /// Modulo actual en curso (para que parse_namespace_decl exporte las
    /// plantillas/concepts de sus decls anidadas).  Set por parse_program.
    ast::ModuleNode *tpl_export_mod_ = nullptr;
    /// @c bytes name { db/dw/dd/dq/times ... }  (datos crudos NASM, AOT).
    std::unique_ptr<ast::BytesDecl> parse_bytes_decl();
    /// @c asm name { <nasm 16/32/64> }  (codigo ensamblado por Keystone, AOT).
    std::unique_ptr<ast::BytesDecl> parse_asm_block_decl();
    std::unique_ptr<ast::StructDecl> parse_struct_decl(bool is_overlay = false);
    /// `typedef struct {...} Name;` o
    /// `typedef enum {...} Name;`.  Devuelve StructDecl o EnumDecl.
    std::unique_ptr<ast::Node>
    parse_typedef_struct_or_enum(bool leading_typedef = true);
    std::unique_ptr<ast::ClassDecl> parse_class_decl();
    std::unique_ptr<ast::ClassDecl> parse_interface_decl();

    /**
     * @briefparsea @c enum @c Name { @c Variant, @c Variant(T1, T2), ... }
     *
     * El parser reconoce las dos formas de variante:
     *   - Sin payload: solo el identificador de la variante.
     *   - Con payload: identificador seguido de @c (T1, T2, ...).
     * Las variantes se separan por coma; el bloque puede tener una
     * coma trailing opcional.  No se admite valor por defecto ni
     * herencia (los enums son tipos de datos algebraicos planos).
     */
    std::unique_ptr<ast::EnumDecl> parse_enum_decl();

    /**
     * @brief parsea @c match @c expr @c { @c case ... }
     *
     * Sintaxis aceptada:
     *   match expr {
     *       case Variant            => stmt;
     *       case Variant(b1, b2)    => { stmts; }
     *       case _                  => default_stmt;   // catchall opcional
     *   }
     * El cuerpo de cada arm puede ser una expression-bodied
     * (`=> expr;`) que se reescribe a `{ return expr; }` o un bloque
     * (`=> { ... }`).  Cada arm termina en @c ;
     */
    std::unique_ptr<ast::Expr> parse_match_expr();
    std::unique_ptr<ast::BlockStmt> parse_method_body(bool is_void);

    /// @brief Parsea `<U1, U2, ...>` de type-params de un metodo generico.
    ///
    /// Precondicion: @c current_ es @c LT.  Consume hasta el `>` de cierre
    /// y rellena @p out con los nombres de los parametros de tipo.  Se usa
    /// en las declaraciones de metodo (`R metodo<U>(...)`).  Para metodos
    /// NO genericos, el llamante no invoca este helper (no hay `<`).
    void parse_method_type_params(std::vector<std::string> &out);

    /// @brief Parsea `<T, U: C, V: A + B>`: type-params con constraints (#6).
    ///
    /// Precondicion: @c current_ es @c LT.  Rellena @p params con los
    /// nombres y @p bounds con los constraints inline (`T: C`).  Equivale a
    /// @c parse_method_type_params pero ademas captura los bounds `: ...`.
    void parse_type_params_with_bounds(std::vector<std::string> &params,
                                       std::vector<ast::TypeBound> &bounds);

    /// @brief Parsea una clausula `where T: A + B, U: C` (#6).
    ///
    /// Precondicion: @c current_ es el identificador contextual @c where.
    /// anyade los bounds a @p bounds (acumula con los inline si los hubo).
    void parse_where_clause(std::vector<ast::TypeBound> &bounds);

    /// @brief Parsea el patron `<i64>` / `<T*>` de una especializacion (#7).
    ///
    /// Precondicion: @c current_ es '<'.  Rellena @p pattern con los
    /// type-nodes del patron y @p fresh_params con los identificadores que
    /// aparecen DENTRO de un patron compuesto (`T*`, `T[]`) -> son los params
    /// frescos de una especializacion PARCIAL.  Un identificador desnudo
    /// (`Punto`) o un primitivo (`i64`) es CONCRETO (especializacion TOTAL).
    void parse_specialization_pattern(
        std::vector<std::unique_ptr<ast::TypeNode>> &pattern,
        std::vector<std::string> &fresh_params);

    /// #7: nombres de struct/clase/funcion genericos ya vistos como template
    /// PRIMARIO.  La PRIMERA decl `Caja<...>` es el primario; las siguientes
    /// con el mismo nombre son especializaciones (total/parcial).
    std::unordered_set<std::string> generic_struct_names_seen_;
    std::unordered_set<std::string> generic_class_names_seen_;
    std::unordered_set<std::string> generic_fn_names_seen_;

    /// @brief Parsea una declaracion de concepto (#6).  Tres formas:
    ///   - `concept N<T> = <bool-expr>;`        (predicado)
    ///   - `concept N<T> { <comptime stmts> }`  (bloque estilo comptime)
    ///   - `concept N { <metodo-sigs> }`        (estructural -> has_method)
    /// Precondicion: @c current_ es el identificador contextual @c concept.
    std::unique_ptr<ast::ConceptDecl> parse_concept_decl();

    /// @brief NS.6-ext: @c "extension Tipo { metodos }".
    std::unique_ptr<ast::ExtensionDecl> parse_extension_decl();
    /// @brief NS.6-ext: @c "impl Concept for Tipo { metodos }".
    std::unique_ptr<ast::ImplDecl> parse_impl_decl();
    /// @brief NS.6-ext: parsea UN metodo de instancia (return name(params)
    /// body) para el cuerpo de una extension/impl.  @p target_tparams son los
    /// type params del tipo destino (para reconocer casts).  nullptr si error.
    std::unique_ptr<ast::ClassMethodDecl>
    parse_extension_method(uint8_t access);

    /// @brief Registra @p names como type-aliases temporales para que
    /// `(T)x` se reconozca como cast dentro de un body generico (los
    /// type-params del struct/clase contenedor y del metodo no son
    /// typedefs conocidos a priori).  Devuelve SOLO los nombres que
    /// realmente se insertaron (no estaban ya en @c declared_aliases_),
    /// para retirarlos despues con @c unregister_temp_type_aliases.
    std::vector<std::string>
    register_temp_type_aliases(const std::vector<std::string> &names);
    /// @brief Retira los aliases temporales insertados por el helper
    /// anterior (restaura @c declared_aliases_ al estado previo).
    void unregister_temp_type_aliases(const std::vector<std::string> &inserted);

    // -----------------------------------------------------------------
    // Reglas gramaticales: tipos.
    // -----------------------------------------------------------------

    std::unique_ptr<ast::TypeNode> parse_type_node();

    // -----------------------------------------------------------------
    // Reglas gramaticales: statements.
    // -----------------------------------------------------------------

    std::unique_ptr<ast::BlockStmt> parse_block();
    std::unique_ptr<ast::Stmt> parse_statement();
    /// Cuerpo real; @ref parse_statement lo envuelve para medir la extension.
    std::unique_ptr<ast::Stmt> parse_statement_inner();
    std::unique_ptr<ast::Stmt> parse_var_decl_stmt(bool is_const,
                                                   bool from_comptime = false);
    std::unique_ptr<ast::Stmt> parse_if_stmt();
    std::unique_ptr<ast::Stmt> parse_while_stmt();
    std::unique_ptr<ast::Stmt> parse_do_while_stmt();
    std::unique_ptr<ast::Stmt> parse_for_stmt();
    std::unique_ptr<ast::Stmt> parse_return_stmt();
    std::unique_ptr<ast::Stmt> parse_try_stmt();
    std::unique_ptr<ast::Stmt> parse_throw_stmt();
    std::unique_ptr<ast::Stmt> parse_synchronized_stmt();
    std::unique_ptr<ast::Stmt>
    parse_asm_stmt(); ///<  AS: asm [quals] { ... } clobbers(...)
    std::unique_ptr<ast::Stmt> parse_expr_stmt();

    // -----------------------------------------------------------------
    // Reglas gramaticales: expresiones, por nivel de precedencia.
    // -----------------------------------------------------------------

    std::unique_ptr<ast::Expr> parse_expr();
    std::unique_ptr<ast::Expr> parse_assignment();
    std::unique_ptr<ast::Expr> parse_ternary(); ///< cond ? then : else
    std::unique_ptr<ast::Expr> parse_logical_or();
    std::unique_ptr<ast::Expr> parse_logical_and();
    std::unique_ptr<ast::Expr> parse_bitwise_or();
    std::unique_ptr<ast::Expr> parse_bitwise_xor();
    std::unique_ptr<ast::Expr> parse_bitwise_and();
    std::unique_ptr<ast::Expr> parse_equality();
    std::unique_ptr<ast::Expr> parse_relational();
    std::unique_ptr<ast::Expr> parse_shift();
    std::unique_ptr<ast::Expr> parse_additive();
    std::unique_ptr<ast::Expr> parse_multiplicative();
    std::unique_ptr<ast::Expr> parse_unary();
    std::unique_ptr<ast::Expr> parse_postfix();
    std::unique_ptr<ast::Expr> parse_primary();

    /**
     * @brief Parsea una lambda @c (args) => expr/{stmts} a partir del LPAREN.
     *
     * El @c current_ debe estar en LPAREN cuando se llama (precondicion
     * que comprueba @c is_lambda_start()).  Consume desde el LPAREN hasta
     * el final del cuerpo (expression-bodied o block).
     */
    std::unique_ptr<ast::Expr> parse_lambda_expr();

    /**
     * @brief Lookahead que determina si lo que sigue al @c current_ LPAREN
     *        es una lambda y no una expresion parentizada.
     *
     * Cuenta parentesis con balance hasta cerrar el grupo; si el siguiente
     * token tras el RPAREN matching es FAT_ARROW, es una lambda.  Sin
     * consumir tokens (usa @c Lexer::peek_at).  Coste O(N) donde N es la
     * longitud del grupo entre parentesis; despreciable para listas de
     * argumentos tipicas.
     *
     * @return true si la siguiente forma sintactica es una lambda.
     */
    [[nodiscard]] bool is_lambda_start() const noexcept;

    /**
     * @brief Decide si el token actual abre un tipo primitivo (i32, ...).
     *
     * Para tipos escritos como IDENTIFIER (`Punto`, `Cls<T>`) el criterio
     * incluye un lookahead: tras el tipo debe venir un NOMBRE.  Sin ese
     * lookahead no se podria distinguir `a * b;` (expresion) de
     * `Punto* p;` (declaracion).
     *
     * @param allow_reserved_name Si true, acepta ademas una palabra
     *        reservada en la posicion del nombre.  Solo debe usarse donde
     *        NO exista ambiguedad con expresiones (top-level), y sirve
     *        para que el error se reporte sobre el nombre culpable en vez
     *        de degenerar en "se esperaba un tipo" al inicio de la linea.
     */
    [[nodiscard]] bool
    starts_type(bool allow_reserved_name = false) const noexcept;

    /**
     * @brief  AS inc.2: decide si el statement actual es un var-decl
     *        con storage-class @c register("reg").
     *
     * Reconoce el patron EXACTO @c register @c ( @c "reg" @c ) seguido de
     * un type-starter.  Solo asi se trata como var-decl; una llamada
     * @c register("x"); (sin tipo despues) queda como expresion.  El
     * lookahead es preciso para no robar sintaxis a expresiones legitimas.
     */
    [[nodiscard]] bool looks_like_register_storage() const noexcept;

    /**
     * @brief Consume una anotacion opcional `register("rXX")` al inicio de un
     *        parametro (o de un tipo de parametro en `cfn(...)`), devolviendo
     * el nombre del registro o "" si no hay.  Habilita la ABI custom por
     *        funcion: el parametro se recibe (y el caller lo coloca) en ese
     *        registro fisico.  Solo consume si el patron exacto
     *        `register ( "reg" )` aparece; deja intacto cualquier otro caso.
     */
    std::string parse_opt_param_reg();

    /**
     * @brief Lee la direccion opcional de un parametro (`in`/`out`/`inout`).
     *
     * @return La direccion leida, o @c ParamDir::None si no habia marca (y
     *         entonces no se ha consumido nada).
     *
     * Se llama al INICIO de cada parametro, antes de `register(...)` y del
     * tipo.  `out`/`inout` son contextuales a proposito: son identificadores
     * corrientes en cualquier otra posicion, incluido el `out` de x86 dentro
     * de un bloque @c asm.
     */
    ParamDir parse_opt_param_dir_();

    /**
     * @brief El statement actual empieza por una direccion (`in`/`out`/
     *        `inout`) seguida de un tipo, o sea es una declaracion.
     *
     * Hace falta porque @c starts_type mira el token de AHORA y la marca va
     * DELANTE del tipo -- el mismo caso que @c looks_like_register_storage.
     */
    bool looks_like_param_dir_storage() const noexcept;

    /**
     * @brief Lee los efectos definidos de una funcion externa (`@io`,
     *        `@throws`, `@panics`, `@alloc`, ...), con `when:` opcional.
     * @param out Donde se acumulan, ya RESUELTOS contra el objetivo activo.
     *
     * Se llama antes del `fn` de cada declaracion dentro de un bloque
     * `extern`.  Si lo que hay no es un efecto conocido, no consume nada.
     */
    void parse_extern_effects_(ast::ExternEffects &out);

    /**
     * @brief Decide si el `(` actual inicia un cast C-style `(T) expr`.
     *
     * El parser reconoce el patron `(<type>) <unary>` solo cuando el
     * primer token tras `(` es claramente un type-starter (primitivo,
     * @c VirtualPtr, @c fn, @c nonnull) y la secuencia se cierra con
     * un `)` seguido de un token que pueda iniciar una expresion.
     * Sin esto, el parser bajaria a `(expr)` y fallaria al ver el
     * `)` en mitad del tipo.  No aceptamos `(Foo) x` para typedefs
     * de identificadores; el usuario puede escribir
     * `(VirtualPtr<Foo>) x` o `(Foo*) x` que son inequivocos.
     */
    [[nodiscard]] bool looks_like_cast() const noexcept;

    /**
     * @brief Detecta un compound literal C99: `(Tipo){...}` o
     *        `(Tipo<args>){...}`.  Precondicion: @c current_ es '('.  Es
     *        inequivoco (un `(expr){` no tiene otro significado), asi que
     *        acepta un nombre de tipo aunque @c looks_like_cast lo rechace.
     */
    [[nodiscard]] bool looks_like_compound_literal() const noexcept;

    Lexer &lex_;
    Diagnostics &diags_;
    Token current_;
    /// contador para nombres unicos de static_asserts top-level
    /// que se modelan como GlobalVarDecl dummy.  El type checker los
    /// procesa en la pasada de globales sin generar storage runtime.
    uint32_t static_assert_counter_ = 0;
    /// Registry de macros con params @c expr.  Llave: nombre del @Macro.
    /// Valor: indices (0-based) de los params declarados con tipo `expr`.
    /// Poblado cuando se parsea la FunctionDecl del macro; consultado
    /// en @c parse_postfix al construir un @c CallExpr para hacer
    /// raw-text capture en las posiciones marcadas.
    ///
    /// Limitacion  A: el @Macro debe estar declarado ANTES de su
    /// llamada en el archivo (single-pass parser). Forward refs requieren
    /// un pre-scanner ( B futura).
    std::unordered_map<std::string, std::vector<int>> macro_expr_params_;

    /**
     * @struct MemberContracts
     * @brief Contratos de huella declarados sobre un metodo de struct/clase.
     *
     * Los mismos que admite una funcion libre.  Se recogen antes del miembro y
     * se vuelcan sobre el @c ClassMethodDecl cuando resulta ser un metodo; si
     * el miembro era un campo, se ignoran con un error claro (un campo no tiene
     * huella que declarar).
     */
    struct MemberContracts {
        bool pure = false;
        bool nothrow_ = false;
        bool nopanic = false;
        int64_t alloc = -1;         ///< @alloc(total: N) o `@alloc(N)`.
        int64_t alloc_partial = -1; ///< @alloc(partial: N).
        int64_t stack = -1;         ///< @stack(total: N) o `@stack(N)`.
        int64_t stack_partial = -1; ///< @stack(partial: N).
        std::string complexity_expr;
        std::vector<std::string> complexity_vars;
        std::string partial_pre, partial_post, total_pre, total_post;
        /// Los @complexity cuyo `when:` habla del parametro de tipo: se
        /// resuelven al monomorphizar, no aqui.  Ver @ref
        /// ast::PendingComplexity.
        std::vector<ast::PendingComplexity> pending;
        /// Contratos de HUELLA con `when:`, sin resolver.
        std::vector<ast::PendingFootprint> footprint_pending;
        bool any = false; ///< true si se declaro alguno (para el diagnostico).
    };

    /// @brief Parsea los argumentos de `@complexity(...)`.
    ///
    /// Compartido entre las anotaciones top-level y las de un metodo: es el
    /// mismo contrato sobre lo mismo.  Se entra con `complexity` ya consumido
    /// (el siguiente token debe ser `(`) y se sale tras el `)` de cierre.
    /// Las dimensiones se parsean SIEMPRE; quien decide que hacer con ellas es
    /// el caller, porque un contrato no se puede resolver mirandolo solo a el:
    /// varios `when:` pueden casar a la vez y hay que compararlos por
    /// especificidad (ver `contract_when.h`).
    /// @param out_when  el texto del `when:` tal cual (vacio si no lo lleva).
    /// @param out_aplica false si el `when:` habla SOLO del target y NO casa:
    ///        el contrato no es de esta compilacion y el caller lo tira.  Los
    ///        que hablan del parametro de tipo salen con true y sin evaluar --
    ///        el que puede es el clon de la monomorphizacion, con T concreto.
    void parse_complexity_args_(std::string &expr,
                                std::vector<std::string> &vars,
                                std::string &partial_pre,
                                std::string &partial_post,
                                std::string &total_pre, std::string &total_post,
                                std::string *out_when = nullptr,
                                bool *out_aplica = nullptr);

    /// @brief Lee `when: <expr>` de un contrato de huella y devuelve el texto
    ///        raw de la expresion (sin comillas, como en @complexity).
    ///
    /// Se entra con @c current_ en el identificador `when`.  Captura hasta
    /// --sin consumir-- el `)` de nivel 0, respetando los parentesis de un
    /// predicado
    /// (`is_float<T>()`).  Devuelve "" y reporta si esta mal formado.
    std::string read_footprint_when_();

    /// @brief Dimensiones parseadas de un `@alloc`/`@stack`.
    ///
    /// La forma corta `@alloc(N)` fija @c total (el peor caso que importa desde
    /// fuera); la nombrada `@alloc(partial: N, total: M)` fija lo que liste.
    /// -1 = esa dimension no se declaro.  @c when vacio = sin `when:`.
    struct FootprintDims {
        int64_t partial = -1;
        int64_t total = -1;
        std::string when;
    };

    /// @brief Parsea el contenido de `@alloc(...)`/`@stack(...)` TRAS consumir
    /// el
    ///        `(` y hasta --sin consumir-- el `)`.  Acepta la forma corta
    ///        (un entero -> total) y la nombrada (`partial:`/`total:`), con un
    ///        `when:` opcional al final.  @p nm es "alloc"/"stack" (mensajes).
    FootprintDims parse_footprint_dims_(const std::string &nm);

    /// @brief Consume las anotaciones de contrato que preceden a un miembro.
    /// @param out se rellena con lo declarado; @c out.any dice si habia alguna.
    void parse_member_contracts_(MemberContracts &out);

    /// @brief Vuelca @p mc sobre un metodo ya parseado.
    void apply_member_contracts_(const MemberContracts &mc,
                                 ast::ClassMethodDecl &m);

    /// @brief Suprime el postfijo `{}` (sobrecarga de `__braces__`) mientras se
    ///        parsea una expresion a la que SIGUE un bloque del lenguaje.
    ///
    /// El unico sitio donde una expresion no va parentizada y lleva un `{`
    /// pegado es el scrutinee del `match` (`match s { case ... }`, estilo
    /// Rust). Ahi el `{` abre el cuerpo del match, no una llamada.
    bool no_braces_call_ = false;

    /// Set de identifiers declarados como typedef / using en el archivo
    /// (alias de tipos).  Poblado por @c parse_typedef_decl /
    /// @c parse_using_decl.  Consultado por @c looks_like_cast para
    /// permitir `(MyTypedef) x` cuando el identifier es un alias
    /// conocido (cierre de Item 19 de pendientes).  Limitacion
    /// single-pass: el typedef debe declararse ANTES del uso (igual
    /// que cualquier forward decl en C/Vesta).
    std::unordered_set<std::string> declared_aliases_;
    /// Segmentos accesores de los namespaces importados (`import a.b.c;` ->
    /// `c`, o el alias si hay `as`).  Poblado por @c parse_import.  Consultado
    /// por @c looks_like_cast para reconocer un cast a un tipo CUALIFICADO
    /// `(ns.Tipo) x` (p.ej. `(types.size_t) 40`), igual que
    /// @c looks_like_var_decl ya acepta `ns.Tipo name`.  Sin esto la deteccion
    /// del cast solo veria el primer identifier (`types`, un namespace, no un
    /// alias) y rechazaria la secuencia como agrupacion.
    std::unordered_set<std::string> imported_namespaces_;
    /// Nombres de los parametros `expr` de la funcion cuyo CUERPO se esta
    /// parseando ahora mismo.  Sirve para el forwarding de expr-capture
    /// anidado: si el argumento de una llamada a otra fn expr-capture es
    /// exactamente uno de estos nombres (`return src(code);` donde `code` es un
    /// `expr` param del macro), NO se re-captura el identificador como texto
    /// ("code") sino que se emite un IdentExpr que en AST-eval resuelve al
    /// texto ya capturado.
    std::unordered_set<std::string> current_expr_param_names_;

    /// Aliases extra producidos por un typedef C-style multi-declarador
    /// (`typedef LONG *PLONG, *LPLONG;` o `typedef struct {...} FOO, *PFOO;`).
    /// parse_typedef_* solo devuelve el PRIMER declarador; los siguientes se
    /// encolan aqui y @c parse_program / @c parse_namespace_decl los drenan al
    /// nivel del modulo.  Reusa el patron de @c parse_extern_block (N decls).
    std::vector<std::unique_ptr<ast::Node>> pending_extra_decls_;

    /// Structs/uniones ANONIMOS sintetizados dentro del cuerpo de otro struct
    /// (`struct { ... } campo;` o miembro anonimo C11 `union { ... };`).  Se
    /// emiten como decls top-level ANTES del struct contenedor (que los
    /// referencia por su nombre sintetico), asi que se drenan ANTES del decl
    /// actual en parse_program / parse_namespace_decl.
    std::vector<std::unique_ptr<ast::Node>> pending_before_decls_;
    /// Contador para nombres sinteticos de agregados anonimos.
    int anon_aggr_counter_ = 0;

    /// Parsea la cola de declaradores C-style tras el primer alias:
    /// mientras haya `,`, consume `[*]* NOMBRE` y encola un TypeAliasDecl
    /// (base clonado + N punteros) en @c pending_extra_decls_.  @c base es el
    /// tipo especificador SIN los punteros del primer declarador.
    void parse_c_typedef_ptr_aliases_(const ast::TypeNode *base);

    /// Consume un sufijo de array C-style `[N][M]...` (uni o multidimensional,
    /// dimension opcional para `[]`) tras el nombre de un campo/variable y
    /// envuelve @c base en @c ArrayTypeNode anidados.  `T[N][M]` = array de N
    /// de (array de M de T): el primer `[` es el mas externo.  Devuelve @c base
    /// sin cambios si no hay `[`.
    std::unique_ptr<ast::TypeNode>
    wrap_c_array_dims_(std::unique_ptr<ast::TypeNode> base);

    /// Parsea un agregado ANONIMO inline (`struct { ... }` / `union { ... }`,
    /// tag opcional) dentro del cuerpo de otro struct.  Devuelve un StructDecl
    /// con nombre SINTETICO (`__anon<N>`) que el caller encola en
    /// @c pending_before_decls_ y referencia como tipo del campo. Precondicion:
    /// current_ es 'struct'/'union' y el siguiente token (tras un tag opcional)
    /// es '{'.
    /**
     * @brief Analiza el CUERPO de un struct: lo que va entre las llaves.
     *
     * Campos, agregados anonimos, metodos, constructores y destructor, con sus
     * modificadores de acceso, `static`, `comptime`, contratos y anotaciones.
     *
     * Lo llaman las DOS formas de declarar un agregado -- `struct X { }` y
     * `typedef struct { } X;` --, que es el motivo de que este aparte: la
     * segunda tenia su propia copia, y se habia quedado en los campos a secas.
     * Un metodo, un `private`, un `static` o un destructor escritos en la forma
     * C se rechazaban con un "se esperaba un tipo de campo", sin que nada
     * dijera que esa forma admite menos.
     *
     * @param sd         Declaracion que se va rellenando.
     * @param is_overlay Si es una vista sobre memoria (admite `[count]` y
     *                   `stride(...)` en los campos).
     */
    void parse_struct_body_(ast::StructDecl &sd, bool is_overlay);

    std::unique_ptr<ast::StructDecl> parse_inline_anon_aggregate_();

    /// Declarador de PUNTERO A FUNCION estilo C: `R (*name)(params)`.  Tras
    /// parsear el tipo de retorno @c ret, si en la posicion actual hay
    /// `( * IDENT ) ( params )`, lo parsea: devuelve true, escribe el nombre en
    /// @c out_name y un @c FunctionTypeNode (is_raw = cfn, 8 bytes) en
    /// @c out_type.  Si no coincide el patron, devuelve false sin consumir.
    /// Cubre campos/typedefs/params/vars de headers C (`int (*cb)(void*)`).
    bool try_parse_c_func_ptr_(std::unique_ptr<ast::TypeNode> &ret,
                               std::string &out_name,
                               std::unique_ptr<ast::TypeNode> &out_type);

    /// Nombres de @c struct declarados (single-pass, antes de su uso).  Lo
    /// consulta @c looks_like_compound_literal para distinguir un compound
    /// literal `(Struct){...}` de un scrutinee de control de flujo como
    /// `match (val) {` -- solo se trata como compound literal si el nombre es
    /// un struct conocido.
    std::unordered_set<std::string> declared_structs_;

    ///  M.L24: flag indicando si la ultima invocacion de
    /// @c parse_top_level_decl skipeo la decl por @c @Target no
    /// matcheado.  @c parse_program lo consulta para evitar
    /// llamar a @c synchronize() (que descartaria tokens validos
    /// de la siguiente decl).
    bool last_decl_was_target_skip_ = false;

    /// @NoExceptions a nivel modulo (sticky): una vez visto, se propaga a
    /// ModuleNode::no_exceptions -> todas las funciones lo heredan.
    bool module_no_exceptions_ = false;

    /// El modulo usa @Target en alguna declaracion (sticky): se propaga a
    /// @c ModuleNode::uses_conditional_target para que su `.vxi` quede atado
    /// al objetivo con que se genero.
    bool module_uses_target_ = false;

    ///  M6.a L.3: visibilidad pendiente capturada en
    /// @c parse_top_level_decl.  Los sub-parsers que produzcan un
    /// nodo top-level llaman @c apply_pending_visibility_ al final
    /// antes de devolver el nodo.  Valores: 0 = sin keyword (mantener
    /// el default del nodo), 1 = @c public explicito, 2 = @c private
    /// explicito.  El destructor @c VisGuard en
    /// @c parse_top_level_decl resetea a 0 al salir.
    uint8_t pending_visibility_ = 0;

    /**
     * @brief Un @c final leido antes de la palabra @c class.
     *
     * Mismo mecanismo que la visibilidad y por el mismo motivo: el modificador
     * va DELANTE -- `final class C` --, igual que en Java y en C#, y quien
     * parsea la clase ya empieza en la palabra @c class.  Lo recoge
     * @c parse_top_level_decl y lo aplica el parseo de la clase; el guarda lo
     * limpia al salir.
     */
    bool pending_final_ = false;

  public:
    /// Helper que aplica @c pending_visibility_ al nodo si el nodo
    /// es de un kind con campo @c is_public.  Llamado al final de
    /// cada @c parse_<xxx>_decl que pueda aparecer en top-level.
    /// No-op si @c pending_visibility_ == 0.
    void apply_pending_visibility(ast::Node *n) noexcept;

    ///  M.L24: descarta una decl top-level cuya @Target no matcheo.
    /// Consume tokens hasta el final natural de la decl ({ ... } o ;).
    /// @param spec Condicion @Target que no se cumplio; se anota junto al
    ///             nombre descartado en @c target_skipped_ para poder decir
    ///             despues "existe, pero para otro objetivo".
    void skip_target_skipped_decl(const std::string &spec = std::string());

    /// Nombre descartado por @Target -> condicion(es) bajo las que si existe.
    /// Un mismo nombre puede tener varias variantes (una por plataforma).
    std::unordered_map<std::string, std::vector<std::string>> target_skipped_;

  public:
    /// Simbolos que este fichero declara SOLO para otros objetivos.  Quien
    /// resuelve nombres lo consulta cuando una busqueda falla, para distinguir
    /// "no existe" de "existe pero no para este target".
    const std::unordered_map<std::string, std::vector<std::string>> &
    target_skipped() const noexcept {
        return target_skipped_;
    }
};

} // namespace vx

#endif // VX_PARSER_H
