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
 * @file ast.h
 * @brief Arbol de Sintaxis Abstracta (AST) para el lenguaje Vesta.
 *
 * Modelo de jerarquia plana con discriminador (NodeKind) + downcast
 * controlado.  Cada nodo lleva su SourceLoc para reportes y la propiedad
 * por @c std::unique_ptr garantiza ownership claro y zero-cost frente a
 * @c shared_ptr (sin contadores atomicos).
 *
 * Cobertura actual del AST:
 *   - ModuleNode (raiz): lista de FunctionDecl, GlobalVarDecl, ClassDecl,
 *                       StructDecl, EnumDecl, ExternFnDecl.
 *   - Statements: Block, VarDecl, ExprStmt, If, While, DoWhile, For (C),
 *                 ForEach (Vesta), Return, Break, Continue, Goto, Label,
 *                 Try/Catch/Finally, Synchronized, Throw, Match.
 *   - Expressions: literales (int/float/bool/null/char/string con
 *                  interpolacion), Ident, Binary, Unary, Assign, Call,
 *                  New, Spawn, RSpawn, Lambda, Match, Cast, FieldAccess,
 *                  Index, This, InitList.
 *   - Type AST: PrimitiveTypeNode + PointerTypeNode + ArrayTypeNode +
 *               NamedTypeNode (con generics) + FunctionTypeNode.
 *
 * Decisiones de hardware:
 *   - NodeKind cabe en 1 byte; el discriminador se inlinea en cada nodo.
 *   - Los enum BinOp/UnOp/AssignOp tambien son uint8_t para minimizar
 *     padding cuando el AST se aloja en alguna arena futura.
 *   - Los downcasts en lowering / type checker se hacen con static_cast
 *     tras chequear @c kind, NO con dynamic_cast (cero RTTI overhead).
 */

#ifndef VX_AST_H
#define VX_AST_H

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "vx/diagnostic.h"
#include "vx/types.h"

namespace vx::ast {

/// Sufijo del nombre de la variante que usa el JIT (@Target("mode:jit")).
///
/// La variante del interprete conserva el nombre desnudo para que ningun punto
/// de llamada cambie; el JIT sustituye la llamada por la del sufijo cuando
/// compila la funcion.  Asi las dos viajan en el mismo `.velb` sin tocar el
/// formato ni anadir tablas.
inline constexpr const char *kSufijoVarianteJit = "__jit";

// -------------------------------------------------------------------
// Discriminadores: NodeKind, BinOp, UnOp, AssignOp.
// -------------------------------------------------------------------

/**
 * @enum NodeKind
 * @brief Identifica la categoria concreta de cada nodo del AST.
 *
 * Agrupados por seccion (decls, stmts, exprs, types).  Los rangos
 * son contiguos para que predicados como is_expr() puedan implementarse
 * con una comparacion numerica en lugar de un switch.
 */
enum class NodeKind : uint8_t {
    // ----- Declaraciones (top-level y locales) -----
    Module = 0,
    FunctionDecl,
    ParamDecl,
    GlobalVarDecl,
    TypeAliasDecl,
    StructDecl,
    ClassDecl,
    EnumDecl,      ///< Declaracion de tipo algebraico (enum + variantes con/sin
                   ///< payload).
    ExternFnDecl,  ///< @c extern "lib.dll" fn name(params) -> ret; (FFI
                   ///< declarativo, 0 overhead).
    ImportDecl,    ///< @c import "path" [as alias] [only A, B];  ( M sistema
                   ///< de modulos).
    NamespaceDecl, ///< @c namespace foo { decls }  ( M.7.c, inline
                   ///< namespace estilo C++).
    BytesDecl,     ///< @c bytes name { db/dw/dd/dq/times ... }  (datos crudos
                   ///< estilo NASM, AOT).
    ConceptDecl,   ///< @c concept Name<T> = pred; | { stmts } | { metodos }
    ///< (constraints/bounds de genericos, #6; compile-time puro).
    ExtensionDecl, ///< @c extension Tipo { metodos }  (NS.6-ext: anyade metodos
                   ///< a un tipo existente; dispatch estatico directo).
    ImplDecl, ///< @c impl Concept for Tipo { metodos }  (NS.6-ext: implementa
              ///< un concept para un tipo; conformance estructural).

    // ----- Statements -----
    BlockStmt,
    VarDeclStmt,
    ExprStmt,
    IfStmt,
    WhileStmt,
    DoWhileStmt,
    ForStmt,
    ReturnStmt,
    BreakStmt,
    ContinueStmt,
    GotoStmt,
    LabelStmt,
    TryStmt,           ///< try { ... } catch (T e) { ... }
    ThrowStmt,         ///< throw expr;
    ForEachStmt,       ///< for (T x : col) body
    SynchronizedStmt,  ///< synchronized (obj) { ... }  (monenter/monexit con
                       ///< cleanup implicito en cada via de salida)
    ComptimeBlockStmt, ///< A.39: comptime { ... } scope para comptime const +
                       ///< for + asserts
    ComptimeForStmt, ///< A.39: comptime for (i in lo..hi) { body } -- unrolled
    AsmStmt,         ///<  AS: asm [quals] { ...NASM... } clobbers(...)  (inline
                     ///< asm nativo)

    // ----- Expressions -----
    IntLitExpr,
    FloatLitExpr,
    BoolLitExpr,
    NullLitExpr,
    CharLitExpr,
    StringLitExpr,
    IdentExpr,
    FieldAccessExpr,
    BinaryExpr,
    UnaryExpr,
    AssignExpr,
    TernaryExpr, ///< cond ? then : else (A.38)
    TryExpr,     ///< expr? (P2: early-return para Result<V,E>)
    CallExpr,
    IndexExpr,
    ThisExpr,
    NewExpr,
    SpawnExpr,  ///< spawn { body }: arranca proceso hijo, devuelve PID encoded
    RSpawnExpr, ///< rspawn(node) { body }: spawn cross-node, devuelve Future
                ///< handle
    LambdaExpr, ///< (args) => expr  o  (args) => { stmts }: closure inline
    MatchExpr,  ///< ADTs: match scrutinee { case Variant(bindings) => body; ...
                ///< }
    SuperCallExpr,       ///< super(args) -- delegacion ctor (R1)
    SuperMethodCallExpr, ///< super.method(args) -- callsuper no-virtual (R1)
    InitListExpr,        ///< { 1, 2, 3 } o { .x = 1, .y = 2 } como
                         ///< inicializador de array o struct.  Solo valido en
                         ///< var-decl o como init de campo nested.  Lowering
                         ///< asigna cada elemento al slot correspondiente del
                         ///< destino (no construye un valor temporal).
    CastExpr,            ///< (T)expr: cast C-style.  El parser solo reconoce
                         ///< el patron `(<type>) <unary>` cuando el contenido
                         ///< del parentesis es un type-node (no una expresion
                         ///< que produce valor).  Cubre tanto conversiones
                         ///< numericas como bitcasts de punteros entre
                         ///< VirtualPtr<T> y T*, ptr<->int, etc.

    // ----- Types AST -----
    PrimitiveTypeNode,
    NamedTypeNode,
    PointerTypeNode,
    ArrayTypeNode,
    FunctionTypeNode, ///< fn(T1, T2) -> R: tipo de variable / parametro /
                      ///< retorno closure

    // Sentinela.
    COUNT
};

/**
 * @enum BinOp
 * @brief Operadores binarios reconocidos por el parser.
 *
 * Mapeo 1-a-1 con TokenKind operador, mantenido en parse_binary_op_from_token.
 */
enum class BinOp : uint8_t {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    LogicalAnd,
    LogicalOr,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
};

/**
 * @enum UnOp
 * @brief Operadores unarios prefijo y postfijo.
 *
 * La distincion prefijo/postfijo (++x vs x++) se codifica como dos
 * variantes separadas para que el lowering vea exactamente la
 * semantica deseada sin necesidad de una flag aparte.
 */
enum class UnOp : uint8_t {
    Neg,        ///< -x
    Pos,        ///< +x (raramente util, pero el parser lo acepta)
    LogicalNot, ///< !x
    BitNot,     ///< ~x
    PreInc,     ///< ++x
    PreDec,     ///< --x
    PostInc,    ///< x++
    PostDec,    ///< x--
    AddrOf,     ///< &x (toma direccion de un lvalue; el lvalue se promociona a
                ///< ALLOCA)
    Deref,      ///< *p (lectura a traves de puntero; tipo = *p->pointee)
    Unwrap,     ///< !!x  (Optional: assert non-null; lanza NPE si nulo)
    Await,      ///< await fut (Future: bloquea hasta resuelto, devuelve valor)
};

/**
 * @enum AssignOp
 * @brief Variantes del operador de asignacion (simple o compuesto).
 */
enum class AssignOp : uint8_t {
    Assign,       ///< =
    AddAssign,    ///< +=
    SubAssign,    ///< -=
    MulAssign,    ///< *=
    DivAssign,    ///< /=
    ModAssign,    ///< %=
    BitAndAssign, ///< &=
    BitOrAssign,  ///< |=
    BitXorAssign, ///< ^=
    ShlAssign,    ///< <<=
    ShrAssign,    ///< >>=
};

// -------------------------------------------------------------------
// Nodo base.
// -------------------------------------------------------------------

/**
 * @struct Node
 * @brief Raiz de la jerarquia AST.
 *
 * Toda la informacion comun (discriminador + posicion) vive aqui;
 * los campos especificos viven en las clases derivadas.  El destructor
 * es virtual para que @c unique_ptr<Node> libere correctamente el
 * subtipo, pero NO se confia en RTTI para el dispatch (vease NodeKind).
 */
struct Node {
    NodeKind kind = NodeKind::COUNT;
    SourceLoc loc;

    /**
     * @brief El tramo de TEXTO del que salio esta declaracion.
     *
     * @c loc apunta a un token de dentro y su @c length es la de ese token, no
     * la de la declaracion; quien necesite su fuente completo -- extraer el
     * conjunto comptime para compilarlo aparte, por ejemplo -- necesita los dos
     * extremos.  Lo anota el parser, que los sabe sin adivinar: primer token
     * (anotaciones incluidas) hasta el inicio del siguiente.  Cero = no se supo
     * (decl sintetizada por el compilador, que no sale de ningun texto).
     *
     * Va EN EL NODO y no en un mapa aparte, y eso costo encontrarlo: con un
     * mapa por modulo indexado por puntero, un decl que se MUDA de modulo --
     * los `namespace` parciales reparten decls entre ficheros -- deja su tramo
     * atras.  Se veia como un modulo de tipos que viajaba vacio y una cadena de
     * alias que no resolvia, sin nada que apuntara al traslado.  En el nodo no
     * hay identidad que perder.
     */
    uint32_t span_start = 0;
    uint32_t span_end = 0;

    Node() = default;
    explicit Node(NodeKind k) : kind(k) {}
    virtual ~Node() = default;

    // Prohibimos copia para forzar el move-only de uniquept owners.
    Node(const Node &) = delete;
    Node &operator=(const Node &) = delete;
    Node(Node &&) = default;
    Node &operator=(Node &&) = default;
};

// Forward declarations utiles para signatures cruzadas.
struct Expr;
struct Stmt;
struct TypeNode;
struct ParamDecl;       ///< Necesaria para LambdaExpr antes de su definicion.
struct ClassMethodDecl; ///< Necesaria para StructDecl::methods antes de
                        ///< definirse.
struct BlockStmt;       ///< Necesaria para LambdaExpr antes de su definicion.

/**
 * @enum ParamDir
 * @brief Direccion declarada: que puede hacerse con lo que algo APUNTA.
 *
 * `in T* p` = solo se lee;  `out T* p` = solo se escribe;  `inout T* p` = las
 * dos cosas.  Sin marca, @c None: no se dice nada, que NO es lo mismo que
 * decir que no toca nada.
 *
 * Habla de lo APUNTADO y no de lo declarado: un valor viaja por copia -- Vesta
 * no tiene paso por referencia --, asi que `out i32 x` no significaria nada y
 * el comprobador lo rechaza.  Por eso vive en la DECLARACION y no en el tipo.
 *
 * Es un eje DISTINTO de `const`, y compone con el.  `const` es un permiso por
 * NIVEL sobre el tipo, igual que en C, donde `const T*` y `T* const` no son lo
 * mismo; la direccion habla del nivel EXTERNO.  Por eso `in T const*` se puede
 * escribir -- y es algo redundante -- y `out T const**` tambien: se escribe el
 * puntero de fuera y lo de dentro sigue siendo const.  Colapsarlos haria el
 * segundo inexpresable sin ganar nada.
 *
 * Y significa dos cosas segun donde este, a proposito:
 *   - en un @c ExternFnDecl DEFINE, porque no hay cuerpo que mirar y lo unico
 *     que hay es la palabra de quien lo escribe;
 *   - en codigo Vesta es un CONTRATO, que el compilador COMPRUEBA.
 * Una palabra, dos sitios; lo que cambia es quien responde por ella.
 *
 * Vive arriba del todo porque la llevan varias clases de declaracion -- el
 * parametro, la variable local -- y tienen que verla todas.
 */
enum class ParamDir : uint8_t {
    None = 0, ///< sin marca: no se afirma nada sobre lo apuntado.
    In,       ///< `in`: solo se LEE lo apuntado.
    Out,      ///< `out`: solo se ESCRIBE lo apuntado.
    InOut,    ///< `inout`: se lee y se escribe.
};

/**
 * @brief La palabra que el usuario escribio, para citarla en un diagnostico.
 * @param d La direccion.
 * @return "in" / "out" / "inout", o "" si no hay marca.
 *
 * En un sitio porque la citan el parser y el comprobador de tipos, y un
 * mensaje que llame `out` a lo que el usuario escribio `inout` manda a mirar
 * la linea equivocada.
 */
inline const char *param_dir_name(ParamDir d) noexcept {
    switch (d) {
    case ParamDir::In: return "in";
    case ParamDir::Out: return "out";
    case ParamDir::InOut: return "inout";
    default: return "";
    }
}


/**
 * @struct PendingComplexity
 * @brief Un @c @complexity cuyo @c when: habla del PARAMETRO DE TIPO y por
 *        tanto no se puede resolver al parsear.
 *
 * Los atomos de target (`arch:x86_64`) los resuelve el parser -- el target se
 * conoce al compilar --, pero un predicado como `is_float<T>()` solo tiene
 * respuesta cuando T es concreto, o sea al MONOMORPHIZAR.  El coste de un
 * metodo generico depende de T de verdad: `atomic<i64>::fetch_add` es un
 * `lock xadd` (O(1)) y `atomic<f64>::fetch_add` un bucle CAS (O(n)), porque el
 * `if (is_float<T>())` lo decide en comptime.
 *
 * El parser guarda aqui esas declaraciones tal cual; el clon de la
 * monomorphizacion evalua cada @c when con T ligado y vuelca la que casa a los
 * campos normales de la instanciacion.
 */
struct PendingComplexity {
    std::string
        when; ///< expresion del `when:` (con al menos un atomo sobre T).
    std::string expr; ///< azucar posicional (= total_post).
    std::vector<std::string> vars;
    std::string partial_pre;
    std::string partial_post;
    std::string total_pre;
    std::string total_post;
};

/**
 * @struct PendingFootprint
 * @brief Un contrato de HUELLA (@pure/@nothrow/@nopanic/@alloc/@stack) con un
 *        `when:`, sin resolver.
 *
 * La huella tambien varia con la arquitectura: una variante
 * @Target("arch:arm64") con `register()` gasta frame y toca memoria que su
 * gemela x86-64 no, asi que su `@stack`/`@pure` no son los mismos.  Como el
 * @complexity, un contrato de huella puede condicionarse con `when:` y resolver
 * por especificidad; los que hablan de un type param solo se resuelven al
 * monomorphizar.  Cada entrada escribe UN campo (la anotacion que lo declaro).
 * Los tri-estado son -1 = no declarado, 0/1 = valor.
 */
struct PendingFootprint {
    std::string when; ///< expresion del `when:` (vacia = siempre).
    int8_t pure = -1;
    int8_t nothrow_ = -1;
    int8_t nopanic = -1;
    int64_t alloc = -1;         ///< @alloc(total: N) o `@alloc(N)`.
    int64_t alloc_partial = -1; ///< @alloc(partial: N).
    int64_t stack = -1;         ///< @stack(total: N) o `@stack(N)`.
    int64_t stack_partial = -1; ///< @stack(partial: N).
};

/**
 * @brief @c true si k representa una expresion.
 */
constexpr bool is_expr_kind(NodeKind k) noexcept {
    // Rango contiguo: cualquier NodeKind entre IntLitExpr y CastExpr
    // (la ultima expresion definida) es una expresion.
    return (uint8_t)k >= (uint8_t)NodeKind::IntLitExpr &&
           (uint8_t)k <= (uint8_t)NodeKind::CastExpr;
}
/**
 * @brief @c true si k representa un statement.
 */
constexpr bool is_stmt_kind(NodeKind k) noexcept {
    return (uint8_t)k >= (uint8_t)NodeKind::BlockStmt &&
           (uint8_t)k <= (uint8_t)NodeKind::SynchronizedStmt;
}

// -------------------------------------------------------------------
// Tipos en AST (aun sin punteros / arrays / generics).
// -------------------------------------------------------------------

/**
 * @struct TypeNode
 * @brief Nodo abstracto raiz para nodos de tipo.
 *
 * @c is_nonnull se activa cuando el usuario escribio `nonnull T`
 * antes del tipo, indicando que la variable / parametro / campo
 * NO puede ser null en compile time.  El type checker rechaza
 * asignaciones de @c null o de tipos nullable sin un `!!` de por
 * medio.  Solo es semanticamente significativo para reference
 * types (CLASS / PTR); para primitivos (i32, etc) no aplica.
 */
struct TypeNode : Node {
    bool is_nonnull = false;
    /// const-correctness C-style POR NIVEL: `const T` marca el nodo del tipo
    /// base; `T *const` marca el PointerTypeNode de ese nivel.  Se propaga a
    /// @c Type::is_const en type_from_node.  (volatile se parsea pero se
    /// ignora: Vesta no tiene semantica volatile.)
    bool is_const = false;
    explicit TypeNode(NodeKind k) : Node(k) {}
};

/**
 * @struct PrimitiveTypeNode
 * @brief Nodo de tipo primitivo (i32, u8, f64, ...).
 *
 * La categoria primitiva se almacena ya canonicalizada (Vesta acepta
 * ambos estilos i32 / int32_t y aqui se guarda solo la forma canonica).
 */
struct PrimitiveTypeNode : TypeNode {
    PrimitiveKind prim = PrimitiveKind::VOID;
    /// type args para colecciones genericas.
    /// `ArrayList<T>` -> prim=ARRAYLIST + type_args=[T].
    /// `HashMap<K,V>` -> prim=HASHMAP   + type_args=[K, V].
    /// El type checker resuelve estos al `pointee`/`pointee2` del
    /// `Type` semantico final, que el lowering consulta para
    /// despachar a las variantes gc-aware del plugin (vcol_*_gc)
    /// cuando el tipo de elemento es GC (string, class, ...).
    std::vector<std::unique_ptr<TypeNode>> type_args;

    PrimitiveTypeNode() : TypeNode(NodeKind::PrimitiveTypeNode) {}
};

/**
 * @struct NamedTypeNode
 * @brief Referencia a un tipo por nombre.
 *
 * Aparece cuando el usuario menciona un tipo introducido por
 * @c typedef / @c using o por @c struct.  El type checker lo
 * resuelve consultando la tabla de aliases / structs registrada
 * a nivel de modulo.
 */
struct NamedTypeNode : TypeNode {
    std::string name;
    /// Argumentos de tipo de un instanciado generico (ej. `Box<i32>`
    /// produce name="Box" + type_args=[PrimitiveTypeNode(i32)]).
    /// Vacio para referencias no genericas.  El type checker
    /// monomorphiza la clase generica al ver el primer instanciado y
    /// reemplaza la referencia por NamedTypeNode con name="Box_i32".
    std::vector<std::unique_ptr<TypeNode>> type_args;
    NamedTypeNode() : TypeNode(NodeKind::NamedTypeNode) {}
};

/**
 * @struct PointerTypeNode
 * @brief Tipo puntero raw: T*.
 *
 * El parser apila estos nodos cada vez que ve un '*' tras un tipo
 * (postfix), por lo que T** se representa como PointerTypeNode envolviendo
 * a otro PointerTypeNode envolviendo a T.  El type checker desenvuelve la
 * cadena para producir un @c Type plano (con shared_ptr<Type> como
 * pointee).  Punteros raw NO son rastreados por el GC y NO tienen
 * verificacion de null en deref (solo el tipo @c nonnull T la fuerza).
 */
struct PointerTypeNode : TypeNode {
    std::unique_ptr<TypeNode>
        pointee; ///< Tipo apuntado (puede ser otro puntero).
    /// true si el parser vio @c VirtualPtr<T> (direccion de memoria VM);
    /// false si vio @c T* (direccion HOST por defecto).  El type checker
    /// propaga al campo @c is_virtual del @c Type resultante.
    bool is_virtual = false;
    PointerTypeNode() : TypeNode(NodeKind::PointerTypeNode) {}
};

/**
 * @struct ArrayTypeNode
 * @brief Tipo array nativo: T[N] (size fijo) o T[] (size variable /
 * decay-to-ptr).
 *
 * En Vesta los arrays nativos son simplemente bloques contiguos de
 * memoria; @c element_type indica el tipo de cada elemento y
 * @c size_expr el numero de elementos.  Cuando @c size_expr es nulo
 * el array es @c T[] (sin tamano conocido en compile time, util como
 * tipo de parametro de funcion: equivale a T*).  El type checker
 * exige que @c size_expr, si presente, sea un literal entero positivo
 * (las constantes mas elaboradas llegaran en hitos posteriores).
 */
struct ArrayTypeNode : TypeNode {
    std::unique_ptr<TypeNode> element_type;
    std::unique_ptr<Expr> size_expr; ///< nullopt => T[] (decay)
    ArrayTypeNode() : TypeNode(NodeKind::ArrayTypeNode) {}
};

/**
 * @struct FunctionTypeNode
 * @brief Tipo de funcion / closure: @c fn(T1, T2, ...) -> R.
 *
 * Permite declarar variables, parametros y campos cuyo tipo es una
 * funcion / closure.  El parser lo construye al ver el keyword @c fn
 * seguido de la lista de tipos de parametros entre parentesis y el
 * @c -> con el tipo de retorno opcional (si se omite, se asume void).
 *
 * Ejemplo de sintaxis aceptada:
 * @code
 *   fn(i32, i32) -> i32 sumador = (a, b) => a + b;
 *   fn() -> void log = () => println("hi");
 * @endcode
 *
 * El type checker resuelve el nodo a @c Type{FUNCTION, params, ret}
 * y lo usa para validar la asignacion de lambdas y las llamadas.
 */
struct FunctionTypeNode : TypeNode {
    /// Tipos de los parametros, en orden.  Vacio para @c fn() -> R.
    std::vector<std::unique_ptr<TypeNode>> param_types;
    /// Tipo de retorno.  Nunca null (el parser inserta VOID si el
    /// usuario omite la flecha @c ->).
    std::unique_ptr<TypeNode> return_type;
    /// true si es un PUNTERO A FUNCION crudo estilo C (@c cfn(...) -> R):
    /// 8 bytes (solo la direccion), llamada directa (CALLIND), SIN env.
    /// false = lambda/closure (@c fn(...) -> R): fat-pointer de 16 bytes
    /// {fn_addr, env}.  Conceptos distintos: lambda != puntero a funcion.
    bool is_raw = false;
    /// El ultimo parametro recoge los que sobren (`fn(T...) -> R`).  Quien
    /// llame puede pasar cuantos quiera: se meten en un array y el llamado
    /// recibe su direccion y cuantos son.
    bool is_variadic = false;
    /// ABI custom por-parametro (`cfn(register("rax") T, register("rdi") T,
    /// ...)`): registro fisico de entrada por parametro, alineado con @c
    /// param_types. Cadena vacia = ABI estandar.  La ABI forma parte del TIPO:
    /// dos @c cfn con abi_regs distintos son tipos INCOMPATIBLES (el type
    /// checker rechaza mezclarlos), de modo que una CALLIND siempre conoce la
    /// ABI en compile-time desde el tipo del puntero (aunque el VALOR del
    /// puntero cambie en runtime). Vacio TAMBIEN cuando ningun parametro
    /// declara ABI custom (caso comun).
    std::vector<std::string> param_abi_regs;
    FunctionTypeNode() : TypeNode(NodeKind::FunctionTypeNode) {}
};

// -------------------------------------------------------------------
// Expresiones.
// -------------------------------------------------------------------

/**
 * @struct Expr
 * @brief Nodo abstracto raiz para todas las expresiones.
 *
 * El campo @c result_type es el tipo deducido por el type checker;
 * el parser lo deja en su valor por defecto y el type checker lo
 * fija despues.  Mantenerlo en el nodo evita una tabla auxiliar
 * en lowering y reduce pointer chasing.
 */
struct Expr : Node {
    Type result_type{}; ///< Inicialmente VOID; el type checker lo rellena.

    /// Borrow checker (F4 - lifetime elision): si esta Expr produce
    /// un borrow<T>/borrow_mut<T> derivado de algun owner trackeable
    /// (var local, param, etc.), aqui se guarda el nombre de ese
    /// owner.  Vacio si no aplica o si la fuente no es trackeable.
    /// Usado para propagar la "lifetime source" a traves de:
    ///   - lend(x) / lend_mut(x): borrow_owner_source = x
    ///   - identity_borrow(p): si la firma tiene 1 input borrow, el
    ///     resultado hereda el source del arg
    ///   - reborrow lend(b): borrow_owner_source = b's source
    std::string borrow_owner_source;

    /// Borrow checker (F3 ext - suspend semantics): si esta Expr es
    /// un lend()/lend_mut() cuya fuente es un borrow_mut, aqui se
    /// guarda el nombre de la fuente para que @c check_var_decl
    /// pueda llamar @c mark_as_reborrow tras registrar el binding.
    std::string borrow_reborrow_source_name;
    /// Flag asociado: true si la fuente era borrow_mut (necesita
    /// restore al drop).  False si era borrow shared o owner directo.
    bool borrow_reborrow_source_is_mut = false;

    /// si esta Expr es un IdentExpr que resuelve a un comptime
    /// const (global de A.38 o local de A.39), el type checker
    /// graba aqui el valor para que el lowering lo inline como CONST
    /// directo.  Sin esto, los comptime const LOCALES se perderian
    /// al pop_comptime_scope() del type checker antes del lowering.
    bool comptime_const_resolved = false;
    bool comptime_const_is_str = false;
    int64_t comptime_const_int = 0;
    std::string comptime_const_str;

    explicit Expr(NodeKind k) : Node(k) {}
};

struct IntLitExpr : Expr {
    uint64_t value = 0;
    /// Tipo fijado por el sufijo (`42i8`), o @c VOID si el literal va desnudo
    /// y el tipo lo sigue infiriendo el contexto.
    PrimitiveKind suffix = PrimitiveKind::VOID;
    /// Cierto si el literal aparece justo detras de un `-`.  Lo marca el
    /// parser porque el rango no se puede juzgar mirando solo el numero:
    /// `128i8` se sale, pero `-128i8` es exactamente el minimo de i8.
    bool negated = false;
    IntLitExpr() : Expr(NodeKind::IntLitExpr) {}
};

struct FloatLitExpr : Expr {
    double value = 0.0;
    /// Tipo fijado por el sufijo (`3.14f32`), o @c VOID si va desnudo.
    PrimitiveKind suffix = PrimitiveKind::VOID;
    FloatLitExpr() : Expr(NodeKind::FloatLitExpr) {}
};

struct BoolLitExpr : Expr {
    bool value = false;
    BoolLitExpr() : Expr(NodeKind::BoolLitExpr) {}
};

struct NullLitExpr : Expr {
    NullLitExpr() : Expr(NodeKind::NullLitExpr) {}
};

struct CharLitExpr : Expr {
    uint32_t codepoint = 0;
    CharLitExpr() : Expr(NodeKind::CharLitExpr) {}
};

/**
 * @struct StringLitExpr
 * @brief Literal de cadena.
 *
 * Almacena los bytes ya resueltos (post-escapes para "...", verbatim
 * para r"...").  El tipo deducido por el type checker es
 * @c PTR (puntero a los bytes en la seccion de datos del modulo).
 * El lowering registra los bytes en @c IrModule::static_data y emite
 * un @c IrOp::STR_LIT_ADDR con el indice resultante.
 */
struct StringLitExpr : Expr {
    std::string
        value; ///< Bytes del literal (sin las comillas ni escapes textuales).
               ///< Para STRINGS SIMPLES contiene todo el contenido.
               ///< Para STRINGS INTERPOLADOS queda vacio y los datos
               ///< viven en @c interp_parts + @c interp_exprs.
    bool is_raw = false;
    /// El ultimo parametro recoge los que sobren (`fn(T...) -> R`).  Quien
    /// llame puede pasar cuantos quiera: se meten en un array y el llamado
    /// recibe su direccion y cuantos son.
    bool is_variadic = false;

    /// Interpolacion ${expr}.  Layout intercalado:
    ///   parts[0] + expr[0] + parts[1] + expr[1] + ... + parts[N]
    /// Si hay N expresiones, hay N+1 parts (algunas pueden ser "").
    /// Los vectores quedan vacios para strings sin interpolacion.
    std::vector<std::string> interp_parts;
    std::vector<std::unique_ptr<Expr>> interp_exprs;

    /// Formato opcional por interpolacion: @c ${expr:fmt}.  Vector
    /// paralelo a @c interp_exprs (tambien tamano N).  Cadena vacia
    /// = sin formato (default).  El formato es una mini-DSL parseada
    /// en lowering: kinds (`hex`, `bin`, `oct`, `dec`, `ptr`, `gc`,
    /// `char`, `bool`) y alineacion (`>N` right, `<N` left, opcional
    /// fill char tras el ancho).  Multiples specs se separan por `:`.
    std::vector<std::string> interp_formats;

    /// @c true si el string contiene al menos una expresion ${...}.
    bool is_interpolated() const noexcept { return !interp_exprs.empty(); }

    StringLitExpr() : Expr(NodeKind::StringLitExpr) {}
};

struct IdentExpr : Expr {
    std::string name;
    /// Function pointers: el type checker marca @c true cuando el ident
    /// resuelve a una funcion top-level usada como VALOR (no llamada
    /// directa).  El lowering emite @c LABEL_ADDR (direccion de la funcion)
    /// en vez de un load de variable.  @c func_ref_mangled guarda el nombre
    /// mangled real del simbolo a referenciar.
    bool is_func_ref = false;
    std::string func_ref_mangled;
    IdentExpr() : Expr(NodeKind::IdentExpr) {}
};

/**
 * @struct FieldAccessExpr
 * @brief Acceso a un campo: base.field.
 *
 * @c base es la expresion que evalua al struct (lvalue o rvalue
 * de tipo STRUCT); @c field_name es el nombre del campo.  El type
 * checker valida que @c base es un struct y que @c field_name
 * existe en su layout, y rellena @c result_type con el tipo del
 * campo.  El lowering calcula el offset desde el puntero base
 * y emite LOAD (lectura) o STORE (asignacion) sobre la VA
 * resultante.
 */
struct FieldAccessExpr : Expr {
    std::unique_ptr<Expr> base;
    std::string field_name;
    /// @brief Si !=0, el acceso resuelve a un accesor de
    /// propiedad y el lowering emite la llamada en vez de un
    /// getfield directo.  1 = getter (`obj.prop`), 2 = setter (lhs
    /// de un AssignExpr; @ref AssignExpr::is_property_set se marca
    /// en el padre).  3 = static field de clase (Counter.count).
    /// 4 = simbolo de namespace importado ( M.7, `lib_a.valor_a`).
    /// El metodo se llama `get_<field_name>` o
    /// `set_<field_name>` segun el caso.
    uint8_t property_kind = 0;
    ///  M.7: cuando @c property_kind == 4 este campo guarda
    /// el indice del namespace en @c TypeChecker::imported_namespaces_
    /// para que el lowering pueda resolver el mangled_label sin
    /// depender de la pila de scopes (que ya esta vacia al lower).
    /// Sentinel: UINT32_MAX = no resuelto.
    uint32_t ns_index = 0xFFFFFFFFu;
    /// `&Tipo.metodo`: referencia a la funcion libre de un metodo (puntero
    /// a metodo NO ligado estilo C).  El checker la marca al ver el patron
    /// `&Tipo.metodo` (base = nombre de struct/clase, field = metodo) y
    /// deja en @c func_ref_mangled el nombre de la free fn (`Tipo__metodo`).
    /// El lowering emite LABEL_ADDR de ese label -- un cfn cuya firma lleva
    /// `Tipo*` como primer parametro (this explicito).
    bool is_func_ref = false;
    std::string func_ref_mangled;
    FieldAccessExpr() : Expr(NodeKind::FieldAccessExpr) {}
};

struct BinaryExpr : Expr {
    BinOp op;
    std::unique_ptr<Expr> lhs;
    std::unique_ptr<Expr> rhs;
    /// Operator overloading via metodos dunder (C-1).  Cuando el type
    /// checker detecta que @c lhs es de tipo CLASS y declara el metodo
    /// dunder correspondiente al operador (@c __add__ para `+`,
    /// @c __eq__ para `==`/`!=`) cuya firma acepta @c rhs, deja aqui el
    /// nombre del metodo a invocar (@c "__add__" / @c "__eq__").  El
    /// lowering, al ver este campo no vacio, desugara @c `a OP b` a la
    /// llamada de metodo @c `a.__op__(b)` (CALLVIRT) reusando la
    /// maquinaria de @c lower_class_method_call.  Cadena vacia = sin
    /// sobrecarga; comportamiento clasico (aritmetica/concat/etc.).
    /// @c overload_negate indica que el operador era @c `!=` y NO existe
    /// @c __ne__, asi el lowering invoca @c __eq__ y niega el resultado.
    std::string overload_method;
    bool overload_negate = false;
    BinaryExpr() : Expr(NodeKind::BinaryExpr) {}
};

struct UnaryExpr : Expr {
    UnOp op;
    std::unique_ptr<Expr> operand;
    /// Operator overloading via metodo dunder (C-2).  Cuando el type
    /// checker detecta que @c operand es CLASS o STRUCT y declara
    /// @c __neg__ (metodo sin parametros sobre el tipo del operando)
    /// para @c `-x`, deja aqui el nombre del metodo.  El lowering, al
    /// ver este campo no vacio, desugara @c `-x` a la llamada de metodo
    /// @c `x.__neg__()`.  Cadena vacia = sin sobrecarga; comportamiento
    /// clasico (negacion aritmetica de primitivos).
    std::string overload_method;
    /// `&obj.metodo` (puntero a metodo LIGADO): el type checker lo desugara a
    /// un lambda `(args) => obj.metodo(args)` que captura el receptor, y lo
    /// deja aqui.  Si != null, el lowering baja ESTE lambda en vez del AddrOf.
    /// Reusa toda la maquinaria de closures (env owned, Fase 1).
    std::unique_ptr<Expr> desugared_bound_method;
    /// `&expr.metodo` con base COMPUESTA (no una variable simple, p.ej.
    /// `&getObj().metodo`): el receptor debe evaluarse UNA vez.  El type
    /// checker materializa un temporal oculto (@c bound_recv_name) y mueve la
    /// expresion base aqui (@c bound_recv_init); el lowering la evalua y la
    /// liga al temporal ANTES de bajar @c desugared_bound_method (que captura
    /// ese temporal por nombre).  Vacio/null si la base es una variable simple.
    std::string bound_recv_name;
    std::unique_ptr<Expr> bound_recv_init;
    UnaryExpr() : Expr(NodeKind::UnaryExpr) {}
};

/**
 * @brief La expresion nombra un SITIO al que se puede escribir.
 * @param e Expresion, puede ser nula.
 * @return true si es un lvalue.
 *
 * Es una pregunta de FORMA -- un nombre, un campo, un indice o un deref --,
 * asi que se contesta sobre el AST y no necesita tipos.  Vive aqui, y no mas
 * arriba con el resto de ayudas, porque necesita ver @c UnaryExpr.
 *
 * Estaba escrita DOS veces (las dos en el chequeo de `++`/`--`) y hacia falta
 * una tercera para el argumento de un parametro de salida.  Tres copias de un
 * criterio son tres sitios donde anadir una forma nueva de lvalue y acordarse
 * solo de dos.
 */
inline bool is_lvalue_expr(const Expr *e) noexcept {
    if (e == nullptr) return false;
    switch (e->kind) {
    case NodeKind::IdentExpr:
    case NodeKind::FieldAccessExpr:
    case NodeKind::IndexExpr: return true;
    case NodeKind::UnaryExpr:
        return static_cast<const UnaryExpr *>(e)->op == UnOp::Deref;
    default: return false;
    }
}

/**
 * @struct TernaryExpr
 * @brief Operador ternario `cond ? then : else` (A.38).
 *
 * Equivalente semantico a `if (cond) then_value else else_value` pero
 * como expresion.  El type checker deduce el tipo resultado como el
 * "common type" entre @c then_expr y @c else_expr (mismo
 * @c types_assignable que usa AssignExpr).  El lowering emite el patron
 * `cond -> br_cond %c, then_bb, else_bb; bb_then -> ...; bb_else -> ...;
 * merge -> phi.t [then_val, then_bb] [else_val, else_bb]`.
 *
 * Asociativo por la derecha: `a ? b : c ? d : e` == `a ? b : (c ? d : e)`.
 * Cortocircuita: solo se evalua la rama elegida (importante si las
 * sub-expresiones tienen efectos secundarios como calls).
 */
struct TernaryExpr : Expr {
    std::unique_ptr<Expr> cond;
    std::unique_ptr<Expr> then_expr;
    std::unique_ptr<Expr> else_expr;
    TernaryExpr() : Expr(NodeKind::TernaryExpr) {}
};

/**
 * @struct TryExpr
 * @brief Operador @c `?` postfix para Result -- early-return sintactico.
 *
 * Sintaxis: @c `expr?` -- donde @c expr es de tipo @c Result<V,E>.
 *
 * Equivalente a:
 * @code
 *   let __tmp = expr;
 *   if (isErr(__tmp)) { return __tmp; }
 *   value(__tmp)
 * @endcode
 *
 * Solo valido dentro de funciones cuyo return type sea @c Result<_, E>
 * compatible (mismo @c E o convertible).  El type checker valida estas
 * condiciones; el lowering desugara emitiendo una rama if-error con
 * RET via SRET copy (mismo patron que @c return X cuando la funcion
 * retorna Result).
 *
 * El tipo de la expresion es @c V (el payload Ok del Result).
 */
struct TryExpr : Expr {
    std::unique_ptr<Expr> operand; ///< Expresion de tipo Result<V,E>
    TryExpr() : Expr(NodeKind::TryExpr) {}
};

struct AssignExpr : Expr {
    AssignOp op;
    std::unique_ptr<Expr>
        target; // lvalue: IdentExpr, FieldAccess, IndexExpr o UnaryExpr Deref
    std::unique_ptr<Expr> value;
    /// Operator overloading del COMPOUND ASSIGN via dunder propio
    /// (@c __iadd__ para `+=`, @c __isub__ para `-=`, ...).  Cuando el type
    /// checker ve que @c target es de tipo CLASS o STRUCT que declara el dunder
    /// cuya firma acepta @c value, deja aqui su nombre; el lowering emite UNA
    /// llamada a `target.__iop__(value)` en vez del clasico load-op-store.
    ///
    /// Tiene dunder PROPIO y no se desugara a `target = target OP value`
    /// (@c __add__ + store) por una razon de fondo: eso son DOS operaciones.
    /// Para un tipo que promete atomicidad (@c atomic<T>) la diferencia no es
    /// de rendimiento sino de correccion -- `g += 1` tiene que ser UNA
    /// instruccion indivisible, no leer-sumar-escribir.  Cadena vacia = sin
    /// sobrecarga; comportamiento clasico.
    std::string overload_method;
    AssignExpr() : Expr(NodeKind::AssignExpr) {}
};

struct CallExpr : Expr {
    std::unique_ptr<Expr> callee;
    std::vector<std::unique_ptr<Expr>> args;
    /// Argumentos de tipo @c <T,U,...> para builtins comptime
    /// (@c sizeof<T>, @c offsetof<T>, etc.).  Vacio para llamadas
    /// normales.  Solo poblado por el parser cuando el callee es un
    /// IdentExpr cuyo nombre matchea un builtin comptime conocido y
    /// va seguido de @c <...>.  El type checker valida que el numero
    /// de type args coincida con la aridad esperada del builtin.
    std::vector<std::unique_ptr<TypeNode>> type_args;
    /** Nombre del tipo cuyo constructor `comptime T(expr)` resuelve esta
     * llamada.  Vacio en el caso normal.  Se rellena cuando ninguna
     * sobrecarga encajaba y el tipo declara ese constructor: el lowering
     * lo usa para invocarlo en tiempo de compilacion y materializar el
     * valor donde estaba la llamada. */
    std::string comptime_ctor_type;
    /// A.43.10: macros Lisp con quote/emit/splicing.  Cuando el type
    /// checker detecta @c comptime_emit_expr("texto"), parsea el
    /// texto como una expresion Vesta, lo type-checa en el contexto
    /// actual y guarda el AST resultante aqui.  El lowering, al ver
    /// este campo no-null, baja la expresion sustituida en lugar de
    /// emitir una llamada.  Equivalente al `splice` de Lisp/Scheme
    /// para emitir codigo al AST runtime (no solo eval comptime).
    std::unique_ptr<Expr> macro_expanded;
    /// Function pointers: el type checker marca @c true cuando el callee es
    /// una expresion de tipo FUNCTION (variable/cast/etc.), no una llamada
    /// directa por nombre.  El lowering baja a CALLIND (llamada indirecta a
    /// traves del puntero que resulta de evaluar @c callee).
    bool is_indirect_call = false;
    /// Sobrecarga de `{}`: el postfijo @c `a{3,4,5}` produce un CallExpr con
    /// este flag, que el type checker resuelve a @c `a.__braces__(3,4,5)` en
    /// lugar de a @c __call__.  Son operadores DISTINTOS: un tipo puede
    /// definir uno, el otro o los dos.  No confundir con @c `T a = {2,3,3}`
    /// (init-list de campos), que es un InitListExpr y no pasa por aqui.
    bool is_braces_call = false;
    /// `Struct()` sin constructores declarados y 0 args: constructor por
    /// defecto, equivalente a `Struct{}`.  El type checker lo marca; el
    /// lowering emite los valores por defecto de los campos (o cero) en vez
    /// de una llamada.
    bool is_default_struct_ctor = false;
    CallExpr() : Expr(NodeKind::CallExpr) {}
};

/**
 * @struct ThisExpr
 * @brief Referencia implicita al receptor de un metodo de instancia.
 *
 * Aparece dentro del cuerpo de un metodo de clase (no constructor).  El
 * type checker valida que el contexto es un metodo de instancia y le
 * asigna como tipo la clase receptora.  El lowering lo baja al primer
 * parametro implicito del metodo (slot reservado para el receptor).
 */
struct ThisExpr : Expr {
    ThisExpr() : Expr(NodeKind::ThisExpr) {}
};

/**
 * @struct SuperCallExpr (BugFix R1)
 * @brief @c super(args) -- delegacion al constructor de la superclase
 *        dentro del cuerpo de un constructor.
 *
 * Solo valida dentro del body de un ctor de clase con super_name no
 * vacio.  El type checker resuelve al constructor de la super, valida
 * la aridad y tipos de args.  El lowering emite CALLVIRT a la
 * vtable_index del super_ctor con this como receptor.
 */
struct SuperCallExpr : Expr {
    std::vector<std::unique_ptr<Expr>> args;
    SuperCallExpr() : Expr(NodeKind::SuperCallExpr) {}
};

/**
 * @struct SuperMethodCallExpr (BugFix R1)
 * @brief @c super.method(args) -- llamada a metodo de la superclase
 *        evitando el dispatch virtual.
 *
 * Util para overrides que delegan al super.  El lowering emite
 * @c callsuper (opcode 0xFC) o equivalent que dispatcha a la
 * vtable_index del SUPER directamente, no del receiver dinamico.
 */
struct SuperMethodCallExpr : Expr {
    std::string method_name;
    std::vector<std::unique_ptr<Expr>> args;
    SuperMethodCallExpr() : Expr(NodeKind::SuperMethodCallExpr) {}
};

/**
 * @struct NewExpr
 * @brief Creacion de instancia: @c new ClassName(args).
 *
 * El type checker resuelve @c class_name al ClassInfo correspondiente
 * y valida que existe un constructor que encaja con la lista de
 * argumentos.  El lowering emite findclass + newobj + callvirt al
 * indice del constructor en la vtable.
 */
struct NewExpr : Expr {
    std::string class_name;
    std::vector<std::unique_ptr<Expr>> args;
    /// Argumentos de tipo para @c new Box<i32>(42).
    /// Vacio para clases no genericas.  El type checker monomorphiza
    /// la clase plantilla y reemplaza class_name con el nombre del
    /// tipo concreto generado (ej. "Box_i32").
    std::vector<std::unique_ptr<TypeNode>> type_args;
    /// bug4: array allocation `new T[N]`.  Si esta seteado, el
    /// expression aloca un array de N elementos del tipo `class_name`
    /// en host heap (via malloc).  El resultado es un host_ptr al
    /// buffer de N * sizeof(T) bytes.  args queda vacio en este caso.
    std::unique_ptr<Expr> array_size;
    /// Z.6: marca que esta instancia debe alocarse en el SharedHeap
    /// (cross-process visible).  Lo setea @c lower_var_decl cuando el
    /// var-decl padre tiene @c is_shared=true.  El lowering despacha
    /// a @c __new_<Class>_shared (que emite el opcode @c newobjs en
    /// lugar de @c newobj).
    bool is_shared = false;
    /// gc<T> opt-in (`import vx.gc`): el var-decl padre es @c gc<Class>.  Lo
    /// setea @c lower_var_decl; el lowering despacha a @c __new_<Class>_gc
    /// (aloca con @c vx_gc_alloc + marca @c is_gc_object) y NO registra
    /// cleanup RAII (el GC colecta, incl. ciclos).
    bool is_gc = false;
    /// Bug fix 2026-05-23: indica que @c class_name YA fue mutado a su
    /// forma mangled (Node_i32 etc).  Sin este flag, re-llamadas a
    /// @c check_new sobre el mismo NewExpr (e.g. por compound assign
    /// que re-evalua RHS) concatenarian el sufijo otra vez ("Node_i32_i32").
    bool is_mangled = false;
    NewExpr() : Expr(NodeKind::NewExpr) {}
};

// SpawnExpr se define DESPUES de BlockStmt porque lo referencia.

/**
 * @struct IndexExpr
 * @brief Subscript: base[index].
 *
 * @c base es siempre un puntero (T*) y @c index un entero.
 * El type checker valida los tipos y rellena @c result_type con el
 * tipo apuntado.  El lowering desugara `p[i]` a `*(p + i*sizeof(*p))`,
 * reutilizando los mismos LOAD/STORE de los punteros.
 *
 * Es un lvalue: `p[i] = v` se acepta como destino de AssignExpr.
 */
struct IndexExpr : Expr {
    std::unique_ptr<Expr> base;
    std::unique_ptr<Expr> index;
    /// Operator overloading via metodo dunder (C-2).  Cuando el type
    /// checker detecta que @c base es CLASS o STRUCT y declara
    /// @c __index__(i) cuya firma acepta @c index para @c `base[index]`
    /// (LECTURA), deja aqui @c "__index__".  El lowering desugara
    /// @c `base[index]` a la llamada @c `base.__index__(index)`.  Cadena
    /// vacia = comportamiento clasico (subscript de puntero/array).
    std::string overload_method;
    /// Operator overloading (escritura): cuando este IndexExpr es el
    /// destino de un @c AssignExpr (@c `base[index] = value`) y @c base
    /// es CLASS o STRUCT que declara @c __index_set__(index, value), el
    /// type checker deja aqui @c "__index_set__".  El lowering del assign
    /// desugara @c `base[index] = value` a la llamada
    /// @c `base.__index_set__(index, value)`.  Cadena vacia = sin
    /// sobrecarga de escritura (subscript clasico de puntero/array).
    std::string index_set_method;
    /// String Inc 3 (native_poo_): slice `s[a..b]` (exclusivo) o
    /// `s[a..=b]` (inclusivo).  Cuando @c is_range es true, @c index
    /// es el limite inferior @c a y @c range_hi es el limite superior
    /// @c b.  Hoy solo aplica al value-type `string` en modo native_poo_
    /// (devuelve una COPIA owned de los bytes [a, b)); RAII libera la
    /// copia.  La vista zero-copy (`borrow<string>`) llegara con borrow.
    bool is_range = false;          ///< true para `s[a..b]` / `s[a..=b]`.
    bool range_inclusive = false;   ///< true para `..=` (incluye b).
    std::unique_ptr<Expr> range_hi; ///< limite superior @c b del rango.
    /// Overlay F3b: true si @c base es `v.arr` (campo array de un overlay).
    /// El lowering computa `base_overlay + pos + index*stride` (escala por el
    /// STRIDE del overlay, no por sizeof).  @c result_type = tipo del elemento.
    bool is_overlay_array = false;
    IndexExpr() : Expr(NodeKind::IndexExpr) {}
};

// -------------------------------------------------------------------
// Statements.
// -------------------------------------------------------------------

/**
 * @struct Stmt
 * @brief Nodo abstracto raiz para todos los statements.
 */
struct Stmt : Node {
    explicit Stmt(NodeKind k) : Node(k) {}
};

struct BlockStmt : Stmt {
    std::vector<std::unique_ptr<Stmt>> body;
    BlockStmt() : Stmt(NodeKind::BlockStmt) {}
};

/**
 * @struct SpawnExpr
 * @brief @c spawn @c { @c body @c }: arranca un proceso hijo en el scheduler
 *        actual y devuelve su PID encoded como @c i64.
 *
 * El @c body se compila como una funcion sintetica @c __spawn_<N>(void)
 * que termina con @c hlt (no @c ret).  El lowering del @c SpawnExpr
 * emite @c mov + @c spawn con la direccion de esa funcion.  El PID
 * encoded del hijo (devuelto en @c R0 por el opcode @c spawn) se
 * captura en el SSA value de la expresion.
 *
 * No hay captura lexica en MVP: el body solo accede a su propio
 * estado y al pasado via mailbox (@c msgsend / @c msgrecv).  Closures
 * con captura llegan en  B.
 */
struct SpawnExpr : Expr {
    /// @brief politica de placement del proceso hijo.
    ///
    /// - @c Auto    : el VM elige automaticamente el scheduler propietario
    ///                (round-robin entre todos los schedulers cuando hay
    ///                mas de uno; mismo scheduler que el padre si hay uno
    ///                solo).  Sintaxis: `spawn { body }`.
    /// - @c Here    : el hijo se asigna al MISMO scheduler que el padre
    ///                (ruta cooperativa, sin overhead de IPC cross-thread).
    ///                Sintaxis: `spawn here { body }`.
    /// - @c Pinned  : el hijo se fija al scheduler indicado en
    ///                @c sched_idx (modulo num_schedulers para evitar
    ///                fuera de rango).  Sintaxis: `spawn on(expr) { body }`.
    ///
    /// Spawn distribuido cross-node se modela via @c RSpawnExpr en
    /// lugar de extender este enum, porque cambia la semantica del
    /// valor de retorno (Future<T> vs PID).
    enum class Policy : uint8_t { Auto = 0, Here = 1, Pinned = 2 };
    Policy policy = Policy::Auto;

    std::unique_ptr<Expr> sched_idx; ///< Solo @c Pinned: indice del scheduler.
    std::unique_ptr<BlockStmt> body;
    SpawnExpr() : Expr(NodeKind::SpawnExpr) {}
};

/**
 * @struct RSpawnExpr
 * @brief rspawn(node_idx) { body } -- spawn distribuido cross-node.
 *
 * Diferencias clave con SpawnExpr:
 *   - Devuelve `i64` que es un GcHandle de FutureObject (NO un PID).
 *   - El body se ejecuta en el nodo remoto especificado por @c node_idx
 *     (indice en el NodeRegistry de la VM, registrado via `--dist-add-node`).
 *   - El valor de @c return en el body se captura en R0 antes de hlt; el
 *     runtime remoto envia ese valor de vuelta via VDP_FUTURE_FULFILL.
 *   - El caller usa `await fut` para bloquear hasta que llegue el valor.
 *
 * Patron tipico:
 *   @code
 *     i64 fut = rspawn(node) { return 42; };
 *     i64 r   = await fut;  // r == 42 cuando el remoto responde
 *   @endcode
 *
 * Si la VM no tiene `dist_runtime->start()` invocado o el node_idx no existe,
 * el bytecode `rspawn` devuelve handle invalido (0xFFFFFFFF) y `await` falla.
 */
struct RSpawnExpr : Expr {
    std::unique_ptr<Expr> node_idx;  ///< Indice de nodo remoto (entero).
    std::unique_ptr<BlockStmt> body; ///< Cuerpo a ejecutar remotamente.
    RSpawnExpr() : Expr(NodeKind::RSpawnExpr) {}
};

/**
 * @struct LambdaExpr
 * @brief Expresion lambda / closure inline con captura lexica.
 *
 * Sintaxis aceptada por el parser:
 * @code
 *   (i32 x, i32 y) => x + y          // expression-bodied (un solo return)
 *   (x, y)         => x + y          // tipos deducidos por inferencia
 *   ()             => 42             // sin parametros
 *   (i32 n)        => { return n*n; } // bloque (multiples stmts)
 * @endcode
 *
 * Lowering (vease Lowering::lower_lambda_expr):
 *   - Cada lambda distinta produce una funcion sintetica @c __lambda_<N>
 *     en el modulo IR (acumulada en @c pending_spawn_helpers_ junto con
 *     las de @c spawn / @c rspawn).
 *   - Los parametros formales del helper son los mismos que los de la
 *     lambda; el helper recibe ademas los captures via el registro @c R14
 *     (calling convention compartida con @c callrawclosure).
 *   - En el call site donde se construye la lambda, el lowering aloca
 *     un bloque de captures de @c (8 * n_captures) bytes en la pila del
 *     caller (@c subsp), copia los valores capturados ahi y devuelve un
 *     valor SSA "function value" de 16 bytes alocado tambien en la pila:
 *         `[+0 i64 fn_addr][+8 i64 env_addr]`.
 *
 * Para invocar el function value, vease @c CallExpr lowering: carga
 * fn_addr y env_addr del slot de 16 bytes, mete env_addr en R14 y
 * emite @c callvmr fn_addr.  Cero overhead vs llamada directa cuando
 * no hay captures (env_addr = 0, ignorado por el helper).
 *
 * MVP: el env_addr vive en la pila del caller y la lambda solo es valida
 * dentro del scope donde se creo.  Escape detection (closures que
 * sobreviven al scope) y promocion a heap quedan para una fase posterior.
 */
/**
 * @struct MatchArm
 * @brief Una rama de un @c match: pattern + body (destructuring de ADT).
 *
 * El patron puede ser:
 *   - Variant simple: @c Color.Red    (variant_name="Red", bindings vacio)
 *   - Variant con bindings: @c Color.Green(n)  (variant_name="Green",
 * bindings=["n"])
 *   - Comodin (default): @c _   (variant_name="_", bindings vacio)
 *
 * El body es un Stmt; tipicamente un bloque (`=> { ... }`) o una
 * expresion-bodied (`=> expr;` reescrita por el parser a un return).
 * Los bindings introducen variables nuevas en el scope del body con
 * los tipos declarados de los payload fields de la variante.
 */
struct MatchArm {
    std::string variant_name; ///< "Red", "Green", "_" (default), etc.
    std::vector<std::string>
        bindings; ///< Nombres locales para los payload fields.
    /// Patron de VALOR para `match` sobre escalares (enteros/chars): `case 1
    /// =>`, `case 'a' =>`.  no-owning-al-cuerpo IntLitExpr/CharLitExpr.  null
    /// en las arms de variante ADT y en el default `_`.  El type checker exige
    /// que el scrutinee sea entero/char y todos los patrones literales de ese
    /// tipo. Tambien es el literal de un match sobre string (StringLitExpr).
    std::unique_ptr<Expr> value_pattern;
    /// Fin (alto) de un patron de RANGO `case a..b =>` (exclusivo) o
    /// `case a..=b =>` (inclusivo), donde @c value_pattern es el inicio (bajo).
    /// null = patron de valor unico.  Solo para enteros/chars.
    std::unique_ptr<Expr> value_pattern_hi;
    /// true si el rango es inclusivo (`..=`): `a <= v <= b`.  false si es
    /// exclusivo (`..`): `a <= v < b`.  Solo relevante si value_pattern_hi.
    bool range_inclusive = false;
    std::unique_ptr<Stmt> body;
    /// Bug fix 2026-05-23: guard opcional `case Pat if expr =>`.  Si
    /// presente, el lowering evalua la expr DESPUES del tag match;
    /// solo entra al body si guard es true.  Si false, continua al
    /// siguiente arm.  La exhaustividad se relaja: la presencia de
    /// guards permite que el match no sea estaticamente exhaustivo.
    std::unique_ptr<Expr> guard;
    SourceLoc loc;
};

/**
 * @struct MatchExpr
 * @brief @c match expr @c { case Variant(bindings) => body; ... }
 *
 * Estrategia de lowering:
 *   - Carga el tag del scrutinee (i64 en offset 0 del slot enum).
 *   - Si todas las arms son variantes con tag entero contiguo y
 *     conocido en compile time -> emite IrOp::JUMPTABLE para dispatch
 *     O(1) (bytecode 0x27).
 *   - Si hay arms tipo class hierarchy -> usa IrOp::TYPESWITCH (0x28).
 *   - En cada arm: bind de los payload fields como SSA values nuevos
 *     leyendo del slot del scrutinee + offsets fijos, luego lower del
 *     body.  Las arms terminan con @c jmp end_label.
 *   - Si no es exhaustive y no hay default arm, el type checker
 *     reporta error en compile time.
 *
 * El SSA value de la expresion @c match es VOID a nivel global del IR;
 * para usar match como expresion (e.g. asignar el resultado a una
 * variable), se modela en el frontend asignando el resultado dentro
 * de cada arm a una variable comun.  En MVP @c match es un statement-
 * like dentro de @c ExprStmt.
 */
struct MatchExpr : Expr {
    std::unique_ptr<Expr> scrutinee; ///< El valor a inspeccionar (tipo enum).
    std::vector<MatchArm> arms;      ///< Arms en orden de prioridad.
    MatchExpr() : Expr(NodeKind::MatchExpr) {}
};

/**
 * @struct InitListExpr
 * @brief Inicializador de lista C-style: `{ e0, e1, ... }`
 *        o `{ .field = e0, .field2 = e1, ... }` para structs designado.
 *
 * Solo valido como inicializador de var-decl con tipo array, struct, o
 * struct anidado.  Para arrays solo se admite la forma posicional
 * (sin .field).  Para structs se admiten ambas formas: positional (en
 * orden de declaracion) o designado (orden libre, no requiere todos).
 *
 * Si @c is_designated es true, @c field_names tiene N entradas
 * paralelas a @c elements.  Si es false, @c field_names esta vacio.
 */
struct InitListExpr : Expr {
    std::vector<std::unique_ptr<Expr>> elements;
    std::vector<std::string> field_names;
    bool is_designated = false;
    /// Tipo destino anotado por el type checker desde el contexto.
    /// Para `unique<Punto> p = {.x=10, .y=20}` el desugar marca aqui
    /// "Punto" para que el lowering sepa que el init list construye
    /// un struct Punto y emita los STOREs en posiciones correctas.
    /// Vacio = init list contextual (el type checker resuelve por
    /// uso en var-decl u otros sitios).
    std::string target_type_name;
    InitListExpr() : Expr(NodeKind::InitListExpr) {}
};

/**
 * @struct CastExpr
 * @brief Cast C-style: `(T) expr`.
 *
 * El parser lo reconoce solo cuando el contenido del parentesis es
 * un type-node valido (incluyendo @c VirtualPtr<T>, @c T*, primitivos
 * y aliases declarados via typedef/using).  Si el parentesis contiene
 * una expresion (e.g. `(a + b)`), el parser usa la rama de expresion
 * agrupada y NO genera @c CastExpr.
 *
 * El type checker valida la conversion: cualquier ptr->ptr es bitcast
 * (mismo bit-pattern), conversiones numericas usan el cast IR
 * apropiado (ZEXT/SEXT/TRUNC/FTOI/...), y el flag @c is_virtual del
 * tipo destino se propaga al SSA value resultante para que el LOAD/
 * STORE posterior emita @c mov vs @c movh correctamente.
 */
struct CastExpr : Expr {
    std::unique_ptr<TypeNode> target_type; ///< Tipo destino del cast.
    std::unique_ptr<Expr> operand;         ///< Expresion a convertir.
    CastExpr() : Expr(NodeKind::CastExpr) {}
};

struct LambdaExpr : Expr {
    /// Parametros de la lambda con tipos opcionales (si el parser ve
    /// @c (x, y) => ... sin tipos, el type checker debe inferirlos
    /// del contexto, e.g. de la firma de la variable destino).
    std::vector<std::unique_ptr<ParamDecl>> params;
    /// Tipo de retorno declarado.  null = inferido del @c return del body
    /// (o del tipo del expression-body).
    std::unique_ptr<TypeNode> return_type;
    /// Cuerpo: siempre un @c BlockStmt.  Las lambdas expression-bodied
    /// @c (x) => expr se reescriben en el parser a @c (x) => { return expr; }.
    std::unique_ptr<BlockStmt> body;

    // ----- Llenado por el TypeChecker -----
    /// Nombres de las variables del outer scope que el body referencia
    /// y que por tanto deben copiarse al env.  Se computa durante el
    /// type check del body recorriendo IdentExpr y comprobando si el
    /// nombre se resuelve en un scope ANCESTRO del scope de la lambda.
    std::vector<std::string> captures;
    /// Tipos de los captures (paralelo a @c captures).  Lo necesita el
    /// lowering para decidir el ancho del LOAD/STORE en el env block y
    /// asignar offsets correctos.
    std::vector<Type> capture_types;

    /// Subconjunto de @c captures que aparece en lhs de una
    /// asignacion dentro del body (mutables).  Estas se promueven a
    /// address-taken en el scope outer y el env block guarda su
    /// PUNTERO en lugar del valor: reads/writes en el body son
    /// LOAD/STORE indirectos via el puntero, asi las modificaciones
    /// se ven fuera del scope de la lambda (capture-by-reference).
    /// Captures NO mutadas siguen el modelo by-value (valor copiado
    /// al env, sin overhead de indireccion).
    std::vector<std::string> mutable_captures;

    // ----- Llenado por el Lowering -----
    /// Nombre del helper sintetico generado (@c __lambda_<N>).  El call
    /// site lo usa para emitir @c mov r_fn, @c \@Absolute("code." + name).
    std::string synthetic_name;
    /// true si el env block se aloca en HEAP RAW
    /// (RAW_ALLOC) en lugar de en STACK (ALLOCA).  Lo activa el
    /// lowering cuando la funcion contenedora retorna FUNCTION; el
    /// helper sintetico marca @c env_ptr.is_host_ptr=true para que
    /// los LOAD del prologue de captures emitan @c movh (host mem)
    /// en lugar de @c mov (vm mem).
    bool env_in_heap = false;
    /// true si el env es PROPIEDAD del objeto contenedor (el closure se
    /// almacena en un campo).  Implica @c env_in_heap, pero el env se aloca
    /// con @c RAW_ALLOC host SIN etiqueta (no GC, no "__closure_env"): el
    /// destructor del contenedor lo libera (RAII), igual que un campo
    /// @c unique<T>.  Modelo "sin GC" -- ver
    /// doc/VMdoc/Vesta/ClosuresEnCampos.md.
    bool env_owned_by_field = false;

    LambdaExpr() : Expr(NodeKind::LambdaExpr) {}
};

/**
 * @struct VarDeclStmt
 * @brief Declaracion de variable local (dentro de un bloque o init de for).
 */
struct VarDeclStmt : Stmt {
    std::unique_ptr<TypeNode> type;
    std::string name;
    std::unique_ptr<Expr> init; ///< null si no hay inicializador.
    bool is_const = false;
    /** Direccion declarada (`in i64* p`), ver @c ParamDir.
     *
     * En un parametro la marca dice dos cosas -- que puede hacerse por ahi, y
     * que HACE la funcion --; en una variable solo queda la primera, que es un
     * PERMISO: por un `in` solo se lee.
     *
     * Sigue siendo un eje distinto de `const`, con el que compone:
     * `in nonnull i64* p` y `in const i64* p` se escriben los dos, y cada
     * palabra sigue diciendo lo suyo. */
    ParamDir dir = ParamDir::None;
    /// marca `comptime const NAME = expr;` local.  El type
    /// checker evalua el init y registra en
    /// @c TypeChecker::comptime_const_locals_; el lowering omite la
    /// emision (no genera ALLOCA ni STORE).
    bool is_comptime = false;
    /// A.43.7: marca `auto NAME = expr;` o `var NAME = expr;` con
    /// inferencia local de tipo.  El parser deja @c type=nullptr y
    /// setea @c infer_type=true; el type checker computa el tipo del
    /// @c init y lo aplica al binding sin requerir TypeNode en el AST.
    bool infer_type = false;
    /// Liberador ADOPTADO del inicializador cuando el tipo se escribio sin el
    /// (`unique<T> p = unique_with(h, del);`).  Lo pone el comprobador de
    /// tipos y lo lee el bajado, que resuelve el tipo desde el nodo y por si
    /// solo no veria la adopcion.  Vacio = el de por defecto.
    std::string declared_deleter;
    /// Z.6: marca `shared T name = new T()` -- el storage class
    /// dispatcha al SharedHeap en lugar del gc_heap local.  El handle
    /// resultante tiene bit 31 (SHARED_HANDLE_BIT) set.  Stdlib clases
    /// son agnosticas; solo el var-decl decide.
    bool is_shared = false;
    ///  AS inc.2: storage-class `register("reg") T name;` -- la
    /// variable vive en el registro fisico nombrado (NASM).  En el
    /// cuerpo @c asm el programador usa el registro directamente, no el
    /// nombre Vesta.  Vacio = sin storage register (var-decl normal).  Lo
    /// consumen el backend port-C (inc.3) y el JIT (inc.5).
    std::string reg_binding;
    /// storage-class `static T name = init;` local -- la variable tiene
    /// DURACION ESTATICA (una sola instancia, no en el stack) y su init corre
    /// UNA VEZ (init-once).  El lowering la emite como global (gdata) con el
    /// nombre mangleado por funcion; si el init es constante lo hornea en el
    /// dato, si es dinamico envuelve el init con un guard booleano global.
    /// Estado persistente entre llamadas (mismo contrato que `static` de C).
    bool is_static = false;
    VarDeclStmt() : Stmt(NodeKind::VarDeclStmt) {}
};

struct ExprStmt : Stmt {
    std::unique_ptr<Expr> expr;
    ExprStmt() : Stmt(NodeKind::ExprStmt) {}
};

/**
 * @struct ComptimeBlockStmt
 * @brief bloque `comptime { ... }` -- scope para comptime const,
 *        comptime for y static_assert.
 *
 * Todo lo declarado dentro vive en un scope comptime nuevo (push_/
 * pop_comptime_scope en el type checker).  El bloque NO emite
 * codigo runtime; el lowering lo trata como no-op.  Runtime stmts
 * dentro son error (no se permite).
 */
struct ComptimeBlockStmt : Stmt {
    std::vector<std::unique_ptr<Stmt>> stmts;
    ComptimeBlockStmt() : Stmt(NodeKind::ComptimeBlockStmt) {}
};

/**
 * @struct ComptimeForStmt
 * @brief `comptime for (i in lo..hi) { body }` unrolled.
 *
 * El type checker evalua @c lo y @c hi en compile-time.  Para cada
 * valor de @c var_name en [lo, hi) (o [lo, hi] si @c inclusive), el
 * lowering CLONA el body con @c var_name bindeado al valor concreto
 * (registrado en @c comptime_const_locals_).  Result: N copias del
 * body emitidas en secuencia, sin loop runtime.  Cuerpo emite
 * codigo runtime normalmente.
 */
struct ComptimeForStmt : Stmt {
    std::string var_name; ///< nombre del index
    std::unique_ptr<Expr> lo_expr;
    std::unique_ptr<Expr> hi_expr;
    bool inclusive = false;     ///< true para `..=`
    std::unique_ptr<Stmt> body; ///< BlockStmt usualmente
    ComptimeForStmt() : Stmt(NodeKind::ComptimeForStmt) {}
};

struct IfStmt : Stmt {
    std::unique_ptr<Expr> cond;
    std::unique_ptr<Stmt> then_branch;
    std::unique_ptr<Stmt> else_branch; ///< null si no hay else.
    /**
     * @brief marca `comptime if (cond) { ... }`.
     *
     * El type checker exige que `cond` se evalue 100% en compile-time
     * (literales + builtins comptime + operadores logicos/aritmeticos
     * sobre constantes).  El lowering descarta la rama no tomada
     * COMPLETAMENTE -- no se baja a IR, no se emite bytecode --
     * eliminando branches y phi nodes.  Util para generic code que
     * elige implementaciones por tipo (sizeof<T>() <= 8 -> by-value
     * vs by-pointer) sin coste runtime.
     */
    bool is_comptime = false;
    IfStmt() : Stmt(NodeKind::IfStmt) {}
};

struct WhileStmt : Stmt {
    std::unique_ptr<Expr> cond;
    std::unique_ptr<Stmt> body;
    WhileStmt() : Stmt(NodeKind::WhileStmt) {}
};

/**
 * @struct DoWhileStmt
 * @brief Bucle 'do { body } while (cond);' con primera iteracion garantizada.
 *
 * Semantica: ejecuta @c body una vez, evalua @c cond y, si es verdadera,
 * repite la ejecucion del body.  Equivalente a un while que se ejecuta
 * al menos una vez.  El lowering lo baja a un patron CFG dedicado para
 * evitar duplicar el body en el AST: entry -> body -> header -> body|exit.
 */
struct DoWhileStmt : Stmt {
    std::unique_ptr<Stmt> body;
    std::unique_ptr<Expr> cond;
    DoWhileStmt() : Stmt(NodeKind::DoWhileStmt) {}
};

/**
 * @struct ForStmt
 * @brief @c for(init; cond; step) body al estilo C.
 *
 * Cualquiera de los tres campos init/cond/step puede ser nulo:
 *   - init nulo  => no hay inicializador.
 *   - cond nulo  => bucle infinito (semantica de while(true)).
 *   - step nulo  => no hay paso por iteracion.
 */
struct ForStmt : Stmt {
    std::unique_ptr<Stmt> init;
    std::unique_ptr<Expr> cond;
    std::unique_ptr<Expr> step;
    std::unique_ptr<Stmt> body;
    ForStmt() : Stmt(NodeKind::ForStmt) {}
};

struct ReturnStmt : Stmt {
    std::unique_ptr<Expr> value; ///< null si return sin valor.
    ReturnStmt() : Stmt(NodeKind::ReturnStmt) {}
};

/**
 * @struct ForEachStmt
 * @brief @c for (T name : collection) body.
 *
 * Soportamos colecciones que sean arrays nativos con tamano conocido
 * en compile time (T[N]) o decay-to-pointer (T[]).  El lowering
 * desazucara a un counted loop usando un indice oculto.  Para T[N]
 * usamos N como cota; para T[] el caller debe pasar un tamano
 * (limitacion actual: solo @c T[N] inline esta verificado).
 */
struct ForEachStmt : Stmt {
    std::unique_ptr<TypeNode> iter_type;
    std::string iter_name;
    std::unique_ptr<Expr> iter_expr;
    std::unique_ptr<Stmt> body;
    ForEachStmt() : Stmt(NodeKind::ForEachStmt) {}
};

struct BreakStmt : Stmt {
    BreakStmt() : Stmt(NodeKind::BreakStmt) {}
};
struct ContinueStmt : Stmt {
    ContinueStmt() : Stmt(NodeKind::ContinueStmt) {}
};

/// `goto label;` -- salto incondicional a una etiqueta declarada en
/// la funcion actual.  Las labels son visibles en toda la funcion;
/// se permiten gotos forward o backward.  Igual que en C.
struct GotoStmt : Stmt {
    std::string label;
    GotoStmt() : Stmt(NodeKind::GotoStmt) {}
};

/// `label:` -- declaracion de etiqueta dentro del cuerpo de una
/// funcion.  El statement que sigue se asocia con la etiqueta.
/// Multiples labels seguidas son permitidas.
struct LabelStmt : Stmt {
    std::string name;
    LabelStmt() : Stmt(NodeKind::LabelStmt) {}
};

/**
 * @struct CatchClause
 * @brief Una clausula catch dentro de un try.
 *
 * Captura excepciones de la clase @c exc_class_name (o de cualquiera
 * de sus subclases por el dispatcher de @c do_throw).  Si
 * @c exc_class_name esta vacio, es un catch-all.  El parametro
 * @c var_name (puede estar vacio) recibe el objeto excepcion
 * lanzado (tipo equivalente a @c exc_class_name).
 */
struct CatchClause {
    SourceLoc loc;
    std::string exc_class_name; ///< vacio = catch-all
    std::string var_name;       ///< vacio = sin binding
    std::unique_ptr<BlockStmt> body;
};

/**
 * @struct TryStmt
 * @brief Statement try/catch (sin finally).
 *
 * Lowering: emite @c tryenter ANTES del body con (handler, type) del
 * primer catch.  El body normal termina con @c tryleave.  El handler
 * binda el objeto excepcion (que do_throw deja en r0) a la variable
 * del catch y ejecuta el body del catch.  Multi-catch se serializa:
 * cada catch tiene su propio tryenter consecutivo.
 */
struct TryStmt : Stmt {
    std::unique_ptr<BlockStmt> body;
    std::vector<CatchClause> catches;
    std::unique_ptr<BlockStmt> finally_body; ///< nullptr si no hay finally
    TryStmt() : Stmt(NodeKind::TryStmt) {}
};

/**
 * @struct ThrowStmt
 * @brief @c throw expr; lanza una excepcion con el objeto resultante.
 */
struct ThrowStmt : Stmt {
    std::unique_ptr<Expr> value;
    ThrowStmt() : Stmt(NodeKind::ThrowStmt) {}
};

/**
 * @struct SynchronizedStmt
 * @brief @c synchronized (obj) @c { @c ...body... } adquiere el monitor
 *        del objeto @p obj con @c monenter al entrar y lo libera con
 *        @c monexit a la salida (incluyendo salida por excepcion).
 *
 * Lowering: emite @c monenter ANTES del body y @c monexit DESPUES del
 * body con el handle del objeto en un registro local.  Para garantizar
 * la liberacion en caso de excepcion, el lowering envuelve el body en
 * un try/finally implicito: el bloque finally hace @c monexit.
 *
 * Dentro del body, los builtins @c wait(), @c notify() y @c notifyAll()
 * sin argumento operan sobre el monitor de la expresion @p target del
 * synchronized mas cercano (resuelto por el type checker via stack).
 * No los implementamos como tokens dedicados sino como funciones
 * builtin reconocidas en lower_call.
 */
struct SynchronizedStmt : Stmt {
    std::unique_ptr<Expr> target; ///< Objeto cuyo monitor se adquiere.
    std::unique_ptr<BlockStmt> body;
    SynchronizedStmt() : Stmt(NodeKind::SynchronizedStmt) {}
};

/**
 * @struct AsmStmt
 * @brief @c asm [quals] @c { @c ...NASM... } @c clobbers(...) -- ensamblador
 *        en linea nativo ( AS), distinto del @c @Asm whole-function
 *        (que es bytecode .vel de la VM).
 *
 * El cuerpo es texto NASM Intel verbatim, capturado por raw-slicing del
 * source (no se tokeniza).  Las variables Vesta se enlazan a registros via
 * la storage-class @c register("reg") en su declaracion (Incremento 2);
 * en el Incremento 1 el cuerpo es opaco.  Los calificadores siguen la
 * semantica C (@c volatile por defecto): @c nomem, @c preserves_flags,
 * @c pure (= nomem + preserves_flags).  La clausula @c clobbers("rdx",
 * "memory", "flags") lista registros/efectos que el bloque destruye.
 *
 * Lowering: baja a @c IrOp::INLINE_ASM (marker host, distinto de RAW_ASM
 * que es asm de la VM).  Backends que lo materializan: port-C, JIT, AOT.
 * El backend bytecode/interp NO lo soporta y reporta error claro.
 */
/**
 * @struct AsmOperand
 * @brief  AS inc.7: un enlace de la lista `( ... )` de un @c asm.  Modelo
 *        moderno "read-back": la CLASE de registro es el tipo del enlace
 *        (@c reg = el compilador elige; @c rax/rcx/... = fijo por ISA;
 *        @c xmm/ymm = vector; @c mem = memoria).  La DIRECCION se infiere del
 *        uso: con inicializador = entrada; el nombre leido tras el bloque =
 *        salida; sin inicializador ni lectura posterior = scratch.
 */
struct AsmOperand {
    std::string reg_class; ///< "reg" | "rax".."r15" | "xmm"/"ymm"/... | "mem".
    std::string name;      ///< placeholder usado en el cuerpo NASM.
    std::unique_ptr<Expr>
        init;      ///< valor de entrada (nullptr = scratch/out-only).
    SourceLoc loc; ///< para diagnosticos.
};

/**
 * @enum AsmLevel
 * @brief Nivel de analisis de un bloque de inline asm (3 niveles):
 *  - @c Analyzable (default, `asm { }`): el compilador lo entiende, saca
 *    efectos/coste y PUEDE reoptimizarlo (reordenar por latencia/puertos).
 *  - @c Volatile (`asm volatile { }`): se analiza para contratos, pero se
 *    emite VERBATIM (no se reordena ni pliega alrededor).
 *  - @c Raw (`asm raw { }`): caja negra, verbatim, cero analisis; el usuario
 *    posee la correccion y declara sus contratos a mano.
 */
enum class AsmLevel { Analyzable, Volatile, Raw };

struct AsmStmt : Stmt {
    std::string body; ///< Cuerpo NASM Intel verbatim (raw-slice del source).
    /// Nivel de analisis (Analyzable por defecto).  Lo consume el futuro
    /// reoptimizador de asm: solo @c Analyzable se reordena; @c Volatile/@c Raw
    /// son verbatim.  @c q_volatile (abajo) es legado (bit informativo del IR).
    AsmLevel level = AsmLevel::Analyzable;
    ///  AS inc.7: enlaces de operandos `( reg p = addr, rax a = exp, ... )`.
    /// Vacio = modelo clasico (register() en var-decls, sin sustitucion).
    std::vector<AsmOperand> operands;
    SourceLoc body_loc; ///< loc del primer token del cuerpo (para mapear el
                        ///< error de ensamblado a la linea/columna exactas).
    bool q_volatile =
        true; ///< @c volatile (default): no optimizar/reordenar/eliminar.
    bool q_nomem = false; ///< @c nomem: el bloque no accede a memoria.
    bool q_preserves_flags = false; ///< @c preserves_flags: RFLAGS se conserva.
    bool q_pure = false; ///< @c pure: implica nomem + preserves_flags.
    bool q_noinfer =
        false; ///< @c noinfer: desactiva la inferencia de clobbers (inc.4);
               ///< clobbers(...) pasa a ser la lista exacta.
    std::vector<std::string>
        clobbers; ///< Registros explicitos destruidos (sin "memory"/"flags").
    bool clobbers_memory =
        false; ///< @c clobbers("memory"): barrera de loads/stores.
    bool clobbers_flags =
        false; ///< @c clobbers("flags"): RFLAGS no preservado.
    AsmStmt() : Stmt(NodeKind::AsmStmt) {}
};

// -------------------------------------------------------------------
// Declaraciones.
// -------------------------------------------------------------------

/**
 * @struct ParamDecl
 * @brief Declaracion de un parametro de funcion.
 */
struct ParamDecl : Node {
    std::unique_ptr<TypeNode> type;
    std::string name;
    /** Direccion declarada (`in`/`out`/`inout`), ver @c ParamDir.  @c None
     * cuando no se escribio ninguna. */
    ParamDir dir = ParamDir::None;
    /** @c true si el tipo declarado fue `expr` (solo valido en @Macro):
     * el parser captura el texto raw del call site como string en lugar
     * de parsear la expresion. El @c type queda materializado como
     * primitivo STRING para el body del macro. */
    bool is_expr_capture = false;
    /** @c true si el parametro es VARIADICO (`T... name`, debe ser el ultimo).
     * El callee lo recibe como un puntero @c T* al array empaquetado por el
     * caller; el numero de args variadicos se lee con el builtin @c vacount().
     * El @c type guarda el tipo del ELEMENTO (T), no el del puntero. */
    bool is_variadic = false;
    /** @c true si el parametro es un VARIADICO CRUDO: un `...` pelado (sin tipo
     * ni nombre), estilo C.  Acepta N args de CUALQUIER tipo; cada uno se
     * coloca segun su propia regla de ABI en el call site (enteros/punteros ->
     * arg-regs GP, float -> arg-regs XMM).  El callee NO los empaqueta ni
     * ofrece
     * @c vacount()/array: es para funciones @c @Naked, donde el cuerpo asm lee
     * los registros ABI directamente.  Implica @c is_variadic. */
    bool is_raw_variadic = false;
    /** ABI custom por funcion: registro fisico en el que este parametro se
     * RECIBE (y en el que el caller lo COLOCA), declarado con
     * `register("rXX") T name`.  Vacio = ABI estandar del target (el i-esimo
     * arg-reg SysV/Win64).  Habilita wrappers de syscall/FFI de coste minimo:
     * `register("rax") i64 id, register("rdi") i64 a1, ...` -> el call site
     * pone cada valor directo en su registro (cero shift) y el cuerpo asm los
     * lee tal cual.  Nombre en minusculas ("rax".."r15"); validado por el type
     * checker. */
    std::string abi_reg;
    ParamDecl() : Node(NodeKind::ParamDecl) {}
};

/**
 * @struct FunctionDecl
 * @brief Declaracion (o definicion) de una funcion top-level.
 *
 * Si @c body es null, se trata de una declaracion sin definicion
 * (typicamente FFI extern; las funciones extern reales se modelan
 * via @c ExternFnDecl, este caso queda como fallback general).
 */
/**
 * @struct TypeBound
 * @brief Constraint sobre un type-param generico (#6).
 *
 * `<T: Comparable>` o `where T: Comparable + Sized` produce un TypeBound
 * con @c type_param = "T" y @c concepts = ["Comparable"] (o ["Comparable",
 * "Sized"]).  El type-arg concreto debe satisfacer TODOS los conceptos.
 * La verificacion es compile-time (al monomorphizar); cero codigo emitido.
 */
struct TypeBound {
    std::string type_param;            ///< nombre del type-param (e.g. "T")
    std::vector<std::string> concepts; ///< conceptos exigidos (A + B + ...)
    SourceLoc loc;
};

struct FunctionDecl : Node {
    std::unique_ptr<TypeNode> return_type;
    std::string name;
    std::vector<std::unique_ptr<ParamDecl>> params;
    std::unique_ptr<BlockStmt> body;
    /// #6: constraints de los type-params (`<T: C>` inline o `where T: A+B`).
    /// Vacio = sin bounds.  Verificados al monomorphizar; cero runtime.
    std::vector<TypeBound> type_bounds;
    /// #7: especializacion de FUNCION generica (`R id<i64>(...)` total /
    /// `R id<T*>(...)` parcial).  Si @c is_specialization, @c spec_pattern
    /// son los type-args del patron y @c type_params los params frescos.
    bool is_specialization = false;
    std::vector<std::unique_ptr<TypeNode>> spec_pattern;
    ///  M6.a L.3: visibilidad cross-module.  @c true (default) =
    /// publica, exportada al `.vxi` y accesible desde otros modulos.
    /// @c false = privada al modulo (no se exporta).  El parser setea
    /// segun keyword `public`/`private` precedente; sin keyword = true
    /// (default permisivo para compat con codigo existente).
    /**
     * @brief Exportada fuera de su modulo.
     *
     * PRIVADA por defecto: `public` es obligatorio para exportar.  Nacia en
     * `true` -- las funciones comptime son anteriores al sistema de visibilidad
     * y se quedo asi --, y eso hacia que un ayudante de compilacion sin
     * `public` viajara en el `.vxi` con su codigo fuente entero.
     */
    bool is_public = false;
    ///  NS.3: @c "internal" -- visible en TODO el paquete (mismo
    /// PackageId) pero NO exportado a paquetes distintos.  Se exporta al .vxi
    /// con flag; el consumidor de OTRO paquete lo filtra.
    bool is_internal = false;
    bool is_async = false; ///< @Async: el cuerpo se ejecuta en un proceso hijo,
                           ///< devuelve handle de Future
    /// marca `comptime fn` -- la funcion se interpreta en
    /// compile-time, no genera codigo runtime.  Solo puede llamarse
    /// desde contextos comptime (init de comptime const, condicion
    /// de comptime if, args de comptime for, otros comptime fn).
    bool is_comptime = false;
    /// parametros de tipo genericos.  Dos sintaxis:
    ///   - comptime: `comptime <T, U> R name(params) { ... }` (type-level
    ///     metaprogramming; el body usa T como tipo, sizeof<T>/kind<T>/...).
    ///   - runtime:  `R name<T>(params) { ... }` (funcion generica
    ///   monomorphizada
    ///     en cada llamada `name<i64>(...)` o con args inferidos; equivalente a
    ///     un template de C++).
    /// En ambos casos se rellena este vector; @c is_comptime distingue el modo.
    std::vector<std::string> type_params;
    /// marca `@Macro` -- comptime fn cuyo string de retorno
    /// se INYECTA como codigo Vesta en el call site (parse + lower).
    /// Equivalente a invocar `comptime_emit_expr(my_fn(args))`
    /// transparentemente.  Solo aplica a comptime fns que retornan
    /// string.  Permite la sintaxis `i32 r = mi_macro(args);` con
    /// inyeccion automatica del codigo generado.
    bool is_macro = false;
    /// marca `@Pure` -- el cuerpo NO depende ni modifica
    /// state externo (globales mutables, gensym, etc.) -- solo de
    /// los args.  El evaluador comptime puede MEMOIZAR la salida
    /// por (nombre, args).  Llamadas repetidas con mismos args
    /// devuelven el resultado cacheado sin reejecutar el body.
    /// Coste runtime cero (todo compile-time).  Si el usuario
    /// marca @Pure una fn impura, el resultado es indefinido --
    /// la memoizacion no detecta el cheating.
    bool is_pure = false;
    /// Cross-module comptime/macro: esta fn fue RE-PARSEADA e inyectada por el
    /// importer desde el texto fuente exportado del dep (generic_template_
    /// exports).  El importer la registra para AST-evaluarla, pero NO debe
    /// re-bajarla a IR: su cuerpo re-parseado referencia helpers del dep por su
    /// nombre SIMPLE (`helper`), invisible/incoherente en el importer -> el
    /// lowering emitiria un `callvm code.helper` colgante.  El dep ya baja el
    /// `__macro_<X>` + sus helpers force-lowered, y el importer MERGEA ese IR;
    /// re-bajar en el importer es redundante Y rompe el mangling.
    bool is_imported_comptime = false;
    /// Bug fix 2026-05-23: forward declaration `T fn(args);` sin body.
    /// El parser lo setea cuando ve `;` post-`)`.  El type checker
    /// registra la firma sin requerir body; otra FunctionDecl con el
    /// mismo nombre debe aparecer despues con body, o error.
    bool is_forward_decl = false;
    /// @fp(strict|fast): politica de contraccion de coma flotante de ESTA
    /// funcion.  true (default) = fast (se permite contraer a*b+c en FMA, 1
    /// redondeo).  false = strict (IEEE, 2 redondeos, sin FMA).  Se propaga a
    /// @c IrFunction::fp_contract en el lowering.  El CLI -ffp-contract=off lo
    /// AND-ea a false para todo el modulo.
    bool fp_contract = true;
    ///  AOT.3 2b (dev OS): `@section(".name"[,"perms"])` -- seccion de
    /// salida del codigo de la funcion en AOT.  Vacio => default `.text`.
    /// @c attr_section_perms = subconjunto de "rwx" (vacio => convencion del
    /// nombre).  Solo lo consume el codegen AOT.
    std::string attr_section;
    std::string attr_section_perms;
    int64_t attr_at = -1; ///< @at(N): offset/VA fijo (AOT .bin); -1 = auto
    int32_t attr_order =
        0x7fffffff; ///< @order(N): orden de seccion; max = creacion
    bool is_alloc_override = false; ///< @AllocatorOverride (AOT freestanding)
    bool is_panic_handler = false;  ///< @PanicHandler (AOT freestanding)
    ///  NR: `@Naked` -- funcion sin prologo/epilogo NI ret implicito.
    /// El cuerpo (tipicamente inline `asm { ... }`) se emite verbatim; el
    /// programador provee la salida (`ret`/`iretq`/`iret`).  Para ISRs,
    /// stubs de entry y cambio de modo en dev OS.  Semantica de
    /// `__attribute__((naked))` de GCC.  Solo lo consume el codegen.
    bool is_naked = false;
    /// @NoIdiom: el compilador NO reconoce idiomas dentro de esta funcion.
    ///
    /// Hay pases que ven un bucle y lo reescriben a la operacion equivalente
    /// (un bucle de copia -> `memcpy`).  Eso es correcto en codigo normal y
    /// desastroso en el codigo que IMPLEMENTA esa operacion: el bucle de
    /// `memcpy` se convertiria en una llamada a `memcpy`, o sea a si mismo.
    ///
    /// Lo lleva quien escribe una primitiva de memoria, incluido quien aporte
    /// la suya con @c @HelperOverride.  No cambia la semantica: solo impide
    /// que el codigo se sustituya por una llamada a lo que esta definiendo.
    bool is_no_idiom = false;
    /// @Target("mode:jit"): esta es la variante que usa el JIT.  Su nombre
    /// lleva el sufijo @c kSufijoVarianteJit para convivir con la del
    /// interprete, que conserva el nombre desnudo.
    bool mode_variant_jit = false;
    /// @NoExcept (o modulo @NoExceptions): esta funcion promete no propagar
    /// excepciones.  El frontend rechaza throw/try/catch en su cuerpo y el
    /// codegen omite el bookkeeping de excepciones (cero overhead).  Un
    /// unwrap-null en este scope termina el proceso (no es catchable).
    bool is_noexcept = false;
    /// C-3: @StringConcat -- esta fn libre reemplaza el operador `+`
    /// (y el builtin str_concat) entre dos strings.  Firma esperada:
    /// fn(string, string) -> string.  Aplica en native_poo_ (AOT) y Full.
    bool is_string_concat_override = false;
    /// C-3: @StringEq -- esta fn libre reemplaza el operador `==`
    /// (y `!=` via negacion) entre dos strings.  Firma esperada:
    /// fn(string, string) -> bool.  Aplica en native_poo_ (AOT) y Full.
    bool is_string_eq_override = false;
    /// @SyncImpl -- esta fn libre reemplaza la primitiva de monitor de
    /// `synchronized`.  El nombre convenido de la fn selecciona el rol:
    /// `monitor_enter` (adquiere) o `monitor_exit` (libera); firma
    /// esperada `void(<ptr> obj)`.  Si el programa declara un @SyncImpl,
    /// `synchronized` baja a un CALL a estas funciones en LOS 3 MODOS
    /// (interp/JIT/AOT); sin override se usa el default de cada tier
    /// (opcode MONENTER/MONEXIT en interp/JIT, __vx_monenter/monexit en
    /// AOT).  Mecanismo, no politica: el programador decide la impl
    /// (spinlock, pthread, disable-IRQ en kernel, lock cooperativo de
    /// fibras, etc.).  Mismo patron que @AllocatorOverride/@PanicHandler.
    bool is_sync_impl = false;
    /// CPU dispatch Inc 4: @HelperOverride(<helper>) -- esta fn libre
    /// reemplaza el helper multi-versionado del build.  @c
    /// helper_override_target guarda el nombre del helper objetivo
    /// (hoy solo "memcpy"; escala a strcmp/strlen/itoa en el futuro).
    /// Vacio => no es override.  Solo aplica en native_poo_ (AOT): el
    /// dispatch por cpuid se salta y el fp apunta a esta fn.  Firma
    /// esperada para "memcpy": void(u8*, u8*, u64).
    std::string helper_override_target;
    /// Subsistema de coste (modo --analyze): `@complexity(O(...))`.
    /// Metadata PURA -- NO afecta el codegen.  La consume el analizador
    /// estatico (analyze::bigo) como contrato a validar contra la
    /// complejidad inferida del IR.  @c complexity_expr guarda la
    /// expresion de coste normalizada (e.g. "O(n^2)", "O(n log n)");
    /// vacio si la funcion no declara @complexity.  @c complexity_vars
    /// guarda los bindings opcionales `n = <expr>` (texto raw) que
    /// indican cual es la variable de tamano del input.
    ///
    /// @c complexity_expr es AZUCAR: equivale a declarar la dimension
    /// @c total_post (el coste efectivo real, validado contra el TOTAL
    /// POST-opt).  Para documentar las CUATRO dimensiones por separado se
    /// usan los campos nombrados de abajo.
    std::string complexity_expr;
    std::vector<std::string> complexity_vars;
    /// Contratos por DIMENSION del subsistema de coste.  Cada uno es la
    /// expresion declarada para una de las cuatro combinaciones
    /// PARCIAL/TOTAL x PRE-opt/POST-opt.  Vacio => esa dimension no se
    /// declara (no se valida).  Sintaxis:
    ///   @complexity(partial_pre: O(n), partial_post: O(n),
    ///               total_pre: O(n^2), total_post: O(n^2))
    /// La forma posicional @complexity(O(n)) llena @c complexity_total_post
    /// (compat).  Los campos son opcionales e independientes.
    std::string complexity_partial_pre;
    std::string complexity_partial_post;
    std::string complexity_total_pre;
    std::string complexity_total_post;
    /// @complexity con un `when:` que habla del parametro de tipo: no se puede
    /// resolver al parsear (T aun no es nada), asi que se guarda tal cual y lo
    /// resuelve el clon de la monomorphizacion.  Ver @ref PendingComplexity.
    std::vector<PendingComplexity> complexity_pending;
    /// Contratos de HUELLA con `when:`, sin resolver.  Ver @ref
    /// PendingFootprint.
    std::vector<PendingFootprint> footprint_pending;
    /// Contratos comprobables de recurso/efecto (huella computacional).  El
    /// compilador los VERIFICA contra la huella inferida del IR (sound: solo
    /// error cuando la violacion es demostrable).  Ausente = no declarado.
    ///   @pure @nothrow @nopanic  (flags)
    ///   @alloc(N) @stack(N)       (N = maximo permitido)
    bool contract_pure = false;    ///< @pure declarado.
    bool contract_nothrow = false; ///< @nothrow declarado.
    bool contract_nopanic = false; ///< @nopanic declarado.
    // @alloc/@stack con DOS dimensiones (parcial=propio, total=cierre/pila peor
    // caso).  La forma corta `@alloc(N)`/`@stack(N)` fija el TOTAL.  -1 = no
    // decl.
    int64_t contract_alloc = -1;         ///< @alloc(total: N) o `@alloc(N)`.
    int64_t contract_alloc_partial = -1; ///< @alloc(partial: N).
    int64_t contract_stack = -1;         ///< @stack(total: N) o `@stack(N)`.
    int64_t contract_stack_partial = -1; ///< @stack(partial: N).
    FunctionDecl() : Node(NodeKind::FunctionDecl) {}
};

/**
 * @enum ConceptKind
 * @brief Forma sintactica de un @c ConceptDecl (#6).
 */
enum class ConceptKind : uint8_t {
    Predicate,  ///< `concept N<T> = <bool-expr>;`
    Block,      ///< `concept N<T> { <comptime stmts>; return <bool>; }`
    Structural, ///< `concept N { metodo-sigs }` (desugar a has_method)
};

/**
 * @struct ConceptDecl
 * @brief Declaracion de un CONCEPTO: un predicado comptime sobre un tipo (#6).
 *
 * Un concepto es una funcion booleana evaluada en compile-time sobre un
 * type-arg.  Tres formas (ver @c ConceptKind).  Se evalua al monomorphizar
 * un generico con bound `<T: N>`; si devuelve false, error claro.  No emite
 * codigo: las constraints DESAPARECEN tras el type-check.
 */
/**
 * @struct StructuralMethod
 * @brief Firma de un metodo exigido por un concepto estructural (#6 ext).
 *
 * `concept Dibujable { i64 area(); bool igual(i64 x); }` produce dos
 * StructuralMethod.  El chequeo compara nombre + aridad + tipo de retorno +
 * tipos de parametros contra los metodos del tipo concreto.
 */
struct StructuralMethod {
    std::string name;
    std::unique_ptr<TypeNode> return_type; ///< null = void
    std::vector<std::unique_ptr<TypeNode>> param_types;
};

struct ConceptDecl : Node {
    std::string name;
    std::vector<std::string> type_params; ///< usualmente ["T"]
    ConceptKind ckind = ConceptKind::Predicate;
    std::unique_ptr<Expr> predicate; ///< forma Predicate
    std::unique_ptr<BlockStmt> body; ///< forma Block
    /// forma Structural: firmas completas (nombre + retorno + params).
    std::vector<StructuralMethod> structural_methods;
    bool is_public = true;
    ConceptDecl() : Node(NodeKind::ConceptDecl) {}
};

/**
 * @struct ExtensionDecl
 * @brief NS.6-ext: @c "extension Tipo { metodos }".  anyade metodos a un tipo
 * (struct o clase) ya declarado, posiblemente desde otro fichero/namespace
 * (estilo Swift extension / C# extension methods).  Los metodos se APENDEAN al
 * layout del tipo destino; el dispatch es ESTATICO (CALL directo a
 * @c Tipo__metodo, inline-able, coste cero) -- no entran en la vtable.
 * Coherencia (Vesta): permisivo (cualquier tipo, local o foraneo); error duro
 * solo en la colision real de un metodo+aridad ya existente en el tipo.
 */
struct ExtensionDecl : Node {
    std::string target_type; ///< nombre del tipo a extender (struct o clase)
    std::vector<std::unique_ptr<ClassMethodDecl>> methods;
    bool is_public = true;
    ExtensionDecl() : Node(NodeKind::ExtensionDecl) {}
};

/**
 * @struct ImplDecl
 * @brief NS.6-ext: @c "impl Concept for Tipo { metodos }".  Implementa un
 * @c concept para un tipo anyadiendo los metodos requeridos (estilo Rust impl).
 * Como los concepts de Vesta son PREDICADOS comptime estructurales (cero
 * codigo), un @c impl es identico a una @c extension mas la VALIDACION de que
 * el tipo satisface el concept tras anyadir los metodos.
 */
struct ImplDecl : Node {
    std::string concept_name; ///< concept que se implementa
    std::string target_type;  ///< tipo para el que se implementa
    std::vector<std::unique_ptr<ClassMethodDecl>> methods;
    bool is_public = true;
    ImplDecl() : Node(NodeKind::ImplDecl) {}
};

/**
 * @struct ExternFnDecl
 * @brief FFI declarativo - declaracion `extern "lib.dll" fn name(...) -> R;`
 *
 * Sintaxis Vesta:
 * @code
 *     extern "user32.dll" {
 *         fn MessageBoxA(i64 hwnd, ptr text, ptr caption, i32 type) -> i32;
 *     }
 *     extern "kernel32.dll" {
 *         fn Sleep(i32 ms) -> void;
 *         fn GetCurrentProcessId() -> i32;
 *     }
 * @endcode
 *
 * Cada @c fn dentro del bloque produce un @c ExternFnDecl.  El parser
 * desarma el bloque y emite N decls independientes (uno por funcion);
 * todas comparten @c lib.  El type checker registra la funcion como
 * @c Symbol::Function con @c FunctionSig::extern_lib = lib, asi el
 * lowering al ver una llamada al simbolo emite @c CALLN
 * @c @Method("<lib>:<name>") en lugar de @c CALLVM.
 *
 * Cero overhead runtime: el ensamblador resuelve @c "user32.dll" igual
 * que @c "stdlib/native/io/vesta_io" usando el mismo mecanismo
 * @c LoadLibraryA + @c GetProcAddress de @c src/ffi/native_ffi.cpp.
 */
/**
 * @struct ExternEffects
 * @brief Lo que se DEFINIO de una funcion externa, aparte de sus punteros.
 *
 * Los ejes que hablan de argumentos (`in`/`out`/`inout`) viven en cada
 * @c ParamDecl porque son posicionales; estos son los que hablan de la funcion
 * entera.
 *
 * Es una DESCRIPCION COMPLETA: lo que no se escribe, no ocurre.  Por eso el
 * vocabulario tiene formas POSITIVAS (`@io`, `@throws`, `@panics`, `@alloc`)
 * que un contrato no necesita -- un contrato ACOTA, y por eso le bastan las
 * negativas (`@nothrow`, `@nopanic`) --.  Una descripcion tiene que poder decir
 * que SI, o el silencio se leeria como una demostracion.
 *
 * @c any distingue "nadie dijo nada" de "dijeron que no hace nada", que son
 * cosas MUY distintas: la primera obliga a suponer lo peor.
 *
 * El `when:` de cada anotacion ya esta RESUELTO aqui: el objetivo se conoce al
 * compilar -- igual que para un `@Target` sobre una declaracion --, asi que el
 * parser se queda solo con lo que aplica.  Lo que llega mas abajo es un
 * conjunto para EL objetivo activo, sin ambitos que arrastrar.
 */
struct ExternEffects {
    bool any = false; ///< alguien escribio algo (aunque fuera `@pure`)
    bool io = false;
    bool may_throw = false;
    bool may_panic = false;
    bool allocates = false;
    bool reads_global = false;
    bool writes_global = false;
    bool nondeterministic = false;
};

struct ExternFnDecl : Node {
    std::string lib; ///< nombre de la libreria (e.g. "user32.dll")
    std::unique_ptr<TypeNode> return_type;
    std::string name; ///< nombre de la funcion nativa
    std::vector<std::unique_ptr<ParamDecl>> params;
    /// Lo definido de ella, ya resuelto contra el objetivo activo.
    ExternEffects effects;
    ExternFnDecl() : Node(NodeKind::ExternFnDecl) {}
};

/**
 * @struct GlobalVarDecl
 * @brief Variable declarada a nivel de modulo (top-level).
 */
struct GlobalVarDecl : Node {
    std::unique_ptr<TypeNode> type;
    std::string name;
    std::unique_ptr<Expr> init;
    bool is_const = false;
    ///  M6.a L.3: visibilidad cross-module (default true).
    bool is_public = true;
    ///  NS.3: @c "internal" -- package-scoped (ver FunctionDecl::is_internal).
    bool is_internal = false;
    ///  marca `comptime const`.  El init debe ser comptime-
    /// evaluable; el type checker guarda el valor en
    /// @c TypeChecker::comptime_const_values_ y los usos posteriores
    /// se baja como @c IrOp::CONST inline (cero overhead).  No genera
    /// global runtime storage.
    bool is_comptime = false;
    /// `thread_local <type> name = init;`  -- almacenamiento por-hilo (TLS).
    /// El init debe ser comptime-constante (plantilla por-hilo, como en C).
    /// En AOT baja a TLS NATIVO: seccion SHF_TLS + PT_TLS / TLS directory PE.
    bool is_thread_local = false;
    /// v4: atributos `@hot`/`@cold`/`@align(N)`/`@section("name")`.
    /// Solo aplicables a comptime const (string/array/struct).
    bool attr_hot = false;
    bool attr_cold = false;
    uint16_t attr_align = 0;        ///< 0 = default
    std::string attr_section;       ///< vacio = default
    std::string attr_section_perms; ///< "rwx" explicito (vacio = convencion)
    GlobalVarDecl() : Node(NodeKind::GlobalVarDecl) {}
};

/**
 * @struct BytesDecl
 * @brief Bloque de datos crudos estilo NASM (AOT): @c bytes name { ... }.
 *
 * Directivas: @c db (1B), @c dw (2B), @c dd (4B), @c dq (8B) -- cada una
 * acepta literales (int/char/string) y, mas adelante, referencias a simbolos
 * (funcion/dato -> reloc).  @c times N <dir> repite.  Da control byte a byte
 * para firmas, tablas, estructuras binarias exactas, firmware, etc.  Se coloca
 * en la @c @section indicada (default @c .rodata) y se emite VERBATIM.
 */
struct BytesSymRef {
    uint32_t offset; ///< offset dentro de @c data del campo a relocar.
    std::string sym; ///< simbolo referenciado (funcion/dato).
    uint8_t width;   ///< 4 (dd) u 8 (dq).
    bool is_rel;     ///< true = REL32 (rip-rel); false = ABS64.
};
struct BytesDecl : Node {
    std::string name;
    std::string attr_section; ///< @section (vacio = .rodata)
    std::string attr_section_perms;
    int64_t attr_at = -1; ///< @at(N): offset fijo (AOT .bin); -1 = auto
    int32_t attr_order =
        0x7fffffff; ///< @order(N): orden de seccion; max = creacion
    bool is_public = true;
    std::vector<uint8_t> data; ///< bytes resueltos (placeholder 0 en sym refs)
    std::vector<BytesSymRef>
        sym_refs; ///< refs a simbolos (vacio en v1 literales)
    // Bloque `asm` (codigo NASM 16/32/64-bit): si @c is_asm, el lowering
    // ensambla @c asm_body via Keystone a @c asm_bits y el resultado va a
    // @c data (la seccion).  Reusa toda la maquinaria de placement.
    bool is_asm = false;
    std::string asm_body;  ///< texto NASM crudo (si is_asm)
    uint8_t asm_bits = 64; ///< 16/32/64 (@bits(N))
    BytesDecl() : Node(NodeKind::BytesDecl) {}
};

/**
 * @struct TypeAliasDecl
 * @brief Declaracion de alias de tipo via @c typedef o @c using.
 *
 * Sintaxis equivalente:
 * @code
 *     typedef u32 Edad;        // estilo C
 *     using   Edad = u32;      // estilo C++ moderno
 * @endcode
 *
 * Pure frontend: el type checker registra (name -> aliased) y al
 * resolver un NamedTypeNode con ese nombre devuelve el tipo
 * subyacente.  No genera codigo.  El campo @c is_using_form se
 * conserva solo para la presentacion de mensajes de error.
 */
struct TypeAliasDecl : Node {
    std::string name;
    std::unique_ptr<TypeNode> aliased;
    bool is_using_form = false;
    ///  M6.a L.3: visibilidad cross-module (default true).
    bool is_public = true;
    /// Si @c true, el alias es un NEWTYPE: comparte la representacion
    /// del tipo subyacente pero es nominalmente DISTINTO en el type
    /// checker.  Sintaxis: @c "typedef u64 ptr new;".  El type checker
    /// asigna un @c nominal_id unico que distingue este tipo de su
    /// underlying y de otros newtypes.  Sin conversion implicita;
    /// requiere cast explicito @c (T)x para cruzar al underlying.
    bool is_newtype = false;
    /// Si @c true (solo aplica si @c is_newtype), el newtype es
    /// @c @opaque: ademas de la barrera nominal, el usuario NO puede
    /// inicializar con literal del underlying ni hacer cast explicito.
    /// Sintaxis: @c "typedef u64 fd new @opaque;".  Sirve para handles
    /// donde el codigo cliente no debe ver la representacion.
    bool is_opaque = false;
    /// Alineacion forzada en bytes via @c "@align(N)" (potencia de 2,
    /// 1..4096).  0 = sin override (alineacion natural del underlying).
    uint16_t align_override = 0;
    /// Tipos desde los que se permite construir este newtype via
    /// cast explicito (@c "explicit from T;" en el bloque).  Una entrada
    /// con @c is_public=true permite cross-file; sin esa marca el cast
    /// solo se admite en el mismo fichero donde se declaro el typedef.
    struct ExplicitConv {
        std::unique_ptr<TypeNode> type;
        bool is_public = false;
    };
    std::vector<ExplicitConv> explicit_from;
    std::vector<ExplicitConv> explicit_to;
    /// Tipos que convierten a/desde este newtype SIN cast, declarados con
    /// @c "implicit from T;" / @c "implicit to T;".  La barrera nominal sigue
    /// en pie para todo lo demas: el typedef enumera las conversiones que
    /// forman parte de su contrato en lugar de abrirse entero.
    ///
    /// El caso que lo motivo: @c uintptr es el tipo del lenguaje para una
    /// DIRECCION, asi que pasarla donde se espera un @c T* no es una
    /// conversion entero->puntero que haya que justificar con un cast, es su
    /// razon de ser.  Declararlo en la stdlib -- en vez de cablear el nombre
    /// @c uintptr en el compilador -- deja el mecanismo disponible para
    /// cualquier newtype (handles, offsets, identificadores).
    std::vector<ExplicitConv> implicit_from;
    std::vector<ExplicitConv> implicit_to;
    TypeAliasDecl() : Node(NodeKind::TypeAliasDecl) {}
};

/**
 * @struct ImportDecl
 * @brief Declaracion de @c import "path" [as alias] [only A, B];
 *
 *  M (sistema de modulos).  El @c path es siempre un string
 * literal por consistencia con @c extern "lib.dll", @c loadmodule(),
 * @c @Method("lib:fn"), etc.  Se resuelve a un fichero @c .vx en
 * el filesystem por el module resolver del compilador.
 *
 * Sin @c as ni @c only, el modulo se accede via su namespace (el
 * ultimo segmento del path: @c "editor/buffer" -> @c buffer).  Con
 * @c as, el namespace se renombra.  Con @c only, los simbolos
 * listados se inyectan al scope local sin necesidad de prefijo.
 *
 * Si @c is_public_reexport es @c true (sintaxis @c "public import"),
 * los simbolos importados se reexportan a su vez para los modulos
 * que importen ESTE modulo.  Sin esa marca, los imports son privados
 * al modulo actual (no se re-exportan transitivamente).
 */
struct ImportDecl : Node {
    /// Ruta literal tal como aparecio en el source (sin las comillas).
    /// E.g. @c "editor/buffer" o @c "std/io".  Cuando @c by_namespace es
    /// true, contiene el path punteado del namespace (e.g. @c
    /// "std.collections").
    std::string path;
    ///  NS.2-full: true si el import vino de la forma por-NAMESPACE
    /// @c "import a.b.c;" (identificadores punteados) en lugar de la forma
    /// por-PATH @c "import \"a/b/c\";" (literal string).  En ese caso @c path
    /// contiene el namespace punteado y el resolver lo mapea a fichero via el
    /// indice de namespaces (no via el sistema de ficheros directo).
    bool by_namespace = false;
    /// Alias opcional para el namespace.  Vacio si no hay @c as.
    std::string alias;
    /// Lista de simbolos especificos a importar al scope local
    /// cuando se usa @c "only A, B" o @c "only A as B, C as D".
    /// Vacio significa "todos los publicos accesibles via namespace".
    struct OnlySymbol {
        std::string name;   // nombre original en el modulo
        std::string rename; // nombre local (vacio = sin rename)
    };
    std::vector<OnlySymbol> only_symbols;
    /// `import ns only *;` -- glob: trae TODOS los simbolos publicos del modulo
    /// al scope (estilo Rust `use ns::*;`).  Con @c is_public_reexport ademas
    /// los re-exporta (`pub use ns::*;`).  Cuando es @c true, @c only_symbols
    /// esta vacio (no hay lista explicita).
    bool only_all = false;
    /// Si el import es @c "public import "x";" (re-export).  Sin esa
    /// marca, los simbolos importados son privados al modulo actual.
    bool is_public_reexport = false;

    ImportDecl() : Node(NodeKind::ImportDecl) {}
};

/**
 * @struct NamespaceDecl
 * @brief Declaracion de namespace inline estilo C++:
 *        @c "namespace foo { ... }"
 *
 * Agrupa declaraciones top-level bajo un namespace logico.  Estructura
 * identica a @c ModuleNode (raiz) en cuanto a contenidos, pero anidable
 * dentro del fichero.  Permite tener dos clases / structs / enums /
 * funciones con el mismo nombre en namespaces distintos del mismo
 * modulo (e.g. @c ui.Button vs @c audio.Button).
 *
 * El mangling automatico aplica prefijo @c <ns_name>__ a todas las
 * declaraciones internas, de modo que en el bytecode emitido los
 * labels son @c ui__Button vs @c audio__Button.  Anidamiento se
 * concatena: @c "namespace a { namespace b { class C } }" produce
 * label @c a__b__C.  Cero overhead runtime: el namespace es
 * puramente lexical.
 *
 * Acceso desde fuera del namespace: sintaxis qualified @c foo.X
 * (no @c foo::X -- Vesta prefiere el punto sobre el scope-op de C++).
 */
struct NamespaceDecl : Node {
    std::string name; ///< "ui", "audio", "std.collections" (path punteado)
    std::vector<std::unique_ptr<Node>> decls; ///< contenidos top-level
    ///  NS.1: true si vino de la forma STATEMENT `namespace a.b.c;` (agrupa
    /// el resto del fichero) en lugar de la forma BLOQUE `namespace a.b.c
    /// {...}`. Semanticamente equivalentes (ambas manglan sus @c decls con el
    /// path); el flag es informativo para diagnosticos.
    bool is_statement_form = false;
    ///  NS.3: override opcional del PackageId via @c "namespace X
    ///  @id(\"..\");".
    /// Vacio = usar el PackageId derivado del vx.toml.  Permite renombrar el
    /// namespace manteniendo la identidad ABI (el .vxi del modulo lo estampa).
    std::string package_id_override;
    NamespaceDecl() : Node(NodeKind::NamespaceDecl) {}
};

/**
 * @struct StructFieldDecl
 * @brief Campo de un struct: tipo + nombre.
 *
 * Solo lo usa @c StructDecl; no es un nodo de top-level.  No deriva
 * de Node porque vive como elemento de un vector dentro de StructDecl;
 * no tenemos uso polimorfico para campos.
 */
struct StructFieldDecl {
    std::unique_ptr<TypeNode> type;
    std::string name;
    SourceLoc loc;
    /** Direccion declarada (`in i64* p;`), ver @c ParamDir.
     *
     * En un campo queda lo mismo que en una variable: el PERMISO.  Por un `in`
     * solo se lee, y da igual quien lo tenga delante -- un parametro, un local
     * o un campo --, que es justo lo que se le pide a una marca del lenguaje:
     * que signifique lo mismo en todos los sitios donde se puede escribir. */
    ParamDir dir = ParamDir::None;
    /// `static`: el campo NO vive en cada instancia sino una sola vez (storage
    /// global `<Struct>__<campo>`); habilita singletons y contadores por-tipo.
    /// Se accede via `Struct.campo` (lectura/escritura), no `instancia.campo`.
    bool is_static = false;
    /// Miembro ANONIMO C11: `struct { ... };` / `union { ... };` sin nombre de
    /// campo.  Sus campos se APLANAN en el struct contenedor (se accede a
    /// `parent.inner_field` directamente).  @c type apunta al agregado
    /// sintetico y @c name es un placeholder sintetico (no usado para acceso).
    bool is_anonymous = false;
    /// Bit field width.  0 = campo normal (byte-aligned).
    /// >0 = bit field con esta cantidad de bits.  El type checker
    /// calcula bit_offset y los empaqueta en storage words del tipo
    /// declarado (i32 -> 32 bits por word, etc.).  Estilo C/C++.
    uint8_t bit_width = 0;
    /// Overlay (F1): offset EXPLICITO CONSTANTE del campo dentro de la vista
    /// (`ptr X @offset(0x30);` o `@0x30`).  -1 = sin offset constante (campo
    /// normal, o offset dado por @c offset_expr).  Fast-path del caso
    /// constante.
    int64_t explicit_offset = -1;
    /// Overlay (F2): offset del campo dado por una EXPRESION que puede
    /// referenciar campos hermanos (`@offset(prev_off + 0x10)`).  null = usa
    /// @c explicit_offset (constante).  Se evalua en tiempo de acceso; el caso
    /// puramente constante se pliega a @c explicit_offset en el parser.
    std::unique_ptr<Expr> offset_expr;
    /// Overlay (F3): resolver de la DIRECCION del campo -- `@offset { ...;
    /// return <direccion>; }`.  A diferencia de un offset (F1/F2), el bloque
    /// DEVUELVE la DIRECCION absoluta donde vive el campo; puede tener control
    /// de flujo (if/else, bucles), `let` locales y referenciar los campos
    /// hermanos + el puntero `base` de la vista.  null = usa expr/offset const.
    std::unique_ptr<BlockStmt> offset_block;
    /// Overlay (F3b) ARRAY: `T Name[count] @offset(pos) stride(s)`.  count =
    /// num de elementos (expr, para bounds), stride = bytes entre elementos
    /// (expr). El tipo del campo (@c type) es el tipo del ELEMENTO. `v.Name[i]`
    /// resuelve a `base + pos + i*stride`.  null = campo escalar (no array).
    std::unique_ptr<Expr> array_count;
    std::unique_ptr<Expr> array_stride;
    /// Overlay array POR-ELEMENTO (`T Name[count] @element { ... }`): resolver
    /// que devuelve la DIRECCION del elemento `index` (con `index` en scope),
    /// para stride VARIABLE / records de longitud variable / TLV.  Puede
    /// acceder al elemento anterior (`self.Name[index-1]`).  null = array de
    /// stride fijo.
    std::unique_ptr<BlockStmt> element_block;
    /// Overlay array marcado con `[` (aunque el count este vacio: `T Name[]`).
    /// Distingue un array NO acotado (el usuario gestiona la terminacion) de un
    /// campo escalar.  true = es un array (con o sin @c array_count).
    bool is_array = false;
    /// Overlay ENDIANNESS del campo (F5): 0 = nativo/host (sin swap), 1 = big-
    /// endian (`@be`), 2 = little-endian explicito (`@le`).  Un campo `@be` en
    /// un host little-endian (x86-64) emite BYTESWAP en cada read/write.  Para
    /// formatos de endianness fija (red = BE, ELF lo declara en e_ident).
    uint8_t endian = 0;
    /// Overlay endianness DINAMICA (F5): `@endian(expr)` -- la expr (bool/int:
    /// nonzero = big-endian) decide el orden EN TIEMPO DE ACCESO.  Puede
    /// referenciar campos hermanos (`@endian(ei_data == 2)`, ELF) o un comptime
    /// const (se pliega).  null = usa @c endian estatico.  El swap es
    /// condicional (branchless select) cuando la expr es runtime.
    std::unique_ptr<Expr> endian_expr;
    /// Valor por defecto del campo (`u8 a = 0x10;`).  null = sin default
    /// (el campo se zero-inicializa).  Se aplica cuando el struct se crea con
    /// `= {}` o cuando el campo NO aparece en el init-list, y por el `init()`
    /// sintetizado.  Debe ser una expresion comptime-constante.
    std::unique_ptr<Expr> default_init;
    /// `comptime T campo`: el campo existe SOLO en tiempo de compilacion (p.ej.
    /// `comptime char* name` para calcular un hash en compile-time).  NO ocupa
    /// espacio en el layout runtime del struct ni se serializa; el type checker
    /// lo excluye del calculo de offsets/tamano.  Su valor lo consume el codigo
    /// comptime (constructores/metodos comptime).
    bool is_comptime = false;
};

/**
 * @struct StructDecl
 * @brief Declaracion de un @c struct (value type con herencia ESTATICA
 * opcional).
 *
 * Solo cubre campos; los metodos opcionales llegan en hitos posteriores.
 * El type checker
 * registra el struct con su layout y permite usarlo via
 * NamedTypeNode.
 */
struct StructDecl : Node {
    std::string name;
    /// Herencia ESTATICA de structs (value-type, sin vtable): el derivado
    /// `struct D : Base` embebe los campos del base al INICIO de su layout
    /// (layout-compatible, upcast trivial) y hereda sus metodos con dispatch
    /// estatico.  El tipo `Self` en los metodos del base se reinstancia al tipo
    /// concreto del derivado (covarianza estilo CRTP / Rust `Self`), asi los
    /// operadores comunes viven una sola vez y devuelven el tipo correcto en
    /// cada derivado.  Vacio = sin base.
    std::string super_name;
    /// Interfaces / conceptos que el struct declara satisfacer
    /// (`struct S : Base, IWide`).  Verificado en compile-time; cero coste.
    std::vector<std::string> interface_names;
    std::vector<StructFieldDecl> fields;
    /// Metodos del struct (value-type, dispatch estatico).  Reusa
    /// @c ClassMethodDecl pero los structs NO tienen vtable, herencia
    /// ni constructores con this(...): cada metodo baja a una funcion
    /// libre @c <Struct>__<metodo>(this_ptr, args...) donde @c this_ptr
    /// es la direccion (PTR) del buffer del struct.  El dispatch es
    /// siempre CALL directo (sin CALLVIRT).
    std::vector<std::unique_ptr<ClassMethodDecl>> methods;
    ///  M6.a L.3: visibilidad cross-module (default true).
    bool is_public = true;
    /// marca `@Introspect` -- el compilador
    /// emite IntrospectInfo POD en static_data y registra el tipo en
    /// el global `__introspect_registry` para que `find_type("Name")`
    /// runtime lo encuentre.  Sin esta marca, el tipo solo es
    /// introspectable via builtins comptime (sin overhead).
    bool is_introspect = false;
    /// marca `@overlay` -- el struct es una VISTA tipada sobre un puntero base
    /// ajeno (PEB, cabeceras PE/ELF, ...), no un value-type que se posee.  Un
    /// valor overlay ES un puntero (8 bytes): no aloca, no zero-init, no copia;
    /// `v.campo` se baja a `*(T*)(base + offset)`.  Los campos usan @c
    /// explicit_offset (`@offset(N)`).
    bool is_overlay = false;
    /// union C-style: todos los campos comparten el offset 0; el tamano es el
    /// del campo mayor y el alineamiento el maximo.  Reusa toda la maquinaria
    /// de struct salvo el calculo de layout (offsets/size).
    bool is_union = false;
    /// `@Abstract` -- el struct NO es instanciable por si mismo; solo sirve
    /// como base de otros (`struct D : Base`).  Independiente de `Self`: un
    /// struct con `Self` es instanciable por defecto (Self = el propio tipo si
    /// no hay derivado).  Ver [[proj_struct_self_inheritance]].
    bool is_abstract = false;
    /// Parametros de tipo opcionales (templates).  `struct Box<T> { T v; }`
    /// produce type_params = ["T"].  Vacio para structs no genericos.  Si no
    /// esta vacio, el struct es una plantilla: NO se procesa como concreto;
    /// cada uso `Box<i32>` se monomorphiza on-demand (mismo modelo que las
    /// clases A.8 y los enums L2.3).
    std::vector<std::string> type_params;
    /// #6: constraints de los type-params (`struct S<T: Concepto>` o
    /// `where T: A + B`).  Verificados al monomorphizar; cero runtime.
    std::vector<TypeBound> type_bounds;
    /// #7: especializacion (total o parcial).  Si @c is_specialization es
    /// true, esta declaracion NO es el template primario sino una
    /// especializacion de @c name: @c spec_pattern son los type-args del
    /// patron (`<i64>` total, `<T*>` parcial) y @c type_params son los
    /// FRESH params del patron (e.g. ["T"] en `Caja<T*>`; vacio en total).
    /// Al instanciar `Caja<X>` se elige la especializacion mas especifica
    /// que matchee (exacto > patron > primario).  Compile-time puro.
    bool is_specialization = false;
    std::vector<std::unique_ptr<TypeNode>> spec_pattern;
    /// Contratos de layout/recurso comprobables (modo --analyze): @pod,
    /// @no_heap, @size(N).  Metadata compile-time; el codegen los ignora.
    /// -1 en @c contract_size = no declarado.
    bool contract_pod = false;
    bool contract_no_heap = false;
    int64_t contract_size = -1;
    /// `@align(N)` a nivel de struct: fuerza la alineacion del layout a N (max
    /// con la natural) y padea el tamano a un multiplo de N.  0 = sin override.
    /// Equivalente a C `__declspec(align(N))` / `_Alignas(N)`.
    uint16_t attr_align = 0;
    /// Struct INCOMPLETO (forward-decl opaco `typedef struct Tag *P;` sin
    /// cuerpo). Se registra el tipo (usable via puntero, 8 bytes) pero sin
    /// campos; una definicion posterior `struct Tag { ... }` lo completa
    /// (sobrescribe).
    bool is_incomplete = false;
    StructDecl() : Node(NodeKind::StructDecl) {}
};

/**
 * @struct EnumVariantDecl
 * @brief Variante de un @c enum.
 *
 * Cada variante tiene un nombre y una lista (posiblemente vacia) de
 * tipos para sus payloads.  Variantes sin payload son meros
 * "marcadores" (e.g. @c None, @c Red).  Variantes con payloads se
 * representan en memoria como una tagged union: tag (i64) + payload
 * fields concatenados a partir del offset 8, padded a 8 bytes cada
 * uno para alineacion uniforme.
 *
 * El tag asignado es el indice de la variante en
 * @c EnumDecl::variants (0..N-1), estable entre compilaciones.
 */
struct EnumVariantDecl {
    std::string name;
    /// Valor entero explicito para enums con tipo base (C-style,
    /// `A = 0x01`).  Nulo -> auto-incremento (prev+1, primero 0).
    std::unique_ptr<Expr> value_expr;
    std::vector<std::unique_ptr<TypeNode>>
        field_types; ///< Vacio para variantes sin payload.
    SourceLoc loc;
};

/**
 * @struct EnumDecl
 * @brief Declaracion de un tipo algebraico.
 *
 * Sintaxis aceptada por el parser:
 * @code
 *   enum Color {
 *       Red,                    // sin payload
 *       Green(i32),             // un payload
 *       Blue(i32, i32)          // multiples payloads
 *   }
 * @endcode
 *
 * Layout en memoria (mismo modelo que @c Optional / @c Result builtins):
 *   `[+0 i64 tag][+8 payload_field_0][+16 payload_field_1] ...`
 * El tamano total de un valor del enum es @c 8 + 8 * max_payload_fields,
 * suficiente para cualquier variante.  Cero alocaciones de heap; cero
 * overhead GC.
 *
 * Construccion: @c Color.Green(42) -> escribe tag=1 + payload[0]=42 en
 * un slot recien alocado en stack del caller.
 *
 * Destructuring: @c match c { case Green(n) => ... } -> el lowering
 * carga el tag, dispatcha via @c jumptable (0x27) al label de la
 * variante, y en el body ya tiene el payload accesible via LOAD del
 * slot del scrutinee a un SSA value bindeado al nombre @c n.
 */
struct EnumDecl : Node {
    std::string name;
    /// Tipo base para enums con VALOR entero (C-style):
    /// `enum Op : u8 { ... }`.  Vacio -> enum ADT (tagged union).
    std::string backing_type;
    /// C-style `typedef enum { ... } Name;` sin `: tipo` explicito.  El enum
    /// es un conjunto de constantes enteras (NO una tagged union), pero el
    /// ancho del backing se INFIERE del rango de valores en el type checker
    /// (i32 si todos caben en int, si no se ensancha a u32/i64/u64), imitando
    /// las reglas de C.  No confundir con `backing_type` fijo.
    bool c_style_auto_backing = false;
    std::vector<EnumVariantDecl> variants;
    /// marca `@Introspect`.  Ver `StructDecl`.
    bool is_introspect = false;
    ///  M6.a L.3: visibilidad cross-module (default true).
    bool is_public = true;
    /// L2.3: parametros de tipo opcionales `enum Maybe<T> { None, Some(T) }`.
    /// Si no esta vacio, el enum es un template y se monomorphiza on demand
    /// en cada uso `Maybe<i32>` (mismo modelo que generic classes A.8).
    std::vector<std::string> type_params;
    /// #6: constraints de los type-params (`enum E<T: Concepto>`).
    std::vector<TypeBound> type_bounds;
    /// Contratos de layout comprobables (modo --analyze): @size(N)
    /// (@pod/@no_heap aplican tambien, aunque un enum sin payload es
    /// trivialmente @pod).
    bool contract_pod = false;
    bool contract_no_heap = false;
    int64_t contract_size = -1;
    EnumDecl() : Node(NodeKind::EnumDecl) {}
};

/**
 * @struct ClassFieldDecl
 * @brief Campo de instancia o estatico de una clase.
 *
 * Estructura ligera (no hereda de Node) usada como elemento de un
 * vector dentro de @c ClassDecl.  Modificadores @c access, @c is_static
 * y @c is_final se llenan por el parser; el type checker los valida
 * y los traduce a flags de @c FieldDecl al registrar la clase.
 */
struct ClassFieldDecl {
    std::unique_ptr<TypeNode> type;
    std::string name;
    std::unique_ptr<Expr> init; ///< null = sin valor por defecto
    SourceLoc loc;
    /// Direccion declarada (`in i64* p;`), ver @c ParamDir y la nota en
    /// @c StructFieldDecl::dir: en un campo queda el PERMISO.
    ParamDir dir = ParamDir::None;
    uint8_t access = 0; ///< 0 = default/public, 1 = private, 2 = protected
    bool is_static = false;
    bool is_final = false;
    // Sprint lombok (2026-06-03): anotaciones a nivel de campo.
    // El pre-pase de TypeChecker genera metodos sinteticos segun
    // estos flags antes de check_classes.
    bool lombok_getter = false;  ///< @Getter -> get_<name>()
    bool lombok_setter = false;  ///< @Setter -> set_<name>(v)
    bool lombok_nonnull = false; ///< @NonNull -> check runtime
    bool lombok_with = false;    ///< @With -> with_<name>(v) -> nueva instancia
    bool lombok_getter_lazy = false; ///< @Getter(lazy=true)
};

/**
 * @struct ClassMethodDecl
 * @brief Metodo o constructor de una clase.
 *
 * Reusa la firma de @c FunctionDecl pero anade un primer parametro
 * implicito @c this (no listado en @c params).  El campo
 * @c is_constructor distingue el ctor del resto de metodos: el ctor
 * tiene el mismo nombre que la clase y no devuelve valor.
 */
struct ClassMethodDecl : Node {
    std::unique_ptr<TypeNode> return_type; ///< null si es constructor
    std::string name;
    std::vector<std::unique_ptr<ParamDecl>> params;
    std::unique_ptr<BlockStmt> body;
    uint8_t access = 0;
    bool is_static = false;
    bool is_final = false;
    bool is_override = false;
    /// `@Virtual` (structs): el metodo se despacha dinamicamente por vtable
    /// (modelo AOT: vtable estatica + devirtualizacion a llamada directa cuando
    /// el tipo concreto se conoce).  Opt-in por metodo; el resto es estatico.
    /// Prohibido combinar con `Self` (mecanismos opuestos) o con `static`.
    bool is_virtual = false;
    bool is_constructor = false;
    /// F1b: constructor `comptime T(expr)` de un struct value-type.  Se ejecuta
    /// en compile-time (ComptimeVM) y materializa el struct; base de los
    /// literales de tipo usuario (modelo Swift ExpressibleByIntegerLiteral).
    /// Solo valido en constructores; el lowering lo baja a
    /// `__macro_<T>__ctor_N` y el call site `T(literal)` lo invoca via
    /// `invoke_struct_macro`.
    bool is_comptime = false;
    /// true si es destructor `~ClassName()` declarado dentro
    /// del cuerpo de la clase.  Sin parametros (validado en parser).
    /// Body lowereado como un metodo void normal; el frontend invoca
    /// CALLVIRT al destructor automaticamente al exit del scope para
    /// instancias locales que NO escapan (escape detection ya
    /// rastrea esto).
    bool is_destructor = false;
    /// @brief Si el metodo es un advice AOP.  @c advice_kind:
    /// 0 = no es advice (default), 1 = BEFORE, 2 = AFTER, 3 = AROUND.
    /// @c advice_target tiene la forma "ClassName.methodName" extraida
    /// del argumento de la anotacion (@Before("Animal.sonido")).  El
    /// lowering lo resuelve via findclass/findmethod en __module_init.
    uint8_t advice_kind = 0;
    std::string advice_target;
    /// @brief Contratos de huella declarados sobre el metodo, iguales a los de
    ///        una funcion libre (ver @ref FunctionDecl):
    ///
    ///     @pure @nothrow @nopanic @alloc(N) @stack(N) @complexity(O(...))
    ///
    /// Un metodo hace lo mismo que una funcion libre con un argumento mas, asi
    /// que no habia motivo para que no pudiera declarar lo mismo -- y sin esto,
    /// un tipo cuya API son METODOS (`atomic<T>`, las colecciones, ...) no
    /// puede declarar sus propiedades aunque el compilador sepa verificarlas.
    bool contract_pure = false;          ///< @pure declarado.
    bool contract_nothrow = false;       ///< @nothrow declarado.
    bool contract_nopanic = false;       ///< @nopanic declarado.
    int64_t contract_alloc = -1;         ///< @alloc(total: N) o `@alloc(N)`.
    int64_t contract_alloc_partial = -1; ///< @alloc(partial: N).
    int64_t contract_stack = -1;         ///< @stack(total: N) o `@stack(N)`.
    int64_t contract_stack_partial = -1; ///< @stack(partial: N).
    /// @complexity(...) del metodo.  Mismos campos y semantica que en
    /// @ref FunctionDecl: `complexity_expr` es azucar de `total_post`.
    std::string complexity_expr;
    std::vector<std::string> complexity_vars;
    std::string complexity_partial_pre;
    std::string complexity_partial_post;
    std::string complexity_total_pre;
    std::string complexity_total_post;
    /// @complexity con un `when:` que habla del parametro de tipo: no se puede
    /// resolver al parsear (T aun no es nada), asi que se guarda tal cual y lo
    /// resuelve el clon de la monomorphizacion.  Ver @ref PendingComplexity.
    std::vector<PendingComplexity> complexity_pending;
    /// Contratos de HUELLA con `when:`, sin resolver.  Ver @ref
    /// PendingFootprint.
    std::vector<PendingFootprint> footprint_pending;

    /// @brief si !=0, el metodo es accesor de propiedad.
    /// 1 = getter (`public get name => expr;`).  Sin params, devuelve T.
    /// 2 = setter (`public set name(T v) { ... }`).  1 param, retorna void.
    /// El nombre interno almacenado en @c name es `get_<prop>` o
    /// `set_<prop>` para evitar colision con el field del mismo nombre;
    /// el frontend reescribe el acceso `obj.prop`/`obj.prop = X` a la
    /// llamada al metodo accesor correspondiente.
    uint8_t property_kind = 0;
    std::string property_name; ///< nombre logico de la propiedad (e.g. "value")

    /// @brief @Inline marca para inlining en el call site.
    /// El lowering, en lugar de emitir CALLVIRT, sustituye la llamada
    /// por una copia del body del metodo con `this` y los params
    /// resueltos a los SSA values del call site.  MVP: solo metodos
    /// expression-bodied o bloques con 1 statement, sin try/await/spawn.
    bool is_inline = false;
    /// Parametros de tipo del METODO (independientes de los del
    /// struct/clase contenedor).  `R metodo<U>(...)` produce
    /// method_type_params = ["U"].  Vacio para metodos no genericos.
    /// Dispatch SIEMPRE estatico (como C++/Rust): la llamada
    /// `obj.metodo<U>(args)` clona este metodo con U sustituido por el
    /// tipo concreto (`metodo_<mangle(U)>`) y lo baja como un metodo
    /// normal.  El metodo template (con method_type_params no vacio) se
    /// omite en el lowering.  Ver src/vx/generic_methods.cpp (#4).
    std::vector<std::string> method_type_params;
    /// #6: constraints de los type-params del METODO (`R m<U: Concepto>()`
    /// o `where U: A + B`).  Verificados al monomorphizar el metodo.
    std::vector<TypeBound> type_bounds;
    ClassMethodDecl() : Node(NodeKind::FunctionDecl) {}
};

/**
 * @struct ClassDecl
 * @brief Declaracion de una clase Vesta.
 *
 * Reference type con semantica Java: instancias creadas con
 * @c new ClassName(args) viven en heap (NEWOBJ), gestionadas por GC.
 * El type checker registra la clase en su tabla local; el lowering
 * la traduce a un bloque de inicializacion (defclass + deffield* +
 * defmethod*) que se ejecuta una vez por modulo antes de @c main.
 *
 * solo clases sin herencia ni interfaces.  La
 * superclass por defecto es @c null (equivalente a Object una vez
 * exista). Se anaden modificadores y final.
 */
struct ClassDecl : Node {
    std::string name;
    std::string super_name; ///< vacio = sin superclase explicita
    std::vector<std::string> interface_names;
    std::vector<ClassFieldDecl> fields;
    std::vector<std::unique_ptr<ClassMethodDecl>> methods;
    bool is_final = false;
    ///  M6.a L.3: visibilidad cross-module (default true).
    bool is_public = true;
    /// Parametros de tipo (templates).  `class Box<T>` produce
    /// type_params = ["T"].  Vacio para clases no genericas.  El
    /// type checker no procesa la clase como tal sino que la guarda
    /// como "plantilla" en @c generic_class_templates_; cada
    /// instanciado (`Box<i32>`) genera por monomorphizacion una
    /// nueva ClassDecl concreta con T -> i32 y la procesa como una
    /// clase normal (collect_classes + lower_class_methods).
    std::vector<std::string> type_params;
    /// #6: constraints de los type-params (`class C<T: Concepto>` o
    /// `where T: A + B`).  Verificados al monomorphizar; cero runtime.
    std::vector<TypeBound> type_bounds;
    /// #7: especializacion de CLASE generica (total/parcial).  Si
    /// @c is_specialization, @c spec_pattern son los type-args del patron
    /// y @c type_params los params frescos (mismo modelo que StructDecl).
    bool is_specialization = false;
    std::vector<std::unique_ptr<TypeNode>> spec_pattern;
    /// @brief Marca de aspecto AOP.  Si es @c true, los metodos con
    /// @Before/@After/@Around dentro de esta clase se registran como
    /// advices en __module_init (ademas de definirse como metodos
    /// normales para que el dispatch directo y la reflexion funcionen).
    bool is_aspect = false;
    /// @brief Marca de interfaz pura.  Si es @c true, esta declaracion
    /// procede del keyword @c interface y todos sus metodos son
    /// abstractos (sin body).  El type checker usa esto para validar
    /// que las clases implementadoras provean los metodos requeridos
    /// con firmas compatibles.  Las interfaces SI se registran en el
    /// ClassRegistry como ClassInfo* (sin instanciar) para que la
    /// reflexion (findclass) y el typeswitch las puedan localizar.
    bool is_interface = false;
    /// marca `@Introspect`.  Ver `StructDecl`.
    bool is_introspect = false;
    /// Contratos de layout/recurso comprobables (modo --analyze): @pod,
    /// @no_heap, @size(N).  Una clase es un tipo por REFERENCIA (vive en el
    /// heap), asi que @pod/@no_heap sobre una clase siempre resultan VIOLATED;
    /// @size(N) verifica el tamano de la instancia.  Metadata compile-time.
    bool contract_pod = false;
    bool contract_no_heap = false;
    int64_t contract_size = -1;
    // Sprint lombok (2026-06-03): anotaciones tipo Lombok a nivel de
    // clase.  El pre-pase de TypeChecker genera metodos sinteticos +
    // expanding combos como @Data / @Value antes de check_classes.
    bool lombok_getter = false;        ///< @Getter en todos los fields
    bool lombok_setter = false;        ///< @Setter en todos los fields no-final
    bool lombok_tostring = false;      ///< @ToString -> string toString()
    bool lombok_equals_hash = false;   ///< @EqualsAndHashCode
    bool lombok_no_args_ctor = false;  ///< @NoArgsConstructor
    bool lombok_all_args_ctor = false; ///< @AllArgsConstructor
    bool lombok_required_ctor =
        false; ///< @RequiredArgsConstructor (solo final/nonnull)
    bool lombok_data =
        false; ///< @Data = combo de Getter+Setter+ToString+EqHash+RequiredCtor
    bool lombok_value =
        false; ///< @Value = @Data inmutable (todos los fields final)
    bool lombok_builder = false;  ///< @Builder -> genera clase <Name>Builder
    bool lombok_with_all = false; ///< @With en todos los fields
    bool lombok_log = false;      ///< @Log -> field static logger
    bool lombok_sync_methods = false; ///< @Synchronized class-wide
    ClassDecl() : Node(NodeKind::ClassDecl) {}
};

/**
 * @struct ModuleNode
 * @brief Raiz del AST: lista de declaraciones top-level.
 */
/**
 * @struct GenericTemplateExport
 * @brief Fuente textual de una plantilla generica exportable cross-module.
 *
 * Los genericos se monomorphizan donde se USAN; para que un modulo importador
 * pueda instanciar `Caja<i64>` necesita el AST del template `struct Caja<T>`.
 * En vez de serializar el AST, guardamos el TEXTO FUENTE del decl (capturado
 * por el parser) en el `.vxi`; el importador lo re-parsea e inyecta en su AST.
 * Cubre struct/clase/funcion/enum genericos (type_params no vacios) y los
 * `concept`.  @c kind = NodeKind del decl.
 */
struct GenericTemplateExport {
    std::string name; ///< nombre del template (para diagnostico/dedup)
    uint8_t kind =
        0; ///< NodeKind del decl (Struct/Class/Function/Enum/Concept)
    std::string source; ///< texto fuente completo del decl
    bool is_public = true;
};

struct ModuleNode : Node {
    std::vector<std::unique_ptr<Node>> decls; ///< FunctionDecl o GlobalVarDecl.

    /// @NoExceptions a nivel modulo: deshabilita excepciones en TODO el
    /// modulo (todas las funciones + metodos lo heredan).  Para contextos
    /// que no pueden tenerlas (kernel, freestanding, embedded).
    bool no_exceptions = false;
    /// Plantillas genericas + conceptos declarados en este modulo, con su
    /// texto fuente para exportarlos cross-module via `.vxi`.  Lo rellena
    /// el parser; lo consume el emitter del `.vxi`.
    std::vector<GenericTemplateExport> generic_template_exports;
    /// El modulo contiene alguna anotacion @Target, asi que lo que declara
    /// DEPENDE del objetivo de compilacion.  Lo marca el parser en cuanto ve
    /// una; lo consume el emisor del `.vxi` para atar el artefacto a su
    /// objetivo (@c VxiHeader::target_offset).
    ///
    /// Es una distincion de eficiencia: sin ella habria que atar TODOS los
    /// `.vxi` al objetivo y cambiar de target recompilaria la stdlib entera,
    /// cuando en realidad la inmensa mayoria de modulos no depende de el.
    bool uses_conditional_target = false;
    /// Simbolos que este modulo declara SOLO para otros objetivos, con la(s)
    /// condicion(es) @Target bajo la(s) que si existen.  Quien resuelve
    /// nombres lo consulta cuando una busqueda falla, para poder decir
    /// "declarado para otro objetivo" en vez de "no declarado".
    std::unordered_map<std::string, std::vector<std::string>> target_skipped;
    ModuleNode() : Node(NodeKind::Module) {}
};

// -------------------------------------------------------------------
// Helpers de mapeo desde tokens (usados por el parser).
// -------------------------------------------------------------------

/**
 * @brief Convierte un TokenKind operador binario a BinOp.
 *
 * Devuelve @c true si el token es un operador binario reconocido.
 * El BinOp se escribe en @p out.
 */
bool binop_from_token(TokenKind k, BinOp &out) noexcept;

/**
 * @brief Convierte un TokenKind operador de asignacion a AssignOp.
 *
 * Devuelve @c true si el token es un operador de asignacion (incluido
 * el simple '=').  El AssignOp se escribe en @p out.
 */
bool assignop_from_token(TokenKind k, AssignOp &out) noexcept;

} // namespace vx::ast

#endif // VX_AST_H
