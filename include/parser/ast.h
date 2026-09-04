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
 * @brief Arboles de Sintaxis Abstracta (AST) para el lenguaje ensamblador de
 * VestaVM.
 *
 * Define la jerarquia de nodos del AST que representa el codigo parseado.
 * Cada nodo concreto hereda de @c ASTNode e implementa @c print() para
 * depuracion.
 *
 * Tipos de nodo disponibles:
 *  - @c LabelDecl        : declaracion de label (p.ej. @c code:).
 *  - @c Instruction      : instruccion con mnemotecnico y lista de operandos.
 *  - @c DataDecl         : directiva de datos (db, dw, dd, dq, ptr).
 *  - @c RegisterNode     : referencia a un registro de la VM.
 *  - @c NumberLiteral    : literal numerico (entero o flotante).
 *  - @c StringLiteral    : literal de cadena.
 *  - @c ExprNode         : expresion binaria (+, -, *, /).
 *  - @c MemRefNode       : referencia a memoria ([reg] o [reg+off]).
 *  - @c SIBNode          : direccionamiento SIB (base + index*scale + disp).
 *  - @c AnnotationNode   : anotacion de metadatos (@SpaceAddress, @Section,
 * ...).
 *  - @c ImportNode       : directiva de importacion de archivo (.vel externo).
 */

#ifndef AST_H
#define AST_H

#include <iostream>
#include <memory>
#include <ostream>

#include "lexer/lexer.h"
#include "parser/parser.h"

/**
 * @namespace vm
 * @brief Namespace principal de Vesta.
 *
 * Contiene lexer, parser, AST y componentes
 */
namespace vm {
struct ExprNode;
/**
 * @struct ASTNode
 * @brief Nodo base abstracto del Arbol de Sintaxis Abstracta (AST).
 *
 * Todos los nodos del AST heredan de esta clase base proporcionando:
 * - Polimorfismo para visitors/generacion de codigo
 * - Gestion automatica de memoria (RAII)
 * - Extensibilidad para nuevas construcciones sintacticas
 */
/**
 * @enum NodeKind
 * @brief De que clase es un nodo, sin preguntarselo al sistema de tipos.
 *
 * El emisor de bytecode desentierra la clase de cada operando para codificarlo,
 * y lo hacia con `dynamic_cast`: 184 veces, y recorriendo la jerarquia de tipos
 * en EJECUCION cada una.  Medido con VTune sobre un fuente de 21k lineas, eran
 * 91 millones de instrucciones -- el 4,6 % de todo lo que ejecuta el compilador
 * -- para responder algo que el nodo sabe de si mismo desde que se construyo.
 *
 * Solo llevan etiqueta las clases HOJA, que son las que se preguntan.  Para las
 * bases (@ref ExprNode) sigue valiendo `dynamic_cast`: ahi la pregunta es "y
 * alguna de sus derivadas?", que una etiqueta suelta no responde.
 */
enum class NodeKind : uint8_t {
    Unknown = 0, ///< nodo sin etiquetar: nadie pregunta por el
    Register,
    Number,
    Memory,
    LabelOperandK,
    Annotation,
    LabelNodeK,
    InstructionK,
    DataDeclK,
    ImportK,
    NumberExprK,
    StringExprK,
    LabelExprK,
    BinaryExprK,
    AbsRefExprK,
};

struct ASTNode {
    /**
     * @brief De que clase es este nodo.
     *
     * Devuelve una constante, asi que preguntarlo son dos lecturas y un salto,
     * frente a las docenas de instrucciones que cuesta recorrer la jerarquia de
     * tipos.  Ver @ref NodeKind.
     *
     * @return La etiqueta; @c Unknown en las clases que nadie pregunta.
     */
    virtual NodeKind node_kind() const { return NodeKind::Unknown; }

    /**
     * @brief Destructor virtual para polimorfismo correcto.
     *
     * Garantiza que los destructores de nodos derivados se llamen
     * correctamente.
     */
    virtual ~ASTNode() = default;

    /**
     * @brief Imprime el nodo con indentacion para visualizacion jerarquica.
     * @param indent Nivel de indentacion (espacios)
     */
    virtual void print(int indent) const { std::cout << "ASTNode"; }
};

/**
 * @struct LabelDecl
 * @brief Declaracion de etiqueta/label (`code:`, `data:`, `end_code:`, etc.).
 *
 * Representa las secciones delimitadoras del lenguaje:
 * ```
 * code:      <- LabelDecl("code")
 * end_code:  <- LabelDecl("end_code")
 * data:      <- LabelDecl("data")
 * ```
 */
struct LabelDecl : ASTNode {
    std::string
        name; ///< Nombre de la etiqueta (`code`, `data`, `end_code`, etc.)

    /**
     * @brief Constructor implicito de LabelDecl.
     * @param n Nombre de la etiqueta
     */
    LabelDecl(std::string n) : name(std::move(n)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "LABEL: " << name << std::endl;
    }
};

/**
 * @struct Instruction
 * @brief Instruccion generica de la VM (mov, add, jmp, call, etc.)
 */
struct Instruction : ASTNode {
    static constexpr NodeKind kKind = NodeKind::InstructionK;
    NodeKind node_kind() const override { return kKind; }
    std::string opcode;                             // "mov", "add", "jmp", "db"
    std::vector<std::unique_ptr<ASTNode>> operands; // r0, 1, "msg", etc.
    // Linea fuente Vesta que origino esta instruccion (capturada del
    // marcador `// @line N` previo en el .vel).  0 = sin info (la
    // instruccion no proviene de codigo Vesta con --vx-debug).  Usado
    // por el linker para construir la seccion DebugLineEntry[] del
    // .velb que el debugger usa para resolver `b file.vx:42`.
    int source_line = 0;
    /// Columna del fuente, o 0 si no consta.  Con la linea sola no se puede
    /// senalar cual de las cosas que caben en ella fallo.
    int source_column = 0;

    // Stackmap PRECISO ( E.1) para esta instruccion de safepoint,
    // capturado del marcador `// @sm <hex>` previo en el .vel.  Vacio =
    // esta instruccion no es un safepoint con info precisa de raices GC.
    // El ensamblador lo decodifica y registra en Context::stackmap_recs;
    // el linker lo emite como seccion VSMP del .velb.
    std::string stackmap_hex;

    Instruction(std::string op, std::vector<std::unique_ptr<ASTNode>> ops)
        : opcode(std::move(op)), operands(std::move(ops)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "INSTR: " << opcode;
        for (const auto &op : operands) {
            std::cout << " ";
            if (op)
                op->print(0); // Sin indentacion extra
            else
                std::cout << "NULL";
        }
        std::cout << std::endl;
    }
};

/**
 * Nodo que indica la importacion de un archivo
 */
struct ImportNode : ASTNode {
    static constexpr NodeKind kKind = NodeKind::ImportK;
    NodeKind node_kind() const override { return kKind; }
    std::string filename;

    ImportNode(const std::string &f) : filename(f) {}

    void print(int indent = 0) const override {
        std::string pad(indent, ' ');
        std::cout << pad << "IMPORT: " << filename << "\n";
    }
};

struct EndLabelNode : ASTNode {
    std::string label;

    EndLabelNode(const std::string &label) : label(label) {}

    void print(int indent = 0) const override {
        std::string pad(indent, ' ');
        std::cout << pad << "END: " << label << "\n";
    }
};

/**
 * @struct ExprNode
 * @brief Nodo base para representar expresiones aritmeticas en directivas de
 * datos.
 *
 * Las expresiones pueden incluir:
 * - Literales numericos
 * - Labels
 * - Operadores binarios (+, -, *, /)
 * - Operadores unarios (+, -)
 */
struct ExprNode : ASTNode {
    ~ExprNode() override = default;

    /**
     * @brief Imprime el nodo de expresion.
     * @param indent Nivel de indentacion
     */
    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "EXPR";
    }
};

struct StringExpr : ExprNode {
    static constexpr NodeKind kKind = NodeKind::StringExprK;
    NodeKind node_kind() const override { return kKind; }
    std::string value;

    explicit StringExpr(std::string v) : value(std::move(v)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "STRING_EXPR: \"" << value
                  << "\"\n";
    }
};

/**
 * @struct NumberExpr
 * @brief Expresion que representa un literal numerico.
 */
struct NumberExpr : ExprNode {
    static constexpr NodeKind kKind = NodeKind::NumberExprK;
    NodeKind node_kind() const override { return kKind; }
    std::string value;

    explicit NumberExpr(std::string v) : value(std::move(v)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "NUMBER_EXPR: " << value
                  << std::endl;
    }
};

/**
 * @struct LabelExpr
 * @brief Expresion que representa un identificador (label).
 */
struct LabelExpr : ExprNode {
    static constexpr NodeKind kKind = NodeKind::LabelExprK;
    NodeKind node_kind() const override { return kKind; }
    std::string name;

    explicit LabelExpr(std::string n) : name(std::move(n)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "LABEL_EXPR: " << name
                  << std::endl;
    }
};

/**
 * @struct AbsRefExpr
 * @brief Referencia absoluta a un simbolo (`@Absolute("code.<sym>")`) usada
 * como VALOR de una directiva de datos (`dq @Absolute("code.Tipo__m")`).  A
 * diferencia de @c LabelExpr (que @c eval_expr resuelve al offset local sin
 * reloc), esta registra una relocacion @c Absolute64 que el linker rebasa a la
 * direccion VM final del simbolo.  La usa la vtable de los structs @Virtual
 * (reloc datos->codigo).
 */
struct AbsRefExpr : ExprNode {
    static constexpr NodeKind kKind = NodeKind::AbsRefExprK;
    NodeKind node_kind() const override { return kKind; }
    std::string symbol; ///< nombre completo del simbolo, p.ej. "code.Tipo__m".

    explicit AbsRefExpr(std::string s) : symbol(std::move(s)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "ABSREF_EXPR: " << symbol
                  << std::endl;
    }
};

/**
 * @struct BinaryExpr
 * @brief Expresion binaria (expr + expr, expr - expr, etc.).
 */
struct BinaryExpr : ExprNode {
    static constexpr NodeKind kKind = NodeKind::BinaryExprK;
    NodeKind node_kind() const override { return kKind; }
    char op;
    std::unique_ptr<ExprNode> left;
    std::unique_ptr<ExprNode> right;

    BinaryExpr(char o, std::unique_ptr<ExprNode> l, std::unique_ptr<ExprNode> r)
        : op(o), left(std::move(l)), right(std::move(r)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "BINARY_EXPR (" << op << ")\n";
        left->print(indent + 4);
        right->print(indent + 4);
    }
};

/**
 * @struct UnaryExpr
 * @brief Expresion unaria (+expr, -expr).
 */
struct UnaryExpr : ExprNode {
    char op;
    std::unique_ptr<ExprNode> expr;

    UnaryExpr(char o, std::unique_ptr<ExprNode> e)
        : op(o), expr(std::move(e)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "UNARY_EXPR (" << op << ")\n";
        expr->print(indent + 4);
    }
};

/**
 * @struct DataDecl
 * @brief Declaracion de datos estaticos (`msg db "Hola"`, `size dw label1 -
 * label2`).
 *
 * Ahora soporta expresiones completas gracias a ExprNode.
 */
struct DataDecl : ASTNode {
    static constexpr NodeKind kKind = NodeKind::DataDeclK;
    NodeKind node_kind() const override { return kKind; }
    std::string label;     ///< Nombre del simbolo (msg, bytes, count)
    std::string directive; ///< Directiva de datos (db, dw, dd, dq, ptr)
    std::vector<std::unique_ptr<ExprNode>> values; ///< Lista de expresiones

    /**
     * @brief Constructor de DataDecl.
     * @param l Nombre del simbolo
     * @param d Directiva de datos
     * @param vals Lista de expresiones parseadas
     */
    DataDecl(std::string l, std::string d,
             std::vector<std::unique_ptr<ExprNode>> vals)
        : label(std::move(l)), directive(std::move(d)),
          values(std::move(vals)) {}

    /**
     * @brief Imprime la declaracion de datos y sus expresiones.
     */
    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "DATA_DECL: " << label << " "
                  << directive << "\n";

        for (const auto &expr : values) {
            expr->print(indent + 4);
        }
    }
};

struct LabelNode : ASTNode {
    static constexpr NodeKind kKind = NodeKind::LabelNodeK;
    NodeKind node_kind() const override { return kKind; }
    std::string name;
    std::vector<std::unique_ptr<ASTNode>> body;

    LabelNode(std::string n, std::vector<std::unique_ptr<ASTNode>> b)
        : name(std::move(n)), body(std::move(b)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "LABEL: " << name << std::endl;
        for (const auto &child : body) {
            if (child) child->print(indent + 4);
        }
    }
};

struct NumberLiteral : ASTNode {
    std::string value;
    explicit NumberLiteral(std::string v) : value(std::move(v)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "NUMBER: " << value
                  << std::endl;
    }
};

struct Operand : ASTNode {
    ~Operand() override = default;

    void print(int indent) const override = 0;
};

struct RegisterOperand : public Operand {
    static constexpr NodeKind kKind = NodeKind::Register;
    NodeKind node_kind() const override { return kKind; }
    std::string name; // "r0", "r15d", "rp"
    int size_bits;    // 8, 16, 32, 64

    RegisterOperand(std::string n, int size)
        : name(std::move(n)), size_bits(size) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "REG[" << size_bits
                  << "]: " << name;
    }
};

struct NumberOperand : public Operand {
    static constexpr NodeKind kKind = NodeKind::Number;
    NodeKind node_kind() const override { return kKind; }
    std::string value;
    TokenType type; // NUMBER_DEC, NUMBER_HEX, etc.

    NumberOperand(std::string v, TokenType t) : value(std::move(v)), type(t) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "NUM["
                  << token_type_to_string(type) << "]: " << value;
    }
};

struct StringOperand : public Operand {
    std::string value;

    StringOperand(std::string v) : value(std::move(v)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "STR: \"" << value << "\"";
    }
};

/**
 * Un operando de tipo Memoria puede ser:
 * -> [0x20000]
 * -> [r0 + r1 * r12]
 * -> [r3 + 8]
 * -> [r4 * 2]
 * -> [r1 + r2 * 4 + 0x100]
 */
struct MemoryOperand : ASTNode {
    static constexpr NodeKind kKind = NodeKind::Memory;
    NodeKind node_kind() const override { return kKind; }
    std::unique_ptr<ASTNode> expr; // expresion dentro de los corchetes

    MemoryOperand(std::unique_ptr<ASTNode> e) : expr(std::move(e)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "MEMORY: ";
        expr->print(indent);
    }
};

struct LabelOperand : Operand {
    static constexpr NodeKind kKind = NodeKind::LabelOperandK;
    NodeKind node_kind() const override { return kKind; }
    std::string name;

    LabelOperand(std::string n) : name(std::move(n)) {}

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "LABEL: " << name;
    }
};

struct AnnotationNode : ASTNode {
    static constexpr NodeKind kKind = NodeKind::Annotation;
    NodeKind node_kind() const override { return kKind; }
    std::string key;
    std::string value;
    std::vector<std::unique_ptr<AnnotationNode>> children;

    explicit AnnotationNode(std::string k, std::string v = "")
        : key(std::move(k)), value(std::move(v)) {}

    void add_child(std::unique_ptr<AnnotationNode> child) {
        children.push_back(std::move(child));
    }

    void print(int indent) const override {
        std::cout << std::string(indent, ' ') << "ANNOTATION: @" << key;
        if (!value.empty()) {
            std::cout << " = " << value;
        }
        std::cout << std::endl;

        for (const auto &child : children) {
            if (child) child->print(indent + 2);
        }
    }
};

/**
 * @brief @p n visto como @p T, o @c nullptr si no es de esa clase.
 *
 * Sustituye a `dynamic_cast` donde lo que se pregunta es por una clase HOJA,
 * que es casi siempre: el emisor de bytecode lo hace 184 veces para saber que
 * clase de operando esta codificando.  Hace lo mismo -- devuelve nulo si no
 * coincide -- pero comparando una etiqueta en vez de recorrer la jerarquia de
 * tipos en ejecucion.
 *
 * Solo compila con clases que tengan @c kKind, asi que preguntar por una que no
 * lleva etiqueta es un error de compilacion y no un nulo silencioso.  Para las
 * clases BASE sigue haciendo falta `dynamic_cast`: ahi la pregunta incluye a
 * las derivadas, y una etiqueta suelta no la responde.
 *
 * @tparam T Clase hoja por la que se pregunta.
 * @param n  Nodo, puede ser nulo.
 * @return El nodo como @p T, o @c nullptr.
 */
template <typename T> inline T *node_as(ASTNode *n) {
    return (n != nullptr && n->node_kind() == T::kKind) ? static_cast<T *>(n)
                                                        : nullptr;
}

/// @copydoc node_as
template <typename T> inline const T *node_as(const ASTNode *n) {
    return (n != nullptr && n->node_kind() == T::kKind)
               ? static_cast<const T *>(n)
               : nullptr;
}

} // namespace vm

#endif // AST_H
