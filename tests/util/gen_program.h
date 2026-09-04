/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/gen_program.h
 * @brief Programas `.velb` generados por el propio test, para que un test que
 *        necesita un binario no dependa de que se lo pasen.
 *
 * POR QUE EXISTE.  Varios tests de este arbol piden un `.velb` por argumento y,
 * sin el, imprimen el uso y salen con codigo 2.  El lanzador lo cuenta --
 * correctamente -- como "pide argumentos, no es un fallo", con lo que NO SE
 * EJECUTAN nunca en la tanda: `test_bundles`, que es el que valida que los
 * paquetes no cambian el resultado, llevaba asi desde que existe.
 *
 * Es el mismo patron que dejo los veintiseis de `tests/aot/` meses sin correr,
 * y la leccion es la misma: una prueba que hay que acordarse de lanzar a mano
 * es una prueba que no se lanza.
 *
 * Generando el programa aqui, el test corre SIEMPRE y ademas controla que
 * ejercita -- que es algo que un `.velb` de fuera no garantiza.
 */

#ifndef VESTA_TESTS_GEN_PROGRAM_H
#define VESTA_TESTS_GEN_PROGRAM_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "emmit/parser_to_bytecode.h"
#include "lexer/lexer.h"
#include "linker/velb_linker_bytecode.h"
#include "parser/parser.h"

namespace tests {

/**
 * @brief Ensambla y enlaza un `.vel` dejandolo en @p output.
 * @return true si salio bien.
 */
inline bool assemble_program(const std::string &source,
                             const std::string &output) {
    try {
        vm::Lexer lexer(source);
        vm::Parser parser(lexer);
        auto program = parser.parse();
        Assembly::Bytecode::Assembler asmblr;
        std::vector<uint8_t> bytecode = asmblr.assemble(program);
        if (bytecode.empty()) return false;
        Assembly::Bytecode::Linker::LinkerOptions opts;
        // Sin optimizar: lo que escribe el generador es lo que se ejecuta, y
        // asi la cuenta de instrucciones del test sigue significando algo.
        opts.optimize_bytecode = false;
        opts.generate_map_file = false;
        opts.output_path = output;
        opts.verbose = false;
        Assembly::Bytecode::Linker::Linker linker(opts);
        linker.add_assembly_unit(bytecode, &asmblr.ctx);
        linker.write_to_file(opts.output_path);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "  no se pudo ensamblar: %s\n", e.what());
        return false;
    }
    return true;
}

/// Que clase de instrucciones lleva el cuerpo del programa generado.
enum class BodyKind {
    Alu,     ///< aritmetica y logica entre registros
    Widths,  ///< las mismas en 8/16/32/64: ejercita el despacho por ANCHO
    Memory,  ///< cargas y almacenes: pasa por la traduccion de direcciones
    Branch,  ///< saltos condicionales cortos: rompe el tramo recto a menudo
    Float,   ///< coma flotante escalar: OTRO banco de registros
    Mixed,   ///< las anteriores alternadas
};

/// @brief Nombre corto de una clase, para los nombres de fichero y las tablas.
inline const char *body_kind_name(BodyKind k) {
    switch (k) {
    case BodyKind::Alu: return "alu";
    case BodyKind::Widths: return "anchos";
    case BodyKind::Memory: return "memoria";
    case BodyKind::Branch: return "ramas";
    case BodyKind::Float: return "float";
    default: return "mixta";
    }
}

/// @brief Una instruccion del cuerpo, de la clase pedida.
inline std::string body_instruction(BodyKind kind, uint32_t i) {
    BodyKind k = kind;
    if (kind == BodyKind::Mixed) k = static_cast<BodyKind>(i % 5);

    const std::string rn = std::to_string((int)(i % 3) + 2); // r2..r4
    const std::string other = std::to_string((int)((i + 1) % 3) + 2);
    switch (k) {
    case BodyKind::Widths: {
        static const char *kSuf[4] = {"b", "w", "d", ""};
        const std::string s = kSuf[i % 4];
        if (i % 2 == 0) return "    adds r" + rn + s + ", 3\n";
        return "    xor r" + rn + s + ", r" + other + s + "\n";
    }
    case BodyKind::Memory:
        // Direccion fija: lo que se quiere ejercitar es el ACIERTO de la cache
        // de pagina, que es el caso comun; el fallo tiene otra historia.
        //
        // Y BIEN LEJOS del codigo (r14 = 0x800000).  Con 0x10000 el programa
        // largo -- 2,2 MB de codigo -- se escribia ENCIMA de si mismo y moria
        // ejecutando basura en 0x10002.
        if (i % 2 == 0) return "    mov [r14], r" + rn + "\n";
        return "    mov r" + rn + ", [r14]\n";
    case BodyKind::Branch:
        /* Un salto condicional que NUNCA se toma.  Rompe el tramo recto sin
         * cambiar el flujo, que es lo que hace falta para que el paquete tenga
         * que decidir si sigue o abandona -- y ese es justo el camino que mas
         * facil es romper al formar. */
        return "    cmps r" + rn + ", r" + rn +
               "\n    jmp.jne @Absolute(\"code.nunca\")\n";
    case BodyKind::Float: {
        const std::string f = "f" + std::to_string((int)(i % 3) + 2);
        const std::string g = "f" + std::to_string((int)((i + 1) % 3) + 2);
        if (i % 2 == 0) return "    fadd " + f + ", " + g + "\n";
        return "    fsub " + f + ", " + g + "\n";
    }
    default:
        if (i % 3 == 0) return "    adds r" + rn + ", 3\n";
        if (i % 3 == 1) return "    subs r" + rn + ", 1\n";
        return "    xor r" + rn + ", r" + other + "\n";
    }
}

/**
 * @brief Un bucle con @p body instrucciones rectas por vuelta.
 *
 * El cuerpo alterna registros a proposito: mil `adds r0, 1` seguidos medirian
 * una cadena de dependencias en serie, no el despacho.
 *
 * @param loops Vueltas del bucle.
 * @param body  Instrucciones rectas dentro de la vuelta.
 * @return El fuente `.vel`.
 */
inline std::string make_loop_program(uint64_t loops, uint32_t body,
                                     BodyKind kind = BodyKind::Alu) {
    static const char *kSkeleton = R"VEL(
@Format("raw")
@SpaceAddress { @Name("anonymous"), @IniAddress(0x0000000000000000),
                @EndAddress(0xFFFFFFFFFFFFFFFF) }
/* La seccion se llama `code` porque las referencias son `@Absolute("code.X")`:
 * el prefijo es el nombre de la SECCION, no una etiqueta.  Con la seccion
 * llamada `all` el simbolo no resolvia y el salto quedaba en 0 -- que es
 * `main`, o sea el `enter` --, asi que cada vuelta empujaba un marco que nadie
 * cerraba: la pila crecia sin fin y la VM pedia una arena nueva cada 512
 * vueltas.  Gigabytes, y ni un aviso. */
@Section { @Name("code"), @SpaceAddress("anonymous") @Align(0x1000) }
main:
    enter 0
    mov r1, %LOOPS%
    mov r0, 0
    mov r14, 0x800000
    mov r2, 1
    mov r3, 2
    mov r4, 3
    fmowi f2, 0x3FF0000000000000
    fmowi f3, 0x3FF0000000000000
    fmowi f4, 0x3FF0000000000000
vuelta:
%BODY%    adds r0, 1
    subs r1, 1
    cmps r1, 0
    jmp.jne @Absolute("code.vuelta")
    leave
    hlt
nunca:
    leave
    hlt
)VEL";

    std::string straight;
    straight.reserve((size_t)body * 24);
    for (uint32_t i = 0; i < body; ++i) straight += body_instruction(kind, i);

    std::string src = kSkeleton;
    const size_t pl = src.find("%LOOPS%");
    src.replace(pl, 7, std::to_string(loops));
    const size_t pb = src.find("%BODY%");
    src.replace(pb, 6, straight);
    return src;
}

/**
 * @brief Los programas por defecto de los tests de paquetes.
 *
 * Dos, y con intencion:
 *
 *   - `corto`: un bucle apretado.  Forma un punado de paquetes y no llena
 *     nada.  Es el caso normal.
 *   - `largo`: un tramo recto de cientos de miles de instrucciones.  Forma mas
 *     paquetes de los que caben en una region, o sea que OBLIGA a recoger.  Es
 *     el unico que ejercita la copia, el intercambio y el reinicio de la cache
 *     de doble region; sin el, el recolector estaria sin probar.
 *
 * @param prefix Prefijo de los ficheros generados.
 * @return Rutas de los `.velb`, o vacio si algo fallo.
 */
inline std::vector<std::string>
default_bundle_programs(const char *prefix = "test_bundles") {
    struct Case {
        const char *name;
        uint64_t loops;
        uint32_t body;
        BodyKind kind;
    };
    /* UN solo programa sintetico no valida nada: cubre un camino y deja los
     * demas sin mirar.  Estos siete se eligen para que entre todos toquen las
     * decisiones que el formador de paquetes tiene que acertar:
     *
     *   - las seis CLASES de instruccion, porque cada una entra al paquete por
     *     un sitio: la aritmetica va por el manejador rapido, los anchos por la
     *     tabla por tamano, la memoria por la traduccion de direcciones, la
     *     coma flotante por OTRO banco de registros, y las ramas obligan al
     *     paquete a decidir si sigue o abandona -- que es el camino que mas
     *     facil es romper.
     *   - dos LONGITUDES: una corta que no llena nada, y una que desborda la
     *     region y OBLIGA a recoger.  Sin la segunda el recolector no se
     *     ejecutaria en el test. */
    /* Las vueltas dan unos pocos millones de instrucciones por programa: lo
     * suficiente para que las cabeceras se formen, se entren muchas veces y se
     * juzguen (`JUDGE_AFTER` = 64 entradas), sin que el test tarde.
     *
     * El que desborda va aparte: forma TODOS sus paquetes en la PRIMERA pasada
     * -- son 9375 cabeceras sobre una region de 8192 --, asi que darle vueltas
     * no anade cobertura, solo tiempo. */
    const Case kCases[] = {
        {"alu", 200000, 8, BodyKind::Alu},
        {"anchos", 200000, 8, BodyKind::Widths},
        {"memoria", 200000, 8, BodyKind::Memory},
        {"ramas", 100000, 8, BodyKind::Branch},
        {"float", 200000, 8, BodyKind::Float},
        {"mixta", 150000, 12, BodyKind::Mixed},
        {"desborda", 4, 300000, BodyKind::Mixed},
    };

    std::vector<std::string> out;
    for (const Case &c : kCases) {
        const std::string path = std::string(prefix) + "_" + c.name + ".velb";
        if (!assemble_program(make_loop_program(c.loops, c.body, c.kind), path))
            return {};
        out.push_back(path);
    }
    return out;
}

} // namespace tests

#endif // VESTA_TESTS_GEN_PROGRAM_H
