/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_vxdbg_frontend.cpp
 * @brief De un fuente Vesta de verdad al grafo semantico.
 *
 * Los demas tests del subsistema construyen el grafo a mano.  Eso comprueba que
 * las piezas encajan, pero no que lo que el compilador SABE quepa en el modelo:
 * un grafo escrito para pasar el test siempre cabe.  Aqui se compila codigo
 * Vesta y se comprueba lo que salio.
 */

#include "vx/type_checker.h"
#include "vx/vxdbg_emit.h"
#include "vxdbg/codec.h"
#include "vxdbg/pack_store.h"
#include "vxdbg/store.h"

#include "vx/lexer.h"
#include "vx/lowering.h"
#include "vxdbg/roots.h"
#include "ir/ssa_ir.h"
#include "vx/parser.h"

#include <cstdio>
#include <thread>
#include <functional>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

#include "../test_support.h"

static int fallos = 0;

/**
 * @brief Comprueba una condicion y deja constancia.
 * @param cond Lo que debe cumplirse.
 * @param que Descripcion.
 */
static void comprobar(bool cond, const char *que) {
    if (cond) {
        std::printf("  OK   %s\n", que);
    } else {
        std::printf("  FALLA %s\n", que);
        ++fallos;
    }
}

/// Un programa con las formas que Vesta distingue de verdad.
static const char *FUENTE = R"(
interface Cerrable {
    void cerrar();
}

class Flujo {
    i64 pos;
    i64 leer() { return this.pos; }
}

class Lector : Flujo, Cerrable {
    i64 total;
    public Lector() { this.total = 0; }
    void cerrar() { this.total = 0; }
}

struct Punto {
    f64 x;
    f64 y;
    Punto(f64 a, f64 b) { this.x = a; this.y = b; }
    f64 suma() { return this.x + this.y; }
    ~Punto() { }
}

union Palabra {
    u32 entero;
    f32 real;
}

enum Color : u8 {
    Rojo = 1,
    Verde = 2,
}

i32 main() {
    return 0;
}
)";

/**
 * @brief Busca una entidad emitida por su clave.
 * @param stats Lo que reporto el emisor.
 * @param clave Clave del compilador.
 * @return Su identificador, o uno vacio.
 */
static vxdbg::LanguageEntityId buscar(const vx::VxdbgEmitStats &stats,
                                      const std::string &clave) {
    for (const auto &r : stats.roots)
        if (r.first == clave) return r.second;
    return {};
}

/**
 * @brief Lee una entidad del almacen.
 * @param store Almacen.
 * @param id Identificador.
 * @param out Recibe la entidad.
 * @return @c true si estaba.
 */
static bool leer(const vxdbg::NodeStore &store, vxdbg::LanguageEntityId id,
                 vxdbg::LanguageEntity &out) {
    if (id.hash.empty()) return false;
    return vxdbg::load_node(store, id.hash, out);
}

int main() {
    std::printf("=== vxdbg: del fuente Vesta al grafo semantico ===\n");

    // Carpeta propia para no mezclarse con el cache real del compilador.
    const std::string dir = vesta_test::dir_unico("vxdbg_frontend_test");
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);

    vx::Diagnostics diags;
    vx::Lexer lex(FUENTE, "prueba.vx", diags);
    vx::Parser parser(lex, diags);
    auto mod = parser.parse_program();
    if (!mod || diags.has_errors()) {
        std::printf("  FALLA el fuente de prueba no compila\n");
        return 1;
    }
    vx::TypeChecker tc(*mod, diags);
    if (!tc.run()) {
        std::printf("  FALLA el fuente de prueba no pasa el checker\n");
        for (const auto &d : diags.all())
            std::printf("    %s\n", d.message.c_str());
        return 1;
    }

    // El grafo se emite tras bajar a intermedio: es cuando existen los
    // SIMBOLOS, y sin ellos no habria por donde entrar desde una direccion de
    // ejecucion.
    ir::IrModule irmod;
    vx::Lowering lo(*mod, tc, diags);
    if (!lo.run(irmod, "prueba")) {
        std::printf("  FALLA el fuente de prueba no baja a intermedio\n");
        return 1;
    }

    // Los tramos de fuente, tal como los anoto el lowering al bajar cada
    // sentencia: son los que permiten subrayar lo que fallo y no solo la linea.
    std::vector<vxdbg::SourceExtent> tramos;
    for (const auto &e : lo.emitted_spans())
        tramos.push_back({e.symbol, e.line, e.column, e.length});

    vx::VxdbgEmitStats stats;
    std::string err;
    comprobar(vx::emit_vxdbg_source(tc, lo.emitted_symbols(), tramos,
                                    "prueba.vx", FUENTE, dir, stats, err),
              "se emite el grafo");
    comprobar(stats.entities > 0, "y no sale vacio");

    /* Se LEE con el mismo almacen con el que se ESCRIBIo.
     *
     * La emision EMPAQUETA -- un fichero por nodo se llevaba el 90% del tiempo
     * de compilar en frio --, y este test seguia leyendo con el almacen de
     * ficheros sueltos, que no sabe abrir un paquete.  Resultado: veinticuatro
     * comprobaciones sobre los tipos del programa dejaron de comprobar nada, y
     * en silencio: el grafo se emitia bien, solo que nadie miraba donde
     * estaba.
     *
     * El suelto va DETRAS y no en su lugar: lo que quede de una emision
     * anterior sin empaquetar se sigue leyendo igual. */
    vxdbg::PackNodeStore store(
        dir, std::unique_ptr<vxdbg::NodeStore>(new vxdbg::FileNodeStore(dir)));

    std::printf("Los tipos, con la especie que les corresponde\n");
    vxdbg::LanguageEntity e;
    comprobar(leer(store, buscar(stats, "Lector"), e), "la clase esta");
    comprobar(e.kind == vxdbg::EntityKind::Type && e.lang_kind == "class",
              "  es un tipo, y Vesta lo llama clase");
    // Lo que pedia el usuario ver en un fallo: de quien deriva y que cumple.
    size_t deriva = 0, cumple = 0;
    for (const auto &r : e.relations) {
        if (r.kind == vxdbg::RelationKind::Derives) ++deriva;
        if (r.kind == vxdbg::RelationKind::Implements) ++cumple;
    }
    comprobar(deriva == 1, "  deriva de una");
    comprobar(cumple == 1, "  y cumple un contrato");

    comprobar(leer(store, buscar(stats, "Cerrable"), e), "la interfaz esta");
    comprobar(e.kind == vxdbg::EntityKind::Contract,
              "  y es un contrato, no un tipo: se cumple, no se instancia");

    comprobar(leer(store, buscar(stats, "Punto"), e), "el struct esta");
    comprobar(e.kind == vxdbg::EntityKind::Type && e.lang_kind == "struct",
              "  con su genero");
    comprobar(e.byte_size == 16, "  y su tamano de verdad, no uno inventado");
    comprobar(e.alignment == 8, "  con su alineamiento");

    comprobar(leer(store, buscar(stats, "Palabra"), e), "la union esta");
    comprobar(e.lang_kind == "union", "  distinguida de un struct normal");

    comprobar(leer(store, buscar(stats, "Color"), e), "el enum esta");
    comprobar(e.kind == vxdbg::EntityKind::Enumeration, "  como enumeracion");
    comprobar(e.lang_kind == "valued enum",
              "  sabiendo que sus casos SON valores de otro tipo");

    std::printf("Nada se inventa\n");
    comprobar(stats.duplicates == 0, "ninguna clave se declaro dos veces");
    comprobar(buscar(stats, "NoExiste").hash.empty(),
              "un tipo que no existe no aparece");
    comprobar(stats.unresolved == 0, "y no queda ninguna relacion sin destino");

    std::printf("Los tramos de fuente\n");
    comprobar(!stats.span_map.empty(), "se emite el mapa de tramos");
    comprobar(!stats.spans.empty(), "con tramos dentro");
    {
        // Un tramo sirve de algo solo si trae columna: con la linea sola no se
        // distingue cual de las cosas que caben en ella fallo.
        bool con_columna = false;
        for (const auto &sp : stats.spans)
            if (sp.column > 0 && sp.length > 0) con_columna = true;
        comprobar(con_columna, "  y al menos uno dice columna y longitud");

        vxdbg::SpanMap sm;
        for (const auto &sp : stats.spans)
            sm.add(sp);
        const auto encontrado =
            sm.find(stats.spans[0].symbol, stats.spans[0].line);
        comprobar(encontrado.line == stats.spans[0].line,
                  "  y se encuentran por funcion y linea");
        comprobar(sm.find("NoExisteTalFuncion", 1).line == 0,
                  "  sin inventarse los que no estan");
    }

    std::printf("La puerta de entrada\n");
    comprobar(!stats.artifact_map.empty(), "se emite el mapa de simbolos");
    comprobar(stats.linked > 0, "con simbolos ligados a su entidad");

    // Una compilacion cualquiera, identificada por su CONTENIDO y no por como
    // se llame el fichero: es lo unico que sobrevive a renombrarlo o moverlo.
    const vxdbg::BuildId build{vxdbg::hash_bytes("artefacto-de-prueba", 19)};
    vxdbg::CacheRootRepository repo(dir, store);
    comprobar(repo.publish(build, stats.artifact_map),
              "y se publica bajo su identificador de construccion");

    vxdbg::ArtifactMap mapa;
    comprobar(repo.lookup(build, mapa), "que es por donde se entra despues");
    comprobar(!mapa.symbols.empty(), "  y trae los simbolos");

    // El recorrido que motiva todo esto: de un simbolo -- lo unico a lo que
    // llega una direccion -- a la declaracion que lo origino.
    const auto id_metodo = mapa.find("Lector__cerrar");
    comprobar(!id_metodo.hash.empty(), "  un simbolo lleva a su entidad");
    comprobar(leer(store, id_metodo, e), "  que se puede leer");
    comprobar(e.name == "cerrar" && e.kind == vxdbg::EntityKind::Function,
              "  y resulta ser el metodo que se escribio");

    // Lo que ninguna convencion adivinada acertaria: un constructor de clase se
    // emite como `Clase__ctor` y el de un struct como `Struct__ctor_<aridad>`,
    // formas que no salen del nombre del metodo.  Como el vinculo lo anota el
    // lowering al crear el nombre, estos se ligan igual que los demas.
    comprobar(!mapa.find("Lector__ctor").hash.empty(),
              "  un constructor de clase, que no se llama como su metodo");
    comprobar(!mapa.find("Punto__ctor_2").hash.empty(),
              "  uno de struct, que ademas lleva la aridad");
    comprobar(!mapa.find("Punto____dtor").hash.empty(), "  y un destructor");
    comprobar(!mapa.find("Punto__suma").hash.empty(), "  ademas del metodo");
    comprobar(stats.unlinked == 0,
              "  sin dejar ningun simbolo del lowering sin ligar");

    comprobar(mapa.find("NoExisteTalSimbolo").hash.empty(),
              "un simbolo desconocido no lleva a ningun sitio");

    const vxdbg::BuildId otra{vxdbg::hash_bytes("otra-compilacion", 16)};
    vxdbg::ArtifactMap vacio;
    comprobar(!repo.lookup(otra, vacio),
              "y otra compilacion no hereda el mapa de esta");

    std::printf("Se puede volver a emitir\n");
    // Emitir dos veces lo mismo tiene que dar exactamente los mismos nodos: es
    // la propiedad que hace incremental al sistema, y si se rompiera aqui el
    // cache creceria sin parar sin que nadie lo notara.
    vx::VxdbgEmitStats stats2;
    comprobar(vx::emit_vxdbg_source(tc, lo.emitted_symbols(), tramos,
                                    "prueba.vx", FUENTE, dir, stats2, err),
              "la segunda vez tambien va");
    comprobar(stats2.roots.size() == stats.roots.size(),
              "con los mismos tipos");
    bool iguales = true;
    for (size_t i = 0; i < stats.roots.size() && iguales; ++i)
        iguales = (stats.roots[i] == stats2.roots[i]);
    comprobar(iguales, "y exactamente las mismas huellas");

    std::filesystem::remove_all(dir, ec);

    if (fallos == 0) {
        std::printf("=== todo correcto ===\n");
        return 0;
    }
    std::printf("=== %d comprobaciones fallidas ===\n", fallos);
    return 1;
}
