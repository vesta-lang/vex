/**
 * @file test_vx_module_resolver.cpp
 * @brief Tests del resolver de modulos + dep graph + topo sort ( M.1).
 *
 * Construye fixtures con ficheros temporales en disco que se importan
 * entre si, verifica:
 *   - Resolucion de paths multi-plataforma (relativo + search path).
 *   - Construccion del dep graph siguiendo los imports.
 *   - Orden topologico (deps primero, dependents despues).
 *   - Deteccion de ciclos con mensaje claro.
 *   - Cache: el mismo modulo se carga UNA sola vez aunque aparezca en
 *     multiples imports.
 *   - Resolucion del path canonico (Windows `\` -> `/`).
 *
 * Estilo: cada test imprime PASS/FAIL en su linea con el contador final.
 * No usamos framework (consistente con el resto del proyecto).
 */

#include "vx/module/module_resolver.h"
#include "vx/diagnostic.h"
#include "vx/ast.h"
#include "util/toolchain_compat.h" // getpid: en MSVC se llama _getpid

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

namespace {

int g_checks_passed = 0;
int g_checks_failed = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) {                                                            \
            ++g_checks_passed;                                                 \
            std::cout << "  PASS  " << label << "\n";                          \
        } else {                                                               \
            ++g_checks_failed;                                                 \
            std::cout << "  FAIL  " << label << "  (" << __FILE__ << ":"       \
                      << __LINE__ << ")\n";                                    \
        }                                                                      \
    } while (0)

/// Crea un directorio temporal unico para esta corrida.  Lo devuelve
/// como ruta absoluta normalizada (forward slash).
std::string make_temp_dir(const std::string &suffix) {
    fs::path base = fs::temp_directory_path() /
                    ("vx_modtest_" + std::to_string(::getpid()) + "_" + suffix);
    fs::remove_all(base); // limpia si quedo de una corrida anterior
    fs::create_directories(base);
    std::string s = base.string();
    for (char &c : s)
        if (c == '\\') c = '/';
    return s;
}

void write_file(const std::string &path, const std::string &content) {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream f(path);
    f << content;
}

// --------------------------------------------------------------------------
// Test 1: cadena simple A -> B -> C, sin ciclos.  El topo debe emitir
// C, B, A en ese orden.
// --------------------------------------------------------------------------
void test_simple_chain() {
    std::cout << "\n[Test] cadena A -> B -> C\n";

    std::string root = make_temp_dir("chain");
    write_file(root + "/c.vx", "i32 main() { return 1; }\n");
    write_file(root + "/b.vx", "import \"c\";\n"
                               "i32 fn_b() { return 2; }\n");
    write_file(root + "/a.vx", "import \"b\";\n"
                               "i32 main() { return 3; }\n");

    vx::Diagnostics diags;
    vx::ModuleGraph graph(diags);

    const uint32_t root_id = graph.build_from_root(root + "/a.vx");
    CHECK(root_id != UINT32_MAX, "build_from_root devuelve id valido");
    CHECK(!diags.has_errors(), "no hay errores tras build");
    CHECK(graph.module_count() == 3, "se cargaron 3 modulos (a, b, c)");
    CHECK(!graph.has_cycle(), "no se detecto ciclo");

    auto order = graph.topological_order();
    CHECK(order.size() == 3, "topo order tiene 3 modulos");
    if (order.size() == 3) {
        const auto *m0 = graph.module(order[0]);
        const auto *m1 = graph.module(order[1]);
        const auto *m2 = graph.module(order[2]);
        CHECK(m0 && m0->module_name == "c", "primer en topo es 'c' (sin deps)");
        CHECK(m1 && m1->module_name == "b", "segundo en topo es 'b'");
        CHECK(m2 && m2->module_name == "a", "tercero en topo es 'a' (root)");
    }

    fs::remove_all(root);
}

// --------------------------------------------------------------------------
// Test 2: dependencia compartida (diamond).  A -> B -> D, A -> C -> D.
// D debe cargarse UNA sola vez.  Topo: D, (B|C), (C|B), A.
// --------------------------------------------------------------------------
void test_diamond() {
    std::cout << "\n[Test] diamond A->B->D, A->C->D\n";

    std::string root = make_temp_dir("diamond");
    write_file(root + "/d.vx", "i32 fn_d() { return 4; }\n");
    write_file(root + "/c.vx", "import \"d\";\n"
                               "i32 fn_c() { return 3; }\n");
    write_file(root + "/b.vx", "import \"d\";\n"
                               "i32 fn_b() { return 2; }\n");
    write_file(root + "/a.vx", "import \"b\";\n"
                               "import \"c\";\n"
                               "i32 main() { return 1; }\n");

    vx::Diagnostics diags;
    vx::ModuleGraph graph(diags);

    const uint32_t root_id = graph.build_from_root(root + "/a.vx");
    CHECK(root_id != UINT32_MAX, "build_from_root OK");
    CHECK(graph.module_count() == 4,
          "se cargaron 4 modulos (a,b,c,d, sin dups)");
    CHECK(!graph.has_cycle(), "no se detecto ciclo");

    auto order = graph.topological_order();
    CHECK(order.size() == 4, "topo order tiene 4 modulos");

    // d debe aparecer ANTES de b y c.  a debe ser el ultimo.
    if (order.size() == 4) {
        int pos_a = -1, pos_b = -1, pos_c = -1, pos_d = -1;
        for (size_t i = 0; i < order.size(); ++i) {
            const std::string &n = graph.module(order[i])->module_name;
            if (n == "a")
                pos_a = (int)i;
            else if (n == "b")
                pos_b = (int)i;
            else if (n == "c")
                pos_c = (int)i;
            else if (n == "d")
                pos_d = (int)i;
        }
        CHECK(pos_d >= 0 && pos_d < pos_b, "d antes de b");
        CHECK(pos_d >= 0 && pos_d < pos_c, "d antes de c");
        CHECK(pos_b < pos_a && pos_c < pos_a, "b y c antes de a");
    }

    fs::remove_all(root);
}

// --------------------------------------------------------------------------
// Test 3: ciclo A -> B -> A.  Debe detectarse y emitir error claro.
// --------------------------------------------------------------------------
void test_cycle() {
    std::cout << "\n[Test] ciclo A <-> B\n";

    std::string root = make_temp_dir("cycle");
    write_file(root + "/a.vx", "import \"b\";\n"
                               "i32 fn_a() { return 1; }\n");
    write_file(root + "/b.vx", "import \"a\";\n"
                               "i32 fn_b() { return 2; }\n");

    vx::Diagnostics diags;
    vx::ModuleGraph graph(diags);

    const uint32_t root_id = graph.build_from_root(root + "/a.vx");
    CHECK(root_id != UINT32_MAX, "build_from_root devuelve id (parse OK)");
    CHECK(graph.module_count() == 2, "2 modulos cargados");

    // build_from_root NO detecta el ciclo (eso pasa en topo).  Solo
    // topological_order lo detecta.
    auto order = graph.topological_order();
    CHECK(graph.has_cycle(), "ciclo detectado en topological_order");
    CHECK(diags.has_errors(), "diagnostics tiene errores tras topo");

    fs::remove_all(root);
}

// --------------------------------------------------------------------------
// Test 4: modulo no encontrado.  Debe emitir error con la lista de
// paths probados.
// --------------------------------------------------------------------------
void test_not_found() {
    std::cout << "\n[Test] modulo no encontrado\n";

    std::string root = make_temp_dir("missing");
    write_file(root + "/a.vx", "import \"no_existe\";\n"
                               "i32 main() { return 0; }\n");

    vx::Diagnostics diags;
    vx::ModuleGraph graph(diags);

    const uint32_t root_id = graph.build_from_root(root + "/a.vx");
    // root_id es valido (a.vx existe y parsea) pero hay error de import.
    CHECK(root_id != UINT32_MAX, "el root se carga aunque haya import roto");
    CHECK(diags.has_errors(),
          "diagnostics reporta error de modulo no encontrado");

    fs::remove_all(root);
}

// --------------------------------------------------------------------------
// Test 5: normalizacion de paths (forward slash + colapso `..`).
// --------------------------------------------------------------------------
void test_path_normalization() {
    std::cout << "\n[Test] normalizacion de paths\n";

    std::string root = make_temp_dir("paths");
    fs::create_directories(root + "/sub");
    write_file(root + "/sub/lib.vx", "i32 fn_lib() { return 9; }\n");
    write_file(root + "/main.vx",
               "import \"sub/lib\";\n" // import normal
               "i32 main() { return 0; }\n");

    vx::Diagnostics diags;
    vx::ModuleGraph graph(diags);

    const uint32_t root_id = graph.build_from_root(root + "/main.vx");
    CHECK(root_id != UINT32_MAX, "build OK");
    CHECK(!diags.has_errors(), "sin errores con path subdir");
    CHECK(graph.module_count() == 2, "main + sub/lib cargados");

    if (graph.module_count() == 2) {
        // Cada canonical_path debe usar '/' (no '\\').
        for (size_t i = 0; i < graph.module_count(); ++i) {
            const auto *m = graph.module(static_cast<uint32_t>(i));
            CHECK(m != nullptr, "modulo no nulo");
            if (m) {
                bool no_backslash =
                    (m->canonical_path.find('\\') == std::string::npos);
                CHECK(no_backslash, "canonical_path sin backslash");
            }
        }
    }

    fs::remove_all(root);
}

// --------------------------------------------------------------------------
// Test 6: import con alias y selectivo (parsing).  Verifica que el AST
// preserva alias y only_symbols correctamente.
// --------------------------------------------------------------------------
void test_import_alias_and_only() {
    std::cout << "\n[Test] alias + only (parsing AST)\n";

    // Nota: 'public' a nivel de top-level fn es trabajo futuro (M6).
    // En M1 solo verificamos el PARSING del import, no la resolucion
    // de simbolos publicos cross-module.  Por eso lib.vx no usa public.
    std::string root = make_temp_dir("alias");
    write_file(root + "/lib.vx", "i32 fn_a() { return 1; }\n"
                                 "i32 fn_b() { return 2; }\n");
    write_file(root + "/main.vx", "import \"lib\" as core;\n"
                                  "import \"lib\" only fn_a, fn_b as bee;\n"
                                  "i32 main() { return 0; }\n");

    vx::Diagnostics diags;
    vx::ModuleGraph graph(diags);

    const uint32_t root_id = graph.build_from_root(root + "/main.vx");
    CHECK(root_id != UINT32_MAX, "build OK");
    CHECK(!diags.has_errors(), "sin errores de parse");

    const auto *main_mod = graph.module(root_id);
    CHECK(main_mod != nullptr, "modulo main valido");
    if (main_mod && main_mod->parsed_ast) {
        int alias_imports = 0, only_imports = 0;
        for (auto &d : main_mod->parsed_ast->decls) {
            if (d && d->kind == vx::ast::NodeKind::ImportDecl) {
                auto *imp = static_cast<vx::ast::ImportDecl *>(d.get());
                if (!imp->alias.empty()) ++alias_imports;
                if (!imp->only_symbols.empty()) ++only_imports;
                // Verificar rename en only: "fn_b as bee".
                if (imp->only_symbols.size() == 2) {
                    CHECK(imp->only_symbols[0].name == "fn_a" &&
                              imp->only_symbols[0].rename.empty(),
                          "only_symbols[0] = fn_a sin rename");
                    CHECK(imp->only_symbols[1].name == "fn_b" &&
                              imp->only_symbols[1].rename == "bee",
                          "only_symbols[1] = fn_b as bee");
                }
            }
        }
        CHECK(alias_imports == 1, "1 import con alias");
        CHECK(only_imports == 1, "1 import con only");
    }

    fs::remove_all(root);
}

} // namespace

int main() {
    std::cout << "=== test_vx_module_resolver:  M.1 ===\n";

    test_simple_chain();
    test_diamond();
    test_cycle();
    test_not_found();
    test_path_normalization();
    test_import_alias_and_only();

    std::cout << "\n=== Resultado: " << g_checks_passed << " PASS, "
              << g_checks_failed << " FAIL ===\n";

    return (g_checks_failed == 0) ? 0 : 1;
}
