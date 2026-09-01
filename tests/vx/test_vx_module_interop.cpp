/**
 * @file test_vx_module_interop.cpp
 * @brief Round-trip TypeChecker -> VxiModule -> serialized -> parsed
 *        -> TypeChecker ( M.2.d).
 *
 * Verifica el ciclo completo de compartir simbolos cross-module:
 *
 *  1. Compilar un modulo "lib" via el TypeChecker normal.
 *  2. Exportar su estado a un VxiModule via export_typechecker_to_vxi.
 *  3. Serializarlo a bytes via vxi_emit.
 *  4. Parsear los bytes con vxi_parse.
 *  5. Crear un segundo TypeChecker (modulo "main") e inyectar los
 *     simbolos via import_vxi_into_typechecker con only_symbols.
 *  6. Verificar que el segundo TypeChecker conoce los simbolos
 *     inyectados (resuelve nombres correctamente).
 *
 * Esto demuestra que la cadena M2.a -> M2.b -> M2.c -> M2.d funciona
 * end-to-end SIN aun integrar al pipeline compile_vx_source (eso es
 * M2.e en el siguiente sprint).
 */

#include "vx/module/module_interop.h"
#include "vx/module/vxi_format.h"
#include "vx/type_checker.h"
#include "vx/diagnostic.h"
#include "vx/lexer.h"
#include "vx/parser.h"
#include "vx/ast.h"

#include <cstdio>
#include <iostream>
#include <string>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) {                                                            \
            ++g_pass;                                                          \
            std::cout << "  PASS  " << label << "\n";                          \
        } else {                                                               \
            ++g_fail;                                                          \
            std::cout << "  FAIL  " << label << "  (" << __FILE__ << ":"       \
                      << __LINE__ << ")\n";                                    \
        }                                                                      \
    } while (0)

// Compila una fuente y devuelve un TypeChecker poblado.  Util para
// preparar el "modulo lib" del test.
struct CompiledModule {
    vx::Diagnostics diags;
    std::unique_ptr<vx::ast::ModuleNode> ast;
    std::unique_ptr<vx::TypeChecker> tc;
};

std::unique_ptr<CompiledModule>
compile_to_typechecker(const std::string &source, const std::string &filename) {
    auto m = std::make_unique<CompiledModule>();
    vx::Lexer lex(source, filename, m->diags);
    vx::Parser parser(lex, m->diags);
    m->ast = parser.parse_program();
    if (!m->ast) return m;
    m->tc = std::make_unique<vx::TypeChecker>(*m->ast, m->diags);
    m->tc->run();
    return m;
}

// ------------------------------------------------------------------
// Test 1: round-trip typedef.
// El lib expone `typedef u64 user_id new;`; main importa con `only`.
// ------------------------------------------------------------------
void test_typedef_roundtrip() {
    std::cout << "\n[Test] round-trip typedef new (lib -> .vxi -> main)\n";

    // 1. Compilar el modulo lib con un typedef new.
    auto lib = compile_to_typechecker("typedef u64 user_id new;\n"
                                      "typedef u32 port_num new;\n"
                                      /* `public` es lo que EXPORTA.
                                       *
                                       * Sin el, la funcion no salia al `.vxi`
                                       * -- correcto -- y el test la pedia
                                       * igual.  De propina, su comprobacion de
                                       * "fn_lib exportada" pasaba por las 84
                                       * funciones del preludio, no por esta:
                                       * contaba cuantas hay, no si estaba la
                                       * suya. */
                                      "public i32 fn_lib(i32 x) { return x + "
                                      "1; }\n",
                                      "lib.vx");

    CHECK(lib->tc != nullptr, "lib compila");
    CHECK(!lib->diags.has_errors(), "lib sin errores");
    if (lib->tc == nullptr) return;

    // 2. Exportar a VxiModule + serializar.
    vx::VxiModule vm;
    vx::export_typechecker_to_vxi(*lib->tc, /*source_hash=*/0xABCD, vm);
    CHECK(!vm.symbols.empty(), "exported tiene simbolos");

    int td_count = 0, fn_count = 0;
    for (const auto &s : vm.symbols) {
        if (s.kind == vx::VxiSymbolKind::TYPEDEF_NEW) ++td_count;
        if (s.kind == vx::VxiSymbolKind::FUNCTION) ++fn_count;
    }
    CHECK(td_count == 2, "2 newtypes exportados (user_id, port_num)");
    /* Que este LA SUYA, no que haya alguna.
     *
     * Esto era `fn_count >= 1` y pasaba por las 84 funciones del preludio: con
     * `fn_lib` sin exportar seguia en verde, y el fallo aparecia dos
     * comprobaciones mas abajo sin decir por que. */
    bool hay_fn_lib = false;
    for (const auto &sy : vm.symbols)
        if (sy.kind == vx::VxiSymbolKind::FUNCTION && sy.name == "fn_lib")
            hay_fn_lib = true;
    CHECK(hay_fn_lib, "fn_lib exportada");

    auto bytes = vx::vxi_emit(vm);
    auto parsed = vx::vxi_parse(bytes.data(), bytes.size());
    CHECK(parsed.ok, "round-trip parse OK");
    if (!parsed.ok) return;

    // 3. Compilar un main vacio + inyectar simbolos.
    auto mainmod =
        compile_to_typechecker("i32 main() { return 42; }\n", "main.vx");
    CHECK(mainmod->tc != nullptr, "main compila");
    if (mainmod->tc == nullptr) return;

    // 4. Inyectar SOLO user_id y fn_lib (no port_num).
    std::vector<vx::TypeChecker::VxiOnlyEntry> only;
    only.push_back({"user_id", ""});
    only.push_back({"fn_lib", ""});
    vx::import_vxi_into_typechecker(*mainmod->tc, parsed.module_, only, "lib");

    // 5. Verificar que main ahora conoce user_id pero NO port_num.
    {
        const auto &aliases = mainmod->tc->type_aliases();
        bool has_user = aliases.find("user_id") != aliases.end();
        bool has_port = aliases.find("port_num") != aliases.end();
        CHECK(has_user, "main conoce user_id tras import");
        CHECK(!has_port, "main NO conoce port_num (no estaba en only)");
    }
    {
        const auto &fns = mainmod->tc->function_names();
        bool has_fn = fns.find("fn_lib") != fns.end();
        CHECK(has_fn, "main conoce fn_lib tras import");
        const vx::FunctionSig *sig =
            mainmod->tc->function_sig_by_name("fn_lib");
        CHECK(sig != nullptr, "function_sig_by_name devuelve fn_lib");
        if (sig) {
            CHECK(sig->return_type.kind == vx::PrimitiveKind::I32,
                  "fn_lib retorna i32");
            CHECK(sig->param_types.size() == 1, "fn_lib tiene 1 param");
            if (!sig->param_types.empty()) {
                CHECK(sig->param_types[0].kind == vx::PrimitiveKind::I32,
                      "fn_lib param 0 = i32");
            }
        }
    }
}

// ------------------------------------------------------------------
// Test 2: round-trip struct con campos.
// ------------------------------------------------------------------
void test_struct_roundtrip() {
    std::cout << "\n[Test] round-trip struct (lib -> .vxi -> main)\n";

    auto lib = compile_to_typechecker("struct Point { f64 x; f64 y; }\n"
                                      "i32 main() { return 0; }\n",
                                      "lib2.vx");
    CHECK(lib->tc != nullptr, "lib compila");
    if (!lib->tc) return;

    vx::VxiModule vm;
    vx::export_typechecker_to_vxi(*lib->tc, 0x1234, vm);

    auto bytes = vx::vxi_emit(vm);
    auto parsed = vx::vxi_parse(bytes.data(), bytes.size());
    CHECK(parsed.ok, "parse OK");

    auto mainmod =
        compile_to_typechecker("i32 main() { return 0; }\n", "main2.vx");
    std::vector<vx::TypeChecker::VxiOnlyEntry> only = {{"Point", ""}};
    vx::import_vxi_into_typechecker(*mainmod->tc, parsed.module_, only, "lib2");

    const auto &structs = mainmod->tc->struct_layouts();
    auto it = structs.find("Point");
    CHECK(it != structs.end(), "main conoce struct Point tras import");
    if (it != structs.end()) {
        CHECK(it->second.fields.size() == 2, "Point tiene 2 fields");
        if (it->second.fields.size() == 2) {
            CHECK(it->second.fields[0].name == "x", "field 0 = x");
            CHECK(it->second.fields[1].name == "y", "field 1 = y");
            CHECK(it->second.fields[0].type.kind == vx::PrimitiveKind::F64,
                  "field 0 type = f64");
        }
    }
}

// ------------------------------------------------------------------
// Test 3: only con rename ("foo as bar").
// ------------------------------------------------------------------
void test_only_rename() {
    std::cout << "\n[Test] only con rename\n";

    auto lib = compile_to_typechecker("typedef u64 fd new;\n"
                                      "i32 main() { return 0; }\n",
                                      "lib3.vx");
    if (!lib->tc) return;

    vx::VxiModule vm;
    vx::export_typechecker_to_vxi(*lib->tc, 0, vm);
    auto bytes = vx::vxi_emit(vm);
    auto parsed = vx::vxi_parse(bytes.data(), bytes.size());

    auto mainmod =
        compile_to_typechecker("i32 main() { return 0; }\n", "main3.vx");
    std::vector<vx::TypeChecker::VxiOnlyEntry> only = {{"fd", "FileDesc"}};
    vx::import_vxi_into_typechecker(*mainmod->tc, parsed.module_, only, "lib3");

    const auto &aliases = mainmod->tc->type_aliases();
    CHECK(aliases.find("fd") == aliases.end(),
          "el nombre original NO esta (solo el renombrado)");
    CHECK(aliases.find("FileDesc") != aliases.end(),
          "el nombre renombrado SI esta");
}

// ------------------------------------------------------------------
// Test 4: only_symbols vacio = no inyecta nada.
// ------------------------------------------------------------------
void test_empty_only_no_inject() {
    std::cout << "\n[Test] only vacio no inyecta nada (M2 MVP)\n";

    auto lib = compile_to_typechecker("typedef u64 X new;\n"
                                      "i32 main() { return 0; }\n",
                                      "lib4.vx");
    if (!lib->tc) return;

    vx::VxiModule vm;
    vx::export_typechecker_to_vxi(*lib->tc, 0, vm);
    auto bytes = vx::vxi_emit(vm);
    auto parsed = vx::vxi_parse(bytes.data(), bytes.size());

    auto mainmod =
        compile_to_typechecker("i32 main() { return 0; }\n", "main4.vx");
    const size_t before = mainmod->tc->type_aliases().size();

    // only vacio.
    std::vector<vx::TypeChecker::VxiOnlyEntry> only;
    vx::import_vxi_into_typechecker(*mainmod->tc, parsed.module_, only, "lib4");

    const size_t after = mainmod->tc->type_aliases().size();
    CHECK(before == after, "only vacio no cambio nada");
}

} // namespace

int main() {
    std::cout << "=== test_vx_module_interop:  M.2.d ===\n";
    test_typedef_roundtrip();
    test_struct_roundtrip();
    test_only_rename();
    test_empty_only_no_inject();
    std::cout << "\n=== Resultado: " << g_pass << " PASS, " << g_fail
              << " FAIL ===\n";
    return (g_fail == 0) ? 0 : 1;
}
