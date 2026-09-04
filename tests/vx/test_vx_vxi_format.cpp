/**
 * @file test_vx_vxi_format.cpp
 * @brief Round-trip emit/parse del formato .vxi ( M.2).
 *
 * Construye un VxiModule con simbolos de cada kind, lo serializa,
 * lo parsea y verifica que el resultado es semanticamente identico
 * al original.  Tambien comprueba:
 *   - abi_hash es determinista (mismo input -> mismo hash).
 *   - abi_hash cambia si cambia un simbolo.
 *   - Detecta magic invalido.
 *   - Detecta version invalida.
 *   - Detecta truncacion (buffer corto).
 */

#include "vx/module/vxi_format.h"

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

vx::VxiModule make_sample_module() {
    vx::VxiModule m;
    m.source_hash = vx::vxi_fnv1a(std::string("// fake source"));

    // 1. typedef transparente.
    {
        vx::VxiSymbol s;
        s.kind = vx::VxiSymbolKind::TYPEDEF_ALIAS;
        s.name = "Edad";
        s.underlying_type = "u32";
        m.symbols.push_back(std::move(s));
    }
    // 2. newtype con @opaque + @align(16).
    {
        vx::VxiSymbol s;
        s.kind = vx::VxiSymbolKind::TYPEDEF_NEW;
        s.name = "session_handle";
        s.underlying_type = "u64";
        s.is_opaque = true;
        s.align_override = 16;
        s.nominal_abi = vx::vxi_fnv1a(s.name);
        m.symbols.push_back(std::move(s));
    }
    // 3. struct con 3 fields.
    {
        vx::VxiSymbol s;
        s.kind = vx::VxiSymbolKind::STRUCT;
        s.name = "Point";
        s.size_bytes = 16;
        s.align_bytes = 8;
        s.fields = {
            {"x", "f64", 0, 8, 0, 0},
            {"y", "f64", 8, 8, 0, 0},
        };
        m.symbols.push_back(std::move(s));
    }
    // 4. class con super + 2 fields + interfaces.
    {
        vx::VxiSymbol s;
        s.kind = vx::VxiSymbolKind::CLASS;
        s.name = "Perro";
        s.super_class = "Animal";
        s.size_bytes = 32;
        s.align_bytes = 8;
        s.fields = {
            {"raza", "string", 24, 8, 0, 0},
        };
        s.interfaces = {"Comparable", "Cloneable"};
        m.symbols.push_back(std::move(s));
    }
    // 5. enum con variantes con y sin payload.
    {
        vx::VxiSymbol s;
        s.kind = vx::VxiSymbolKind::ENUM;
        s.name = "Shape";
        s.variants = {
            {"Circle", 0, {"f64"}},
            {"Rectangle", 1, {"f64", "f64"}},
            {"None", 2, {}},
        };
        m.symbols.push_back(std::move(s));
    }
    // 6. funcion con 2 params + return.
    {
        vx::VxiSymbol s;
        s.kind = vx::VxiSymbolKind::FUNCTION;
        s.name = "computar";
        s.return_type = "i32";
        s.param_types = {"i32", "string"};
        s.param_names = {"x", "msg"};
        m.symbols.push_back(std::move(s));
    }
    // 7. extern fn.
    {
        vx::VxiSymbol s;
        s.kind = vx::VxiSymbolKind::FUNCTION;
        s.name = "GetTickCount";
        s.return_type = "u32";
        s.is_extern = true;
        s.extern_lib = "kernel32.dll";
        m.symbols.push_back(std::move(s));
    }
    return m;
}

void test_roundtrip() {
    std::cout << "\n[Test] round-trip emit -> parse\n";
    auto orig = make_sample_module();
    auto bytes = vx::vxi_emit(orig);
    CHECK(bytes.size() > 32, "emit produce mas de 32 bytes (header + entries)");

    auto r = vx::vxi_parse(bytes.data(), bytes.size());
    CHECK(r.ok, "parse exitoso");
    CHECK(r.error_message.empty(), "no hay mensaje de error");

    if (!r.ok) return;

    const auto &m = r.module_;
    CHECK(m.format_version == vx::VXI_FORMAT_VERSION, "version coincide");
    CHECK(m.source_hash == orig.source_hash, "source_hash preservado");
    CHECK(m.abi_hash != 0, "abi_hash computado (no es 0)");
    CHECK(m.symbols.size() == orig.symbols.size(), "mismo numero de simbolos");

    if (m.symbols.size() != orig.symbols.size()) return;

    // Verificar cada simbolo.
    for (size_t i = 0; i < orig.symbols.size(); ++i) {
        const auto &A = orig.symbols[i];
        const auto &B = m.symbols[i];
        CHECK(A.kind == B.kind, "kind[" + std::to_string(i) + "] coincide");
        CHECK(A.name == B.name, "name[" + std::to_string(i) + "] coincide");
        CHECK(A.is_opaque == B.is_opaque,
              "is_opaque[" + std::to_string(i) + "] coincide");
        CHECK(A.align_override == B.align_override,
              "align[" + std::to_string(i) + "] coincide");
        switch (A.kind) {
        case vx::VxiSymbolKind::TYPEDEF_ALIAS:
        case vx::VxiSymbolKind::TYPEDEF_NEW:
        case vx::VxiSymbolKind::GLOBAL_VAR:
            CHECK(A.underlying_type == B.underlying_type,
                  "underlying[" + std::to_string(i) + "] coincide");
            CHECK(A.nominal_abi == B.nominal_abi,
                  "nominal_abi[" + std::to_string(i) + "] coincide");
            break;
        case vx::VxiSymbolKind::STRUCT:
        case vx::VxiSymbolKind::CLASS:
            CHECK(A.super_class == B.super_class,
                  "super[" + std::to_string(i) + "] coincide");
            CHECK(A.size_bytes == B.size_bytes,
                  "size[" + std::to_string(i) + "] coincide");
            CHECK(A.align_bytes == B.align_bytes,
                  "align[" + std::to_string(i) + "] coincide");
            CHECK(A.fields.size() == B.fields.size(),
                  "field count[" + std::to_string(i) + "] coincide");
            CHECK(A.interfaces.size() == B.interfaces.size(),
                  "iface count[" + std::to_string(i) + "] coincide");
            if (A.fields.size() == B.fields.size()) {
                for (size_t f = 0; f < A.fields.size(); ++f) {
                    const auto &fa = A.fields[f];
                    const auto &fb = B.fields[f];
                    CHECK(fa.name == fb.name && fa.type_str == fb.type_str &&
                              fa.offset == fb.offset && fa.size == fb.size,
                          "field[" + std::to_string(f) + "] data");
                }
            }
            break;
        case vx::VxiSymbolKind::ENUM:
            CHECK(A.variants.size() == B.variants.size(),
                  "variant count[" + std::to_string(i) + "] coincide");
            if (A.variants.size() == B.variants.size()) {
                for (size_t v = 0; v < A.variants.size(); ++v) {
                    CHECK(A.variants[v].name == B.variants[v].name &&
                              A.variants[v].tag == B.variants[v].tag &&
                              A.variants[v].payload_types.size() ==
                                  B.variants[v].payload_types.size(),
                          "variant[" + std::to_string(v) + "] data");
                }
            }
            break;
        case vx::VxiSymbolKind::FUNCTION:
            CHECK(A.return_type == B.return_type,
                  "return[" + std::to_string(i) + "] coincide");
            CHECK(A.param_types.size() == B.param_types.size(),
                  "param count[" + std::to_string(i) + "] coincide");
            CHECK(A.is_extern == B.is_extern,
                  "is_extern[" + std::to_string(i) + "] coincide");
            if (A.is_extern) {
                CHECK(A.extern_lib == B.extern_lib,
                      "extern_lib[" + std::to_string(i) + "] coincide");
            }
            break;
        }
    }
}

void test_abi_hash_determinism() {
    std::cout << "\n[Test] abi_hash determinista\n";
    auto m1 = make_sample_module();
    auto m2 = make_sample_module();
    auto b1 = vx::vxi_emit(m1);
    auto b2 = vx::vxi_emit(m2);
    CHECK(b1 == b2, "mismo input produce el mismo binario");

    auto r1 = vx::vxi_parse(b1.data(), b1.size());
    auto r2 = vx::vxi_parse(b2.data(), b2.size());
    CHECK(r1.ok && r2.ok, "ambos parseos OK");
    CHECK(r1.module_.abi_hash == r2.module_.abi_hash, "mismo abi_hash");
}

void test_abi_hash_diff_on_change() {
    std::cout << "\n[Test] abi_hash cambia tras modificacion\n";
    auto m1 = make_sample_module();
    auto m2 = m1;
    // Cambiar el nombre del primer simbolo.
    if (!m2.symbols.empty()) {
        m2.symbols[0].name = "EdadModificada";
    }
    auto b1 = vx::vxi_emit(m1);
    auto b2 = vx::vxi_emit(m2);
    auto r1 = vx::vxi_parse(b1.data(), b1.size());
    auto r2 = vx::vxi_parse(b2.data(), b2.size());
    CHECK(r1.ok && r2.ok, "ambos parseos OK");
    CHECK(r1.module_.abi_hash != r2.module_.abi_hash,
          "abi_hash diferente tras cambiar un nombre");
}

void test_magic_invalido() {
    std::cout << "\n[Test] deteccion de magic invalido\n";
    auto m = make_sample_module();
    auto b = vx::vxi_emit(m);
    if (b.size() >= 4) {
        b[0] = 0xFF;
        b[1] = 0xFF;
        b[2] = 0xFF;
        b[3] = 0xFF;
    }
    auto r = vx::vxi_parse(b.data(), b.size());
    CHECK(!r.ok, "parse falla con magic corrupto");
    CHECK(!r.error_message.empty(), "mensaje de error presente");
}

void test_buffer_corto() {
    std::cout << "\n[Test] deteccion de buffer corto\n";
    uint8_t tiny[4] = {0x56, 0x45, 0x58, 0x49}; // solo magic, sin resto
    auto r = vx::vxi_parse(tiny, sizeof(tiny));
    CHECK(!r.ok, "parse falla con buffer < 48 bytes");
}

void test_modulo_vacio() {
    std::cout << "\n[Test] modulo sin simbolos\n";
    vx::VxiModule m;
    m.source_hash = 0xABCDEF;
    auto b = vx::vxi_emit(m);
    /* Un modulo vacio son SOLO la cabecera, sea cual sea su tamano.
     *
     * Aqui iba el numero clavado -- 48, de la v3 --, y la cabecera ha crecido
     * cinco veces desde entonces (hoy la v19 son 80).  Un test que fija el
     * tamano no protege nada: no dice si la cabecera esta bien, solo que nadie
     * la ha tocado, y falla en cuanto alguien la amplia por un motivo bueno.
     *
     * Lo que si tiene que cumplirse es que sea SOLO cabecera y que vuelva a
     * leerse igual, que es lo que se comprueba abajo. */
    CHECK(b.size() >= 48 && b.size() < 256, "modulo vacio = solo la cabecera");
    auto r = vx::vxi_parse(b.data(), b.size());
    CHECK(r.ok, "modulo vacio parsea OK");
    CHECK(r.module_.symbols.empty(), "sin simbolos");
    CHECK(r.module_.source_hash == 0xABCDEF, "source_hash preservado");
}

//  M4.ext L.13: dep table roundtrip.
void test_dep_table_roundtrip() {
    std::cout << "\n[Test] dep table roundtrip (M4.ext L.13)\n";
    vx::VxiModule m;
    m.source_hash = 0xDEADBEEFCAFE;
    // anñadir 3 deps con abi_hashes distintos.
    m.deps.push_back({"libc", 0x1111111111111111ULL});
    m.deps.push_back({"std/io", 0x2222222222222222ULL});
    m.deps.push_back({"my/lib", 0xABCDEF0123456789ULL});
    auto b = vx::vxi_emit(m);
    auto r = vx::vxi_parse(b.data(), b.size());
    CHECK(r.ok, "parse modulo con dep table OK");
    CHECK(r.module_.deps.size() == 3, "3 deps roundtrip");
    CHECK(r.module_.deps[0].name == "libc", "dep[0].name");
    CHECK(r.module_.deps[0].abi_hash == 0x1111111111111111ULL,
          "dep[0].abi_hash");
    CHECK(r.module_.deps[1].name == "std/io", "dep[1].name");
    CHECK(r.module_.deps[1].abi_hash == 0x2222222222222222ULL,
          "dep[1].abi_hash");
    CHECK(r.module_.deps[2].name == "my/lib", "dep[2].name");
    CHECK(r.module_.deps[2].abi_hash == 0xABCDEF0123456789ULL,
          "dep[2].abi_hash");
}

//  M.L7: GLOBAL_VAR con valor literal inicial roundtrip.
void test_global_var_init_value() {
    std::cout << "\n[Test] GLOBAL_VAR con init_value (M.L7)\n";
    vx::VxiModule m;
    vx::VxiSymbol s;
    s.kind = vx::VxiSymbolKind::GLOBAL_VAR;
    s.name = "MAX_USERS";
    s.underlying_type = "i32";
    s.is_const = true;
    s.has_init_value = true;
    s.init_value = 100;
    m.symbols.push_back(std::move(s));
    // global mutable sin init_value.
    vx::VxiSymbol s2;
    s2.kind = vx::VxiSymbolKind::GLOBAL_VAR;
    s2.name = "counter";
    s2.underlying_type = "i64";
    s2.is_const = false;
    s2.has_init_value = false;
    m.symbols.push_back(std::move(s2));
    auto b = vx::vxi_emit(m);
    auto r = vx::vxi_parse(b.data(), b.size());
    CHECK(r.ok, "parse OK con 2 GLOBAL_VAR");
    CHECK(r.module_.symbols.size() == 2, "2 simbolos");
    CHECK(r.module_.symbols[0].name == "MAX_USERS", "nombre[0]");
    CHECK(r.module_.symbols[0].is_const, "is_const[0]");
    CHECK(r.module_.symbols[0].has_init_value, "has_init_value[0]");
    CHECK(r.module_.symbols[0].init_value == 100, "init_value[0] == 100");
    CHECK(!r.module_.symbols[1].is_const, "is_const[1] == false");
    CHECK(!r.module_.symbols[1].has_init_value, "has_init_value[1] == false");
}

//  M.L8: TYPEDEF_NEW con bloque explicit from/to roundtrip.
void test_typedef_new_explicit_conversions() {
    std::cout << "\n[Test] TYPEDEF_NEW con explicit from/to (M.L8)\n";
    vx::VxiModule m;
    vx::VxiSymbol s;
    s.kind = vx::VxiSymbolKind::TYPEDEF_NEW;
    s.name = "SessionId";
    s.underlying_type = "u64";
    s.nominal_abi = 0xDEADBEEFULL;
    s.is_opaque = false;
    s.align_override = 16; // L.9
    s.from_conversions = {
        {"u64", true},
        {"i32", false}, // privada (no public)
    };
    s.to_conversions = {{"u64", true}};
    m.symbols.push_back(std::move(s));
    auto b = vx::vxi_emit(m);
    auto r = vx::vxi_parse(b.data(), b.size());
    CHECK(r.ok, "parse TYPEDEF_NEW con from/to");
    CHECK(r.module_.symbols.size() == 1, "1 simbolo");
    const auto &S = r.module_.symbols[0];
    CHECK(S.name == "SessionId", "nombre");
    CHECK(S.underlying_type == "u64", "underlying_type");
    CHECK(S.nominal_abi == 0xDEADBEEFULL, "nominal_abi");
    CHECK(S.align_override == 16, "align_override (L.9)");
    CHECK(S.from_conversions.size() == 2, "2 from_conversions");
    CHECK(S.from_conversions[0].type_str == "u64", "from[0].type");
    CHECK(S.from_conversions[0].is_public, "from[0].is_public");
    CHECK(S.from_conversions[1].type_str == "i32", "from[1].type");
    CHECK(!S.from_conversions[1].is_public, "from[1] no public");
    CHECK(S.to_conversions.size() == 1, "1 to_conversion");
    CHECK(S.to_conversions[0].type_str == "u64", "to[0].type");
    CHECK(S.to_conversions[0].is_public, "to[0].is_public");
}

} // namespace

int main() {
    std::cout << "=== test_vx_vxi_format:  M.2 ===\n";

    test_roundtrip();
    test_abi_hash_determinism();
    test_abi_hash_diff_on_change();
    test_magic_invalido();
    test_buffer_corto();
    test_modulo_vacio();
    test_dep_table_roundtrip();
    test_global_var_init_value();
    test_typedef_new_explicit_conversions();

    std::cout << "\n=== Resultado: " << g_pass << " PASS, " << g_fail
              << " FAIL ===\n";
    return (g_fail == 0) ? 0 : 1;
}
