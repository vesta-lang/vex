/**
 * @file diag_catalog_test.cpp
 * @brief Tests del catalogo multi-idioma de diagnosticos (ver
 * vx/diag_catalog.h): seleccion de idioma, sustitucion de placeholders,
 * fallback.
 */
#include "vx/diag/diag_catalog.h"
#include "vx/diag/diag_format.h"
#include "vx/diagnostic.h"

#include <cstdio>
#include <sstream>
#include <string>

using namespace vx;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  FAIL: %s (linea %d)\n", (msg), __LINE__);           \
        }                                                                      \
    } while (0)

int main() {
    std::printf("=== diag_catalog_test ===\n");

    // Idiomas del catalogo: al menos en (0) y es (1).
    const int en = diag::language_index("en");
    const int es = diag::language_index("es");
    CHECK(en == 0, "en es el idioma 0 (fallback)");
    CHECK(es == 1, "es es el idioma 1");
    CHECK(diag::language_count() >= 2, "al menos 2 idiomas");

    // language_index acepta locales completas (es_ES.UTF-8 -> es).
    CHECK(diag::language_index("es_ES.UTF-8") == es, "es_ES.UTF-8 -> es");
    CHECK(diag::language_index("en_US") == en, "en_US -> en");
    CHECK(diag::language_index("fr") == -1, "fr no esta -> -1");

    // has_code.
    CHECK(diag::has_code("VXA001"), "VXA001 existe");
    CHECK(!diag::has_code("VX9999"), "VX9999 no existe");

    // Formateo sin args, por idioma.
    CHECK(diag::format("VXA001", en, {}) ==
              "asm: dead code: unreachable instruction in the asm block",
          "VXA001 en");
    CHECK(diag::format("VXA001", es, {}) ==
              "asm: codigo muerto: instruccion inalcanzable en el bloque asm",
          "VXA001 es");

    // Sustitucion de placeholder {0}.
    CHECK(diag::format("VXA002", en, {".fin"}) ==
              "asm: jump to label '.fin' not defined in the asm block",
          "VXA002 en con arg");
    CHECK(diag::format("VXA004", es, {"rbx"}) ==
              "asm: registro 'rbx' leido sin inicializar en el bloque asm",
          "VXA004 es con arg");

    // Codigo desconocido -> devuelve el propio codigo.
    CHECK(diag::format("VX9999", en, {}) == "VX9999", "codigo desconocido");

    // Idioma activo global.
    diag::set_language(es);
    CHECK(diag::current_language() == es, "set_language es");
    CHECK(diag::format("VXA003", {}).find("bucle sin salida") !=
              std::string::npos,
          "format usa el idioma activo (es)");
    diag::set_language(en);
    CHECK(diag::format("VXA003", {}).find("infinite loop") != std::string::npos,
          "format usa el idioma activo (en)");

    // set_language fuera de rango se ignora.
    diag::set_language(999);
    CHECK(diag::current_language() == en, "idx fuera de rango ignorado");

    // === Salida maquina: render_diagnostics JSON / SARIF. ===
    diag::set_language(en);
    Diagnostics diags;
    SourceLoc loc;
    loc.set_file("foo.vx");
    loc.line = 9;
    loc.column = 5;
    diags.diag(loc, DiagLevel::WARN, "VXA002", {".fin"});

    CHECK(parse_diag_format("json") == DiagFormat::Json, "parse json");
    CHECK(parse_diag_format("sarif") == DiagFormat::Sarif, "parse sarif");
    CHECK(parse_diag_format("text") == DiagFormat::Text, "parse text");
    bool okf = true;
    (void)parse_diag_format("xxx", &okf);
    CHECK(!okf, "formato desconocido -> ok=false");

    {
        std::ostringstream os;
        render_diagnostics(os, diags, DiagFormat::Json);
        const std::string j = os.str();
        CHECK(j.find("\"code\": \"VXA002\"") != std::string::npos,
              "json lleva el codigo");
        CHECK(j.find("\"severity\": \"warning\"") != std::string::npos,
              "json lleva la severidad");
        CHECK(j.find("\".fin\"") != std::string::npos, "json lleva el arg");
        CHECK(j.find("jump to label '.fin'") != std::string::npos,
              "json lleva el mensaje formateado (en)");
    }
    {
        std::ostringstream os;
        render_diagnostics(os, diags, DiagFormat::Sarif);
        const std::string s = os.str();
        CHECK(s.find("\"version\": \"2.1.0\"") != std::string::npos,
              "sarif version 2.1.0");
        CHECK(s.find("\"ruleId\": \"VXA002\"") != std::string::npos,
              "sarif ruleId = codigo");
        CHECK(s.find("\"startLine\": 9") != std::string::npos,
              "sarif localizacion");
    }

    std::printf("=== diag_catalog_test: %d checks OK, %d fallidos ===\n",
                g_checks - g_fail, g_fail);
    return g_fail ? 1 : 0;
}
