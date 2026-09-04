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
 * @file diag_format.cpp
 * @brief Implementacion del renderizado de diagnosticos (texto/JSON/SARIF).
 */

#include "vx/diag/diag_format.h"

#include "vx/diag/diag_catalog.h"

#include <set>

namespace vx {

namespace {

/// Escapa una cadena para un literal JSON (comillas, backslash, control chars).
std::string json_esc(const std::string &s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) {
                static const char *hex = "0123456789abcdef";
                o += "\\u00";
                o += hex[(c >> 4) & 0xF];
                o += hex[c & 0xF];
            } else {
                o += static_cast<char>(c);
            }
        }
    }
    return o;
}

/// Nombre de severidad para JSON/SARIF (SARIF usa error|warning|note).
const char *severity_name(DiagLevel l) {
    switch (l) {
    case DiagLevel::ERR: return "error";
    case DiagLevel::WARN: return "warning";
    case DiagLevel::NOTE: return "note";
    }
    return "note";
}

void render_json(std::ostream &os, const Diagnostics &diags) {
    os << "{\n  \"diagnostics\": [\n";
    const auto &all = diags.all();
    for (size_t i = 0; i < all.size(); ++i) {
        const Diagnostic &d = all[i];
        os << "    {\n";
        os << "      \"code\": \"" << json_esc(d.code) << "\",\n";
        os << "      \"severity\": \"" << severity_name(d.level) << "\",\n";
        os << "      \"file\": \"" << json_esc(d.loc.file()) << "\",\n";
        os << "      \"line\": " << d.loc.line << ",\n";
        os << "      \"column\": " << d.loc.column << ",\n";
        os << "      \"offset\": " << d.loc.offset << ",\n";
        os << "      \"length\": " << d.loc.length << ",\n";
        os << "      \"args\": [";
        for (size_t k = 0; k < d.args.size(); ++k) {
            if (k) os << ", ";
            os << "\"" << json_esc(d.args[k]) << "\"";
        }
        os << "],\n";
        os << "      \"message\": \"" << json_esc(formatted_message(d))
           << "\"\n";
        os << "    }" << (i + 1 < all.size() ? "," : "") << "\n";
    }
    os << "  ]\n}\n";
}

void render_sarif(std::ostream &os, const Diagnostics &diags) {
    const auto &all = diags.all();
    // Reglas = codigos distintos que aparecen.
    std::set<std::string> rules;
    for (const Diagnostic &d : all)
        if (!d.code.empty()) rules.insert(d.code);

    os << "{\n";
    os << "  \"version\": \"2.1.0\",\n";
    os << "  \"$schema\": "
          "\"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    os << "  \"runs\": [\n    {\n";
    os << "      \"tool\": {\n        \"driver\": {\n";
    os << "          \"name\": \"vesta\",\n";
    os << "          \"rules\": [";
    {
        size_t k = 0;
        for (const std::string &r : rules) {
            if (k++) os << ", ";
            os << "{\"id\": \"" << json_esc(r) << "\"}";
        }
    }
    os << "]\n";
    os << "        }\n      },\n";
    os << "      \"results\": [\n";
    for (size_t i = 0; i < all.size(); ++i) {
        const Diagnostic &d = all[i];
        os << "        {\n";
        os << "          \"ruleId\": \"" << json_esc(d.code) << "\",\n";
        os << "          \"level\": \"" << severity_name(d.level) << "\",\n";
        os << "          \"message\": {\"text\": \""
           << json_esc(formatted_message(d)) << "\"},\n";
        os << "          \"locations\": [\n";
        os << "            {\n              \"physicalLocation\": {\n";
        os << "                \"artifactLocation\": {\"uri\": \""
           << json_esc(d.loc.file()) << "\"},\n";
        os << "                \"region\": {\"startLine\": " << d.loc.line
           << ", \"startColumn\": " << d.loc.column << "}\n";
        os << "              }\n            }\n          ]\n";
        os << "        }" << (i + 1 < all.size() ? "," : "") << "\n";
    }
    os << "      ]\n    }\n  ]\n}\n";
}

} // namespace

std::string formatted_message(const Diagnostic &d) {
    if (!d.code.empty() && diag::has_code(d.code))
        return diag::format(d.code, d.args);
    return d.message;
}

DiagFormat parse_diag_format(const std::string &s, bool *ok) {
    if (ok) *ok = true;
    if (s == "text") return DiagFormat::Text;
    if (s == "json") return DiagFormat::Json;
    if (s == "sarif") return DiagFormat::Sarif;
    if (ok) *ok = false;
    return DiagFormat::Text;
}

void render_diagnostics(std::ostream &os, const Diagnostics &diags,
                        DiagFormat fmt) {
    switch (fmt) {
    case DiagFormat::Json: render_json(os, diags); break;
    case DiagFormat::Sarif: render_sarif(os, diags); break;
    case DiagFormat::Text:
    default: print_all_diagnostics(os, diags); break;
    }
}

} // namespace vx
