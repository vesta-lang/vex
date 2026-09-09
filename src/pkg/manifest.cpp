/**
 * @file manifest.cpp
 * @brief Implementacion del parser dual TOML/JSON del manifest de paquete.
 */
#include "pkg/manifest.h"
#include "pkg/toml_lite.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

#include "json.hpp"

namespace pkg {

namespace {

bool is_hex_n(const std::string &s, size_t n) {
    if (s.size() != n) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

bool is_valid_sha256(const std::string &s) {
    return is_hex_n(s, 64);
}

bool is_valid_fingerprint(const std::string &s) {
    // kpub1:<64 hex chars>
    if (s.size() != 64 + 6) return false;
    if (s.substr(0, 6) != "kpub1:") return false;
    return is_hex_n(s.substr(6), 64);
}

bool string_ends_with(const std::string &s, const std::string &suffix) {
    if (s.size() < suffix.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// ------------------------------------------------------------
// TOML -> Manifest
// ------------------------------------------------------------

static void parse_capabilities_from_toml(const toml::TomlValue &caps,
                                         Manifest &m) {
    if (!caps.is_table()) return;
    const toml::TomlValue &declared = caps.get("declared");
    if (declared.is_array()) {
        for (const auto &v : declared.as_array()) {
            if (v.is_string()) {
                m.capabilities.declared.push_back(v.as_string());
            }
        }
    }
}

static DependencySpec parse_dep_spec_from_toml(const std::string &name,
                                               const toml::TomlValue &v) {
    DependencySpec d;
    d.name = name;
    if (v.is_string()) {
        // "name" = "1.2.3"  (version semver simple, sin sha256: invalido)
        d.version = v.as_string();
        return d;
    }
    if (v.is_table()) {
        d.version = v.get_string("version");
        d.sha256 = v.get_string("sha256");
        d.git_url = v.get_string("git");
        d.git_rev = v.get_string("rev");
        d.path = v.get_string("path");
        d.trust_key = v.get_string("trust");
        // tag/branch tambien soportados via git_rev (priority: rev > tag >
        // branch)
        std::string tag = v.get_string("tag");
        std::string branch = v.get_string("branch");
        if (d.git_rev.empty() && !tag.empty()) d.git_rev = "tag:" + tag;
        if (d.git_rev.empty() && !branch.empty())
            d.git_rev = "branch:" + branch;
        if (d.git_rev.empty()) d.git_rev = "branch:main";
        // url tarball
        std::string url = v.get_string("url");
        if (!url.empty() && d.git_url.empty()) {
            d.git_url = url; // reusa git_url como source URL generico
            d.git_rev = "url";
        }
    }
    return d;
}

static void parse_dependencies_from_toml(const toml::TomlValue &deps,
                                         Manifest &m, bool is_dev) {
    if (!deps.is_table()) return;
    for (const auto &kv : deps.as_table()) {
        DependencySpec d = parse_dep_spec_from_toml(kv.first, kv.second);
        d.is_dev = is_dev;
        m.dependencies.push_back(std::move(d));
    }
}

static void parse_trust_from_toml(const toml::TomlValue &trust, Manifest &m) {
    if (!trust.is_table()) return;
    for (const auto &kv : trust.as_table()) {
        if (kv.second.is_string()) {
            TrustPin p;
            p.glob = kv.first;
            p.fingerprint = kv.second.as_string();
            m.trust_pins.push_back(std::move(p));
        }
    }
}

ParseResult parse_toml(const std::string &buffer,
                       const std::string &source_path) {
    ParseResult res;
    auto pr = toml::parse(buffer);
    if (!pr.ok) {
        res.ok = false;
        res.error_msg = pr.error_msg;
        res.error_line = pr.error_line;
        return res;
    }
    Manifest m;
    m.source_path = source_path;

    const toml::TomlValue pkg(pr.root);
    const toml::TomlValue &pkg_section = pkg.get("package");
    if (pkg_section.is_table()) {
        m.name = pkg_section.get_string("name");
        m.version = pkg_section.get_string("version");
        m.license = pkg_section.get_string("license");
        m.edition = static_cast<int>(pkg_section.get_int("edition", 1));
        const toml::TomlValue &authors = pkg_section.get("authors");
        if (authors.is_array()) {
            for (const auto &a : authors.as_array()) {
                if (a.is_string()) m.authors.push_back(a.as_string());
            }
        }
    }
    parse_capabilities_from_toml(pkg.get("capabilities"), m);
    /* [cache]: lo que este proyecto dice sobre sus caches.  Ausente = cero, que
     * el consumidor lee como "el defecto" -- asi no hay que repetir aqui un
     * numero que ya vive donde se usa. */
    {
        const toml::TomlValue &cache = pkg.get("cache");
        if (cache.is_table())
            m.cache.analysis_unused_runs =
                static_cast<uint32_t>(cache.get_int("analysis_unused_runs", 0));
    }
    parse_dependencies_from_toml(pkg.get("dependencies"), m, false);
    parse_dependencies_from_toml(pkg.get("dev-dependencies"), m, true);
    parse_trust_from_toml(pkg.get("trust"), m);
    // [scripts]: tabla nombre -> comando.  Solo strings.
    {
        const toml::TomlValue &scr = pkg.get("scripts");
        if (scr.is_table()) {
            for (const auto &kv : scr.as_table()) {
                if (kv.second.is_string()) {
                    m.scripts.emplace_back(kv.first, kv.second.as_string());
                }
            }
        }
    }

    res.ok = true;
    res.manifest = std::move(m);
    return res;
}

// ------------------------------------------------------------
// JSON -> Manifest
// ------------------------------------------------------------

ParseResult parse_json(const std::string &buffer,
                       const std::string &source_path) {
    ParseResult res;
    try {
        auto j = nlohmann::json::parse(buffer);
        Manifest m;
        m.source_path = source_path;
        if (j.contains("package")) {
            auto p = j["package"];
            if (p.contains("name")) m.name = p["name"].get<std::string>();
            if (p.contains("version"))
                m.version = p["version"].get<std::string>();
            if (p.contains("license"))
                m.license = p["license"].get<std::string>();
            if (p.contains("edition")) m.edition = p["edition"].get<int>();
            if (p.contains("authors") && p["authors"].is_array()) {
                for (auto &a : p["authors"]) {
                    if (a.is_string())
                        m.authors.push_back(a.get<std::string>());
                }
            }
        }
        if (j.contains("capabilities")) {
            auto c = j["capabilities"];
            if (c.contains("declared") && c["declared"].is_array()) {
                for (auto &v : c["declared"]) {
                    if (v.is_string())
                        m.capabilities.declared.push_back(v.get<std::string>());
                }
            }
        }
        if (j.contains("cache")) {
            auto c = j["cache"];
            if (c.contains("analysis_unused_runs") &&
                c["analysis_unused_runs"].is_number_integer())
                m.cache.analysis_unused_runs =
                    c["analysis_unused_runs"].get<uint32_t>();
        }
        auto parse_deps = [&](const nlohmann::json &j_deps, bool is_dev) {
            if (!j_deps.is_object()) return;
            for (auto it = j_deps.begin(); it != j_deps.end(); ++it) {
                DependencySpec d;
                d.name = it.key();
                d.is_dev = is_dev;
                const auto &v = it.value();
                if (v.is_string()) {
                    d.version = v.get<std::string>();
                } else if (v.is_object()) {
                    /* `package = "..."`: la clave pasa a ser un ALIAS y esto es
                     * el nombre real.  Es como se desempata cuando dos
                     * dependencias ofrecen el mismo namespace, sin tocar el
                     * lenguaje. */
                    if (v.contains("package"))
                        d.paquete = v["package"].get<std::string>();
                    if (v.contains("version"))
                        d.version = v["version"].get<std::string>();
                    if (v.contains("sha256"))
                        d.sha256 = v["sha256"].get<std::string>();
                    if (v.contains("git"))
                        d.git_url = v["git"].get<std::string>();
                    if (v.contains("rev"))
                        d.git_rev = v["rev"].get<std::string>();
                    if (v.contains("path"))
                        d.path = v["path"].get<std::string>();
                    if (v.contains("trust"))
                        d.trust_key = v["trust"].get<std::string>();
                    std::string tag, branch, url;
                    if (v.contains("tag")) tag = v["tag"].get<std::string>();
                    if (v.contains("branch"))
                        branch = v["branch"].get<std::string>();
                    if (v.contains("url")) url = v["url"].get<std::string>();
                    if (d.git_rev.empty() && !tag.empty())
                        d.git_rev = "tag:" + tag;
                    if (d.git_rev.empty() && !branch.empty())
                        d.git_rev = "branch:" + branch;
                    if (d.git_rev.empty()) d.git_rev = "branch:main";
                    if (!url.empty() && d.git_url.empty()) {
                        d.git_url = url;
                        d.git_rev = "url";
                    }
                }
                m.dependencies.push_back(std::move(d));
            }
        };
        if (j.contains("dependencies")) parse_deps(j["dependencies"], false);
        if (j.contains("dev-dependencies"))
            parse_deps(j["dev-dependencies"], true);
        if (j.contains("trust") && j["trust"].is_object()) {
            for (auto it = j["trust"].begin(); it != j["trust"].end(); ++it) {
                if (it.value().is_string()) {
                    TrustPin p;
                    p.glob = it.key();
                    p.fingerprint = it.value().get<std::string>();
                    m.trust_pins.push_back(std::move(p));
                }
            }
        }
        if (j.contains("scripts") && j["scripts"].is_object()) {
            for (auto it = j["scripts"].begin(); it != j["scripts"].end();
                 ++it) {
                if (it.value().is_string()) {
                    m.scripts.emplace_back(it.key(),
                                           it.value().get<std::string>());
                }
            }
        }
        res.ok = true;
        res.manifest = std::move(m);
    } catch (const std::exception &e) {
        res.ok = false;
        res.error_msg = std::string("error parseando JSON: ") + e.what();
    }
    return res;
}

} // namespace

// ----------------------------------------------------------------
// Publicos
// ----------------------------------------------------------------

ParseResult parse_manifest_buffer(const std::string &buffer,
                                  const std::string &format,
                                  const std::string &source_path) {
    if (format == "toml") return parse_toml(buffer, source_path);
    if (format == "json") return parse_json(buffer, source_path);
    ParseResult r;
    r.error_msg = "formato desconocido (esperado toml o json): " + format;
    return r;
}

ParseResult parse_manifest_file(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        ParseResult r;
        r.error_msg = "no se puede abrir el manifest: " + path;
        return r;
    }
    std::ostringstream buf;
    buf << f.rdbuf();
    std::string format = string_ends_with(path, ".json") ? "json" : "toml";
    return parse_manifest_buffer(buf.str(), format, path);
}

// ----------------------------------------------------------------
// Serializers
// ----------------------------------------------------------------

std::string serialize_manifest_toml(const Manifest &m) {
    std::ostringstream out;
    // [package]
    out << "[package]\n";
    out << "name        = " << toml::escape_string(m.name) << "\n";
    out << "version     = " << toml::escape_string(m.version) << "\n";
    if (!m.authors.empty()) {
        out << "authors     = [";
        for (size_t i = 0; i < m.authors.size(); ++i) {
            if (i) out << ", ";
            out << toml::escape_string(m.authors[i]);
        }
        out << "]\n";
    }
    if (!m.license.empty()) {
        out << "license     = " << toml::escape_string(m.license) << "\n";
    }
    out << "edition     = " << m.edition << "\n";
    out << "\n";

    // [capabilities]
    if (!m.capabilities.declared.empty()) {
        out << "[capabilities]\n";
        out << "declared = [";
        for (size_t i = 0; i < m.capabilities.declared.size(); ++i) {
            if (i) out << ", ";
            out << toml::escape_string(m.capabilities.declared[i]);
        }
        out << "]\n\n";
    }

    // [dependencies]
    std::vector<const DependencySpec *> deps_normal, deps_dev;
    for (const auto &d : m.dependencies) {
        if (d.is_dev)
            deps_dev.push_back(&d);
        else
            deps_normal.push_back(&d);
    }
    auto emit_dep = [&](const DependencySpec *d) {
        // Tabla inline
        out << toml::escape_string(d->name) << " = { ";
        bool first = true;
        auto kv = [&](const std::string &k, const std::string &v) {
            if (v.empty()) return;
            if (!first) out << ", ";
            out << k << " = " << toml::escape_string(v);
            first = false;
        };
        if (!d->path.empty()) {
            kv("path", d->path);
        } else {
            if (!d->git_url.empty()) {
                kv("git", d->git_url);
                // rev format: "tag:X" "branch:Y" "url" o hex commit.
                if (d->git_rev.rfind("tag:", 0) == 0) {
                    kv("tag", d->git_rev.substr(4));
                } else if (d->git_rev.rfind("branch:", 0) == 0) {
                    kv("branch", d->git_rev.substr(7));
                } else if (d->git_rev == "url") {
                    // nada (url ya implicito)
                } else if (!d->git_rev.empty()) {
                    kv("rev", d->git_rev);
                }
            }
            if (!d->version.empty()) kv("version", d->version);
            if (!d->sha256.empty()) kv("sha256", d->sha256);
            if (!d->trust_key.empty()) kv("trust", d->trust_key);
        }
        out << " }\n";
    };
    if (!deps_normal.empty()) {
        out << "[dependencies]\n";
        for (auto *d : deps_normal)
            emit_dep(d);
        out << "\n";
    }
    if (!deps_dev.empty()) {
        out << "[dev-dependencies]\n";
        for (auto *d : deps_dev)
            emit_dep(d);
        out << "\n";
    }

    // [trust]
    if (!m.trust_pins.empty()) {
        out << "[trust]\n";
        for (const auto &t : m.trust_pins) {
            out << toml::escape_string(t.glob) << " = "
                << toml::escape_string(t.fingerprint) << "\n";
        }
        out << "\n";
    }

    return out.str();
}

std::string serialize_manifest_json(const Manifest &m) {
    nlohmann::json j;
    j["package"]["name"] = m.name;
    j["package"]["version"] = m.version;
    if (!m.authors.empty()) j["package"]["authors"] = m.authors;
    if (!m.license.empty()) j["package"]["license"] = m.license;
    j["package"]["edition"] = m.edition;

    if (!m.capabilities.declared.empty()) {
        j["capabilities"]["declared"] = m.capabilities.declared;
    }

    auto emit_dep_json = [&](const DependencySpec &d) -> nlohmann::json {
        nlohmann::json o;
        if (!d.version.empty()) o["version"] = d.version;
        if (!d.sha256.empty()) o["sha256"] = d.sha256;
        if (!d.git_url.empty()) o["git"] = d.git_url;
        if (d.git_rev.rfind("tag:", 0) == 0) {
            o["tag"] = d.git_rev.substr(4);
        } else if (d.git_rev.rfind("branch:", 0) == 0) {
            o["branch"] = d.git_rev.substr(7);
        } else if (d.git_rev != "url" && !d.git_rev.empty()) {
            o["rev"] = d.git_rev;
        }
        if (!d.path.empty()) o["path"] = d.path;
        if (!d.trust_key.empty()) o["trust"] = d.trust_key;
        return o;
    };
    for (const auto &d : m.dependencies) {
        const char *key = d.is_dev ? "dev-dependencies" : "dependencies";
        j[key][d.name] = emit_dep_json(d);
    }
    if (!m.trust_pins.empty()) {
        for (const auto &t : m.trust_pins) {
            j["trust"][t.glob] = t.fingerprint;
        }
    }
    return j.dump(2);
}

// ----------------------------------------------------------------
// Validacion semantica
// ----------------------------------------------------------------

ValidationResult validate_manifest(const Manifest &m) {
    ValidationResult vr;
    if (m.name.empty()) {
        vr.ok = false;
        vr.errors.push_back("manifest: 'name' obligatorio");
    }
    if (m.version.empty()) {
        vr.ok = false;
        vr.errors.push_back("manifest: 'version' obligatorio");
    }
    for (const auto &d : m.dependencies) {
        if (d.path.empty()) {
            // Remote dep: requiere sha256 (excepto branch HEAD modo dev).
            if (d.sha256.empty()) {
                vr.warnings.push_back("dep '" + d.name +
                                      "': sin 'sha256' (modo dev; falla en "
                                      "install si no hay vx.lock)");
            } else if (!is_valid_sha256(d.sha256)) {
                vr.ok = false;
                vr.errors.push_back(
                    "dep '" + d.name +
                    "': sha256 invalido (debe ser 64 hex chars)");
            }
        }
        // Source: al menos uno de git, path, url.
        if (d.git_url.empty() && d.path.empty()) {
            // version puro = futuro (registry).  Warning.
            if (!d.version.empty()) {
                vr.warnings.push_back(
                    "dep '" + d.name +
                    "': solo 'version' sin 'git' ni 'path' requiere un "
                    "registry (vacio por defecto)");
            } else {
                vr.ok = false;
                vr.errors.push_back("dep '" + d.name +
                                    "': debe especificar 'git=', 'url=', "
                                    "'path=' o 'version=' (con registry)");
            }
        }
    }
    for (const auto &t : m.trust_pins) {
        if (!is_valid_fingerprint(t.fingerprint)) {
            vr.ok = false;
            vr.errors.push_back(
                "trust pin '" + t.glob +
                "': fingerprint invalido (esperado kpub1:<64 hex chars>)");
        }
    }
    return vr;
}

} // namespace pkg
