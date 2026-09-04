/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file roots.cpp
 * @brief Implementacion de la entrada al grafo.
 */

#include "vxdbg/roots.h"

#include "vxdbg/codec.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>

namespace vxdbg {

LanguageEntityId ArtifactMap::find(const std::string &symbol) const {
    // Busqueda binaria: el orden se mantiene al insertar precisamente para
    // poder buscar sin construir ningun indice al leer, que es lo que hace que
    // resolver una traza no cueste mas que la traza.
    auto it =
        std::lower_bound(symbols.begin(), symbols.end(), symbol,
                         [](const std::pair<std::string, LanguageEntityId> &a,
                            const std::string &b) { return a.first < b; });
    if (it == symbols.end() || it->first != symbol) return {};
    return it->second;
}

void ArtifactMap::add(std::string symbol, LanguageEntityId entity) {
    auto it =
        std::lower_bound(symbols.begin(), symbols.end(), symbol,
                         [](const std::pair<std::string, LanguageEntityId> &a,
                            const std::string &b) { return a.first < b; });
    // Un simbolo corresponde a UNA entidad.  Si llega otra vez es que quien lo
    // construyo se contradice; se queda la primera, igual que con las claves
    // repetidas del grafo.
    if (it != symbols.end() && it->first == symbol) return;
    symbols.insert(it, std::make_pair(std::move(symbol), entity));
}

namespace {
/// Orden por (simbolo, linea): el mismo con el que se guardan y se buscan.
bool extent_less(const SourceExtent &a, const SourceExtent &b) {
    /* Una sola comparacion de cadenas, no dos.  Preguntar primero si son
     * distintas y luego cual va antes recorre el nombre DOS veces, y los
     * nombres que se comparan aqui comparten prefijo casi siempre -- son los
     * simbolos de un mismo modulo, con su espacio de nombres por delante --,
     * que es el caso en el que recorrerlo cuesta. */
    const int c = a.symbol.compare(b.symbol);
    if (c != 0) return c < 0;
    return a.line < b.line;
}

/// Dos tramos son EL MISMO sitio si coinciden simbolo y linea.
bool extent_same_place(const SourceExtent &a, const SourceExtent &b) {
    return a.line == b.line && a.symbol == b.symbol;
}
} // namespace

SourceExtent SpanMap::find(const std::string &symbol, uint32_t line) const {
    SourceExtent buscado;
    buscado.symbol = symbol;
    buscado.line = line;
    auto it =
        std::lower_bound(extents.begin(), extents.end(), buscado, extent_less);
    if (it == extents.end() || it->symbol != symbol || it->line != line)
        return {};
    return *it;
}

void SpanMap::add(SourceExtent e) {
    auto it = std::lower_bound(extents.begin(), extents.end(), e, extent_less);
    /* Una linea puede tener varias sentencias.  Se queda la PRIMERA: es donde
     * empieza lo que hay en esa linea, y sin poder afinar por columna -- que es
     * lo unico que el runtime sabe -- elegir otra seria arbitrario. */
    if (it != extents.end() && it->symbol == e.symbol && it->line == e.line)
        return;
    extents.insert(it, std::move(e));
}

void SpanMap::build(std::vector<SourceExtent> in) {
    extents = std::move(in);
    std::stable_sort(extents.begin(), extents.end(), extent_less);
    extents.erase(
        std::unique(extents.begin(), extents.end(), extent_same_place),
        extents.end());
}

std::string CacheRootRepository::path_for(BuildId build) const {
    return dir_ + "/roots/" + build.hash.to_hex() + ".ptr";
}

bool CacheRootRepository::publish(BuildId build, ContentHash map,
                                  ContentHash spans,
                                  const std::string &artifact_path) const {
    if (build.empty() || map.empty()) return false;
    const std::string path = path_for(build);
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path(), ec);

    std::FILE *f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    // Se escribe tambien de quien es: si el fichero acabara donde no toca, al
    // leerlo se nota en vez de servir el mapa de otro programa.
    /* Cuarta linea, la ruta, y sin saltos dentro: se lee hasta el final del
     * fichero, asi que una ruta con un salto de linea la partiria.  Ninguna
     * ruta real los lleva, pero si llegara una asi es mejor quedarse sin pista
     * que con una pista falsa. */
    std::string pista = artifact_path;
    if (pista.find('\n') != std::string::npos) pista.clear();
    const std::string body = map.to_hex() + "\n" + build.hash.to_hex() + "\n" +
                             spans.to_hex() + "\n" + pista + "\n";
    const bool ok = std::fwrite(body.data(), 1, body.size(), f) == body.size();
    std::fclose(f);
    return ok;
}

bool CacheRootRepository::lookup(BuildId build, ArtifactMap &out_map) const {
    if (build.empty()) return false;
    std::FILE *f = std::fopen(path_for(build).c_str(), "rb");
    if (!f) return false;
    char buf[256];
    const size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = '\0';

    const std::string body(buf, n);
    const size_t nl = body.find('\n');
    if (nl == std::string::npos) return false;
    const ContentHash map = ContentHash::from_hex(body.substr(0, nl));
    if (map.empty()) return false;

    const size_t nl2 = body.find('\n', nl + 1);
    if (nl2 == std::string::npos) return false;
    const ContentHash owner =
        ContentHash::from_hex(body.substr(nl + 1, nl2 - nl - 1));
    // Explicar un fallo con los simbolos de otra compilacion es peor que no
    // explicarlo: ante la duda, no se devuelve nada.
    if (owner != build.hash) return false;
    // Que el mapa viva en un almacen por contenido es asunto de aqui: quien
    // pregunta recibe el mapa y no se entera de que hubo una huella por medio.
    return load_node(store_, map, out_map);
}

bool CacheRootRepository::lookup_spans(BuildId build,
                                       SpanMap &out_spans) const {
    if (build.empty()) return false;
    std::FILE *f = std::fopen(path_for(build).c_str(), "rb");
    if (!f) return false;
    char buf[256];
    const size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = 0;
    const std::string body(buf, n);
    // Tercera linea: los tramos.  Un apuntador escrito antes de que existieran
    // no la trae, y entonces simplemente no hay tramos.
    size_t p1 = body.find(10);
    if (p1 == std::string::npos) return false;
    size_t p2 = body.find(10, p1 + 1);
    if (p2 == std::string::npos) return false;
    size_t p3 = body.find(10, p2 + 1);
    if (p3 == std::string::npos) return false;
    const ContentHash h =
        ContentHash::from_hex(body.substr(p2 + 1, p3 - p2 - 1));
    if (h.empty()) return false;
    return load_node(store_, h, out_spans);
}

} // namespace vxdbg
