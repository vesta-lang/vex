/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vxdbg/store_cli.cpp
 * @brief Implementacion del subcomando (contrato en store_cli.h).
 */

#include "vxdbg/store_cli.h"

#include "vx/vxdbg_emit.h"
#include "vxdbg/codec.h"
#include "vxdbg/maintenance.h"
#include "vxdbg/pack_store.h"
#include "vxdbg/reachable.h"
#include "util/file_read.h"
#include "vxdbg/source_meta.h"

#include <cstdio>
#include <filesystem>
#include <memory>
#include <map>
#include <set>
#include <vector>
#include <string>

namespace vxdbg {
namespace cli {

namespace {

/// Lo que ocupa el almacen en disco, contado del propio disco.
struct StoreSize {
    size_t packs = 0;
    uint64_t pack_bytes = 0;
    size_t loose = 0;
    size_t roots = 0;
};

StoreSize measure_store(const std::string &dir) {
    namespace stdfs = std::filesystem;
    StoreSize size;
    std::error_code ec;

    for (const auto &e : stdfs::directory_iterator(dir + "/packs", ec)) {
        if (ec) break;
        const std::string p = e.path().string();
        if (p.size() < 5 || p.compare(p.size() - 5, 5, ".vxpk") != 0) continue;
        ++size.packs;
        const auto n = e.file_size(ec);
        if (!ec) size.pack_bytes += static_cast<uint64_t>(n);
        ec.clear();
    }
    ec.clear();

    for (const auto &e : stdfs::directory_iterator(dir + "/roots", ec)) {
        if (ec) break;
        if (e.is_regular_file(ec)) ++size.roots;
    }
    ec.clear();

    /* Los sueltos van repartidos en carpetas de dos digitos, como los objetos
     * de git, asi que hay que bajar un nivel.  Se salta `packs` y `roots`, que
     * viven al mismo nivel y no son eso. */
    for (const auto &e : stdfs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!e.is_directory(ec)) continue;
        const std::string name = e.path().filename().string();
        if (name == "packs" || name == "roots") continue;
        std::error_code ec2;
        for (const auto &f : stdfs::directory_iterator(e.path(), ec2)) {
            if (ec2) break;
            if (f.is_regular_file(ec2)) ++size.loose;
        }
    }
    return size;
}

const char *reason_text(ReachStatus st) {
    switch (st) {
    case ReachStatus::UnknownKind:
        return "un genero de nodo que el recorrido no sabe seguir";
    case ReachStatus::Undecodable:
        return "un nodo que el codec rechazo (esquema de otra version?)";
    case ReachStatus::Ok: break;
    }
    return "";
}

void print_usage() {
    std::printf(
        "uso: vm vxdbg <orden> [argumento] [carpeta]\n\n"
        "  status          Que hay en el almacen y cuanto sobra.  No borra.\n"
        "  gc              Borra lo que ya no se usa y junta el resto.  SI "
        "borra.\n"
        "  node <huella>   Que es ese nodo y a quien cita.\n"
        "  dangling        Referencias a nodos que no estan, CON quien las "
        "hace.\n\n"
        "La carpeta por defecto es la del cache del proyecto.\n");
}

/// Nombre legible de un genero de nodo.  Solo los que se escriben hoy; del
/// resto se da el numero, que es mejor que inventarle un nombre.
const char *kind_name(NodeKind k) {
    switch (k) {
    case NodeKind::Entity: return "Entity";
    case NodeKind::File: return "File";
    case NodeKind::ArtifactMap: return "ArtifactMap";
    case NodeKind::SpanMap: return "SpanMap";
    default: return nullptr;
    }
}

/// Cuantos citantes se listan.  Casi siempre son pocos con muchas cada uno, asi
/// que con una decena ya se ve donde esta el problema.
constexpr size_t kMaxCitersShown = 10;

void print_kind(NodeKind k) {
    const char *n = kind_name(k);
    if (n != nullptr)
        std::printf("%s", n);
    else
        std::printf("genero %u", static_cast<unsigned>(k));
}

/**
 * @brief De donde salio cada mapa: la ruta del artefacto que explica.
 *
 * Los apuntadores de raiz guardan donde se escribio el artefacto, asi que
 * invertirlos da lo unico descriptivo que hay en un almacen cuyas claves son
 * huellas.  Sin esto, mirar el almacen es leer identificadores de 32 caracteres
 * y adivinar cual es cual.
 *
 * Se lee entero -- son miles de ficheros diminutos -- porque estas ordenes
 * estan para mirar y ya pagan el recorrido.  El mantenimiento que corre al
 * compilar no lo llama.
 */
std::map<ContentHash, std::string> load_artifact_paths(const std::string &dir) {
    namespace stdfs = std::filesystem;
    std::map<ContentHash, std::string> out;
    std::error_code ec;
    const std::string roots_dir = dir + "/roots";
    if (!stdfs::exists(roots_dir, ec)) return out;
    const util::DirectoryReader reader(roots_dir);
    for (const auto &e : stdfs::directory_iterator(roots_dir, ec)) {
        if (ec) break;
        const std::string p = e.path().string();
        if (p.size() < 4 || p.compare(p.size() - 4, 4, ".ptr") != 0) continue;
        std::vector<uint8_t> bytes;
        const std::string leaf = e.path().filename().string();
        if (!(reader.ok() ? reader.read_file(leaf, bytes)
                          : util::read_whole_file(p, bytes)))
            continue;
        const std::string body(bytes.begin(), bytes.end());
        const size_t n1 = body.find('\n');
        if (n1 == std::string::npos) continue;
        const ContentHash map = ContentHash::from_hex(body.substr(0, n1));
        if (map.empty()) continue;
        const size_t n2 = body.find('\n', n1 + 1);
        if (n2 == std::string::npos) continue;
        const size_t n3 = body.find('\n', n2 + 1);
        if (n3 == std::string::npos) continue;
        const size_t n4 = body.find('\n', n3 + 1);
        std::string ruta = n4 == std::string::npos
                               ? body.substr(n3 + 1)
                               : body.substr(n3 + 1, n4 - n3 - 1);
        if (!ruta.empty()) out.emplace(map, std::move(ruta));
    }
    return out;
}

/// Lo que comparten al principio todas las claves: el modulo del que salen.
/// Vacio si no comparten nada, que tambien es informacion.
std::string common_prefix(
    const std::vector<std::pair<std::string, LanguageEntityId>> &syms) {
    if (syms.empty()) return std::string();
    std::string pre = syms.front().first;
    for (const auto &s : syms) {
        size_t i = 0;
        while (i < pre.size() && i < s.first.size() && pre[i] == s.first[i])
            ++i;
        pre.resize(i);
        if (pre.empty()) break;
    }
    // Se corta en el ultimo separador para no dejar medio identificador.
    const size_t cut = pre.rfind("__");
    if (cut == std::string::npos) return std::string();
    return pre.substr(0, cut + 2) + "*";
}

/// Como se reconoce un nodo de un vistazo.  Una huella no dice nada; el nombre
/// de una entidad, o de que va un mapa, todo.
std::string node_label(const StoredNode &node) {
    if (node.header.kind == NodeKind::Entity) {
        LanguageEntity e;
        if (!decode(node, e)) return std::string();
        /* La CLAVE distingue (`Vector` de dos espacios de nombres se llaman
         * igual); el nombre se lee mejor.  Se dan los dos si difieren. */
        if (!e.key.empty() && e.key != e.name)
            return e.name + "  [" + e.key + "]";
        return e.name;
    }
    if (node.header.kind == NodeKind::ArtifactMap) {
        ArtifactMap m;
        if (!decode(node, m)) return std::string();
        std::string s = std::to_string(m.symbols.size()) + " simbolos";
        if (!m.modules.empty())
            s += ", " + std::to_string(m.modules.size()) + " modulos";
        const std::string pre = common_prefix(m.symbols);
        if (!pre.empty())
            s += "   " + pre;
        else if (!m.symbols.empty())
            s += "   p.ej. " + m.symbols.front().first;
        return s;
    }
    if (node.header.kind == NodeKind::File) {
        FileNode f;
        if (!decode(node, f)) return std::string();
        return f.path;
    }
    return std::string();
}

int run_node(const std::string &dir, const std::string &hex, bool listar_todo) {
    const ContentHash h = ContentHash::from_hex(hex);
    if (h.empty()) {
        std::printf("huella invalida: %s\n", hex.c_str());
        return 2;
    }
    PackNodeStore store(dir,
                        std::unique_ptr<NodeStore>(new FileNodeStore(dir)));
    StoredNode node;
    if (!store.get(h, node)) {
        std::printf("%s\n  NO esta en el almacen\n", hex.c_str());
        return 1;
    }
    std::printf("%s\n  ", hex.c_str());
    print_kind(node.header.kind);
    std::printf(" v%u, %zu bytes", node.header.schema_version,
                node.payload.size());
    const std::string etiqueta = node_label(node);
    if (!etiqueta.empty()) std::printf("\n  %s", etiqueta.c_str());
    // De donde salio: el artefacto al que explica, si alguna raiz lo ofrece.
    const auto rutas = load_artifact_paths(dir);
    auto itr = rutas.find(h);
    if (itr != rutas.end()) std::printf("\n  explica  %s", itr->second.c_str());
    std::printf("\n");

    /* A quien cita, con la MISMA rutina que usa el recorrido.  Listarlas aparte
     * habria dejado dos versiones de la verdad, y esta orden existe justo para
     * poder creerse lo que dice el recorrido. */
    std::vector<ContentHash> refs;
    const ReachStatus st = collect_references(node, refs);
    if (st != ReachStatus::Ok) {
        std::printf("  cita: no se sabe (%s)\n", reason_text(st));
        return 1;
    }
    if (refs.empty()) {
        std::printf("  no cita a nadie\n");
        return 0;
    }

    /* Se resuelve todo, pero se ENSENA lo excepcional.  Volcar las 292 lineas
     * de un mapa para que una sola sea la que importa es dejarle el trabajo de
     * filtrar a quien pregunta. */
    std::vector<std::pair<ContentHash, StoredNode>> presentes;
    std::vector<ContentHash> ausentes;
    for (const auto &r : refs) {
        StoredNode dest;
        if (store.get(r, dest))
            presentes.emplace_back(r, std::move(dest));
        else
            ausentes.push_back(r);
    }
    std::printf("  cita %zu nodos: %zu estan, %zu no\n", refs.size(),
                presentes.size(), ausentes.size());

    if (!ausentes.empty()) {
        std::printf("\n  ausentes:\n");
        for (const auto &a : ausentes)
            std::printf("    %s\n", a.to_hex().c_str());
    }
    if (listar_todo) {
        std::printf("\n  presentes:\n");
        for (const auto &p : presentes) {
            std::printf("    %s  %-12s", p.first.to_hex().c_str(),
                        kind_name(p.second.header.kind)
                            ? kind_name(p.second.header.kind)
                            : "?");
            const std::string lbl = node_label(p.second);
            if (!lbl.empty()) std::printf(" %s", lbl.c_str());
            std::printf("\n");
        }
    } else if (!presentes.empty()) {
        std::printf("\n  (los %zu presentes no se listan; anade --todo)\n",
                    presentes.size());
    }
    return 0;
}

int run_dangling(const std::string &dir) {
    namespace stdfs = std::filesystem;
    std::error_code ec;
    if (!stdfs::exists(dir, ec)) {
        std::printf("no hay almacen en %s\n", dir.c_str());
        return 0;
    }
    PackNodeStore store(dir,
                        std::unique_ptr<NodeStore>(new FileNodeStore(dir)));
    std::vector<ContentHash> roots;
    read_published_roots(dir, roots);
    std::set<ContentHash> live;
    // Aqui SI se pide la procedencia: esta orden existe para eso.  El
    // mantenimiento que corre al compilar la pide apagada y no paga nada.
    const ReachReport report =
        compute_live_set(store, roots, live, /*track_dangling_sources=*/true);

    if (report.dangling_refs == 0) {
        std::printf("ninguna referencia sin destino.\n");
        return 0;
    }
    std::printf("%zu referencias sin destino\n\n", report.dangling_refs);

    /* Las dos averias, separadas: una raiz colgada es un artefacto que ya no se
     * puede explicar; una del grafo es un nodo incompleto.  Sumarlas en un solo
     * numero es lo que impedia ver cual habia. */
    size_t desde_nodos = 0;
    for (const auto &c : report.dangling_by_citer)
        desde_nodos += c.count;
    std::printf("  desde raices (.ptr)   %6zu   el mapa que ofrecian ya no "
                "esta\n",
                report.dangling_from_roots);
    std::printf("  desde nodos del grafo %6zu\n", desde_nodos);

    if (!report.dangling_by_citer.empty()) {
        std::printf("\n  los que mas citan lo que falta:\n");
        // De donde salio cada uno.  Una huella sola no dice nada de que es.
        const auto rutas = load_artifact_paths(dir);
        size_t n = 0;
        for (const auto &c : report.dangling_by_citer) {
            if (n++ >= kMaxCitersShown) break;
            /* La huella ENTERA, no abreviada.  Estas lineas estan para pegarlas
             * en `vm vxdbg node`, y una abreviada no sirve para eso: la primera
             * version la acortaba para que se leyera mejor y dejaba la orden
             * que sugiere debajo sin poder usarse. */
            std::printf("    %s  %5zu  ", c.from.to_hex().c_str(), c.count);
            auto itr = rutas.find(c.from);
            if (itr != rutas.end()) {
                // Lo mas descriptivo que hay: a que artefacto explica.
                std::printf("%s\n", itr->second.c_str());
                continue;
            }
            StoredNode citante;
            const std::string lbl = store.get(c.from, citante)
                                        ? node_label(citante)
                                        : std::string();
            std::printf("%s\n", lbl.empty() ? (kind_name(c.from_kind)
                                                   ? kind_name(c.from_kind)
                                                   : "?")
                                            : lbl.c_str());
        }
        if (report.dangling_by_citer.size() > kMaxCitersShown)
            std::printf("    (y %zu mas)\n",
                        report.dangling_by_citer.size() - kMaxCitersShown);
        std::printf("\n  vm vxdbg node <huella>   para ver cual le falta\n");
    }
    return 0;
}

int run_gc(const std::string &dir) {
    /* La MISMA rutina que corre sola al compilar, forzada.  Dos codigos que
     * recogen el almacen acabarian recogiendo cosas distintas, y el que se
     * usa a diario -- el automatico -- seria justo el que nadie prueba a
     * mano. */
    const MaintenanceResult r = maintain_store(dir, 0, /*force=*/true);
    switch (r.status) {
    case MaintenanceStatus::NoStore:
        std::printf("no hay almacen en %s\n", dir.c_str());
        return 0;
    case MaintenanceStatus::NoRoots:
        std::printf("sin raices publicadas: no se toca nada.\n"
                    "  Que no haya raices no quiere decir que no haya nada "
                    "vivo; quiere decir que no se sabe.\n");
        return 1;
    case MaintenanceStatus::TraversalIncomplete:
        std::printf("no se pudo saber que vive; no se toca nada.\n"
                    "  `vm vxdbg status` dice que lo bloquea.\n");
        return 1;
    case MaintenanceStatus::WriteFailed:
        std::printf("fallo al escribir los paquetes nuevos; los viejos se "
                    "quedan como estaban.\n");
        return 1;
    case MaintenanceStatus::BelowThreshold:
    case MaintenanceStatus::Ran: break;
    }
    std::printf("raices retiradas (sobrescritas): %zu\n", r.roots_retired);
    std::printf("paquetes borrados enteros: %zu\n", r.packs_removed);
    std::printf("compactado: %zu paquetes -> %zu   (%.1f MiB -> %.1f MiB)\n",
                r.packs_before, r.packs_after, r.bytes_before / 1048576.0,
                r.bytes_after / 1048576.0);
    std::printf("  entradas conservadas %zu, descartadas %zu\n", r.entries_kept,
                r.entries_dropped);
    return 0;
}

int run_status(const std::string &dir) {
    namespace stdfs = std::filesystem;
    std::error_code ec;
    if (!stdfs::exists(dir, ec)) {
        std::printf("no hay almacen en %s\n", dir.c_str());
        return 0;
    }

    const StoreSize size = measure_store(dir);
    std::printf("almacen  %s\n\n", dir.c_str());
    std::printf("  paquetes           %8zu     %.1f MiB\n", size.packs,
                size.pack_bytes / 1048576.0);
    std::printf("  objetos sueltos    %8zu\n", size.loose);
    std::printf("  raices             %8zu\n", size.roots);

    if (size.roots == 0) {
        /* Sin raices TODO estaria muerto, y reclamar vaciaria el almacen.  Se
         * dice en vez de dar un cero que parece un resultado. */
        std::printf(
            "\n  sin raices publicadas: no se puede decir que sobra.\n");
        return 0;
    }

    PackNodeStore store(dir,
                        std::unique_ptr<NodeStore>(new FileNodeStore(dir)));

    std::vector<ContentHash> roots;
    read_published_roots(dir, roots);

    std::set<ContentHash> live;
    // Mirar es lo que hace esta orden, asi que pide el desglose.  El
    // mantenimiento que corre al compilar no lo pide y no lo paga.
    const ReachReport report =
        compute_live_set(store, roots, live, /*track_dangling_sources=*/true);

    std::printf("\n  alcanzable         %8zu nodos, desde %zu entradas de "
                "raiz\n",
                report.nodes_reached, report.roots_read);
    /* Y DE QUE son esos nodos.  En un almacen cuyas claves son huellas no hay
     * forma de saber que guarda mirandolo, y "20.560 nodos" no dice nada de si
     * son tipos, ficheros o mapas. */
    for (const auto &kv : report.reached_by_kind) {
        const char *n = kind_name(kv.first);
        std::printf("                     %8zu %s\n", kv.second,
                    n != nullptr ? n : "de otro genero");
    }
    std::printf("  sin destino        %8zu referencias", report.dangling_refs);
    if (report.dangling_refs != 0) std::printf("       vm vxdbg dangling");
    std::printf("\n");

    if (report.status != ReachStatus::Ok) {
        /* Se para y se dice por que.  Seguir daria un conjunto vivo incompleto
         * y con el se borraria lo que si se usa. */
        std::printf("\nel recorrido NO se completo: %s\n",
                    reason_text(report.status));
        std::printf("  genero  %u\n  nodo    %s\n",
                    static_cast<unsigned>(report.blocking_kind),
                    report.blocking_node.to_hex().c_str());
        std::printf("\nmientras siga asi no se puede reclamar nada sin "
                    "arriesgarse a borrar lo vivo.\n");
        return 1;
    }

    const PackNodeStore::ReclaimPreview preview = store.preview_reclaim(live);
    std::printf("\n  sobra              %8zu paquetes de %zu     %.1f MiB",
                preview.packs_to_delete, preview.packs,
                preview.bytes_to_free / 1048576.0);
    if (preview.packs_to_delete != 0) std::printf("      vm vxdbg gc");
    std::printf("\n");
    std::printf("                     %8zu entradas muertas de %zu\n",
                preview.entries - preview.live_entries, preview.entries);

    /* La discrepancia de arriba se explica, porque si no parece un fallo: la
     * primera cifra son los FICHEROS que hay en el directorio, y esta los
     * paquetes que aportan alguna entrada al indice.  Un paquete recien escrito
     * por otra compilacion que sigue en marcha cuenta en la primera y no en la
     * segunda. */
    if (preview.packs != size.packs)
        std::printf("                              (%zu de los %zu ficheros "
                    "no aportan indice todavia)\n",
                    size.packs - preview.packs, size.packs);

    if (preview.packs_to_delete == 0)
        std::printf("\n  ninguno se puede borrar entero: cada paquete conserva "
                    "alguna entrada viva.\n");
    return 0;
}

} // namespace

int run(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 2;
    }
    const std::string order = argv[1];

    // `node` lleva la huella como primer argumento, asi que su carpeta -- si se
    // da -- es el segundo.  El resto la llevan en el primero.
    if (order == "node") {
        if (argc < 3) {
            print_usage();
            return 2;
        }
        // `--todo` puede ir en cualquier sitio; lo que quede es la carpeta.
        bool listar_todo = false;
        std::string dir;
        for (int i = 3; i < argc; ++i) {
            const std::string a = argv[i];
            if (a == "--todo")
                listar_todo = true;
            else if (dir.empty())
                dir = a;
        }
        if (dir.empty()) dir = vx::default_vxdbg_dir();
        return run_node(dir, argv[2], listar_todo);
    }

    const std::string dir = argc >= 3 ? argv[2] : vx::default_vxdbg_dir();
    if (order == "status") return run_status(dir);
    if (order == "gc") return run_gc(dir);
    if (order == "dangling") return run_dangling(dir);

    std::printf("orden desconocida: %s\n\n", order.c_str());
    print_usage();
    return 2;
}

} // namespace cli
} // namespace vxdbg
