/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vxdbg/maintenance.cpp
 * @brief Implementacion del mantenimiento (contrato en maintenance.h).
 */

#include "vxdbg/maintenance.h"

#include "util/file_read.h"
#include "vxdbg/ids.h"
#include "vxdbg/pack_store.h"
#include "vxdbg/reachable.h"
#include "vxdbg/store.h"

#include <filesystem>

#include <map>
#include <memory>
#include <string>
#include <set>
#include <vector>

namespace vxdbg {

namespace {

/// Cuenta de paquetes: cuantos hay, y cuales se pueden tocar.
struct PackCount {
    size_t total = 0;
    /// Los de compilaciones YA TERMINADAS.  De los de las que siguen en marcha
    /// no se sabe todavia si su raiz llegara, asi que no se tocan.
    std::set<std::string> collectable;
};

/**
 * @brief Cuenta los paquetes sin abrir ninguno.
 *
 * @param con_procedencia Si averiguar ademas CUALES son de compilaciones ya
 *        terminadas.  Eso cuesta una llamada al sistema por fichero -- hay que
 *        preguntar si ese proceso sigue vivo -- y este recuento lo hace TODA
 *        compilacion, asi que en el caso normal, que es no llegar al umbral, no
 *        se pregunta por ninguno: basta con cuantos hay.
 */
PackCount count_packs(const std::string &dir, bool con_procedencia) {
    namespace stdfs = std::filesystem;
    std::error_code ec;
    PackCount count;
    for (const auto &e : stdfs::directory_iterator(dir + "/packs", ec)) {
        if (ec) break;
        const std::string p = e.path().string();
        if (p.size() < 5 || p.compare(p.size() - 5, 5, ".vxpk") != 0) continue;
        ++count.total;
        if (con_procedencia && !pack_writer_is_running(p))
            count.collectable.insert(p);
    }
    return count;
}

/// Un apuntador de raiz, tal como esta en disco.
struct RootPointer {
    std::string path;     ///< del propio `.ptr`
    ContentHash map;      ///< el mapa que ofrece
    ContentHash build;    ///< de quien dice ser
    std::string artifact; ///< donde se escribio; vacio = sin pista
};

/// Lee los apuntadores con su pista, sin resolver nada.
std::vector<RootPointer> read_root_pointers(const std::string &dir) {
    namespace stdfs = std::filesystem;
    std::vector<RootPointer> out;
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
        const std::string body(reinterpret_cast<const char *>(bytes.data()),
                               bytes.size());
        // Lineas: mapa, de quien es, tramos, y (opcional) donde se escribio.
        const size_t n1 = body.find('\n');
        if (n1 == std::string::npos) continue;
        const size_t n2 = body.find('\n', n1 + 1);
        if (n2 == std::string::npos) continue;
        const size_t n3 = body.find('\n', n2 + 1);

        RootPointer rp;
        rp.path = p;
        rp.map = ContentHash::from_hex(body.substr(0, n1));
        rp.build = ContentHash::from_hex(body.substr(n1 + 1, n2 - n1 - 1));
        if (n3 != std::string::npos) {
            const size_t n4 = body.find('\n', n3 + 1);
            rp.artifact = n4 == std::string::npos
                              ? body.substr(n3 + 1)
                              : body.substr(n3 + 1, n4 - n3 - 1);
        }
        out.push_back(std::move(rp));
    }
    return out;
}

/**
 * @brief Retira los apuntadores que quedaron SOBRESCRITOS.
 *
 * La regla es un hecho comprobable, no una preferencia: para una ruta dada solo
 * puede seguir vivo el apuntador cuyo identificador coincide con el fichero que
 * hay ahi AHORA.  Compilar quinientas veces publica quinientos apuntadores, y
 * el binario es uno: los otros 499 describen algo que ya no existe.
 *
 * Se comprueba rehaciendo la huella de los bytes -- el mismo calculo que hizo
 * `publish` --, asi que la ruta solo dice donde mirar; lo que decide es el
 * contenido.  Ni fechas ni orden de llegada.
 *
 * Lo que NO se toca:
 *   - los que no traen pista (escritos antes de que existiera, o de otra
 *     maquina): no se sabe, se conservan;
 *   - los de una ruta que ya no existe: pudo moverse el binario, y `roots.h`
 *     dice justo que la identidad no es el nombre.  Ante la duda, se queda.
 *
 * @return Cuantos se retiraron.
 */
size_t retire_superseded_roots(const std::string &dir) {
    namespace stdfs = std::filesystem;
    const std::vector<RootPointer> pointers = read_root_pointers(dir);

    // Agrupados por ruta: el fichero de cada una se lee UNA vez.
    std::map<std::string, std::vector<const RootPointer *>> por_ruta;
    for (const auto &rp : pointers)
        if (!rp.artifact.empty() && !rp.build.empty())
            por_ruta[rp.artifact].push_back(&rp);

    size_t retirados = 0;
    std::error_code ec;
    for (const auto &kv : por_ruta) {
        // Un solo apuntador para esa ruta no puede haber sido sobrescrito por
        // otro que conozcamos: no hay nada que decidir y nos ahorramos leerlo.
        if (kv.second.size() < 2) continue;

        std::vector<uint8_t> bytes;
        if (!util::read_whole_file(kv.first, bytes) || bytes.empty())
            continue; // ya no esta: pudo moverse, no se toca ninguno
        const ContentHash actual = hash_bytes(bytes.data(), bytes.size());

        /* Si el fichero de ahi no es NINGUNO de los que conocemos, no se
         * retira nada.  Puede ser legitimo -- lo compilo otra herramienta, o lo
         * sustituyeron a mano -- pero tambien puede ser que otro proceso lo
         * este reescribiendo ahora mismo y hayamos leido un fichero a medias,
         * cuya huella no coincide con nada.  Retirar entonces se llevaria por
         * delante el apuntador bueno.  Solo se retira cuando el superviviente
         * esta IDENTIFICADO. */
        bool hay_superviviente = false;
        for (const RootPointer *rp : kv.second)
            if (rp->build == actual) hay_superviviente = true;
        if (!hay_superviviente) continue;

        for (const RootPointer *rp : kv.second) {
            if (rp->build == actual) continue; // este es el del fichero de ahi
            stdfs::remove(rp->path, ec);
            if (!ec) ++retirados;
            ec.clear();
        }
    }
    return retirados;
}

/**
 * @brief Retira los apuntadores que ya no llevan a ningun sitio.
 *
 * Un apuntador cuyo mapa no esta en el almacen no puede explicar nada: es una
 * puerta a una habitacion que ya no existe.  Retirarlo no pierde nada, y aqui
 * tampoco hay nada que elegir -- se comprueba, no se decide.
 *
 * Es lo unico que limpia el sedimento anterior a que los apuntadores llevaran
 * la ruta: sin pista no se puede saber si quedaron sobrescritos, pero si se
 * puede saber que ya no sirven.
 *
 * Se llama ANTES de recoger nada.  Al reves seria una carrera consigo mismo:
 * la recogida deja apuntadores colgados en la misma pasada que los crea.
 *
 * @return Cuantos se retiraron.
 */
size_t retire_dangling_roots(const NodeStore &store, const std::string &dir) {
    namespace stdfs = std::filesystem;
    size_t retirados = 0;
    std::error_code ec;
    for (const auto &rp : read_root_pointers(dir)) {
        // Sin mapa el apuntador esta corrupto; tampoco sirve.
        if (!rp.map.empty() && store.contains(rp.map)) continue;
        stdfs::remove(rp.path, ec);
        if (!ec) ++retirados;
        ec.clear();
    }
    return retirados;
}

} // namespace

MaintenanceResult maintain_store(const std::string &dir, size_t pack_threshold,
                                 bool force) {
    namespace stdfs = std::filesystem;
    MaintenanceResult result;
    std::error_code ec;
    if (!stdfs::exists(dir, ec)) {
        result.status = MaintenanceStatus::NoStore;
        return result;
    }

    /* Lo primero es lo barato: contar ficheros.  Este camino lo recorre CADA
     * compilacion, asi que mientras no haga falta recoger no puede costar mas
     * que enumerar un directorio. */
    /* ESTE ORDEN ES LA PARTE DELICADA DE TODO EL FICHERO.
     *
     * Primero se fija QUE paquetes se pueden tocar -- los de procesos que ya
     * han terminado -- y solo DESPUES se leen las raices.  Al reves se pierden
     * datos, y esta visto pasar con la suite en paralelo: un proceso escribe su
     * paquete, sigue vivo mientras se le comprueba, publica su raiz y muere.
     * Si las raices se leyeron antes de que la publicara, su contenido no sale
     * en el conjunto vivo; y si la comprobacion se hace al borrar, para
     * entonces ya esta muerto y su paquete ha dejado de estar protegido.  Se
     * borraria justo lo que acaba de anunciar.
     *
     * Fijandolo antes, la regla se sostiene sola: si un proceso ya estaba
     * muerto cuando se miro, su raiz esta publicada y la lectura de despues la
     * va a ver.  Y el que muera despues no esta en el conjunto, asi que no se
     * le toca.
     *
     * Se decide ademas por los TOCABLES y no por el total: en una tanda
     * paralela casi todos son de procesos vivos, y mirar el total llevaria a
     * recorrer el grafo entero en cada compilacion para acabar sin poder borrar
     * nada. */
    /* Primero lo mas barato de todo: cuantos hay.  Si no se llega al umbral, se
     * vuelve sin preguntar por ninguno -- y ese es el caso de casi todas las
     * compilaciones, asi que es el que no puede costar nada. */
    const PackCount solo_contar = count_packs(dir, /*con_procedencia=*/false);
    result.packs_before = solo_contar.total;
    if (!force && solo_contar.total < pack_threshold) {
        result.status = MaintenanceStatus::BelowThreshold;
        return result;
    }

    // Ahora si: cuales se pueden tocar.  Esto cuesta una llamada por fichero y
    // solo se paga cuando de verdad puede haber algo que recoger.
    const PackCount count = count_packs(dir, /*con_procedencia=*/true);
    if (!force && count.collectable.size() < pack_threshold) {
        result.status = MaintenanceStatus::BelowThreshold;
        return result;
    }

    /* Antes de mirar que vive, quitar los apuntadores que ya no describen
     * nada.  Va aqui y no despues por dos motivos: sus nodos dejan de estar
     * vivos y se recogen en esta misma pasada, y ademas el recorrido tiene
     * menos por donde entrar -- con 12.776 apuntadores eso era 0,84 s. */
    result.roots_retired = retire_superseded_roots(dir);

    PackNodeStore store(dir,
                        std::unique_ptr<NodeStore>(new FileNodeStore(dir)));
    // Y los que ya no llevan a ningun sitio.  Es lo unico que limpia lo
    // anterior a que los apuntadores llevaran la ruta.
    result.roots_retired += retire_dangling_roots(store, dir);

    std::vector<ContentHash> roots;
    read_published_roots(dir, roots);
    if (roots.empty()) {
        /* Sin raices el recorrido no alcanza nada y TODO pareceria muerto:
         * recoger aqui vaciaria el almacen entero.  Que no haya raices no
         * significa que no haya nada vivo, significa que no se sabe. */
        result.status = MaintenanceStatus::NoRoots;
        return result;
    }

    std::set<ContentHash> live;
    const ReachReport report = compute_live_set(store, roots, live);
    if (report.status != ReachStatus::Ok) {
        // Con un conjunto vivo incompleto se borraria lo que si se usa.
        result.status = MaintenanceStatus::TraversalIncomplete;
        return result;
    }

    /* Reclamar antes de compactar: reclamar borra paquetes enteros sin leerlos,
     * asi que quitarlos primero es trabajo que la compactacion ya no hace. */
    result.packs_removed = store.reclamar(live, &count.collectable);

    const PackNodeStore::CompactResult compacted =
        store.compact(live, 8192, &count.collectable);
    if (!compacted.ok) {
        result.status = MaintenanceStatus::WriteFailed;
        return result;
    }
    result.status = MaintenanceStatus::Ran;
    result.packs_after = compacted.packs_after;
    result.entries_kept = compacted.entries_kept;
    result.entries_dropped = compacted.entries_dropped;
    result.bytes_before = compacted.bytes_before;
    result.bytes_after = compacted.bytes_after;
    return result;
}

} // namespace vxdbg
