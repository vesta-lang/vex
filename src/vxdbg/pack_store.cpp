/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file pack_store.cpp
 * @brief Implementacion del almacen empaquetado (contrato en pack_store.h).
 */
#include "vxdbg/pack_store.h"

#include "util/fnv.h"
#include "util/fs_utils.h"
#include "util/file_read.h"
#include "util/serialize.h"

#include <algorithm>

#include <set>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <unistd.h>
#endif

namespace vxdbg {

namespace {

/// Un nodo dentro del cuerpo del paquete: el mismo formato que en el almacen
/// suelto, para que empaquetar no invente una segunda forma de escribir un
/// nodo.  Dos formatos para lo mismo acaban divergiendo.
void escribir_cuerpo(util::ByteWriter &w, const StoredNode &n) {
    w.u32(VXDBG_NODE_MAGIC);
    w.u16(static_cast<uint16_t>(n.header.kind));
    w.u16(0); // reservado
    w.u32(n.header.schema_version);
    w.u32(static_cast<uint32_t>(n.payload.size()));
    w.raw(n.payload.data(), n.payload.size());
}

bool leer_cuerpo(util::ByteReader &r, StoredNode &out) {
    const uint32_t magia = r.u32();
    if (!r.ok() || magia != VXDBG_NODE_MAGIC) return false;
    const uint16_t genero = r.u16();
    (void)r.u16(); // reservado
    const uint32_t esquema = r.u32();
    const uint32_t tam = r.u32();
    if (!r.ok()) return false;
    if (tam > r.remaining()) return false; // truncado: no se inventa
    out.header.kind = static_cast<NodeKind>(genero);
    out.header.schema_version = esquema;
    out.payload.resize(tam);
    return tam == 0 || r.raw(out.payload.data(), tam);
}

/**
 * @brief Saca el identificador de proceso del nombre `p<pid>_<n>.vxpk`.
 * @return 0 si el nombre no tiene esa forma.
 */
uint64_t pid_del_nombre(const std::string &ruta) {
    const size_t barra = ruta.find_last_of("/\\");
    const std::string hoja =
        barra == std::string::npos ? ruta : ruta.substr(barra + 1);
    if (hoja.size() < 2 || hoja[0] != 'p') return 0;
    const size_t guion = hoja.find('_', 1);
    if (guion == std::string::npos || guion == 1) return 0;
    uint64_t pid = 0;
    for (size_t i = 1; i < guion; ++i) {
        if (hoja[i] < '0' || hoja[i] > '9') return 0;
        pid = pid * 10 + static_cast<uint64_t>(hoja[i] - '0');
    }
    return pid;
}

/// Existe todavia ese proceso?
bool proceso_vivo(uint64_t pid) {
    if (pid == 0) return false;
#ifdef _WIN32
    /* SYNCHRONIZE es el permiso mas modesto que sirve para preguntar por su
     * existencia; pedir mas podria fallar por permisos y hacernos creer que un
     * proceso vivo no lo esta, que es el error caro. */
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (h == nullptr) {
        // Si no se pudo abrir por algo que NO sea que no existe, se supone
        // vivo: equivocarse hacia conservar no cuesta nada.
        return GetLastError() != ERROR_INVALID_PARAMETER;
    }
    // Abrirlo no basta: un proceso terminado conserva su objeto mientras
    // alguien lo tenga abierto, y responde al instante a la espera.
    const bool vivo = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    CloseHandle(h);
    return vivo;
#else
    // La senal 0 no se envia: solo comprueba que se PODRIA.  ESRCH es la unica
    // respuesta que significa "no existe"; EPERM significa que existe y es de
    // otro.
    if (::kill(static_cast<pid_t>(pid), 0) == 0) return true;
    return errno != ESRCH;
#endif
}

/// Identificador del proceso, para que dos compilaciones a la vez no elijan el
/// mismo nombre de paquete.
uint64_t id_proceso() {
#ifdef _WIN32
    return static_cast<uint64_t>(GetCurrentProcessId());
#else
    return static_cast<uint64_t>(::getpid());
#endif
}

} // namespace

bool pack_writer_is_running(const std::string &pack_path) {
    const uint64_t pid = pid_del_nombre(pack_path);
    // Un nombre que no sigue la convencion no dice de quien es.  Como no se
    // sabe, se conserva.
    if (pid == 0) return true;
    return proceso_vivo(pid);
}

PackNodeStore::PackNodeStore(std::string root,
                             std::unique_ptr<NodeStore> suelto, size_t tope)
    : root_(std::move(root)), suelto_(std::move(suelto)), tope_(tope) {}

PackNodeStore::~PackNodeStore() {
    // Lo que quede sin escribir se escribe aqui.  Si fallara no hay a quien
    // avisar desde un destructor, pero tampoco se pierde correccion: lo que no
    // llegue al paquete simplemente se recalculara la proxima vez.
    volcar();
}

size_t PackNodeStore::pendientes() const {
    std::lock_guard<std::mutex> g(mx_);
    return pendientes_.size();
}

bool PackNodeStore::put(const StoredNode &node) {
    if (node.header.hash.empty()) return false; // sin huella no hay donde ir
    std::lock_guard<std::mutex> g(mx_);
    /* PRIMERO REUSAR, y solo despues escribir.
     *
     * Si el nodo ya esta -- en un paquete de otra compilacion o suelto -- no se
     * vuelve a guardar.  Sin esta comprobacion cada compilacion reescribiria
     * ENTERO lo que ya estaba: los paquetes se duplicarian, y ademas los viejos
     * dejarian de poder borrarse porque seguirian teniendo entradas vivas.  El
     * almacen crecerria sin parar guardando lo mismo una y otra vez.
     *
     * Es barato porque la clave ES el contenido: basta mirar el indice en
     * memoria; no hay que leer ni comparar el cuerpo. */
    cargar_indices_();
    if (indice_.count(node.header.hash) != 0) return true;
    if (suelto_ && suelto_->contains(node.header.hash)) return true;
    /* Si ya esta pendiente con OTRO contenido, algo va mal de verdad: o la
     * huella se calculo sobre otra cosa o se guardo bajo la clave equivocada.
     * Callarlo dejaria el almacen sirviendo un nodo por otro. */
    auto it = pendientes_.find(node.header.hash);
    if (it != pendientes_.end())
        return it->second.payload == node.payload &&
               it->second.header.kind == node.header.kind;
    pendientes_.emplace(node.header.hash, node);
    if (pendientes_.size() >= tope_) {
        // Volcado parcial: una compilacion enorme no puede llevarse toda su
        // salida a memoria antes de escribir nada.
        mx_.unlock();
        const bool ok = volcar();
        mx_.lock();
        return ok;
    }
    return true;
}

bool PackNodeStore::write_pack_(
    const std::map<ContentHash, StoredNode> &lote, std::string &out_path,
    std::vector<std::pair<ContentHash, Sitio>> &out_sites) {
    /* El UNICO sitio donde se escribe el formato del paquete.  Lo usan el
     * volcado normal y la compactacion: dos codigos que escriben el mismo
     * formato acaban divergiendo, y aqui divergir significa que un paquete
     * escrito por uno no lo sabe leer el otro. */
    util::ByteWriter w;
    w.u32(VXDBG_PACK_MAGIC);
    w.u32(VXDBG_PACK_VERSION);
    w.u32(static_cast<uint32_t>(lote.size()));
    w.u32(0); // relleno, deja el cuerpo alineado a 8

    // Cuerpo, y de paso donde queda cada nodo.
    std::vector<std::pair<ContentHash, std::pair<uint64_t, uint32_t>>> sitios;
    sitios.reserve(lote.size());
    for (const auto &kv : lote) {
        const uint64_t off = static_cast<uint64_t>(w.size());
        escribir_cuerpo(w, kv.second);
        sitios.push_back(
            {kv.first, {off, static_cast<uint32_t>(w.size() - off)}});
    }

    // Indice al final: hasta aqui no se sabian los desplazamientos.
    const uint64_t off_indice = static_cast<uint64_t>(w.size());
    util::ByteWriter idx;
    for (const auto &s : sitios) {
        idx.u64(s.first.lo);
        idx.u64(s.first.hi);
        idx.u64(s.second.first);
        idx.u32(s.second.second);
        idx.u32(0); // relleno
    }
    const uint64_t suma =
        util::fnv_bytes(util::kFnvOffset, idx.bytes().data(), idx.size());
    w.raw(idx.bytes().data(), idx.size());
    w.u64(off_indice);
    w.u64(suma);
    w.u32(VXDBG_PACK_MAGIC_FIN);

    // Nombre propio de este proceso y volcado: dos compilaciones a la vez no
    // comparten fichero, asi que no hay nada que coordinar.
    out_path = root_ + "/packs/p" + std::to_string(id_proceso()) + "_" +
               std::to_string(n_volcados_++) + ".vxpk";
    if (!fs::write_file_atomic(out_path, w.bytes())) return false;

    out_sites.clear();
    out_sites.reserve(sitios.size());
    for (const auto &s : sitios)
        out_sites.push_back(
            {s.first, Sitio{out_path, s.second.first, s.second.second}});
    return true;
}

bool PackNodeStore::volcar() {
    std::map<ContentHash, StoredNode> lote;
    {
        std::lock_guard<std::mutex> g(mx_);
        if (pendientes_.empty()) return true;
        lote.swap(pendientes_);
    }

    std::string ruta;
    std::vector<std::pair<ContentHash, Sitio>> sitios;
    if (!write_pack_(lote, ruta, sitios)) return false;

    // Lo recien escrito pasa a poder leerse sin releer el fichero.
    {
        std::lock_guard<std::mutex> g(mx_);
        for (const auto &s : sitios)
            indice_[s.first] = s.second;
    }
    return true;
}

void PackNodeStore::cargar_indices_() const {
    if (indices_leidos_) return;
    indices_leidos_ = true;
    namespace stdfs = std::filesystem;
    std::error_code ec;
    const std::string dir = root_ + "/packs";
    if (!stdfs::exists(dir, ec)) return;
    /* El directorio se abre UNA vez y cada paquete se lee relativo a el, dando
     * solo su nombre.  Son 26,2 ms frente a 26,8 abriendo por ruta absoluta:
     * un 2%, y aqui sale gratis porque el directorio hay que abrirlo de todas
     * formas para enumerarlo.  Si no se pudiera abrir, se sigue por la ruta
     * completa y solo se pierde ese 2%. */
    const util::DirectoryReader dir_reader(dir);
    for (const auto &ent : stdfs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!ent.is_regular_file(ec)) continue;
        const std::string ruta = ent.path().string();
        if (ruta.size() < 5 || ruta.compare(ruta.size() - 5, 5, ".vxpk") != 0)
            continue;
        /* El paquete se lee ENTERO y de una vez, aunque para indexar solo
         * hagan falta la cabecera, la cola y el indice.  Lo intuitivo seria
         * traerse solo esos tres tramos, y esta medido que sale PEOR: con
         * 12 KiB de media el paquete son tres paginas, asi que tres lecturas
         * cuestan mas que una.  Sobre los 1.424 paquetes del almacen, entero
         * 27,7 ms frente a 32,3 ms por tramos.
         *
         * Lo que si se cambio es POR DONDE se lee: `util::read_whole_file` va
         * por la llamada del sistema en vez de por `ifstream`, y eso son 33,4
         * ms -> 27,7.  El detalle esta en `util/file_read.h`.
         *
         * Queda dicho para quien venga a optimizar esto: el coste no son los
         * bytes, son las 1.424 APERTURAS -- unos 20 us cada una.  Bajar de
         * aqui pide abrir menos ficheros, no leer menos de cada uno. */
        std::vector<uint8_t> bytes;
        const std::string hoja = ent.path().filename().string();
        if (!(dir_reader.ok() ? dir_reader.read_file(hoja, bytes)
                              : util::read_whole_file(ruta, bytes)))
            continue;
        // 16 de cabecera + 20 de cola es el minimo para que haya algo.
        if (bytes.size() < 16 + 20) continue;

        util::ByteReader cab(bytes);
        const uint32_t magia = cab.u32();
        const uint32_t version = cab.u32();
        const uint32_t n = cab.u32();
        (void)cab.u32(); // relleno
        if (!cab.ok() || magia != VXDBG_PACK_MAGIC) continue;
        if (version != VXDBG_PACK_VERSION) continue;

        util::ByteReader cola(bytes);
        cola.seek(bytes.size() - 20);
        const uint64_t off_indice = cola.u64();
        const uint64_t suma = cola.u64();
        const uint32_t magia_fin = cola.u32();
        if (!cola.ok()) continue;
        // Sin la magia final el fichero se quedo a medias: se ignora ENTERO.
        if (magia_fin != VXDBG_PACK_MAGIC_FIN) continue;
        if (off_indice > bytes.size() - 20) continue;

        const size_t tam_idx =
            bytes.size() - 20 - static_cast<size_t>(off_indice);
        if (tam_idx != static_cast<size_t>(n) * 32) continue;
        /* La suma del indice se comprueba SIEMPRE.  Un indice alterado no
         * rompe la compilacion: sirve un nodo por otro, y el fallo aparece
         * lejisimos de aqui.  Ante la duda, el paquete entero se descarta y lo
         * suyo se recalcula. */
        if (util::fnv_bytes(util::kFnvOffset, bytes.data() + off_indice,
                            tam_idx) != suma)
            continue;

        util::ByteReader ri(bytes);
        ri.seek(static_cast<size_t>(off_indice));
        for (uint32_t i = 0; i < n; ++i) {
            ContentHash h;
            h.lo = ri.u64();
            h.hi = ri.u64();
            const uint64_t off = ri.u64();
            const uint32_t tam = ri.u32();
            (void)ri.u32(); // relleno
            if (!ri.ok()) break;
            if (off + tam > off_indice) break; // apunta fuera del cuerpo
            // El primero que aparece gana: el contenido es el mismo (la clave
            // ES el contenido), asi que da igual de que paquete salga.
            indice_.emplace(h, Sitio{ruta, off, tam});
        }
    }
}

PackNodeStore::ReclaimPreview
PackNodeStore::preview_reclaim(const std::set<ContentHash> &vivas) const {
    std::lock_guard<std::mutex> g(mx_);
    cargar_indices_();

    ReclaimPreview preview;
    std::map<std::string, size_t> total, vivos;
    for (const auto &kv : indice_) {
        ++total[kv.second.ruta];
        if (vivas.count(kv.first) != 0) ++vivos[kv.second.ruta];
    }
    preview.packs = total.size();
    preview.entries = indice_.size();

    namespace stdfs = std::filesystem;
    std::error_code ec;
    for (const auto &kv : total) {
        preview.live_entries += vivos[kv.first];
        if (vivos[kv.first] != 0) continue;
        ++preview.packs_to_delete;
        const auto tam = stdfs::file_size(kv.first, ec);
        if (!ec) preview.bytes_to_free += static_cast<uint64_t>(tam);
        ec.clear();
    }
    return preview;
}

size_t PackNodeStore::reclamar(const std::set<ContentHash> &vivas,
                               const std::set<std::string> *tocables) {
    std::lock_guard<std::mutex> g(mx_);
    cargar_indices_();

    // Que entradas tiene cada paquete, y cuantas de ellas siguen vivas.
    std::map<std::string, size_t> total, vivos;
    for (const auto &kv : indice_) {
        ++total[kv.second.ruta];
        if (vivas.count(kv.first) != 0) ++vivos[kv.second.ruta];
    }

    namespace stdfs = std::filesystem;
    std::error_code ec;
    size_t borrados = 0;
    for (const auto &kv : total) {
        const std::string &ruta = kv.first;
        if (vivos[ruta] != 0) continue; // algo suyo se sigue usando: se queda
        // Recien escrito: puede ser de una compilacion que aun no publico su
        // raiz, y entonces parece muerto sin estarlo.
        if (tocables && tocables->count(ruta) == 0) continue;

        /* Primero se renombra a un nombre muerto y despues se borra.  Si otro
         * proceso lo tiene abierto, termina su lectura tranquilamente sobre el
         * fichero renombrado: en Windows borrar un fichero abierto falla, y
         * dejarlo a medio borrar seria peor que no borrarlo. */
        const std::string muerto = ruta + ".muerto";
        stdfs::rename(ruta, muerto, ec);
        if (ec) {
            ec.clear();
            continue;
        } // otro se adelanto: no pasa nada
        stdfs::remove(muerto, ec);
        ec.clear();
        ++borrados;
    }

    if (borrados != 0) {
        // El indice en memoria deja de describir el disco: se rehace a la
        // proxima consulta.  Mas barato que ir quitando entrada por entrada, y
        // sobre todo imposible de dejar a medias.
        indice_.clear();
        indices_leidos_ = false;
    }
    return borrados;
}

PackNodeStore::CompactResult
PackNodeStore::compact(const std::set<ContentHash> &vivas,
                       size_t entries_per_pack,
                       const std::set<std::string> *tocables) {
    if (entries_per_pack == 0) entries_per_pack = 1;
    std::lock_guard<std::mutex> g(mx_);
    cargar_indices_();

    CompactResult result;
    namespace stdfs = std::filesystem;
    std::error_code ec;

    /* Las entradas vivas, agrupadas POR PAQUETE.  Es lo que permite leer cada
     * paquete UNA vez: ir entrada por entrada llamando a `get` releeria el
     * fichero entero por cada nodo -- 14.685 lecturas de los mismos 1.454
     * ficheros. */
    std::map<std::string, std::vector<std::pair<ContentHash, Sitio>>>
        por_paquete;
    for (const auto &kv : indice_) {
        if (vivas.count(kv.first) != 0)
            por_paquete[kv.second.ruta].push_back(kv);
        else
            ++result.entries_dropped;
    }

    /* Todos los paquetes que hay AHORA, separando los que NO se pueden tocar:
     * los recien escritos pueden ser de una compilacion en vuelo que todavia no
     * ha publicado su raiz.  Esos se quedan tal cual -- ni se leen ni se
     * reescriben ni se borran -- y ya los cogera la siguiente recogida. */
    std::vector<std::string> viejos;
    std::set<std::string> protegidos;
    for (const auto &ent : stdfs::directory_iterator(root_ + "/packs", ec)) {
        if (ec) break;
        const std::string ruta = ent.path().string();
        if (ruta.size() < 5 || ruta.compare(ruta.size() - 5, 5, ".vxpk") != 0)
            continue;
        if (tocables && tocables->count(ruta) == 0) {
            protegidos.insert(ruta);
            continue;
        }
        viejos.push_back(ruta);
        const auto tam = ent.file_size(ec);
        if (!ec) result.bytes_before += static_cast<uint64_t>(tam);
        ec.clear();
    }
    ec.clear();
    result.packs_before = viejos.size();
    if (por_paquete.empty()) return result; // nada vivo que reescribir

    const util::DirectoryReader lector(root_ + "/packs");
    std::map<ContentHash, StoredNode> lote;
    std::vector<std::string> nuevos;
    /* El indice NUEVO se va construyendo aqui.  `write_pack_` ya dice donde
     * quedo cada nodo, asi que tirarlo y releer los paquetes despues seria
     * rehacer un trabajo que ya esta hecho. */
    std::map<ContentHash, Sitio> indice_nuevo;

    // Vuelca el lote acumulado y lo deja listo para el siguiente.
    const auto volcar_lote = [&]() -> bool {
        if (lote.empty()) return true;
        std::string ruta;
        std::vector<std::pair<ContentHash, Sitio>> sitios;
        if (!write_pack_(lote, ruta, sitios)) return false;
        nuevos.push_back(ruta);
        for (auto &s : sitios)
            indice_nuevo.emplace(s.first, std::move(s.second));
        result.entries_kept += lote.size();
        lote.clear();
        return true;
    };

    std::set<std::string> ilegibles;
    for (const auto &kv : por_paquete) {
        // Intocable: lo suyo se queda donde esta.
        if (protegidos.count(kv.first) != 0) continue;
        std::vector<uint8_t> bytes;
        const std::string hoja = stdfs::path(kv.first).filename().string();
        if (!(lector.ok() ? lector.read_file(hoja, bytes)
                          : util::read_whole_file(kv.first, bytes))) {
            /* No se deja leer.  Se salta en vez de abortar, porque un solo
             * paquete estropeado no puede dejar el almacen sin compactar para
             * siempre.  Pero se APUNTA, y no se borra despues: sus entradas
             * vivas no se han copiado a ningun sitio, asi que borrarlo seria
             * perderlas.  Si el fallo era pasajero -- otro proceso lo tenia
             * abierto -- la siguiente recogida lo cogera bien. */
            ilegibles.insert(kv.first);
            continue;
        }
        for (const auto &entrada : kv.second) {
            const Sitio &sitio = entrada.second;
            if (sitio.offset + sitio.tam > bytes.size()) continue;
            util::ByteReader r(bytes);
            r.seek(static_cast<size_t>(sitio.offset));
            StoredNode nodo;
            if (!r.ok() || !leer_cuerpo(r, nodo)) continue;
            nodo.header.hash = entrada.first;
            lote.emplace(entrada.first, std::move(nodo));
            if (lote.size() >= entries_per_pack && !volcar_lote()) {
                result.ok = false;
                return result;
            }
        }
    }
    if (!volcar_lote()) {
        result.ok = false;
        return result;
    }
    result.packs_after = nuevos.size();

    /* Los nuevos ya estan publicados: a partir de aqui borrar los viejos solo
     * quita copias de sobra.  Se renombra antes de borrar por lo mismo que en
     * `reclamar`: en Windows no se puede borrar lo que otro tiene abierto, y un
     * borrado a medias seria peor que ninguno. */
    for (const auto &ruta : viejos) {
        if (ilegibles.count(ruta) != 0) continue; // lo suyo no se copio
        const std::string muerto = ruta + ".muerto";
        stdfs::rename(ruta, muerto, ec);
        if (ec) {
            ec.clear();
            continue;
        }
        stdfs::remove(muerto, ec);
        ec.clear();
        ++result.packs_removed;
    }
    for (const auto &ruta : nuevos) {
        const auto tam = stdfs::file_size(ruta, ec);
        if (!ec) result.bytes_after += static_cast<uint64_t>(tam);
        ec.clear();
    }

    /* El indice se SUSTITUYE por el que se acaba de construir, no se tira: ya
     * describe el disco exactamente, entrada por entrada.  Vaciarlo obligaria
     * a releer los paquetes en la siguiente consulta para averiguar lo que
     * aqui ya se sabia.
     *
     * Lo que se queda fuera es justo lo que debe: las entradas muertas, que ya
     * no estan en ningun paquete. */
    if (!ilegibles.empty() || !protegidos.empty()) {
        /* Quedan paquetes que no se procesaron -- protegidos por recientes, o
         * ilegibles --, asi que el indice nuevo no describe todo el disco: esos
         * siguen ahi con entradas que no estan en el.  Se rehace leyendo, que
         * es lo unico que da la foto completa. */
        indice_.clear();
        indices_leidos_ = false;
    } else {
        indice_.swap(indice_nuevo);
        indices_leidos_ = true;
    }
    return result;
}

bool PackNodeStore::get(ContentHash hash, StoredNode &out) const {
    Sitio sitio;
    {
        std::lock_guard<std::mutex> g(mx_);
        auto p = pendientes_.find(hash);
        if (p !=
            pendientes_.end()) { // aun sin escribir, pero ya se puede servir
            out = p->second;
            return true;
        }
        cargar_indices_();
        auto it = indice_.find(hash);
        if (it == indice_.end()) {
            // No esta empaquetado: puede estar suelto de antes.
            return suelto_ && suelto_->get(hash, out);
        }
        sitio = it->second;
    }

    /* SOLO el cuerpo del nodo, no el paquete entero.  Leerlo entero funcionaba
     * mientras los paquetes eran de 12 KiB, pero desde que se compactan un
     * paquete son megabytes: traerselo por cada nodo son 2 MiB tirados cada
     * vez, y recorrer el grafo entero pasaba a mover decenas de gigabytes.
     * Aqui el tramo es una porcion minuscula de algo grande, que es
     * exactamente cuando leer por tramos compensa. */
    std::vector<uint8_t> bytes;
    if (!util::read_file_range(sitio.ruta, sitio.offset, sitio.tam, bytes))
        return false;
    util::ByteReader r(bytes);
    if (!leer_cuerpo(r, out)) return false;
    out.header.hash = hash;
    return true;
}

bool PackNodeStore::contains(ContentHash hash) const {
    {
        std::lock_guard<std::mutex> g(mx_);
        if (pendientes_.count(hash) != 0) return true;
        cargar_indices_();
        if (indice_.count(hash) != 0) return true;
    }
    return suelto_ && suelto_->contains(hash);
}

} // namespace vxdbg
