/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/manager/analysis_store.cpp
 * @brief Implementacion de @ref analysis::AnalysisStore.
 *
 * El paquete es un fichero plano y deliberadamente simple:
 *
 *   magia u32 | version u32 | n_entradas u32
 *   n x ( clave u64 | longitud u32 | bytes )
 *   magia_final u32
 *
 * Sin indice al final ni desplazamientos: se lee ENTERO de una vez -- que es
 * justo el punto de que sea un solo fichero --, asi que saltarse una entrada no
 * ahorra nada y un indice solo seria otra cosa que puede desincronizarse.
 */

#include "analysis/manager/analysis_store.h"

#include "util/env_flags.h"
#include "util/file_read.h" // NUESTRA E/S: NtOpenFile + fichero entero
#include "util/fnv.h"       // la mezcla del proyecto, no otra escrita aqui
#include "util/serialize.h"
#include "vx/diag/diag_catalog.h" // el texto, en todos los idiomas

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>

namespace analysis {

namespace {

/// Marca del paquete.  Un fichero que no la lleve no es de aqui y se descarta
/// entero: interpretar bytes ajenos como analisis no daria error, daria hechos
/// inventados.
constexpr uint32_t kMagic = 0x414E4C53u;    // "ANLS"
constexpr uint32_t kMagicEnd = 0x534C4E41u; // "SLNA": dice que esta COMPLETO
/// Version del CONTENEDOR (no la de cada analisis, que va en su clave).  Sube
/// si cambia este layout; entonces lo viejo se descarta y se vuelve a llenar.
///
/// La 2 anade a cada entrada cuantas corridas lleva sin pedirse, que es lo que
/// evita que el almacen se vacie solo cuando un consumidor no corre.
constexpr uint32_t kVersion = 2;

/**
 * @brief Mezcla un texto en la huella, con separador detras.
 *
 * La mezcla es la del proyecto (@c util::fnv_bytes), no una escrita aqui: dos
 * formas de mezclar acaban dando dos identidades para lo mismo, y entonces una
 * invalida y la otra no.
 *
 * El separador es lo unico que anade: sin el, ("ab","c") y ("a","bc")
 * mezclarian la misma secuencia y dos analisis distintos podrian compartir
 * clave -- que aqui significa leer los bytes de otro e interpretarlos como
 * propios --.
 */
uint64_t mix_text(uint64_t h, const char *s) noexcept {
    const char *p = (s != nullptr) ? s : "";
    return util::fnv_mix(util::fnv_bytes(h, p, std::strlen(p)), 0xFFull);
}

} // namespace

uint64_t AnalysisStore::key_of(const char *analysis, uint32_t version,
                               uint64_t fn_key, const char *stage) const {
    // dominio: "ANALYSIS", para que estas claves no puedan chocar con otras.
    uint64_t h = util::fnv_mix(util::kFnvOffset, 0x414E414C59534953ull);
    h = mix_text(h, analysis);
    /* La version del formato de ESTE analisis, no una global: asi cambiar lo
     * que serializa uno no tira lo guardado de los demas. */
    h = util::fnv_mix(h, version);
    h = util::fnv_mix(h, fn_key);
    h = mix_text(h, stage);
    h = util::fnv_mix(h, config_);
    return util::fnv_mix(h, compiler_);
}

void AnalysisStore::open(const std::string &path) {
    path_ = path;
    entries_.clear();
    live_.clear();
    if (path.empty()) return;

    std::vector<uint8_t> bytes;
    /* Por NUESTRA lectura y no por `std::ifstream`.
     *
     * No es cosmetico: `util::read_whole_file` va por `NtOpenFile` y se trae el
     * fichero de una pieza, y esta medido contra las alternativas -- 27,7 ms
     * frente a los 33,4 del flujo estandar sobre los 1.424 paquetes del almacen
     * de depuracion --.  Y lo que ese banco enseno vale doble aqui: **el grueso
     * del coste es ABRIR, no leer**, que es exactamente por lo que este almacen
     * tiene un fichero por modulo y no uno por analisis.
     *
     * Que no exista no es un error: es la primera compilacion, o alguien limpio
     * la cache.  Se empieza vacio -- y no hace falta preguntar antes si esta,
     * porque no poder abrirlo ya lo dice. */
    if (!util::read_whole_file(path, bytes)) return;
    if (bytes.size() < 16) return;

    util::ByteReader r(bytes.data(), bytes.size());
    if (r.u32() != kMagic) return;
    if (r.u32() != kVersion) return;
    const uint32_t n = r.u32();
    if (!r.ok()) return;
    /* La cuenta se comprueba contra lo que QUEDA: una entrada no baja de
     * dieciseis bytes (clave, corridas sin usar y longitud), asi que mas de eso
     * es imposible por mucho que diga el fichero -- y creerselo seria reservar
     * memoria a lo bruto. */
    if (static_cast<size_t>(n) * 16u > r.remaining()) return;

    for (uint32_t i = 0; i < n && r.ok(); ++i) {
        const uint64_t k = r.u64();
        Entry e;
        e.unused_runs = r.u32();
        const uint32_t len = r.u32();
        if (!r.ok() || len > r.remaining()) return;
        e.bytes.resize(len);
        if (len != 0 && !r.raw(e.bytes.data(), len)) return;
        entries_.emplace(k, std::move(e));
    }
    /* Y la marca del final, que es lo unico que distingue un paquete COMPLETO
     * de uno que se quedo a medias porque el proceso murio escribiendolo.  Sin
     * ella, un fichero truncado se lee como "aqui no habia mas entradas". */
    if (r.u32() != kMagicEnd) {
        entries_.clear();
        return;
    }
    stats_.bytes_read = bytes.size();
}

void AnalysisStore::flush() {
    if (path_.empty()) return;
    /* Nada vivo: no se escribe, y sobre todo NO se borra lo que hubiera.  Una
     * compilacion que no llego a preguntar nada no es motivo para tirar lo que
     * otra dejo. */
    if (live_.empty()) return;

    /* Cada entrada envejece: la que se uso vuelve a cero, la que no sube una.
     * Y se cae la que lleve demasiadas seguidas sin pedirse.
     *
     * Envejecer y no "quedarse solo con lo usado" es la diferencia entre un
     * almacen que dura y uno que se vacia solo: un consumidor que no corre en
     * esta compilacion -- porque sus hechos vinieron del fichero de hechos -- no
     * significa que su analisis sobre.  @see kDefaultUnusedRuns */
    std::vector<uint64_t> to_write;
    to_write.reserve(entries_.size());
    for (std::pair<const uint64_t, Entry> &kv : entries_) {
        const bool used = live_.count(kv.first) != 0;
        kv.second.unused_runs = used ? 0u : kv.second.unused_runs + 1u;
        if (kv.second.unused_runs <= max_unused_runs_)
            to_write.push_back(kv.first);
    }

    util::ByteWriter w;
    w.u32(kMagic);
    w.u32(kVersion);
    w.u32(static_cast<uint32_t>(to_write.size()));
    for (size_t i = 0; i < to_write.size(); ++i) {
        const Entry &e = entries_[to_write[i]];
        w.u64(to_write[i]);
        w.u32(e.unused_runs);
        w.u32(static_cast<uint32_t>(e.bytes.size()));
        if (!e.bytes.empty()) w.raw(e.bytes.data(), e.bytes.size());
    }
    w.u32(kMagicEnd);
    const std::vector<uint8_t> bytes = w.take();
    /* Por NUESTRA escritura, la de `NtCreateFile`/`NtWriteFile`, que ademas
     * dice el tamano final de antemano para que el sistema no vaya extendiendo
     * el fichero por trozos.  La de `fs::write_file_atomic` va por Win32 y por
     * un temporal con renombrado.
     *
     * Y aqui NO hace falta que sea atomica, que es lo que costaria la pasada de
     * mas: esto es una CACHE, y un fichero cortado por una muerte a mitad de
     * escritura lo caza `kMagicEnd` y se descarta entero.  El precio de ese
     * caso es una compilacion en frio, no un resultado equivocado -- que es la
     * unica razon por la que valdria la pena pagar el temporal --. */
    /* El cajon, antes de escribir.  Nuestra escritura NO crea directorios --
     * es una llamada al nucleo, no un ayudante -- y este almacen es el unico
     * que no pasa por la escritura atomica, que si los crea.  Sin esto el
     * primer guardado fallaba en SILENCIO y la cache no arrancaba nunca. */
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(path_).parent_path(), ec);
    if (util::write_whole_file(path_, bytes)) stats_.bytes_written = bytes.size();
}

bool AnalysisStore::load(uint64_t key, std::vector<uint8_t> &out) {
    if (path_.empty()) {
        /* Sin almacen no se cuenta como fallo: no es que faltara lo guardado,
         * es que no hay donde guardar.  Contarlo hundiria la tasa de aciertos
         * y taparia el caso que si dice algo. */
        return false;
    }
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        ++stats_.misses;
        return false;
    }
    out = it->second.bytes;
    /* Usada por ESTA compilacion: su contador vuelve a cero al volcar.  La que
     * nadie pida envejece, y a la larga se cae. */
    live_.insert(key);
    ++stats_.hits;
    return true;
}

bool AnalysisStore::store(uint64_t key, const std::vector<uint8_t> &bytes) {
    if (path_.empty() || bytes.empty()) return false;
    Entry &e = entries_[key];
    e.bytes = bytes;
    e.unused_runs = 0;
    live_.insert(key);
    ++stats_.stored;
    return true;
}

void AnalysisStore::dump_if_asked() const {
    static const bool log_it = util::flag_on(util::FlagId::AsaFactsDebug);
    if (!log_it) return;
    /* Nada que decir si nadie pregunto: un resumen de ceros es ruido que tapa
     * los que si dicen algo. */
    if (stats_.hits == 0 && stats_.misses == 0 && stats_.stored == 0) return;
    /* Por el CATALOGO, como cualquier otro texto que lea una persona.  Que sea
     * una traza de depuracion no la saca de la regla: aqui solo se dan los
     * DATOS, y el texto vive en `catalog/diagnostics.toml` en todos los
     * idiomas. */
    const std::string msg = vx::diag::format(
        "VXA075", vx::diag::current_language(),
        {std::to_string(stats_.hits), std::to_string(stats_.misses),
         std::to_string(stats_.stored), std::to_string(stats_.rejected),
         std::to_string(stats_.bytes_read),
         std::to_string(stats_.bytes_written)});
    std::fprintf(stderr, "%s\n", msg.c_str());
}

} // namespace analysis
