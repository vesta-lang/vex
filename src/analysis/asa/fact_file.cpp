/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_file.cpp
 * @brief Implementacion del fichero de hechos (ver @c
 * analysis/asa/fact_file.h).
 */

#include "util/env_flags.h"
#include "analysis/asa/fact_file.h"

#include "util/fnv.h"
#include "util/fs_utils.h"
#include "util/serialize.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <unordered_map>

namespace analysis {
namespace asa {

namespace {

constexpr uint32_t kMagic = 0x46415856u;    ///< 'VXAF' en little-endian.
constexpr uint32_t kMagicEnd = 0x4E494658u; ///< 'XFIN': cierra el fichero.

/**
 * @brief Lo MENOS que puede ocupar un hecho serializado.
 *
 * Sirve para acotar lo que se reserva al leer: el numero de hechos lo dice el
 * fichero, y un fichero roto puede decir cualquier cosa.  Con esto, lo que se
 * pide depende de los bytes que quedan de verdad.
 */
constexpr size_t kMinFactBytes = 4 + 4 + 8 + 8 + 4 + 3 * 4 + 4 /* why */ +
                                      1 + 4 + 4 + 1 + 1 /* unknown_reason */ +
                                      1 + 4 + 4 + 4 + 4 * 4 + 4 + 4;

/// Marca de "esta cadena no esta" en la tabla de un registro.  No es la cadena
/// cero: la cadena vacia es una entrada legitima.
constexpr uint32_t kNoString = 0xFFFFFFFFu;

/// Huella del nombre de un dominio, solo para indexarlo en la cola: la
/// coincidencia se CONFIRMA leyendo el nombre, asi que una colision no engaña.
uint64_t name_hash(const char *s) {
    if (s == nullptr) return util::kFnvOffset;
    return util::fnv_bytes(util::kFnvOffset, s, std::strlen(s));
}

/**
 * @brief Tabla de cadenas de UN registro.
 *
 * Por registro y no global a proposito: un lector que no conoce un dominio lo
 * SALTA entero, y no podria hacerlo si sus cadenas vivieran en una tabla
 * compartida que hay que leer si o si.  Es lo que hace que añadir un productor
 * no invalide las caches escritas antes.
 */
class StringTable {
  public:
    uint32_t index_of(const char *s) {
        const std::string k = (s == nullptr) ? std::string() : std::string(s);
        auto it = idx_.find(k);
        if (it != idx_.end()) return it->second;
        const uint32_t i = static_cast<uint32_t>(order_.size());
        order_.push_back(k);
        idx_.emplace(k, i);
        return i;
    }
    void write_to(util::ByteWriter &w) const {
        w.u32(static_cast<uint32_t>(order_.size()));
        for (const std::string &s : order_)
            w.str(s);
    }
    bool empty() const { return order_.empty(); }

  private:
    std::vector<std::string> order_;
    std::unordered_map<std::string, uint32_t> idx_;
};

/**
 * @brief Devuelve una cadena leida a su literal canonico si lo tiene.
 *
 * Es LO QUE HACE QUE UN HECHO DE DISCO SIGA SIENDO EL MISMO HECHO: ASA compara
 * productores y dominios por direccion, asi que una cadena recien leida no se
 * reconoceria a si misma.  Si nadie dio de alta ese nombre -- un productor que
 * este build no tiene -- se interna: el hecho se conserva y se puede leer, pero
 * nadie de aqui va a preguntar por el con un literal que no existe.
 */
const char *canonicalize(FactStore &store, const std::string &s) {
    if (const char *c = canonical_name(s)) return c;
    return store.intern(s);
}

} // namespace

uint64_t record_checksum(const uint8_t *d, size_t begin, size_t hole,
                         size_t end) {
    const uint64_t h = util::fnv_bytes(util::kFnvOffset, d + begin, hole - begin);
    return util::fnv_bytes(h, d + hole + 8, end - (hole + 8));
}

uint64_t file_checksum(const uint8_t *d, size_t n) {
    /* Todo menos la propia suma y la magia que cierra: lo que va antes de ella.
     */
    return util::fnv_bytes(util::kFnvOffset, d, n - kTailBytes + 8);
}

const char *diag_code(ReadReason m) {
    switch (m) {
    case ReadReason::NoFile: return "VXA036";
    case ReadReason::Empty: return "VXA037";
    case ReadReason::NotAFactFile: return "VXA038";
    case ReadReason::OtherVersion: return "VXA039";
    case ReadReason::OtherModule: return "VXA042";
    case ReadReason::OtherCompiler: return "VXA046";
    case ReadReason::Truncated: return "VXA043";
    case ReadReason::Corrupt: return "VXA045";
    case ReadReason::ReadFailed: return "VXA044";
    default: return "";
    }
}

uint64_t function_name_hash(const std::string &name) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : name) {
        h ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
        h *= 0x100000001b3ULL;
    }
    return h;
}

CacheLevel cache_level() {
    /* Una vez por proceso: es una decision de configuracion, no cambia a mitad
     * de una compilacion, y consultarla es barato solo si no se relee. */
    static const CacheLevel n = [] {
        const std::string &v = util::flag_text(util::FlagId::AsaCache);
        if (v.empty()) return CacheLevel::ByCost;
        switch (v[0]) {
        case '0': return CacheLevel::Off;
        case '1': return CacheLevel::Minimum;
        case '3': return CacheLevel::All;
        default: return CacheLevel::ByCost;
        }
    }();
    return n;
}

const char *level_name(CacheLevel n) {
    switch (n) {
    case CacheLevel::Off: return "nada";
    case CacheLevel::Minimum: return "minimo";
    case CacheLevel::All: return "todo";
    default: return "por-coste";
    }
}

bool should_store(CacheLevel level, const DomainCost &c) {
    switch (level) {
    case CacheLevel::Off: return false;
    /* Lo imprescindible: lo que si no se guarda se perdio.  Los niveles son
     * monotonos, asi que esto entra tambien en los dos de arriba. */
    case CacheLevel::Minimum: return !c.recomputable;
    case CacheLevel::All: return true;
    default: break;
    }
    /* Por coste.  El umbral no es una constante inventada sino la respuesta a
     * "cuesta mas rehacerlo que leerlo": por debajo de un milisegundo,
     * recalcular sale igual de barato que abrir el fichero. */
    constexpr long kMicrosThreshold = 1000;
    return !c.recomputable || c.micros >= kMicrosThreshold;
}

std::vector<uint8_t> serialize(const FactStore &store, uint64_t fingerprint,
                               CacheLevel level,
                               const std::vector<DomainCost> &costs,
                               uint64_t compiler) {
    if (level == CacheLevel::Off || store.size() == 0) return {};

    /* Agrupar por dominio, indexando por el PUNTERO del nombre: dentro de un
     * almacen los hechos de un dominio comparten literal (es como el propio
     * FactStore los indexa), asi que esto evita construir una cadena por hecho.
     * Se conserva el orden de aparicion para que dos volcados del mismo modulo
     * den el mismo fichero y se puedan comparar. */
    std::vector<const char *> domains;
    std::unordered_map<const char *, std::vector<FactId>> facts_of;
    std::unordered_map<const char *, bool> accepted;
    std::unordered_map<const char *, uint64_t> key_of;
    /* Y la misma clave repartida por funcion, que es la que de verdad ahorra.
     * Se copia del coste del dominio -- no se recalcula aqui -- porque quien
     * sabe de que depende cada dominio es el productor, no el serializador. */
    std::unordered_map<const char *, std::vector<std::pair<uint64_t, uint64_t>>>
        keys_by_function;
    for (FactId id = 0; id < static_cast<FactId>(store.size()); ++id) {
        const Fact &f = store.at(id);
        const char *const dom = f.what.domain;
        auto ad = accepted.find(dom);
        if (ad == accepted.end()) {
            /* El criterio se resuelve UNA vez por dominio: depende del dominio,
             * y preguntarlo por hecho seria repetir la misma respuesta cientos
             * de miles de veces. */
            DomainCost c;
            c.domain = dom;
            for (const DomainCost &q : costs) {
                if (q.domain != nullptr && dom != nullptr &&
                    std::strcmp(q.domain, dom) == 0) {
                    c = q;
                    break;
                }
            }
            key_of[dom] = c.fingerprint;
            if (!c.by_function.empty()) keys_by_function[dom] = c.by_function;
            ad = accepted.emplace(dom, should_store(level, c)).first;
        }
        if (!ad->second) continue;
        auto it = facts_of.find(dom);
        if (it == facts_of.end()) {
            domains.push_back(dom);
            it = facts_of.emplace(dom, std::vector<FactId>{}).first;
        }
        it->second.push_back(id);
    }
    if (domains.empty()) return {};

    util::ByteWriter w;
    /* Un hecho ocupa del orden de 80 bytes con su tabla de cadenas amortizada;
     * reservar de una evita una veintena de realojos en un modulo grande. */
    w.reserve(store.size() * 80 + 64);

    w.u32(kMagic);
    w.u16(kContainerVersion);
    w.u16(0); // reservado: alinea las huellas a 8.
    w.u64(compiler);
    w.u64(fingerprint);
    w.u32(static_cast<uint32_t>(store.size())); // dimensiona el remapeo.
    w.u32(static_cast<uint32_t>(domains.size()));

    struct IndexEntry {
        uint64_t hash = 0;
        uint64_t offset = 0;
    };
    std::vector<IndexEntry> index;
    index.reserve(domains.size());

    for (const char *dom : domains) {
        const std::vector<FactId> &ids = facts_of[dom];
        IndexEntry e;
        e.hash = name_hash(dom);
        e.offset = w.size();

        const size_t record_begin = w.size();
        w.str(dom == nullptr ? std::string() : std::string(dom));
        w.u16(kFactVersion);
        /* La huella de LO QUE MIRO este dominio, no la del modulo: es lo que
         * permite tirar un registro y conservar los demas. */
        w.u64(key_of[dom]);
        /* Y la tabla POR FUNCIoN, que baja la granularidad de "el dominio
         * entero" a "los hechos de esta funcion".  Con la huella de dominio a
         * secas, tocar una linea invalidaba el modulo: esa huella se pliega
         * sobre TODAS las funciones, asi que cualquier cambio la mueve.
         *
         * Se referencia por HASH DEL NOMBRE y no por indice: el fichero se lee
         * en otra compilacion, donde el modulo se construyo de nuevo y la
         * posicion de una funcion no tiene por que ser la misma. */
        {
            const auto it_fn = keys_by_function.find(dom);
            const size_t n_fn =
                (it_fn == keys_by_function.end()) ? 0 : it_fn->second.size();
            w.u32(static_cast<uint32_t>(n_fn));
            if (it_fn != keys_by_function.end()) {
                for (const auto &kv : it_fn->second) {
                    w.u64(kv.first);  // hash del nombre de la funcion
                    w.u64(kv.second); // su clave para ESTE dominio
                }
            }
        }
        /* Hueco para la suma de comprobacion del cuerpo, que solo se sabe tras
         * escribirlo.  Va POR REGISTRO y no por fichero para no perder la
         * granularidad: unos bytes estropeados tiran ese dominio, no todo. */
        const size_t checksum_hole = w.size();
        w.u64(0);
        w.u32(static_cast<uint32_t>(ids.size()));
        /* La longitud del cuerpo no se sabe hasta escribirlo, y va DELANTE
         * porque es lo que permite saltarse un dominio desconocido.  Se deja el
         * hueco y se rellena al final: armar el cuerpo aparte para medirlo
         * costaria una copia entera de todo el fichero. */
        const size_t length_hole = w.size();
        w.u32(0);
        const size_t body_begin = w.size();

        /* La tabla de cadenas tampoco se conoce hasta codificar los hechos, asi
         * que va DETRAS y el cuerpo empieza por su desplazamiento.  Misma
         * razon: ni buffers intermedios ni copias. */
        const size_t strings_hole = w.size();
        w.u32(0);

        StringTable strings;
        auto str = [&](const char *s) { return strings.index_of(s); };
        for (FactId id : ids) {
            const Fact &f = store.at(id);
            w.u32(id); // identidad dentro del fichero, para las pruebas.
            w.u32(str(f.what.code));
            w.i64(f.what.a);
            w.i64(f.what.b);
            w.u32(str(f.what.detail));
            w.u32(str(f.scope.isa));
            w.u32(str(f.scope.os));
            w.u32(str(f.scope.backend));
            /* En que MOMENTO de la compilacion vale.  Va con el resto del
             * alcance porque es lo mismo que ellos: una condicion bajo la cual
             * el hecho es cierto.  Sin guardarlo, un hecho de antes de
             * optimizar volvia del disco valiendo tambien para despues, que es
             * justo lo que no vale -- y peor: nombra ids que el optimizador ya
             * habia renumerado. */
            w.u32(str(f.scope.stage));
            /* Por que el alcance esta restringido.  Va con el alcance y no
             * aparte: restringir es afirmar que algo NO vale en otro sitio, y
             * sin el motivo esa afirmacion no se puede comprobar.  Sin este
             * campo, todo hecho sellado volvia del disco sin justificar. */
            w.u32(str(f.scope.why));
            w.u8(static_cast<uint8_t>(f.about.kind));
            w.u32(str(f.about.function));
            w.u32(f.about.id);
            w.u8(static_cast<uint8_t>(f.seal.certainty));
            /* Y de que CLASE es lo que no se supo.  Es lo que separa "se miro y
             * no hay nada que decir" de "no dio tiempo" y de "no se miro", que
             * se arreglan de tres formas distintas.  Sin guardarlo, la cache
             * convertia cualquiera de las tres en la ultima. */
            w.u8(static_cast<uint8_t>(f.seal.unknown_reason));
            w.u8(static_cast<uint8_t>(f.seal.origin.source));
            w.u32(str(f.seal.origin.producer));
            w.u32(str(f.seal.origin.function));
            /* El ancla, con su CLASE delante.  Antes iba un `uint32` a secas
             * cuyo significado dependia del dominio, asi que al volver del
             * disco no habia forma de saber si aquello era una linea, un
             * value-id o un bloque -- y sin saberlo no se puede ni resolver ni
             * refrescar. */
            w.u8(static_cast<uint8_t>(f.seal.origin.site.kind));
            w.u32(f.seal.origin.site.id);
            for (int i = 0; i < Support::kMax; ++i) {
                const char *a = f.seal.support.on[i];
                w.u32(a == nullptr ? kNoString : str(a));
            }
            w.u32(str(f.proof.rule));
            w.u32(static_cast<uint32_t>(f.proof.from.size()));
            for (FactId d : f.proof.from)
                w.u32(d);
        }
        w.patch_u32(strings_hole, static_cast<uint32_t>(w.size() - body_begin));
        strings.write_to(w);
        w.patch_u32(length_hole, static_cast<uint32_t>(w.size() - body_begin));
        /* La suma cubre el registro ENTERO menos ella misma: si solo cubriera
         * el cuerpo, un byte estropeado en el nombre del dominio atribuiria sus
         * hechos a otro, y uno en la huella los daria por caducados o por
         * vigentes sin motivo.  Esos campos deciden tanto como el contenido. */
        w.patch_u64(checksum_hole,
                    record_checksum(w.bytes().data(), record_begin,
                                    checksum_hole, w.size()));
        index.push_back(e);
    }

    const uint64_t index_offset = w.size();
    for (const IndexEntry &e : index) {
        w.u64(e.hash);
        w.u64(e.offset);
    }
    w.u64(index_offset);
    /* Y una suma del FICHERO ENTERO, que cubre lo que las de cada registro no
     * pueden: la cabecera, el indice de la cola y los huecos.  Con las dos, no
     * queda un solo byte que se pueda cambiar sin que se note -- y "casi todos"
     * aqui significa que de vez en cuando el compilador se cree algo falso. */
    w.u64(util::fnv_bytes(util::kFnvOffset, w.bytes().data(), w.size()));
    /* Coincide con @ref file_checksum por construccion: lo que se acaba de
     * escribir es exactamente todo lo anterior a la suma. */
    w.u32(kMagicEnd);
    return w.take();
}

ReadResult read_facts(const uint8_t *data, size_t n, uint64_t fingerprint,
                      FactStore &dest,
                      const std::vector<DomainCost> &current,
                      uint64_t compiler, const Scope &here) {
    ReadResult r;
    if (data == nullptr || n == 0) {
        r.reason = ReadReason::Empty;
        return r;
    }
    util::ByteReader L(data, n);
    if (L.u32() != kMagic) {
        r.reason = ReadReason::NotAFactFile;
        return r;
    }
    const uint16_t ver = L.u16();
    L.u16();
    if (!L.ok()) {
        r.reason = ReadReason::Truncated;
        return r;
    }
    if (ver != kContainerVersion) {
        r.reason = ReadReason::OtherVersion;
        return r;
    }
    /* Quien los produjo, antes que de que hablan: un compilador nuevo puede
     * concluir otra cosa del mismo programa sin que su fuente se haya tocado, y
     * leer las conclusiones del viejo como propias es creerse un analisis que
     * nadie ha hecho. */
    if (L.u64() != compiler) {
        r.reason = ReadReason::OtherCompiler;
        return r;
    }
    /* La huella es lo unico que garantiza que estos hechos hablan de ESTE
     * modulo.  Sin ella, un fichero viejo al lado de un fuente nuevo daria
     * respuestas de otro programa, que es peor que no dar ninguna. */
    if (L.u64() != fingerprint) {
        r.reason = ReadReason::OtherModule;
        return r;
    }
    const uint32_t total_original = L.u32();
    const uint32_t n_records = L.u32();
    if (!L.ok()) {
        r.reason = ReadReason::Truncated;
        return r;
    }

    /* La COLA se comprueba ANTES de leer nada.  Sin esto, un fichero cortado
     * justo en el limite de un registro se lee entero y parece bueno: los
     * registros que faltan no se distinguen de registros que no existian.  Que
     * el indice cuadre exactamente con lo que dice la cabecera es lo que
     * convierte "he leido algo" en "he leido todo lo que habia". */
    constexpr size_t kTailSize = kTailBytes;
    constexpr size_t kIndexEntryBytes = 8 + 8; // huella del nombre + posicion.
    if (n < kTailSize) {
        r.reason = ReadReason::Truncated;
        return r;
    }
    util::ByteReader tail(data, n);
    tail.seek(n - kTailSize);
    const uint64_t index_offset = tail.u64();
    const uint64_t file_sum = tail.u64();
    if (tail.u32() != kMagicEnd) {
        r.reason = ReadReason::Truncated;
        return r;
    }
    if (file_checksum(data, n) != file_sum) {
        r.reason = ReadReason::Corrupt;
        return r;
    }
    if (index_offset > n - kTailSize ||
        (n - kTailSize) - index_offset !=
            static_cast<uint64_t>(n_records) * kIndexEntryBytes) {
        r.reason = ReadReason::Truncated;
        return r;
    }
    const size_t records_end = static_cast<size_t>(index_offset);

    /* Los hechos se arman aparte antes de depositarlos porque sus pruebas
     * apuntan a identificadores del FICHERO, y hasta no saber cuales se han
     * cargado de verdad no se pueden traducir. */
    std::vector<Fact> loaded;
    /* Tabla asociativa y NO un vector dimensionado por @c total_original: ese
     * numero lo dice el fichero, y creerselo es reservar dieciseis gigas si
     * pone cuatro mil millones.  Aqui solo entran identidades que se han leido
     * de verdad, asi que lo que cuesta lo marca el contenido, no un campo. */
    std::unordered_map<uint32_t, FactId> remap;
    const FactId base = static_cast<FactId>(dest.size());
    (void)total_original;

    for (uint32_t i = 0; i < n_records && L.ok(); ++i) {
        const size_t record_begin = L.position();
        const std::string name = L.str();
        const uint16_t fact_version = L.u16();
        const uint64_t domain_key = L.u64();
        /* La tabla POR FUNCIoN va aqui por posicion, asi que se lee siempre --
         * aunque el registro acabe descartandose --: saltarsela dejaria el
         * lector desalineado sobre el resto del registro. */
        std::vector<std::pair<uint64_t, uint64_t>> stored_fn_keys;
        {
            const uint32_t n_fn = L.u32();
            if (L.ok()) {
                /* Por lo que quede y no por lo que diga el fichero: cada
                 * entrada ocupa 16 bytes, asi que mas de eso es imposible y
                 * pedirlo solo serviria para agotar la memoria. */
                stored_fn_keys.reserve(
                    std::min<size_t>(n_fn, L.remaining() / 16));
                for (uint32_t k = 0; k < n_fn && L.ok(); ++k) {
                    const uint64_t name_hash_v = L.u64();
                    const uint64_t key = L.u64();
                    stored_fn_keys.emplace_back(name_hash_v, key);
                }
            }
        }
        const size_t checksum_hole = L.position();
        const uint64_t stored_sum = L.u64();
        const uint32_t n_facts = L.u32();
        const uint32_t body_len = L.u32();
        if (!L.ok()) break;
        const size_t body_begin = L.position();
        const size_t record_end = body_begin + body_len;
        if (record_end > n) {
            L.seek(n + 1); // rompe el lector: el registro se sale del fichero.
            break;
        }

        /* Un dominio cuyo layout no se reconoce SE SALTA.  Para esto lleva la
         * longitud delante: cambiar el contenido de un dominio descarta lo
         * suyo, no el fichero entero, y nadie tiene que subir una version
         * global para añadir un productor. */
        if (fact_version != kFactVersion) {
            ++r.skipped;
            L.seek(record_end);
            continue;
        }

        /* Y aqui la granularidad: si el llamante dice de que dependen HOY los
         * hechos de este dominio y no cuadra, se descarta SOLO este registro.
         * Un dominio del que no dice nada -- o que no supo decir de que
         * dependia -- se acepta: no se puede comprobar, y suponer lo peor
         * tiraria una cache que probablemente vale. */
        /* Y ANTES de creerse una sola cifra del cuerpo, comprobar que es el
         * que se escribio.  Sin esto, un byte estropeado dentro de un numero da
         * otro numero igual de valido: el compilador razonaria sobre hechos
         * falsos y nadie se enteraria.  Un registro que no cuadra se tira solo
         * el, que para eso la suma va por registro. */
        if (record_checksum(data, record_begin, checksum_hole, record_end) !=
            stored_sum) {
            ++r.corrupt;
            L.seek(record_end);
            continue;
        }

        /* Que dice HOY este dominio de que depende.  Sin entrada no hay con que
         * comparar, y entonces se acepta lo guardado: no se puede comprobar, y
         * suponer lo peor tiraria una cache que probablemente vale. */
        const DomainCost *today = nullptr;
        for (const DomainCost &v : current)
            if (v.domain != nullptr && name == v.domain) {
                today = &v;
                break;
            }

        /* Las funciones cuyos hechos ya no describen nada, ORDENADAS: se
         * pregunta una vez por hecho, y con cientos de funciones recorrerlas
         * enteras por cada hecho seria cuadratico. */
        std::vector<uint64_t> stale_fns;
        bool expired = false;
        bool partial = false;
        if (today != nullptr) {
            if (!stored_fn_keys.empty() && !today->by_function.empty()) {
                /* La via GRANULAR, que es la que ahorra: cada funcion se valida
                 * por su cuenta y caduca solo lo suyo.  Con la huella de
                 * dominio a secas -- que se pliega sobre TODAS -- tocar una
                 * linea obligaba a rehacer el modulo entero. */
                std::vector<std::pair<uint64_t, uint64_t>> now =
                    today->by_function;
                std::sort(now.begin(), now.end());
                for (const auto &stored : stored_fn_keys) {
                    const auto it = std::lower_bound(
                        now.begin(), now.end(),
                        std::make_pair(stored.first, uint64_t(0)));
                    /* Desaparecio, o sus entradas cambiaron: en los dos casos
                     * lo que se guardo de ella ya no habla de este programa. */
                    if (it == now.end() || it->first != stored.first ||
                        it->second != stored.second)
                        stale_fns.push_back(stored.first);
                }
                std::sort(stale_fns.begin(), stale_fns.end());
                /* Si cambiaron TODAS no hay nada que rescatar, y ademas parsear
                 * el cuerpo para tirarlo entero seria trabajo por gusto: se
                 * trata como caducado, que es exactamente lo de antes. */
                if (stale_fns.size() >= stored_fn_keys.size()) {
                    expired = true;
                } else if (!stale_fns.empty() ||
                           now.size() != stored_fn_keys.size()) {
                    /* Parcial tambien cuando aparecio una funcion NUEVA: no
                     * esta en el fichero, luego hay que producirla, luego el
                     * dominio no puede darse por completo. */
                    partial = true;
                }
            } else if (domain_key != 0) {
                /* Sin tabla por funcion -- un dominio que trae su propia huella
                 * de modulo, o un fichero de antes -- manda la de dominio.
                 * Correcto, solo mas grueso. */
                expired =
                    today->fingerprint != 0 && today->fingerprint != domain_key;
            }
        }
        if (expired) {
            ++r.stale;
            L.seek(record_end);
            continue;
        }
        if (partial) ++r.partial_domains;

        const char *domain = canonicalize(dest, name);

        /* Las cadenas van al final del cuerpo, asi que se leen antes de los
         * hechos saltando a ellas y volviendo. */
        const uint32_t strings_off = L.u32();
        if (!L.ok()) break;
        const size_t facts_pos = L.position();
        L.seek(body_begin + strings_off);
        const uint32_t n_strings = L.u32();
        std::vector<const char *> strings;
        /* Reservar por lo que quede, no por lo que diga el fichero: una cadena
         * ocupa como minimo su longitud (4 bytes), asi que mas de eso es
         * imposible y pedirlo solo serviria para agotar la memoria. */
        strings.reserve(std::min<size_t>(n_strings, L.remaining() / 4));
        for (uint32_t c = 0; c < n_strings && L.ok(); ++c)
            strings.push_back(canonicalize(dest, L.str()));
        if (!L.ok()) break;
        L.seek(facts_pos);
        auto str = [&](uint32_t k) -> const char * {
            return k < strings.size() ? strings[k] : "";
        };

        /* Los MOMENTOS de los hechos de este dominio, para marcarlo en TODOS.
         *
         * No basta con el del primero: un dominio puede traer del disco lo de
         * antes de optimizar Y lo de despues, y marcar solo uno deja el otro
         * sin marca -- con lo que se vuelve a producir y el almacen acaba con
         * los hechos por DUPLICADO, que es lo que se midio (27 -> 50 rangos en
         * la segunda corrida).  Son dos o tres; un vector plano sobra. */
        std::vector<const char *> domain_stages;

        /* Y en carga parcial, QUE funciones se trajeron, para marcarlas una a
         * una.  Solo se anade cuando cambia respecto a la anterior: los hechos
         * llegan agrupados por funcion, asi que esto queda casi sin repetidos y
         * la limpieza final es barata. */
        std::vector<std::pair<const char *, const char *>> reused_here;
        const char *last_fn_name = nullptr;
        uint64_t last_fn_hash = 0;

        /* Mismo criterio: un hecho no baja de @c kMinFactBytes. */
        loaded.reserve(
            loaded.size() +
            std::min<size_t>(n_facts, L.remaining() / kMinFactBytes));
        for (uint32_t h = 0; h < n_facts && L.ok(); ++h) {
            Fact f;
            const uint32_t id_original = L.u32();
            f.what.domain = domain;
            f.what.code = str(L.u32());
            f.what.a = L.i64();
            f.what.b = L.i64();
            f.what.detail = str(L.u32());
            f.scope.isa = str(L.u32());
            f.scope.os = str(L.u32());
            f.scope.backend = str(L.u32());
            f.scope.stage = str(L.u32());
            f.scope.why = str(L.u32());
            f.about.kind = static_cast<Subject::Kind>(L.u8());
            f.about.function = str(L.u32());
            f.about.id = L.u32();
            f.seal.certainty = static_cast<Certainty>(L.u8());
            f.seal.unknown_reason = static_cast<UnknownReason>(L.u8());
            f.seal.origin.source = static_cast<Source>(L.u8());
            f.seal.origin.producer = str(L.u32());
            f.seal.origin.function = str(L.u32());
            f.seal.origin.site.kind = static_cast<Anchor::Kind>(L.u8());
            f.seal.origin.site.id = L.u32();
            for (int k = 0; k < Support::kMax; ++k) {
                const uint32_t idx = L.u32();
                f.seal.support.on[k] = (idx == kNoString) ? nullptr : str(idx);
            }
            f.proof.rule = str(L.u32());
            const uint32_t n_support = L.u32();
            if (!L.ok()) break;
            f.proof.from.reserve(std::min<size_t>(n_support, L.remaining() / 4));
            for (uint32_t k = 0; k < n_support && L.ok(); ++k)
                f.proof.from.push_back(
                    L.u32()); // aun en identidades del fichero.
            if (!L.ok()) break;
            /* Y aqui el filtro por ambito, que solo actua si QUIEN LEE dijo
             * donde esta.
             *
             * Cargar NO es preguntar, y confundirlo costo un hecho de cada dos.
             * El almacen es un deposito: guarda lo que se sabe de todos los
             * objetivos, y quien filtra es `find`, con el ambito de quien
             * pregunta en la mano.  Un mismo almacen se consulta desde `vm`,
             * desde `jit` y desde `aot` en la misma compilacion, asi que
             * quedarse en la carga solo con lo de UNO haria desaparecer lo de
             * los otros -- y sin decirlo.
             *
             * Con un ambito vacio -- el defecto, "no estoy diciendo donde
             * estoy" -- no se descarta nada.  Es lo contrario de lo que hacia:
             * `vale_en` mira si el ambito del HECHO cabe en el de quien
             * pregunta, asi que un ambito vacio no daba por bueno "todo" sino
             * SOLO lo universal, y todo hecho sellado -- justo el que costo
             * trabajo sellar bien -- se perdia en silencio al volver del disco.
             *
             * Quien si quiera estrechar al leer pasa su ambito y entonces se
             * cuenta lo descartado: no saber por que falta un hecho es lo mismo
             * que no tenerlo. */
            if (!here.universal() && !f.scope.holds_in(here)) {
                ++r.out_of_scope;
                continue;
            }
            /* En que MOMENTO valen los que trae este dominio.  Se necesita
             * abajo para marcarlo: "ya corrio" se pregunta por (dominio,
             * momento), asi que marcar sin el dejaba la marca fuera de
             * alcance y `producir` recalculaba todo lo que acababa de leer --
             * la cache se escribia, se leia, y no ahorraba nada. */
            const char *st = f.scope.stage != nullptr ? f.scope.stage : "";
            /* Y en carga PARCIAL, solo lo de las funciones que siguen valiendo.
             *
             * Lo del modulo -- un hecho sin funcion -- se queda fuera tambien.
             * No es un descuido: el productor va a correr, y no hay forma de
             * decirle que se salte lo que no pertenece a ninguna funcion, asi
             * que quedarselo lo afirmaria dos veces.  Producirlo otra vez es
             * trabajo de mas; tenerlo duplicado seria un almacen que dice lo
             * mismo dos veces, y eso si se nota aguas abajo. */
            if (partial) {
                const char *fname =
                    f.about.function != nullptr ? f.about.function : "";
                if (*fname == '\0') {
                    ++r.stale_facts;
                    continue;
                }
                /* Los hechos de un dominio llegan agrupados por funcion, asi
                 * que recordar el ultimo nombre evita rehashearlo por hecho. */
                if (fname != last_fn_name) {
                    last_fn_name = fname;
                    last_fn_hash = function_name_hash(fname);
                }
                if (std::binary_search(stale_fns.begin(), stale_fns.end(),
                                       last_fn_hash)) {
                    ++r.stale_facts;
                    continue;
                }
                /* Y queda apuntada para marcarla: es lo que hara que el
                 * productor se la salte en vez de repetirla. */
                if (reused_here.empty() || reused_here.back().first != st ||
                    reused_here.back().second != fname)
                    reused_here.emplace_back(st, fname);
            }
            /* Y lo que YA ESTA en el almacen no se vuelve a traer.
             *
             * Una compilacion abre esta puerta una vez POR MOMENTO, y cada
             * apertura leia el fichero ENTERO -- que trae los dos --, asi que
             * la segunda duplicaba lo que la primera acababa de cargar.  Y
             * como despues se vuelve a escribir, el fichero crecia solo en
             * cada compilacion: 102 hechos, 306, 714...  Sin fallar, sin
             * decir nada, y con el almacen afirmando lo mismo tres veces. */
            if (dest.has_domain(domain, st)) {
                ++r.duplicates;
                continue;
            }
            bool seen = false;
            for (const char *q : domain_stages)
                if (q == st || std::strcmp(q, st) == 0) {
                    seen = true;
                    break;
                }
            if (!seen) domain_stages.push_back(st);
            remap[id_original] = base + static_cast<FactId>(loaded.size());
            loaded.push_back(std::move(f));
        }
        if (!L.ok()) break;
        L.seek(record_end);
        ++r.domains;
        /* Y queda dicho que ese dominio YA ESTA en el almacen.
         *
         * Sin esto la cache no ahorraba nada: `producir` no tiene forma de
         * saber que el conocimiento vino de disco, lo volveria a calcular, y
         * ademas el almacen acabaria con los hechos por duplicado.  Leer y
         * producir son dos caminos hacia el mismo sitio, y el almacen tiene que
         * decir lo mismo se haya llegado por uno o por el otro. */
        if (!partial) {
            if (domain_stages.empty())
                dest.mark_domain(domain, "");
            else
                for (const char *st : domain_stages)
                    dest.mark_domain(domain, st);
        } else {
            /* En carga parcial el dominio NO se da por hecho: quedan funciones
             * que cambiaron -- o que son nuevas -- y hay que producirlas.  Lo
             * que se marca es lo que SI vino, funcion a funcion, y de eso vive
             * la granularidad: el productor recorre el modulo como siempre y
             * `is_interesting` le salta lo que ya esta.
             *
             * Marcar el dominio aqui seria el fallo silencioso de siempre: los
             * hechos de las funciones que cambiaron no los produciria nadie y
             * el compilador razonaria con un agujero, sin que nada lo dijera. */
            std::sort(reused_here.begin(), reused_here.end());
            reused_here.erase(
                std::unique(reused_here.begin(), reused_here.end()),
                reused_here.end());
            for (const auto &kv : reused_here)
                dest.mark_function(domain, kv.first, kv.second);
            r.reused_functions += static_cast<uint32_t>(reused_here.size());
        }
    }

    if (!L.ok()) {
        r.reason = ReadReason::Truncated;
        return r;
    }

    /* Traducir las pruebas.  Un apoyo cuyo hecho no se cargo -- porque su
     * dominio se salto -- se PIERDE y se cuenta: mejor una derivacion mas corta
     * que una que apunte a un hecho que no existe. */
    for (Fact &f : loaded) {
        size_t out = 0;
        for (size_t k = 0; k < f.proof.from.size(); ++k) {
            const auto it = remap.find(f.proof.from[k]);
            const FactId mapped = (it == remap.end()) ? kNoFact : it->second;
            if (mapped == kNoFact) {
                ++r.lost_proofs;
                continue;
            }
            f.proof.from[out++] = mapped;
        }
        f.proof.from.resize(out);
    }

    dest.reserve(dest.size() + loaded.size());
    for (Fact &f : loaded)
        dest.add(std::move(f));
    r.facts = static_cast<uint32_t>(loaded.size());
    r.ok = true;
    return r;
}

ReadResult read_facts_file(const std::string &path, uint64_t fingerprint,
                           FactStore &dest,
                           const std::vector<DomainCost> &current,
                           uint64_t compiler, const Scope &here) {
    ReadResult r;
    std::vector<uint8_t> bytes;
    if (!::fs::file_exists(path)) {
        r.reason = ReadReason::NoFile;
        return r;
    }
    if (!::fs::read_file_bytes(path, bytes)) {
        r.reason = ReadReason::ReadFailed;
        return r;
    }
    if (bytes.empty()) {
        r.reason = ReadReason::Empty;
        return r;
    }
    return read_facts(bytes.data(), bytes.size(), fingerprint, dest, current,
                      compiler, here);
}

} // namespace asa
} // namespace analysis
