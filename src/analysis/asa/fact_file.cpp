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
constexpr size_t kBytesMinimosHecho = 4 + 4 + 8 + 8 + 4 + 3 * 4 + 4 /* why */ +
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
        const uint32_t i = static_cast<uint32_t>(orden_.size());
        orden_.push_back(k);
        idx_.emplace(k, i);
        return i;
    }
    void escribir(util::ByteWriter &w) const {
        w.u32(static_cast<uint32_t>(orden_.size()));
        for (const std::string &s : orden_)
            w.str(s);
    }
    bool vacia() const { return orden_.empty(); }

  private:
    std::vector<std::string> orden_;
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

uint64_t record_checksum(const uint8_t *d, size_t ini, size_t suma,
                         size_t fin) {
    const uint64_t h = util::fnv_bytes(util::kFnvOffset, d + ini, suma - ini);
    return util::fnv_bytes(h, d + suma + 8, fin - (suma + 8));
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

bool should_store(CacheLevel nivel, const DomainCost &c) {
    switch (nivel) {
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
    constexpr long kUmbralMicros = 1000;
    return !c.recomputable || c.micros >= kUmbralMicros;
}

std::vector<uint8_t> serialize(const FactStore &almacen, uint64_t huella,
                               CacheLevel nivel,
                               const std::vector<DomainCost> &costes,
                               uint64_t compilador) {
    if (nivel == CacheLevel::Off || almacen.size() == 0) return {};

    /* Agrupar por dominio, indexando por el PUNTERO del nombre: dentro de un
     * almacen los hechos de un dominio comparten literal (es como el propio
     * FactStore los indexa), asi que esto evita construir una cadena por hecho.
     * Se conserva el orden de aparicion para que dos volcados del mismo modulo
     * den el mismo fichero y se puedan comparar. */
    std::vector<const char *> dominios;
    std::unordered_map<const char *, std::vector<FactId>> por_dominio;
    std::unordered_map<const char *, bool> admitido;
    std::unordered_map<const char *, uint64_t> huella_de;
    for (FactId id = 0; id < static_cast<FactId>(almacen.size()); ++id) {
        const Fact &f = almacen.at(id);
        const char *const dom = f.what.domain;
        auto ad = admitido.find(dom);
        if (ad == admitido.end()) {
            /* El criterio se resuelve UNA vez por dominio: depende del dominio,
             * y preguntarlo por hecho seria repetir la misma respuesta cientos
             * de miles de veces. */
            DomainCost c;
            c.domain = dom;
            for (const DomainCost &q : costes) {
                if (q.domain != nullptr && dom != nullptr &&
                    std::strcmp(q.domain, dom) == 0) {
                    c = q;
                    break;
                }
            }
            huella_de[dom] = c.fingerprint;
            ad = admitido.emplace(dom, should_store(nivel, c)).first;
        }
        if (!ad->second) continue;
        auto it = por_dominio.find(dom);
        if (it == por_dominio.end()) {
            dominios.push_back(dom);
            it = por_dominio.emplace(dom, std::vector<FactId>{}).first;
        }
        it->second.push_back(id);
    }
    if (dominios.empty()) return {};

    util::ByteWriter w;
    /* Un hecho ocupa del orden de 80 bytes con su tabla de cadenas amortizada;
     * reservar de una evita una veintena de realojos en un modulo grande. */
    w.reserve(almacen.size() * 80 + 64);

    w.u32(kMagic);
    w.u16(kContainerVersion);
    w.u16(0); // reservado: alinea las huellas a 8.
    w.u64(compilador);
    w.u64(huella);
    w.u32(static_cast<uint32_t>(almacen.size())); // dimensiona el remapeo.
    w.u32(static_cast<uint32_t>(dominios.size()));

    struct IndexEntry {
        uint64_t hash = 0;
        uint64_t offset = 0;
    };
    std::vector<IndexEntry> indice;
    indice.reserve(dominios.size());

    for (const char *dom : dominios) {
        const std::vector<FactId> &ids = por_dominio[dom];
        IndexEntry e;
        e.hash = name_hash(dom);
        e.offset = w.size();

        const size_t inicio_registro = w.size();
        w.str(dom == nullptr ? std::string() : std::string(dom));
        w.u16(kFactVersion);
        /* La huella de LO QUE MIRO este dominio, no la del modulo: es lo que
         * permite tirar un registro y conservar los demas. */
        w.u64(huella_de[dom]);
        /* Hueco para la suma de comprobacion del cuerpo, que solo se sabe tras
         * escribirlo.  Va POR REGISTRO y no por fichero para no perder la
         * granularidad: unos bytes estropeados tiran ese dominio, no todo. */
        const size_t pos_suma = w.size();
        w.u64(0);
        w.u32(static_cast<uint32_t>(ids.size()));
        /* La longitud del cuerpo no se sabe hasta escribirlo, y va DELANTE
         * porque es lo que permite saltarse un dominio desconocido.  Se deja el
         * hueco y se rellena al final: armar el cuerpo aparte para medirlo
         * costaria una copia entera de todo el fichero. */
        const size_t pos_longitud = w.size();
        w.u32(0);
        const size_t inicio_cuerpo = w.size();

        /* La tabla de cadenas tampoco se conoce hasta codificar los hechos, asi
         * que va DETRAS y el cuerpo empieza por su desplazamiento.  Misma
         * razon: ni buffers intermedios ni copias. */
        const size_t pos_tabla = w.size();
        w.u32(0);

        StringTable tabla;
        auto cad = [&](const char *s) { return tabla.index_of(s); };
        for (FactId id : ids) {
            const Fact &f = almacen.at(id);
            w.u32(id); // identidad dentro del fichero, para las pruebas.
            w.u32(cad(f.what.code));
            w.i64(f.what.a);
            w.i64(f.what.b);
            w.u32(cad(f.what.detail));
            w.u32(cad(f.scope.isa));
            w.u32(cad(f.scope.os));
            w.u32(cad(f.scope.backend));
            /* En que MOMENTO de la compilacion vale.  Va con el resto del
             * alcance porque es lo mismo que ellos: una condicion bajo la cual
             * el hecho es cierto.  Sin guardarlo, un hecho de antes de
             * optimizar volvia del disco valiendo tambien para despues, que es
             * justo lo que no vale -- y peor: nombra ids que el optimizador ya
             * habia renumerado. */
            w.u32(cad(f.scope.stage));
            /* Por que el alcance esta restringido.  Va con el alcance y no
             * aparte: restringir es afirmar que algo NO vale en otro sitio, y
             * sin el motivo esa afirmacion no se puede comprobar.  Sin este
             * campo, todo hecho sellado volvia del disco sin justificar. */
            w.u32(cad(f.scope.why));
            w.u8(static_cast<uint8_t>(f.about.kind));
            w.u32(cad(f.about.function));
            w.u32(f.about.id);
            w.u8(static_cast<uint8_t>(f.seal.certainty));
            /* Y de que CLASE es lo que no se supo.  Es lo que separa "se miro y
             * no hay nada que decir" de "no dio tiempo" y de "no se miro", que
             * se arreglan de tres formas distintas.  Sin guardarlo, la cache
             * convertia cualquiera de las tres en la ultima. */
            w.u8(static_cast<uint8_t>(f.seal.unknown_reason));
            w.u8(static_cast<uint8_t>(f.seal.origin.source));
            w.u32(cad(f.seal.origin.producer));
            w.u32(cad(f.seal.origin.function));
            w.u32(f.seal.origin.site);
            for (int i = 0; i < Support::kMax; ++i) {
                const char *a = f.seal.support.on[i];
                w.u32(a == nullptr ? kNoString : cad(a));
            }
            w.u32(cad(f.proof.rule));
            w.u32(static_cast<uint32_t>(f.proof.from.size()));
            for (FactId d : f.proof.from)
                w.u32(d);
        }
        w.patch_u32(pos_tabla, static_cast<uint32_t>(w.size() - inicio_cuerpo));
        tabla.escribir(w);
        w.patch_u32(pos_longitud,
                    static_cast<uint32_t>(w.size() - inicio_cuerpo));
        /* La suma cubre el registro ENTERO menos ella misma: si solo cubriera
         * el cuerpo, un byte estropeado en el nombre del dominio atribuiria sus
         * hechos a otro, y uno en la huella los daria por caducados o por
         * vigentes sin motivo.  Esos campos deciden tanto como el contenido. */
        w.patch_u64(pos_suma, record_checksum(w.bytes().data(), inicio_registro,
                                              pos_suma, w.size()));
        indice.push_back(e);
    }

    const uint64_t offset_indice = w.size();
    for (const IndexEntry &e : indice) {
        w.u64(e.hash);
        w.u64(e.offset);
    }
    w.u64(offset_indice);
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

ReadResult read_facts(const uint8_t *datos, size_t n, uint64_t huella,
                      FactStore &destino,
                      const std::vector<DomainCost> &vigentes,
                      uint64_t compilador, const Scope &aqui) {
    ReadResult r;
    if (datos == nullptr || n == 0) {
        r.reason = ReadReason::Empty;
        return r;
    }
    util::ByteReader L(datos, n);
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
    if (L.u64() != compilador) {
        r.reason = ReadReason::OtherCompiler;
        return r;
    }
    /* La huella es lo unico que garantiza que estos hechos hablan de ESTE
     * modulo.  Sin ella, un fichero viejo al lado de un fuente nuevo daria
     * respuestas de otro programa, que es peor que no dar ninguna. */
    if (L.u64() != huella) {
        r.reason = ReadReason::OtherModule;
        return r;
    }
    const uint32_t total_original = L.u32();
    const uint32_t n_registros = L.u32();
    if (!L.ok()) {
        r.reason = ReadReason::Truncated;
        return r;
    }

    /* La COLA se comprueba ANTES de leer nada.  Sin esto, un fichero cortado
     * justo en el limite de un registro se lee entero y parece bueno: los
     * registros que faltan no se distinguen de registros que no existian.  Que
     * el indice cuadre exactamente con lo que dice la cabecera es lo que
     * convierte "he leido algo" en "he leido todo lo que habia". */
    constexpr size_t kBytesCola = kTailBytes;
    constexpr size_t kBytesEntradaIndice =
        8 + 8; // huella del nombre + posicion.
    if (n < kBytesCola) {
        r.reason = ReadReason::Truncated;
        return r;
    }
    util::ByteReader cola(datos, n);
    cola.seek(n - kBytesCola);
    const uint64_t offset_indice = cola.u64();
    const uint64_t suma_global = cola.u64();
    if (cola.u32() != kMagicEnd) {
        r.reason = ReadReason::Truncated;
        return r;
    }
    if (file_checksum(datos, n) != suma_global) {
        r.reason = ReadReason::Corrupt;
        return r;
    }
    if (offset_indice > n - kBytesCola ||
        (n - kBytesCola) - offset_indice !=
            static_cast<uint64_t>(n_registros) * kBytesEntradaIndice) {
        r.reason = ReadReason::Truncated;
        return r;
    }
    const size_t fin_registros = static_cast<size_t>(offset_indice);

    /* Los hechos se arman aparte antes de depositarlos porque sus pruebas
     * apuntan a identificadores del FICHERO, y hasta no saber cuales se han
     * cargado de verdad no se pueden traducir. */
    std::vector<Fact> leidos;
    /* Tabla asociativa y NO un vector dimensionado por @c total_original: ese
     * numero lo dice el fichero, y creerselo es reservar dieciseis gigas si
     * pone cuatro mil millones.  Aqui solo entran identidades que se han leido
     * de verdad, asi que lo que cuesta lo marca el contenido, no un campo. */
    std::unordered_map<uint32_t, FactId> remapeo;
    const FactId base = static_cast<FactId>(destino.size());
    (void)total_original;

    for (uint32_t i = 0; i < n_registros && L.ok(); ++i) {
        const size_t inicio_registro = L.position();
        const std::string nombre = L.str();
        const uint16_t ver_hecho = L.u16();
        const uint64_t huella_dom = L.u64();
        const size_t pos_suma = L.position();
        const uint64_t suma = L.u64();
        const uint32_t n_hechos = L.u32();
        const uint32_t longitud = L.u32();
        if (!L.ok()) break;
        const size_t inicio_cuerpo = L.position();
        const size_t fin_registro = inicio_cuerpo + longitud;
        if (fin_registro > n) {
            L.seek(n + 1); // rompe el lector: el registro se sale del fichero.
            break;
        }

        /* Un dominio cuyo layout no se reconoce SE SALTA.  Para esto lleva la
         * longitud delante: cambiar el contenido de un dominio descarta lo
         * suyo, no el fichero entero, y nadie tiene que subir una version
         * global para añadir un productor. */
        if (ver_hecho != kFactVersion) {
            ++r.skipped;
            L.seek(fin_registro);
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
        if (record_checksum(datos, inicio_registro, pos_suma, fin_registro) !=
            suma) {
            ++r.corrupt;
            L.seek(fin_registro);
            continue;
        }

        bool caduco = false;
        if (huella_dom != 0) {
            for (const DomainCost &v : vigentes) {
                if (v.domain == nullptr || nombre != v.domain) continue;
                caduco = v.fingerprint != 0 && v.fingerprint != huella_dom;
                break;
            }
        }
        if (caduco) {
            ++r.stale;
            L.seek(fin_registro);
            continue;
        }

        const char *dominio = canonicalize(destino, nombre);

        /* Las cadenas van al final del cuerpo, asi que se leen antes de los
         * hechos saltando a ellas y volviendo. */
        const uint32_t off_tabla = L.u32();
        if (!L.ok()) break;
        const size_t pos_hechos = L.position();
        L.seek(inicio_cuerpo + off_tabla);
        const uint32_t n_cadenas = L.u32();
        std::vector<const char *> cadenas;
        /* Reservar por lo que quede, no por lo que diga el fichero: una cadena
         * ocupa como minimo su longitud (4 bytes), asi que mas de eso es
         * imposible y pedirlo solo serviria para agotar la memoria. */
        cadenas.reserve(std::min<size_t>(n_cadenas, L.remaining() / 4));
        for (uint32_t c = 0; c < n_cadenas && L.ok(); ++c)
            cadenas.push_back(canonicalize(destino, L.str()));
        if (!L.ok()) break;
        L.seek(pos_hechos);
        auto cad = [&](uint32_t k) -> const char * {
            return k < cadenas.size() ? cadenas[k] : "";
        };

        /* Mismo criterio: un hecho no baja de @c kBytesMinimosHecho. */
        leidos.reserve(
            leidos.size() +
            std::min<size_t>(n_hechos, L.remaining() / kBytesMinimosHecho));
        for (uint32_t h = 0; h < n_hechos && L.ok(); ++h) {
            Fact f;
            const uint32_t id_original = L.u32();
            f.what.domain = dominio;
            f.what.code = cad(L.u32());
            f.what.a = L.i64();
            f.what.b = L.i64();
            f.what.detail = cad(L.u32());
            f.scope.isa = cad(L.u32());
            f.scope.os = cad(L.u32());
            f.scope.backend = cad(L.u32());
            f.scope.stage = cad(L.u32());
            f.scope.why = cad(L.u32());
            f.about.kind = static_cast<Subject::Kind>(L.u8());
            f.about.function = cad(L.u32());
            f.about.id = L.u32();
            f.seal.certainty = static_cast<Certainty>(L.u8());
            f.seal.unknown_reason = static_cast<UnknownReason>(L.u8());
            f.seal.origin.source = static_cast<Source>(L.u8());
            f.seal.origin.producer = cad(L.u32());
            f.seal.origin.function = cad(L.u32());
            f.seal.origin.site = L.u32();
            for (int k = 0; k < Support::kMax; ++k) {
                const uint32_t idx = L.u32();
                f.seal.support.on[k] = (idx == kNoString) ? nullptr : cad(idx);
            }
            f.proof.rule = cad(L.u32());
            const uint32_t n_apoyos = L.u32();
            if (!L.ok()) break;
            f.proof.from.reserve(std::min<size_t>(n_apoyos, L.remaining() / 4));
            for (uint32_t k = 0; k < n_apoyos && L.ok(); ++k)
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
            if (!aqui.universal() && !f.scope.holds_in(aqui)) {
                ++r.out_of_scope;
                continue;
            }
            remapeo[id_original] = base + static_cast<FactId>(leidos.size());
            leidos.push_back(std::move(f));
        }
        if (!L.ok()) break;
        L.seek(fin_registro);
        ++r.domains;
        /* Y queda dicho que ese dominio YA ESTA en el almacen.
         *
         * Sin esto la cache no ahorraba nada: `producir` no tiene forma de
         * saber que el conocimiento vino de disco, lo volveria a calcular, y
         * ademas el almacen acabaria con los hechos por duplicado.  Leer y
         * producir son dos caminos hacia el mismo sitio, y el almacen tiene que
         * decir lo mismo se haya llegado por uno o por el otro. */
        destino.mark_domain(dominio);
    }

    if (!L.ok()) {
        r.reason = ReadReason::Truncated;
        return r;
    }

    /* Traducir las pruebas.  Un apoyo cuyo hecho no se cargo -- porque su
     * dominio se salto -- se PIERDE y se cuenta: mejor una derivacion mas corta
     * que una que apunte a un hecho que no existe. */
    for (Fact &f : leidos) {
        size_t escribe = 0;
        for (size_t k = 0; k < f.proof.from.size(); ++k) {
            const auto it = remapeo.find(f.proof.from[k]);
            const FactId nuevo = (it == remapeo.end()) ? kNoFact : it->second;
            if (nuevo == kNoFact) {
                ++r.lost_proofs;
                continue;
            }
            f.proof.from[escribe++] = nuevo;
        }
        f.proof.from.resize(escribe);
    }

    destino.reserve(destino.size() + leidos.size());
    for (Fact &f : leidos)
        destino.add(std::move(f));
    r.facts = static_cast<uint32_t>(leidos.size());
    r.ok = true;
    return r;
}

ReadResult read_facts_file(const std::string &ruta, uint64_t huella,
                           FactStore &destino,
                           const std::vector<DomainCost> &vigentes,
                           uint64_t compilador, const Scope &aqui) {
    ReadResult r;
    std::vector<uint8_t> bytes;
    if (!::fs::file_exists(ruta)) {
        r.reason = ReadReason::NoFile;
        return r;
    }
    if (!::fs::read_file_bytes(ruta, bytes)) {
        r.reason = ReadReason::ReadFailed;
        return r;
    }
    if (bytes.empty()) {
        r.reason = ReadReason::Empty;
        return r;
    }
    return read_facts(bytes.data(), bytes.size(), huella, destino, vigentes,
                      compilador, aqui);
}

} // namespace asa
} // namespace analysis
