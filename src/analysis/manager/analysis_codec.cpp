/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/manager/analysis_codec.cpp
 * @brief Implementacion de @ref analysis/analysis_codec.h.
 */

#include "analysis/manager/analysis_codec.h"

#include "util/fnv.h"       // la mezcla FNV-1a del proyecto, no otra
#include "util/name_pool.h" // punteros estables para los codigos leidos

#include <cstring>

namespace analysis {

namespace {

/**
 * @brief La marca de un analisis, DERIVADA de su nombre.
 *
 * Derivada y no elegida a mano: asi nadie tiene que inventar un numero ni
 * comprobar que no lo use otro.  Dos nombres distintos dan marcas distintas, y
 * eso es lo unico que hace falta -- porque el fallo que importa es leer los
 * bytes de OTRO analisis creyendolos propios, que no da error sino un resultado
 * inventado.
 *
 * Con @c util::fnv_bytes y no con una mezcla escrita aqui: la del proyecto ya
 * existe, y dos formas de mezclar acaban dando dos identidades para lo mismo.
 */
uint32_t magic_of(const char *name) {
    const char *s = (name != nullptr) ? name : "";
    const uint64_t h = util::fnv_bytes(util::kFnvOffset, s, std::strlen(s));
    /* Los 32 de arriba, que es donde la mezcla ha movido mas bits.  La marca no
     * necesita mas: solo tiene que separar nombres, no resistir a nadie. */
    return static_cast<uint32_t>(h >> 32);
}

} // namespace

void write_analysis_header(util::ByteWriter &w, const char *name,
                           uint32_t format) {
    w.u32(magic_of(name));
    w.u32(format);
}

bool read_analysis_header(util::ByteReader &r, const char *name,
                          uint32_t format) {
    if (r.u32() != magic_of(name)) return false;
    return r.u32() == format;
}

uint32_t CodeTable::index_of(const char *code) {
    const std::string s = (code != nullptr) ? std::string(code) : std::string();
    /* Busqueda lineal, y a proposito: un dominio publica una veintena de
     * codigos como mucho, asi que un mapa aqui seria indireccion y una reserva
     * para recorrer veinte cadenas cortas. */
    for (size_t i = 0; i < order_.size(); ++i)
        if (order_[i] == s) return static_cast<uint32_t>(i);
    order_.push_back(s);
    return static_cast<uint32_t>(order_.size() - 1);
}

void CodeTable::write(util::ByteWriter &w) const {
    w.u32(static_cast<uint32_t>(order_.size()));
    for (size_t i = 0; i < order_.size(); ++i)
        w.str(order_[i]);
}

bool CodeTable::read(util::ByteReader &r, std::vector<const char *> &out) {
    const uint32_t n = r.u32();
    /* Una cadena ocupa como minimo su longitud (4 bytes), asi que mas de eso es
     * imposible por muchas que diga el fichero. */
    if (!r.ok() || !fits_in(r, n, 4)) return false;
    out.clear();
    out.reserve(n);
    for (uint32_t i = 0; i < n && r.ok(); ++i) {
        /* Internado: da un puntero estable para toda la vida del proceso, que
         * es lo que el analisis espera de un `const char *` de codigo.  Una vez
         * por cadena DISTINTA, no por entrada: internar toma un cerrojo. */
        out.push_back(util::intern_name(r.str())->c_str());
    }
    return r.ok();
}

} // namespace analysis
