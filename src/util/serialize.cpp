/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/serialize.cpp
 * @brief Implementacion de la escritura y lectura de bytes.
 */

#include "util/serialize.h"

#include <cstring>

namespace util {

// ---------------------------------------------------------------------------
//  Escritura
// ---------------------------------------------------------------------------

void ByteWriter::u8(uint8_t v) {
    buf_.push_back(v);
}

/* Los enteros se escriben de UNA vez, no byte a byte.
 *
 * Con `push_back` en bucle, cada byte pasa por su comprobacion de capacidad --
 * ocho por cada `u64` --, y eso es exactamente lo que la guia del proyecto
 * dice que no se haga al escribir muchos bytes seguidos.  Medido con VTune
 * sobre 144k lineas: `std::vector<uint8_t>::emplace_back` retiraba 1.155
 * millones de instrucciones.
 *
 * Se sigue escribiendo byte a byte EN EL VALOR -- desplazando -- y no con un
 * `memcpy` del entero: el formato es de bytes bajos primero, y copiarlo en
 * crudo lo ataria al orden del anfitrion.  Al ser posiciones consecutivas y ya
 * reservadas, el compilador junta las escrituras. */
template <class T> void ByteWriter::put_le(T v) {
    /* Se arma aparte y se copia, en vez de agrandar el buffer y escribir
     * dentro: `resize` PONE A CERO lo que anade, y aqui se sobrescribe entero
     * acto seguido.  `insert` desde un puntero copia y ya. */
    uint8_t tmp[sizeof(T)];
    for (size_t i = 0; i < sizeof(T); ++i)
        tmp[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    buf_.insert(buf_.end(), tmp, tmp + sizeof(T));
}

void ByteWriter::u16(uint16_t v) { put_le(v); }

void ByteWriter::u32(uint32_t v) { put_le(v); }

void ByteWriter::u64(uint64_t v) { put_le(v); }

void ByteWriter::i64(int64_t v) {
    u64(static_cast<uint64_t>(v));
}

void ByteWriter::f64(double v) {
    // Por los bits, no por su forma decimal: un texto perderia precision y
    // haria que dos valores identicos dieran huellas distintas.
    uint64_t bits = 0;
    std::memcpy(&bits, &v, sizeof(bits));
    u64(bits);
}

void ByteWriter::boolean(bool v) {
    u8(v ? 1u : 0u);
}

void ByteWriter::str(const std::string &s) {
    u32(static_cast<uint32_t>(s.size()));
    raw(s.data(), s.size());
}

void ByteWriter::raw(const void *data, size_t size) {
    if (size == 0) return;
    const auto *p = static_cast<const uint8_t *>(data);
    buf_.insert(buf_.end(), p, p + size);
}

void ByteWriter::patch_u32(size_t pos, uint32_t v) {
    if (pos + 4 > buf_.size()) return;
    for (int i = 0; i < 4; ++i)
        buf_[pos + static_cast<size_t>(i)] =
            static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

void ByteWriter::patch_u64(size_t pos, uint64_t v) {
    if (pos + 8 > buf_.size()) return;
    for (int i = 0; i < 8; ++i)
        buf_[pos + static_cast<size_t>(i)] =
            static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

// ---------------------------------------------------------------------------
//  Lectura
// ---------------------------------------------------------------------------

bool ByteReader::want(size_t n) {
    if (!ok_) return false;
    if (pos_ + n > size_) {
        // Una vez roto, se queda roto: seguir leyendo tras un fallo daria
        // valores que parecen buenos y no lo son.
        ok_ = false;
        return false;
    }
    return true;
}

uint8_t ByteReader::u8() {
    if (!want(1)) return 0;
    return data_[pos_++];
}

uint16_t ByteReader::u16() {
    if (!want(2)) return 0;
    const uint16_t v = static_cast<uint16_t>(data_[pos_]) |
                       (static_cast<uint16_t>(data_[pos_ + 1]) << 8);
    pos_ += 2;
    return v;
}

uint32_t ByteReader::u32() {
    if (!want(4)) return 0;
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i)
        v |= static_cast<uint32_t>(data_[pos_ + i]) << (8 * i);
    pos_ += 4;
    return v;
}

uint64_t ByteReader::u64() {
    if (!want(8)) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(data_[pos_ + i]) << (8 * i);
    pos_ += 8;
    return v;
}

int64_t ByteReader::i64() {
    return static_cast<int64_t>(u64());
}

double ByteReader::f64() {
    const uint64_t bits = u64();
    double v = 0.0;
    std::memcpy(&v, &bits, sizeof(v));
    return v;
}

bool ByteReader::boolean() {
    return u8() != 0;
}

std::string ByteReader::str() {
    const uint32_t n = u32();
    if (!ok_) return std::string();
    // Una longitud disparatada delata bytes corruptos: sin comprobarlo, aqui se
    // intentaria reservar lo que dijera un fichero roto.
    if (!want(n)) return std::string();
    std::string s(reinterpret_cast<const char *>(data_ + pos_), n);
    pos_ += n;
    return s;
}

bool ByteReader::raw(void *out, size_t size) {
    if (size == 0) return true;
    if (!want(size)) return false;
    std::memcpy(out, data_ + pos_, size);
    pos_ += size;
    return true;
}

void ByteReader::seek(size_t pos) {
    if (!ok_) return;
    if (pos > size_) {
        ok_ = false;
        return;
    }
    pos_ = pos;
}

} // namespace util
