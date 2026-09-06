/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file util/serialize.h
 * @brief Escribir y leer bytes: lo minimo para pasar algo a disco y
 * recuperarlo.
 *
 * Vivia dentro del subsistema de depuracion, que fue quien lo necesito primero.
 * Al hacerle falta tambien al fichero de hechos del ASA habia dos salidas malas
 * -- que el analisis dependiera de la depuracion, o copiar el codigo -- y una
 * buena: subirlo a un sitio comun.  Quien lo usaba antes lo sigue viendo donde
 * estaba (@c vxdbg/serialize.h), con sus primitivos propios encima.
 *
 * **Leer nunca desborda.**  Los bytes pueden venir de un fichero truncado, de
 * un cache de otra version o de un disco con un sector malo, asi que el lector
 * comprueba el limite en CADA lectura y, al primer fallo, se marca como roto y
 * devuelve ceros en vez de seguir leyendo memoria ajena.  Quien lee comprueba
 * @ref ByteReader::ok una vez al final en lugar de en cada campo, que es lo que
 * hace que el codigo de deserializacion se pueda leer de corrido.
 *
 * Todo en little-endian explicito: el mismo cache tiene que servir en maquinas
 * distintas, y depender del orden nativo lo habria atado a la que lo escribio.
 * Por eso mismo NUNCA se escribe una estructura entera de golpe
 * (`raw(&algo, sizeof(algo))`): eso arrastra el relleno que meta el compilador,
 * el orden de bytes de la maquina y el orden de los campos, y basta con
 * recompilar con otras opciones para que el cache deje de leerse.  Campo a
 * campo, siempre.
 */

#ifndef VESTA_UTIL_SERIALIZE_H
#define VESTA_UTIL_SERIALIZE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace util {

/**
 * @brief Acumula bytes.
 */
class ByteWriter {
  public:
    void u8(uint8_t v);
    /// Un entero sin signo, bytes bajos primero, escrito de una vez.
    template <class T> void put_le(T v);
    void u16(uint16_t v);
    void u32(uint32_t v);
    void u64(uint64_t v);
    void i64(int64_t v);
    void f64(double v);
    void boolean(bool v);

    /// Escribe una cadena como longitud + contenido.
    void str(const std::string &s);

    /// Escribe bytes en crudo, sin longitud.
    void raw(const void *data, size_t size);

    /**
     * @brief Reescribe un @c u32 ya escrito en @p pos.
     *
     * Hace falta para los campos que no se conocen hasta despues -- la longitud
     * de un bloque, un desplazamiento a algo que va detras --: se deja un
     * hueco, se escribe el contenido y se vuelve a rellenar.  Es eso o armar el
     * bloque en un buffer aparte y copiarlo entero, que es justo la copia que
     * esto ahorra.
     *
     * @param pos Donde empieza el entero (el que devolvio @ref size antes).
     * @param v   Valor definitivo.
     */
    void patch_u32(size_t pos, uint32_t v);

    /// Igual que @ref patch_u32 para un entero de 64 bits (una suma de
    /// comprobacion, por ejemplo, que solo se sabe tras escribir lo que cubre).
    void patch_u64(size_t pos, uint64_t v);

    /// @return Los bytes acumulados.
    const std::vector<uint8_t> &bytes() const { return buf_; }

    /**
     * @brief Se lleva los bytes y deja el escritor vacio y reutilizable.
     *
     * El vaciado es EXPLICITO: un contenedor del que se han movido los datos
     * queda en un estado valido pero no especificado, asi que dar por hecho que
     * queda vacio es confiar en como esta hecha la biblioteca y no en lo que
     * promete.
     *
     * @return Los bytes acumulados.
     */
    std::vector<uint8_t> take() {
        std::vector<uint8_t> out;
        out.swap(buf_);
        return out;
    }

    /**
     * @brief Reserva sitio de antemano.
     *
     * Quien sepa aproximadamente cuanto ocupa lo que va a escribir se ahorra
     * varias reservas al ir creciendo.  No hace falta llamarlo.
     *
     * @param n Bytes que se esperan.
     */
    void reserve(size_t n) { buf_.reserve(n); }

    /// @return Cuantos bytes lleva.
    size_t size() const { return buf_.size(); }

  protected:
    std::vector<uint8_t> buf_;
};

/**
 * @brief Lee bytes, sin salirse nunca.
 */
class ByteReader {
  public:
    ByteReader(const uint8_t *data, size_t size) : data_(data), size_(size) {}
    explicit ByteReader(const std::vector<uint8_t> &v)
        : data_(v.data()), size_(v.size()) {}

    uint8_t u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    int64_t i64();
    double f64();
    bool boolean();
    std::string str();

    /**
     * @brief Lee bytes en crudo.
     * @param out Destino.
     * @param size Cuantos.
     * @return @c true si habia suficientes.
     */
    bool raw(void *out, size_t size);

    /// @return @c true si no ha habido ninguna lectura fallida.
    bool ok() const { return ok_; }

    /**
     * @brief Mira el siguiente byte sin consumirlo.
     *
     * Util cuando hay que decidir que leer segun lo que venga.
     *
     * @return El byte, o 0 si no queda ninguno (sin marcar el lector roto:
     *         ojear el final no es un fallo de lectura).
     */
    uint8_t peek_u8() const { return (ok_ && pos_ < size_) ? data_[pos_] : 0u; }

    /**
     * @brief Salta a un punto del buffer.
     *
     * Un formato con indice o con bloques de longitud conocida se lee saltando,
     * no leyendolo todo: es lo que permite ignorar lo que no interesa.  Saltar
     * fuera del buffer rompe el lector, igual que leer de mas.
     *
     * @param pos Posicion absoluta.
     */
    void seek(size_t pos);

    /// @return En que byte va la lectura.  Sirve para decir donde fallo.
    size_t position() const { return pos_; }

    /// @return Cuantos bytes quedan por leer.
    size_t remaining() const { return ok_ ? size_ - pos_ : 0; }

    /// @return Los bytes que se estan leyendo (para mirar sin copiar).
    const uint8_t *data() const { return data_; }

  protected:
    /**
     * @brief Comprueba que quedan @p n bytes; si no, marca el lector roto.
     * @param n Bytes que se van a leer.
     * @return @c true si se puede leer.
     */
    bool want(size_t n);

    const uint8_t *data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
    bool ok_ = true;
};

} // namespace util

#endif // VESTA_UTIL_SERIALIZE_H
