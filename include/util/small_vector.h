/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file small_vector.h
 * @brief Vector con las primeras N posiciones DENTRO del propio objeto.
 *
 * Para lo que casi siempre es diminuto pero a veces no.  Un `std::vector` pide
 * memoria la primera vez que se le mete algo, y cuando la vida media del
 * contenedor son cuatro elementos esa reserva cuesta mas que todo lo que se
 * hace con ellos.
 *
 * Medido con VTune sobre una compilacion en frio de 15.000 lineas: el estado
 * del analisis de rangos -- un `std::vector` por bloque y por vuelta -- se
 * llevaba el 3,6 % de las instrucciones retiradas SOLO en crecer y copiar, con
 * `util::host_alloc` al lado en el 3,5 %.  Y el tamano medio de esos estados
 * era de 0,7 entradas, con 25 como maximo visto.
 *
 * No pretende ser un `std::vector` completo: tiene lo que usan sus
 * consumidores.  Anadir una operacion es trivial; tener una que nadie usa es
 * codigo que hay que mantener sin que nadie lo pruebe.
 *
 * @tparam T Tipo de elemento.  Se asume trivialmente copiable: los
 *           consumidores de aqui lo son, y suponerlo permite mover con
 *           @c memcpy en vez de elemento a elemento.
 * @tparam N Cuantos caben sin pedir memoria.
 */
#ifndef UTIL_SMALL_VECTOR_H
#define UTIL_SMALL_VECTOR_H

#include "util/host_allocator.h"

#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <type_traits>
#include <utility>
#include <vector> // para volcar un `std::vector` aqui donde ya se construia uno

namespace util {

template <typename T, size_t N> class SmallVector {
    static_assert(std::is_trivially_copyable<T>::value,
                  "SmallVector mueve con memcpy: el tipo debe ser trivialmente "
                  "copiable");

  public:
    /* Constructor ESCRITO, no `= default`.  El hueco de dentro no se
     * inicializa a proposito (ver abajo), y con un constructor implicito eso
     * convierte al tipo en no-inicializable como `const` sin inicializador --
     * que es justo como se declara un centinela vacio compartido. */
    SmallVector() noexcept {}
    SmallVector(std::initializer_list<T> il) { assign(il.begin(), il.end()); }
    ~SmallVector() { release(); }

    SmallVector(const SmallVector &o) { copy_from(o); }
    SmallVector &operator=(const SmallVector &o) {
        if (this != &o) {
            /* Se conserva el bufer si ya cabe.  Es la razon de ser de esto: el
             * consumidor asigna un estado sobre otro miles de veces, y soltar
             * y volver a pedir en cada una es justo el coste que se venia a
             * quitar. */
            if (o.size_ > cap_) {
                release();
                copy_from(o);
            } else {
                std::memcpy(data(), o.data(), o.size_ * sizeof(T));
                size_ = o.size_;
            }
        }
        return *this;
    }
    SmallVector(SmallVector &&o) noexcept { move_from(o); }
    SmallVector &operator=(SmallVector &&o) noexcept {
        if (this != &o) {
            release();
            move_from(o);
        }
        return *this;
    }

    // ------------------------------------------------------------- consulta
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    T *data() noexcept { return heap_ ? heap_ : reinterpret_cast<T *>(inline_); }
    const T *data() const noexcept {
        return heap_ ? heap_ : reinterpret_cast<const T *>(inline_);
    }
    T &operator[](size_t i) noexcept { return data()[i]; }
    const T &operator[](size_t i) const noexcept { return data()[i]; }
    T *begin() noexcept { return data(); }
    T *end() noexcept { return data() + size_; }
    const T *begin() const noexcept { return data(); }
    const T *end() const noexcept { return data() + size_; }

    // ---------------------------------------------------------- modificacion
    void clear() noexcept { size_ = 0; } // conserva el bufer a proposito
    void push_back(const T &v) {
        if (size_ == cap_) grow(size_ + 1);
        data()[size_++] = v;
    }
    void reserve(size_t n) {
        if (n > cap_) grow(n);
    }
    /// Solo CRECE con relleno o encoge; no destruye nada (T es trivial).
    void resize(size_t n, const T &fill = T{}) {
        if (n > cap_) grow(n);
        for (size_t i = size_; i < n; ++i) data()[i] = fill;
        size_ = n;
    }

    /// Asignacion desde lista, que es como se escriben los operandos de una
    /// instruccion (`operands = {a, b}`) en cientos de sitios.
    SmallVector &operator=(std::initializer_list<T> il) {
        assign(il.begin(), il.end());
        return *this;
    }

    /// Asignacion desde cualquier cosa que se pueda recorrer (una vista, otro
    /// contenedor).  Excluye a `SmallVector` para no pisar la copia de arriba.
    template <typename C,
              typename = typename std::enable_if<
                  !std::is_same<typename std::decay<C>::type,
                                SmallVector>::value>::type,
              typename = decltype(std::declval<const C &>().begin())>
    SmallVector &operator=(const C &c) {
        assign(c.begin(), c.end());
        return *this;
    }

    /// Sustituye el contenido por [@p first, @p last).
    template <typename It> void assign(It first, It last) {
        clear();
        for (It it = first; it != last; ++it) push_back(*it);
    }

    /// Quita el elemento en @p pos (indice).  Desplaza lo que haya detras.
    void erase_at(size_t pos) {
        if (pos >= size_) return;
        T *p = data();
        if (pos + 1 < size_)
            std::memmove(p + pos, p + pos + 1, (size_ - pos - 1) * sizeof(T));
        --size_;
    }

    /// Inserta en @p pos (indice, no iterador: aqui los punteros se
    /// invalidan al crecer y un indice sobrevive).  Desplaza lo que haya
    /// detras, que con estos tamanos es un @c memmove de nada.
    void insert_at(size_t pos, const T &v) {
        if (size_ == cap_) grow(size_ + 1);
        T *p = data();
        if (pos < size_)
            std::memmove(p + pos + 1, p + pos, (size_ - pos) * sizeof(T));
        p[pos] = v;
        ++size_;
    }

    /**
     * @brief Intercambia contenidos.
     *
     * Con almacenamiento en linea NO puede ser un intercambio de punteros: lo
     * que vive dentro del objeto no se puede robar.  Cuando los dos estan
     * fuera si se cambian los punteros, que es el caso que importa (los
     * grandes); si no, se copia, y son como mucho N elementos.
     */
    void swap(SmallVector &o) noexcept {
        if (heap_ != nullptr && o.heap_ != nullptr) {
            T *h = heap_;
            heap_ = o.heap_;
            o.heap_ = h;
            size_t c = cap_;
            cap_ = o.cap_;
            o.cap_ = c;
            size_t s = size_;
            size_ = o.size_;
            o.size_ = s;
            return;
        }
        SmallVector tmp(std::move(*this));
        *this = std::move(o);
        o = std::move(tmp);
    }

    bool operator==(const SmallVector &o) const noexcept {
        if (size_ != o.size_) return false;
        return size_ == 0 ||
               std::memcmp(data(), o.data(), size_ * sizeof(T)) == 0;
    }
    bool operator!=(const SmallVector &o) const noexcept {
        return !(*this == o);
    }

  private:
    void release() noexcept {
        if (heap_ != nullptr) {
            util::host_free(heap_);
            heap_ = nullptr;
        }
        cap_ = N;
        size_ = 0;
    }

    void copy_from(const SmallVector &o) {
        if (o.size_ > N) {
            heap_ = static_cast<T *>(util::host_alloc(o.size_ * sizeof(T)));
            cap_ = o.size_;
        }
        std::memcpy(data(), o.data(), o.size_ * sizeof(T));
        size_ = o.size_;
    }

    void move_from(SmallVector &o) noexcept {
        if (o.heap_ != nullptr) {
            /* El bufer de fuera SE ROBA; el de dentro no se puede robar --
             * vive en el otro objeto -- y hay que copiarlo. */
            heap_ = o.heap_;
            cap_ = o.cap_;
            o.heap_ = nullptr;
            o.cap_ = N;
        } else {
            std::memcpy(inline_, o.inline_, o.size_ * sizeof(T));
        }
        size_ = o.size_;
        o.size_ = 0;
    }

    void grow(size_t least) {
        size_t next = cap_ * 2;
        if (next < least) next = least;
        T *fresh = static_cast<T *>(util::host_alloc(next * sizeof(T)));
        std::memcpy(fresh, data(), size_ * sizeof(T));
        if (heap_ != nullptr) util::host_free(heap_);
        heap_ = fresh;
        cap_ = next;
    }

    /* Sin inicializar: `T` es trivial y solo se leen las `size_` primeras.
     * Ponerlas a cero costaria N escrituras por cada estado que se crea, que
     * es precisamente lo que se venia a evitar. */
    alignas(T) unsigned char inline_[N * sizeof(T)];
    T *heap_ = nullptr; ///< nullptr = se esta usando el de dentro.
    size_t size_ = 0;
    size_t cap_ = N;
};

} // namespace util

#endif // UTIL_SMALL_VECTOR_H
