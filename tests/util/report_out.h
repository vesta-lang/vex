/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/report_out.h
 * @brief Componer un informe en memoria y volcarlo de una vez.
 *
 * Por que existe
 * --------------
 * Los informes de estos tests son miles de lineas, y con `printf` eso es una
 * llamada por linea: formateo, bloqueo del `FILE*` y descarga al terminal cada
 * vez.  En Windows es el caso peor --cada escritura a la consola cruza a la API
 * del sistema-- y se notaba.
 *
 * Aqui se compone todo en un `std::string` y se escribe con UN `fwrite`.
 * Ademas los numeros se formatean a mano en vez de con `snprintf`: son dos
 * enteros y un punto, y evitarlo quita decenas de miles de llamadas de
 * formateo.  Portable: solo `std::string` y `fwrite`.
 *
 * Estaba dentro de `test_coste_opcodes`.  Esta aqui porque lo usa tambien
 * `test_efectos_opcodes`, y dos copias del mismo formateador acaban pintando
 * distinto.
 */

#ifndef VESTA_TESTS_REPORT_OUT_H
#define VESTA_TESTS_REPORT_OUT_H

#include <cstdint>
#include <cstdio>
#include <string>

namespace tests {
struct Salida {
    std::string b;

    Salida() { b.reserve(8u << 20); } // ~8 MB: cabe el informe entero

    Salida &s(const char *t) {
        b += t;
        return *this;
    }
    Salida &s(const std::string &t) {
        b += t;
        return *this;
    }
    Salida &ch(char c) {
        b += c;
        return *this;
    }
    Salida &nl() {
        b += '\n';
        return *this;
    }
    Salida &rep(char c, int n) {
        b.append(static_cast<size_t>(n < 0 ? 0 : n), c);
        return *this;
    }

    /// Texto alineado a la IZQUIERDA en @p ancho.  Se rellena con espacios y
    /// no se trunca por debajo: el color se anade FUERA, porque los codigos
    /// ANSI no ocupan ancho visible y meterlos dentro descuadra la columna.
    Salida &izq(const char *t, int ancho) {
        int n = 0;
        while (t[n]) {
            b += t[n];
            ++n;
        }
        return rep(' ', ancho - n);
    }

    /// Texto alineado a la DERECHA.  Hace falta para los rotulos de las
    /// columnas numericas: si la cabecera se alinea a la izquierda y los datos
    /// a la derecha, los titulos no caen sobre sus numeros -- y un rotulo mas
    /// largo que su campo se come el del vecino.
    Salida &der(const char *t, int ancho) {
        int n = 0;
        while (t[n])
            ++n;
        rep(' ', ancho - n);
        return s(t);
    }

    /// Entero sin signo alineado a la DERECHA.
    Salida &num(uint64_t v, int ancho) {
        char tmp[24];
        int n = 0;
        do {
            tmp[n++] = static_cast<char>('0' + v % 10);
            v /= 10;
        } while (v);
        rep(' ', ancho - n);
        while (n)
            b += tmp[--n];
        return *this;
    }

    /// Numero con UN decimal, alineado a la derecha.  Se redondea a la decima
    /// mas cercana con enteros, sin pasar por la conversion de `printf`.
    ///
    /// OJO: no da siempre lo mismo que `%.1f`.  En los empates exactos esto
    /// redondea hacia arriba y `printf` mira la representacion binaria del
    /// double: `9.95` sale aqui `10.0` y por `printf` `9.9`, porque el `9.95`
    /// que cabe en un double es un pelo menor.  Comprobado sobre once valores;
    /// solo difieren los empates.
    ///
    /// Se deja asi a proposito -- redondear .5 hacia arriba es lo que espera
    /// quien lee -- pero queda dicho para que nadie lo "arregle" al comparar
    /// esta salida con una generada por `printf`, y porque el JSON lleva el
    /// valor con toda su precision: la unica cifra redondeada es la del
    /// terminal.
    Salida &dec1(double v, int ancho) {
        const bool neg = v < 0.0;
        if (neg) v = -v;
        const uint64_t escalado = static_cast<uint64_t>(v * 10.0 + 0.5);
        const uint64_t ent = escalado / 10, frac = escalado % 10;
        char tmp[24];
        int n = 0;
        uint64_t e = ent;
        do {
            tmp[n++] = static_cast<char>('0' + e % 10);
            e /= 10;
        } while (e);
        rep(' ', ancho - n - 2 - (neg ? 1 : 0));
        if (neg) b += '-';
        while (n)
            b += tmp[--n];
        b += '.';
        b += static_cast<char>('0' + frac);
        return *this;
    }

    /// Vuelca y vacia.  Se llama una vez al final, o por tramos si hiciera
    /// falta acotar la memoria.
    void volcar(std::FILE *fp) {
        if (!b.empty()) std::fwrite(b.data(), 1, b.size(), fp);
        b.clear();
    }
};

} // namespace tests

#endif // VESTA_TESTS_REPORT_OUT_H
