/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/borrow/place.h
 * @brief EL LUGAR que un prestamo ocupa: una raiz y el camino hasta el.
 *
 * @par Por que existe
 * El comprobador de prestamos llevaba los suyos por NOMBRE de variable, y un
 * nombre no es una region.  De ahi salian los dos fallos opuestos:
 *
 *   - de MAS: `mueve(p.a, p.b)` -- dos campos distintos del mismo struct, que
 *     no se tocan -- se rechazaba, porque los dos nombres eran `p`.  Rechazar
 *     un programa correcto es el lado caro de equivocarse: quien lo sufre no
 *     puede hacer nada, su codigo ya esta bien;
 *   - de MENOS: dos nombres de la MISMA region no chocaban entre si.
 *
 * Un lugar arregla los dos a la vez, y no por acumular casos: es que la
 * pregunta "se pisan estos dos prestamos" es sobre MEMORIA, y un lugar es lo
 * que nombra memoria.
 *
 * @par Que NO es
 * No es una @c AbstractLoc.  Aquella vive sobre el intermedio, con raiz
 * resuelta y rango de bytes; esta se construye sobre el ARBOL, donde lo unico
 * que hay es lo que el programador escribio.  Son la misma idea en dos
 * momentos, y por eso el vocabulario se parece a proposito -- pero mezclarlas
 * seria juzgar el arbol con el criterio del intermedio.
 *
 * @par Un `*p` NO es un agujero: casi siempre se sabe de quien es
 * Es la diferencia con un lenguaje donde un puntero es un entero con suerte.
 * Aqui la procedencia viaja: un `borrow<T>` sabe de que dueno salio -- el
 * comprobador ya la sigue entera con @c root_owner_of, represtamos incluidos --
 * y un `unique<T>` o un `shared<T>` POSEEN lo apuntado.  Asi que quien
 * construye el lugar RESUELVE el `*p` al lugar del dueno en vez de rendirse, y
 * con eso dos nombres de la misma region dejan de ser dos cosas.
 *
 * @par Y lo que queda sin resolver NO es "un puntero opaco"
 * Aqui no se levantan barreras por supuesto desconocimiento.  De un `T*` que
 * llega de fuera se sigue sabiendo mucho: que contrato declara su `extern`, que
 * efectos tiene, que funciones lo tocan y con que direccion.  Lo que falta es
 * UNA cosa muy concreta -- que region nombra -- y falta EN ESTE NIVEL, porque
 * el arbol solo tiene lo que el programador escribio.
 *
 * Por eso el motivo que sale de aqui se llama por lo que le falta y no por lo
 * que no se puede: es un HUECO con destinatario.  Lo cierra quien tiene la
 * pieza -- el resolutor de punteros sobre el intermedio, los efectos
 * declarados de la externa, el contrato del parametro -- y mientras tanto la
 * respuesta es la conservadora, que nunca deja pasar un error.
 *
 * @par El prefijo habla de DERIVACION, no de bytes
 * `p` y `*p` no comparten un solo byte -- uno es la ranura del puntero y el
 * otro lo apuntado -- y aun asi chocan, porque el segundo se DERIVA del
 * primero: prestar lo apuntado y luego mover el puntero rompe el prestamo.
 * Igual con `p` y `p.a`.  Por eso la regla es "uno es prefijo del otro" y no
 * "sus rangos se cortan": lo que se persigue es la cadena de derivacion, que es
 * de lo que hablan las reglas de prestamo.
 */

#ifndef VX_BORROW_PLACE_H
#define VX_BORROW_PLACE_H

#include <cstdint>
#include <string>
#include <vector>

namespace vx {
namespace borrow {

/**
 * @brief Un paso del camino desde la raiz hasta el lugar.
 *
 * Los cuatro son necesarios y ninguno se puede fundir con otro: dos campos
 * distintos SI se separan, dos indices constantes distintos TAMBIEN, y los
 * otros dos no se separan nunca -- pero por motivos distintos, y el motivo es
 * lo que el usuario necesita leer para saber que cambiar.
 */
struct PlaceStep {
    enum class Kind : uint8_t {
        Field,      ///< `.nombre`
        ConstIndex, ///< `[N]` con N sabido al compilar
        /// `[i]` con i de ejecucion.  No separa, y ese es su motivo.
        UnknownIndex,
        /**
         * Lo APUNTADO por el lugar de mas arriba.
         *
         * No es "no se": es un lugar mas, y dos `*p` del mismo `p` son la misma
         * memoria.  Cuando la procedencia del puntero se conoce -- un
         * `borrow<T>`, un `unique<T>`, un `shared<T>` --, quien construye el
         * lugar ni siquiera llega a poner este paso: sustituye por el lugar del
         * dueno, que es lo que hace que dos nombres de una region se junten.
         *
         * Queda puesto cuando la region todavia no se ha resuelto EN ESTE
         * NIVEL, y ahi vale como identidad: `*q` choca consigo mismo y con `q`.
         * Que la region no este resuelta no quiere decir que del puntero no se
         * sepa nada -- su contrato y sus efectos siguen ahi --, solo que esa
         * pieza la pone otro.
         */
        Deref,
    };

    Kind kind = Kind::Field;
    /// Nombre del campo.  Solo con @c Kind::Field.
    std::string field;
    /// El indice.  Solo con @c Kind::ConstIndex.
    int64_t index = 0;

    static PlaceStep of_field(std::string name) {
        PlaceStep s;
        s.kind = Kind::Field;
        s.field = std::move(name);
        return s;
    }
    static PlaceStep of_const_index(int64_t n) {
        PlaceStep s;
        s.kind = Kind::ConstIndex;
        s.index = n;
        return s;
    }
    static PlaceStep of_unknown_index() {
        PlaceStep s;
        s.kind = Kind::UnknownIndex;
        return s;
    }
    static PlaceStep of_deref() {
        PlaceStep s;
        s.kind = Kind::Deref;
        return s;
    }

    bool operator==(const PlaceStep &o) const noexcept {
        if (kind != o.kind) return false;
        if (kind == Kind::Field) return field == o.field;
        if (kind == Kind::ConstIndex) return index == o.index;
        return true; // los dos opacos: iguales COMO PASO, no como memoria
    }
};

/**
 * @brief La memoria que un prestamo ocupa, tal como se escribio.
 *
 * @c root vacia significa que ni siquiera se pudo nombrar la raiz -- una
 * llamada, un temporal --, y entonces no hay lugar que registrar.
 */
struct Place {
    std::string root;
    std::vector<PlaceStep> path;

    bool valid() const noexcept { return !root.empty(); }

    /// @brief Como se escribe para el usuario: `p.a[2]`.
    ///
    /// Va aqui y no en quien informa porque el diagnostico tiene que citar el
    /// lugar EXACTO que estorba, y si cada sitio lo compone a su manera acaban
    /// saliendo dos formas distintas del mismo lugar en el mismo mensaje.
    std::string text() const;
};

/// @brief Por que dos lugares no se pudieron separar.
enum class PlaceUnknown : uint8_t {
    None = 0,     ///< Se decidio: no hay nada que explicar.
    RuntimeIndex, ///< Falta el VALOR del indice, que no es constante aqui.
    /// Falta la REGION que el puntero nombra, y falta en este nivel.  No sale
    /// con un `borrow<T>`, un `unique<T>` ni un `shared<T>` -- esos dicen de
    /// quien es lo apuntado y el lugar se resuelve al dueno --, sino con un
    /// `T*` que llega de fuera o de aritmetica.  La pieza que falta la tiene el
    /// resolutor sobre el intermedio o el contrato de la externa.
    RegionNotResolvedHere,
};

/// @brief Le falta a este lugar la region de algun puntero?
///
/// Lo pregunta quien tenga que saber si la respuesta de @ref places_may_overlap
/// es exacta o conservadora, sin tener que mirarle el camino paso a paso.  Se
/// llama por lo que FALTA y no por lo que el lugar "es": del puntero se sabe su
/// contrato y sus efectos, y lo que no esta puesto todavia es una sola cosa.
bool place_region_unresolved(const Place &p) noexcept;

/**
 * @brief Pueden estos dos lugares tocar algun byte comun?
 *
 * Con los dos lugares RESUELTOS -- ninguno acaba en un deref opaco -- la
 * respuesta es exacta: raices distintas son variables distintas, y con la misma
 * raiz se recorre el camino en paralelo hasta que un paso los separa (dos
 * campos distintos, dos indices constantes distintos).  Si se acaba el camino
 * de uno sin separarlos, ese CONTIENE al otro y por tanto se tocan.
 *
 * @par Y la trampa que hay debajo
 * En cuanto a UNO de los dos le falta la region de su puntero, la raiz deja de
 * decidir: `*q` y `*r` son dos variables distintas y pueden nombrar la misma
 * memoria.  Darlo por disjunto seria un falso NEGATIVO -- dejar pasar un error
 * de verdad --, que es peor que el falso positivo que este fichero viene a
 * quitar.  Asi que ahi no se separa, y sale @c RegionNotResolvedHere.
 *
 * Eso NO es el final de la pregunta, es su reenvio: la region la resuelve el
 * points-to sobre el intermedio, donde @c AbstractLoc lleva raiz y rango, y de
 * una externa la ponen sus efectos declarados.  Aqui se para donde toca y se
 * dice quien sigue.
 *
 * @param a Un lugar.
 * @param b El otro.
 * @param[out] why Por que no se pudo separar, si es que no se pudo.  Puede ser
 *             nulo si a quien pregunta no le hace falta.
 * @return @c true si pueden compartir memoria.
 */
bool places_may_overlap(const Place &a, const Place &b,
                        PlaceUnknown *why = nullptr);

/// @brief Nombran EXACTAMENTE la misma memoria, sin duda ninguna?
///
/// Distinto de @ref places_may_overlap: aquello es un "puede", esto es un "es".
/// Hace falta para contar prestamos compartidos del mismo sitio, donde sumar
/// dos que solo se SOLAPAN daria un recuento que no corresponde a nada.
bool places_same(const Place &a, const Place &b) noexcept;

} // namespace borrow
} // namespace vx

#endif // VX_BORROW_PLACE_H
