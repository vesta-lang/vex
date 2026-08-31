/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/facts/value_range.h
 * @brief Entre que dos numeros esta un valor.  Hecho fundacional, sin dueno.
 *
 * Es la pieza que hace decidible lo que si no habria que callar: una region de
 * tamano SIMBOLICO (`malloc(n)`) no se puede comprobar sin saber cuanto puede
 * valer `n`, y un acceso indexado (`buf[i]`) tampoco sin saber cuanto vale `i`.
 *
 * Reticulo de intervalos con TRES estados, no dos:
 *
 *     TOP      no se nada del valor
 *     [lo,hi]  esta entre esos dos
 *     BOTTOM   este punto del programa NO SE ALCANZA
 *
 * BOTTOM no es "no se": es "aqui no se llega".  Confundirlos hace que una rama
 * imposible -- `x = 20; if (x < 10)` -- se trate como una rama de la que no se
 * sabe nada, y peor: permite declarar inalcanzable un punto vivo, que habilita
 * a cualquier consumidor a concluir lo que quiera sobre codigo que si se
 * ejecuta.
 *
 * TOP y `todo(T)` NO son lo mismo, y la diferencia importa:
 *
 *     TOP        ni siquiera se sabe en que dominio se esta hablando
 *     todo(u8)   se sabe que es un `u8`; el valor, no.  Y eso ya acota: [0,255]
 *
 * CADA INTERVALO CONOCE SU TIPO -- ancho en bits e interpretacion --, y esa es
 * la diferencia entre un prototipo y algo sobre lo que se puede demostrar:
 *
 *   - Un `u64` puede valer mas que el mayor `int64_t`.  Representarlo con
 *     enteros con signo obliga a callarse en la mitad del dominio.
 *   - La aritmetica del IR ENVUELVE al ancho: un `u8` con `250 + 10` vale 4, no
 *     260.  Un dominio que calcula 260 no puede hacer nada con ese numero salvo
 *     tirarlo; uno que sabe el ancho responde 4, que es la verdad.
 *
 * POR ESO TODA LA SEMANTICA VIVE AQUI y no en el motor de flujo: envoltura,
 * comparaciones con y sin signo, extensiones y truncados son propiedades del
 * TIPO, no del recorrido del grafo.  El motor decide QUE se compone; el
 * dominio, COMO.  Un dominio que se prueba solo -- sin construir una funcion IR
 * -- es un dominio del que se puede uno fiar.
 *
 * SEPARADO de "que bits estan a uno" a proposito: aqui se habla del VALOR, no
 * de la representacion fisica.
 *
 * INDEPENDIENTE DE ARQUITECTURA: se razona sobre el IR y los anchos de sus
 * tipos.  Ni registros, ni acarreos, ni convenios de llamada.
 */
#ifndef ANALYSIS_FACTS_VALUE_RANGE_H
#define ANALYSIS_FACTS_VALUE_RANGE_H

#include "analysis/facts/ir_facts.h"

#include <cstddef> // offsetof: las aserciones que fijan el layout de RangeEntry
#include <cstdint>
#include <memory>
#include <vector>

namespace ir {
struct IrFunction;
/// Identificador de bloque: lo necesita @c RangeWalk, que pregunta por uno.
using IrBlockId = uint32_t;
enum class IrType : uint8_t;
} // namespace ir

namespace analysis {

/**
 * @brief Tipo numerico sobre el que se razona: cuantos bits y como se leen.
 *
 * Es el UNICO sitio donde se convierte entre "los bits" y "el numero".  Tenerlo
 * repartido es como acaban los analisis afirmando que un `u64` grande es
 * negativo.
 *
 * Se construye SIEMPRE por las factorias, que validan el ancho.  Un ancho fuera
 * de [1,64] no existe en el IR; si llegara, se ensancha a 64 bits, que es una
 * sobre-aproximacion (se afirma menos), nunca una mentira.
 */
struct RangeType {
    uint8_t bits = 64;
    bool sin_signo = false;

    /// Construccion validada.  Es la unica puerta de entrada.
    static RangeType de(uint8_t bits, bool sin_signo) {
        RangeType t;
        t.bits = (bits >= 1 && bits <= 64) ? bits : 64;
        t.sin_signo = sin_signo;
        return t;
    }
    /// Atajos que se leen como los tipos del lenguaje: `i(32)`, `u(8)`.
    static RangeType i(uint8_t bits) { return de(bits, false); }
    static RangeType u(uint8_t bits) { return de(bits, true); }

    bool valido() const { return bits >= 1 && bits <= 64; }
    bool operator==(const RangeType &o) const {
        return bits == o.bits && sin_signo == o.sin_signo;
    }
    bool operator!=(const RangeType &o) const { return !(*this == o); }

    /// Mascara del ancho: los bits que el tipo realmente tiene.
    uint64_t mascara() const {
        return bits >= 64 ? UINT64_MAX : ((uint64_t(1) << bits) - 1);
    }
    /// Cuantos valores distintos hay.  0 significa "2^64", que no cabe.
    uint64_t cardinal() const { return bits >= 64 ? 0 : (uint64_t(1) << bits); }

    /// Mayor y menor valor representables, EN CRUDO (los bits, no el numero).
    uint64_t max_crudo() const {
        if (bits >= 64)
            return sin_signo ? UINT64_MAX : static_cast<uint64_t>(INT64_MAX);
        const uint64_t m = mascara();
        return sin_signo ? m : (m >> 1);
    }
    uint64_t min_crudo() const {
        if (sin_signo) return 0;
        if (bits >= 64) return static_cast<uint64_t>(INT64_MIN);
        return (uint64_t(1) << (bits - 1)) & mascara();
    }

    /// Deja el valor dentro del ancho (lo que hace el hardware al envolver).
    uint64_t normalizar(uint64_t v) const { return v & mascara(); }

    /// Los bits leidos como NUMERO, segun la interpretacion del tipo.
    int64_t hacia_signo(uint64_t v) const {
        v = normalizar(v);
        if (sin_signo || bits >= 64) return static_cast<int64_t>(v);
        const uint64_t bit = uint64_t(1) << (bits - 1);
        return static_cast<int64_t>((v ^ bit) - bit); // extension de signo
    }
    /// Un numero guardado como bits del tipo (envolviendo si no cabe).
    uint64_t desde_signo(int64_t v) const {
        return normalizar(static_cast<uint64_t>(v));
    }

    /// Orden del tipo: un `u8` compara 200 < 250; un `i8`, -56 < 0.
    bool menor(uint64_t a, uint64_t b) const {
        if (sin_signo) return normalizar(a) < normalizar(b);
        return hacia_signo(a) < hacia_signo(b);
    }
    uint64_t menor_de(uint64_t a, uint64_t b) const {
        return menor(a, b) ? a : b;
    }
    uint64_t mayor_de(uint64_t a, uint64_t b) const {
        return menor(a, b) ? b : a;
    }
};

enum class RangeKind : uint8_t { Bottom, Bounded, Top };

/**
 * @brief Intervalo cerrado dentro de un tipo, o TOP, o BOTTOM.
 *
 * Los extremos se guardan EN CRUDO (los bits) y se leen segun el tipo.  Asi un
 * `u64` por encima del mayor `int64_t` se representa igual de bien que un `i8`
 * negativo, sin que el analisis tenga que rendirse en medio dominio.
 *
 * INVARIANTE (comprobable con @c valida): si esta acotado, el tipo es valido,
 * los dos extremos pertenecen al tipo y `lo <= hi` EN EL ORDEN DEL TIPO.  Las
 * factorias son las que lo garantizan; construir el struct a mano lo rompe.
 *
 * NO REPRESENTA intervalos CIRCULARES.  Cuando el resultado exacto de una
 * operacion da la vuelta al tipo -- `u8 [250,4]` -- no hay intervalo simple que
 * lo diga, y la respuesta es `todo(u8)`: menos preciso, nunca falso.
 */
struct ValueRange {
    RangeKind kind = RangeKind::Top;
    RangeType t{};
    uint64_t lo_c = 0; ///< extremo inferior, en crudo
    uint64_t hi_c = 0; ///< extremo superior, en crudo

    // ----------------------------------------------------------------- crear
    static ValueRange top(RangeType ty = RangeType{}) {
        ValueRange r;
        r.kind = RangeKind::Top;
        r.t = ty;
        return r;
    }
    static ValueRange bottom(RangeType ty = RangeType{}) {
        ValueRange r;
        r.kind = RangeKind::Bottom;
        r.t = ty;
        return r;
    }

    /**
     * @brief Intervalo a partir de VALORES DEL TIPO (se normalizan al ancho).
     *
     * Si tras normalizar el intervalo queda invertido, el conjunto DA LA VUELTA
     * al tipo y no hay intervalo simple que lo represente: se responde
     * `todo(ty)`.  NUNCA BOTTOM -- un conjunto no vacio no puede convertirse en
     * "aqui no se llega" por una limitacion de la representacion.
     */
    static ValueRange crudo(RangeType ty, uint64_t lo, uint64_t hi) {
        lo = ty.normalizar(lo);
        hi = ty.normalizar(hi);
        if (ty.menor(hi, lo)) return todo(ty);
        return armar(ty, lo, hi);
    }

    /**
     * @brief Intervalo procedente de un CORTE: si queda vacio, es BOTTOM.
     *
     * Es la otra mitad de @c crudo, y la distincion es deliberada.  Aqui el
     * intervalo invertido significa "ninguna de las dos afirmaciones puede
     * cumplirse a la vez", que es exactamente inalcanzable.
     */
    static ValueRange corte(RangeType ty, uint64_t lo, uint64_t hi) {
        lo = ty.normalizar(lo);
        hi = ty.normalizar(hi);
        if (ty.menor(hi, lo)) return bottom(ty);
        return armar(ty, lo, hi);
    }

    /// Intervalo desde numeros con signo (el caso comun al escribir codigo).
    static ValueRange de_enteros(RangeType ty, int64_t lo, int64_t hi) {
        return crudo(ty, ty.desde_signo(lo), ty.desde_signo(hi));
    }
    static ValueRange constante(RangeType ty, uint64_t v) {
        return armar(ty, ty.normalizar(v), ty.normalizar(v));
    }
    /// Todo el tipo: se sabe el dominio, no el valor.  Distinto de TOP.
    static ValueRange todo(RangeType ty) {
        return armar(ty, ty.min_crudo(), ty.max_crudo());
    }

    // -------------------------------------------------------------- consultar
    bool es_top() const { return kind == RangeKind::Top; }
    bool es_bottom() const { return kind == RangeKind::Bottom; }
    bool acotada() const { return kind == RangeKind::Bounded; }
    bool es_constante() const { return acotada() && lo_c == hi_c; }
    /// Si cubre el tipo entero: acotado, pero sin informacion util.
    bool es_todo() const {
        return acotada() && lo_c == t.min_crudo() && hi_c == t.max_crudo();
    }

    /// El invariante de la struct.  Se comprueba en las pruebas y en
    /// depuracion.
    bool valida() const {
        if (kind != RangeKind::Bounded) return true;
        return t.valido() && !t.menor(hi_c, lo_c) &&
               t.normalizar(lo_c) == lo_c && t.normalizar(hi_c) == hi_c;
    }

    /// Los extremos leidos como NUMEROS del tipo.  Sin sentido si no acotada.
    int64_t lo() const { return t.hacia_signo(lo_c); }
    int64_t hi() const { return t.hacia_signo(hi_c); }

    /// Cuantos valores contiene (0 = "no cabe en `uint64_t`", solo `u64`
    /// entero).
    uint64_t cardinal() const {
        if (!acotada()) return 0;
        const uint64_t d = t.normalizar(hi_c - lo_c);
        return (d == UINT64_MAX) ? 0 : d + 1;
    }

    /**
     * @brief Los dos extremos leidos como `int64_t`, si ambos caben ahi.
     *
     * Es una consulta de REPRESENTACION, no una conversion semantica: dice si
     * este intervalo puede entregarse a un consumidor que trabaja con enteros
     * con signo de 64 bits (un desplazamiento, un tamano).  Un `u64` por encima
     * del mayor `int64_t` no cabe, y decirlo es mejor que mentir.
     */
    bool vista_con_signo(int64_t &lo_out, int64_t &hi_out) const {
        if (!acotada()) return false;
        if (t.sin_signo &&
            (lo_c > uint64_t(INT64_MAX) || hi_c > uint64_t(INT64_MAX)))
            return false;
        lo_out = lo();
        hi_out = hi();
        return true;
    }

    bool operator==(const ValueRange &o) const {
        if (kind != o.kind || t != o.t) return false;
        return kind != RangeKind::Bounded || (lo_c == o.lo_c && hi_c == o.hi_c);
    }
    bool operator!=(const ValueRange &o) const { return !(*this == o); }

    // ---------------------------------------------------------------- reticulo
    /// UNION: lo que puede valer si viene por cualquiera de dos caminos.
    /// BOTTOM es el neutro (ese camino no aporta valores); TOP absorbe.
    ValueRange unir(const ValueRange &o) const;

    /**
     * @brief CORTE: lo que cumple las dos afirmaciones sobre el MISMO punto.
     *
     * Si no queda nada, el punto no se alcanza -> BOTTOM (no "no se").
     *
     * Con tipos DISTINTOS no se corta: mezclar dominios es un fallo del IR o
     * del llamante, y la respuesta segura es quedarse con lo que ya se sabia.
     * Devolver BOTTOM ahi convertiria un fallo NUESTRO en "este codigo no se
     * ejecuta", que es la peor conclusion posible.  Quien quiera cruzar
     * dominios reinterpreta primero (@c reinterpretar), que si esta definido.
     */
    ValueRange cortar(const ValueRange &o) const;

    /**
     * @brief ENSANCHAMIENTO: el extremo que crece se suelta hasta el del tipo.
     *
     * Es lo que hace que el analisis TERMINE.  Se suelta SOLO el extremo que se
     * movio: soltar el intervalo entero tira tambien lo que no habia cambiado,
     * y en `for (i = 100; i < 200)` lo que no cambia es la cota inferior, que
     * es justo lo que permite demostrar algo.  Ensanchar no es olvidar.
     */
    ValueRange ensanchar(const ValueRange &nuevo) const;

    // -------------------------------------------------- aritmetica del dominio
    //
    //  Todas ENVUELVEN como el IR.  El conjunto exacto se calcula en enteros
    //  sin limite y luego se pliega al tipo: si cabe, el resultado es exacto
    //  (un `u8` con 250+10 responde 4); si al plegarlo da la vuelta al tipo, la
    //  respuesta es `todo(T)`.
    ValueRange sumar(const ValueRange &o) const;
    ValueRange restar(const ValueRange &o) const;
    ValueRange multiplicar(const ValueRange &o) const;
    ValueRange negar() const;
    /**
     * @brief Division entera.
     *
     * Con un divisor que PUEDE valer cero no se afirma nada.  Descartar el cero
     * "porque dividir por cero corta la ejecucion" seria apoyarse en una
     * propiedad del backend -- que la operacion atrape SIEMPRE, en interprete,
     * JIT y nativo --, y el dominio no razona sobre backends.
     */
    ValueRange dividir(const ValueRange &o) const;
    /// Resto: su valor absoluto es menor que el del divisor y su signo lo pone
    /// el dividendo.  Mismo trato del divisor cero que @c dividir.
    ValueRange resto(const ValueRange &o) const;

    // --- bit a bit -----------------------------------------------------------
    /// `x & c` con `c` constante no negativa no pasa de `c`, venga x de donde
    /// venga.  Es lo unico afirmable sin mirar los bits del otro lado.
    ValueRange conjuncion(const ValueRange &o) const;
    /// `x | y` solo ENCIENDE bits: no baja de ninguno de los dos, y no puede
    /// pasar del tope de bits del mayor.  Requiere los dos no negativos.
    ValueRange disyuncion(const ValueRange &o) const;
    /// `x ^ y` puede apagar bits, asi que solo se acota por arriba.
    ValueRange exclusiva(const ValueRange &o) const;
    /// `~x` es una biyeccion que INVIERTE el orden: exacta siempre.
    ValueRange complemento() const;

    // --- desplazamientos -----------------------------------------------------
    /// `x << k` es `x * 2^k` dentro del tipo.  Un `k` fuera de [0, bits) no
    /// tiene significado definido y no se afirma nada.
    ValueRange desplazar_izq(const ValueRange &o) const;
    /// `x >> k` LOGICO: se razona en el dominio sin signo del mismo ancho.
    ValueRange desplazar_der_logico(const ValueRange &o) const;
    /// `x >> k` ARITMETICO: conserva el signo; es division con redondeo hacia
    /// abajo, no hacia cero, y por eso no es lo mismo que `dividir` por 2^k.
    ValueRange desplazar_der_aritmetico(const ValueRange &o) const;

    // ------------------------------------------------- conversiones del IR
    //
    //  CUATRO operaciones distintas, no una: `u8 -> u32`, `i8 -> i32`,
    //  `u32 -> u8` y "los mismos bits, otra lectura" no significan lo mismo.
    /// Extension SIN signo: el origen se lee como natural (un `i8` que vale -1
    /// pasa a valer 255).
    ValueRange extender_sin_signo(RangeType destino) const;
    /// Extension CON signo: el numero no cambia.
    ValueRange extender_con_signo(RangeType destino) const;
    /// Truncado: es MODULAR.  `u16 [250,260]` en `u8` no es `[250,255]`; el
    /// conjunto exacto da la vuelta, asi que lo afirmable es `[0,255]`.
    ValueRange truncar(RangeType destino) const;
    /// Misma representacion, otra lectura.  La correspondencia no es monotona
    /// (`u32 [0x7FFFFFF0,0xFFFFFFFF]` en `i32` se parte en dos), y cuando se
    /// rompe el orden lo afirmable es el tipo entero.
    ValueRange reinterpretar(RangeType destino) const;

    // --------------------------------------------------------- restricciones
    //
    //  Lo que AFIRMA una comparacion sobre este valor.  Viven aqui, y no en el
    //  motor, porque un `<` no significa lo mismo en `i8` que en `u64`, y esa
    //  diferencia es del tipo.  Se apoyan en @c corte: si lo afirmado
    //  contradice lo que ya se sabia, el resultado es BOTTOM -- por ahi no se
    //  pasa.
    ValueRange restringir_menor(const ValueRange &o) const;
    ValueRange restringir_menor_igual(const ValueRange &o) const;
    ValueRange restringir_mayor(const ValueRange &o) const;
    ValueRange restringir_mayor_igual(const ValueRange &o) const;
    ValueRange restringir_igual(const ValueRange &o) const;
    /**
     * @brief El valor NO esta en @p o.  Resta de intervalos.
     *
     * Si @p o se come este intervalo entero, no queda nada: BOTTOM.  Si lo
     * muerde por un extremo, se recorta.  Si lo parte por en medio quedarian
     * dos trozos y eso no se representa, asi que se deja como estaba --
     * correcto, solo menos preciso.
     *
     * Sirve para dos cosas distintas que son la misma: `x != k` y la rama por
     * DEFECTO de un `switch`, que afirma que el selector cae fuera de la tabla.
     */
    ValueRange restringir_fuera(const ValueRange &o) const;
    /// `x != k`.  Solo afirma algo con un @p o de un unico valor: `x != y` con
    /// `y` en un rango no dice nada de `x`.
    ValueRange restringir_distinto(const ValueRange &o) const;

  private:
    /// Constructor interno: los extremos YA cumplen el invariante.
    static ValueRange armar(RangeType ty, uint64_t lo, uint64_t hi) {
        ValueRange r;
        r.kind = RangeKind::Bounded;
        r.t = ty;
        r.lo_c = lo;
        r.hi_c = hi;
        return r;
    }
};

/* PENDIENTE, y dicho aqui para que no se pierda: un rango simple no basta para
 * `base + i*8`.  Hace falta el PASO ademas del intervalo -- `i en [0,63]` paso
 * 8
 * -> `offset en [0,504]` -- para demostrar `offset + sizeof(T) <= tamano` sin
 * conocer `i`, y ademas la CONGRUENCIA (`offset % 8 == 0`) para hablar de
 * alineacion.  Es lo que hara comprobables las vistas dinamicas (`@overlay`),
 * cuya geometria se compone de sumas de cotas.
 *
 * Ese paso NO entra aqui dentro: sale un hecho HERMANO -- congruencias -- y el
 * consumidor pregunta a los dos.  Un rango que ademas conoce el paso, los bits,
 * la region y la alineacion deja de ser un dominio demostrable para convertirse
 * en el saco de todo lo que se sabe de un valor. */

/// Ajustes del analisis.  Los presupuestos son una RED ante un fallo del propio
/// motor, no el mecanismo de terminacion (de eso se encarga el ensanchamiento).
struct RangeOptions {
    /// Vueltas por una arista de retroceso antes de ensanchar.  Con 0 se
    /// ensancha a la primera (termina antes, afirma menos).
    uint32_t retardo_ensanche = 3;
    uint32_t pasos_por_bloque = 64;
    uint32_t pasos_extra = 256;
    /// Vueltas del descenso.  El descenso solo estrecha, asi que pararlo antes
    /// cuesta precision, nunca correccion.
    uint32_t pasos_descenso = 8;
};

/**
 * @brief Que hizo el motor para llegar al resultado.
 *
 * Sirve para depurar el COMPILADOR, no el programa: un caso que no converge o
 * que ensancha mil veces es un fallo del analisis, y sin estas cuentas se
 * confunde con "ese programa es dificil".
 */
struct RangeStats {
    uint32_t pasos = 0;     ///< bloques procesados en total (ascenso+descenso)
    uint32_t cambios = 0;   ///< veces que un IN[B] cambio
    uint32_t ensanches = 0; ///< veces que se aplico ensanchamiento
    uint32_t estrechados = 0; ///< veces que el descenso mejoro un IN[B]
    /// Si el descenso llego hasta el final.  Pararlo a medias NO invalida el
    /// resultado -- toda la cadena descendente sigue conteniendo al punto fijo
    /// real --, solo lo deja menos preciso; por eso se cuenta aparte de
    /// @c RangeFacts::convergio, que si es una condicion de correccion.
    bool descenso_completo = true;

    // ------------------------------------------------- coste de la estructura
    //
    // El estado de un bloque se guarda DISPERSO (solo los valores con rango) y
    // ordenado por identificador.  Esa eleccion tiene dos costes opuestos y hay
    // que poder verlos: meter un valor nuevo desplaza la mitad del vector, pero
    // copiar el estado mueve solo lo que hay.  Cual domina depende de la
    // DENSIDAD -- cuantos de los valores de la funcion llegan a tener rango --,
    // que no se puede suponer: se mide.

    uint32_t valores =
        0; ///< valores SSA de la funcion (tamano si fuese denso).
    uint32_t ref_max = 0;  ///< mayor numero de valores con rango en un estado.
    uint64_t ref_suma = 0; ///< suma de tamanos, para la media.
    uint32_t ref_muestras = 0; ///< estados medidos (denominador de la media).
    uint64_t inserciones =
        0; ///< altas de un valor nuevo (desplazan el vector).
    uint64_t reescrituras =
        0;               ///< cambios de un valor ya presente (no desplazan).
    uint64_t copias = 0; ///< estados copiados enteros.
    uint64_t busquedas =
        0;                ///< consultas al estado (busqueda binaria cada una).
    uint64_t uniones = 0; ///< confluencias: cada una construye un estado NUEVO.
    uint64_t unidos = 0;  ///< elementos anadidos al fusionar (reservas).
};

/**
 * @brief Estado del analisis a la ENTRADA de un bloque.
 *
 * Guarda solo los REFINAMIENTOS sobre el suelo del tipo: lo que un camino sabe
 * de mas son unas pocas variables acotadas por una guarda, asi que una tabla
 * densa por bloque pagaria bloques x valores para repetir lo que ya dice el
 * tipo.  La ausencia de una entrada significa "lo que diga el tipo".
 *
 * Es lo que permite preguntar por un PUNTO y no solo por una definicion.
 */
/**
 * @brief Una entrada del refinamiento: que valor, y que se sabe de el.
 *
 * Los campos del rango van APLANADOS aqui en vez de guardar un `ValueRange`
 * dentro de un `std::pair`.  Motivo, medido: el par ocupa 32 bytes de los
 * cuales OCHO son relleno -- el `u32` del identificador deja cuatro por la
 * alineacion del rango, y el rango deja otros cuatro al final --.  Aplanados
 * caben en 24.
 *
 * Y es la estructura mas movida del compilador: copiar, fusionar y comparar
 * estos vectores eran 3,5 s de 16,6 s.  Un 25% menos de bytes es un 25% menos
 * de memoria pedida y de memoria movida en todo eso.
 *
 * El precio es no poder devolver un `const ValueRange *` al interior, asi que
 * @c range() lo entrega por valor.  Son 24 bytes de POD: sale mucho mas barato
 * que el relleno que se ahorra.
 */
struct RangeEntry {
    ir::IrValueId id = 0;            ///< el valor refinado
    RangeKind kind = RangeKind::Top; ///< los tres campos de ValueRange,
    RangeType t{};                   ///< aplanados para que no haya relleno
    uint8_t _pad = 0;
    uint64_t lo_c = 0;
    uint64_t hi_c = 0;

    /// El rango, reconstruido.  Por valor: aqui no hay ningun `ValueRange`.
    ValueRange range() const {
        ValueRange r;
        r.kind = kind;
        r.t = t;
        r.lo_c = lo_c;
        r.hi_c = hi_c;
        return r;
    }
    /// Guarda @p r en los campos aplanados.
    void set_range(const ValueRange &r) {
        kind = r.kind;
        t = r.t;
        lo_c = r.lo_c;
        hi_c = r.hi_c;
    }
    static RangeEntry make(ir::IrValueId v, const ValueRange &r) {
        RangeEntry e;
        e.id = v;
        e.set_range(r);
        return e;
    }
    /// Compara SOLO el rango (el identificador se compara aparte).
    bool same_range(const RangeEntry &o) const {
        return kind == o.kind && t.bits == o.t.bits &&
               t.sin_signo == o.t.sin_signo && lo_c == o.lo_c && hi_c == o.hi_c;
    }
};
static_assert(sizeof(RangeEntry) == 24,
              "si esto crece, se pierde justo lo que se venia a ganar");
/* Y NO puede haber ni un hueco implicito, porque de eso depende poder comparar
 * dos estados enteros con un solo `memcmp` en vez de campo a campo.  Un hueco
 * llevaria bytes sin inicializar y dos estados iguales podrian salir
 * distintos.  Si alguien reordena o anade un campo, esto rompe la compilacion
 * en vez de romper las comparaciones en silencio. */
static_assert(offsetof(RangeEntry, id) == 0, "layout fijado: ver el memcmp");
static_assert(offsetof(RangeEntry, kind) == 4, "layout fijado: ver el memcmp");
static_assert(offsetof(RangeEntry, t) == 5, "layout fijado: ver el memcmp");
static_assert(offsetof(RangeEntry, _pad) == 7, "layout fijado: ver el memcmp");
static_assert(offsetof(RangeEntry, lo_c) == 8, "layout fijado: ver el memcmp");
static_assert(offsetof(RangeEntry, hi_c) == 16, "layout fijado: ver el memcmp");
static_assert(sizeof(RangeType) == 2, "layout fijado: ver el memcmp");

struct RangeBlockState {
    bool alcanzable = false;
    std::vector<RangeEntry> refinamientos;
};

// Los resumenes se declaran aparte (range_summary.h incluye a este, no al
// reves): aqui basta con nombrarlos.
struct FnRangeSummary;
struct RangeSummaries;

/**
 * @brief Lo que el analisis LEYO ademas de la funcion, y como estaba entonces.
 *
 * Sirve para responder a una sola pregunta: "lo que calcule sigue valiendo?".
 * Y la responde sin volver a calcularlo -- basta releer lo mismo y comparar.
 *
 * La razon de que exista es que la entrada de este analisis NO se deja enumerar
 * desde fuera.  Se intento: al IR de la funcion hubo que sumarle los resumenes
 * que consume, las opciones, el tipo de cada valor y el destino resuelto de las
 * llamadas indirectas, y AUN ASI quedaban casos de "misma entrada, otro
 * resultado".  Cada uno de esos habria sido un resultado viejo servido como
 * bueno.  Enumerar a mano no converge y, peor, no es verificable: no hay forma
 * de saber cuando has terminado.
 *
 * Por eso no se enumera: se APUNTA.  Las lecturas de resumenes pasan todas por
 * @c LectorResumenes, que las registra aqui segun ocurren, asi que una lectura
 * nueva entra en la clave sola -- sin que nadie se acuerde de anadirla.
 */
struct DependenciasRango {
    uint64_t huella_ir = 0; ///< la funcion analizada (forma, tipos, destinos).
    uint64_t huella_opciones =
        0; ///< el presupuesto: con otro puede converger a otra cosa.
    /// Cada resumen CONSULTADO: a quien se pregunto y que contesto entonces.
    /// Se guarda el nombre para poder RELEERLO, no solo comparar un total.
    std::vector<std::pair<std::string, uint64_t>> resumenes;
    /**
     * @brief Si HABIA resumenes cuando se calculo esto.
     *
     * No es lo mismo que la lista de arriba, y confundirlo servia un resultado
     * PEOR que el pedido, en silencio.  El motor solo pregunta por un resumen
     * cuando tiene alguno: sin ellos no consulta NADA, la lista queda vacia, y
     * una lista vacia vale contra cualquier conjunto de resumenes -- asi que un
     * resultado calculado a ciegas se reutilizaba para una peticion que SI
     * traia resumenes, y los parametros seguian valiendo todo su tipo.
     *
     * La asimetria es lo que lo hacia dificil de ver: al reves funciona.  Un
     * calculo CON resumenes si deja lecturas anotadas, y al releerlas sin ellos
     * las huellas cambian y se recalcula.
     *
     * Es la misma regla que rige el resto del analisis, aplicada al GUARDIA y
     * no solo a lo que hay detras: no haber mirado no es haber comprobado.
     */
    bool had_summaries = false;
    /// @c false si no se llego a registrar nada (analisis sin dependencias
    /// conocidas): entonces no se afirma que valga, se recalcula.
    bool registrada = false;
};

/// Huella de la FUNCION: forma, tipos y destinos.  Es la parte de la entrada
/// que si se puede leer entera de un sitio.
uint64_t huella_de_funcion(const ir::IrFunction &fn);

/// Huella de un resumen (nulo incluido: "no habia" es un estado distinto de
/// cualquier resumen, y confundirlos serviria un resultado viejo).
uint64_t huella_de_resumen(const FnRangeSummary *s);

/**
 * @brief Dice si unos hechos calculados antes siguen valiendo AHORA.
 *
 * Relee exactamente lo que se leyo entonces y lo compara.  Coste O(lecturas),
 * que es lo que hace que preguntar salga mas barato que recalcular.
 */
bool dependencias_vigentes(const DependenciasRango &d, const ir::IrFunction &fn,
                           const RangeOptions &op, const RangeSummaries *sum);

/// Rango de cada valor SSA, indexado por value-id.
struct RangeFacts;

/**
 * @brief Los rangos de una funcion SIN copiarlos.
 *
 * Preferir esta forma a @c compute_ranges cuando solo se van a LEER.
 * @c RangeFacts lleva dentro el estado de entrada de cada bloque, asi que
 * devolverlo por valor copia todo eso -- medido, 16 s de una compilacion de 26
 * en el camino que pide los rangos una vez por bloque de asm.
 */
std::shared_ptr<const RangeFacts>
compute_ranges_ptr(const ir::IrFunction &fn, const IrFacts &facts,
                   const RangeOptions &op = RangeOptions{},
                   const RangeSummaries *sum = nullptr);

struct RangeFacts {
    std::vector<ValueRange> r;
    /// Estado a la entrada de cada bloque, para @c RangeWalk.
    std::vector<RangeBlockState> entrada;
    /**
     * @brief Si el calculo llego a PUNTO FIJO o se paro por presupuesto.
     *
     * El tope no significa "analisis terminado": significa "hasta aqui he
     * llegado".  Quien va a DEMOSTRAR algo tiene derecho a distinguir una
     * conclusion de una parada, asi que sin convergencia no se afirma nada.
     */
    bool convergio = true;
    /// Lo que se leyo para llegar hasta aqui.  Es lo que permite reusar estos
    /// hechos sin recalcularlos, y lo que impide reusarlos cuando no valen.
    DependenciasRango deps;
    RangeStats stats;

    const ValueRange &at(ir::IrValueId v) const {
        static const ValueRange kTop = ValueRange::top();
        return v < r.size() ? r[v] : kTop;
    }
};

/**
 * @brief Calcula los rangos de @p fn, con sensibilidad al FLUJO.
 *
 * Contrato del motor -- tres estados, no uno:
 *
 *     IN[B]              = union de OUT_ARISTA[P -> B]
 *     OUT[B]             = transferencia(B, IN[B])
 *     OUT_ARISTA[P -> S] = cortar(OUT[P], lo que afirma la guarda de esa
 * arista)
 *
 * Las PHI se resuelven leyendo el estado DE LA ARISTA por la que llega cada
 * argumento: sin eso, una guarda no puede afectar a la PHI que depende de ella.
 *
 * DOS FASES con papeles distintos, no el mismo bucle con una bandera:
 *
 *     ASCENSO   crece hasta un post-punto-fijo; ensancha en las aristas de
 *               retroceso, que es lo unico que garantiza terminar.
 *     DESCENSO  parte de esa solucion y solo ESTRECHA; recupera lo que el
 *               ensanchamiento solto.  Pararlo antes cuesta precision, nunca
 *               correccion.
 *
 * El resultado por valor es su rango EN SU PUNTO DE DEFINICION -- una
 * proyeccion derivada, no el transporte del analisis.  Vale en cualquier uso
 * porque en SSA la definicion domina a todos ellos, pero NO incorpora los
 * refinamientos posteriores: en `if (i < 10) usar(i)`, la definicion puede
 * decir `[0,1000]` mientras el uso esta en `[0,9]`.  Quien necesite esa
 * precision pregunta por el punto, no por el valor.
 *
 * @param sum Resumenes de frontera del modulo, si se tienen.  Con ellos un
 *            parametro deja de valer lo que su tipo y el resultado de una
 *            llamada deja de ser desconocido.  Sin ellos el analisis sigue
 *            siendo correcto, solo mas ciego en los bordes.
 */
RangeFacts compute_ranges(const ir::IrFunction &fn, const IrFacts &facts,
                          const RangeOptions &op = RangeOptions{},
                          const struct RangeSummaries *sum = nullptr);

/**
 * @brief Recorre un bloque entregando el rango de un valor EN CADA PUNTO.
 *
 * @c RangeFacts responde por la DEFINICION de un valor, que vale en cualquier
 * uso pero se queda corto justo donde mas falta hace:
 *
 *     i32 i = leer();          // aqui i es [INT32_MIN, INT32_MAX]
 *     if (i >= 0 && i < 10)
 *         buf[i] = 0;          // aqui i es [0,9] -- y esto es lo que decide
 *
 * Preguntando por el valor, el acceso indexado se juzga con el rango de la
 * definicion y no se puede demostrar nada.  Preguntando por el PUNTO, se juzga
 * con lo que las guardas ya afirmaron.
 *
 * Se recorre en vez de indexar porque guardar el estado en cada punto costaria
 * instrucciones x valores; reproducir un bloque cuesta lo que el bloque mide, y
 * el consumidor natural (recorrer una funcion comprobando accesos) ya va en ese
 * orden.  La transferencia que se reproduce es LA MISMA que uso el motor: no
 * hay dos semanticas que puedan separarse con el tiempo.
 *
 * El rango que devuelve es el corte del estado del punto con el de la
 * definicion.  Los dos son ciertos ahi -- en SSA la definicion domina a todos
 * sus usos --, y quedarse solo con uno perderia lo que sabe el otro.
 */
class RangeWalk {
  public:
    /// Se coloca al principio de @p b.  @p rf debe venir del mismo @p fn.
    RangeWalk(const ir::IrFunction &fn, const IrFacts &facts,
              const RangeFacts &rf, ir::IrBlockId b);
    RangeWalk(RangeWalk &&) noexcept;
    ~RangeWalk();

    /**
     * @brief Recoloca el recorrido al principio de @p b, en la MISMA funcion.
     *
     * Existe porque el consumidor natural recorre TODOS los bloques de una
     * funcion, y montar un recorrido nuevo por bloque rehacia un trabajo que no
     * depende del bloque: el suelo de cada valor -- lo que impone su tipo, mas
     * lo que fije si es constante -- se deriva de la funcion, y se estaba
     * calculando una vez por bloque.  Eso convierte un coste de "un valor, una
     * vez" en "un valor por cada bloque", que es lo que hacia que comprobar los
     * limites dominara el tiempo de compilar.
     *
     * Lo unico que cambia entre bloques es donde se empieza y con que estado,
     * asi que es lo unico que se rehace.
     */
    void situar(ir::IrBlockId b);

    /// Si se llega a ejecutar el punto en curso.
    bool alcanzable() const;
    /// Rango de @p v JUSTO ANTES de la instruccion en curso.
    ValueRange rango(ir::IrValueId v) const;
    /// Consume la instruccion en curso y pasa a la siguiente.
    void avanzar();

  private:
    struct Impl;
    Impl *impl_; ///< puntero desnudo: el tipo completo vive en el .cpp
};

/**
 * @brief El rango que impone un TIPO del IR, sin mirar el codigo.
 *
 * Es el suelo de cualquier afirmacion sobre un valor de ese tipo, y sale
 * gratis: un `u8` no pasa de 255 en ninguna arquitectura.  Se expone porque hay
 * quien lo necesita sin analizar la funcion -- por ejemplo para saber que vale
 * un parametro del que aun no se sabe quien llama.
 */
ValueRange rango_del_tipo(ir::IrType t);

/// Marcador para el AnalysisManager (cachea por funcion; depende de IRFacts).
struct RangeAnalysis {
    using Result = RangeFacts;
    static char ID;
};

} // namespace analysis

#endif // ANALYSIS_FACTS_VALUE_RANGE_H
