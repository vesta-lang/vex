/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_store.h
 * @brief Donde viven los hechos: se depositan y se consultan.  UNA
 * representacion para todo el conocimiento del programa.
 *
 * Es la frontera del dibujo:
 *
 *      estatico        observacion en ejecucion        perfil
 *          \                    |                       /
 *           +--------- producen hechos ----------------+
 *                              |
 *                        [ FactStore ]
 *                              |
 *           +------------------+------------------+
 *           |                  |                  |
 *        volcado           optimizador          codegen
 *
 * Lo que hace que esto NO sea otro sistema de conocimiento paralelo es que el
 * consumidor no sabe -- ni le importa -- de que rama viene un hecho: lee el
 * @c Claim y la @c Certainty, que viajan dentro.  Un hecho observado nace
 * @c Inferred, y de ahi sale la guarda; uno demostrado deja quitar la
 * comprobacion.  Ninguna de esas dos decisiones se toma consultando el origen.
 *
 * QUE NO ES: no es una cache de analisis.  Los resultados crudos de cada
 * dominio (rangos, points-to, ...) se cachean en @c FactBase; aqui vive el
 * CONOCIMIENTO ya afirmado, con su certeza y su prueba.  Son dos capas y hacen
 * falta las dos: una evita recomputar, la otra permite razonar y explicar.
 */
#ifndef ANALYSIS_ASA_FACT_STORE_H
#define ANALYSIS_ASA_FACT_STORE_H

#include "analysis/asa/fact.h"

#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace analysis {
namespace asa {

/**
 * @brief Da de alta un nombre CANONICO (un literal estable y unico).
 *
 * ASA identifica al productor por la DIRECCION del literal
 * (@c Support::depends_on compara punteros), y eso funciona mientras los hechos
 * nacen en memoria.  En cuanto uno vuelve de disco su nombre es una cadena
 * recien leida: apuntaria a otro sitio y el mismo productor dejaria de
 * reconocerse a si mismo.  Por eso al leer se devuelven los nombres conocidos a
 * su literal, y quien tenga uno lo da de alta aqui.
 *
 * @param name Literal estable (vive lo que el programa).
 */
void register_canonical_name(const char *name);

/// El literal canonico de @p s, o @c nullptr si nadie lo ha dado de alta.
const char *canonical_name(const std::string &s);

/**
 * @brief Almacen de hechos: se anaden y se consultan.
 *
 * Solo CRECE mientras se produce.  Un hecho no se corrige: si algo cambia, se
 * afirma otro con su procedencia y su certeza, y quien consulte vera los dos --
 * que es justo lo que hace falta cuando el analisis estatico dice una cosa y la
 * ejecucion otra.
 */
class FactStore {
  public:
    /// Deposita @p f y devuelve su identidad.
    FactId add(Fact f);

    const Fact &at(FactId id) const { return facts_[id]; }
    size_t size() const { return facts_.size(); }
    const std::vector<Fact> &all() const { return facts_; }

    /**
     * @brief Guarda una cadena y devuelve un puntero ESTABLE a ella.
     *
     * Los sujetos apuntan a nombres; si cada productor guardara los suyos, el
     * almacen quedaria lleno de punteros a memoria ajena que puede morir antes.
     * Aqui se internan una vez y viven lo que el almacen.
     */
    const char *intern(const std::string &s);

    /**
     * @brief Avisa de cuantos hechos se esperan.
     *
     * Un programa grande produce cientos de miles, y hacerlos crecer de uno en
     * uno significa copiar el vector entero unas veinte veces.  El llamante lo
     * sabe estimar (valores del modulo x dominios) y decirlo sale gratis.
     *
     * @param n Hechos previstos.
     */
    void reserve(size_t n) { facts_.reserve(n); }

    // -----------------------------------------------------------------
    // Que dominios se han producido YA en este almacen.
    // -----------------------------------------------------------------
    // Sin esto, cada consumidor que pide lo suyo vuelve a correr el productor,
    // y dos consumidores del mismo dominio pagan el calculo dos veces.  Es la
    // tercera pata del ASA -- reutilizar el conocimiento, centralizarlo y NO
    // REPETIR TRABAJO --, y la que se pierde si producir no es idempotente.
    //
    // Se guarda el dominio y no un contador de hechos porque un dominio puede
    // haber corrido y no afirmar nada: "ya se miro" y "no dio nada" son cosas
    // distintas, y confundirlas haria correrlo una y otra vez.

    /// Ya corrio @p domain sobre este almacen?
    bool has_domain(const char *domain) const;
    /// Deja constancia de que corrio.  Lo llama @ref produce; un productor
    /// suelto no tiene por que saber de esto.
    void mark_domain(const char *domain);

    /// Hechos que hablan de @p function (cualquier clase de sujeto dentro).
    const std::vector<FactId> &of_function(const std::string &function) const;
    /// Hechos que produjo @p domain.
    const std::vector<FactId> &of_domain(const char *domain) const;

    /**
     * @brief La derivacion de @p id: el hecho y, detras, aquellos de los que se
     *        dedujo, en anchura y sin repetir.
     *
     * Es "todo veredicto lleva su prueba" hecho consulta: con esto un
     * diagnostico, una herramienta o una persona pueden preguntar POR QUE.
     *
     * @param id Hecho a explicar.
     * @return Los identificadores, empezando por @p id.
     */
    std::vector<FactId> explain(FactId id) const;

    // -----------------------------------------------------------------
    // Consultar POR AMBITO: la unica puerta que sabe decir que descarto.
    // -----------------------------------------------------------------
    /**
     * @brief Lo que devuelve una consulta: el hecho, o por que no lo hay.
     *
     * `nullptr` a secas no vale.  "No existe ese hecho" y "existe pero no vale
     * aqui" se arreglan de formas OPUESTAS -- una produciendolo, la otra
     * corrigiendo su alcance --, y devolviendo solo un puntero las dos se leen
     * igual.  Asi fue como un hecho cierto estuvo meses mudo: sellado para el
     * interprete, invisible desde el JIT, y quien preguntaba no podia notar la
     * diferencia entre eso y que nadie lo hubiera producido.
     */
    struct Query {
        const Fact *fact = nullptr; ///< el que vale aqui, o nullptr.
        /// Cuantos habia con ese codigo que NO valian en el ambito pedido.
        /// Mayor que cero con @c fact nulo = el conocimiento existe y esta
        /// mal sellado, o el ambito de la pregunta es otro.
        uint32_t out_of_scope = 0;

        explicit operator bool() const { return fact != nullptr; }
    };

    /**
     * @brief El hecho de @p code que vale en @p here, y que se descarto.
     *
     * Es la puerta por la que un consumidor DEBE preguntar.  Recorrer @c all()
     * a mano -- que es lo que se hacia -- se salta el filtro de alcance y
     * ademas no deja rastro de la consulta, con lo que un hecho que nadie mira
     * nunca no se distingue de uno muy usado.
     *
     * @param code Codigo estable del hecho.
     * @param here Objetivo desde el que se pregunta.
     */
    Query find(const char *code, const Scope &here) const;

    /**
     * @brief Igual, pero de UNA funcion.
     *
     * Casi todo lo que se sabe es de una funcion concreta, y sin esta puerta un
     * consumidor tenia que recorrer @c of_function a mano -- que ni filtra por
     * alcance ni deja rastro de la consulta, o sea las dos cosas que la puerta
     * existe para dar.  Se ofrece aqui y no se deja al consumidor por lo mismo
     * que la de modulo: en cuanto haya dos formas de preguntar, una de las dos
     * se olvidara del alcance.
     *
     * @param code     Codigo estable del hecho.
     * @param function Nombre de la funcion (el mangled, el que el IR usa).
     * @param here     Objetivo desde el que se pregunta.
     */
    Query find(const char *code, const char *function, const Scope &here) const;

    /**
     * @brief TODOS los de @p code que valen en @p here, no solo el primero.
     *
     * `find` responde "que se sabe de esto", que es una pregunta con UNA
     * respuesta.  Hay otra distinta -- "cuantas veces pasa esto, y donde" -- y
     * con `find` no se podia hacer: de tres valores sin usar en la misma
     * funcion devolvia uno, y quien quisiera los tres acababa recorriendo el
     * almacen a mano, que es justo lo que estas puertas existen para evitar
     * (ni filtra por alcance ni deja rastro de la consulta).
     *
     * Mismo filtro y misma contabilidad que @ref find; lo unico que cambia es
     * cuantos devuelve.
     *
     * @param code     Codigo estable del hecho.
     * @param function Nombre de la funcion, o nulo para no filtrar por ella.
     * @param here     Objetivo desde el que se pregunta.
     */
    std::vector<const Fact *> find_all(const char *code, const char *function,
                                       const Scope &here) const;

    /**
     * @brief Hechos que se PRODUJERON y no consulto nadie.
     *
     * Un hecho que no mira nadie es o bien trabajo tirado, o bien conocimiento
     * bien calculado y mal sellado que nadie encuentra.  Las dos cosas
     * interesan, y ninguna se puede descubrir escribiendo tests: un test cubre
     * lo que ya sospechabas, y esto sale justo de lo que no sospechaba nadie.
     *
     * @return Los identificadores, en el orden en que se produjeron.
     */
    std::vector<FactId> never_queried() const;

    /// Cuantos hechos hay por certeza (para saber de que se fia uno).
    struct Counts {
        uint32_t proven = 0;
        uint32_t inferred = 0;
        uint32_t unknown = 0;
    };
    Counts counts() const;

  private:
    std::vector<Fact> facts_;
    /**
     * Una marca por hecho: alguien lo consulto alguna vez.
     *
     * `mutable` porque consultar no cambia lo que el almacen SABE, solo lo que
     * se ha usado de el; un consumidor pide hechos por una referencia constante
     * y tiene que seguir pudiendo.
     */
    mutable std::vector<uint8_t> queried_;
    /// Dominios ya corridos.  Son pocos y se recorren enteros; un mapa aqui
    /// seria indireccion para nada.
    std::vector<const char *> produced_;
    std::deque<std::string> names_; ///< arena: no invalida punteros al crecer.
    std::unordered_map<std::string, const char *> interned_;
    std::unordered_map<std::string, std::vector<FactId>> by_function_;
    std::unordered_map<const char *, std::vector<FactId>> by_domain_;
};

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_FACT_STORE_H
