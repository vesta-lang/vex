/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/*
La clave esta especialmente aqui:

                                    +-------------+
                    analisis  ----->|             |
                    estatico        |             |
                                    |     ASA     |----> DSE
                    C2/runtime ---->|    Fact     |----> scheduler
                                    |             |----> codegen
                    PGO ----------->|             |----> otros
                                    +-------------+

    estatico -> certeza demostrada
    C2       -> certeza posiblemente invalida
    PGO      -> conocimiento observado

En un diseno convencional es frecuente encontrar algo conceptualmente mas
parecido a:

    range analysis ----> optimizador --> criterio propio
    points-to ---------> optimizador --> criterio propio
    profile -----------> JIT ----------> criterio propio
    type analysis -----> codegen ------> criterio propio

Aunque existen sistemas que comparten analisis, la idea fuerte de que el
conocimiento sea un recurso arquitectonico explicito, con
certeza/procedencia/prueba, y que los consumidores sean deliberadamente
agnosticos respecto al productor, es otra cosa:

    Vesta introduce una arquitectura de conocimiento unificada basada en ASA,
    donde analisis estatico, runtime/JIT y PGO actuan como productores de
    hechos con certeza y procedencia, mientras los consumidores consultan ese
    conocimiento sin mantener criterios paralelos.
*/

/**
 * @file analysis/asa/producers.h
 * @brief Quien convierte el resultado de un analisis en HECHOS del ASA.
 *
 * Un analisis produce una estructura de datos suya -- intervalos, tablas
 * points-to, formas de bucle --; un hecho es una afirmacion con certeza,
 * procedencia y prueba.  El paso de lo uno a lo otro es una DECISION del
 * dominio: cual de sus resultados dice algo y cual no.  Ese criterio vive aqui,
 * en el productor, y NO en quien luego mire los hechos.
 *
 * Es la separacion que hace que el sistema no se bifurque:
 *
 *      analisis  ->  PRODUCTOR  ->  FactStore  ->  consumidores
 *      (calcula)    (afirma)       (guarda)       (deciden)
 *
 * Si el criterio de "esto merece afirmarse" viviera en el consumidor, cada
 * consumidor tendria el suyo -- y volveriamos justo al problema que el ASA
 * existe para quitar.  Por eso el volcado (@c analysis/asa/dump.h) NO decide
 * nada: solo ensena lo que hay.
 *
 * AMPLIAR es anadir un productor con @c register_producer: aparece en el
 * almacen, en el volcado y en los filtros sin tocar el motor.  Manana el mismo
 * mecanismo recibe lo observado en ejecucion o un perfil de corridas
 * anteriores: otro productor, mismos hechos, otra procedencia y otra certeza.
 */
#ifndef ANALYSIS_ASA_PRODUCERS_H
#define ANALYSIS_ASA_PRODUCERS_H

#include "analysis/asa/fact_base.h"
#include "analysis/asa/fact_store.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ir {
struct IrModule;
struct IrFunction;
} // namespace ir

namespace analysis {
namespace asa {

/**
 * @brief POR QUE un dominio no supo algo, y cuantas veces.
 *
 * NO SABER ALGO ES UN RESULTADO, y sin el motivo no sirve para nada: "no lo se"
 * puede significar que el valor de verdad puede ser cualquiera, que el analisis
 * se quedo sin presupuesto, o que ni siquiera se miro porque se pidio un tope.
 * Son tres cosas distintas y se arreglan de tres formas distintas.  Por eso el
 * motivo se cuenta SIEMPRE, aunque no se pidan los hechos desconocidos uno a
 * uno: callarse el porque es lo unico que el ASA no puede hacer.
 */
struct UnknownEntry {
    const char *code = "?"; ///< estable, del vocabulario del dominio.
    /// De que clase es.  Dos codigos distintos de la misma clase se arreglan
    /// igual, y es lo que permite a un consumidor decidir sin conocer el
    /// dominio.
    UnknownReason reason = UnknownReason::NotAsked;
    uint32_t times = 0;
};

/// Lo que se produjo por dominio.  Lo "mirado" incluye lo que no dio nada.
struct ProductionSummary {
    const char *domain = nullptr;
    uint32_t facts = 0;     ///< afirmaciones con algo que decir.
    uint32_t looked_at = 0; ///< entidades examinadas.
    uint32_t silent = 0;    ///< de esas, las que no dieron nada.
    /**
     * @brief Las que NI SE MIRARON, y por que se descartaron.
     *
     * Sin esto el resumen no cuadraba: no habia forma de saber si un dominio
     * habia visto todo el modulo o se habia saltado media docena de funciones
     * en silencio.  `looked_at + skipped` = todo lo que habia.
     *
     * Se cuenta AGREGADO y no una por una a proposito: el descarte es una
     * politica uniforme del dominio -- hoy, "un stub nativo no tiene cuerpo"
     * --, no una sorpresa por funcion, y repetirlo N veces seria ruido que tapa
     * los motivos que si dicen algo.
     */
    uint32_t skipped = 0;
    long micros = 0;
    /// Desglose de @c silent por motivo.  Pocos por dominio: vector plano.
    std::vector<UnknownEntry> reasons;
};

/**
 * @brief Lo que un productor recibe.
 *
 * Trae la base de hechos ya montada -- un productor tampoco reconstruye lo
 * comun (Regla 1) -- y el almacen donde deposita.
 */
struct Production {
    const ir::IrModule &mod;
    FactBase &base;
    FactStore &store;
    ProductionSummary &summary;
    /**
     * @brief El hecho de estructura de cada funcion, si ya se produjo.
     *
     * Permite que un productor apoye SU hecho en otro CONCRETO -- no solo en el
     * nombre del productor -- y que la derivacion se pueda recorrer despues.
     */
    std::unordered_map<std::string, FactId> &structure_of;

    /// Si hay algo que mirar en ella (los stubs de funciones nativas no tienen
    /// cuerpo del que sacar nada).
    bool is_interesting(const ir::IrFunction &fn) const;
    /// Deposita un hecho contandolo en el resumen.
    FactId assert_fact(Fact f);
    /**
     * @brief Anota que se miro @p about y no se saco nada, Y POR QUE.
     *
     * El motivo se registra siempre (agregado por codigo); ademas se afirma
     * como hecho de certeza desconocida.  Un dominio NUNCA se calla sin decir
     * por que: sin el motivo, "no lo se" y "no lo mire" se leen igual.
     *
     * @param about   De que entidad no se supo nada.
     * @param reason  De QUE TIPO es el no saber.  Es lo que decide la accion
     *                -- declarar una frontera no se parece en nada a subir un
     *                limite --, y por lo que pregunta un consumidor que no
     *                conoce este dominio.  El codigo de abajo dice el caso
     *                exacto; esto dice de que clase es.
     * @param code    Codigo ESTABLE del vocabulario del dominio.
     * @param domain  Quien lo dice.
     * @param detail  Texto para una persona (lo mismo, en cristiano).
     */
    void say_unknown(Subject about, UnknownReason reason, const char *code,
                     const char *domain, const char *detail);
};

/// Un dominio que sabe convertir su analisis en hechos.
using Producer = void (*)(Production &);

/**
 * @brief Da de alta un productor.
 *
 * @param domain Nombre estable (el que aparece como procedencia).
 * @param p      Funcion que afirma sus hechos.
 */
void register_producer(const char *domain, Producer p);

/// Los dominios dados de alta, en orden de registro.
std::vector<const char *> registered_producers();

/**
 * @brief Da de alta el dominio de la FORMA DE UN VALOR.
 *
 * Aparte de los demas porque su analisis vive en otra unidad de traduccion
 * (@c aggregate_facts.cpp) y arrastrarlo al motor ataria el registro a un
 * dominio concreto.  Lo llama @ref produce, que es quien monta la lista.
 */
void register_value_shape_producer();

/**
 * @brief Corre los productores pedidos sobre @p mod y deposita en @p store.
 *
 * Monta UNA base de hechos para todos: el conocimiento comun se calcula una vez
 * aunque lo usen cinco dominios.
 *
 * SOLO SE PRODUCE LO QUE ALGUIEN VAYA A CONSULTAR.  Con @p wanted vacio corren
 * todos -- lo que quiere una herramienta que ensena el conocimiento entero --;
 * con dominios nombrados corre solo esos, que es lo que quiere el compilador.
 * La diferencia no es pequena: al medirlo, los rangos se llevaban el 80% del
 * tiempo, y un consumidor que solo pregunta por la disposicion no tiene por que
 * pagarlo.  Es la misma idea que el informe de "nadie consulto", en la otra
 * direccion: no calcular conocimiento que nadie va a mirar.
 *
 * Es IDEMPOTENTE: un dominio que ya corrio sobre @p store -- porque lo pidio
 * otro consumidor, o porque vino de la cache en disco -- no se vuelve a correr.
 *
 * @param mod    Modulo IR ya optimizado (el codigo que de verdad va a existir).
 * @param store  Donde se depositan los hechos.
 * @param wanted Dominios a correr.  Vacio = todos.
 * @return El resumen de los dominios que de verdad corrieron.
 */
std::vector<ProductionSummary>
produce(const ir::IrModule &mod, FactStore &store,
        const std::vector<const char *> &wanted = {});

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_PRODUCERS_H
