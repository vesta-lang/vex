/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/effects/param_aliasing.h
 * @brief Que se sabe, mirando las LLAMADAS, de si dos parametros puntero de una
 *        funcion reciben la misma region.
 *
 * Dentro de la funcion sus parametros son dos NOMBRES y la pregunta no tiene
 * respuesta.  En la llamada se ven los ARGUMENTOS, y ahi casi siempre se sabe:
 * dos posiciones de la misma reserva con desplazamientos conocidos, o dos
 * reservas distintas.
 *
 * @par Por que vive aqui y no dentro de un consumidor
 * Es conocimiento DEL MoDULO, no de una funcion -- para saber que le llega a un
 * parametro hay que ver a todos los que la llaman --, exactamente por el mismo
 * motivo que los resumenes de frontera, y se cachea igual: una vez por base.
 *
 * Y sobre todo, porque lo preguntan DOS: el productor de contratos de parametro,
 * que lo afirma como hecho, y la comprobacion de prestamos, que lo cruza con la
 * exclusividad prometida.  Calcularlo en cada uno serian dos productores del
 * mismo hecho, que es el primer invariante del ASA roto -- y el dia que uno de
 * los dos cambiara, el mismo programa se juzgaria de dos maneras.
 *
 * @par COSTE, que es lo que decide la forma de esto
 * Lo que se guarda son las POSICIONES ya resueltas por argumento y sitio de
 * llamada, no un veredicto por PAR.  Es la diferencia entre lineal y cuadratico,
 * y no es teorica:
 *
 *   - Resolver por par obliga a recorrer todos los sitios una vez por par, o sea
 *     `pares x sitios` resoluciones -- y los pares son el cuadrado de los
 *     parametros.
 *   - Resolviendo por ARGUMENTO se hace una vez por argumento y sitio, que
 *     sumado sobre el modulo es exactamente el tamano de sus listas de
 *     argumentos: LINEAL en el programa.
 *
 * Y no vale decir "los parametros estan acotados": lo estan en la maquina
 * virtual, que pasa doce, pero un binario NATIVO no tiene ese limite -- la
 * convencion derrama en la pila lo que no cabe --.  O sea que el cuadrado
 * creceria con el programa.
 *
 * Una consulta recorre entonces los sitios de ESA funcion comparando dos
 * posiciones ya resueltas, y solo se pagan los pares que alguien pregunta de
 * verdad, que son pocos.
 */

#ifndef ANALYSIS_EFFECTS_PARAM_ALIASING_H
#define ANALYSIS_EFFECTS_PARAM_ALIASING_H

#include "analysis/effects/effects.h" // AbstractLoc

#include <cstddef>
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
class FactBase;
struct ModuleWalk;
} // namespace asa

namespace effects {

/**
 * @brief Lo que se sabe de un par, y NO es un si/no.
 *
 * Los tres valores llevan acciones distintas detras, y por eso son tres: en uno
 * hay que declarar, en otro hay que cambiar el programa, y en el tercero no hay
 * nada que decir todavia.  Colapsar el ultimo con cualquiera de los otros seria
 * confundir "no lo se" con una respuesta -- y en la direccion mala: no poder
 * demostrar que dos regiones son disjuntas NO es demostrar que se solapan.
 */
enum class ParamPairVerdict : uint8_t {
    /// En TODAS las llamadas visibles se demuestra que no coinciden.
    Disjoint,
    /// En alguna se demuestra que SI, y esa se puede senyalar por su linea.
    Overlaps,
    /// En alguna no se pudo decidir, o hay llamadas que no se ven.
    Unknown,
};

/// @brief El veredicto de un par, con la linea que lo demuestra si la hay.
struct ParamPairInfo {
    ParamPairVerdict verdict = ParamPairVerdict::Unknown;
    /// Linea del sitio de llamada que lo decidio; 0 si no hay ninguno que
    /// senyalar (nadie la llama, o el veredicto no sale de un sitio concreto).
    uint32_t line = 0;
};

/**
 * @brief Lo que un argumento de una llamada alcanza, ya resuelto.
 *
 * Son DOS cosas y hacen falta las dos, porque contestan a preguntas distintas:
 *
 *   - @c base es DONDE APUNTA el argumento.  Siempre se sabe, y es lo unico que
 *     hay cuando del llamado no se puede mirar el cuerpo.
 *   - @c reached son los BYTES que el llamado alcanza por ahi, en memoria del
 *     llamante.  Es lo que separa `f(m + 1, m)` -- que se pisa -- de
 *     `f(m + 8, m)` -- que no --, dos casos que mirando solo la base son
 *     indistinguibles.
 */
struct ParamReach {
    /// Donde apunta el argumento.  Respaldo cuando no hay resumen del llamado.
    AbstractLoc base;
    /// Los bytes que el llamado alcanza por ese parametro.  Vale si @c known.
    LocSet reached;
    /// Hay resumen del llamado, asi que @c reached es la respuesta.
    bool known = false;
    /// @c reached son TODOS.  Sin esto solo sirve para demostrar un solape --
    /// cada byte que lleva es real --, nunca la disyuncion, que necesita saber
    /// que no falta ninguno.
    bool complete = false;
};

/**
 * @brief Lo que alcanza cada argumento de una llamada, ya resuelto.
 *
 * Una entrada por argumento, en el orden de los parametros.  Un argumento que no
 * era puntero, o cuya posicion no se pudo resolver, queda con una posicion NO
 * concreta -- que es una respuesta, no un hueco.
 */
struct CallSiteLocs {
    uint32_t line = 0;
    std::vector<ParamReach> arg;
};

/**
 * @brief Lo que le llega a cada parametro, resuelto SOLO cuando se pregunta.
 *
 * @par Perezoso, como el resto del ASA
 * Resolver el modulo entero en la primera consulta seria pagar por todas las
 * funciones para contestar por una.  Aqui se resuelve la funcion que se
 * pregunta, la primera vez que se pregunta, y se guarda: quien pregunte por dos
 * paga dos, no el modulo.
 *
 * El recorrido de llamadas NO es suyo: llega ya hecho, porque es el mismo que
 * comparten los productores.  Construir otro seria la pasada de mas que
 * @c ModuleWalk existe para quitar.
 */
class ParamAliasing {
  public:
    ParamAliasing() = default;
    /// @param mod   Modulo completo.
    /// @param walk  El recorrido, ya hecho: de ahi salen los sitios de llamada.
    /// @param base  La base, de donde salen el points-to y los efectos.
    /// @param stage EN QUE MOMENTO se pregunta.  Va porque los efectos se piden
    ///              con el: el resumen de antes de optimizar y el de despues
    ///              hablan de codigos distintos, y darle uno al otro describe
    ///              memoria que ya no se toca.
    ParamAliasing(const ir::IrModule &mod, const asa::ModuleWalk &walk,
                  asa::FactBase &base, const char *stage)
        : mod_(&mod), walk_(&walk), base_(&base), stage_(stage) {}

    /**
     * @brief Lo que se sabe del par (@p a, @p b) de @p function.
     *
     * Recorre los sitios de esa funcion comparando dos posiciones ya resueltas.
     * Basta UNA llamada donde se DEMUESTRE el solapamiento para que ese sea el
     * veredicto -- es un dato del programa, y gana sobre cualquier sitio
     * indeciso, por eso se miran todos --, y basta una donde no se pueda decidir
     * para que la disyuncion no se pueda afirmar: ahi la respuesta es "no se",
     * no "disjunto".  Darlo por disjunto mirando solo las llamadas faciles seria
     * dar por buena una promesa sin comprobarla.
     *
     * Y @c Overlaps sale de @ref must_overlap, no de @ref may_alias: la segunda
     * contesta "no se pudo demostrar que sean disjuntas", que como respuesta
     * PARA ACUSAR esta invertida.  Con ella, `f(m + 8, m)` sobre una reserva
     * comun -- dos regiones que no se tocan -- salia como solape probado y
     * tumbaba un programa correcto.
     *
     * @param function Nombre de la funcion, el que el IR usa.
     * @param a Indice del primer parametro.
     * @param b Indice del segundo.
     * @return El veredicto; @c Unknown si no hay llamadas visibles.
     */
    ParamPairInfo of(const std::string &function, size_t a, size_t b) const;

  private:
    /// @brief Los sitios de @p function con sus argumentos ya resueltos.
    ///
    /// La primera vez los resuelve; despues los devuelve.  Nulo si a esa
    /// funcion no la llama nadie visible.
    const std::vector<CallSiteLocs> *sites_of(const std::string &function) const;

    /// @brief La funcion @p name del modulo, o nulo.
    ///
    /// Hace falta para leer SU contrato: la extension que un parametro promete
    /// (`i64 p[3]`) es lo que da ancho a la region del argumento, y sin ancho
    /// dos posiciones de la misma reserva no se pueden separar.  El indice se
    /// construye entero la primera vez -- una pasada -- porque hacerlo por
    /// consulta seria recorrer las funciones una vez por cada una.
    const ir::IrFunction *function_named(const std::string &name) const;

    const ir::IrModule *mod_ = nullptr;
    const asa::ModuleWalk *walk_ = nullptr;
    asa::FactBase *base_ = nullptr;
    const char *stage_ = "";
    /// Nombre -> funcion, construido a la primera consulta.  Vacio mientras no
    /// se pregunte: quien no necesite contratos no lo paga.
    mutable std::unordered_map<std::string, const ir::IrFunction *> by_name_;
    /// Lo ya resuelto.  `mutable` porque la consulta es const y el cacheo es un
    /// detalle suyo: quien pregunta no cambia nada de lo que se sabe.
    mutable std::unordered_map<std::string, std::vector<CallSiteLocs>> resolved_;
};

} // namespace effects
} // namespace analysis

#endif // ANALYSIS_EFFECTS_PARAM_ALIASING_H
