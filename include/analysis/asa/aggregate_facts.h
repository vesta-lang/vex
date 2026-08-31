/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/aggregate_facts.h
 * @brief FORMA de un valor con componentes: ¿saco de partes, o unidad?
 *
 * Dominio de ASA.  Descubre conocimiento; no decide transformaciones.  Un hecho
 * dice "he observado esto"; el que optimiza decide despues si le conviene
 * romper el valor o conservarlo.  Si el hecho dijera "esto se puede romper",
 * dos consumidores con criterios distintos no podrian usarlo sin contradecirse.
 *
 * NO SE CLASIFICA POR TIPO.  Ni por nombre, ni por tamano, ni por una lista de
 * tipos conocidos.  Que algo ocupe 256 bits no lo convierte en un numero, y que
 * tenga tres campos no lo convierte en un saco.  Esa ignorancia es deliberada:
 * en cuanto se mete una lista de tipos, el analisis deja de descubrir y pasa a
 * reconocer lo que ya sabiamos.
 *
 * =========================================================================
 *  EL PRINCIPIO: NO COMPRIMIR LA EVIDENCIA ANTES DE TIEMPO
 * =========================================================================
 *
 * Un `load` de un componente NO es un hecho: es un hecho EN UNA RELACION.  El
 * mismo `load` dentro de una operacion que consume el valor entero lo
 * IMPLEMENTA; en quien lo posee, y sin que nada lo consuma entero, lo DESTRIPA.
 * Reducirlo a un contador pierde exactamente lo que decide.
 *
 * Esa perdida se MIDIO dos veces, y las dos destaparon un fallo que ninguna
 * lectura del codigo habia visto: una senal que disparaba en el 100% de los
 * agregados, y un 46.5% de "evidencia contradictoria" que no era del programa
 * sino de haber comprimido antes de tiempo -- al conservar la relacion,
 * desaparecio por completo.
 *
 * De ahi los tres niveles, que ordenan el fichero entero:
 *
 *     A  OBSERVACION      lo que se demuestra mirando el IR, CON su contexto.
 *     B  RELACION         lo derivable de A sin semantica de tipos.
 *     C  PROYECCION       una CONSULTA sobre B, no un sustituto de B.
 *
 * El productor llena A.  B se deriva.  C se pregunta.  Asi, el dia que se
 * descubra que una regla de interpretacion era falsa, se cambia la consulta y
 * no el productor: los hechos sobreviven a los cambios de interpretacion.
 *
 * DOS DIMENSIONES QUE NO SE MEZCLAN, y por el mismo motivo:
 *
 *     ESCAPE       conocimiento sobre el PROGRAMA: la direccion se va por ahi.
 *     LIMITACION   conocimiento sobre el ALCANCE DEL ANALISIS: no pude
 * seguirlo.
 *
 * "La direccion escapa" es algo que hace el programa y que seguira siendo
 * cierto por mucho que mejoremos el analisis.  "No pude resolver el destino"
 * desaparece el dia que el resolvedor mejore.  Meterlos en el mismo saco impide
 * saber cual de las dos cosas hay que arreglar.
 *
 * =========================================================================
 *  EL RETICULO (nivel C)
 * =========================================================================
 *
 *              Desconocida   hay conocimiento, pero no permite elegir forma
 *             /           \
 *      Agregado          Compuesto
 *             \           /
 *              SinEvidencia   no hay observaciones que basten
 *
 * `SinEvidencia` es no haber terminado; `Desconocida` es haber terminado sin
 * poder elegir.  Regla para quien consuma: NUNCA `if (forma == Agregado) ...
 * else <suponer unidad>`.  Ninguna de las dos puntas es "unidad".
 *
 * Y participar como unidad NO se contradice con que se toquen las partes: asi
 * es como se implementa una unidad.  Los accesos quedan anotados con su
 * relacion, disponibles para quien quiera mirar DONDE ocurren.
 *
 * =========================================================================
 *  EXPLICABILIDAD: DOS PREGUNTAS, NO UNA
 * =========================================================================
 *
 *     ¿por que esta forma?          -> @c motivos_forma()
 *     ¿que impide demostrarla mas?  -> @c limitaciones
 *
 * `compuesto / inferida` no es contradictorio: es "tengo evidencia para
 * pensarlo, no he podido cerrar la observacion".  Todo en DATOS -- codigo +
 * sitio + operandos --, nunca frases: las palabras las pone el catalogo i18n.
 *
 * Los dos salen del MISMO perfil derivado.  Dos logicas escritas a mano en
 * paralelo -- una que concluye y otra que explica -- divergen, y entonces la
 * explicacion deja de explicar lo que el analisis hace.
 *
 * Sirve a cuatro consumidores: el programador (por que su valor no se
 * optimiza), el optimizador (que le falta para especular), la seguridad (que
 * queda sin demostrar) y el RASTREO cuando otro sistema falla -- un analisis
 * que solo guarda su veredicto no puede explicar el fallo de nadie.
 */
#ifndef ANALYSIS_ASA_AGGREGATE_FACTS_H
#define ANALYSIS_ASA_AGGREGATE_FACTS_H

#include "analysis/asa/fact.h"
#include "analysis/facts/ir_facts.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ir {
struct IrFunction;
struct IrModule;
} // namespace ir

namespace analysis {

/* Solo se pasa por referencia, asi que basta declararlo: arrastrar el
 * points-to entero a todo el que incluya esta cabecera seria pagar en tiempo de
 * compilacion por un tipo que aqui no se abre. */
struct PointsTo;

namespace asa {

/// Idem: la base solo se pasa por puntero (ver @c analysis/asa/fact_base.h).
class FactBase;

// =========================================================================
//  NIVEL A -- observaciones, con su contexto
// =========================================================================

/**
 * @brief Un ambito de observacion, y si se ha podido CERRAR.
 *
 * NO hay un solo universo.  Hay uno global, casi siempre abierto, y dentro
 * pequenos universos cerrados donde reside una verdad propia:
 *
 *     U(mul)     cerrado  -> aqui el valor participa como unidad, DEMOSTRADO
 *     U(modulo)  abierto  -> por un callind sin destino unico
 *
 * Las dos son ciertas a la vez y no se contradicen: son vistas distintas del
 * mismo valor.  Un unico booleano obliga a quedarse con la peor y borrar la
 * mejor, que es perder conocimiento ya calculado -- la misma compresion
 * prematura de siempre, un nivel mas arriba.
 */
using UniversoId = uint32_t;
/// "Existe una frontera, pero no se puede nombrar el destino".  NO es el
/// universo 0: confundir "no lo se" con "es la raiz" es justo la ambiguedad que
/// este modelo existe para evitar.
constexpr UniversoId kUniversoDesconocido = 0xFFFFFFFFu;

/**
 * @brief ¿Se puede nombrar este ambito?
 *
 * Eje SEPARADO de si se ha mirado dentro, porque son cosas distintas: "se
 * exactamente que hay al otro lado y aun no lo he analizado" es conocimiento
 * util, y "se que hay una frontera pero no a donde va" es otra cosa.
 */
enum class IdentidadUniverso : uint8_t {
    Conocido = 0,
    Desconocido = 1,
};

/// ¿Se ha mirado dentro?  Nada que ver con poder nombrarlo.
enum class EstadoObservacion : uint8_t {
    Observado = 0,
    NoObservado = 1,
};

const char *nombre_identidad(IdentidadUniverso i);
const char *nombre_observacion(EstadoObservacion o);

/**
 * @brief Un ambito de conocimiento.
 *
 * Un universo NO es un nivel de profundidad: es un CONTEXTO EPISTEMOLOGICO. Hoy
 * los delimita una funcion porque es lo que el recorrido sabe seguir, pero
 * manana pueden nacer de una region de control, de una biblioteca parcialmente
 * conocida, de una frontera con codigo externo o de una region especulativa,
 * sin que "universo" tenga que significar "funcion", ni su id un contador de
 * profundidad.
 */
struct Universo {
    UniversoId id = 0;
    /// CONTENCION: quien lo envuelve.  Es una relacion estructural, y NO la
    /// unica por la que se llega a otros ambitos -- para eso estan las
    /// fronteras, que conectan universos que no son padre ni hijo.
    UniversoId padre = 0;
    std::string ambito; ///< quien lo delimita (hoy, una funcion).
    IdentidadUniverso identidad = IdentidadUniverso::Conocido;
    EstadoObservacion observacion = EstadoObservacion::Observado;
    /// Se ha visto TODO lo que podria contradecir lo afirmado AQUI DENTRO.  El
    /// cierre es del universo, no del hecho: uno hijo abierto no abre al padre
    /// para lo que el padre ya demostro por su cuenta.
    bool cerrado = true;
};

/// Donde ocurrio algo.  Sin esto una explicacion no se puede seguir hasta el
/// codigo, y una explicacion que no se puede seguir no sirve para rastrear
/// nada.
struct SitioIr {
    std::string funcion;
    uint32_t universo = 0; ///< ambito de observacion en el que se vio.
    uint32_t bloque = 0;
    uint32_t indice = 0; ///< posicion de la instruccion dentro del bloque.
    uint32_t linea = 0;  ///< linea fuente, si el IR la lleva.
};

/**
 * @brief En que relacion con el valor esta un acceso a uno de sus componentes.
 *
 * Es lo UNICO que se puede demostrar del contexto de un acceso.  "Proyeccion de
 * un componente" frente a "descomposicion estructural" NO entra aqui: las dos
 * son un `load` en el propietario, y lo unico que las separaria es si el valor
 * participa ademas como unidad -- que es lo que se intenta concluir.  Meterlo
 * seria circular, y contaminaria el productor con interpretacion.
 */
enum class RelacionAcceso : uint8_t {
    Ninguna = 0,
    /// En la funcion que posee el ancla.
    EnPropietario = 1,
    /// En una funcion a la que se llego PORQUE el valor se paso entero.  NO
    /// significa "es parte de la unidad".
    EnOperacion = 2,
};

const char *nombre_relacion(RelacionAcceso r);

/// Un acceso a un componente, con todo lo que permitio situarlo.
struct AccesoComponente {
    SitioIr sitio;
    int64_t offset = 0;
    bool offset_sabido = false; ///< false = indice variable.
    bool escribe = false;
    RelacionAcceso relacion = RelacionAcceso::Ninguna;
    ir::IrValueId puntero = 0;
    /**
     * @brief Lo que este acceso toca, ¿lo produce o lo consume una operacion?
     *
     * Un acceso del propietario a un desplazamiento que alguna de sus
     * operaciones ESCRIBE esta consumiendo lo que esa operacion produjo; uno a
     * un desplazamiento que alguna LEE lo esta construyendo.  En los dos casos
     * el acceso pertenece al ciclo de vida del valor y no lo desmiente.
     *
     * Un acceso a un desplazamiento que NINGUNA operacion toca es otra cosa: se
     * usa una parte al margen de todo lo que el valor hace.  Esa es la unica
     * forma en que "unidad" y "partes" llegan a ser incompatibles de verdad.
     *
     * Se deriva de dos observaciones que ya existen (el desplazamiento y la
     * relacion de cada acceso); no mira tipos ni mide cobertura.
     */
    bool ligado_a_operacion = false;
};

/// El valor entero entra en una operacion cuya implementacion se ha visto
/// ENTERA.  Solo entonces se sabe que la llamada es una operacion sobre el
/// valor y no una fuga por donde puede pasar cualquier cosa.
struct ParticipacionUnidad {
    SitioIr sitio;
    std::string operacion;
    uint32_t parametro = 0;
};

/// Por donde se va la direccion.  Conocimiento sobre el PROGRAMA: seguira
/// siendo cierto por mucho que mejore el analisis.
enum class CodigoFrontera : uint8_t {
    DireccionGuardada = 0, ///< el puntero se escribe en memoria.
    ComponenteSeLleva = 1, ///< se pasa la direccion de una parte.
};

const char *nombre_frontera(CodigoFrontera c);

/**
 * @brief Una FRONTERA entre ambitos.  Relacion del programa, no del valor.
 *
 * "El valor escapa" describe el estado del VALOR y cierra la conversacion.
 * "Desde U3 hay una frontera hacia U7 por esta operacion" describe una relacion
 * del PROGRAMA y la abre: dice de donde sale, adonde va y por que, y deja que
 * el efecto epistemologico -- lo demostrado en U3 no se eleva -- se DERIVE en
 * vez de guardarse como conclusion.
 *
 * Es una relacion distinta de la contencion: `padre` dice quien envuelve a
 * quien; esto dice por donde se sale.  Tratar una como la otra haria creer que
 * el padre es el unico sitio al que se puede llegar desde aqui.
 */
struct Frontera {
    CodigoFrontera codigo = CodigoFrontera::DireccionGuardada;
    SitioIr sitio; ///< donde esta.  Su `universo` es redundante con @c desde.
    UniversoId desde = 0;
    UniversoId hacia = kUniversoDesconocido;
    ir::IrValueId valor = 0;
};

/// Que impidio OBSERVAR mas.  Conocimiento sobre el alcance del analisis:
/// desaparece el dia que la pieza que falta mejore.
enum class CodigoLimitacion : uint8_t {
    ProfundidadAgotada = 0,
    DestinoIndirectoNoUnico = 1, ///< un `callind` sin un destino sabido.
    DestinoNoVisible = 2,        ///< el codigo del destino no esta.
    ParametroFueraDeRango = 3,   ///< la firma no encaja con la llamada.
};

const char *nombre_limitacion(CodigoLimitacion c);

struct Limitacion {
    CodigoLimitacion codigo = CodigoLimitacion::ProfundidadAgotada;
    SitioIr sitio;
    std::string destino;
    uint32_t profundidad = 0;
    ir::IrValueId valor = 0;
    /**
     * @brief De que CLASE es la limitacion, en el vocabulario comun del ASA.
     *
     * El codigo de arriba dice el caso EXACTO de este dominio; esto dice de que
     * tipo es, que es lo unico que puede leer un consumidor que no lo conoce --
     * y lo que decide la accion.  `DestinoIndirectoNoUnico` cubria SIETE
     * situaciones distintas: desde "hay dos destinos segun el camino" (que se
     * puede especular con guarda) hasta "esa operacion no la modelamos" (que se
     * arregla ampliando el analisis).  Con un solo codigo se trataban igual.
     */
    asa::UnknownReason reason = asa::UnknownReason::NotAsked;
    /// Y el codigo estable del sub-caso, cuando quien limita lo sabe.
    const char *reason_code = "";
};

// =========================================================================
//  NIVEL B -- perfil de uso, derivado de las observaciones
// =========================================================================

/**
 * @brief Los MODOS DE USO observados.  Ninguno excluye a otro.
 *
 * Que un valor tenga a la vez uso como unidad y acceso a partes no es una
 * contradiccion: es un perfil con dos modos, y eso ya es conocimiento.  Aqui no
 * se elige entre ellos -- eso es cosa de la proyeccion.
 */
struct PerfilDeUso {
    bool unidad = false; ///< entra entero en una operacion vista.
    bool acceso_en_propietario = false; ///< se toca una parte donde vive.
    bool acceso_en_operacion = false;   ///< se toca una parte dentro de una op.
    /// Se toca una parte que NINGUNA de sus operaciones produce ni consume: un
    /// uso al margen del valor.  Derivado, no observado.
    bool acceso_independiente = false;
    bool acceso_dinamico = false; ///< no se sabe a que componente.
    bool escapa = false;          ///< su direccion, o la de una parte, se va.
    bool transferencia_entera = false; ///< los bytes viajan juntos.
    bool retorno_entero = false;
    bool paso_por_abi = false; ///< se pasa entero (representacion).
    /// Se ha podido OBSERVAR todo.  Derivado: ni limitaciones ni escapes. Habla
    /// del alcance del analisis, no del valor.
    bool universo_completo = false;
};

// =========================================================================
//  NIVEL C -- proyecciones: consultas sobre B, no sustitutos de B
// =========================================================================

enum class FormaDeValor : uint8_t {
    SinEvidencia = 0,
    Agregado = 1,
    Compuesto = 2,
    Desconocida = 3,
};

/// Union del reticulo: dos afirmaciones distintas no se promedian, dan TOP.
inline FormaDeValor unir(FormaDeValor a, FormaDeValor b) {
    if (a == FormaDeValor::SinEvidencia) return b;
    if (b == FormaDeValor::SinEvidencia) return a;
    return a == b ? a : FormaDeValor::Desconocida;
}

const char *nombre_forma(FormaDeValor f);

/**
 * @brief Por que la forma es la que es.  Una conclusion tiene VARIOS motivos.
 *
 * Los nombres conservan la epistemologia exacta: "no se observo participacion"
 * NO es "no participa".  Un motivo que afirma mas de lo que se demostro acaba
 * autorizando a un consumidor a concluir lo que el analisis nunca dijo.
 */
enum class MotivoForma : uint8_t {
    SinObservacion = 0,
    UniversoIncompleto = 1,
    ParticipaComoUnidad = 2,
    SinParticipacionUnidadObservada = 3,
    AccesoEnPropietario = 4,
    AccesoEnOperacion = 5,
    AccesoDinamico = 6,
    /// Se toca una parte al margen de lo que el valor hace.  Este SI es un
    /// nombre con conclusion, y puede serlo porque ya esta derivado: no dice
    /// donde ocurre el acceso, dice que ninguna operacion toca ese sitio.
    AccesoIndependienteDeOperacion = 7,
};

const char *nombre_motivo(MotivoForma m);

/// Lo OBSERVADO de un valor con componentes.  Evidencia, no veredicto.
struct AggregateFacts {
    /**
     * @brief Ancla local con la que esta implementacion sigue al valor.
     *
     * Hoy es el valor que lo reserva.  NO implica que la forma dependa de que
     * exista una reserva: puede venir de un parametro, de una constante, de un
     * global o del monton, y el dia que se sigan tambien esos, esta identidad
     * cambia sin que cambie el dominio.
     */
    ir::IrValueId ancla = 0;
    /**
     * @brief IDENTIDAD que sobrevive al pipeline: donde se DECLARO el valor.
     *
     * El ancla es un value-id y no sirve para esto: la optimizacion los
     * renumera, los borra y los crea, asi que comparar dos momentos por ancla
     * no compara nada.  Lo que si sobrevive es el SITIO DEL FUENTE donde el
     * valor nace, que ademas es lo que un programador llama "esa variable".
     *
     * Correlacionar por tamano o por orden de aparicion habria sido inventarse
     * la relacion: dos agregados de 16 bytes en la misma funcion son
     * indistinguibles asi, y una correlacion equivocada es peor que ninguna
     * porque produce transiciones que no ocurrieron.
     *
     * La identidad COMPLETA de un valor incluye ademas su MODULO: el mismo
     * fuente se observa una vez en su propio modulo y otra en el programa
     * fusionado, y son dos observaciones legitimas de cadenas distintas.
     * Colapsarlas por nombre y linea producia contradicciones que no existian.
     */
    SitioIr declaracion;
    /// Que INSTANCIA es, cuando el sitio del fuente no es unico (una funcion
    /// inlinada dos veces en el mismo llamante).  Ver @c IdentidadValor.
    uint32_t instancia = 0xFFFFFFFFu;
    int64_t bytes = -1;

    // --- nivel A ---
    std::vector<AccesoComponente> accesos;
    std::vector<ParticipacionUnidad> participaciones;
    std::vector<Frontera> fronteras;      ///< sobre el programa
    std::vector<Limitacion> limitaciones; ///< sobre el analisis
    std::vector<std::string> frontera;
    /// Los ambitos observados.  El 0 es el del propietario; cada operacion que
    /// se pudo mirar entera anade el suyo.
    std::vector<Universo> universos;

    // Representacion: los bytes viajan juntos.  NO clasifica -- un `memcpy`
    // demuestra que se copiaron, no que el valor signifique algo, y por el
    // convenio de llamada un saco y un numero de 256 bits se pasan IGUAL.
    bool pasado_por_abi = false;
    bool devuelto_entero = false;
    bool transferido_como_bloque = false;

    Seal seal;

    // --- nivel B ---
    PerfilDeUso perfil() const;
    uint32_t accesos_con(RelacionAcceso r) const;
    /// Desplazamientos DISTINTOS tocados.  Desplazamientos y no campos: el IR
    /// no tiene campos, tiene direcciones.
    uint32_t offsets_tocados() const;

    /// Si un ambito concreto quedo cerrado.  Un universo abierto por dentro NO
    /// invalida lo que otro cerrado demostro.
    bool cerrado(uint32_t universo) const;

    /**
     * @brief Hasta donde NO llega una verdad local, y por culpa de que.
     *
     * Es el eje de EFECTO, y es epistemologico: dice que deja de poder
     * afirmarse, no que deberia hacer nadie.  "Esta frontera impide elevar lo
     * demostrado en `u128::add` al ambito de `u256::add`" se deriva de la
     * relacion padre/hijo y de la causa registrada; "no escalarices"
     * necesitaria saber para que maquina, y eso ya seria una decision.
     *
     * Junto con el sitio (ORIGEN) y el codigo de la frontera (CAUSA) completa
     * las tres cosas que toda pieza de conocimiento tiene que responder.
     */
    struct EfectoAlcance {
        uint32_t universo = 0; ///< donde la verdad SI esta demostrada.
        FormaDeValor forma = FormaDeValor::SinEvidencia;
        uint32_t bloqueado_en = 0; ///< ambito al que no puede elevarse.
        bool por_frontera = false;
        CodigoFrontera frontera = CodigoFrontera::DireccionGuardada;
        CodigoLimitacion limitacion = CodigoLimitacion::ProfundidadAgotada;
        SitioIr causa; ///< donde esta la frontera que lo bloquea.
        /**
         * @brief Si se pudo situar la causa EN ese ambito.
         *
         * A veces un ambito no cierra por si mismo sino por otro que contiene,
         * y entonces la frontera no esta ahi.  El efecto se emite IGUAL
         * diciendo que la causa no se localizo en ese ambito: callarse haria
         * creer que no hay nada que decir, e inventar una causa seria peor.  Ni
         * silencio ni mentira -- se dice exactamente lo que se sabe y lo que
         * no.
         */
        bool causa_localizada = true;
    };
    std::vector<EfectoAlcance> efectos() const;

    // --- nivel C: las dos salen del MISMO perfil ---
    /// Forma vista desde @p universo: solo cuenta lo observado ahi dentro.  La
    /// global es esta misma con el universo del propietario, y se COMPONE
    /// cuando alguien la pide en vez de hornearse.
    FormaDeValor forma_en(uint32_t universo) const;
    FormaDeValor forma() const;
    std::vector<MotivoForma> motivos_forma() const;
};

struct AggregateFactsMap {
    std::vector<AggregateFacts> agregados;

    const AggregateFacts *de(ir::IrValueId ancla) const {
        for (const AggregateFacts &a : agregados)
            if (a.ancla == ancla) return &a;
        return nullptr;
    }
};

/**
 * @brief Observa los valores con componentes de @p fn.
 *
 * Necesita el MODULO porque la frontera no se cierra mirando una sola funcion.
 * Con una funcion suelta se puede decir que NO SE HA VISTO acceso externo;
 * nunca que no lo hay.
 */
AggregateFactsMap observar_agregados(const ir::IrModule &mod,
                                     const ir::IrFunction &fn,
                                     const IrFacts &facts);

/**
 * @brief Igual, pero CONSUMIENDO un points-to que ya se calculo.
 *
 * La forma de arriba lo calcula ella misma, y eso es trabajo repetido en cuanto
 * quien llama ya lo tiene: en el camino del ASA, la base de hechos cachea el
 * points-to de cada funcion para el dominio de memoria y este dominio lo volvia
 * a calcular entero para la misma funcion.
 *
 * Es la Regla 1 -- un pase CONSUME la base, no la CONSTRUYE -- aplicada a un
 * sitio donde no se veia: no habia dos criterios, habia dos COMPUTOS del mismo,
 * que es la otra forma de desperdiciar lo que el ASA existe para compartir.
 *
 * @param pt   Points-to de @p fn, ya calculado por quien llama.
 * @param base Base de hechos compartida, o @c nullptr.  Con ella, las funciones
 *             que el recorrido visita al SEGUIR LLAMADAS tampoco se recalculan:
 *             sin esto, la cache interna las computaba por su cuenta aunque la
 *             base ya las tuviera, que es el mismo desperdicio un nivel mas
 *             adentro.
 */
AggregateFactsMap observar_agregados(const ir::IrModule &mod,
                                     const ir::IrFunction &fn,
                                     const IrFacts &facts, const PointsTo &pt,
                                     FactBase *base = nullptr);

// =========================================================================
//  El modulo entero, y que le pasa entre dos estados
// =========================================================================

/**
 * @brief Identidad de un valor A TRAVES del pipeline.
 *
 * Los value-id se renumeran al optimizar, asi que no sirven para emparejar dos
 * estados.  Lo que sobrevive es DONDE NACE el valor, que ademas es lo que un
 * programador llama "esa variable".
 *
 * @c instancia distingue los casos en que ese sitio NO es unico: si una funcion
 * se inlina dos veces en el mismo llamante, la misma linea del fuente produce
 * dos valores distintos, y sin esto se colapsarian en uno.  Con reservas
 * locales normales vale @c IR_NO_INLINE_SITE y no cambia nada.
 */
struct IdentidadValor {
    std::string funcion;
    uint32_t linea = 0;
    uint32_t indice = 0;    ///< columna, o numero de parametro si linea==0
    uint32_t instancia = 0; ///< sitio de inlinado, si lo hay
    /**
     * @brief Cual de los que comparten sitio es, dentro de UN estado.
     *
     * El cuerpo de un macro se expande varias veces y cada expansion produce un
     * valor distinto con la MISMA posicion del fuente.  Sin esto se colapsan y
     * el informe repite la misma fila sin poder distinguirlas.
     *
     * Es un orden de aparicion, y por eso NO sirve para emparejar entre
     * estados: si una transformacion se lleva uno de los del grupo, el resto se
     * renumera.  Para eso esta la regla de multiplicidad de
     * @c comparar_estados, que prefiere no emparejar a emparejar mal.
     */
    uint32_t orden = 0;

    /// Sin el @c orden: identifica el SITIO, no cual de los de ese sitio.
    bool mismo_sitio(const IdentidadValor &o) const {
        return funcion == o.funcion && linea == o.linea && indice == o.indice &&
               instancia == o.instancia;
    }
    bool operator<(const IdentidadValor &o) const {
        if (funcion != o.funcion) return funcion < o.funcion;
        if (linea != o.linea) return linea < o.linea;
        if (indice != o.indice) return indice < o.indice;
        if (instancia != o.instancia) return instancia < o.instancia;
        return orden < o.orden;
    }
};

/// Lo observado de un modulo entero, en UN estado.
struct ObservacionModulo {
    std::vector<std::pair<IdentidadValor, AggregateFacts>> valores;
};

ObservacionModulo observar_modulo(const ir::IrModule &mod);

/// Que le paso a un valor entre dos estados.  ASA no juzga la transformacion:
/// dice que se observo a cada lado.
enum class TipoTransicion : uint8_t {
    Sobrevive = 0, ///< sigue ahi con la misma forma.
    Desaparece =
        1, ///< la transformacion se lo llevo: eso CONFIRMA que ocurrio.
    CambiaForma = 2, ///< lo que hay que mirar: una transformacion no deberia
                     ///< alterar la naturaleza semantica de un valor.
    Aparece = 3,     ///< no estaba antes y esta despues.
    /**
     * @brief Varios valores comparten sitio y su numero cambio entre estados.
     *
     * Emparejarlos por orden de aparicion seria inventarse la correspondencia:
     * si una transformacion se llevo uno del grupo, el resto se renumera y cada
     * emparejamiento sale corrido.  Decir que no se puede es la respuesta
     * honesta; una transicion equivocada es peor que ninguna, porque describe
     * un cambio que no ocurrio.
     */
    NoEmparejable = 4,
};

const char *nombre_transicion(TipoTransicion t);

struct TransicionValor {
    IdentidadValor valor;
    TipoTransicion tipo = TipoTransicion::Sobrevive;
    FormaDeValor antes = FormaDeValor::SinEvidencia;
    FormaDeValor despues = FormaDeValor::SinEvidencia;
};

/**
 * @brief Empareja dos estados del MISMO modulo y dice que cambio.
 *
 * Solo tiene sentido entre estados relacionados: dos observaciones de modulos
 * distintos no estan en la misma cadena de transformacion, y compararlas no
 * compara nada.  Eso lo garantiza quien llama.
 *
 * Vive aqui y no en el informe porque no es una cuestion de presentacion: es un
 * hecho sobre el programa, y lo van a querer tanto quien lo lee como quien
 * entrena un modelo con ello.
 */
std::vector<TransicionValor> comparar_estados(const ObservacionModulo &antes,
                                              const ObservacionModulo &despues);

/**
 * @brief Volcado de MEDICION de todo un modulo, a `stderr`.
 *
 * Responde a "¿este analisis distingue algo?" ANTES de que nadie lo consuma. Un
 * clasificador que mete todo en la misma casilla pasa desapercibido si primero
 * se engancha y luego se mira; medir antes es lo unico que lo destapa, y ya lo
 * destapo dos veces.  Solo se activa con `VESTA_ASA_FORMAS`.
 *
 * @param etapa NOMBRE de la etapa.  El estado se identifica ademas con un
 *        contador: la misma etapa se recorre VARIAS VECES por compilacion -- el
 *        emisor se invoca mas de una vez -- y agruparlas bajo una etiqueta hace
 *        que el mismo valor parezca tener dos formas a la vez.  MEDIDO: 3443
 *        observaciones incoherentes consigo mismas, todas por esto.
 *
 * @param momento ESTADO del pipeline en el que se observa.  No es una etiqueta
 *        decorativa: antes y despues de optimizar son dos contextos distintos
 *        del mismo programa, cada uno con su verdad, y mezclarlos hace creer
 * que lo que se ve es "los agregados del programa" cuando en realidad es "los
 * que sobrevivieron".  Ninguno de los dos es el correcto.
 */
void volcar_formas(const ir::IrModule &mod, const char *momento);

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_AGGREGATE_FACTS_H
