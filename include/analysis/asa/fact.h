/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact.h
 * @brief NUCLEO de ASA: que es un hecho, de donde viene y cuanto se puede uno
 *        fiar de el.  Vocabulario UNICO para todos los dominios.
 *
 * ASA no es un analisis: es la base de conocimiento del compilador.  Un dominio
 * (rangos, regiones, efectos, agregados, prestamos, bucles) DESCUBRE hechos;
 * los consumidores (comprobaciones de seguridad, optimizador, diagnosticos,
 * herramientas) deciden que hacer con ellos.  Este fichero define lo unico que
 * todos comparten, y existe por una razon concreta:
 *
 *   SI CADA DOMINIO INVENTA SU PROPIA PALABRA PARA "SEGURO", "DE DONDE SALE" Y
 *   "HECHO", CRUZARLOS DEJA DE SER POSIBLE.  No se puede combinar lo que no se
 *   mide igual, y lo que hace util una base de conocimiento es justo cruzarla.
 *
 * Tres piezas, y ninguna es decorativa:
 *
 *   CERTEZA      cuanto te puedes fiar.  Va DENTRO del hecho, no en el
 *                consumidor: si cada consumidor decide por su cuenta si algo es
 *                fiable, el mismo hecho justifica cosas contradictorias.
 *   PROCEDENCIA  quien lo descubrio y mirando que.  Sin esto no se puede
 *                explicar un veredicto ni depurar un analisis que miente.
 *   DEPENDENCIAS de que otros hechos se dedujo.  Un hecho derivado no puede ser
 *                mas fuerte que el peor de los que lo sostienen, y sin
 *                declararlas no hay forma de invalidarlo cuando uno cambia.
 */
#ifndef ANALYSIS_ASA_FACT_H
#define ANALYSIS_ASA_FACT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace analysis {
namespace asa {

/**
 * @brief Confianza de un hecho.  El orden importa: a mayor valor, mas fuerte.
 *
 * La frontera que decide es la de arriba:
 *
 *   Unknown   no hay evidencia suficiente.  NO es "falso": es que no se ha
 *             mirado, o lo mirado no dice nada.  Distinguirlo de "falso" es lo
 *             que impide que un analisis ciego parezca uno concluyente.
 *   Inferred  la evidencia apunta ahi, pero pudo quedar algo sin ver.  Sirve
 *             para OPTIMIZAR CON RED: especular con un guard, elegir una
 *             version rapida con camino de vuelta.
 *   Proven    se ha visto TODO lo que podria contradecirlo.  Es lo unico sobre
 *             lo que se puede rechazar un programa o quitar una comprobacion
 *             sin dejar red.
 *
 * NO confundir con el VEREDICTO sobre una propiedad ("esto es seguro / no lo
 * es"): son ejes distintos.  Un hecho Proven puede afirmar que algo NO es
 * seguro.  Aqui se mide cuanto te fias de la afirmacion, no lo que dice.
 */
enum class Certainty : uint8_t {
    Unknown = 0,
    Inferred = 1,
    Proven = 2,
};

/**
 * @brief POR QUE no se sabe.  Califica a @c Certainty::Unknown.
 *
 * "Unknown" metia en el mismo cajon cosas que se arreglan de formas distintas,
 * y esa es la diferencia que hace util un "no lo se".  El caso que mas importa
 * es el segundo: cuando el analisis no pudo mirar porque el codigo no tiene una
 * forma que reconozca, se puede decir QUE ESCRIBIR para que pase a ser
 * demostrable.  Eso es accionable; un porcentaje de confianza no lo es.
 *
 * Cada dominio conserva ADEMAS su codigo propio (`asm_flujo.terminador_
 * desconocido`), que dice el caso exacto y de donde sale el mensaje del
 * catalogo.  Esto dice la CLASE, que es lo que decide la accion y por lo que
 * pregunta un consumidor que no conoce el dominio.
 *
 * La lista es CERRADA a proposito: cada valor lleva una accion detras, y uno
 * que no la tenga no ayuda a nadie.  Antes de anadir otro, la pregunta es "que
 * puede hacer quien lo lea".
 */
enum class UnknownReason : uint8_t {
    /// Ni se miro.  No es lo mismo que haber mirado sin sacar nada, y por eso
    /// existe: el silencio de lo no mirado no dice donde ampliar el analisis.
    NotAsked = 0,
    /// Se miro y NO HABIA NADA QUE DECIR: la funcion no tiene bucles, el valor
    /// no es un puntero.  No es ignorancia -- se sabe perfectamente --, y
    /// mezclarlo con los demas inflaba el recuento de "no supe" con casos donde
    /// no hay nada que arreglar.  Se descubrio clasificando los sitios reales,
    /// no disenando la lista en abstracto.  Accion: ninguna, y eso es util:
    /// dice al consumidor que aqui no hay nada que mirar.
    NothingToSay,
    /// Se miro y de verdad depende de un valor que solo existe al ejecutar.
    /// Accion: una precondicion, una comprobacion, o especular con guarda.
    RuntimeDependent,
    /// El analisis no cubre esa FORMA.  Accion: se puede decir que escribir
    /// para que pase a ser demostrable.  Es el que mas valor tiene.
    ShapeNotRecognized,
    /// Se renuncio por presupuesto (demasiados caminos, bucle muy grande).
    /// Accion: subir el limite o simplificar.  NO es culpa del programa, es del
    /// analisis, y decirlo asi es lo honesto.
    BudgetExceeded,
    /// Cruza algo por lo que no se ve: un `extern` sin efectos declarados, un
    /// `dlsym`, un puntero a funcion sin resolver, `asm` sin ligaduras.
    /// Accion: declararlo.  Ademas se puede CUANTIFICAR lo que cuesta no
    /// hacerlo, siguiendo el grafo de dependencias.
    OpaqueBoundary,
    /// Depende de otro hecho que tampoco se sabe.  Accion: arreglar aquel, y
    /// este cae solo.  Se dice cual.
    MissingDependency,
    /// Dos productores del mismo hecho no coinciden.  Eso NO es una limitacion
    /// del analisis: es un fallo del compilador, y tiene que gritar.
    SourcesDisagree,
};

/// Nombre estable para volcados.  NO es texto de usuario.
const char *unknown_reason_name(UnknownReason r);

/**
 * @brief El codigo del catalogo con el que se le cuenta al usuario.
 *
 * Separado del nombre de arriba a proposito, y no por gusto: el de arriba
 * identifica la clase en un volcado de depuracion y no se traduce nunca; este
 * es el que sale por pantalla, en el idioma de quien compile, con su ACCION
 * dentro del mensaje.  Un motivo sin accion no le sirve a nadie -- "no pude"
 * solo enfada; "no pude porque cruza un extern sin efectos declarados,
 * declaralos" se arregla --.
 *
 * @param r Clase del no saber.
 * @return Codigo estable (`VXA06x`) del catalogo multi-idioma.
 */
const char *unknown_reason_code(UnknownReason r);

/// La confianza de algo deducido de varias cosas es la MAS DEBIL de todas: una
/// cadena no es mas fuerte que su eslabon peor.
inline Certainty weakest(Certainty a, Certainty b) {
    return a < b ? a : b;
}

/// Nombre estable para volcados y depuracion.  NO es texto de usuario: los
/// mensajes salen del catalogo i18n, nunca de aqui.
inline const char *certainty_name(Certainty c) {
    switch (c) {
    case Certainty::Proven: return "proven";
    case Certainty::Inferred: return "inferred";
    default: return "unknown";
    }
}

/**
 * @brief De DONDE sale un hecho.  Ojo: no es su certeza.
 *
 * La certeza es lo que decide al consumidor -- usar directamente, usar con
 * guarda, o no suponer nada -- y va aparte a proposito.  Esto dice quien lo
 * vio, que sirve para explicarlo y depurarlo, no para decidir.  Justo por eso
 * un consumidor puede pasar de mirar la fuente: dos hechos de origen distinto
 * con la misma certeza se tratan igual.
 */
enum class Source : uint8_t {
    Static,   ///< leyendo el programa, sin ejecutarlo.
    Runtime,  ///< observado corriendo: cierto en lo visto, no en general.
    Profile,  ///< medido en corridas anteriores.
    Declared, ///< lo afirma el programador (un contrato).  Se VERIFICA, no se
              ///< cree.
};

/// Nombre estable para volcados.  No es texto de usuario.
const char *source_name(Source s);

/**
 * @brief Quien descubrio un hecho y mirando que.
 *
 * Un hecho sin procedencia no se puede explicar ni depurar: cuando un veredicto
 * sorprende, la primera pregunta es siempre "de donde ha salido esto".  El
 * @c producer es un literal estatico (el nombre del analisis), no una cadena
 * construida: identifica al modulo, no al caso.
 */
struct Origin {
    Source source = Source::Static;
    const char *producer = "?"; ///< analisis que lo emitio.
    const char *function = "";  ///< funcion mirada (vacio si es de modulo).
    uint32_t site = 0;          ///< value-id, bloque o linea, segun el dominio.
};

/**
 * @brief Que otros hechos sostienen a este.
 *
 * Se guarda por PRODUCTOR, no por instancia: basta para saber a quien invalidar
 * cuando algo cambia, y no obliga a que cada hecho arrastre punteros a otros.
 * Un maximo pequeno y fijo evita que un hecho crezca sin control; si a un
 * dominio le hicieran falta mas dependencias, es senal de que ese hecho hace
 * demasiadas cosas.
 */
struct Support {
    static constexpr int kMax = 4;
    const char *on[kMax] = {nullptr, nullptr, nullptr, nullptr};

    void add(const char *producer) {
        for (int i = 0; i < kMax; ++i) {
            if (on[i] == nullptr) {
                on[i] = producer;
                return;
            }
            if (on[i] == producer) return;
        }
    }
    bool depends_on(const char *producer) const {
        for (int i = 0; i < kMax; ++i)
            if (on[i] == producer) return true;
        return false;
    }
};

/**
 * @brief Lo que TODO hecho de ASA lleva encima, sea cual sea su dominio.
 *
 * Se embebe por composicion en cada hecho concreto en vez de heredarse: los
 * hechos se copian en bucles calientes y viven en vectores, y una jerarquia con
 * funciones virtuales pagaria indireccion en el sitio equivocado.
 */
struct Seal {
    Certainty certainty = Certainty::Unknown;
    /**
     * @brief Por que no se sabe.  Solo tiene sentido con @c Unknown.
     *
     * Va aqui y no aparte porque CALIFICA a la certeza: es la respuesta a la
     * segunda pregunta que se hace quien lee "no lo se", y separarla llevaria a
     * consultarlas por caminos distintos y a que una de las dos se olvidara.
     */
    UnknownReason unknown_reason = UnknownReason::NotAsked;
    Origin origin;
    Support support;
};

// ===========================================================================
// EL HECHO.  La frontera comun: lo que un productor deja y un consumidor lee.
// ===========================================================================

/// Identidad de un hecho dentro de un almacen.  Indice, no puntero: los hechos
/// viven en un vector contiguo y se referencian entre si.
using FactId = uint32_t;
/// "Ningun hecho".  No es el hecho cero.
extern const FactId kNoFact;

/**
 * @brief De QUE habla un hecho.
 *
 * Tipado y no una cadena: el sujeto es la clave por la que un consumidor busca,
 * y compararlo por texto convertiria cada consulta en un parseo.  El nombre de
 * la funcion es un puntero al que guarda el almacen, estable mientras el viva.
 */
struct Subject {
    enum class Kind : uint8_t {
        Module,      ///< el programa entero.
        Function,    ///< una funcion; @c id no se usa.
        Value,       ///< un valor SSA; @c id es su value-id.
        Block,       ///< un bloque basico; @c id es su indice.
        Instruction, ///< una instruccion; @c id es su posicion lineal.
        Symbol       ///< algo con nombre que no es funcion (global, clase).
    };
    Kind kind = Kind::Module;
    const char *function = ""; ///< a quien pertenece (vacio si es del modulo).
    uint32_t id = 0;

    bool operator==(const Subject &o) const {
        return kind == o.kind && id == o.id &&
               (function == o.function || std::string(function) == o.function);
    }
};

const char *subject_kind_name(Subject::Kind k);

/**
 * @brief QUE se afirma, en DATOS.
 *
 * Cada dominio tiene su vocabulario -- un rango no es un prestamo --, pero el
 * ASA exige que la afirmacion sea material y no una frase: un @c code estable
 * que un consumidor puede comparar, los NUMEROS que la acompanan, y un texto
 * SOLO para lo que no cabe en numeros.  Quien decida algo mira @c code y los
 * numeros; el texto es para que lo lea una persona.
 */
struct Claim {
    const char *domain = "?"; ///< quien habla (uno de los productores).
    const char *code = "?";   ///< que dice, en vocabulario estable del dominio.
    int64_t a = 0;            ///< primer numero del hecho (lo, offset, ...).
    int64_t b = 0;            ///< segundo (hi, ancho, profundidad, ...).
    /**
     * @brief Lo que no cabe en dos numeros, INTERNADO en el almacen.
     *
     * Puntero y no cadena propia por dos razones que van juntas: un programa
     * grande produce cientos de miles de hechos y los textos se REPITEN
     * ("vale todo su tipo", "i64", "monton#3"), asi que internarlos guarda una
     * sola copia de cada uno; y comparar dos hechos pasa a ser comparar
     * punteros.  Vive lo que el almacen.
     */
    const char *detail = "";
};

/**
 * @brief COMO se llego a el.
 *
 * @c Support dice de que PRODUCTORES depende (grueso, para invalidar); esto
 * dice de que HECHOS CONCRETOS se dedujo, que es lo que permite recorrer una
 * derivacion hacia atras y ensenarla.  Sin ella, "todo veredicto lleva su
 * prueba" se queda en una intencion.
 */
struct Proof {
    const char *rule = "";    ///< la regla aplicada, nombre estable.
    std::vector<FactId> from; ///< hechos de los que se sigue.
};

/**
 * @brief DONDE vale un hecho.  Un campo vacio quiere decir "en cualquiera".
 *
 * NO TODO LO QUE SE SABE VALE EN TODAS PARTES, y hasta ahora eso no se podia
 * decir: la unica forma de proteger un hecho especifico de una arquitectura era
 * separar el ALMACEN ENTERO por objetivo, con lo que se duplicaba tambien todo
 * lo universal -- que es la mayor parte.  El alcance es propiedad del HECHO, no
 * del sitio donde se guarda: dicho aqui, un solo almacen sirve a todos los
 * objetivos y solo se descarta lo que de verdad es de otro.
 *
 * Los tres ejes son independientes y se cruzan: un hecho puede valer para
 * cualquier backend pero solo en x86-64 (lo que exige una instruccion
 * concreta), o para cualquier ISA pero solo compilando a nativo (lo que impone
 * el enlace), o para todo (que un valor cabe en 32 bits).
 *
 * REGLA AL PRODUCIR: en la duda, el alcance MAS ESTRECHO.  Equivocarse hacia
 * estrecho solo cuesta recalcular; hacia ancho es afirmar en un sitio algo que
 * se comprobo en otro.
 */
// ---------------------------------------------------------------------------
// El VOCABULARIO de los tres ejes.  Un solo sitio.
// ---------------------------------------------------------------------------
// Eran literales sueltos repartidos por tres ficheros, y ya habian divergido:
// `fact.h` documentaba DOS backends, `facts/alignment.h` usaba TRES, y el unico
// sitio que sellaba un hecho escribia siempre "vm".  Un eje cuyo vocabulario no
// esta en ninguna parte no se puede ni completar ni comprobar: nadie sabe si
// falta un valor hasta que un hecho se vuelve invisible.
//
// Se comparan por TEXTO y no por enum a proposito: el ambito viaja al fichero
// de hechos y al MCP, donde un entero no significa nada y un nombre si.  Las
// constantes son para que nadie vuelva a teclearlo.

/// Como se EJECUTA el codigo.  Son tres, no dos: el interprete y el JIT parten
/// del mismo bytecode pero no ejecutan el mismo codigo -- el JIT lo traduce --,
/// y el 2026-08-31 se vio la diferencia: el JIT fallaba donde el interprete no.
///
/// Antes de sellar un hecho aqui, la pregunta es si de verdad depende de COMO
/// se ejecuta o de EN QUE ESTA ESCRITO.  Lo segundo es `isa`, y suele ser lo
/// que se queria decir.
constexpr const char *kBackendVm = "vm";   ///< interprete
constexpr const char *kBackendJit = "jit"; ///< compilado en caliente
constexpr const char *kBackendAot = "aot"; ///< nativo, compilado antes

/// Juego de instrucciones.  El vocabulario tiene que cubrir TODO lo que el
/// proyecto sabe nombrar, o un productor acaba inventandose el suyo -- que es
/// lo que estaba pasando.
///
/// El BYTECODE DE LA MAQUINA ES UNA ISA MAS, y ponerlo aqui deja de mezclar dos
/// preguntas que son distintas: en que juego de instrucciones esta expresado el
/// codigo (`isa`) y como se ejecuta (`backend`).  El interprete y el JIT cargan
/// los dos bytecode -- el JIT ademas lo traduce a x86-64 en caliente --, y el
/// nativo no lo ve nunca.  Asi, lo que vale "porque lo coloco el cargador de la
/// maquina" es un hecho de `isa = velb`, no dos hechos de backend: dice POR QUE
/// vale, y no solo DoNDE.
constexpr const char *kIsaVelb = "velb"; ///< el bytecode de la maquina
constexpr const char *kIsaX8664 = "x86-64";
constexpr const char *kIsaX8632 = "x86-32";
constexpr const char *kIsaArm64 = "aarch64";
constexpr const char *kIsaArm32 = "arm";
constexpr const char *kIsaRiscv = "riscv";

/// Sistema operativo del OBJETIVO, no del que compila.
constexpr const char *kOsWindows = "windows";
constexpr const char *kOsLinux = "linux";

struct Scope {
    const char *isa = "";     ///< @see kIsa*.      "" = cualquiera.
    const char *os = "";      ///< @see kOs*.       "" = cualquiera.
    const char *backend = ""; ///< @see kBackend*.  "" = cualquiera.
    /**
     * @brief POR QUE se restringe.  Vacio solo si el alcance es universal.
     *
     * Afirmar algo obliga a adjuntar su @c Proof; restringirlo no obligaba a
     * nada, y esa asimetria costo meses de silencio: un hecho sellado para el
     * interprete valia tambien con el JIT, nadie tuvo que escribir por que lo
     * limitaba, y al leerlo no habia nada que hiciera saltar la pregunta.
     *
     * Con el motivo escrito, "vale solo con bytecode porque lo coloca el
     * cargador" se lee y se discute; sin el, un `backend = "vm"` suelto no dice
     * si es una propiedad del backend o un descuido.  Es el cuarto invariante
     * -- todo veredicto lleva su prueba -- aplicado al ALCANCE.
     *
     * Nombre estable y corto, del vocabulario del dominio; el texto para una
     * persona sale del catalogo, como todo.
     */
    const char *why = "";

    /// Si un campo del hecho es vacio vale en cualquiera; si no, tiene que
    /// coincidir con el de @p here.
    bool holds_in(const Scope &here) const {
        auto matches = [](const char *mine, const char *theirs) {
            if (mine == nullptr || mine[0] == '\0') return true;
            if (theirs == nullptr) return false;
            for (size_t i = 0;; ++i) {
                if (mine[i] != theirs[i]) return false;
                if (mine[i] == '\0') return true;
            }
        };
        return matches(isa, here.isa) && matches(os, here.os) &&
               matches(backend, here.backend);
    }
    /**
     * @brief Esta el alcance JUSTIFICADO?
     *
     * Universal no necesita motivo -- no restringe nada --; restringido si.
     * Lo comprueba el volcado y no un `assert`: un motivo que falta no invalida
     * el hecho, solo lo deja sin explicar, y abortar la compilacion por una
     * deuda nuestra seria castigar al usuario por ella.
     */
    bool justified() const {
        return universal() || (why != nullptr && why[0] != '\0');
    }

    /// Universal: sin ninguna restriccion.
    bool universal() const {
        return (isa == nullptr || isa[0] == '\0') &&
               (os == nullptr || os[0] == '\0') &&
               (backend == nullptr || backend[0] == '\0');
    }
};

/**
 * @brief Un hecho completo.  Es LA representacion; no hay otra.
 *
 * Da igual que lo produzca el analisis estatico, la observacion en ejecucion o
 * un perfil de corridas anteriores: lo que cambia es el @c Origin y la
 * @c Certainty, que viajan DENTRO.  Un consumidor no pregunta de donde viene:
 * mira lo que dice y cuanto puede fiarse.
 */
struct Fact {
    Claim what;
    Subject about;
    Scope scope; ///< en que objetivos vale (vacio = en todos).
    Seal seal;
    Proof proof;
};

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_FACT_H
