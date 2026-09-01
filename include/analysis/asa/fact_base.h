/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_base.h
 * @brief La base de hechos: lo que se sabe del programa, en UN sitio, con su
 *        procedencia y su certeza, para que quien lo necesite CONSULTE en vez
 *        de redescubrirlo.
 *
 * Es la Regla 1 hecha objeto: un pase CONSUME la base, no la CONSTRUYE.  Vive
 * en @c analysis/ y no en @c jit/ porque no es del JIT: el compilador en
 * caliente es UN consumidor, y lo mismo valen el volcado
 * (@c analysis/asa/dump.h), el nativo o una herramienta.
 *
 * POR QUE IMPORTA MAS ALLA DE AHORRAR UN COMPUTO.  Un consumidor que construye
 * lo que necesita solo puede preguntar por lo que sabe construir: se queda con
 * un dominio y con la precision que ese sitio del codigo se molesto en pedir.
 * Uno que CONSULTA puede cruzar dominios sin cambiar, y sobre todo puede
 * recibir hechos que EL no sabe producir -- los que solo existen ejecutando,
 * que es lo que aportara el C2.  Anadir una fuente de conocimiento pasa a ser
 * anadir un productor, no tocar a cada consumidor.
 *
 * DE DONDE VIENE UN HECHO NO ES ASUNTO DEL CONSUMIDOR.  Analisis estatico,
 * observacion en ejecucion o perfil de corridas anteriores alimentan la MISMA
 * base.  Lo que el consumidor mira es el hecho y su certeza -- que viaja DENTRO
 * del hecho, no la pone quien pregunta.  De ahi sale la guarda: no porque el
 * especulador lo decida, sino porque un hecho observado nace sin demostrar.
 *
 * AMBITO Y VIDA.  Una base vale para UN modulo: dentro de el un nombre
 * identifica una funcion, que es lo que hace legitimo cachear por nombre. Quien
 * la crea la mantiene viva mientras trabaja sobre ese modulo y se la pasa a
 * cada consumidor; el conocimiento se calcula una vez y se reparte.  Sin base,
 * el consumidor se monta la suya como ultimo recurso: correcto, solo sin
 * reparto.
 *
 * MUTAR EL IR CADUCA LOS HECHOS: quien lo toque avisa con @c invalidate.
 */
#ifndef ANALYSIS_ASA_FACT_BASE_H
#define ANALYSIS_ASA_FACT_BASE_H

#include "analysis/asa/fact.h"
#include "analysis/facts/ir_facts.h"
#include "analysis/facts/loop_facts.h"
#include "analysis/facts/loop_iv_bounds.h"
#include "analysis/facts/range_summary.h"
#include "analysis/facts/value_range.h"
#include "analysis/manager/analysis_manager.h"
#include "analysis/memory/points_to.h"

#include <cstddef>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

namespace ir {
struct IrFunction;
struct IrModule;
} // namespace ir

namespace analysis {
namespace asa {

/// Los dominios que hoy guarda la base.  Nombres ESTABLES: son la procedencia
/// que aparece en el volcado, no texto de usuario.
///
/// Se DECLARAN aqui y se definen una sola vez en el .cpp, y eso no es
/// cosmetico: ASA identifica al productor por la DIRECCION del literal
/// (@c Support::depends_on compara punteros).  Con @c constexpr cada unidad de
/// traduccion plegaria la lectura a SU propio literal -- los literales no se
/// unifican entre ficheros objeto -- y el mismo productor dejaria de
/// reconocerse a si mismo visto desde otro fichero.
extern const char *const kProducerStructure;
extern const char *const kProducerRanges;
extern const char *const kProducerMemory;
extern const char *const kProducerBoundary;
extern const char *const kProducerLoops;
/// Como se COLOCA la memoria del programa: lo unico que un compilador con
/// enlazador propio sabe y uno tradicional no.
extern const char *const kProducerLayout;
/// El FLUJO DE CONTROL dentro de un bloque `asm`: cuantos bloques basicos
/// tiene, de que clase es cada terminador y que destinos quedan sin resolver.
extern const char *const kProducerAsmFlow;
/// Que un bucle es en realidad UNA operacion de bloque -- un relleno o una
/// copia escritos largos.  Publico y no interno del productor porque lo
/// afirman DOS sitios: el dominio, mirando el codigo, y el pase que lo reduce,
/// que lo dice justo antes de que el bucle deje de existir.
extern const char *const kProducerBulkMemory;

/// Clave con la que se guarda lo que es del MODULO entero y no de una funcion.
extern const char *const kModuleUnit;

/**
 * @brief Da de alta los nombres de arriba como CANONICOS.
 *
 * Perezoso y a peticion: hace falta antes de leer hechos de disco, porque ASA
 * compara productores por direccion y una cadena recien leida no se
 * reconoceria a si misma.  No es un inicializador estatico a proposito --
 * reservar memoria antes de @c main corre las direcciones de todo lo demas.
 */
void register_asa_canonical_names();

/**
 * @brief Una entrada de la base, tal y como se vuelca.
 *
 * Es DATO, no frase: quien quiera ensenarlo lo formatea.  Lleva el sello de ASA
 * -- certeza, procedencia y de que otros hechos se dedujo -- porque un hecho
 * sin origen no se puede explicar ni depurar, y porque de la certeza depende lo
 * que el consumidor tiene derecho a hacer con el.
 */
struct RecordedFact {
    const char *domain = kProducerStructure;
    std::string function;
    Seal seal;
};

/**
 * @brief Base de hechos compartida.
 *
 * Cachea por funcion y calcula bajo demanda.  Las dependencias entre dominios
 * las anota el @c AnalysisManager solo: cuando el computo de uno pide otro por
 * la base, queda registrado, y asi invalidar el de abajo arrastra al de arriba.
 */
class FactBase {
  public:
    /// Al morir cuenta lo que repartio si se pide con @c
    /// VESTA_ASA_HECHOS_DEBUG: una base compartida que no ahorra ninguna
    /// pregunta es un computo con otro nombre, y eso se ve o no se ve.
    /**
     * @brief Da de alta los nombres canonicos del ASA.
     *
     * Aqui y no en un inicializador estatico: reservar memoria antes de
     * @c main corre las direcciones de todo lo demas, y en un programa que
     * dependa de la alineacion de lo suyo eso cambia si funciona o no.  Y aqui
     * y no dentro del fichero de hechos, que es el formato y no tiene por que
     * conocer a los productores de nadie.
     */
    FactBase();
    ~FactBase();
    FactBase(const FactBase &) = delete;
    FactBase &operator=(const FactBase &) = delete;

    /**
     * @brief Hechos estructurales de @p fn: def-use, sitios de llamada, bucles.
     * @param fn Funcion IR a consultar.
     * @return Los hechos, cacheados mientras viva la base.
     */
    const IrFacts &structure(const ir::IrFunction &fn);

    /**
     * @brief Entre que dos numeros esta cada valor de @p fn.
     * @param fn Funcion IR a consultar.
     * @return Los rangos por valor SSA, cacheados mientras viva la base.
     */
    const RangeFacts &ranges(const ir::IrFunction &fn);

    /**
     * @brief A que memoria puede referirse cada puntero de @p fn.
     * @param fn Funcion IR a consultar.
     * @return La tabla points-to, cacheada mientras viva la base.
     */
    const PointsTo &memory(const ir::IrFunction &fn);

    /**
     * @brief Forma del CFG de @p fn: bucles, cabeceras y profundidad.
     * @param fn Funcion IR a consultar.
     * @return Los hechos de bucle, cacheados mientras viva la base.
     */
    const LoopFacts &loops(const ir::IrFunction &fn);

    /**
     * @brief Hasta donde llega la variable de cada bucle CONTADO de @p fn.
     *
     * Se pide ANTES que los rangos y va DENTRO de ellos, como suelo.  El orden
     * no es casual: esto no consulta rangos -- solo la forma del bucle y las
     * constantes escritas --, asi que puede alimentarlos sin que se muerdan la
     * cola.  Al reves seria imposible.
     *
     * @param fn Funcion IR a consultar.
     * @return Las cotas por valor SSA, cacheadas mientras viva la base.
     */
    const LoopIvBounds &iv_bounds(const ir::IrFunction &fn);

    /**
     * @brief Lo que cruza la frontera de cada funcion del modulo.
     *
     * Es conocimiento DEL MoDULO, no de una funcion: para saber que le llega a
     * un parametro hay que ver a todos los que llaman.  Por eso se cachea una
     * vez por base y no por funcion.
     *
     * @param mod Modulo completo.
     * @return Los resumenes de entrada y salida por funcion.
     */
    const RangeSummaries &boundary(const ir::IrModule &mod);

    /**
     * @brief Los hechos de @p fn han caducado porque su IR cambio.
     * @param fn Funcion IR cuyo conocimiento se descarta (en cascada).
     */
    void invalidate(const ir::IrFunction &fn);

    /**
     * @brief El sello del conocimiento de @p producer sobre @p fn.
     *
     * La certeza NO la pone quien pregunta, viaja DENTRO del hecho, y de ella
     * se sigue lo que el consumidor puede hacer: sobre un hecho @c Proven se
     * puede quitar una comprobacion; sobre uno @c Inferred -- el analisis paro
     * por presupuesto, o manana: lo observado en ejecucion -- hay que dejar
     * red, o sea una guarda.
     *
     * @param producer Uno de los @c kProducer*.
     * @param fn       Funcion IR consultada.
     * @return El sello, o uno @c Unknown si nadie ha preguntado todavia.
     */
    Seal seal(const char *producer, const ir::IrFunction &fn) const;

    /// Igual que @c seal pero para lo que es del modulo entero (la frontera).
    Seal module_seal(const char *producer) const;

    /**
     * @brief Todo lo que la base sabe, en DATOS y en orden estable.
     *
     * Un conocimiento que no se puede volcar no se puede auditar: ni explicar
     * un veredicto, ni ver por que un analisis se callo, ni comprobar que la
     * procedencia es la que se cree.  Ordenado por funcion y dominio para que
     * dos volcados se puedan comparar.
     *
     * @return Una entrada por hecho vivo.
     */
    std::vector<RecordedFact> dump() const;

    /// Preguntas atendidas.  Con @c computations mide el reparto de verdad, que
    /// es lo unico que distingue una base compartida de un computo con otro
    /// nombre.
    size_t queries() const { return queries_; }
    /// Analisis que hubo que ejecutar de verdad (los demas salieron de la
    /// cache).
    size_t computations() const { return computations_; }

  private:
    /// Identidad de @p fn dentro del modulo.  Sin nombre no hay identidad
    /// estable, y entonces vale su direccion: es unica mientras la funcion
    /// viva, que es lo que dura la base.
    static std::string key_of(const ir::IrFunction &fn);

    /// Anota el sello de un hecho recien producido.
    void mark(const char *producer, const std::string &key, Certainty c,
              const char *support = nullptr);

    /// Sellos por (productor, unidad).  Se guardan aparte del resultado porque
    /// el gestor cachea el DATO del dominio; la procedencia es del hecho, y la
    /// llevan todos por igual.
    std::unordered_map<const char *, std::unordered_map<std::string, Seal>>
        seals_;

    AnalysisManager manager_;
    size_t queries_ = 0;
    size_t computations_ = 0;
};

/**
 * @brief Vuelca @p entries por @p out en una linea por hecho.
 *
 * Formato de DEPURACION, no de usuario: los mensajes de usuario salen del
 * catalogo multi-idioma.
 *
 * @param entries Lo devuelto por @c FactBase::dump.
 * @param out     Fichero abierto donde escribir.
 */
void dump_facts(const std::vector<RecordedFact> &entries, FILE *out);

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_FACT_BASE_H
