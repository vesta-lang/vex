/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file analysis/asa/fact_file.h
 * @brief Los hechos, en disco: lo que solo se sabe al BAJAR el codigo sobrevive
 *        al primer acierto de cache.
 *
 * EL PROBLEMA QUE RESUELVE.  Hay conocimiento que no se puede recalcular
 * mirando el modulo ya compilado porque nacio ANTES, mientras se bajaba: que
 * exige del procesador un bloque de asm, por que no se pudo demostrar algo, que
 * ligaduras habia.  Sin esto, la primera vez el compilador avisa y la segunda
 * -- con la cache caliente -- se calla, y el aviso depende de si alguien borro
 * un directorio.  Un diagnostico que va y viene solo no es un diagnostico.
 *
 * QUE SE GUARDA.  El criterio NO es "recomputable si o no", es el COSTE:
 *
 *      no recomputable          siempre (si no se guarda, se perdio)
 *      recomputable y caro      se guarda (cuesta mas rehacerlo que leerlo)
 *      recomputable y barato    no se guarda
 *
 * Y como el coste depende del TAMAÑO del modulo, no puede ser una regla fija en
 * el codigo: cada dominio dice CUANTO le costo producir lo suyo
 * (@c DomainCost) y con eso se decide.  Un modulo pequeño no engorda su cache;
 * uno grande si, que es justo donde compensa.
 *
 * EL FORMATO, y por que es asi.  Registros AUTO-DESCRIPTIVOS por dominio, cada
 * uno con su LONGITUD delante:
 *
 *      cabecera   magia + version + compilador + modulo + cuantos hechos
 *      registro   [dominio][version][huella][suma][cuantos][longitud][cuerpo]
 *      cola       indice dominio -> posicion, para leer solo lo que se pida
 *
 * La longitud por delante es lo importante: un lector que no conoce un dominio
 * LO SALTA en vez de fallar.  Añadir un productor no invalida las caches
 * escritas antes ni obliga a subir una version global, y cada dominio versiona
 * LO SUYO -- cambiar su contenido descarta sus registros, no el fichero entero.
 * Es el mismo reparto que hacen ELF o PNG, y por la misma razon.
 *
 * Cada registro lleva ademas la SUMA DE COMPROBACION de su cuerpo, y se mira
 * antes de creerse una sola cifra.  Sin ella, un byte estropeado dentro de un
 * numero da otro numero igual de valido y el compilador razonaria sobre hechos
 * falsos sin que nadie se entere -- que es peor que no tener cache.  Va por
 * registro, como la huella, para no perder la granularidad: unos bytes malos
 * tiran ese dominio, no el fichero.
 *
 * Y la HUELLA VA POR REGISTRO, no solo en la cabecera: cada dominio se valida
 * por su cuenta contra lo que hoy dependeria, asi que tocar algo que solo le
 * afecta a el descarta su registro y deja en pie los demas.  Cuanto menos haya
 * que invalidar, menos hay que rehacer -- y con una unica huella global,
 * cambiar una linea obligaria a recalcularlo todo.
 *
 * Y LA VERSION DEL COMPILADOR va en la cabecera, aparte de la del modulo.  Un
 * hecho no lo dice el codigo: lo dice el ANALISIS que lo miro, asi que cambiar
 * el compilador puede cambiar lo que se sabe del mismo programa sin que su
 * fuente se haya tocado.  Sin este campo, un compilador nuevo leeria las
 * conclusiones del viejo y las daria por suyas.  Es un campo y no algo mezclado
 * en la huella del modulo a proposito: asi el motivo se puede contar -- "esto
 * lo escribio otro compilador" y "esto es de otro programa" se arreglan de
 * formas distintas.
 *
 * DONDE VIVE.  En un fichero propio al lado del `.vxir`, con la huella del
 * modulo dentro: si no cuadra, se descarta y se recalcula.  Aparte del IR
 * porque el IR lo lee CADA compilacion y esto casi nadie, y porque ampliar lo
 * que el compilador sabe no debe versionar lo que se ejecuta.
 */
#ifndef ANALYSIS_ASA_FACT_FILE_H
#define ANALYSIS_ASA_FACT_FILE_H

#include "analysis/asa/fact_store.h"

#include <cstdint>
#include <string>
#include <vector>

namespace analysis {
namespace asa {

/// Version del CONTENEDOR (cabecera, troceado en registros, indice).  Se sube
/// solo si cambia el sobre; el contenido de cada dominio versiona aparte.
constexpr uint16_t kContainerVersion = 1;

/// Version del layout de un HECHO.  La 2 anade el ambito (donde vale); la 3, el
/// POR QUE de ese ambito y la CLASE de lo que no se supo -- sin ellos, la cache
/// devolvia hechos sin justificar y convertia cualquier motivo en "no
/// preguntado".  Va en cada registro: cambiarla descarta los registros viejos
/// de todos los dominios, pero no rompe el fichero.
constexpr uint16_t kFactVersion = 3;

/**
 * @brief Cuanto se guarda.  Ajustable con @c VESTA_ASA_CACHE.
 *
 * Dos reglas lo hacen sano, y no son opcionales:
 *
 *  - El nivel NO entra en la identidad de lo cacheado.  Escribir con @c Todo y
 *    compilar despues con @c Minimo no invalida nada: lo que hay en disco sigue
 *    valiendo, solo se deja de producir mas.  Los niveles son MONOTONOS (cada
 *    uno contiene al anterior), asi que "esta esto guardado?" no depende del
 *    nivel con que se escribio.  Si el nivel se mezclara con la huella, cambiar
 *    de nivel tiraria caches validas -- justo lo que se quiere evitar.
 *  - El nivel NO puede afectar a la CORRECCION.  En los cuatro, el codigo
 *    generado es identico; lo unico que cambia es cuanto hay que rehacer.  Si
 * un nivel cambiara la salida dejaria de ser una cache, y volveriamos a que el
 *    programa dependa de si habia cache.
 */
enum class CacheLevel : uint8_t {
    Off = 0,     ///< no guardar nada.  Es la herramienta para contestar a "esto
                 ///< es la cache o es el codigo?" sin borrar ficheros a mano.
    Minimum = 1, ///< solo lo que no se puede recalcular.
    ByCost = 2,  ///< DEFECTO: lo caro tambien.  Se ajusta solo a la maquina.
    All = 3,     ///< todo lo que se sepa guardar.
};

/**
 * @brief Suma de comprobacion de un registro, saltandose el hueco donde ella
 *        misma vive.
 *
 * Es parte del CONTRATO del formato, no un detalle: el que escribe y el que lee
 * tienen que calcularla igual, y dos copias que se separen una linea harian
 * ilegible toda cache escrita por la otra version -- con el sintoma inutil de
 * "la cache no funciona".  Publica ademas porque quien pruebe el formato
 * necesita poder fabricar un fichero VALIDO de otra version, que no es lo mismo
 * que uno corrupto.
 *
 * @param d    Bytes.
 * @param ini  Donde empieza el registro.
 * @param suma Donde esta el hueco de la suma (8 bytes que se saltan).
 * @param fin  Donde acaba el registro.
 * @return La suma.
 */
uint64_t record_checksum(const uint8_t *d, size_t ini, size_t suma, size_t fin);

/**
 * @brief Suma del fichero ENTERO, que cubre lo que las de cada registro no
 *        pueden: la cabecera, el indice de la cola y los huecos.
 *
 * @param d Bytes.
 * @param n Cuantos (el fichero completo, con su cola).
 * @return La suma que deberia llevar dentro.
 */
uint64_t file_checksum(const uint8_t *d, size_t n);

/// Cuanto ocupa la cola: desplazamiento del indice + suma global + magia final.
constexpr size_t kTailBytes = 8 + 8 + 4;

/// El nivel en vigor, leido una vez de @c VESTA_ASA_CACHE (0..3).
CacheLevel cache_level();

/// Nombre estable del nivel, para volcados y depuracion.
const char *level_name(CacheLevel n);

/**
 * @brief Lo que un dominio cuenta de si mismo para decidir si se guarda.
 *
 * Es el productor quien sabe estas dos cosas; el fichero solo aplica el
 * criterio.  Sin @c micros el nivel @c PorCoste no puede decidir, y sin
 * @c recomputable el nivel @c Minimo no sabe que es imprescindible.
 */
struct DomainCost {
    const char *domain = "?";
    long micros = 0;          ///< lo que costo producirlo.
    bool recomputable = true; ///< false = se perdio si no se guarda.
    /**
     * @brief Huella de LO QUE ESTE DOMINIO MIRO, no del modulo entero.
     *
     * Es lo que hace la cache GRANULAR: cada registro se valida por su cuenta,
     * asi que tocar algo que solo afecta a un dominio descarta ese registro y
     * deja en pie los demas.  Con una unica huella global, cambiar una linea
     * obligaria a rehacerlo todo -- y cuanto menos haya que invalidar, menos
     * hay que rehacer.
     *
     * Cero = este dominio no sabe decir de que depende; entonces no se puede
     * comprobar y se acepta lo que haya (que es lo mismo que hoy, no peor).
     */
    uint64_t fingerprint = 0;
};

/**
 * @brief Si @p nivel manda guardar un dominio con ese coste.
 *
 * @param nivel Nivel en vigor.
 * @param c     Lo que el dominio dice de si mismo.
 * @return true si merece ir a disco.
 */
bool should_store(CacheLevel nivel, const DomainCost &c);

/**
 * @brief Empaqueta @p almacen en bytes.
 *
 * @param almacen Hechos a guardar.
 * @param huella  Identidad del modulo; al leer, si no cuadra se descarta todo.
 * @param compilador Identidad de la version del compilador que los produjo
 *                   (@c VXI_COMPILER_BUILD_ID donde este disponible).  Al leer,
 *                   si no cuadra se descarta todo: los hechos son conclusiones
 *                   del analisis, y otro analisis puede concluir otra cosa.
 * @param nivel   Cuanto guardar.
 * @param costes  Lo que cada dominio dice de si mismo.  Un dominio que no
 *                aparezca se trata como recomputable y de coste cero, o sea que
 *                solo entra en el nivel @c Todo.
 * @return Los bytes, o vacio si el nivel es @c Nada o no quedo nada que
 * guardar.
 */
std::vector<uint8_t> serialize(const FactStore &almacen, uint64_t huella,
                               CacheLevel nivel,
                               const std::vector<DomainCost> &costes,
                               uint64_t compilador = 0);

/**
 * @brief POR QUE no se pudo leer.  Es un DATO, no una frase.
 *
 * Quien lo muestre saca el texto del catalogo con @ref diag_code, que es lo
 * que hace que el mismo motivo se lea en el idioma de quien compila.  Un modulo
 * de analisis no escribe mensajes.
 */
enum class ReadReason : uint8_t {
    Ok = 0,        ///< se leyo bien.
    NoFile,        ///< primera compilacion, o se limpio la cache.
    Empty,         ///< existe pero no tiene nada.
    NotAFactFile,  ///< la magia no cuadra: no es esto.
    OtherVersion,  ///< contenedor de otra version.
    OtherModule,   ///< hechos de otro modulo.
    OtherCompiler, ///< los escribio otra version del compilador.
    Truncated,     ///< se corto a mitad de escribirlo.
    Corrupt,       ///< los bytes no son los que se escribieron.
    ReadFailed,    ///< el disco fallo al leerlo.
};

/// El codigo del catalogo con el que se cuenta @p m en el idioma de quien
/// compila.  Vacio para @c Ninguno.
const char *diag_code(ReadReason m);

/// Que paso al leer.  Un fichero que no vale NO es un error: es que hay que
/// recalcular, y el motivo se dice para poder distinguirlo de un fallo real.
struct ReadResult {
    bool ok = false;
    ReadReason reason = ReadReason::Ok;
    uint32_t facts = 0;        ///< depositados en el almacen.
    uint32_t domains = 0;      ///< registros leidos.
    uint32_t skipped = 0;      ///< registros de dominios/versiones ajenas.
    uint32_t stale = 0;        ///< registros cuya huella ya no vale.
    uint32_t out_of_scope = 0; ///< hechos que valen en otro objetivo.
    uint32_t corrupt = 0;      ///< registros cuya suma no cuadra.
    uint32_t lost_proofs = 0;  ///< apoyos en hechos que no se cargaron.
};

/**
 * @brief Deposita en @p destino los hechos de @p datos.
 *
 * FILTRA POR AMBITO: un hecho que dice valer solo en otra arquitectura, otro
 * sistema u otro backend NO se deposita, y se cuenta en
 * @c ReadResult::out_of_scope.  Es lo que permite que un SOLO fichero sirva a
 * todos los objetivos: lo universal -- que es la mayor parte -- se comparte, y
 * solo se descarta lo que de verdad es de otro sitio.  Sin esto habria que
 * separar el fichero entero por objetivo y duplicar tambien lo comun.
 *
 * Un @c here vacio no filtra nada: sirve para leerlo todo (volcados,
 * herramientas) sin decir donde se esta.  Es el DEFECTO a proposito: cargar no
 * es preguntar -- el almacen es un deposito y quien filtra es @c
 * FactStore::find con el ambito de quien pregunta --, y con el filtro puesto
 * por omision todo hecho sellado desaparecia al volver del disco sin que nadie
 * lo notara.
 *
 * EXIGE que los nombres canonicos esten dados de alta antes (ver
 * @c register_canonical_name).  Este fichero es el FORMATO y no conoce a los
 * productores de nadie: quien tenga literales estables los registra, y quien
 * solo lea hechos de dominios ajenos los recibira internados -- se conservan y
 * se pueden leer, pero no se encontraran buscando por un literal que este
 * programa no tiene.
 *
 * REORDENA: los hechos se guardan agrupados por dominio, asi que al volver no
 * estan en el orden en que se afirmaron.  Lo que se conserva es la DERIVACION
 * -- cada hecho sigue apoyandose en el mismo --, no la posicion; quien dependa
 * del orden de llegada esta dependiendo de algo que el fichero no promete.
 *
 * AÑADE: el almacen puede traer hechos ya puestos y los identificadores de las
 * pruebas se recolocan sobre el.  Un registro cuya version no se reconozca se
 * SALTA -- para eso lleva la longitud delante --, y lo que se apoyaba en el
 * pierde ese apoyo en vez de arrastrar una referencia a un hecho que no existe.
 *
 * @param data        Bytes del fichero.
 * @param n           Cuantos.
 * @param fingerprint La que debe llevar dentro; si no cuadra no se lee nada.
 * @param dest        Donde se depositan.
 * @param current     De que depende hoy cada dominio, para anular solo lo suyo.
 * @param compiler    Version del compilador que los produjo.
 * @param here        Desde donde se lee.  Vacio = no se estrecha nada.
 * @return Que se leyo, o por que no.
 */
ReadResult read_facts(const uint8_t *data, size_t n, uint64_t fingerprint,
                      FactStore &dest,
                      const std::vector<DomainCost> &current = {},
                      uint64_t compiler = 0, const Scope &here = Scope{});

/// Lee @p path y deposita en @p dest.  Si no existe, @c motivo lo dice.
ReadResult read_facts_file(const std::string &path, uint64_t fingerprint,
                           FactStore &dest,
                           const std::vector<DomainCost> &current = {},
                           uint64_t compiler = 0, const Scope &here = Scope{});

} // namespace asa
} // namespace analysis

#endif // ANALYSIS_ASA_FACT_FILE_H
