/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file roots.h
 * @brief Como se entra al grafo: de un artefacto a sus entidades.
 *
 * Todo lo demas del subsistema da por hecho que ya se conoce una huella.  Pero
 * quien depura nunca empieza asi: empieza por `PC = 0x4015c2`, por `frame #7` o
 * por el nombre de una funcion.  Sin algo que convierta eso en una identidad,
 * el grafo es impecable y a la vez inalcanzable.
 *
 *     direccion --> simbolo --> BuildId --> ArtifactMap --> entidad --> resto
 *     \_______________/   \_________________________________________________/
 *      NO es de aqui                          esto si
 *
 * El primer tramo -- de una direccion a un simbolo -- pertenece al ARTEFACTO y
 * no a este subsistema: depende del formato del ejecutable, de su tabla de
 * simbolos y de donde lo cargo el sistema, cosas que cambian con cada objetivo
 * y que aqui no se conocen.  Quien lo sepa lo resuelve y entra por el simbolo.
 * Mezclarlo habria atado el grafo a un formato de binario, que es justo lo que
 * hace a DWARF y PDB inservibles fuera de su mundo.
 *
 * La identidad del artefacto es un @ref BuildId y NO su nombre.  Un fichero
 * llamado `programa` puede ser cinco compilaciones distintas; con el nombre
 * como identidad, un binario viejo se explicaria con los simbolos del nuevo,
 * que es peor que no explicarlo.  Por eso ni Windows busca un PDB por el nombre
 * ni Linux busca un DWARF por el nombre: los dos buscan por identificador de
 * construccion.
 *
 * Un @ref ArtifactMap es un nodo mas -- inmutable, identificado por su
 * contenido
 * -- y por tanto tampoco se encuentra sin su huella.  Lo que rompe el circulo
 * es el @ref RootProvider: el mecanismo de DESCUBRIMIENTO, que es lo unico
 * mutable de todo el subsistema y esta fuera del grafo a proposito.  Es lo
 * mismo que hacen Git, Nix, Bazel, PDB o dSYM: contenido inmutable, y aparte
 * algo que dice cual es la raiz de ahora.
 *
 * Que el mapa si sea un nodo tiene consecuencia practica: dos compilaciones que
 * produzcan los mismos simbolos lo comparten, y una que cambie produce otro sin
 * pisar el anterior, con lo que un binario viejo que siga por ahi sigue siendo
 * explicable.
 */

#ifndef VXDBG_ROOTS_H
#define VXDBG_ROOTS_H

#include "vxdbg/ids.h"
#include "vxdbg/node.h"
#include "vxdbg/store.h"

#include <string>
#include <utility>
#include <vector>

namespace vxdbg {

/// Etiqueta de genero para el identificador de construccion.
struct BuildTag {};

/**
 * @brief Identifica UNA compilacion concreta.
 *
 * Sale del contenido del artefacto, no de como se llame ni de donde este.  Es
 * lo que sobrevive a que lo renombren, lo muevan, le quiten los simbolos o lo
 * manden a otra maquina, y por tanto lo unico con lo que tiene sentido pedir su
 * informacion de depuracion.
 */
using BuildId = NodeId<BuildTag>;

/**
 * @brief Que simbolos de un artefacto corresponden a que entidades.
 *
 * Los simbolos son los que el artefacto lleva de verdad -- las etiquetas que
 * quedan en el codigo generado -- y no los nombres del fuente: es lo unico que
 * una direccion puede llegar a dar.
 *
 * No se llama indice porque no lo es: un indice es una estructura auxiliar que
 * se puede tirar y reconstruir.  Esto es conocimiento -- que simbolo salio de
 * que declaracion -- que solo tuvo quien compilo, y si se pierde no hay de
 * donde sacarlo.
 *
 * Hoy solo lleva simbolos.  Acabara siendo la RAIZ PUBLICA del artefacto: de
 * que compilacion salio, cual es su entidad principal, que funciones
 * intermedias y que modulos contiene.  Se anadira cuando esas capas existan de
 * verdad; ponerlo ahora seria adivinar la forma de algo que todavia no hay.
 */
struct ArtifactMap {
    /// v2: @ref modules.
    static constexpr uint32_t kSchemaVersion = 2;
    DebugNodeHeader header{NodeKind::ArtifactMap, kSchemaVersion, {}};

    /// Ordenados por simbolo, para poder buscar sin construir nada al leer.
    std::vector<std::pair<std::string, LanguageEntityId>> symbols;

    /**
     * @brief Mapas de OTROS modulos que este artefacto contiene.
     *
     * POR QUE.  El grafo de un modulo se emite al bajarlo, y bajar se salta si
     * el modulo viene de su cache.  Sin esto, sus simbolos no llegaban al mapa
     * del artefacto y su grafo quedaba sin nadie que lo sostuviera: en un arbol
     * de trabajo, `atomic.vx` o `vx_fiber.vx` aparecian con 1-2 referencias
     * frente a las 14 de `main.vx`, y no porque se usaran menos.
     *
     * Un modulo guarda su propio mapa -- que es un @ref ArtifactMap igual que
     * este, porque es exactamente lo mismo: simbolo a entidad -- y aqui se cita
     * su huella.  Un modulo servido desde cache aporta esa huella sin volver a
     * emitir nada: el grafo ya esta guardado y es el mismo, porque la clave es
     * el contenido.
     *
     * Se citan en vez de copiarse por lo que cuesta lo contrario a escala: con
     * seis mil modulos, copiar sus simbolos aqui haria un mapa enorme por cada
     * ejecutable, y recorrerlo obligaria a abrirlos todos.  Citandolos, el
     * artefacto sigue siendo UN nodo y quien recorre baja solo por donde
     * necesita.
     */
    std::vector<ContentHash> modules;

    /**
     * @brief Busca la entidad de un simbolo.
     * @param symbol Nombre tal como aparece en el artefacto.
     * @return Su entidad, o una vacia si el simbolo no consta.
     */
    LanguageEntityId find(const std::string &symbol) const;

    /**
     * @brief Anade una correspondencia, manteniendo el orden.
     * @param symbol Simbolo.
     * @param entity Entidad.
     */
    void add(std::string symbol, LanguageEntityId entity);
};

/**
 * @brief Un tramo de fuente: donde empieza y cuanto ocupa.
 */
struct SourceExtent {
    std::string symbol; ///< funcion a la que pertenece
    uint32_t line = 0;
    uint32_t column = 0; ///< base 1
    uint32_t length = 0; ///< en bytes
};

/**
 * @brief Los tramos de fuente de un artefacto.
 *
 * Con la linea sola no se puede senalar QUE fallo: en
 * `return foo(a) / bar(b);` hay tres candidatos y comparten linea.  Con la
 * columna y la longitud se subraya el culpable.
 *
 * El tramo lo produce quien compila -- el arbol ya lo tiene -- y viaja hasta
 * aqui: reconstruirlo al fallar seria adivinar.
 */
struct SpanMap {
    static constexpr uint32_t kSchemaVersion = 1;
    DebugNodeHeader header{NodeKind::SpanMap, kSchemaVersion, {}};

    /// Ordenados por (simbolo, linea), para buscar sin construir nada al leer.
    std::vector<SourceExtent> extents;

    /**
     * @brief Busca el tramo de una linea dentro de una funcion.
     * @param symbol Funcion.
     * @param line Linea.
     * @return El tramo, o uno vacio si no consta.
     */
    SourceExtent find(const std::string &symbol, uint32_t line) const;

    /**
     * @brief Anade un tramo manteniendo el orden.
     * @param e Tramo.
     */
    void add(SourceExtent e);

    /**
     * @brief Construye el mapa de golpe a partir de todos los tramos.
     *
     * Hace lo mismo que llamar a @c add con cada uno, pero sin pagar el precio
     * de ir manteniendo el orden a cada paso: insertar en medio de un vector
     * ordenado desplaza toda la cola, y cada elemento desplazado arrastra su
     * cadena.  Con un tramo por sentencia eso es cuadratico en el numero de
     * sentencias del fichero, y era lo mas caro de compilar.
     *
     * Aqui se ordena UNA vez.  El orden es estable a proposito: cuando una
     * linea tiene varias sentencias se queda la PRIMERA, que es exactamente lo
     * que hacia el otro camino, y sin estabilidad se quedaria una cualquiera.
     *
     * @param in Los tramos, en cualquier orden (se consume).
     */
    void build(std::vector<SourceExtent> in);
};

/**
 * @brief De donde se saca el mapa de un artefacto.
 *
 * Se declara como interfaz porque el mismo grafo se va a alcanzar de maneras
 * muy distintas segun donde este: dentro del propio ejecutable, en la cache de
 * quien compilo, en un fichero al lado, o en un servidor al otro extremo de la
 * red. Quien resuelve una traza no deberia enterarse de cual fue.
 *
 * Sin esta separacion, anadir manana un servidor de simbolos o un depurador
 * remoto obligaria a tocar todo lo que hoy busca en disco.
 */
class RootProvider {
  public:
    virtual ~RootProvider() = default;

    /**
     * @brief Da el mapa de una compilacion.
     *
     * Devuelve el MAPA y no su huella: que exista un almacen direccionado por
     * contenido es asunto de quien lo provee, no de quien pregunta.  El dia que
     * venga de un servidor, comprimido o embebido en el propio ejecutable,
     * quien resuelve una traza no tiene que cambiar ni enterarse de que antes
     * hubo una huella por medio.
     *
     * @param build De que compilacion.
     * @param out_map Recibe el mapa.
     * @return @c true si se encontro.
     */
    virtual bool lookup(BuildId build, ArtifactMap &out_map) const = 0;

    /**
     * @brief Da los tramos de fuente de una compilacion.
     * @param build De que compilacion.
     * @param out_spans Recibe los tramos.
     * @return @c true si constaban.
     */
    virtual bool lookup_spans(BuildId build, SpanMap &out_spans) const = 0;
};

/**
 * @brief La cache local, que es donde deja las cosas el compilador.
 *
 * Sirve al interprete y al compilador al vuelo: ahi la informacion se genera
 * siempre y nunca sale de la maquina.
 *
 * Se llama repositorio y no proveedor porque hace las dos cosas: da y guarda.
 * Los que vengan despues -- una seccion del ejecutable, un fichero al lado, un
 * servidor de simbolos -- solo daran, y seran proveedores a secas.
 */
class CacheRootRepository : public RootProvider {
  public:
    /**
     * @param dir Carpeta donde viven los apuntadores.
     * @param store De donde salen los nodos.
     */
    CacheRootRepository(std::string dir, const NodeStore &store)
        : dir_(std::move(dir)), store_(store) {}

    bool lookup(BuildId build, ArtifactMap &out_map) const override;
    bool lookup_spans(BuildId build, SpanMap &out_spans) const override;

    /**
     * @brief Deja constancia de que mapa corresponde a una compilacion.
     *
     * Lo escrito aqui es lo unico mutable del subsistema, y lo es por
     * necesidad: un almacen por contenido no tiene por donde empezar.  Va en su
     * propia carpeta para que nadie lo confunda con un nodo.
     *
     * La RUTA del artefacto se guarda como PISTA, no como identidad -- la
     * identidad sigue siendo el contenido, que es lo que sobrevive a que lo
     * muevan.  Sirve para una sola cosa: saber que un apuntador quedo
     * SOBRESCRITO.  Si en esa ruta hay ahora un fichero cuyo identificador es
     * otro, este ya no describe nada, y eso se comprueba rehaciendo la huella
     * de sus bytes; no se cree la ruta, solo se usa para saber donde mirar.
     *
     * Sin ella no habria forma de retirar apuntadores sin elegir a dedo o sin
     * mirar el reloj: se acumula uno por compilacion y nada los quita.  Medido:
     * 12.776 apuntadores ocupando 16 MB, mas que los propios paquetes, y de
     * todos ellos apenas unos cientos pueden corresponder a un fichero que
     * exista.
     *
     * Va en su propia linea al final para que lo escrito antes se siga leyendo
     * igual: quien no la encuentre se queda sin la pista, no sin el apuntador.
     *
     * @param build De que compilacion.
     * @param map Huella de su mapa.
     * @param spans Huella de sus tramos, si los hay.
     * @param artifact_path Donde se escribio.  Vacio = sin pista.
     * @return @c true si se escribio.
     */
    bool publish(BuildId build, ContentHash map,
                 ContentHash spans = ContentHash{},
                 const std::string &artifact_path = std::string()) const;

  private:
    /// @return Ruta del apuntador de una compilacion.
    std::string path_for(BuildId build) const;

    std::string dir_;
    const NodeStore &store_;
};

} // namespace vxdbg

#endif // VXDBG_ROOTS_H
