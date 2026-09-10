/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file cache_paths.h
 * @brief Donde va CADA artefacto de cache, y de que ALCANCE es.
 *
 * Dos ejes, y los dos hacen falta.
 *
 * **Por tipo.**  Antes esto estaba repartido: las interfaces y el intermedio
 * caian AL LADO del fuente, los temporales de escritura en `.cache/tmp`, el
 * grafo de depuracion en `.cache/vxdbg`, los resultados de ejecutar al
 * compilar en `.cache/ctpe`, y el gestor de paquetes en `.vx_cache/pkg`,
 * `.vx_cache/work` y `.vx_cache/projects`.  Cinco reglas distintas escritas en
 * seis sitios, y ninguna sabia de las otras.  Costaba de dos maneras: limpiar
 * exigia saberselas todas -- borrar `.cache` dejaba vivos los `.vxi` del arbol
 * de fuentes, y quien media en frio media en caliente sin enterarse --, y el
 * arbol de fuentes se ensuciaba con `a.vxi`, `a.pre.vxfacts` y
 * `a.pre.vxfacts.analysis` junto a `a.vx`, que salian en `git status`
 * mezclados con lo del proyecto sin que nadie supiera si hacian falta.
 *
 * **Por alcance.**  Separar por tipo no basta, porque lo que hay dentro no
 * vale lo mismo: un `.vxi` sale del fuente, de la version del compilador y del
 * objetivo, asi que sirve en CUALQUIER maquina donde esos tres coincidan; los
 * apuntadores de raiz del grafo de depuracion y la cache de proyecto llevan
 * rutas ABSOLUTAS y no sirven en ninguna otra.  Con el alcance declarado se
 * puede archivar o compartir la mitad portable y tirar la local sin pensarlo,
 * y una herramienta puede decir cuanto ocupa cada categoria.
 *
 * Anadir un tipo es anadir aqui una constante y su fila en la tabla del `.cpp`
 * -- nombre y alcance --; no hay ninguna otra tabla que tocar.
 */

#ifndef VESTA_UTIL_CACHE_PATHS_H
#define VESTA_UTIL_CACHE_PATHS_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace util {

/**
 * @brief Hasta donde vale lo que hay en un cajon de la cache.
 *
 * No es una etiqueta descriptiva: es lo que decide si un artefacto se puede
 * copiar a otra maquina o hay que rehacerlo alli.
 */
enum class CacheScope : uint8_t {
    /**
     * Sirve en otra maquina.  Lo que hay dentro se deriva del fuente, de la
     * version del compilador y del objetivo -- los tres entran en la clave --,
     * asi que copiarlo es valido y compartirlo entre proyectos, tambien.
     */
    Portable,
    /**
     * Solo sirve AQUI.  Lleva rutas absolutas de esta maquina, o apunta a
     * artefactos por donde estan.  Copiarlo no da un error: da apuntadores a
     * sitios que en la otra maquina no existen.
     */
    Local,
    /**
     * Nada que conservar.  Es trabajo a medias de un proceso; se puede borrar
     * en cualquier momento, incluso con una compilacion en marcha de otro.
     */
    Transient,
    /**
     * Las dos cosas, y el cajon lo separa por dentro.  Hoy solo el grafo de
     * depuracion: `vxdbg/packs` esta direccionado por CONTENIDO y es portable,
     * mientras que `vxdbg/roots` son apuntadores con rutas absolutas y no lo
     * es.  Quien reparta por alcance tiene que bajar un nivel en este.
     */
    Mixed,
};

/**
 * @brief Los tipos de artefacto que la cache guarda separados.
 *
 * Cada uno es un directorio dentro de la raiz.  La extension distingue lo que
 * comparte cajon: `ir` guarda el `.vxi` y el `.vxir` de un modulo porque nacen
 * y mueren juntos -- son la misma compilacion vista por sus dos caras --.
 */
enum class CacheKind : uint8_t {
    ModuleIr,  ///< interfaz e intermedio de un modulo (`.vxi`, `.vxir`).
    Facts,     ///< lo que el ASA supo de el al bajarlo (`.vxfacts`).
    Analysis,  ///< los analisis del ASA ya calculados (`.analysis`).
    Vel,       ///< su `.vel` suelto, para distribuirlo aparte.
    Bytecode,  ///< el `.velb` ya compilado de un fuente, por su contenido.
    Comptime,  ///< resultados de ejecutar codigo AL COMPILAR.
    DebugInfo, ///< el grafo de depuracion del LENGUAJE (`packs` + `roots`).
    Packages,  ///< descargas y metadatos del gestor de paquetes.
    Projects,  ///< la cache de proyecto entera.
    Work,      ///< area de trabajo del resolutor de dependencias.
    Temp,      ///< temporales de las escrituras atomicas.
};

/// Cuantos tipos hay.  Va detras del ultimo valor del enum.
constexpr size_t kCacheKindCount = static_cast<size_t>(CacheKind::Temp) + 1;

/**
 * @brief El nombre de la raiz de cache, sin ninguna ruta delante.
 * @return @c ".cache" .
 */
const char *cache_root_name() noexcept;

/**
 * @brief El nombre del cajon de @p kind dentro de la raiz.
 *
 * @param kind Tipo de artefacto.
 * @return Nombre del directorio (@c "ir" , @c "facts" , ...).  Nunca nulo.
 */
const char *cache_kind_dir(CacheKind kind) noexcept;

/**
 * @brief Hasta donde vale lo que guarda @p kind .
 *
 * @param kind Tipo de artefacto.
 * @return Su alcance.  @see CacheScope
 */
CacheScope cache_kind_scope(CacheKind kind) noexcept;

/**
 * @brief Nombre del alcance, para poder decirlo en un informe.
 *
 * @param scope Alcance.
 * @return Palabra corta y estable.  Nunca nula.
 */
const char *cache_scope_name(CacheScope scope) noexcept;

/**
 * @brief Sube desde @p start_dir buscando el manifiesto de un PAQUETE.
 *
 * Un paquete es un directorio con `vx.toml` o `vx.json`.  Vive aqui y no en el
 * gestor de paquetes porque tambien lo necesita la cache: es lo que hace que
 * compilar desde una subcarpeta y desde la raiz usen la MISMA.
 *
 * @param start_dir Desde donde subir; vacio para el directorio de trabajo.
 * @return Ruta absoluta de la raiz del paquete, o vacio si no hay ninguno.
 */
std::string project_root_from(const std::string &start_dir);

/**
 * @brief Igual, pero acepta ademas la raiz de una copia de trabajo (`.git`).
 *
 * Es lo que ancla la CACHE, y la diferencia con la de arriba no es un detalle:
 * la mayoria de los directorios desde los que se invoca al compilador no son
 * un paquete -- un banco de pruebas, una carpeta de herramientas, el caso de
 * un test --, y sin este segundo criterio cada uno estrenaba su propia cache.
 * En este mismo repositorio llegaron a convivir noventa, repartidas por el
 * arbol, con el mismo trabajo repetido dentro y sin enterarse unas de otras.
 *
 * El manifiesto sigue mandando cuando lo hay: un paquete dentro de un arbol
 * mayor es una unidad propia y su cache le pertenece.
 *
 * @param start_dir Desde donde subir; vacio para el directorio de trabajo.
 * @return Ruta absoluta de la raiz del arbol, o vacio si no hay ninguna.
 */
std::string tree_root_from(const std::string &start_dir);

/**
 * @brief La raiz de la cache, resuelta UNA vez por proceso.
 *
 * Por orden: la valvula @c VX_CACHE_DIR , que gana siempre y permite que
 * varios proyectos compartan la cache de las librerias comunes; la raiz del
 * proyecto, para que compilar desde una subcarpeta no estrene otra; y el
 * directorio de trabajo cuando no hay proyecto.
 *
 * @return Ruta de la raiz.  La referencia vive lo que el proceso.
 */
const std::string &cache_root();

/**
 * @brief El cajon de @p kind dentro de @ref cache_root .
 *
 * @param kind Tipo de artefacto.
 * @return Ruta del directorio.  La referencia vive lo que el proceso.
 */
const std::string &cache_dir(CacheKind kind);

/**
 * @brief El cajon de @p kind dentro de OTRA raiz.
 *
 * Para quien ya sabe donde va su cache y no quiere la del proceso -- el gestor
 * de paquetes la ancla en la raiz del proyecto que esta instalando, que no
 * tiene por que ser desde donde se le invoco --.
 *
 * @param root Directorio que hace de raiz; se le anade @ref cache_root_name .
 * @param kind Tipo de artefacto.
 * @return Ruta del directorio, o vacio si @p root lo esta.
 */
std::string cache_dir_under(const std::string &root, CacheKind kind);

} // namespace util

#endif // VESTA_UTIL_CACHE_PATHS_H
