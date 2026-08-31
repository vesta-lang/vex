/**
 * @file project_cache.h
 * @brief  M5.B - cache del @c .velb final del proyecto.
 *
 * Cache a nivel de bytecode-final: si nada cambio en el root + deps
 * recursivos + opciones de compile, el siguiente @c vm @c --vx es un
 * cache hit instantaneo (copia del @c .velb cacheado al output sin
 * invocar el frontend).
 *
 * Layout del cache file (binary, little-endian):
 * @verbatim
 * +0   u32  magic = 'VPCK' (0x4B435056)
 * +4   u16  format_version (=1)
 * +6   u16  _reserved
 * +8   u32  opts_hash (FNV-1a sobre las opciones de compile que afectan
 *           la salida -- opt_level, emit_debug, vx_base, etc.)
 * +12  u32  dep_count
 * +16  DepEntry[dep_count]:
 *           u32  path_len
 *           u8   path[path_len]
 *           u64  source_hash (FNV-1a 64 del source crudo)
 * +    u32  velb_size
 * +    u8   velb_bytes[velb_size]
 * @endverbatim
 *
 * El cache file vive en `<cache_dir>/<root_hash>.vpc`.  El @c root_hash
 * es FNV-1a 64 del path canonico del root.
 */

#ifndef VX_PROJECT_CACHE_H
#define VX_PROJECT_CACHE_H

#include <cstdint>
#include <string>
#include <vector>

#include "analysis/asa/fact.h"
#include "analysis/asa/fact_store.h" // los hechos que se dejan al compilar
#include "ir/ssa_ir.h"               // el modulo del que se sabe
#include "vx/diagnostic.h"

namespace vx {

///  M5.B: opciones que afectan el output del compile.  Cualquier
/// cambio en estos campos invalida el cache (se incluye en opts_hash).
struct ProjectCacheKey {
    int opt_level = 1;
    bool emit_debug = false;
    uint64_t vx_base = 0;
    std::string instrument_mode; ///< "none", "trace", "coverage", etc.
    std::string port_target;     ///< "" si no es port; "c", "java", etc.
    /// La maquina que ejecuta el codigo de compilacion estaba cargada.  Sin
    /// ella las funciones comptime no se ejecutan y lo compilado es
    /// provisional, asi que no puede compartir entrada con lo definitivo.
    bool comptime_prebuilt = false;
    /**
     * @brief De DONDE salen los modulos que no son del proyecto.
     *
     * El cache guarda las rutas de cada dep y comprueba que sigan diciendo lo
     * mismo, pero si se cambia el arbol de la stdlib el compile usa OTROS
     * ficheros -- y los de antes siguen ahi, intactos, asi que la comprobacion
     * pasaba y se servia un artefacto construido contra una libreria distinta.
     * Medido apuntando `VX_STDLIB_DIR` a una instalacion aparte: la corrida
     * devolvia exito y salida vacia sin compilar nada.
     */
    std::string stdlib_dir;
    std::string vx_path; ///< Directorios extra de busqueda (@c VX_PATH).

    /**
     * @name Que artefacto se pidio
     *
     * El cache guarda el fichero FINAL, y ese fichero no es el mismo segun lo
     * que se pidiera: un `.velb` de la maquina virtual, o un binario nativo, y
     * de este ultimo hay uno por formato, por tipo de emision y por
     * arquitectura.  Sin estos campos en la clave, un acierto podria servir un
     * `.velb` a quien pidio un `.exe` -- por eso el AOT se salto el cache
     * entero durante un tiempo, y por eso volver a construirlo sin cambios
     * costaba lo mismo que construirlo por primera vez.
     * @{
     */
    bool aot = false;       ///< Se pidio codigo NATIVO, no bytecode de la VM.
    std::string aot_arch;   ///< x86-64 / x86-32 / aarch64.
    std::string aot_format; ///< pe / elf.
    std::string aot_emit;   ///< exe / obj / shared / bin.
    std::string aot_target; ///< SO objetivo, si se fijo (@Target / --target).
    std::string aot_tier;   ///< Nivel de runtime (full / embed / bare).
    std::string aot_perfil; ///< Resto de opciones que cambian lo emitido.
    /** @} */
};

///  M5.B: entrada por modulo en el cache file.  Tras un compile
/// exitoso, el caller persiste @c path + @c source_hash de cada modulo
/// participante (root + deps recursivos).
struct ProjectCacheDep {
    std::string path;     ///< Path canonico (absoluto + normalizado).
    uint64_t source_hash; ///< FNV-1a 64 del source crudo.
};

///  M5.B: API publica.
///
/// @brief Computa el path donde se cachearia el .velb del proyecto.
/// @param root_path  Path canonico del root.
/// @param cache_dir  Directorio del cache global (puede ser una funcion
///                   centralizada en @c $VX_HOME o @c ./.vx_cache ).
std::string project_cache_path(const std::string &root_path,
                               const std::string &cache_dir);

/// @brief Computa el directorio default del cache de proyectos.
/// Por defecto: @c $VX_HOME/cache/projects o @c ./.vx_cache/projects .
std::string default_project_cache_dir();

/// @brief Lee un cache file y devuelve sus contenidos parseados.
/// @return @c true si el archivo existe, magic + version validos.
///         Los campos out_* se llenan en caso OK.  En miss/error,
///         devuelve @c false y los out_* quedan vacios.
bool project_cache_load(const std::string &cache_path, uint32_t &out_opts_hash,
                        std::vector<ProjectCacheDep> &out_deps,
                        std::vector<uint8_t> &out_velb);

/// @brief Escribe un cache file con los contenidos dados.  Usa atomic
/// rename (igual que @c write_file_atomic_ del compiler_project).
/// @return @c true si exito.
bool project_cache_save(const std::string &cache_path, uint32_t opts_hash,
                        const std::vector<ProjectCacheDep> &deps,
                        const std::vector<uint8_t> &velb);

/**
 * @brief Huella de lo que decide QUE AVISOS salen, que no es lo mismo que la
 *        de lo que decide QUE ARTEFACTO se emite.
 *
 * Los diagnosticos son del frontend: el mismo fuente da los mismos avisos en
 * interprete, JIT y nativo.  Indexarlos por @ref project_cache_opts_hash --
 * que lleva formato, tipo de emision y demas -- los guardaria tres veces y
 * cambiar de backend los perderia, cuando no ha cambiado nada de lo que se
 * mira.
 *
 * Y NO entra el objetivo: cada aviso dice en que arquitectura, sistema y
 * backend vale (su @c Ambito) y el lector filtra por donde esta.  Asi un solo
 * fichero sirve a todos los objetivos: lo universal se comparte y solo se
 * descarta lo que de verdad es de otro sitio.
 *
 * Entra lo que cambia QUE CODIGO SE MIRA: el nivel de optimizacion y la
 * informacion de depuracion (cambian el IR sobre el que se analiza), la
 * instrumentacion, si la maquina de compilacion estaba cargada (sin ella el
 * codigo comptime no se ejecuto y lo que se ve es otra cosa), de donde salen
 * los modulos ajenos, y el nivel de runtime, que cambia que se baja.
 *
 * Queda fuera lo que solo cambia el envoltorio: el formato del fichero, el
 * tipo de emision, la direccion base y el resto del perfil de emision.  Pedir
 * un `.obj` en vez de un `.exe` no altera ni un aviso.
 *
 * @param key Opciones de la compilacion.
 * @return La huella con la que se guardan y se recuperan sus diagnosticos.
 */
uint32_t project_cache_diag_hash(const ProjectCacheKey &key);

/// @brief Computa el @c opts_hash sobre la @c ProjectCacheKey .
/// FNV-1a 32 sobre los campos concatenados.
uint32_t project_cache_opts_hash(const ProjectCacheKey &key);

/// @brief Verifica si el cache esta vigente: dado el cache file cargado, leer
/// cada @c ProjectCacheDep::path del disco, calcular su huella actual y
/// comparar.  Si todas coinciden, cache HIT.
///
/// La huella es la del CONTENIDO CON SIGNIFICADO (@ref vx::hash_de_tokens), no
/// la de los bytes: anadir un comentario o reindentar no cambia lo que el
/// modulo dice y no debe tirar lo que ya se construyo de el.
///
/// @param cached_deps Dependencias tal como se guardaron.
/// @param con_lineas  Incluir la linea de cada token.  Debe valer lo MISMO que
///                    cuando se guardo, y vale @c emit_debug: con informacion
///                    de depuracion el artefacto si depende de las lineas.
/// @return @c true si las huellas actuales coinciden con las cacheadas.
bool project_cache_validate(const std::vector<ProjectCacheDep> &cached_deps,
                            bool con_lineas);

/**
 * @brief Guarda los diagnosticos de una compilacion junto a su cache.
 *
 * SIN ESTO, un acierto de cache SILENCIA los avisos: el artefacto se sirve del
 * disco sin volver a compilar, asi que nadie los vuelve a emitir.  La primera
 * vez el compilador avisa y la segunda se calla, y el aviso acaba dependiendo
 * de si alguien borro un directorio -- que es como no tenerlo.  Y es en los
 * proyectos grandes, donde el cache acierta casi siempre, donde mas se nota.
 *
 * Se guardan como DATOS -- codigo del catalogo, posicion y argumentos --, no
 * como texto: al rehacerlos se formatean en el idioma activo, igual que si se
 * acabaran de emitir.
 *
 * @param cache_path Fichero de cache del proyecto (se le anade su extension).
 * @param diag_hash  Huella de lo que decide que avisos salen
 *                   (@ref project_cache_diag_hash); si no cuadra no se rehacen.
 *                   Va tambien en el NOMBRE del fichero, para que dos objetivos
 *                   distintos del mismo proyecto no se pisen el uno al otro.
 * @param diags      Los diagnosticos a guardar.
 * @param donde      Donde valen.  CONSERVADOR por defecto: lo que no se sepa
 *                   universal se marca con el objetivo actual, con lo que en el
 *                   peor caso se comporta como antes -- se recalcula -- y nunca
 *                   se afirma en un sitio algo comprobado en otro.
 * @return @c true si quedo algo escrito.
 */
bool project_cache_save_diags(const std::string &cache_path, uint32_t diag_hash,
                              const std::vector<Diagnostic> &diags,
                              const analysis::asa::Scope &donde);

/**
 * @brief Recupera lo guardado por @ref project_cache_save_diags.
 *
 * @param cache_path Mismo que al guardar.
 * @param diag_hash  Misma que al guardar.
 * @param out        Donde se depositan (se vacia antes).
 * @param aqui       Donde se esta ahora; se descarta lo que valga en otro
 * sitio.
 * @return @c true si se recupero algo.
 */
bool project_cache_load_diags(const std::string &cache_path, uint32_t diag_hash,
                              std::vector<Diagnostic> &out,
                              const analysis::asa::Scope &aqui);

/**
 * @brief Guarda con que se vuelve a publicar la raiz de diagnostico.
 *
 * POR QUE HACE FALTA.  El grafo de conocimiento se emite durante el lowering,
 * asi que un artefacto servido desde este cache no emite NADA: se comprobo con
 * el cache purgado (1 paquete, 1 raiz) y sin purgar (0 y 0).  El binario sale
 * igual, pero nada en el almacen lo explica, asi que si falla no hay de donde
 * sacar su traza.  Y no basta con recompilar para arreglarlo: la recompilacion
 * vuelve a acertar en el cache y vuelve a no emitir nada.
 *
 * No se guarda el grafo, que ya esta en su almacen y es el mismo: solo las dos
 * huellas por las que se pregunta.  Con ellas, servir desde el cache puede
 * republicar la raiz y el binario cacheado vuelve a ser explicable.
 *
 * Va en un fichero al lado de la entrada, como los diagnosticos, para no tocar
 * el formato de lo que ya hay en disco.
 *
 * @param cache_path Misma ruta que @ref project_cache_save.
 * @param map_hex    Huella del mapa del artefacto, en hexadecimal.
 * @param spans_hex  Huella de sus tramos; puede ir vacia.
 * @return @c true si quedo escrito.
 */
bool project_cache_save_vxdbg(const std::string &cache_path,
                              const std::string &map_hex,
                              const std::string &spans_hex);

/**
 * @brief Recupera lo guardado por @ref project_cache_save_vxdbg.
 * @param cache_path Mismo que al guardar.
 * @param out_map_hex Recibe la huella del mapa.
 * @param out_spans_hex Recibe la de los tramos.
 * @return @c true si habia algo que recuperar.
 */
bool project_cache_load_vxdbg(const std::string &cache_path,
                              std::string &out_map_hex,
                              std::string &out_spans_hex);

/// @brief FNV-1a 64 helper (publico para uso en @c compile_vx_project).
uint64_t fnv1a64_bytes(const uint8_t *data, size_t size) noexcept;

/**
 * @brief Deja en @p store los hechos de @p wanted, vengan de donde vengan.
 *
 * Es la puerta que usan los consumidores, y esconde a proposito de DoNDE sale
 * el conocimiento: de la cache de una compilacion anterior, o producido ahora.
 * Un consumidor que tuviera que saberlo acabaria decidiendo por su cuenta
 * cuando fiarse de la cache, y esa decision estaria escrita en tantos sitios
 * como consumidores haya.
 *
 * Se declara aqui -- y no se queda dentro del compilador de proyecto -- porque
 * la usan los DOS caminos.  Compilar un fichero suelto no producia ni
 * reutilizaba nada: todo lo que se sabia del modulo se recalculaba en cada
 * compilacion y se tiraba al acabar, que es justo lo que esta capa existe para
 * no hacer.  Escribir aqui una segunda version habria sido tener dos criterios
 * de cuando fiarse de la cache.
 *
 * @param mod         Modulo del que se sabe.
 * @param store       Almacen de esta compilacion.
 * @param wanted      Dominios que alguien va a consultar.  Vacio = todos.
 * @param path        Fichero de hechos, o vacio para no tocar disco.
 * @param fingerprint Identidad del modulo: si no coincide, lo guardado no vale.
 */
void ensure_facts(const ir::IrModule &mod, analysis::asa::FactStore &store,
                  const std::vector<const char *> &wanted,
                  const std::string &path, uint64_t fingerprint);

/// Path del fichero de hechos de @p source_path (`.vxfacts` en la cache).
std::string vxfacts_path_for(const std::string &source_path,
                             const std::string &tgt_suffix);

} // namespace vx

#endif // VX_PROJECT_CACHE_H
