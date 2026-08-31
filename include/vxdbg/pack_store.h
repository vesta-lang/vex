/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vxdbg/pack_store.h
 * @brief Almacen de nodos EMPAQUETADO: muchos nodos en un fichero, no uno cada
 *        uno.
 *
 * POR QUE EXISTE.  El almacen suelto (@c FileNodeStore) guarda un fichero por
 * nodo, y eso paga metadatos del sistema de ficheros por NODO: abrir, escribir,
 * cerrar y renombrar.  Medido con VTune sobre una compilacion en frio de 2.004
 * lineas, que escribe **2.030 nodos**: el 90 % del tiempo de CPU se iba en
 * `fclose`, `MoveFileExW`, `fsopen` y `wstat64`.  El coste crece con el NUMERO
 * de nodos, no con los bytes -- por eso escribir mas rapido cada fichero (que
 * ya se hizo, con llamadas nativas) no basta: hay que escribir menos ficheros.
 *
 * QUE HACE.  @c put acumula en memoria; al destruirse, vuelca UN fichero con
 * todos los nodos seguidos, su indice al final, y lo publica con UN solo
 * renombrado atomico.  De 2.030 operaciones a una.
 *
 * QUE NO ROMPE.  Es aditivo: no cambia el formato suelto ni migra nada.  Lo que
 * ya hay en disco se sigue leyendo por el mismo camino, porque @c get y
 * @c contains preguntan primero a los paquetes y despues delegan en el almacen
 * suelto.  Un arbol de cache de antes de esto funciona igual.
 *
 * LAS CUATRO PREGUNTAS DIFICILES DE EMPAQUETAR, Y COMO QUEDAN:
 *
 *   CONCURRENCIA  Cada proceso escribe SU paquete, con un nombre que lleva su
 *                 identificador y un contador.  Dos compilaciones a la vez no
 *                 comparten fichero, asi que no hay nada que coordinar.  Es la
 *                 misma propiedad que hoy da el almacen suelto (el nombre ES el
 *                 contenido), llevada al paquete entero.
 *   CAIDAS        El paquete no existe hasta el renombrado.  Si el proceso
 *                 muere antes, no queda un paquete a medias: queda ninguno, y
 *                 lo que se perdio se vuelve a calcular.  Ademas el indice
 *                 lleva su suma de comprobacion: un paquete corrupto se
 *                 IGNORA entero en vez de servir un nodo por otro.
 *   BORRADO       AUTOMATICO, y sin compactar.  El modelo de git -- un `gc` que
 *                 lanza el usuario -- no vale en un cache de compilador: aqui
 *                 una entrada muere en cuanto cambia el fuente, cada pocos
 *                 segundos, y pedirle al programador que limpie es pedirle algo
 *                 que el compilador sabe solo.  Como un paquete es la salida de
 *                 UNA compilacion y es inmutable, cuando ninguna de sus
 *                 entradas se usa ya se borra ENTERO (ver @ref
 *                 PackNodeStore::reclamar).  Nunca se reescribe: reescribir es
 *                 la parte cara y delicada, y asi no hace falta.
 *   LECTURA       El indice se lee una vez por paquete y se consulta en
 *                 memoria; el cuerpo se lee solo cuando el nodo se pide.
 *
 * FORMATO (todo en little-endian, escrito con @c util::ByteWriter):
 *
 *     [magia 'VXPK'][version][n_nodos]
 *     [cuerpo: nodo0][nodo1]...        <- cada uno como en el almacen suelto
 *     [indice: (hash.lo, hash.hi, offset, tam) x n_nodos]
 *     [offset_del_indice][suma_del_indice][magia final]
 *
 * El indice va al FINAL a proposito: al escribir no se conocen los
 * desplazamientos hasta haber puesto los cuerpos, y ponerlo detras evita tener
 * que reservar hueco o volver atras.
 */
#ifndef VXDBG_PACK_STORE_H
#define VXDBG_PACK_STORE_H

#include "vxdbg/store.h"

#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vxdbg {

/// Magia del fichero de paquete ('VXPK' en little-endian).
static constexpr uint32_t VXDBG_PACK_MAGIC = 0x4B505856u;
/// Magia de cierre: si no esta, el fichero se quedo a medias.
static constexpr uint32_t VXDBG_PACK_MAGIC_FIN = 0x4E495856u;
/// Version del formato.  Un paquete de otra version se ignora, no se adivina.
static constexpr uint32_t VXDBG_PACK_VERSION = 1;

/**
 * @brief Almacen que escribe los nodos en paquetes y lee de paquetes + suelto.
 *
 * Se le pasa el almacen suelto al que delegar.  No lo sustituye: lo respalda.
 */
/**
 * @brief Sigue compilando el proceso que escribio este paquete?
 *
 * QUE PROBLEMA RESUELVE, porque no es una precaucion de mas y esta visto
 * perder datos por no tenerla.  Un paquete se escribe ANTES de que se publique
 * la raiz que lo mantiene vivo -- la raiz sale del artefacto final, que
 * mientras tanto no existe --, asi que entre lo uno y lo otro sus nodos
 * PARECEN muertos.  Con ocho compilaciones a la vez, la primera que termina
 * recoge y se lleva por delante lo que las otras siete acaban de escribir.
 *
 * POR QUE POR PROCESO Y NO POR FECHA.  Una gracia por antiguedad seria una
 * suposicion -- "ninguna compilacion tarda mas de X" -- y ademas ataria el
 * almacen al reloj: una cache copiada de otra maquina o restaurada de una
 * integracion continua traeria fechas que no dicen nada de ella, y se
 * comportaria distinta por eso.  Todo este subsistema se identifica por
 * CONTENIDO; meter el tiempo por la puerta de atras lo estropea.
 *
 * Esto en cambio es exacto y no supone nada: el nombre del paquete ya lleva el
 * identificador de quien lo escribio -- `p<pid>_<n>.vxpk`, puesto asi por este
 * mismo motivo de concurrencia --, y basta preguntar al sistema si ese proceso
 * sigue ahi.  Si sigue, esta compilando.  Si no, termino: o publico su raiz o
 * ya no lo hara nunca, y en los dos casos se puede decidir sobre sus nodos.
 *
 * En una cache traida de fuera ningun identificador correspondera a un
 * compilador vivo, que es justo lo que se quiere: todo pasa a ser recogible.
 *
 * El identificador se puede reutilizar, y por eso el error solo puede caer del
 * lado bueno: si toca a otro proceso vivo, se conserva un paquete que se podia
 * haber borrado y la siguiente recogida lo pilla.
 *
 * @param pack_path Ruta del paquete.
 * @return @c true si conviene no tocarlo.  Ante cualquier duda, @c true.
 */
bool pack_writer_is_running(const std::string &pack_path);

class PackNodeStore : public NodeStore {
  public:
    /**
     * @param root    Carpeta raiz del almacen (donde viven los paquetes).
     * @param suelto  Almacen de respaldo para lo que no este en un paquete.
     *                Puede ser nulo: entonces solo se leen paquetes.
     * @param tope    Cuantos nodos como mucho se acumulan antes de volcar un
     *                paquete parcial.  Sin tope, una compilacion enorme se
     *                llevaria toda su salida a memoria antes de escribir nada.
     */
    PackNodeStore(std::string root, std::unique_ptr<NodeStore> suelto,
                  size_t tope = 8192);
    ~PackNodeStore() override;

    bool put(const StoredNode &node) override;
    bool get(ContentHash hash, StoredNode &out) const override;
    bool contains(ContentHash hash) const override;

    /// Vuelca lo pendiente a un paquete nuevo.  Lo llama el destructor; se
    /// expone para poder comprobarlo y para cerrar antes de tiempo.
    bool volcar();

    /// Cuantos nodos hay esperando a escribirse.
    size_t pendientes() const;

    /**
     * @brief Borra los paquetes de los que YA NO SE USA NADA.
     *
     * El modelo de git -- objetos sueltos y un `gc` que el usuario lanza -- no
     * vale aqui: en un cache de compilador una entrada muere en cuanto cambia
     * el fuente, y eso pasa cada pocos segundos.  Pedirle al programador que
     * limpie es pedirle algo que el compilador sabe solo.
     *
     * Y no hace falta compactar, que es la parte cara y delicada: un paquete es
     * la salida de UNA compilacion y es inmutable, asi que cuando ninguna de
     * sus entradas se usa ya, **se borra entero**.  Nunca se reescribe.
     *
     * @param vivas Las entradas que siguen alcanzables desde las raices
     *        validas del cache.  Quien llama es el que sabe cuales son: el
     *        almacen no conoce el criterio de validez, solo lo aplica.
     * @return Cuantos paquetes se borraron.
     *
     * @note Un paquete con UNA sola entrada viva NO se borra.  Recuperar el
     *       hueco de las muertas exigiria reescribirlo, y eso se pospone a
     *       proposito: si algun dia quedan muchos paquetes medio vivos, ese
     *       sera el momento de compactar.
     */
    /**
     * @param vivas Las entradas que siguen alcanzables.
     * @param tocables Los UNICOS paquetes que se pueden borrar, o @c nullptr
     *        para no poner limite.  Ver @ref compact para por que esto lo
     *        decide quien llama y no esta clase.
     */
    size_t reclamar(const std::set<ContentHash> &vivas,
                    const std::set<std::string> *tocables = nullptr);

    /// Que pasaria al reclamar, sin tocar el disco.
    struct ReclaimPreview {
        size_t packs = 0;           ///< paquetes en el almacen
        size_t entries = 0;         ///< entradas indexadas, en total
        size_t live_entries = 0;    ///< de ellas, las que siguen vivas
        size_t packs_to_delete = 0; ///< paquetes sin ninguna viva
        uint64_t bytes_to_free = 0; ///< lo que ocupan esos paquetes
    };

    /**
     * @brief Lo que @ref reclamar haria, sin hacerlo.
     *
     * Existe porque borrar el cache es de las pocas cosas de aqui que no se
     * pueden deshacer, y porque el criterio de que raices siguen valiendo es
     * una decision -- no un calculo --: quien la tome necesita ver los numeros
     * antes, no despues.
     *
     * @param vivas Las entradas que se consideran vivas.
     * @return El recuento.
     */
    ReclaimPreview preview_reclaim(const std::set<ContentHash> &vivas) const;

    /// Lo que hizo una compactacion.
    struct CompactResult {
        bool ok = true;
        size_t packs_before = 0;
        size_t packs_after = 0;     ///< los que escribio
        size_t packs_removed = 0;   ///< los viejos que borro
        size_t entries_kept = 0;    ///< entradas vivas reescritas
        size_t entries_dropped = 0; ///< las muertas que se quedaron fuera
        uint64_t bytes_before = 0;
        uint64_t bytes_after = 0;
    };

    /**
     * @brief Reescribe las entradas vivas en pocos paquetes llenos.
     *
     * @ref reclamar solo borra un paquete cuando TODAS sus entradas murieron, y
     * eso deja de bastar en cuanto los paquetes quedan medio vivos: uno con una
     * sola entrada viva mantiene ocupadas las otras cincuenta, y sobre todo
     * mantiene un fichero que hay que ABRIR en cada compilacion -- que es lo
     * caro, ~20 us cada uno.  Medido en este arbol: 78.348 entradas indexadas
     * con solo 14.685 vivas, y aun asi 1.226 paquetes irreclamables con un 78%
     * de basura dentro.  Justo el caso que esta clase dejo apuntado como
     * disparador para compactar.
     *
     * ORDEN, Y ES LO QUE LA HACE SEGURA ANTE UNA CAIDA: primero se escriben
     * TODOS los paquetes nuevos, cada uno con su renombrado atomico, y solo
     * despues se borran los viejos.  Si el proceso muere en medio quedan las
     * dos copias, y eso no rompe nada porque la clave ES el contenido: al leer
     * los indices gana el primero que aparece y los dos dicen lo mismo.  Al
     * reves -- borrar antes de escribir -- se perderia el cache entero.
     *
     * @param vivas Las entradas que se conservan.  Igual que en @ref reclamar,
     *        el criterio lo pone quien llama.
     * @param entries_per_pack Cuantas entradas como mucho por paquete nuevo.
     * @param tocables Los UNICOS paquetes que se pueden tocar, o @c nullptr
     *        para no poner limite.  Lo decide quien llama porque el orden
     *        importa y esta clase no lo puede garantizar sola: el conjunto de
     *        paquetes tocables hay que fijarlo ANTES de leer las raices.  Un
     *        proceso que muere DESPUES de esa lectura publico su raiz sin que
     *        nadie la viera, y si se le tocara el paquete su raiz quedaria
     *        apuntando al vacio.  Ver @ref pack_writer_is_running.
     * @return El recuento de lo hecho.
     */
    CompactResult compact(const std::set<ContentHash> &vivas,
                          size_t entries_per_pack = 8192,
                          const std::set<std::string> *tocables = nullptr);

  private:
    /// Donde vive un nodo dentro de un paquete ya escrito.
    struct Sitio {
        std::string ruta; ///< fichero de paquete
        uint64_t offset;  ///< desplazamiento del cuerpo
        uint32_t tam;     ///< bytes del cuerpo
    };

    void cargar_indices_() const; ///< lee los indices de los paquetes, una vez

    /**
     * @brief Escribe UN paquete con @p lote y lo publica.
     *
     * El unico sitio donde se escribe el formato: lo comparten el volcado
     * normal y la compactacion.  No toca el indice ni el cerrojo; de eso se
     * encarga quien llame.
     *
     * @param lote      Que nodos van dentro.
     * @param out_path  Recibe la ruta del paquete escrito.
     * @param out_sites Recibe donde quedo cada nodo.
     */
    bool write_pack_(const std::map<ContentHash, StoredNode> &lote,
                     std::string &out_path,
                     std::vector<std::pair<ContentHash, Sitio>> &out_sites);

    std::string root_;
    std::unique_ptr<NodeStore> suelto_;
    size_t tope_;

    mutable std::mutex mx_;
    std::map<ContentHash, StoredNode> pendientes_; ///< aun sin escribir
    mutable std::map<ContentHash, Sitio> indice_;  ///< ya en algun paquete
    mutable bool indices_leidos_ = false;
    uint32_t n_volcados_ = 0;
};

} // namespace vxdbg

#endif // VXDBG_PACK_STORE_H
