/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vxdbg/reachable.h
 * @brief Que nodos del almacen siguen alcanzables desde las raices.
 *
 * POR QUE EXISTE.  @ref PackNodeStore::reclamar sabe borrar los paquetes de los
 * que ya no se usa nada, pero pide que le digan CUALES siguen vivos: el almacen
 * aplica el criterio, no lo conoce.  Esto es lo que lo calcula.
 *
 * COMO.  Un recorrido en anchura desde las raices publicadas
 * (`<cache>/roots/*.ptr`, lo unico mutable del subsistema) siguiendo las
 * referencias de cada nodo.  Las referencias SON huellas -- un @ref NodeId
 * envuelve un @ref ContentHash --, asi que no hace falta traducir nada.
 *
 * LA REGLA DE SEGURIDAD, Y ES LA RAZON DE QUE ESTO DEVUELVA UN ESTADO Y NO UN
 * CONJUNTO A SECAS.  Un genero de nodo que este codigo no sepa recorrer NO se
 * salta: se aborta el recorrido entero.  Saltarlo daria un conjunto vivo
 * incompleto, y con un conjunto incompleto la reclamacion borra datos que si se
 * usaban -- en silencio, y sin forma de recuperarlos salvo recompilando.  Hoy
 * el compilador escribe cuatro generos (Entity, File, ArtifactMap, SpanMap); el
 * dia que anada un quinto, esto deja de reclamar hasta que alguien lo ensene a
 * recorrerlo.  Preferimos un cache que crece a un cache que miente.
 *
 * Una referencia COLGADA -- a un nodo que no esta en el almacen -- si es normal
 * y no aborta nada: si no esta, no hay nada suyo que conservar.  Pasa de
 * verdad, porque una entidad puede citar su funcion intermedia y esos nodos hoy
 * no se emiten.  Se cuentan, para que se vea.
 */
#ifndef VXDBG_REACHABLE_H
#define VXDBG_REACHABLE_H

#include "vxdbg/ids.h"
#include "vxdbg/node.h"
#include "vxdbg/store.h"

#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace vxdbg {

/// Por que un recorrido no pudo completarse.
enum class ReachStatus {
    Ok,          ///< se recorrio entero; el conjunto vivo es de fiar
    UnknownKind, ///< un genero que este codigo no sabe recorrer
    Undecodable, ///< del genero esperado, pero el codec lo rechazo
};

/**
 * @brief Un nodo que cita a otros que no estan, y CUANTOS.
 *
 * Se agrega por quien cita, no se guarda una muestra de referencias sueltas.
 * La diferencia importa al mirarlo: veinticuatro ejemplos de un total de mil no
 * dicen nada, mientras que "este mapa cita 93 que faltan" senala el sitio a la
 * primera.  Y casi siempre son pocos citantes con muchas cada uno, que es
 * justo el patron que una muestra al azar esconde.
 */
struct DanglingSource {
    ContentHash from; ///< quien cita
    NodeKind from_kind = NodeKind::Unknown;
    size_t count = 0; ///< cuantas ausentes cita
};

/// Lo que un recorrido encontro.  Son DATOS: quien lo pida decide que decir.
struct ReachReport {
    ReachStatus status = ReachStatus::Ok;
    /// Que genero lo bloqueo, cuando @c status no es @c Ok.
    NodeKind blocking_kind = NodeKind::Unknown;
    /// La huella del nodo que lo bloqueo, para poder ir a mirarlo.
    ContentHash blocking_node;
    size_t roots_read = 0;    ///< apuntadores de raiz leidos
    size_t nodes_reached = 0; ///< nodos distintos alcanzados
    size_t dangling_refs = 0; ///< referencias a nodos que no estan

    /* Lo que sigue solo se rellena si se pidio seguir la procedencia.  Separar
     * las de las RAICES de las del grafo no es un detalle: una raiz colgada
     * significa un artefacto que ya no se puede explicar, y una del grafo
     * significa un nodo incompleto.  Son dos averias distintas y mezclarlas en
     * un solo numero fue lo que impidio ver cual habia. */

    /// Colgadas cuyo origen es un apuntador de raiz, no un nodo del grafo.
    size_t dangling_from_roots = 0;
    /// Los nodos que citan ausentes, de mas a menos.
    std::vector<DanglingSource> dangling_by_citer;
    /// Cuantos nodos alcanzados de cada genero.  Es lo que contesta "y esto que
    /// contiene", que en un almacen de huellas no se puede saber mirandolo.
    std::map<NodeKind, size_t> reached_by_kind;
};

/**
 * @brief Las huellas que @p node referencia.
 *
 * @param node Nodo ya leido del almacen.
 * @param out  Se le ANADEN las referencias; no se limpia.
 * @return @c Ok, o el motivo por el que no se pudo saber.
 */
ReachStatus collect_references(const StoredNode &node,
                               std::vector<ContentHash> &out);

/**
 * @brief Lee las raices publicadas en `<cache_dir>/roots`.
 *
 * Cada apuntador cita el mapa del artefacto y sus tramos de fuente; los dos
 * entran como raices.  Un apuntador ilegible se salta: es mutable y externo al
 * grafo, asi que perderlo solo hace inexplicable UN artefacto, no corrompe
 * nada.
 *
 * @param cache_dir Carpeta del almacen (la que contiene `roots` y `packs`).
 * @param out_roots Recibe las huellas.
 * @return Cuantos apuntadores se leyeron.
 */
size_t read_published_roots(const std::string &cache_dir,
                            std::vector<ContentHash> &out_roots);

/**
 * @brief El conjunto alcanzable desde @p roots.
 *
 * @param store Donde viven los nodos.
 * @param roots Por donde se entra.
 * @param out_live Recibe las huellas vivas.  Solo es de fiar si el estado
 *        devuelto es @c Ok; con cualquier otro NO debe usarse para reclamar.
 * @param track_dangling_sources Si apuntar QUIEN cita a lo que no esta.
 *        Apagado -- lo normal -- no cuesta nada: este recorrido tambien corre
 *        durante la compilacion, dentro del mantenimiento del almacen, y
 *        apuntar la procedencia exige una tabla del tamano del grafo.
 *        Cobrarsela a toda compilacion para que casi nunca la mire nadie seria
 *        justo lo que este proyecto evita.  Lo piden solo las ordenes que estan
 *        para mirar.
 * @return El informe del recorrido.
 */
ReachReport compute_live_set(const NodeStore &store,
                             const std::vector<ContentHash> &roots,
                             std::set<ContentHash> &out_live,
                             bool track_dangling_sources = false);

} // namespace vxdbg

#endif // VXDBG_REACHABLE_H
