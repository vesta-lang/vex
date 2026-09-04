/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vxdbg_emit.h
 * @brief Traduce lo que sabe el frontend de Vesta a nodos de depuracion.
 *
 * El subsistema @c vxdbg no conoce Vesta -- ni ningun otro lenguaje -- a
 * proposito: guarda entidades con un @c kind que decide quien las declara.  La
 * correspondencia entre el vocabulario de Vesta (clase, struct, enum, campo,
 * metodo, variante) y ese modelo generico vive AQUI, en el frontend, que es
 * quien la conoce.  Un frontend de otro lenguaje escribiria su propio traductor
 * contra las mismas estructuras sin tocar nada de @c vxdbg.
 *
 * Solo cubre la capa SEMANTICA: que tipos hay, que miembros tienen y como se
 * relacionan.  Las sentencias, la bajada al intermedio y la correspondencia con
 * el codigo generado van en incrementos aparte, cada uno con su capa.
 */

#ifndef VX_VXDBG_EMIT_H
#define VX_VXDBG_EMIT_H

#include "vxdbg/ids.h"
#include "vxdbg/roots.h"

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace vx {

class TypeChecker;

/**
 * @brief Cuenta de lo emitido, para poder informar sin adivinar.
 */
struct VxdbgEmitStats {
    size_t entities = 0; ///< entidades escritas (tipos y miembros)
    size_t members = 0;  ///< de las anteriores, campos/metodos/variantes
    /// Nombres referenciados que no corresponden a ningun tipo conocido.  La
    /// relacion se omite en vez de inventarse un destino: preferimos no decir
    /// nada a decir algo falso.  Que este contador no sea cero es informacion
    /// util, no necesariamente un fallo.
    size_t unresolved = 0;
    /// Claves declaradas dos veces.  No es un dato repetido: la clave es la
    /// identidad, asi que es una incoherencia de quien construyo el grafo.
    size_t duplicates = 0;
    /// Los tipos emitidos, por su clave.  Un almacen direccionado por contenido
    /// no se puede recorrer: no hay listado, solo se llega a un nodo si ya se
    /// sabe su huella.  Quien acaba de emitir es el unico que las conoce, y
    /// esta es la lista que despues acaba en la unidad de compilacion como sus
    /// raices.
    std::vector<std::pair<std::string, vxdbg::LanguageEntityId>> roots;

    /**
     * @brief Huella del mapa de ESTE modulo -- sus simbolos con su entidad.
     *
     * Se guarda como nodo aqui, aprovechando el almacen que la emision ya tiene
     * abierto, y su huella acaba en el `.vxi` del modulo.  Con eso, una
     * compilacion que sirva este modulo desde cache puede citarlo en el mapa
     * del artefacto sin re-emitir el grafo ni abrir un solo fichero de mas.
     *
     * Vacia si el modulo no ligo ningun simbolo.
     */
    vxdbg::ContentHash module_map;

    /// Simbolos del artefacto que se pudieron ligar a una entidad.
    size_t linked = 0;
    /// Y los que no.  Un simbolo sin entidad no es un fallo por si mismo -- hay
    /// codigo generado que no viene de ninguna declaracion, como los ayudantes
    /// que fabrica el compilador -- pero que crezca de golpe si lo es.
    size_t unlinked = 0;
    /// Los pares (simbolo, entidad) que se ligaron.  Los expone porque un
    /// ejecutable puede juntar varios modulos y su mapa tiene que cubrirlos a
    /// todos: una direccion suya puede caer en cualquiera.
    std::vector<std::pair<std::string, vxdbg::LanguageEntityId>> symbol_links;
    /// Huella del mapa de simbolos.  Con ella y el identificador de la
    /// compilacion se entra al grafo desde una direccion de ejecucion.
    vxdbg::ContentHash artifact_map;
    /// Huella del mapa de TRAMOS de fuente.  Va aparte del de simbolos porque
    /// cambia con cualquier reformateo del fuente mientras que el otro no.
    vxdbg::ContentHash span_map;
    /// Los tramos, para que quien junte varios modulos pueda componer el suyo.
    std::vector<vxdbg::SourceExtent> spans;
};

/**
 * @brief Carpeta por defecto del almacen: dentro del cache del compilador.
 *
 * Va con el resto de artefactos intermedios porque es uno mas: se regenera al
 * recompilar y se borra con ellos.  Sacarlo aparte obligaria a acordarse de
 * limpiarlo, y un grafo de una version anterior mezclado con el actual es peor
 * que no tener ninguno.
 *
 * @return La ruta, respetando @c VX_CACHE_DIR si esta puesta.
 */
std::string default_vxdbg_dir();

/**
 * @brief Publica el mapa de un artefacto bajo su identificador de construccion.
 *
 * El identificador sale del CONTENIDO del fichero producido, no de como se
 * llame: es lo unico que sobrevive a renombrarlo, moverlo o mandarlo a otra
 * maquina, y por tanto lo unico con lo que tiene sentido pedir despues su
 * informacion.  Un binario viejo que siga por ahi se sigue explicando con SUS
 * simbolos y no con los de la ultima compilacion.
 *
 * @param artifact_path Fichero producido.
 * @param map Huella del mapa (@c VxdbgEmitStats::artifact_map).
 * @param out_dir Carpeta del almacen; vacia = la de por defecto.
 * @return @c true si quedo publicado.
 */
/**
 * @param artifact_bytes Los bytes del artefacto, si quien llama ya los tiene.
 *        El identificador sale de ellos, asi que darlos evita releer del disco
 *        un fichero que se acaba de escribir.  No es un detalle: al servir
 *        desde el cache de proyecto los bytes estan en memoria, y releerlos
 *        costaba +87 ms en un proyecto de 6k lineas -- mas de lo que costaba
 *        el acierto entero.  @c nullptr = leerlo del disco.
 */
bool publish_vxdbg_artifact(
    const std::string &artifact_path, vxdbg::ContentHash map,
    vxdbg::ContentHash spans = vxdbg::ContentHash{},
    const std::string &out_dir = std::string(),
    const std::vector<uint8_t> *artifact_bytes = nullptr);

/**
 * @brief Vuelca la capa semantica del modulo al almacen de depuracion.
 *
 * Toma los tipos del @ref TypeChecker y no del AST porque la tabla del checker
 * incluye tambien los IMPORTADOS: emitir desde el AST dejaria sin destino toda
 * relacion que apunte fuera del fichero, que es justo lo que hace util saber de
 * quien deriva algo.
 *
 * @param tc Checker ya ejecutado.
 * @param symbol_links Que declaracion produjo cada simbolo, tal como lo anoto
 *        el lowering al crear los nombres (@c Lowering::emitted_symbols).  Es
 * lo que permite ir de una direccion de ejecucion a una declaracion; vacio
 *        emite el grafo pero sin forma de entrar en el.
 * @param spans Los tramos de fuente, uno por sentencia bajada.  Se toman POR
 *        VALOR y quien llama los mueve: cada uno lleva el nombre de su funcion,
 *        asi que copiarlos es reservar una cadena por sentencia del fichero
 *        para tirar la del que llama justo despues.
 * @param source_path Ruta del fuente principal.
 * @param source_text Su contenido, para resumirlo y poder detectar despues que
 *        el fichero de disco ya no es el que se compilo.  Vacio = sin resumen.
 * @param out_dir Carpeta del almacen; se crea si no existe.
 * @param stats Recibe la cuenta de lo emitido.
 * @param err Recibe el motivo si algo fallo.
 * @return @c true si se escribio todo.
 */
bool emit_vxdbg_source(
    const TypeChecker &tc,
    const std::vector<std::pair<std::string, std::string>> &symbol_links,
    std::vector<vxdbg::SourceExtent> spans, const std::string &source_path,
    const std::string &source_text, const std::string &out_dir,
    VxdbgEmitStats &stats, std::string &err);

} // namespace vx

#endif // VX_VXDBG_EMIT_H
