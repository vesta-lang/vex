/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vxdbg/maintenance.h
 * @brief Mantener el almacen acotado, SOLO, sin que nadie lo pida.
 *
 * POR QUE AUTOMATICO.  Es lo que @ref PackNodeStore dejo escrito desde el
 * principio: el modelo de git -- un `gc` que lanza el usuario -- no vale en un
 * cache de compilador, porque aqui una entrada muere en cuanto cambia el
 * fuente, cada pocos segundos, y pedirle al programador que limpie es pedirle
 * algo que el compilador sabe solo.  Una orden manual sirve para mirar y para
 * probar; no para que el almacen se mantenga.
 *
 * QUE PASABA SIN ESTO.  Nada retiraba nada, asi que el almacen crecia con cada
 * compilacion y con el el tiempo de compilar: cargar sus indices llego a ser el
 * 99,6% de la E/S de una compilacion trivial, unos 90 ms de 127, subiendo.
 *
 * CUANDO SE PASA.  Por numero de PAQUETES y no por bytes, porque lo caro es
 * abrir ficheros (~20 us cada uno) y no leerlos: mil paquetes de 12 KiB duelen
 * mucho mas que dos de 6 MiB.  El umbral por defecto pone techo a ese peaje.
 *
 * EL ORDEN IMPORTA, Y ES LA TRAMPA DE TODO ESTO.  Los nodos que una compilacion
 * acaba de emitir no estan vivos hasta que se PUBLICA su raiz.  Pasar por aqui
 * entre lo uno y lo otro los daria por muertos y los borraria -- justo los que
 * mas falta hacen.  Se llama despues de publicar, nunca antes.
 */
#ifndef VXDBG_MAINTENANCE_H
#define VXDBG_MAINTENANCE_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace vxdbg {

/// En que quedo una pasada de mantenimiento.
enum class MaintenanceStatus {
    Ran,                 ///< se hizo
    BelowThreshold,      ///< no hacia falta todavia
    NoStore,             ///< no hay almacen en esa carpeta
    NoRoots,             ///< sin raices, todo pareceria muerto: no se toca
    TraversalIncomplete, ///< no se pudo saber que vive: no se toca
    WriteFailed,         ///< fallo al escribir; lo viejo se queda
};

/// Lo que se hizo.  Son DATOS: quien llame decide si decir algo y como.
struct MaintenanceResult {
    MaintenanceStatus status = MaintenanceStatus::BelowThreshold;
    size_t packs_before = 0;
    size_t packs_after = 0;
    size_t packs_removed = 0; ///< borrados enteros, sin reescribir
    size_t roots_retired = 0; ///< apuntadores de raiz que ya no describian nada
    size_t entries_kept = 0;
    size_t entries_dropped = 0;
    uint64_t bytes_before = 0;
    uint64_t bytes_after = 0;
};

/**
 * @brief Cuantos paquetes se toleran antes de recoger.
 *
 * Sale de medir, no de estimar.  Una compilacion trivial cuesta 44 ms con 3
 * paquetes y 62 ms con 370: **~49 us por paquete**, bastante mas que los ~20
 * que cuesta la apertura a secas, porque cada uno ademas trae su indice, lo
 * parsea y lo mete en el mapa.
 *
 * Doscientos cincuenta y seis dejan ese peaje en unos 12 ms, que es lo que se
 * acepta que pague TODA compilacion antes de mirar una linea de codigo.
 * Subirlo abarata recoger -- que cuesta un par de segundos -- a costa de que
 * las 255 compilaciones siguientes paguen mas; bajarlo hace lo contrario.  Con
 * la recogida en ~2 s cada 256 compilaciones, lo repartido son ~8 ms, del
 * mismo orden que lo que se ahorra.
 */
constexpr size_t kDefaultPackThreshold = 256;

/**
 * @brief Recoge el almacen si le hace falta.
 *
 * Barato cuando no toca: solo cuenta los ficheros del directorio de paquetes y
 * se vuelve.  El recorrido, que es lo que cuesta, solo ocurre al pasarse.
 *
 * @param dir Carpeta del almacen.
 * @param pack_threshold A partir de cuantos paquetes se recoge.
 * @param force Recoger aunque no se llegue al umbral (la orden manual).
 * @return Que se hizo.
 */
MaintenanceResult maintain_store(const std::string &dir,
                                 size_t pack_threshold = kDefaultPackThreshold,
                                 bool force = false);

} // namespace vxdbg

#endif // VXDBG_MAINTENANCE_H
