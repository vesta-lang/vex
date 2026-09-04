/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 */

/**
 * @file util/name_pool.cpp
 * @copydoc util/name_pool.h
 */

#include "util/name_pool.h"

#include <mutex>
#include <unordered_set>

namespace util {

namespace {

/**
 * @brief El pozo.
 *
 * Conjunto y no vector porque lo que se pide es "dame EL puntero de este
 * nombre", y por nodos porque los elementos no se mueven al crecer: un puntero
 * repartido hace diez ficheros tiene que seguir valiendo.  Un vector ordenado
 * seria mas amable con la cache al buscar, pero al crecer REUBICA, y entonces
 * los punteros ya repartidos apuntarian a memoria liberada -- que no daria un
 * error, daria otro nombre.
 */
std::unordered_set<std::string> &pool() {
    static std::unordered_set<std::string> p;
    return p;
}

std::mutex &pool_mutex() {
    static std::mutex m;
    return m;
}

} // namespace

const std::string *intern_name(const std::string &name) {
    std::lock_guard<std::mutex> guard(pool_mutex());
    return &*pool().insert(name).first;
}

const std::string *empty_name() noexcept {
    // Fuera del pozo a proposito: es el valor por defecto de toda posicion, y
    // no debe costar ni un cerrojo ni una busqueda.
    static const std::string empty;
    return &empty;
}

} // namespace util
