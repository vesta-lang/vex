/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_pack_store.cpp
 * @brief Que un nodo empaquetado se lea IGUAL que se escribio, y que un paquete
 *        estropeado no sirva un nodo por otro.
 *
 * El modo de fallo de empaquetar no es que la compilacion se rompa -- eso se
 * veria --: es que el almacen devuelva el nodo equivocado y el error aparezca
 * dias despues, en un binario que no corresponde al fuente.  Por eso aqui no se
 * comprueba "que funcione": se comprueba entrada por entrada que lo que sale es
 * exactamente lo que entro, y que un indice alterado se DESCARTA en vez de
 * creerse.
 */
#include "vxdbg/pack_store.h"
#include "util/fs_utils.h"

#include <cstdio>
#include <thread>
#include <functional>
#include <chrono>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../test_support.h"

namespace {

int fallos = 0;

void comprueba(bool cond, const std::string &que) {
    if (cond) {
        std::printf("  ok    %s\n", que.c_str());
    } else {
        std::printf("  FALLA %s\n", que.c_str());
        ++fallos;
    }
}

vxdbg::StoredNode nodo(uint64_t id, size_t tam) {
    vxdbg::StoredNode n;
    n.header.hash.lo = id;
    n.header.hash.hi = id * 2654435761u + 7u;
    n.header.kind = static_cast<vxdbg::NodeKind>(id % 4);
    n.header.schema_version = 1;
    n.payload.resize(tam);
    for (size_t i = 0; i < tam; ++i)
        n.payload[i] = static_cast<uint8_t>((id * 31 + i * 7) & 0xFF);
    return n;
}

} // namespace

int main() {
    namespace stdfs = std::filesystem;
    const std::string raiz = vesta_test::dir_unico("vesta_test_pack");
    std::error_code ec;
    stdfs::remove_all(raiz, ec);

    std::printf("[paquetes] lo que sale tiene que ser lo que entro\n");

    // Tamanos variados a proposito: uno vacio, uno de un byte y uno que cruza
    // varios kilobytes.  Un formato con desplazamientos se rompe justo en los
    // extremos.
    const size_t N = 300;
    std::vector<vxdbg::StoredNode> originales;
    originales.reserve(N);
    for (size_t i = 0; i < N; ++i)
        originales.push_back(nodo(i + 1, (i % 7 == 0) ? 0 : (i * 13) % 5000));

    // --- escribir ---------------------------------------------------------
    {
        vxdbg::PackNodeStore store(raiz, nullptr);
        bool todos = true;
        for (const auto &n : originales)
            todos = store.put(n) && todos;
        comprueba(todos, "se aceptan los " + std::to_string(N) + " nodos");
        comprueba(store.pendientes() == N, "quedan pendientes hasta volcar");
        comprueba(store.volcar(), "el volcado escribe el paquete");
        comprueba(store.pendientes() == 0,
                  "tras volcar no queda nada pendiente");
    }

    // Un solo fichero de paquete: esa es toda la razon de ser de esto.
    size_t n_packs = 0;
    for (const auto &e : stdfs::directory_iterator(raiz + "/packs", ec))
        if (e.is_regular_file(ec)) ++n_packs;
    comprueba(n_packs == 1,
              "los " + std::to_string(N) + " nodos caben en UN fichero");

    // --- releer, con OTRO almacen (proceso distinto en la practica) --------
    {
        vxdbg::PackNodeStore lector(raiz, nullptr);
        size_t iguales = 0, presentes = 0;
        for (const auto &orig : originales) {
            if (lector.contains(orig.header.hash)) ++presentes;
            vxdbg::StoredNode leido;
            if (!lector.get(orig.header.hash, leido)) continue;
            if (leido.payload == orig.payload &&
                leido.header.kind == orig.header.kind &&
                leido.header.schema_version == orig.header.schema_version &&
                leido.header.hash == orig.header.hash)
                ++iguales;
        }
        comprueba(presentes == N, "un almacen NUEVO los encuentra todos");
        comprueba(iguales == N, "y los devuelve BYTE A BYTE como entraron");

        vxdbg::StoredNode fuera;
        vxdbg::ContentHash inventada;
        inventada.lo = 0xDEADBEEF;
        inventada.hi = 0xC0FFEE;
        comprueba(!lector.get(inventada, fuera),
                  "una huella que no existe no devuelve nada");
    }

    // --- lo que ya esta NO se vuelve a escribir ----------------------------
    //
    // Reutilizar es lo primero: si una compilacion vuelve a producir los mismos
    // nodos -- lo normal, porque la clave es el contenido -- no debe escribir
    // nada.  Sin esto los paquetes se duplican y, peor, los viejos dejan de
    // poder borrarse porque conservan entradas vivas.
    {
        vxdbg::PackNodeStore otra(raiz, nullptr);
        for (const auto &n : originales)
            otra.put(n);
        comprueba(otra.pendientes() == 0,
                  "volver a guardar lo mismo no deja NADA pendiente");
        comprueba(otra.volcar(), "y volcar no falla");
        size_t packs2 = 0;
        for (const auto &e : stdfs::directory_iterator(raiz + "/packs", ec))
            if (e.is_regular_file(ec)) ++packs2;
        comprueba(packs2 == 1, "sigue habiendo UN solo paquete, no dos");
    }

    // --- un paquete estropeado se DESCARTA, no se cree ---------------------
    {
        std::string ruta;
        for (const auto &e : stdfs::directory_iterator(raiz + "/packs", ec))
            if (e.is_regular_file(ec)) ruta = e.path().string();
        std::vector<uint8_t> bytes;
        fs::read_file_bytes(ruta, bytes);
        // Se toca un byte DEL INDICE (justo antes de la cola de 20 bytes), que
        // es el caso peligroso: el cuerpo esta intacto, asi que sin la suma de
        // comprobacion el almacen serviria un nodo por otro tan campante.
        if (bytes.size() > 40) bytes[bytes.size() - 30] ^= 0xFF;
        fs::write_file_atomic(ruta, bytes);

        vxdbg::PackNodeStore roto(raiz, nullptr);
        size_t encontrados = 0;
        for (const auto &orig : originales)
            if (roto.contains(orig.header.hash)) ++encontrados;
        comprueba(
            encontrados == 0,
            "con el indice alterado NO se sirve nada (se descarta el paquete)");
    }

    stdfs::remove_all(raiz, ec);

    // ======================================================================
    //  ESTRES: el peor caso de la reclamacion
    // ======================================================================
    //
    // El peor caso no es "muchos paquetes": es que casi todos esten MEDIO
    // vivos.  Ahi no se puede borrar casi nada -- hacerlo perderia la entrada
    // que sigue usandose -- y el almacen tiene que seguir sirviendo TODO lo
    // vivo despues de barrer.  Un fallo aqui no da error: da AUSENCIA, y se
    // manifiesta mucho despues como un artefacto que ya no esta.
    std::printf("\n[paquetes] estres: reclamar con paquetes medio vivos\n");
    {
        const size_t PACKS = 40, POR_PACK = 50;
        std::vector<vxdbg::StoredNode> todos;
        std::set<vxdbg::ContentHash> vivas;
        {
            vxdbg::PackNodeStore store(raiz, nullptr);
            uint64_t id = 1000;
            for (size_t p = 0; p < PACKS; ++p) {
                for (size_t i = 0; i < POR_PACK; ++i) {
                    vxdbg::StoredNode n = nodo(id++, (i * 37) % 900);
                    todos.push_back(n);
                    // Uno de cada cinco paquetes queda ENTERO muerto; de los
                    // demas sobrevive una sola entrada, que es justo lo que
                    // impide borrarlos.
                    if (p % 5 != 0 && i == 0) vivas.insert(n.header.hash);
                    store.put(n);
                }
                store.volcar(); // un paquete por vuelta
            }
        }

        size_t antes = 0;
        for (const auto &e : stdfs::directory_iterator(raiz + "/packs", ec))
            if (e.is_regular_file(ec)) ++antes;
        comprueba(antes == PACKS,
                  "se escribieron " + std::to_string(PACKS) + " paquetes");

        vxdbg::PackNodeStore store(raiz, nullptr);
        const size_t borrados = store.reclamar(vivas);
        comprueba(borrados == PACKS / 5,
                  "se borran SOLO los " + std::to_string(PACKS / 5) +
                      " sin nada vivo (borrados: " + std::to_string(borrados) +
                      ")");

        // La comprobacion que de verdad importa: barrer de mas no da error.
        size_t vivos_ok = 0;
        for (const auto &n : todos) {
            if (vivas.count(n.header.hash) == 0) continue;
            vxdbg::StoredNode leido;
            if (store.get(n.header.hash, leido) && leido.payload == n.payload)
                ++vivos_ok;
        }
        comprueba(vivos_ok == vivas.size(),
                  "TODO lo vivo sigue ahi tras barrer (" +
                      std::to_string(vivos_ok) + "/" +
                      std::to_string(vivas.size()) + ")");

        comprueba(store.reclamar(vivas) == 0,
                  "barrer otra vez no borra nada mas");

        comprueba(store.reclamar({}) == PACKS - PACKS / 5,
                  "sin nada vivo se borran todos los que quedaban");
        size_t despues = 0;
        for (const auto &e : stdfs::directory_iterator(raiz + "/packs", ec))
            if (e.is_regular_file(ec)) ++despues;
        comprueba(despues == 0, "no queda ningun paquete");
    }
    stdfs::remove_all(raiz, ec);

    std::printf(fallos == 0 ? "\n[paquetes] TODO OK\n"
                            : "\n[paquetes] %d FALLOS\n",
                fallos);
    return fallos == 0 ? 0 : 1;
}
