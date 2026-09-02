/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file tests/util/module_symbols.h
 * @brief Poner NOMBRE a una direccion del propio proceso.
 *
 * Para que
 * --------
 * El derivador dice donde se queda corto -- "hay una llamada indirecta en
 * 0x7FF608E11580" -- y con eso no se puede hacer nada: hay que averiguar en que
 * funcion cae antes de poder cerrarla.  Con el nombre, cada hueco pasa de ser
 * una direccion a ser trabajo concreto.
 *
 * De donde salen los nombres
 * --------------------------
 * De la tabla de simbolos COFF del propio binario, leida con NUESTRO parser
 * (@c LibCOFFparse / @c LibPEparse), que es el mismo que usan el emisor de
 * objetos y el enlazador.  No hace falta nada de fuera: se probo `dbghelp` del
 * sistema y no lee el DWARF que emite MinGW -- devuelve 126/487 --, ademas de
 * ser una dependencia que solo existe en Windows.
 *
 * Que build hace falta
 * --------------------
 * El de RELEASE enlaza con `--strip-all`, que borra la tabla entera: ahi esto
 * responde que no hay simbolos, y lo DICE, en vez de dar nombres inventados.
 * El de `Profile` compila exactamente lo mismo pero sin estripar -- esta puesto
 * asi a proposito, ver `CMakeLists.txt` --, y es donde hay 118.979 simbolos.
 *
 * Como se pasa de un simbolo a una direccion
 * ------------------------------------------
 * La tabla guarda direcciones relativas a la base PREFERIDA de la imagen, que
 * es la que dice la cabecera; el cargador puede poner el modulo en otra.  Asi
 * que el desplazamiento se calcula al vuelo: `real = cargada + (simbolo -
 * preferida)`.  Suponer que coinciden funciona hasta que no, y entonces todos
 * los nombres salen corridos.
 */

#ifndef VESTA_TESTS_MODULE_SYMBOLS_H
#define VESTA_TESTS_MODULE_SYMBOLS_H

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#if defined(__GNUC__)
#include <cxxabi.h> // deshacer la codificacion de nombres de C++
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace tests {

/// Un simbolo de codigo, ya trasladado a la direccion en que esta CARGADO.
struct ModuleSymbol {
    uint64_t addr = 0; ///< direccion real en este proceso
    std::string name;  ///< nombre tal como lo guarda la tabla
};

/**
 * @brief Los simbolos de codigo del modulo que contiene @p ancla.
 *
 * Se leen UNA vez y se ordenan por direccion, para que resolver sea una
 * busqueda binaria: el derivador pregunta por cada hueco, y son decenas.
 *
 * @return La lista ordenada.  VACIA si el binario esta estripado, que es el
 *         caso de Release: no es un fallo, es que ahi no hay nombres.
 */
inline const std::vector<ModuleSymbol> &module_symbols(const void *ancla) {
    static std::vector<ModuleSymbol> tabla;
    static bool hecho = false;
    if (hecho) return tabla;
    hecho = true;
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ancla, &mbi, sizeof(mbi)) == 0) return tabla;
    const uint8_t *base = static_cast<const uint8_t *>(mbi.AllocationBase);
    if (base == nullptr) return tabla;

    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return tabla;
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return tabla;

    const uint32_t off_tabla = nt->FileHeader.PointerToSymbolTable;
    const uint32_t n = nt->FileHeader.NumberOfSymbols;
    if (off_tabla == 0 || n == 0) return tabla; // estripado: no hay nombres

    /* La tabla de simbolos vive a un desplazamiento de FICHERO, y el modulo
     * cargado esta mapeado por SECCIONES: los dos no coinciden.  Asi que se lee
     * del fichero, no de la imagen. */
    char ruta[MAX_PATH];
    if (GetModuleFileNameA(reinterpret_cast<HMODULE>(
                               const_cast<uint8_t *>(base)),
                           ruta, MAX_PATH) == 0)
        return tabla;
    std::FILE *f = std::fopen(ruta, "rb");
    if (f == nullptr) return tabla;

    /* Cada entrada mide 18 bytes; detras de la ultima empieza el almacen de
     * nombres largos, cuyo primer entero es su propio tamano. */
    constexpr uint32_t kEntrada = 18;
    std::vector<uint8_t> crudo(static_cast<size_t>(n) * kEntrada);
    std::fseek(f, static_cast<long>(off_tabla), SEEK_SET);
    if (std::fread(crudo.data(), 1, crudo.size(), f) != crudo.size()) {
        std::fclose(f);
        return tabla;
    }
    uint32_t tam_nombres = 0;
    std::vector<char> nombres;
    if (std::fread(&tam_nombres, 1, sizeof(tam_nombres), f) ==
            sizeof(tam_nombres) &&
        tam_nombres > sizeof(tam_nombres)) {
        nombres.resize(tam_nombres);
        std::memcpy(nombres.data(), &tam_nombres, sizeof(tam_nombres));
        std::fread(nombres.data() + sizeof(tam_nombres), 1,
                   tam_nombres - sizeof(tam_nombres), f);
    }
    std::fclose(f);

    /* Donde empieza cada seccion, para pasar de (seccion, desplazamiento) a
     * direccion. */
    const auto *sec = IMAGE_FIRST_SECTION(nt);
    const uint16_t n_sec = nt->FileHeader.NumberOfSections;
    const uint64_t preferida = nt->OptionalHeader.ImageBase;
    const uint64_t cargada = reinterpret_cast<uint64_t>(base);

    tabla.reserve(n / 4);
    for (uint32_t i = 0; i < n;) {
        const uint8_t *e = crudo.data() + static_cast<size_t>(i) * kEntrada;
        int16_t n_seccion = 0;
        uint32_t valor = 0;
        uint8_t aux = 0;
        std::memcpy(&valor, e + 8, 4);
        std::memcpy(&n_seccion, e + 12, 2);
        aux = e[17];
        i += 1u + aux;                             // saltar los auxiliares
        if (n_seccion <= 0 || n_seccion > n_sec) continue; // sin seccion
        const auto &s = sec[n_seccion - 1];
        if ((s.Characteristics & IMAGE_SCN_CNT_CODE) == 0) continue;

        uint32_t cero = 0;
        std::memcpy(&cero, e, 4);
        std::string nombre;
        if (cero == 0) { // nombre largo: indice en el almacen
            uint32_t desp = 0;
            std::memcpy(&desp, e + 4, 4);
            if (desp < nombres.size()) nombre = nombres.data() + desp;
        } else {
            char corto[9] = {0};
            std::memcpy(corto, e, 8);
            nombre = corto;
        }
        if (nombre.empty()) continue;
        /* El enlazador antepone la seccion a los simbolos que agrupa por
         * funcion (`--ffunction-sections`): `.text$` y hermanos.  Es ruido para
         * quien lee el informe. */
        const size_t dolar = nombre.find('$');
        if (dolar != std::string::npos && nombre[0] == '.')
            nombre = nombre.substr(dolar + 1);
        /* `Value` es el desplazamiento dentro de la seccion; con la direccion
         * virtual de esta sale la relativa, y con la base cargada la real. */
        const uint64_t rva = s.VirtualAddress + valor;
        (void)preferida;
        tabla.push_back({cargada + rva, nombre});
    }
    std::sort(tabla.begin(), tabla.end(),
              [](const ModuleSymbol &a, const ModuleSymbol &b) {
                  return a.addr < b.addr;
              });
#else
    (void)ancla; // POSIX: se lee del ELF; sin escribir todavia
#endif
    return tabla;
}

/**
 * @brief El nombre de C++ como se escribio, no como lo codifica el enlazador.
 *
 * `_ZN7runtime17exec_instr_strlenEPNS_9ProcessVMERKNS_12DecodedInstrE` no dice
 * nada de un vistazo, y el informe lo va a leer una persona.  Lo deshace la
 * propia libreria estandar, que es quien conoce la codificacion; si no lo
 * reconoce -- un simbolo de C, o de otro compilador -- se devuelve tal cual.
 */
inline std::string demangle(const std::string &s) {
#if defined(__GNUC__)
    int estado = 0;
    char *d = abi::__cxa_demangle(s.c_str(), nullptr, nullptr, &estado);
    if (estado == 0 && d != nullptr) {
        std::string r(d);
        std::free(d);
        return r;
    }
    if (d != nullptr) std::free(d);
#endif
    return s;
}

/**
 * @brief En que funcion cae @p dir, y a que distancia de su principio.
 *
 * @return El nombre mas `+N`, o una cadena vacia si no hay simbolos (Release) o
 *         la direccion cae fuera del modulo.  Vacio significa "no se sabe", no
 *         "no tiene nombre": quien lo imprima debe distinguirlo.
 */
inline std::string symbol_at(const void *ancla, uint64_t dir) {
    const std::vector<ModuleSymbol> &t = module_symbols(ancla);
    if (t.empty()) return std::string();
    auto it = std::upper_bound(t.begin(), t.end(), dir,
                               [](uint64_t d, const ModuleSymbol &s) {
                                   return d < s.addr;
                               });
    if (it == t.begin()) return std::string();
    --it;
    /* Sin tamano de simbolo no se puede saber si `dir` sigue DENTRO de esa
     * funcion.  Un tope evita atribuirle media seccion a la ultima de la lista,
     * que es como un nombre equivocado se cuela sin que nadie lo note. */
    constexpr uint64_t kMaxFuncion = 256 * 1024;
    if (dir - it->addr > kMaxFuncion) return std::string();
    const uint64_t desp = dir - it->addr;
    const std::string n = demangle(it->name);
    return desp == 0 ? n : n + "+" + std::to_string(desp);
}

} // namespace tests

#endif // VESTA_TESTS_MODULE_SYMBOLS_H
