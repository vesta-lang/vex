/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file toolchain/aot_build.cpp
 * @brief Emisor AOT nativo (PE/ELF) extraido del monolito de main.cpp.
 *
 * Contiene @c vesta::tc::compile_aot: toma el @c CompileResult del frontend
 * (con el IR embebido + los simbolos @AllocatorOverride/@PanicHandler) y emite
 * el artefacto nativo pedido (.exe/.o/.so/.bin, PE o ELF, x86-64/x86-32),
 * auto-bundleando el runtime de excepciones / I/O / colecciones cuando hace
 * falta y auto-enlazando con el linker propio.  Movido aqui para desmonolitizar
 * main.cpp; la logica es la misma (mismo camino que producia el `.exe` AOT).
 *
 * @note De momento recibe el @c cxxopts::ParseResult para leer los flags
 *       especificos de AOT (--format/--emit/--aot-arch/--float-isa/--no-pie/
 *       --bin-base/--sysroot); el resto de estado llega por parametros.  Una
 *       limpieza posterior puede sustituir @c result por una struct de opciones
 *       para que consumidores sin cxxopts (el LSP) tambien puedan invocarlo.
 */

#include "util/env_flags.h"
#include "toolchain/aot_build.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include "vx/vxdbg_emit.h"

#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "aot/aot_analyze.h"
#include "aot/aot_lower.h"
#include "aot/aot_native.h"
#include "aot/linker.h"
#include "aot/object_writer.h"
#include "ir/ir_emitter.h"
#include "ir/ir_optimizer.h"
#include "ir/ssa_ir.h"
#include "ir/ssa_ir_serialize.h"
#include "jit/vec_isa.h"
#include "jit/vreg_pipeline.h"
#include "toolchain/native_backend.h" // backend de codegen nativo por arch (H.5)
#include "util/fnv.h"                 // huella de las claves del CAS
#include "util/fs_utils.h"
#include "vx/incremental.h"            // CasStore: artefactos por contenido
#include "vx/module/module_resolver.h" // grafo de dependencias
#include "vx/module/vxi_format.h"      // vxi_compiler_version_hash
#include "vx/parser.h"                 // get_aot_condcomp_target
#include "vx/compiler.h"

namespace vesta {
namespace tc {

/**
 * @brief Un punto del fuente al que corresponde un tramo de codigo nativo.
 */
struct PuntoAcompanante {
    uint32_t off;  ///< desplazamiento dentro de la funcion
    uint32_t line; ///< linea del fuente
    uint32_t col;  ///< columna (0 = no consta)
    uint32_t len;  ///< cuanto ocupa el tramo (0 = no consta)
};

/**
 * @brief Escribe el fichero acompanante que explica despues un fallo.
 *
 * NO toca el binario.  Ni una seccion, ni un byte: el programa emitido es
 * exactamente el mismo con esta informacion y sin ella.  Meterle un manejador
 * o un trap para que se explique solo cambiaria el programa que despues se
 * depura, y lo que veria un depurador externo o un desensamblador ya no seria
 * lo que se compilo.  Por eso va aparte, al modo de un `.pdb` o un `.dSYM`.
 *
 * Los desplazamientos son RELATIVOS a cada funcion, no direcciones absolutas:
 * asi se apoya en el otro mecanismo en lugar de duplicarlo -- el `.symtab` que
 * emite `--debug-info=1` hace que un depurador diga `main+0x3a`, y esto explica
 * que hay ahi.
 *
 * @param ruta Fichero destino.
 * @param fuente Ruta del `.vx` que se compilo.
 * @param funcs Nombres de funcion, en el mismo orden que @p puntos.
 * @param puntos Puntos de fuente de cada funcion.
 * @return true si se pudo escribir.
 */
static bool
escribir_acompanante(const std::string &ruta, const std::string &fuente,
                     const std::vector<std::string> &funcs,
                     const std::vector<std::vector<PuntoAcompanante>> &puntos) {
    std::ofstream f(ruta, std::ios::binary);
    if (!f) return false;
    auto u32 = [&](uint32_t v) { f.write((const char *)&v, 4); };
    auto str = [&](const std::string &t) {
        u32((uint32_t)t.size());
        if (!t.empty()) f.write(t.data(), (std::streamsize)t.size());
    };
    f.write("VXDG", 4);
    u32(2u); // v2: cada punto lleva linea, columna y tramo
    str(fuente);
    uint32_t n_con_mapa = 0;
    for (const auto &m : puntos)
        if (!m.empty()) ++n_con_mapa;
    u32(n_con_mapa);
    for (size_t i = 0; i < funcs.size() && i < puntos.size(); ++i) {
        if (puntos[i].empty()) continue;
        str(funcs[i]);
        u32((uint32_t)puntos[i].size());
        for (const PuntoAcompanante &p : puntos[i]) {
            u32(p.off);
            u32(p.line);
            u32(p.col);
            u32(p.len);
        }
    }
    return true;
}

/**
 * @struct TelemetriaBackend
 * @brief Reparto del tiempo del backend AOT, publicado al terminar.
 *
 * El frontend ya dice donde se le va el tiempo (analisis, tipos, bajada,
 * optimizar, emitir); el backend nativo no decia nada, y es donde vive la
 * mitad cara de una compilacion AOT.  Esto lo cierra con cuatro tramos que
 * se corresponden con las fronteras REALES del codigo, no con una division
 * inventada: preparar el IR para nativo, generar codigo maquina funcion a
 * funcion, montar el fichero objeto y enlazar.
 *
 * Se publica en el DESTRUCTOR a proposito: `compile_aot` sale por muchos
 * sitios (cada validacion de flag, cada error de codegen) y asi el reparto
 * aparece tambien cuando la compilacion falla -- que es justo cuando saber
 * hasta donde se llego tiene mas valor.  Los tramos que no se alcanzaron
 * quedan a cero y no se imprimen.
 */
struct TelemetriaBackend {
    long preparar_us = 0; ///< IR -> IR listo para nativo (merge, lowering).
    long codegen_us = 0;  ///< Seleccion + regalloc + codificacion por funcion.
    long objeto_us = 0;   ///< Secciones, relocalizaciones y escritura.
    long enlazar_us = 0;  ///< Enlazador propio (solo si hubo auto-link).

    /** Parte de @c preparar_us que se va en compilar los modulos de stdlib
     *  escritos en Vesta (vx_exc, vx_sync, vx_thread, vx_async, vx_fiber,
     *  vx_io, vx_fault, vx_mem, vx_ffi).  NO es "runtime": no hay servicio
     *  vivo detras -- son codigo que se compila DENTRO del programa, igual
     *  que el del usuario.  El runtime es otra cosa (libvesta_rt: GC,
     *  monitores, futuros).  NO suma aparte: es un DE LOS CUALES, para no
     *  contar dos veces. */
    long stdlib_us = 0;

    int stdlib_cache_ = 0; ///< Cuantos modulos de stdlib vinieron del CAS.
    int stdlib_total_ = 0; ///< Cuantos modulos de stdlib se necesitaron.

    std::chrono::steady_clock::time_point marca =
        std::chrono::steady_clock::now();

    /** @brief Cierra un tramo: acumula lo transcurrido y reinicia el reloj. */
    void cerrar(long &destino) {
        const auto ahora = std::chrono::steady_clock::now();
        destino += (long)std::chrono::duration_cast<std::chrono::microseconds>(
                       ahora - marca)
                       .count();
        marca = ahora;
    }

    /** @brief Suma a @c stdlib_us lo transcurrido desde @p desde. */
    void sumar_stdlib(const std::chrono::steady_clock::time_point &desde) {
        stdlib_us +=
            (long)std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - desde)
                .count();
    }

    long total_us() const {
        return preparar_us + codegen_us + objeto_us + enlazar_us;
    }

    ~TelemetriaBackend() {
        if (total_us() <= 0) return;
        auto ms = [](long us) { return (double)us / 1000.0; };
        std::cout << "[aot] backend: preparar " << ms(preparar_us) << " ms";
        if (stdlib_us > 0)
            std::cout << " (stdlib en Vesta " << ms(stdlib_us) << " ms";
        if (stdlib_us > 0 && stdlib_cache_ > 0)
            std::cout << ", " << stdlib_cache_ << " de cache";
        if (stdlib_us > 0) std::cout << ")";
        std::cout << " | codegen " << ms(codegen_us) << " ms | objeto "
                  << ms(objeto_us) << " ms";
        if (enlazar_us > 0)
            std::cout << " | enlazar " << ms(enlazar_us) << " ms";
        std::cout << " | total " << ms(total_us()) << " ms\n";
        // Linea para consumo automatico (el banco de pruebas de compilacion la
        // lee sin tener que parsear la prosa de arriba).
        std::cout << "__VESTA_TIMES_BACKEND__ {\"preparar_us\":" << preparar_us
                  << ",\"codegen_us\":" << codegen_us
                  << ",\"objeto_us\":" << objeto_us
                  << ",\"enlazar_us\":" << enlazar_us
                  << ",\"stdlib_us\":" << stdlib_us
                  << ",\"stdlib_cache\":" << stdlib_cache_
                  << ",\"stdlib_total\":" << stdlib_total_
                  << ",\"total_us\":" << total_us() << "}\n";
    }
};

/**
 * @brief Mezcla una cadena (con su longitud) en una huella FNV-1a.
 *
 * La longitud entra aparte para que dos campos contiguos no se confundan:
 * sin ella, ("ab","c") y ("a","bc") darian la misma huella.
 *
 * @param h Huella acumulada.
 * @param s Cadena a mezclar.
 * @return La huella actualizada.
 */
static uint64_t mezclar_str_(uint64_t h, const std::string &s) {
    h = util::fnv_mix(h, s.size());
    return util::fnv_bytes(h, s.data(), s.size());
}

/**
 * @brief Le pone el bit de ejecucion a un artefacto recien escrito.
 *
 * Los emisores abren el fichero con @c fopen(path,"wb"), que en POSIX lo crea
 * con 0666 & ~umask -- o sea 0644 -- y por tanto SIN permiso de ejecucion.  El
 * resultado era un ELF perfectamente valido que no se podia ejecutar:
 * `Permission denied` al lanzarlo, sin que nada en la compilacion hubiera
 * fallado.  En Windows no se veia porque no existe ese bit, asi que el fallo
 * solo aparecia en Linux y parecia un problema de permisos del usuario.
 *
 * Se hace aqui, en el toolchain, y no en cada emisor: los emisores tambien
 * escriben `.o` y binarios planos, que NO deben ser ejecutables, y este es el
 * unico sitio que sabe que clase de artefacto se pidio.
 *
 * Anade el bit a los tres grupos respetando lo que ya haya (0644 -> 0755).  Un
 * fallo no aborta la compilacion: el fichero esta bien escrito, y avisar es
 * mas util que tirar un build entero por un permiso.
 *
 * @param ruta Artefacto a marcar.  En Windows no hace nada.
 */
static void marcar_ejecutable_(const std::string &ruta) {
#ifndef _WIN32
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::permissions(ruta,
                    fs::perms::owner_exec | fs::perms::group_exec |
                        fs::perms::others_exec,
                    fs::perm_options::add, ec);
    if (ec)
        std::cerr << "[aot] aviso: no se pudo marcar '" << ruta
                  << "' como ejecutable: " << ec.message() << "\n";
#else
    (void)ruta;
#endif
}

/**
 * @struct EntradaModulo
 * @brief Lo que se recuerda de UN modulo: su huella y de quien depende.
 *
 * Descubrir de quien depende un modulo exige PARSEARLO, y eso cuesta mas que
 * la cache que se intenta aprovechar (medido: reconstruir el cierre de
 * vx_mem son ~165 ms, frente a los ~52 de recorrer el arbol entero).  La
 * salida no es descubrirlo mejor, es no volver a descubrirlo: se guarda la
 * RELACION -- este modulo importa estos otros -- y la siguiente construccion
 * se limita a comprobar si sigue siendo cierta, que es mucho mas barato que
 * derivarla.
 *
 * Se guarda por MODULO y no por programa a proposito.  Asi dos programas que
 * compartan dependencias comparten tambien su descubrimiento, y un cambio en
 * una hoja solo obliga a re-resolver esa hoja en vez de todo el cierre: el
 * numero de modulos deja de importar tanto.
 *
 * Todo lo que puede invalidarla va en la CLAVE, no en el valor, porque el
 * store es direccionado por contenido: su escritura es idempotente y no
 * reescribe lo que ya existe.  Guardar ahi un dato mutable -- la huella del
 * fichero, por ejemplo -- deja la primera version pegada para siempre, y a
 * partir de entonces la comprobacion falla en cada construccion sin que se
 * note mas que en el tiempo.  Con la clave completa no hay obsolescencia
 * posible: si algo cambio, es OTRA entrada.
 *
 * La clave cubre las dos maneras de quedarse obsoleto:
 *
 *   - que el fichero haya cambiado (si cambio, sus imports pueden ser otros);
 *   - que haya APARECIDO o desaparecido un fichero que cambiaria la
 *     resolucion -- un hermano nuevo de un namespace parcial se une al modulo
 *     sin que ningun import cambie -> entran los NOMBRES @c .vx de su
 *     directorio (sin recursion: son decenas, no las ~1500 del arbol).  El
 *     @c mtime del directorio seria mas barato pero no sirve: el propio
 *     compilador escribe ahi sus @c .vxi / @c .vxir con temp+rename, asi que
 *     cambia en cada construccion aunque ningun fuente se haya tocado.
 */
struct EntradaModulo {
    /** Ruta canonica del modulo.  Va DENTRO de la entrada porque la ruta con
     *  la que se busca no tiene por que ser la canonica: el AOT localiza sus
     *  modulos con rutas relativas (@c stdlib/vx/vx_mem.vx) mientras que el
     *  resolutor trabaja en absolutas normalizadas.  Guardarla aqui permite
     *  indexar la raiz por la ruta tal como llega sin que el resto del grafo
     *  -- que sigue en canonicas -- deje de encajar. */
    std::string canonico;
    std::vector<std::string> deps; ///< Rutas canonicas de lo que importa.
};

/** @brief Escribe un entero de 32 bits en little-endian al final de @p out. */
static void poner_u32_(std::vector<uint8_t> &out, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
}

/** @brief Escribe un entero de 64 bits en little-endian al final de @p out. */
static void poner_u64_(std::vector<uint8_t> &out, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        out.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
}

/** @brief Escribe una cadena con su longitud delante. */
static void poner_str_(std::vector<uint8_t> &out, const std::string &s) {
    poner_u32_(out, (uint32_t)s.size());
    out.insert(out.end(), s.begin(), s.end());
}

/**
 * @brief Serializa una @c EntradaModulo para guardarla en el store.
 * @param e Entrada a serializar.
 * @return Bytes del artefacto.
 */
static std::vector<uint8_t> escribir_entrada_(const EntradaModulo &e) {
    std::vector<uint8_t> out;
    poner_str_(out, e.canonico);
    poner_u32_(out, (uint32_t)e.deps.size());
    for (const auto &d : e.deps)
        poner_str_(out, d);
    return out;
}

/**
 * @brief Deserializa lo que escribio @c escribir_entrada_.
 * @param b Bytes leidos del store.
 * @param e Entrada destino.
 * @return false si el blob esta truncado (se trata como "no hay entrada").
 */
static bool leer_entrada_(const std::vector<uint8_t> &b, EntradaModulo &e) {
    size_t p = 0;
    auto u32 = [&](uint32_t &v) -> bool {
        if (p + 4 > b.size()) return false;
        v = 0;
        for (int i = 0; i < 4; ++i)
            v |= (uint32_t)b[p + i] << (i * 8);
        p += 4;
        return true;
    };
    auto str = [&](std::string &s) -> bool {
        uint32_t len = 0;
        if (!u32(len) || p + len > b.size()) return false;
        s.assign((const char *)b.data() + p, len);
        p += len;
        return true;
    };
    uint32_t n = 0;
    if (!str(e.canonico) || !u32(n)) return false;
    e.deps.resize(n);
    for (uint32_t i = 0; i < n; ++i)
        if (!str(e.deps[i])) return false;
    return true;
}

/**
 * @brief Hash de los NOMBRES de los fuentes @c .vx de un directorio.
 *
 * Sin recursion y sin preguntar por cada entrada si es un fichero regular:
 * basta la extension, que viene con el propio recorrido.  Son decenas de
 * entradas por directorio (26 en @c stdlib/vx , 147 en @c stdlib/vx/std ),
 * no las ~1500 del arbol completo, y varios modulos comparten directorio, asi
 * que se calcula una vez por proceso.
 *
 * @param dir Directorio a listar.
 * @return Hash de los nombres, o 0 si no se puede listar.
 */
static uint64_t huella_nombres_vx_(const std::filesystem::path &dir) {
    namespace fs = std::filesystem;
    static std::map<std::string, uint64_t> memo;
    const std::string clave = dir.string();
    auto it = memo.find(clave);
    if (it != memo.end()) return it->second;

    std::error_code ec;
    std::vector<std::string> nombres;
    for (fs::directory_iterator it2(dir, ec), fin; it2 != fin;
         it2.increment(ec)) {
        if (ec) break;
        if (it2->path().extension() != ".vx") continue;
        nombres.push_back(it2->path().filename().string());
    }
    if (ec || nombres.empty()) {
        memo[clave] = 0;
        return 0;
    }
    // El orden del sistema de ficheros no es estable entre maquinas.
    std::sort(nombres.begin(), nombres.end());
    uint64_t h = util::kFnvOffset;
    for (const auto &n : nombres)
        h = mezclar_str_(h, n);
    if (h == 0) h = 1; // 0 esta reservado para "no se pudo".
    memo[clave] = h;
    return h;
}

/** @brief Hash del contenido de un fichero, o 0 si no se puede leer. */
static uint64_t huella_fichero_(const std::string &ruta) {
    std::ifstream in(ruta, std::ios::binary);
    if (!in) return 0;
    std::string c((std::istreambuf_iterator<char>(in)),
                  std::istreambuf_iterator<char>());
    const uint64_t h = util::fnv_bytes(util::kFnvOffset, c.data(), c.size());
    return h == 0 ? 1ull : h; // 0 esta reservado para "no se pudo".
}

/**
 * @brief Clave con la que se recuerda un modulo en el store.
 *
 * Lleva TODO lo que puede invalidar la entrada -- el contenido del fichero y
 * los nombres de su directorio, ademas de donde se buscan los imports -- para
 * que el valor guardado no pueda quedarse obsoleto: si algo cambia, es otra
 * clave.  Es lo que exige un store direccionado por contenido, cuya escritura
 * es idempotente y jamas reescribe una clave existente.
 *
 * @param ruta Ruta del modulo (tal como se busca; no tiene por que ser la
 *        canonica).
 * @param huella_contenido Hash del contenido del fichero.
 * @param huella_dir Hash de los nombres @c .vx de su directorio.
 * @return Clave del store.
 */
static uint64_t clave_entrada_(const std::string &ruta,
                               uint64_t huella_contenido, uint64_t huella_dir) {
    uint64_t k = util::kFnvOffset;
    k = util::fnv_mix(k, 0x414F544445505347ull); // dominio "AOTDEPSG".
    /* Version del FORMATO de la entrada.  Sin esto, cambiar que se guarda
     * dentro deja las entradas viejas bajo la misma clave y el lector nuevo
     * las encuentra truncadas: no es un fallo visible, solo deja de acertar
     * en silencio.  Subir este numero al tocar `EntradaModulo`. */
    k = util::fnv_mix(k, 3ull);
    k = util::fnv_mix(k, vx::vxi_compiler_version_hash());
    k = mezclar_str_(k, ruta);
    k = util::fnv_mix(k, huella_contenido);
    k = util::fnv_mix(k, huella_dir);
    const char *vp = std::getenv("VX_PATH");
    k = mezclar_str_(k, vp != nullptr ? vp : "");
    k = mezclar_str_(k, vx::detect_stdlib_vx_dir());
    return k;
}

/**
 * @brief Resuelve el cierre de imports PARSEANDO, y recuerda cada modulo.
 *
 * Lo calcula el mismo @c ModuleGraph que usa la compilacion de verdad, con la
 * misma configuracion.  Reimplementar aqui las reglas de resolucion seria
 * tener dos criterios para lo mismo, y dos criterios acaban dando dos
 * respuestas distintas: el resolutor tambien arrastra los ficheros HERMANOS
 * de un namespace parcial, y una copia se dejaria eso fuera sin avisar.
 *
 * Deja en el store una entrada POR MODULO, con sus dependencias directas, de
 * modo que la proxima construccion -- de este programa o de otro que comparta
 * dependencias -- pueda recorrer el grafo sin volver a parsear.
 *
 * @param path Modulo raiz.
 * @param store Donde recordar (nullptr = no recordar).
 * @param cierre Salida: (ruta, huella) de cada modulo alcanzado.
 * @return false ante cualquier duda (no resuelve, ciclo, errores).
 */
static bool
resolver_y_recordar_(const std::string &path, const vx::CasStore *store,
                     std::vector<std::pair<std::string, uint64_t>> &cierre) {
    namespace fs = std::filesystem;
    vx::Diagnostics diags;
    vx::ModuleGraph graph(diags);
    // Misma configuracion que `compile_vx_project`: si difiere, el cierre
    // podria no ser el que se compila.  (El overlay del LSP y los search paths
    // extra no aplican al camino AOT.)
    graph.add_vx_path_env();
    const std::string sd = vx::detect_stdlib_vx_dir();
    if (!sd.empty()) graph.set_stdlib_dir(sd);
    {
        std::string norm = path;
        for (char &c : norm)
            if (c == '\\') c = '/';
        const size_t barra = norm.find_last_of('/');
        if (barra != std::string::npos)
            graph.add_search_path(norm.substr(0, barra));
    }

    const uint32_t raiz = graph.build_from_root(path);
    if (raiz == UINT32_MAX || diags.has_errors() || graph.has_cycle())
        return false;
    if (graph.module_count() == 0) return false;

    cierre.clear();
    for (size_t i = 0; i < graph.module_count(); ++i) {
        const vx::ResolvedModule *m = graph.module((uint32_t)i);
        if (m == nullptr || m->canonical_path.empty()) return false;
        const uint64_t h = huella_fichero_(m->canonical_path);
        if (h == 0) return false; // no se pudo leer -> sin certeza.
        cierre.emplace_back(m->canonical_path, h);

        if (store == nullptr) continue;
        EntradaModulo e;
        e.canonico = m->canonical_path;
        const uint64_t hd =
            huella_nombres_vx_(fs::path(m->canonical_path).parent_path());
        if (hd == 0) continue; // sin listado no se puede validar.
        // La RELACION: a que ficheros resolvieron sus imports.
        bool completa = true;
        for (uint32_t dep : m->dependencies) {
            const vx::ResolvedModule *d = graph.module(dep);
            if (d == nullptr || d->canonical_path.empty()) {
                completa = false;
                break;
            }
            e.deps.push_back(d->canonical_path);
        }
        if (!completa) continue;
        const std::vector<uint8_t> bytes = escribir_entrada_(e);
        (void)store->put(clave_entrada_(m->canonical_path, h, hd), bytes);
        // La raiz, ademas, indexada por la ruta con la que la pidieron: es
        // por donde entrara la siguiente busqueda.  Mismo fichero y mismo
        // directorio, asi que las otras dos partes de la clave no cambian.
        if ((uint32_t)i == raiz && m->canonical_path != path)
            (void)store->put(clave_entrada_(path, h, hd), bytes);
    }
    return true;
}

/**
 * @brief Recorre el cierre de imports A TRAVES de lo recordado, sin parsear.
 *
 * Este es el camino que evita el coste constante: en vez de preguntar "que
 * importa este arbol", se parte de "ya se que este modulo depende de estos
 * otros" y solo se comprueba si sigue siendo cierto.  Se toca el sistema de
 * ficheros unicamente para los nodos del cierre -- tres o cuatro -- y no para
 * las ~1500 entradas del directorio.
 *
 * @param raiz Modulo de partida.
 * @param store Store con las entradas recordadas.
 * @param cierre Salida: (ruta, huella) de cada modulo alcanzado, ordenado.
 * @return false si falta alguna entrada o alguna dejo de ser valida; entonces
 *         hay que resolver de verdad.
 */
static bool
recorrer_recordado_(const std::string &raiz, const vx::CasStore &store,
                    std::vector<std::pair<std::string, uint64_t>> &cierre) {
    namespace fs = std::filesystem;
    std::vector<std::string> pendientes{raiz};
    std::set<std::string> vistos;
    cierre.clear();

    while (!pendientes.empty()) {
        const std::string ruta = pendientes.back();
        pendientes.pop_back();
        /* La cuenta de visitados se lleva SOLO por ruta canonica, y por eso
         * se apunta despues de leer la entrada.  Llevarla tambien por la ruta
         * de busqueda hacia que todo nodo que no fuera la raiz -- donde ambas
         * coinciden -- se diera por visitado antes de mirarlo, y se cayera del
         * cierre.  Volver a consultar el store por un nodo repetido no cuesta
         * casi nada; perderlo del cierre si. */
        /* El contenido y el listado del directorio son PARTE de la clave, no
         * del valor: encontrar la entrada ya demuestra que ninguno de los dos
         * ha cambiado desde que se recordo, sin comparar nada despues.  Si
         * algo cambio, sencillamente no hay entrada y toca resolver. */
        const uint64_t h = huella_fichero_(ruta);
        if (h == 0) return false;
        const uint64_t hd = huella_nombres_vx_(fs::path(ruta).parent_path());
        if (hd == 0) return false;

        std::vector<uint8_t> blob;
        EntradaModulo e;
        if (!store.get(clave_entrada_(ruta, h, hd), blob) ||
            !leer_entrada_(blob, e))
            return false; // no esta en cache -> hay que resolver.
        if (e.canonico.empty()) return false;
        // A partir de aqui se trabaja con la ruta CANONICA que trae la
        // entrada: la de busqueda puede ser relativa y no coincidiria con la
        // que usan las dependencias.
        if (!vistos.insert(e.canonico).second) continue;

        cierre.emplace_back(e.canonico, h);
        for (const auto &d : e.deps)
            pendientes.push_back(d);
    }
    return !cierre.empty();
}

/**
 * @brief Empaqueta el artefacto de un modulo de stdlib para el CAS.
 *
 * Formato: @c [u32 n_ir][ir][u32 n_alloc][alloc][u32 n_free][free].  Los dos
 * simbolos son los que declara @c vx_mem via @c \@AllocatorOverride; el resto
 * de modulos los deja vacios.  Sin ellos, un acierto de cache perderia la
 * configuracion del asignador y el enlazado bajaria a otra funcion.
 */
static std::vector<uint8_t> empaquetar_modulo_(const std::vector<uint8_t> &ir,
                                               const std::string &alloc_sym,
                                               const std::string &free_sym) {
    std::vector<uint8_t> out;
    auto poner = [&out](const uint8_t *datos, size_t n) {
        const uint32_t len = (uint32_t)n;
        for (int i = 0; i < 4; ++i)
            out.push_back((uint8_t)((len >> (i * 8)) & 0xFF));
        out.insert(out.end(), datos, datos + n);
    };
    poner(ir.data(), ir.size());
    poner((const uint8_t *)alloc_sym.data(), alloc_sym.size());
    poner((const uint8_t *)free_sym.data(), free_sym.size());
    return out;
}

/**
 * @brief Desempaqueta lo que escribio @c empaquetar_modulo_.
 * @return false si el blob esta truncado o corrupto (se trata como fallo).
 */
static bool desempaquetar_modulo_(const std::vector<uint8_t> &blob,
                                  std::vector<uint8_t> &ir,
                                  std::string &alloc_sym,
                                  std::string &free_sym) {
    size_t p = 0;
    auto leer = [&](std::vector<uint8_t> &dst) -> bool {
        if (p + 4 > blob.size()) return false;
        uint32_t len = 0;
        for (int i = 0; i < 4; ++i)
            len |= (uint32_t)blob[p + i] << (i * 8);
        p += 4;
        if (p + len > blob.size()) return false;
        dst.assign(blob.begin() + (long)p, blob.begin() + (long)(p + len));
        p += len;
        return true;
    };
    std::vector<uint8_t> a, f;
    if (!leer(ir) || !leer(a) || !leer(f)) return false;
    alloc_sym.assign(a.begin(), a.end());
    free_sym.assign(f.begin(), f.end());
    return true;
}

/**
 * @brief Huella de los FUENTES de los que depende un modulo de stdlib.
 *
 * Tres vias, de la barata a la cara:
 *
 *   1. Modulo sin imports (se compila como fichero suelto): su cierre es el
 *      mismo, asi que basta el hash de su contenido.  Coste nulo.
 *   2. Grafo RECORDADO y todavia valido: se comprueban los pocos ficheros y
 *      directorios implicados, sin parsear nada ni recorrer el arbol.
 *   3. Reconstruirlo parseando, y recordarlo para la proxima.
 *
 * La via 3 cuesta ~165 ms -- por eso existen la 1 y la 2 -- y solo se paga
 * cuando algo cambio de verdad, que es cuando ademas hay que recompilar.
 *
 * @param path Ruta del modulo.
 * @param proyecto true si el modulo tiene imports.
 * @param store Store donde se recuerda el grafo (nullptr = no recordar).
 * @return Huella, o 0 si no se pudo determinar con certeza.
 */
static uint64_t huella_fuentes_(const std::string &path, bool proyecto,
                                const vx::CasStore *store) {
    // Via 1: sin imports, el cierre es el propio fichero.
    if (!proyecto) return huella_fichero_(path);

    std::vector<std::pair<std::string, uint64_t>> cierre;
    // Via 2: recorrer lo recordado.  Via 3: resolver parseando.
    if (store == nullptr || !recorrer_recordado_(path, *store, cierre))
        if (!resolver_y_recordar_(path, store, cierre)) return 0;

    // Ordenado por ruta: ni el orden de descubrimiento de los imports ni el
    // del recorrido son estables, y la huella tiene que ser la misma siempre.
    std::sort(cierre.begin(), cierre.end());
    uint64_t h = util::kFnvOffset;
    for (const auto &m : cierre) {
        h = mezclar_str_(h, m.first);
        h = util::fnv_mix(h, m.second);
    }
    return h == 0 ? 1ull : h; // 0 esta reservado para "no se pudo".
}

/**
 * @brief Trae el IR de un modulo de stdlib escrito en Vesta, del CAS si vale.
 *
 * Estos modulos se compilan igual en cada construccion aunque no cambien:
 * @c vx_mem solo cuesta ~190 ms de los ~200 que tarda el backend entero.
 * Aqui se guarda el resultado en el store direccionado por contenido -- el
 * mismo que ya comparte la stdlib entre proyectos y maquinas -- para que la
 * segunda construccion no lo recalcule.
 *
 * La clave cubre TODO lo que puede cambiar el resultado:
 *   - la version del compilador (un cambio nuestro invalida lo guardado);
 *   - el contenido del arbol de fuentes (incluidas las dependencias);
 *   - el modulo pedido;
 *   - las dimensiones que el AOT varia: @c opt_level, @c asm_target_bits,
 *     @c native_poo y @c exceptions_enabled;
 *   - el objetivo (os/arch), porque la stdlib tiene parciales por arquitectura
 *     y @c asm_target_bits no distingue arm64 de x86-64 (ambos son 64);
 *   - si la maquina de compilacion estaba disponible, que decide si un valor
 *     comptime se pudo calcular o salio vacio.
 *
 * A diferencia del CAS por-modulo del camino de proyecto, lo que se guarda
 * aqui es IR POST-optimizacion: estos modulos se compilan como unidades
 * sueltas y el AOT no vuelve a optimizar tras fusionar.  Por eso @c opt_level
 * SI entra en la clave -- alli no hace falta y aqui si.
 *
 * @param path Ruta del @c .vx.
 * @param src Contenido ya leido (evita releerlo).
 * @param opts Opciones con las que se compilaria.
 * @param proyecto true si el modulo tiene imports (via @c compile_vx_project).
 * @param tel Telemetria a la que imputar el tiempo.
 * @param out Modulo IR resultante.
 * @param alloc_sym Simbolo del asignador, si el modulo lo declara (opcional).
 * @param free_sym Simbolo del liberador, si el modulo lo declara (opcional).
 * @return false si no se pudo compilar (los diagnosticos ya van a stderr).
 */
static bool traer_modulo_stdlib_(const std::string &path,
                                 const std::string &src,
                                 const vx::CompileOptions &opts, bool proyecto,
                                 TelemetriaBackend &tel, ir::IrModule &out,
                                 std::string *alloc_sym = nullptr,
                                 std::string *free_sym = nullptr) {
    namespace fs = std::filesystem;
    const auto t0 = std::chrono::steady_clock::now();
    ++tel.stdlib_total_;

    // El store se abre una vez y sirve para las dos cosas: recordar el grafo
    // de dependencias y guardar el modulo compilado.
    std::unique_ptr<vx::CasStore> store;
    try {
        store.reset(new vx::CasStore(vx::CasStore::open_default()));
    } catch (const std::exception &) {
        // Un store inaccesible no debe tumbar la compilacion.
    }

    const uint64_t huella = huella_fuentes_(path, proyecto, store.get());

    uint64_t clave = util::kFnvOffset;
    clave = util::fnv_mix(clave, 0x414F545354444C42ull); // dominio "AOTSTDLB".
    clave = util::fnv_mix(clave, vx::vxi_compiler_version_hash());
    clave = util::fnv_mix(clave, huella);
    clave = mezclar_str_(clave, opts.module_name);
    clave = util::fnv_mix(clave, (uint64_t)opts.opt_level);
    clave = util::fnv_mix(clave, opts.asm_target_bits);
    clave = util::fnv_mix(clave, opts.native_poo ? 1ull : 0ull);
    clave = util::fnv_mix(clave, opts.exceptions_enabled ? 1ull : 0ull);
    clave = util::fnv_mix(clave, proyecto ? 1ull : 0ull);
    {
        // La stdlib tiene parciales por objetivo; sin esto, compilar para
        // aarch64 reutilizaria el artefacto de x86-64.
        std::string tgt_os, tgt_arch;
        vx::get_aot_condcomp_target(tgt_os, tgt_arch);
        clave = mezclar_str_(clave, tgt_os);
        clave = mezclar_str_(clave, tgt_arch);
    }
    {
        const char *pre = std::getenv("VESTA_MC_PREBUILT");
        clave = util::fnv_mix(clave,
                              (pre != nullptr && pre[0] != '\0') ? 1ull : 0ull);
    }

    // Huella 0 = no se pudo determinar de que depende el modulo -> compilar
    // sin tocar el store: una clave incompleta es peor que no tener cache.
    const bool usar_cache = (huella != 0 && store);

    std::vector<uint8_t> ir_bytes;
    if (usar_cache) {
        std::vector<uint8_t> blob;
        std::string a, f;
        if (store->get(clave, blob) &&
            desempaquetar_modulo_(blob, ir_bytes, a, f) &&
            ir::parse_ir_module_cache(ir_bytes, out)) {
            if (alloc_sym) *alloc_sym = a;
            if (free_sym) *free_sym = f;
            ++tel.stdlib_cache_;
            tel.sumar_stdlib(t0);
            return true;
        }
    }

    vx::CompileResult r = proyecto ? vx::compile_vx_project(path, opts)
                                   : vx::compile_vx_source(src, path, opts);
    if (!r.ok || r.ir_module_cache_bytes.empty() ||
        !ir::parse_ir_module_cache(r.ir_module_cache_bytes, out)) {
        // Sin el motivo el mensaje del llamador no sirve de nada.
        for (const auto &d : r.diagnostics.all())
            vx::print_diagnostic(std::cerr, d);
        tel.sumar_stdlib(t0);
        return false;
    }
    if (alloc_sym) *alloc_sym = r.aot_alloc_sym;
    if (free_sym) *free_sym = r.aot_free_sym;

    if (usar_cache)
        (void)store->put(clave,
                         empaquetar_modulo_(r.ir_module_cache_bytes,
                                            r.aot_alloc_sym, r.aot_free_sym));
    tel.sumar_stdlib(t0);
    return true;
}

int compile_aot(const vx::CompileResult &cr, const vx::CompileOptions &copts,
                std::string out_prefix, const AotOptions &opt) {
    // Reparto del tiempo del backend: se publica al salir, por
    // cualquier via (exito o error).
    TelemetriaBackend tel;
    // Alias locales de las opciones para no alterar el cuerpo movido.
    const aot::Tier aot_tier = opt.tier;
    const bool aot_freestanding = opt.freestanding;
    const bool aot_no_exceptions = opt.no_exceptions;
    const bool aot_no_io = opt.no_io;
    /* Cierto cuando el programa hace `panic(msg)` y no aporta un hook
     * propio: entonces PANIC baja al __panic de vx_io, que escribe
     * el mensaje.  Sin esto bajaba a `abort`, que no recibe
     * argumentos, y el texto que puso el programador se perdia. */
    bool io_default_panic = false;
    const bool aot_no_mem = opt.no_mem;
    const char *argv0 = opt.argv0.c_str();
    (void)aot_no_mem; // usado condicionalmente segun el codegen
    aot::AotTarget tgt;
    tgt.tier = aot_tier;
    tgt.freestanding = aot_freestanding;
    // AOT.2.d: roles cubiertos por @AllocatorOverride / @PanicHandler
    // -> admiten su LIBC_MAPPED tambien en --freestanding.
    tgt.alloc_provided = !cr.aot_alloc_sym.empty();
    tgt.free_provided = !cr.aot_free_sym.empty();
    tgt.panic_provided = !cr.aot_panic_sym.empty();
    tgt.exceptions_enabled = !aot_no_exceptions; // C3: configurable

    const char *tier_name = (aot_tier == aot::Tier::BARE)    ? "bare"
                            : (aot_tier == aot::Tier::EMBED) ? "embed"
                                                             : "full";

    if (cr.ir_module_cache_bytes.empty()) {
        std::cerr << "[aot] el modulo no produjo IR; nada que compilar a "
                     "nativo.\n";
        return EXIT_FAILURE;
    }

    // Modulo COMPLETO (functions + static_data + globals): el codegen
    // AOT necesita el static_data para materializar los literales en
    // .rodata.
    ir::IrModule aot_mod;
    if (!ir::parse_ir_module_cache(cr.ir_module_cache_bytes, aot_mod)) {
        std::cerr << "[aot] no se pudo deserializar el IR del modulo.\n";
        return EXIT_FAILURE;
    }

    /* Si el gancho de "excepcion sin recoger" lo puso el USUARIO.  Se mira
     * AQUI, antes de fusionar ningun runtime, que es cuando lo que hay en el
     * modulo es suyo y no nuestro; luego decide si el driver lo completa o lo
     * deja en paz. */
    bool uncaught_hook_es_del_usuario = false;
    for (const auto &af : aot_mod.functions)
        if (af.name == "__vx_uncaught") uncaught_hook_es_del_usuario = true;

    // ----------------------------------------------------------------
    // Auto-bundle del runtime de excepciones (stdlib/vx/vx_exc.vx).
    // Si el modulo usa try/catch/throw (THROW o CALL __vx_setjmp en el
    // IR) y no define el runtime el mismo, lo compilamos inline (mismo
    // native_poo + el @Target ya seleccionado para el target AOT) y
    // FUSIONAMOS sus funciones + la seccion .vxexc en aot_mod -> el .o
    // queda autocontenido (no hay que enlazar vx_exc.o a mano).  El
    // dead-elim posterior conserva solo las __vx_* realmente usadas.
    // Removible con --no-exceptions (exceptions_enabled=false).
    // ----------------------------------------------------------------
    if (!aot_no_exceptions) {
        bool uses_exc = false, defines_exc = false;
        for (const auto &af : aot_mod.functions) {
            if (af.name == "__vx_setjmp") defines_exc = true;
            for (const auto &b : af.blocks)
                for (const auto &ins : b.instrs)
                    if (ins.op == ir::IrOp::THROW ||
                        (ins.op == ir::IrOp::CALL &&
                         ins.func_name == "__vx_setjmp"))
                        uses_exc = true;
        }
        if (uses_exc && !defines_exc) {
            // Localizar vx_exc.vx: junto al exe (instalacion) o en el
            // repo (dev: build_dir/../stdlib/vx) o cwd.
            const std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            const std::vector<std::string> cands = {
                exe_dir + "/stdlib/vx/vx_exc.vx",
                exe_dir + "/../stdlib/vx/vx_exc.vx", "stdlib/vx/vx_exc.vx"};
            std::string ve_path;
            for (const auto &c : cands)
                if (std::filesystem::exists(c)) {
                    ve_path = c;
                    break;
                }
            if (ve_path.empty()) {
                std::cerr << "[aot] usa excepciones pero no encuentro "
                             "stdlib/vx/vx_exc.vx (enlazalo a mano o "
                             "compila con --no-exceptions).\n";
                return EXIT_FAILURE;
            }
            std::ifstream vef(ve_path);
            std::string ve_src((std::istreambuf_iterator<char>(vef)),
                               std::istreambuf_iterator<char>());
            vx::CompileOptions ve_opts;
            ve_opts.module_name = "vx_exc";
            ve_opts.opt_level = copts.opt_level;
            ve_opts.native_poo = true;
            ve_opts.exceptions_enabled = true;
            // Mismo target bits que el modulo principal (el @Naked
            // setjmp/longjmp x86-32 debe ensamblarse en mode32).
            ve_opts.asm_target_bits = copts.asm_target_bits;
            /* Por PROYECTO: desde que la excepcion que nadie recoge se CUENTA
             * en vez de colgar el programa, el modulo importa `std.os` (write
             * y exit), y solo esta ruta resuelve los imports.  Mismo criterio
             * que vx_io, vx_thread y vx_fault. */
            ir::IrModule ve_mod;
            if (!traer_modulo_stdlib_(ve_path, ve_src, ve_opts,
                                      /*proyecto=*/true, tel, ve_mod)) {
                std::cerr << "[aot] no pude compilar el runtime de "
                             "excepciones vx_exc.vx.\n";
                return EXIT_FAILURE;
            }
            // Merge (mismo patron que compiler_project): remap de
            // STR_LIT_ADDR/code.s_N por el offset del static_data, luego
            // append de funciones (las que no existan ya) + static_data
            // + globals + native_imports.  vx_exc no tiene literales,
            // pero el remap es correcto en general (defensa).
            const uint64_t sd_off =
                static_cast<uint64_t>(aot_mod.static_data.size());
            std::unordered_set<std::string> have;
            for (const auto &af : aot_mod.functions)
                have.insert(af.name);
            for (auto &fn : ve_mod.functions) {
                if (sd_off != 0)
                    for (auto &bb : fn.blocks)
                        for (auto &ins : bb.instrs)
                            if (ins.op == ir::IrOp::STR_LIT_ADDR)
                                ins.imm += sd_off;
                if (!have.count(fn.name))
                    aot_mod.functions.push_back(std::move(fn));
            }
            aot_mod.static_data.append_raw_entries(
                std::move(ve_mod.static_data));
            for (auto &gv : ve_mod.globals)
                aot_mod.globals.emplace(gv.first, gv.second);
            for (auto &ni : ve_mod.native_imports)
                aot_mod.register_native_import(ni.lib, ni.name);
            std::cout << "[aot] runtime de excepciones "
                         "(stdlib/vx/vx_exc.vx) incluido en el "
                         "objeto.\n";
        }
    }

    // ----------------------------------------------------------------
    // Auto-bundle del runtime de monitores (stdlib/vx/vx_sync.vx).
    // Si el modulo usa `synchronized`/`monitor`, el lowering native_poo
    // emite CALL __vx_monenter/__vx_monexit (monitor reentrante inline
    // en el objeto, palabra en obj+16) en vez de las IR ops MONENTER/
    // MONEXIT.  Fusionamos vx_sync.vx (atomic CAS + tid nativos) ->
    // el .o queda autocontenido.  El dead-elim conserva solo lo usado.
    // ----------------------------------------------------------------
    {
        bool uses_sync = false, defines_sync = false;
        for (const auto &af : aot_mod.functions) {
            if (af.name == "__vx_monenter") defines_sync = true;
            for (const auto &b : af.blocks)
                for (const auto &ins : b.instrs)
                    if (ins.op == ir::IrOp::CALL &&
                        (ins.func_name == "__vx_monenter" ||
                         ins.func_name == "__vx_monexit"))
                        uses_sync = true;
        }
        if (uses_sync && !defines_sync) {
            const std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            const std::vector<std::string> cands = {
                exe_dir + "/stdlib/vx/vx_sync.vx",
                exe_dir + "/../stdlib/vx/vx_sync.vx", "stdlib/vx/vx_sync.vx"};
            std::string vs_path;
            for (const auto &c : cands)
                if (std::filesystem::exists(c)) {
                    vs_path = c;
                    break;
                }
            if (vs_path.empty()) {
                std::cerr << "[aot] usa synchronized pero no encuentro "
                             "stdlib/vx/vx_sync.vx (enlazalo a mano).\n";
                return EXIT_FAILURE;
            }
            vx::CompileOptions vs_opts;
            vs_opts.module_name = "vx_sync";
            vs_opts.opt_level = copts.opt_level;
            vs_opts.native_poo = true;
            vs_opts.asm_target_bits = copts.asm_target_bits;
            // LIM-5: vx_sync `import`a vx_async (monitor cooperativo:
            // fiber-id + vasync_yield).  compile_vx_project resuelve el
            // import y MERGEA ambos modulos -> el .o queda con las fns de
            // vx_sync Y vx_async cross-resueltas (single-module fallaba
            // con "simbolo no resuelto").  Si el programa ademas usa
            // async directo, el bloque de vx_async de abajo ve sus fns ya
            // presentes (dedup por `have`) y las salta.
            ir::IrModule vs_mod;
            if (!traer_modulo_stdlib_(vs_path, std::string(), vs_opts,
                                      /*proyecto=*/true, tel, vs_mod)) {
                std::cerr << "[aot] no pude compilar el runtime de "
                             "monitores vx_sync.vx.\n";
                return EXIT_FAILURE;
            }
            const uint64_t sd_off =
                static_cast<uint64_t>(aot_mod.static_data.size());
            std::unordered_set<std::string> have;
            for (const auto &af : aot_mod.functions)
                have.insert(af.name);
            for (auto &fn : vs_mod.functions) {
                if (sd_off != 0)
                    for (auto &bb : fn.blocks)
                        for (auto &ins : bb.instrs)
                            if (ins.op == ir::IrOp::STR_LIT_ADDR)
                                ins.imm += sd_off;
                if (!have.count(fn.name))
                    aot_mod.functions.push_back(std::move(fn));
            }
            aot_mod.static_data.append_raw_entries(
                std::move(vs_mod.static_data));
            for (auto &gv : vs_mod.globals)
                aot_mod.globals.emplace(gv.first, gv.second);
            for (auto &ni : vs_mod.native_imports)
                aot_mod.register_native_import(ni.lib, ni.name);
            std::cout << "[aot] runtime de monitores "
                         "(stdlib/vx/vx_sync.vx) incluido en el "
                         "objeto.\n";
        }
    }

    // ----------------------------------------------------------------
    // Auto-bundle del runtime de MULTIHILO (stdlib/vx/vx_thread.vx).
    // `spawn { }` en AOT baja a CALL __vx_thread_run (hilo real del SO) +
    // el lowering inyecta CALL __vx_thread_join_all al final de main.
    // Fusionamos vx_thread.vx (CreateThread/pthread) -> .o autocontenido.
    // ----------------------------------------------------------------
    {
        bool uses_thread = false, defines_thread = false;
        for (const auto &af : aot_mod.functions) {
            if (af.name == "__vx_thread_run") defines_thread = true;
            for (const auto &b : af.blocks)
                for (const auto &ins : b.instrs)
                    if (ins.op == ir::IrOp::CALL &&
                        (ins.func_name == "__vx_thread_run" ||
                         ins.func_name == "__vx_thread_join_all"))
                        uses_thread = true;
        }
        if (uses_thread && !defines_thread) {
            const std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            const std::vector<std::string> cands = {
                exe_dir + "/stdlib/vx/vx_thread.vx",
                exe_dir + "/../stdlib/vx/vx_thread.vx",
                "stdlib/vx/vx_thread.vx"};
            std::string vt_path;
            for (const auto &c : cands)
                if (std::filesystem::exists(c)) {
                    vt_path = c;
                    break;
                }
            if (vt_path.empty()) {
                std::cerr << "[aot] usa spawn (hilo) pero no encuentro "
                             "stdlib/vx/vx_thread.vx (enlazalo a mano).\n";
                return EXIT_FAILURE;
            }
            std::ifstream vtf(vt_path);
            std::string vt_src((std::istreambuf_iterator<char>(vtf)),
                               std::istreambuf_iterator<char>());
            vx::CompileOptions vt_opts;
            vt_opts.module_name = "vx_thread";
            vt_opts.opt_level = copts.opt_level;
            vt_opts.native_poo = true;
            vt_opts.asm_target_bits = copts.asm_target_bits;
            // compile_vx_project (no _source) para resolver el
            // `import std.types` de vx_thread (uintptr/usize en las
            // firmas de los extern).  std.types son typedefs (sin
            // codigo) -> el merge no anade nada, solo resuelve tipos.
            (void)vt_src;
            ir::IrModule vt_mod;
            if (!traer_modulo_stdlib_(vt_path, vt_src, vt_opts,
                                      /*proyecto=*/true, tel, vt_mod)) {
                std::cerr << "[aot] no pude compilar el runtime de "
                             "multihilo vx_thread.vx.\n";
                return EXIT_FAILURE;
            }
            const uint64_t sd_off =
                static_cast<uint64_t>(aot_mod.static_data.size());
            std::unordered_set<std::string> have;
            for (const auto &af : aot_mod.functions)
                have.insert(af.name);
            for (auto &fn : vt_mod.functions) {
                if (sd_off != 0)
                    for (auto &bb : fn.blocks)
                        for (auto &ins : bb.instrs)
                            if (ins.op == ir::IrOp::STR_LIT_ADDR)
                                ins.imm += sd_off;
                if (!have.count(fn.name))
                    aot_mod.functions.push_back(std::move(fn));
            }
            aot_mod.static_data.append_raw_entries(
                std::move(vt_mod.static_data));
            for (auto &gv : vt_mod.globals)
                aot_mod.globals.emplace(gv.first, gv.second);
            for (auto &ni : vt_mod.native_imports)
                aot_mod.register_native_import(ni.lib, ni.name);
            std::cout << "[aot] runtime de multihilo "
                         "(stdlib/vx/vx_thread.vx) incluido en el "
                         "objeto.\n";
        }
    }

    // ----------------------------------------------------------------
    // Auto-bundle del runtime de asincronia (stdlib/vx/vx_async.vx).
    // Si el modulo usa spawn/future/await/fulfill, el lowering
    // native_poo emite CALL __vx_spawn/__vx_future_new/__vx_await/
    // __vx_fulfill (scheduler cooperativo, no hilos del SO).
    // Fusionamos vx_async.vx -> .o autocontenido.
    // ----------------------------------------------------------------
    {
        bool uses_async = false, defines_async = false;
        for (const auto &af : aot_mod.functions) {
            if (af.name == "__vx_spawn") defines_async = true;
            for (const auto &b : af.blocks)
                for (const auto &ins : b.instrs)
                    if (ins.op == ir::IrOp::CALL &&
                        (ins.func_name == "__vx_spawn" ||
                         ins.func_name == "__vx_future_new" ||
                         ins.func_name == "__vx_await" ||
                         ins.func_name == "__vx_fulfill" ||
                         ins.func_name == "__vx_msgsend" ||
                         ins.func_name == "__vx_msgrecv" ||
                         ins.func_name == "__vx_pid"))
                        uses_async = true;
        }
        if (uses_async && !defines_async) {
            const std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            const std::vector<std::string> cands = {
                exe_dir + "/stdlib/vx/vx_async.vx",
                exe_dir + "/../stdlib/vx/vx_async.vx", "stdlib/vx/vx_async.vx"};
            std::string va_path;
            for (const auto &c : cands)
                if (std::filesystem::exists(c)) {
                    va_path = c;
                    break;
                }
            if (va_path.empty()) {
                std::cerr << "[aot] usa spawn/async pero no encuentro "
                             "stdlib/vx/vx_async.vx (enlazalo a mano).\n";
                return EXIT_FAILURE;
            }
            std::ifstream vaf(va_path);
            std::string va_src((std::istreambuf_iterator<char>(vaf)),
                               std::istreambuf_iterator<char>());
            vx::CompileOptions va_opts;
            va_opts.module_name = "vx_async";
            va_opts.opt_level = copts.opt_level;
            va_opts.native_poo = true;
            va_opts.asm_target_bits = copts.asm_target_bits;
            ir::IrModule va_mod;
            if (!traer_modulo_stdlib_(va_path, va_src, va_opts,
                                      /*proyecto=*/false, tel, va_mod)) {
                std::cerr << "[aot] no pude compilar el runtime de "
                             "asincronia vx_async.vx.\n";
                return EXIT_FAILURE;
            }
            const uint64_t sd_off =
                static_cast<uint64_t>(aot_mod.static_data.size());
            std::unordered_set<std::string> have;
            for (const auto &af : aot_mod.functions)
                have.insert(af.name);
            for (auto &fn : va_mod.functions) {
                if (sd_off != 0)
                    for (auto &bb : fn.blocks)
                        for (auto &ins : bb.instrs)
                            if (ins.op == ir::IrOp::STR_LIT_ADDR)
                                ins.imm += sd_off;
                if (!have.count(fn.name))
                    aot_mod.functions.push_back(std::move(fn));
            }
            aot_mod.static_data.append_raw_entries(
                std::move(va_mod.static_data));
            for (auto &gv : va_mod.globals)
                aot_mod.globals.emplace(gv.first, gv.second);
            for (auto &ni : va_mod.native_imports)
                aot_mod.register_native_import(ni.lib, ni.name);
            std::cout << "[aot] runtime de asincronia "
                         "(stdlib/vx/vx_async.vx) incluido en el "
                         "objeto.\n";
        }
    }

    // ----------------------------------------------------------------
    // Auto-bundle del primitivo de fibras (stdlib/vx/vx_fiber.vx).
    // Si el modulo usa el builtin `fiber_swapctx`, el lowering
    // native_poo (FN.2) emite CALL __vx_swapctx (context-switch nativo
    // @Naked, host-stack).  Fusionamos vx_fiber.vx -> .o autocontenido,
    // salvo que el modulo YA lo defina (import explicito).  Mismo patron
    // que vx_async: el context-switch es puro Vesta (inline-asm), sin
    // runtime.
    // ----------------------------------------------------------------
    {
        bool uses_fiber = false, defines_fiber = false;
        for (const auto &af : aot_mod.functions) {
            if (af.name == "__vx_swapctx") defines_fiber = true;
            for (const auto &b : af.blocks)
                for (const auto &ins : b.instrs)
                    if (ins.op == ir::IrOp::CALL &&
                        ins.func_name == "__vx_swapctx")
                        uses_fiber = true;
        }
        if (uses_fiber && !defines_fiber) {
            const std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            const std::vector<std::string> cands = {
                exe_dir + "/stdlib/vx/vx_fiber.vx",
                exe_dir + "/../stdlib/vx/vx_fiber.vx", "stdlib/vx/vx_fiber.vx"};
            std::string vf_path;
            for (const auto &c : cands)
                if (std::filesystem::exists(c)) {
                    vf_path = c;
                    break;
                }
            if (vf_path.empty()) {
                std::cerr << "[aot] usa fiber_swapctx pero no encuentro "
                             "stdlib/vx/vx_fiber.vx (enlazalo a mano).\n";
                return EXIT_FAILURE;
            }
            std::ifstream vff(vf_path);
            std::string vf_src((std::istreambuf_iterator<char>(vff)),
                               std::istreambuf_iterator<char>());
            vx::CompileOptions vf_opts;
            vf_opts.module_name = "vx_fiber";
            vf_opts.opt_level = copts.opt_level;
            vf_opts.native_poo = true;
            vf_opts.asm_target_bits = copts.asm_target_bits;
            ir::IrModule vf_mod;
            if (!traer_modulo_stdlib_(vf_path, vf_src, vf_opts,
                                      /*proyecto=*/false, tel, vf_mod)) {
                std::cerr << "[aot] no pude compilar el primitivo de "
                             "fibras vx_fiber.vx.\n";
                return EXIT_FAILURE;
            }
            const uint64_t sd_off =
                static_cast<uint64_t>(aot_mod.static_data.size());
            std::unordered_set<std::string> have;
            for (const auto &af : aot_mod.functions)
                have.insert(af.name);
            for (auto &fn : vf_mod.functions) {
                if (sd_off != 0)
                    for (auto &bb : fn.blocks)
                        for (auto &ins : bb.instrs)
                            if (ins.op == ir::IrOp::STR_LIT_ADDR)
                                ins.imm += sd_off;
                if (!have.count(fn.name))
                    aot_mod.functions.push_back(std::move(fn));
            }
            aot_mod.static_data.append_raw_entries(
                std::move(vf_mod.static_data));
            for (auto &gv : vf_mod.globals)
                aot_mod.globals.emplace(gv.first, gv.second);
            for (auto &ni : vf_mod.native_imports)
                aot_mod.register_native_import(ni.lib, ni.name);
            std::cout << "[aot] primitivo de fibras "
                         "(stdlib/vx/vx_fiber.vx) incluido en el "
                         "objeto.\n";
        }
    }

    // ----------------------------------------------------------------
    // Auto-bundle del runtime de I/O (stdlib/vx/vx_io.vx).
    // Si el modulo usa print/println, el lowering native_poo emite
    // CALLN `vx_bare_io:__vx_*` (write + formateadores).  En vez de
    // exigir enlazar vesta_io_bare.o (libc/printf), fusionamos un
    // runtime Vesta puro que escribe via FFI a write/_write (fd 1, sin
    // printf -> mas rapido) y formatea los numeros en Vesta.  Tras el
    // merge reescribimos esas CALLN a CALL plano (__vx_*) -> resuelven
    // a las funciones bundle-adas (no quedan como import externo).  El
    // usuario puede REDEFINIR cualquier __vx_* en su modulo: si lo
    // hace, el lowering ya emitio CALL a la suya y no detectamos la
    // CALLN -> no se bundle-a.  Removible con --freestanding (el
    // usuario aporta los __vx_*) o --no-io.
    // ----------------------------------------------------------------
    if (!aot_no_io && !aot_freestanding) {
        const std::string io_pfx = "vx_bare_io:";
        bool uses_io = false, defines_io = false;
        // Un `unwrap` necesita el hook __vx_panic_null, que vive en el
        // mismo vx_io.vx.  Un programa que use Optional pero no imprima
        // nada no arrastraba el runtime, asi que el hook no existia y
        // el backend acababa pidiendolo como import externo.
        bool needs_panic_null = false, defines_panic_null = false;
        // Un `panic(msg)` necesita __panic, que vive tambien aqui.
        // Sin esto el mensaje que escribio el programador se perdia:
        // PANIC bajaba a `abort`, que no recibe argumentos.
        bool needs_panic = false, defines_panic = false;
        for (const auto &af : aot_mod.functions) {
            if (af.name == "__vx_write") defines_io = true;
            if (af.name == "__vx_panic_null") defines_panic_null = true;
            if (af.name == "__panic") defines_panic = true;
            for (const auto &b : af.blocks)
                for (const auto &ins : b.instrs) {
                    if (ins.op == ir::IrOp::CALLN &&
                        ins.func_name.rfind(io_pfx, 0) == 0)
                        uses_io = true;
                    if (ins.op == ir::IrOp::UNWRAP) needs_panic_null = true;
                    if (ins.op == ir::IrOp::PANIC) needs_panic = true;
                }
        }
        // El hook por defecto solo se usa si el programa no trae uno
        // suyo (@PanicHandler) ni redefine __panic.
        if (needs_panic && !defines_panic && cr.aot_panic_sym.empty())
            io_default_panic = true;
        if ((uses_io || (needs_panic_null && !defines_panic_null) ||
             io_default_panic) &&
            !defines_io) {
            const std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            const std::vector<std::string> cands = {
                exe_dir + "/stdlib/vx/vx_io.vx",
                exe_dir + "/../stdlib/vx/vx_io.vx", "stdlib/vx/vx_io.vx"};
            std::string io_path;
            for (const auto &c : cands)
                if (std::filesystem::exists(c)) {
                    io_path = c;
                    break;
                }
            if (io_path.empty()) {
                std::cerr << "[aot] usa print/println pero no encuentro "
                             "stdlib/vx/vx_io.vx (enlazalo a mano o "
                             "compila con --freestanding y aporta "
                             "__vx_write).\n";
                return EXIT_FAILURE;
            }
            std::ifstream iof(io_path);
            std::string io_src((std::istreambuf_iterator<char>(iof)),
                               std::istreambuf_iterator<char>());
            vx::CompileOptions io_opts;
            io_opts.module_name = "vx_io";
            io_opts.opt_level = copts.opt_level;
            io_opts.native_poo = true;
            io_opts.asm_target_bits = copts.asm_target_bits;
            /* Por PROYECTO: el modulo importa std.syscall / std.unix /
             * std.types del lado de Linux, y solo esa ruta resuelve los
             * imports.  Mismo criterio que vx_thread y vx_fault. */
            ir::IrModule io_mod;
            if (!traer_modulo_stdlib_(io_path, io_src, io_opts,
                                      /*proyecto=*/true, tel, io_mod)) {
                // El motivo lo volco `traer_modulo_stdlib_`.
                std::cerr << "[aot] no pude compilar el runtime de I/O "
                             "vx_io.vx.\n";
                return EXIT_FAILURE;
            }
            // Merge (mismo patron que vx_exc): remap de STR_LIT_ADDR por
            // el offset del static_data + append de funciones nuevas +
            // static_data + globals + native_imports (write/_write/abort).
            const uint64_t sd_off =
                static_cast<uint64_t>(aot_mod.static_data.size());
            std::unordered_set<std::string> have;
            for (const auto &af : aot_mod.functions)
                have.insert(af.name);
            for (auto &fn : io_mod.functions) {
                if (sd_off != 0)
                    for (auto &bb : fn.blocks)
                        for (auto &ins : bb.instrs)
                            if (ins.op == ir::IrOp::STR_LIT_ADDR)
                                ins.imm += sd_off;
                if (!have.count(fn.name))
                    aot_mod.functions.push_back(std::move(fn));
            }
            aot_mod.static_data.append_raw_entries(
                std::move(io_mod.static_data));
            for (auto &gv : io_mod.globals)
                aot_mod.globals.emplace(gv.first, gv.second);
            for (auto &ni : io_mod.native_imports)
                aot_mod.register_native_import(ni.lib, ni.name);
            // Reescribir CALLN `vx_bare_io:__vx_*` -> CALL `__vx_*`
            // (las funciones ahora viven en el modulo; resolucion
            // intra-imagen, sin import externo).
            for (auto &af : aot_mod.functions)
                for (auto &b : af.blocks)
                    for (auto &ins : b.instrs)
                        if (ins.op == ir::IrOp::CALLN &&
                            ins.func_name.rfind(io_pfx, 0) == 0) {
                            ins.op = ir::IrOp::CALL;
                            ins.func_name = ins.func_name.substr(io_pfx.size());
                        }
            // El I/O es block-buffered: inyectar CALL __vx_flush antes
            // de cada RET de main para volcar al salir (el _start nativo
            // no corre atexit).  Asi nada se pierde y el buffering vale
            // (1 syscall por 4 KiB en vez de 1 por write).
            for (auto &af : aot_mod.functions) {
                if (af.name != "main") continue;
                // Una llamada de COLA en main no deja donde volcar: el
                // tail-call salta sin volver, asi que no hay RET ante el
                // que inyectar el flush y todo lo impreso se quedaba en
                // el buffer (un `i32 main() { return corre(); }` no
                // sacaba una sola linea).  Se deshace la optimizacion
                // SOLO en main -- CALL + RET del resultado -- que ahi no
                // cuesta nada: es la ultima llamada del programa.
                for (auto &b : af.blocks) {
                    for (size_t i = 0; i < b.instrs.size(); ++i) {
                        if (b.instrs[i].op != ir::IrOp::TAILCALL) continue;
                        ir::IrInstr &tc = b.instrs[i];
                        tc.op = ir::IrOp::CALL;
                        // El tail-call no guardaba el resultado en
                        // ningun valor (saltaba y ya); ahora hay que
                        // retornarlo, asi que se le da uno.
                        if (tc.dst == ir::IR_NO_VALUE &&
                            tc.type != ir::IrType::VOID)
                            tc.dst = af.new_value(tc.type, "%tc_ret");
                        ir::IrInstr rt{};
                        rt.op = ir::IrOp::RET;
                        rt.type = tc.type;
                        rt.source_line = tc.source_line;
                        if (tc.dst != ir::IR_NO_VALUE)
                            rt.operands.push_back(tc.dst);
                        b.instrs.insert(b.instrs.begin() +
                                            static_cast<long>(i) + 1,
                                        std::move(rt));
                        ++i; // saltar el RET recien insertado
                    }
                }
                for (auto &b : af.blocks) {
                    std::vector<ir::IrInstr> ni;
                    ni.reserve(b.instrs.size() + 1);
                    for (auto &ins : b.instrs) {
                        if (ins.op == ir::IrOp::RET) {
                            ir::IrInstr fl{};
                            fl.op = ir::IrOp::CALL;
                            // type por defecto = VOID (0); evitamos la
                            // macro VOID de windef.h (restaurada tras
                            // incluir ssa_ir.h).
                            fl.dst = ir::IR_NO_VALUE;
                            fl.func_name = "__vx_flush";
                            fl.source_line = ins.source_line;
                            ni.push_back(std::move(fl));
                        }
                        ni.push_back(std::move(ins));
                    }
                    b.instrs = std::move(ni);
                }
            }
            /* El gancho de "excepcion que nadie recogio" se COMPLETA aqui.
             *
             * `vx_exc.vx` no importa nada a proposito: sin sistema, lo unico
             * que se puede hacer es parar la maquina, y un objeto freestanding
             * no debe arrastrar la I/O del sistema solo por usar try/catch.
             * Cuando SI hay sistema -- y este bloque solo corre entonces --, se
             * le antepone la llamada que vuelca lo impreso, lo cuenta por la
             * salida de error y sale con 134.  No vuelve, asi que el cuerpo de
             * parada de `vx_exc.vx` queda inalcanzable.
             *
             * Solo al gancho NUESTRO: si el usuario definio el suyo, el suyo
             * gano al fusionar y no se le anade nada -- completar una funcion
             * ajena seria cambiarle el comportamiento a quien la escribio. */
            if (!uncaught_hook_es_del_usuario) {
                for (auto &af : aot_mod.functions) {
                    if (af.name != "__vx_uncaught" || af.blocks.empty())
                        continue;
                    ir::IrInstr rp{};
                    rp.op = ir::IrOp::CALL;
                    rp.dst = ir::IR_NO_VALUE;
                    rp.func_name = "__vx_uncaught_report";
                    if (!af.blocks[0].instrs.empty())
                        rp.source_line = af.blocks[0].instrs[0].source_line;
                    af.blocks[0].instrs.insert(af.blocks[0].instrs.begin(),
                                               std::move(rp));
                    break;
                }
            }
            std::cout << "[aot] runtime de I/O (stdlib/vx/vx_io.vx) "
                         "incluido en el objeto.\n";
        }
    }

    /* Info de depuracion del LENGUAJE nivel 2: el binario se explica
     * solo al fallar.  Se enlaza el manejador (stdlib/vx/vx_fault.vx) y
     * se antepone su instalacion a `main`.
     *
     * A partir de aqui el ejecutable YA NO es identico al de no pedir
     * nada: lleva codigo dentro.  Es deliberado y por eso tiene nivel
     * propio -- el nivel 1 son solo datos, en un fichero aparte, y deja
     * el binario intacto.  Meter codigo cambia el programa que despues
     * se depura, asi que se pide a proposito o no se pide. */
    if (opt.lang_debug_level >= 2 && !aot_freestanding) {
        const std::string exe_dir =
            std::filesystem::path(fs::get_executable_path())
                .parent_path()
                .string();
        const std::vector<std::string> cands = {
            exe_dir + "/stdlib/vx/vx_fault.vx",
            exe_dir + "/../stdlib/vx/vx_fault.vx", "stdlib/vx/vx_fault.vx"};
        std::string fpath;
        for (const auto &c : cands)
            if (std::filesystem::exists(c)) {
                fpath = c;
                break;
            }
        if (fpath.empty()) {
            std::cerr << "[aot] no encuentro stdlib/vx/vx_fault.vx; "
                         "sin el, el binario no puede explicarse solo."
                      << "\n";
            return EXIT_FAILURE;
        }
        vx::CompileOptions fopts;
        fopts.module_name = "vx_fault";
        fopts.opt_level = copts.opt_level;
        fopts.native_poo = true;
        fopts.asm_target_bits = copts.asm_target_bits;
        /* Por PROYECTO y no por fuente suelto: el modulo importa
         * `std.types` (uintptr / nullptr) y solo esa ruta resuelve los
         * imports.  Mismo criterio que vx_thread y vx_async. */
        ir::IrModule fmod;
        if (!traer_modulo_stdlib_(fpath, std::string(), fopts,
                                  /*proyecto=*/true, tel, fmod)) {
            // El motivo lo volco `traer_modulo_stdlib_`.
            std::cerr << "[aot] no pude compilar vx_fault.vx.\n";
            return EXIT_FAILURE;
        }
        // Mismo merge que el runtime de I/O: remap de literales por el
        // offset del static_data, funciones nuevas, datos e imports.
        const uint64_t sd_off2 =
            static_cast<uint64_t>(aot_mod.static_data.size());
        std::unordered_set<std::string> have2;
        for (const auto &af : aot_mod.functions)
            have2.insert(af.name);
        for (auto &fn : fmod.functions) {
            if (sd_off2 != 0)
                for (auto &bb : fn.blocks)
                    for (auto &ins : bb.instrs)
                        if (ins.op == ir::IrOp::STR_LIT_ADDR)
                            ins.imm += sd_off2;
            if (!have2.count(fn.name))
                aot_mod.functions.push_back(std::move(fn));
        }
        aot_mod.static_data.append_raw_entries(std::move(fmod.static_data));
        for (auto &gv : fmod.globals)
            aot_mod.globals.emplace(gv.first, gv.second);
        for (auto &ni : fmod.native_imports) {
            /* Las primitivas de I/O NO son un import: viven en el
             * mismo objeto (las trae vx_io) y sus llamadas se
             * reescriben a internas ahi abajo.  Copiar el import haria
             * que el ejecutable arrancara pidiendo una `vx_bare_io.dll`
             * que no existe. */
            if (ni.lib == "vx_bare_io") continue;
            aot_mod.register_native_import(ni.lib, ni.name);
        }
        /* Sus llamadas al I/O tienen que resolverse DENTRO de la
         * imagen, igual que las del resto: el modulo usa `print` y al
         * compilarse suelto eso queda como una importacion externa.
         * La reescritura del bundle de I/O ya paso cuando este modulo
         * aun no estaba, asi que hay que repetirla aqui -- si no, el
         * ejecutable arranca pidiendo una DLL que no existe. */
        {
            const std::string io_pfx2 = "vx_bare_io:";
            for (auto &af : aot_mod.functions)
                for (auto &b : af.blocks)
                    for (auto &ins : b.instrs)
                        if (ins.op == ir::IrOp::CALLN &&
                            ins.func_name.rfind(io_pfx2, 0) == 0) {
                            ins.op = ir::IrOp::CALL;
                            ins.func_name =
                                ins.func_name.substr(io_pfx2.size());
                        }
        }

        // Y que `main` lo instale antes que nada.
        for (auto &af : aot_mod.functions) {
            if (af.name != "main" || af.blocks.empty()) continue;
            ir::IrInstr call_f{};
            call_f.op = ir::IrOp::CALL;
            call_f.type = ir::IrType::VOID;
            call_f.dst = ir::IR_NO_VALUE;
            call_f.func_name = "__vx_fault_init";
            af.blocks[0].instrs.insert(af.blocks[0].instrs.begin(),
                                       std::move(call_f));
            break;
        }
        std::cout << "[aot] el binario se explicara solo al fallar "
                     "(stdlib/vx/vx_fault.vx incluido; YA NO es "
                     "identico al de no pedir depuracion)."
                  << "\n";
    }

    // AOT: eliminar funciones MUERTAS (no alcanzables) antes de
    // analizar/compilar.  Sin esto, una factoria-de-closure inlineada
    // en su caller queda como copia standalone no usada y su GC_ALLOC
    // bloquearia la compilacion bare.  Cierre transitivo desde main +
    // funciones @section, siguiendo CALL/TAILCALL/LABEL_ADDR y los
    // sym_refs de las vtablas (static_data).  Conservador: ante la duda
    // se conserva (un drop erroneo daria un error de enlace ruidoso,
    // nunca corrupcion).
    {
        std::unordered_set<std::string> live;
        std::vector<std::string> work;
        auto add_live = [&](const std::string &n) {
            if (!n.empty() && live.insert(n).second) work.push_back(n);
        };
        std::unordered_map<std::string, const ir::IrFunction *> by_name;
        for (auto &f : aot_mod.functions)
            by_name[f.name] = &f;
        // Modo LIBRERIA: un modulo sin `main` es una libreria (.o/.so);
        // TODAS sus funciones son raices (son la API publica; no se sabe
        // quien las llamara desde fuera).  El linker final hace el
        // dead-strip del ejecutable (--gc-sections), asi que esto NO
        // infla el .exe: con `main`, la poda desde main mantiene el exe
        // lean (una funcion no alcanzable se elimina).  Sin esto, una
        // libreria Vesta compilaba a 0 funciones.
        const bool is_library = (by_name.count("main") == 0);
        add_live("main");
        add_live("__module_init");
        // AUTO multiversion (--float-isa auto): el dispatch (auto_init)
        // referencia las VARIANTES por nombre derivado (NAME$sse2/...),
        // no la funcion base NAME -> la poda no la veria.  Mantener viva
        // toda funcion con ops VEC (la base de la que el driver deriva
        // las 3 variantes); su recorrido arrastra sus callees (p.ej.
        // sum_f64).  Espejo de la siembra del BFS de codegen.
        const bool auto_keep_vec = (opt.float_isa == "auto");
        auto has_vec = [](const ir::IrFunction &f) -> bool {
            for (const auto &b : f.blocks)
                for (const auto &in : b.instrs) {
                    const auto op = in.op;
                    if (op == ir::IrOp::VEC_BINOP || op == ir::IrOp::VEC_UNOP ||
                        op == ir::IrOp::VEC_FMA ||
                        op == ir::IrOp::VEC_BINOP_S ||
                        op == ir::IrOp::VEC_BCAST ||
                        op == ir::IrOp::VEC_ACC_ZERO ||
                        op == ir::IrOp::VEC_ACC_ADD ||
                        op == ir::IrOp::VEC_ACC_FMA ||
                        op == ir::IrOp::VEC_ACC_STORE ||
                        op == ir::IrOp::VEC_ACC_COMBINE)
                        return true;
                }
            return false;
        };
        for (auto &f : aot_mod.functions) {
            if (!f.section.empty() || f.is_naked || is_library ||
                (auto_keep_vec && has_vec(f)))
                add_live(f.name);
        }
        // `unwrap` no llama a su hook en el IR: la llamada a
        // __vx_panic_null la EMITE el backend (vreg_select) al bajar
        // IrOp::UNWRAP, o sea despues de esta poda.  Sin sembrarlo
        // aqui, el hook se elimina por "no alcanzable" y el codegen
        // acaba pidiendolo como simbolo externo -> queda en la tabla de
        // imports del PE y Windows rechaza el binario al cargarlo
        // (STATUS_ENTRYPOINT_NOT_FOUND).  Mismo caso que las variantes
        // vectoriales de arriba: referencia creada fuera del IR.
        for (const auto &f : aot_mod.functions) {
            bool has_unwrap = false;
            for (const auto &b : f.blocks)
                for (const auto &in : b.instrs)
                    if (in.op == ir::IrOp::UNWRAP) {
                        has_unwrap = true;
                        break;
                    }
            if (has_unwrap) {
                add_live("__vx_panic_null");
                break;
            }
        }
        // Lo mismo con `panic`: la llamada al hook no esta en el IR
        // todavia -- la crea aot_lower al bajar IrOp::PANIC, o sea
        // DESPUES de esta poda.  Sin sembrarlo, el hook se va por "no
        // alcanzable" y acaba en la tabla de imports; Windows entonces
        // rechaza el binario al cargarlo y el proceso muere con 127 sin
        // llegar a ejecutar nada.
        if (io_default_panic) add_live("__panic");
        if (!cr.aot_panic_sym.empty()) add_live(cr.aot_panic_sym);
        // Raices por vtablas/datos: nombres referenciados en sym_refs.
        for (size_t si = 0; si < aot_mod.static_data.size(); ++si)
            for (const auto &sr : aot_mod.static_data.meta_at(si).sym_refs)
                add_live(sr.sym);
        while (!work.empty()) {
            const std::string cur = work.back();
            work.pop_back();
            auto it = by_name.find(cur);
            if (it == by_name.end()) continue;
            for (const auto &b : it->second->blocks)
                for (const auto &ins : b.instrs) {
                    if ((ins.op == ir::IrOp::CALL ||
                         ins.op == ir::IrOp::TAILCALL ||
                         ins.op == ir::IrOp::LABEL_ADDR) &&
                        !ins.func_name.empty())
                        add_live(ins.func_name);
                    // THROW baja a CALL __vx_throw en el backend
                    // (no es un CALL en el IR) -> referencia implicita
                    // al runtime de excepciones auto-hospedado.
                    if (ins.op == ir::IrOp::THROW) add_live("__vx_throw");
                    // INLINE_ASM: el cuerpo (func_name) puede referenciar
                    // funciones del modulo via tokens `__vxf_<label>` que
                    // el lowering inserto (inline-asm accede simbolos
                    // propios).  La poda NO ve estas refs porque el asm es
                    // texto opaco -> escanearlas explicitamente para que la
                    // funcion referenciada sobreviva y se compile.  Los
                    // `__vxg_<slot>` son globales (rodata), no funciones.
                    if (ins.op == ir::IrOp::INLINE_ASM &&
                        !ins.func_name.empty()) {
                        const std::string &body = ins.func_name;
                        const std::string tag = "__vxf_";
                        size_t p = 0;
                        while ((p = body.find(tag, p)) != std::string::npos) {
                            size_t s = p + tag.size();
                            size_t e = s;
                            while (e < body.size() &&
                                   (std::isalnum((unsigned char)body[e]) ||
                                    body[e] == '_' || body[e] == '$'))
                                ++e;
                            if (e > s) add_live(body.substr(s, e - s));
                            p = e;
                        }
                    }
                }
        }
        std::vector<ir::IrFunction> kept;
        kept.reserve(aot_mod.functions.size());
        for (auto &f : aot_mod.functions)
            if (live.count(f.name)) kept.push_back(std::move(f));
        aot_mod.functions = std::move(kept);
    }

    // AOT: promover envs de closure de heap a stack cuando no escapan
    // (closure-aware escape analysis).  Tras esto, los que no se
    // pudieron promover quedan GC_ALLOC -> aot_analyze los rechaza
    // limpio (nunca heap sin liberar).  Corre solo en el path AOT.
    for (auto &afn : aot_mod.functions)
        (void)ir::ir_pass_promote_closure_env(afn);

    // AOT opcion 1: las closures que escapan CROSS-FUNCTION (env creado
    // en una factoria y retornado; no inlinable -> promote no lo pudo
    // poner en stack) se liberan con RAW_FREE determinista en el dueno
    // terminal.  Lo que no tenga dueno limpio se revierte a GC_ALLOC
    // (aot_analyze lo rechaza -> nunca leak).  Corre tras promote.
    (void)ir::ir_pass_own_closure_envs(aot_mod);

    if (util::flag_on(util::FlagId::AotDumpIr)) {
        std::cerr << "===== AOT native_poo IR =====\n";
        ir::ir_print(aot_mod, std::cerr);
        std::cerr << "=============================\n";
    }
    aot::AotCompatReport rep = aot::aot_analyze_module(aot_mod, tgt);
    std::cout << "[aot] target=" << tier_name
              << (aot_freestanding ? " --freestanding" : "") << ": "
              << aot_mod.functions.size() << " funcion(es), "
              << rep.ok_functions.size() << " compilable(s) a nativo.\n";

    if (!rep.compatible) {
        std::cerr << rep.render();
        std::cerr << "[aot] modulo NO compilable a nativo en este target "
                     "(ver incompatibilidades arriba).\n";
        return EXIT_FAILURE;
    }

    //  AOT.2: re-bajar las ops sintetizadas (RAW_ALLOC/RAW_FREE/
    // PANIC) a CALL a simbolos externos (convencion libc; los resuelve
    // el linker -> el .o NO depende de libc).  Tras esto el selector ve
    // solo CALL.  Se ejecuta DESPUES del gate de analyze para que el
    // chequeo freestanding sobre RAW_ALLOC siga aplicando.
    // AOT.2.d: nombres de simbolo segun
    // @AllocatorOverride/@PanicHandler (vacio = convencion C
    // malloc/free/abort).
    aot::AotLowerConfig lcfg;
    // Detectar si el modulo usa el allocator (RAW_ALLOC/RAW_FREE o el
    // calloc del `new`) para decidir el auto-bundle del slab Vesta.
    bool aot_uses_alloc = false;
    for (const auto &af : aot_mod.functions)
        for (const auto &b : af.blocks)
            for (const auto &in : b.instrs)
                if (in.op == ir::IrOp::RAW_ALLOC ||
                    in.op == ir::IrOp::RAW_FREE ||
                    ((in.op == ir::IrOp::CALL || in.op == ir::IrOp::TAILCALL) &&
                     in.func_name == "calloc"))
                    aot_uses_alloc = true;
    bool bundle_mem = false;
    ir::IrModule mem_mod; // poblado si bundle_mem (merge tras aot_lower)
    if (!cr.aot_alloc_sym.empty()) {
        // @AllocatorOverride del usuario: respetarlo (no bundle).
        lcfg.alloc_sym = cr.aot_alloc_sym;
        lcfg.has_alloc_override = true; // __new calloc -> alloc_sym(size)
    } else if (aot_uses_alloc && !aot_no_mem && !aot_freestanding) {
        // Sin @AllocatorOverride del usuario -> el slab Vesta
        // (stdlib/vx/vx_mem.vx) es el allocator por DEFECTO, via el
        // MISMO mecanismo @AllocatorOverride (reciclamos la sintaxis):
        // compilamos vx_mem y leemos sus simbolos override
        // (__vx_malloc / __vx_free) genericamente, no hardcoded.  Sin
        // libc malloc/free.  El usuario sustituye con su propio
        // @AllocatorOverride, o lo desactiva con --no-mem.
        const std::string exe_dir =
            std::filesystem::path(fs::get_executable_path())
                .parent_path()
                .string();
        const std::vector<std::string> cands = {
            exe_dir + "/stdlib/vx/vx_mem.vx",
            exe_dir + "/../stdlib/vx/vx_mem.vx", "stdlib/vx/vx_mem.vx"};
        std::string mem_path;
        for (const auto &c : cands)
            if (std::filesystem::exists(c)) {
                mem_path = c;
                break;
            }
        if (mem_path.empty()) {
            std::cerr << "[aot] usa el allocator pero no encuentro "
                         "stdlib/vx/vx_mem.vx (enlazalo a mano, usa "
                         "@AllocatorOverride o compila con --no-mem).\n";
            return EXIT_FAILURE;
        }
        std::ifstream mf(mem_path);
        std::string mem_src((std::istreambuf_iterator<char>(mf)),
                            std::istreambuf_iterator<char>());
        vx::CompileOptions mem_opts;
        mem_opts.module_name = "vx_mem";
        mem_opts.opt_level = copts.opt_level;
        mem_opts.native_poo = true;
        mem_opts.asm_target_bits = copts.asm_target_bits;
        // Como PROYECTO, no como fichero suelto: la stdlib es codigo
        // Vesta normal y sus modulos se importan entre si (vx_mem usa
        // los atomicos de atomic en vez de reimplementarlos).
        std::string mem_alloc_sym, mem_free_sym;
        if (!traer_modulo_stdlib_(mem_path, mem_src, mem_opts,
                                  /*proyecto=*/true, tel, mem_mod,
                                  &mem_alloc_sym, &mem_free_sym) ||
            mem_alloc_sym.empty() || mem_free_sym.empty()) {
            std::cerr << "[aot] no pude compilar el slab allocator "
                         "vx_mem.vx (o no expone @AllocatorOverride).\n";
            return EXIT_FAILURE;
        }
        // Override por defecto = los simbolos que vx_mem declaro con
        // @AllocatorOverride (mismo trato que un override del usuario).
        lcfg.alloc_sym = mem_alloc_sym;
        lcfg.free_sym = mem_free_sym;
        lcfg.has_alloc_override = true; // __new calloc -> alloc_sym(size)
        bundle_mem = true;
    }
    if (!cr.aot_free_sym.empty()) lcfg.free_sym = cr.aot_free_sym;
    if (!cr.aot_panic_sym.empty()) {
        lcfg.panic_sym = cr.aot_panic_sym;
        lcfg.panic_takes_msg = true; // @PanicHandler(msg_addr, len)
    } else if (io_default_panic) {
        /* Sin hook del usuario, el panic por defecto es el de vx_io:
         * escribe el mensaje y sale con 134, igual que el interprete y
         * el JIT.  `abort` (el defecto anterior) tiraba el mensaje. */
        lcfg.panic_sym = "__panic";
        lcfg.panic_takes_msg = true;
    }

    // FFI dinamico (ffi_open/ffi_sym -> DLOPEN/DLSYM): bundle
    // stdlib/vx/vx_ffi.vx que define __vx_dlopen/__vx_dlsym
    // (LoadLibraryA/dlopen via @Target, Vesta puro).  Igual que vx_mem:
    // el usuario puede REDEFINIR esas funciones en su modulo (el merge
    // respeta las suyas).  Se detecta ANTES de aot_lower (que convierte
    // DLOPEN/DLSYM en CALL __vx_dlopen/__vx_dlsym).
    bool bundle_ffi = false;
    ir::IrModule ffi_mod;
    {
        bool aot_uses_ffi = false;
        for (const auto &af : aot_mod.functions)
            for (const auto &b : af.blocks)
                for (const auto &in : b.instrs)
                    if (in.op == ir::IrOp::DLOPEN || in.op == ir::IrOp::DLSYM)
                        aot_uses_ffi = true;
        if (aot_uses_ffi && !aot_freestanding) {
            const std::string exe_dir =
                std::filesystem::path(fs::get_executable_path())
                    .parent_path()
                    .string();
            const std::vector<std::string> cands = {
                exe_dir + "/stdlib/vx/vx_ffi.vx",
                exe_dir + "/../stdlib/vx/vx_ffi.vx", "stdlib/vx/vx_ffi.vx"};
            std::string ffi_path;
            for (const auto &c : cands)
                if (std::filesystem::exists(c)) {
                    ffi_path = c;
                    break;
                }
            if (ffi_path.empty()) {
                std::cerr << "[aot] usa ffi_open/ffi_sym pero no "
                             "encuentro stdlib/vx/vx_ffi.vx.\n";
                return EXIT_FAILURE;
            }
            std::ifstream ff(ffi_path);
            std::string ffi_src((std::istreambuf_iterator<char>(ff)),
                                std::istreambuf_iterator<char>());
            vx::CompileOptions ffi_opts;
            ffi_opts.module_name = "vx_ffi";
            ffi_opts.opt_level = copts.opt_level;
            ffi_opts.native_poo = true;
            ffi_opts.asm_target_bits = copts.asm_target_bits;
            if (!traer_modulo_stdlib_(ffi_path, ffi_src, ffi_opts,
                                      /*proyecto=*/false, tel, ffi_mod)) {
                std::cerr << "[aot] no pude compilar el FFI dinamico "
                             "vx_ffi.vx.\n";
                return EXIT_FAILURE;
            }
            bundle_ffi = true;
        }
    }

    aot::aot_lower_runtime(aot_mod, lcfg);

    // Merge del slab (stdlib/vx/vx_mem.vx, ya compilado en mem_mod)
    // DESPUES de aot_lower: ahora RAW_ALLOC/calloc/RAW_FREE ya son CALL
    // __vx_malloc/__vx_free, asi que el codegen BFS los alcanza desde
    // main.  Mismo patron de merge que vx_io/vx_exc.
    if (bundle_mem) {
        const uint64_t sd_off =
            static_cast<uint64_t>(aot_mod.static_data.size());
        std::unordered_set<std::string> have;
        for (const auto &af : aot_mod.functions)
            have.insert(af.name);
        for (auto &fn : mem_mod.functions) {
            if (sd_off != 0)
                for (auto &bb : fn.blocks)
                    for (auto &ins : bb.instrs)
                        if (ins.op == ir::IrOp::STR_LIT_ADDR) ins.imm += sd_off;
            if (!have.count(fn.name))
                aot_mod.functions.push_back(std::move(fn));
        }
        aot_mod.static_data.append_raw_entries(std::move(mem_mod.static_data));
        for (auto &gv : mem_mod.globals)
            aot_mod.globals.emplace(gv.first, gv.second);
        for (auto &ni : mem_mod.native_imports)
            aot_mod.register_native_import(ni.lib, ni.name);
        std::cout << "[aot] slab allocator (stdlib/vx/vx_mem.vx) "
                     "incluido en el objeto.\n";
    }

    // Merge del FFI dinamico (vx_ffi.vx) DESPUES de aot_lower: ahora
    // DLOPEN/DLSYM ya son CALL __vx_dlopen/__vx_dlsym y el BFS los
    // alcanza.  Mismo patron que vx_mem.  Si el usuario definio sus
    // propias __vx_dlopen/__vx_dlsym, el dedup (have) las respeta.
    if (bundle_ffi) {
        const uint64_t sd_off =
            static_cast<uint64_t>(aot_mod.static_data.size());
        std::unordered_set<std::string> have;
        for (const auto &af : aot_mod.functions)
            have.insert(af.name);
        for (auto &fn : ffi_mod.functions) {
            if (sd_off != 0)
                for (auto &bb : fn.blocks)
                    for (auto &ins : bb.instrs)
                        if (ins.op == ir::IrOp::STR_LIT_ADDR) ins.imm += sd_off;
            if (!have.count(fn.name))
                aot_mod.functions.push_back(std::move(fn));
        }
        aot_mod.static_data.append_raw_entries(std::move(ffi_mod.static_data));
        for (auto &gv : ffi_mod.globals)
            aot_mod.globals.emplace(gv.first, gv.second);
        for (auto &ni : ffi_mod.native_imports)
            aot_mod.register_native_import(ni.lib, ni.name);
        std::cout << "[aot] FFI dinamico (stdlib/vx/vx_ffi.vx) "
                     "incluido en el objeto.\n";
    }

    // Bare AOT: NO hay VM stack (rbx no es un ProcessVM*).  Forzar
    // TODAS las ALLOCAs a la pila nativa (host_alloca), incluso las
    // que "escapan" a un CALL -- en nativo el host stack ES
    // addressable cross-call.  Sin esto, un local cuya direccion se
    // pasa a una funcion (p.ej. un buffer para itoa) se aloca con
    // ALLOCA_VM ([rbx+0x40]) -> direccion basura -> SIGSEGV.
    for (auto &afn : aot_mod.functions)
        ir::ir_pass_promote_local_allocas(afn, /*force_all=*/true);

    /* Deteccion de CPU de los modulos FUSIONADOS.
     *
     * `cpu_features()` no sirve de nada por si sola: alguien tiene que
     * llamar a `__vx_cpu_init` antes que el programa, y de eso se
     * encarga el lowering PREPENDIENDOLO a main.  Pero solo lo hace si
     * la marca se puso al bajar el modulo del usuario, y estos modulos
     * -- `std.memory` y compania -- se fusionan DESPUES.  Resultado: el
     * bitmask se quedaba a cero y todo reparto de la stdlib elegia
     * siempre la variante base, sin que se notara mas que en el
     * tiempo.  Medido: `rep stosb` estaba en el binario y no se
     * ejecutaba nunca, porque su rama preguntaba por un bit que nadie
     * habia puesto.
     *
     * Aqui, ya con todo fusionado, se comprueba si el helper existe y
     * si main lo llama; si no, se prepende.  Es el mismo cableado que
     * hace el lowering, en el unico punto donde se sabe que modulos
     * acabaron dentro. */
    {
        bool hay_init = false;
        for (const auto &f : aot_mod.functions)
            if (f.name == "__vx_cpu_init") {
                hay_init = true;
                break;
            }
        if (hay_init) {
            for (auto &f : aot_mod.functions) {
                if (f.name != "main" || f.blocks.empty()) continue;
                auto &ins = f.blocks[0].instrs;
                bool ya = false;
                for (const auto &i2 : ins)
                    if (i2.op == ir::IrOp::CALL &&
                        i2.func_name == "__vx_cpu_init") {
                        ya = true;
                        break;
                    }
                if (!ya) {
                    ir::IrInstr call_init{};
                    call_init.op = ir::IrOp::CALL;
                    call_init.type = ir::IrType::VOID;
                    call_init.dst = ir::IR_NO_VALUE;
                    call_init.func_name = "__vx_cpu_init";
                    call_init.source_line = 0;
                    ins.insert(ins.begin(), std::move(call_init));
                }
                break;
            }
        }
    }

    tel.cerrar(tel.preparar_us);

    // ------------------------------------------------------------------
    // Paso 2: codegen nativo (HOST_LEAF) + emision del ejecutable.
    //
    // Hito minimo: compila SOLO `main` (sin CALL ni datos -> bytes
    // position-independent, sin relocations) y sintetiza un _start
    // arch+formato-especifico que llama a main y termina el proceso con
    // su codigo de retorno.  Todo el codegen pasa por el path vreg
    // (TargetRegInfo + selector + encoder), portable a otras arch.
    // ------------------------------------------------------------------

    // Arquitectura objetivo: x86-64 (default) o x86-32 (modo protegido,
    // kernels): 8 GP eax-edi, sin REX, operando 32-bit, regparm(3);
    // subset entero de 32-bit (i32/u32/ptr32).
    aot::AotArch arch = aot::AotArch::X86_64;
    {
        const std::string a = opt.arch;
        if (a == "x86-32" || a == "x86_32" || a == "i386")
            arch = aot::AotArch::X86_32;
        else if (a == "x86-64" || a == "x86_64" || a == "amd64")
            arch = aot::AotArch::X86_64;
        else if (a == "aarch64" || a == "arm64" || a == "arm-64")
            arch = aot::AotArch::ARM64;
        else {
            std::cerr << "[aot] --aot-arch desconocido: '" << a
                      << "' (use x86-64 | x86-32 | aarch64).\n";
            return EXIT_FAILURE;
        }
    }
    // aot_mode32 (bandera x86-32) se deriva de la arch; se usa aguas
    // abajo (contenedor ELF32, mode32 del codegen, etc.).
    const bool aot_mode32 = (arch == aot::AotArch::X86_32);

    // Backend de codegen nativo por arquitectura ( H.5): el driver
    // ya no llama al codegen x86 directamente, sino a traves de esta
    // interfaz.  Anadir una arch = implementar NativeBackend.
    std::unique_ptr<aot::NativeBackend> native_backend =
        aot::make_native_backend(arch);
    if (!native_backend) {
        std::cerr << "[aot] no hay backend de codegen para la arch "
                     "solicitada.\n";
        return EXIT_FAILURE;
    }

    // Backend de punto flotante (--float-isa).  Hoy el codegen float
    // (FP-regalloc en XMM, packing-ready) esta en construccion; el flag
    // queda cableado para que el selector elija el backend cuando llegue.
    jit::FloatIsa aot_fisa = jit::FloatIsa::SSE2;
    {
        const std::string f = opt.float_isa;
        if (f == "sse2" || f == "sse")
            aot_fisa = jit::FloatIsa::SSE2;
        else if (f == "x87" || f == "fpu")
            aot_fisa = jit::FloatIsa::X87;
        else if (f == "avx")
            aot_fisa = jit::FloatIsa::AVX;
        else if (f == "avx512f" || f == "avx512")
            aot_fisa = jit::FloatIsa::AVX512F;
        else if (f == "auto")
            aot_fisa = jit::FloatIsa::AUTO;
        else {
            std::cerr << "[aot] --float-isa desconocido: '" << f
                      << "' (use sse2 | x87 | avx | avx512f | auto).\n";
            return EXIT_FAILURE;
        }
    }

    // Formato de salida: --format pe|elf, o default por host.
    aot::ObjFormat fmt =
#if defined(_WIN32)
        aot::ObjFormat::PE;
#else
        aot::ObjFormat::ELF;
#endif
    if (!opt.format.empty()) {
        const std::string f = opt.format;
        if (f == "pe" || f == "PE")
            fmt = aot::ObjFormat::PE;
        else if (f == "elf" || f == "ELF")
            fmt = aot::ObjFormat::ELF;
        else {
            std::cerr << "[aot] --format desconocido: '" << f
                      << "' (use pe|elf).\n";
            return EXIT_FAILURE;
        }
    }

    // Referencias a datos: PIC (RIP-relativo, default) vs absoluto
    // (--no-pie, requiere base de imagen fija).  Analogo gcc/clang.
    // x86-32 NO tiene RIP-relative -> el PIC clasico exige GOT/PLT (no
    // implementado); forzamos no-PIE (ABS32/R_386_32 con base fija), que
    // es lo que un `gcc -m32` sin -fPIC produce por defecto.  Sin esto,
    // los STR_LIT_ADDR/LABEL_ADDR (static ctx, punteros a funcion en
    // memoria) tomaban direcciones RIP-relativas inconsistentes.
    const bool aot_pic = !opt.no_pie && !aot_mode32;

    // --emit exe|obj|shared.
    //   EXEC   : ejecutable standalone con _start (requiere main).
    //   OBJECT : .o/.obj relocatable (sin _start; main global; relocs
    //   como
    //            registros; linkable con ld/gcc/link).
    //   SHARED : .so/.dll (sin _start; exporta TODAS las funciones;
    //   PIC).
    bool emit_obj = false, emit_shared = false, emit_bin = false;
    if (!opt.emit.empty()) {
        const std::string em = opt.emit;
        if (em == "exe" || em == "exec") {
        } else if (em == "obj" || em == "o")
            emit_obj = true;
        else if (em == "shared" || em == "dll" || em == "so")
            emit_shared = true;
        else if (em == "bin" || em == "flat")
            emit_bin = true;
        else {
            std::cerr << "[aot] --emit desconocido: '" << em
                      << "' (use exe|obj|shared|bin).\n";
            return EXIT_FAILURE;
        }
    }
    // Increment 3: auto-link de libvesta_gc.a si el modulo usa gc<T>.
    // El frontend emite __vxgc_init cuando hay gc<T>; ese codigo llama
    // a vx_gc_* (definidos en libvesta_gc.a).  Para --emit exe se emite
    // un .obj temporal y se enlaza con la lib (vm --link interno),
    // porque la ruta inline mandaria vx_gc_* a imports de DLL (rotos).
    // Solo PE por ahora (la lib se distribuye como COFF .a).
    // Auto-link de librerias ESTATICAS de la stdlib (.a) cuando el
    // programa las usa: gc<T> (libvesta_gc.a), colecciones
    // (libvesta_collections.a), math (libvesta_math.a).  Asi el .exe es
    // STANDALONE (sin DLLs).  Se emite un .obj temporal y se enlaza con
    // las .a (vm --link interno).  Las .a son de NUESTRO lenguaje ->
    // siempre estaticas; solo se anaden si el programa las usa de verdad.
    bool need_temp_link = false;
    std::string link_real_out, link_tmp_obj;
    std::vector<std::string> autolink_libs;
    {
        bool uses_gc = false, uses_col = false, uses_math = false;
        for (const auto &fn : aot_mod.functions)
            for (const auto &b : fn.blocks)
                for (const auto &ins : b.instrs) {
                    const std::string &f = ins.func_name;
                    if (f.rfind("vx_gc_", 0) == 0) uses_gc = true;
                    if (f.find("vcol_") != std::string::npos) uses_col = true;
                    if (f.find("vmath_") != std::string::npos) uses_math = true;
                }
        const bool want_exec = !emit_obj && !emit_shared && !emit_bin;
        namespace fs = std::filesystem;
        auto find_a = [&](const char *libfile) -> std::string {
            std::vector<fs::path> cands;
            const fs::path self(argv0);
            if (self.has_parent_path())
                cands.push_back(self.parent_path() / libfile);
            cands.emplace_back(libfile);
            cands.push_back(fs::path("cmake-build-release") / libfile);
            cands.push_back(fs::path("cmake-build-debug") / libfile);
            for (const auto &c : cands) {
                std::error_code ec;
                if (fs::exists(c, ec)) return c.string();
            }
            return "";
        };
        if (want_exec) {
            if (uses_gc) {
                const std::string p = find_a("libvesta_gc.a");
                if (p.empty()) {
                    std::cerr << "[aot] gc<T>: no se encontro "
                                 "libvesta_gc.a (junto a vm o cwd).\n";
                    return EXIT_FAILURE;
                }
                autolink_libs.push_back(p);
            }
            // Colecciones / math: preferir la .a estatica (standalone);
            // si no esta, se deja para el import IAT de la DLL (fallback,
            // la DLL acompana al exe).
            if (uses_col) {
                const std::string p = find_a("libvesta_collections.a");
                if (!p.empty()) autolink_libs.push_back(p);
            }
            if (uses_math) {
                const std::string p = find_a("libvesta_math.a");
                if (!p.empty()) autolink_libs.push_back(p);
            }
        }
        if (!autolink_libs.empty()) {
            need_temp_link = true;
            emit_obj = true;            // emitir .obj temporal...
            link_real_out = out_prefix; // ...y enlazarlo al .exe final
            link_tmp_obj = out_prefix + ".aotlink.tmp.obj";
            out_prefix = link_tmp_obj;
        }
    }

    // --emit shared: ELF (.so) y PE (.dll).
    if (emit_shared && !aot_pic) {
        std::cerr << "[aot] --emit shared requiere PIC; --no-pie no es "
                     "compatible con .so.\n";
        return EXIT_FAILURE;
    }
    // base de carga del binario plano (.bin) -- solo afecta refs
    // absolutas.
    uint64_t bin_base = 0;
    if (!opt.bin_base.empty()) {
        bin_base = std::strtoull(opt.bin_base.c_str(), nullptr, 0);
    }
    // OBJECT/SHARED/BIN no llevan _start (lo aporta el
    // crt/host/loader).
    const bool no_stub = emit_obj || emit_shared || emit_bin;

    // x86-32: soporta --emit bin (flat), --emit exe (ELF32/PE32) y
    // --emit obj (.o ELF32 -- COFF32 .obj es follow-up).  .so/.dll de
    // 32-bit pendientes.  El objeto conserva la extension .o (linkable
    // con gcc -m32 / ld).
    if (aot_mode32) {
        // --emit obj: .o ELF32 (--format elf) o .obj COFF i386
        // (--format pe), ambos conservando la extension para linkers
        // externos (gcc -m32 / ld / link.exe).
        const bool ok32 =
            emit_bin || emit_obj || (!no_stub /* EXEC: ELF32 o PE32 */);
        if (!ok32) {
            std::cerr << "[aot] --aot-arch x86-32: soporta --emit bin, "
                         "--emit exe (ELF32 / PE32) o --emit obj (.o ELF32 / "
                         ".obj COFF i386); .so/.dll de 32-bit son "
                         "follow-ups.\n";
            return EXIT_FAILURE;
        }
    }

    // main: requerido para EXEC y OBJECT; OPCIONAL para SHARED
    // (libreria).
    const ir::IrFunction *main_fn = nullptr;
    for (const auto &fn : aot_mod.functions)
        if (fn.name == "main") {
            main_fn = &fn;
            break;
        }
    if (!main_fn && !emit_shared && !emit_bin && !emit_obj) {
        std::cerr << "[aot] no se encontro la funcion 'main' en el modulo.\n";
        return EXIT_FAILURE;
    }

    // _start (arch+formato): solo para EXEC.  OBJECT/SHARED/BIN no
    // llevan _start (lo aporta el crt del linker / el host / el loader
    // externo).
    aot::StartStub stub{};
    if (!no_stub) stub = aot::aot_make_start_stub(arch, fmt);
    if (!no_stub && !stub.ok) {
        std::cerr << "[aot] " << stub.err << "\n";
        return EXIT_FAILURE;
    }

    // TLS: derivar in-memory el flag is_tls de cada STR_LIT_ADDR cuya
    // entrada static_data lleve SD_FLAG_TLS (la TLS-ness no se
    // serializa por-instruccion; se reconstruye aqui desde el flag de
    // la entrada, que SI round-trippea).  El codegen vreg lo consume
    // para emitir el acceso por thread pointer (fs/gs + TPOFF).
    bool module_has_tls = false;
    {
        const auto &sd_tls = aot_mod.static_data;
        for (size_t i = 0; i < sd_tls.size(); ++i)
            if (sd_tls.entries[i].meta.flags & ir::IrModule::SD_FLAG_TLS) {
                module_has_tls = true;
                break;
            }
        for (auto &f : aot_mod.functions)
            for (auto &blk : f.blocks)
                for (auto &in : blk.instrs)
                    if (in.op == ir::IrOp::STR_LIT_ADDR &&
                        in.imm < sd_tls.size() &&
                        (sd_tls.entries[in.imm].meta.flags &
                         ir::IrModule::SD_FLAG_TLS))
                        in.is_tls = true;
    }
    // thread_local en libreria/binario:
    //   - PE shared (.dll): VALIDO -- el TLS directory de Windows lo
    //     procesa el cargador tambien para DLLs (Vista+, incl.
    //     LoadLibrary); el emisor lo sintetiza igual que en el .exe.
    //   - ELF shared (.so): NO -- el modelo local-exec es incorrecto en
    //     una lib cargada con dlopen (el offset TLS se asigna en
    //     runtime; requiere initial-exec/general-dynamic, que nuestro
    //     codegen aun no emite).
    //   - bin (binario plano): NO -- no hay cargador que monte el bloque.
    const bool tls_is_pe = (fmt == aot::ObjFormat::PE);
    if (module_has_tls && (emit_bin || (emit_shared && !tls_is_pe))) {
        std::cerr << "[aot] thread_local no soportado en --emit "
                  << (emit_bin ? "bin" : "shared (ELF)") << " todavia: "
                  << (emit_bin
                          ? "un binario plano no tiene cargador que monte el "
                            "bloque TLS"
                          : "una .so con dlopen necesita initial-exec/"
                            "general-dynamic, no local-exec")
                  << ".  Usa --emit exe/obj (o --format pe --emit shared para "
                     "una .dll).\n";
        return EXIT_FAILURE;
    }
    // PE shared (.dll) con TLS: el emisor sintetiza el TLS directory
    // (isolation por-hilo) y, ademas, fija el AddressOfEntryPoint a
    // __vx_tls_init (un DllMain minimo).  ntdll lo invoca en cada
    // DLL_PROCESS_ATTACH / DLL_THREAD_ATTACH, aplicando la plantilla
    // (valores iniciales no-cero) a la copia por-hilo -- funciona con
    // cualquier consumidor (con o sin CRT).  Sin nota necesaria.

    // Indice nombre -> IrFunction* del modulo (para resolver CALLs).
    std::unordered_map<std::string, const ir::IrFunction *> fn_by_name;
    for (const auto &f : aot_mod.functions)
        fn_by_name[f.name] = &f;

    // Codigo compilado de cada funcion + sus relocations + su seccion.
    struct AotFn {
        std::string name;
        std::vector<uint8_t> bytes;
        std::vector<jit::NativeReloc> relocs;
        std::string section;                // @section ("" = .text)
        std::string section_perms;          // "rwx" explicito ("" = convencion)
        int64_t section_at = -1;            // @at(N)
        int32_t section_order = 0x7fffffff; // @order(N)
        //  AOT-GC (Inc 1): stackmaps de raices GC por safepoint
        // (pc_offset relativo a esta funcion).  Vacios salvo gc<T>.
        std::vector<jit::Stackmap> stackmaps;
        /// Donde cambia el punto del fuente dentro de @c bytes: es un
        /// DATO, no cambia lo emitido.  Vacio salvo que se pidiera.
        ///
        /// Lleva COLUMNA ademas de linea porque con la linea sola no se
        /// puede subrayar QUE de ella fallo, que es la diferencia entre
        /// senalar una sentencia y senalar la operacion.
        struct PuntoFuente {
            uint32_t off;  ///< desplazamiento dentro de la funcion
            uint32_t line; ///< linea del fuente
            uint32_t col;  ///< columna (0 = no consta)
            uint32_t len;  ///< cuanto ocupa el tramo (0 = no consta)
            /// De que funcion vino ESTE tramo si no se escribio aqui,
            /// sino que llego al inlinar.  Vacio = de esta misma.
            /// Sin ello el informe manda a la funcion FISICA cuando el
            /// codigo que fallo se escribio en otra.
            std::string venia_de;
            /// La instruccion del INTERMEDIO que produjo este tramo, ya
            /// escrita.  Se renderiza AL COMPILAR: hacerlo dentro de un
            /// manejador de fallo exigiria un impresor de intermedio
            /// entero corriendo con el proceso ya roto.
            std::string ir_txt;
        };
        std::vector<PuntoFuente> puntos;
    };
    std::vector<AotFn> compiled;
    std::unordered_map<std::string, size_t> compiled_idx; // name -> compiled[]

    // BFS desde main: compila cada funcion alcanzada por un CALL.
    // Ademas se SIEMBRAN las funciones con @section explicito (el
    // usuario las coloco a proposito; pueden referenciarse SOLO via
    // section_start/end o asm, sin CALL directo -> no dead-strip).  En
    // SHARED (.so) se siembran TODAS las funciones: la libreria las
    // EXPORTA todas.
    std::vector<std::string> work;
    std::unordered_map<std::string, bool> queued;
    if (main_fn) {
        work.push_back("main");
        queued["main"] = true;
    }
    for (const auto &fn : aot_mod.functions) {
        // SHARED siembra todo (exporta todo).  OBJECT sin main es una
        // libreria -> tambien siembra todo (compila todas sus funciones
        // para que un linker las pueda usar).  Con main, OBJECT mantiene
        // el BFS desde main (no regresa programas con funciones
        // inalcanzables no-compilables).  @section siempre se siembra.
        //  NR @Naked: un ISR/stub se referencia desde la IDT/GDT
        // o por asm externo, NUNCA por un CALL visible -> sembrarlo
        // siempre para que no lo elimine el dead-strip del BFS.
        if ((emit_shared || (emit_obj && !main_fn) || !fn.section.empty() ||
             fn.is_naked) &&
            !queued.count(fn.name)) {
            queued[fn.name] = true;
            work.push_back(fn.name);
        }
    }
    // __vx_tls_init (TLS callback): lo llama el cargador de Windows (no
    // un CALL visible) -> sembrarlo siempre para que se compile.
    if (!queued.count("__vx_tls_init"))
        for (const auto &fn : aot_mod.functions)
            if (fn.name == "__vx_tls_init") {
                queued["__vx_tls_init"] = true;
                work.push_back("__vx_tls_init");
                break;
            }

    // Sembrar las funciones referenciadas por bloques `bytes` (`dq
    // foo`) para que se compilen aunque main no las alcance por CALL.
    for (const auto &e : aot_mod.static_data.entries) {
        for (const auto &sr : e.meta.sym_refs) {
            if (fn_by_name.count(sr.sym) && !queued.count(sr.sym)) {
                queued[sr.sym] = true;
                work.push_back(sr.sym);
            }
        }
    }
    bool aot_codegen_ok = true;
    // AUTO (--float-isa auto): multiversion por cpuid.  Las funciones
    // con ops VEC_* (vectorizadas) se compilan 3x (sse2/avx2/avx512); el
    // IR es UNO (chunk dual: element-wise 64, reduccion 16 -> cada
    // variante decompone a su ancho).  El dispatch (fp+init+trampolin) va
    // despues; aqui solo emitimos las variantes fn$sse2/avx2/avx512.
    const bool aot_auto = (aot_fisa == jit::FloatIsa::AUTO);
    auto fn_has_vec_ops = [](const ir::IrFunction &f) -> bool {
        for (const auto &b : f.blocks)
            for (const auto &in : b.instrs) {
                const auto op = in.op;
                if (op == ir::IrOp::VEC_BINOP || op == ir::IrOp::VEC_UNOP ||
                    op == ir::IrOp::VEC_FMA || op == ir::IrOp::VEC_BINOP_S ||
                    op == ir::IrOp::VEC_BCAST || op == ir::IrOp::VEC_ACC_ZERO ||
                    op == ir::IrOp::VEC_ACC_ADD ||
                    op == ir::IrOp::VEC_ACC_FMA ||
                    op == ir::IrOp::VEC_ACC_STORE ||
                    op == ir::IrOp::VEC_ACC_COMBINE)
                    return true;
            }
        return false;
    };
    // Nombres de las variantes multiversionadas (los consume el dispatch).
    std::vector<std::string> mv_funcs; // funciones multiversionadas
    // AUTO: sembrar toda funcion con ops VEC.  __vx_main_body (el main
    // del usuario renombrado por la lowering) NO se alcanza por CALL
    // directo (el main sintetico hace CALLIND via fp), asi que hay que
    // encolarlo explicitamente para que se dequeue -> compile sus 3
    // variantes.  __vx_auto_init si se alcanza (main lo CALL-prepende).
    if (aot_auto) {
        for (const auto &fn : aot_mod.functions) {
            if (fn_has_vec_ops(fn) && !queued.count(fn.name)) {
                queued[fn.name] = true;
                work.push_back(fn.name);
            }
        }
    }
    // ABI custom por funcion: el CALL directo resuelve los param_abi_regs
    // del callee por nombre (register() en su firma).  Copiamos SOLO las
    // funciones con ABI custom a un mapa respaldado por shared_ptr (el
    // resolver lo captura por valor -> sin referencia colgante y sin
    // limpieza manual; el 99% de programas no tiene ninguna entrada).
    {
        auto abi_map = std::make_shared<
            std::unordered_map<std::string, std::vector<std::string>>>();
        for (const auto &f : aot_mod.functions)
            if (!f.param_abi_regs.empty())
                (*abi_map)[f.name] = f.param_abi_regs;
        jit::vreg_set_abi_resolver([abi_map](const std::string &name)
                                       -> const std::vector<std::string> * {
            auto it = abi_map->find(name);
            return it == abi_map->end() ? nullptr : &it->second;
        });
    }
    while (!work.empty()) {
        const std::string nm = work.back();
        work.pop_back();
        auto itf = fn_by_name.find(nm);
        if (itf == fn_by_name.end()) {
            std::cerr << "[aot] simbolo no resuelto: la funcion '" << nm
                      << "' (referenciada por un CALL) no existe en el "
                         "modulo.\n";
            aot_codegen_ok = false;
            break;
        }
        AotFn af;
        af.name = nm;
        af.section = itf->second->section;
        af.section_perms = itf->second->section_perms;
        af.section_at = itf->second->section_at;
        af.section_order = itf->second->section_order;
        {
            aot::NativeCompileOpts nopts;
            nopts.pic = aot_pic;
            nopts.target_sysv = (fmt == aot::ObjFormat::ELF);
            nopts.mode32 = aot_mode32;
            nopts.fisa = aot_fisa;
            // Con info de depuracion, tambien la correlacion con el
            // fuente.  No cambia ni un byte de lo emitido.
            nopts.want_line_map = (opt.lang_debug_level >= 1);
            aot::NativeCompileResult ncr =
                native_backend->compile_function(*itf->second, nopts);
            af.bytes = std::move(ncr.bytes);
            af.relocs = std::move(ncr.relocs);
            af.stackmaps = std::move(ncr.stackmaps);
            /* El punto de fuente de cada tramo de codigo.  La linea
             * la da el mapa; la COLUMNA y el tramo salen de la propia
             * instruccion del intermedio, que el mapa identifica por
             * @c ir_id (bloque*65536 + posicion).  Se resuelve aqui,
             * al compilar, para que el fichero acompanante se baste
             * solo y quien lo lea no necesite el intermedio. */
            {
                const ir::IrFunction &irf = *itf->second;
                uint32_t ultima = 0;
                for (const jit::LineMapEntry &e : ncr.line_map) {
                    if (e.source_line == 0 || e.source_line == ultima) continue;
                    ultima = e.source_line;
                    AotFn::PuntoFuente pf{e.byte_offset, e.source_line, 0u, 0u,
                                          std::string(), std::string()};
                    if (e.ir_id != 0xFFFFFFFFu) {
                        const uint32_t bi = e.ir_id >> 16;
                        const uint32_t pos = e.ir_id & 0xFFFFu;
                        if (bi < irf.blocks.size() &&
                            pos < irf.blocks[bi].instrs.size()) {
                            const ir::IrInstr &in = irf.blocks[bi].instrs[pos];
                            pf.col = in.source_column;
                            pf.len = in.source_len;
                            /* Y de donde vino: la instruccion sabe si
                             * llego aqui al inlinar y desde que
                             * funcion. */
                            if (in.inline_site != ir::IR_NO_INLINE_SITE &&
                                in.inline_site < irf.inline_sites.size())
                                pf.venia_de =
                                    irf.inline_sites[in.inline_site].callee;
                            // Y la instruccion, ya escrita.
                            {
                                std::ostringstream os;
                                ir::print_instr(os, irf, in);
                                std::string t = os.str();
                                while (!t.empty() &&
                                       (t.back() == 10 || t.back() == 13))
                                    t.pop_back();
                                const size_t ini2 = t.find_first_not_of(' ');
                                if (ini2 != std::string::npos)
                                    t = t.substr(ini2);
                                pf.ir_txt = std::move(t);
                            }
                        }
                    }
                    af.puntos.push_back(pf);
                }
            }
        }
        if (af.bytes.empty()) {
            /* CUAL op, no "una op".  El selector lo sabe y lo dejaba
             * morir detras de una variable de entorno, asi que esto
             * obligaba a recompilar con la traza puesta y a adivinar de
             * que funcion se hablaba. */
            const std::string &porque = jit::vreg_ultimo_motivo();
            std::cerr << "[aot] el selector vreg no soporta la funcion '" << nm
                      << "' todavia: "
                      << (porque.empty() ? std::string("no consta que op")
                                         : ("op " + porque))
                      << ".\n";
            aot_codegen_ok = false;
            break;
        }
        compiled_idx[nm] = compiled.size();
        compiled.push_back(std::move(af));

        // AUTO: si la funcion tiene ops VEC, emitir las 3 variantes de
        // ancho compilando el MISMO IR con fisa sse2/avx2/avx512.  El
        // dispatch (mas abajo) las cablea via fp+init+trampolin.  La
        // copia `nm` (compilada arriba con AUTO=host) sirve de baseline
        // hasta que el trampolin la reemplace.
        if (aot_auto && fn_has_vec_ops(*itf->second)) {
            const std::pair<const char *, jit::FloatIsa> variants[] = {
                {"$sse2", jit::FloatIsa::SSE2},
                {"$avx2", jit::FloatIsa::AVX},
                {"$avx512", jit::FloatIsa::AVX512F}};
            bool ok = true;
            for (const auto &v : variants) {
                AotFn vf;
                vf.name = nm + v.first;
                {
                    aot::NativeCompileOpts vopts;
                    vopts.pic = aot_pic;
                    vopts.target_sysv = (fmt == aot::ObjFormat::ELF);
                    vopts.mode32 = aot_mode32;
                    vopts.fisa = v.second;
                    aot::NativeCompileResult vcr =
                        native_backend->compile_function(*itf->second, vopts);
                    vf.bytes = std::move(vcr.bytes);
                    vf.relocs = std::move(vcr.relocs);
                }
                if (vf.bytes.empty()) {
                    std::cerr << "[aot] variante " << vf.name
                              << " no compilable.\n";
                    ok = false;
                    break;
                }
                // Las CALL de la variante encolan callees igual que el
                // baseline (se hace abajo en el loop de relocs comun? no:
                // las variantes no pasan por ese loop -> encolar aqui).
                for (const jit::NativeReloc &r : vf.relocs)
                    if (r.kind == jit::NativeReloc::Kind::CALL_REL32 &&
                        fn_by_name.count(r.symbol) && !queued.count(r.symbol)) {
                        queued[r.symbol] = true;
                        work.push_back(r.symbol);
                    }
                compiled_idx[vf.name] = compiled.size();
                compiled.push_back(std::move(vf));
            }
            if (!ok) {
                aot_codegen_ok = false;
                break;
            }
            mv_funcs.push_back(nm);
        }
        // Encolar los callees (relocs CALL_REL32 a nombres de funcion).
        // Los simbolos que NO son funciones del modulo son EXTERNOS
        // (libc/runtime, resueltos por el linker): no se encolan, se
        // emiten como relocs externas en PASS 2.
        for (const jit::NativeReloc &r : compiled.back().relocs) {
            // CALL directo a un callee del modulo -> encolar (x86 rel32 o
            // AArch64 bl/CALL26).
            if (r.kind == jit::NativeReloc::Kind::CALL_REL32 ||
                r.kind == jit::NativeReloc::Kind::ARM64_CALL26) {
                if (queued.count(r.symbol)) continue;
                if (!fn_by_name.count(r.symbol)) continue; // externo
                queued[r.symbol] = true;
                work.push_back(r.symbol);
                continue;
            }
            // Referencia a la DIRECCION de una funcion ("fnsym:<name>",
            // de LABEL_ADDR: puntero de funcion para CALLIND, p.ej. el
            // despacho de helpers multi-versionados o as_native_callback)
            // -> encolar el target tambien (no llega por CALL directo).
            if (r.symbol.rfind("fnsym:", 0) == 0) {
                const std::string tgt = r.symbol.substr(6);
                if (queued.count(tgt)) continue;
                if (!fn_by_name.count(tgt)) continue; // externo
                queued[tgt] = true;
                work.push_back(tgt);
            }
        }
    }
    if (!aot_codegen_ok) return EXIT_FAILURE;

    tel.cerrar(tel.codegen_us);

    // ------------------------------------------------------------------
    // Layout MULTI-SECCION (2b, dev OS): el usuario decide en que
    // seccion vive cada funcion (@section) / dato.  Construimos un
    // buffer por seccion; .text (indice 0) es la de entrada (el _start
    // stub va en su offset 0).  TODAS las refs (stub->main, llamadas,
    // datos) se declaran al ObjectWriter, que las resuelve tras el
    // layout (unica entidad que conoce la VA de cada seccion) ->
    // CALL/JMP cross-seccion "just work".
    // ------------------------------------------------------------------
    struct SecAccum {
        std::string name;
        bool is_code = true;
        std::string perms; // "" = por convencion del nombre
        std::vector<uint8_t> bytes;
        int64_t at = -1;            // @at(N) (.bin)
        int32_t order = 0x7fffffff; // @order(N) (.bin)
    };
    std::vector<SecAccum> secs;
    std::unordered_map<std::string, int> sec_index;
    // Recoge perms/at/order de cualquier fn/dato que toque la seccion.
    // El primer @at no-default gana; el menor @order gana.  Conflictos
    // de @at distintos en la misma seccion se reportan.
    auto get_sec = [&](const std::string &name, bool is_code,
                       const std::string &perms, int64_t at = -1,
                       int32_t order = 0x7fffffff) -> int {
        auto it = sec_index.find(name);
        if (it != sec_index.end()) {
            SecAccum &s = secs[it->second];
            if (!perms.empty() && s.perms.empty()) s.perms = perms;
            if (at >= 0) {
                if (s.at >= 0 && s.at != at)
                    std::cerr << "[aot] @at en conflicto para la seccion '"
                              << name << "' (" << s.at << " vs " << at
                              << ").\n";
                else
                    s.at = at;
            }
            if (order < s.order) s.order = order;
            return it->second;
        }
        const int idx = static_cast<int>(secs.size());
        SecAccum s;
        s.name = name;
        s.is_code = is_code;
        s.perms = perms;
        s.at = at;
        s.order = order;
        secs.push_back(std::move(s));
        sec_index[name] = idx;
        return idx;
    };
    // .text es SIEMPRE la seccion 0 (entry); el stub arranca en su off
    // 0.
    const int text_sec = get_sec(".text", true, "");
    secs[text_sec].bytes = stub.bytes;

    // Colocar cada funcion en su seccion (default .text).  main primero
    // dentro de su seccion (determinismo).
    struct FnLoc {
        int sec;
        uint32_t off;
    };
    std::unordered_map<std::string, FnLoc> fn_loc;
    auto place_fn = [&](size_t ci) {
        AotFn &af = compiled[ci];
        const std::string &fsec = af.section.empty() ? ".text" : af.section;
        const int si = get_sec(fsec, /*is_code=*/true, af.section_perms,
                               af.section_at, af.section_order);
        const uint32_t off = static_cast<uint32_t>(secs[si].bytes.size());
        fn_loc[af.name] = {si, off};
        secs[si].bytes.insert(secs[si].bytes.end(), af.bytes.begin(),
                              af.bytes.end());
    };
    // main primero (si existe; en SHARED puede no haber).
    if (main_fn) place_fn(compiled_idx["main"]);
    for (size_t ci = 0; ci < compiled.size(); ++ci)
        if (!main_fn || compiled[ci].name != "main") place_fn(ci);

    // gc<T> (Inc 4b): emitir la seccion .vxgc_smap con los stackmaps de
    // cada funcion que retiene GC roots, para que __vxgc_init la
    // registre en el GC al arranque (scan_jit_roots_precise sobre frames
    // nativos).  func_addr va como placeholder + reloc ABS64 a la fn
    // (resuelto tras el layout).  Solo si hay stackmaps no vacios.
    std::vector<std::pair<uint32_t, std::string>> smap_func_relocs;
    int smap_si = -1;
    {
        std::vector<size_t> gc_fns;
        for (size_t ci = 0; ci < compiled.size(); ++ci) {
            // Registrar TODA funcion con al menos un safepoint (call),
            // aunque NO retenga roots GC: el WALK POR TAMANO DE FRAME
            // debe poder ATRAVESARLA (leer su frame_size) para llegar a
            // los frames superiores que si retienen roots.  Si solo
            // registraramos las que tienen slots no vacios, el walk se
            // cortaria en una funcion intermedia sin roots y perderia
            // los roots de sus llamadores -> colectaria vivos.  Las
            // hojas frameless (sin calls) no tienen stackmaps y nunca
            // aparecen a mitad de pila durante un GC -> se omiten (cero
            // coste).
            if (!compiled[ci].stackmaps.empty()) gc_fns.push_back(ci);
        }
        // Emitir la seccion siempre que ALGUNA funcion referencie
        // .vxgc_smap (via section_start/size de __vxgc_init, posible-
        // mente INLINEADO en main) -- aunque no haya stackmaps no vacios
        // -- porque la reloc secsym exige que la seccion exista.
        bool gc_smap_ref = false;
        for (const auto &af : compiled) {
            for (const auto &r : af.relocs)
                if (r.symbol.find(".vxgc_smap") != std::string::npos) {
                    gc_smap_ref = true;
                    break;
                }
            if (gc_smap_ref) break;
        }
        if (gc_smap_ref) {
            std::vector<uint8_t> b;
            auto put32 = [&b](uint32_t v) {
                for (int i = 0; i < 4; ++i)
                    b.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
            };
            auto put64 = [&b](uint64_t v) {
                for (int i = 0; i < 8; ++i)
                    b.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
            };
            put32(0x4D475856u);                          // 'VXGM'
            put32(2u);                                   // version
            put32(static_cast<uint32_t>(gc_fns.size())); // n_fn
            put32(0u); // total_size (parcheado al final, offset 12)
            for (size_t ci : gc_fns) {
                const AotFn &af = compiled[ci];
                smap_func_relocs.push_back(
                    {static_cast<uint32_t>(b.size()), af.name});
                put64(0); // func_addr placeholder (ABS64 reloc)
                put32(static_cast<uint32_t>(af.bytes.size())); // code_size
                // frame_size (v2): RBP - RSP en un safepoint call.  Igual
                // en todos los stackmaps de la fn; el WALK POR TAMANO DE
                // FRAME lo usa para reconstruir RBP sin cadena RBP.
                put32(af.stackmaps.empty() ? 0u
                                           : af.stackmaps.front().frame_size);
                put32(static_cast<uint32_t>(
                    af.stackmaps.size())); // n_safepoints (todos)
                for (const auto &sm : af.stackmaps) {
                    put32(sm.pc_offset);
                    put32(static_cast<uint32_t>(sm.slots.size()));
                    for (const auto &slot : sm.slots) {
                        const int16_t off = slot.rbp_offset;
                        b.push_back(static_cast<uint8_t>(off & 0xFF));
                        b.push_back(static_cast<uint8_t>((off >> 8) & 0xFF));
                        b.push_back(static_cast<uint8_t>(slot.gc_kind));
                        b.push_back(0); // _pad
                    }
                }
            }
            // Parchear total_size (offset 12) con el tamanño final.
            const uint32_t total = static_cast<uint32_t>(b.size());
            for (int i = 0; i < 4; ++i)
                b[12 + i] = static_cast<uint8_t>((total >> (i * 8)) & 0xFF);
            smap_si = get_sec(".vxgc_smap", /*is_code=*/false, "r");
            secs[smap_si].bytes = std::move(b);
        }
    }

    // ------------------------------------------------------------------
    // AOT.2.exec (PE-IAT): EXEC/SHARED standalone que llaman a simbolos
    // EXTERNOS (libc malloc/free/calloc/abort, o un FFI extern).  El
    // codigo emitio `call <sym>` (E8 rel32 directo) pero el simbolo NO
    // esta en la imagen -> hay que pasar por la IAT.  Como un `call
    // [rip+IAT]` (FF 15) mide 6 bytes y el E8 ya emitido mide 5, NO se
    // puede parchear in-situ.  Solucion estandar (como un linker): un
    // THUNK de import por simbolo en .text -- `FF 25 disp32` (jmp
    // [rip+IAT], 6 bytes) -- y el `call <sym>` apunta al thunk (REL32
    // normal intra-.text).  El `FF 25` del thunk se parchea via el
    // mecanismo de imports (mismo que ExitProcess del _start).  El
    // loader rellena la IAT con la direccion real -> el thunk salta
    // ahi. Solo PE EXEC por ahora (ELF EXEC = PLT-GOT, slice 2;
    // SHARED/.dll = follow-up; .o sigue emitiendo relocs externas que
    // resuelve gcc/ld).
    struct PeThunkImport {
        std::string dll, func;
        uint64_t off;
    };
    std::vector<PeThunkImport> pe_thunk_imports;
    // EXEC (PE o ELF) que llama a externos -> thunks de import.  PE los
    // resuelve por IAT (slice 1); ELF por eager-GOT como PIE dinamico
    // (slice 2).  El mismo thunk FF 25 sirve a ambos; difiere solo la
    // metadata (idata vs dynamic) que pone el emisor.
    const bool exec_native = !no_stub;
    if (exec_native) {
        // Recolectar externos (CALL_REL32 a un nombre que NO es funcion
        // del modulo), en orden estable y deduplicado.
        std::vector<std::string> ext_syms;
        std::unordered_set<std::string> ext_seen;
        for (const AotFn &af : compiled)
            for (const jit::NativeReloc &r : af.relocs)
                if (r.kind == jit::NativeReloc::Kind::CALL_REL32 &&
                    !fn_by_name.count(r.symbol) && !ext_seen.count(r.symbol)) {
                    ext_seen.insert(r.symbol);
                    ext_syms.push_back(r.symbol);
                }
        // Mapa simbolo -> DLL.  PE: libc (MinGW/Windows) = msvcrt.dll;
        // los FFI extern de DLL del usuario llegan como "sym" (el lib
        // se perdio en el selector) -> default msvcrt.dll (follow-up:
        // cablear el DLL real desde el CompileResult).  ELF: el campo
        // se ignora (todo va a libc.so.6 via DT_NEEDED).
        const bool is_pe = (fmt == aot::ObjFormat::PE);
        // DLL real de cada simbolo externo via el mecanismo FFI del
        // lenguaje: `extern "kernel32.dll" { fn WriteFile(...); }`
        // registra ("kernel32.dll", "WriteFile") en native_imports (ver
        // lower_call FFI declarativo).  Construimos symbol -> DLL desde
        // ahi, en vez de una tabla hardcodeada en el compilador.  PE: si
        // un simbolo no esta declarado en ningun extern (libc implicito:
        // malloc/free/abort de msvcrt) -> msvcrt.dll.  ELF: todo va a
        // libc.so.6 via DT_NEEDED (el SONAME no se usa para resolver).
        std::unordered_map<std::string, std::string> sym2dll;
        for (const auto &ni : aot_mod.native_imports) {
            // (a) FFI extern a sistema: lib ya es un nombre de DLL real
            //     (`extern "kernel32.dll"`).
            if (ni.lib.size() >= 4 &&
                (ni.lib.rfind(".dll") == ni.lib.size() - 4 ||
                 ni.lib.rfind(".DLL") == ni.lib.size() - 4)) {
                sym2dll[ni.name] = ni.lib;
                continue;
            }
            // (b) Plugin de la stdlib (ruta tipo
            //     "stdlib/native/collections/vesta_collections"): el
            //     plugin se distribuye como una DLL con el basename de la
            //     ruta (vesta_collections.dll).  Lo importamos por IAT
            //     -> las colecciones (ArrayList/HashMap/...) funcionan en
            //     AOT sin la VM (sus funciones vcol_* toman uint64, no
            //     proc_ptr).  La DLL debe acompanar al .exe.
            const auto slash = ni.lib.find_last_of("/\\");
            const std::string base = (slash == std::string::npos)
                                         ? ni.lib
                                         : ni.lib.substr(slash + 1);
            if (!base.empty()) sym2dll[ni.name] = base + ".dll";
        }
        auto dll_for = [is_pe,
                        &sym2dll](const std::string &sym) -> std::string {
            if (!is_pe) return "libc.so.6";
            auto it = sym2dll.find(sym);
            if (it != sym2dll.end()) return it->second;
            return "msvcrt.dll";
        };
        for (const std::string &sym : ext_syms) {
            const uint32_t toff =
                static_cast<uint32_t>(secs[text_sec].bytes.size());
            // FF 25 00 00 00 00 -> jmp [rip+disp32]; disp32 a parchear.
            const uint8_t thunk[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
            secs[text_sec].bytes.insert(secs[text_sec].bytes.end(), thunk,
                                        thunk + 6);
            fn_loc[sym] = {text_sec, toff}; // el call <sym> -> el thunk
            pe_thunk_imports.push_back({dll_for(sym), sym, toff});
        }
    }

    // PASADA 1: colocar (lazy, una vez por entry) los datos
    // referenciados en su seccion (default .rodata) -> completa `secs`
    // ANTES de crearlas en el writer.  Devuelve (sec, off) del entry N.
    const auto &sd = aot_mod.static_data;
    std::unordered_map<uint32_t, std::pair<int, uint64_t>> data_loc;
    auto place_data = [&](uint32_t N) -> std::pair<int, uint64_t> {
        auto it = data_loc.find(N);
        if (it != data_loc.end()) return it->second;
        const auto &e = sd.entries[N];
        const std::string dsec =
            e.meta.section_name.empty() ? ".rodata" : e.meta.section_name;
        const int si = get_sec(dsec, /*is_code=*/false, e.meta.section_perms,
                               e.meta.section_at, e.meta.section_order);
        const uint64_t off = secs[si].bytes.size();
        const uint8_t *p = sd.bytes.data() + e.byte_offset;
        secs[si].bytes.insert(secs[si].bytes.end(), p, p + e.byte_len);
        std::pair<int, uint64_t> loc{si, off};
        data_loc[N] = loc;
        return loc;
    };
    for (const AotFn &af : compiled) {
        for (const jit::NativeReloc &r : af.relocs) {
            if (r.kind == jit::NativeReloc::Kind::CALL_REL32 ||
                r.kind == jit::NativeReloc::Kind::ARM64_CALL26)
                continue; // llamada a funcion (pass 2), no un dato
            if (r.symbol.rfind("secsym:", 0) == 0)
                continue; // simbolo de seccion (pass 2)
            if (r.symbol.rfind("fnsym:", 0) == 0)
                continue; // direccion de funcion (pass 2, sin dato)
            if (r.symbol.rfind("tdata.", 0) == 0) {
                // thread_local (TLS): colocar la plantilla en su seccion
                // (.tdata, via section_name).  El reloc se emite en
                // pass 2 como TPOFF32 (ELF) o SECREL32 (PE).
                place_data(static_cast<uint32_t>(
                    std::strtoul(r.symbol.c_str() + 6, nullptr, 10)));
                continue;
            }
            if (r.symbol == "__vx_tls_index")
                continue; // TLS PE: simbolo del emisor (pass 2, sin dato)
            if (r.symbol.rfind("rodata.", 0) != 0) {
                std::cerr << "[aot] reloc de dato con simbolo inesperado: '"
                          << r.symbol << "'.\n";
                return EXIT_FAILURE;
            }
            const uint32_t N = static_cast<uint32_t>(
                std::strtoul(r.symbol.c_str() + 7, nullptr, 10));
            if (N >= sd.size()) {
                std::cerr << "[aot] reloc a static_data fuera de rango: N=" << N
                          << ".\n";
                return EXIT_FAILURE;
            }
            place_data(N);
        }
    }
    // FORCE_EMIT: bloques `bytes` y datos en @section que deben
    // emitirse aunque ningun reloc los referencie (firmas, tablas,
    // boot sectors).  Se colocan en orden de aparicion.
    for (uint32_t N = 0; N < sd.size(); ++N) {
        if (sd.entries[N].meta.flags & ir::IrModule::SD_FLAG_FORCE_EMIT)
            place_data(N);
    }

    //  NR / dev-OS: nombre de bloque (asm/bytes) -> su ubicacion.
    // Permite que OTROS bloques lo referencien por simbolo (un `jmp
    // other_block` o un `dd gdt` cross-block).  Los bloques con
    // symbol_name son FORCE_EMIT -> ya estan colocados (loop de
    // arriba); ademas place_data() es idempotente.
    std::unordered_map<std::string, std::pair<int, uint64_t>> data_sym_loc;
    for (uint32_t N = 0; N < sd.size(); ++N) {
        const std::string &snm = sd.entries[N].meta.symbol_name;
        if (snm.empty()) continue;
        data_sym_loc[snm] = place_data(N);
    }

    /* Info de depuracion del LENGUAJE: la seccion `.vxdbg` con la
     * correlacion codigo-nativo <-> fuente, EMBEBIDA en el ejecutable.
     *
     * Va dentro y no en un fichero aparte porque es lo que permite que
     * el binario se explique solo, sin depender de que alguien haya
     * conservado un fichero al lado -- que es justo lo que no pasa
     * cuando algo falla en produccion.  Es lo que hacen DWARF (dentro
     * del ELF) y Go (su tabla embebida); el fichero suelto es para el
     * flujo de distribuir el binario pelado, no la norma.
     *
     * Es una seccion de DATOS: no cambia ni una instruccion, asi que lo
     * que ve un depurador o un desensamblador del CODIGO sigue siendo
     * exactamente lo que se compilo.  Lo que no puede colarse es
     * CODIGO, y por eso el manejador tiene su propio nivel.
     *
     * Se crea al FINAL de la pasada 1, cuando el resto de secciones ya
     * existen: si se creara antes, se colaria delante de `.rodata` y
     * `.data` y les moveria la direccion -- con lo que cambiarian las
     * direcciones absolutas del CODIGO, que es justo lo que no puede
     * pasar.  Medido: creandola antes, `.text` sale distinto.
     *
     * Formato: ['VXDB'][version][n_fn] y por funcion
     * [off_en_texto][tam][n_puntos][largo_nombre] + el nombre (relleno
     * a multiplo de 4) + n_puntos x [off][linea][col][tramo].
     * Los desplazamientos son relativos a la seccion de codigo, que es
     * lo que el manejador puede calcular restando su propia direccion.
     */
    if (opt.lang_debug_level >= 1) {
        std::vector<uint8_t> db;
        auto db32 = [&db](uint32_t v) {
            for (int i = 0; i < 4; ++i)
                db.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
        };
        uint32_t n_fn = 0;
        for (const AotFn &af : compiled)
            if (!af.puntos.empty() && fn_loc.count(af.name)) ++n_fn;
        db32(0x42445856u); // 'VXDB'
        db32(5u);          // v5: + la instruccion del intermedio
        /* Los nombres de las funciones que el inlinado se comio van en
         * UNA tabla al final y los puntos la indexan: la misma funcion
         * aparece en muchos tramos y repetir la cadena engordaria la
         * seccion sin decir nada nuevo. */
        /* Como se lee: `Clase__metodo` es como se llama el simbolo,
         * pero quien lee un fallo espera `Clase.metodo`.  Se traduce
         * AQUI y no en el manejador: es trabajo que se puede hacer una
         * vez al compilar en vez de con el proceso ya roto.  Los
         * helpers internos empiezan por `_` y se dejan tal cual. */
        auto legible = [](const std::string &n) -> std::string {
            if (n.empty() || n[0] == '_') return n;
            const size_t p2 = n.find("__");
            if (p2 == std::string::npos) return n;
            return n.substr(0, p2) + "." + n.substr(p2 + 2);
        };
        std::vector<std::string> tabla;
        auto idx_de = [&tabla](const std::string &n) -> uint32_t {
            if (n.empty()) return 0xFFFFFFFFu;
            for (size_t i = 0; i < tabla.size(); ++i)
                if (tabla[i] == n) return static_cast<uint32_t>(i);
            tabla.push_back(n);
            return static_cast<uint32_t>(tabla.size() - 1);
        };
        db32(n_fn);
        db32(0u); // hueco: desplazamiento de la tabla de nombres
        /* La ruta del fuente.  Sin ella el informe dice "linea 27" sin
         * decir de que fichero, que en un programa de varios modulos no
         * sirve de nada. */
        db32(static_cast<uint32_t>(opt.source_path.size()));
        for (char c : opt.source_path)
            db.push_back(static_cast<uint8_t>(c));
        while ((db.size() % 4u) != 0u)
            db.push_back(0);
        for (const AotFn &af : compiled) {
            if (af.puntos.empty()) continue;
            auto it = fn_loc.find(af.name);
            if (it == fn_loc.end()) continue;
            db32(static_cast<uint32_t>(it->second.off));
            db32(static_cast<uint32_t>(af.bytes.size()));
            db32(static_cast<uint32_t>(af.puntos.size()));
            /* El nombre, para poder decir EN QUE funcion y no solo en
             * que linea.  Se rellena hasta multiplo de 4 para que lo
             * que viene detras siga alineado: x86 lo toleraria, pero
             * otras arquitecturas no. */
            const std::string nm_leg = legible(af.name);
            db32(static_cast<uint32_t>(nm_leg.size()));
            for (char c : nm_leg)
                db.push_back(static_cast<uint8_t>(c));
            while ((db.size() % 4u) != 0u)
                db.push_back(0);
            for (const auto &q : af.puntos) {
                db32(q.off);
                db32(q.line);
                db32(q.col);
                db32(q.len);
                db32(idx_de(legible(q.venia_de)));
                db32(idx_de(q.ir_txt));
            }
        }
        /* La tabla de nombres, al final: los puntos la indexan.  Su
         * desplazamiento se apunta en la cabecera para que el lector no
         * tenga que recorrer todas las funciones para llegar. */
        const uint32_t off_tabla = static_cast<uint32_t>(db.size());
        db32(static_cast<uint32_t>(tabla.size()));
        for (const std::string &n : tabla) {
            db32(static_cast<uint32_t>(n.size()));
            for (char c : n)
                db.push_back(static_cast<uint8_t>(c));
            while ((db.size() % 4u) != 0u)
                db.push_back(0);
        }
        // El hueco reservado en la cabecera (offset 12).
        for (int i = 0; i < 4; ++i)
            db[12 + i] = static_cast<uint8_t>((off_tabla >> (i * 8)) & 0xFF);

        const int dbg_si = get_sec(".vxdbg", /*is_code=*/false, "r");
        secs[dbg_si].bytes = std::move(db);
    }

    // Crear el writer + TODAS las secciones (writer idx == secs idx,
    // mismo orden; `secs` ya esta completa tras la pasada 1).
    aot::ObjectWriter w(fmt);
    w.set_mode32(aot_mode32); // x86-32 EXEC -> contenedor ELF32
    // Arquitectura del contenedor: arm64 -> e_machine EM_AARCH64 (183)
    // en el MISMO emisor (LibPEparse), sin writer hand-rolled aparte.
    // Base de carga en la RAM de la machine `virt` de QEMU (0x40000000+;
    // el _start bare fija sp en 0x40300000); el x86 usa su default.
    if (arch == aot::AotArch::ARM64) {
        w.set_machine(183 /*EM_AARCH64*/);
        w.set_image_base(0x40200000ull);
    }
    // TLS PE: si el modulo tiene __vx_tls_init (callback de plantilla),
    // pasar su ubicacion al emisor para registrarlo en el TLS directory.
    {
        auto tcb = fn_loc.find("__vx_tls_init");
        if (tcb != fn_loc.end())
            w.set_tls_callback(tcb->second.sec,
                               static_cast<uint32_t>(tcb->second.off));
    }
    for (const SecAccum &s : secs) {
        // Permisos: explicitos (@section(".x","rwx")), o por convencion
        // del nombre (.text*->rx, .rodata*->r, .data*/.bss*->rw).
        std::string p = s.perms;
        // .tdata/.tbss: plantilla thread_local (TLS).  rw + SHF_TLS.
        const bool is_tls_sec =
            (s.name.rfind(".tdata", 0) == 0 || s.name.rfind(".tbss", 0) == 0);
        if (p.empty()) {
            if (s.name.rfind(".text", 0) == 0)
                p = "rx";
            else if (is_tls_sec)
                p = "rw";
            else if (s.name.rfind(".rodata", 0) == 0)
                p = "r";
            else if (s.name.rfind(".data", 0) == 0)
                p = "rw";
            else if (s.name.rfind(".bss", 0) == 0)
                p = "rw";
            else
                p = s.is_code ? "rx" : "r";
        }
        uint32_t flags = 0;
        if (p.find('r') != std::string::npos) flags |= aot::SecFlag::READ;
        if (p.find('w') != std::string::npos) flags |= aot::SecFlag::WRITE;
        const bool exec = (p.find('x') != std::string::npos);
        if (exec)
            flags |= aot::SecFlag::EXEC | aot::SecFlag::CODE;
        else
            flags |= aot::SecFlag::DATA;
        if (is_tls_sec) flags |= aot::SecFlag::TLS;
        aot::WriterSection ws;
        ws.name = s.name;
        ws.flags = flags;
        ws.data = s.bytes;
        ws.at = s.at;
        ws.order = s.order; // ubicacion/orden (.bin)
        w.add_section(std::move(ws));
    }
    // gc<T> (Inc 4b): relocs ABS64 de los func_addr de .vxgc_smap a la
    // VA real de cada funcion (resuelta tras el layout).
    if (smap_si >= 0) {
        for (const auto &fr : smap_func_relocs) {
            auto it = fn_loc.find(fr.second);
            if (it != fn_loc.end())
                w.add_reloc(
                    smap_si, fr.first,
                    aot::RelocTarget::addr(it->second.sec, it->second.off),
                    aot::RelocKind::ABS64);
        }
    }
    if (emit_shared) {
        // Libreria compartida: exporta TODAS las funciones como
        // simbolos globales (dlsym).  Sin _start ni entry.
        w.set_output_kind(aot::OutputKind::SHARED);
        // --aot-debug: symtab COFF (.dll) / .symtab (.so via dynsym) con
        // los nombres de funcion.
        if (opt.debug_level >= 1) w.set_debug(true);
        for (const AotFn &af : compiled) {
            const FnLoc &fl = fn_loc[af.name];
            w.add_symbol(af.name, fl.sec, fl.off, /*is_func=*/true);
        }
    } else if (emit_obj) {
        // Objeto relocatable: main es un simbolo GLOBAL (lo invoca el
        // crt del linker externo); sin _start ni entry.
        w.set_output_kind(aot::OutputKind::OBJECT);
        // Exporta como GLOBAL todas las funciones de USUARIO (no
        // empiezan por "__").  Los helpers internos (__vx_*/__new_*/
        // __module_init/...) quedan LOCALES -> no colisionan al enlazar
        // varios .o Vesta (cada .o lleva su propia copia, referenciada via
        // relocs de seccion).  Asi una libreria .o (sin main) expone sus
        // funciones y otro .o las resuelve cross-file con el linker.
        for (const AotFn &af : compiled) {
            // Los inits de programa del CPU-dispatch (cpu/memcpy/strdisp)
            // se EXPORTAN como globales aunque empiecen por "__": el
            // linker los recolecta de CADA .o y los ejecuta antes de main
            // (cada .o tiene sus propios slots fp; basta correr su init).
            const bool is_init =
                (af.name == "__vx_cpu_init" || af.name == "__vx_memcpy_init" ||
                 af.name == "__vx_strdisp_init");
            // En un EJECUTABLE (hay main) los helpers __-prefijados
            // quedan LOCALES (program-internos; evita colisiones al
            // enlazar varios .o).  En una LIBRERIA (sin main) son la
            // API publica -> se exportan globales (p.ej. el runtime
            // __vx_setjmp/__vx_throw/... que otro .o resuelve).
            if (main_fn && af.name.rfind("__", 0) == 0 && !is_init)
                continue; // helper interno del ejecutable -> local
            const FnLoc &fl2 = fn_loc[af.name];
            w.add_symbol(af.name, fl2.sec, fl2.off, /*is_func=*/true);
        }
    } else if (emit_bin) {
        // Binario plano: sin cabecera ni _start; entry = offset 0 (la
        // primera seccion .text, donde va main si existe).  Las refs
        // absolutas se resuelven contra --bin-base.
        w.set_output_kind(aot::OutputKind::FLAT_BIN);
        w.set_flat_base(bin_base);
    } else {
        w.set_entry(text_sec, 0); // _start en .text offset 0
        // stub->main: reloc a la VA real de main (resuelta por el
        // writer).  x86 usa REL32; arm64 usa el imm26 del BL (CALL26).
        const FnLoc &ml = fn_loc["main"];
        w.add_reloc(text_sec, stub.main_call_off,
                    aot::RelocTarget::addr(ml.sec, ml.off),
                    (arch == aot::AotArch::ARM64) ? aot::RelocKind::ARM64_CALL26
                                                  : aot::RelocKind::REL32);
    }

    // --aot-debug=1: en un EJECUTABLE, registra TODAS las funciones como
    // simbolos (nombre -> VA) para que gdb/WinDbg/lldb muestren nombres
    // en los backtraces.  OBJECT/SHARED ya llevan symtab por diseno; el
    // EXEC solo lo anyade con este flag (cero coste sin el).
    if (opt.debug_level >= 1 && !emit_shared && !emit_obj && !emit_bin) {
        w.set_debug(true);
        for (const AotFn &af : compiled) {
            const FnLoc &fl = fn_loc[af.name];
            w.add_symbol(af.name, fl.sec, fl.off, /*is_func=*/true);
        }
    }

    // PASADA 2: declarar las relocs de cada funcion (llamadas + datos +
    // simbolos de seccion).  El writer las resuelve (EXEC) o las emite
    // como registros (OBJECT) tras el layout.
    for (const AotFn &af : compiled) {
        const FnLoc &fl = fn_loc[af.name];
        for (const jit::NativeReloc &r : af.relocs) {
            const uint64_t site = static_cast<uint64_t>(fl.off) + r.offset;
            if (r.kind == jit::NativeReloc::Kind::CALL_REL32 ||
                r.kind == jit::NativeReloc::Kind::ARM64_CALL26) {
                // x86 usa REL32; AArch64 el imm26 del BL (CALL26).
                const aot::RelocKind callk =
                    (r.kind == jit::NativeReloc::Kind::ARM64_CALL26)
                        ? aot::RelocKind::ARM64_CALL26
                        : aot::RelocKind::REL32;
                auto it = fn_loc.find(r.symbol);
                if (it == fn_loc.end()) {
                    // Simbolo EXTERNO (libc/runtime:
                    // malloc/free/abort...). Solo en OBJECT (.o/.obj):
                    // el linker del sistema lo resuelve.
                    // EXEC/SHARED/BIN necesitarian IAT/PLT-GOT
                    // (AOT.2.exec, futuro).
                    if (!emit_obj) {
                        // PE EXEC ya resolvio sus externos via thunks
                        // de IAT (el simbolo ESTA en fn_loc -> no llega
                        // aqui). Quedan: ELF EXEC/SHARED (PLT-GOT,
                        // slice 2), PE SHARED (.dll, follow-up) y .bin.
                        std::cerr
                            << "[aot] llamada a simbolo externo '" << r.symbol
                            << "' aun no soportada para este target ("
                            << (fmt == aot::ObjFormat::ELF ? "ELF EXEC/shared: "
                                                             "PLT-GOT pendiente"
                                                           : "PE shared/.bin")
                            << "); usa --emit obj (enlazar con gcc/ld) "
                               "o, en "
                               "Windows, --emit exe (PE-IAT).\n";
                        return EXIT_FAILURE;
                    }
                    w.add_reloc(fl.sec, site,
                                aot::RelocTarget::extern_sym(r.symbol), callk);
                } else {
                    w.add_reloc(
                        fl.sec, site,
                        aot::RelocTarget::addr(it->second.sec, it->second.off),
                        callk);
                }
            } else if (r.symbol.rfind("secsym:", 0) == 0) {
                // Simbolo de seccion "secsym:<k>:<name>" (dev OS):
                // s=start (base), e=end (base+size), z=size (tamano).
                const char kc = r.symbol.size() > 7 ? r.symbol[7] : 's';
                const std::string sname = r.symbol.substr(9);
                auto si = sec_index.find(sname);
                if (si == sec_index.end()) {
                    std::cerr << "[aot] section_"
                              << (kc == 'z'   ? "size"
                                  : kc == 'e' ? "end"
                                              : "start")
                              << "(\"" << sname
                              << "\"): la seccion no existe "
                                 "(ningun codigo/dato la usa).\n";
                    return EXIT_FAILURE;
                }
                const int tsi = si->second;
                // REL32 si la ref fue RIP-relativa (DATA_REL32), ABS64
                // si absoluta (--no-pie).  SIZE es siempre un inmediato
                // (IMM64).
                const bool rel = (r.kind == jit::NativeReloc::Kind::DATA_REL32);
                if (kc == 'z') {
                    w.add_reloc(fl.sec, site, aot::RelocTarget::size(tsi),
                                aot::RelocKind::IMM64);
                } else if (kc == 'e') {
                    w.add_reloc(fl.sec, site, aot::RelocTarget::end(tsi),
                                rel ? aot::RelocKind::REL32
                                    : aot::RelocKind::ABS64,
                                r.addend);
                } else {
                    w.add_reloc(fl.sec, site, aot::RelocTarget::addr(tsi, 0),
                                rel ? aot::RelocKind::REL32
                                    : aot::RelocKind::ABS64,
                                r.addend);
                }
            } else if (r.symbol.rfind("fnsym:", 0) == 0) {
                // Direccion de una FUNCION del modulo ("fnsym:<name>",
                // de LABEL_ADDR): puntero de funcion para CALLIND.  Se
                // resuelve contra el offset de la funcion en su seccion
                // (REL32 si RIP-rel, ABS64 si --no-pie).
                const std::string tgt = r.symbol.substr(6);
                auto fit = fn_loc.find(tgt);
                if (fit == fn_loc.end()) {
                    std::cerr << "[aot] direccion de funcion no resuelta: '"
                              << tgt << "' (referenciada como puntero).\n";
                    return EXIT_FAILURE;
                }
                const aot::RelocKind k =
                    (r.kind == jit::NativeReloc::Kind::DATA_REL32)
                        ? aot::RelocKind::REL32
                    : (r.kind == jit::NativeReloc::Kind::ABS32)
                        ? aot::RelocKind::IMM32
                        : aot::RelocKind::ABS64;
                w.add_reloc(
                    fl.sec, site,
                    aot::RelocTarget::addr(fit->second.sec, fit->second.off), k,
                    r.addend);
            } else if (r.kind == jit::NativeReloc::Kind::TPOFF32) {
                // thread_local (TLS local-exec): simbolo "tdata.<N>".
                // Colocar la plantilla en .tdata y emitir un reloc
                // TPOFF32 contra (sec=.tdata, off); el object_writer lo
                // materializa como R_X86_64_TPOFF32 + STT_TLS y el
                // --link calcula el offset TP-relativo.
                const uint32_t N = static_cast<uint32_t>(
                    std::strtoul(r.symbol.c_str() + 6, nullptr, 10));
                const std::pair<int, uint64_t> loc = place_data(N);
                w.add_reloc(fl.sec, site,
                            aot::RelocTarget::addr(loc.first, loc.second),
                            aot::RelocKind::TPOFF32);
            } else if (r.kind == jit::NativeReloc::Kind::SECREL32) {
                // thread_local (TLS PE): simbolo "tdata.<N>".  Colocar la
                // plantilla en .tdata (=.tls) y emitir SECREL32 contra
                // (sec, off); el emisor PE escribe el offset del var
                // dentro de la seccion (el acceso lo suma a la base del
                // bloque TLS cargada del TEB).
                const uint32_t N = static_cast<uint32_t>(
                    std::strtoul(r.symbol.c_str() + 6, nullptr, 10));
                const std::pair<int, uint64_t> loc = place_data(N);
                w.add_reloc(fl.sec, site,
                            aot::RelocTarget::addr(loc.first, loc.second),
                            aot::RelocKind::SECREL32);
            } else if (r.symbol == "__vx_tls_index") {
                // TLS PE: ref RIP-relativa al _tls_index sintetizado por
                // el emisor; se pasa como simbolo externo que el emisor
                // resuelve a la VA del slot.
                w.add_reloc(fl.sec, site,
                            aot::RelocTarget::extern_sym("__vx_tls_index"),
                            aot::RelocKind::REL32);
            } else {
                const uint32_t N = static_cast<uint32_t>(
                    std::strtoul(r.symbol.c_str() + 7, nullptr, 10));
                const std::pair<int, uint64_t> loc = place_data(N);
                /* ABS32 (x86-32): IMM32 -> el emisor ELF32 lo emite como
                 * R_386_32 (VA absoluta de 32 bits).  DATA_REL32 (x86-64
                 * PIC): REL32.  Resto (--no-pie x64): ABS64. */
                const aot::RelocKind k =
                    (r.kind == jit::NativeReloc::Kind::DATA_REL32)
                        ? aot::RelocKind::REL32
                    : (r.kind == jit::NativeReloc::Kind::ABS32)
                        ? aot::RelocKind::IMM32
                        : aot::RelocKind::ABS64;
                w.add_reloc(fl.sec, site,
                            aot::RelocTarget::addr(loc.first, loc.second), k,
                            r.addend);
            }
        }
    }

    // Relocs de los bloques `bytes` con referencias a simbolos
    // (`dq main`): el campo (placeholder 0) se parchea con la direccion
    // del simbolo.  Solo se resuelven contra FUNCIONES (fn_loc); una
    // ref a otro dato/seccion es trabajo futuro.
    for (uint32_t N = 0; N < sd.size(); ++N) {
        const auto &meta = sd.entries[N].meta;
        if (meta.sym_refs.empty()) continue;
        auto dit = data_loc.find(N);
        if (dit == data_loc.end()) continue; // no colocada (no deberia)
        const int dsec = dit->second.first;
        const uint64_t doff = dit->second.second;
        for (const auto &sr : meta.sym_refs) {
            // Resolver contra una FUNCION (fn_loc) o, si no, contra
            // otro BLOQUE asm/bytes nombrado (data_sym_loc): un dev-OS
            // hace `jmp pm32` / `dd gdt` cross-block.
            int tsec;
            uint64_t toff;
            auto fit = fn_loc.find(sr.sym);
            if (fit != fn_loc.end()) {
                tsec = fit->second.sec;
                toff = fit->second.off;
            } else {
                auto dsit = data_sym_loc.find(sr.sym);
                if (dsit == data_sym_loc.end()) {
                    std::cerr << "[aot] referencia a simbolo no "
                                 "resuelto '"
                              << sr.sym
                              << "' (ni funcion ni bloque asm/bytes).\n";
                    return EXIT_FAILURE;
                }
                tsec = dsit->second.first;
                toff = dsit->second.second;
            }
            // Kind segun is_rel + ancho: REL32 (jmp/call near), IMM32
            // (dd -> VA absoluta de 32 bits) o ABS64 (dq -> 64 bits).
            const aot::RelocKind k =
                sr.is_rel ? aot::RelocKind::REL32
                          : (sr.width == 4 ? aot::RelocKind::IMM32
                                           : aot::RelocKind::ABS64);
            w.add_reloc(dsec, doff + sr.offset,
                        aot::RelocTarget::addr(tsec, toff), k);
        }
    }

    if (!no_stub && stub.has_import_call) {
        w.add_import_call(aot::ImportCall{stub.import_dll, stub.import_func,
                                          text_sec, stub.import_call_off});
    }
    // AOT.2.exec: registrar el import de cada thunk (FF 25 -> IAT).  Se
    // agrupan por DLL junto al ExitProcess (kernel32) en el emisor PE.
    for (const PeThunkImport &ti : pe_thunk_imports) {
        w.add_import_call(aot::ImportCall{ti.dll, ti.func, text_sec, ti.off});
    }

    /* El acompanante de depuracion del LENGUAJE.  Se escribe con el
     * binario ya emitido y NO lo modifica: ni una seccion, ni un byte.
     * El programa es exactamente el mismo con esta informacion y sin
     * ella, que es la razon de que vaya aparte -- meterle un manejador
     * para que se explique solo cambiaria el programa que despues se
     * depura, y lo que veria un depurador externo o un desensamblador
     * ya no seria lo que se compilo. */
    auto soltar_acompanante = [&](const std::string &destino) {
        if (opt.lang_debug_level < 1) return;
        std::vector<std::string> nombres;
        std::vector<std::vector<PuntoAcompanante>> puntos;
        nombres.reserve(compiled.size());
        puntos.reserve(compiled.size());
        for (const AotFn &af : compiled) {
            nombres.push_back(af.name);
            std::vector<PuntoAcompanante> ps;
            ps.reserve(af.puntos.size());
            for (const auto &q : af.puntos)
                ps.push_back({q.off, q.line, q.col, q.len});
            puntos.push_back(std::move(ps));
        }
        /* Y el grafo semantico queda pedible A PARTIR DEL BINARIO.
         * Se publica bajo la huella del fichero, igual que ya se hace
         * con el `.velb`: quien lo tenga delante la calcula sobre los
         * mismos bytes y llega a las entidades -- de que tipo es cada
         * funcion, con que firma --, que es lo que convierte un nombre
         * suelto en algo que se entiende sin ir al fuente.
         *
         * Se hace aqui y no al compilar porque la huella no existe
         * hasta que existe el fichero. */
        if (!cr.vxdbg_artifact_map.empty()) {
            vx::publish_vxdbg_artifact(destino, cr.vxdbg_artifact_map,
                                       cr.vxdbg_span_map, copts.vxdbg_dir);
        }

        const std::string ruta = destino + ".vxdbg";
        if (escribir_acompanante(ruta, opt.source_path, nombres, puntos))
            std::cout << "[aot] info de depuracion del lenguaje en '" << ruta
                      << "' (fichero aparte; el codigo emitido es el "
                         "mismo byte a byte).\n";
    };

    std::string werr;
    if (!w.write(out_prefix, werr)) {
        std::cerr << "[aot] error al escribir '" << out_prefix << "': " << werr
                  << "\n";
        return EXIT_FAILURE;
    }

    tel.cerrar(tel.objeto_us);

    // Auto-link: enlazar el .obj temporal con las .a estaticas de la
    // stdlib que el programa usa (gc / colecciones / math) -> .exe
    // STANDALONE (vm --link interno, sin g++ ni DLLs).
    if (need_temp_link) {
        namespace fs = std::filesystem;
        aot::LinkOptions lopts;
        lopts.fmt = fmt; // PE o ELF, segun el destino
        lopts.sysroot = opt.sysroot;
        std::vector<std::string> inputs;
        inputs.push_back(link_tmp_obj);
        for (const auto &l : autolink_libs)
            inputs.push_back(l);
        std::string lerr;
        const bool ok = aot::aot_link(inputs, link_real_out, lopts, lerr);
        std::error_code ec;
        fs::remove(link_tmp_obj, ec); // limpiar el .obj temporal
        tel.cerrar(tel.enlazar_us);
        if (!ok) {
            std::cerr << "[aot] auto-link error: " << lerr << "\n";
            return EXIT_FAILURE;
        }
        marcar_ejecutable_(link_real_out);
        std::cout << "[aot] ejecutable nativo "
                  << (fmt == aot::ObjFormat::PE ? "PE" : "ELF")
                  << " STANDALONE escrito en '" << link_real_out << "' ("
                  << autolink_libs.size()
                  << " lib(s) estatica(s) de la stdlib auto-enlazada(s), "
                     "sin DLLs ni g++).\n";
        soltar_acompanante(link_real_out);
        return EXIT_SUCCESS;
    }

    const char *fmt_name = (fmt == aot::ObjFormat::PE) ? "PE" : "ELF";
    // Ejecutable y libreria compartida SI llevan el bit; el `.o` y el binario
    // plano NO: el primero es una entrada para el enlazador y el segundo es
    // una imagen para una ROM o un bootloader, y marcarlos como ejecutables
    // seria mentir sobre lo que son.
    if (emit_shared || !(emit_obj || emit_bin)) marcar_ejecutable_(out_prefix);
    if (emit_shared)
        std::cout << "[aot] libreria compartida " << fmt_name
                  << (fmt == aot::ObjFormat::PE ? " (.dll)" : " (.so)")
                  << " escrita en '" << out_prefix << "' (" << compiled.size()
                  << " simbolo(s) exportado(s); "
                  << (fmt == aot::ObjFormat::PE ? "LoadLibrary/GetProcAddress"
                                                : "dlopen/dlsym")
                  << ").\n";
    else if (emit_obj)
        std::cout << "[aot] objeto relocatable " << fmt_name
                  << (fmt == aot::ObjFormat::PE ? " (.obj)" : " (.o)")
                  << " escrito en '" << out_prefix
                  << "' (main GLOBAL; linkable con "
                  << (fmt == aot::ObjFormat::PE ? "link.exe/gcc-mingw"
                                                : "ld/gcc")
                  << ").\n";
    else if (emit_bin)
        std::cout << "[aot] binario plano (.bin) escrito en '" << out_prefix
                  << "' (sin cabecera; entry en offset 0; base de carga 0x"
                  << std::hex << bin_base << std::dec << ").\n";
    else
        std::cout << "[aot] ejecutable nativo " << fmt_name << " escrito en '"
                  << out_prefix
                  << "' (entry _start -> main -> exit, return "
                     "de main como exit-code).\n";
    soltar_acompanante(out_prefix);
    return EXIT_SUCCESS;
}

} // namespace tc
} // namespace vesta
