/**
 * @file compiler_project.cpp
 * @brief Compilador multi-modulo ( M.2.e).
 *
 * Detecta @c import declaraciones en el fichero raiz, construye el dep
 * graph via @c ModuleGraph, ordena topologicamente, compila cada modulo
 * en orden (con .vxi compartido cross-modulo) y mergea las IrFunctions
 * en un solo @c IrModule final que el emitter produce como un unico
 * @c .vel.  El linker se encarga (M5 futuro) de empaquetar al .velb.
 *
 * Diseno:
 *   - Reusa @c ModuleGraph (M1) para paths + topo + ciclos.
 *   - Reusa @c export_typechecker_to_vxi (M2.d) + @c vxi_emit (M2.c)
 *     para producir las interfaces.
 *   - Reusa @c import_vxi_into_typechecker (M2.d) para inyectar en
 *     consumidores.
 *   - Cada modulo del path se compila con su propio @c TypeChecker y
 *     @c Lowering, produciendo un @c IrModule local.  Al final, todos
 *     los modulos se mergean en uno solo.
 *
 * MVP (M2.e):
 *   - Solo @c "only" imports inyectan simbolos (alias/namespace son M2.x).
 *   - Las @c IrFunctions de cada dep se appendea al IrModule final.
 *   - El @c static_data y los @c globals tambien se merge.
 *   - Sin checks de colision de nombres cross-module todavia (M5).
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "util/file_read.h"

/* El ensamblador, DECLARADO y no incluido.  Su cabecera arrastra `windows.h`,
 * que define `VOID` como macro y hace que el `void` del enum de tipos de Vesta
 * deje de compilar.  Se declara lo que se usa y punto. */
namespace asm_multi_process {
int run_worker_from_source(std::string code, const std::string &file_name,
                           const std::string &output_prefix,
                           bool skip_preprocessor, bool keep_labels,
                           const std::vector<uint8_t> *ir_section_bytes,
                           bool emit_map);
} // namespace asm_multi_process
#include "vx/comptime/comptime_collect.h"
#include "vx/compiler.h"
#include "vx/source_text.h" // un solo fin de linea para todo el pipeline
#include "vx/vxdbg_emit.h"  // grafo de conocimiento del programa
#include "vxdbg/codec.h"
#include "vxdbg/roots.h"
#include "analysis/facts/alignment.h"    // de cuanto es multiplo un valor
#include "analysis/facts/asm_bindings.h" // de que valor habla un operando de asm
#include "analyze/fingerprint.h"         // verificacion de contratos
#include "vx/asm/asm_effects.h"          // que exige cada instruccion
#include "vx/asm/asm_phys_reg.h" // clases de registro (ancho de cada operando)
#include "vx/incremental.h" // CAS global direccionado por contenido (cross-proyecto)
#include <algorithm>        // UCRT64: no transitivo
#include <chrono>           // reparto del coste por fase
#include <unordered_set>

#include "ir/ir_emitter.h"
#include "ir/ir_optimizer.h"
#include "util/env_flags.h"
#include <climits>
#include "util/crono_tramo.h"
#include "analysis/asa/aggregate_facts.h"
#include "analysis/effects/bounds.h" // accesos fuera de region -> diagnostico
#include "vx/diag/diag_format.h"
#include "ir/passes/select_policy.h"
#include "ir/ssa_ir.h"
#include "ir/ssa_ir_serialize.h"
#include "vx/lexer.h"
#include "vx/lowering.h"
#include "vx/module/module_interop.h"
#include "vx/module/module_resolver.h"
#include "vx/module/namespace_flatten.h" // NS.2: flatten inline namespaces por modulo
#include "vx/parser.h"
// IMPORTANTE: incluir los headers de diagramas DESPUES de parser.h / lowering.h
// para que la fwd decl @c namespace ast { struct ModuleNode; } del header
// resuelva correctamente al tipo @c vx::ast::ModuleNode ya conocido en
// este punto.  De otra forma el compilador interpreta @c ast::ModuleNode
// como @c ::ast::ModuleNode (global), causando mismatch de tipos.
#include "vx/diagram/graphviz_diagrams.h"
#include "vx/diagram/html_diagrams.h"
#include "vx/diagram/mermaid_diagrams.h"
#include "vx/type_checker.h"
#include "pkg/manifest.h" // las dependencias DECLARADAS del proyecto
#include "vx/module/vxi_format.h"
#include "vx/source_hash.h" // la identidad de un fuente son sus tokens
#include "analysis/asa/fact_file.h"
#include "analysis/asa/producers.h" // produce() + FactStore::find
#include "util/fs_utils.h"          // fs::get_executable_path()

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>

//  M5.A: cabeceras para PID + atomic rename portable.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
// windows.h define VOID como macro -> colisiona con PrimitiveKind::VOID que
// usamos en la validacion de firma de @HelperOverride.  Lo deshacemos aqui
// (este TU no usa el macro VOID de WinAPI).
#ifdef VOID
#undef VOID
#endif
#else
#include <unistd.h>
#endif

namespace vx {

namespace {

/// Convierte enum int -> ir::OptLevel.  Duplicado de compiler.cpp para
/// no exponer la helper privada.
ir::OptLevel opt_level_from_int_(int n) noexcept {
    switch (n) {
    case 0: return ir::OptLevel::O0;
    case 1: return ir::OptLevel::O1;
    case 2: return ir::OptLevel::O2;
    case 3: return ir::OptLevel::O3;
    default: return ir::OptLevel::O1;
    }
}

/// Verifica si la cache esta deshabilitada via env var.  Por defecto
/// activa (escribe + lee de disco).  El usuario puede setear
/// `VX_NO_CACHE=1` para forzar rebuild completo (util en CI / debug).
bool vxi_cache_disabled_() noexcept {
    return util::flag_on(util::FlagId::NoCache);
}

/// Escribe @p bytes al fichero @p path (binary).  Devuelve true si OK.
/// Crea el directorio padre si no existe.
bool write_file_(const std::string &path, const std::vector<uint8_t> &bytes) {
    try {
        std::filesystem::create_directories(
            std::filesystem::path(path).parent_path());
    } catch (...) { /* ignorar; el ofstream tambien fallara */
    }
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    if (!bytes.empty()) {
        f.write(reinterpret_cast<const char *>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    }
    return f.good();
}

///  M5.A L.17: escritura atomica de fichero.  Escribe a un .tmp
/// unico (PID + tid + counter para evitar colisiones de procesos
/// concurrentes) y hace rename al destino.  En la mayoria de sistemas
/// (Windows NTFS, Linux ext4/btrfs, macOS APFS) el rename es atomic:
/// el destino o tiene el contenido viejo o el nuevo, nunca un parcial.
/// Esto cierra L.17: dos compilaciones simultaneas del mismo proyecto
/// no corrompen los archivos de cache compartidos (.vxi, .vxir, .velb).
bool write_file_atomic_(const std::string &path,
                        const std::vector<uint8_t> &bytes) {
    namespace fs = std::filesystem;
    static std::atomic<uint64_t> tmp_counter{0};
    try {
        fs::create_directories(fs::path(path).parent_path());
    } catch (...) { /* ignorar */
    }
    // Sufijo unico por proceso + thread + counter.  Asi multiples
    // compilaciones concurrentes nunca colisionan en el tmp.
    std::ostringstream suffix;
    suffix << ".tmp."
#ifdef _WIN32
           << static_cast<uint64_t>(GetCurrentProcessId())
#else
           << static_cast<uint64_t>(getpid())
#endif
           << "." << tmp_counter.fetch_add(1, std::memory_order_relaxed);
    const std::string tmp_path = path + suffix.str();
    {
        std::ofstream f(tmp_path, std::ios::binary);
        if (!f.is_open()) return false;
        if (!bytes.empty()) {
            f.write(reinterpret_cast<const char *>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
        }
        if (!f.good()) {
            f.close();
            std::error_code ec;
            fs::remove(tmp_path, ec);
            return false;
        }
        f.close();
    }
    // rename atomico (Windows: MoveFileExA con MOVEFILE_REPLACE_EXISTING;
    // POSIX: rename(2)).  std::filesystem::rename hace lo correcto en
    // ambos.  Si el destino existe, lo reemplaza atomicamente.
    std::error_code ec;
    fs::rename(tmp_path, path, ec);
    if (ec) {
        // Fallback: en Windows hay race rara donde MoveFileEx falla con
        // ERROR_ACCESS_DENIED si otro proceso tiene el destino abierto.
        // Intentar copy + delete como segundo recurso.
        fs::copy_file(tmp_path, path, fs::copy_options::overwrite_existing, ec);
        fs::remove(tmp_path, ec);
        return !ec;
    }
    return true;
}

/// Lee el fichero entero a bytes.  Devuelve true si OK.
bool read_file_bytes_(const std::string &path, std::vector<uint8_t> &out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    const std::streamsize sz = f.tellg();
    if (sz < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    if (sz > 0) f.read(reinterpret_cast<char *>(out.data()), sz);
    return f.good();
}

/// Clave de CONTENIDO de un modulo para el CAS global (cross-proyecto).
///
/// A diferencia del cache por-path (.vxi/.vxir junto al source), esta clave es
/// independiente de la RUTA: solo depende del contenido del modulo + los
/// abi_hashes (ya de por si content-based) de sus deps directos + la version
/// del compilador + el sufijo de target.  Asi dos proyectos con la MISMA
/// stdlib (aunque este en rutas distintas) obtienen la MISMA clave -> hit en el
/// store global -> se compila una sola vez para toda la maquina.  Es tambien la
/// base de la compilacion DISTRIBUIDA (misma clave -> mismo artefacto en
/// cualquier nodo).  @p dep_hashes debe venir ORDENADO por el caller.
uint64_t module_content_key_(uint64_t source_hash,
                             const std::vector<uint64_t> &dep_hashes,
                             const std::string &tgt_suffix,
                             uint64_t config_fp) {
    uint64_t h = util::kFnvOffset; // FNV-1a 64 offset basis.
    auto mix = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            h ^= (v >> (i * 8)) & 0xFF;
            h *= util::kFnvPrime;
        }
    };
    mix(0x5641434B4559ull);           // dominio "CAS module key".
    mix(vxi_compiler_version_hash()); // build del compilador -> no reusar
                                      // stale.
    mix(source_hash); // contenido (incl. instrument/native_poo).
    // Config que afecta al IR pre-optimize (BuildConfig::ir_fingerprint):
    // asm_target_bits, native_poo, exceptions, instrument.  Cierra el hueco de
    // cross-bits AOT (@Naked/asm{} baja distinto en 32/64) con CAS compartido.
    mix(config_fp);
    /* Si la maquina de compilacion estaba cargada o no.  Es un eje REAL del
     * resultado: sin ella, una funcion comptime no se puede ejecutar y su
     * valor sale vacio, asi que el modulo compilado en esa pasada es
     * PROVISIONAL.  Sin distinguirlo, la pasada buena reutilizaba el modulo
     * provisional de la anterior y el arreglo no llegaba nunca. */
    {
        mix(util::flag_text(util::FlagId::McPrebuilt).empty() ? 0ull : 1ull);
    }
    if (!tgt_suffix.empty())
        mix(vxi_fnv1a(tgt_suffix)); // @Target (PE/ELF/...).
    for (uint64_t d : dep_hashes)
        mix(d);
    return h;
}

/// Empaqueta el par (.vxi, .vxir) en un blob del CAS: `[u32 len][vxi][u32
/// len][vxir]` (little-endian).  Es el artefacto por-modulo (interfaz + IR
/// completo: functions + static_data + globals + native_imports).
std::vector<uint8_t> cas_pack_module_(const std::vector<uint8_t> &vxi,
                                      const std::vector<uint8_t> &vxir) {
    std::vector<uint8_t> out;
    out.reserve(8 + vxi.size() + vxir.size());
    auto put_u32 = [&](uint32_t v) {
        out.push_back(v & 0xFF);
        out.push_back((v >> 8) & 0xFF);
        out.push_back((v >> 16) & 0xFF);
        out.push_back((v >> 24) & 0xFF);
    };
    put_u32(static_cast<uint32_t>(vxi.size()));
    out.insert(out.end(), vxi.begin(), vxi.end());
    put_u32(static_cast<uint32_t>(vxir.size()));
    out.insert(out.end(), vxir.begin(), vxir.end());
    return out;
}

/// Divide un blob del CAS en sus partes (.vxi, .vxir).  @return false si el
/// blob esta truncado o mal formado.
bool cas_unpack_module_(const std::vector<uint8_t> &blob,
                        std::vector<uint8_t> &vxi, std::vector<uint8_t> &vxir) {
    size_t off = 0;
    auto get_u32 = [&](uint32_t &v) -> bool {
        if (off + 4 > blob.size()) return false;
        v = static_cast<uint32_t>(blob[off]) |
            (static_cast<uint32_t>(blob[off + 1]) << 8) |
            (static_cast<uint32_t>(blob[off + 2]) << 16) |
            (static_cast<uint32_t>(blob[off + 3]) << 24);
        off += 4;
        return true;
    };
    uint32_t vl = 0, il = 0;
    if (!get_u32(vl) || off + vl > blob.size()) return false;
    vxi.assign(blob.begin() + off, blob.begin() + off + vl);
    off += vl;
    if (!get_u32(il) || off + il > blob.size()) return false;
    vxir.assign(blob.begin() + off, blob.begin() + off + il);
    return true;
}

/// Calcula el path del .vxi cacheado para un .vx.  Convencion:
/// `path/to/lib.vx` -> `path/to/lib.vxi`.  Mantener el cache junto al
/// source es la ruta mas predecible (vs un .cache/ global): facilita
/// distribucion (publicar la libreria = copiar .vx + .vxi + .ir
/// juntos) y limpieza (borrar la carpeta del modulo lo limpia todo).
///  M.L16: cache global opt-in via @c VX_CACHE_DIR .  Si la env
/// var esta definida, los caches (@c .vxi / @c .vxir / @c .vel ) se
/// redirigen a @c "$VX_CACHE_DIR/<hash_64>_<basename><ext>" donde
/// @c hash_64 es FNV-1a 64 del path canonico completo.  Esto permite
/// que multiples proyectos compartan el mismo cache de libs comunes
/// (e.g. stdlib en read-only).  Sin la env var, comportamiento default:
/// cache junto al source (estable + facilita distribucion bundle).
static const std::string &global_cache_dir_() {
    /* Una vez por proceso, y por referencia.  Antes se consultaba el entorno y
     * se construia una cadena en CADA llamada, y hay cuatro rutas por modulo
     * -- que ademas la pedian dos veces cada una --: en un proyecto grande eso
     * son miles de consultas al entorno para obtener siempre lo mismo.  El
     * entorno no cambia a mitad de una compilacion. */
    return util::flag_text(util::FlagId::CacheDir);
}

/**
 * @brief Huella del compilador que esta generando los artefactos.
 *
 * Se toma del propio ejecutable (tamano y fecha de modificacion): cambia en
 * cuanto se recompila el compilador, que es justo cuando los artefactos
 * cacheados dejan de ser validos.  Se calcula una sola vez.
 *
 * @return Valor que identifica esta version del compilador.
 */
static uint64_t compiler_fingerprint_() {
    static const uint64_t fp = []() -> uint64_t {
        // Valvula para depurar: al recompilar el compilador (p.ej. para
        // anadir una traza) la huella cambia, los artefactos se invalidan y
        // se regeneran limpios -- con lo que el escenario que se queria
        // observar desaparece justo al ir a mirarlo.  Con VX_CACHE_FINGERPRINT
        // la huella queda fija en el valor que se le pase, asi que se puede
        // instrumentar sin perder la cache que reproduce el fallo.
        {
            const std::string &fixed =
                util::flag_text(util::FlagId::CacheFingerprint);
            if (!fixed.empty()) return vxi_fnv1a(fixed);
        }
        std::error_code ec;
        const std::string self = ::fs::get_executable_path();
        uint64_t h = 0xcbf29ce484222325ULL;
        auto mix = [&h](uint64_t v) {
            h ^= v;
            h *= 0x100000001b3ULL;
        };
        if (!self.empty()) {
            const std::filesystem::path p(self);
            const auto sz = std::filesystem::file_size(p, ec);
            if (!ec) mix(static_cast<uint64_t>(sz));
            const auto tm = std::filesystem::last_write_time(p, ec);
            if (!ec) mix(static_cast<uint64_t>(tm.time_since_epoch().count()));
        }
        // Respaldo por si no se pudo mirar el ejecutable: al menos el formato
        // de interfaz, que ya cambia con las modificaciones de fondo.
        mix(VXI_FORMAT_VERSION);
        return h;
    }();
    return fp;
}

static std::string global_cache_path_(const std::string &source_path,
                                      const std::string &ext) {
    namespace fs = std::filesystem;
    const std::string dir = global_cache_dir_();
    if (dir.empty()) return std::string(); // no global cache
    // hash 64 del path canonico para que multiples sources con mismo
    // basename no colisionen.
    const uint64_t h = util::fnv_bytes(util::kFnvOffset, source_path.data(),
                                       source_path.size());
    std::string base = fs::path(source_path).stem().string();
    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llx",
                  static_cast<unsigned long long>(h));
    return (fs::path(dir) / (std::string(hex) + "_" + base + ext)).string();
}

/**
 * @brief Las rutas de cache de un modulo, calculadas UNA vez.
 *
 * Todas comparten el mismo trabajo: mirar si hay cache global, hashear el path
 * canonico y componer un prefijo.  Pedirlas por separado repetia ese trabajo
 * cuatro veces por modulo, y cada compilacion vuelve a preguntar por las mismas
 * -- una al mirar si hay acierto de cache y otra al escribir --.  En un
 * proyecto pequeño da igual; en uno grande es donde se nota.
 */
struct RutasCache {
    std::string vxi;    ///< interfaz binaria del modulo.
    std::string vxir;   ///< su IR serializado.
    std::string vel;    ///< su .vel suelto, para distribuirlo aparte.
    std::string hechos; ///< lo que el ASA supo de el al bajarlo.
};

/// Prefijo comun de las rutas de @p source_path, sin extension.
static std::string prefijo_cache_(const std::string &source_path,
                                  const std::string &tgt_suffix) {
    if (!global_cache_dir_().empty())
        return global_cache_path_(source_path, tgt_suffix);
    const size_t dot = source_path.find_last_of('.');
    return (dot == std::string::npos ? source_path
                                     : source_path.substr(0, dot)) +
           tgt_suffix;
}

/**
 * @brief Las rutas de @p source_path, calculadas la primera vez y reusadas.
 *
 * @param source_path Path canonico del modulo.
 * @param tgt_suffix  Separa el cache por objetivo (ver @c vxir_path_for_).
 * @return Las cuatro rutas.  La referencia vive lo que el proceso.
 */
static const RutasCache &rutas_cache_(const std::string &source_path,
                                      const std::string &tgt_suffix) {
    /* Compartida entre los hilos que compilan modulos en paralelo, asi que va
     * con cerrojo.  Es un puñado de entradas y se tocan una vez por modulo:
     * el cerrojo cuesta muchisimo menos que rehacer las rutas. */
    static std::mutex mtx;
    static std::unordered_map<std::string, RutasCache> tabla;
    std::string clave = source_path;
    clave.push_back('\0');
    clave += tgt_suffix;
    std::lock_guard<std::mutex> lk(mtx);
    auto it = tabla.find(clave);
    if (it != tabla.end()) return it->second;
    const std::string base = prefijo_cache_(source_path, tgt_suffix);
    RutasCache r;
    r.vxi = base + ".vxi";
    r.vxir = base + ".vxir";
    r.hechos = base + ".vxfacts";
    /* El .vel no se separa por objetivo: es el mismo modulo suelto. */
    r.vel = prefijo_cache_(source_path, std::string()) + ".vel";
    return tabla.emplace(std::move(clave), std::move(r)).first->second;
}

std::string vxi_path_for_(const std::string &source_path,
                          const std::string &tgt_suffix = "") {
    return rutas_cache_(source_path, tgt_suffix).vxi;
}

/**
 * @brief Guarda junto al modulo lo que el ASA supo de el AL BAJARLO.
 *
 * Existe porque ese conocimiento no se puede recalcular mirando el modulo ya
 * compilado: nacio antes, mientras se bajaba el codigo.  Sin esto, la primera
 * compilacion avisa de algo y la segunda -- con la cache caliente -- se calla,
 * y el aviso acaba dependiendo de si alguien borro un directorio.
 *
 * Se escribe junto al @c .vxi y al @c .vxir, con la misma identidad que ellos:
 * la huella del modulo dice de que programa habla, y la del compilador que
 * analisis lo concluyo.
 *
 * @param ruta       Donde (de @c RutasCache::hechos, ya calculada).
 * @param almacen    Hechos a guardar.
 * @param huella     Identidad del modulo.
 * @param costes     Lo que cada dominio dice de si mismo (coste y de que
 *                   depende), con lo que se decide que merece guardarse.
 * @return @c true si quedo algo escrito.
 */
static bool
guardar_hechos_(const std::string &ruta,
                const analysis::asa::FactStore &almacen, uint64_t huella,
                const std::vector<analysis::asa::DomainCost> &costes) {
    const std::vector<uint8_t> bytes =
        analysis::asa::serialize(almacen, huella, analysis::asa::cache_level(),
                                 costes, compiler_fingerprint_());
    if (bytes.empty()) return false;
    return ::fs::write_file_atomic(ruta, bytes);
}

/**
 * @brief Recupera lo guardado por @ref guardar_hechos_.
 *
 * Que no haya nada NO es un error: es la primera compilacion, o alguien limpio
 * la cache, o el modulo cambio.  El motivo viaja dentro del resultado para que
 * quien quiera pueda contarlo -- callarse por que no se sabe algo es lo unico
 * que el ASA no puede hacer.
 *
 * @param ruta     De donde.
 * @param destino  Donde se depositan (se AÑADEN a lo que ya haya).
 * @param huella   La que debe llevar dentro.
 * @param vigentes De que depende hoy cada dominio, para anular solo lo suyo.
 * @return Que se leyo, o por que no.
 */
static analysis::asa::ReadResult
recuperar_hechos_(const std::string &ruta, analysis::asa::FactStore &destino,
                  uint64_t huella,
                  const std::vector<analysis::asa::DomainCost> &vigentes) {
    return analysis::asa::read_facts_file(ruta, huella, destino, vigentes,
                                          compiler_fingerprint_());
}

/**
 * @brief Deja en @p store los hechos de @p wanted, vengan de donde vengan.
 *
 * Es la puerta que usan los consumidores, y esconde a proposito de DoNDE sale
 * el conocimiento: de la cache de una compilacion anterior, o producido ahora.
 * Un consumidor que tuviera que saberlo acabaria decidiendo por su cuenta
 * cuando fiarse de la cache, y esa decision estaria escrita en tantos sitios
 * como consumidores haya.
 *
 * El orden es el que ahorra trabajo: primero se LEE lo guardado -- que marca
 * sus dominios en el almacen --, y solo despues se produce, que se salta lo que
 * ya esta.  Si no habia nada, se produce todo y se guarda para la proxima.
 *
 * Que no haya cache NO es un error: es la primera compilacion, o el modulo
 * cambio, o alguien la limpio.  El motivo viaja dentro del resultado.
 *
 * @param mod         Modulo del que se sabe.
 * @param store       Almacen de esta compilacion.
 * @param wanted      Dominios que alguien va a consultar.  Vacio = todos.
 * @param path        Fichero de hechos, o vacio para no tocar disco.
 * @param fingerprint Identidad del modulo: si no coincide, lo guardado no vale.
 */
void ensure_facts_impl_(const ir::IrModule &mod,
                        analysis::asa::FactStore &store,
                        const std::vector<const char *> &wanted,
                        const std::string &path, uint64_t fingerprint) {
    /* Sin ruta no hay cache entre compilaciones: se produce y ya.  Pasa en los
     * caminos que no tienen un fichero al que atribuir el modulo. */
    if (path.empty()) {
        analysis::asa::produce(mod, store, wanted);
        return;
    }

    /* Lo de antes, validado POR DOMINIO con lo que hoy depende cada uno.
     *
     * Antes esto iba vacio y la invalidacion era todo-o-nada: una sola huella,
     * la del modulo, decidia por todos, asi que tocar una linea de una funcion
     * tiraba tambien los hechos que no dependen del codigo.  El formato ya
     * contemplaba lo contrario -- guarda una huella por registro --; lo que
     * faltaba era quien la calculara.
     *
     * El dominio que no sepa decirlo no sale de `current_inputs`, y entonces lo
     * suyo se acepta sin comprobar, que es lo de siempre.  Asi la cache se
     * vuelve granular de uno en uno, segun cada dominio aprenda a responder. */
    recuperar_hechos_(path, store, fingerprint,
                      analysis::asa::current_inputs(mod));

    /* Y lo que falte.  `producir` se salta los dominios que la lectura ya
     * marco, asi que esto es exactamente el trabajo que la cache no cubrio. */
    const std::vector<analysis::asa::ProductionSummary> summaries =
        analysis::asa::produce(mod, store, wanted);
    if (summaries.empty()) return; // todo vino de la cache: nada que guardar

    /* Se guarda lo que costo, para que el nivel de cache decida que merece ir a
     * disco.  Un dominio que se produce en 3 us no compensa escribirlo. */
    std::vector<analysis::asa::DomainCost> costs;
    costs.reserve(summaries.size());
    for (const analysis::asa::ProductionSummary &r : summaries) {
        analysis::asa::DomainCost c;
        c.domain = r.domain;
        c.micros = r.micros;
        /* Y de que dependia al producirlo, que es lo que la proxima
         * compilacion comparara.  Sin esto se guardaba con huella cero -- "no
         * se puede comprobar" -- y el registro se aceptaba siempre, incluso
         * cuando sus entradas habian cambiado. */
        c.fingerprint = r.fingerprint;
        costs.push_back(c);
    }
    guardar_hechos_(path, store, fingerprint, costs);
}

/// Idem para el cache de IR del dep (.vxir).  @c tgt_suffix separa el cache por
/// target (p.ej. ".linux-x86_64") para modulos con @Target -> alternar de
/// target no recompila (HALLAZGO-2).  Vacio => fichero unico compartido.
std::string vxir_path_for_(const std::string &source_path,
                           const std::string &tgt_suffix = "") {
    return rutas_cache_(source_path, tgt_suffix).vxir;
}

/// Path del fichero de hechos del ASA: lo que se supo del modulo al bajarlo y
/// no se puede recalcular mirando el modulo ya compilado.
std::string vxfacts_path_for_(const std::string &source_path,
                              const std::string &tgt_suffix = "") {
    return rutas_cache_(source_path, tgt_suffix).hechos;
}

///  M5.C: path del @c .vel cacheado per-dep (output secundario
/// junto al @c .vxi para distribucion de libs precompiladas).
std::string dep_vel_path_for_(const std::string &source_path) {
    return rutas_cache_(source_path, std::string()).vel;
}

/// Lee el fichero a string.  Devuelve cadena vacia en error (el caller
/// detecta el error via @c diags).
///
/// Los fines de linea se normalizan aqui, en la PUERTA: de ahi en adelante todo
/// el pipeline ve `\n` y nadie mas tiene que acordarse (ver @ref
/// vx::leer_fuente).
std::string read_source_(const std::string &path) {
    std::string s;
    if (!vx::leer_fuente(path, s)) return {};
    return s;
}

/// Estructura de trabajo por modulo durante la compilacion del proyecto.
struct ProjectModuleWork {
    uint32_t module_id = 0;
    std::string canonical_path;
    std::string module_name;
    std::string source;
    /// v18: el conjunto comptime de este modulo, tal como se extrajo de su AST.
    /// Se recolecta al compilarlo y se guarda en su `.vxi`, porque la proxima
    /// compilacion puede servirlo del cache y entonces no habra AST.
    std::string comptime_unit_source;
    uint64_t comptime_unit_hash = 0;
    std::vector<std::string> comptime_unit_names;
    std::vector<std::string> comptime_unit_not_collected;
    std::unique_ptr<ast::ModuleNode> ast;
    std::unique_ptr<TypeChecker> tc;
    ir::IrModule ir;
    VxiModule vxi;
    bool ok = false;
    /// Los pares (simbolo, entidad) del grafo de depuracion de ESTE modulo.  Se
    /// juntan al final: el ejecutable contiene todos los modulos, asi que su
    /// mapa tiene que cubrirlos a todos.
    std::vector<std::pair<std::string, vxdbg::LanguageEntityId>> vxdbg_symbols;
    /// Y sus tramos de fuente, que se juntan igual.
    std::vector<vxdbg::SourceExtent> vxdbg_spans;
    ///  M.L20-full: Diagnostics local del modulo.  Cuando se
    /// paraleliza el compile (VX_PARALLEL_COMPILE=1), cada thread
    /// usa este diags propio en lugar del res.diagnostics compartido,
    /// evitando race conditions.  Post-join se mergean al global.
    Diagnostics diags;
};

/// Extrae los ImportDecl del AST en orden de declaracion.  Util para
/// procesar los `only` imports tras tener las VxiModule de los deps.
struct ImportRequest {
    std::string module_name;
    std::string local_name; // alias o module_name
    std::vector<TypeChecker::VxiOnlyEntry> only_symbols;
    bool is_plain = false;           // sin only -> registra namespace
    bool only_all = false;           // `only *` -> inyecta TODOS los publicos
    bool is_public_reexport = false; // L.23: public import
    bool by_namespace = false;       // NS.2-full: import a.b.c; (por-namespace)
    std::string ns_path;             // namespace original (por-namespace): para
                                     // registrar TODOS los ficheros de un
    // namespace PARCIAL (varios modulos = 1 ns)
    SourceLoc loc{}; // posicion del ImportDecl (M6.a.3 diags)
};

/**
 * @brief Huella de lo que un modulo VE de uno de sus deps.
 *
 * Es lo unico que le puede afectar de el, y por eso es lo que se guarda en su
 * tabla de dependencias y lo que se recomprueba al reusar lo compilado.  Antes
 * se guardaba el `abi_hash` ENTERO del dep: anadirle una funcion publica que
 * nadie usa invalidaba a todos sus consumidores.
 *
 * Un import con `only` acota exactamente lo que se puede usar -- para nombrar
 * un tipo hay que haberlo importado --, asi que ahi la huella es la de esos
 * simbolos.  Sin `only` (import llano, `only *`, o re-export) el modulo puede
 * usar cualquier cosa del dep, y entonces lo que le afecta es su interfaz
 * entera.
 *
 * @param dep_vxi Interfaz del dep, ya parseada.
 * @param req     Como se importo.
 * @return Huella de lo que este modulo ve de @p dep_vxi.
 */
static uint64_t huella_de_lo_usado(const VxiModule &dep_vxi,
                                   const ImportRequest &req) {
    if (req.is_plain || req.only_all || req.is_public_reexport ||
        req.only_symbols.empty()) {
        return dep_vxi.abi_hash;
    }
    std::vector<std::string> nombres;
    nombres.reserve(req.only_symbols.size());
    for (const auto &e : req.only_symbols)
        nombres.push_back(e.name);
    return vxi_hash_de_simbolos(dep_vxi, nombres);
}

///  NS.2-full: mapa namespace punteado -> module_name (filename) del
/// modulo que lo declara.  Se construye desde los AST de todos los modulos
/// del proyecto y traduce los imports por-namespace (`import a.b.c;`) al
/// module_name del dep resuelto, para reusar toda la maquinaria de imports
/// por-path (que ya soporta acceso cualificado multi-segmento via ns_path).
using NsToModname = std::unordered_map<std::string, std::string>;

/// `a.b.c` -> `a__b__c`: el mismo aplanado que usa el mangling de namespaces.
///
/// Sirve para CUALIFICAR los simbolos que entran por un import por-namespace.
/// Hacerlo con el nombre de FICHERO era el origen de que un mismo tipo tuviera
/// varias identidades: `std.types` lo declaran `types.vx`, `types/arm64.vx` y
/// `types/x86_64.vx`, y el resolver devuelve el PRIMERO que encuentra el
/// escaneo del disco.  Segun cual ganase, el mismo `uintptr` entraba como
/// `arm64__uintptr` o como `std__types__uintptr` y luego no unificaba consigo
/// mismo.  El namespace es el mismo para todos los ficheros que lo declaran,
/// asi que cualificar por el da UNA identidad estable.
inline std::string flatten_ns_(const std::string &dotted) {
    std::string out;
    out.reserve(dotted.size() + 8);
    for (const char c : dotted) {
        if (c == '.')
            out += "__";
        else
            out.push_back(c);
    }
    return out;
}

///  M.5: renombrar las top-level FunctionDecl y GlobalVarDecl del
/// modulo con un prefijo `<modname>__`.  Esto evita colisiones de
/// nombres cuando dos modulos definen una funcion con el mismo nombre
/// (e.g. ambos `lib_a` y `lib_b` declaran `i32 init();`).
///
/// IMPORTANTE: las llamadas DENTRO del modulo a esas mismas funciones
/// tambien necesitan referenciar el nombre mangled.  Como el lowering
/// resuelve el nombre via @c IdentExpr::name, una segunda pasada
/// recorre las CALL exprs y reescribe sus nombres si encajan con un
/// simbolo renombrado del propio modulo.
///
/// NO renombramos:
///   - Identifiers que comienzan con `__` (estan reservados, p. ej.
///     `__module_init`, `__new_<X>`, `__macro_<X>` que el lowering
///     genera automaticamente).
///   - `main` (entry point unico del programa: solo el root lo define
///     y se invoca via su nombre canonico).
void mangle_top_level_(ast::ModuleNode &mod, const std::string &module_name) {
    const std::string prefix = module_name + "__";

    // Recopilar los nombres a renombrar.
    std::unordered_map<std::string, std::string> rename_map;
    for (auto &decl : mod.decls) {
        if (!decl) continue;
        if (decl->kind == ast::NodeKind::FunctionDecl) {
            auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
            if (fd->name.empty()) continue;
            if (fd->name == "main") continue;
            if (fd->name.size() >= 2 && fd->name[0] == '_' &&
                fd->name[1] == '_')
                continue;
            // Mangle: lib::foo -> lib__foo.
            const std::string newn = prefix + fd->name;
            rename_map.emplace(fd->name, newn);
            fd->name = newn;
        } else if (decl->kind == ast::NodeKind::GlobalVarDecl) {
            auto *gd = static_cast<ast::GlobalVarDecl *>(decl.get());
            if (gd->name.empty()) continue;
            if (gd->name.size() >= 2 && gd->name[0] == '_' &&
                gd->name[1] == '_')
                continue;
            const std::string newn = prefix + gd->name;
            rename_map.emplace(gd->name, newn);
            gd->name = newn;
        }
    }
    if (rename_map.empty()) return;

    // Walker recursivo que reescribe identificadores en cada Expr.
    std::function<void(ast::Stmt *)> walk_stmt;
    std::function<void(ast::Expr *)> walk_expr;
    walk_expr = [&](ast::Expr *e) {
        if (!e) return;
        switch (e->kind) {
        case ast::NodeKind::IdentExpr: {
            auto *id = static_cast<ast::IdentExpr *>(e);
            auto it = rename_map.find(id->name);
            if (it != rename_map.end()) id->name = it->second;
            break;
        }
        case ast::NodeKind::CallExpr: {
            auto *c = static_cast<ast::CallExpr *>(e);
            walk_expr(c->callee.get());
            for (auto &a : c->args)
                walk_expr(a.get());
            break;
        }
        case ast::NodeKind::BinaryExpr: {
            auto *b = static_cast<ast::BinaryExpr *>(e);
            walk_expr(b->lhs.get());
            walk_expr(b->rhs.get());
            break;
        }
        case ast::NodeKind::UnaryExpr: {
            auto *u = static_cast<ast::UnaryExpr *>(e);
            walk_expr(u->operand.get());
            break;
        }
        case ast::NodeKind::AssignExpr: {
            auto *a = static_cast<ast::AssignExpr *>(e);
            walk_expr(a->target.get());
            walk_expr(a->value.get());
            break;
        }
        case ast::NodeKind::IndexExpr: {
            auto *ix = static_cast<ast::IndexExpr *>(e);
            walk_expr(ix->base.get());
            walk_expr(ix->index.get());
            break;
        }
        case ast::NodeKind::FieldAccessExpr: {
            auto *fa = static_cast<ast::FieldAccessExpr *>(e);
            walk_expr(fa->base.get());
            break;
        }
        case ast::NodeKind::CastExpr: {
            auto *ce = static_cast<ast::CastExpr *>(e);
            walk_expr(ce->operand.get());
            break;
        }
        case ast::NodeKind::TernaryExpr: {
            auto *tn = static_cast<ast::TernaryExpr *>(e);
            walk_expr(tn->cond.get());
            walk_expr(tn->then_expr.get());
            walk_expr(tn->else_expr.get());
            break;
        }
        case ast::NodeKind::NewExpr: {
            auto *ne = static_cast<ast::NewExpr *>(e);
            for (auto &a : ne->args)
                walk_expr(a.get());
            break;
        }
        case ast::NodeKind::StringLitExpr: {
            // Interpolaciones `"...${expr}..."`: recorrer cada expr
            // interna.  Sin esto, identificadores referenciados desde
            // dentro de un string interpolado no se manglan cuando el
            // modulo se compila como dep.
            auto *sl = static_cast<ast::StringLitExpr *>(e);
            for (auto &ie : sl->interp_exprs)
                walk_expr(ie.get());
            break;
        }
        case ast::NodeKind::LambdaExpr: {
            auto *la = static_cast<ast::LambdaExpr *>(e);
            if (la->body) walk_stmt(la->body.get());
            break;
        }
        case ast::NodeKind::MatchExpr: {
            auto *me = static_cast<ast::MatchExpr *>(e);
            walk_expr(me->scrutinee.get());
            for (auto &arm : me->arms) {
                if (arm.guard) walk_expr(arm.guard.get());
                if (arm.body) walk_stmt(arm.body.get());
            }
            break;
        }
        // Otros expr-kinds que pueden contener idents se cubren
        // conforme aparezcan en tests.
        default: break;
        }
    };
    walk_stmt = [&](ast::Stmt *s) {
        if (!s) return;
        switch (s->kind) {
        case ast::NodeKind::BlockStmt: {
            auto *b = static_cast<ast::BlockStmt *>(s);
            for (auto &c : b->body)
                walk_stmt(c.get());
            break;
        }
        case ast::NodeKind::ExprStmt: {
            auto *es = static_cast<ast::ExprStmt *>(s);
            walk_expr(es->expr.get());
            break;
        }
        case ast::NodeKind::VarDeclStmt: {
            auto *vd = static_cast<ast::VarDeclStmt *>(s);
            if (vd->init) walk_expr(vd->init.get());
            break;
        }
        case ast::NodeKind::IfStmt: {
            auto *ifs = static_cast<ast::IfStmt *>(s);
            walk_expr(ifs->cond.get());
            walk_stmt(ifs->then_branch.get());
            walk_stmt(ifs->else_branch.get());
            break;
        }
        case ast::NodeKind::WhileStmt: {
            auto *w = static_cast<ast::WhileStmt *>(s);
            walk_expr(w->cond.get());
            walk_stmt(w->body.get());
            break;
        }
        case ast::NodeKind::ForStmt: {
            auto *fr = static_cast<ast::ForStmt *>(s);
            walk_stmt(fr->init.get());
            walk_expr(fr->cond.get());
            walk_expr(fr->step.get());
            walk_stmt(fr->body.get());
            break;
        }
        case ast::NodeKind::ReturnStmt: {
            auto *r = static_cast<ast::ReturnStmt *>(s);
            walk_expr(r->value.get());
            break;
        }
        case ast::NodeKind::AsmStmt: {
            // Inline-asm @Naked: el cuerpo es texto NASM verbatim.  Un
            // `call helper2` / `jmp helper2` / `lea rax, [helper2]` que
            // referencie una fn/global top-level del PROPIO modulo debe ver
            // el nombre MANGLED (`mod__helper2`), igual que un IdentExpr.
            // Sin esto, al compilar el modulo como dep el simbolo del asm
            // queda con su nombre LOCAL y el resolver de @Naked cross-modulo
            // (jit/naked_native.cpp::resolve_naked_symbol) no lo encuentra
            // -> "simbolo externo no resuelto" -> la fn @Naked no compila.
            // (Las labels internas del bloque `.foo:` empiezan por `.` y las
            // fns reservadas por `__`; ninguna esta en rename_map, no se
            // tocan.)  Reescritura por TOKEN completo (frontera de
            // identificador) para no pisar substrings de otro simbolo.
            auto *as = static_cast<ast::AsmStmt *>(s);
            std::string &body = as->body;
            std::string out;
            out.reserve(body.size());
            const auto is_ident_ch = [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_';
            };
            size_t i = 0;
            while (i < body.size()) {
                char c = body[i];
                // Inicio de un identificador NASM (letra o `_`; el `.` de una
                // label local NO inicia identificador renombrable porque los
                // nombres de rename_map nunca empiezan por `.`).
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    c == '_') {
                    size_t j = i + 1;
                    while (j < body.size() && is_ident_ch(body[j]))
                        ++j;
                    std::string tok = body.substr(i, j - i);
                    auto it = rename_map.find(tok);
                    if (it != rename_map.end())
                        out += it->second;
                    else
                        out += tok;
                    i = j;
                } else {
                    out += c;
                    ++i;
                }
            }
            body.swap(out);
            break;
        }
        default: break;
        }
    };

    // Aplicar el walker a los bodies de cada FunctionDecl + GlobalVarDecl init,
    // mas los bodies de TODOS los metodos de cada ClassDecl (Bug Fix M.cm).
    // Sin esto, los metodos de clase no ven los simbolos mangled del
    // propio modulo cuando se compila como dep.
    for (auto &decl : mod.decls) {
        if (!decl) continue;
        if (decl->kind == ast::NodeKind::FunctionDecl) {
            auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
            walk_stmt(fd->body.get());
        } else if (decl->kind == ast::NodeKind::GlobalVarDecl) {
            auto *gd = static_cast<ast::GlobalVarDecl *>(decl.get());
            walk_expr(gd->init.get());
        } else if (decl->kind == ast::NodeKind::ClassDecl) {
            auto *cd = static_cast<ast::ClassDecl *>(decl.get());
            for (auto &m : cd->methods) {
                if (m && m->body) walk_stmt(m->body.get());
            }
        }
    }
}

std::vector<ImportRequest>
collect_imports_(const ast::ModuleNode &mod,
                 const NsToModname *ns_to_modname = nullptr) {
    std::vector<ImportRequest> out;
    // NS.1 fix: en la forma statement `namespace a.b.c;` los imports quedan
    // ANIDADOS dentro del NamespaceDecl -> recolectarlos recursivamente (si no,
    // no se procesan y el dep no se inyecta).
    std::vector<const ast::ImportDecl *> imports;
    std::function<void(const std::vector<std::unique_ptr<ast::Node>> &)>
        gather = [&](const std::vector<std::unique_ptr<ast::Node>> &decls) {
            for (const auto &d : decls) {
                if (!d) continue;
                if (d->kind == ast::NodeKind::ImportDecl)
                    imports.push_back(
                        static_cast<const ast::ImportDecl *>(d.get()));
                else if (d->kind == ast::NodeKind::NamespaceDecl)
                    gather(static_cast<const ast::NamespaceDecl *>(d.get())
                               ->decls);
            }
        };
    gather(mod.decls);
    for (const auto *im : imports) {
        ImportRequest req;
        req.by_namespace = im->by_namespace;
        if (im->by_namespace) req.ns_path = im->path; // namespace parcial
        if (im->by_namespace) {
            // NS.2-full: import a.b.c;  El `path` es el namespace punteado.
            // Lo traducimos al module_name (filename) del dep que lo declara,
            // para reusar la maquinaria de imports por-path.  Si no hay mapa
            // (o el ns no esta), dejamos el dotted (fallara el by_name lookup
            // con diagnostico claro mas arriba/abajo).
            req.module_name = im->path; // dotted por defecto
            if (ns_to_modname) {
                auto it = ns_to_modname->find(im->path);
                if (it != ns_to_modname->end()) req.module_name = it->second;
            }
            req.local_name = im->alias.empty() ? req.module_name : im->alias;
        } else {
            // Por-path: module_name = ultimo segmento del path.
            size_t slash = im->path.find_last_of('/');
            req.module_name = (slash == std::string::npos)
                                  ? im->path
                                  : im->path.substr(slash + 1);
            req.local_name = im->alias.empty() ? req.module_name : im->alias;
        }
        // Mapear OnlySymbol AST -> TypeChecker::VxiOnlyEntry.
        req.only_symbols.reserve(im->only_symbols.size());
        for (const auto &os : im->only_symbols) {
            req.only_symbols.push_back({os.name, os.rename});
        }
        // Plain import = sin only Y sin glob.  Registra namespace en lugar de
        // inyectar.  `only *` (glob) inyecta TODOS los publicos -> NO es plain.
        req.only_all = im->only_all;
        req.is_plain = im->only_symbols.empty() && !im->only_all;
        req.is_public_reexport = im->is_public_reexport;
        req.loc = im->loc;
        out.push_back(std::move(req));
    }
    return out;
}

///  NS.2-full: construye el mapa namespace -> module_name recorriendo
/// los AST de todos los modulos del proyecto.  Cada @c NamespaceDecl top-level
/// (formas statement y bloque) mapea su path punteado al module_name del
/// modulo que lo contiene.  Namespaces parciales (varios modulos, mismo ns):
/// gana el primero registrado (MVP; el import trae ese fichero).
NsToModname build_ns_to_modname_(const std::vector<ProjectModuleWork> &work) {
    NsToModname out;
    for (const auto &pm : work) {
        if (!pm.ast) continue;
        for (const auto &d : pm.ast->decls) {
            if (!d || d->kind != ast::NodeKind::NamespaceDecl) continue;
            const auto *ns = static_cast<const ast::NamespaceDecl *>(d.get());
            if (ns->name.empty()) continue;
            out.emplace(ns->name, pm.module_name);
        }
    }
    return out;
}

/// Namespace PARCIAL: mapa namespace -> TODOS los module_name que lo declaran.
/// A diferencia de @c build_ns_to_modname_ (que gana el primero), este recoge
/// la lista completa para que `import std.types` registre los simbolos de
/// TODOS los ficheros del namespace (base + arch-specific), no solo el primero.
/// Recoge los nombres de tipo que menciona un nodo de tipo, a cualquier
/// profundidad.  Un alias puede derivar de otro por debajo de un puntero, de un
/// array o de la firma de una funcion, asi que mirar solo la raiz se dejaria
/// fuera los casos que no son `typedef A B`.
void nombres_de_tipo_(const ast::TypeNode *t, std::vector<std::string> &out) {
    if (t == nullptr) return;
    switch (t->kind) {
    case ast::NodeKind::NamedTypeNode: {
        const auto *n = static_cast<const ast::NamedTypeNode *>(t);
        out.push_back(n->name);
        for (const auto &a : n->type_args)
            nombres_de_tipo_(a.get(), out);
        break;
    }
    case ast::NodeKind::PrimitiveTypeNode: {
        const auto *p = static_cast<const ast::PrimitiveTypeNode *>(t);
        for (const auto &a : p->type_args)
            nombres_de_tipo_(a.get(), out);
        break;
    }
    case ast::NodeKind::PointerTypeNode:
        nombres_de_tipo_(
            static_cast<const ast::PointerTypeNode *>(t)->pointee.get(), out);
        break;
    case ast::NodeKind::ArrayTypeNode:
        nombres_de_tipo_(
            static_cast<const ast::ArrayTypeNode *>(t)->element_type.get(),
            out);
        break;
    case ast::NodeKind::FunctionTypeNode: {
        const auto *f = static_cast<const ast::FunctionTypeNode *>(t);
        for (const auto &p : f->param_types)
            nombres_de_tipo_(p.get(), out);
        nombres_de_tipo_(f->return_type.get(), out);
        break;
    }
    default: break;
    }
}

/// Reordena los @c TypeAliasDecl de un namespace fusionado para que cada uno
/// vaya DESPUES de aquellos de los que deriva.
///
/// Solo se mueven los alias entre si: las posiciones que ocupaban se rellenan
/// en el nuevo orden y el resto de decls no se toca.  Un alias que participa en
/// un ciclo conserva su sitio -- callarlo o inventarle un orden esconderia un
/// error que el type checker sabe nombrar.
void ordenar_alias_por_dependencia_(
    std::vector<std::unique_ptr<ast::Node>> &decls) {
    std::vector<size_t> huecos; // posiciones que ocupan los alias
    std::unordered_map<std::string, size_t> por_nombre;
    for (size_t i = 0; i < decls.size(); ++i) {
        if (!decls[i] || decls[i]->kind != ast::NodeKind::TypeAliasDecl)
            continue;
        por_nombre.emplace(
            static_cast<ast::TypeAliasDecl *>(decls[i].get())->name,
            huecos.size());
        huecos.push_back(i);
    }
    if (huecos.size() < 2) return;

    // Aristas alias -> alias del que deriva, restringidas a este namespace: un
    // nombre de fuera ya esta resuelto cuando llega el pase.
    const size_t n = huecos.size();
    std::vector<std::vector<size_t>> deriva_de(n);
    std::vector<std::string> nombres;
    for (size_t k = 0; k < n; ++k) {
        const auto *al =
            static_cast<const ast::TypeAliasDecl *>(decls[huecos[k]].get());
        nombres.clear();
        nombres_de_tipo_(al->aliased.get(), nombres);
        for (const auto &nm : nombres) {
            auto it = por_nombre.find(nm);
            if (it != por_nombre.end() && it->second != k)
                deriva_de[k].push_back(it->second);
        }
    }

    // DFS post-orden: cada alias se emite tras aquellos de los que deriva.  Un
    // nodo en la pila actual (marca 1) cierra un ciclo; se deja pasar sin
    // reordenar para que el diagnostico lo de quien sabe explicarlo.
    std::vector<uint8_t> marca(n, 0); // 0 sin ver, 1 en pila, 2 emitido
    std::vector<size_t> orden;
    orden.reserve(n);
    std::function<void(size_t)> visitar = [&](size_t k) {
        if (marca[k] != 0) return;
        marca[k] = 1;
        for (size_t d : deriva_de[k])
            visitar(d);
        marca[k] = 2;
        orden.push_back(k);
    };
    for (size_t k = 0; k < n; ++k)
        visitar(k);

    std::vector<std::unique_ptr<ast::Node>> movidos(n);
    for (size_t k = 0; k < n; ++k)
        movidos[k] = std::move(decls[huecos[k]]);
    for (size_t k = 0; k < n; ++k)
        decls[huecos[k]] = std::move(movidos[orden[k]]);
}

using NsToAllModnames =
    std::unordered_map<std::string, std::vector<std::string>>;
NsToAllModnames
build_ns_to_all_modnames_(const std::vector<ProjectModuleWork> &work) {
    NsToAllModnames out;
    for (const auto &pm : work) {
        if (!pm.ast) continue;
        for (const auto &d : pm.ast->decls) {
            if (!d || d->kind != ast::NodeKind::NamespaceDecl) continue;
            const auto *ns = static_cast<const ast::NamespaceDecl *>(d.get());
            if (ns->name.empty()) continue;
            auto &v = out[ns->name];
            if (std::find(v.begin(), v.end(), pm.module_name) == v.end())
                v.push_back(pm.module_name);
        }
    }
    return out;
}

///  NS.3: deriva el PackageId del proyecto.  Camina hacia arriba desde el
/// directorio del fichero raiz buscando @c "vx.toml" (o @c "vx.json"); lee el
/// @c [package] con un scan minimo (sin dependencia de @c src/pkg).  El id es:
///   - el valor explicito de @c id / @c "id" si esta presente, o
///   - @c fnv1a_hex(name @ version) derivado, o
///   - vacio (paquete anonimo) si no hay manifest ni nombre.

} // namespace

/* Las dos puertas que el camino de un fichero suelto tambien usa.  Salen del
 * namespace anonimo -- y no se duplican alli -- porque el criterio de cuando
 * fiarse de lo guardado tiene que ser UNO: con dos, basta que uno se quede
 * atras para que el mismo programa se compile distinto segun por donde entre.
 */
std::string vxfacts_path_for(const std::string &source_path,
                             const std::string &tgt_suffix) {
    return rutas_cache_(source_path, tgt_suffix).hechos;
}

void ensure_facts(const ir::IrModule &mod, analysis::asa::FactStore &store,
                  const std::vector<const char *> &wanted,
                  const std::string &path, uint64_t fingerprint) {
    ensure_facts_impl_(mod, store, wanted, path, fingerprint);
}

///  M.L20: calcula el nivel topologico de cada modulo.  Nivel 0 =
/// sin imports.  Nivel N = 1 + max(niveles de sus deps).  Modulos del
/// MISMO nivel son independientes entre si (sus interfaces solo
/// dependen de niveles menores), por lo que pueden compilarse en
/// paralelo.  El root siempre tiene el nivel maximo.
/// @brief Indice del modulo al que se refiere un import, o SIZE_MAX.
///
/// Se resuelve por NAMESPACE COMPLETO cuando el import es por-namespace, y
/// solo si no, por nombre de modulo.  El orden importa: el nombre de un modulo
/// es el de su FICHERO, asi que dos ficheros homonimos en carpetas distintas
/// (std/os/linux.vx y std/syscall/linux.vx, ambos "linux") colapsan en el mapa
/// por nombre y quien pregunte se lleva el que no es.
///
/// Vive aqui, en un solo sitio, porque cualquiera que resuelva un import de
/// otra manera reintroduce esa confusion en su rincon.
size_t
resolve_import_module_(const ImportRequest &req,
                       const std::unordered_map<std::string, size_t> &by_name,
                       const std::unordered_map<std::string, size_t> &by_ns) {
    if (req.by_namespace && !req.ns_path.empty()) {
        auto itn = by_ns.find(req.ns_path);
        if (itn != by_ns.end()) return itn->second;
    }
    auto itd = by_name.find(req.module_name);
    if (itd != by_name.end()) return itd->second;
    return SIZE_MAX;
}

std::vector<int>
compute_module_levels_(const std::vector<ProjectModuleWork> &work,
                       const std::unordered_map<std::string, size_t> &by_name,
                       const std::unordered_map<std::string, size_t> &by_ns,
                       const NsToModname &ns_to_modname) {
    std::vector<int> levels(work.size(), 0);
    // Procesamos en orden topologico (work ya esta en topo).  Para cada
    // modulo, recogemos los imports de su AST + calculamos su nivel
    // como 1 + max(nivel de cada dep).
    for (size_t i = 0; i < work.size(); ++i) {
        const auto &pm = work[i];
        if (!pm.ast) continue;
        int max_dep_level = -1;
        auto imports = collect_imports_(*pm.ast, &ns_to_modname);
        for (const auto &req : imports) {
            // Resolver el dep por NAMESPACE COMPLETO (by_ns) cuando el import
            // es por-namespace: `by_name` colisiona cuando dos modulos
            // comparten el ultimo segmento (std.syscall.linux.x86_64 y
            // ...windows.x86_64 son ambos "x86_64") -> un import de
            // linux.x86_64 podia resolver al idx de windows.x86_64 (o a
            // ninguno) y el nivel topo quedaba mal -> race en el compile
            // paralelo (el consumidor compila antes que su dep real).  Igual
            // que la resolucion de deps del propio compilador.
            const size_t dep_idx = resolve_import_module_(req, by_name, by_ns);
            if (dep_idx >= work.size()) continue;
            if (static_cast<int>(levels[dep_idx]) > max_dep_level) {
                max_dep_level = levels[dep_idx];
            }
        }
        levels[i] = max_dep_level + 1; // -1 + 1 = 0 si no hay deps
    }
    return levels;
}

/**
 * @brief El asignador escrito en el lenguaje, compilado UNA vez por ejecucion.
 *
 * El binario nativo lo trae desde hace tiempo; el JIT no, y por eso un fallo
 * que solo se ve en el nativo hay que perseguirlo en el nativo.  Compartiendo
 * mecanismo, ese mismo camino se puede recorrer dentro de la maquina, con el
 * depurador y los volcados de IR delante.  No es por velocidad.
 *
 * Se compila una sola vez y se guarda: hacerlo por cada modulo que reserva
 * memoria multiplicaba el tiempo de compilacion hasta agotar el limite en los
 * proyectos con varias dependencias.
 *
 * @param opts Opciones de la compilacion en curso (nivel y objetivo).
 * @param alloc_sym Recibe el nombre de la funcion que reserva.
 * @param free_sym Recibe el de la que libera.
 * @return El modulo, o @c nullptr si no se encuentra o no lo expone.
 */
static const ir::IrModule *asignador_del_lenguaje_(const CompileOptions &opts,
                                                   std::string &alloc_sym,
                                                   std::string &free_sym) {
    struct Cache {
        bool intentado = false;
        std::unique_ptr<ir::IrModule> mod;
        std::string alloc, libera;
    };
    static Cache c;
    static std::mutex m;
    std::lock_guard<std::mutex> g(m);
    if (!c.intentado) {
        c.intentado = true;
        namespace stdfs = std::filesystem;
        const std::string dir =
            stdfs::path(fs::get_executable_path()).parent_path().string();
        for (const std::string &p :
             {dir + "/stdlib/vx/vx_mem.vx", dir + "/../stdlib/vx/vx_mem.vx",
              std::string("stdlib/vx/vx_mem.vx")}) {
            if (!stdfs::exists(p)) continue;
            CompileOptions mo;
            mo.module_name = "vx_mem";
            mo.opt_level = opts.opt_level;
            mo.asm_target_bits = opts.asm_target_bits;
            mo.sin_asignador_vesta = true; // no puede traerse a si mismo
            const CompileResult r = compile_vx_project(p, mo, nullptr, nullptr);
            if (!r.ok || r.aot_alloc_sym.empty() || r.aot_free_sym.empty())
                break;
            std::unique_ptr<ir::IrModule> mm(new ir::IrModule());
            if (!ir::parse_ir_module_cache(r.ir_module_cache_bytes, *mm)) break;
            c.mod = std::move(mm);
            c.alloc = r.aot_alloc_sym;
            c.libera = r.aot_free_sym;
            break;
        }
    }
    if (!c.mod) return nullptr;
    alloc_sym = c.alloc;
    free_sym = c.libera;
    return c.mod.get();
}

/**
 * @brief Deja el asignador del lenguaje DENTRO del modulo, sin tocar las
 *        reservas.
 *
 * Sus funciones quedan disponibles para quien quiera llamarlas -- el selector
 * del JIT --, y quien no las llame no las nota: el interprete sigue con la
 * instruccion de la maquina.  Reescribir aqui las reservas seria decidir por
 * los dos, y ese fue el error del primer intento: se llevo por delante al
 * interprete.
 *
 * @param mod Modulo ya fusionado, antes de optimizar.
 * @param opts Opciones de la compilacion en curso.
 * @param root_path Fuente raiz, para no traerse a si mismo.
 */
void traer_asignador_del_lenguaje(ir::IrModule &mod, const CompileOptions &opts,
                                  const std::string &root_path) {
    if (opts.sin_asignador_vesta) return;
    if (root_path.find("vx_mem") != std::string::npos) return;
    /* El binario nativo ya lo trae por su cuenta -- su driver lo compila y lee
     * sus simbolos --, asi que metiendolo tambien desde aqui acabaria con dos
     * copias del mismo asignador.  Esto es para el camino de maquina, que es el
     * que no lo tenia. */
    if (opts.native_poo) return;

    bool reserva = false;
    for (const ir::IrFunction &f : mod.functions) {
        if (f.name == "__vx_malloc") return; // ya esta dentro
        for (const ir::IrBlock &b : f.blocks)
            for (const ir::IrInstr &in : b.instrs)
                if (in.op == ir::IrOp::RAW_ALLOC || in.op == ir::IrOp::RAW_FREE)
                    reserva = true;
    }
    if (!reserva) return;

    std::string alloc_sym, free_sym;
    const ir::IrModule *mem =
        asignador_del_lenguaje_(opts, alloc_sym, free_sym);
    if (mem == nullptr) return; // sin el, todo sigue como estaba.
    /* Y QUIEN es, para que la maquina no tenga que adivinarlo.  Si el programa
     * declara el suyo con @AllocatorOverride manda ese; el de la biblioteca
     * solo cubre a quien no lo hace. */
    mod.alloc_sym = alloc_sym;
    mod.free_sym = free_sym;

    /* Los nombres que ya estan, en un indice construido UNA vez.  Preguntarlo
     * recorriendo todas las funciones por cada candidata seria multiplicar dos
     * listas y comparar cadenas en el bucle interno. */
    std::unordered_set<std::string> presentes;
    presentes.reserve(mod.functions.size() * 2);
    for (const ir::IrFunction &g : mod.functions)
        presentes.insert(g.name);

    std::unordered_set<std::string> traidas;
    for (const ir::IrFunction &f : mem->functions) {
        if (presentes.count(f.name) == 0) {
            /* Alcanzable aunque nadie la llame TODAVIA: quien la va a llamar es
             * el selector del JIT, que trabaja despues de optimizar, y para
             * entonces el pase que limpia lo que no se usa ya se la habria
             * llevado. */
            ir::IrFunction copia = f;
            copia.is_public = true;
            traidas.insert(copia.name);
            mod.functions.push_back(std::move(copia));
        }
    }
    /* Los datos, y con ellos el DESPLAZAMIENTO de sus indices.
     *
     * Cada modulo numera sus ranuras desde cero.  Al concatenar, las del
     * asignador se van al final y sus indices cambian, pero sus instrucciones
     * siguen pidiendo el numero viejo -- que ahora es otra cosa.  Ademas de
     * leer lo que no es, se pierde su naturaleza: una ranura de variable global
     * vive en memoria del HOST y el resto en la de la maquina, asi que el
     * asignador acababa usando una direccion de la maquina como si fuera del
     * host y el programa caia con un acceso invalido.
     *
     * Es el mismo desplazamiento que ya hace el merge de dependencias. */
    ir::IrModule copia_datos = *mem;
    const uint64_t desplazamiento = mod.static_data.size();
    mod.static_data.append_raw_entries(std::move(copia_datos.static_data));
    /* Con la operacion compartida: corre los indices Y las referencias
     * textuales del ensamblador embebido, que esta fusion se dejaba. */
    for (ir::IrFunction &f : mod.functions)
        if (traidas.count(f.name))
            ir::ir_correr_indices_de_datos(f, desplazamiento);
    for (const auto &gv : mem->globals)
        mod.globals.emplace(gv.first, gv.second);
    // Lo que el asignador llama por su cuenta: pide memoria al sistema por la
    // interfaz nativa, asi que sus importaciones tienen que venir con el.
    for (const auto &ni : mem->native_imports)
        mod.register_native_import(ni.lib, ni.name);
    for (const auto &nl : mem->native_libs) {
        bool ya = false;
        for (const auto &x : mod.native_libs)
            if (x == nl) {
                ya = true;
                break;
            }
        if (!ya) mod.native_libs.push_back(nl);
    }
    /* Y el punto de entrada de nombre conocido que lleva hasta el.  Al final,
     * cuando el asignador YA esta dentro: el puente comprueba que existe a
     * quien llamar antes de ponerse, asi que antes de copiarlo no encontraba
     * nada.  Aqui pasan los dos caminos de compilacion. */
}

CompileResult compile_vx_project(
    const std::string &root_path, const CompileOptions &opts,
    const std::unordered_map<std::string, std::string> *source_overlay,
    const std::vector<std::string> *extra_search_paths) {
    CompileResult res;

    /* Reparto del coste, con el mismo criterio que el camino de fichero
     * suelto: se mide siempre, porque una medida que hay que pedir es una
     * medida que nadie mira.  Aqui interesa sobre todo separar RESOLVER el
     * grafo -- que crece con el numero de modulos -- de compilarlos. */
    using RelojProyecto = std::chrono::steady_clock;
    auto marca = RelojProyecto::now();
    auto cerrar_fase = [&marca](long &destino) {
        const auto ahora = RelojProyecto::now();
        destino += (long)std::chrono::duration_cast<std::chrono::microseconds>(
                       ahora - marca)
                       .count();
        marca = ahora;
    };

    // 1. Construir el dep graph + topo sort.
    ModuleGraph graph(res.diagnostics);
    // LSP: overlay del buffer en memoria (root con ediciones sin guardar).  Se
    // aplica ANTES de build_from_root para que la lectura del root use el texto
    // inyectado en vez del disco; los imports se siguen leyendo del disco.
    if (source_overlay) {
        for (const auto &kv : *source_overlay)
            graph.set_source_overlay(kv.first, kv.second);
    }
    // LSP: directorios extra donde resolver imports (ancestros del fichero
    // analizado), para que un modulo con imports relativos al root del proyecto
    // (p.ej. `import "modules/buffer"`) resuelva aunque se abra standalone.
    if (extra_search_paths) {
        for (const auto &d : *extra_search_paths)
            graph.add_search_path(d);
    }
    // Permitir override del directorio de busqueda via env var VX_PATH.
    graph.add_vx_path_env();

    /* Las dependencias DECLARADAS del proyecto.
     *
     * Hasta aqui un `import` resolvia contra lo que hubiera suelto por el disco
     * -- el directorio del fuente, `VX_PATH`, la stdlib --, y el manifiesto no
     * pintaba nada: el gestor de paquetes sabia descargar y verificar, pero el
     * compilador no miraba lo que se habia declarado.  De ahi que dos copias de
     * una libreria fueran indistinguibles.
     *
     * Ahora lo que el `vx.toml` declara entra como sitio donde buscar, y con
     * PRIORIDAD sobre la stdlib: si el proyecto dice de que depende, eso es lo
     * que quiere, no lo que se encuentre por ahi. */
    {
        std::string manifiesto;
        (void)derive_package_id(root_path, &manifiesto);
        if (!manifiesto.empty()) {
            const pkg::ParseResult pr = pkg::parse_manifest_file(manifiesto);
            if (pr.ok) {
                namespace fs = std::filesystem;
                const fs::path dir_man = fs::path(manifiesto).parent_path();
                for (const auto &dep : pr.manifest.dependencies) {
                    /* Con `path` se toma tal cual (relativo al manifiesto);
                     * si no, donde el gestor deja lo instalado.  Se usa el
                     * nombre REAL del paquete, que con un alias no es la clave
                     * de la entrada. */
                    const std::string &nombre =
                        dep.paquete.empty() ? dep.name : dep.paquete;
                    /* El override del usuario manda sobre lo declarado: es como
                     * se trabaja SOBRE una libreria sin tocar el manifiesto de
                     * cada proyecto que la usa. */
                    const std::string ov = override_de_paquete(nombre);
                    fs::path cand =
                        !ov.empty() ? fs::path(ov)
                                    : (dep.path.empty()
                                           ? (dir_man / "vx_modules" / nombre)
                                           : (dir_man / dep.path));
                    std::error_code ec;
                    if (fs::exists(cand, ec) && fs::is_directory(cand, ec))
                        graph.add_search_path(cand.lexically_normal().string());
                }
            }
        }
    }
    // Cablear el directorio de la stdlib Vesta (stdlib/vx).  Permite que
    // `import "simd_string"` (y futuras libs Vesta de la stdlib) resuelva sin
    // que el usuario tenga que copiar la lib a su proyecto.  Autodetect por
    // candidatos comunes desde el cwd (override via env var VX_STDLIB_DIR).
    {
        // Autodetect de la stdlib Vesta (env VX_STDLIB_DIR, cwd, o relativo al
        // ejecutable).  Factorizado en detect_stdlib_vx_dir() para reuso del
        // LSP.
        std::string sd = detect_stdlib_vx_dir();
        if (!sd.empty()) graph.set_stdlib_dir(sd);
    }
    // añadir como search path implicito la carpeta del modulo root.  Asi
    // los modulos hermanos pueden importarse con paths relativos al root
    // (`import "modules/foo"` desde @c src/modules/bar.vx resuelve a
    // @c src/modules/foo.vx aunque el importer dir sea @c src/modules/).
    // Sin esto, cada modulo tendria que usar paths siblings (`import "foo"`)
    // que cambian segun donde vive el archivo -- frustrante a escala.
    {
        std::string norm = root_path;
        for (char &c : norm)
            if (c == '\\') c = '/';
        size_t slash = norm.find_last_of('/');
        if (slash != std::string::npos) {
            graph.add_search_path(norm.substr(0, slash));
        }
    }
    const uint32_t root_id = graph.build_from_root(root_path);
    if (root_id == UINT32_MAX || res.diagnostics.has_errors()) {
        res.ok = false;
        return res;
    }
    auto topo = graph.topological_order();
    if (graph.has_cycle()) {
        res.ok = false;
        return res;
    }

    cerrar_fase(res.tiempos.resolver_us);

    // 2. Mover los AST parseados del graph a estructuras de trabajo.
    std::vector<ProjectModuleWork> work(topo.size());
    std::unordered_map<std::string, size_t> by_name; // module_name -> idx
    for (size_t i = 0; i < topo.size(); ++i) {
        const uint32_t mid = topo[i];
        const ResolvedModule *rm = graph.module(mid);
        // El ModuleGraph mantiene el AST como unique_ptr.  Necesitamos
        // tomarlo prestado SIN const_cast del puntero, asi que pedimos
        // que el graph nos lo entregue via un getter que mueva el unique_ptr.
        // Como simplificacion, hacemos const_cast aqui (el ModuleGraph
        // no se usa mas despues de este punto).
        ResolvedModule *rm_mut = const_cast<ResolvedModule *>(rm);
        work[i].module_id = mid;
        work[i].canonical_path = rm_mut->canonical_path;
        work[i].module_name = rm_mut->module_name;
        work[i].ast = std::move(rm_mut->parsed_ast);
        // Cargar source de disco para el lexer (necesario para el
        // diagnostics: queremos preservar locs).
        work[i].source = read_source_(rm_mut->canonical_path);
        by_name.emplace(rm_mut->module_name, i);
    }

    /* ------------------------------------------------------------------
     * El conjunto comptime, compilado ANTES que ningun modulo.
     *
     * El codigo que se ejecuta al compilar -- los `@Macro`, las `comptime fn`
     * -- necesita bytecode que ejecutar.  Hasta ahora ese bytecode se producia
     * compilando el programa ENTERO y volviendo a compilarlo todo con el ya
     * cargado; mientras tanto, los modulos que se compilaban antes de que
     * existiera salian con lo que ese codigo debia generar SIN generar: cuerpos
     * de `asm` vacios, sobre todo.
     *
     * Aqui se hace al reves y una sola vez: se extrae el conjunto -- solo las
     * decls que se ejecutan al compilar, que son pocas: seis funciones de las
     * treinta y cinco en `std.memory.x86_64` --, se compila, y el bucle de
     * modulos arranca con el ya disponible.
     *
     * Se puede hacer AQUi porque en este punto TODOS los modulos estan
     * parseados (el resolvedor lo hace para construir el grafo de
     * dependencias), tambien los que luego se serviran del cache.  Extraer el
     * conjunto solo necesita el AST y el fuente, y los dos estan.
     * ------------------------------------------------------------------ */
    std::vector<uint8_t> artefacto_comptime;
    CompileOptions opts_modulos = opts;
    /* De momento APAGADO por defecto (`VESTA_ARTEFACTO_TEMPRANO=1` lo activa).
     * El conjunto extraido todavia no compila por si solo: se lleva las
     * funciones comptime y sus dependencias de FUNCION, pero no las
     * declaraciones de TIPO que ese codigo usa, asi que falla con "el operando
     * de '.' debe ser un struct" y "sizeof: tipo no reconocido".  Hasta que el
     * cierre arrastre los tipos, encenderlo solo gasta tiempo -- y compilar el
     * conjunto EN PROCESO toca estado global, que se noto en un caso que dejo
     * de pasar. */
    if (!opts.building_comptime_artifact &&
        util::flag_on(util::FlagId::ArtefactoTemprano)) {
        /* Cada modulo se SUSTITUYE por su propio conjunto comptime, y se
         * compila el mismo programa.
         *
         * Concatenar los conjuntos de todos en un solo texto no vale: al
         * resolverse los `import`, los modulos reales entran tambien y todo
         * queda por duplicado ("redefinicion de simbolo", "alias de tipo
         * redefinido").  Sustituyendolos, el grafo de dependencias es el mismo,
         * cada `import` resuelve a la version recortada y no hay duplicados --
         * ni hace falta arrastrar los tipos de otros modulos, porque cada uno
         * sigue trayendo los suyos.
         *
         * Se puede hacer aqui porque TODOS los modulos estan ya parseados: el
         * resolvedor lo hace para construir el grafo, tambien los que luego se
         * serviran del cache.  Extraer solo necesita el AST y el fuente. */
        std::unordered_map<std::string, std::string> overlay_ct;
        if (source_overlay) overlay_ct = *source_overlay;
        bool hay_comptime = false;
        /* Primero, QUE llama el codigo comptime y no encuentra en su modulo.
         *
         * El cierre de cada modulo es local: solo ve sus decls.  Una funcion
         * que el comptime de un modulo llama por un `import` no viaja en el
         * conjunto del que la DEFINE, y al compilarlo todo junto el que la
         * exporta ya no la tiene.  Se juntan las de todos y se pide el conjunto
         * otra vez, diciendole a cada uno que ademas incluya las que le tocan.
         */
        std::unordered_set<std::string> pedidas;
        for (auto &w : work) {
            if (!w.ast) continue;
            const ComptimeUnit prev = collect_comptime_unit(*w.ast, w.source);
            pedidas.insert(prev.external_calls.begin(),
                           prev.external_calls.end());
        }
        if (util::flag_on(util::FlagId::McVerbose)) {
            std::fprintf(stderr, "[pedidas] %zu:", pedidas.size());
            for (const auto &n : pedidas)
                std::fprintf(stderr, " %s", n.c_str());
            std::fprintf(stderr, "%c", 10);
        }
        for (auto &w : work) {
            if (!w.ast) continue;
            const ComptimeUnit cu =
                collect_comptime_unit(*w.ast, w.source, &pedidas);
            std::string texto;
            /* El `namespace` delante: se lee del AST, donde el `namespace X;`
             * todavia es un nodo -- el aplanado, mas adelante, lo deshace. */
            for (const auto &d : w.ast->decls) {
                if (!d || d->kind != ast::NodeKind::NamespaceDecl) continue;
                const auto *nd =
                    static_cast<const ast::NamespaceDecl *>(d.get());
                if (nd->name.empty()) break;
                texto += "namespace " + nd->name + ";";
                texto.push_back(static_cast<char>(10));
                break;
            }
            texto += cu.unit_source;
            if (!cu.empty()) hay_comptime = true;
            overlay_ct[w.canonical_path] = texto;
            /* El texto que de VERDAD se compila para este modulo.  El volcado
             * por conjunto se salta los modulos sin codigo comptime -- los que
             * solo aportan tipos --, que son justo los que hacen falta mirar
             * cuando una cadena de tipos no resuelve. */
            if (!util::flag_text(util::FlagId::VolcarUnidad).empty()) {
                const std::string &dd =
                    util::flag_text(util::FlagId::VolcarUnidad);
                std::error_code oec;
                std::filesystem::create_directories(dd, oec);
                std::ofstream fo(
                    dd + "/overlay_" + w.module_name + "_" +
                    std::to_string(
                        static_cast<unsigned long long>(vxi_fnv1a(
                            w.canonical_path.data(), w.canonical_path.size())) %
                        100000ULL) +
                    ".vx");
                if (fo) fo << texto;
            }
        }
        if (hay_comptime) {
            /* Compilarlo SIN volver a adelantar nada: el conjunto se contiene a
             * si mismo -- `inject` es un `@Macro` -- y sin la marca construiria
             * el artefacto DEL artefacto, nivel tras nivel. */
            CompileOptions o_ct = opts;
            o_ct.building_comptime_artifact = true;
            o_ct.native_poo = false; // lo ejecuta la VM, no codigo nativo.
            CompileResult cr_ct = compile_vx_project(
                root_path, o_ct, &overlay_ct, extra_search_paths);
            if (util::flag_on(util::FlagId::McVerbose) && !cr_ct.ok) {
                int n = 0;
                for (const auto &dg : cr_ct.diagnostics.all()) {
                    if (dg.level != DiagLevel::ERR) continue;
                    if (++n > 3) break;
                    std::fprintf(stderr, "[conjunto] %u: %s%c", dg.loc.line,
                                 dg.message.c_str(), 10);
                }
            }
            if (cr_ct.ok && !cr_ct.vel_text.empty()) {
                std::error_code cec;
                const std::string dir =
                    (std::filesystem::temp_directory_path(cec) / "vx_ct")
                        .string();
                std::filesystem::create_directories(dir, cec);
                const std::string pref =
                    dir + "/ct_" +
                    std::to_string(static_cast<unsigned long long>(vxi_fnv1a(
                        cr_ct.vel_text.data(), cr_ct.vel_text.size())));
                if (asm_multi_process::run_worker_from_source(
                        std::string(cr_ct.vel_text), pref + ".vel.tmp", pref,
                        /*skip_preprocessor=*/true, /*keep_labels=*/false,
                        &cr_ct.ir_section_bytes,
                        /*emit_map=*/false) == EXIT_SUCCESS) {
                    if (util::read_whole_file(pref + ".velb",
                                              artefacto_comptime) &&
                        !artefacto_comptime.empty()) {
                        opts_modulos.comptime_artifact = &artefacto_comptime;
                        /* Cuantos modulos entraron y cuanto ocupa lo producido.
                         * Es la medida que dice si el conjunto llego COMPLETO:
                         * compila limpio y aun asi puede registrar menos macros
                         * de los que el programa necesita, y entonces lo que
                         * dependa de ellos sale con valores de relleno. */
                        if (util::flag_on(util::FlagId::McVerbose))
                            std::fprintf(
                                stderr, "[conjunto] %zu modulos -> %zu B%c",
                                work.size(), artefacto_comptime.size(), 10);
                    }
                }
            }
        }
    }

    // Colision de module_name (filename): dos modulos con el mismo ultimo
    // segmento (p.ej. std.syscall.linux.x86_64 y std.syscall.windows.x86_64,
    // ambos "x86_64") colapsan en by_name (emplace conserva el primero).  by_ns
    // mapea el NAMESPACE COMPLETO (unico) -> idx, para resolver sin ambiguedad
    // los imports por-namespace (`import a.b.c;`).
    std::unordered_map<std::string, size_t> by_ns;
    for (size_t i = 0; i < work.size(); ++i) {
        if (!work[i].ast) continue;
        for (const auto &d : work[i].ast->decls) {
            if (d && d->kind == ast::NodeKind::NamespaceDecl) {
                auto *nd = static_cast<ast::NamespaceDecl *>(d.get());
                by_ns.emplace(nd->name, i);
                break;
            }
        }
    }

    // Simbolos que el parser dejo fuera por @Target, agregados de TODOS los
    // modulos del build.  Usar uno de ellos no es "no existe": existe para
    // otro objetivo, y el diagnostico tiene que distinguirlo.  Se agrega a
    // nivel de proyecto porque el simbolo puede estar descartado en un dep y
    // usarse desde el modulo raiz.
    std::unordered_map<std::string, std::vector<std::string>>
        target_skipped_proyecto;
    for (const auto &w : work) {
        if (!w.ast) continue;
        for (const auto &kv : w.ast->target_skipped) {
            auto &dst = target_skipped_proyecto[kv.first];
            for (const auto &spec : kv.second) {
                if (std::find(dst.begin(), dst.end(), spec) == dst.end())
                    dst.push_back(spec);
            }
        }
    }

    //  NS.2-full: mapa namespace -> module_name para traducir los
    // imports por-namespace (`import a.b.c;`) al module_name del dep.
    const NsToModname ns_to_modname = build_ns_to_modname_(work);
    // Namespace parcial: todos los module_name por namespace (para registrar
    // los simbolos de TODOS los ficheros de un `namespace X;` compartido).
    const NsToAllModnames ns_to_all_modnames = build_ns_to_all_modnames_(work);

    // NS.parcial fix: un mismo `namespace X;` declarado por VARIOS ficheros
    // (p.ej. std.types = types.vx base + types/<arch>.vx) se parsea como
    // modulos SEPARADOS, cada uno con su propio TypeChecker.  Una ref
    // CROSS-FICHERO -- `typedef usize size_t` en la base, con `usize` (newtype)
    // definido en el fichero del arch -- NO resolvia: el TC de la base no ve
    // los simbolos del arch, y el flatten (por-modulo) no manglea la ref.
    // Fix: fusionar las decls de los ficheros SECUNDARIOS en el NamespaceDecl
    // del PRINCIPAL antes de compilar.  Asi el flatten usa un rename_map COMuN
    // (manglea `usize` -> `std__types__usize`) y el TC ve todas las decls en
    // el mismo modulo.  Los secundarios quedan con el NamespaceDecl vacio (se
    // compilan a un .vxi vacio, sin romper el registro del importador).
    {
        auto find_ns_decl = [](ast::ModuleNode *m,
                               const std::string &ns) -> ast::NamespaceDecl * {
            if (!m) return nullptr;
            for (auto &d : m->decls)
                if (d && d->kind == ast::NodeKind::NamespaceDecl) {
                    auto *nd = static_cast<ast::NamespaceDecl *>(d.get());
                    if (nd->name == ns) return nd;
                }
            return nullptr;
        };
        for (const auto &kv : ns_to_all_modnames) {
            if (kv.second.size() < 2) continue; // no es namespace parcial
            const std::string &ns = kv.first;
            auto it0 = by_name.find(kv.second[0]);
            if (it0 == by_name.end()) continue;
            const size_t pidx = it0->second;
            ast::NamespaceDecl *pns = find_ns_decl(work[pidx].ast.get(), ns);
            if (!pns) continue;
            for (size_t k = 1; k < kv.second.size(); ++k) {
                auto itk = by_name.find(kv.second[k]);
                if (itk == by_name.end()) continue;
                ProjectModuleWork &sec = work[itk->second];
                ast::NamespaceDecl *sns = find_ns_decl(sec.ast.get(), ns);
                if (!sns) continue;
                for (auto &d : sns->decls)
                    pns->decls.push_back(std::move(d));
                sns->decls.clear();
                // El source del secundario entra en el hash del principal para
                // que el cache del .vxi se invalide si cualquier fichero del
                // namespace parcial cambia.
                work[pidx].source += "\n";
                work[pidx].source += sec.source;
            }
            // El check de aliases (type_checker) es un SOLO pase ordenado: un
            // alias exige que el tipo del que se deriva ya este procesado.  El
            // orden de las decls fusionadas no lo da el usuario -- lo da la
            // fusion --, asi que ordenarlas es responsabilidad de aqui.
            //
            // Antes se movian los alias PUROS al final, dando por hecho que un
            // newtype nunca deriva de otro newtype del mismo namespace.  Eso es
            // falso: `typedef isize offset new` en el fichero base deriva de
            // `typedef i64 isize new` del fichero del arch, y ambos son
            // newtypes, asi que la particion los dejaba al reves y `std.types`
            // -- del que depende media stdlib -- no compilaba suelto.
            //
            // Se ordenan por DEPENDENCIA REAL entre los alias del namespace,
            // que es la condicion que el pase necesita, en vez de por una
            // propiedad que se le parece.  Los ciclos se dejan en su sitio: el
            // type checker es quien tiene que decir que un alias es circular.
            ordenar_alias_por_dependencia_(pns->decls);
        }
    }

    //  NS.3: PackageId del proyecto (derivado de vx.toml o anonimo).
    // Compartido por todos los modulos del proyecto salvo override @id.
    const std::string project_package_id = derive_package_id(root_path);
    //  NS.3: override @id por-modulo, capturado AQUI (antes de que el
    // flatten elimine el NamespaceDecl del AST durante compile_one_module).
    std::vector<std::string> module_pkgid_override(work.size());
    for (size_t i = 0; i < work.size(); ++i) {
        if (!work[i].ast) continue;
        for (const auto &d : work[i].ast->decls) {
            if (!d || d->kind != ast::NodeKind::NamespaceDecl) continue;
            const auto *ns = static_cast<const ast::NamespaceDecl *>(d.get());
            if (!ns->package_id_override.empty()) {
                module_pkgid_override[i] = ns->package_id_override;
                break;
            }
        }
    }

    // 3. Compilar cada modulo en orden topologico (deps primero).
    //
    // Estrategia con cache (M3+M4):
    //   - El ROOT (work.back()) SIEMPRE se compila (es lo que el usuario
    //     pidio compilar; su .velb es el output del comando).
    //   - Los DEPS comprueban el cache `.vxi` + `.vxir` junto al source:
    //     si ambos existen y source_hash coincide con el del .vxi, se
    //     SKIPEAN el lex+parse+typecheck+lower del dep y se carga el IR
    //     directo desde .vxir.  Speedup esperado: 5-20x en builds
    //     incrementales con cache hit.
    //   - Cache desactivable via env VX_NO_CACHE=1.
    const bool cache_enabled = !vxi_cache_disabled_();
    const bool verbose_cache = util::flag_on(util::FlagId::VerboseCache);
    //  M.L21: progreso/feedback al usuario durante compile de
    // proyectos grandes.  Activado via @c VX_VERBOSE_COMPILE=1 .
    // Emit @c [i/N] compiling <name>... al iniciar cada modulo +
    // @c (hit/wrote) al cerrar.  Util para identificar cuellos de
    // botella en build incrementales.
    const bool verbose_compile = util::flag_on(util::FlagId::VerboseCompile);
    //  M.L20: computar niveles topologicos para reporting.  Modulos
    // del MISMO nivel son independientes (pueden paralelizarse).  Esto
    // detecta el potencial paralelismo del proyecto; la ejecucion
    // paralela queda como infraestructura para M8 (ThreadPool dedicado
    // al compiler) -- el refactor del loop a paralelo requiere thread
    // safety review del TypeChecker compartido + file lock cache que
    // M5.A ya cubre via atomic write.
    const std::vector<int> module_levels =
        compute_module_levels_(work, by_name, by_ns, ns_to_modname);
    int max_level = 0;
    for (int L : module_levels) {
        if (L > max_level) max_level = L;
    }
    if (verbose_compile && max_level > 0) {
        // Reporte de paralelismo potencial.
        std::vector<int> per_level_count(max_level + 1, 0);
        for (int L : module_levels)
            per_level_count[L]++;
        int parallel_opportunities = 0;
        for (int c : per_level_count) {
            if (c > 1) parallel_opportunities += c - 1;
        }
        std::cerr << "[topo] " << work.size() << " modulos en "
                  << (max_level + 1) << " niveles, " << parallel_opportunities
                  << " modulos paralelizables\n";
    }
    // CPU dispatch Inc 5b: pre-pase de escaneo de @HelperOverride
    // CROSS-MODULE.  A diferencia del path single-file (compiler.cpp), aqui
    // un modulo IMPORTADO puede declarar el override (la "lib" hereda su
    // implementacion al consumidor via import).  El override debe resolverse
    // ANTES de lowerear el ROOT, porque es el root quien genera los inits
    // (__vx_memcpy_init / __vx_strdisp_init) que apuntan el fp a la fn del
    // override.  Estrategia: recorrer el AST de TODOS los modulos (root +
    // imports) recolectando un map agregado target->fn_name; luego, cuando se
    // lowerea el root, aplicarlo via lo.set_*_override.  El fn_name resuelve
    // contra el simbolo del IR mergeado (las fns top-level conservan su
    // nombre; los imports mantienen su nombre LOCAL via el mangle, pero el
    // override referencia el nombre tal cual aparece en su modulo -> hay que
    // capturar el nombre ya manglado para que el reloc fnsym lo resuelva).
    //
    // Precedencia: si el ROOT y un import overriden el MISMO target, gana el
    // ROOT (es codigo directo del usuario; el import es la lib heredada).
    std::unordered_map<std::string, std::string> aot_helper_override_syms;
    {
        // Set de targets cuyo override provino del ROOT (para precedencia).
        std::unordered_set<std::string> from_root;
        for (size_t mi = 0; mi < work.size(); ++mi) {
            auto &pm = work[mi];
            if (!pm.ast) continue; // cache hit con AST conservado igual sirve
            const bool is_root = (mi + 1 == work.size());
            for (auto &decl : pm.ast->decls) {
                if (!decl || decl->kind != ast::NodeKind::FunctionDecl)
                    continue;
                auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
                if (fd->helper_override_target.empty()) continue;
                const std::string &tgt = fd->helper_override_target;
                const bool is_multiversioned =
                    (tgt == "memcpy" || tgt == "strcmp" || tgt == "strlen");
                if (!is_multiversioned) {
                    pm.diags.warning(
                        fd->loc,
                        "@HelperOverride: helper '" + tgt +
                            "' no es multi-versionado (solo 'memcpy', "
                            "'strcmp', "
                            "'strlen' por ahora); la anotacion se ignora");
                    continue;
                }
                // El nombre del simbolo: en modulos NO-root las fns top-level
                // se manglan con prefijo `<module>__` (ver mangle_top_level_
                // mas abajo).  Aqui aun no se ha manglado el AST (eso ocurre
                // dentro de compile_one_module), asi que construimos el nombre
                // manglado a mano para que coincida con el simbolo del IR
                // mergeado.  El root conserva su nombre tal cual.
                const std::string sym_name =
                    is_root ? fd->name : (pm.module_name + "__" + fd->name);
                // Validacion de firma (no fatal, el usuario manda).
                bool ret_void =
                    !fd->return_type || (fd->return_type->kind ==
                                             ast::NodeKind::PrimitiveTypeNode &&
                                         static_cast<ast::PrimitiveTypeNode *>(
                                             fd->return_type.get())
                                                 ->prim == PrimitiveKind::VOID);
                bool sig_ok = true;
                std::string expected;
                if (tgt == "memcpy") {
                    sig_ok = (fd->params.size() == 3 && ret_void);
                    expected = "void(u8*, u8*, u64)";
                } else if (tgt == "strcmp") {
                    sig_ok = (fd->params.size() == 4 && !ret_void);
                    expected = "i64(u8*, i64, u8*, i64)";
                } else { // strlen
                    sig_ok = (fd->params.size() == 1 && !ret_void);
                    expected = "i64(u8*)";
                }
                if (!sig_ok) {
                    pm.diags.warning(
                        fd->loc,
                        "@HelperOverride(" + tgt + "): firma esperada " +
                            expected +
                            "; la del override puede ser incompatible");
                }
                // Precedencia + deteccion de conflicto.
                auto existing = aot_helper_override_syms.find(tgt);
                if (existing != aot_helper_override_syms.end()) {
                    const bool prev_from_root = from_root.count(tgt) != 0;
                    if (is_root && !prev_from_root) {
                        // El root pisa al import: gana el root.
                        existing->second = sym_name;
                        from_root.insert(tgt);
                    } else if (!is_root && prev_from_root) {
                        // Ya teniamos el del root: el import se ignora.
                    } else {
                        // Conflicto real: dos modulos del MISMO nivel de
                        // precedencia (ambos imports, o el caso imposible de
                        // dos roots) overriden el mismo target -> error.
                        res.ok = false;
                        res.diagnostics.error(fd->loc,
                                              "multiples @HelperOverride(" +
                                                  tgt + ") cross-module: '" +
                                                  existing->second + "' y '" +
                                                  sym_name + "'");
                        return res;
                    }
                } else {
                    aot_helper_override_syms[tgt] = sym_name;
                    if (is_root) from_root.insert(tgt);
                }
            }
        }
    }

    //  M8: refactor del loop body a lambda para enable dispatch paralelo
    // por nivel topo.  La lambda captura todo el entorno por referencia.
    // Cada thread tiene su propio @c pm = work[i] por diseno (slots distintos
    // del vector, no overlap).  Lectura cross-thread de @c work[dep_idx] es
    // safe porque los deps estan en niveles topologicos ANTERIORES y ya
    // finalizaron antes de que este nivel empiece (barrier por nivel).
    // Mutex para verbose output: en modo paralelo, los @c std::cerr de
    // multiples threads pueden interleaved a nivel de byte (cerr no es
    // line-buffered atomic).  Construimos la linea en un string local y
    // hacemos una sola @c cerr<< con lock.  En modo secuencial, el lock
    // es un no-op virtual (un solo thread nunca contiende).
    std::mutex verbose_mtx;
    // HALLAZGO-2: capturar el override de @Target (thread_local del parser) en
    // el main thread.  Se usa para (a) mezclarlo en el source_hash del cache
    // -> PE y ELF del MISMO proyecto no comparten `.vxir` (si no,
    // cross-compilar a un target y luego a otro reusaba el IR del target
    // equivocado), y (b) re-aplicarlo en los workers del compile paralelo (el
    // thread_local arranca vacio en un thread nuevo).
    std::string cc_tgt_os, cc_tgt_arch;
    vx::get_aot_condcomp_target(cc_tgt_os, cc_tgt_arch);

    // CAS global direccionado por contenido (opt-in via VX_CAS_DIR): tier de
    // cache ADICIONAL, independiente de la ruta, que permite reusar el
    // artefacto de un modulo (interfaz + IR) entre proyectos distintos y entre
    // maquinas. Ejemplo: la stdlib se compila una sola vez para toda la
    // maquina.  Default OFF -> comportamiento y builds actuales intactos.
    // Comparte un solo CasStore entre threads (sus ops de fichero son atomicas
    // / read-only).
    std::unique_ptr<CasStore> cas;
    if (cache_enabled && util::flag_present(util::FlagId::CasDir))
        cas = std::make_unique<CasStore>(CasStore::open_default());
    // Config de build que afecta al IR pre-optimize (fold en la clave del CAS).
    // Layered: opt_level / aot_vec_width / os/arch de codegen NO entran (son
    // post-merge) -> el IR se comparte entre esas configs.  Su fingerprint
    // COMPLETO (BuildConfig::full_fingerprint) queda para el futuro cache del
    // ARTEFACTO FINAL (.velb/.exe AOT).
    uint64_t cas_config_fp = 0;
    if (cas) {
        BuildConfig bcfg;
        bcfg.asm_target_bits = opts.asm_target_bits;
        bcfg.native_poo = opts.native_poo;
        bcfg.exceptions_enabled = opts.exceptions_enabled;
        bcfg.instrument_mode = opts.instrument_mode;
        // tgt_os/tgt_arch quedan vacios: la precision por-modulo de @Target la
        // aporta cache_tgt_suffix (solo divide los modulos que USAN @Target).
        cas_config_fp = bcfg.ir_fingerprint();
    }

    /* Lo que se sabe del programa vive TODA la compilacion, no lo que dure un
     * consumidor.  Declararlo dentro de quien pregunta -- como estaba -- hacia
     * que el conocimiento naciera y muriera con la pregunta, asi que el
     * siguiente que llegara volveria a calcularlo: justo lo contrario de
     * centralizarlo. */
    analysis::asa::FactStore facts;
    /* Y su identidad, para que sobreviva a la compilacion.  Es la MISMA clave
     * con la que se identifica el modulo en el almacen por contenido: el
     * fuente, de que depende, y con que se compilo.  Cero mientras no se sepa,
     * y entonces no se toca el disco -- un fichero de hechos sin identidad no
     * se puede comprobar, y aceptar hechos de otro programa es peor que no
     * tener cache. */
    uint64_t root_facts_key = 0;

    auto compile_one_module = [&](size_t i) -> void {
        auto &pm = work[i];
        const bool is_root = (i + 1 == work.size());
        if (verbose_compile) {
            std::ostringstream ln;
            ln << "[L" << module_levels[i] << "][" << (i + 1) << "/"
               << work.size() << "] compiling " << pm.module_name
               << (is_root ? " (root)" : "") << "...\n";
            std::lock_guard<std::mutex> lk(verbose_mtx);
            std::cerr << ln.str();
        }

        // Mezclamos opts.instrument_mode (y cualquier flag futuro que
        // afecte la emision IR/bytecode) en el source_hash para que el
        // cache se invalide automaticamente al cambiar entre "trace"/"none".
        // Sin esto, builds con cache de un modo distinto producen
        // `.vel` con relocations sin resolver -> SEGV silente en runtime
        // (limitacion MC.12 documentada).
        /* La identidad del modulo es lo que DICE, no como esta escrito: se
         * keyea por sus tokens y no por los bytes del fichero.  Anadir un
         * comentario o reindentar obligaba a recompilar un modulo identico --
         * medido en el banco, tocar un comentario salia mas caro que cambiar el
         * cuerpo de una funcion.
         *
         * Con informacion de depuracion SI cuenta la linea de cada token: el
         * artefacto lleva dentro donde esta cada cosa, y un comentario metido
         * en medio las desplaza todas. */
        uint64_t source_hash = hash_de_tokens(pm.source, opts.emit_debug);
        // El COMPILADOR forma parte de lo que produjo el artefacto: un mismo
        // fuente compilado por dos versiones distintas da IR distinto.  Sin
        // esto, arreglar un bug de codegen no invalidaba nada y se seguian
        // sirviendo artefactos generados por la version anterior -- el fallo
        // parecia seguir vivo, o revivia al repoblarse la cache, y no habia
        // forma de distinguirlo de un bug real.
        source_hash ^= compiler_fingerprint_() + 0x9E3779B97F4A7C15ULL +
                       (source_hash << 6) + (source_hash >> 2);
        /* Y los mandos del entorno que cambian lo EMITIDO: el `.vxir` de un
         * modulo compilado con un pase apagado no vale para uno compilado con
         * el puesto.  Vale cero cuando no hay ninguno -- el caso normal --, asi
         * que no invalida nada de lo ya guardado. */
        if (const uint64_t env_fp = util::emitted_fingerprint()) {
            source_hash ^= env_fp + 0x9E3779B97F4A7C15ULL + (source_hash << 6) +
                           (source_hash >> 2);
        }
        if (!opts.instrument_mode.empty() && opts.instrument_mode != "none") {
            const uint64_t instrument_hash = vxi_fnv1a(opts.instrument_mode);
            source_hash ^= instrument_hash + 0x9E3779B97F4A7C15ULL +
                           (source_hash << 6) + (source_hash >> 2);
        }
        //  AOT (fix): el IR de un dep depende del MODO de POO con que se
        // baja.  En modo Full/VM las clases usan GC (newobj + gc_deref); en
        // modo AOT (`native_poo`) usan stack/heap nativo (calloc + dtor RAII).
        // Son IR DISTINTOS para el mismo source.  Si no mezclamos native_poo
        // en el source_hash, un `.vxir` cacheado por `-m vm` se reusaria en
        // `-m aot` (y viceversa) -> IR incompatible con el backend objetivo.
        // Esto solo muerde libs con clases/funciones CONCRETAS (las plantillas
        // genericas no producen IR en el dep; se monomorphizan en el root).
        if (opts.native_poo) {
            source_hash ^=
                0xA07A07A07A07A07AULL + (source_hash << 7) + (source_hash >> 3);
        }
        // HALLAZGO-2: un modulo SOLO es target-especifico si usa @Target (que
        // descarta decls distintas segun os/arch al parsear).  Para NO
        // recompilar al alternar de target, separamos su cache por FICHERO (no
        // por source_hash, que sobrescribiria el unico .vxir y forzaria
        // recompilar en cada cambio).  Asi persisten `mod.<os>-<arch>.vxir`
        // para cada target y alternar PE<->ELF es cache-hit.  Los modulos SIN
        // @Target usan el fichero unico compartido (mismo IR para todos los
        // targets).  El sufijo va vacio cuando no aplica.
        std::string cache_tgt_suffix;
        if ((!cc_tgt_os.empty() || !cc_tgt_arch.empty()) &&
            pm.source.find("@Target") != std::string::npos) {
            cache_tgt_suffix = "." + cc_tgt_os + "-" + cc_tgt_arch;
        }
        /* Compilar con la maquina de compilacion cargada da un resultado
         * DISTINTO al de compilar sin ella: sin la maquina, una funcion
         * comptime no se puede ejecutar y su valor sale vacio.  Los dos
         * resultados no pueden compartir artefacto, o la pasada buena se
         * encuentra el de la provisional y lo da por valido -- que es lo que
         * pasaba: el valor correcto se calculaba y se tiraba.
         *
         * Se marca la pasada CON maquina y no la de sin ella, que es la unica
         * que existe cuando no hay codigo de compilacion de por medio: asi el
         * caso normal conserva sus artefactos de siempre. */
        if (!util::flag_text(util::FlagId::McPrebuilt).empty())
            cache_tgt_suffix += ".mc";

        // ---- CAS global (content-addressed, cross-proyecto) ----
        // Clave de contenido del modulo (independiente de la ruta).  Se calcula
        // aqui para reusarla tambien en el write path (mas abajo).  Solo DEPS
        // (el root se ensambla, no se cachea como artefacto reusable).
        uint64_t cas_key = 0;
        /* La identidad del RAIZ, para la cache de hechos.  El almacen por
         * contenido solo la calcula para los deps -- el raiz no se guarda ahi
         * --, pero los hechos SI son suyos: se producen sobre el modulo ya
         * fusionado, que es el raiz con todo lo que arrastra.
         *
         * Se calcula igual, con la misma funcion, para que dos cosas que son la
         * misma identidad no se separen nunca.  Lo escribe SOLO la tarea del
         * raiz y se lee cuando todas han terminado, asi que no compite con
         * nadie aunque los modulos se compilen en paralelo. */
        if (is_root && pm.ast) {
            std::vector<uint64_t> dep_hashes;
            auto imps = collect_imports_(*pm.ast, &ns_to_modname);
            for (const auto &req : imps) {
                auto itd = by_name.find(req.module_name);
                if (itd != by_name.end())
                    dep_hashes.push_back(work[itd->second].vxi.abi_hash);
            }
            std::sort(dep_hashes.begin(), dep_hashes.end());
            root_facts_key = module_content_key_(
                source_hash, dep_hashes, cache_tgt_suffix, cas_config_fp);
        }
        bool cas_key_ok = false;
        if (cas && !is_root && pm.ast) {
            std::vector<uint64_t> dep_hashes;
            auto imps = collect_imports_(*pm.ast, &ns_to_modname);
            for (const auto &req : imps) {
                auto itd = by_name.find(req.module_name);
                if (itd != by_name.end())
                    dep_hashes.push_back(work[itd->second].vxi.abi_hash);
            }
            std::sort(dep_hashes.begin(), dep_hashes.end());
            cas_key = module_content_key_(source_hash, dep_hashes,
                                          cache_tgt_suffix, cas_config_fp);
            cas_key_ok = true;
            std::vector<uint8_t> blob;
            if (cas->get(cas_key, blob)) {
                std::vector<uint8_t> vb, ib;
                if (cas_unpack_module_(blob, vb, ib)) {
                    auto pr = vxi_parse(vb.data(), vb.size());
                    ir::IrModule dep_mod;
                    if (pr.ok && ir::parse_ir_module_cache(ib, dep_mod)) {
                        /* Lo que sale del almacen se comprueba igual que lo
                         * recien construido.  Es el sitio donde un IR mal
                         * guardado deja de ser un problema de quien lo guardo
                         * y pasa a ser el de quien lo usa: aqui ya no hay
                         * fuente al que volver, y lo que venga se optimiza y
                         * se emite tal cual. */
                        if (util::flag_on(util::FlagId::VerifyIr)) {
                            std::vector<std::string> ir_errs;
                            if (!ir::ir_verify(dep_mod, ir_errs)) {
                                for (const std::string &m : ir_errs)
                                    std::fprintf(stderr,
                                                 "[ir-verify cache] %s\n",
                                                 m.c_str());
                                std::fprintf(
                                    stderr,
                                    "[ir-verify cache] %zu problemas en lo "
                                    "guardado de '%s'\n",
                                    ir_errs.size(), pm.module_name.c_str());
                            }
                        }
                        pm.vxi = std::move(pr.module_);
                        /* v18: el conjunto comptime tambien por AQUi.  Hay dos
                         * caminos de cache-hit -- el del almacen global y el de
                         * los ficheros junto al fuente -- y los dos tienen que
                         * recuperarlo, o el conjunto sale distinto segun por
                         * cual se entre. */
                        if (!pm.vxi.comptime_unit_source.empty()) {
                            pm.comptime_unit_source +=
                                pm.vxi.comptime_unit_source;
                            pm.comptime_unit_names.insert(
                                pm.comptime_unit_names.end(),
                                pm.vxi.comptime_unit_names.begin(),
                                pm.vxi.comptime_unit_names.end());
                            pm.comptime_unit_hash = pm.vxi.comptime_unit_hash;
                        }
                        pm.comptime_unit_not_collected.insert(
                            pm.comptime_unit_not_collected.end(),
                            pm.vxi.comptime_unit_not_collected.begin(),
                            pm.vxi.comptime_unit_not_collected.end());
                        // abi_hash: leerlo del header del .vxi (offset 8).
                        if (vb.size() >= 16) {
                            uint64_t hh = 0;
                            for (int b = 0; b < 8; ++b)
                                hh |= static_cast<uint64_t>(vb[8 + b])
                                      << (b * 8);
                            pm.vxi.abi_hash = hh;
                        }
                        pm.ir.functions = std::move(dep_mod.functions);
                        pm.ir.static_data = std::move(dep_mod.static_data);
                        pm.ir.globals = std::move(dep_mod.globals);
                        pm.ir.native_imports =
                            std::move(dep_mod.native_imports);
                        pm.ok = true;
                        if (verbose_cache) {
                            std::ostringstream tmp;
                            tmp << "[vx-cas] hit: " << pm.canonical_path
                                << "\n";
                            std::lock_guard<std::mutex> lk(verbose_mtx);
                            std::cerr << tmp.str();
                        }
                        return; // artefacto reusado del CAS global.
                    }
                }
            }
        }

        // ---- M4: cache hit path ----
        // Solo se aplica a DEPS, no al root.  Verifica:
        //   1. Existe `<source>.vxi`.
        //   2. .vxi.source_hash == source_hash actual.
        //   3. Existe `<source>.vxir` para reusar el IR.
        // Si los 3 se cumplen, se skipea el recompile del dep.
        if (cache_enabled && !is_root) {
            const std::string vp =
                vxi_path_for_(pm.canonical_path, cache_tgt_suffix);
            const std::string ip =
                vxir_path_for_(pm.canonical_path, cache_tgt_suffix);
            std::vector<uint8_t> vbytes;
            if (read_file_bytes_(vp, vbytes)) {
                auto pr = vxi_parse(vbytes.data(), vbytes.size());
                // v13: un artefacto atado a OTRO objetivo no sirve.  Solo los
                // modulos que usan @Target llevan objetivo (el resto va con el
                // campo vacio y vale para todos), asi que esto no invalida nada
                // que no dependa de verdad del target.
                //
                // Sin esta comprobacion, un .vxi generado compilando para arm64
                // se servia tal cual en un build x86-64 y metia sus tipos en la
                // resolucion: el mismo `uintptr` acababa con dos identidades
                // (`arm64__uintptr` y `std__types__uintptr`) segun la ruta de
                // importacion, con un error de tipos incomprensible.
                if (pr.ok && !pr.module_.target.empty()) {
                    std::string tos;
                    std::string tarch;
                    vx::get_aot_condcomp_target(tos, tarch);
                    if (tos.empty()) tos = vxi_host_os_name();
                    if (tarch.empty()) tarch = vxi_host_arch_name();
                    const std::string actual = tos + "|" + tarch;
                    if (pr.module_.target != actual) {
                        if (verbose_cache) {
                            std::ostringstream tmp;
                            tmp << "[vx-cache] miss (objetivo): '"
                                << pm.module_name << "' se genero para "
                                << pr.module_.target << " y se compila para "
                                << actual << "\n";
                            std::cerr << tmp.str();
                        }
                        pr.ok = false; // fuerza recompilar con este objetivo
                    }
                }
                if (pr.ok && pr.module_.source_hash == source_hash) {
                    //  M4.ext L.13: cache transitivo.  El source_hash
                    // del modulo coincide, pero alguno de sus deps directos
                    // podria haber cambiado.  Verificar que cada DepRecord
                    // del .vxi cacheado matchea el abi_hash actual del dep
                    // (que ya viene populated en work[] por topo order).
                    /* Como importa este modulo cada dep, para recomputar la
                     * huella con EL MISMO criterio con que se guardo. */
                    std::unordered_map<std::string, const ImportRequest *>
                        como_importa;
                    std::vector<ImportRequest> imps_val;
                    if (pm.ast) {
                        imps_val = collect_imports_(*pm.ast, &ns_to_modname);
                        for (const auto &r : imps_val)
                            como_importa.emplace(r.module_name, &r);
                    }
                    bool deps_match = true;
                    for (const auto &dep_rec : pr.module_.deps) {
                        auto itd = by_name.find(dep_rec.name);
                        if (itd == by_name.end()) {
                            // El dep ya no existe -> miss.
                            deps_match = false;
                            if (verbose_cache) {
                                std::ostringstream tmp;
                                tmp << "[vx-cache] miss (transitivo): dep '"
                                    << dep_rec.name << "' no encontrado\n";
                                std::lock_guard<std::mutex> lk(verbose_mtx);
                                std::cerr << tmp.str();
                            }
                            break;
                        }
                        auto itc = como_importa.find(dep_rec.name);
                        const uint64_t actual =
                            itc != como_importa.end()
                                ? huella_de_lo_usado(work[itd->second].vxi,
                                                     *itc->second)
                                : work[itd->second].vxi.abi_hash;
                        if (actual != dep_rec.abi_hash) {
                            deps_match = false;
                            if (verbose_cache) {
                                std::ostringstream tmp;
                                tmp << "[vx-cache] miss (transitivo): dep '"
                                    << dep_rec.name
                                    << "' cambio (abi_hash old=0x" << std::hex
                                    << dep_rec.abi_hash << " new=0x" << actual
                                    << std::dec << ")\n";
                                std::lock_guard<std::mutex> lk(verbose_mtx);
                                std::cerr << tmp.str();
                            }
                            break;
                        }
                    }
                    if (deps_match) {
                        // Hash match -> intentar cargar tambien el .vxir.
                        std::vector<uint8_t> ibytes;
                        if (read_file_bytes_(ip, ibytes) && !ibytes.empty()) {
                            // BugFix M.vxir-sd: cargar el modulo COMPLETO
                            // (functions + static_data + globals).  El formato
                            // viejo (solo functions) perdia el static_data del
                            // dep -> relocaciones `code.s_*` colgantes en el
                            // `.velb` con cache caliente.  Un `.vxir` viejo
                            // falla el magic y cae a recompilar.
                            ir::IrModule dep_mod;
                            // La interfaz y el IR son dos ficheros que tienen
                            // que corresponderse.  Entre validar la primera y
                            // leer el segundo, otra compilacion simultanea del
                            // mismo modulo puede publicar una version nueva de
                            // ambos: se acabaria mezclando la interfaz que se
                            // valido con un IR que no es el suyo.  Releerla
                            // despues y comprobar que sigue siendo la misma lo
                            // descarta; ante la duda, se recompila.
                            bool par_coherente = true;
                            {
                                std::vector<uint8_t> vb2;
                                if (!read_file_bytes_(vp, vb2)) {
                                    par_coherente = false;
                                } else {
                                    auto pr2 =
                                        vxi_parse(vb2.data(), vb2.size());
                                    if (!pr2.ok ||
                                        pr2.module_.source_hash != source_hash)
                                        par_coherente = false;
                                }
                            }
                            if (par_coherente &&
                                ir::parse_ir_module_cache(ibytes, dep_mod)) {
                                pm.vxi = std::move(pr.module_);
                                /* v18: el conjunto comptime, del `.vxi`.  Un
                                 * modulo servido del cache NO se parsea, asi
                                 * que aqui no hay AST del que extraerlo: sin
                                 * esto el conjunto del proyecto salia con un
                                 * modulo de siete -- el unico recompilado -- y
                                 * nada lo decia. */
                                if (!pm.vxi.comptime_unit_source.empty()) {
                                    pm.comptime_unit_source +=
                                        pm.vxi.comptime_unit_source;
                                    pm.comptime_unit_names.insert(
                                        pm.comptime_unit_names.end(),
                                        pm.vxi.comptime_unit_names.begin(),
                                        pm.vxi.comptime_unit_names.end());
                                    pm.comptime_unit_hash =
                                        pm.vxi.comptime_unit_hash;
                                }
                                pm.comptime_unit_not_collected.insert(
                                    pm.comptime_unit_not_collected.end(),
                                    pm.vxi.comptime_unit_not_collected.begin(),
                                    pm.vxi.comptime_unit_not_collected.end());
                                pm.ir.functions = std::move(dep_mod.functions);
                                pm.ir.static_data =
                                    std::move(dep_mod.static_data);
                                pm.ir.globals = std::move(dep_mod.globals);
                                // BugFix M.ni-cache: restaurar tambien los
                                // native_imports del dep en el cache-hit.  Sin
                                // esto, el merge cross-modulo (mas abajo) no
                                // tiene que propagar y el linker deja simbolos
                                // colgantes (p.ej. `vrt:inline_asm_exec` /
                                // `vrt:naked_fnaddr` de un dep con cuerpos
                                // @Naked/inline-asm) -> RelocationError con el
                                // .vxir caliente (frio compilaba bien).
                                // parse_ir_module_cache ya los deserializo en
                                // dep_mod; solo faltaba trasladarlos a pm.ir.
                                pm.ir.native_imports =
                                    std::move(dep_mod.native_imports);
                                pm.ok = true;
                                // Seed del CAS global desde un HIT del cache
                                // por-path: asi el primer build con .vxir
                                // caliente (pero CAS frio) puebla el store
                                // global para otros proyectos/maquinas, no solo
                                // el build que compila desde cero.  El .vxi
                                // valido ya confirmo que corresponde al
                                // contenido actual -> cas_key es la clave
                                // correcta para este artefacto.
                                if (cas && cas_key_ok)
                                    (void)cas->put(
                                        cas_key,
                                        cas_pack_module_(vbytes, ibytes));
                                if (verbose_cache) {
                                    std::ostringstream tmp;
                                    tmp << "[vx-cache] hit: "
                                        << pm.canonical_path << "\n";
                                    std::lock_guard<std::mutex> lk(verbose_mtx);
                                    std::cerr << tmp.str();
                                }
                                return; // skip rest of compile (lambda)
                            }
                        }
                    }
                }
            }
            if (verbose_cache) {
                std::ostringstream tmp;
                tmp << "[vx-cache] miss: " << pm.canonical_path << "\n";
                std::lock_guard<std::mutex> lk(verbose_mtx);
                std::cerr << tmp.str();
            }
        }

        // ---- Compile path (cache miss o root) ----
        //  M.5: si es DEP (no root), mangle top-level fns y globals
        // con prefijo `<module>__` para evitar colisiones cross-module.
        // El root NO se mangla (mantiene `main` y demas nombres tal cual).
        if (!is_root) {
            mangle_top_level_(*pm.ast, pm.module_name);
        }

        // NS.2: aplanar los `namespace X;` inline de ESTE modulo (root o dep).
        // mangle_top_level_ (arriba) solo toca las decls anonimas top-level (no
        // recorre NamespaceDecl), asi que no hay doble-mangle: las decls
        // namespaced se manglan por su NAMESPACE (mylib__X), las anonimas de un
        // dep por su MODULO (lib__Y).  Se registran en el TypeChecker para que
        // el acceso qualified (mylib.helper()) resuelva dentro del modulo.
        auto inline_namespaces = flatten_namespaces(*pm.ast);

        /* El conjunto comptime de ESTE modulo, con los nombres ya mangled.  El
         * volcado equivalente del camino de fichero suelto
         * (`compile_vx_source`) no sirve aqui: los modulos que de verdad tienen
         * comptime -- la stdlib
         * -- llegan por el camino de PROYECTO, asi que sin esto la medida se
         * tomaba sobre casos sinteticos y la granularidad del artefacto se
         * elegia por arquitectura en vez de por dato.  Solo diagnostico. */
        {
            const ComptimeUnit cu = collect_comptime_unit(*pm.ast, pm.source);
            if (!cu.empty()) {
                /* Los conjuntos de TODOS los modulos se CONCATENAN en uno solo:
                 * el trabajo comptime esta concentrado (medido: 6 de las 8
                 * raices de este proyecto viven en un unico modulo), asi que
                 * repartirlo en artefactos por modulo no tendria de que morder,
                 * y ademas cada compilacion paga un suelo fijo (~8.5 ms) que se
                 * multiplicaria por el numero de artefactos. */
                /* Con su `namespace` delante.  El conjunto de cada modulo
                 * se concatena con los demas en UN solo texto, asi que sin el
                 * todos caen en el mismo espacio de nombres y chocan entre si
                 * (`nullptr`, `ANCHO`, `UMBRAL_*`...).  No sale de las decls
                 * porque a estas alturas los namespaces ya estan APLANADOS: el
                 * nombre lo tiene el aplanado, que es quien lo sabe. */
                /* En el MODULO, no en el acumulado del proyecto: esta lambda
                 * corre en hasta ocho hilos a la vez y `res` es uno solo.  Un
                 * `+=` sobre la misma `std::string` desde dos hilos revienta su
                 * bufer -- el compilador moria con 0xC0000374 sin imprimir
                 * nada, con victima distinta cada vuelta.  Cada modulo llena lo
                 * suyo y la suma se hace despues del bucle, en orden de indice,
                 * que ademas la vuelve determinista.  Con el `namespace`
                 * delante: el texto tiene que sostenerse solo venga de donde
                 * venga. */
                for (const auto &fns : inline_namespaces) {
                    if (fns.name.empty()) continue;
                    pm.comptime_unit_source += "namespace ";
                    pm.comptime_unit_source += fns.name;
                    pm.comptime_unit_source += ";";
                    pm.comptime_unit_source.push_back(static_cast<char>(10));
                    break;
                }
                pm.comptime_unit_source += cu.unit_source;
                pm.comptime_unit_hash = cu.content_hash;
                for (const auto *lista :
                     {&cu.comptime_fns, &cu.macros, &cu.helper_deps})
                    pm.comptime_unit_names.insert(pm.comptime_unit_names.end(),
                                                  lista->begin(), lista->end());
                pm.comptime_unit_not_collected.insert(
                    pm.comptime_unit_not_collected.end(),
                    cu.not_collected.begin(), cu.not_collected.end());
                if (util::flag_on(util::FlagId::DumpComptimeUnit)) {
                    std::cerr << "[comptime-unit] modulo " << pm.module_name
                              << "\n";
                    dump_comptime_unit(cu, std::cerr);
                }
                /* El TEXTO extraido, a un fichero por modulo.  Cuando la suma
                 * no compila hay que poder LEER lo que se extrajo: reproducirlo
                 * con fuentes de juguete no lo consigue -- se intento con
                 * `namespace` y con la concatenacion de dos modulos, y los dos
                 * compilan bien. */
                if (!util::flag_text(util::FlagId::VolcarUnidad).empty()) {
                    const std::string &d =
                        util::flag_text(util::FlagId::VolcarUnidad);
                    std::error_code vec;
                    std::filesystem::create_directories(d, vec);
                    /* Con la HUELLA de su ruta en el nombre.  El nombre de
                     * modulo es el ultimo segmento del path, y hay dos
                     * `x86_64.vx` -- el de tipos y el de memoria --, asi que
                     * uno pisaba al otro y el volcado enseñaba un modulo
                     * distinto del que se estaba mirando. */
                    std::ofstream f(
                        std::string(d) + "/" + pm.module_name + "_" +
                        std::to_string(
                            static_cast<unsigned long long>(
                                vxi_fnv1a(pm.canonical_path.data(),
                                          pm.canonical_path.size())) %
                            100000ULL) +
                        ".unidad.vx");
                    if (f) f << cu.unit_source;
                }
            } else if (!cu.not_collected.empty()) {
                /* Conjunto VACIO pero con comptime dentro de un tipo.  Sin esta
                 * rama, este caso y "el modulo no tiene nada comptime" se leen
                 * IGUAL desde fuera, y son opuestos: aqui el artefacto se
                 * quedaria sin algo que hace falta.  No saber es un resultado y
                 * se dice por que. */
                pm.comptime_unit_not_collected.insert(
                    pm.comptime_unit_not_collected.end(),
                    cu.not_collected.begin(), cu.not_collected.end());
                if (util::flag_on(util::FlagId::DumpComptimeUnit)) {
                    std::cerr << "[comptime-unit] modulo " << pm.module_name
                              << "\n";
                    dump_comptime_unit(cu, std::cerr);
                }
            }
        }

        pm.tc = std::make_unique<TypeChecker>(*pm.ast, pm.diags);
        /* El conjunto comptime ya compilado, en memoria: TODOS los modulos lo
         * ven desde su primer call site.  Es lo que evita que un modulo se
         * compile antes de que exista la maquina que genera parte de su
         * codigo -- y salga con cuerpos de `asm` vacios. */
        pm.tc->set_comptime_artifact(opts_modulos.comptime_artifact);

        for (const auto &kv : target_skipped_proyecto) {
            for (const auto &spec : kv.second)
                pm.tc->register_target_skipped(kv.first, spec);
        }

        for (const auto &ins : inline_namespaces) {
            const uint32_t ns_idx =
                pm.tc->register_imported_namespace(ins.name, ins.name);
            for (const auto &sym : ins.symbols) {
                TypeChecker::ImportedNamespace::Sym ns_sym;
                ns_sym.kind =
                    (sym.kind == FlattenedNamespace::Sym::Function)
                        ? 0
                        : (sym.kind == FlattenedNamespace::Sym::Type ? 2 : 1);
                ns_sym.mangled_label = sym.mangled_label;
                pm.tc->register_namespace_symbol(ns_idx, sym.public_name,
                                                 std::move(ns_sym));
                // NS.2 round-trip: recordar que este mangled_label pertenece al
                // namespace declarado `ins.name` con nombre publico
                // `sym.public_name`, para el export al .vxi.
                pm.tc->register_declared_ns_symbol(sym.mangled_label, ins.name,
                                                   sym.public_name);
            }
        }

        // ANTES de typecheck: inyectar simbolos de los deps via .vxi.
        // Dos modos:
        //   - `import "x" only A, B;`   -> inyecta A, B directos en scope.
        //   - `import "x" [as alias];`  -> registra namespace para `x.A` o
        //                                   `alias.A` ( M.7).
        auto imports = collect_imports_(*pm.ast, &ns_to_modname);

        // LANG.fix-3: pre-importar las .vxi de los deps TRANSITIVOS
        // antes de procesar los imports explicitos.  Si main tiene
        // `import "outer";` + outer depende de inner, main necesita
        // inner.vxi en su TC ANTES de procesar outer (porque outer.vxi
        // referencia tipos como `inner__Bar`).  Sin esto el resolver de
        // fields falla con "void" para tipos del dep transitivo.
        //
        // Estrategia: recorrer la cadena topo de los deps directos y
        // pre-importar cada dep que NO este ya en los imports explicitos.
        // Solo registramos namespaces (no inyectamos al scope) para no
        // contaminar el namespace global del consumer.
        // Recolectar deps TRANSITIVOS (no incluidos en imports explicitos)
        // y pre-importarlos como namespaces silenciosos ANTES del loop de
        // imports explicitos.  Asi cuando outer.vxi se procesa, las
        // referencias a tipos de inner ya estan en class_layouts_ via la
        // pre-importacion de inner.  Cada namespace solo se registra una
        // vez (los explicitos van por el loop normal mas abajo).
        // Recolectar TODOS los deps (directos + transitivos) y pre-importar
        // en orden topo inverso (mas profundo primero).  El register_*
        // usa operator[] (overwrite) y register_imported_namespace ahora
        // dedupea por local_name, asi que registrar el mismo dep dos
        // veces es no-op.

        // NS.3: PackageId del consumidor + helper para filtrar los simbolos
        // `internal` de un dep que pertenece a OTRO paquete (package_id
        // distinto, ambos no vacios).  Dentro del mismo paquete, internal es
        // visible (no se filtra).  El storage lo aporta el caller (vive lo que
        // dure el uso del &const devuelto).
        const std::string consumer_pkgid = (i < module_pkgid_override.size() &&
                                            !module_pkgid_override[i].empty())
                                               ? module_pkgid_override[i]
                                               : project_package_id;
        auto filter_internal_ = [&](const VxiModule &v,
                                    VxiModule &storage) -> const VxiModule & {
            if (consumer_pkgid.empty() || v.package_id.empty() ||
                consumer_pkgid == v.package_id) {
                return v; // mismo paquete (o anonimo) -> internal visible
            }
            bool any_internal = false;
            for (const auto &s : v.symbols)
                if (s.is_internal) {
                    any_internal = true;
                    break;
                }
            if (!any_internal) return v;
            storage = v;
            auto &syms = storage.symbols;
            syms.erase(std::remove_if(
                           syms.begin(), syms.end(),
                           [](const VxiSymbol &s) { return s.is_internal; }),
                       syms.end());
            return storage;
        };
        // Si una dependencia no compilo, este modulo tampoco vale.  Sin esta
        // comprobacion se compilaba igual -- con la superficie del dep VACIA --
        // y, lo que es peor, se PERSISTIA su interfaz: la siguiente compilacion
        // hacia cache hit sobre esa interfaz degradada y el fallo sobrevivia al
        // arreglo del dep.  Solo se nota si el import no lleva `only`, porque
        // entonces no hay ningun simbolo concreto que echar en falta.
        for (const auto &req : imports) {
            const size_t dep_idx = resolve_import_module_(req, by_name, by_ns);
            if (dep_idx >= work.size() || work[dep_idx].ok) continue;
            pm.diags.error(req.loc, "no puedo usar '" +
                                        (req.ns_path.empty() ? req.module_name
                                                             : req.ns_path) +
                                        "': no ha compilado");
            pm.ok = false;
            return;
        }
        {
            std::unordered_set<std::string> seen;
            std::vector<std::string> queue;
            for (const auto &req : imports) {
                if (seen.insert(req.module_name).second) {
                    queue.push_back(req.module_name);
                }
            }
            for (size_t qi = 0; qi < queue.size(); ++qi) {
                const std::string &mn = queue[qi];
                auto itd = by_name.find(mn);
                if (itd == by_name.end()) continue;
                const ProjectModuleWork &transit = work[itd->second];
                for (const auto &de : transit.vxi.deps) {
                    if (seen.insert(de.name).second) {
                        queue.push_back(de.name);
                    }
                }
            }
            for (auto it = queue.rbegin(); it != queue.rend(); ++it) {
                const std::string &mn = *it;
                auto itd = by_name.find(mn);
                if (itd == by_name.end()) continue;
                const ProjectModuleWork &transit = work[itd->second];
                VxiModule tstore;
                register_namespace_for_import(
                    *pm.tc, mn, mn, filter_internal_(transit.vxi, tstore));
            }
        }

        for (auto &req : imports) {
            // Resolver el dep por NAMESPACE completo (unico) cuando el import
            // es por-namespace: evita la colision de module_name corto (dos
            // "x86_64" de linux vs windows).  Fallback a by_name (por-path).
            size_t dep_idx = 0;
            bool dep_found = false;
            if (req.by_namespace && !req.ns_path.empty()) {
                auto itns = by_ns.find(req.ns_path);
                if (itns != by_ns.end()) {
                    dep_idx = itns->second;
                    dep_found = true;
                }
            }
            if (!dep_found) {
                auto itd = by_name.find(req.module_name);
                if (itd == by_name.end()) {
                    // Un import que no resuelve se saltaba en silencio: no se
                    // inyectaba ninguno de sus simbolos y la compilacion
                    // seguia como si nada, fallando mucho mas tarde y en otro
                    // sitio -- o peor, dando un resultado equivocado.  Quien
                    // escribio el import merece enterarse aqui.
                    SourceLoc iloc;
                    iloc.file = pm.canonical_path;
                    /* Al saco del MODULO, que es el que el bucle de mas abajo
                     * vuelca en el del proyecto.  Escribir directamente en el
                     * global desde aqui es lo mismo que hacia el conjunto
                     * comptime: esta lambda corre en varios hilos y el saco es
                     * uno solo. */
                    pm.diags.error(
                        std::move(iloc),
                        "no se encuentra el modulo '" + req.module_name +
                            "' que pide un import; sus simbolos no se han "
                            "importado");
                    pm.ok = false;
                    continue;
                }
                dep_idx = itd->second;
            }
            const ProjectModuleWork &dep = work[dep_idx];
            VxiModule dep_filtered_storage;
            const VxiModule &dep_vxi =
                filter_internal_(dep.vxi, dep_filtered_storage);
            // Los modulos de los que el dep importa.  Sus plantillas viajan
            // como texto y se re-parsean aqui, asi que sus firmas pueden
            // nombrar tipos que el dep trajo de un tercero (`usize`, de
            // `std.types`); sin esto ese nombre no existe al re-parsear y el
            // parametro se queda en `void`.
            std::vector<const VxiModule *> dep_alias_srcs;
            for (const auto &dr : dep_vxi.deps) {
                auto itx = by_name.find(dr.name);
                if (itx != by_name.end())
                    dep_alias_srcs.push_back(&work[itx->second].vxi);
            }
            // `only *` (glob): expandir a TODOS los simbolos publicos del dep,
            // como si el usuario hubiera listado cada uno (nombre directo, sin
            // rename).  Se hace aqui -- no en el mapeo AST -- porque necesita
            // el .vxi del dep (la lista de sus simbolos).  Con `public import`
            // los re-exporta (req.is_public_reexport se propaga a
            // mark_imported).
            if (req.only_all && req.only_symbols.empty()) {
                // Inyectar TODOS los simbolos publicos del dep.  El .vxi ya
                // filtro los sinteticos del compilador, asi que NO descartamos
                // por prefijo `_`: un `public __NR_write` (convencion POSIX) es
                // legitimo y debe entrar al scope.
                for (const auto &sym : dep_vxi.symbols) {
                    if (sym.name.empty()) continue;
                    req.only_symbols.push_back({sym.name, ""});
                }
            }
            if (req.is_plain) {
                // M.7: registrar namespace.
                register_namespace_for_import(*pm.tc, req.local_name,
                                              req.module_name, dep_vxi);
                // #cross-module-generics: inyectar TODAS las plantillas del
                // dep bajo el namespace (`lib.Caja<i64>`).
                inject_generic_templates_from_vxi(
                    *pm.tc, dep_vxi, /*wanted=*/{}, req.local_name,
                    /*alias_unqualified=*/{}, dep_alias_srcs);
                // Namespace PARCIAL: registrar tambien los simbolos de los
                // OTROS ficheros que declaran el mismo `namespace X;` (p.ej.
                // std.types + std/types/x86_64.vx).  Sin esto, `import
                // std.types` solo veia el primer fichero y los tipos del arch
                // file (`std.types.uintptr`) no resolvian.
                if (req.by_namespace && !req.ns_path.empty()) {
                    auto ita = ns_to_all_modnames.find(req.ns_path);
                    if (ita != ns_to_all_modnames.end()) {
                        for (const auto &other_mn : ita->second) {
                            if (other_mn == req.module_name) continue;
                            auto ito = by_name.find(other_mn);
                            if (ito == by_name.end()) continue;
                            VxiModule other_store;
                            const VxiModule &other_vxi = filter_internal_(
                                work[ito->second].vxi, other_store);
                            register_namespace_for_import(
                                *pm.tc, req.local_name, other_mn, other_vxi);
                            inject_generic_templates_from_vxi(
                                *pm.tc, other_vxi, /*wanted=*/{},
                                req.local_name, /*alias_unqualified=*/{},
                                dep_alias_srcs);
                        }
                    }
                }
                // M.reexport ext: para `public import "base";` (sin only),
                // inyectar TAMBIEN cada simbolo publico del dep como si
                // fuera un `only A, B, ...` sintetico Y marcarlo
                // re-export.  Sin esto, `mid` con `public import "base"`
                // no reexpone ningun simbolo de base a sus propios
                // consumidores.
                if (req.is_public_reexport) {
                    std::vector<TypeChecker::VxiOnlyEntry> synth_only;
                    for (const auto &sym : dep_vxi.symbols) {
                        // skip simbolos privados o synthetic (mangled).
                        if (sym.name.empty()) continue;
                        if (sym.name[0] == '_') continue;
                        synth_only.push_back({sym.name, ""});
                    }
                    // Cualificar por NAMESPACE, no por fichero: en un namespace
                    // parcial todos sus ficheros deben dar la MISMA identidad.
                    const std::string qual =
                        (req.by_namespace && !req.ns_path.empty())
                            ? flatten_ns_(req.ns_path)
                            : req.module_name;
                    auto missing = import_vxi_into_typechecker_with_missing(
                        *pm.tc, dep_vxi, synth_only, qual);
                    (void)missing; // best-effort; los privados ya fueron
                                   //              filtrados al construir el
                                   //              .vxi.
                    for (const auto &os : synth_only) {
                        pm.tc->mark_imported(os.name, /*is_reexport=*/true);
                    }
                    // Re-exportar TAMBIEN las plantillas genericas / comptime
                    // fns / @Macros: viven en `generic_templates` (texto
                    // fuente), NO en `symbols`.  Sin esto, `public import
                    // std.comptime. basics` no reexpone `source`/`inject`
                    // (comptime fns) -> `import std.comptime only source` daba
                    // "no exporta source". La rama is_plain de arriba YA las
                    // inyecto en este modulo (inject_generic_templates_from_vxi
                    // con ns_prefix=local); aqui solo las anyadimos a sus
                    // exports marcadas re-export para que floten a su .vxi.  NO
                    // re-inyectar (doble inject -> "redefinicion de comptime
                    // fn").
                    if (!dep_vxi.generic_templates.empty()) {
                        for (const auto &g : dep_vxi.generic_templates) {
                            if (g.name.empty() || g.name[0] == '_') continue;
                            ast::GenericTemplateExport tex;
                            tex.name = g.name;
                            tex.kind = g.kind;
                            tex.source = g.source;
                            tex.is_public = true;
                            pm.tc->add_reexported_generic_template(
                                std::move(tex));
                            pm.tc->mark_imported(g.name, /*is_reexport=*/true);
                        }
                    }
                }
            } else {
                // #cross-module-generics: inyectar las plantillas del dep
                // (sin namespace -> nombre directo `Caja<i64>`).  Se inyectan
                // TODAS (no solo las listadas en `only`) para que las
                // dependencias entre plantillas se satisfagan (p.ej. una fn
                // generica con bound de un `concept` del mismo modulo).  Son
                // inertes si no se usan (se monomorphizan solo on-use).  Se
                // hace ANTES de la inyeccion de simbolos para que el template
                // exista en mod_.decls cuando run() registre los templates.
                // Los nombres listados en `only` que sean comptime/macro fns
                // deben quedar invocables SIN cualificar (como una fn regular
                // via only) -> pasarlos como alias_unqualified.
                // Nota: el matching en el inject es por el nombre ORIGINAL del
                // decl (`nm`), por eso usamos os.name.  El `as <rename>` de un
                // macro invocado sin cualificar es un caso raro no cubierto
                // aun.
                std::unordered_set<std::string> only_alias;
                for (const auto &os : req.only_symbols)
                    only_alias.insert(os.name);
                inject_generic_templates_from_vxi(*pm.tc, dep_vxi,
                                                  /*wanted=*/{},
                                                  /*ns_prefix=*/"", only_alias,
                                                  dep_alias_srcs);
                // M2.d: inyeccion directa via only.  M6.a.3: usar la variante
                // que devuelve los missing para emitir diagnostico claro.
                // Cualificar por NAMESPACE, no por fichero (ver flatten_ns_).
                const std::string qual =
                    (req.by_namespace && !req.ns_path.empty())
                        ? flatten_ns_(req.ns_path)
                        : req.module_name;
                auto missing = import_vxi_into_typechecker_with_missing(
                    *pm.tc, dep_vxi, req.only_symbols, qual);
                // Namespace PARCIAL: un `import std.types only uintptr`
                // resuelve `req.module_name` al PRIMER fichero del namespace
                // (p.ej. arm64), donde el simbolo puede estar @Target-inactivo
                // -> queda en `missing`.  Reintentar los que faltan contra los
                // OTROS ficheros del mismo `namespace X;` (p.ej.
                // std/types/x86_64.vx), igual que el plain-import de arriba.
                // Sin esto, `only X` de un namespace multi-fichero fallaba con
                // "no exporta 'X'".
                if (!missing.empty() && req.by_namespace &&
                    !req.ns_path.empty()) {
                    auto ita = ns_to_all_modnames.find(req.ns_path);
                    if (ita != ns_to_all_modnames.end()) {
                        // `retry` = los only_symbols que aun faltan.
                        std::vector<TypeChecker::VxiOnlyEntry> retry;
                        for (const auto &os : req.only_symbols) {
                            for (const auto &m : missing) {
                                if (os.name == m) {
                                    retry.push_back(os);
                                    break;
                                }
                            }
                        }
                        for (const auto &other_mn : ita->second) {
                            if (retry.empty()) break;
                            if (other_mn == req.module_name) continue;
                            auto ito = by_name.find(other_mn);
                            if (ito == by_name.end()) continue;
                            VxiModule other_store;
                            const VxiModule &other_vxi = filter_internal_(
                                work[ito->second].vxi, other_store);
                            // Mismo cualificador que arriba: los ficheros
                            // restantes del namespace parcial NO pueden dar una
                            // identidad distinta a la del primero.
                            auto still =
                                import_vxi_into_typechecker_with_missing(
                                    *pm.tc, other_vxi, retry, qual);
                            // reducir retry a los que aun faltan tras este
                            // fichero
                            std::vector<TypeChecker::VxiOnlyEntry> next_retry;
                            for (const auto &os : retry) {
                                for (const auto &m : still) {
                                    if (os.name == m) {
                                        next_retry.push_back(os);
                                        break;
                                    }
                                }
                            }
                            retry = std::move(next_retry);
                        }
                        // el `missing` final = lo que aun no aparecio en NINGUN
                        // fichero del namespace.
                        std::vector<std::string> final_missing;
                        for (const auto &os : retry)
                            final_missing.push_back(os.name);
                        missing = std::move(final_missing);
                    }
                }
                // #cross-module-generics: un nombre `only` puede ser una
                // PLANTILLA generica (no esta en symbols sino en
                // generic_templates) -> no es "missing".
                std::unordered_set<std::string> gen_names;
                for (const auto &g : dep_vxi.generic_templates)
                    gen_names.insert(g.name);
                for (const auto &m : missing) {
                    if (gen_names.count(m)) continue; // es un template: OK
                    std::string msg = "el modulo '";
                    msg += req.module_name;
                    msg += "' no exporta '";
                    msg += m;
                    msg += "' (es privado o no existe)";
                    pm.diags.error(req.loc, std::move(msg));
                }
                // Recalcular missing real (excluyendo templates) para el
                // early-abort de abajo.
                {
                    std::vector<std::string> real_missing;
                    for (const auto &m : missing)
                        if (!gen_names.count(m)) real_missing.push_back(m);
                    missing = std::move(real_missing);
                }
                if (!missing.empty()) {
                    pm.ok = false;
                    return;
                }
                //  M.L23: marcar cada simbolo importado como
                // (imported, is_reexport).  El export del .vxi del
                // modulo actual filtra los importados NO marcados como
                // public.
                for (const auto &os : req.only_symbols) {
                    const std::string &local =
                        os.rename.empty() ? os.name : os.rename;
                    pm.tc->mark_imported(local, req.is_public_reexport);
                }
            }
        }

        // NS.6-ext: re-apendear los metodos de `extension`/`impl` que
        // declararon los deps (directos + transitivos) al layout del tipo
        // destino en este consumidor.  Asi `obj.metodo()` resuelve cross-modulo
        // (dispatch estatico al mangled_label del .velb del dep).  Los layouts
        // de los tipos importados ya estan registrados (import loop de arriba).
        {
            std::unordered_set<std::string> seen;
            std::vector<std::string> queue;
            for (const auto &req : imports)
                if (seen.insert(req.module_name).second)
                    queue.push_back(req.module_name);
            for (size_t qi = 0; qi < queue.size(); ++qi) {
                auto itd = by_name.find(queue[qi]);
                if (itd == by_name.end()) continue;
                for (const auto &de : work[itd->second].vxi.deps)
                    if (seen.insert(de.name).second) queue.push_back(de.name);
            }
            for (const auto &mn : queue) {
                auto itd = by_name.find(mn);
                if (itd == by_name.end()) continue;
                for (const auto &em : work[itd->second].vxi.ext_methods) {
                    pm.tc->inject_imported_ext_method(
                        em.target_key, em.target_is_class, em.name,
                        em.return_type, em.param_types, em.mangled_label);
                }
            }
        }

        if (!pm.tc->run()) {
            pm.ok = false;
            return;
        }

        //  M.L26: warning de imports sin usar.  Tras el check, el
        // TypeChecker tiene un set de nombres referenciados.  Cada
        // `import "lib" only A, B, C;` declara nombres en el scope
        // global; si alguno no aparece en @c referenced_names() , el
        // usuario lo importo pero no lo uso -> warning suave (NO error;
        // imports pueden documentar API surface intencionalmente).
        // Solo aplicable al root (no a deps; sus imports solo importan
        // si el dep luego los reexporta, pero el reexport plain no esta
        // soportado todavia en MVP).  Cualquier modulo con @c warning
        // ya promovido se cubrira en M.reexport.
        if (is_root) {
            const auto &refs = pm.tc->referenced_names();
            for (const auto &req : imports) {
                if (req.is_plain) {
                    // Plain `import "x";` registra @c x como Symbol::Namespace.
                    // Si el namespace alias nunca se accedio, warning.
                    if (refs.find(req.local_name) == refs.end()) {
                        std::string msg = "import '";
                        msg += req.module_name;
                        if (!req.local_name.empty() &&
                            req.local_name != req.module_name) {
                            msg += "' as '";
                            msg += req.local_name;
                        }
                        msg += "' no se usa";
                        pm.diags.warning(req.loc, std::move(msg));
                    }
                } else {
                    // `only A, B`: chequear cada A, B individualmente.
                    for (const auto &os : req.only_symbols) {
                        const std::string &local =
                            os.rename.empty() ? os.name : os.rename;
                        if (refs.find(local) == refs.end()) {
                            std::string msg = "simbolo importado '";
                            msg += local;
                            msg += "' de '";
                            msg += req.module_name;
                            msg += "' no se usa";
                            pm.diags.warning(req.loc, std::move(msg));
                        }
                    }
                }
            }
        }

        Lowering lo(*pm.ast, *pm.tc, pm.diags);
        lo.avisar_asm_opaco_ = opts.emit_ir_preopt;
        //  AOT multi-modulo: propagar POO/strings nativos a TODOS los
        // modulos del proyecto (no solo al single-file).  Sin esto los deps
        // se bajaban en modo Full (GC) y el IR mergeado no era AOT-compatible.
        lo.set_native_poo(opts.native_poo);
        // Ancho del target para el inline-asm que GENERA el lowering (el
        // detector de features de CPU, los helpers @Naked...).  El camino de
        // fichero suelto ya lo propagaba; este no, asi que al compilar un
        // proyecto para x86-32 se emitian registros de 64 bits y el ensamblado
        // fallaba, tumbando la funcion entera al interprete.
        lo.set_asm_target_bits(opts.asm_target_bits);
        // CPU dispatch Inc 5b: aplicar los @HelperOverride agregados (root +
        // imports, ya resueltos por precedencia en el pre-pase) SOLO al
        // modulo ROOT, que es quien emite __vx_memcpy_init / __vx_strdisp_init.
        // El fp de cada init apunta entonces a la fn del override (que puede
        // vivir en un modulo importado; su simbolo se resuelve en el IR
        // mergeado via el reloc fnsym del LABEL_ADDR).
        if (is_root) {
            auto itmc = aot_helper_override_syms.find("memcpy");
            if (itmc != aot_helper_override_syms.end())
                lo.set_memcpy_override(itmc->second);
            auto itsc = aot_helper_override_syms.find("strcmp");
            if (itsc != aot_helper_override_syms.end())
                lo.set_strcmp_override(itsc->second);
            auto itsl = aot_helper_override_syms.find("strlen");
            if (itsl != aot_helper_override_syms.end())
                lo.set_strlen_override(itsl->second);
        }
        if (!opts.instrument_mode.empty() && opts.instrument_mode != "none") {
            lo.set_instrument_mode(opts.instrument_mode);
        }
        const std::string mod_name = pm.module_name;
        if (!lo.run(pm.ir, mod_name)) {
            pm.ok = false;
            return;
        }

        // Grafo de conocimiento del programa, por modulo.  Cada uno aporta sus
        // tipos y los simbolos que emitio; el mapa del artefacto se compone
        // despues con lo de todos, porque el ejecutable final los contiene a
        // todos y una direccion suya puede caer en cualquiera.
        {
            VxdbgEmitStats st;
            std::string dbg_err;
            std::vector<vxdbg::SourceExtent> spans;
            spans.reserve(lo.emitted_spans().size());
            for (const auto &e : lo.emitted_spans())
                spans.push_back({e.symbol, e.line, e.column, e.length});
            if (!emit_vxdbg_source(*pm.tc, lo.emitted_symbols(), spans,
                                   pm.canonical_path, pm.source, opts.vxdbg_dir,
                                   st, dbg_err)) {
                std::cerr << "[vxdbg] no se pudo emitir " << pm.canonical_path
                          << ": " << dbg_err << "\n";
            }
            pm.vxdbg_symbols = st.symbol_links;
            pm.vxdbg_spans = st.spans;
            /* La huella del mapa de este modulo viaja en su `.vxi`.  Es lo que
             * permite que, cuando el modulo se sirva desde cache y no se baje,
             * siga aportando su grafo al artefacto: sin esto sus simbolos no
             * llegaban al mapa y su grafo se quedaba sin sostener. */
            pm.vxi.vxdbg_map_lo = st.module_map.lo;
            pm.vxi.vxdbg_map_hi = st.module_map.hi;
        }

        // -ffp-contract=off (CLI, per-modulo): fuerza IEEE estricto (sin FMA)
        // en cada funcion del modulo.  Mismo criterio que compile_vx_source; se
        // aplica aqui (misma TU que el optimizer del proyecto) para no depender
        // del global mutable duplicado entre vm.exe/DLL/vmcore.
        if (!opts.fp_contract) {
            for (auto &fn : pm.ir.functions)
                fn.fp_contract = false;
        }

        //  M.5: export con strip_prefix = `<module>__` para que el
        // .vxi exponga nombres publicos sin el mangle.  El consumidor
        // importa "sumar" pero la FunctionSig lleva mangled_label="lib__sumar".
        const std::string strip_prefix =
            is_root ? std::string() // root: sin prefix (no se exporta)
                    : (pm.module_name + "__");
        export_typechecker_to_vxi(*pm.tc, source_hash, pm.vxi, strip_prefix);
        /* v18: y el conjunto comptime de ESTE modulo, para que el `.vxi` lo
         * lleve.  Extraerlo necesita el AST, y la proxima compilacion que sirva
         * este modulo del cache no lo va a parsear: si no viaja aqui, se
         * pierde. */
        pm.vxi.comptime_unit_source = pm.comptime_unit_source;
        pm.vxi.comptime_unit_hash = pm.comptime_unit_hash;
        pm.vxi.comptime_unit_names = pm.comptime_unit_names;
        pm.vxi.comptime_unit_not_collected = pm.comptime_unit_not_collected;

        //  NS.3: estampar el PackageId en el .vxi del modulo.  Por defecto
        // el del proyecto (vx.toml); si el modulo declaro `namespace X
        // @id(..)`, ese override gana (identidad ABI por-namespace).  El
        // override se capturo antes del flatten (que borra el NamespaceDecl del
        // AST).
        pm.vxi.package_id = (i < module_pkgid_override.size() &&
                             !module_pkgid_override[i].empty())
                                ? module_pkgid_override[i]
                                : project_package_id;

        // v13: atar el .vxi al OBJETIVO, pero solo si el modulo usa @Target --
        // lo que declara depende entonces del target y su artefacto no vale
        // para otro.  Los demas (la inmensa mayoria) siguen con un unico .vxi
        // compartido, de modo que cambiar de objetivo no recompila la stdlib
        // entera.
        //
        // Sin esto, un .vxi generado compilando para arm64 se seguia sirviendo
        // en un build x86-64 y metia sus tipos en la resolucion: el mismo
        // `uintptr` acababa con dos identidades segun la ruta de importacion.
        if (pm.ast && pm.ast->uses_conditional_target) {
            // Misma fuente de verdad que @Target: el override de cross-target
            // si lo hay, y el host si no.  Dos lecturas distintas del objetivo
            // volverian a desincronizar artefacto y compilacion.
            std::string tos;
            std::string tarch;
            vx::get_aot_condcomp_target(tos, tarch);
            if (tos.empty()) tos = vxi_host_os_name();
            if (tarch.empty()) tarch = vxi_host_arch_name();
            pm.vxi.target = tos + "|" + tarch;
        }

        //  M4.ext L.13: poblar dep table con los (name, abi_hash) de
        // los deps directos del modulo.  El loader del cache verifica
        // estos hashes al cache hit para invalidacion transitiva: si
        // cualquier dep cambio su .vxi (distinto abi_hash), este modulo
        // tambien debe recompilarse.
        pm.vxi.deps.clear();
        for (const auto &req : imports) {
            auto itd = by_name.find(req.module_name);
            if (itd == by_name.end()) continue;
            const ProjectModuleWork &dep = work[itd->second];
            VxiModule::DepRecord drec;
            drec.name = req.module_name;
            /* Lo que este modulo VE del dep, no la interfaz entera del dep:
             * anadirle algo publico que nadie usa no tiene por que invalidar a
             * quien no lo usa.  El mismo criterio se aplica al validar. */
            drec.abi_hash = huella_de_lo_usado(dep.vxi, req);
            pm.vxi.deps.push_back(std::move(drec));
        }

        // ---- M3: persistir .vxi + .vxir a disco para futuro cache ----
        if (cache_enabled && !is_root) {
            const std::string vp =
                vxi_path_for_(pm.canonical_path, cache_tgt_suffix);
            const std::string ip =
                vxir_path_for_(pm.canonical_path, cache_tgt_suffix);
            auto vbytes = vxi_emit(pm.vxi);
            //  M4.ext L.13: capturar el abi_hash recien calculado
            // por vxi_emit (lo escribio en offset 8 del header) para
            // que los modulos sucesores en topo order que importen este
            // puedan apuntarlo en su dep table.
            if (vbytes.size() >= 16) {
                uint64_t h = 0;
                for (int i = 0; i < 8; ++i) {
                    h |= static_cast<uint64_t>(vbytes[8 + i]) << (i * 8);
                }
                pm.vxi.abi_hash = h;
            }
            //  M5.A L.17: escritura atomica (rename temp file).
            // El IR va PRIMERO y la interfaz DESPUES.  Cada fichero se
            // escribe de forma atomica, pero son dos ficheros que tienen que
            // corresponderse, y quien los lee entra por la interfaz: si esta
            // se publicara antes, otra compilacion simultanea podria
            // encontrarse la interfaz nueva junto al IR viejo y quedarse con
            // una mezcla de dos versiones.  Publicando el IR primero, ver la
            // interfaz nueva garantiza que su IR ya esta en disco.
            //
            // BugFix M.vxir-sd: persistir el modulo COMPLETO (functions +
            // static_data + globals) para que un dep cache-hit aporte sus
            // slots `code.s_*` al merge.  emit_ir_section (solo functions)
            // los perdia.
            auto ibytes = ir::emit_ir_module_cache(pm.ir);
            (void)write_file_atomic_(ip, ibytes);
            (void)write_file_atomic_(vp, vbytes);
            // Poblar el CAS global (content-addressed) con el mismo par
            // (interfaz, IR).  Idempotente: la clave es el contenido.  Asi el
            // siguiente proyecto/maquina con esta misma stdlib hace hit sin
            // recompilar, sin importar en que ruta viva.
            if (cas && cas_key_ok)
                (void)cas->put(cas_key, cas_pack_module_(vbytes, ibytes));
            //  M5.C L.18: ademas del .vxi (interfaz) + .vxir (IR
            // serializado), emitir el .vel del dep solo (sin merge) para
            // que la libreria sea distribuible standalone.  El
            // consumidor puede tomar lib.vx + lib.vxi + lib.vel y
            // armar su .velb directamente con vm --asm-file lib.vel.
            ir::EmitOptions dep_emit_opts;
            dep_emit_opts.opt_level = opt_level_from_int_(opts.opt_level);
            dep_emit_opts.emit_debug = opts.emit_debug;
            // emit_stackmaps queda en su default (true): VSMP siempre presente.
            dep_emit_opts.module_name = pm.module_name;
            ir::EmitResult dep_eres = ir::ir_emit_module(pm.ir, dep_emit_opts);
            std::string dvel_path = dep_vel_path_for_(pm.canonical_path);
            if (dep_eres.ok) {
                std::vector<uint8_t> velb_bytes(dep_eres.vel_text.begin(),
                                                dep_eres.vel_text.end());
                (void)write_file_atomic_(dvel_path, velb_bytes);
            }
            if (verbose_cache) {
                std::ostringstream tmp;
                tmp << "[vx-cache] wrote: " << vp << " (" << vbytes.size()
                    << " B) + " << ip << " (" << ibytes.size() << " B) + "
                    << dvel_path << " ("
                    << (dep_eres.ok ? dep_eres.vel_text.size() : 0) << " B)\n";
                std::lock_guard<std::mutex> lk(verbose_mtx);
                std::cerr << tmp.str();
            }
        }

        pm.ok = true;
    }; // end of compile_one_module lambda

    //  M8: dispatch.  Por defecto secuencial (preserve cache hit
    // determinism y el orden de @c verbose_compile output).  Activado via
    // env @c VX_PARALLEL_COMPILE=N (N >= 1).  N=1 fuerza secuencial (util
    // para diagnostico).  N >= 2 corre hasta N modulos del MISMO nivel
    // topologico en paralelo via @c std::thread + join al final de cada
    // nivel (barrier natural).  Modulos en niveles distintos NUNCA se
    // solapan: el barrier garantiza que los deps esten finalizados antes
    // de que un consumer empiece.
    int parallel_threads = 0;
    const bool env_present = util::flag_present(util::FlagId::ParallelCompile);
    if (env_present) {
        /* Un valor que no sea un numero cuenta como 0, igual que antes: el
         * registro ya devolvio 0 si no pudo leerlo, sin lanzar. */
        const long n = util::flag_int(util::FlagId::ParallelCompile, 0);
        parallel_threads = (n < 0 || n > INT_MAX) ? 0 : static_cast<int>(n);
    }
    //  M8 AUTO (2026-06-05): sin env var (o =0) el compile usa
    // hardware_concurrency() limitado a max 8 threads (cap para evitar
    // oversubscription: >8 da diminishing returns por contention en cache
    // writes + mutex verbose).  VX_PARALLEL_COMPILE=1 fuerza SECUENCIAL
    // (diagnostico / output determinista); >=2 fija N exacto.  Proyectos
    // triviales (1 modulo por nivel) NO pagan overhead: el dispatch
    // paralelo solo crea threads cuando un nivel tiene >=2 modulos.
    if (!env_present || parallel_threads == 0) {
        unsigned hc = std::thread::hardware_concurrency();
        if (hc < 1) hc = 1;
        parallel_threads = (hc > 8u) ? 8 : static_cast<int>(hc);
    }
    if (parallel_threads <= 1) {
        // Path secuencial: identico al comportamiento pre-M8.
        for (size_t i = 0; i < work.size(); ++i) {
            compile_one_module(i);
        }
    } else {
        // Path paralelo: agrupar modulos por nivel topologico.
        std::vector<std::vector<size_t>> by_level(max_level + 1);
        for (size_t i = 0; i < module_levels.size(); ++i) {
            by_level[module_levels[i]].push_back(i);
        }
        if (verbose_compile) {
            std::cerr << "[parallel] threads=" << parallel_threads
                      << " niveles=" << (max_level + 1) << "\n";
        }
        for (int L = 0; L <= max_level; ++L) {
            const auto &mods = by_level[L];
            if (mods.empty()) continue;
            // Si el nivel tiene 1 solo modulo, no merece thread.
            if (mods.size() == 1) {
                compile_one_module(mods[0]);
                continue;
            }
            // Particionar @c mods en lotes de tamano @c parallel_threads .
            // Cada lote se ejecuta concurrentemente; los lotes son
            // secuenciales entre si.  Ejemplo: 5 modulos en L0 con
            // threads=2 -> lotes [0,1], [2,3], [4].
            const size_t chunk = static_cast<size_t>(parallel_threads);
            for (size_t base = 0; base < mods.size(); base += chunk) {
                const size_t end_idx = std::min(base + chunk, mods.size());
                std::vector<std::thread> threads;
                threads.reserve(end_idx - base);
                for (size_t k = base; k < end_idx; ++k) {
                    std::string cc_modo;
                    vx::get_aot_condcomp_mode(cc_modo);
                    std::string cc_tier;
                    bool cc_sin_libc = false;
                    vx::get_aot_condcomp_tier(cc_tier, cc_sin_libc);
                    threads.emplace_back([&compile_one_module, idx = mods[k],
                                          cc_tgt_os, cc_tgt_arch, cc_modo,
                                          cc_tier, cc_sin_libc]() {
                        // HALLAZGO-2: re-aplicar el target de @Target en
                        // este worker antes de parsear (el thread_local del
                        // parser arranca vacio en un thread nuevo).
                        if (!cc_tgt_os.empty() || !cc_tgt_arch.empty())
                            vx::set_aot_condcomp_target(cc_tgt_os, cc_tgt_arch);
                        /* Los otros dos ejes van por el MISMO thread_local y
                         * arrancan igual de vacios aqui.  Sin esto, un modulo
                         * compilado en paralelo veia `mode:aot` falso y
                         * cualquier `tier:` falso -- y una variante marcada
                         * para el tier del binario desaparecia sin decir nada,
                         * segun en que hilo cayera el modulo. */
                        if (!cc_modo.empty())
                            vx::set_aot_condcomp_mode(cc_modo);
                        if (!cc_tier.empty())
                            vx::set_aot_condcomp_tier(cc_tier, cc_sin_libc);
                        compile_one_module(idx);
                    });
                }
                // Barrier: esperar todos los threads del lote antes de
                // pasar al siguiente.  Necesario porque modulos del mismo
                // nivel pueden compartir cache writes que deben terminar
                // antes de que el siguiente nivel intente cache hit.
                for (auto &t : threads)
                    t.join();
            }
        }
    }

    //  M.L20-full: mergear @c pm.diags al res.diagnostics + abortar
    // si algun modulo fallo.  Hacemos esto post-loop para que las
    // versiones paralelas no compitan por el @c res.diagnostics global.
    // NOTA: @c res.ok default es @c false ; setear early-abort solo si
    // hubo un @c pm.ok==false real, no por inicializacion.
    bool any_pm_failed = false;
    for (auto &pm : work) {
        for (const auto &d : pm.diags.all()) {
            res.diagnostics.emit(d);
        }
        /* El conjunto comptime del proyecto se suma AQUi, por el mismo motivo
         * que los diagnosticos: dentro del bucle, hasta ocho hilos escribian
         * sobre la misma `std::string` y el mismo `std::vector` sin candado, y
         * eso destroza el bufer -- el compilador moria con 0xC0000374 sin
         * imprimir nada y con victima distinta cada vuelta.  Sumar despues, en
         * orden de indice, ademas quita el otro sintoma: la concatenacion ya
         * no depende de que hilo llegue antes, asi que dos compilaciones del
         * mismo fuente dan el mismo texto y la misma clave. */
        /* "Aporto algo" se mide por el TEXTO o por los NOMBRES, no solo por el
         * texto: un modulo cuyo conjunto son unicamente constantes comptime
         * trae nombres con el texto vacio, y mirando solo el texto se perdian
         * -- y con ellos el criterio de pertenencia al emitir el artefacto. */
        if (!pm.comptime_unit_source.empty() ||
            !pm.comptime_unit_names.empty()) {
            res.comptime_unit_source += pm.comptime_unit_source;
            res.comptime_unit_names.insert(res.comptime_unit_names.end(),
                                           pm.comptime_unit_names.begin(),
                                           pm.comptime_unit_names.end());
            res.comptime_unit_hash ^=
                pm.comptime_unit_hash + 0x9e3779b97f4a7c15ULL +
                (res.comptime_unit_hash << 6) + (res.comptime_unit_hash >> 2);
        }
        res.comptime_unit_not_collected.insert(
            res.comptime_unit_not_collected.end(),
            pm.comptime_unit_not_collected.begin(),
            pm.comptime_unit_not_collected.end());
        if (!pm.ok) any_pm_failed = true;
    }
    if (any_pm_failed) {
        res.ok = false;
        return res;
    }

    // 4. Merge IR de todos los modulos en uno solo.
    //
    // Estrategia: el modulo ROOT (work.back() en topo order, ya que el
    // root es el ultimo) se usa como destino base.  Los demas modulos
    // contribuyen sus IrFunctions, static_data y globals.
    //
    // Nota: el orden topologico garantiza que el root es el ULTIMO.
    // Lo verificamos defensivamente.
    if (work.empty()) {
        res.ok = false;
        return res;
    }
    ir::IrModule &merged = work.back().ir;

    //  M.L25: tree-shaking opt-in via VX_TREE_SHAKE=1 .  Si el root
    // hace `import "lib" only X, Y` y NINGUNO de X, Y aparece en
    // referenced_names() del root, el dep NO se mergea al .velb final.
    // Reduce el tamano de programas con muchos deps opcionales.
    //
    // SEMANTICA: solo se tree-shakean deps cuyos imports son TODOS `only`
    // sin usar Y el dep NO declara clases (las clases requieren ejecutar
    // __module_init para registrarse en el ClassRegistry runtime; saltar
    // el merge perderia eso).  Plain imports (`import "x";` sin only)
    // jamas se shake-an (son referencia opaca, dificil de demostrar
    // unused).
    const bool tree_shake = util::flag_on(util::FlagId::TreeShake);
    std::unordered_set<size_t> shaken_indices;
    if (tree_shake && work.size() >= 2) {
        const auto &root_pm = work.back();
        const auto &root_refs = root_pm.tc ? root_pm.tc->referenced_names()
                                           : std::unordered_set<std::string>{};
        auto root_imports = collect_imports_(*root_pm.ast, &ns_to_modname);
        for (const auto &req : root_imports) {
            if (req.is_plain) continue;           // namespace -> nunca shake
            if (req.is_public_reexport) continue; // re-export consume el dep
            auto itd = by_name.find(req.module_name);
            if (itd == by_name.end()) continue;
            // Verificar si el dep declara clases (no shake-able).
            const auto &dep_pm = work[itd->second];
            bool dep_has_classes = false;
            if (dep_pm.ast) {
                for (const auto &d : dep_pm.ast->decls) {
                    if (d && d->kind == ast::NodeKind::ClassDecl) {
                        dep_has_classes = true;
                        break;
                    }
                }
            }
            if (dep_has_classes) continue;
            // Verificar si TODOS los only simbolos estan sin usar.
            bool all_unused = true;
            for (const auto &os : req.only_symbols) {
                const std::string &local =
                    os.rename.empty() ? os.name : os.rename;
                if (root_refs.find(local) != root_refs.end()) {
                    all_unused = false;
                    break;
                }
            }
            if (all_unused && !req.only_symbols.empty()) {
                shaken_indices.insert(itd->second);
                if (verbose_compile) {
                    std::cerr << "[tree-shake] dep '" << req.module_name
                              << "' eliminado (ninguno de "
                              << req.only_symbols.size()
                              << " simbolos importados se usa)\n";
                }
            }
        }
    }

    // #cross-module-generics: dedup de funciones por nombre al mergear.  Una
    // misma instanciacion `Caja_i64__leer` puede producirse en VARIOS modulos
    // (cada uno inyecta la plantilla y monomorphiza on-use); son IDENTICAS por
    // construccion (mismo template + mismos args), asi que se conserva UNA.
    // Sin esto, el linker veria simbolos duplicados.  Modelo COMDAT de C++.
    std::unordered_set<std::string> merged_fn_names;
    merged_fn_names.reserve(merged.functions.size() * 2);
    for (const auto &fn : merged.functions)
        merged_fn_names.insert(fn.name);

    for (size_t i = 0; i + 1 < work.size(); ++i) {
        if (shaken_indices.count(i)) continue; // L.25: skip dep no usado
        auto &dep_ir = work[i].ir;
        // BugFix M.sd: remapeo de STR_LIT_ADDR.imm al mergear static_data.
        // Cada modulo usa indices locales 0..N-1 para sus literales.  Al
        // concatenar el static_data del dep tras el del root, los indices
        // del dep deben desplazarse en @c offset = merged.static_data.size()
        // ANTES de mover las funciones.  Sin esto, las STR_LIT_ADDR del dep
        // (`s_0`, `s_1`, ...) apuntan a las strings del root tras el merge
        // y se imprime garbage (cross-module string aliasing).
        // BugFix M.mi: renombrar el `__module_init` del dep a un nombre
        // unico (`__module_init_<modname>`) y NO permitir colision con la
        // del root.  Sin esto, el merge genera multiples labels
        // `__module_init` y solo se ejecuta la primera -- las clases de
        // los deps no se registran y los `new dep.Class()` crashean.  El
        // root encadena llamadas a las del dep via injeccion de CALLs en
        // su propia __module_init (mas abajo).
        const std::string dep_mod_init = "__module_init_" + work[i].module_name;
        /* Se renombran TODAS las `__module_init*` del dep, no solo la
         * principal.  Desde que se parte en tandas, cada modulo trae ademas
         * sus `__module_init_partN`, y esos nombres son los MISMOS en todos
         * los modulos: sin esto, dos deps aportan `__module_init_part0` y el
         * merge se queda con una.
         *
         * Y renombrar obliga a reescribir las llamadas, porque a diferencia de
         * la principal -- que el cargador invoca por `init_pc` y nadie nombra
         * -- las tandas SI se llaman por nombre desde ella. */
        std::unordered_map<std::string, std::string> init_renames;
        for (auto &fn : dep_ir.functions) {
            if (fn.name.rfind("__module_init", 0) != 0) continue;
            const std::string renamed =
                (fn.name == "__module_init")
                    ? dep_mod_init
                    : fn.name + "_" + work[i].module_name;
            init_renames.emplace(fn.name, renamed);
            fn.name = renamed;
        }
        if (!init_renames.empty()) {
            for (auto &fn : dep_ir.functions)
                for (auto &blk : fn.blocks)
                    for (auto &in : blk.instrs) {
                        if (in.op != ir::IrOp::CALL &&
                            in.op != ir::IrOp::TAILCALL)
                            continue;
                        auto it = init_renames.find(in.func_name);
                        if (it != init_renames.end()) in.func_name = it->second;
                    }
        }
        const uint64_t sd_offset =
            static_cast<uint64_t>(merged.static_data.size());
        if (sd_offset != 0) {
            // Helper: en cualquier string que contenga subcadenas
            // `code.s_<N>` (referencias a static_data del dep), reemplaza
            // <N> por <N + sd_offset>.  Cubre RAW_ASM, etiquetas de
            // findclass, cache slots de clase y otros literales s_*.
            auto remap_static_refs = [sd_offset](std::string &s) {
                std::string out;
                out.reserve(s.size());
                size_t i = 0;
                while (i < s.size()) {
                    size_t p = s.find("code.s_", i);
                    if (p == std::string::npos) {
                        out.append(s, i, s.size() - i);
                        break;
                    }
                    out.append(s, i, p - i);
                    out.append("code.s_");
                    p += 7;
                    // Parsear los digitos.
                    size_t j = p;
                    uint64_t num = 0;
                    while (j < s.size() && s[j] >= '0' && s[j] <= '9') {
                        num = num * 10 + static_cast<uint64_t>(s[j] - '0');
                        ++j;
                    }
                    out.append(std::to_string(num + sd_offset));
                    i = j;
                }
                s = std::move(out);
            };
            for (auto &fn : dep_ir.functions) {
                for (auto &bb : fn.blocks) {
                    for (auto &ins : bb.instrs) {
                        if (ins.op == ir::IrOp::STR_LIT_ADDR) {
                            ins.imm += sd_offset;
                            continue;
                        }
                        if (ins.op == ir::IrOp::RAW_ASM) {
                            // El texto del RAW_ASM esta en func_name.
                            if (!ins.func_name.empty()) {
                                remap_static_refs(ins.func_name);
                            }
                        }
                    }
                }
            }
        }
        for (auto &fn : dep_ir.functions) {
            // #cross-module-generics: dedup -- saltar funciones cuyo nombre
            // ya existe (monomorphizaciones identicas de otro modulo).  Las
            // synteticas por-modulo (`__module_init_<mod>`) ya son unicas.
            if (!fn.name.empty() && !merged_fn_names.insert(fn.name).second)
                continue;
            merged.functions.push_back(std::move(fn));
        }
        // M.staticdata-pool: el storage canonico es ahora un pool unico
        // por modulo.  El merge usa @c append_raw_entries para concatenar
        // bytes + reescribir offsets en un solo paso O(total_bytes).
        merged.static_data.append_raw_entries(std::move(dep_ir.static_data));
        // Globals: merge insertando entradas del dep en el mapa del root.
        // Si una entrada ya existe en root, dep gana? No -- dep no
        // sobrescribe (root tiene prioridad).  En la practica los nombres
        // no colisionan en MVP.
        for (auto &gv : dep_ir.globals) {
            merged.globals.emplace(gv.first, gv.second);
        }
        // BugFix M.ni: native_imports cross-module.  Sin este merge,
        // los CALLN emitidos desde un dep (e.g. `vesta_io:vio_print` al
        // usar @c print desde un metodo de clase) generan un simbolo no
        // resuelto en el linker.  La funcion @c register_native_import
        // ya deduplica internamente, asi que llamarla directo es seguro.
        /* Con lo DECLARADO sobre cada nativa: si el dep dijo lo que hace, esa
         * es la unica copia que hay de ese dato, y perderla aqui devuelve la
         * funcion a "puede hacer cualquier cosa" en el modulo fusionado -- que
         * es el que se analiza. */
        for (auto &ni : dep_ir.native_imports) {
            merged.register_native_import(ni.lib, ni.name, ni.effects);
        }
    }

    // BugFix M.mi: injetar al inicio del @c __module_init del root un
    // CALL a cada @c __module_init_<dep> mergeado.  Sin esto, las
    // clases declaradas en deps nunca se registran (sus defclass viven
    // dentro de su propio @c __module_init , que el main no llama
    // directamente).  Se ejecutan en topo order (deps primero).
    {
        std::vector<std::string> dep_init_names;
        for (size_t i = 0; i + 1 < work.size(); ++i) {
            if (shaken_indices.count(i) != 0) continue;
            // Verifica que existe un @c __module_init_<dep> entre las
            // funciones mergeadas (algunos deps sin clases/globals no
            // tienen uno; saltar silente).
            const std::string nm = "__module_init_" + work[i].module_name;
            for (const auto &fn : merged.functions) {
                if (fn.name == nm) {
                    dep_init_names.push_back(nm);
                    break;
                }
            }
        }
        if (!dep_init_names.empty()) {
            bool found = false;
            for (auto &fn : merged.functions) {
                if (fn.name != "__module_init") continue;
                if (fn.blocks.empty()) continue;
                auto &entry = fn.blocks.front();
                std::vector<ir::IrInstr> head;
                head.reserve(dep_init_names.size());
                for (const auto &dn : dep_init_names) {
                    ir::IrInstr c{};
                    c.op = ir::IrOp::CALL;
                    c.type = ir::IrType::I64;
                    c.dst = ir::IR_NO_VALUE;
                    c.func_name = dn;
                    head.push_back(std::move(c));
                }
                entry.instrs.insert(entry.instrs.begin(),
                                    std::make_move_iterator(head.begin()),
                                    std::make_move_iterator(head.end()));
                found = true;
                break;
            }
            // Si el root no genero su propio __module_init pero hay deps
            // con classes, creamos un stub que solo encadena llamadas.
            if (!found) {
                ir::IrFunction stub;
                stub.name = "__module_init";
                stub.ret_type = ir::IrType::I64;
                const ir::IrBlockId entry = stub.new_block("entry");
                for (const auto &dn : dep_init_names) {
                    ir::IrInstr c{};
                    c.op = ir::IrOp::CALL;
                    c.type = ir::IrType::I64;
                    c.dst = ir::IR_NO_VALUE;
                    c.func_name = dn;
                    stub.append(entry, std::move(c));
                }
                ir::IrInstr ret{};
                ret.op = ir::IrOp::RET;
                ret.type = ir::IrType::I64;
                ret.dst = ir::IR_NO_VALUE;
                stub.append(entry, std::move(ret));
                merged.functions.push_back(std::move(stub));
            }
        }
    }

    // CPU dispatch cross-module: los globals fp-table (__vx_*_fp,
    // __vx_cpu_features) son program-globales (unificados arriba por
    // shared_key), pero los `__vx_*_init` que los inicializan se preponen
    // a `main` SOLO en el modulo que baja `main` (Lowering::run).  Si el
    // ROOT no usa dispatch pero un DEP si (p.ej. el dep llama s.length()
    // -> __vx_strlen_fp), el init existe como funcion pero nunca se
    // llama -> el slot queda en 0 -> call a fp nulo -> SEGV.  Aqui, sobre
    // el modulo mergeado, prepondemos a `main` las CALLs a los inits que
    // existan y que main aun no invoque (idempotente: si el root ya las
    // prepuso, se detectan y no se duplican).  Orden de ejecucion:
    // __vx_cpu_init (cpuid) -> __vx_memcpy_init -> __vx_strdisp_init.
    {
        // Que inits existen tras el merge.
        bool has_cpu = false, has_mc = false, has_sd = false;
        for (const auto &fn : merged.functions) {
            if (fn.name == "__vx_cpu_init")
                has_cpu = true;
            else if (fn.name == "__vx_memcpy_init")
                has_mc = true;
            else if (fn.name == "__vx_strdisp_init")
                has_sd = true;
        }
        if (has_cpu || has_mc || has_sd) {
            for (auto &fn : merged.functions) {
                if (fn.name != "main" || fn.blocks.empty()) continue;
                auto &ins = fn.blocks.front().instrs;
                // Detectar inits ya presentes (idempotencia).
                bool have_cpu = false, have_mc = false, have_sd = false;
                for (const auto &x : ins) {
                    if (x.op != ir::IrOp::CALL) continue;
                    if (x.func_name == "__vx_cpu_init")
                        have_cpu = true;
                    else if (x.func_name == "__vx_memcpy_init")
                        have_mc = true;
                    else if (x.func_name == "__vx_strdisp_init")
                        have_sd = true;
                }
                // Prepend en orden inverso (insert(begin) invierte): primero
                // strdisp, luego memcpy, luego cpu -> cpu queda de primero.
                auto prepend_call = [&](const char *name) {
                    ir::IrInstr c{};
                    c.op = ir::IrOp::CALL;
                    c.type = ir::IrType::VOID;
                    c.dst = ir::IR_NO_VALUE;
                    c.func_name = name;
                    c.source_line = 0;
                    ins.insert(ins.begin(), std::move(c));
                };
                if (has_sd && !have_sd) prepend_call("__vx_strdisp_init");
                if (has_mc && !have_mc) prepend_call("__vx_memcpy_init");
                if (has_cpu && !have_cpu) prepend_call("__vx_cpu_init");
                break;
            }
        }
    }

    // Dedup de las funciones synthetic del CPU dispatch (`__vx_*`): el
    // root y cada dep emiten su propio juego de helpers (__vx_strlen_base,
    // __vx_memcpy_init, etc.) con nombres identicos.  Tras el merge habria
    // colision de simbolos en el linker AOT.  Mantener la PRIMERA aparicion
    // (root primero, luego deps) y descartar las siguientes con el mismo
    // nombre.  Solo afecta a los synthetic `__vx_*` (los simbolos de
    // usuario ya estan mangled con prefijo de modulo, no colisionan).
    {
        // Primera pasada: detectar si hay duplicados (sin mover nada).
        std::unordered_set<std::string> seen_vx_fns;
        bool has_dup = false;
        for (const auto &fn : merged.functions) {
            if (fn.name.rfind("__vx_", 0) == 0) {
                if (!seen_vx_fns.insert(fn.name).second) {
                    has_dup = true;
                    break;
                }
            }
        }
        // Segunda pasada: reconstruir solo si hubo duplicados (preserva la
        // PRIMERA aparicion; root primero, luego deps).
        if (has_dup) {
            seen_vx_fns.clear();
            std::vector<ir::IrFunction> kept;
            kept.reserve(merged.functions.size());
            for (auto &fn : merged.functions) {
                if (fn.name.rfind("__vx_", 0) == 0 &&
                    !seen_vx_fns.insert(fn.name).second) {
                    continue; // ya presente: descartar duplicado
                }
                kept.push_back(std::move(fn));
            }
            merged.functions = std::move(kept);
        }
    }

    // M.staticdata-pool full: dedup de @c static_data por content_hash
    // + remap de STR_LIT_ADDR.imm a los indices unificados.  Indices
    // estables y deterministicos: dos builds del mismo source producen el
    // mismo mapping (JIT cache friendly).  Tambien colapsa bytes
    // duplicados cuando dos modulos importan el mismo string.
    if (merged.static_data.size() >= 2) {
        // Construir mapping old_idx -> new_idx via first-occurrence
        // por content_hash.  Mantener orden estable de aparicion.
        const size_t N = merged.static_data.size();
        std::vector<uint64_t> remap(N);
        std::unordered_map<uint64_t, uint64_t> first_by_hash;
        // Globals de programa (CPU dispatch fp-table): un slot por
        // shared_key en TODO el binario, aunque sean NON_DEDUP.  El init
        // del root inicializa el slot unificado que leen las funciones de
        // los modulos dependientes.
        std::unordered_map<std::string, uint64_t> first_by_shared_key;
        ir::IrModule::StaticDataStore new_store;
        new_store.alignment_default = merged.static_data.alignment_default;
        new_store.reserve(N);
        for (size_t i = 0; i < N; ++i) {
            auto [bp, bn] = merged.static_data.bytes_at(i);
            auto &m = merged.static_data.meta_at(i);
            // Compute hash si no esta (defensa: push_back ya lo calcula,
            // pero entries movidas del dep podrian tenerlo en 0 si el
            // dep no lo hizo).
            if (m.content_hash == 0 && bn != 0) {
                uint64_t h = 0xcbf29ce484222325ull;
                for (size_t k = 0; k < bn; ++k) {
                    h ^= static_cast<uint64_t>(bp[k]);
                    h *= 0x100000001b3ull;
                }
                m.content_hash = h;
            }
            // Dos entries colapsan SOLO si tienen el mismo hash + bytes
            // identicos (defensa contra colision hash) + mismas flags +
            // mismo alignment.  Diferencias en cualquiera de esos
            // campos preservan ambas entradas.
            //
            // SD_FLAG_NON_DEDUP: globals mutables zero-init colapsarian
            // entre si por bytes identicos {0,0,...,0} -- el flag los
            // marca como "siempre distintos" para preservar storage real.
            const uint64_t hkey = m.content_hash;
            bool merged_in = false;
            // Prioridad maxima: shared_key (global de programa).  Unifica
            // todas las entries con la misma clave en un solo slot,
            // independientemente de NON_DEDUP / bytes.
            if (!m.shared_key.empty()) {
                auto it = first_by_shared_key.find(m.shared_key);
                if (it != first_by_shared_key.end()) {
                    remap[i] = it->second;
                    merged_in = true;
                } else {
                    const uint64_t new_idx = new_store.push_back(bp, bn);
                    new_store.meta_at(new_idx) = m;
                    first_by_shared_key.emplace(m.shared_key, new_idx);
                    remap[i] = new_idx;
                    merged_in = true;
                }
            }
            const bool is_non_dedup =
                (m.flags & ir::IrModule::SD_FLAG_NON_DEDUP) != 0;
            if (!merged_in && !is_non_dedup) {
                auto it = first_by_hash.find(hkey);
                if (it != first_by_hash.end()) {
                    const uint64_t prev_idx = it->second;
                    if (new_store.equals(prev_idx, bp, bn) &&
                        new_store.meta_at(prev_idx).flags == m.flags &&
                        new_store.meta_at(prev_idx).alignment == m.alignment) {
                        remap[i] = prev_idx;
                        merged_in = true;
                    }
                }
            }
            if (!merged_in) {
                const uint64_t new_idx = new_store.push_back(bp, bn);
                new_store.meta_at(new_idx) = m; // copiar flags/section
                first_by_hash.emplace(hkey, new_idx);
                remap[i] = new_idx;
            }
        }
        // Aplicar remap a TODAS las instrucciones STR_LIT_ADDR + a las
        // referencias `code.s_<N>` dentro de RAW_ASM.
        if (new_store.size() < N) {
            for (auto &fn : merged.functions) {
                for (auto &bb : fn.blocks) {
                    for (auto &ins : bb.instrs) {
                        if (ins.op == ir::IrOp::STR_LIT_ADDR) {
                            if (ins.imm < remap.size()) {
                                ins.imm = remap[ins.imm];
                            }
                            continue;
                        }
                        if (ins.op == ir::IrOp::RAW_ASM &&
                            !ins.func_name.empty()) {
                            std::string &s = ins.func_name;
                            std::string out;
                            out.reserve(s.size());
                            size_t i = 0;
                            while (i < s.size()) {
                                const size_t p = s.find("code.s_", i);
                                if (p == std::string::npos) {
                                    out.append(s, i, s.size() - i);
                                    break;
                                }
                                out.append(s, i, p - i);
                                out.append("code.s_");
                                size_t j = p + 7;
                                uint64_t num = 0;
                                while (j < s.size() && s[j] >= '0' &&
                                       s[j] <= '9') {
                                    num = num * 10 +
                                          static_cast<uint64_t>(s[j] - '0');
                                    ++j;
                                }
                                const uint64_t nidx =
                                    (num < remap.size()) ? remap[num] : num;
                                out.append(std::to_string(nidx));
                                i = j;
                            }
                            s = std::move(out);
                        }
                    }
                }
            }
            merged.static_data = std::move(new_store);
        }
    }

    // 5.b. Verificar los CONTRATOS de huella (@pure/@nothrow/@nopanic/@alloc/
    // @stack) sobre el IR PRE-opt (snapshot antes de optimizar): ahi TODAS las
    // funciones existen (el inline/DCE aun no las elimino) -> enforcement
    // completo.  Semantica source-level (source<=N => efectivo<=N, sound).
    // Solo ERROR cuando la violacion es DEMOSTRABLE.  Parte del sistema de
    // tipos.
    {
        // Recoger los contratos declarados en los AST de los modulos (root +
        // deps), guardarlos en el resultado (para --analyze) y verificar.
        std::function<void(const std::vector<std::unique_ptr<ast::Node>> &)>
            collect = [&](const std::vector<std::unique_ptr<ast::Node>>
                              &decls) {
                for (const auto &d : decls) {
                    if (!d) continue;
                    if (d->kind == ast::NodeKind::NamespaceDecl) {
                        collect(static_cast<const ast::NamespaceDecl *>(d.get())
                                    ->decls);
                        continue;
                    }
                    if (d->kind == ast::NodeKind::FunctionDecl) {
                        const auto *fd =
                            static_cast<const ast::FunctionDecl *>(d.get());
                        analyze::FunctionContracts c;
                        c.pure = fd->contract_pure;
                        c.nothrow = fd->contract_nothrow;
                        c.nopanic = fd->contract_nopanic;
                        c.alloc_total = fd->contract_alloc;
                        c.alloc_partial = fd->contract_alloc_partial;
                        c.stack_total = fd->contract_stack;
                        c.stack_partial = fd->contract_stack_partial;
                        if (c.any()) res.contracts[fd->name] = c;
                    }
                    // Metodos de struct/clase: mismo contrato sobre lo mismo.
                    // Un metodo baja a una IrFunction `Tipo__metodo`, asi que
                    // se registra con esa clave -- la que vera el analizador.
                    auto tomar_metodos =
                        [&](const std::string &tipo,
                            const std::vector<
                                std::unique_ptr<ast::ClassMethodDecl>> &ms) {
                            for (const auto &m : ms) {
                                if (!m) continue;
                                analyze::FunctionContracts c;
                                c.pure = m->contract_pure;
                                c.nothrow = m->contract_nothrow;
                                c.nopanic = m->contract_nopanic;
                                c.alloc_total = m->contract_alloc;
                                c.alloc_partial = m->contract_alloc_partial;
                                c.stack_total = m->contract_stack;
                                c.stack_partial = m->contract_stack_partial;
                                if (c.any())
                                    res.contracts[tipo + "__" + m->name] = c;
                            }
                        };
                    // Los TEMPLATES genericos se saltan: no producen IR (solo
                    // sus instanciaciones), y su clave casaria por sufijo con
                    // la instanciacion, duplicando cada incumplimiento.  La
                    // monomorphizacion copia los contratos.
                    if (d->kind == ast::NodeKind::StructDecl) {
                        const auto *sd =
                            static_cast<const ast::StructDecl *>(d.get());
                        if (sd->type_params.empty() && !sd->is_specialization)
                            tomar_metodos(sd->name, sd->methods);
                    } else if (d->kind == ast::NodeKind::ClassDecl) {
                        const auto *cd =
                            static_cast<const ast::ClassDecl *>(d.get());
                        if (cd->type_params.empty())
                            tomar_metodos(cd->name, cd->methods);
                    }
                }
            };
        for (auto &pm : work)
            if (pm.ast) collect(pm.ast->decls);

        /* Aqui es donde MAS aparece: `merged` es la fusion de los modulos del
         * proyecto, asi que la misma nativa declarada en dos de ellos llega
         * junta por primera vez.  Fuera del `if` de contratos, porque el choque
         * existe aunque nadie haya escrito uno. */
        analyze::report_native_effect_conflicts(merged, root_path,
                                                res.diagnostics);
        if (!res.contracts.empty()) {
            // Arch del TARGET activo (@Target/AOT); vacio = host (x86_64).
            std::string fp_os, fp_arch;
            vx::get_aot_condcomp_target(fp_os, fp_arch);
            if (fp_arch.empty()) fp_arch = "x86_64";
            auto fps = analyze::compute_module_fingerprints(merged, fp_arch);
            /* Con el modulo: lo que las importaciones DECLAREN de una nativa
             * cuenta, en vez de volver opaco el cierre entero. */
            analyze::compose_fingerprints(fps, &res.contracts, &merged);
            // En modo --analyze (`emit_ir_preopt`) una violacion NO se emite
            // como error ni aborta: analyze mide y ensena (el reporte muestra
            // la discrepancia aparte), no construye.  Si emitiera el error, la
            // matriz por-arch marcaria fallo justo en el arch que hay que
            // mostrar para corregirlo.  El build real (`--vesta`, sin
            // emit_ir_preopt) SI emite el error y aborta.
            if (!opts.emit_ir_preopt) {
                /* Los tres veredictos por UNA sola puerta.  Aqui habia una
                 * copia del criterio que se quedaba solo con el incumplimiento
                 * y descartaba el indecidible sin decir nada -- y habia otras
                 * dos copias iguales en `compiler.cpp`. */
                const analyze::ContractReport rep =
                    analyze::report_contract_checks(
                        analyze::verify_contracts(fps, res.contracts),
                        root_path, res.diagnostics);
                if (rep.violated != 0) {
                    res.ok = false;
                    return res;
                }
            }
        }
    }

    // Modo --analyze: capturar el IR PRE-optimizacion para que el analizador
    // contraste la complejidad del FUENTE con la del codigo final.  Sin esto la
    // ruta de proyecto (con imports) reportaba "PRE-opt: no disponible".
    //
    // Se pliegan las ramas comptime-constantes (const fold + unreachable, SIN
    // inline): `is_float<T>()` es una CONSTANTE para cada instanciacion, asi
    // que la rama muerta del template (el bucle CAS que solo toca el caso
    // float) no es parte del cuerpo de `fetch_add<i64>` -- su algoritmo real es
    // O(1).  Es resolucion de la monomorfizacion, no optimizacion.  NO se
    // inlinea: el parcial es propiedad del cuerpo escrito.
    /* Copia para el modulo CON inline, tomada ANTES de ese plegado.  Importa
     * que sea antes: el plegado se hace para medir el cuerpo escrito y modifica
     * `merged`, asi que partir de ahi describiria un programa que el compilador
     * nunca ve.  Desde aqui, la entrada es exactamente la de una compilacion
     * normal, que es lo unico que hace util al informe. */
    ir::IrModule para_inline;
    const bool quiere_inline = opts.emit_ir_inlined && opts.emit_ir_preopt;
    if (quiere_inline) para_inline = merged;

    if (opts.emit_ir_preopt) {
        for (auto &fn : merged.functions) {
            bool changed = true;
            while (changed) {
                changed = false;
                if (ir::ir_pass_const_fold(fn)) changed = true;
                if (ir::ir_pass_unreachable(fn)) changed = true;
            }
        }
        res.ir_module_cache_bytes_preopt = ir::emit_ir_module_cache(merged);
    }

    // --vx-emit-ir: copia del IR PRE-opt (antes de optimizar) para el dump.
    // La ruta de proyecto (con imports) NO rellenaba res.ir_text -- solo lo
    // hacia compile_vx_source --, asi que `vm --vesta prog.vx --vx-emit-ir`
    // generaba un .ir VACIO en cuanto el fuente tenia un import.
    ir::IrModule ir_pre_dump;
    if (opts.dump_ir) ir_pre_dump = merged;

    cerrar_fase(res.tiempos.modulos_us);

    // 5. Optimizar el IR mergeado.  En modo --analyze SIN inline: el coste
    //    PARCIAL es propiedad del cuerpo escrito -- si el inline lo alterase,
    //    dependeria del optimizador (`return this.swap(v)` es parcial O(1), no
    //    O(n) por el bucle de swap inyectado).  El coste TOTAL lo compone el
    //    analizador via el callgraph.  Fuera de --analyze, inline normal.
    // Multi-ISA: la rentabilidad de la if-conversion (SELECT vs branch) depende
    // de la microarquitectura destino (cmov ~2c x86, csel ~1c ARM64, sin cmov
    // nativo en RISC-V).  Ajustamos el modelo de coste al arch del TARGET
    // activo antes de optimizar; asi la decision horneada en el IR corresponde
    // a la ISA para la que se compila (host x86_64 por defecto).
    {
        std::string tisa_os, tisa_arch;
        vx::get_aot_condcomp_target(tisa_os, tisa_arch);
        if (tisa_arch == "arm64" || tisa_arch == "aarch64")
            ir::set_target_isa(ir::TargetIsa::ARM64);
        else if (tisa_arch == "riscv" || tisa_arch == "riscv64")
            ir::set_target_isa(ir::TargetIsa::RISCV);
        else
            ir::set_target_isa(ir::TargetIsa::X86_64);
    }

    /* ASA observa ANTES de optimizar: esta es la forma del programa tal como se
     * escribio.  Es una verdad distinta de la de despues, no una version peor
     * -- medido: de tres sacos escritos a mano, la escalarizacion se lleva dos
     * antes de que nadie los mire, asi que observar solo despues hace creer que
     * el programa no los tenia. */
    {
        util::CronoTramo t_("fase-opt:asa-volcar-formas");
        analysis::asa::volcar_formas(merged, "pre-opt");
    }

    /* El codigo que de verdad se construye, para quien ademas del coste del
     * cuerpo escrito necesita ver eso.  Sale de la misma bajada, asi que no hay
     * que compilar el fuente otra vez: basta optimizar la copia de arriba con
     * el inline puesto.  Aqui y no antes, porque la ISA del objetivo ya esta
     * fijada y el optimizador decide con ella. */
    if (quiere_inline) {
        ir::ir_optimize(para_inline, opt_level_from_int_(opts.opt_level),
                        /*allow_inline=*/true);
        res.ir_module_cache_bytes_inlined =
            ir::emit_ir_module_cache(para_inline);
    }

    /* El asignador del lenguaje queda DENTRO del modulo (sin tocar las
     * reservas): asi el selector del JIT puede llamarlo y compartir mecanismo
     * con el binario nativo, que es lo que permite depurar aquel desde aqui. */
    {
        util::CronoTramo t_("fase-opt:asignador-del-lenguaje");
        traer_asignador_del_lenguaje(merged, opts, root_path);
    }

    {
        util::CronoTramo t_("fase-opt:ir_optimize");
        ir::ir_optimize(merged, opt_level_from_int_(opts.opt_level),
                        /*allow_inline=*/!opts.emit_ir_preopt);
    }

    /* Sobre el codigo que DE VERDAD se va a emitir: lo que el analisis puede
     * demostrar fuera de su region no puede quedarse en `--analyze`, tiene que
     * salir al compilar, que es cuando se lee. */
    if (opts.report_bounds)
        vx_report_bounds(merged, res.diagnostics, root_path);
    /* Precondiciones del asm.  SIEMPRE, no bajo opcion: una instruccion cuya
     * exigencia no se cumple no da un resultado peor, hace caer el programa --
     * y callarselo ya costo descubrirlo ejecutando.
     *
     * Aqui esta TODO lo que se va a enlazar, asi que si hay un `main` lo que se
     * construye es el programa entero y no queda ningun fuera desde el que
     * llamar: entonces se puede afirmar de una funcion publica lo mismo que de
     * una privada.  Sin `main` esto es una libreria (o un modulo suelto) y lo
     * publico sigue siendo alcanzable por quien no se ve. */
    bool hay_main = false;
    for (const ir::IrFunction &f : merged.functions)
        if (f.name == "main") {
            hay_main = true;
            break;
        }
    {
        util::CronoTramo t_("fase-opt:asm-precondiciones");
        /* Antes de preguntar, que este lo que se va a preguntar -- venga de la
         * compilacion anterior o de producirlo ahora.  El consumidor no
         * distingue una cosa de la otra a proposito: si tuviera que decidir
         * cuando fiarse de la cache, esa decision acabaria escrita en tantos
         * sitios como consumidores haya, y bastaria que uno se separara para
         * que el mismo programa dijera cosas distintas segun quien preguntara.
         *
         * Sin identidad del modulo no se toca el disco: comprobar que lo
         * guardado es de ESTE programa es lo unico que hace sana una cache. */
        /* `asa.layout` porque lo consume el informe de precondiciones de aqui
         * abajo, y ademas lo que haya pedido quien compila: el linter y el
         * editor saben que dominios van a consultar, y producirlos AQUI -- con
         * el modulo en memoria y su identidad conocida -- deja el trabajo hecho
         * y guardado, en vez de que cada consumidor lo rehaga despues y lo
         * tire al terminar. */
        std::vector<const char *> quiere = {"asa.layout"};
        for (const char *d : opts.asa_domains)
            if (d != nullptr) quiere.push_back(d);
        ensure_facts_impl_(merged, facts, quiere,
                           root_facts_key != 0
                               ? rutas_cache_(root_path, std::string()).hechos
                               : std::string(),
                           root_facts_key);
        /* Y sale con el resultado, para que quien compilo pueda consultarlo sin
         * volver a producirlo.  Se COPIA y no se mueve: el informe de abajo
         * todavia lo usa. */
        res.facts = facts;
        vx_report_asm_preconditions(merged, res.diagnostics, root_path,
                                    hay_main, opts.emit_ir_preopt,
                                    opts.native_poo ? "aot" : "vm", facts);
    }

    if (opts.dump_ir) {
        std::ostringstream ir_oss;
        ir_oss << "// ============================================\n";
        ir_oss << "// SSA IR pre-optimizacion (frontend output, mergeado)\n";
        ir_oss << "// ============================================\n";
        ir::ir_print(ir_pre_dump, ir_oss);
        ir_oss << "\n// ============================================\n";
        ir_oss << "// SSA IR post-optimizacion (opt_level=" << opts.opt_level
               << ")\n";
        ir_oss << "// ============================================\n";
        ir::ir_print(merged, ir_oss);
        res.ir_text = ir_oss.str();
    }

    cerrar_fase(res.tiempos.optimizar_us);

    // 6. Emitir .vel desde el IR mergeado.
    ir::EmitOptions emit_opts;
    emit_opts.opt_level = opt_level_from_int_(opts.opt_level);
    emit_opts.emit_comments = true;
    emit_opts.emit_debug = opts.emit_debug;
    // emit_opts.emit_stackmaps queda en su default (true): VSMP siempre.
    emit_opts.module_name =
        opts.module_name.empty() ? work.back().module_name : opts.module_name;
    /* `merged` sale ya optimizado de la fase anterior.  El emisor optimizaba su
     * copia otra vez -- el mismo trabajo, el mismo modulo -- y eso era la mayor
     * parte de lo que costaba emitir.
     *
     * Salvo con `emit_ir_preopt`, donde la optimizacion de arriba se hace SIN
     * inline a proposito (el coste que se mide es el del cuerpo escrito) y el
     * codigo que se emite si tiene que llevarlo. */
    emit_opts.ya_optimizado = !opts.emit_ir_preopt;
    /* Quien solo quiere el IR se salta esto.  Asignar registros y escribir el
     * texto `.vel` es el noventa por ciento del coste del frontend, y el
     * informe de `--analyze` no lee ni una linea de ese texto.  Lo que le falta
     * al modulo es en que registro quedo cada valor, que la pone el emisor por
     * ser quien lo decide; el resto sale igual.
     *
     * Se salta la EMISION, no lo que viene detras: ahi se decide si el modulo
     * necesita la maquina de compilacion, y volver antes la habria apagado
     * justo para quien mas la necesita. */
    ir::EmitResult eres;
    if (!opts.ir_only) {
        eres = ir::ir_emit_module(merged, emit_opts);

        /* PRUEBA: el artefacto comptime, FILTRANDO EL IR en vez de recortar el
         * fuente.  Aqui `merged` ya esta parseado, chequeado, bajado, fusionado
         * y optimizado, con los nombres resueltos: quedarse con unas funciones
         * es copiar el modulo y filtrar un vector.  El enfoque por texto tenia
         * que RECONSTRUIR eso, y el AST ni siquiera guarda el tramo de cada
         * decl (`SourceLoc::length` es la del token). */
        /* Valvula: `VESTA_NO_FILTRO_COMPTIME=1` vuelve al artefacto del
         * programa entero.  Sirve para separar en un fallo si la causa es el
         * filtro o cualquier otra cosa, sin recompilar el compilador. */
        if (!res.comptime_unit_names.empty() &&
            !util::flag_on(util::FlagId::NoFiltroComptime)) {
            std::unordered_set<std::string> del_conjunto(
                res.comptime_unit_names.begin(), res.comptime_unit_names.end());
            /* Indice por nombre para no recorrer el modulo por cada callee. */
            std::unordered_map<std::string, const ir::IrFunction *> por_nombre;
            por_nombre.reserve(merged.functions.size());
            for (const ir::IrFunction &f : merged.functions)
                por_nombre.emplace(f.name, &f);

            /* RAICES: lo que la ComptimeVM tiene que poder invocar.
             *
             * No basta con lo que el recolector nombra.  Hay dos familias
             * SINTETICAS que nadie declara y que se ejecutan al compilar igual:
             * los `__macro_<X>` (incluidos los constructores `comptime
             * T(expr)`, que bajan a `__macro_<T>__ctor_N`) y los `__ctblock_N`
             * de un bloque `comptime { }`.  Dejarlas fuera rompio
             * `comptime_literal_import` y `bfc311`. */
            std::vector<std::string> pendientes;
            std::unordered_set<std::string> dentro;
            for (const ir::IrFunction &f : merged.functions) {
                /* `__module_init` es raiz aunque nadie lo nombre: es lo que
                 * registra clases y macros al cargar el artefacto.  Sin el, la
                 * carga deja simbolos sin resolver y el comptime no se entera
                 * -- el programa compilaba y daba otro resultado. */
                const bool sintetica = f.name.rfind("__macro_", 0) == 0 ||
                                       f.name.rfind("__ctblock_", 0) == 0 ||
                                       f.name == "__module_init";
                const std::string desnudo = f.name.rfind("__macro_", 0) == 0
                                                ? f.name.substr(8)
                                                : f.name;
                if (sintetica || del_conjunto.count(f.name) ||
                    del_conjunto.count(desnudo)) {
                    if (dentro.insert(f.name).second)
                        pendientes.push_back(f.name);
                }
            }
            /* CLAUSURA sobre el grafo de llamadas del IR: lo que una raiz llama
             * tiene que viajar con ella o el artefacto no es auto-suficiente y
             * la invocacion falla EN COMPILACION.  Hacerlo aqui -- y no sobre
             * el fuente -- es lo que lo vuelve cerrado POR CONSTRUCCION: los
             * nombres ya estan resueltos y no hay que adivinar nada. */
            while (!pendientes.empty()) {
                const std::string actual = std::move(pendientes.back());
                pendientes.pop_back();
                const auto it = por_nombre.find(actual);
                if (it == por_nombre.end()) continue;
                for (const ir::IrBlock &b : it->second->blocks)
                    for (const ir::IrInstr &in : b.instrs) {
                        /* Llamarla no es la unica forma de necesitarla:
                         * TOMAR SU DIRECCION tambien.  `LABEL_ADDR` nombra una
                         * funcion que se usa como VALOR -- un puntero a
                         * funcion -- y esa funcion tiene que viajar igual.
                         *
                         * Sin esto se rompia de verdad, y con un fallo dificil:
                         * `std.syscall.windows` tiene
                         *
                         *     invoke_syscall invoke_method = invoke;
                         *     resolve_syscall resolve_method =
                         * resolve_ntdll_export;
                         *
                         * -- valores por defecto de campo --, asi que `invoke`
                         * y `resolve_ntdll_export` se referencian por nombre y
                         * NO se llaman.  El cierre no las veia, no viajaban al
                         * artefacto, y al ejecutarlo la llamada saltaba a
                         * `0x31`.  El destino se sabe: es un nombre. */
                        if (in.op != ir::IrOp::CALL &&
                            in.op != ir::IrOp::TAILCALL &&
                            in.op != ir::IrOp::LABEL_ADDR)
                            continue;
                        if (in.func_name.empty()) continue; // indirecta
                        if (dentro.insert(in.func_name).second)
                            pendientes.push_back(in.func_name);
                    }
            }

            /* `main` NO viaja.  Se probo incluirlo -- el artefacto se carga
             * como ejecutable y parecia necesitar punto de entrada -- pero sus
             * llamadas quedaban COLGANDO y el enlazado fallaba con "simbolo no
             * resuelto: code.copy_ok".  Cerrar sobre `main` traeria el programa
             * entero, que es justo lo que se evita.  Lo que de verdad faltaba
             * era `__module_init`, que si es raiz. */
            ir::IrModule solo_ct = merged; // cabecera: imports/globals/libs
            solo_ct.functions.clear();
            for (const ir::IrFunction &f : merged.functions)
                if (dentro.count(f.name)) solo_ct.functions.push_back(f);
            if (!solo_ct.functions.empty()) {
                ir::EmitOptions eo_ct = emit_opts;
                /* Ninguna de estas funciones es la entrada de un programa:
                 * todas se invocan por su PC y cualquiera puede llamar a otra,
                 * asi que todas tienen que poder VOLVER. */
                eo_ct.sin_punto_de_entrada = true;
                ir::EmitResult e_ct = ir::ir_emit_module(solo_ct, eo_ct);
                if (e_ct.ok) {
                    res.comptime_vel_text = std::move(e_ct.vel_text);
                    /* PUNTO DE ENTRADA: `__module_init`, no `main`.
                     *
                     * El artefacto comptime NO es un programa: es una
                     * biblioteca de funciones que la ComptimeVM invoca por su
                     * PC, resuelto desde la tabla de simbolos.  Nunca se entra
                     * por `main`. Pero se carga con `load_executable`, y un
                     * ejecutable tiene entrada: sin ninguna, el enlazador deja
                     * `start_pc = 0` -- avisa con "PC(0) por defecto" -- y
                     * usarlo salta a la direccion 0 (segfault).
                     *
                     * Incluir `main` para taparlo no vale: arrastra sus
                     * llamadas y el enlazado falla con simbolos sin resolver
                     * (`code.copy_ok`), y cerrar sobre el traeria el programa
                     * entero, que es lo que se esta evitando.
                     *
                     * La entrada correcta es `__module_init`, que es justo lo
                     * que debe ejecutarse al cargar el artefacto: registra las
                     * clases y los macros. */
                    bool tiene_init = false;
                    for (const ir::IrFunction &f : solo_ct.functions)
                        if (f.name == "__module_init") {
                            tiene_init = true;
                            break;
                        }
                    if (tiene_init)
                        /* ENTRE COMILLAS y AL FINAL.  Las dos cosas, y las dos
                         * costaron un fallo:
                         *
                         *  - sin comillas, el ensamblador se para en el `.` con
                         *    "se esperaba un )".  Es la convencion del `.vel`
                         *    para una etiqueta con punto
                         * (`@Absolute("code.X")`).
                         *  - al PRINCIPIO, las anotaciones se procesan en orden
                         *    y todavia no hay ninguna seccion definida, asi que
                         *    la etiqueta no se puede resolver ("no se ha
                         *    definido ninguna seccion ... code.__module_init").
                         *
                         * Nadie los habia visto porque el fallo se tragaba: el
                         * sitio que ensambla el artefacto tenia un `if (ok)`
                         * sin `else`, asi que la compilacion seguia sin
                         * artefacto y sin decir nada. */
                        res.comptime_vel_text +=
                            "\n@InitPc(\"__module_init\")\n";
                    /* La seccion @ir del conjunto: la del programa entero no
                     * vale, describe otras funciones. */
                    res.comptime_ir_section_bytes.clear();
                }
                if (util::flag_on(util::FlagId::PruebaIrComptime)) {
                    /* QUE se queda fuera: es lo que hay que mirar cuando el
                     * artefacto filtrado se comporta distinto del entero. */
                    std::cerr << "[comptime-ir] fuera:";
                    for (const ir::IrFunction &f : merged.functions)
                        if (!dentro.count(f.name)) std::cerr << " " << f.name;
                    std::cerr << "\n";
                }
                if (util::flag_on(util::FlagId::PruebaIrComptime))
                    std::cerr
                        << "[comptime-ir] programa " << merged.functions.size()
                        << " fns / " << eres.vel_text.size() << " B .vel"
                        << "  ->  conjunto " << solo_ct.functions.size()
                        << " fns / " << res.comptime_vel_text.size()
                        << " B .vel" << (e_ct.ok ? "" : "  (FALLO)") << "\n";
            }
        }
        if (!eres.ok) {
            SourceLoc loc;
            loc.file = root_path;
            res.diagnostics.error(
                std::move(loc), std::string("emisor IR fallo: ") + eres.error);
            res.ok = false;
            return res;
        }
    }
    res.vel_text = std::move(eres.vel_text);

    // Mapa del artefacto: uno solo con los simbolos de TODOS los modulos.  El
    // ejecutable los contiene a todos, asi que una direccion suya puede caer en
    // cualquiera; un mapa por modulo dejaria sin explicar todo lo que no fuera
    // el modulo raiz.  Sin artefacto no hay nada que mapear.
    if (!opts.ir_only) {
        vxdbg::ArtifactMap map;
        for (const auto &pm : work) {
            /* Dos cosas distintas, y las dos hacen falta.
             *
             * Los SIMBOLOS son para BUSCAR: dada una direccion que resolvio a
             * un simbolo, dan su entidad.  Solo los tiene el modulo que se bajo
             * en esta compilacion.
             *
             * El mapa del modulo es para SOSTENER: lleva todo lo que ese modulo
             * emitio -- tipos y miembros incluidos, no solo lo que tiene codigo
             * --, asi que citarlo es lo que impide que el grafo se quede sin
             * raiz.  Lo traen los dos casos: el que se acaba de bajar y el que
             * vino de su cache, porque la huella viaja en el `.vxi`. */
            for (const auto &kv : pm.vxdbg_symbols)
                map.add(kv.first, kv.second);
            const vxdbg::ContentHash mm{pm.vxi.vxdbg_map_lo,
                                        pm.vxi.vxdbg_map_hi};
            if (!mm.empty()) map.modules.push_back(mm);
        }
        vxdbg::FileNodeStore store(opts.vxdbg_dir.empty() ? default_vxdbg_dir()
                                                          : opts.vxdbg_dir);
        vxdbg::ContentHash h;
        if (!map.symbols.empty() && vxdbg::store_node(store, map, h))
            res.vxdbg_artifact_map = h;
    }
    /* Donde dejo el asignador cada valor, antes de guardar el intermedio: es
     * lo que permite decir que `%8` es el `r1` de la instruccion maquina.  Se
     * estampa aqui, entre emitir y serializar, porque el emisor recibe el
     * modulo como solo-lectura y este es el punto en que ya se sabe. */
    for (auto &fn : merged.functions) {
        auto it = eres.value_regs.find(fn.name);
        if (it == eres.value_regs.end()) continue;
        const size_t n = std::min(fn.values.size(), it->second.size());
        for (size_t v = 0; v < n; ++v)
            fn.values[v].reg = it->second[v];
    }
    // El intermedio que viaja dentro del artefacto: sin artefacto, sobra.
    if (!opts.ir_only)
        res.ir_section_bytes = ir::emit_ir_section(merged.functions);
    //  AOT multi-modulo: exponer el IR mergeado (functions + static_data
    // + globals) como module_cache para que el path -m aot lo consuma.  El
    // single-file lo rellena en compile_vx_source; aqui lo rellenamos desde
    // el modulo mergeado de todos los .vx del proyecto.
    res.ir_module_cache_bytes = ir::emit_ir_module_cache(merged);

    cerrar_fase(res.tiempos.emitir_us);

    // AOT.2.d: detectar @AllocatorOverride / @PanicHandler en el modulo ROOT,
    // igual que hace compile_vx_source.  Sin esto, un .vx que declara el
    // allocator NO podia tener imports: el driver -m aot lo compilaba como
    // fichero suelto porque por el camino de proyecto no le llegaban estos
    // simbolos, y abortaba con "no pude compilar el slab allocator (o no expone
    // @AllocatorOverride)".  O sea: la stdlib era la unica parte del lenguaje
    // que no podia importar.
    if (!work.empty() && work.back().ast) {
        for (auto &decl : work.back().ast->decls) {
            if (!decl || decl->kind != ast::NodeKind::FunctionDecl) continue;
            auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
            if (fd->is_panic_handler) res.aot_panic_sym = fd->name;
            if (!fd->is_alloc_override) continue;
            // El que devuelve puntero es el alloc; el que devuelve void, el
            // free.
            bool ret_ptr = false;
            if (fd->return_type &&
                fd->return_type->kind == ast::NodeKind::PrimitiveTypeNode) {
                ret_ptr = (static_cast<ast::PrimitiveTypeNode *>(
                               fd->return_type.get())
                               ->prim == PrimitiveKind::PTR);
            } else if (fd->return_type && fd->return_type->kind ==
                                              ast::NodeKind::PointerTypeNode) {
                ret_ptr = true;
            }
            if (ret_ptr)
                res.aot_alloc_sym = fd->name;
            else
                res.aot_free_sym = fd->name;
        }
    }
    /* El del PROGRAMA manda sobre el de la biblioteca, tambien para la maquina:
     * si alguien declara el suyo, se usa entero -- usarlo a medias, con el JIT
     * llamando a otro, seria peor que no usarlo. */
    if (!res.aot_alloc_sym.empty()) merged.alloc_sym = res.aot_alloc_sym;
    if (!res.aot_free_sym.empty()) merged.free_sym = res.aot_free_sym;
    /* Y un punto de entrada de nombre CONOCIDO que lleve hasta el.
     *
     * El backend tiene que saber que llamar sin suponer quien hay detras: si
     * buscara un nombre concreto quedaria atado al asignador de la biblioteca,
     * y un programa con el suyo acabaria usandolo a medias.  Asi busca siempre
     * lo mismo y quien conteste lo decide aqui.
     *
     * Es un puente de una linea, no una copia: llama al de verdad y devuelve lo
     * que devuelva. */
    /* has_lowerable_macros: gate del two- compile.  El single-file
     * (compile_vx_source) lo setea escaneando su irmod; en el path multi-modulo
     * hay que escanear el MODULO MERGEADO -- si cualquier funcion (root o dep)
     * es `is_macro_compiled` (un @Macro o una comptime fn ruteada a la
     * ComptimeVM, `__macro_<X>`), el proyecto necesita el two- para que
     * esos call sites se evaluen en la VM (si no, quedan deferidos -> codigo
     * vacio).  Sin esto, un proyecto CON imports que use comptime fns nunca
     * disparaba el segundo pase. */
    for (const auto &fn : merged.functions) {
        // Un constructor comptime tambien es codigo que hay que compilar y
        // cargar antes de poder invocarlo.  Se reconoce por el nombre porque
        // es lo que sobrevive al merge; sin esto la fase no se disparaba y el
        // constructor acababa resolviendose por el evaluador de AST -- que
        // solo funciona dentro del mismo fichero.
        if (fn.is_macro_compiled || fn.name.rfind("__macro_", 0) == 0) {
            res.has_lowerable_macros = true;
            break;
        }
    }
    /* Y si a CUALQUIER modulo del camino le quedo un `inject(...)` pendiente,
     * su bloque asm salio vacio: hay que repetir.  Mirar solo el IR no basta,
     * porque una funcion comptime invocada UNICAMENTE desde un inject no deja
     * rastro en el IR cuando el inject no llega a expandirse. */
    /* El conjunto ENTERO, ya concatenado, a un fichero.  Es lo que de verdad
     * habria que compilar para tener la maquina de compilacion antes que los
     * modulos, asi que es lo que hay que poder leer cuando no compila: los
     * volcados por modulo no lo enseñan, porque el `namespace` de cada uno se
     * añade AL JUNTARLOS. */
    if (!util::flag_text(util::FlagId::VolcarUnidad).empty() &&
        !res.comptime_unit_source.empty()) {
        const std::string &d = util::flag_text(util::FlagId::VolcarUnidad);
        std::error_code tec;
        std::filesystem::create_directories(d, tec);
        /* Con el numero de modulos en el nombre.  Una misma orden compila
         * VARIAS veces -- se han visto tres, de 2, 11 y 2 modulos -- y con un
         * nombre fijo la ultima pisaba a las demas: el fichero parecia decir
         * que el conjunto traia un modulo de siete cuando lo que pasaba es que
         * se estaba mirando otra compilacion. */
        std::ofstream f(d + "/_conjunto_" + std::to_string(work.size()) +
                        "mods.vx");
        if (f) f << res.comptime_unit_source;
    }
    for (const auto &pm : work) {
        if (pm.tc && pm.tc->inject_diferido()) {
            res.has_lowerable_macros = true;
            res.unresolved_inject = true;
            break;
        }
    }
    /* Y ADEMAS, mirando lo que se va a emitir.
     *
     * Preguntarle a cada modulo si le quedo algo pendiente solo funciona con
     * los que se acaban de compilar: los que se sirven del cache no traen type
     * checker al que preguntar, asi que un cuerpo vacio heredado de una pasada
     * anterior pasaba invisible -- que es justo el caso que hay que cazar.
     *
     * El IR fusionado si lo dice, venga de donde venga: el cuerpo lleva la
     * marca que dejo quien no pudo expandirlo.  Cuesta un recorrido del modulo
     * ya construido y no depende de cuantas pasadas haya habido. */
    if (!res.unresolved_inject) {
        for (const ir::IrFunction &fn : merged.functions) {
            for (const ir::IrBlock &b : fn.blocks) {
                for (const ir::IrInstr &in : b.instrs) {
                    if (in.op != ir::IrOp::INLINE_ASM) continue;
                    if (in.func_name.find("inject pendiente") ==
                        std::string::npos)
                        continue;
                    res.unresolved_inject = true;
                    break;
                }
                if (res.unresolved_inject) break;
            }
            if (res.unresolved_inject) break;
        }
    }
    res.ok = !res.diagnostics.has_errors();

    // Diagramas (Mermaid / Graphviz) del AST del root + IR mergeado +
    // .vel final.  En el path project compile (multi-fichero) el AST
    // que se diagrama es el root (work.back() en topo order).  Los IR
    // pre y post-opt se diagraman desde @c merged (sin distincion de
    // pre vs post porque @c ir_optimize ya corrio sobre merged; el
    // diagrama "pre" es identico al "post" en project compile -- esto
    // es una limitacion documentada del modelo merge IR).
    const auto &root_pm = work.back();
    if (root_pm.ast) {
        if (opts.dump_mermaid_ast) {
            res.mermaid_ast = mermaid_from_ast(*root_pm.ast);
        }
        if (opts.dump_graphviz_ast) {
            res.graphviz_ast = graphviz_from_ast(*root_pm.ast);
        }
        if (opts.dump_html_ast) {
            res.html_ast = html_from_ast(*root_pm.ast);
        }
    }
    if (opts.dump_mermaid_ir_pre || opts.dump_mermaid_ir_post) {
        std::string ir_text =
            mermaid_from_ir_module(merged, "IR (merged + optimized)");
        if (opts.dump_mermaid_ir_pre) res.mermaid_ir_pre = ir_text;
        if (opts.dump_mermaid_ir_post) res.mermaid_ir_post = ir_text;
    }
    if (opts.dump_graphviz_ir_pre || opts.dump_graphviz_ir_post) {
        std::string ir_text =
            graphviz_from_ir_module(merged, "IR (merged + optimized)");
        if (opts.dump_graphviz_ir_pre) res.graphviz_ir_pre = ir_text;
        if (opts.dump_graphviz_ir_post) res.graphviz_ir_post = ir_text;
    }
    if (opts.dump_html_ir_pre || opts.dump_html_ir_post) {
        // Proyecto multi-fichero: el IR ya esta merged + optimizado, asi que
        // pre y post comparten el mismo grafo (igual que Mermaid/Graphviz).
        std::string html =
            html_from_ir_module(merged, "SSA IR (merged + optimized)");
        if (opts.dump_html_ir_pre) res.html_ir_pre = html;
        if (opts.dump_html_ir_post) res.html_ir_post = html;
    }
    if (opts.dump_mermaid_vel) {
        res.mermaid_vel = mermaid_from_vel_text(res.vel_text);
    }
    if (opts.dump_graphviz_vel) {
        res.graphviz_vel = graphviz_from_vel_text(res.vel_text);
    }
    if (opts.dump_html_vel) {
        res.html_vel = html_from_vel_text(res.vel_text);
    }

    //  M5.B: poblar dep_paths con los paths canonicos de TODOS los
    // modulos compilados (incluido root).  main.cpp persistira el project
    // cache asociando (paths, hashes, .velb final).
    res.dep_paths.reserve(work.size());
    for (const auto &pm : work) {
        res.dep_paths.push_back(pm.canonical_path);
    }
    return res;
}

/**
 * @brief Aparece la palabra @p kw en el texto, fuera de comentarios y cadenas?
 *
 * Escaner deliberadamente simple, y permisivo por diseno: si dice que si y el
 * parser luego no la encuentra, no pasa nada.  Se busca por palabra COMPLETA
 * para que `importante` o `namespaced` no cuenten.
 */
static bool contiene_palabra(const std::string &source, const char *kw) {
    const size_t klen = std::strlen(kw);
    enum {
        NORMAL,
        IN_LINE_COMMENT,
        IN_BLOCK_COMMENT,
        IN_STRING
    } state = NORMAL;
    size_t i = 0;
    auto at_word_boundary = [&](size_t k) {
        if (k > 0) {
            char p = source[k - 1];
            if ((p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') ||
                (p >= '0' && p <= '9') || p == '_')
                return false;
        }
        if (k + klen > source.size()) return false;
        if (source.compare(k, klen, kw) != 0) return false;
        if (k + klen < source.size()) {
            char n = source[k + klen];
            if ((n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') ||
                (n >= '0' && n <= '9') || n == '_')
                return false;
        }
        return true;
    };
    while (i < source.size()) {
        char c = source[i];
        switch (state) {
        case NORMAL:
            if (c == '/' && i + 1 < source.size() && source[i + 1] == '/') {
                state = IN_LINE_COMMENT;
                i += 2;
                continue;
            }
            if (c == '/' && i + 1 < source.size() && source[i + 1] == '*') {
                state = IN_BLOCK_COMMENT;
                i += 2;
                continue;
            }
            if (c == '"') {
                state = IN_STRING;
                ++i;
                continue;
            }
            if (at_word_boundary(i)) return true;
            break;
        case IN_LINE_COMMENT:
            if (c == '\n') state = NORMAL;
            break;
        case IN_BLOCK_COMMENT:
            if (c == '*' && i + 1 < source.size() && source[i + 1] == '/') {
                state = NORMAL;
                i += 2;
                continue;
            }
            break;
        case IN_STRING:
            if (c == '\\' && i + 1 < source.size()) {
                i += 2;
                continue;
            }
            if (c == '"') state = NORMAL;
            break;
        }
        ++i;
    }
    return false;
}

/**
 * @brief Ver la declaracion en compiler.h.
 *
 * El texto sale del catalogo multi-idioma: aqui solo viajan DATOS (que region,
 * que tramo, que hueco).  La prueba va DENTRO del mensaje, porque un "acceso
 * fuera de region" sin su derivacion obliga a reconstruirla a mano.
 */

/**
 * @brief Ver la declaracion en compiler.h.
 */
void vx_report_asm_preconditions(const ir::IrModule &mod, Diagnostics &diags,
                                 const std::string &file, bool programa_cerrado,
                                 bool decir_lo_no_acotado, const char *backend,
                                 analysis::asa::FactStore &facts) {
    /* Con QUE garantia se coloca la seccion de datos NO es una propiedad del
     * programa: depende de donde acabe corriendo.  Por eso se pregunta con el
     * destino en la mano, en vez de llevar un numero dentro.
     *
     * Y se PREGUNTA AL ASA en vez de recalcularlo.  Antes esta linea llamaba
     * directamente a `alineacion_seccion_datos(backend)`, que es el mismo
     * calculo que el dominio `disposicion` ya hace y deposita como hecho: dos
     * sitios respondiendo lo mismo, que es justo lo que el primer invariante
     * -- un hecho, un productor -- existe para impedir.  El dia que la garantia
     * cambie, con dos calculos uno de los dos se queda viejo y nadie se entera.
     *
     * Se produce SOLO ese dominio: en la medicion costaba 0 us, mientras que
     * producirlo todo se iba a ~544 us por modulo, y el 80% eran los rangos que
     * aqui no se consultan.
     *
     * Si el hecho no aparece, se cae al calculo directo.  No es un respaldo
     * silencioso: `find` dice si habia hechos con ese codigo fuera de alcance,
     * y eso distingue "aun no se produce" de "se produce y no vale aqui". */
    analysis::asa::produce(mod, facts, {"asa.layout"});
    analysis::asa::Scope here;
    here.backend = backend;
    /* El bytecode es una ISA mas, y el hecho del cargador se sella por ella. */
    if (backend != nullptr &&
        (std::strcmp(backend, analysis::asa::kBackendVm) == 0 ||
         std::strcmp(backend, analysis::asa::kBackendJit) == 0))
        here.isa = analysis::asa::kIsaVelb;
    const auto found = facts.find("layout.section_alignment", here);
    const uint32_t computed = analysis::alineacion_seccion_datos(backend);
    const uint32_t garantia =
        found ? static_cast<uint32_t>(found.fact->what.a) : computed;
    /* Y SI LAS DOS FUENTES NO DICEN LO MISMO, eso no es una duda del analisis:
     * es un FALLO DEL COMPILADOR, y tiene que gritar.
     *
     * Mientras el respaldo exista hay dos caminos que contestan a la misma
     * pregunta, y el dia que uno se quede viejo el otro lo TAPA en silencio --
     * que es exactamente como este hecho estuvo meses mudo.  Comparar cuesta
     * una instruccion y convierte un fallo invisible en uno ruidoso.
     *
     * Solo se compara cuando el hecho VALE aqui: si no vale, el respaldo es la
     * respuesta buena y no hay nada que contrastar. */
    if (found && static_cast<uint32_t>(found.fact->what.a) != computed) {
        SourceLoc loc;
        loc.file = file;
        diags.diag(loc, DiagLevel::WARN,
                   analysis::asa::unknown_reason_code(
                       analysis::asa::UnknownReason::SourcesDisagree),
                   {"layout.section_alignment",
                    std::to_string(found.fact->what.a),
                    std::to_string(computed)});
    }
    const uint32_t cabecera = analysis::alineacion_payload_reserva(backend);
    /* Lo que le llega a cada funcion desde sus sitios de llamada.  Sin esto,
     * un parametro no vale nada y la comprobacion se queda en la frontera --
     * que es justo donde NO esta el asm: quien exige alineacion suele recibir
     * el destino, no reservarlo. */
    const analysis::AlignmentSummaries resumen =
        analysis::compute_alignment_summaries(mod, programa_cerrado);

    /**
     * @brief Lo que se pudo decir de UNA instruccion que exige alineacion.
     *
     * El orden importa: es el de menos a mas fuerte.  Una misma instruccion del
     * fuente puede verse VARIAS veces -- el inline trae una copia a cada sitio
     * donde se llamo --, y cada copia sabe lo suyo: donde se ve la direccion
     * concreta se puede demostrar, y en la funcion original quiza no.  Son la
     * misma instruccion, asi que el usuario tiene que recibir UN veredicto.
     */
    enum class Veredicto : uint8_t {
        SinAncho = 0,  ///< no se pudo determinar cuanto exige.
        SinPrueba = 1, ///< se sabe cuanto exige, no si se cumple.
        Cumple = 2,    ///< demostrado que cumple.
        Falla = 3,     ///< demostrado que NO cumple.
    };
    /// Una instruccion del fuente y lo mejor que se pudo decir de ella.
    struct Sitio {
        uint32_t line = 0;
        uint32_t column = 0;
        std::string mnemonic;
        uint16_t bytes = 0;
        std::string operando;
        uint32_t resto = 0;  ///< la prueba, cuando @c Falla.
        uint32_t modulo = 0; ///< la prueba, cuando @c Falla.
        Veredicto v = Veredicto::SinAncho;
    };
    std::vector<Sitio> sitios;

    /**
     * @brief Lo que una funcion EXIGE de quien la llama.
     *
     * Dentro de la funcion, la alineacion de un parametro no se puede saber: la
     * pone el llamante.  Asi que la exigencia que el asm impone sobre un
     * parametro deja de morir en "sin prueba" y viaja HACIA FUERA, para
     * cruzarla con lo que se sabe del argumento en cada sitio de llamada.
     *
     * Es el simetrico de los resumenes de rango, que hacen el viaje contrario
     * (lo que los llamantes pasan, hacia dentro).  Y es DERIVADA: sale de lo
     * que la instruccion exige segun la base de datos, no de una anotacion.
     */
    struct ExigenciaFrontera {
        std::string funcion;
        uint32_t param = 0;
        uint32_t bytes = 0;   ///< de cuanto tiene que ser multiplo.
        std::string mnemonic; ///< quien lo exige, para la prueba.
    };
    std::vector<ExigenciaFrontera> exigencias;
    /// La alineacion de cada funcion, calculada UNA vez: la usan el recorrido
    /// del asm y despues el de los sitios de llamada.
    std::unordered_map<std::string, analysis::AlignmentFacts> alineacion_de;

    for (const ir::IrFunction &fn : mod.functions) {
        if (fn.blocks.empty()) continue;
        /* Una funcion de la que se ha visto TODO lo que podria llamarla, y no
         * habia nada, no se ejecuta nunca.  Eso no es ignorancia -- es la
         * ausencia demostrada --, y comprobar el cuerpo de algo que nadie llama
         * solo produce ruido: es lo que pasa con la copia que el inline deja
         * huerfana. */
        if (resumen.universo_de(fn.name) ==
            analysis::Universo::CerradoSinLlamantes)
            continue;
        (void)exigencias; // se llena mas abajo y se cruza tras el recorrido
        /* De que valor habla cada operando del asm.  Lo responde el mismo sitio
         * que se lo responde al modelo de efectos y al eliminador de escrituras
         * muertas: el camino marcador -> ligadura -> hueco -> contenido se
         * recorre UNA vez y en un solo sitio. */
        const analysis::AsmBindingFacts lig =
            analysis::compute_asm_bindings(fn);
        /* Y el diccionario que le falta al analisis del texto: tras la
         * sustitucion, `movdqa [$0], $1` no dice que `$1` mida 128 bits.  Lo
         * dice la CLASE con la que se declaro, que es lo que escribio el
         * programador. */
        std::vector<std::pair<std::string, std::string>> clases;
        clases.reserve(lig.ligaduras.size());
        for (const analysis::LigaduraAsm &l : lig.ligaduras)
            clases.emplace_back(l.marcador, l.clase);

        /* Se guarda para el segundo recorrido (el de los sitios de llamada) en
         * vez de volver a calcularla: es el mismo hecho sobre la misma funcion,
         * y recalcularlo seria pagar dos veces por saber lo mismo. */
        const analysis::AlignmentFacts &alin =
            alineacion_de
                .emplace(fn.name, analysis::compute_alignment(
                                      fn, &resumen, &mod, garantia, cabecera))
                .first->second;
        for (const ir::IrBlock &b : fn.blocks) {
            for (const ir::IrInstr &in : b.instrs) {
                /* Tambien el asm ELEVADO.
                 *
                 * Esto solo miraba los bloques opacos, asi que entender mejor
                 * un bloque hacia que se comprobara MENOS: en cuanto el elevado
                 * aprendia a pasarlo a IR, la comprobacion de alineacion
                 * desaparecia y un programa que revienta al ejecutarse pasaba
                 * el compilador.  Justo al reves de lo que tiene que pasar.
                 *
                 * Un micro asm lleva su instruccion en la plantilla, asi que el
                 * analisis del texto es el mismo; lo que cambia es de donde
                 * sale la direccion: en el opaco la dicen las ligaduras del
                 * bloque y aqui la lleva el propio operando. */
                if (in.op != ir::IrOp::INLINE_ASM &&
                    in.op != ir::IrOp::ASM_MICRO)
                    continue;
                const ir::AsmMicro *am = (in.op == ir::IrOp::ASM_MICRO &&
                                          in.imm < fn.asm_micros.size())
                                             ? &fn.asm_micros[in.imm]
                                             : nullptr;
                if (in.op == ir::IrOp::ASM_MICRO && am == nullptr) continue;
                /* Cuanto MIDE cada operando.  En el bloque opaco lo dice la
                 * clase que escribio el programador; en el elevado lo lleva la
                 * ficha, que para eso guarda el ancho de cada operando.  Sin
                 * esto la comprobacion se queda a medias: sabe que la
                 * instruccion exige alineacion pero no de cuantos bytes. */
                std::vector<std::pair<std::string, std::string>> clases_micro;
                if (am != nullptr) {
                    clases_micro.reserve(am->operands.size());
                    for (size_t oi = 0; oi < am->operands.size(); ++oi) {
                        const ir::AsmMicroOperand &o = am->operands[oi];
                        const char *c = "reg";
                        if (o.regclass == vx::ASM_RC_VEC ||
                            o.regclass == vx::ASM_RC_FP)
                            c = o.width == 512   ? "zmm"
                                : o.width == 256 ? "ymm"
                                                 : "xmm";
                        clases_micro.emplace_back("$" + std::to_string(oi), c);
                    }
                }
                const std::string texto =
                    am != nullptr ? vx::asm_micro_texto_con_forma(*am)
                                  : in.func_name;
                const vx::AsmInferResult inf = vx::asm_infer_clobbers(
                    texto, {}, am != nullptr ? clases_micro : clases);
                for (const vx::AsmAlignReq &req : inf.align_reqs) {
                    Sitio s;
                    s.line = in.source_line;
                    s.column = in.source_column;
                    s.mnemonic = req.mnemonic;
                    s.bytes = req.bytes;
                    s.operando = req.operando.empty() ? "?" : req.operando;
                    if (req.bytes != 0) {
                        /* Que valor es la direccion.  El analisis del texto ya
                         * dijo por que operando se llega (@c req.base); las
                         * ligaduras dicen de que valor habla ese operando.
                         *
                         * Puede haber VARIAS candidatas (dos variables en el
                         * mismo registro).  Entonces no se sabe cual es, pero
                         * eso no obliga a callarse: si TODAS cumplen, cumple
                         * sea cual sea; si TODAS fallan, revienta sea cual sea.
                         * Solo cuando discrepan no hay nada demostrado -- y ahi
                         * se avisa, que no es lo mismo que dar por bueno ni que
                         * dar por malo. */
                        s.v = Veredicto::SinPrueba;
                        /* En el micro asm la base es un operando de la propia
                         * instruccion, y su valor viaja con ella: no hay que
                         * preguntarle a nadie de que variable se trata. */
                        std::vector<analysis::LigaduraAsm> cands_micro;
                        if (am != nullptr && req.base.size() >= 2 &&
                            req.base[0] == '$') {
                            const size_t k =
                                (size_t)std::atoi(req.base.c_str() + 1);
                            size_t nv = 0;
                            for (size_t oi = 0; oi < am->operands.size();
                                 ++oi) {
                                if (am->operands[oi].value == ir::IR_NO_VALUE)
                                    continue;
                                if (oi == k && nv < in.operands.size()) {
                                    analysis::LigaduraAsm l;
                                    l.valor = in.operands[nv];
                                    cands_micro.push_back(l);
                                    break;
                                }
                                ++nv;
                            }
                        }
                        analysis::AsmBindingFacts::Candidatas cands;
                        if (am != nullptr) {
                            cands.datos = cands_micro.data();
                            cands.n = cands_micro.size();
                        } else {
                            cands = lig.candidatas(req.base);
                        }
                        if (!cands.empty()) {
                            bool todas_cumplen = true, todas_fallan = true;
                            for (const analysis::LigaduraAsm &l : cands) {
                                const ir::IrValueId dir = l.valor;
                                const bool cumple =
                                    dir != ir::IR_NO_VALUE &&
                                    alin.multiplo_de(dir, req.bytes);
                                const bool falla =
                                    dir != ir::IR_NO_VALUE &&
                                    alin.seguro_no_multiplo_de(dir, req.bytes);
                                todas_cumplen = todas_cumplen && cumple;
                                todas_fallan = todas_fallan && falla;
                                if (falla) {
                                    // La prueba: la primera que falla vale para
                                    // explicarlo, y si fallan todas dan la
                                    // misma razon.
                                    s.resto = alin.resto_de(dir);
                                    s.modulo = alin.de(dir);
                                }
                            }
                            if (todas_cumplen)
                                s.v = Veredicto::Cumple;
                            else if (todas_fallan)
                                s.v = Veredicto::Falla;
                            /* Y si la direccion es un PARaMETRO, aqui no se
                             * puede saber: la alineacion la pone QUIEN LLAMA.
                             * En vez de morir en "sin prueba", la exigencia
                             * sale de la funcion y se apunta como propiedad
                             * suya -- "el parametro N debe ser multiplo de K"
                             * --, para cruzarla despues en cada sitio de
                             * llamada.
                             *
                             * Derivada, no declarada: sale de lo que la
                             * instruccion EXIGE (base de datos) y de por donde
                             * le llega la direccion.  Nadie la escribe. */
                            if (s.v == Veredicto::SinPrueba) {
                                for (const analysis::LigaduraAsm &l : cands) {
                                    for (size_t pi = 0; pi < fn.params.size();
                                         ++pi) {
                                        if (fn.params[pi] != l.valor) continue;
                                        ExigenciaFrontera e;
                                        e.funcion = fn.name;
                                        e.param = static_cast<uint32_t>(pi);
                                        e.bytes = req.bytes;
                                        e.mnemonic = req.mnemonic;
                                        exigencias.push_back(std::move(e));
                                    }
                                }
                            }
                        }
                    }
                    /* Se acumula en vez de emitirse: el veredicto es del SITIO
                     * del fuente, y hasta haber visto todas sus copias no se
                     * sabe cual es el mejor que se pudo dar. */
                    bool fusionado = false;
                    for (Sitio &y : sitios) {
                        if (y.line != s.line || y.column != s.column ||
                            y.mnemonic != s.mnemonic)
                            continue;
                        fusionado = true;
                        if (s.v > y.v) {
                            const uint32_t l0 = y.line, c0 = y.column;
                            y = s;
                            y.line = l0;
                            y.column = c0;
                        }
                        break;
                    }
                    if (!fusionado) sitios.push_back(std::move(s));
                }
            }
        }
    }

    /* Y ahora UN veredicto por sitio.  La regla es la de siempre: una prueba no
     * la borra una copia que no pudo demostrar nada, y no poder demostrar que
     * algo es seguro no es demostrar que es inseguro.  Demostrado-que-falla
     * manda sobre todo: basta con que UN camino reviente. */
    for (const Sitio &s : sitios) {
        SourceLoc loc;
        loc.line = s.line;
        loc.column = s.column;
        loc.file = file;
        switch (s.v) {
        case Veredicto::Cumple: break; // demostrado: no hay nada que decir.
        case Veredicto::Falla:
            diags.diag(loc, DiagLevel::ERR, "VXA013",
                       {s.mnemonic, std::to_string(s.bytes),
                        std::to_string(s.resto), std::to_string(s.modulo)});
            break;
        case Veredicto::SinPrueba:
            diags.diag(loc, DiagLevel::WARN, "VXA011",
                       {s.mnemonic, s.operando, std::to_string(s.bytes)});
            break;
        case Veredicto::SinAncho:
            diags.diag(loc, DiagLevel::WARN, "VXA012", {s.mnemonic});
            break;
        }
    }

    /* Y AHORA lo que la funcion exige, cruzado con lo que se sabe del argumento
     * EN CADA SITIO DE LLAMADA.
     *
     * Es la otra mitad: dentro de la funcion la alineacion de un parametro no
     * se puede saber, asi que la exigencia salio hacia fuera; aqui se encuentra
     * con quien si lo sabe.  Sin esto, una precondicion que el propio asm
     * declara se quedaba sin comprobar en el unico sitio donde era comprobable.
     *
     * Indexado por funcion llamada: un vector recorrido por cada llamada seria
     * llamadas x exigencias, y de eso ya se ha aprendido bastante hoy. */
    if (!exigencias.empty()) {
        std::unordered_map<std::string, std::vector<const ExigenciaFrontera *>>
            por_llamada;
        for (const ExigenciaFrontera &e : exigencias)
            por_llamada[e.funcion].push_back(&e);
        /* Un sitio del fuente se dice UNA vez.  La misma llamada aparece tantas
         * veces como copias tenga el codigo (inline, monomorfizacion, la propia
         * funcion analizada en dos modulos), y repetir el mismo aviso cinco
         * veces no informa cinco veces: entierra los demas.  La clave es el
         * SITIO y el argumento, que es de lo que se habla. */
        std::unordered_set<uint64_t> ya_dicho;
        for (const ir::IrFunction &fn : mod.functions) {
            if (fn.is_native) continue;
            /* La alineacion del LLAMANTE, ya calculada en el recorrido de
             * arriba.  Si esta funcion no llego a analizarse alli, no se
             * inventa: se deja sin comprobar. */
            auto ia = alineacion_de.find(fn.name);
            if (ia == alineacion_de.end()) continue;
            const analysis::AlignmentFacts &alin_caller = ia->second;
            for (const ir::IrBlock &b : fn.blocks) {
                for (const ir::IrInstr &in : b.instrs) {
                    if (in.op != ir::IrOp::CALL || in.func_name.empty())
                        continue;
                    auto it = por_llamada.find(in.func_name);
                    if (it == por_llamada.end()) continue;
                    for (const ExigenciaFrontera *e : it->second) {
                        if (e->param >= in.operands.size()) continue;
                        const ir::IrValueId arg = in.operands[e->param];
                        if (arg == ir::IR_NO_VALUE) continue;
                        if (alin_caller.multiplo_de(arg, e->bytes))
                            continue; // demostrado que cumple: nada que decir
                        const uint64_t sitio =
                            (static_cast<uint64_t>(in.source_line) << 32) ^
                            (static_cast<uint64_t>(in.source_column) << 8) ^
                            e->param;
                        if (!ya_dicho.insert(sitio).second)
                            continue; // ya se dijo de este sitio
                        SourceLoc loc;
                        loc.line = in.source_line;
                        loc.column = in.source_column;
                        loc.file = file;
                        const std::vector<std::string> args = {
                            in.func_name, std::to_string(e->param),
                            std::to_string(e->bytes), e->mnemonic};
                        if (alin_caller.seguro_no_multiplo_de(arg, e->bytes))
                            diags.diag(loc, DiagLevel::ERR, "VXA040", args);
                        else
                            diags.diag(loc, DiagLevel::WARN, "VXA041", args);
                    }
                }
            }
        }
    }

    /* Y lo que NO se pudo acotar, dicho.
     *
     * Un acceso cuya extension no se determina vale "toca el objeto entero", y
     * un objeto entero NUNCA se sale de si mismo: la comprobacion de limites
     * mira ese acceso y calla.  O sea que la unica senal de que el analisis no
     * llego era... ninguna.  Eso ya costo caro: un `asm` que escribia mas alla
     * del buffer del llamante pasaba sin un aviso y corrompia la variable de al
     * lado, y el fallo aparecia despues, lejos y disfrazado de fallo del motor.
     *
     * No saber es un resultado, y se cuenta como tal.  Con el MOTIVO, que es lo
     * unico accionable: quien lee no puede hacer nada con "no se pudo", pero si
     * con "el bloque salta" o "ese operando no dice cuantos bytes mide". */
    if (!decir_lo_no_acotado) return;
    for (const ir::IrFunction &fn : mod.functions) {
        const analysis::AsmBindingFacts lig =
            analysis::compute_asm_bindings(fn);
        std::vector<std::pair<std::string, std::string>> clases;
        clases.reserve(lig.ligaduras.size());
        for (const analysis::LigaduraAsm &l : lig.ligaduras)
            clases.emplace_back(l.marcador, l.clase);
        for (const ir::IrBlock &b : fn.blocks) {
            for (const ir::IrInstr &in : b.instrs) {
                if (in.op != ir::IrOp::INLINE_ASM) continue;
                const vx::AsmBlockEffects e = vx::asm_analyze_block(
                    in.func_name, vx::asm_arch_actual(), clases);
                // Solo importa lo que ESCRIBE: leer de mas no corrompe a nadie.
                const char *motivo = nullptr;
                for (const vx::AsmBlockEffects::Acceso &a : e.accesos) {
                    if (!a.escribe) continue;
                    if (!a.valida) {
                        motivo = "VXA016";
                        break;
                    }
                    if (!a.extension.ancho_conocido()) {
                        motivo = "VXA015";
                        break;
                    }
                    if (lig.candidatas(a.base).size() != 1) {
                        motivo = "VXA017";
                        break;
                    }
                }
                if (motivo == nullptr && !e.accesos_incompletos) continue;
                if (motivo == nullptr) motivo = "VXA016";
                SourceLoc loc;
                loc.line = in.source_line;
                loc.column = in.source_column;
                loc.file = file;
                const std::string razon =
                    vx::diag::format(motivo, {std::string()});
                diags.diag(loc, DiagLevel::WARN, "VXA014", {razon});
            }
        }
    }
}

void vx_report_bounds(const ir::IrModule &mod, Diagnostics &diags,
                      const std::string &file) {
    // Medicion del dominio de FORMA, apagada salvo que se pida explicitamente.
    // Todavia no la consume nadie: primero hay que saber si distingue algo.
    analysis::asa::volcar_formas(mod, "post-opt");
    for (const analysis::effects::BoundsViolation &v :
         analysis::effects::check_region_bounds(mod)) {
        SourceLoc loc;
        loc.line = v.line;
        loc.file = file;
        diags.diag(loc, DiagLevel::ERR, "VX3001",
                   {vx::diag::format(v.write ? "VX3002" : "VX3003", {}),
                    std::to_string(v.width), v.region, std::to_string(v.limite),
                    std::to_string(v.off), std::to_string(v.off + v.width)});
        /* COMO se detecto -- no solo que pasa.  Quien lee un error tiene que
         * poder juzgar si se lo cree, y para eso necesita saber de donde sale
         * cada mitad del veredicto. */
        /* EN QUE funcion.  El analisis siempre lo supo (@c BoundsViolation
         * lleva su nombre) y el informe lo tiraba, con lo que un error en una
         * funcion de la stdlib -- fusionada en el modulo -- se leia como si
         * estuviera en el fichero del usuario.  Peor aun: la linea es la del
         * modulo de origen y el fichero el del raiz, asi que un programa de
         * quince lineas recibia errores en la linea 414.  Hasta que el informe
         * sepa de que fichero viene cada funcion, al menos se dice de quien es
         * la linea para que nadie la busque donde no esta. */
        if (!v.function.empty())
            diags.note(loc, vx::diag::format("VX3006", {v.function}));
        diags.note(loc, vx::diag::format("VX3004", {std::to_string(v.objeto)}));
        /* Y QUE hacer.  El analisis conoce las dos salidas: agrandar el objeto
         * hasta donde llega el acceso, o no pasar de donde llega el objeto. */
        diags.note(loc,
                   vx::diag::format("VX3005", {std::to_string(v.off + v.width),
                                               std::to_string(v.limite)}));
    }
}

bool vx_source_has_imports(const std::string &source) {
    return contiene_palabra(source, "import");
}

bool vx_source_declara_namespace(const std::string &source) {
    return contiene_palabra(source, "namespace");
}

} // namespace vx
