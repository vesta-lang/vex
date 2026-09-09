/**
 * @file manifest.h
 * @brief Parser dual TOML/JSON del manifest de paquete (vx.toml / vx.json).
 *
 *  PM.1: estructura unica @c Manifest con accesores tipados.  Soporta
 * dos serializaciones equivalentes:
 *   - vx.toml (humano-friendly, canonico)
 *   - vx.json (machine-friendly, otros lenguajes pueden leer)
 *
 * El parser detecta el formato por la extension del archivo.  Si ambos
 * coexisten en un proyecto, error explicito ("manifest duplicado").
 *
 * Anti-malware:
 *  - @c [capabilities] declared = ["fs:read", "net=..."] OBLIGATORIO
 *    para cualquier paquete que necesite acceso a recursos.  Default
 *    sin entry = sin capabilities (deny-all).
 *  - @c [trust] mapa glob -> fingerprint clave publica.  Una dep firmada
 *    por key NO listada en trust falla en compile time.
 *  - @c [dependencies] cada entry DEBE traer @c sha256 (lockfile) o
 *    @c path (local) o @c git (con rev).  Sin estos, error.
 */
#ifndef VESTAVM_PKG_MANIFEST_H
#define VESTAVM_PKG_MANIFEST_H

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>

namespace pkg {

/**
 * @brief Spec de una sola dependencia.
 *
 * Tres modos exclusivos:
 *  1. version + sha256 (descarga remota; sha256 OBLIGATORIO).
 *  2. git + rev + sha256 (descarga git URL en ese rev exacto).
 *  3. path (local; sin descarga; cualquier cambio re-compila).
 */
struct DependencySpec {
    std::string name; ///< @c "@vesta/buffer" (qualified).  Es la CLAVE de la
                      ///< entrada del manifiesto, que por defecto es tambien el
                      ///< nombre del paquete.
    /**
     * @brief Nombre REAL del paquete cuando la clave es un alias.
     *
     * `mibuffer = { package = "@vesta/buffer", version = "1.2" }` deja
     * @c name = "mibuffer" y @c paquete = "@vesta/buffer".  Sirve para
     * desempatar cuando dos dependencias ofrecen el mismo namespace: se les
     * pone un nombre distinto en el manifiesto y ese nombre es por el que se
     * las importa, sin anadir sintaxis al lenguaje.  Misma convencion que
     * Cargo.
     *
     * Vacio = la clave ya es el nombre del paquete.
     */
    std::string paquete;
    std::string version;   ///< @c "1.2" (semver opcional)
    std::string sha256;    ///< hash hex del .vx+.vxi (32 bytes hex = 64 chars)
    std::string git_url;   ///< @c "https://github.com/..."  vacio si no es git
    std::string git_rev;   ///< commit hash exacto (NO branch, NO tag) si es git
    std::string path;      ///< ruta local relativa o absoluta si es local
    std::string trust_key; ///< fingerprint de la clave que firma (opcional,
                           ///< override trust pin)
    bool is_dev =
        false; ///< @c [dev-dependencies] = solo build/test, no runtime
};

/**
 * @brief Capabilities declaradas por el paquete propio (qué necesita).
 *
 * El CONSUMER decide si grant via su propio manifest.  Default: deny-all.
 * Sintaxis identica a `--vx-caps`:
 *   - "fs:read"
 *   - "fs:read=/tmp,/etc"
 *   - "net=localhost:8080;api.foo.com:443"
 *   - "ffi:call=kernel32.dll"
 *   - "spawn", "distrib", "classreg", "mem:host", "loadmod"
 */
struct CapabilitiesDecl {
    std::vector<std::string> declared; ///< caps que el paquete DECLARA usar
};

/**
 * @brief Pin de confianza: glob de paquetes -> fingerprint de clave publica.
 *
 * Ejemplos:
 *   "@vesta/*"  -> fingerprint clave oficial Vesta
 *   "@me/*"     -> fingerprint clave del propio autor
 *   "exact/foo" -> match exacto
 */
struct TrustPin {
    std::string glob;        ///< patron glob ("@vesta/*", "exact/foo")
    std::string fingerprint; ///< hex de SHA-256 de la pubkey
};

/**
 * @brief Manifest completo (vx.toml / vx.json).
 *
 * Layout canonico:
 * @code
 * [package]
 * name = "@user/app"
 * version = "0.1.0"
 * authors = ["David"]
 * license = "MIT"
 * edition = "1"
 *
 * [capabilities]
 * declared = ["fs:read", "net=api.foo.com:443"]
 *
 * [dependencies]
 * "@vesta/buffer" = { version = "1.2", sha256 = "..." }
 *
 * [trust]
 * "@vesta/*" = "kpub1abc..."
 * @endcode
 */
/**
 * @brief Lo que el proyecto dice sobre SUS caches.
 *
 * Va en el manifiesto y no en una variable de entorno porque es una propiedad
 * del PROYECTO, no de quien compila: una libreria que se recompila cada minuto
 * y un binario que se toca una vez al mes no quieren lo mismo, y quien lo sabe
 * es el paquete.  Una variable de entorno obligaria a que cada uno se acordara
 * de ponerla, y ademas se la llevaria puesta al compilar OTRO paquete.
 */
struct CacheConfig {
    /**
     * @brief Corridas seguidas que aguanta un analisis guardado sin pedirse.
     *
     * Cero = el defecto (@c analysis::AnalysisStore::kDefaultUnusedRuns).
     *
     * Subirlo conserva mas trabajo hecho a costa de sitio; bajarlo libera antes
     * a costa de recomputar.  Y los dos lados NO cuestan igual: perder trabajo
     * hecho es justo lo que ese almacen viene a evitar, asi que en la duda se
     * sube.
     *
     * `[cache] analysis_unused_runs = 30`
     */
    uint32_t analysis_unused_runs = 0;
};

struct Manifest {
    // [package]
    std::string name;
    std::string version;
    std::vector<std::string> authors;
    std::string license;
    int edition = 1; ///< schema version del manifest

    // [capabilities]
    CapabilitiesDecl capabilities;

    // [cache]
    CacheConfig cache;

    // [dependencies] + [dev-dependencies]
    std::vector<DependencySpec> dependencies;

    // [trust]
    std::vector<TrustPin> trust_pins;

    // [scripts]: mapa nombre -> comando completo.  Ejecutado via
    // @c vm pkg run <nombre>.  Solo invocan @c vm <args> por
    // seguridad (no shell arbitrario); el dispatcher rechaza
    // comandos que no empiecen con "vm ".
    std::vector<std::pair<std::string, std::string>> scripts;

    // Para diagnostico: ruta del archivo cargado.
    std::string source_path;

    // Detecta si el manifest tiene minimo viable (name + version).
    bool valid() const noexcept { return !name.empty() && !version.empty(); }
};

/**
 * @brief Resultado de parse: manifest si OK, mensaje de error si no.
 */
struct ParseResult {
    bool ok = false;
    Manifest manifest;
    std::string error_msg; ///< vacio si ok
    int error_line = 0;
};

/**
 * @brief Parsea desde un path.  Detecta TOML/JSON por extension.
 */
ParseResult parse_manifest_file(const std::string &path);

/**
 * @brief Parsea desde un buffer en memoria.  @p format es "toml" o "json".
 */
ParseResult parse_manifest_buffer(const std::string &buffer,
                                  const std::string &format,
                                  const std::string &source_path = "");

/**
 * @brief Serializa a TOML (canonico humano).
 */
std::string serialize_manifest_toml(const Manifest &m);

/**
 * @brief Serializa a JSON.
 */
std::string serialize_manifest_json(const Manifest &m);

/**
 * @brief Validacion semantica post-parse (anti-malware checks).
 *
 * Checks aplicados:
 *  - cada dep tiene @c sha256 O @c path O @c git+rev+sha256.
 *  - sha256 valido (64 hex chars).
 *  - trust_pins fingerprints validos (64 hex chars).
 *  - name del paquete tiene formato qualified (@org/name) si va a publish.
 *  - capabilities.declared usa sintaxis valida.
 */
struct ValidationResult {
    bool ok = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

ValidationResult validate_manifest(const Manifest &m);

} // namespace pkg

#endif // VESTAVM_PKG_MANIFEST_H
