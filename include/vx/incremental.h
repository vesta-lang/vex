/**
 * @file incremental.h
 * @brief Driver de compilacion incremental GRANULAR (por-simbolo) + store
 *        direccionado por contenido (CAS).  Piedra angular de la compilacion
 *        rapida y, a futuro, DISTRIBUIDA.
 *
 * Idea: la unidad de cache NO es el fichero sino el SiMBOLO (fn / struct /
 * class / enum / concept / global / typedef).  Cada simbolo recibe una CLAVE
 * MERKLE que resume su contenido MAS las claves de sus dependencias:
 *
 *     key(X) = H( content_hash(X) ++ sorted( key(dep) : dep in deps(X) ) )
 *
 * El artefacto compilado de X (su IR / su fragmento) se guarda en un store
 * direccionado por esa clave.  En un rebuild se recomputan las claves; un
 * simbolo cuyo artefacto ya esta en el store se REUSA, el resto se recompila.
 *
 * Por que es DISTRIBUIBLE y cross-proyecto: la clave es un hash de contenido
 * puro (mismo input -> misma clave -> mismo artefacto).  Un store global
 * sirve el artefacto de un simbolo compilado en CUALQUIER proyecto o maquina.
 * Ejemplo canonico: la stdlib se compila UNA vez; todos los proyectos que la
 * importan reusan sus artefactos desde el store global en vez de recompilarla.
 *
 * Ecosistema alpha: SIN compat de versiones.  El layout del store puede
 * cambiar libremente; un artefacto con clave desconocida simplemente no se
 * encuentra y se recompila (regeneracion, no legacy).
 */
#ifndef VESTA_VX_INCREMENTAL_H
#define VESTA_VX_INCREMENTAL_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "ir/ssa_ir.h"
#include "vx/semantic_index.h"

namespace vx {

/// Clave Merkle de un simbolo (64-bit por ahora; ampliable a 128 si el store
/// global crece hasta hacer relevante la colision).
using MerkleKey = uint64_t;

/**
 * @struct BuildConfig
 * @brief Fingerprint de la CONFIGURACIoN de compilacion: todo lo (mas alla del
 *        contenido del fuente) que puede cambiar un artefacto compilado.
 *
 * Es la fuente unica para el keying de cache "por configuracion".  El cache es
 * LAYERED: distintos artefactos dependen de distintas dimensiones, asi que hay
 * dos fingerprints:
 *
 *   - @c ir_fingerprint(): dimensiones que cambian el IR PRE-OPTIMIZE (lo que
 *     cachea hoy el CAS de modulo).  La OPTIMIZACIoN + el CODEGEN son
 *     POSTERIORES (post-merge), asi que @c opt_level, @c aot_vec_width y el
 *     os/arch de codegen NO entran aqui -> el IR se comparte entre esas
 *     configuraciones (mas reuso, sin perder correctitud).
 *   - @c full_fingerprint(): TODAS las dimensiones.  Lo usara el cache del
 *     ARTEFACTO FINAL (.velb / .exe AOT), que SI depende de arch/os/opt/perfil.
 *
 * Extender = añadir un campo + incluirlo en el fingerprint que corresponda.
 */
struct BuildConfig {
    // -- Dimensiones que afectan al IR PRE-OPTIMIZE --------------------------
    uint8_t asm_target_bits = 64;   ///< 64/32/16: lowering de @Naked / asm{}.
    bool native_poo = false;        ///< clases AOT (calloc/dtor) vs VM (GC).
    bool exceptions_enabled = true; ///< lowering de try/catch en AOT.
    std::string instrument_mode; ///< "none"/"trace"/"profile": afecta emision.
    /**
     * @brief Huella de los `@Hook` activos; 0 = ninguno.
     *
     * Los ganchos NO son configuracion de la linea de ordenes: se declaran en
     * el fuente.  Aun asi entran aqui, y no en el hash del modulo, porque su
     * efecto es GLOBAL -- un gancho declarado en un fichero teje llamadas en
     * las funciones de OTROS, cuyo fuente no ha cambiado.  Sin esta huella se
     * les serviria el IR cacheado SIN instrumentar: no daria error, daria un
     * programa que dice medir y no mide.
     *
     * De paso resuelve lo otro: al ser parte de la clave, el IR instrumentado
     * y el limpio viven en entradas distintas y no se pisan.  El aislamiento
     * sale de la clave, sin una cache aparte que mantener.
     */
    uint64_t hooks_fp = 0;
    std::string tgt_os;          ///< @Target OS (solo si el modulo lo usa).
    std::string tgt_arch;        ///< @Target arch (idem).
    // -- Dimensiones que afectan SOLO al artefacto final (post-merge) --------
    int opt_level = 2;          ///< 0..3: optimizacion post-merge.
    bool emit_debug = false;    ///< info de debug en el .velb final.
    uint8_t aot_vec_width = 16; ///< SSE2/AVX/AVX512: vectorizador (post-opt).
    std::string profile_id;     ///< PGO / perfil (futuro).

    /// @brief Fingerprint de las dimensiones que cambian el IR pre-optimize.
    uint64_t ir_fingerprint() const;
    /// @brief Fingerprint de TODAS las dimensiones (cache del artefacto final).
    uint64_t full_fingerprint() const;
};

/**
 * @struct MerkleKeys
 * @brief Clave Merkle de cada simbolo de un modulo, por nombre cualificado.
 */
struct MerkleKeys {
    std::unordered_map<std::string, MerkleKey> by_symbol;

    /// @brief Clave de @p qname, o 0 si el simbolo no esta en el mapa.
    MerkleKey of(const std::string &qname) const;
};

/**
 * @brief Calcula las claves Merkle de todos los simbolos de @p idx.
 *
 * @c key(X) = H(content_hash(X) ++ sorted(key(dep))).  Las dependencias se
 * resuelven por nombre SIMPLE (igual criterio que @c changed_symbols_closure):
 * X depende de todo simbolo cuyo nombre simple aparece en @c deps(X).  Los
 * CICLOS se tratan como una componente fuertemente conexa (SCC): sus miembros
 * comparten el contexto de dependencias externas, de modo que un cambio en
 * cualquier miembro del ciclo cambia la clave de todos (recompilan juntos).
 *
 * El resultado es determinista e independiente del orden de @c idx.symbols.
 */
MerkleKeys compute_merkle_keys(const SemanticIndex &idx);

/**
 * @class CasStore
 * @brief Store direccionado por contenido (CAS) en disco: un artefacto por
 *        clave Merkle.  Thread-safe a nivel de fichero via escritura atomica
 *        (temp + rename); varios procesos pueden poblarlo en paralelo.
 *
 * Layout: @c <root>/<xx>/<clave_hex> donde @c xx son los 2 primeros hex de la
 * clave (sharding para no crear un directorio gigante).  Global por defecto
 * para habilitar el reuso cross-proyecto (ver @c open_default).
 */
class CasStore {
  public:
    /// @brief Abre (creando si falta) un store en @p root.
    explicit CasStore(std::string root);

    /**
     * @brief Store por defecto: @c $VX_CAS_DIR, si no @c $VX_HOME/cas, si no
     *        @c $APPDATA/Vesta/cas (Win) o @c $HOME/.vesta/cas (POSIX).
     *
     * Global (no per-proyecto) a proposito: es lo que permite que la stdlib
     * compilada por un proyecto la reusen los demas.
     */
    static CasStore open_default();

    /// @brief Directorio raiz del store.
    const std::string &root() const noexcept { return root_; }

    /// @brief @c true si existe un artefacto para @p k.
    bool has(MerkleKey k) const;

    /// @brief Lee el artefacto de @p k en @p out.  @return false si no existe.
    bool get(MerkleKey k, std::vector<uint8_t> &out) const;

    /// @brief Escribe (atomico) el artefacto de @p k.  Idempotente: si ya
    /// existe, no reescribe.  @return false ante error de I/O.
    bool put(MerkleKey k, const uint8_t *data, size_t n) const;
    bool put(MerkleKey k, const std::vector<uint8_t> &b) const {
        return put(k, b.data(), b.size());
    }

  private:
    std::string path_for_(MerkleKey k) const;
    std::string root_;
};

/**
 * @struct RebuildPlan
 * @brief Particion de los simbolos de un modulo en {reuse, recompile}.
 */
struct RebuildPlan {
    std::vector<std::string> reuse;     ///< artefacto ya presente en el CAS.
    std::vector<std::string> recompile; ///< artefacto ausente -> recompilar.
    MerkleKeys keys;                    ///< clave Merkle de cada simbolo.
};

/**
 * @brief Plan de recompilacion: computa las claves de @p idx y las particiona
 *        segun esten (reuse) o no (recompile) sus artefactos en @p cas.
 *
 * No necesita el indice PREVIO: la clave ES la identidad.  Si otro proyecto o
 * maquina ya poblo el artefacto de esta clave exacta, se reusa.  Las listas
 * salen ordenadas (determinismo).
 */
RebuildPlan plan_rebuild(const SemanticIndex &idx, const CasStore &cas);

// -- Fragmentos de IR por-simbolo (I2) --------------------------------------

/**
 * @struct IrFragment
 * @brief Artefacto compilado de UN simbolo: su @c IrFunction MAS los blobs de
 *        static_data que referencia, LOCALIZADOS (indices 0..k-1).
 *
 * Autocontenido respecto al pool de literales: las @c STR_LIT_ADDR y las refs
 * @c code.s_<N> en bloques @c RAW_ASM de la funcion apuntan a @c blobs (indices
 * locales), no al pool del modulo original.  Asi el fragmento se guarda en el
 * CAS por su clave Merkle y se re-integra en CUALQUIER modulo (re-internando
 * sus blobs y remapeando los indices).  Los @c globals son estado a nivel de
 * MoDULO, no del fragmento (los gestiona el driver, I3).
 */
struct IrFragment {
    ir::IrFunction fn;                   ///< funcion con refs a blobs LOCALES.
    ir::IrModule::StaticDataStore blobs; ///< blobs referidos (indice = local).
};

/**
 * @brief Extrae el fragmento de @p fn desde @p mod: recolecta los blobs de
 *        static_data que @p fn referencia y reescribe sus refs a indices
 *        locales del fragmento.  @p fn debe pertenecer a @p mod.
 */
IrFragment extract_ir_fragment(const ir::IrModule &mod,
                               const ir::IrFunction &fn);

/// @brief Serializa un fragmento a bytes (para el CAS).
std::vector<uint8_t> serialize_ir_fragment(const IrFragment &frag);

/// @brief Deserializa un fragmento.  @return false si el buffer es invalido.
bool parse_ir_fragment(const std::vector<uint8_t> &bytes, IrFragment &out);

/**
 * @brief Re-integra @p frag en @p target: re-interna sus blobs (dedup por
 *        contenido para los planos), remapea las refs de la funcion de local
 *        al indice del @p target y anexa la funcion (dedup por nombre).
 */
void merge_ir_fragment(ir::IrModule &target, const IrFragment &frag);

} // namespace vx

#endif // VESTA_VX_INCREMENTAL_H
