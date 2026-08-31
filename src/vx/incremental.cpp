/**
 * @file incremental.cpp
 * @brief Implementacion del driver incremental granular + CAS (ver
 *        incremental.h).
 */
#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "util/env_flags.h"
#include "vx/incremental.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>

#include "ir/ssa_ir_serialize.h"

namespace fs = std::filesystem;

namespace vx {

namespace {

/// FNV-1a 64 sobre un bloque de bytes.
uint64_t fnv1a64(const void *data, size_t n) {
    const uint8_t *p = static_cast<const uint8_t *>(data);
    uint64_t h = util::kFnvOffset;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= util::kFnvPrime;
    }
    return h;
}

/// Mezcla una lista de u64 en un solo hash (orden-sensible: el llamador ordena
/// cuando la semantica lo pide).
uint64_t mix64(const std::vector<uint64_t> &vals) {
    return fnv1a64(vals.data(), vals.size() * sizeof(uint64_t));
}

/// Ultimo segmento punteado (nombre simple) de un nombre cualificado.
std::string simple_name(const std::string &q) {
    const size_t p = q.rfind('.');
    return (p == std::string::npos) ? q : q.substr(p + 1);
}

/// Tarjan: componentes fuertemente conexas de un grafo dirigido dado como
/// listas de adyacencia (indices).  @p out_comp[i] = id de la SCC del nodo i.
/// Devuelve el numero de SCCs.  Las SCCs se numeran en orden topologico
/// INVERSO (una SCC recibe id MENOR que las SCCs de las que depende), lo que
/// nos da directamente "dependencias primero" al iterar por id ascendente.
size_t tarjan_scc(const std::vector<std::vector<uint32_t>> &adj,
                  std::vector<uint32_t> &out_comp) {
    const size_t n = adj.size();
    out_comp.assign(n, UINT32_MAX);
    std::vector<int64_t> idx(n, -1), low(n, 0);
    std::vector<char> on_stack(n, 0);
    std::vector<uint32_t> stack;
    stack.reserve(n);
    int64_t counter = 0;
    uint32_t scc_id = 0;

    // DFS iterativo (evita desbordar la pila del host con modulos grandes).
    std::vector<std::pair<uint32_t, size_t>> work; // (nodo, siguiente vecino)
    for (uint32_t s = 0; s < n; ++s) {
        if (idx[s] != -1) continue;
        work.push_back({s, 0});
        while (!work.empty()) {
            auto &[v, i] = work.back();
            if (i == 0) {
                idx[v] = low[v] = counter++;
                stack.push_back(v);
                on_stack[v] = 1;
            }
            if (i < adj[v].size()) {
                const uint32_t w = adj[v][i];
                ++i; // avanzar al siguiente vecino para la proxima visita.
                if (idx[w] == -1) {
                    work.push_back({w, 0});
                } else if (on_stack[w]) {
                    low[v] = std::min(low[v], idx[w]);
                }
            } else {
                // Todos los vecinos visitados: cerrar SCC si v es raiz.
                if (low[v] == idx[v]) {
                    for (;;) {
                        const uint32_t w = stack.back();
                        stack.pop_back();
                        on_stack[w] = 0;
                        out_comp[w] = scc_id;
                        if (w == v) break;
                    }
                    ++scc_id;
                }
                const uint32_t child = v;
                work.pop_back();
                if (!work.empty()) {
                    const uint32_t parent = work.back().first;
                    low[parent] = std::min(low[parent], low[child]);
                }
            }
        }
    }
    return scc_id;
}

} // namespace

// -- BuildConfig -------------------------------------------------------------

namespace {
/// Mezcla un string en un hash FNV-1a acumulado (con separador de longitud).
void mix_str(uint64_t &h, const std::string &s) {
    h ^= s.size();
    h *= util::kFnvPrime;
    for (unsigned char c : s) {
        h ^= c;
        h *= util::kFnvPrime;
    }
}
void mix_u64(uint64_t &h, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        h ^= (v >> (i * 8)) & 0xFF;
        h *= util::kFnvPrime;
    }
}
} // namespace

uint64_t BuildConfig::ir_fingerprint() const {
    // SOLO las dimensiones que cambian el IR pre-optimize.
    uint64_t h = util::kFnvOffset;
    mix_u64(h, 0x49524647u); // dominio "IRFG".
    mix_u64(h, asm_target_bits);
    mix_u64(h, native_poo ? 1u : 0u);
    mix_u64(h, exceptions_enabled ? 1u : 0u);
    mix_str(h, instrument_mode);
    mix_str(h, tgt_os);
    mix_str(h, tgt_arch);
    /* Y los mandos del entorno que cambian lo EMITIDO.  Es lo que la cabecera
     * de env_flags.h lleva declarando desde que existe -- "un mando que cambia
     * el codigo emitido y no entra en la clave de la cache hace que se sirva un
     * artefacto construido con OTRA configuracion; no da error: da un binario
     * que no corresponde al fuente" --, con su huella escrita y probada... y
     * sin que nadie la llamara.  Compilar con `VESTA_NO_SPEC_DEVIRT=1` y
     * despues sin el devolvia el artefacto de la primera vez, byte a byte.
     *
     * Va dentro de la huella y no en un campo de la configuracion a proposito:
     * un campo hay que acordarse de rellenarlo, y olvidarlo no da error.
     *
     * Vale CERO cuando no hay ninguno puesto, que es el caso normal, asi que
     * esto no invalida nada de lo ya guardado. */
    mix_u64(h, util::emitted_fingerprint());
    return h;
}

uint64_t BuildConfig::full_fingerprint() const {
    // Todas las dimensiones (IR + las del artefacto final).
    uint64_t h = ir_fingerprint();
    mix_u64(h, 0x46554C4Cu); // dominio "FULL".
    mix_u64(h, static_cast<uint64_t>(opt_level));
    mix_u64(h, emit_debug ? 1u : 0u);
    mix_u64(h, aot_vec_width);
    mix_str(h, profile_id);
    return h;
}

MerkleKey MerkleKeys::of(const std::string &qname) const {
    auto it = by_symbol.find(qname);
    return (it == by_symbol.end()) ? 0 : it->second;
}

MerkleKeys compute_merkle_keys(const SemanticIndex &idx) {
    MerkleKeys out;
    const auto &syms = idx.symbols;
    const size_t n = syms.size();
    if (n == 0) return out;

    // 1. Resolucion de deps: nombre SIMPLE -> indices de simbolos que lo tienen
    //    (varios namespaces pueden compartir un nombre simple -> arista a
    //    todos, conservador).  Igual criterio que changed_symbols_closure.
    std::unordered_map<std::string, std::vector<uint32_t>> by_simple;
    by_simple.reserve(n * 2 + 1);
    for (uint32_t i = 0; i < n; ++i)
        by_simple[simple_name(syms[i].name)].push_back(i);

    // 2. Grafo de adyacencia (i -> sus deps).  Deduplicado + sin auto-aristas.
    std::vector<std::vector<uint32_t>> adj(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<uint32_t> outs;
        for (const auto &d : syms[i].deps) {
            auto it = by_simple.find(d);
            if (it == by_simple.end()) continue;
            for (uint32_t j : it->second)
                if (j != i) outs.push_back(j);
        }
        std::sort(outs.begin(), outs.end());
        outs.erase(std::unique(outs.begin(), outs.end()), outs.end());
        adj[i] = std::move(outs);
    }

    // 3. SCCs (Tarjan): numeradas en orden topologico inverso (id menor =
    //    dependencia primero), asi al iterar por id ascendente las deps ya
    //    tienen clave.
    std::vector<uint32_t> comp;
    const size_t n_scc = tarjan_scc(adj, comp);

    // Miembros por SCC.
    std::vector<std::vector<uint32_t>> members(n_scc);
    for (uint32_t i = 0; i < n; ++i)
        members[comp[i]].push_back(i);

    // 4. Clave de cada SCC (contexto compartido) y de cada simbolo.
    //    scc_ctx = H( sorted(content_hash de los miembros) ++
    //                 sorted(clave de las deps EXTERNAS a la SCC) )
    //    key(simbolo) = mix( content_hash(simbolo), scc_ctx )
    std::vector<uint64_t> sym_key(n, 0);
    std::vector<uint64_t> scc_ctx(n_scc, 0);
    for (uint32_t s = 0; s < n_scc; ++s) {
        std::vector<uint64_t> content_hashes, ext_dep_keys;
        for (uint32_t m : members[s]) {
            content_hashes.push_back(syms[m].content_hash);
            for (uint32_t w : adj[m]) {
                if (comp[w] == s) continue;         // dep interna a la SCC.
                ext_dep_keys.push_back(sym_key[w]); // ya calculada (topo).
            }
        }
        std::sort(content_hashes.begin(), content_hashes.end());
        std::sort(ext_dep_keys.begin(), ext_dep_keys.end());
        ext_dep_keys.erase(
            std::unique(ext_dep_keys.begin(), ext_dep_keys.end()),
            ext_dep_keys.end());
        std::vector<uint64_t> buf;
        buf.reserve(content_hashes.size() + ext_dep_keys.size() + 1);
        buf.push_back(0xC0FFEEull); // separador de dominio (contexto de SCC).
        for (uint64_t h : content_hashes)
            buf.push_back(h);
        buf.push_back(0xDEADBEEFull); // separador contenido | deps.
        for (uint64_t k : ext_dep_keys)
            buf.push_back(k);
        const uint64_t ctx = mix64(buf);
        scc_ctx[s] = ctx;
        for (uint32_t m : members[s]) {
            const uint64_t pair[2] = {syms[m].content_hash, ctx};
            sym_key[m] = fnv1a64(pair, sizeof(pair));
        }
    }

    out.by_symbol.reserve(n * 2 + 1);
    for (uint32_t i = 0; i < n; ++i)
        out.by_symbol.emplace(syms[i].name, sym_key[i]);
    return out;
}

// -- CasStore ----------------------------------------------------------------

CasStore::CasStore(std::string root) : root_(std::move(root)) {
    std::error_code ec;
    fs::create_directories(root_, ec); // best-effort; put() revalida.
}

CasStore CasStore::open_default() {
    // 1. Override explicito.
    const std::string &cas = util::flag_text(util::FlagId::CasDir);
    if (!cas.empty()) return CasStore(cas + "/cas");
    // 2. VX_HOME/cas.
    const std::string &home = util::flag_text(util::FlagId::VxHome);
    if (!home.empty()) return CasStore(home + "/cas");
    // 3. Convencion por plataforma.
#if defined(_WIN32)
    const std::string &appdata = util::flag_text(util::FlagId::SysAppData);
    if (!appdata.empty()) return CasStore(appdata + "/Vesta/cas");
#else
    const std::string &h = util::flag_text(util::FlagId::SysHome);
    if (!h.empty()) return CasStore(h + "/.vesta/cas");
#endif
    return CasStore("./.vesta/cas"); // ultimo recurso.
}

std::string CasStore::path_for_(MerkleKey k) const {
    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llx",
                  static_cast<unsigned long long>(k));
    // Sharding por los 2 primeros hex.
    std::string dir = root_ + "/" + std::string(hex, 2);
    return dir + "/" + std::string(hex);
}

bool CasStore::has(MerkleKey k) const {
    std::error_code ec;
    return fs::exists(path_for_(k), ec);
}

bool CasStore::get(MerkleKey k, std::vector<uint8_t> &out) const {
    std::ifstream f(path_for_(k), std::ios::binary);
    if (!f.good()) return false;
    f.seekg(0, std::ios::end);
    const std::streamoff sz = f.tellg();
    if (sz < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    if (sz > 0) f.read(reinterpret_cast<char *>(out.data()), sz);
    return f.good() || f.eof();
}

bool CasStore::put(MerkleKey k, const uint8_t *data, size_t n) const {
    const std::string dst = path_for_(k);
    std::error_code ec;
    // Idempotente: la clave es la identidad; si ya existe, nada que hacer.
    if (fs::exists(dst, ec)) return true;
    const std::string dir = dst.substr(0, dst.find_last_of('/'));
    fs::create_directories(dir, ec);
    // Escritura atomica: temp unico + rename.  Varios procesos pueden poblar
    // la misma clave en paralelo; el rename resuelve la carrera (el ultimo
    // gana, mismo contenido).
    char suffix[32];
    std::snprintf(
        suffix, sizeof(suffix), ".tmp.%llx",
        static_cast<unsigned long long>(fnv1a64(&data, sizeof(data)) ^
                                        reinterpret_cast<uintptr_t>(data)));
    const std::string tmp = dst + suffix;
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.good()) return false;
        if (n > 0) f.write(reinterpret_cast<const char *>(data), n);
        if (!f.good()) return false;
    }
    fs::rename(tmp, dst, ec);
    if (ec) {
        // El destino pudo aparecer entre el exists() y el rename (carrera):
        // aceptamos si ya existe; si no, limpiamos el temp y fallamos.
        if (fs::exists(dst)) {
            fs::remove(tmp, ec);
            return true;
        }
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

// -- plan_rebuild ------------------------------------------------------------

RebuildPlan plan_rebuild(const SemanticIndex &idx, const CasStore &cas) {
    RebuildPlan plan;
    plan.keys = compute_merkle_keys(idx);
    for (const auto &s : idx.symbols) {
        const MerkleKey k = plan.keys.of(s.name);
        if (cas.has(k))
            plan.reuse.push_back(s.name);
        else
            plan.recompile.push_back(s.name);
    }
    std::sort(plan.reuse.begin(), plan.reuse.end());
    std::sort(plan.recompile.begin(), plan.recompile.end());
    return plan;
}

// -- Fragmentos de IR por-simbolo (I2) --------------------------------------

namespace {

constexpr uint32_t VXFRAG_MAGIC = 0x47524658u; // 'X''F''R''G' little-endian
constexpr uint16_t VXFRAG_VERSION = 1; // alpha: sin compat de versiones.

/// Reescribe cada substring `code.s_<N>` en @p s aplicando @p mapfn(N).
void remap_code_s(std::string &s,
                  const std::function<uint64_t(uint64_t)> &mapfn) {
    if (s.find("code.s_") == std::string::npos) return;
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
        size_t j = p;
        uint64_t num = 0;
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') {
            num = num * 10 + static_cast<uint64_t>(s[j] - '0');
            ++j;
        }
        out.append(std::to_string(mapfn(num)));
        i = j;
    }
    s = std::move(out);
}

/// Recolecta los indices de static_data que referencia @p fn: @c
/// STR_LIT_ADDR.imm mas cada @c code.s_<N> en el texto de un bloque @c RAW_ASM.
/// Mismo criterio que el remap cross-module de compiler_project.cpp.
void collect_static_refs(const ir::IrFunction &fn, std::set<uint64_t> &out) {
    for (const auto &bb : fn.blocks) {
        for (const auto &ins : bb.instrs) {
            if (ins.op == ir::IrOp::STR_LIT_ADDR) {
                out.insert(ins.imm);
                continue;
            }
            if (ins.op == ir::IrOp::RAW_ASM && !ins.func_name.empty()) {
                const std::string &s = ins.func_name;
                size_t i = 0;
                while ((i = s.find("code.s_", i)) != std::string::npos) {
                    i += 7;
                    uint64_t num = 0;
                    bool any = false;
                    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
                        num = num * 10 + static_cast<uint64_t>(s[i] - '0');
                        ++i;
                        any = true;
                    }
                    if (any) out.insert(num);
                }
            }
        }
    }
}

} // namespace

IrFragment extract_ir_fragment(const ir::IrModule &mod,
                               const ir::IrFunction &fn) {
    IrFragment frag;
    frag.fn = fn; // copia profunda.

    std::set<uint64_t> refs;
    collect_static_refs(fn, refs);

    // orig -> local, en orden ascendente de orig (determinista).
    std::map<uint64_t, uint64_t> orig2local;
    for (uint64_t orig : refs) {
        if (orig >= mod.static_data.size()) continue; // ref colgante: ignorar.
        auto b = mod.static_data.bytes_at(static_cast<size_t>(orig));
        const uint64_t local = frag.blobs.push_back(b.first, b.second);
        // Meta COMPLETA (alignment/flags/section/sym_refs/symbol_name/...).
        frag.blobs.meta_at(local) =
            mod.static_data.meta_at(static_cast<size_t>(orig));
        orig2local[orig] = local;
    }

    auto mapfn = [&](uint64_t n) -> uint64_t {
        auto it = orig2local.find(n);
        return (it == orig2local.end()) ? n : it->second;
    };
    for (auto &bb : frag.fn.blocks) {
        for (auto &ins : bb.instrs) {
            if (ins.op == ir::IrOp::STR_LIT_ADDR) {
                auto it = orig2local.find(ins.imm);
                if (it != orig2local.end()) ins.imm = it->second;
                continue;
            }
            if (ins.op == ir::IrOp::RAW_ASM && !ins.func_name.empty())
                remap_code_s(ins.func_name, mapfn);
        }
    }
    return frag;
}

std::vector<uint8_t> serialize_ir_fragment(const IrFragment &frag) {
    std::vector<uint8_t> out;
    ir::write_u32(out, VXFRAG_MAGIC);
    ir::write_u16(out, VXFRAG_VERSION);
    ir::write_u16(out, 0); // reservado.
    ir::serialize_function(frag.fn, out);
    ir::serialize_static_data(frag.blobs, out);
    return out;
}

bool parse_ir_fragment(const std::vector<uint8_t> &bytes, IrFragment &out) {
    size_t off = 0;
    uint32_t magic = 0;
    uint16_t ver = 0, pad = 0;
    if (!ir::read_u32(bytes, off, magic) || magic != VXFRAG_MAGIC) return false;
    if (!ir::read_u16(bytes, off, ver) || ver != VXFRAG_VERSION) return false;
    if (!ir::read_u16(bytes, off, pad)) return false;
    out = IrFragment{};
    if (!ir::deserialize_function(bytes, off, out.fn)) return false;
    if (!ir::deserialize_static_data(bytes, off, out.blobs)) return false;
    return true;
}

void merge_ir_fragment(ir::IrModule &target, const IrFragment &frag) {
    // 1. Re-internar los blobs del fragmento en el target.  Sin dedup aqui: la
    //    identidad ya la garantiza la clave Merkle a nivel de FUNCiON; el
    //    compactado por-contenido del pool lo hace el pase de dedup del driver
    //    (M.staticdata-pool).  Copiamos la meta COMPLETA -> lossless.
    std::vector<uint64_t> local2target(frag.blobs.size(), 0);
    for (size_t i = 0; i < frag.blobs.size(); ++i) {
        auto b = frag.blobs.bytes_at(i);
        const uint64_t tgt = target.static_data.push_back(b.first, b.second);
        target.static_data.meta_at(static_cast<size_t>(tgt)) =
            frag.blobs.meta_at(i);
        local2target[i] = tgt;
    }

    // 2. Reescribir las refs de la funcion de indice LOCAL -> indice del
    // target.
    ir::IrFunction fn = frag.fn;
    auto mapfn = [&](uint64_t n) -> uint64_t {
        return (n < local2target.size()) ? local2target[n] : n;
    };
    for (auto &bb : fn.blocks) {
        for (auto &ins : bb.instrs) {
            if (ins.op == ir::IrOp::STR_LIT_ADDR) {
                if (ins.imm < local2target.size())
                    ins.imm = local2target[ins.imm];
                continue;
            }
            if (ins.op == ir::IrOp::RAW_ASM && !ins.func_name.empty())
                remap_code_s(ins.func_name, mapfn);
        }
    }

    // 3. Anexar la funcion (dedup por nombre: no re-anexar si ya esta).
    if (!fn.name.empty()) {
        for (const auto &e : target.functions)
            if (e.name == fn.name) return;
    }
    target.functions.push_back(std::move(fn));
}

} // namespace vx
