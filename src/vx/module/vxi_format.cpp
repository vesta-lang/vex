/**
 * @file vxi_format.cpp
 * @brief Implementacion del formato `.vxi` ( M.2).
 *
 * Layout binario detallado:
 *
 *   Header (40 bytes en v2; 32 bytes en v1):
 *     +0   u32  magic
 *     +4   u16  format_version
 *     +6   u16  _reserved
 *     +8   u64  abi_hash
 *     +16  u64  source_hash
 *     +24  u64  compiler_version_hash  (v2+)  cierra L.27
 *     +32  u32  symbol_count
 *     +36  u32  string_pool_offset
 *
 *   Symbol entry (variable, alineado a 4):
 *     +0   u8   kind (VxiSymbolKind)
 *     +1   u8   flags (bit 0 = is_opaque, bit 1 = is_extern)
 *     +2   u16  align_override (typedef new)
 *     +4   u32  name_off              (offset en string pool)
 *     +8   u32  name_len
 *     +12  u32  payload_off           (offset al payload variable)
 *     +16  u32  payload_len           (longitud del payload en bytes)
 *
 *   Payload per-kind (en el bloque de payload contiguo):
 *
 *     TYPEDEF_ALIAS / TYPEDEF_NEW (16+ bytes):
 *       +0   u64  nominal_abi
 *       +8   u32  underlying_off
 *       +12  u32  underlying_len
 *
 *     FUNCTION (16 + variable):
 *       +0   u32  ret_type_off
 *       +4   u32  ret_type_len
 *       +8   u32  param_count
 *       +12  u32  extern_lib_off (0 si !is_extern)
 *       +16  ParamSlot[param_count] (8 bytes c/u: u32 type_off, u16 type_len,
 * u16 name_off_packed/len)
 *
 *     STRUCT / CLASS (variable):
 *       +0   u32  super_off    (0 si STRUCT)
 *       +4   u32  super_len    (0 si STRUCT)
 *       +8   u32  size_bytes
 *       +12  u32  align_bytes
 *       +16  u32  field_count
 *       +20  u32  iface_count  (siempre 0 para STRUCT)
 *       +24  FieldSlot[field_count] (24 bytes c/u)
 *       +    NameSlot[iface_count]  (8 bytes c/u)
 *
 *     ENUM (variable):
 *       +0   u32  variant_count
 *       +4   VariantSlot[variant_count] (16 bytes c/u: tag, name_off, name_len,
 * payload_count, payload_off_off, payload_off_len)
 *       +    PayloadType[]   (entries de 8 bytes: off + len)
 *
 *   String pool (al final):
 *     bytes raw concatenados de cada nombre + tipo unique.  Sin null
 *     terminators (longitud va en el slot).  Dedup: cada string que se
 *     reuse apunta al mismo offset.
 *
 * Coste runtime estimado del emit/parse: ~5 us por modulo con 20 simbolos.
 * Despreciable comparado con el lex+parse del .vx original (~3-5 ms).
 */

#include "util/fnv.h" // la semilla y el primo, en UN sitio
#include "vx/module/vxi_format.h"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

// Header generado por CMake (cmake/gen_codegen_version.cmake) que define
// VXI_COMPILER_BUILD_ID con un hash de las fuentes de codegen.  Asi el
// cvh cambia SOLO cuando el codigo de generacion del compilador cambia.
// __has_include para no romper builds fuera del CMake (cae al __DATE__/__TIME__
// de abajo si el header no existe).
#if defined(__has_include)
#if __has_include("vx_codegen_version.h")
#include "vx_codegen_version.h"
#endif
#endif

namespace vx {

// ---------------------------------------------------------------------------
// FNV-1a 64-bit.  Identica formula que ModuleGraph::fnv1a_; replicada
// aqui para evitar dep circular module_resolver -> vxi_format.
// ---------------------------------------------------------------------------
namespace {

/**
 * @brief Nombres que aparecen dentro de un tipo canonico y NO son un tipo de
 *        usuario: primitivos y constructores del propio lenguaje.
 *
 * Lo que no este aqui y tampoco lo defina el modulo se toma por AJENO, que es
 * el lado seguro: equivocarse hacia aqui solo cuesta recompilar de mas.
 */
bool es_nombre_del_lenguaje(const std::string &n) {
    /* Solo lo que trae el LENGUAJE.  `usize`, `isize`, `byte` y `uintptr` NO
     * estan: son newtypes que declara `std.types`, o sea tipos de otro modulo,
     * y darlos por propios seria justo el error peligroso -- una interfaz que
     * los usa depende de ese modulo y tiene que enterarse si cambia. */
    static const std::unordered_set<std::string> k = {
        "void",
        "bool",
        "char",
        "string",
        "i8",
        "i16",
        "i32",
        "i64",
        "u8",
        "u16",
        "u32",
        "u64",
        "f32",
        "f64",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "float",
        "double",
        "ptr",
        "Object",
        "Any",
        // Constructores del lenguaje que envuelven a otro tipo.
        "Optional",
        "Result",
        "Array",
        "unique",
        "shared",
        "borrow",
        "borrow_mut",
        "gc",
        "atomic",
        "fn",
        "cfn",
        "VirtualPtr",
        "Future",
        "ArrayList",
        "HashMap",
        "HashSet",
        "Queue",
        "Deque",
        "TreeMap",
        "TreeSet",
        "Stack",
    };
    return k.count(n) != 0;
}

/// @brief Llama a @p ver por cada identificador de un typename canonico.
template <class F> void por_cada_identificador(const std::string &t, F ver) {
    size_t i = 0;
    while (i < t.size()) {
        const char c = t[i];
        const bool inicio =
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
        if (!inicio) {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < t.size()) {
            const char d = t[j];
            const bool sigue = (d >= 'A' && d <= 'Z') ||
                               (d >= 'a' && d <= 'z') ||
                               (d >= '0' && d <= '9') || d == '_';
            if (!sigue) break;
            ++j;
        }
        ver(t.substr(i, j - i));
        i = j;
    }
}

/**
 * @brief La cara publica del modulo, ¿menciona un tipo que no es suyo?
 *
 * Si la menciona, el tamano y la forma de ese tipo son parte de lo que ofrece:
 * quien llame a la funcion tiene que reservar y leer con ese layout.  Entonces
 * su interfaz SI depende de sus deps y la tabla de dependencias entra en el
 * hash.  Si se cierra sobre primitivos y sus propios tipos, no.
 */
bool interfaz_menciona_tipo_ajeno(const VxiModule &mod) {
    std::unordered_set<std::string> propios;
    for (const auto &s : mod.symbols) {
        switch (s.kind) {
        case VxiSymbolKind::TYPEDEF_ALIAS:
        case VxiSymbolKind::TYPEDEF_NEW:
        case VxiSymbolKind::STRUCT:
        case VxiSymbolKind::CLASS:
        case VxiSymbolKind::ENUM: propios.insert(s.name); break;
        default: break;
        }
    }
    bool ajeno = false;
    auto revisar = [&](const std::string &t) {
        if (ajeno || t.empty()) return;
        por_cada_identificador(t, [&](const std::string &id) {
            if (ajeno) return;
            if (es_nombre_del_lenguaje(id)) return;
            if (propios.count(id) != 0) return;
            ajeno = true;
        });
    };
    for (const auto &s : mod.symbols) {
        revisar(s.return_type);
        for (const auto &p : s.param_types)
            revisar(p);
        for (const auto &f : s.fields)
            revisar(f.type_str);
        revisar(s.underlying_type);
        revisar(s.super_class);
        for (const auto &i : s.interfaces)
            revisar(i);
        for (const auto &m : s.methods) {
            revisar(m.return_type);
            for (const auto &p : m.param_types)
                revisar(p);
        }
        if (ajeno) break;
    }
    return ajeno;
}

} // namespace

uint64_t vxi_fnv1a(const void *data, size_t len) noexcept {
    // La semilla y el primo viven en util/fnv.h, no aqui.
    return util::fnv_bytes(util::kFnvOffset, data, len);
}

// ===========================================================================
// String pool builder con dedup.  Cada string se añade una sola vez;
// segundo uso devuelve el mismo offset.
// ===========================================================================
class StringPoolBuilder {
  public:
    StringPoolBuilder() {
        // Reservar primer slot para "string vacio" (offset 0, len 0).
        // Esto permite usar offset=0 como sentinel "sin string" en
        // campos opcionales (super_class de struct, etc.).
        offsets_[""] = 0;
    }

    /// Devuelve el offset del string en el pool.  Si no estaba, lo añade.
    uint32_t intern(const std::string &s) {
        if (s.empty()) return 0;
        auto it = offsets_.find(s);
        if (it != offsets_.end()) return it->second;
        const uint32_t off = static_cast<uint32_t>(buf_.size());
        offsets_.emplace(s, off);
        buf_.insert(buf_.end(), s.begin(), s.end());
        return off;
    }

    const std::vector<uint8_t> &bytes() const noexcept { return buf_; }
    size_t size() const noexcept { return buf_.size(); }

  private:
    std::vector<uint8_t> buf_;
    std::unordered_map<std::string, uint32_t> offsets_;
};

// ---------------------------------------------------------------------------
// Helpers de escritura little-endian a un buffer.
// ---------------------------------------------------------------------------
static inline void write_u8(std::vector<uint8_t> &b, uint8_t v) {
    b.push_back(v);
}
static inline void write_u16(std::vector<uint8_t> &b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v & 0xFFu));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}
static inline void write_u32(std::vector<uint8_t> &b, uint32_t v) {
    b.push_back(static_cast<uint8_t>(v & 0xFFu));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    b.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    b.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}
static inline void write_u64(std::vector<uint8_t> &b, uint64_t v) {
    write_u32(b, static_cast<uint32_t>(v & 0xFFFFFFFFull));
    write_u32(b, static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFull));
}

// ---------------------------------------------------------------------------
// Helpers de lectura little-endian con bounds check.  Devuelven false si
// el read excede el buffer.
// ---------------------------------------------------------------------------
static inline bool read_u8(const uint8_t *p, size_t cap, size_t &off,
                           uint8_t &v) {
    if (off + 1 > cap) return false;
    v = p[off];
    off += 1;
    return true;
}
static inline bool read_u16(const uint8_t *p, size_t cap, size_t &off,
                            uint16_t &v) {
    if (off + 2 > cap) return false;
    v = static_cast<uint16_t>(p[off]) |
        (static_cast<uint16_t>(p[off + 1]) << 8);
    off += 2;
    return true;
}
static inline bool read_u32(const uint8_t *p, size_t cap, size_t &off,
                            uint32_t &v) {
    if (off + 4 > cap) return false;
    v = static_cast<uint32_t>(p[off]) |
        (static_cast<uint32_t>(p[off + 1]) << 8) |
        (static_cast<uint32_t>(p[off + 2]) << 16) |
        (static_cast<uint32_t>(p[off + 3]) << 24);
    off += 4;
    return true;
}
static inline bool read_u64(const uint8_t *p, size_t cap, size_t &off,
                            uint64_t &v) {
    uint32_t lo = 0, hi = 0;
    if (!read_u32(p, cap, off, lo)) return false;
    if (!read_u32(p, cap, off, hi)) return false;
    v = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
    return true;
}

// ===========================================================================
// Emitter: serializa VxiModule -> bytes.
// ===========================================================================
//
// Estrategia:
//   1. Construir string pool.
//   2. Emitir payloads variables a un buffer separado.
//   3. Emitir symbol entries (con offsets al pool + payload buffer).
//   4. añadir header al inicio + payloads + pool.
//   5. Calcular abi_hash sobre los simbolos serializados (sin header).
//
// El abi_hash incluye los bytes de TODAS las entries en orden + el pool.
// Cualquier cambio en la interfaz publica (nuevo simbolo, cambio de
// firma, etc.) produce un hash distinto.

// Base comun: 16 bytes con nominal_abi + underlying typename.  Usado
// por typedef alias/new y por global var (que extiende con init_value).
static void emit_typedef_base(std::vector<uint8_t> &payload,
                              StringPoolBuilder &pool, const VxiSymbol &sym) {
    write_u64(payload, sym.nominal_abi);
    const uint32_t und_off = pool.intern(sym.underlying_type);
    write_u32(payload, und_off);
    write_u32(payload, static_cast<uint32_t>(sym.underlying_type.size()));
}

static void emit_payload_for_typedef(std::vector<uint8_t> &payload,
                                     StringPoolBuilder &pool,
                                     const VxiSymbol &sym) {
    emit_typedef_base(payload, pool, sym);
    //  M.L8: bloque {explicit from/to T;}.  Para TYPEDEF_ALIAS el
    // bloque siempre esta vacio (cuenta 0); para TYPEDEF_NEW puede llevar
    // N entries.  Layout: u32 from_count + u32 to_count + entries en
    // orden (cada entry: type_off u32 + type_len u32 + is_public u8 + 3 pad).
    write_u32(payload, static_cast<uint32_t>(sym.from_conversions.size()));
    write_u32(payload, static_cast<uint32_t>(sym.to_conversions.size()));
    write_u32(payload,
              static_cast<uint32_t>(sym.implicit_from_conversions.size()));
    write_u32(payload,
              static_cast<uint32_t>(sym.implicit_to_conversions.size()));
    auto emit_conv = [&](const VxiSymbol::ExplicitConvEntry &c) {
        const uint32_t t_off = pool.intern(c.type_str);
        write_u32(payload, t_off);
        write_u32(payload, static_cast<uint32_t>(c.type_str.size()));
        write_u8(payload, c.is_public ? 1u : 0u);
        write_u8(payload, 0);
        write_u8(payload, 0);
        write_u8(payload, 0);
    };
    for (const auto &c : sym.from_conversions)
        emit_conv(c);
    for (const auto &c : sym.to_conversions)
        emit_conv(c);
    for (const auto &c : sym.implicit_from_conversions)
        emit_conv(c);
    for (const auto &c : sym.implicit_to_conversions)
        emit_conv(c);
}

// .vxi v4: GLOBAL_VAR.  Layout:
//   +0   typedef_base (16 bytes: nominal_abi u64 + und_off u32 + und_len u32)
//   +16  has_init_value u8 + 7 pad
//   +24  init_value u64
//   +32  has_blob_ref u8 + blob_kind_hint u8 + attr_flags u8 + 1 pad
//   +36  attr_align u16 + 2 pad
//   +40  blob_offset u32
//   +44  attr_section_off u32
//   +48  attr_section_len u32
//   = 52 bytes (multiplo de 4)
static void emit_payload_for_global(std::vector<uint8_t> &payload,
                                    StringPoolBuilder &pool,
                                    const VxiSymbol &sym) {
    emit_typedef_base(payload, pool, sym); // 16 bytes
    write_u8(payload, sym.has_init_value ? 1u : 0u);
    write_u8(payload, 0);
    write_u8(payload, 0);
    write_u8(payload, 0);
    write_u8(payload, 0);
    write_u8(payload, 0);
    write_u8(payload, 0);
    write_u8(payload, 0); // 7 bytes pad para alinear el u64
    write_u32(payload, static_cast<uint32_t>(sym.init_value & 0xFFFFFFFFull));
    write_u32(payload,
              static_cast<uint32_t>((sym.init_value >> 32) & 0xFFFFFFFFull));
    // v4: blob ref + atributos.
    write_u8(payload, sym.has_blob_ref ? 1u : 0u);
    write_u8(payload, sym.blob_kind_hint);
    write_u8(payload, sym.attr_flags);
    write_u8(payload, 0);
    write_u16(payload, sym.attr_align);
    write_u8(payload, 0);
    write_u8(payload, 0);
    write_u32(payload, sym.blob_offset);
    const uint32_t sec_off =
        sym.attr_section.empty() ? 0u : pool.intern(sym.attr_section);
    write_u32(payload, sec_off);
    write_u32(payload, static_cast<uint32_t>(sym.attr_section.size()));
    // NS.2 (v7): ns_path del global (off + len; vacio = nivel de modulo).
    const uint32_t nsp_off = pool.intern(sym.ns_path);
    write_u32(payload, nsp_off);
    write_u32(payload, static_cast<uint32_t>(sym.ns_path.size()));
}

static void emit_payload_for_function(std::vector<uint8_t> &payload,
                                      StringPoolBuilder &pool,
                                      const VxiSymbol &sym) {
    const uint32_t ret_off = pool.intern(sym.return_type);
    write_u32(payload, ret_off);
    write_u32(payload, static_cast<uint32_t>(sym.return_type.size()));
    write_u32(payload, static_cast<uint32_t>(sym.param_types.size()));
    const uint32_t lib_off = sym.is_extern ? pool.intern(sym.extern_lib) : 0;
    write_u32(payload, lib_off);
    //  M5.b L.5: lib_len explicito (sustituye el hack de truncar al
    // primer NUL o a 256 bytes en versiones previas).
    write_u32(payload, sym.is_extern
                           ? static_cast<uint32_t>(sym.extern_lib.size())
                           : 0u);
    //  M.5: mangled_label (8 bytes: off + len; vacio = mismo que name).
    const uint32_t ml_off = pool.intern(sym.mangled_label);
    write_u32(payload, ml_off);
    write_u32(payload, static_cast<uint32_t>(sym.mangled_label.size()));
    // NS.2: ns_path (8 bytes: off + len; vacio = simbolo a nivel de modulo).
    // El namespace DECLARADO al que pertenece el simbolo, para que el
    // consumidor haga visible `mylib.helper()` al importar el modulo.
    const uint32_t nsp_off = pool.intern(sym.ns_path);
    write_u32(payload, nsp_off);
    write_u32(payload, static_cast<uint32_t>(sym.ns_path.size()));
    // ParamSlot: type_off (u32) + type_len (u32) + name_off (u32) + name_len
    // (u32) + abi_off (u32) + abi_len (u32). 24 bytes c/u.  El abi_reg es el
    // registro fisico canonico del ABI custom (`register("rax")` en params);
    // vacio = ABI estandar.
    const size_t n = sym.param_types.size();
    for (size_t i = 0; i < n; ++i) {
        const uint32_t t_off = pool.intern(sym.param_types[i]);
        write_u32(payload, t_off);
        write_u32(payload, static_cast<uint32_t>(sym.param_types[i].size()));
        std::string nm =
            (i < sym.param_names.size()) ? sym.param_names[i] : std::string();
        const uint32_t n_off = pool.intern(nm);
        write_u32(payload, n_off);
        write_u32(payload, static_cast<uint32_t>(nm.size()));
        std::string ab = (i < sym.param_abi_regs.size()) ? sym.param_abi_regs[i]
                                                         : std::string();
        const uint32_t a_off = pool.intern(ab);
        write_u32(payload, a_off);
        write_u32(payload, static_cast<uint32_t>(ab.size()));
    }
}

static void emit_payload_for_struct_or_class(std::vector<uint8_t> &payload,
                                             StringPoolBuilder &pool,
                                             const VxiSymbol &sym) {
    const uint32_t super_off = pool.intern(sym.super_class);
    write_u32(payload, super_off);
    write_u32(payload, static_cast<uint32_t>(sym.super_class.size()));
    write_u32(payload, sym.size_bytes);
    write_u32(payload, sym.align_bytes);
    // STRUCT overlay: flag + extension real (para reconocer `Tipo(ptr)`
    // cross-modulo).
    write_u8(payload, sym.is_overlay ? 1u : 0u);
    write_u32(payload, sym.overlay_extent);
    write_u32(payload, static_cast<uint32_t>(sym.fields.size()));
    write_u32(payload, static_cast<uint32_t>(sym.interfaces.size()));
    //  M6.b L.6: method_count antes de las entries.
    write_u32(payload, static_cast<uint32_t>(sym.methods.size()));
    // FieldSlot: name_off+len + type_off+len + offset + size + bit_offset +
    // bit_width + pad. 24 bytes c/u alineados.
    for (const auto &f : sym.fields) {
        const uint32_t no = pool.intern(f.name);
        const uint32_t to = pool.intern(f.type_str);
        write_u32(payload, no);
        write_u32(payload, static_cast<uint32_t>(f.name.size()));
        write_u32(payload, to);
        write_u32(payload, static_cast<uint32_t>(f.type_str.size()));
        write_u32(payload, f.offset);
        write_u16(payload, static_cast<uint16_t>(f.size));
        write_u8(payload, f.bit_offset);
        write_u8(payload, f.bit_width);
    }
    // InterfaceSlot: name_off+len (8 bytes c/u).
    for (const auto &iname : sym.interfaces) {
        const uint32_t no = pool.intern(iname);
        write_u32(payload, no);
        write_u32(payload, static_cast<uint32_t>(iname.size()));
    }
    // MethodSlot: name + return_type + param_count + vtable_index + flags
    //             + mangled_label + param_types[].  Variable length.
    for (const auto &m : sym.methods) {
        const uint32_t no = pool.intern(m.name);
        const uint32_t ro = pool.intern(m.return_type);
        const uint32_t ml = pool.intern(m.mangled_label);
        write_u32(payload, no);
        write_u32(payload, static_cast<uint32_t>(m.name.size()));
        write_u32(payload, ro);
        write_u32(payload, static_cast<uint32_t>(m.return_type.size()));
        write_u32(payload, static_cast<uint32_t>(m.param_types.size()));
        write_u32(payload, m.vtable_index);
        write_u32(payload, static_cast<uint32_t>(m.flags));
        write_u32(payload, ml);
        write_u32(payload, static_cast<uint32_t>(m.mangled_label.size()));
        // Param types inline.
        for (const auto &pt : m.param_types) {
            const uint32_t to = pool.intern(pt);
            write_u32(payload, to);
            write_u32(payload, static_cast<uint32_t>(pt.size()));
        }
    }
    // NS.2 (v8): ns_path del tipo al final del payload (off+len; vacio = nivel
    // de modulo).  Permite el round-trip cross-modulo de tipos namespaced.
    const uint32_t nsp_off = pool.intern(sym.ns_path);
    write_u32(payload, nsp_off);
    write_u32(payload, static_cast<uint32_t>(sym.ns_path.size()));
}

static void emit_payload_for_enum(std::vector<uint8_t> &payload,
                                  StringPoolBuilder &pool,
                                  const VxiSymbol &sym) {
    // v5: size_bytes + align_bytes al inicio para que el consumer
    // pueda allocar slots correctamente.  Antes de v5 el consumer
    // veia size_bytes=0 y allocaba slots de 0 bytes -> corrupcion.
    write_u32(payload, sym.size_bytes);
    write_u32(payload, sym.align_bytes);
    /* El TIPO BASE del enum (`enum Color : u8`).
     *
     * El lector lo lee aqui desde siempre -- su comprobacion de tamano minimo
     * cuenta con el (4+4+8+4) -- y este lado no lo escribia NUNCA.  El
     * resultado no era un campo vacio: el lector se comia ocho bytes que eran
     * la cuenta de variantes y la etiqueta de la primera, y a partir de ahi
     * leia el payload corrido.  Un `.vxi` con un enum dentro NO PARSEA.
     *
     * No se veia porque un interfaz que no parsea es un fallo de cache, y un
     * fallo de cache se arregla solo recompilando desde el fuente: el programa
     * sale bien y lo unico que se pierde es, en silencio, todo lo incremental
     * de cualquier modulo que declare un enum. */
    const uint32_t und_off = pool.intern(sym.underlying_type);
    write_u32(payload, und_off);
    write_u32(payload, static_cast<uint32_t>(sym.underlying_type.size()));
    write_u32(payload, static_cast<uint32_t>(sym.variants.size()));
    // VariantSlot: tag + name_off+len + payload_count + payload entries inline.
    for (const auto &v : sym.variants) {
        write_u32(payload, v.tag);
        const uint32_t no = pool.intern(v.name);
        write_u32(payload, no);
        write_u32(payload, static_cast<uint32_t>(v.name.size()));
        write_u32(payload, static_cast<uint32_t>(v.payload_types.size()));
        for (const auto &pt : v.payload_types) {
            const uint32_t to = pool.intern(pt);
            write_u32(payload, to);
            write_u32(payload, static_cast<uint32_t>(pt.size()));
        }
        // v15: valor de la variante (enums C-style, `Less = -1`).  Sin esto
        // un enum con valor importado llegaba con sus variantes sin valor.
        write_u64(payload, static_cast<uint64_t>(v.int_value));
    }
    // NS.2 (v8): ns_path del enum al final del payload (off+len).
    const uint32_t nsp_off = pool.intern(sym.ns_path);
    write_u32(payload, nsp_off);
    write_u32(payload, static_cast<uint32_t>(sym.ns_path.size()));
}

std::vector<uint8_t> vxi_emit(const VxiModule &mod) {
    // 1. Construir string pool + payloads contiguos.
    StringPoolBuilder pool;
    std::vector<uint8_t> payloads;
    payloads.reserve(mod.symbols.size() * 32);

    struct SymOffset {
        uint32_t name_off;
        uint32_t name_len;
        uint32_t payload_off;
        uint32_t payload_len;
        uint8_t flags;
        uint16_t align_override;
    };
    std::vector<SymOffset> sym_offsets;
    sym_offsets.reserve(mod.symbols.size());

    for (const auto &sym : mod.symbols) {
        SymOffset so{};
        so.name_off = pool.intern(sym.name);
        so.name_len = static_cast<uint32_t>(sym.name.size());
        so.payload_off = static_cast<uint32_t>(payloads.size());
        so.flags = 0;
        if (sym.is_opaque) so.flags |= 0x01;
        if (sym.is_extern) so.flags |= 0x02;
        if (sym.is_const) so.flags |= 0x04; // L.7: GLOBAL_VAR const
        if (sym.is_naked) so.flags |= 0x08; // LIM-A: FUNCTION @Naked
        if (sym.is_internal)
            so.flags |= 0x10; // NS.3: internal (package-scoped)
        so.align_override = sym.align_override;

        switch (sym.kind) {
        case VxiSymbolKind::TYPEDEF_ALIAS:
        case VxiSymbolKind::TYPEDEF_NEW:
            emit_payload_for_typedef(payloads, pool, sym);
            break;
        case VxiSymbolKind::FUNCTION:
            emit_payload_for_function(payloads, pool, sym);
            break;
        case VxiSymbolKind::STRUCT:
        case VxiSymbolKind::CLASS:
            emit_payload_for_struct_or_class(payloads, pool, sym);
            break;
        case VxiSymbolKind::ENUM:
            emit_payload_for_enum(payloads, pool, sym);
            break;
        case VxiSymbolKind::GLOBAL_VAR:
            //  M.L7: extiende typedef payload con init_value
            // para que el lowering pueda inline-ar const numericas.
            emit_payload_for_global(payloads, pool, sym);
            break;
        }
        so.payload_len =
            static_cast<uint32_t>(payloads.size()) - so.payload_off;
        sym_offsets.push_back(so);
    }

    // 2. Construir el buffer final: header + symbol entries + payloads + deps
    //    + blob_pool + string_pool.
    // .vxi v4: header crece de 48 a 64 bytes (añade blob_pool_offset u32 +
    // blob_pool_size u32 + blob_pool_alignment u8 + 7 pad en offsets 48..63).
    // v6: crece a 80 (gen_templates_offset u32 + gen_templates_count u32 +
    // 8 pad en offsets 64..79).
    const size_t HEADER_BYTES = 136; // v18: +conjunto comptime (104..132)
    const size_t GEN_ENTRY_BYTES =
        28; // name_off+name_len+kind+src_off+src_len+ns_off+ns_len (v9)
    const size_t SYMENTRY_BYTES = 20; // 1 + 1 + 2 + 4 + 4 + 4 + 4
    const size_t DEP_ENTRY_BYTES =
        16; // u32 name_off + u32 name_len + u64 abi_hash
    const size_t entries_bytes = mod.symbols.size() * SYMENTRY_BYTES;
    const size_t payloads_bytes = payloads.size();
    const size_t deps_bytes = mod.deps.size() * DEP_ENTRY_BYTES;
    const size_t blob_pool_bytes = mod.blob_pool.size();
    const size_t pool_bytes = pool.bytes().size();

    // Pre-internamos los nombres de los deps al pool ANTES de calcular
    // offsets (asi el pool_start no cambia tras emit de la dep table).
    std::vector<std::pair<uint32_t, uint32_t>> dep_name_offs;
    dep_name_offs.reserve(mod.deps.size());
    for (const auto &d : mod.deps) {
        dep_name_offs.emplace_back(pool.intern(d.name),
                                   static_cast<uint32_t>(d.name.size()));
    }
    // v6: pre-internar nombre + fuente de cada plantilla generica exportada.
    struct GenTplOff {
        uint32_t name_off, name_len, kind, src_off, src_len, ns_off, ns_len;
    };
    std::vector<GenTplOff> gen_offs;
    gen_offs.reserve(mod.generic_templates.size());
    for (const auto &g : mod.generic_templates) {
        GenTplOff go{};
        go.name_off = pool.intern(g.name);
        go.name_len = static_cast<uint32_t>(g.name.size());
        go.kind = g.kind;
        go.src_off = pool.intern(g.source);
        go.src_len = static_cast<uint32_t>(g.source.size());
        go.ns_off = pool.intern(g.ns_path);
        go.ns_len = static_cast<uint32_t>(g.ns_path.size());
        gen_offs.push_back(go);
    }
    /* v18: internar el conjunto comptime -- su texto y los nombres que lo
     * forman.  Va en el `.vxi` porque extraerlo necesita el AST y un modulo
     * servido del cache no se parsea; guardarlo aqui lo deja disponible sin
     * volver a parsear nada. */
    const uint32_t ct_src_off = pool.intern(mod.comptime_unit_source);
    const uint32_t ct_src_len =
        static_cast<uint32_t>(mod.comptime_unit_source.size());
    std::vector<std::pair<uint32_t, uint32_t>> ct_name_offs;
    ct_name_offs.reserve(mod.comptime_unit_names.size());
    for (const auto &n : mod.comptime_unit_names)
        ct_name_offs.emplace_back(pool.intern(n),
                                  static_cast<uint32_t>(n.size()));
    std::vector<std::pair<uint32_t, uint32_t>> ct_notcol_offs;
    ct_notcol_offs.reserve(mod.comptime_unit_not_collected.size());
    for (const auto &n : mod.comptime_unit_not_collected)
        ct_notcol_offs.emplace_back(pool.intern(n),
                                    static_cast<uint32_t>(n.size()));
    // v13: internar el OBJETIVO con el que se genera este .vxi, pero SOLO si el
    // modulo usa @Target.  Vacio -> offset 0 -> artefacto valido para cualquier
    // objetivo, que es el caso de casi todos los modulos.
    const uint32_t target_off =
        mod.target.empty() ? 0u : pool.intern(mod.target);
    // NS.3 (v10): internar el package_id (vacio = paquete anonimo).
    const uint32_t pkgid_off = pool.intern(mod.package_id);
    const uint32_t pkgid_len = static_cast<uint32_t>(mod.package_id.size());
    // NS.6-ext (v11): pre-internar los strings de cada ext_method.
    struct ExtOff {
        uint32_t tk_off, tk_len, nm_off, nm_len, rt_off, rt_len, ml_off, ml_len;
        uint8_t is_class;
        std::vector<std::pair<uint32_t, uint32_t>> params; // (off, len)
    };
    std::vector<ExtOff> ext_offs;
    ext_offs.reserve(mod.ext_methods.size());
    for (const auto &em : mod.ext_methods) {
        ExtOff eo{};
        eo.tk_off = pool.intern(em.target_key);
        eo.tk_len = static_cast<uint32_t>(em.target_key.size());
        eo.nm_off = pool.intern(em.name);
        eo.nm_len = static_cast<uint32_t>(em.name.size());
        eo.rt_off = pool.intern(em.return_type);
        eo.rt_len = static_cast<uint32_t>(em.return_type.size());
        eo.ml_off = pool.intern(em.mangled_label);
        eo.ml_len = static_cast<uint32_t>(em.mangled_label.size());
        eo.is_class = em.target_is_class ? 1 : 0;
        for (const auto &pt : em.param_types)
            eo.params.emplace_back(pool.intern(pt),
                                   static_cast<uint32_t>(pt.size()));
        ext_offs.push_back(std::move(eo));
    }

    std::vector<uint8_t> out;
    out.reserve(HEADER_BYTES + entries_bytes + payloads_bytes + deps_bytes +
                blob_pool_bytes + pool_bytes + 8);

    // Header placeholder; rellenamos al final con offsets correctos.
    out.resize(HEADER_BYTES, 0);

    // Symbol entries (todos consecutivos).
    const uint32_t entries_start = static_cast<uint32_t>(out.size());
    for (size_t i = 0; i < mod.symbols.size(); ++i) {
        const auto &sym = mod.symbols[i];
        const auto &so = sym_offsets[i];
        write_u8(out, static_cast<uint8_t>(sym.kind));
        write_u8(out, so.flags);
        write_u16(out, so.align_override);
        write_u32(out, so.name_off);
        write_u32(out, so.name_len);
        write_u32(out, so.payload_off);
        write_u32(out, so.payload_len);
    }

    // Payloads contiguos tras las entries.
    const uint32_t payloads_start = static_cast<uint32_t>(out.size());
    out.insert(out.end(), payloads.begin(), payloads.end());

    //  M4.ext L.13: dep table tras los payloads, antes del blob_pool.
    const uint32_t deps_start = static_cast<uint32_t>(out.size());
    for (size_t i = 0; i < mod.deps.size(); ++i) {
        write_u32(out, dep_name_offs[i].first);  // name_off (rel al pool)
        write_u32(out, dep_name_offs[i].second); // name_len
        // abi_hash u64 little-endian
        const uint64_t h = mod.deps[i].abi_hash;
        write_u32(out, static_cast<uint32_t>(h & 0xFFFFFFFFull));
        write_u32(out, static_cast<uint32_t>((h >> 32) & 0xFFFFFFFFull));
    }

    // v4: blob_pool tras la dep table.  Alineado a 8 bytes para que los
    // BlobHeaders dentro mantengan su alineamiento absoluto al inicio del
    // fichero (asumiendo HEADER_BYTES=64 + entries+payloads+deps son ya
    // multiplos de 4).  Pad explicito al multiplo de 8.
    while (out.size() % 8 != 0)
        out.push_back(0);
    const uint32_t blob_pool_start = static_cast<uint32_t>(out.size());
    if (!mod.blob_pool.empty()) {
        out.insert(out.end(), mod.blob_pool.begin(), mod.blob_pool.end());
    }

    // v6: tabla de plantillas genericas tras el blob_pool, antes del pool.
    // Cada entrada referencia offsets dentro del string pool (name + source).
    const uint32_t gen_start = static_cast<uint32_t>(out.size());
    for (const auto &go : gen_offs) {
        write_u32(out, go.name_off);
        write_u32(out, go.name_len);
        write_u32(out, go.kind);
        write_u32(out, go.src_off);
        write_u32(out, go.src_len);
        write_u32(out, go.ns_off);
        write_u32(out, go.ns_len);
    }

    // NS.6-ext (v11): tabla de ext_methods tras las plantillas genericas.
    // Entrada variable: tk+nm+rt+ml (off+len c/u) + is_class(u8) + pad(3) +
    // param_count(u32) + params[param_count] (off+len c/u).
    const uint32_t ext_start = static_cast<uint32_t>(out.size());
    for (const auto &eo : ext_offs) {
        write_u32(out, eo.tk_off);
        write_u32(out, eo.tk_len);
        write_u32(out, eo.nm_off);
        write_u32(out, eo.nm_len);
        write_u32(out, eo.rt_off);
        write_u32(out, eo.rt_len);
        write_u32(out, eo.ml_off);
        write_u32(out, eo.ml_len);
        out.push_back(eo.is_class);
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        write_u32(out, static_cast<uint32_t>(eo.params.size()));
        for (const auto &pp : eo.params) {
            write_u32(out, pp.first);
            write_u32(out, pp.second);
        }
    }

    /* v18: las dos tablas del conjunto comptime (nombres y no-recogidos).
     * Ocho bytes por entrada: offset en el pool + longitud. */
    const uint32_t ct_names_start = static_cast<uint32_t>(out.size());
    for (const auto &p : ct_name_offs) {
        write_u32(out, p.first);
        write_u32(out, p.second);
    }
    const uint32_t ct_notcol_start = static_cast<uint32_t>(out.size());
    for (const auto &p : ct_notcol_offs) {
        write_u32(out, p.first);
        write_u32(out, p.second);
    }

    // String pool al final.
    const uint32_t pool_start = static_cast<uint32_t>(out.size());
    out.insert(out.end(), pool.bytes().begin(), pool.bytes().end());

    // 3. Re-escribir header con los valores reales.
    auto patch_u32 = [&](size_t pos, uint32_t v) {
        out[pos + 0] = static_cast<uint8_t>(v & 0xFFu);
        out[pos + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
        out[pos + 2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
        out[pos + 3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
    };
    auto patch_u64 = [&](size_t pos, uint64_t v) {
        patch_u32(pos, static_cast<uint32_t>(v & 0xFFFFFFFFull));
        patch_u32(pos + 4, static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFull));
    };
    patch_u32(0, VXI_MAGIC);
    patch_u32(4, static_cast<uint16_t>(VXI_FORMAT_VERSION) |
                     (static_cast<uint32_t>(0) << 16));
    /* 4. abi_hash: lo que el modulo OFRECE.  Cubre todo lo que va despues del
     * header MENOS la tabla de dependencias.
     *
     * Que esa tabla entrase era el motivo de que la invalidacion se propagara a
     * ciegas: la tabla lleva el `abi_hash` de cada dep, asi que tocar la
     * interfaz de `m0` cambiaba tambien la de `m1` -- aunque `m1` ofreciera
     * exactamente lo mismo que antes -- y de ahi a `m2`, y asi hasta el final.
     * Medido en una cadena de cuarenta modulos: se rehacian veintiuno.
     *
     * De quien depende un modulo NO es parte de lo que ofrece.  Sigue estando
     * en el fichero, y sigue comprobandose: el lector compara dep a dep contra
     * el `abi_hash` actual de cada uno.  Eso es lo que hace la validacion
     * transitiva, y hacerlo ademas por el hash de la interfaz era contarlo dos
     * veces, mal. */
    /* SALVEDADES, y por eso no es un simple borrado.  Hay dos formas de que lo
     * que un modulo ofrece dependa DE VERDAD de sus deps:
     *
     *   - Exporta PLANTILLAS genericas.  Una plantilla exporta codigo FUENTE,
     * no una firma cerrada: quien la instancia la compila en su propio modulo,
     *     asi que lo que la plantilla llame -- que vive en los deps de QUIEN LA
     *     EXPORTA -- le afecta aunque el no lo importe.
     *
     *   - Sus firmas publicas MENCIONAN un tipo ajeno.  Entonces el tamano y la
     *     forma de ese tipo son parte de lo que se ofrece: quien llame a la
     *     funcion necesita reservar y leer con ese layout.  Verificado: con un
     *     `Punto` de otro modulo en la firma, cambiarle un campo dejaba a un
     *     consumidor intermedio con el layout viejo.  (No daba un programa mal:
     *     lo cazaba el analisis de regiones al construir, diciendo que la
     *     lectura se salia del objeto.  Pero romper la construccion tampoco es
     *     la respuesta correcta.)
     *
     * En los dos casos la tabla de dependencias SI es parte de la interfaz.  En
     * el resto -- un modulo cuya cara publica se cierra sobre primitivos y sus
     * propios tipos -- no lo es, y ahi se corta la propagacion. */
    const bool exporta_plantillas = !gen_offs.empty();
    const bool interfaz_abierta = interfaz_menciona_tipo_ajeno(mod);
    const bool depende_de_sus_deps = exporta_plantillas || interfaz_abierta;
    uint64_t abi_hash =
        depende_de_sus_deps
            ? vxi_fnv1a(out.data() + HEADER_BYTES, out.size() - HEADER_BYTES)
            : vxi_fnv1a(out.data() + HEADER_BYTES, deps_start - HEADER_BYTES);
    if (!depende_de_sus_deps) {
        const uint64_t resto = vxi_fnv1a(out.data() + blob_pool_start,
                                         out.size() - blob_pool_start);
        abi_hash ^=
            resto + 0x9E3779B97F4A7C15ULL + (abi_hash << 6) + (abi_hash >> 2);
    }
    patch_u64(8, abi_hash);
    patch_u64(16, mod.source_hash);
    //  M5.b L.27: compiler_version_hash en offset 24.  Si el caller
    // ya lo seteo en mod (testing), respetamos su valor; si no, usamos
    // el del compilador actual.
    const uint64_t cvh = (mod.compiler_version_hash != 0)
                             ? mod.compiler_version_hash
                             : vxi_compiler_version_hash();
    patch_u64(24, cvh);

    // symbol_count + string_pool_offset (relativo al inicio del fichero).
    patch_u32(32, static_cast<uint32_t>(mod.symbols.size()));
    patch_u32(36, pool_start);
    //  M4.ext L.13: dep_count + dep_table_offset (offset al inicio
    // del bloque de DepEntry, 16 bytes c/u en formato u32+u32+u64).
    patch_u32(40, static_cast<uint32_t>(mod.deps.size()));
    patch_u32(44, deps_start);
    // v4: blob_pool_offset + blob_pool_size + blob_pool_alignment + pad.
    patch_u32(48, blob_pool_start);
    patch_u32(52, static_cast<uint32_t>(mod.blob_pool.size()));
    out[56] = mod.blob_pool_alignment;
    out[57] = 0;
    out[58] = 0;
    out[59] = 0;
    // v13: target_offset (60).  0 = el modulo no usa @Target -> su contenido
    // no depende del objetivo y el artefacto vale para todos.  Solo los que si
    // lo usan quedan atados, para no invalidar la stdlib entera al cambiar de
    // target.
    patch_u32(60, target_off);
    // v6: gen_templates_offset (64) + gen_templates_count (68).
    patch_u32(64, gen_start);
    patch_u32(68, static_cast<uint32_t>(mod.generic_templates.size()));
    // NS.3 (v10): package_id en el pad v6 (72 = offset RELATIVO al pool,
    // 76 = longitud).  El parser suma string_pool_offset al leerlo.
    patch_u32(72, pkgid_off);
    patch_u32(76, pkgid_len);
    // NS.6-ext (v11): ext_methods (80 = offset absoluto de la tabla en el
    // fichero, 84 = numero de entradas).
    patch_u32(80, ext_start);
    patch_u32(84, static_cast<uint32_t>(mod.ext_methods.size()));
    // v17 (88, 96): huella del mapa de diagnostico del modulo.  Cero = no
    // aporta ninguno, que es lo que era cierto antes de que esto existiera.
    patch_u64(88, mod.vxdbg_map_lo);
    patch_u64(96, mod.vxdbg_map_hi);
    /* v18 (104..132): el conjunto comptime.  Texto (offset RELATIVO al pool +
     * longitud), su huella, y las dos tablas de nombres (offset ABSOLUTO en el
     * fichero + numero de entradas), en la misma convencion que el resto. */
    patch_u32(104, ct_src_off);
    patch_u32(108, ct_src_len);
    patch_u64(112, mod.comptime_unit_hash);
    patch_u32(120, static_cast<uint32_t>(ct_name_offs.size()));
    patch_u32(124, ct_names_start);
    patch_u32(128, static_cast<uint32_t>(ct_notcol_offs.size()));
    patch_u32(132, ct_notcol_start);

    // Adjustar payload_off de cada entry: hasta ahora son relativos al
    // BLOQUE de payloads (empieza en 0).  Sumar payloads_start para que
    // sean offsets absolutos desde el inicio del fichero.
    for (size_t i = 0; i < mod.symbols.size(); ++i) {
        const size_t entry_pos = entries_start + i * SYMENTRY_BYTES;
        const size_t poff_pos =
            entry_pos + 12; // tras kind+flags+align+name_off+name_len
        uint32_t cur = 0;
        cur = static_cast<uint32_t>(out[poff_pos + 0]) |
              (static_cast<uint32_t>(out[poff_pos + 1]) << 8) |
              (static_cast<uint32_t>(out[poff_pos + 2]) << 16) |
              (static_cast<uint32_t>(out[poff_pos + 3]) << 24);
        cur += payloads_start;
        patch_u32(poff_pos, cur);
    }
    // Similarmente, todos los name_off + offsets dentro de payloads
    // apuntan al pool; los emitimos ya con offset relativo al pool.
    // El parser sabe sumar pool_start (= string_pool_offset del header)
    // para obtener offset absoluto al pool.  Convencion: en disco, los
    // *_off de strings se almacenan RELATIVOS al inicio del pool (no
    // absolutos al fichero) para simplificar el parser.

    return out;
}

uint64_t vxi_hash_de_simbolos(const VxiModule &m,
                              const std::vector<std::string> &nombres) {
    /* Orden fijo: el consumidor puede escribir sus imports como quiera, y la
     * huella tiene que salir la misma. */
    std::vector<std::string> orden = nombres;
    std::sort(orden.begin(), orden.end());
    orden.erase(std::unique(orden.begin(), orden.end()), orden.end());

    uint64_t h = 0xCBF29CE484222325ULL;
    auto mezclar = [&h](const void *datos, size_t n) {
        const auto *p = static_cast<const unsigned char *>(datos);
        for (size_t i = 0; i < n; ++i) {
            h ^= static_cast<uint64_t>(p[i]);
            h *= 0x100000001B3ULL;
        }
    };

    for (const std::string &nombre : orden) {
        /* El nombre SIEMPRE, exista o no el simbolo: asi quitar de la libreria
         * algo que alguien usaba tambien cambia su huella (antes solo cambiaba
         * si quedaba algun otro simbolo que si estuviera). */
        mezclar(nombre.data(), nombre.size());
        const VxiSymbol *encontrado = nullptr;
        for (const auto &s : m.symbols) {
            if (s.name == nombre) {
                encontrado = &s;
                break;
            }
        }
        if (encontrado == nullptr) {
            h ^= 0xA5A5A5A5A5A5A5A5ULL; // marca de "no esta"
            h *= 0x100000001B3ULL;
            continue;
        }
        /* Y su contenido, definido como LO QUE EL ESCRITOR PERSISTE de el: se
         * serializa un modulo con ese unico simbolo y se hashean sus bytes.
         * Enumerar los campos a mano seria una lista que se queda corta el dia
         * que se anade uno, y quedarse corto aqui no recompila de mas: sirve un
         * artefacto que no corresponde al fuente. */
        VxiModule solo;
        solo.package_id = m.package_id; // la identidad del paquete si cuenta
        solo.target = m.target;         // y el objetivo, que cambia layouts
        solo.blob_pool = m.blob_pool;   // el simbolo puede referenciarlo
        solo.blob_pool_alignment = m.blob_pool_alignment;
        solo.symbols.push_back(*encontrado);
        const std::vector<uint8_t> bytes = vxi_emit(solo);
        /* Sin la cabecera: ahi vive el `abi_hash` de este modulo de un solo
         * simbolo, que es funcion de lo demas y no aporta. */
        constexpr size_t kCabecera = 104;
        if (bytes.size() > kCabecera)
            mezclar(bytes.data() + kCabecera, bytes.size() - kCabecera);
    }
    return h;
}

// ===========================================================================
// Parser: bytes -> VxiModule.
// ===========================================================================

static bool read_name(const uint8_t *data, size_t size, uint32_t name_off,
                      uint32_t name_len, uint32_t pool_start,
                      std::string &out) {
    const size_t abs = static_cast<size_t>(pool_start) + name_off;
    if (abs + name_len > size) return false;
    out.assign(reinterpret_cast<const char *>(data) + abs, name_len);
    return true;
}

static bool parse_payload_typedef(const uint8_t *data, size_t size,
                                  uint32_t payload_off, uint32_t payload_len,
                                  uint32_t pool_start, VxiSymbol &out) {
    if (payload_len < 16) return false;
    size_t off = payload_off;
    if (!read_u64(data, size, off, out.nominal_abi)) return false;
    uint32_t und_off = 0, und_len = 0;
    if (!read_u32(data, size, off, und_off)) return false;
    if (!read_u32(data, size, off, und_len)) return false;
    if (!read_name(data, size, und_off, und_len, pool_start,
                   out.underlying_type)) {
        return false;
    }
    //  M.L8: bloque {from/to} conversions.  Si payload no incluye
    // estos campos (compat con .vxi v2 viejos), retornar OK con listas
    // vacias.  El offset actual debe caber dentro de payload_off+payload_len.
    if (off + 8 > payload_off + payload_len) {
        return true;
    }
    uint32_t from_count = 0, to_count = 0;
    uint32_t imp_from_count = 0, imp_to_count = 0;
    if (!read_u32(data, size, off, from_count)) return false;
    if (!read_u32(data, size, off, to_count)) return false;
    if (!read_u32(data, size, off, imp_from_count)) return false;
    if (!read_u32(data, size, off, imp_to_count)) return false;
    if (from_count > 1000 || to_count > 1000 || imp_from_count > 1000 ||
        imp_to_count > 1000)
        return false; // sanity
    auto read_conv = [&](VxiSymbol::ExplicitConvEntry &c) -> bool {
        uint32_t t_off = 0, t_len = 0;
        if (!read_u32(data, size, off, t_off)) return false;
        if (!read_u32(data, size, off, t_len)) return false;
        uint8_t pub = 0;
        if (!read_u8(data, size, off, pub)) return false;
        // skip 3 bytes pad
        off += 3;
        c.is_public = (pub != 0);
        return read_name(data, size, t_off, t_len, pool_start, c.type_str);
    };
    out.from_conversions.resize(from_count);
    for (uint32_t i = 0; i < from_count; ++i) {
        if (!read_conv(out.from_conversions[i])) return false;
    }
    out.to_conversions.resize(to_count);
    for (uint32_t i = 0; i < to_count; ++i) {
        if (!read_conv(out.to_conversions[i])) return false;
    }
    out.implicit_from_conversions.resize(imp_from_count);
    for (uint32_t i = 0; i < imp_from_count; ++i) {
        if (!read_conv(out.implicit_from_conversions[i])) return false;
    }
    out.implicit_to_conversions.resize(imp_to_count);
    for (uint32_t i = 0; i < imp_to_count; ++i) {
        if (!read_conv(out.implicit_to_conversions[i])) return false;
    }
    return true;
}

//  M.L7: parse del payload extendido para GLOBAL_VAR.  Layout:
//   bytes 0-15  : nominal_abi (u64) + und_off (u32) + und_len (u32)
//   bytes 16-31 : has_init_value (u8) + 7 pad + init_value (u64)
static bool parse_payload_global(const uint8_t *data, size_t size,
                                 uint32_t payload_off, uint32_t payload_len,
                                 uint32_t pool_start, VxiSymbol &out) {
    if (payload_len < 16) return false;
    size_t off = payload_off;
    if (!read_u64(data, size, off, out.nominal_abi)) return false;
    uint32_t und_off = 0, und_len = 0;
    if (!read_u32(data, size, off, und_off)) return false;
    if (!read_u32(data, size, off, und_len)) return false;
    if (!read_name(data, size, und_off, und_len, pool_start,
                   out.underlying_type)) {
        return false;
    }
    // Si hay extras (>=16 bytes mas), leer init.  Compat con .vxi viejos:
    // si solo hay 16 bytes, asumir has_init_value=false.
    if (payload_len < 16 + 16) {
        return true;
    }
    uint8_t has = 0;
    if (!read_u8(data, size, off, has)) return false;
    off += 7; // skip pad
    uint32_t lo = 0, hi = 0;
    if (!read_u32(data, size, off, lo)) return false;
    if (!read_u32(data, size, off, hi)) return false;
    out.has_init_value = (has != 0);
    out.init_value =
        static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
    // v4: campos extra (blob ref + atributos).  Total payload >= 52.
    if (payload_len < 52) {
        return true;
    }
    uint8_t hbr = 0, bkh = 0, af = 0, _p0 = 0;
    uint16_t align = 0, _p1 = 0;
    uint32_t blob_off = 0, sec_off = 0, sec_len = 0;
    if (!read_u8(data, size, off, hbr)) return false;
    if (!read_u8(data, size, off, bkh)) return false;
    if (!read_u8(data, size, off, af)) return false;
    if (!read_u8(data, size, off, _p0)) return false;
    if (!read_u16(data, size, off, align)) return false;
    if (!read_u16(data, size, off, _p1)) return false;
    if (!read_u32(data, size, off, blob_off)) return false;
    if (!read_u32(data, size, off, sec_off)) return false;
    if (!read_u32(data, size, off, sec_len)) return false;
    out.has_blob_ref = (hbr != 0);
    out.blob_kind_hint = bkh;
    out.attr_flags = af;
    out.attr_align = align;
    out.blob_offset = blob_off;
    if (sec_len > 0) {
        if (!read_name(data, size, sec_off, sec_len, pool_start,
                       out.attr_section)) {
            return false;
        }
    }
    // NS.2 (v7): ns_path del global.
    uint32_t nsp_off = 0, nsp_len = 0;
    if (!read_u32(data, size, off, nsp_off)) return false;
    if (!read_u32(data, size, off, nsp_len)) return false;
    if (nsp_len > 0) {
        if (!read_name(data, size, nsp_off, nsp_len, pool_start, out.ns_path))
            return false;
    }
    return true;
}

static bool parse_payload_function(const uint8_t *data, size_t size,
                                   uint32_t payload_off, uint32_t payload_len,
                                   uint32_t pool_start, VxiSymbol &out) {
    //  M5.b L.5: format v2 añade lib_len explicito.  NS.2 (v7) añade
    // ns_path (off+len).  Total fixed bytes en payload = 36:
    // ret_off+ret_len+pc+lib_off+lib_len+ml_off+ml_len+nsp_off+nsp_len =
    // 9 u32 = 36 bytes.
    if (payload_len < 36) return false;
    size_t off = payload_off;
    uint32_t ret_off = 0, ret_len = 0, pc = 0, lib_off = 0, lib_len = 0;
    uint32_t ml_off = 0, ml_len = 0, nsp_off = 0, nsp_len = 0;
    if (!read_u32(data, size, off, ret_off)) return false;
    if (!read_u32(data, size, off, ret_len)) return false;
    if (!read_u32(data, size, off, pc)) return false;
    if (!read_u32(data, size, off, lib_off)) return false;
    if (!read_u32(data, size, off, lib_len)) return false;
    if (!read_u32(data, size, off, ml_off)) return false;
    if (!read_u32(data, size, off, ml_len)) return false;
    if (!read_u32(data, size, off, nsp_off)) return false;
    if (!read_u32(data, size, off, nsp_len)) return false;
    if (ml_len > 0) {
        if (!read_name(data, size, ml_off, ml_len, pool_start,
                       out.mangled_label))
            return false;
    }
    if (nsp_len > 0) {
        if (!read_name(data, size, nsp_off, nsp_len, pool_start, out.ns_path))
            return false;
    }
    if (!read_name(data, size, ret_off, ret_len, pool_start, out.return_type))
        return false;
    if (out.is_extern && lib_off > 0 && lib_len > 0) {
        //  M5.b L.5: lib_len explicito (format v2).  Cero ambiguedad
        // sobre donde termina el nombre, sin hack de cap 256 bytes.
        if (!read_name(data, size, lib_off, lib_len, pool_start,
                       out.extern_lib))
            return false;
    }
    out.param_types.reserve(pc);
    out.param_names.reserve(pc);
    out.param_abi_regs.reserve(pc);
    for (uint32_t i = 0; i < pc; ++i) {
        uint32_t t_off = 0, t_len = 0, n_off = 0, n_len = 0, a_off = 0,
                 a_len = 0;
        if (!read_u32(data, size, off, t_off)) return false;
        if (!read_u32(data, size, off, t_len)) return false;
        if (!read_u32(data, size, off, n_off)) return false;
        if (!read_u32(data, size, off, n_len)) return false;
        if (!read_u32(data, size, off, a_off)) return false;
        if (!read_u32(data, size, off, a_len)) return false;
        std::string tnm;
        if (!read_name(data, size, t_off, t_len, pool_start, tnm)) return false;
        std::string nnm;
        if (!read_name(data, size, n_off, n_len, pool_start, nnm)) return false;
        std::string anm;
        if (!read_name(data, size, a_off, a_len, pool_start, anm)) return false;
        out.param_types.push_back(std::move(tnm));
        out.param_names.push_back(std::move(nnm));
        out.param_abi_regs.push_back(std::move(anm));
    }
    return true;
}

static bool parse_payload_struct_or_class(const uint8_t *data, size_t size,
                                          uint32_t payload_off,
                                          uint32_t payload_len,
                                          uint32_t pool_start, VxiSymbol &out) {
    // Header fijo: super(off+len) + size + align + is_overlay(1) +
    // overlay_extent(4) + field_count + interface_count + method_count = 33
    // bytes.
    if (payload_len < 33) return false;
    size_t off = payload_off;
    uint32_t super_off = 0, super_len = 0, fc = 0, ic = 0, mc = 0;
    if (!read_u32(data, size, off, super_off)) return false;
    if (!read_u32(data, size, off, super_len)) return false;
    if (!read_u32(data, size, off, out.size_bytes)) return false;
    if (!read_u32(data, size, off, out.align_bytes)) return false;
    uint8_t ov_flag = 0;
    if (!read_u8(data, size, off, ov_flag)) return false;
    out.is_overlay = (ov_flag != 0);
    if (!read_u32(data, size, off, out.overlay_extent)) return false;
    if (!read_u32(data, size, off, fc)) return false;
    if (!read_u32(data, size, off, ic)) return false;
    if (!read_u32(data, size, off, mc)) return false;
    if (super_len > 0) {
        if (!read_name(data, size, super_off, super_len, pool_start,
                       out.super_class))
            return false;
    }
    out.fields.reserve(fc);
    for (uint32_t i = 0; i < fc; ++i) {
        VxiSymbol::FieldInfo fi{};
        uint32_t n_off = 0, n_len = 0, t_off = 0, t_len = 0;
        uint16_t fsize = 0;
        uint8_t bo = 0, bw = 0;
        if (!read_u32(data, size, off, n_off)) return false;
        if (!read_u32(data, size, off, n_len)) return false;
        if (!read_u32(data, size, off, t_off)) return false;
        if (!read_u32(data, size, off, t_len)) return false;
        if (!read_u32(data, size, off, fi.offset)) return false;
        if (!read_u16(data, size, off, fsize)) return false;
        if (!read_u8(data, size, off, bo)) return false;
        if (!read_u8(data, size, off, bw)) return false;
        fi.size = fsize;
        fi.bit_offset = bo;
        fi.bit_width = bw;
        if (!read_name(data, size, n_off, n_len, pool_start, fi.name))
            return false;
        if (!read_name(data, size, t_off, t_len, pool_start, fi.type_str))
            return false;
        out.fields.push_back(std::move(fi));
    }
    out.interfaces.reserve(ic);
    for (uint32_t i = 0; i < ic; ++i) {
        uint32_t n_off = 0, n_len = 0;
        if (!read_u32(data, size, off, n_off)) return false;
        if (!read_u32(data, size, off, n_len)) return false;
        std::string nm;
        if (!read_name(data, size, n_off, n_len, pool_start, nm)) return false;
        out.interfaces.push_back(std::move(nm));
    }
    //  M6.b L.6: methods.
    out.methods.reserve(mc);
    for (uint32_t i = 0; i < mc; ++i) {
        VxiSymbol::MethodInfo m{};
        uint32_t n_off = 0, n_len = 0, r_off = 0, r_len = 0, pc = 0, vti = 0,
                 fl = 0, ml_off = 0, ml_len = 0;
        if (!read_u32(data, size, off, n_off)) return false;
        if (!read_u32(data, size, off, n_len)) return false;
        if (!read_u32(data, size, off, r_off)) return false;
        if (!read_u32(data, size, off, r_len)) return false;
        if (!read_u32(data, size, off, pc)) return false;
        if (!read_u32(data, size, off, vti)) return false;
        if (!read_u32(data, size, off, fl)) return false;
        if (!read_u32(data, size, off, ml_off)) return false;
        if (!read_u32(data, size, off, ml_len)) return false;
        m.vtable_index = vti;
        m.flags = static_cast<uint8_t>(fl);
        if (!read_name(data, size, n_off, n_len, pool_start, m.name))
            return false;
        if (!read_name(data, size, r_off, r_len, pool_start, m.return_type))
            return false;
        if (ml_len > 0) {
            if (!read_name(data, size, ml_off, ml_len, pool_start,
                           m.mangled_label))
                return false;
        }
        m.param_types.reserve(pc);
        for (uint32_t j = 0; j < pc; ++j) {
            uint32_t t_off = 0, t_len = 0;
            if (!read_u32(data, size, off, t_off)) return false;
            if (!read_u32(data, size, off, t_len)) return false;
            std::string pt;
            if (!read_name(data, size, t_off, t_len, pool_start, pt))
                return false;
            m.param_types.push_back(std::move(pt));
        }
        out.methods.push_back(std::move(m));
    }
    // NS.2 (v8): ns_path del tipo al final (off+len).  Guardado defensivo por
    // si el payload es de una version anterior sin este campo.
    if (off + 8 <= static_cast<size_t>(payload_off) + payload_len) {
        uint32_t nsp_off = 0, nsp_len = 0;
        if (read_u32(data, size, off, nsp_off) &&
            read_u32(data, size, off, nsp_len) && nsp_len > 0) {
            read_name(data, size, nsp_off, nsp_len, pool_start, out.ns_path);
        }
    }
    return true;
}

static bool parse_payload_enum(const uint8_t *data, size_t size,
                               uint32_t payload_off, uint32_t payload_len,
                               uint32_t pool_start, VxiSymbol &out) {
    if (payload_len < 20) return false; // size+align+base+variants
    size_t off = payload_off;
    // v5: size_bytes + align_bytes al inicio.
    if (!read_u32(data, size, off, out.size_bytes)) return false;
    if (!read_u32(data, size, off, out.align_bytes)) return false;
    // Tipo base del enum (ver emit_payload_for_enum).
    {
        uint32_t und_off = 0, und_len = 0;
        if (!read_u32(data, size, off, und_off)) return false;
        if (!read_u32(data, size, off, und_len)) return false;
        if (!read_name(data, size, und_off, und_len, pool_start,
                       out.underlying_type))
            return false;
    }
    uint32_t vc = 0;
    if (!read_u32(data, size, off, vc)) return false;
    out.variants.reserve(vc);
    for (uint32_t i = 0; i < vc; ++i) {
        VxiSymbol::EnumVariant v{};
        uint32_t n_off = 0, n_len = 0, pc = 0;
        if (!read_u32(data, size, off, v.tag)) return false;
        if (!read_u32(data, size, off, n_off)) return false;
        if (!read_u32(data, size, off, n_len)) return false;
        if (!read_u32(data, size, off, pc)) return false;
        if (!read_name(data, size, n_off, n_len, pool_start, v.name))
            return false;
        v.payload_types.reserve(pc);
        for (uint32_t j = 0; j < pc; ++j) {
            uint32_t t_off = 0, t_len = 0;
            if (!read_u32(data, size, off, t_off)) return false;
            if (!read_u32(data, size, off, t_len)) return false;
            std::string tnm;
            if (!read_name(data, size, t_off, t_len, pool_start, tnm))
                return false;
            v.payload_types.push_back(std::move(tnm));
        }
        // v15: valor de la variante (enums C-style).
        uint64_t raw_val = 0;
        if (!read_u64(data, size, off, raw_val)) return false;
        v.int_value = static_cast<int64_t>(raw_val);
        out.variants.push_back(std::move(v));
    }
    // NS.2 (v8): ns_path del enum al final (off+len; guardado defensivo).
    if (off + 8 <= static_cast<size_t>(payload_off) + payload_len) {
        uint32_t nsp_off = 0, nsp_len = 0;
        if (read_u32(data, size, off, nsp_off) &&
            read_u32(data, size, off, nsp_len) && nsp_len > 0) {
            read_name(data, size, nsp_off, nsp_len, pool_start, out.ns_path);
        }
    }
    return true;
}

VxiParseResult vxi_parse(const uint8_t *data, size_t size) {
    VxiParseResult r;
    // .vxi v6: header crece a 80 bytes.
    if (size < 80) {
        r.error_message = "fichero .vxi truncado (< 80 bytes)";
        return r;
    }
    size_t off = 0;
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    uint64_t abi_hash = 0;
    uint64_t source_hash = 0;
    uint64_t cvh = 0;
    uint32_t symbol_count = 0;
    uint32_t pool_start = 0;
    uint32_t dep_count = 0;
    uint32_t dep_table_offset = 0;
    uint32_t blob_pool_offset_hdr = 0;
    uint32_t blob_pool_size_hdr = 0;
    uint8_t blob_pool_alignment_hdr = 8;
    read_u32(data, size, off, magic);
    read_u16(data, size, off, version);
    read_u16(data, size, off, reserved);
    read_u64(data, size, off, abi_hash);
    read_u64(data, size, off, source_hash);
    read_u64(data, size, off, cvh); // M5.b L.27
    read_u32(data, size, off, symbol_count);
    read_u32(data, size, off, pool_start);
    read_u32(data, size, off, dep_count);              // M4.ext L.13
    read_u32(data, size, off, dep_table_offset);       // M4.ext L.13
    read_u32(data, size, off, blob_pool_offset_hdr);   // v4
    read_u32(data, size, off, blob_pool_size_hdr);     // v4
    read_u8(data, size, off, blob_pool_alignment_hdr); // v4
    off += 3;                                          // pad (offsets 57..59)
    uint32_t target_off_hdr =
        0; // v13 (offset 60, rel al pool; 0 = sin @Target)
    read_u32(data, size, off, target_off_hdr);
    uint32_t gen_offset_hdr = 0; // v6
    uint32_t gen_count_hdr = 0;  // v6
    read_u32(data, size, off, gen_offset_hdr);
    read_u32(data, size, off, gen_count_hdr);
    uint32_t pkgid_off_hdr = 0; // NS.3 v10 (offset 72, rel al pool)
    uint32_t pkgid_len_hdr = 0; // NS.3 v10 (offset 76)
    read_u32(data, size, off, pkgid_off_hdr);
    read_u32(data, size, off, pkgid_len_hdr);
    uint32_t ext_offset_hdr = 0; // NS.6-ext v11 (offset 80, abs)
    uint32_t ext_count_hdr = 0;  // NS.6-ext v11 (offset 84)
    read_u32(data, size, off, ext_offset_hdr);
    read_u32(data, size, off, ext_count_hdr);
    // v17 (88, 96): huella del mapa de diagnostico del modulo.
    uint64_t vxdbg_lo_hdr = 0;
    uint64_t vxdbg_hi_hdr = 0;
    read_u64(data, size, off, vxdbg_lo_hdr);
    read_u64(data, size, off, vxdbg_hi_hdr);
    // v18 (104..132): el conjunto comptime de este modulo.
    uint32_t ct_src_off_hdr = 0, ct_src_len_hdr = 0;
    uint64_t ct_hash_hdr = 0;
    uint32_t ct_names_count_hdr = 0, ct_names_off_hdr = 0;
    uint32_t ct_notcol_count_hdr = 0, ct_notcol_off_hdr = 0;
    read_u32(data, size, off, ct_src_off_hdr);
    read_u32(data, size, off, ct_src_len_hdr);
    read_u64(data, size, off, ct_hash_hdr);
    read_u32(data, size, off, ct_names_count_hdr);
    read_u32(data, size, off, ct_names_off_hdr);
    read_u32(data, size, off, ct_notcol_count_hdr);
    read_u32(data, size, off, ct_notcol_off_hdr);

    if (magic != VXI_MAGIC) {
        r.error_message = "magic invalido en .vxi";
        return r;
    }
    if (version != VXI_FORMAT_VERSION) {
        std::ostringstream os;
        os << "version .vxi no soportada (esperado " << VXI_FORMAT_VERSION
           << ", encontrado " << version << "); el cache se regenerara";
        r.error_message = os.str();
        return r;
    }
    //  M5.b L.27: chequeo del compiler_version_hash.  Si difiere del
    // compilador actual, el .vxi puede haber sido generado por una
    // version distinta con reglas de mangling/ABI diferentes.  Rechazar
    // y forzar regeneracion en el siguiente compile.
    const uint64_t my_cvh = vxi_compiler_version_hash();
    if (cvh != my_cvh) {
        std::ostringstream os;
        os << ".vxi generado por compilador distinto (esperado 0x" << std::hex
           << my_cvh << ", encontrado 0x" << cvh << "); el cache se regenerara";
        r.error_message = os.str();
        return r;
    }
    if (symbol_count > 1000000) {
        r.error_message = "symbol_count excesivo (posible corrupcion)";
        return r;
    }
    if (pool_start > size) {
        r.error_message = "string_pool_offset fuera del fichero";
        return r;
    }

    r.module_.format_version = version;
    r.module_.abi_hash = abi_hash;
    r.module_.source_hash = source_hash;
    r.module_.compiler_version_hash = cvh;
    r.module_.vxdbg_map_lo = vxdbg_lo_hdr;
    r.module_.vxdbg_map_hi = vxdbg_hi_hdr;
    r.module_.symbols.reserve(symbol_count);

    // Symbol entries empiezan tras el header v18 (136 bytes).  Este numero y
    constexpr size_t SYMENTRY_BYTES = 20;
    // el del escritor van SIEMPRE juntos: si uno crece y el otro no, las
    // entradas se leen desplazadas y el sintoma no dice nada de la causa
    // ("kind de simbolo desconocido").
    constexpr size_t HEADER_BYTES = 136;
    constexpr size_t DEP_ENTRY_BYTES = 16;
    constexpr size_t GEN_ENTRY_BYTES = 28; // v9: +ns_off+ns_len
    // v4: blob_pool extraido a un std::vector para conservar la API
    // existente.  Validamos rangos antes de copiar.
    if (blob_pool_size_hdr != 0) {
        const uint64_t blob_end = static_cast<uint64_t>(blob_pool_offset_hdr) +
                                  static_cast<uint64_t>(blob_pool_size_hdr);
        if (blob_pool_offset_hdr < HEADER_BYTES || blob_end > size) {
            r.error_message = "blob_pool fuera del fichero";
            return r;
        }
        r.module_.blob_pool.assign(data + blob_pool_offset_hdr,
                                   data + blob_pool_offset_hdr +
                                       blob_pool_size_hdr);
    }
    r.module_.blob_pool_alignment = blob_pool_alignment_hdr;
    if (HEADER_BYTES + symbol_count * SYMENTRY_BYTES > pool_start) {
        r.error_message = "entries exceden el string_pool_offset";
        return r;
    }
    // Validar dep table dentro del fichero.
    if (dep_count > 100000) {
        r.error_message = "dep_count excesivo (posible corrupcion)";
        return r;
    }
    if (dep_count > 0) {
        const uint64_t dep_table_end =
            static_cast<uint64_t>(dep_table_offset) +
            static_cast<uint64_t>(dep_count) * DEP_ENTRY_BYTES;
        if (dep_table_offset < HEADER_BYTES || dep_table_end > size) {
            r.error_message = "dep_table_offset fuera del fichero";
            return r;
        }
    }

    for (uint32_t i = 0; i < symbol_count; ++i) {
        VxiSymbol s;
        size_t entry_off = HEADER_BYTES + i * SYMENTRY_BYTES;
        uint8_t kind = 0, flags = 0;
        uint16_t align_override = 0;
        uint32_t name_off = 0, name_len = 0;
        uint32_t payload_off = 0, payload_len = 0;
        read_u8(data, size, entry_off, kind);
        read_u8(data, size, entry_off, flags);
        read_u16(data, size, entry_off, align_override);
        read_u32(data, size, entry_off, name_off);
        read_u32(data, size, entry_off, name_len);
        read_u32(data, size, entry_off, payload_off);
        read_u32(data, size, entry_off, payload_len);

        s.kind = static_cast<VxiSymbolKind>(kind);
        s.is_opaque = (flags & 0x01) != 0;
        s.is_extern = (flags & 0x02) != 0;
        s.is_const = (flags & 0x04) != 0;    // L.7
        s.is_naked = (flags & 0x08) != 0;    // LIM-A: FUNCTION @Naked
        s.is_internal = (flags & 0x10) != 0; // NS.3: internal (package-scoped)
        s.align_override = align_override;
        if (!read_name(data, size, name_off, name_len, pool_start, s.name)) {
            r.error_message = "name fuera de bounds";
            return r;
        }

        bool ok = true;
        switch (s.kind) {
        case VxiSymbolKind::TYPEDEF_ALIAS:
        case VxiSymbolKind::TYPEDEF_NEW:
            ok = parse_payload_typedef(data, size, payload_off, payload_len,
                                       pool_start, s);
            break;
        case VxiSymbolKind::GLOBAL_VAR:
            ok = parse_payload_global(data, size, payload_off, payload_len,
                                      pool_start, s);
            break;
        case VxiSymbolKind::FUNCTION:
            ok = parse_payload_function(data, size, payload_off, payload_len,
                                        pool_start, s);
            break;
        case VxiSymbolKind::STRUCT:
        case VxiSymbolKind::CLASS:
            ok = parse_payload_struct_or_class(data, size, payload_off,
                                               payload_len, pool_start, s);
            break;
        case VxiSymbolKind::ENUM:
            ok = parse_payload_enum(data, size, payload_off, payload_len,
                                    pool_start, s);
            break;
        default:
            ok = false;
            r.error_message = "kind de simbolo desconocido";
            break;
        }
        if (!ok) {
            if (r.error_message.empty()) {
                r.error_message =
                    "fallo parseando payload del simbolo '" + s.name + "'";
            }
            return r;
        }
        r.module_.symbols.push_back(std::move(s));
    }

    //  M4.ext L.13: parsear dep table.
    r.module_.deps.reserve(dep_count);
    for (uint32_t i = 0; i < dep_count; ++i) {
        size_t dep_off = dep_table_offset + i * DEP_ENTRY_BYTES;
        uint32_t n_off = 0, n_len = 0;
        uint32_t lo = 0, hi = 0;
        if (!read_u32(data, size, dep_off, n_off)) {
            r.error_message = "dep entry truncada";
            return r;
        }
        if (!read_u32(data, size, dep_off, n_len)) {
            r.error_message = "dep entry truncada";
            return r;
        }
        if (!read_u32(data, size, dep_off, lo)) {
            r.error_message = "dep entry truncada";
            return r;
        }
        if (!read_u32(data, size, dep_off, hi)) {
            r.error_message = "dep entry truncada";
            return r;
        }
        VxiModule::DepRecord d;
        d.abi_hash =
            static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
        if (!read_name(data, size, n_off, n_len, pool_start, d.name)) {
            r.error_message = "dep name fuera de bounds";
            return r;
        }
        r.module_.deps.push_back(std::move(d));
    }

    // v6: parsear la tabla de plantillas genericas.
    /* v18: el conjunto comptime.  Un tope por cordura, igual que las
     * plantillas: un contador absurdo es un fichero corrupto, no un modulo con
     * cien mil decls comptime. */
    if (ct_names_count_hdr > 100000 || ct_notcol_count_hdr > 100000) {
        r.error_message = "conjunto comptime con demasiadas entradas";
        return r;
    }
    r.module_.comptime_unit_hash = ct_hash_hdr;
    if (ct_src_len_hdr != 0 &&
        !read_name(data, size, ct_src_off_hdr, ct_src_len_hdr, pool_start,
                   r.module_.comptime_unit_source)) {
        r.error_message = "fuente del conjunto comptime fuera de bounds";
        return r;
    }
    for (int cual = 0; cual < 2; ++cual) {
        const uint32_t n = cual == 0 ? ct_names_count_hdr : ct_notcol_count_hdr;
        const uint32_t base = cual == 0 ? ct_names_off_hdr : ct_notcol_off_hdr;
        auto &destino = cual == 0 ? r.module_.comptime_unit_names
                                  : r.module_.comptime_unit_not_collected;
        destino.reserve(n);
        for (uint32_t i = 0; i < n; ++i) {
            size_t e = base + i * 8u;
            uint32_t n_off = 0, n_len = 0;
            if (!read_u32(data, size, e, n_off) ||
                !read_u32(data, size, e, n_len)) {
                r.error_message = "entrada del conjunto comptime truncada";
                return r;
            }
            std::string nombre;
            if (!read_name(data, size, n_off, n_len, pool_start, nombre)) {
                r.error_message = "nombre del conjunto comptime fuera de "
                                  "bounds";
                return r;
            }
            destino.push_back(std::move(nombre));
        }
    }

    if (gen_count_hdr > 100000) {
        r.error_message = "gen_templates_count excesivo (posible corrupcion)";
        return r;
    }
    r.module_.generic_templates.reserve(gen_count_hdr);
    for (uint32_t i = 0; i < gen_count_hdr; ++i) {
        size_t g_off = gen_offset_hdr + i * GEN_ENTRY_BYTES;
        uint32_t n_off = 0, n_len = 0, kind = 0, s_off = 0, s_len = 0,
                 ns_off = 0, ns_len = 0;
        if (!read_u32(data, size, g_off, n_off) ||
            !read_u32(data, size, g_off, n_len) ||
            !read_u32(data, size, g_off, kind) ||
            !read_u32(data, size, g_off, s_off) ||
            !read_u32(data, size, g_off, s_len) ||
            !read_u32(data, size, g_off, ns_off) ||
            !read_u32(data, size, g_off, ns_len)) {
            r.error_message = "gen template entry truncada";
            return r;
        }
        VxiModule::GenericTemplateSource g;
        g.kind = static_cast<uint8_t>(kind);
        if (!read_name(data, size, n_off, n_len, pool_start, g.name) ||
            !read_name(data, size, s_off, s_len, pool_start, g.source)) {
            r.error_message = "gen template name/source fuera de bounds";
            return r;
        }
        if (ns_len > 0)
            read_name(data, size, ns_off, ns_len, pool_start, g.ns_path);
        r.module_.generic_templates.push_back(std::move(g));
    }

    // NS.6-ext (v11): parsear la tabla de ext_methods.
    if (ext_count_hdr > 1000000) {
        r.error_message = "ext_methods_count excesivo (posible corrupcion)";
        return r;
    }
    r.module_.ext_methods.reserve(ext_count_hdr);
    {
        size_t e_off = ext_offset_hdr;
        for (uint32_t i = 0; i < ext_count_hdr; ++i) {
            uint32_t tk_off = 0, tk_len = 0, nm_off = 0, nm_len = 0, rt_off = 0,
                     rt_len = 0, ml_off = 0, ml_len = 0;
            if (!read_u32(data, size, e_off, tk_off) ||
                !read_u32(data, size, e_off, tk_len) ||
                !read_u32(data, size, e_off, nm_off) ||
                !read_u32(data, size, e_off, nm_len) ||
                !read_u32(data, size, e_off, rt_off) ||
                !read_u32(data, size, e_off, rt_len) ||
                !read_u32(data, size, e_off, ml_off) ||
                !read_u32(data, size, e_off, ml_len)) {
                r.error_message = "ext_method entry truncada";
                return r;
            }
            uint8_t is_class = 0;
            if (!read_u8(data, size, e_off, is_class)) {
                r.error_message = "ext_method is_class truncado";
                return r;
            }
            e_off += 3; // pad
            uint32_t pcount = 0;
            if (!read_u32(data, size, e_off, pcount) || pcount > 100000) {
                r.error_message = "ext_method param_count invalido";
                return r;
            }
            VxiModule::ExtMethod em;
            em.target_is_class = is_class != 0;
            if (!read_name(data, size, tk_off, tk_len, pool_start,
                           em.target_key) ||
                !read_name(data, size, nm_off, nm_len, pool_start, em.name) ||
                !read_name(data, size, ml_off, ml_len, pool_start,
                           em.mangled_label)) {
                r.error_message = "ext_method strings fuera de bounds";
                return r;
            }
            if (rt_len > 0)
                read_name(data, size, rt_off, rt_len, pool_start,
                          em.return_type);
            em.param_types.reserve(pcount);
            for (uint32_t p = 0; p < pcount; ++p) {
                uint32_t p_off = 0, p_len = 0;
                if (!read_u32(data, size, e_off, p_off) ||
                    !read_u32(data, size, e_off, p_len)) {
                    r.error_message = "ext_method param truncado";
                    return r;
                }
                std::string pt;
                if (p_len > 0)
                    read_name(data, size, p_off, p_len, pool_start, pt);
                em.param_types.push_back(std::move(pt));
            }
            r.module_.ext_methods.push_back(std::move(em));
        }
    }

    // NS.3 (v10): package_id desde el pool (vacio = paquete anonimo).
    if (pkgid_len_hdr > 0) {
        read_name(data, size, pkgid_off_hdr, pkgid_len_hdr, pool_start,
                  r.module_.package_id);
    }

    // v13: objetivo del artefacto.  El pool guarda cadenas NUL-terminadas, asi
    // que se lee hasta el terminador (no hay campo de longitud aparte: el
    // offset 0 ya distingue "sin @Target").
    if (target_off_hdr != 0) {
        const size_t abs = static_cast<size_t>(pool_start) + target_off_hdr;
        for (size_t i = abs; i < size && data[i] != 0; ++i)
            r.module_.target.push_back(static_cast<char>(data[i]));
    }

    r.ok = true;
    return r;
}

//  M5.b L.27: hash de la version del compilador.
//
// Combina:
//   - El @c VXI_FORMAT_VERSION (cambios en el layout del .vxi).
//   - El timestamp de compilacion del compilador (__DATE__ + __TIME__).
//   - Una etiqueta de identidad ABI fija (incrementar manualmente al
//     cambiar reglas de mangling o de invariantes del checker).
//
// Si dos compiladores producen .vxi con el mismo hash, son
// ABI-compatibles a nivel cache.  Si difieren, el .vxi se descarta y
// regenera al siguiente compile.
// Vocabulario IDENTICO al de los atomos `os:`/`arch:` de @Target (ver
// target_matches_ en parser.cpp).  Si divergieran, un .vxi quedaria atado a un
// nombre que la evaluacion de @Target no reconoce y la comparacion fallaria
// siempre -- cache inutil en vez de cache correcto.
const char *vxi_host_os_name() noexcept {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

const char *vxi_host_arch_name() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "unknown";
#endif
}

uint64_t vxi_compiler_version_hash() noexcept {
    // String de identidad: includes una etiqueta ABI ('vx-1.0') + el
    // build time del compilador binario para detectar rebuilds del
    // compilador mismo.  El usuario puede sobreescribir definiendo
    // VXI_COMPILER_BUILD_ID en CMake si quiere un hash determinista
    // independiente de __DATE__/__TIME__ (e.g. para CI reproducible).
    static constexpr const char *kIdentity =
#ifdef VXI_COMPILER_BUILD_ID
        VXI_COMPILER_BUILD_ID
#else
        "vx-1.0-abi"
        "|fmt:2|" __DATE__ "|" __TIME__
#endif
        ;
    static const uint64_t cached = vxi_fnv1a(kIdentity, std::strlen(kIdentity));
    return cached;
}

// ===========================================================================
// v4: helpers del blob_pool.
// ===========================================================================

uint32_t vxi_blob_append(std::vector<uint8_t> &pool, VxiBlobKind kind,
                         const uint8_t *payload, size_t payload_len,
                         uint32_t element_size, uint32_t count,
                         uint32_t alignment) {
    if (alignment < 8) alignment = 8;
    // Padding al multiplo de alignment.
    while (pool.size() % alignment != 0)
        pool.push_back(0);
    const uint32_t blob_off = static_cast<uint32_t>(pool.size());
    // Emitir BlobHeader (24 bytes, little-endian).
    write_u32(pool, static_cast<uint32_t>(kind));
    write_u32(pool, element_size);
    write_u32(pool, count);
    write_u32(pool, static_cast<uint32_t>(payload_len));
    const uint64_t h = vxi_fnv1a(payload, payload_len);
    write_u32(pool, static_cast<uint32_t>(h & 0xFFFFFFFFull));
    write_u32(pool, static_cast<uint32_t>((h >> 32) & 0xFFFFFFFFull));
    // Payload.
    pool.insert(pool.end(), payload, payload + payload_len);
    // Padding al multiplo de 8 para que el siguiente blob arranque alineado.
    while (pool.size() % 8 != 0)
        pool.push_back(0);
    return blob_off;
}

const VxiBlobHeader *vxi_blob_read(const std::vector<uint8_t> &pool,
                                   uint32_t offset) noexcept {
    if (offset + sizeof(VxiBlobHeader) > pool.size()) return nullptr;
    // Bytes little-endian -> volcamos a un objeto local con read manual.
    // Como VxiBlobHeader no tiene endianness fija en memoria, leemos via
    // un buffer estatico per-thread.  Para acceso rapido del consumer,
    // el TypeChecker materializa estos campos a una estructura propia.
    // Devolvemos un puntero "casteado" suponiendo que el host es LE
    // (la mayoria de targets actuales).  Para targets BE, añadir
    // bytewise read y copia local.
    return reinterpret_cast<const VxiBlobHeader *>(pool.data() + offset);
}

const uint8_t *vxi_blob_payload(const std::vector<uint8_t> &pool,
                                uint32_t offset) noexcept {
    if (offset + sizeof(VxiBlobHeader) > pool.size()) return nullptr;
    return pool.data() + offset + sizeof(VxiBlobHeader);
}

} // namespace vx
