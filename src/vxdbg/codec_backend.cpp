/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file codec_backend.cpp
 * @brief Serializacion de la bajada, del codigo generado y de las
 *        transferencias de control.
 */

#include "codec_internal.h"

namespace vxdbg {

using codec_detail::expect;
using codec_detail::make;

// ---------------------------------------------------------------------------
//  Bajada: sentencia -> intermedio
// ---------------------------------------------------------------------------

StoredNode encode(const LoweringMap &n) {
    ByteWriter w;
    w.u32(static_cast<uint32_t>(n.entries.size()));
    for (const auto &e : n.entries) {
        w.id(e.statement);
        w.u8(static_cast<uint8_t>(e.kind));
        w.u8(static_cast<uint8_t>(e.origin));
        w.id(e.inlined_into);
        w.u32(static_cast<uint32_t>(e.ir_instrs.size()));
        for (const auto &i : e.ir_instrs)
            w.id(i);
    }
    return make(n.header, w);
}

bool decode(const StoredNode &s, LoweringMap &out) {
    if (!expect<LoweringMap>(s, NodeKind::Lowering)) return false;
    ByteReader r(s.payload);
    const uint32_t n_e = r.u32();
    if (!r.ok()) return false;
    out.entries.clear();
    out.entries.reserve(n_e);
    for (uint32_t i = 0; i < n_e && r.ok(); ++i) {
        LoweringEntry e;
        e.statement = r.id<StatementTag>();
        e.kind = static_cast<LoweringKind>(r.u8());
        e.origin = static_cast<OriginKind>(r.u8());
        e.inlined_into = r.id<IrFunctionTag>();
        const uint32_t n_i = r.u32();
        if (!r.ok()) return false;
        for (uint32_t k = 0; k < n_i && r.ok(); ++k)
            e.ir_instrs.push_back(r.id<IrInstrTag>());
        out.entries.push_back(std::move(e));
    }
    if (!r.ok()) return false;
    // El indice inverso NO se guarda: es cache derivada.  Se reconstruye al
    // leer, que cuesta lo mismo que haberlo leido y evita que pueda llegar
    // desincronizado con las entradas.
    out.build_index();
    return true;
}

// ---------------------------------------------------------------------------
//  Codigo generado
// ---------------------------------------------------------------------------

StoredNode encode(const CodeNode &n) {
    ByteWriter w;
    w.id(n.ir_function);
    w.u16(static_cast<uint16_t>(n.backend));
    w.str(n.backend_name);
    w.str(n.optimization);
    w.u32(n.byte_size);
    w.hash(n.semantic_hash);
    w.hash(n.backend_hash);
    w.id(n.unit);
    w.u32(static_cast<uint32_t>(n.dependencies.size()));
    for (const auto &d : n.dependencies)
        w.hash(d);
    return make(n.header, w);
}

bool decode(const StoredNode &s, CodeNode &out) {
    if (!expect<CodeNode>(s, NodeKind::Code)) return false;
    ByteReader r(s.payload);
    out.header = s.header;
    out.ir_function = r.id<IrFunctionTag>();
    out.backend = static_cast<BackendKind>(r.u16());
    out.backend_name = r.str();
    out.optimization = r.str();
    out.byte_size = r.u32();
    out.semantic_hash = r.hash();
    out.backend_hash = r.hash();
    out.unit = r.id<UnitTag>();
    const uint32_t n_d = r.u32();
    if (!r.ok()) return false;
    out.dependencies.clear();
    for (uint32_t i = 0; i < n_d && r.ok(); ++i)
        out.dependencies.push_back(r.hash());
    return r.ok();
}

StoredNode encode(const CodeDebug &n) {
    ByteWriter w;
    w.id(n.code);
    w.u32(static_cast<uint32_t>(n.ranges.size()));
    for (const auto &rg : n.ranges) {
        w.u32(rg.begin);
        w.u32(rg.end);
        w.u8(static_cast<uint8_t>(rg.kind));
        w.u32(static_cast<uint32_t>(rg.ir_instrs.size()));
        for (const auto &i : rg.ir_instrs)
            w.id(i);
    }
    return make(n.header, w);
}

bool decode(const StoredNode &s, CodeDebug &out) {
    if (!expect<CodeDebug>(s, NodeKind::CodeDebug)) return false;
    ByteReader r(s.payload);
    out.header = s.header;
    out.code = r.id<CodeTag>();
    const uint32_t n_r = r.u32();
    if (!r.ok()) return false;
    out.ranges.clear();
    out.ranges.reserve(n_r);
    for (uint32_t i = 0; i < n_r && r.ok(); ++i) {
        CodeRange rg;
        rg.begin = r.u32();
        rg.end = r.u32();
        rg.kind = static_cast<RangeKind>(r.u8());
        const uint32_t n_i = r.u32();
        if (!r.ok()) return false;
        for (uint32_t k = 0; k < n_i && r.ok(); ++k)
            rg.ir_instrs.push_back(r.id<IrInstrTag>());
        out.ranges.push_back(std::move(rg));
    }
    return r.ok();
}

StoredNode encode(const VariableMap &n) {
    ByteWriter w;
    w.id(n.variable);
    w.u32(static_cast<uint32_t>(n.locations.size()));
    for (const auto &l : n.locations) {
        w.u32(l.from);
        w.u32(l.to);
        w.u8(static_cast<uint8_t>(l.kind));
        w.i64(l.value);
    }
    return make(n.header, w);
}

bool decode(const StoredNode &s, VariableMap &out) {
    if (!expect<VariableMap>(s, NodeKind::VariableMap)) return false;
    ByteReader r(s.payload);
    out.header = s.header;
    out.variable = r.id<VariableTag>();
    const uint32_t n_l = r.u32();
    if (!r.ok()) return false;
    out.locations.clear();
    out.locations.reserve(n_l);
    for (uint32_t i = 0; i < n_l && r.ok(); ++i) {
        LocationRange l;
        l.from = r.u32();
        l.to = r.u32();
        l.kind = static_cast<LocationKind>(r.u8());
        l.value = r.i64();
        out.locations.push_back(l);
    }
    return r.ok();
}

// ---------------------------------------------------------------------------
//  Transferencias de control
// ---------------------------------------------------------------------------

StoredNode encode(const ExecutionEdge &n) {
    ByteWriter w;
    w.id(n.source);
    w.id(n.from);
    w.u8(static_cast<uint8_t>(n.to_kind));
    w.id(n.to);
    w.str(n.to_name);
    w.u8(static_cast<uint8_t>(n.kind));
    w.u8(static_cast<uint8_t>(n.dispatch));
    w.u8(static_cast<uint8_t>(n.form));
    w.u32(static_cast<uint32_t>(n.statements.size()));
    for (const auto &st : n.statements)
        w.id(st);
    return make(n.header, w);
}

bool decode(const StoredNode &s, ExecutionEdge &out) {
    if (!expect<ExecutionEdge>(s, NodeKind::ExecutionEdge)) return false;
    ByteReader r(s.payload);
    out.header = s.header;
    out.source = r.id<IrInstrTag>();
    out.from = r.id<IrFunctionTag>();
    out.to_kind = static_cast<EndpointKind>(r.u8());
    out.to = r.id<IrFunctionTag>();
    out.to_name = r.str();
    out.kind = static_cast<EdgeKind>(r.u8());
    out.dispatch = static_cast<DispatchKind>(r.u8());
    out.form = static_cast<TransferForm>(r.u8());
    const uint32_t n_s = r.u32();
    if (!r.ok()) return false;
    out.statements.clear();
    for (uint32_t i = 0; i < n_s && r.ok(); ++i)
        out.statements.push_back(r.id<StatementTag>());
    return r.ok();
}

StoredNode encode(const InlineSite &n) {
    ByteWriter w;
    w.id(n.at);
    w.id(n.inlined_function);
    w.id(n.edge);
    w.id(n.parent);
    return make(n.header, w);
}

bool decode(const StoredNode &s, InlineSite &out) {
    if (!expect<InlineSite>(s, NodeKind::InlineSite)) return false;
    ByteReader r(s.payload);
    out.header = s.header;
    out.at = r.id<IrInstrTag>();
    out.inlined_function = r.id<IrFunctionTag>();
    out.edge = r.id<EdgeTag>();
    out.parent = r.id<InlineSiteTag>();
    return r.ok();
}

// ---------------------------------------------------------------------------
// Entrada al grafo
// ---------------------------------------------------------------------------

StoredNode encode(const ArtifactMap &n) {
    ByteWriter w;
    /* El fichero se guarda ORDENADO: quien lo lee busca en binario sobre lo
     * almacenado, sin construir ningun indice.  El mapa se llena sin orden
     * -- ver `ArtifactMap::add` --, asi que se pone aqui, una vez. */
    n.normalize();
    w.u32(static_cast<uint32_t>(n.symbols.size()));
    for (const auto &kv : n.symbols) {
        w.str(kv.first);
        w.id(kv.second);
    }
    // v2: los mapas de los modulos que contiene, citados por su huella.
    w.u32(static_cast<uint32_t>(n.modules.size()));
    for (const auto &h : n.modules) {
        w.u64(h.lo);
        w.u64(h.hi);
    }
    return make(n.header, w);
}

bool decode(const StoredNode &s, ArtifactMap &out) {
    /* Aqui NO se usa `expect`, que exige la version exacta, sino el camino
     * escrito a proposito que ese helper deja apuntado para cuando haya que
     * leer las antiguas.  Los mapas v1 son legibles enteros -- v2 solo anade
     * una lista al final -- y rechazarlos dejaria colgadas de golpe todas las
     * raices ya publicadas, que son decenas de miles en un arbol con uso.  Lo
     * que no se hace es adivinar: se aceptan las versiones que se sabe leer, y
     * ninguna mas. */
    if (s.header.kind != NodeKind::ArtifactMap) return false;
    const uint32_t version = s.header.schema_version;
    if (version != 1 && version != ArtifactMap::kSchemaVersion) return false;

    ByteReader r(s.payload);
    out.header = s.header;
    const uint32_t n = r.u32();
    if (!r.ok()) return false;
    out.symbols.clear();
    out.symbols.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::string sym = r.str();
        // Se conserva el orden con el que venia en vez de reordenar al leer: se
        // escribio ya ordenado, y confiar en eso permite leer un mapa grande
        // sin pagar una ordenacion que casi siempre sobra.  Si viniera
        // desordenado, la busqueda binaria no encontraria algun simbolo --
        // fallo de omision, nunca de dar el equivocado.
        out.symbols.emplace_back(std::move(sym), r.id<LanguageEntityTag>());
    }
    out.modules.clear();
    // Un mapa v1 se acaba aqui: no tenia la lista, y eso significa que no cita
    // ningun modulo -- que es justo lo que era cierto cuando se escribio.
    if (version >= 2) {
        const uint32_t m = r.u32();
        if (!r.ok()) return false;
        out.modules.reserve(m);
        for (uint32_t i = 0; i < m; ++i) {
            ContentHash h;
            h.lo = r.u64();
            h.hi = r.u64();
            out.modules.push_back(h);
        }
    }
    return r.ok();
}

StoredNode encode(const SpanMap &n) {
    ByteWriter w;
    w.u32(static_cast<uint32_t>(n.extents.size()));
    for (const auto &e : n.extents) {
        w.str(e.symbol);
        w.u32(e.line);
        w.u32(e.column);
        w.u32(e.length);
    }
    return make(n.header, w);
}

bool decode(const StoredNode &s, SpanMap &out) {
    if (!expect<SpanMap>(s, NodeKind::SpanMap)) return false;
    ByteReader r(s.payload);
    out.header = s.header;
    const uint32_t n = r.u32();
    if (!r.ok()) return false;
    out.extents.clear();
    out.extents.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        SourceExtent e;
        e.symbol = r.str();
        e.line = r.u32();
        e.column = r.u32();
        e.length = r.u32();
        out.extents.push_back(std::move(e));
    }
    return r.ok();
}

} // namespace vxdbg
