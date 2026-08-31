/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/comptime.cpp
 * @brief Lo que ya se sabe al compilar: bajar su RESULTADO, no su calculo.
 *
 * Cuando algo se resuelve en tiempo de compilacion, lo que llega al programa no
 * es el codigo que lo calcula sino lo calculado: un valor, una estructura ya
 * rellena, unos bytes.  Aqui se materializa eso -- se deja el resultado en los
 * datos del modulo y se emite una referencia -- y se recorre el bucle
 * `comptime`, que no genera un bucle: genera sus vueltas.
 *
 * Va con la INTROSPECCION porque es lo mismo visto del otro lado: lo que el
 * programa puede preguntar de un tipo -- sus campos, sus nombres, sus tamanos
 * -- tambien se sabe al compilar, y por eso viaja como datos ya escritos en el
 * binario en vez de como algo que se averigua al ejecutar.  Ahi esta la
 * promesa de que la reflexion no cuesta aparte.
 */
#include "vx/lowering.h"
#include "vx/comptime/comptime_introspect.h"
#include "ffi/virtual_lib_registry.h"
#include "util/thread_slot.h" // el estado por hilo NO va en thread_local
#include "ir/ir_type_info.h"  // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {

// ---------------------------------------------------------------------
// Sprint 4 (A.37.s4): IntrospectInfo POD chunks.
//
// Para cada layout marcado @Introspect emitimos UN chunk en
// static_data con este layout self-contained (todas las direcciones
// son offsets relativos al inicio del chunk, asi no hace falta
// relocation cross-chunk):
//
// HEADER (24 bytes):
//   +0   u32 kind         (0=Prim, 1=Class, 2=Struct, 3=Enum)
//   +4   u32 size_bytes
//   +8   u32 align_bytes
//   +12  u32 field_count
//   +16  u32 name_off     -- offset interno a los bytes del nombre
//   +20  u32 name_len
//
// FIELDS array (16 bytes cada uno):  ofset 24 + i*16
//   +0   u32 offset       -- offset del field DENTRO de la instancia
//   +4   u32 size_bytes
//   +8   u32 name_off     -- offset interno
//   +12  u32 name_len
//
// NAMES area: empieza tras los FIELDS.  Bytes raw, sin NUL
// terminator (la longitud va en name_len; el accesor type_info_name
// construye un StringObject via STRMAKE con name_addr + name_len).
// ---------------------------------------------------------------------
void Lowering::emit_introspect_info_chunks() {
    auto build_chunk =
        [this](
            const std::string &name, uint32_t kind, uint32_t size_bytes,
            uint32_t align_bytes,
            const std::vector<
                std::pair<std::string, std::pair<uint32_t, uint32_t>>> &fields)
        -> std::vector<uint8_t> {
        const uint32_t field_count = static_cast<uint32_t>(fields.size());
        const size_t header_sz = 24;
        const size_t fields_sz = field_count * 16;
        /* Calculamos los offsets de los nombres tras la tabla de fields. */
        uint32_t name_off = static_cast<uint32_t>(header_sz + fields_sz);
        uint32_t name_len = static_cast<uint32_t>(name.size());
        std::vector<std::pair<uint32_t, uint32_t>> field_name_ranges;
        field_name_ranges.reserve(fields.size());
        uint32_t cur = name_off + name_len;
        for (auto &f : fields) {
            const uint32_t flen = static_cast<uint32_t>(f.first.size());
            field_name_ranges.push_back({cur, flen});
            cur += flen;
        }
        /* Reservamos el buffer con tamano exacto y rellenamos. */
        std::vector<uint8_t> buf;
        buf.resize(cur, 0);
        auto put_u32 = [&buf](size_t at, uint32_t v) {
            buf[at + 0] = static_cast<uint8_t>(v & 0xFF);
            buf[at + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
            buf[at + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
            buf[at + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        };
        put_u32(0, kind);
        put_u32(4, size_bytes);
        put_u32(8, align_bytes);
        put_u32(12, field_count);
        put_u32(16, name_off);
        put_u32(20, name_len);
        for (size_t i = 0; i < fields.size(); ++i) {
            const size_t base = header_sz + i * 16;
            put_u32(base + 0, fields[i].second.first);       /* offset */
            put_u32(base + 4, fields[i].second.second);      /* size */
            put_u32(base + 8, field_name_ranges[i].first);   /* name_off */
            put_u32(base + 12, field_name_ranges[i].second); /* name_len */
        }
        /* Copiar bytes del nombre del tipo. */
        for (size_t i = 0; i < name.size(); ++i)
            buf[name_off + i] = static_cast<uint8_t>(name[i]);
        /* Copiar bytes de los nombres de fields. */
        for (size_t i = 0; i < fields.size(); ++i) {
            const auto &nm = fields[i].first;
            const uint32_t pos = field_name_ranges[i].first;
            for (size_t j = 0; j < nm.size(); ++j) {
                buf[pos + j] = static_cast<uint8_t>(nm[j]);
            }
        }
        return buf;
    };
    /* El nombre almacenado en el chunk (lo que devuelve type_info_name)
     * debe ser el nombre PUBLICO del tipo -- el ultimo segmento tras el
     * separador de namespace "__".  La clave del indice sigue siendo el
     * nombre mangled (lo que find_type resuelve en compile-time). */
    auto public_seg = [](const std::string &mangled) -> std::string {
        const size_t p = mangled.rfind("__");
        return (p == std::string::npos) ? mangled : mangled.substr(p + 2);
    };

    /* Structs marcados @Introspect. */
    for (const auto &kv : tc_.struct_layouts()) {
        const auto &lay = kv.second;
        if (!lay.is_introspect) continue;
        std::vector<std::pair<std::string, std::pair<uint32_t, uint32_t>>> fs;
        fs.reserve(lay.fields.size());
        for (const auto &f : lay.fields) {
            fs.push_back({f.name, {f.offset, f.size}});
        }
        std::vector<uint8_t> chunk =
            build_chunk(public_seg(lay.name), /*Struct=*/2, lay.size_bytes,
                        lay.align_bytes, fs);
        const uint64_t idx = out_mod_->intern_static_data(std::move(chunk));
        introspect_idx_by_name_[lay.name] = idx;
    }
    /* Clases marcadas @Introspect.  No emitimos metodos por ahora
     * (Sprint 4 MVP cubre solo fields; Sprint 5 añade methods). */
    for (const auto &kv : tc_.class_layouts()) {
        const auto &lay = kv.second;
        if (!lay.is_introspect) continue;
        std::vector<std::pair<std::string, std::pair<uint32_t, uint32_t>>> fs;
        fs.reserve(lay.fields.size());
        for (const auto &f : lay.fields) {
            fs.push_back({f.name, {f.offset, f.size}});
        }
        std::vector<uint8_t> chunk = build_chunk(
            public_seg(lay.name), /*Class=*/1, lay.size_bytes, /*align=*/8, fs);
        const uint64_t idx = out_mod_->intern_static_data(std::move(chunk));
        introspect_idx_by_name_[lay.name] = idx;
    }
    /* Enums marcados @Introspect.  Listamos variantes como "fields"
     * sinteticos con offset=tag, size=0 -- conveccion para el MVP;
     * el usuario sabe que el campo offset en realidad es el tag. */
    for (const auto &kv : tc_.enum_layouts()) {
        const auto &lay = kv.second;
        if (!lay.is_introspect) continue;
        std::vector<std::pair<std::string, std::pair<uint32_t, uint32_t>>> fs;
        fs.reserve(lay.variants.size());
        for (const auto &v : lay.variants) {
            fs.push_back({v.name, {v.tag, 0}});
        }
        std::vector<uint8_t> chunk = build_chunk(
            public_seg(lay.name), /*Enum=*/3, lay.size_bytes, /*align=*/8, fs);
        const uint64_t idx = out_mod_->intern_static_data(std::move(chunk));
        introspect_idx_by_name_[lay.name] = idx;
    }
}

ir::IrValueId Lowering::materialize_comptime_struct(const ComptimeEvalResult &r,
                                                    const StructLayout &lay,
                                                    uint32_t line) {
    // Alocar el buffer del struct en memoria host (es un value-type).
    const uint64_t buf_bytes =
        (static_cast<uint64_t>(lay.size_bytes) + 7ULL) & ~7ULL;
    const ir::IrValueId v_buf = stack_alloc_buf(buf_bytes, line, true);
    fn_->values[v_buf].is_host_ptr = true;
    fill_comptime_struct_into(v_buf, r, lay, line);
    return v_buf;
}

void Lowering::fill_comptime_struct_into(ir::IrValueId base_addr,
                                         const ComptimeEvalResult &r,
                                         const StructLayout &lay,
                                         uint32_t line) {
    for (const auto &fi : lay.fields) {
        auto it = r.struct_fields.find(fi.name);
        if (it == r.struct_fields.end() || !it->second) continue;
        const ComptimeValue &cv = *it->second;
        // Direccion del campo (base + offset), heredando la naturaleza host/VM.
        ir::IrValueId v_addr = base_addr;
        if (fi.offset != 0) {
            const ir::IrValueId v_off =
                emit_const(ir::IrType::I64, (uint64_t)fi.offset, line);
            v_addr = fn_->new_value(ir::IrType::PTR);
            fn_->values[v_addr].is_host_ptr =
                fn_->values[base_addr].is_host_ptr;
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_addr;
            ad.operands = {base_addr, v_off};
            ad.source_line = line;
            emit(current_block_, std::move(ad));
        }
        if (fi.type.kind == PrimitiveKind::STRUCT && cv.is_struct) {
            // Campo struct anidado: rellenar recursivamente en su direccion.
            auto its = tc_.struct_layouts().find(fi.type.struct_name);
            if (its != tc_.struct_layouts().end()) {
                const ComptimeEvalResult sub = result_from_value(cv);
                fill_comptime_struct_into(v_addr, sub, its->second, line);
            }
            continue;
        }
        // Campo escalar: constante + STORE en la direccion del campo.
        const ir::IrType ir_ft = ir_type_from_primitive(fi.type.kind);
        const ir::IrValueId v_val = emit_const(ir_ft, (uint64_t)cv.value, line);
        emit_store_typed(v_addr, v_val, ir_ft, line);
    }
}

void Lowering::lower_static_local(ast::VarDeclStmt *vd, const Type &sem_type) {
    // Nombre unico por funcion: dos wrappers con `static ctx` no colisionan.
    const std::string fn_name = fn_ ? fn_->name : std::string("?");
    const std::string mangled = fn_name + "$static$" + vd->name;
    const bool aggregate = (sem_type.kind == PrimitiveKind::STRUCT ||
                            sem_type.kind == PrimitiveKind::ARRAY);
    uint64_t nbytes = static_cast<uint64_t>(size_of_type(sem_type));
    if (nbytes < 8) nbytes = 8; // minimo un qword
    const uint64_t slot = get_or_create_runtime_global_slot(mangled, nbytes);
    const ir::IrType ld =
        aggregate ? ir::IrType::PTR : ir_type_from_primitive(sem_type.kind);
    static_local_slots_[vd->name] = {slot, ld, aggregate};

    // Sin init: el slot ya es zero-init (get_or_create_runtime_global_slot).
    if (!vd->init) return;

    // Init cero constante: el slot ya vale 0 -> nada que emitir.
    if (!aggregate && vd->init->kind == ast::NodeKind::IntLitExpr &&
        static_cast<const ast::IntLitExpr *>(vd->init.get())->value == 0) {
        return;
    }

    // Agregado (struct): el init-once emite los valores por defecto de los
    // campos en el slot.  Un array o un struct sin layout queda zero-init.
    const StructLayout *agg_lay = nullptr;
    if (aggregate) {
        if (sem_type.kind != PrimitiveKind::STRUCT)
            return; // array -> zero-init
        auto it_l = tc_.struct_layouts().find(sem_type.struct_name);
        if (it_l == tc_.struct_layouts().end()) return;
        agg_lay = &it_l->second;
    }

    // Init-once: un booleano global guarda si ya se corrio el init.  La
    // PRIMERA ejecucion de la funcion baja el init y marca done=1; las
    // siguientes lo saltan -> estado persistente entre llamadas.
    const uint64_t done_slot =
        get_or_create_runtime_global_slot(mangled + "$done", 8);
    const int ln = vd->loc.line;

    auto emit_addr = [&](uint64_t s) -> ir::IrValueId {
        ir::IrValueId a = emit_str_lit_addr(s, ln);
        fn_->values[a].is_host_ptr = true; // gdata vive en memoria host
        return a;
    };

    // done_val = LOAD i64 [done_slot]
    const ir::IrValueId addr_done = emit_addr(done_slot);
    const ir::IrValueId done_val =
        emit_load_typed(addr_done, ir::IrType::I64, ln);
    // cond = (done_val == 0)
    const ir::IrValueId zero = emit_const(ir::IrType::I64, 0, ln);
    const ir::IrValueId cond =
        emit_ir_binop(ir::IrOp::CMP_EQ, done_val, zero, ir::IrType::BOOL, ln);
    const ir::IrBlockId init_bb = fn_->new_block("static_init");
    const ir::IrBlockId cont_bb = fn_->new_block("static_cont");
    emit_br_cond(cond, init_bb, cont_bb, ln);

    // init_bb: correr el init -> STORE al slot + STORE done=1 -> BR cont.
    current_block_ = init_bb;
    block_terminated_ = false;
    if (aggregate) {
        // Struct: zero-fill + init.
        const ir::IrValueId var_addr = emit_addr(slot);
        emit_zero_fill(var_addr, static_cast<uint64_t>(agg_lay->size_bytes),
                       ln);
        // El inicializador (p.ej. un ctor comptime `T(...)`) se DESCARTABA:
        // el slot solo recibia los defaults, asi que el ctor no se aplicaba
        // nunca a un `static`.  Ahora se baja y se copia su imagen; despues se
        // emiten SOLO los defaults que esa imagen no puede llevar (una
        // referencia a funcion necesita una direccion resuelta al enlazar).
        // `T()` sobre un struct SIN ningun constructor que case es
        // value-init, no una llamada: bajarlo emitiria una CALL a un simbolo
        // inexistente (`code.T`).  En ese caso basta con los defaults.
        bool init_is_bare_value_init = false;
        if (vd->init->kind == ast::NodeKind::CallExpr) {
            auto *ce = static_cast<ast::CallExpr *>(vd->init.get());
            if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr &&
                static_cast<ast::IdentExpr *>(ce->callee.get())->name ==
                    agg_lay->name) {
                bool tiene_ctor = false;
                for (const auto &m : agg_lay->methods)
                    if (m.is_constructor &&
                        m.param_types.size() == ce->args.size()) {
                        tiene_ctor = true;
                        break;
                    }
                init_is_bare_value_init = !tiene_ctor;
            }
        }
        const ir::IrValueId v_src = init_is_bare_value_init
                                        ? ir::IR_NO_VALUE
                                        : lower_expr(vd->init.get());
        if (v_src != ir::IR_NO_VALUE) {
            const bool src_is_host = fn_->values[v_src].is_host_ptr;
            const uint64_t qwords =
                (static_cast<uint64_t>(agg_lay->size_bytes) + 7) / 8;
            for (uint64_t qi = 0; qi < qwords; ++qi) {
                const ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, static_cast<int64_t>(qi * 8), ln);
                const ir::IrValueId v_s = fn_->new_value(ir::IrType::PTR);
                fn_->values[v_s].is_host_ptr = src_is_host;
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = v_s;
                    ad.operands = {v_src, v_off};
                    ad.source_line = ln;
                    emit(current_block_, std::move(ad));
                }
                const ir::IrValueId v_w =
                    emit_load_typed(v_s, ir::IrType::I64, ln);
                const ir::IrValueId v_d = fn_->new_value(ir::IrType::PTR);
                fn_->values[v_d].is_host_ptr = true; // gdata = memoria host
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = v_d;
                    ad.operands = {var_addr, v_off};
                    ad.source_line = ln;
                    emit(current_block_, std::move(ad));
                }
                emit_store_typed(v_d, v_w, ir::IrType::I64, ln);
            }
            emit_struct_field_defaults(var_addr, *agg_lay, ln,
                                       /*only_non_comptime=*/true);
        } else {
            emit_struct_field_defaults(var_addr, *agg_lay, ln);
        }
        if (agg_lay->is_polymorphic)
            emit_struct_vptr_init(var_addr, *agg_lay, ln);
    } else {
        const ir::IrValueId iv = lower_expr(vd->init.get());
        if (iv != ir::IR_NO_VALUE) {
            const ir::IrValueId var_addr = emit_addr(slot);
            emit_store_typed(var_addr, iv, ld, ln);
        }
    }
    {
        const ir::IrValueId one = emit_const(ir::IrType::I64, 1, ln);
        const ir::IrValueId addr_done2 = emit_addr(done_slot);
        emit_store_typed(addr_done2, one, ir::IrType::I64, ln);
    }
    /* La arista se anotaba desde `init_bb` y el salto sale del bloque ACTUAL.
     * Hoy son el mismo -- nada entre medias abre un bloque nuevo --, pero
     * dejaba el grafo a merced de que siguiera siendo asi: bastaria meter un
     * condicional en este init para que la arista dijera que el salto sale de
     * un sitio del que ya no sale. */
    emit_br(cont_bb, ln);

    current_block_ = cont_bb;
    block_terminated_ = false;
}

ir::IrValueId Lowering::lower_enum_constructor(
    const std::string &enum_name, const std::string &variant_name,
    const std::vector<std::unique_ptr<ast::Expr>> &args, const SourceLoc &loc) {
    // Localizar el layout del enum y la variante.
    const auto &elays = tc_.enum_layouts();
    auto it = elays.find(enum_name);
    if (it == elays.end()) {
        // `typedef Color Tinta new;` -> el layout (variantes, tags, payloads)
        // es el del enum de debajo; el newtype solo anade la identidad, que ya
        // viaja en el Type.
        if (const std::string real = tc_.underlying_layout_name(enum_name);
            !real.empty())
            it = elays.find(real);
    }
    if (it == elays.end()) {
        error_at(loc, "lowering: enum desconocido '" + enum_name + "'");
        return ir::IR_NO_VALUE;
    }
    const EnumLayout &elay = it->second;
    const EnumVariantInfo *var = nullptr;
    for (const auto &v : elay.variants) {
        if (v.name == variant_name) {
            var = &v;
            break;
        }
    }
    if (!var) {
        error_at(loc, "lowering: variante desconocida '" + variant_name +
                          "' en enum '" + enum_name + "'");
        return ir::IR_NO_VALUE;
    }

    // Un enum CON VALOR no es un agregado: es su entero base, y la variante ES
    // ese numero.  Construirle un buffer con tag y campos lo convierte en una
    // direccion, y a partir de ahi comparar dos variantes compara direcciones
    // -- dos `Less` distintos dejan de ser iguales.
    //
    // La comprobacion va AQUI, por donde pasan todas las formas de nombrar una
    // variante, y no en cada llamante: con el enum importado alguno de ellos
    // no lo detectaba y caia al camino de agregado.
    if (elay.is_valued && elay.backing_type_name.empty()) {
        const ir::IrType t = ir_type_from_primitive(elay.backing);
        const ir::IrValueId c = fn_->new_value(t);
        fn_->values[c].is_const = true;
        fn_->values[c].const_val = static_cast<uint64_t>(var->int_value);
        ir::IrInstr ci{};
        ci.op = ir::IrOp::CONST;
        ci.type = t;
        ci.dst = c;
        ci.imm = static_cast<uint64_t>(var->int_value);
        ci.source_line = loc.line;
        emit(current_block_, std::move(ci));
        return c;
    }

    // marker: MAKE_VARIANT identifica la construccion completa de
    // un valor ADT.  Emitido ANTES de la secuencia ALLOCA + STOREs para
    // que el C2 JIT ( D.8) pueda reconocer el patron y aplicar
    // escape analysis (promocion del slot a regs si no escapa) +
    // case-splitting eficiente del match downstream.  No produce SSA
    // value; el emitter actual lo trata como no-op.
    //
    // Lower de los args ANTES del marker para que sus SSA values
    // esten disponibles como operandos.  Cada payload se promueve a
    // un slot de 8 bytes (i64).  Para floats (F32/F64) usamos BITCAST
    // (preserva los bits IEEE) en lugar de FTOI/F2I (que truncaria
    // el valor).  El bug se manifiesta como `Circle(5.0)` con payload
    // 0 porque FTOI(5.0) -> 5, pero luego al destructurar como f64
    // se interpreta 5 como bits IEEE de un denormal cerca de cero.
    std::vector<ir::IrValueId> payload_vals;
    payload_vals.reserve(args.size());
    for (size_t i = 0; i < args.size() && i < var->field_types.size(); ++i) {
        // Auto-promotion literal -> StringObject cuando el payload
        // tipo es STRING.  Sin esto, `Token.Word("hello")` almacena
        // el raw ptr del literal en lugar del GcHandle, y la
        // extraccion `case Word(s) => s` da un ptr invalido al
        // intentar usarlo como string.
        ir::IrValueId v;
        const ast::Expr *ae = args[i].get();
        if (var->field_types[i].kind == PrimitiveKind::STRING && ae &&
            ae->kind == ast::NodeKind::StringLitExpr) {
            auto *slit = const_cast<ast::StringLitExpr *>(
                static_cast<const ast::StringLitExpr *>(ae));
            v = lower_string_literal_to_string_object(slit);
        } else {
            v = lower_expr(args[i].get());
        }
        if (v == ir::IR_NO_VALUE) {
            v = emit_const(ir::IrType::I64, 0, loc.line);
        }
        ir::IrType vt = fn_->values[v].type;
        if (vt == ir::IrType::F64) {
            // bitcast f64 -> i64 (mismo ancho, preserva bits IEEE).
            ir::IrValueId v2 =
                emit_ir_unop(ir::IrOp::BITCAST, v, ir::IrType::I64, loc.line);
            v = v2;
        } else if (vt == ir::IrType::F32) {
            // f32: primero ampliar a f64 (preserva el valor), luego
            // bitcast a i64 (preserva los bits IEEE).
            ir::IrValueId vw =
                emit_ir_unop(ir::IrOp::F32TOF64, v, ir::IrType::F64, loc.line);
            ir::IrValueId v2 =
                emit_ir_unop(ir::IrOp::BITCAST, vw, ir::IrType::I64, loc.line);
            v = v2;
        } else if (vt != ir::IrType::I64 && vt != ir::IrType::PTR) {
            // Tipos enteros mas estrechos: promocion normal a i64
            // (sign/zero-extend segun signedness).
            v = cast_if_needed(v, vt, ir::IrType::I64, loc.line);
        }
        payload_vals.push_back(v);
    }
    {
        ir::IrInstr mv{};
        mv.op = ir::IrOp::MAKE_VARIANT;
        mv.type = ir::IrType::VOID;
        mv.dst = ir::IR_NO_VALUE;
        mv.operands = payload_vals;
        mv.func_name = enum_name + "." + variant_name;
        mv.imm = static_cast<uint64_t>(var->tag);
        mv.source_line = loc.line;
        emit(current_block_, std::move(mv));
    }

    // 1. ALLOCA slot del enum (size_bytes = 8 + 8*max_payload_fields).
    const ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = addr;
        al.imm = static_cast<uint64_t>(elay.size_bytes);
        // Host, como todo agregado (ver lower_var_decl).
        al.host_alloca = true;
        al.source_line = loc.line;
        emit(current_block_, std::move(al));
        fn_->values[addr].is_host_ptr = true;
    }

    // 2. STORE i64 tag en offset 0 (= addr).
    {
        ir::IrValueId tag_v = emit_const(
            ir::IrType::I64, static_cast<uint64_t>(var->tag), loc.line);
        emit_store_typed(addr, tag_v, ir::IrType::I64, loc.line);
    }

    // 3. STORE de cada payload arg en offset 8 + 8*i (promovido a i64).
    // Reusa los payload_vals ya lowereados arriba (para el marker
    // MAKE_VARIANT): evita doble-lowering de los args.
    for (size_t i = 0; i < payload_vals.size(); ++i) {
        ir::IrValueId v = payload_vals[i];
        if (v == ir::IR_NO_VALUE) continue;

        // Calcular addr_i = addr + (8 + 8*i).
        const uint64_t off = 8ULL + 8ULL * static_cast<uint64_t>(i);
        ir::IrValueId addr_i = fn_->new_value(ir::IrType::PTR);
        ir::IrValueId off_v = emit_const(ir::IrType::I64, off, loc.line);
        ir::IrInstr ad{};
        ad.op = ir::IrOp::ADD;
        ad.type = ir::IrType::I64;
        ad.dst = addr_i;
        ad.operands = {addr, off_v};
        ad.source_line = loc.line;
        emit(current_block_, std::move(ad));
        // Propagar is_host_ptr del buffer al puntero buf+off (patron
        // is_host_ptr-en-add): el STORE del payload usa la naturaleza del
        // buffer.  No-op hoy (el buffer del constructor es VM stack) pero
        // unifica el patron con Some/Ok/value/error/unwrap.
        fn_->values[addr_i].is_host_ptr = fn_->values[addr].is_host_ptr;

        emit_store_typed(addr_i, v, ir::IrType::I64, loc.line);
    }

    // El SSA value de la expresion es la direccion del slot.
    return addr;
}

void Lowering::lower_comptime_for(ast::ComptimeForStmt *s) {
    if (!s || !s->lo_expr || !s->hi_expr || !s->body) return;
    const ComptimeEvalResult lo = comptime_eval_expr(tc_, s->lo_expr.get());
    const ComptimeEvalResult hi = comptime_eval_expr(tc_, s->hi_expr.get());
    if (!lo.ok || !hi.ok || lo.is_str || hi.is_str) {
        error_at(s->loc, "comptime for: rango no evaluable (lo/hi deben ser "
                         "enteros comptime)");
        return;
    }
    /* Limite defensivo para evitar explosion de codigo. */
    const int64_t lo_v = lo.value;
    int64_t hi_v = hi.value;
    if (s->inclusive) hi_v += 1;
    if (hi_v - lo_v > 4096) {
        error_at(s->loc, "comptime for: rango excede 4096 iteraciones; usar un "
                         "loop runtime en su lugar");
        return;
    }
    /* A.39: el bind del index lo hacemos en DOS lugares:
     *   1. `lowering_comptime_scopes_` para que @c lower_ident lo
     *      inline como CONST en el codigo runtime emitido.
     *   2. `tc.comptime_const_locals_` para que @c comptime_eval_expr
     *      pueda resolverlo cuando aparezca como arg de un comptime fn
     *      o builtin comptime.  Sin esto, `fact(k)` desde el body
     *      del for fallaria con "no comptime-evaluable" porque k
     *      no estaria en tc's stack. */
    auto &mut_tc = const_cast<TypeChecker &>(tc_);
    for (int64_t i = lo_v; i < hi_v; ++i) {
        /* Push lowering scope. */
        std::unordered_map<std::string, ComptimeLocalEntry> scope;
        ComptimeLocalEntry ent;
        ent.value = i;
        ent.ir_t = ir::IrType::I64;
        scope[s->var_name] = ent;
        lowering_comptime_scopes_.push_back(std::move(scope));
        /* Push tc scope. */
        mut_tc.push_comptime_scope();
        TypeChecker::ComptimeConst c;
        c.type = Type{PrimitiveKind::I64};
        c.value = i;
        mut_tc.register_comptime_local(s->var_name, std::move(c));
        /* Lower body. */
        lower_stmt(s->body.get());
        /* Pop. */
        mut_tc.pop_comptime_scope();
        lowering_comptime_scopes_.pop_back();
    }
}

bool Lowering::materialize_comptime_bytes(const std::vector<uint8_t> &bytes,
                                          const StructLayout &layout,
                                          ir::IrValueId v_dst,
                                          uint32_t source_line) {
    if (v_dst == ir::IR_NO_VALUE || bytes.empty()) return false;

    // El valor ES el bloque de memoria que dejo la ejecucion, asi que se copia
    // entero, por palabras.  No se recorren los campos a proposito: mirar la
    // estructura obliga a resolver uniones (varias vistas de los mismos
    // bytes), anidamiento y relleno, y nada de eso cambia lo que hay que
    // copiar.  Un `u256` son cuatro palabras seguidas, se llame como se llame
    // cada trozo por dentro.
    //
    // Lo que si descalifica al tipo es que contenga una direccion: un puntero
    // calculado al compilar apunta a memoria del compilador, que no existe
    // cuando el programa corre.  Eso no se puede trasladar y se dice, en vez
    // de dejar una direccion invalida en el binario.
    for (const auto &f : layout.fields)
        if (f.type.kind == PrimitiveKind::PTR) return false;

    const size_t n = bytes.size();
    for (size_t off = 0; off < n; off += 8) {
        const size_t chunk = (n - off >= 8) ? 8 : (n - off);
        uint64_t raw = 0;
        std::memcpy(&raw, bytes.data() + off, chunk);

        const ir::IrType wt =
            (chunk == 8)
                ? ir::IrType::I64
                : (chunk >= 4
                       ? ir::IrType::I32
                       : (chunk >= 2 ? ir::IrType::I16 : ir::IrType::I8));
        const ir::IrValueId v_val = emit_const(wt, raw, source_line);
        const ir::IrValueId v_off =
            emit_const(ir::IrType::I64, off, source_line);
        const ir::IrValueId v_addr = emit_ir_binop(
            ir::IrOp::ADD, v_dst, v_off, ir::IrType::PTR, source_line);
        fn_->values[v_addr].is_host_ptr = fn_->values[v_dst].is_host_ptr;

        emit_store_typed(v_addr, v_val, wt, source_line);
    }
    return true;
}

uint64_t Lowering::get_or_create_comptime_global_slot(const std::string &name) {
    auto it = comptime_global_slots_.find(name);
    if (it != comptime_global_slots_.end()) return it->second;
    const auto &cgv = tc_.comptime_const_values();
    auto cit = cgv.find(name);
    if (cit == cgv.end()) return UINT64_MAX;
    /* Solo int en v1 -- strings serializados requieren STRMAKE en
     * __module_init que no esta integrado todavia. */
    if (cit->second.is_str) return UINT64_MAX;
    /* Empaquetar el valor inicial como 8 bytes little-endian. */
    const uint64_t init_val = static_cast<uint64_t>(cit->second.value);
    std::vector<uint8_t> bytes(8);
    for (int i = 0; i < 8; ++i) {
        bytes[i] = static_cast<uint8_t>((init_val >> (i * 8)) & 0xFFu);
    }
    const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));
    comptime_global_slots_[name] = idx;
    return idx;
}

/* ---------------------------------------------------------------------
 * Que puede ir en el cuerpo de una macro, y por que no.
 *
 * Una macro de Vesta corre AL COMPILAR, y hay dos maneras de hacerla correr:
 * recorriendo su arbol aqui mismo, o compilandola y dejando que la ejecute la
 * maquina.  La segunda es la buena -- es ejecucion de verdad, con la misma
 * semantica que el resto del lenguaje --, pero no todo cuerpo se puede
 * compilar todavia: lo que usa cosas que solo existen al compilar (mirar un
 * tipo por dentro, pedir un nombre nuevo, una variable que vive en el
 * compilador) no tiene a donde bajar.
 *
 * Lo que hacen estas funciones es DECIDIR cual de las dos vias toca, y decirlo
 * con una razon concreta en vez de con un si o un no.  Esa razon no es
 * cosmetica: es lo que permite que el que llama explique al programador por
 * que su macro va por el camino lento, y lo que hace que ampliar la lista de
 * lo soportado sea quitar un caso de aqui.
 * --------------------------------------------------------------------- */

/**
 * @brief  MC.1 -- detecta si el body de un @Macro contiene
 * caracteristicas que el IR runtime NO soporta todavia.
 *
 * Devuelve la primera razon encontrada (string descriptivo) o cadena
 * vacia si el body es lowerable.  Used by @c lower_function para
 * decidir si lowear o saltar el body al IR.
 *
 * Patrones detectados como NO soportados (todavia):
 *   - Calls a builtins comptime-only (`comptime_concat`, `to_str`,
 *     `gensym`, `comptime_compile`, etc.).
 *   - Calls con type_args (introspect: `sizeof<T>`, `field_name<T>`,
 *     `comptime_type<T>`, etc.).
 *   - VarDeclStmt con `is_comptime=true` (comptime var/const) --
 *     requiere puente de memoria compartida (MC.5).
 *   - ExprStmt con AssignExpr a IdentExpr global comptime --
 *     mismo motivo que arriba.
 *
 * En sprints posteriores (MC.4, MC.5) cada categoria se vuelve
 * "soportada" anadiendo un FFI runtime + bridge de memoria.
 */
std::string macro_body_unsupported_reason(const TypeChecker &tc,
                                          const ast::Stmt *s);

std::string macro_body_unsupported_reason_expr(const TypeChecker &tc,
                                               const ast::Expr *e);

/* Force-lower de comptime helpers: cuando el estado de force-lower esta puesto,
 * el chequeo de lowereabilidad NO rechaza las llamadas a comptime fns no-macro,
 * sino que RECURRE en su body (chequeo transitivo) y, si son lowereables,
 * recolecta su nombre ahi para que @c lower_function las
 * baje a runtime (`code.<helper>`), permitiendo que el `__macro_<X>` que las
 * llama resuelva.  La guarda de ciclos va aparte.  Por hilo
 * porque M8 compila modulos en paralelo (cada thread con su propio contexto).
 * (Definidos arriba, antes de Lowering::run.) */

std::string macro_body_unsupported_reason_expr(const TypeChecker &tc,
                                               const ast::Expr *e) {
    if (!e) return "";
    switch (e->kind) {
    case ast::NodeKind::IdentExpr: {
        /*  MC.17.2: refs a `comptime const` (INMUTABLES)
         * globales de tipo int SE ACEPTAN -- se materializan
         * como slot @c static_data de 8 bytes, leidos via
         * LOAD i64.  El valor es fijo, no hay divergencia
         * posible con el AST evaluator.
         *
         * `comptime var` (MUTABLES) siguen rechazados porque
         * la VM y el AST evaluator mantendrian copias separadas
         * que se desincronizarian con @Pure memoization
         * (test 156).  Soportarlos requiere shared memory
         * cross-AST/VM (deferred). */
        const auto *id = static_cast<const ast::IdentExpr *>(e);
        auto cit = tc.comptime_const_values().find(id->name);
        if (cit != tc.comptime_const_values().end()) {
            if (cit->second.is_str) {
                return "ref a comptime global string '" + id->name + "'";
            }
            if (cit->second.is_mutable) {
                /* comptime var MUTABLE global: se comparte entre lectores
                 * AST-eval (p.ej. `static_assert(g == 3)` top-level, otros
                 * comptime blocks) y el macro.  Si el macro VM-evaluara y
                 * mutara un slot static_data de la VM mientras el static_assert
                 * lee la copia AST (comptime_const_values_) -> DESYNC (el
                 * assert ve el valor viejo).  Por eso el macro que referencia
                 * un mutable global se deja AST-eval (misma copia que los
                 * lectores) -- arquitectural, no un gap de codegen.  Los
                 * mutables SOLO se podrian VM-evaluar si TODO lector comptime
                 * (incl. static_assert) leyera el slot de la VM, lo que
                 * exigiria ejecutar la VM en cada eval comptime -- fuera de
                 * alcance. */
                return "ref a comptime var (mutable) global '" + id->name + "'";
            }
            /* comptime const int (INMUTABLE) OK: slot static_data read-only. */
            return "";
        }
        return "";
    }
    case ast::NodeKind::CallExpr: {
        const auto *ce = static_cast<const ast::CallExpr *>(e);
        /* Calls con type-args -> introspect: NO soportado v1. */
        if (!ce->type_args.empty()) {
            return "introspect builtin con type_args (sizeof<T>, etc.)";
        }
        /* Calls a builtins comptime-only por nombre. */
        if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr) {
            const auto *id =
                static_cast<const ast::IdentExpr *>(ce->callee.get());
            /*  MC.15B+C: los builtins que YA estan aliasados a
             * sus equivalentes runtime str_* en @c lower_call NO
             * deben rechazarse aqui -- el lowering los soporta.
             * Los demas siguen siendo comptime-only.
             *
             * Lowereables (MC.15B: concat/streq/strlen; MC.15C:
             * to_str/chr/ord/substr/gensym):
             *   comptime_concat  -> STRCAT
             *   comptime_streq   -> STRCMP + cmp
             *   comptime_strlen  -> STRLEN
             *   comptime_to_str  -> CALLN(vio_int_to_vmbuf) + STRMAKE
             *   comptime_chr     -> CALLN(vio_char_to_vmbuf) + STRMAKE
             *   comptime_ord     -> STRRAW + LOAD u8
             *   comptime_substr  -> STRSLICE
             *   gensym           -> CALLN(vio_gensym)
             *
             * Restantes (MC.15D futuro): repeat, replace, contains,
             * compile, emit_expr, type, print/ct_print.
             */
            /* Restantes comptime-only tras MC.18+MC.20:
             *   comptime_compile / compile      -- generacion de codigo
             * dinamica comptime_emit_expr / emit_expr  -- splice de AST en
             * compile-time comptime_type                   -- type-as-value
             *
             * `comptime_print`, `ct_print` -> `println` (MC.18).
             * `static_assert` -> virtual lib `vesta_comptime`
             * via FFI bridge (MC.20).  El lowering emite CALLN
             * a "vesta_comptime:static_assert" que el Loader
             * resuelve via @c lookup_virtual_fn al cargar el
             * .velb. */
            static const std::unordered_set<std::string> COMPTIME_ONLY = {
                "comptime_compile", "comptime_emit_expr", "comptime_type",
                "compile",          "emit_expr",
            };
            if (COMPTIME_ONLY.count(id->name)) {
                return "builtin comptime-only '" + id->name + "'";
            }
            /* MC.23 fix (bug 161): los nombres registrados como virtual
             * comptime fns bajo `vesta_comptime`
             * (comptime_type_sizeof/alignof/kind, comptime_compile,
             * static_assert) NO tienen simbolo de bytecode real -- solo existen
             * in-process en el compilador.  Bajar el body del macro a IR
             * emitiria un `callvm code.<nombre>` colgante que el linker no
             * resuelve (RelocationError).  Se fuerza a que el macro corra en
             * comptime (AST/VM eval), que SI resuelve el nombre via
             * lookup_virtual_fn y embebe el resultado como literal. */
            /* Las type-metadata (`comptime_type_sizeof/alignof/kind`) con arg
             * LITERAL string son CONSTANTES compile-time: el lowering las
             * pliega a un CONST (ver lower_call), asi que NO rechazan el macro.
             * El resto de virtual fns (static_assert, comptime_compile) sin
             * simbolo bytecode siguen forzando AST/VM-eval del call site. */
            static const std::unordered_set<std::string> FOLDABLE_TYPE_META = {
                "comptime_type_sizeof", "comptime_type_alignof",
                "comptime_type_kind"};
            if (ffi::lookup_virtual_fn("vesta_comptime", id->name) &&
                !(FOLDABLE_TYPE_META.count(id->name) && ce->args.size() == 1 &&
                  ce->args[0] &&
                  ce->args[0]->kind == ast::NodeKind::StringLitExpr)) {
                return "virtual comptime fn '" + id->name + "'";
            }
            /*  MC.17.3: calls a @Macros user-defined SE ACEPTAN
             * (la callee tambien se baja a IR con nombre
             * `__macro_<callee>`, asi que emitimos CALLVM regular
             * a esa label).  Calls a comptime fns NO-@Macro
             * siguen rechazados (necesitarian inline o lower
             * propio que no esta hecho). */
            auto fn_it = tc.comptime_fns().find(id->name);
            if (fn_it != tc.comptime_fns().end()) {
                if (fn_it->second && fn_it->second->is_macro) {
                    /* Aceptamos.  El callee macro tambien sera
                     * lowereado por el linker (al final del
                     * pase).  Si su body resulta no-lowereable,
                     * el __macro_<callee> no existira y la
                     * CALLVM fallara en runtime -- ese caso
                     * cae al fallback AST por inconsistencia. */
                    for (const auto &a : ce->args) {
                        auto ra =
                            macro_body_unsupported_reason_expr(tc, a.get());
                        if (!ra.empty()) return ra;
                    }
                    return "";
                }
                /* Llamada a una comptime fn NO-macro.  Con force-lower activo
                 * (con force-lower puesto): recurrir en su body; si es
                 * lowereable, recolectarla para bajarla a runtime y ACEPTAR la
                 * llamada.  Sin force-lower (call sites legacy): rechazar
                 * (AST-only), comportamiento previo. */
                auto *force_lower = macro_force_lower();
                auto *visiting = macro_visiting();
                if (force_lower && fn_it->second && fn_it->second->body) {
                    const std::string &hn = fn_it->first; // nombre registrado
                    if (visiting->count(hn)) {
                        return ""; // ciclo: asumir OK (el otro nivel decide)
                    }
                    visiting->insert(hn);
                    std::string sub = macro_body_unsupported_reason(
                        tc, fn_it->second->body.get());
                    visiting->erase(hn);
                    if (sub.empty()) {
                        force_lower->insert(hn);
                        /* Seguir recorriendo los ARGS de esta llamada: pueden
                         * contener llamadas anidadas a OTRAS comptime fns
                         * (p.ej. `bf_emit(bf_classify(x))`) que tambien hay que
                         * recolectar para el force-lower.  Sin esto, el callee
                         * del argumento quedaba fuera del set -> su CALL
                         * emitiria "no es comptime-evaluable (argumento
                         * runtime?)". */
                        for (const auto &a : ce->args) {
                            auto ra =
                                macro_body_unsupported_reason_expr(tc, a.get());
                            if (!ra.empty()) return ra;
                        }
                        return "";
                    }
                    return "helper comptime no-lowereable '" + id->name +
                           "': " + sub;
                }
                return "call a comptime fn user-defined '" + id->name + "'";
            }
        }
        /* Recurse en args. */
        for (const auto &a : ce->args) {
            auto r = macro_body_unsupported_reason_expr(tc, a.get());
            if (!r.empty()) return r;
        }
        auto r = macro_body_unsupported_reason_expr(tc, ce->callee.get());
        if (!r.empty()) return r;
        return "";
    }
    case ast::NodeKind::BinaryExpr: {
        const auto *bn = static_cast<const ast::BinaryExpr *>(e);
        auto r = macro_body_unsupported_reason_expr(tc, bn->lhs.get());
        if (!r.empty()) return r;
        return macro_body_unsupported_reason_expr(tc, bn->rhs.get());
    }
    case ast::NodeKind::StringLitExpr: {
        /* Un string interpolado `"... ${expr} ..."` (o triple-quoted) que un
         * @Macro devuelve puede llevar en su interpolacion llamadas a otras
         * comptime fns (p.ej. `"() => { ${bf_compile_body(src)} }"`).  Recorrer
         * las exprs de interpolacion para que esos callees entren al set de
         * force-lower; sin esto la interpolacion emitia un CALLVM colgante y el
         * macro no era comptime-evaluable a string (solo funcionaba con concat
         * `"a" + f(x) + "b"`, que si se recorre por el case BinaryExpr). */
        const auto *sl = static_cast<const ast::StringLitExpr *>(e);
        for (const auto &ie : sl->interp_exprs) {
            auto r = macro_body_unsupported_reason_expr(tc, ie.get());
            if (!r.empty()) return r;
        }
        return "";
    }
    case ast::NodeKind::InitListExpr: {
        /* Init list `{a, b, c}` de un array local: el lowering del macro lo
         * soporta via el var-decl tipado (`i64 xs[N] = {...}`) que hace ALLOCA
         * + STOREs.  Recurrir en los elementos por si alguno no es lowereable
         * (p.ej. un init list de structs, que si requiere layout). */
        const auto *il = static_cast<const ast::InitListExpr *>(e);
        for (const auto &el : il->elements) {
            auto r = macro_body_unsupported_reason_expr(tc, el.get());
            if (!r.empty()) return r;
        }
        return "";
    }
    case ast::NodeKind::IndexExpr: {
        /* Array indexing `arr[i]`: lowereable en macro body cuando `arr` es un
         * array local tipado (el lowering conoce el elem type via el var-decl).
         * Recurrir en base + index. */
        const auto *ix = static_cast<const ast::IndexExpr *>(e);
        auto r = macro_body_unsupported_reason_expr(tc, ix->base.get());
        if (!r.empty()) return r;
        return macro_body_unsupported_reason_expr(tc, ix->index.get());
    }
    case ast::NodeKind::UnaryExpr: {
        const auto *un = static_cast<const ast::UnaryExpr *>(e);
        return macro_body_unsupported_reason_expr(tc, un->operand.get());
    }
    case ast::NodeKind::TernaryExpr: {
        const auto *te = static_cast<const ast::TernaryExpr *>(e);
        auto r = macro_body_unsupported_reason_expr(tc, te->cond.get());
        if (!r.empty()) return r;
        r = macro_body_unsupported_reason_expr(tc, te->then_expr.get());
        if (!r.empty()) return r;
        return macro_body_unsupported_reason_expr(tc, te->else_expr.get());
    }
    case ast::NodeKind::AssignExpr: {
        const auto *ae = static_cast<const ast::AssignExpr *>(e);
        auto r = macro_body_unsupported_reason_expr(tc, ae->target.get());
        if (!r.empty()) return r;
        return macro_body_unsupported_reason_expr(tc, ae->value.get());
    }
    default: return "";
    }
}

std::string macro_body_unsupported_reason(const TypeChecker &tc,
                                          const ast::Stmt *s) {
    if (!s) return "";
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        const auto *bs = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : bs->body) {
            auto r = macro_body_unsupported_reason(tc, st.get());
            if (!r.empty()) return r;
        }
        return "";
    }
    case ast::NodeKind::VarDeclStmt: {
        const auto *vd = static_cast<const ast::VarDeclStmt *>(s);
        /*   (1/3): `comptime var/const` LOCALES dentro
         * de un macro body ya no se rechazan.  El lowering los
         * trata como vars runtime regulares (en `lower_var_decl`
         * detectamos el flag y descartamos la rama comptime
         * cuando current_fn_is_macro_=true).  El VM computa el
         * init en cada invocacion -- mismo resultado semantico
         * que la evaluacion AST que ocurria one-time.
         *
         * Validamos solo el init si esta presente. */
        /* Vars locales de tipo array nativo `T[N]` o struct
         * nominal NO son lowereables en este path (requeriria
         * ALLOCA + sizeof del elemento + path completo de
         * struct layout).  Fallback al AST evaluator que SI
         * maneja arrays/structs comptime (A.41+A.42). */
        if (vd->type) {
            const auto *t = vd->type.get();
            if (t->kind == ast::NodeKind::ArrayTypeNode) {
                /* Array local `T[N]`: el lowering hace ALLOCA + init (STOREs) y
                 * el indexing usa el elem type del var-decl.  Validar solo el
                 * init. */
                if (vd->init)
                    return macro_body_unsupported_reason_expr(tc,
                                                              vd->init.get());
                return "";
            }
            if (t->kind == ast::NodeKind::NamedTypeNode) {
                /* Si el nombre matchea un struct declarado, es
                 * un struct value-type que no lowereamos en el
                 * body del macro. */
                const auto *nt = static_cast<const ast::NamedTypeNode *>(t);
                if (tc.struct_layouts().find(nt->name) !=
                    tc.struct_layouts().end()) {
                    return "var local de tipo struct '" + nt->name +
                           "' en macro body (usa AST eval)";
                }
            }
        }
        if (vd->init) {
            return macro_body_unsupported_reason_expr(tc, vd->init.get());
        }
        return "";
    }
    case ast::NodeKind::ExprStmt: {
        const auto *es = static_cast<const ast::ExprStmt *>(s);
        return macro_body_unsupported_reason_expr(tc, es->expr.get());
    }
    case ast::NodeKind::ReturnStmt: {
        const auto *rs = static_cast<const ast::ReturnStmt *>(s);
        return macro_body_unsupported_reason_expr(tc, rs->value.get());
    }
    case ast::NodeKind::IfStmt: {
        const auto *is = static_cast<const ast::IfStmt *>(s);
        auto r = macro_body_unsupported_reason_expr(tc, is->cond.get());
        if (!r.empty()) return r;
        r = macro_body_unsupported_reason(tc, is->then_branch.get());
        if (!r.empty()) return r;
        if (is->else_branch) {
            return macro_body_unsupported_reason(tc, is->else_branch.get());
        }
        return "";
    }
    case ast::NodeKind::WhileStmt: {
        const auto *ws = static_cast<const ast::WhileStmt *>(s);
        auto r = macro_body_unsupported_reason_expr(tc, ws->cond.get());
        if (!r.empty()) return r;
        return macro_body_unsupported_reason(tc, ws->body.get());
    }
    case ast::NodeKind::DoWhileStmt: {
        const auto *ds = static_cast<const ast::DoWhileStmt *>(s);
        auto r = macro_body_unsupported_reason_expr(tc, ds->cond.get());
        if (!r.empty()) return r;
        return macro_body_unsupported_reason(tc, ds->body.get());
    }
    case ast::NodeKind::ForStmt: {
        const auto *fs = static_cast<const ast::ForStmt *>(s);
        if (fs->init) {
            auto r = macro_body_unsupported_reason(tc, fs->init.get());
            if (!r.empty()) return r;
        }
        if (fs->cond) {
            auto r = macro_body_unsupported_reason_expr(tc, fs->cond.get());
            if (!r.empty()) return r;
        }
        if (fs->step) {
            auto r = macro_body_unsupported_reason_expr(tc, fs->step.get());
            if (!r.empty()) return r;
        }
        return macro_body_unsupported_reason(tc, fs->body.get());
    }
    case ast::NodeKind::ComptimeBlockStmt:
    case ast::NodeKind::ComptimeForStmt:
        return "comptime block/for en macro body (requiere MC.5)";
    default: return "";
    }
}

/* Detecta si el body de un @Macro FORWARDEA un expr-capture: llama a una
 * comptime fn que tiene un parametro `expr` (p.ej. `source(e)` / `inject(e)`).
 * Esos casos NO pueden correr en la ComptimeVM porque el helper necesita
 * re-capturar el texto en SU sitio de llamada (no una representacion runtime);
 * se dejan a AST-eval.  Un macro con `expr` param que solo lo usa como string
 * (p.ej. `bf_compile_body(src)`) NO forwardea y SI va a la VM. */
bool macro_body_forwards_expr_capture_expr(const TypeChecker &tc,
                                           const ast::Expr *e) {
    if (!e) return false;
    switch (e->kind) {
    case ast::NodeKind::CallExpr: {
        const auto *ce = static_cast<const ast::CallExpr *>(e);
        if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr) {
            const std::string &n =
                static_cast<const ast::IdentExpr *>(ce->callee.get())->name;
            auto it = tc.comptime_fns().find(n);
            if (it != tc.comptime_fns().end() && it->second) {
                for (const auto &p : it->second->params)
                    if (p && p->is_expr_capture) return true;
            }
        }
        for (const auto &a : ce->args)
            if (macro_body_forwards_expr_capture_expr(tc, a.get())) return true;
        return macro_body_forwards_expr_capture_expr(tc, ce->callee.get());
    }
    case ast::NodeKind::BinaryExpr: {
        const auto *bn = static_cast<const ast::BinaryExpr *>(e);
        return macro_body_forwards_expr_capture_expr(tc, bn->lhs.get()) ||
               macro_body_forwards_expr_capture_expr(tc, bn->rhs.get());
    }
    case ast::NodeKind::StringLitExpr: {
        const auto *sl = static_cast<const ast::StringLitExpr *>(e);
        for (const auto &ie : sl->interp_exprs)
            if (macro_body_forwards_expr_capture_expr(tc, ie.get()))
                return true;
        return false;
    }
    case ast::NodeKind::TernaryExpr: {
        const auto *te = static_cast<const ast::TernaryExpr *>(e);
        return macro_body_forwards_expr_capture_expr(tc, te->cond.get()) ||
               macro_body_forwards_expr_capture_expr(tc, te->then_expr.get()) ||
               macro_body_forwards_expr_capture_expr(tc, te->else_expr.get());
    }
    default: return false;
    }
}

bool macro_body_forwards_expr_capture(const TypeChecker &tc,
                                      const ast::Stmt *s) {
    if (!s) return false;
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        const auto *bs = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : bs->body)
            if (macro_body_forwards_expr_capture(tc, st.get())) return true;
        return false;
    }
    case ast::NodeKind::ReturnStmt: {
        const auto *rs = static_cast<const ast::ReturnStmt *>(s);
        return macro_body_forwards_expr_capture_expr(tc, rs->value.get());
    }
    case ast::NodeKind::ExprStmt: {
        const auto *es = static_cast<const ast::ExprStmt *>(s);
        return macro_body_forwards_expr_capture_expr(tc, es->expr.get());
    }
    case ast::NodeKind::VarDeclStmt: {
        const auto *vd = static_cast<const ast::VarDeclStmt *>(s);
        return macro_body_forwards_expr_capture_expr(tc, vd->init.get());
    }
    case ast::NodeKind::IfStmt: {
        const auto *is = static_cast<const ast::IfStmt *>(s);
        return macro_body_forwards_expr_capture_expr(tc, is->cond.get()) ||
               macro_body_forwards_expr_capture(tc, is->then_branch.get()) ||
               macro_body_forwards_expr_capture(tc, is->else_branch.get());
    }
    case ast::NodeKind::WhileStmt: {
        const auto *ws = static_cast<const ast::WhileStmt *>(s);
        return macro_body_forwards_expr_capture_expr(tc, ws->cond.get()) ||
               macro_body_forwards_expr_capture(tc, ws->body.get());
    }
    case ast::NodeKind::ForStmt: {
        const auto *fs = static_cast<const ast::ForStmt *>(s);
        return macro_body_forwards_expr_capture(tc, fs->init.get()) ||
               macro_body_forwards_expr_capture_expr(tc, fs->cond.get()) ||
               macro_body_forwards_expr_capture_expr(tc, fs->step.get()) ||
               macro_body_forwards_expr_capture(tc, fs->body.get());
    }
    default: return false;
    }
}

/* Pre-pase de annotation de tipos para body de @Macro.
 *
 * Los macros NO pasan por `check_functions` (los saltea porque su
 * body se interpreta solo al call site).  Pero MC.1 los baja a IR para
 * que la VM eval pueda ejecutarlos.  Sin annotation de tipos, los
 * IdentExpr en el body tienen result_type=VOID -- `lower_binary` no
 * detecta el caso `code == "OK"` con `code: string` y emite cmpjmp
 * directo sobre los handles en lugar de STRCMP runtime.
 *
 * Este walker recorre el body y annota result_type de los IdentExpr
 * cuyo nombre matchee un param del macro.  Es minimal -- solo cubre
 * el caso de params; otras vars locales se annotan al llamarlas via
 * lower_expr (que internamente usa el scope del lowering).  */
void annotate_macro_param_idents(
    ast::Stmt *s, const std::unordered_map<std::string, Type> &param_types) {
    if (!s) return;
    std::function<void(ast::Expr *)> walk_expr = [&](ast::Expr *e) {
        if (!e) return;
        if (e->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(e);
            auto it = param_types.find(id->name);
            if (it != param_types.end()) {
                /* Siempre sobreescribir: dentro del body del macro
                 * los IdentExpr no fueron type-checkeados; el campo
                 * puede tener un default heredado del parser. */
                id->result_type = it->second;
            }
            return;
        }
        if (e->kind == ast::NodeKind::BinaryExpr) {
            auto *bn = static_cast<ast::BinaryExpr *>(e);
            walk_expr(bn->lhs.get());
            walk_expr(bn->rhs.get());
            return;
        }
        if (e->kind == ast::NodeKind::UnaryExpr) {
            auto *un = static_cast<ast::UnaryExpr *>(e);
            walk_expr(un->operand.get());
            return;
        }
        if (e->kind == ast::NodeKind::CallExpr) {
            auto *ce = static_cast<ast::CallExpr *>(e);
            walk_expr(ce->callee.get());
            for (auto &a : ce->args)
                walk_expr(a.get());
            return;
        }
        if (e->kind == ast::NodeKind::AssignExpr) {
            auto *ae = static_cast<ast::AssignExpr *>(e);
            walk_expr(ae->target.get());
            walk_expr(ae->value.get());
            return;
        }
        if (e->kind == ast::NodeKind::TernaryExpr) {
            auto *te = static_cast<ast::TernaryExpr *>(e);
            walk_expr(te->cond.get());
            walk_expr(te->then_expr.get());
            walk_expr(te->else_expr.get());
            return;
        }
        if (e->kind == ast::NodeKind::IndexExpr) {
            auto *ix = static_cast<ast::IndexExpr *>(e);
            walk_expr(ix->base.get());
            walk_expr(ix->index.get());
            return;
        }
        if (e->kind == ast::NodeKind::FieldAccessExpr) {
            auto *fa = static_cast<ast::FieldAccessExpr *>(e);
            walk_expr(fa->base.get());
            return;
        }
        if (e->kind == ast::NodeKind::CastExpr) {
            auto *ca = static_cast<ast::CastExpr *>(e);
            walk_expr(ca->operand.get());
            return;
        }
        /* Otros tipos de expresion: no necesitan recursion para el
         * caso de annotation de params (literals, ThisExpr, etc.). */
    };
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        auto *bs = static_cast<ast::BlockStmt *>(s);
        for (auto &st : bs->body)
            annotate_macro_param_idents(st.get(), param_types);
        break;
    }
    case ast::NodeKind::VarDeclStmt: {
        auto *vd = static_cast<ast::VarDeclStmt *>(s);
        if (vd->init) walk_expr(vd->init.get());
        break;
    }
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<ast::ExprStmt *>(s);
        walk_expr(es->expr.get());
        break;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *rs = static_cast<ast::ReturnStmt *>(s);
        if (rs->value) walk_expr(rs->value.get());
        break;
    }
    case ast::NodeKind::IfStmt: {
        auto *ifs = static_cast<ast::IfStmt *>(s);
        walk_expr(ifs->cond.get());
        annotate_macro_param_idents(ifs->then_branch.get(), param_types);
        if (ifs->else_branch)
            annotate_macro_param_idents(ifs->else_branch.get(), param_types);
        break;
    }
    case ast::NodeKind::WhileStmt: {
        auto *ws = static_cast<ast::WhileStmt *>(s);
        walk_expr(ws->cond.get());
        annotate_macro_param_idents(ws->body.get(), param_types);
        break;
    }
    case ast::NodeKind::DoWhileStmt: {
        auto *ds = static_cast<ast::DoWhileStmt *>(s);
        walk_expr(ds->cond.get());
        annotate_macro_param_idents(ds->body.get(), param_types);
        break;
    }
    case ast::NodeKind::ForStmt: {
        auto *fs = static_cast<ast::ForStmt *>(s);
        if (fs->init) annotate_macro_param_idents(fs->init.get(), param_types);
        if (fs->cond) walk_expr(fs->cond.get());
        if (fs->step) walk_expr(fs->step.get());
        annotate_macro_param_idents(fs->body.get(), param_types);
        break;
    }
    default: break;
    }
}

} // namespace vx
