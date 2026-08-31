/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/types.cpp
 * @brief De los tipos de Vesta a los del IR, y las conversiones entre ellos.
 *
 * El lenguaje tiene mas tipos de los que el IR distingue: donde el usuario
 * escribe un enum, una vista, un opcional o una clase, abajo hay enteros y
 * punteros.  Traducir uno a otro es la primera mitad del fichero, y no es una
 * tabla: hay que saber cuanto ocupa cada cosa, si viaja por valor o por
 * direccion, y si lo que se declaro es una vista sobre bytes ajenos.
 *
 * La otra mitad es convertir un valor de un tipo a otro, que es donde el
 * lenguaje promete cosas que la maquina no da sola: recortar a menos bits,
 * ensanchar rellenando con el signo o con ceros, pasar de entero a coma
 * flotante y al reves.  Elegir mal ahi no da un error, da un numero distinto.
 */
#include "vx/lowering.h"
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

ir::IrType Lowering::ir_type_from_primitive(PrimitiveKind p) noexcept {
    // Mapeo directo.  Se usa una tabla constexpr indexada por enum
    // (PrimitiveKind y IrType comparten posiciones logicas pero los
    // valores numericos no coinciden, asi que este switch es la
    // version mantenible).
    switch (p) {
    case PrimitiveKind::VOID: return ir::IrType::VOID;
    case PrimitiveKind::BOOL: return ir::IrType::BOOL;
    // CHAR no tiene contraparte directa en ir::IrType; mapeamos a U8
    // (mismo ancho, semanticamente equivalente porque el frontend
    // solo lo usa como entero pequenyo sin codepoint awareness).
    case PrimitiveKind::CHAR: return ir::IrType::U8;
    case PrimitiveKind::I8: return ir::IrType::I8;
    case PrimitiveKind::I16: return ir::IrType::I16;
    case PrimitiveKind::I32: return ir::IrType::I32;
    case PrimitiveKind::I64: return ir::IrType::I64;
    case PrimitiveKind::U8: return ir::IrType::U8;
    case PrimitiveKind::U16: return ir::IrType::U16;
    case PrimitiveKind::U32: return ir::IrType::U32;
    case PrimitiveKind::U64: return ir::IrType::U64;
    case PrimitiveKind::F32: return ir::IrType::F32;
    case PrimitiveKind::F64: return ir::IrType::F64;
    case PrimitiveKind::PTR: return ir::IrType::PTR;
    // Para STRUCT y ARRAY no hay un IrType directo; en el lowering
    // ambos se representan via su PUNTERO base (PTR).  Cuando un
    // caller pasa STRUCT/ARRAY a este helper esperando un IrType
    // unitario, devolvemos PTR como aproximacion mas razonable.
    case PrimitiveKind::STRUCT: return ir::IrType::PTR;
    case PrimitiveKind::ARRAY: return ir::IrType::PTR;
    // CLASS es reference type: la "variable" guarda un puntero a
    // ObjectHeader, asi que el IrType subyacente es PTR.
    case PrimitiveKind::CLASS: return ir::IrType::PTR;
    // Optional/Result builtins: la variable guarda un puntero
    // (PTR) al buffer en stack alocado por Some/Ok/etc.  16 bytes
    // para Optional, 24 para Result; el lowering emite ALLOCA.
    case PrimitiveKind::OPTIONAL: return ir::IrType::PTR;
    case PrimitiveKind::RESULT: return ir::IrType::PTR;
    // string es un GcHandle opaco i64.
    case PrimitiveKind::STRING: return ir::IrType::I64;
    // tipos primitivos de coleccion: i64 handle host pointer.
    // Cero overhead vs llamar el plugin directo (sin wrapping).
    case PrimitiveKind::ARRAYLIST: return ir::IrType::I64;
    case PrimitiveKind::HASHMAP: return ir::IrType::I64;
    case PrimitiveKind::HASHSET: return ir::IrType::I64;
    case PrimitiveKind::QUEUE: return ir::IrType::I64;
    case PrimitiveKind::DEQUE: return ir::IrType::I64;
    case PrimitiveKind::TREEMAP: return ir::IrType::I64;
    case PrimitiveKind::TREESET: return ir::IrType::I64;
    case PrimitiveKind::STACK: return ir::IrType::I64;
    // Smart pointers: slot stack con host_ptr (8 bytes).
    case PrimitiveKind::UNIQUE_PTR: return ir::IrType::PTR;
    case PrimitiveKind::SHARED_PTR: return ir::IrType::PTR;
    // Borrows: host_ptr de 8 bytes (zero overhead vs T* raw).
    case PrimitiveKind::BORROW: return ir::IrType::PTR;
    case PrimitiveKind::BORROW_MUT: return ir::IrType::PTR;
    // Future<T>: handle i64.
    case PrimitiveKind::FUTURE: return ir::IrType::I64;
    // FUNCTION: par (fn_addr, env_addr); usamos PTR como aproximacion.
    case PrimitiveKind::FUNCTION: return ir::IrType::PTR;
    case PrimitiveKind::COUNT: return ir::IrType::VOID;
    }
    return ir::IrType::VOID;
}

void Lowering::compute_type_intervals() {
    type_intervals_.clear();
    const auto &layouts = tc_.class_layouts();
    if (layouts.empty()) return;
    // children[S] = clases cuya super es S (S es a su vez una clase del
    // modulo).
    std::map<std::string, std::vector<std::string>> children;
    std::vector<std::string> roots;
    for (const auto &kv : layouts) {
        const std::string &nm = kv.first;
        const std::string &sup = kv.second.super_name;
        if (!sup.empty() && layouts.count(sup))
            children[sup].push_back(nm);
        else
            roots.push_back(nm);
    }
    for (auto &kv : children)
        std::sort(kv.second.begin(), kv.second.end());
    std::sort(roots.begin(), roots.end());
    uint32_t counter = 0;
    std::unordered_set<std::string> visiting;
    std::function<uint32_t(const std::string &)> dfs =
        [&](const std::string &nm) -> uint32_t {
        const uint32_t lo = counter++;
        uint32_t hi = lo;
        if (visiting.insert(nm).second) {
            // defensa anti-ciclo
            auto it = children.find(nm);
            if (it != children.end())
                for (const std::string &ch : it->second)
                    hi = std::max(hi, dfs(ch));
        }
        type_intervals_[nm] = {lo, hi};
        return hi;
    };
    for (const std::string &r : roots)
        dfs(r);
}

/**
 * @copydoc vx::Lowering::optional_layout
 */
ir::IrValueId Lowering::enforce_nonnull(ir::IrValueId v, int line) {
    if (v == ir::IR_NO_VALUE || !fn_ || v >= fn_->values.size()) return v;
    const ir::IrType t = fn_->values[v].type;
    const ir::IrValueId v_new = fn_->new_value(t);
    ir::IrInstr uw{};
    uw.op = ir::IrOp::UNWRAP; // lanza FATAL_NULL_POINTER si vale cero
    uw.type = t;
    uw.dst = v_new;
    uw.operands = {v};
    uw.source_line = line;
    emit(current_block_, std::move(uw));
    // Lo que sale es el mismo puntero: conserva de que memoria es.
    fn_->values[v_new].is_host_ptr = fn_->values[v].is_host_ptr;
    fn_->values[v_new].pointee_is_host_ptr = fn_->values[v].pointee_is_host_ptr;
    fn_->values[v_new].is_gc_object = fn_->values[v].is_gc_object;
    return v_new;
}

Lowering::TypeMemory Lowering::type_memory(const Type &t) const {
    TypeMemory m;
    /* Una referencia a clase apunta a un objeto del recolector, y eso hay que
     * decirlo ademas de que sea del anfitrion: el asignador de registros tiene
     * que salvarlo por su manejador cuando una llamada por medio pueda mover
     * el monton. */
    if (t.kind == PrimitiveKind::CLASS) {
        m.is_host_ptr = true;
        m.is_gc_object = true;
        return m;
    }
    /* Un puntero o un array que NO sea `VirtualPtr` apunta a memoria del
     * anfitrion.  De eso depende que un deref se emita con una instruccion o
     * con la otra, y equivocarse no da un error: da un cero. */
    if ((t.kind != PrimitiveKind::PTR && t.kind != PrimitiveKind::ARRAY) ||
        t.is_virtual)
        return m;
    m.is_host_ptr = true;
    // `T**`: un deref intermedio tiene que conservar que lo de dentro tambien
    // es del anfitrion.
    if (t.pointee &&
        (t.pointee->kind == PrimitiveKind::PTR ||
         t.pointee->kind == PrimitiveKind::ARRAY) &&
        !t.pointee->is_virtual) {
        m.pointee_is_host_ptr = true;
    }
    return m;
}

void Lowering::apply_type_memory(ir::IrFunction &fn, ir::IrValueId v,
                                 const TypeMemory &m) const {
    if (v == ir::IR_NO_VALUE || v >= fn.values.size()) return;
    if (m.is_host_ptr) fn.values[v].is_host_ptr = true;
    if (m.is_gc_object) fn.values[v].is_gc_object = true;
    if (m.pointee_is_host_ptr) fn.values[v].pointee_is_host_ptr = true;
}

void Lowering::mark_value_from_type(ir::IrValueId v, const Type &t) {
    if (!fn_) return;
    apply_type_memory(*fn_, v, type_memory(t));
}

OptionalLayout Lowering::optional_layout(const Type &t) const {
    /* La disposicion la decide el comprobador de tipos, que es de quien es el
     * dato: es una propiedad del TIPO, y ademas la preguntan el `match` y el
     * calculo del tamano de un struct que lo lleve de campo, que no pasan por
     * aqui.  Este metodo se queda como atajo para el bajado. */
    return tc_.optional_layout(t);
}

size_t Lowering::optional_buf_bytes(const Type &t, size_t base) const {
    /* El tamano sale de la disposicion, que es quien la decide.  El parametro
     * `base` sigue existiendo porque un `Result` lo llama con otra cabecera. */
    if (base == 8) return optional_layout(t).bytes;
    size_t payload = 8;
    if (t.pointee) {
        const Type &p = *t.pointee;
        if (p.kind == PrimitiveKind::STRUCT) {
            const size_t sz = size_of_type(p);
            if (sz > payload) payload = (sz + 7u) & ~static_cast<size_t>(7);
        }
    }
    return base + payload;
}

size_t Lowering::size_of_type(const Type &t) const {
    if (t.kind == PrimitiveKind::STRUCT) {
        const auto &layouts = tc_.struct_layouts();
        auto it = layouts.find(t.struct_name);
        if (it != layouts.end()) return it->second.size_bytes;
        // bug4: STRUCT puede ser un ENUM (mismo kind).  Buscar en
        // enum_layouts_ tambien.  size_bytes = 8 (tag) + 8*max_payload.
        const auto &elayouts = tc_.enum_layouts();
        auto ite = elayouts.find(t.struct_name);
        return (ite == elayouts.end()) ? 0 : ite->second.size_bytes;
    }
    if (t.kind == PrimitiveKind::PTR) return 8;
    if (t.kind == PrimitiveKind::ARRAY) {
        // T[N] ocupa N*sizeof(T) bytes; T[] (size==0) decae a puntero.
        // bug4: para T[] (dynamic) sin tamano fijo, sizeof = 8 (el
        // valor es un host_ptr al buffer).  Caller que pregunte
        // sizeof(slot) obtiene la pointer-size correcta.
        if (!t.pointee) return 0;
        if (t.array_size == 0) return 8; // host_ptr al buffer
        return static_cast<size_t>(t.array_size) * size_of_type(*t.pointee);
    }
    // CLASS: ref host_ptr al objeto GC.
    if (t.kind == PrimitiveKind::CLASS) return 8;
    // STRING: GcHandle u64.
    if (t.kind == PrimitiveKind::STRING) return 8;
    // cfn (puntero a funcion crudo, fn_is_raw): SOLO la direccion -> 8 bytes.
    // Un lambda fn(...) es un fat-pointer de 16 bytes {fn_addr, env}.
    if (t.kind == PrimitiveKind::FUNCTION && t.fn_is_raw) return 8;
    // Un `Optional` mide segun lo que lleve dentro; lo sabe su disposicion.
    if (t.kind == PrimitiveKind::OPTIONAL) return optional_layout(t).bytes;
    return primitive_size_bytes(t.kind);
}

bool Lowering::type_is_overlay(const Type &t) const {
    if (t.kind != PrimitiveKind::STRUCT || t.struct_name.empty()) return false;
    const auto &layouts = tc_.struct_layouts();
    auto it = layouts.find(t.struct_name);
    return it != layouts.end() && it->second.is_overlay;
}

ir::IrValueId Lowering::cast_if_needed(ir::IrValueId v, ir::IrType from,
                                       ir::IrType to, uint32_t source_line,
                                       bool is_explicit) {
    // Overload de compatibilidad: sin SourceLoc completo, el warning apunta al
    // inicio (columna 1) de la linea.  Los call sites de alto impacto pasan el
    // SourceLoc de la expresion para apuntar a su columna real.
    SourceLoc loc;
    loc.file = current_file_;
    loc.line = source_line;
    loc.column = 1;
    return cast_if_needed(v, from, to, loc, is_explicit);
}

ir::IrValueId Lowering::cast_if_needed(ir::IrValueId v, ir::IrType from,
                                       ir::IrType to, const SourceLoc &loc,
                                       bool is_explicit) {
    if (from == to || v == ir::IR_NO_VALUE) return v;
    // Un valor CONSTANTE compile-time que CABE en el tipo destino no pierde
    // informacion aunque el destino sea mas estrecho: `u8 x = 0x48` o
    // `this.mod = 3` (bitfield) o un valued-enum (`Enc.RET`, cuyo valor es una
    // constante) no deben avisar de narrowing.  Misma politica que C/C++: no
    // se avisa por `char c = 65`.  Suprime el warning tratando el cast como
    // explicito (la conversion de bits sigue emitiendose igual).
    if (!is_explicit && v < fn_->values.size() && fn_->values[v].is_const) {
        const uint64_t cv = fn_->values[v].const_val;
        bool fits = false;
        switch (to) {
        case ir::IrType::U8: fits = (cv <= 0xFFULL); break;
        case ir::IrType::U16: fits = (cv <= 0xFFFFULL); break;
        case ir::IrType::U32: fits = (cv <= 0xFFFFFFFFULL); break;
        case ir::IrType::BOOL: fits = (cv <= 1ULL); break;
        case ir::IrType::I8: {
            const int64_t s = (int64_t)cv;
            fits = (s >= -128 && s <= 255);
            break;
        }
        case ir::IrType::I16: {
            const int64_t s = (int64_t)cv;
            fits = (s >= -32768 && s <= 65535);
            break;
        }
        case ir::IrType::I32: {
            const int64_t s = (int64_t)cv;
            fits = (s >= -2147483648LL && s <= 4294967295LL);
            break;
        }
        default: break;
        }
        if (fits) is_explicit = true;
    }
    // Warning de seguridad para casts implicitos que pueden perder
    // informacion: narrowing entero, float -> int, int -> float (los
    // grandes pierden mantissa).  Solo se emite cuando el usuario NO
    // escribio el cast explicitamente: `i32 x = i64_val` avisa, pero
    // `i32 x = (i32) i64_val` no.  Misma politica que -Wconversion en
    // GCC/Clang.
    if (!is_explicit) {
        auto bytes_for = [](ir::IrType t) -> int {
            return static_cast<int>(ir::type_slot_bytes(t));
        };
        const bool from_is_float =
            (from == ir::IrType::F32 || from == ir::IrType::F64);
        const bool to_is_float =
            (to == ir::IrType::F32 || to == ir::IrType::F64);
        const bool from_is_int =
            (from == ir::IrType::I8 || from == ir::IrType::I16 ||
             from == ir::IrType::I32 || from == ir::IrType::I64 ||
             from == ir::IrType::U8 || from == ir::IrType::U16 ||
             from == ir::IrType::U32 || from == ir::IrType::U64 ||
             from == ir::IrType::BOOL);
        const bool to_is_int =
            (to == ir::IrType::I8 || to == ir::IrType::I16 ||
             to == ir::IrType::I32 || to == ir::IrType::I64 ||
             to == ir::IrType::U8 || to == ir::IrType::U16 ||
             to == ir::IrType::U32 || to == ir::IrType::U64 ||
             to == ir::IrType::BOOL);
        const int from_bytes = bytes_for(from);
        const int to_bytes = bytes_for(to);
        std::string warn_msg;
        if (from_is_float && to_is_int) {
            warn_msg = "conversion implicita float -> int trunca la parte "
                       "fraccionaria; "
                       "usa cast explicito si es intencional";
        } else if (from_is_int && to_is_float) {
            // Solo avisar para enteros grandes a f32 (perdida de mantissa).
            // i64/u64 -> f32: ~24 bits de mantissa, perdida garantizada para
            // magnitudes >2^24. i32/u32 -> f32: tambien puede perder.  i*->f64
            // es exacto hasta 2^53.
            if (to == ir::IrType::F32 && from_bytes >= 4) {
                warn_msg =
                    "conversion implicita int -> f32 puede perder precision; "
                    "usa cast explicito si es intencional";
            }
        } else if (from_is_int && to_is_int) {
            if (to_bytes < from_bytes) {
                warn_msg = "conversion implicita reduce el ancho del entero "
                           "(narrowing); usa cast explicito si es intencional";
            }
        } else if (from_is_float && to_is_float) {
            if (to == ir::IrType::F32 && from == ir::IrType::F64) {
                warn_msg = "conversion implicita f64 -> f32 reduce precision; "
                           "usa cast explicito si es intencional";
            }
        }
        if (!warn_msg.empty()) {
            diags_.warning(loc, warn_msg);
        }
    }

    // Elegir el opcode de conversion correcto segun categoria.
    ir::IrOp op = ir::IrOp::CAST;
    const bool from_float =
        (from == ir::IrType::F32 || from == ir::IrType::F64);
    const bool to_float = (to == ir::IrType::F32 || to == ir::IrType::F64);

    if (from_float && to_float) {
        op = (from == ir::IrType::F32 && to == ir::IrType::F64)
                 ? ir::IrOp::F32TOF64
                 : ir::IrOp::F64TOF32;
    } else if (from_float && !to_float) {
        // Heuristica: si el destino es signed -> FTOI; si unsigned -> FTOUI.
        const bool to_signed = (to == ir::IrType::I8 || to == ir::IrType::I16 ||
                                to == ir::IrType::I32 || to == ir::IrType::I64);
        op = to_signed ? ir::IrOp::FTOI : ir::IrOp::FTOUI;
    } else if (!from_float && to_float) {
        // Heuristica simetrica: si origen signed -> ITOF; si unsigned -> UITOF.
        const bool from_signed =
            (from == ir::IrType::I8 || from == ir::IrType::I16 ||
             from == ir::IrType::I32 || from == ir::IrType::I64);
        // Bug fix 2026-05-23: ITOF/UITOF baja a `fcvt rd_gp, f0` que
        // opera sobre el reg de 64 bits.  Si el operando es i8/i16/i32,
        // los bits altos no estan extendidos correctamente -> el float
        // resultante es incorrecto.  Para i32 -7 -> trunc deja
        // 0xFFFFFFF9 con bits altos = 0 -> ITOF lo lee como 4294967289
        // (no -7).  Fix: SEXT (signed) o ZEXT (unsigned) a i64 ANTES
        // del ITOF/UITOF.
        /* Esta tabla se escribia a mano y OMITIA F32, que caia en el default y
         * valia 8 en vez de 4.  No fallaba porque esta rama solo se recorre
         * cuando el origen NO es flotante -- estaba protegida por el contexto,
         * no por ser correcta.  El vocabulario unico ya no deja escribir eso.
         */
        auto bytes_of_local = [](ir::IrType t) -> int {
            return static_cast<int>(ir::type_slot_bytes(t));
        };
        if (bytes_of_local(from) < 8) {
            ir::IrValueId v_ext = fn_->new_value(ir::IrType::I64);
            ir::IrInstr ext{};
            ext.op = from_signed ? ir::IrOp::SEXT : ir::IrOp::ZEXT;
            ext.type = ir::IrType::I64;
            ext.dst = v_ext;
            ext.operands.push_back(v);
            ext.source_line = loc.line;
            emit(current_block_, std::move(ext));
            v = v_ext;
        }
        op = from_signed ? ir::IrOp::ITOF : ir::IrOp::UITOF;
    } else {
        // Entero -> entero: elegir TRUNC, ZEXT o SEXT segun el cambio
        // de ancho y la signedness de la fuente.  Sin esto, el
        // emitter recibia siempre CAST y emitia un mov plano que NO
        // truncaba ni extendia: `i32 x = i64_value` dejaba los 8
        // bytes originales en el registro (bug de truncacion).
        /* Misma historia que bytes_of_local: omitia F32 y sobrevivia porque la
         * rama excluye los flotantes.  Ahora lo contesta el vocabulario. */
        auto bytes_of = [](ir::IrType t) -> int {
            return static_cast<int>(ir::type_slot_bytes(t));
        };
        const int from_b = bytes_of(from);
        const int to_b = bytes_of(to);
        const bool from_signed =
            (from == ir::IrType::I8 || from == ir::IrType::I16 ||
             from == ir::IrType::I32 || from == ir::IrType::I64);
        if (to_b < from_b) {
            op = ir::IrOp::TRUNC;
        } else if (to_b > from_b) {
            op = from_signed ? ir::IrOp::SEXT : ir::IrOp::ZEXT;
        } else {
            // Mismo ancho: nada que extender ni truncar; un BITCAST
            // (mov plano) es lo correcto a nivel de bytecode.  Esto
            // cubre cambios de signedness sin reinterpretacion (e.g.
            // i32 -> u32) y casts entre PTR e i64.
            op = ir::IrOp::BITCAST;
        }
    }

    const ir::IrValueId dst = fn_->new_value(to);
    ir::IrInstr ins{};
    ins.op = op;
    ins.type = to;
    ins.dst = dst;
    ins.operands = {v};
    ins.source_line = loc.line;
    emit(current_block_, std::move(ins));
    return dst;
}

/**
 * @brief Resuelve como se ve un parametro desde el IR.
 *
 * El tipo sale del nodo declarado; lo demas son las excepciones, y cada una
 * esta porque sin ella el codigo generado lee de donde no es:
 *
 *   - Una cadena en un binario nativo es un valor de veinticuatro bytes que
 *     viaja por su direccion, no un manejador del recolector como en la
 *     maquina virtual.
 *   - Un puntero crudo `T*` y un array `T[]` apuntan a memoria del anfitrion;
 *     `VirtualPtr<T>` es la unica forma de nombrar una direccion de la maquina
 *     virtual, y por eso la distincion es @c is_virtual y no el tipo.
 *   - Todo agregado -- struct, enum, vista sobre bytes, Optional, Result --
 *     se pasa por su direccion y vive en memoria del anfitrion en los TRES
 *     modos.  Aqui hubo un fallo que se arreglo tres veces por separado:
 *     limitarlo al modo nativo hacia que en interprete el llamado leyera el
 *     agregado con la instruccion de la maquina virtual y le llegaran ceros,
 *     con el argumento de al lado funcionando.
 *   - Un variadico empaquetado no llega como @c T sino como la direccion del
 *     array que monto quien llama.
 *
 * @param p El parametro declarado.
 * @return Su tipo y su naturaleza.
 */
Lowering::ParamAbi Lowering::param_abi(const ast::ParamDecl &p) const {
    ParamAbi abi;

    /* Un parametro de SALIDA por referencia (`out T x` sobre un valor) no
     * recibe una `T`: recibe la DIRECCION de un hueco del llamante.  Se decide
     * aqui porque este es el unico sitio que dice con que forma entra un
     * parametro, y por el pasan los dos caminos -- la funcion suelta y el
     * metodo --.  Decidirlo en cada uno dejaba al metodo fuera: su parametro
     * se quedaba como un valor y la asignacion del cuerpo compilaba a un
     * calculo MUERTO, sin store y sin error. */
    if (p.type && p.dir != ast::ParamDir::None &&
        is_by_ref_out_param(p.dir, tc_.resolve_type_node(p.type.get()))) {
        abi.type = ir::IrType::PTR;
        abi.mem.is_host_ptr = true; // la direccion de un hueco del anfitrion
        return abi;
    }

    if (p.type && p.type->kind == ast::NodeKind::PrimitiveTypeNode) {
        const auto *ptn =
            static_cast<const ast::PrimitiveTypeNode *>(p.type.get());
        abi.type = ir_type_from_primitive(ptn->prim);
        if (native_poo_ && ptn->prim == PrimitiveKind::STRING)
            abi.mem.is_host_ptr = true;
    } else if (p.type) {
        /* Un tipo compuesto -- un puntero, un array, un nombre que hay que
         * resolver -- no se lee del nodo: se le pregunta al comprobador de
         * tipos, que es quien deshizo los alias y las instanciaciones. */
        const Type sem = tc_.resolve_type_node(p.type.get());
        if (sem.kind != PrimitiveKind::COUNT && sem.kind != PrimitiveKind::VOID)
            abi.type = ir_type_from_primitive(sem.kind);

        /* Lo que el tipo dice de la memoria lo contesta un solo sitio -- ver
         * @c type_memory --, el mismo que responde para el resultado de una
         * llamada o para lo que se saca de un `Optional`. */
        abi.mem = type_memory(sem);

        /* Y lo que es propio de un PARAMETRO: un agregado no viaja en un
         * registro, llega como la DIRECCION de donde esta, y todo agregado
         * vive en memoria del anfitrion.  Por eso esto no esta en
         * `type_memory`: ahi se pregunta por un valor cualquiera, y el de un
         * agregado saca su memoria de donde se construyo. */
        if (sem.kind == PrimitiveKind::STRUCT ||
            sem.kind == PrimitiveKind::OPTIONAL ||
            sem.kind == PrimitiveKind::RESULT)
            abi.mem.is_host_ptr = true;
    }

    if (p.is_variadic) {
        // Llega la DIRECCION del array que monto quien llama, sea lo que sea
        // lo que se declaro: eso manda sobre todo lo de arriba.
        abi.type = ir::IrType::PTR;
        abi.mem = TypeMemory{};
        abi.mem.is_host_ptr = true;
    }
    return abi;
}

/**
 * @copydoc vx::Lowering::declare_params
 */
size_t Lowering::param_slot_count(
    const std::vector<std::unique_ptr<ast::ParamDecl>> &params) {
    size_t n = 0;
    for (const auto &p : params)
        n += p->is_raw_variadic ? 0u : (p->is_variadic ? 2u : 1u);
    return n;
}

std::vector<Lowering::DeclaredParam> Lowering::declare_params(
    ir::IrFunction &fn,
    const std::vector<std::unique_ptr<ast::ParamDecl>> &params,
    std::vector<std::pair<std::string, ir::IrValueId>> &bindings,
    size_t reserved_slots) {
    /* La maquina virtual pasa los argumentos en DOCE registros, y ese modelo se
     * queda: para un interprete es lo mas rapido que hay, y cambiarlo por una
     * pila lo haria mas lento en el caso comun, que es el de siempre -- pocos
     * argumentos --.  El JIT usa el mismo banco, asi que hereda el limite.
     *
     * Un binario NATIVO no lo tiene: la convencion del procesador derrama en la
     * pila lo que no cabe en registros, y ahi doce o veinte da igual.
     *
     * Asi que esto NO es un limite del lenguaje, es de un modo de ejecucion, y
     * por eso se dice aqui -- donde ya se sabe para donde se compila -- y no en
     * el comprobador de tipos, que rechazaria tambien lo que en nativo
     * funciona. Y hay que decirlo: pasarse no daba un error sino un argumento
     * con basura, que compila, arranca y da numeros absurdos. */
    if (!native_poo_ && !params.empty()) {
        const size_t slots = param_slot_count(params) + reserved_slots;
        if (slots > 12) {
            error_at(
                params.front()->loc,
                "'" + fn.name + "' necesita " + std::to_string(slots) +
                    " huecos de argumento y la maquina virtual tiene "
                    "doce" +
                    (reserved_slots ? " (uno lo ocupa 'this')" : "") +
                    ".\n  Un variadico ocupa dos: la direccion y cuantos "
                    "son.\n  sugerencia: agrupa los que sobren en un "
                    "struct, o compila a nativo (`-m aot`), que ahi no hay "
                    "limite");
        }
    }

    std::vector<DeclaredParam> out;
    out.reserve(params.size() + 1);

    for (const auto &p : params) {
        /* El `...` pelado NO declara nada: sus argumentos ocupan los registros
         * que diga la convencion de llamada y el cuerpo en ensamblador los lee
         * de ahi.  Es la `F(a, ...)` de C. */
        if (p->is_raw_variadic) continue;

        const ParamAbi abi = param_abi(*p);
        const ir::IrValueId vid = fn.new_value(abi.type, "%" + p->name);
        fn.values[vid].is_param = true;
        apply_type_memory(fn, vid, abi.mem);
        fn.params.push_back(vid);
        bindings.emplace_back(p->name, vid);
        out.push_back({p.get(), vid, abi.type});
    }

    /* Un variadico EMPAQUETADO (`T... xs`) llega como la direccion del array
     * que monto quien llama, y detras un parametro mas que no se escribio:
     * cuantos hay.  Es lo que `vacount()` lee. */
    if (!params.empty() && params.back()->is_variadic &&
        !params.back()->is_raw_variadic) {
        const ir::IrValueId vcnt = fn.new_value(ir::IrType::I64, "%__vacount");
        fn.values[vcnt].is_param = true;
        fn.params.push_back(vcnt);
        bindings.emplace_back("__vacount", vcnt);
        out.push_back({nullptr, vcnt, ir::IrType::I64});
    }
    return out;
}

/**
 * @copydoc vx::Lowering::pack_variadic_args
 */
void Lowering::pack_variadic_args(std::vector<ir::IrValueId> &arg_ids,
                                  size_t fixed, ir::IrType elem_ty,
                                  uint32_t line) {
    const size_t vcount = arg_ids.size() - fixed;
    const uint64_t esz = ir::type_access_bytes(elem_ty);

    ir::IrValueId v_arr;
    if (vcount > 0) {
        /* El array vive en la pila del ANFITRION: quien lo recibe lo lee por su
         * direccion, y esa direccion tiene que ser de la misma memoria en los
         * tres modos. */
        v_arr = stack_alloc_buf(vcount * esz, line, /*host_memory=*/true);
        for (size_t i = 0; i < vcount; ++i) {
            ir::IrValueId slot = v_arr;
            if (i != 0)
                slot = emit_ptr_add(
                    v_arr, emit_const(ir::IrType::I64, i * esz, line), line);
            emit_store_typed(slot, arg_ids[fixed + i], elem_ty, line);
        }
    } else {
        v_arr = emit_const(ir::IrType::PTR, 0, line); // ninguno: array vacio
    }

    std::vector<ir::IrValueId> packed(arg_ids.begin(), arg_ids.begin() + fixed);
    packed.push_back(v_arr);
    packed.push_back(emit_const(ir::IrType::I64, vcount, line));
    arg_ids = std::move(packed);
}

/**
 * @brief Si los metodos de una clase se despachan por tabla.
 *
 * Tres motivos, y el tercero es el que obliga a mirar el programa entero: que
 * ALGUIEN LA EXTIENDA.  Una clase sin super ni interfaces puede necesitar tabla
 * igualmente, porque `Base b = new Derivada()` tiene que ejecutar el metodo de
 * la derivada y eso solo se sabe viendo quien hereda de quien.
 *
 * Ese tercer motivo se responde con un conjunto que se construye una sola vez.
 * Antes cada consulta recorria TODAS las clases del programa, y las consultas
 * salen dentro de bucles sobre clases y sobre sus campos.
 *
 * @param class_name Nombre de la clase.
 * @return @c true si necesita tabla de metodos.
 */
bool Lowering::class_has_vtable(const std::string &class_name) const {
    const auto &layouts = tc_.class_layouts();
    const auto it = layouts.find(class_name);
    if (it == layouts.end()) return false;
    const ClassLayout &lay = it->second;
    if (!lay.super_name.empty() || !lay.interface_names.empty()) return true;

    /* Una clase final no la extiende nadie, asi que la tercera pregunta ya
     * tiene respuesta y no hay que mirar el programa.  El atajo se apoya en que
     * el comprobador de tipos RECHAZA extender una final: sin ese rechazo esto
     * seria un fallo silencioso -- llamada directa donde hace falta tabla, y el
     * metodo de la derivada sin ejecutarse --, y por eso las dos cosas
     * entraron a la vez. */
    if (lay.is_final) return false;

    if (!extended_classes_built_) {
        for (const auto &kv : layouts)
            if (!kv.second.super_name.empty())
                extended_classes_.insert(kv.second.super_name);
        extended_classes_built_ = true;
    }
    return extended_classes_.count(class_name) != 0;
}

/**
 * @copydoc vx::Lowering::native_iface_slot_count
 */
uint32_t Lowering::native_iface_slot_count() const {
    if (iface_slot_total_ != UINT32_MAX) return iface_slot_total_;

    /* Se recorren las interfaces por NOMBRE, en orden, no en el que las
     * devuelva la tabla: el reparto tiene que salir igual en dos compilaciones
     * del mismo programa o el binario cambia sin que el fuente cambie, y con
     * el cambia su huella en la cache. */
    std::vector<const ClassLayout *> ifaces;
    for (const auto &kv : tc_.class_layouts())
        if (kv.second.is_interface) ifaces.push_back(&kv.second);
    std::sort(ifaces.begin(), ifaces.end(),
              [](const ClassLayout *a, const ClassLayout *b) {
                  return a->name < b->name;
              });

    uint32_t next = 0;
    for (const ClassLayout *lay : ifaces) {
        iface_slot_base_[lay->name] = next;
        /* El tramo mide lo que la interfaz declara.  Se cuenta por el mayor
         * indice y no por cuantos metodos hay, porque los constructores no
         * entran en la numeracion y dejarian huecos. */
        uint32_t hi = 0;
        for (const ClassMethodInfo &m : lay->methods) {
            if (m.is_constructor) continue;
            if (m.vtable_index + 1u > hi) hi = m.vtable_index + 1u;
        }
        next += hi;
    }
    iface_slot_total_ = next;
    return iface_slot_total_;
}

/**
 * @copydoc vx::Lowering::native_iface_slot
 */
uint32_t Lowering::native_iface_slot(const std::string &iface,
                                     uint32_t midx) const {
    native_iface_slot_count(); // asegura el reparto
    const auto it = iface_slot_base_.find(iface);
    return (it == iface_slot_base_.end() ? 0u : it->second) + midx;
}
} // namespace vx
