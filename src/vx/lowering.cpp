/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 *
 * Software libre bajo GPLv2.  La salida del compilador (programas
 * escritos en Vesta) NO queda sujeta a la GPL (excepcion de runtime).
 *
 * Descargo: Autor no responsable por modificaciones.
 */

/**
 * @file lowering.cpp
 * @brief Implementacion del pase AST -> ir::IrModule de Vesta.
 */

#include "vx/lowering.h"
#include "util/thread_slot.h" // el estado por hilo NO va en thread_local
#include "lowering/lowering_internal.h" // helpers que comparten las unidades del lowering
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType

#include <algorithm>

#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>

/* El tamano en bytes de un tipo lo contesta el vocabulario unico
 * (ir/ir_type_info.h) -- aqui vivia una copia mas de esa tabla, y su comentario
 * explicaba por que: "mantener una copia es preferible a exponer el helper del
 * emisor para no acoplar el frontend al detalle de codegen".  El razonamiento
 * era bueno cuando la unica fuente era el emisor; el vocabulario no es codegen,
 * es el idioma del propio IR, asi que la razon de la copia ya no existe.
 *
 * El eje es el de ACCESO, que es lo que esta copia contestaba (un handle mide
 * sus 4 bytes de dato). */

namespace vx {
// =====================================================================
//  Mini-ensamblador de bloques `asm` ( AOT 16/32-bit).
//
//  Keystone (KS_OPT_SYNTAX_NASM) ensambla instrucciones + labels intra-
//  bloque + `db`, PERO no soporta `$`/`$$`/`times`.  Para permitir mezclar
//  codigo y datos crudos en UN solo bloque `asm` (como en NASM), partimos
//  el cuerpo por lineas: las INSTRUCCIONES se acumulan y se mandan a
//  Keystone (un flush por cada directiva de datos, para preservar el orden
//  y resolver labels dentro del run); las directivas de DATOS (db/dw/dd/dq/
//  times) las evaluamos nosotros con $ = offset actual del bloque y $$ = 0.
//
//  Limitacion: un label definido antes de una directiva de datos NO es
//  visible para instrucciones que vengan DESPUES (Keystone resuelve labels
//  dentro de un solo run).  Para boot sectors (codigo contiguo + padding +
//  firma al final) esto no es un problema.
// =====================================================================

/**
 * @brief Recorre un sub-arbol AST acumulando los nombres de variables
 *        que aparecen como destino de AssignExpr o operandos de ++/--.
 *
 * Lo necesita el lower_while() para construir los PHI nodes del bloque
 * header al estilo Braun.  No incluye las variables declaradas dentro
 * del propio sub-arbol (esas son locales al loop y no necesitan PHI);
 * el filtrado real se hace en el caller, que descarta cualquier nombre
 * que no exista en el scope justo antes del loop.
 *
 * @param n   Nodo a inspeccionar (puede ser nullptr).
 * @param out Set destino al que se añaden los nombres.
 */
void collect_assigned_vars(const ast::Node *n, std::set<std::string> &out) {
    if (!n) return;
    switch (n->kind) {
    case ast::NodeKind::AssignExpr: {
        auto *a = static_cast<const ast::AssignExpr *>(n);
        if (a->target && a->target->kind == ast::NodeKind::IdentExpr) {
            out.insert(
                static_cast<const ast::IdentExpr *>(a->target.get())->name);
        }
        collect_assigned_vars(a->value.get(), out);
        return;
    }
    case ast::NodeKind::UnaryExpr: {
        auto *u = static_cast<const ast::UnaryExpr *>(n);
        const bool mutates =
            (u->op == ast::UnOp::PreInc || u->op == ast::UnOp::PostInc ||
             u->op == ast::UnOp::PreDec || u->op == ast::UnOp::PostDec);
        if (mutates && u->operand &&
            u->operand->kind == ast::NodeKind::IdentExpr) {
            out.insert(
                static_cast<const ast::IdentExpr *>(u->operand.get())->name);
        }
        collect_assigned_vars(u->operand.get(), out);
        return;
    }
    case ast::NodeKind::BinaryExpr: {
        auto *b = static_cast<const ast::BinaryExpr *>(n);
        collect_assigned_vars(b->lhs.get(), out);
        collect_assigned_vars(b->rhs.get(), out);
        return;
    }
    case ast::NodeKind::CallExpr: {
        auto *c = static_cast<const ast::CallExpr *>(n);
        collect_assigned_vars(c->callee.get(), out);
        for (auto &a : c->args)
            collect_assigned_vars(a.get(), out);
        return;
    }
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<const ast::BlockStmt *>(n);
        for (auto &s : b->body)
            collect_assigned_vars(s.get(), out);
        return;
    }
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<const ast::ExprStmt *>(n);
        collect_assigned_vars(es->expr.get(), out);
        return;
    }
    case ast::NodeKind::IfStmt: {
        auto *is_ = static_cast<const ast::IfStmt *>(n);
        collect_assigned_vars(is_->cond.get(), out);
        collect_assigned_vars(is_->then_branch.get(), out);
        collect_assigned_vars(is_->else_branch.get(), out);
        return;
    }
    case ast::NodeKind::WhileStmt: {
        auto *w = static_cast<const ast::WhileStmt *>(n);
        collect_assigned_vars(w->cond.get(), out);
        collect_assigned_vars(w->body.get(), out);
        return;
    }
    case ast::NodeKind::DoWhileStmt: {
        auto *d = static_cast<const ast::DoWhileStmt *>(n);
        collect_assigned_vars(d->body.get(), out);
        collect_assigned_vars(d->cond.get(), out);
        return;
    }
    case ast::NodeKind::ForStmt: {
        auto *f = static_cast<const ast::ForStmt *>(n);
        collect_assigned_vars(f->init.get(), out);
        collect_assigned_vars(f->cond.get(), out);
        collect_assigned_vars(f->step.get(), out);
        collect_assigned_vars(f->body.get(), out);
        return;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *r = static_cast<const ast::ReturnStmt *>(n);
        collect_assigned_vars(r->value.get(), out);
        return;
    }
    case ast::NodeKind::TryStmt: {
        auto *t = static_cast<const ast::TryStmt *>(n);
        collect_assigned_vars(t->body.get(), out);
        for (auto &cc : t->catches) {
            collect_assigned_vars(cc.body.get(), out);
        }
        collect_assigned_vars(t->finally_body.get(), out);
        return;
    }
    case ast::NodeKind::SynchronizedStmt: {
        auto *ss = static_cast<const ast::SynchronizedStmt *>(n);
        collect_assigned_vars(ss->target.get(), out);
        collect_assigned_vars(ss->body.get(), out);
        return;
    }
    case ast::NodeKind::ThrowStmt: {
        auto *ts = static_cast<const ast::ThrowStmt *>(n);
        collect_assigned_vars(ts->value.get(), out);
        return;
    }
    case ast::NodeKind::MatchExpr: {
        auto *me = static_cast<const ast::MatchExpr *>(n);
        collect_assigned_vars(me->scrutinee.get(), out);
        for (auto &arm : me->arms) {
            collect_assigned_vars(arm.body.get(), out);
        }
        return;
    }
    case ast::NodeKind::SpawnExpr: {
        auto *se = static_cast<const ast::SpawnExpr *>(n);
        collect_assigned_vars(se->body.get(), out);
        return;
    }
    case ast::NodeKind::RSpawnExpr: {
        auto *re = static_cast<const ast::RSpawnExpr *>(n);
        collect_assigned_vars(re->node_idx.get(), out);
        collect_assigned_vars(re->body.get(), out);
        return;
    }
    /* LabelStmt es solo un marker; el stmt siguiente vive en el
     * BlockStmt enclosing y se procesa por iteracion normal. */
    case ast::NodeKind::VarDeclStmt: {
        auto *v = static_cast<const ast::VarDeclStmt *>(n);
        // VarDeclStmt introduce una variable nueva: NO entra en el
        // set como mutacion (es definicion).  Pero su initializer
        // puede contener asignaciones a variables externas.
        collect_assigned_vars(v->init.get(), out);
        return;
    }
    default: return;
    }
}

// ---------------------------------------------------------------------
// Constructor.
// ---------------------------------------------------------------------

Lowering::Lowering(ast::ModuleNode &mod, const TypeChecker &tc,
                   Diagnostics &diags)
    : mod_(mod), tc_(tc), diags_(diags) {
    // Reservar capacidad razonable para el scope chain.  Programas
    // tipicos no suelen pasar de 5 scopes anidados.
    scopes_.reserve(8);
}

// ---------------------------------------------------------------------
// Helpers de tipo.
// ---------------------------------------------------------------------

// Computa el intervalo DFS [lo,hi] de cada clase sobre el bosque de herencia
// (super_name).  El preorden numera lo; hi = max lo del subarbol.  Asi
// is-a(A,B) <=> B.lo <= A.lo <= B.hi (A es B o un descendiente de B).  Orden de
// hijos deterministico (alfabetico) para estabilidad cross-build.  Defensa
// contra ciclos via marca de visitados (el type checker ya rechaza ciclos de
// herencia, pero el DFS no debe colgarse si reaparece uno).

// Forward-decl del chequeo de lowereabilidad de macros (definido mas abajo) +
// definicion del contexto force-lower, para que el pre-pase de run() los use.
std::string macro_body_unsupported_reason(const TypeChecker &tc,
                                          const ast::Stmt *s);

/* El estado por hilo del bajado de macros va en las ranuras propias del
 * proyecto (util/thread_slot.h) y no en `thread_local`.
 *
 * No es una preferencia: declararlas `extern thread_local` para que otra
 * unidad las alcanzara las hacia pasar por la capa emulada de este toolchain,
 * donde no se leia el nulo con el que nacen sino memoria sin sentido -- el
 * `if (puntero)` daba verdadero y se desreferenciaba --.  Reventaba al compilar
 * programas que ni siquiera tienen macros.  Esa cabecera ya existia y cuenta
 * esta misma historia: la via emulada les habia costado antes un cuelgue.
 *
 * La ranura es una global normal; lo que cambia por hilo es su CONTENIDO, asi
 * que no hay inicializador dinamico ni variable de guarda, que es de donde
 * venian los dos fallos. */
static util::ThreadSlot g_macro_force_lower_slot;
static util::ThreadSlot g_macro_visiting_slot;

std::unordered_set<std::string> *macro_force_lower() {
    return static_cast<std::unordered_set<std::string> *>(
        g_macro_force_lower_slot.get());
}
void set_macro_force_lower(std::unordered_set<std::string> *p) {
    g_macro_force_lower_slot.ensure();
    g_macro_force_lower_slot.set(p);
}
std::unordered_set<std::string> *macro_visiting() {
    return static_cast<std::unordered_set<std::string> *>(
        g_macro_visiting_slot.get());
}
void set_macro_visiting(std::unordered_set<std::string> *p) {
    g_macro_visiting_slot.ensure();
    g_macro_visiting_slot.set(p);
}

/* El buffer de retorno vive SIEMPRE en memoria del anfitrion, sea lo que sea
 * lo que se devuelva.  No es una preferencia: el pase que promueve reservas a
 * memoria del anfitrion cuando lo que sale de ellas acaba en una funcion
 * nativa mira SOLO el lado de quien llama, asi que podia mover el buffer de
 * sitio sin que el llamado se enterara -- y entonces uno escribia en una
 * memoria y el otro leia en la otra.  Los agregados ya estaban fijados aqui
 * por eso mismo; lo que quedaba suelto era devolver un lambda o un puntero
 * inteligente, y bastaba un `println` detras para que el pase disparara.
 *
 * Que sea siempre el mismo lado quita la pregunta de en medio: ya no hay dos
 * respuestas que puedan discrepar. */
Lowering::SretInfo Lowering::sret_info(const Type &ret) const {
    SretInfo info;
    const PrimitiveKind kind = ret.kind;
    const std::string &tname = ret.struct_name;

    // Enum de usuario: se modela como STRUCT cuyo struct_name esta en
    // enum_layouts_.  Es SRET (retbuf del tamano del layout).
    if (kind == PrimitiveKind::STRUCT && !tname.empty()) {
        const auto &elays = tc_.enum_layouts();
        auto it_e = elays.find(tname);
        if (it_e != elays.end()) {
            info.uses_buffer = true;
            info.host_buffer = true;
            info.bytes = static_cast<uint64_t>(it_e->second.size_bytes);
            return info;
        }
        // STRUCT por valor: MISMO motivo que el puntero inteligente -- el
        // buffer vive en el marco del llamado y muere al RET.  Era el unico
        // agregado sin buffer: devolvia el puntero a esa memoria muerta y
        // funcionaba solo si quien llamaba la copiaba antes de tocar la pila.
        // Un `@overlay struct` es un puntero de 8 bytes -> por registro.
        const auto &slays = tc_.struct_layouts();
        auto it_s = slays.find(tname);
        if (it_s != slays.end() && !it_s->second.is_overlay) {
            info.uses_buffer = true;
            info.host_buffer = true;
            // Redondeado a palabra: la copia va palabra a palabra
            // (`bytes / 8`), asi que un struct de 12 copiaria solo 8 y
            // perderia el ultimo campo.  Los dos lados usan ESTE redondeo,
            // asi que copiar la palabra de mas cae dentro del buffer.
            info.bytes =
                (static_cast<uint64_t>(it_s->second.size_bytes) + 7ULL) & ~7ULL;
        }
        return info;
    }
    if (kind == PrimitiveKind::OPTIONAL) {
        info.uses_buffer = true;
        info.host_buffer = true;
        info.bytes = static_cast<uint64_t>(optional_layout(ret).bytes);
        return info;
    }
    if (kind == PrimitiveKind::RESULT) {
        info.uses_buffer = true;
        info.host_buffer = true;
        info.bytes = static_cast<uint64_t>(tc_.result_layout(ret).bytes);
        return info;
    }
    // (gap O): devolver un lambda.  El buffer es su ranura: direccion de la
    // funcion en +0, del entorno en +8.
    if (kind == PrimitiveKind::FUNCTION) {
        info.uses_buffer = true;
        info.host_buffer = true;
        info.bytes = 16ULL;
        return info;
    }
    // Punteros inteligentes.  Sin buffer seria inseguro: la ranura vive en la
    // pila del llamado y muere al RET.  El tamano lo decide un solo sitio, y
    // no son 16 siempre -- un `shared<T>` son 8 --; quien llamaba reservaba
    // 16 a ciegas porque desde alli no se sabia cual de los dos era.
    if (kind == PrimitiveKind::UNIQUE_PTR ||
        kind == PrimitiveKind::SHARED_PTR) {
        info.uses_buffer = true;
        info.host_buffer = true;
        info.bytes = static_cast<uint64_t>(smart_ptr_slot_bytes(kind));
        return info;
    }
    // Vesta Embed (native_poo_): `string` es valor de 24 bytes {ptr,len,cap}
    // -> se devuelve por buffer, igual que un struct.  Solo en native; en
    // Full/JIT un `string` es un asa i64 que cabe en un registro.
    if (native_poo_ && kind == PrimitiveKind::STRING) {
        info.uses_buffer = true;
        info.host_buffer = true;
        info.bytes = 24ULL;
        return info;
    }
    return info;
}

Lowering::SretInfo Lowering::sret_info_for(const std::string &name) const {
    auto it = fn_sret_.find(name);
    return (it == fn_sret_.end()) ? SretInfo{} : it->second;
}

void Lowering::register_fn_ret_info(const std::string &name, const Type &ret,
                                    bool is_async) {
    PrimitiveKind kind = ret.kind;
    ir::IrType rt =
        (kind == PrimitiveKind::VOID || kind == PrimitiveKind::COUNT)
            ? ir::IrType::VOID
            : ir_type_from_primitive(kind);

    const SretInfo info = sret_info(ret);
    fn_sret_[name] = info;

    // Enum de usuario: se modela como STRUCT cuyo struct_name esta en
    // enum_layouts_.
    bool is_user_enum = false;
    if (kind == PrimitiveKind::STRUCT && !ret.struct_name.empty()) {
        const auto &elays = tc_.enum_layouts();
        is_user_enum = (elays.find(ret.struct_name) != elays.end());
    }
    if (kind == PrimitiveKind::FUNCTION) fn_returns_function_.insert(name);
    if (kind == PrimitiveKind::UNIQUE_PTR || kind == PrimitiveKind::SHARED_PTR)
        fn_returns_smartptr_.insert(name);
    if (native_poo_ && kind == PrimitiveKind::STRING)
        fn_returns_str_value_.insert(name);
    if (kind == PrimitiveKind::STRUCT && !is_user_enum && info.uses_buffer)
        fn_ret_struct_name_[name] = ret.struct_name;

    // Estas funciones tienen ret_type IR = VOID y un buffer oculto como
    // primer parametro.  Sin este ajuste, fn_return_types_ apuntaria a PTR
    // y quien llama crearia un destino SSA "huerfano" que el emisor
    // intentaria escribir desde la salida (que no existe).
    if (info.uses_buffer) rt = ir::IrType::VOID;
    // Item 9: @Async wrapper retorna i64 (Future handle), no T.  El tipo
    // logico T se preserva como Future<T> en el sig del type checker para
    // el `await fut`, pero el bytecode del wrapper devuelve i64 raw en R0.
    // Sin este ajuste, el lowering del call site marca dst con tipo T (e.g.
    // f64), emite un cast i64->f64 erroneo (FTOI cambia el valor), y await
    // opera sobre un handle corrupto.
    if (is_async) {
        rt = ir::IrType::I64;
        kind = PrimitiveKind::I64;
    }

    fn_return_types_[name] = rt;
    fn_ret_kind_[name] = kind;
    // El nombre del enum devuelto: lo consultan otros pasos del bajado.  El
    // tamano del buffer ya no sale de aqui, sino de `fn_sret_`.
    if (is_user_enum) fn_ret_enum_name_[name] = ret.struct_name;
}

// ---------------------------------------------------------------------
// Lowering de una funcion.
// ---------------------------------------------------------------------

// Bug D fix: propagar is_gc_object a traves de todos los PHI nodes hasta
// punto fijo.  Cualquier IrValue cuya origen sea un host_ptr GC-managed
// (clase) debe heredar el flag para que save_live_regs del IR emitter
// convierta a gchandle pre-CALL (estable a evacuacion del GC) en lugar
// de pushar host_ptr crudo.  Sin esta propagacion, los PHIs de
// loops/if-merges con NULL inicial + valor real en back-edge perdian el
// flag, causando segfaults tras cualquier CALL (e.g. str_make) que
// disparara GC con head/tail vivos en regs.
void Lowering::propagate_is_gc_object_through_phis(ir::IrFunction &fn) {
    bool gc_changed = true;
    while (gc_changed) {
        gc_changed = false;
        for (auto &blk : fn.blocks) {
            for (auto &ins : blk.instrs) {
                if (ins.op != ir::IrOp::PHI) continue;
                if (ins.dst == ir::IR_NO_VALUE) continue;
                if (static_cast<size_t>(ins.dst) >= fn.values.size()) continue;
                if (fn.values[ins.dst].is_gc_object) continue;
                for (const auto &arg : ins.phi_args) {
                    if (static_cast<size_t>(arg.value) < fn.values.size() &&
                        fn.values[arg.value].is_gc_object) {
                        fn.values[ins.dst].is_gc_object = true;
                        gc_changed = true;
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Statements.
// ---------------------------------------------------------------------

void Lowering::emit_zero_fill(ir::IrValueId addr, uint64_t size_bytes,
                              uint32_t line) {
    // Emite STORE 0 en trozos decrecientes (8/4/2/1) sin desbordar el rango.
    auto store_zero = [&](ir::IrType ty, uint64_t o) {
        ir::IrValueId v_addr = addr;
        if (o > 0) {
            ir::IrValueId v_off = emit_const(ir::IrType::I64, o, line);
            v_addr = fn_->new_value(ir::IrType::PTR);
            // Heredar la naturaleza host/VM de la base (AOT native_poo aloca el
            // struct en la pila NATIVA -> el STORE debe ir a host, no a
            // vm_mem).
            fn_->values[v_addr].is_host_ptr = fn_->values[addr].is_host_ptr;
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_addr;
            ad.operands = {addr, v_off};
            ad.source_line = line;
            emit(current_block_, std::move(ad));
        }
        ir::IrValueId v_zero = emit_const(ty, 0, line);
        emit_store_typed(v_addr, v_zero, ty, line);
    };
    /* A partir de cierto tamano se EMITE EL HECHO (`memset`) en vez de
     * desplegarlo.  Desplegar destruye la semantica "esta region se pone a
     * cero" y ningun nivel inferior puede reconstruirla: medido, `i32[8192]
     * arr;` -- una DECLARACION -- generaba 16397 instrucciones, 86 KB de
     * codigo y 1,7 s de compilacion, con un solo bloque basico de 16405
     * instrucciones que hacia estallar el scheduler (O(n^2) por bloque).
     * Crecia lineal (~2n+13) SIN umbral, a cualquier tamano.
     *
     * Por debajo del umbral se siguen emitiendo stores: para unos pocos bytes
     * "store 0" ES la forma optima y no se pierde nada -- ningun backend
     * tendria algo mejor que hacer con la informacion.  El umbral es de FORMA,
     * no de politica: quien decide COMO rellenar (bucle, `rep stosb`, SIMD, o
     * el `memset` que el programa haya puesto en su lugar) es el backend. */
    static const uint64_t kInlineZeroMax = 64; // bytes desplegados en linea.
    if (size_bytes > kInlineZeroMax) {
        ir::IrValueId v_val = emit_const(ir::IrType::I64, 0, line);
        ir::IrValueId v_len = emit_const(ir::IrType::I64, size_bytes, line);
        ir::IrInstr ms{};
        ms.op = ir::IrOp::MEMSET;
        ms.type = ir::IrType::VOID;
        ms.dst = ir::IR_NO_VALUE;
        ms.operands = {addr, v_val, v_len};
        ms.source_line = line;
        emit(current_block_, std::move(ms));
        return;
    }

    uint64_t off = 0;
    while (size_bytes - off >= 8) {
        store_zero(ir::IrType::I64, off);
        off += 8;
    }
    if (size_bytes - off >= 4) {
        store_zero(ir::IrType::I32, off);
        off += 4;
    }
    if (size_bytes - off >= 2) {
        store_zero(ir::IrType::I16, off);
        off += 2;
    }
    if (size_bytes - off >= 1) {
        store_zero(ir::IrType::I8, off);
        off += 1;
    }
}

// =========================================================================
//  Transcodificacion de literales en tiempo de compilacion
// =========================================================================

// =========================================================================
//  Instrumentacion (vx_trace:enter / vx_trace:exit)
// =========================================================================
//
// Como el lowering emite CALLN a un nombre @c "vx_trace:enter" /
// @c "vx_trace:exit", todos los backends (bytecode VM, JIT, port C,
// futuros) heredan la instrumentacion automaticamente.  Cada backend
// resuelve el simbolo a su forma:
//   - bytecode VM: CALLN se resuelve via stdlib/native/runtime/vx_trace.dll
//   - JIT: idem (mismo CALLN dispatch)
//   - port C: emit_native_call lo bridgea a fprintf stderr (default)
//             o el usuario provee su propia implementacion.

// Forward decls de helpers definidos mas abajo en el TU.  Necesarias
// porque lower_try y try_lower_builtin_call los usan.

/// usado por lower_class_methods para emitir el CALLVIRT a
/// destructores de fields destructibles del contenedor.
// ---------------------------------------------------------------------
// try / catch / throw.
//
// Estrategia: usamos las instrucciones bytecode existentes
// tryenter / tryleave / throw.  El IR no tiene un nodo dedicado para
// exception frames; emitimos RAW_ASM con substitucion {dst}/{srcN}
// para colocar el handler PC y el ClassInfo* en registros.
//
// Layout de bloques (1 catch, sin finally):
//   current      -> RAW_ASM: findclass exc + tryenter handler, type
//                  -> br body
//   body         -> lower(try body)
//                  -> RAW_ASM: tryleave + jmp merge
//   handler      -> bind r0 a var (si la hay) + lower(catch body)
//                  -> br merge
//   merge        -> continuacion
//
// Multi-catch / finally: pendientes (deferidos en MVP).
//
// El handler PC se obtiene como @Absolute("code.<fn>_<handler.name>")
// donde <handler.name> incluye el sufijo numerico que new_block añade.
// Asi el linker resuelve la referencia sin necesitar metadata extra.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// foreach: for (T x : col) body  -- desazucarado a counted loop.
//
// Patron sintetizado para `for (T x : arr) body` con arr: T[N]:
//   {
//     i32 __idx = 0;
//     while (__idx < N) {
//       T x = arr[__idx];
//       body
//       __idx = __idx + 1;
//     }
//   }
//
// Para requerimos N conocido en compile time (T[N]).  Para
// T[] (decay-to-pointer) sin tamano se necesita un parametro de
// longitud explicito o un objeto Array<T> managed (deferido).
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// emit_cleanups_all: emite todos los cleanups activos en orden inverso
// (mas reciente primero).  No modifica el stack: el caller (e.g.,
// lower_synchronized) hace su pop por flujo normal.
// ---------------------------------------------------------------------
void Lowering::emit_cleanups_all() {
    emit_cleanups_range(0, cleanup_stack_.size());
}

// ---------------------------------------------------------------------
// synchronized (obj) { body }   (cierre completo con cleanup)
//
// Lowering con exception safety + return safety:
//   1. Bajar target -> ptr -> gchandle -> monenter (todo en 1 RAW_ASM).
//   2. Emitir tryenter catch-all con handler que hace monexit + rethrow.
//   3. Push CleanupAction(tryleave + monexit) al cleanup_stack_.
//   4. Bajar el body.  Si hace `return`, lower_return correra todos los
//      cleanups del stack (incluyendo el nuestro) antes del RET.
//   5. Pop CleanupAction.
//   6. Si el body NO termino: emitir tryleave + monexit (cleanup normal).
//   7. Bloque handler (alcanzable solo via excepcion del body): emitir
//      monexit + rethrow.
//
// Resultado: el monitor se libera SIEMPRE, sea por:
//   - flujo normal: paso 6.
//   - return temprano: emit_cleanups_all() en lower_return.
//   - throw: el handler del paso 7 lo libera y re-lanza.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// spawn { body } -- arranca proceso hijo en scheduler actual.
//
// Estrategia:
//   1. generate_spawn_helper compila el body como funcion sintetica
//      __spawn_<N> con return type VOID + body original + hlt al final
//      (NO ret: un proceso hijo no retorna a un caller que no existe).
//   2. lower_spawn_expr emite RAW_ASM con:
//        mov {dst_pc_holder}, @Absolute("code.__spawn_<N>")
//        spawn {dst_pc_holder}
//        mov {dst}, r0     ; r0 contiene el PID encoded del hijo
//   3. SSA value devuelto = PID encoded como i64.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// closures: generate_lambda_helper + lower_lambda_expr.
//
// Diseno:
//   - Cada @c LambdaExpr produce una @c IrFunction sintetica
//     @c __lambda_<N>(p0, p1, ...) cuyos params son los declarados
//     por la lambda.  Los captures se pasan via R14 (env_ptr) y se
//     leen en el prologue del helper desde @c [r14 + 8*i] a SSA
//     values con el nombre de la captura.  Asi el body trata las
//     capturas como si fueran locales, sin distinguirlas de los
//     params (el type checker ya las acumulo en e->captures).
//
//   - El call site emite:
//       1. ALLOCA @c 8*N bytes para el env block (si N > 0).
//       2. STORE de cada captura en @c [env + 8*i].
//       3. ALLOCA 16 bytes para el "function value":
//            `[+0 fn_addr][+8 env_addr]`.
//       4. RAW_ASM @c mov ..., @c \@Absolute("code.__lambda_<N>")
//          + STORE en @c [fv+0].
//       5. STORE @c env_addr en @c [fv+8] (o 0 si sin captures).
//
//   - Al llamar a la closure (vease @c lower_call cuando callee es
//     IdentExpr de tipo FUNCTION): se cargan @c fn_addr y @c env_addr
//     del slot, y se emite IrOp::CALLCLOSURE con func_ptr=fn_addr y
//     operands=[env_addr, args...].  El emisor IR coloca env en R14,
//     args en R1..R12 via parallel-move y emite @c callvmr.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// ADTs: lower_enum_constructor + lower_match_expr.
//
// Layout del slot del enum (mismo para todas las variantes):
//   [+0  i64 tag]
//   [+8  i64 payload[0]]
//   [+16 i64 payload[1]] ...
// Tamano total: 8 + 8 * max_payload_fields.  Cada payload se
// promociona a i64 para tener acceso uniforme por offset.  Cero
// alocaciones de heap; cero overhead GC; mismo modelo que
// Optional / Result.
// ---------------------------------------------------------------------

uint64_t Lowering::nested_sret_flat_size(const std::string &callee,
                                         bool *out_is_host) const {
    // Tamano del buffer SRET de BUFFER PLANO (value-type) que devuelve @p
    // callee, o 0 si no lo es.  El fix nested-SRET copia el retbuf del
    // productor a un slot fresco; la NATURALEZA de ese slot (via @p
    // out_is_host) debe coincidir con como el CALLEE lee su parametro:
    //   - ENUM/ADT: desde el modelo "agregados en memoria HOST" ([[proj_
    //     aggregates_host]], commit a0ffa68) el callee marca su param enum como
    //     is_host_ptr y lo lee via acceso HOST (`movh [t]`) -> fresh HOST
    //     (out_is_host=true).  Un slot VM daria segfault (el callee leeria host
    //     sobre una direccion VM).  ESTE sitio nested-SRET se le paso al fix
    //     original -> `emit(classify(x))` inline crasheaba (MOVH sobre pila
    //     VM).
    //   - Optional/Result: el callee los lee via acceso HOST (isPresent/unwrap/
    //     value/error con is_host_ptr) -> fresh HOST (out_is_host=true).  Un
    //     slot VM daria segfault (leeria host en una direccion VM).
    // function/smart-ptr se excluyen (ownership de env/ctrl: copiar el buffer
    // los duplicaria).
    /* Cuanto mide el buffer y donde vive ya se contesto al registrar la
     * funcion -- ver `sret_info` --, asi que aqui se consulta en vez de
     * volver a deducirlo: era otra copia mas, y con menos datos (tenia el
     * NOMBRE del llamado, no su tipo de retorno, asi que el tamano de un
     * `Optional` o un `Result` salia clavado y no daba para un payload que
     * no fuera una palabra).
     *
     * Lo que SI es propio de aqui: un lambda y un puntero inteligente quedan
     * fuera aunque usen buffer, porque copiarlo duplicaria la propiedad de lo
     * que hay dentro (el entorno, el bloque de control). */
    const SretInfo si = sret_info_for(callee);
    const bool copiable =
        si.uses_buffer && si.host_buffer; // agregados: enum, Optional, Result,
                                          // struct, cadena por valor
    if (out_is_host) *out_is_host = copiable;
    return copiable ? si.bytes : 0ULL;
}

void Lowering::emit_enum_copy(ir::IrValueId dst_addr, ir::IrValueId src_addr,
                              bool src_is_host, uint64_t size_bytes,
                              uint32_t line) {
    if (dst_addr == ir::IR_NO_VALUE || src_addr == ir::IR_NO_VALUE) return;
    const bool dst_is_host = fn_->values[dst_addr].is_host_ptr;
    const uint64_t qwords = (size_bytes + 7) / 8;
    for (uint64_t qi = 0; qi < qwords; ++qi) {
        const uint64_t off = qi * 8;
        const ir::IrValueId v_off =
            emit_const(ir::IrType::I64, static_cast<int64_t>(off), line);
        // src + off (hereda la naturaleza del origen para el LOAD).
        const ir::IrValueId v_src_at = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_src_at].is_host_ptr = src_is_host;
        {
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_src_at;
            ad.operands = {src_addr, v_off};
            ad.source_line = line;
            emit(current_block_, std::move(ad));
        }
        const ir::IrValueId v_word =
            emit_load_typed(v_src_at, ir::IrType::I64, line);
        // dst + off (naturaleza del slot destino, tipicamente VM ALLOCA).
        const ir::IrValueId v_dst_at = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_dst_at].is_host_ptr = dst_is_host;
        {
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_dst_at;
            ad.operands = {dst_addr, v_off};
            ad.source_line = line;
            emit(current_block_, std::move(ad));
        }
        emit_store_typed(v_dst_at, v_word, ir::IrType::I64, line);
    }
}

void Lowering::emit_match_arm_phis(
    const std::vector<std::unordered_map<std::string, ir::IrValueId>>
        &entry_scopes,
    const std::vector<
        std::vector<std::unordered_map<std::string, ir::IrValueId>>>
        &arm_scopes,
    const std::vector<ir::IrBlockId> &arm_preds,
    const std::vector<char> &arm_reaches, ir::IrBlockId merge_bb,
    uint32_t line) {
    // Base: partimos del scope de entry (variables no tocadas conservan su
    // valor).
    scopes_ = entry_scopes;
    const size_t depth = entry_scopes.size();
    for (size_t lvl = 0; lvl < depth; ++lvl) {
        for (auto &kv : entry_scopes[lvl]) {
            const std::string &name = kv.first;
            // Recolectar (val, pred) de cada arm que ALCANZA el merge.
            std::vector<std::pair<ir::IrValueId, ir::IrBlockId>> args;
            bool all_same = true;
            ir::IrValueId first = ir::IR_NO_VALUE;
            for (size_t i = 0; i < arm_scopes.size(); ++i) {
                if (!arm_reaches[i]) continue;
                if (lvl >= arm_scopes[i].size()) continue;
                auto it = arm_scopes[i][lvl].find(name);
                if (it == arm_scopes[i][lvl].end()) continue;
                args.push_back({it->second, arm_preds[i]});
                if (first == ir::IR_NO_VALUE)
                    first = it->second;
                else if (it->second != first)
                    all_same = false;
            }
            if (args.empty()) continue;
            if (all_same) {
                scopes_[lvl][name] = first; // coherente en todos los arms
                continue;
            }
            // PHI N-vias al inicio del merge (uno por arm que llega).
            const ir::IrType phi_ty = fn_->values[first].type;
            ir::IrValueId phi_v = fn_->new_value(phi_ty);
            ir::IrInstr phi{};
            phi.op = ir::IrOp::PHI;
            phi.type = phi_ty;
            phi.dst = phi_v;
            for (auto &a : args)
                phi.phi_args.push_back({a.first, a.second});
            phi.source_line = line;
            fn_->blocks[merge_bb].instrs.insert(
                fn_->blocks[merge_bb].instrs.begin(), std::move(phi));
            scopes_[lvl][name] = phi_v;
        }
    }
}

// ---------------------------------------------------------------------
// @Async sugar.  Transforma una FunctionDecl con flag
// is_async en DOS funciones IR:
//
//   1. Wrapper publico `<name>` con firma `i64 <name>()` que el caller
//      invoca.  Internamente:
//        a. future_alloc -> fut handle
//        b. spawn helper sintetica __async_<name>
//        c. msgsend(child_pid, fut handle)
//        d. return fut handle
//
//   2. Spawn helper `__async_<name>(void)` que ejecuta el body original
//      como hijo cooperativo:
//        a. msgrecv -> my_fut handle (set como async_fut_id_)
//        b. lower body original (cada return X intercepta a fulfill+hlt)
//        c. fallback al final: fulfill(my_fut, 0) + hlt
//
// El usuario escribe:
//   @Async i64 compute() { return 42; }
//   i32 main() { i64 r = await compute(); return r; }
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
//  AS: inline asm nativo -> IrOp::INLINE_ASM (marker host).
//
// Incremento 1 (aditivo): el cuerpo NASM viaja verbatim en func_name y
// los calificadores + efectos (memory/flags) en un bitfield en imm.  El
// marker no produce valor SSA ni consume operandos (las variables Vesta se
// enlazaran a registros via register() en el Incremento 2).
//
// Backends:
//   - port-C / JIT / AOT: materializan el asm en la CPU host.
//   - bytecode/interp: NO lo soporta.  El driver (compile_vx_source)
//     detecta INLINE_ASM cuando el target es bytecode y reporta un error
//     claro ANTES de emitir el .vel.
//
// Los clobbers de registros EXPLICITOS (vector) aun no se bajan al IR;
// los efectos memory/flags si (bits 4/5 de imm).  El Incremento 3
// (port-C) decidira el transporte de la lista de registros.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Expresiones.
// ---------------------------------------------------------------------

ir::IrValueId Lowering::lower_expr(ast::Expr *e) {
    if (!e) return ir::IR_NO_VALUE;
    /* Mientras se baja esta expresion, lo que se emita lleva SU columna.  Al
     * anidarse, la de dentro tapa a la de fuera y se restaura al salir, con lo
     * que cada instruccion acaba con la de la expresion mas ajustada que la
     * produjo.  Ahora es posible porque todo pasa por un solo sitio al
     * emitir. */
    struct ColumnaVigente {
        uint32_t *slot;
        uint32_t previa;
        uint32_t *slot_len;
        uint32_t previa_len;

        ~ColumnaVigente() {
            *slot = previa;
            *slot_len = previa_len;
        }
    } col_vigente{&pend_stmt_column_, pend_stmt_column_, &pend_stmt_len_,
                  pend_stmt_len_};
    if (e->loc.column > 0) {
        pend_stmt_column_ = e->loc.column;
        // La longitud va con su columna; si no se sabe, mejor ninguna que
        // la de la expresion de fuera, que recortaria otro trozo.
        pend_stmt_len_ = e->loc.length;
    }
    switch (e->kind) {
    case ast::NodeKind::IntLitExpr: {
        auto *ie = static_cast<ast::IntLitExpr *>(e);
        const ir::IrType t = ir_type_from_primitive(e->result_type.kind);
        return emit_const(t == ir::IrType::VOID ? ir::IrType::I64 : t,
                          ie->value, e->loc.line);
    }
    case ast::NodeKind::FloatLitExpr: {
        auto *fe = static_cast<ast::FloatLitExpr *>(e);
        ir::IrType t = ir_type_from_primitive(e->result_type.kind);
        if (t == ir::IrType::VOID) t = ir::IrType::F64;
        // Reinterpretamos los bits IEEE del literal como uint64 para alojarlos
        // en el campo imm de la instruccion CONST.  Para un literal cuyo tipo
        // es F32, hay que estrechar el double a float PRIMERO y tomar sus 32
        // bits: sin esto un `atomic<f32>.store(5.0)` guardaba los 32 bits bajos
        // del PATRON f64 (= 0).  Los literales F64 (el caso por defecto)
        // conservan los 64 bits del double.
        uint64_t bits;
        static_assert(sizeof(double) == sizeof(uint64_t),
                      "double debe ocupar 64 bits para reinterpret_cast");
        if (t == ir::IrType::F32) {
            const float f32v = static_cast<float>(fe->value);
            uint32_t b32;
            __builtin_memcpy(&b32, &f32v, sizeof(float));
            bits = b32; // bits IEEE-754 binary32 en la parte baja
        } else {
            __builtin_memcpy(&bits, &fe->value, sizeof(double));
        }
        return emit_const(t, bits, e->loc.line);
    }
    case ast::NodeKind::BoolLitExpr: {
        auto *be = static_cast<ast::BoolLitExpr *>(e);
        return emit_const(ir::IrType::BOOL, be->value ? 1 : 0, e->loc.line);
    }
    case ast::NodeKind::CharLitExpr: {
        auto *ce = static_cast<ast::CharLitExpr *>(e);
        return emit_const(ir::IrType::U8, ce->codepoint, e->loc.line);
    }
    case ast::NodeKind::StringLitExpr:
        return lower_string_lit(static_cast<ast::StringLitExpr *>(e));
    case ast::NodeKind::NullLitExpr:
        // Null se modela como el escalar 0 del tipo i64; el type
        // checker valida que solo se asigne a punteros / handles
        // (donde 0 es la representacion canonica de "ausente").
        return emit_const(ir::IrType::I64, 0, e->loc.line);
    case ast::NodeKind::IdentExpr:
        return lower_ident(static_cast<ast::IdentExpr *>(e));
    case ast::NodeKind::FieldAccessExpr:
        return lower_field_access(static_cast<ast::FieldAccessExpr *>(e));
    case ast::NodeKind::BinaryExpr:
        return lower_binary(static_cast<ast::BinaryExpr *>(e));
    case ast::NodeKind::UnaryExpr:
        return lower_unary(static_cast<ast::UnaryExpr *>(e));
    case ast::NodeKind::CallExpr:
        return lower_call(static_cast<ast::CallExpr *>(e));
    case ast::NodeKind::AssignExpr:
        return lower_assign(static_cast<ast::AssignExpr *>(e));
    case ast::NodeKind::TernaryExpr:
        return lower_ternary(static_cast<ast::TernaryExpr *>(e));
    case ast::NodeKind::TryExpr:
        return lower_try_expr(static_cast<ast::TryExpr *>(e));
    case ast::NodeKind::IndexExpr:
        return lower_index(static_cast<ast::IndexExpr *>(e));
    case ast::NodeKind::ThisExpr:
        return lower_this_expr(static_cast<ast::ThisExpr *>(e));
    case ast::NodeKind::NewExpr:
        return lower_new_expr(static_cast<ast::NewExpr *>(e));
    case ast::NodeKind::SuperCallExpr:
        return lower_super_call_expr(static_cast<ast::SuperCallExpr *>(e));
    case ast::NodeKind::SuperMethodCallExpr:
        return lower_super_method_call_expr(
            static_cast<ast::SuperMethodCallExpr *>(e));
    case ast::NodeKind::SpawnExpr:
        return lower_spawn_expr(static_cast<ast::SpawnExpr *>(e));
    case ast::NodeKind::RSpawnExpr:
        return lower_rspawn_expr(static_cast<ast::RSpawnExpr *>(e));
    case ast::NodeKind::LambdaExpr:
        return lower_lambda_expr(static_cast<ast::LambdaExpr *>(e));
    case ast::NodeKind::MatchExpr:
        return lower_match_expr(static_cast<ast::MatchExpr *>(e));
    case ast::NodeKind::CastExpr:
        return lower_cast_expr(static_cast<ast::CastExpr *>(e));
    default:
        unsupported(e->loc, "expresion no soportada por el lowering actual");
        return ir::IR_NO_VALUE;
    }
}

// ---------------------------------------------------------------------
// Helpers: tamano de tipo y aritmetica de punteros.
// ---------------------------------------------------------------------

ir::IrValueId
Lowering::lower_string_literal_to_string_object(ast::StringLitExpr *slit) {
    // Helper local: emite STRMAKE de un trozo literal y devuelve
    // el handle StringObject resultante.
    auto make_part_handle = [&](const std::string &part_text,
                                int line) -> ir::IrValueId {
        std::vector<uint8_t> pbytes(part_text.begin(), part_text.end());
        const uint64_t p_idx = out_mod_->intern_static_data(std::move(pbytes));
        const uint64_t p_len = (uint64_t)part_text.size();
        ir::IrValueId v_addr = emit_str_lit_addr(p_idx, line);
        ir::IrValueId v_len = emit_const(ir::IrType::I64, p_len, line);
        ir::IrValueId v_handle =
            emit_string_literal_repr(v_addr, v_len, -1, line);
        return v_handle;
    };

    // Fast path: string literal SIN interpolacion -> 1 sola STRMAKE.
    if (!slit->is_interpolated()) {
        return make_part_handle(slit->value, slit->loc.line);
    }

    // Path interpolado: construimos el StringObject final como
    // cadena de STRCATs sobre los parts literales y los exprs
    // interpolados.  Layout: parts[0] + exprs[0] + parts[1] + ...
    // + parts[N] (siempre N+1 parts para N exprs).
    //
    // Cada `${expr}` se baja a un StringObject handle.  Strings
    // pasan tal cual; tipos primitivos (int/uint/bool/char/ptr/gc)
    // se pasan por un helper nativo que escribe su representacion
    // ASCII en un buffer VM y luego construimos el StringObject
    // via STRMAKE desde ese buffer.
    const int line = slit->loc.line;

    // Helper: emite la secuencia ALLOCA + CALLN(stringify_to_vmbuf)
    // + STRMAKE para un valor primitivo.  El `native_fn` es el nombre
    // de la funcion en `stdlib/native/io/vesta_io` que toma
    // (proc_ptr, vm_addr, value) y devuelve la longitud escrita.
    // El buffer VM es ALLOCA de 32 bytes (suficiente para todos los
    // tipos: i64=20+signo, hex=18, "false"=5, char UTF-8=4).
    /* Esta secuencia ya existe como @c stringify_primitive_via_native, palabra
     * por palabra.  Era una COPIA, y una copia no es solo mas lineas: es un
     * segundo criterio.  Al declarar lo que hace la nativa se vio enseguida --
     * se declaro en una de las dos y la mitad de las llamadas siguieron
     * saliendo como opacas. */
    auto stringify_primitive = [&](ir::IrValueId v_val, const char *native_fn,
                                   int ln) -> ir::IrValueId {
        return stringify_primitive_via_native(v_val, native_fn, ln);
    };

    // BUG-3 fix: honrar el KIND del format spec `${expr:fmt}` al CONSTRUIR
    // string (return / var-decl), no solo en `print`.  Extrae el keyword de
    // kind (char/hex/bin/oct/dec/ptr/bool/gc) del formato ignorando la parte
    // de alineacion (`>N`/`<N`).  Devuelve "" si no hay kind explicito.
    auto fmt_kind_of = [](const std::string &fmt) -> std::string {
        size_t i = 0;
        while (i < fmt.size()) {
            while (i < fmt.size() && (fmt[i] == ' ' || fmt[i] == '\t'))
                ++i;
            if (i >= fmt.size()) break;
            if (fmt[i] == '<' || fmt[i] == '>') {
                // Segmento de alineacion: `<`/`>` + digitos + fill opcional.
                ++i;
                while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9')
                    ++i;
                if (i < fmt.size() && fmt[i] != ':') ++i; // fill char
            } else {
                size_t start = i;
                while (i < fmt.size() && fmt[i] != ':' && fmt[i] != ' ' &&
                       fmt[i] != '\t')
                    ++i;
                std::string kw = fmt.substr(start, i - start);
                if (kw == "char" || kw == "hex" || kw == "bin" || kw == "oct" ||
                    kw == "dec" || kw == "ptr" || kw == "bool" || kw == "gc")
                    return kw;
            }
            while (i < fmt.size() && (fmt[i] == ' ' || fmt[i] == '\t'))
                ++i;
            if (i < fmt.size() && fmt[i] == ':') ++i;
        }
        return std::string();
    };

    auto coerce_to_string_handle =
        [&](ast::Expr *ex, const std::string &fmt) -> ir::IrValueId {
        if (!ex) return ir::IR_NO_VALUE;
        if (ex->kind == ast::NodeKind::StringLitExpr) {
            auto *sl = static_cast<ast::StringLitExpr *>(ex);
            return lower_string_literal_to_string_object(sl);
        }
        ir::IrValueId v = lower_expr(ex);
        if (v == ir::IR_NO_VALUE) return v;
        const PrimitiveKind ek = ex->result_type.kind;
        const int ln = ex->loc.line;
        // Strings: pasan directamente.
        if (ek == PrimitiveKind::STRING) return v;
        // BUG-3: si el format spec fuerza un KIND concreto, enrutar al helper
        // nativo correspondiente en lugar del dispatch por tipo.  `char`
        // interpreta el valor entero como codepoint -> UTF-8; `hex`/`ptr`/
        // `bool` usan su helper; `bin`/`oct`/`gc`/`dec` no tienen helper de
        // construccion dedicado -> caen al dispatch por tipo (default).
        if (!fmt.empty()) {
            const std::string k = fmt_kind_of(fmt);
            if (k == "char" &&
                (ek == PrimitiveKind::I8 || ek == PrimitiveKind::I16 ||
                 ek == PrimitiveKind::I32 || ek == PrimitiveKind::I64 ||
                 ek == PrimitiveKind::U8 || ek == PrimitiveKind::U16 ||
                 ek == PrimitiveKind::U32 || ek == PrimitiveKind::U64 ||
                 ek == PrimitiveKind::CHAR)) {
                return stringify_primitive(v, "vio_char_to_vmbuf", ln);
            }
            if (k == "hex" &&
                (ek == PrimitiveKind::I8 || ek == PrimitiveKind::I16 ||
                 ek == PrimitiveKind::I32 || ek == PrimitiveKind::I64 ||
                 ek == PrimitiveKind::U8 || ek == PrimitiveKind::U16 ||
                 ek == PrimitiveKind::U32 || ek == PrimitiveKind::U64)) {
                return stringify_primitive(v, "vio_hex_to_vmbuf", ln);
            }
            if (k == "ptr" &&
                (ek == PrimitiveKind::PTR || ek == PrimitiveKind::ARRAY ||
                 ek == PrimitiveKind::I64 || ek == PrimitiveKind::U64)) {
                return stringify_primitive(v, "vio_ptr_to_vmbuf", ln);
            }
            if (k == "bool") {
                return stringify_primitive(v, "vio_bool_to_vmbuf", ln);
            }
        }
        // Stringify por tipo primitivo.  Cada categoria mapea a un
        // helper nativo en vesta_io.
        switch (ek) {
        case PrimitiveKind::I8:
        case PrimitiveKind::I16:
        case PrimitiveKind::I32:
        case PrimitiveKind::I64:
            return stringify_primitive(v, "vio_int_to_vmbuf", ln);
        case PrimitiveKind::U8:
        case PrimitiveKind::U16:
        case PrimitiveKind::U32:
        case PrimitiveKind::U64:
            return stringify_primitive(v, "vio_uint_to_vmbuf", ln);
        case PrimitiveKind::BOOL:
            return stringify_primitive(v, "vio_bool_to_vmbuf", ln);
        case PrimitiveKind::CHAR:
            return stringify_primitive(v, "vio_char_to_vmbuf", ln);
        case PrimitiveKind::PTR:
        case PrimitiveKind::ARRAY:
            return stringify_primitive(v, "vio_ptr_to_vmbuf", ln);
        case PrimitiveKind::F64: {
            // BugFix R7: BITCAST f64->i64 (preserva bits IEEE) y
            // delega a vio_float_to_vmbuf.
            ir::IrValueId v_bits =
                emit_ir_unop(ir::IrOp::BITCAST, v, ir::IrType::I64, ln);
            return stringify_primitive(v_bits, "vio_float_to_vmbuf", ln);
        }
        case PrimitiveKind::F32: {
            // BugFix R7: f32 -> f64 (re-encode) -> BITCAST i64.
            ir::IrValueId v_f64 = fn_->new_value(ir::IrType::F64);
            ir::IrInstr ext{};
            ext.op = ir::IrOp::F32TOF64;
            ext.type = ir::IrType::F64;
            ext.dst = v_f64;
            ext.operands = {v};
            ext.source_line = ln;
            emit(current_block_, std::move(ext));
            ir::IrValueId v_bits =
                emit_ir_unop(ir::IrOp::BITCAST, v_f64, ir::IrType::I64, ln);
            return stringify_primitive(v_bits, "vio_float_to_vmbuf", ln);
        }
        case PrimitiveKind::CLASS: {
            // BugFix R7: convert host_ptr -> GcHandle via gchandle
            // RAW_ASM y delegar a vio_gchandle_to_vmbuf.
            ir::IrValueId v_handle = emit_gc_handle_for_ptr(v, ln);
            return stringify_primitive(v_handle, "vio_gchandle_to_vmbuf", ln);
        }
        default: break;
        }
        error_at(ex->loc, "interpolacion `${expr}` en contexto string: tipo "
                          "no soportado todavia (struct/enum/optional/result). "
                          "Construye el mensaje con `print` o usa los builtins "
                          "de stringify explicito por ahora.");
        return ir::IR_NO_VALUE;
    };

    auto make_strcat = [&](ir::IrValueId a, ir::IrValueId b,
                           int ln) -> ir::IrValueId {
        return emit_strcat(a, b, static_cast<uint32_t>(ln));
    };

    const size_t ne = slit->interp_exprs.size();
    const size_t np = slit->interp_parts.size();
    ir::IrValueId acc = ir::IR_NO_VALUE;

    // Parte literal inicial (parts[0]).  La emitimos siempre (incluso
    // si es vacia) cuando ne > 0 porque necesitamos un acumulador
    // para los STRCAT subsiguientes; si es vacia, el primer STRCAT
    // se evita anclando el acc al primer expr handle.
    if (np > 0 && !slit->interp_parts[0].empty()) {
        acc = make_part_handle(slit->interp_parts[0], line);
    }
    for (size_t i = 0; i < ne; ++i) {
        const std::string fmt_i = (i < slit->interp_formats.size())
                                      ? slit->interp_formats[i]
                                      : std::string();
        ir::IrValueId expr_h =
            coerce_to_string_handle(slit->interp_exprs[i].get(), fmt_i);
        if (expr_h == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        if (acc == ir::IR_NO_VALUE) {
            acc = expr_h;
        } else {
            acc = make_strcat(acc, expr_h, line);
        }
        if (i + 1 < np && !slit->interp_parts[i + 1].empty()) {
            ir::IrValueId p_h =
                make_part_handle(slit->interp_parts[i + 1], line);
            acc = make_strcat(acc, p_h, line);
        }
    }
    if (acc == ir::IR_NO_VALUE) {
        // Edge case: todas las partes vacias y sin exprs.  Devolvemos
        // un StringObject vacio para mantener el contrato (handle
        // valido siempre).
        acc = make_part_handle(std::string(), line);
    }
    return acc;
}

ir::IrValueId Lowering::emit_topfn_value(const std::string &fn_name, int line) {
    // 1. ALLOCA 16 bytes para el slot del function value.
    ir::IrValueId fv_addr = stack_alloc_buf(16, line);
    // 2. fn_addr via LABEL_ADDR IR op (Sprint 3).
    ir::IrValueId fn_addr = emit_label_addr(fn_name, line);
    // 3. env_addr = 0 (sin captures; el callee no debe leer r14).
    ir::IrValueId env_addr = emit_const(ir::IrType::I64, 0, line);
    // 4. STORE fn_addr en [fv_addr+0].
    emit_store_typed(fv_addr, fn_addr, ir::IrType::I64, line);
    // 5. STORE env_addr en [fv_addr+8].
    {
        ir::IrValueId fv_plus_8 = fn_->new_value(ir::IrType::PTR);
        ir::IrValueId off8 = emit_const(ir::IrType::I64, 8, line);
        ir::IrInstr ad{};
        ad.op = ir::IrOp::ADD;
        ad.type = ir::IrType::I64;
        ad.dst = fv_plus_8;
        ad.operands = {fv_addr, off8};
        ad.source_line = line;
        emit(current_block_, std::move(ad));

        emit_store_typed(fv_plus_8, env_addr, ir::IrType::I64, line);
    }
    return fv_addr;
}

// ---------------------------------------------------------------------
// Field access: p.x  (lectura) y  p.x = v  (escritura).
//
// Modelo: las variables tipo struct se representan en scope como un
// IrValueId de tipo PTR que apunta a la zona de memoria reservada
// por ALLOCA (ver lower_var_decl, caso STRUCT).  Para acceder a un
// campo:
//   1. Bajar la base -> ptr al inicio del struct.
//   2. Sumar el offset del campo (consultado al StructLayout del
//      type checker) con un IR ADD.
//   3. Emitir LOAD (lectura) o STORE (escritura) sobre ese puntero.
//
// Si offset == 0 (primer campo del struct) la suma se omite y se
// reusa directamente el ptr base.  Esta optimizacion local evita
// ruido en el .vel para el caso comun de "campo cero".
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Lowering de asignaciones.
//
// En el modelo SSA-construction de Braun, una asignacion `x = expr` no
// produce ninguna instruccion explicita: simplemente actualiza el mapa
// "nombre -> IrValueId actual" en el scope donde @c x esta definida.
// El siguiente uso de @c x leera ese nuevo IrValueId via lookup().
//
// Las asignaciones compuestas (+=, -=, *=, ...) se traducen a un
// binop IR seguido del mismo update; reusan emit_binop_ir() para no
// duplicar la logica de seleccion de opcode aritmetico/bitwise.
// ---------------------------------------------------------------------

// Helper: emite un IrInstr binario y devuelve el IrValueId del resultado.
// Se usa tanto en lower_binary() como en compound assignments.
ir::IrValueId Lowering::emit_binop_ir(ast::BinOp op, ir::IrValueId lhs_val,
                                      ir::IrValueId rhs_val,
                                      PrimitiveKind common,
                                      const SourceLoc &loc) {
    const ir::IrType common_ir = ir_type_from_primitive(common);
    const bool is_float = is_floating(common);
    const bool is_unsign = is_integral(common) && !is_signed_integral(common);

    ir::IrOp ir_op = ir::IrOp::ADD;
    ir::IrType res_ir = common_ir;
    switch (op) {
    case ast::BinOp::Add:
        ir_op = is_float ? ir::IrOp::FADD : ir::IrOp::ADD;
        break;
    case ast::BinOp::Sub:
        ir_op = is_float ? ir::IrOp::FSUB : ir::IrOp::SUB;
        break;
    case ast::BinOp::Mul:
        ir_op = is_float ? ir::IrOp::FMUL : ir::IrOp::MUL;
        break;
    case ast::BinOp::Div:
        ir_op = is_float ? ir::IrOp::FDIV : ir::IrOp::DIV;
        break;
    case ast::BinOp::Mod: ir_op = ir::IrOp::MOD; break;
    case ast::BinOp::BitAnd: ir_op = ir::IrOp::AND; break;
    case ast::BinOp::BitOr: ir_op = ir::IrOp::OR; break;
    case ast::BinOp::BitXor: ir_op = ir::IrOp::XOR; break;
    case ast::BinOp::Shl: ir_op = ir::IrOp::SHL; break;
    case ast::BinOp::Shr:
        ir_op = is_unsign ? ir::IrOp::SHR : ir::IrOp::SAR;
        break;
    // Las comparaciones / logicos no suelen aparecer en compound
    // assignment (no existen ==, &&, etc.), pero las dejamos por
    // completitud; result_ir se cambia a BOOL.
    case ast::BinOp::Eq:
        ir_op = is_float ? ir::IrOp::FCMP_EQ : ir::IrOp::CMP_EQ;
        res_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Neq:
        ir_op = is_float ? ir::IrOp::FCMP_NE : ir::IrOp::CMP_NE;
        res_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Lt:
        ir_op = is_float ? ir::IrOp::FCMP_LT
                         : (is_unsign ? ir::IrOp::CMP_ULT : ir::IrOp::CMP_LT);
        res_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Le:
        ir_op = is_float ? ir::IrOp::FCMP_LE
                         : (is_unsign ? ir::IrOp::CMP_ULE : ir::IrOp::CMP_LE);
        res_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Gt:
        ir_op = is_float ? ir::IrOp::FCMP_GT
                         : (is_unsign ? ir::IrOp::CMP_UGT : ir::IrOp::CMP_GT);
        res_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::Ge:
        ir_op = is_float ? ir::IrOp::FCMP_GE
                         : (is_unsign ? ir::IrOp::CMP_UGE : ir::IrOp::CMP_GE);
        res_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::LogicalAnd:
        ir_op = ir::IrOp::AND;
        res_ir = ir::IrType::BOOL;
        break;
    case ast::BinOp::LogicalOr:
        ir_op = ir::IrOp::OR;
        res_ir = ir::IrType::BOOL;
        break;
    }

    const ir::IrValueId dst = fn_->new_value(res_ir);
    ir::IrInstr ins{};
    ins.op = ir_op;
    ins.type = res_ir;
    ins.dst = dst;
    ins.operands = {lhs_val, rhs_val};
    ins.source_line = loc.line;
    emit(current_block_, std::move(ins));
    return dst;
}

/**
 * @brief A.39 - emite el cuerpo de un `comptime for` desenrollado.
 *
 * Evalua lo/hi en compile-time (ya validados por type checker) y
 * por cada valor del index push scope con i=valor, lower body, pop.
 * Cero loop runtime: N copias del body emitidas en secuencia, con
 * el index sustituido como CONST en cada copia via
 * @c lowering_comptime_scopes_ (consultado por @c lower_ident).
 */

/**
 * @brief A.38 - lowering del operador ternario `cond ? then : else`.
 *
 * Estructura CFG identica a lower_if con PHI en el merge:
 *   current -> br_cond cond, then_bb, else_bb
 *   then_bb -> lower(then_expr) -> br merge_bb
 *   else_bb -> lower(else_expr) -> br merge_bb
 *   merge   -> %r = phi [then_val, then_end] [else_val, else_end]
 *
 * El tipo resultado se toma del then_expr (ya validado por el type
 * checker que tt y et son asignables entre si).  Si difieren, se
 * aplica @c cast_if_needed al else para igualar.  Si then es un side-
 * effecting expr y la cond es comptime-evaluable, una optimizacion
 * futura podria dead-branch-eliminate; por ahora siempre emite el if.
 */

/**
 * @brief P2: lowering del operador `?` postfix para Result<V,E>.
 *
 * Desugar:
 * @code
 *   let v = expr?;
 * @endcode
 * a:
 * @code
 *   let __tmp = expr;       // SSA value = PTR al slot Result (24 bytes)
 *   if (tag(__tmp) == 0) {  // Err branch
 *     // copy __tmp (24 bytes) al sret_retbuf del caller
 *     // RET void
 *   }
 *   // Ok branch: extraer V de [__tmp + 8]
 * @endcode
 *
 * Layout del slot Result<V,E> (24 bytes):
 *   +0  i32 tag (0=Err, 1=Ok)
 *   +8  V      (Ok payload)
 *   +16 E      (Err payload)
 */

ir::IrValueId Lowering::lower_overloaded_step(ast::UnaryExpr *e, bool is_inc,
                                              bool is_pre) {
    // `c++` sobre un tipo que sobrecarga la suma ES `c += 1`.  Se fabrica ese
    // compound y se le pide al type checker que lo resuelva igual que a uno
    // escrito a mano (`__iadd__` in-place, o desazucarado a `c = c + 1`).  El
    // AssignExpr nace AQUI, con el checker ya pasado, asi que hay que pedirselo
    // explicitamente -- pero la regla vive en un solo sitio.
    const Type &tt = e->operand->result_type;
    const int ln = e->loc.line;
    // Postfijo: el valor de la expresion es el ANTERIOR -> leerlo antes.  En
    // los tres lvalues el "valor" de un agregado es su direccion, asi que esto
    // devuelve la direccion del objeto, no una copia; para `c++` como
    // sentencia (el uso normal) da igual, y en expresion es lo mismo que hace
    // el resto del lowering con los agregados.
    ir::IrValueId prev = ir::IR_NO_VALUE;
    if (!is_pre) prev = lower_expr(e->operand.get());

    auto one = std::make_unique<ast::IntLitExpr>();
    one->value = 1;
    // El `1` es un ENTERO aunque `c` no lo sea: el dunder recibe un i64.  Si le
    // copiaramos el tipo de `c` (un STRUCT), el dispatch no casaria.
    one->result_type = Type{PrimitiveKind::I64};
    one->loc = e->loc;

    ast::AssignExpr asn;
    asn.op = is_inc ? ast::AssignOp::AddAssign : ast::AssignOp::SubAssign;
    asn.loc = e->loc;
    asn.result_type = tt;
    asn.target = std::move(e->operand);
    asn.value = std::move(one);
    Type res;
    const bool ok = tc_.prepare_overloaded_compound_assign(
        &asn, tt, Type{PrimitiveKind::I64}, res);
    ir::IrValueId new_val = ir::IR_NO_VALUE;
    if (ok) new_val = lower_assign(&asn);
    e->operand = std::move(asn.target); // devolver el operando al AST
    if (!ok) {
        error_at(e->loc, "lowering: '" + std::string(is_inc ? "++" : "--") +
                             "' sobre un tipo que no sobrecarga la suma");
        return ir::IR_NO_VALUE;
    }
    (void)ln;
    return is_pre ? new_val : prev;
}

// ---------------------------------------------------------------------
// Lowering de literales de string y builtins FFI.
// ---------------------------------------------------------------------

// Forward decls de los helpers definidos mas abajo en el TU.  Necesarias
// porque try_lower_builtin_call los invoca en la implementacion de
// forName/getClass

/* try_lower_builtin_call vive ahora en lowering/builtins.cpp: eran 7425 lineas
 * * en este fichero, un diecisiete por ciento del total, y tienen tema propio.
 */

// ---------------------------------------------------------------------
// POO: clases en Vesta. la integracion completa
// (registro en module init, NEWOBJ + CALLVIRT, GETFIELD/SETFIELD)
// se implementa por fases.  Cada metodo nuevo emite un error claro
// hasta que su implementacion concreta este lista.
// ---------------------------------------------------------------------

// -----------------------------------------------------------------
// NS.6-ext: baja los metodos de extension / impl como funciones libres
// <clave_layout>__<metodo>.  Reusa la emision de lower_struct_methods via un
// StructDecl temporal cuyo `name` es la clave del layout destino (mangled si
// es importado).  El cuerpo ya lo tipo el checker (con current_struct_/
// current_class_ correcto), asi que la emision es agnostica del kind salvo el
// binding de `this` (parametrizado por ext_this_is_class_).
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// Helpers de generacion de codigo .vel para POO dinamica.
// -----------------------------------------------------------------

/**
 * @brief Registra el nombre como bytes UTF-8 en static_data y devuelve
 *        el indice para construir @c @Absolute("code.s_<idx>").
 */
uint64_t intern_class_name(ir::IrModule &mod, const std::string &name) {
    std::vector<uint8_t> bytes(name.begin(), name.end());
    return mod.intern_static_data(std::move(bytes));
}

/**
 * @brief Interna un literal de cadena en los datos estaticos CON su nul.
 *
 * Aparte de @c intern_class_name a proposito: aquel guarda los bytes tal cual
 * porque sus clientes (nombres de clase, mensajes de panic) llevan siempre la
 * longitud al lado.  Un `string` que apunta aqui, en cambio, tiene que poder
 * dar un `cstr()` valido, y eso exige el nul en memoria -- no se puede anadir
 * despues sobre datos de solo lectura.
 *
 * El nul NO cuenta para la longitud: `.bytes()` sigue dando los bytes del
 * literal.  Solo esta para que la cadena valga en la frontera con C.
 *
 * @param mod Modulo donde viven los datos estaticos.
 * @param lit Bytes del literal (UTF-8, sin nul).
 * @return Indice del blob internado.
 */
static uint64_t intern_string_literal_nul(ir::IrModule &mod,
                                          const std::string &lit) {
    std::vector<uint8_t> bytes(lit.begin(), lit.end());
    bytes.push_back(0);
    return mod.intern_static_data(std::move(bytes));
}

/**
 * @brief fix11 - reserva un slot de 8 bytes en static_data para
 * cachear el `ClassInfo*` de una clase.  El slot inicia en 0 y se
 * llena en `__module_init` despues del `defclass`; cada llamada
 * subsiguiente a `__new_<Class>` lee del slot directamente sin
 * pasar por `findclass` (ahorra ~8 instrucciones VM por alloc +
 * elimina el string lookup en el runtime ClassRegistry).
 *
 * Los bytes contienen: 8 ceros (el slot del ClassInfo*) + bytes
 * unicos del nombre de la clase + sentinel 0xFF para evitar
 * deduplicacion con otras clases o con el nombre del simbolo
 * (que es el patron de `intern_class_name`).  El runtime accede
 * SOLO a los primeros 8 bytes del slot.
 */
uint64_t intern_class_cache_slot(ir::IrModule &mod, const std::string &name) {
    std::vector<uint8_t> bytes(8, 0); // 8 zeros (cache)
    bytes.push_back(0xFF); // sentinel: distingue de intern_class_name
    bytes.insert(bytes.end(), name.begin(), name.end()); // nombre para unicidad
    return mod.intern_static_data(std::move(bytes));
}

/**
 * @brief Emite la liberacion RAII del closure almacenado en un campo: libera
 *        el env (RAW_ALLOC, si tiene capturas) y el slot de 16 bytes (RAW_ALLOC
 *        owned por el campo).  Modelo sin GC; ver
 * doc/VMdoc/Vesta/ClosuresEnCampos.md.
 *
 * El campo guarda un PTR a un slot heap de 16 bytes {fn_addr@+0, env_ptr@+8}.
 * Secuencia:
 *   slot = [this + field_offset];       if (slot == 0) skip;   // campo sin
 * closure env  = [slot + 8];                  if (env  != 0) RAW_FREE(env);  //
 * captura RAW_FREE(slot);                                              //
 * siempre
 */

void Lowering::emit_free_unique_field(ir::IrValueId this_vid,
                                      uint32_t field_offset,
                                      const std::string &deleter,
                                      uint32_t line) {
    /* La ranura de un campo ES el campo.
     *
     * Antes el campo guardaba la DIRECCION de una ranura de ocho bytes
     * reservada aparte, asi que habia que cargarla para llegar al recurso: dos
     * saltos de memoria y dos reservas donde el recurso es uno.  Como una
     * ranura no es mas que un sitio donde cabe una palabra, y el campo lo es,
     * la de en medio sobraba: es la misma decision que toma C++, donde un
     * `unique_ptr` dentro de un objeto es un puntero dentro del objeto y nada
     * mas.
     *
     * El CAMPO vive en la memoria del CONTENEDOR -- de la maquina virtual si es
     * un struct en su pila, del anfitrion si es una clase -- y su direccion
     * hereda eso de @c this_vid.  Por eso NO se usa @c emit_field_addr, que la
     * forzaria a anfitriona y leeria de donde no es. */
    const bool container_host = fn_->values[this_vid].is_host_ptr;
    ir::IrValueId slot_addr = this_vid;
    if (field_offset != 0) {
        const ir::IrValueId off = emit_const(
            ir::IrType::I64, static_cast<int64_t>(field_offset), line);
        slot_addr = fn_->new_value(ir::IrType::PTR);
        fn_->values[slot_addr].is_host_ptr = container_host;
        ir::IrInstr ad{};
        ad.op = ir::IrOp::ADD;
        ad.type = ir::IrType::I64;
        ad.dst = slot_addr;
        ad.operands = {this_vid, off};
        ad.source_line = line;
        emit(current_block_, std::move(ad));
    }
    /* Y la ranura NO se suelta: no es una reserva propia, es un trozo del
     * objeto y se va con el. */
    emit_free_unique_slot(slot_addr, deleter, line, /*slot_is_owned=*/false);
}

void Lowering::emit_memberwise_copy(ir::IrValueId dst_addr,
                                    ir::IrValueId src_addr, uint64_t size_bytes,
                                    uint32_t line) {
    const bool dst_host = fn_->values[dst_addr].is_host_ptr;
    const bool src_host = fn_->values[src_addr].is_host_ptr;
    const uint64_t qwords = (size_bytes + 7) / 8;
    for (uint64_t qi = 0; qi < qwords; ++qi) {
        const ir::IrValueId v_off =
            emit_const(ir::IrType::I64, static_cast<int64_t>(qi * 8), line);
        const ir::IrValueId s_at = fn_->new_value(ir::IrType::PTR);
        fn_->values[s_at].is_host_ptr = src_host;
        {
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = s_at;
            ad.operands = {src_addr, v_off};
            ad.source_line = line;
            emit(current_block_, std::move(ad));
        }
        const ir::IrValueId w = emit_load_typed(s_at, ir::IrType::I64, line);
        const ir::IrValueId d_at = fn_->new_value(ir::IrType::PTR);
        fn_->values[d_at].is_host_ptr = dst_host;
        {
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = d_at;
            ad.operands = {dst_addr, v_off};
            ad.source_line = line;
            emit(current_block_, std::move(ad));
        }
        emit_store_typed(d_at, w, ir::IrType::I64, line);
    }
}

std::string Lowering::func_ref_label(const std::string &name,
                                     const std::string &mangled) {
    // Si el nombre es un extern, su direccion cruda no es invocable por
    // callvmr (es codigo nativo, no bytecode VM).  Generamos un thunk Vesta
    // `__cfnthunk_<fn>` que reenvia al CALLN; el cfn apunta a ese thunk.
    if (extern_lib_by_fn_name_.count(name)) {
        extern_cfn_thunks_.insert(name);
        return "__cfnthunk_" + name;
    }
    return mangled.empty() ? name : mangled;
}

namespace {

/**
 * @brief Instrucciones por tanda al partir `__module_init`.
 *
 * Ajustable con `VESTA_MODULE_INIT_CHUNK` para poder comparar; se lee una vez
 * porque consultar el entorno recorre su bloque entero.
 */
size_t module_init_chunk_budget() {
    static const size_t n = [] {
        const long v = util::flag_int(util::FlagId::ModuleInitChunk, 0);
        if (v > 0) return static_cast<size_t>(v);
        return static_cast<size_t>(2000);
    }();
    return n;
}

/// Por debajo de esto no se parte: una llamada por tanda no se paga por
/// ahorrar tan poco.
constexpr size_t kModuleInitSplitMin = 4000;

} // namespace

/* Deja de ser interna a este fichero: la llama generate_module_init_function,
 * que vive con el resto de la POO en lowering/oop.cpp. */
/**
 * @brief Parte @p init en tandas y la deja llamandolas en orden.
 *
 * POR QUE.  `__module_init` es, con diferencia, la funcion mas grande que
 * genera el compilador: en un modulo de 750 funciones se lleva 24.020 de las
 * 69.370 instrucciones del IR -- el 34,6% -- mientras que cada funcion de
 * usuario ronda las 83.  Eso hace dos danos a la vez.  Reparte mal: el bucle
 * de pases se reparte POR FUNCION, asi que un hilo se queda con esta y los
 * demas esperan (medido: el 79% del tiempo dentro del reparto era espera).  Y
 * cuesta de mas: el coste de compilar crece MAS que lineal con el tamano
 * (medido, ~n^1,28 entre 750 y 3.000 funciones), asi que partirla no solo
 * equilibra -- quita trabajo.
 *
 * POR QUE SE PUEDE.  Los bloques de `__module_init` son una CADENA lineal, uno
 * por clase o advice, y NO se pasan valores entre si: lo que una clase necesita
 * de otra viaja por estado GLOBAL -- el hueco estatico donde queda su
 * `ClassInfo*` y el registro que `findclass` consulta por nombre.  Comprobado
 * sobre el IR emitido: de 331 valores, el UNICO que cruza de bloque es el
 * buffer de parametros (un `ALLOCA`), y ese se rematerializa fresco por tanda.
 *
 * Es conservador a proposito.  Cualquier forma que no encaje con eso -- un
 * PHI, una rama, un valor que cruza y no es un `ALLOCA` -- deja la funcion como
 * estaba: partir mal aqui no da un programa mas lento, da uno que registra mal
 * sus clases.
 *
 * @param init `__module_init` recien generada; queda reescrita a llamadas.
 * @param out  Modulo donde se anaden las tandas.
 * @return true si se partio; false si se dejo intacta.
 */
bool split_module_init_into_chunks(ir::IrFunction &init, ir::IrModule &out) {
    const size_t nblocks = init.blocks.size();
    if (nblocks < 2) return false;

    size_t total = 0;
    for (const auto &b : init.blocks)
        total += b.instrs.size();
    if (total < kModuleInitSplitMin) return false;

    // --- 1. La cadena tiene que ser lineal y sin PHIs ---------------------
    for (size_t i = 0; i < nblocks; ++i) {
        const ir::IrBlock &b = init.blocks[i];
        if (b.id != static_cast<ir::IrBlockId>(i)) return false;
        if (b.instrs.empty()) return false;
        for (size_t k = 0; k < b.instrs.size(); ++k) {
            const ir::IrOp op = b.instrs[k].op;
            if (op == ir::IrOp::PHI) return false;
            // Un terminador a mitad de bloque significa que esto no es la
            // cadena que creemos estar mirando.
            if (k + 1 != b.instrs.size() &&
                (op == ir::IrOp::BR || op == ir::IrOp::BR_COND ||
                 op == ir::IrOp::RET))
                return false;
        }
        const ir::IrInstr &last = b.instrs.back();
        if (i + 1 < nblocks) {
            if (last.op != ir::IrOp::BR) return false;
            if (last.target_block != static_cast<ir::IrBlockId>(i + 1))
                return false;
        } else if (last.op != ir::IrOp::RET) {
            return false;
        }
    }

    // --- 2. Que valores cruzan de bloque ----------------------------------
    const size_t nvals = init.values.size();
    std::vector<size_t> def_block(nvals, SIZE_MAX);
    std::vector<const ir::IrInstr *> def_instr(nvals, nullptr);
    for (size_t i = 0; i < nblocks; ++i)
        for (const ir::IrInstr &in : init.blocks[i].instrs)
            if (in.dst != ir::IR_NO_VALUE &&
                static_cast<size_t>(in.dst) < nvals) {
                def_block[in.dst] = i;
                def_instr[in.dst] = &in;
            }

    std::vector<ir::IrValueId> shared; // los que cruzan (en la practica, 1)
    bool splittable = true;
    auto note_use = [&](ir::IrValueId v, size_t blk) {
        if (v == ir::IR_NO_VALUE) return;
        if (static_cast<size_t>(v) >= nvals || def_block[v] == SIZE_MAX) {
            splittable = false; // viene de fuera de la cadena: no se toca
            return;
        }
        if (def_block[v] != blk &&
            std::find(shared.begin(), shared.end(), v) == shared.end())
            shared.push_back(v);
    };
    for (size_t i = 0; i < nblocks && splittable; ++i)
        for (const ir::IrInstr &in : init.blocks[i].instrs) {
            for (ir::IrValueId v : in.operands)
                note_use(v, i);
            note_use(in.func_ptr, i);
        }
    if (!splittable) return false;

    // Rematerializar solo se sabe hacer con un ALLOCA.
    for (ir::IrValueId v : shared)
        if (!def_instr[v] || def_instr[v]->op != ir::IrOp::ALLOCA) return false;

    // --- 3. Cortes por presupuesto de instrucciones -----------------------
    const size_t budget = module_init_chunk_budget();
    std::vector<std::pair<size_t, size_t>> chunks; // [inicio, fin)
    size_t start = 0, acc = 0;
    for (size_t i = 0; i < nblocks; ++i) {
        acc += init.blocks[i].instrs.size();
        if (acc >= budget && i + 1 != nblocks) {
            chunks.emplace_back(start, i + 1);
            start = i + 1;
            acc = 0;
        }
    }
    chunks.emplace_back(start, nblocks);
    if (chunks.size() < 2) return false;

    // --- 4. Una funcion por tanda -----------------------------------------
    const std::string base = init.name;
    std::vector<std::string> names;
    names.reserve(chunks.size());

    for (size_t c = 0; c < chunks.size(); ++c) {
        const size_t first = chunks[c].first, limit = chunks[c].second;
        ir::IrFunction f;
        f.name = base + "_part" + std::to_string(c);
        f.ret_type = ir::IrType::VOID;

        std::vector<ir::IrBlockId> newid(nblocks, 0);
        for (size_t i = first; i < limit; ++i)
            newid[i] = f.new_block(init.blocks[i].name);

        // El buffer de parametros: uno FRESCO por tanda.
        std::vector<ir::IrValueId> vmap(nvals, ir::IR_NO_VALUE);
        for (ir::IrValueId v : shared) {
            ir::IrInstr a = *def_instr[v];
            const ir::IrValueId nv = f.new_value(init.values[v].type);
            f.values[nv].is_host_ptr = init.values[v].is_host_ptr;
            a.dst = nv;
            vmap[v] = nv;
            f.append(newid[first], std::move(a));
        }

        for (size_t i = first; i < limit; ++i)
            for (const ir::IrInstr &in : init.blocks[i].instrs) {
                // El ALLOCA compartido ya se emitio fresco arriba.
                if (in.op == ir::IrOp::ALLOCA && in.dst != ir::IR_NO_VALUE &&
                    std::find(shared.begin(), shared.end(), in.dst) !=
                        shared.end())
                    continue;
                ir::IrInstr copy = in;
                for (ir::IrValueId &v : copy.operands)
                    if (v != ir::IR_NO_VALUE) v = vmap[v];
                if (copy.func_ptr != ir::IR_NO_VALUE)
                    copy.func_ptr = vmap[copy.func_ptr];
                if (copy.op == ir::IrOp::BR) {
                    if (i + 1 < limit) {
                        copy.target_block = newid[i + 1];
                    } else {
                        // Fin de tanda: se vuelve, no se salta a la siguiente.
                        const int ln = copy.source_line;
                        copy = ir::IrInstr{};
                        copy.op = ir::IrOp::RET;
                        copy.type = ir::IrType::VOID;
                        copy.source_line = ln;
                    }
                }
                if (copy.dst != ir::IR_NO_VALUE) {
                    const ir::IrValueId old = copy.dst;
                    const ir::IrValueId nv = f.new_value(init.values[old].type);
                    f.values[nv].is_host_ptr = init.values[old].is_host_ptr;
                    vmap[old] = nv;
                    copy.dst = nv;
                }
                f.append(newid[i], std::move(copy));
            }

        names.push_back(f.name);
        out.add_function(std::move(f));
    }

    // --- 5. `__module_init` pasa a ser la lista de llamadas ---------------
    init.blocks.clear();
    init.values.clear();
    const ir::IrBlockId entry = init.new_block("entry");
    for (const std::string &n : names) {
        ir::IrInstr call{};
        call.op = ir::IrOp::CALL;
        call.type = ir::IrType::VOID;
        call.dst = ir::IR_NO_VALUE;
        call.func_name = n;
        call.source_line = 0;
        init.append(entry, std::move(call));
    }
    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.type = ir::IrType::VOID;
    ret.source_line = 0;
    init.append(entry, std::move(ret));
    return true;
}

std::string Lowering::build_module_init_asm(ir::IrModule & /*out_module*/) {
    // No se usa: la generacion de __module_init se hace via
    // generate_module_init_function (IrFunction completa, no cadena).
    return std::string();
}

ir::IrValueId Lowering::lower_this_expr(ast::ThisExpr *e) {
    const ir::IrValueId v = lookup("this");
    if (v == ir::IR_NO_VALUE) {
        error_at(e->loc, "lowering: 'this' fuera de contexto de metodo");
    }
    return v;
}

/**
 * @brief Helper: construye un IrValueId que apunta a @c base+offset,
 *        marcado como host_ptr (para que LOAD/STORE emitan @c movh).
 *        Si offset es 0, devuelve el base directamente.
 */
ir::IrValueId emit_field_addr(ir::IrFunction *fn, ir::IrBlockId block,
                              ir::IrValueId base, uint32_t offset,
                              uint32_t line) {
    if (offset == 0) {
        // El frontend marca el resultado como host_ptr para que LOAD/
        // STORE usen movh.  Si la base ya tiene is_host_ptr=true, la
        // propagacion es trivial; si no, lo forzamos aqui (siempre lo
        // sera para nuestros punteros de objeto Vesta).
        fn->values[base].is_host_ptr = true;
        return base;
    }
    // Crear constante con el offset y sumar.
    ir::IrInstr c{};
    const ir::IrValueId off_val = fn->new_value(ir::IrType::I64);
    fn->values[off_val].is_const = true;
    fn->values[off_val].const_val = offset;
    c.op = ir::IrOp::CONST;
    c.type = ir::IrType::I64;
    c.dst = off_val;
    c.imm = offset;
    c.source_line = line;
    fn->append(block, std::move(c));

    const ir::IrValueId addr = fn->new_value(ir::IrType::PTR);
    // Marcar host_ptr: las operaciones LOAD/STORE consultan este flag
    // para emitir mov (VM) o movh (host).  Las direcciones derivadas
    // de un host_ptr siguen siendo host_ptr.
    fn->values[addr].is_host_ptr = true;
    ir::IrInstr add{};
    add.op = ir::IrOp::ADD;
    add.type = ir::IrType::PTR;
    add.dst = addr;
    add.operands = {base, off_val};
    add.source_line = line;
    fn->append(block, std::move(add));
    return addr;
}

// ---------------------------------------------------------------------
// @Virtual: vtable estatica + init del vptr (modelo AOT, structs value-type).
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Helpers de constantes y casts.
// ---------------------------------------------------------------------

ir::IrValueId Lowering::emit_const(ir::IrType t, uint64_t imm,
                                   uint32_t source_line) {
    const ir::IrValueId dst = fn_->new_value(t);
    fn_->values[dst].is_const = true;
    fn_->values[dst].const_val = imm;
    ir::IrInstr c{};
    c.op = ir::IrOp::CONST;
    c.type = t;
    c.dst = dst;
    c.imm = imm;
    c.source_line = source_line;
    emit(current_block_, std::move(c));
    return dst;
}

// -----------------------------------------------------------------------
// Helpers para IR ops nativos (anteriormente RAW_ASM).  Migracion 2026-05-23.
// -----------------------------------------------------------------------

// ---------------------------------------------------------------------
// C-3: ruteo del operador `+`/`==` del string built-in a una funcion
// libre marcada con @StringConcat / @StringEq.  Materializa ambos
// operandos al repr `string` adecuado (StringObject handle i64 en Full,
// PTR a value-string en native_poo_) y emite una CALL a la funcion del
// usuario.  La funcion se compila como cualquier otra; solo cambia el
// SITIO de llamada (mecanismo, no politica -- como @AllocatorOverride).
// ---------------------------------------------------------------------
ir::IrValueId
Lowering::emit_string_override_call(const std::string &fn_name, ast::Expr *lhs,
                                    ast::Expr *rhs, ir::IrType ret_ir,
                                    bool negate, uint32_t source_line) {
    // Materializa un operando como `string` para pasarlo por valor a la
    // funcion del usuario.  En native un literal se construye en un slot
    // value-string TEMPORAL (la callee copia los bytes -> se libera tras
    // la CALL); las variables/expresiones devuelven su slot via lower_expr
    // y NO se liberan aqui (su RAII manda).  En Full el literal se
    // promueve a StringObject via STRMAKE; el GC libera el intermedio.
    auto materialize = [&](ast::Expr *ex, bool &is_temp) -> ir::IrValueId {
        is_temp = false;
        if (native_poo_) {
            if (ex && ex->kind == ast::NodeKind::StringLitExpr &&
                !static_cast<ast::StringLitExpr *>(ex)->is_interpolated()) {
                is_temp = true;
                return build_native_string_from_literal(
                    static_cast<ast::StringLitExpr *>(ex), source_line);
            }
            // Concat anidado / cast (string)<char>: slot owned sin RAII ->
            // temporal a liberar tras copiar bytes (igual que el concat).
            if (ex && ex->kind == ast::NodeKind::BinaryExpr &&
                static_cast<ast::BinaryExpr *>(ex)->op == ast::BinOp::Add &&
                ex->result_type.kind == PrimitiveKind::STRING) {
                is_temp = true;
                return lower_expr(ex);
            }
            if (ex && ex->kind == ast::NodeKind::CastExpr &&
                ex->result_type.kind == PrimitiveKind::STRING) {
                is_temp = true;
                return lower_expr(ex);
            }
            return lower_expr(ex);
        }
        // Full: literal -> StringObject handle; var/expr -> handle directo.
        if (ex && ex->kind == ast::NodeKind::StringLitExpr) {
            return lower_string_literal_to_string_object(
                static_cast<ast::StringLitExpr *>(ex));
        }
        return lower_expr(ex);
    };

    bool a_temp = false, b_temp = false;
    ir::IrValueId v_a = materialize(lhs, a_temp);
    ir::IrValueId v_b = materialize(rhs, b_temp);
    if (v_a == ir::IR_NO_VALUE || v_b == ir::IR_NO_VALUE)
        return ir::IR_NO_VALUE;

    // Resolver el label real de la funcion (mismo manejo cross-module que
    // lower_call: si fue importada con mangling, usar el mangled label).
    std::string callee_name = fn_name;
    {
        const FunctionSig *fs = tc_.function_sig_by_name(fn_name);
        if (fs && !fs->mangled_label.empty()) callee_name = fs->mangled_label;
    }

    // Vesta Embed (native_poo_): si el override (@StringConcat) retorna un
    // `string` value-type, su firma IR real es void + retbuf hidden (SRET
    // de 24 bytes).  El call site debe alocar el retbuf, pasarlo PRIMERO,
    // y devolver el retbuf como "valor" del override.  Sin esto, el CALL
    // emite firma i64 (registro) contra una callee void+retbuf -> segfault.
    const bool override_is_str_sret =
        native_poo_ &&
        (fn_returns_str_value_.find(fn_name) != fn_returns_str_value_.end());
    if (override_is_str_sret) {
        const ir::IrValueId v_retbuf = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_retbuf].is_host_ptr = true;
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = v_retbuf;
        al.imm = 24; // value-string {ptr,len,cap}
        al.host_alloca = true;
        al.source_line = source_line;
        emit(current_block_, std::move(al));
        emit_call(std::move(callee_name), {v_retbuf, v_a, v_b},
                  ir::IrType::VOID, source_line);
        // Liberar operandos temporales (bytes ya copiados por la callee).
        // Inc 5 (SSO): solo libera si estaba en HEAP.
        if (a_temp) emit_native_str_free_if_heap(v_a, source_line);
        if (b_temp) emit_native_str_free_if_heap(v_b, source_line);
        // El "valor" del override es el retbuf (PTR al value-string).
        return v_retbuf;
    }

    const ir::IrValueId v_ret =
        emit_call(std::move(callee_name), {v_a, v_b}, ret_ir, source_line);

    // Liberar los operandos LITERAL/expr-temporales en native (sus bytes
    // ya estan copiados por la callee).  Inc 5 (SSO): solo libera si
    // estaba en HEAP.  Las variables NO se liberan aqui.
    if (native_poo_) {
        if (a_temp) emit_native_str_free_if_heap(v_a, source_line);
        if (b_temp) emit_native_str_free_if_heap(v_b, source_line);
    }

    // Para `!=` sobre @StringEq: negar el bool resultante.
    if (negate && ret_ir == ir::IrType::BOOL) {
        const ir::IrValueId v_zero =
            emit_const(ir::IrType::BOOL, 0, source_line);
        const ir::IrValueId v_neg = fn_->new_value(ir::IrType::BOOL);
        ir::IrInstr cmp{};
        cmp.op = ir::IrOp::CMP_EQ; // (resultado == false) => negacion
        cmp.type = ir::IrType::BOOL;
        cmp.dst = v_neg;
        cmp.operands = {v_ret, v_zero};
        cmp.source_line = source_line;
        emit(current_block_, std::move(cmp));
        return v_neg;
    }
    return v_ret;
}

// -----------------------------------------------------------------------
// Vesta Embed Inc 0: string value-type (solo native_poo_).
//
// Repr: struct de 24 bytes en stack (ALLOCA) { u8* ptr; u64 len; u64 cap }.
// HEAP-ALWAYS (sin SSO todavia): incluso "hi" aloca un buffer.  El valor
// SSA de una variable `string` es el PTR al slot de 24 bytes, igual que un
// struct value-type (ver lower_ident: STRUCT/ARRAY devuelven lookup()).
// -----------------------------------------------------------------------

ir::IrValueId
Lowering::build_native_string_from_literal(ast::StringLitExpr *slit,
                                           uint32_t source_line) {
    // El literal ya tiene su contenido resuelto (UTF-8 raw, sin nul) en
    // @c slit->value.  len = numero de bytes; cap = len + 1 (el nul).
    const std::string &lit = slit->value;
    const uint64_t len = static_cast<uint64_t>(lit.size());
    const uint64_t cap = len + 1; // +1 para el nul terminador.

    // 1. Slot de 24 bytes en stack (ALLOCA host).  En native_poo_/AOT el
    //    value-string vive en HOST stack: su ptr debe ser un host_ptr
    //    coherente en TODO el programa (se pasa a funciones que lo leen
    //    via `movh`, se copia al retbuf SRET host).  Un ALLOCA VM-stack
    //    (`[rbx+regs]`) daria un VM-addr que al cruzar a un callee
    //    host_ptr se leeria como host -> segfault.  host_alloca=true +
    //    is_host_ptr=true mantienen la coherencia.
    const ir::IrValueId v_slot = fn_->new_value(ir::IrType::PTR);
    if (native_poo_) fn_->values[v_slot].is_host_ptr = true;
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = v_slot;
        al.imm = 24;
        al.host_alloca = native_poo_;
        al.source_line = source_line;
        emit(current_block_, std::move(al));
    }
    // String Inc 5 (SSO): zero-init el slot (bytes no usados definidos).
    emit_zero_native_str_slot(v_slot, source_line);

    // Helpers comunes (STORE empaquetado al buf en una direccion off).
    auto buf_store_at = [&](ir::IrValueId v_base, uint64_t off, uint64_t val,
                            ir::IrType ty) {
        ir::IrValueId v_dst = v_base;
        if (off != 0) {
            ir::IrValueId v_off = emit_const(ir::IrType::I64, off, source_line);
            v_dst = fn_->new_value(ir::IrType::PTR);
            fn_->values[v_dst].is_host_ptr = true;
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_dst;
            ad.operands = {v_base, v_off};
            ad.source_line = source_line;
            emit(current_block_, std::move(ad));
        }
        ir::IrValueId v_val = emit_const(ty, val, source_line);
        emit_store_typed(v_dst, v_val, ty, source_line);
    };
    auto pack = [](const std::vector<uint8_t> &data, uint64_t pos, int n) {
        return pack_le(data, pos, n);
    };
    // Helper: escribir `data` (incluye el nul final) byte-a-byte agrupado
    // en qwords/dword/word/byte a partir de @p v_base + base_off.
    auto write_packed = [&](ir::IrValueId v_base, uint64_t base_off,
                            const std::vector<uint8_t> &data) {
        uint64_t pos = 0;
        const uint64_t total_w = data.size();
        // En un target de 32 bits un inmediato de 64 no existe: agrupar de
        // ocho en ocho producia una constante que no cabe en un registro, el
        // encoder la truncaba y el literal salia recortado.  Alli se agrupa de
        // cuatro en cuatro.
        const uint64_t paso = (asm_target_bits_ == 32) ? 4u : 8u;
        for (; pos + paso <= total_w; pos += paso)
            buf_store_at(v_base, base_off + pos,
                         pack(data, pos, static_cast<int>(paso)),
                         paso == 8 ? ir::IrType::I64 : ir::IrType::I32);
        if (pos + 4 <= total_w) {
            buf_store_at(v_base, base_off + pos, pack(data, pos, 4),
                         ir::IrType::I32);
            pos += 4;
        }
        if (pos + 2 <= total_w) {
            buf_store_at(v_base, base_off + pos, pack(data, pos, 2),
                         ir::IrType::I16);
            pos += 2;
        }
        if (pos + 1 <= total_w) {
            buf_store_at(v_base, base_off + pos, pack(data, pos, 1),
                         ir::IrType::U8);
            pos += 1;
        }
    };

    // String Inc 5 (SSO): si el literal cabe inline (<= 22 bytes), lo
    // construimos en SSO -> CERO malloc.  Escribimos data + nul INLINE en
    // bytes[0..len] y el len en byte[23] (flag SSO=0 en el bit alto).
    if (len <= 22) {
        std::vector<uint8_t> data(lit.begin(), lit.end());
        data.push_back(0); // nul; data.size() == len+1, cabe en [0..22].
        write_packed(v_slot, 0, data);
        // qword2 = (len << 56): byte[23]=len (SSO), bytes 16..22=0.
        emit_str_meta_sso(v_slot, emit_const(ir::IrType::I64, len, source_line),
                          source_line);
        return v_slot;
    }

    // --- Literal largo (> 22 bytes): VISTA sobre .rodata ---
    //
    // El contenido ya esta en el binario, en datos de solo lectura; copiarlo a
    // memoria pedida al asignador solo para poder leerlo era pagar dos veces
    // por lo mismo -- y arrastraba el asignador entero a cualquier programa
    // que mencionara una cadena, cosa que un modulo freestanding como vx_io no
    // puede permitirse.  Ahora el slot APUNTA al literal y se marca prestado:
    // nadie lo libera y nadie escribe encima (quien vaya a escribir lo copia
    // antes, ver build_native_string_append_inplace).
    //
    // El literal se interna con su nul para que `cstr()` valga tal cual.
    (void)cap;
    const ir::IrValueId v_buf = emit_str_lit_addr(
        intern_string_literal_nul(*out_mod_, lit), source_line, true);
    store_slot_fields_prestado(v_slot, v_buf, len, source_line);
    return v_slot;

    // 3 + 4. Escribir el contenido del literal + nul final al buffer.
    //    El contenido es CONOCIDO en compile-time -> emitimos STOREs
    //    desempaquetados de constantes (sin .rodata, sin loop, sin
    //    LOAD): el nul terminador es el byte (len) del buffer, asi que
    //    escribimos `cap = len+1` bytes (literal + nul) agrupados en
    //    qwords (8B), luego dword (4B), word (2B) y byte (1B) de cola.
    //    Cada STORE es de un CONST empaquetado en little-endian.  ~8x
    //    menos STOREs que byte-a-byte para literales largos; cero
    //    branches (totalmente desenrollado).  Todas las ops son
    //    PURE_NATIVE (CONST + ADD + STORE).
    {
        // Bytes a escribir = el literal seguido del nul terminador.
        std::vector<uint8_t> data(lit.begin(), lit.end());
        data.push_back(0); // nul final; data.size() == cap.

        // Helper: dst = v_buf + off (host_ptr).  off==0 -> v_buf directo.
        auto buf_at = [&](uint64_t off) -> ir::IrValueId {
            if (off == 0) return v_buf;
            ir::IrValueId v_off = emit_const(ir::IrType::I64, off, source_line);
            ir::IrValueId v_dst = fn_->new_value(ir::IrType::PTR);
            fn_->values[v_dst].is_host_ptr = true;
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_dst;
            ad.operands = {v_buf, v_off};
            ad.source_line = source_line;
            emit(current_block_, std::move(ad));
            return v_dst;
        };
        // Helper: STORE de un valor empaquetado de `w` bytes (1/2/4/8) en
        // buf[off].  val ya viene empaquetado little-endian.
        auto store_chunk = [&](uint64_t off, uint64_t val, ir::IrType ty) {
            ir::IrValueId v_dst = buf_at(off);
            ir::IrValueId v_val = emit_const(ty, val, source_line);
            emit_store_typed(v_dst, v_val, ty, source_line);
        };
        // Empaquetar `n` bytes de data[pos..] en un entero little-endian.
        auto pack = [&](uint64_t pos, int n) { return pack_le(data, pos, n); };

        uint64_t pos = 0;
        const uint64_t total_w = data.size(); // = cap
        // Qwords (8B) -- dwords si el target es de 32 bits, donde un inmediato
        // de 64 no cabe en un registro (ver la nota del otro empaquetador).
        const uint64_t paso = (asm_target_bits_ == 32) ? 4u : 8u;
        for (; pos + paso <= total_w; pos += paso)
            store_chunk(pos, pack(pos, static_cast<int>(paso)),
                        paso == 8 ? ir::IrType::I64 : ir::IrType::I32);
        // Dword (4B).
        if (pos + 4 <= total_w) {
            store_chunk(pos, pack(pos, 4), ir::IrType::I32);
            pos += 4;
        }
        // Word (2B).
        if (pos + 2 <= total_w) {
            store_chunk(pos, pack(pos, 2), ir::IrType::I16);
            pos += 2;
        }
        // Byte (1B).
        if (pos + 1 <= total_w) {
            store_chunk(pos, pack(pos, 1), ir::IrType::U8);
            pos += 1;
        }
    }

    // 5. Escribir los 3 campos del slot: ptr@0, len@8, cap@16.
    auto store_field = [&](uint64_t off, ir::IrValueId v_val) {
        ir::IrValueId v_addr = v_slot;
        if (off > 0) {
            ir::IrValueId v_off = emit_const(ir::IrType::I64, off, source_line);
            v_addr = emit_ptr_add(v_slot, v_off, source_line);
        }
        emit_store_typed(v_addr, v_val, ir::IrType::I64, source_line);
    };
    store_field(0, v_buf);
    store_field(8, emit_const(ir::IrType::I64, len, source_line));
    // qword2 = cap (bytes 16..22) | flag HEAP (byte[23]=0x80), un solo i64.
    emit_str_meta_heap(v_slot, emit_const(ir::IrType::I64, cap, source_line),
                       source_line);

    return v_slot;
}

// ---------------------------------------------------------------------
// CPU dispatch (cimiento): global __vx_cpu_features + helper __vx_cpu_init.
//
// Detecta las features de la CPU via `cpuid` UNA VEZ al arranque (el wiring
// prepone `call __vx_cpu_init` al entry de main, solo native_poo_) y guarda
// un bitmask en el slot static_data del global.  El builtin cpu_features()
// lo lee (STR_LIT_ADDR + LOAD).  Sienta la base del despacho de helpers por
// CPU + del override por el usuario.
//
// Detalle critico: en AOT HOST_LEAF rbx esta RESERVADO (frame).  `cpuid`
// pisa eax/ebx/ecx/edx; ebx lleva las features de leaf 7 (AVX2/BMI/AVX512).
// El selector vreg (vreg_select.cpp) ya SALVA/RESTAURA rbx alrededor del
// bloque INLINE_ASM cuando rbx aparece en sus clobbers (asm_effects declara
// que cpuid clobbea rax/rbx/rcx/rdx).  Por eso TODA la deteccion + el
// empaquetado de bits viven DENTRO de un solo bloque asm: leemos ebx ahi
// (entre el push y el pop de rbx) y solo SACAMOS el bitmask final en rax.
// Asi nunca exponemos ebx al IR (no podriamos: rbx no es asignable).
//
// rsi/rdi se usan como scratch porque cpuid NO los pisa (sobreviven entre
// las dos llamadas a cpuid): rsi acumula el bitmask, rdi extrae cada bit.
// Numeros en HEX explicito: el bloque se ensambla con Keystone (que toma los
// enteros BARE como hex) sin pasar por asm_normalize_numbers (eso solo corre
// en lower_asm, no en helpers sinteticos).
// ---------------------------------------------------------------------

bool Lowering::imported_global_slot_of(ast::FieldAccessExpr *e,
                                       uint64_t &out_slot) {
    // property_kind=4 marca `ns.X`; ns_index dice CUAL namespace (el
    // sentinel 0xFFFFFFFF = sin resolver).
    if (e == nullptr || e->property_kind != 4 || e->ns_index == 0xFFFFFFFFu)
        return false;
    const auto &nss = tc_.imported_namespaces();
    if (e->ns_index >= nss.size()) return false;
    const auto &ns = nss[e->ns_index];
    auto it_sym = ns.by_name.find(e->field_name);
    if (it_sym == ns.by_name.end()) return false;
    const auto &sym = ns.symbols[it_sym->second];
    if (sym.kind != 1) return false;       // no es variable/constante
    if (sym.has_const_value) return false; // se inlinea como CONST
    if (sym.mangled_label.empty()) return false;
    // Simbolo de un namespace de ESTE modulo: es local, no importado.  Su
    // storage (o su ausencia, p.ej. un global de tipo funcion) ya se decidio
    // con el tipo delante; aqui solo pasan los de otros modulos.
    if (local_global_names_.count(sym.mangled_label) != 0) return false;
    // Un comptime const string se materializa via STRMAKE desde el blob del
    // .vxi, no tiene storage que compartir.
    if (sym.var_type.kind == PrimitiveKind::STRING) {
        const auto &ics = tc_.imported_global_consts();
        auto it_ic = ics.find(e->field_name);
        if (it_ic != ics.end() && it_ic->second.is_str) return false;
    }
    out_slot = shared_global_slot_for(sym.mangled_label, sym.var_type);
    return true;
}

bool Lowering::ensure_imported_global_slot(const std::string &name) {
    if (runtime_global_slots_.count(name) != 0) return true;
    const auto &igs = tc_.imported_global_storage();
    auto it = igs.find(name);
    if (it == igs.end()) return false;
    const uint64_t slot =
        shared_global_slot_for(it->second.mangled_label, it->second.type);
    // Alias: en ESTE modulo el global se nombra `name` (el nombre local del
    // import), pero su storage es el slot del dep.
    runtime_global_slots_[name] = slot;
    return true;
}

uint64_t Lowering::get_or_create_tls_global_slot(const std::string &name,
                                                 uint64_t nbytes,
                                                 uint64_t init_value,
                                                 uint16_t alignment) {
    auto it = runtime_global_slots_.find(name);
    if (it != runtime_global_slots_.end()) return it->second;
    // Cada slot ocupa >=8 bytes (alineado a 8), igual que un global runtime:
    // los STORE a un global usan ancho de qword, asi que un slot de 4 bytes
    // empacado junto al siguiente seria pisado por el store de 8 bytes del
    // vecino.  El valor vive en los bytes bajos; el LOAD usa el ancho del tipo.
    if (nbytes < 8) nbytes = 8;
    nbytes = (nbytes + 7) & ~static_cast<uint64_t>(7); // multiplo de 8
    // Plantilla estatica con el valor inicial (LE en los primeros 8 bytes).
    std::vector<uint8_t> bytes(static_cast<size_t>(nbytes), 0);
    for (size_t i = 0; i < bytes.size() && i < 8; ++i)
        bytes[i] = static_cast<uint8_t>((init_value >> (i * 8)) & 0xFFu);
    const uint64_t idx = static_cast<uint64_t>(
        out_mod_->static_data.push_back(std::move(bytes)));
    auto &m = out_mod_->static_data.meta_at(idx);
    // NON_DEDUP (storage propio) + TLS (seccion SHF_TLS) + .tdata.
    m.flags |= ir::IrModule::SD_FLAG_NON_DEDUP | ir::IrModule::SD_FLAG_TLS;
    m.section_name = ".tdata";
    m.alignment = alignment < 8 ? 8 : alignment;
    // Registrar en runtime_global_slots_ para que lower_ident lo resuelva
    // como un global ordinario (STR_LIT_ADDR); el driver AOT deriva la
    // TLS-ness desde SD_FLAG_TLS y emite el acceso por thread pointer.
    runtime_global_slots_[name] = idx;
    return idx;
}

// ---------------------------------------------------------------------
// Scopes.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Address-taken locals: pre-pase + accesos via LOAD/STORE.
//
// Cuando el usuario escribe `&x`, x debe vivir en una direccion estable
// (memoria), no en un registro virtual SSA.  Hacemos un escaneo previo
// del cuerpo de cada funcion para detectar todas las variables cuya
// direccion se toma; lower_var_decl emite ALLOCA para esas, y los
// accesos lectura/escritura pasan por LOAD/STORE en lugar de scope SSA.
//
// El conjunto address_taken_locals_ es por-funcion (limpiado al inicio
// de lower_function via run() / lower_function).  Solo registramos los
// nombres; el control de scope inner-shadowing es resposabilidad del
// type checker en hitos posteriores (no usamos shadowing).
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// spawn_body_uses_coop: recorre el body de un `spawn { }` buscando el uso
// de primitivas de asincronia COOPERATIVA (mailbox / future / await).  Su
// presencia indica que el spawn es una TAREA cooperativa del scheduler de
// vx_async (single-thread, run-to-completion), NO un hilo real paralelo.
// Ver la doc de la declaracion en lowering.h.
// ---------------------------------------------------------------------
bool Lowering::spawn_body_uses_coop(ast::Stmt *s) {
    if (!s) return false;
    bool found = false;
    std::function<void(ast::Expr *)> visit_expr;
    std::function<void(ast::Stmt *)> visit_stmt;

    visit_expr = [&](ast::Expr *e) {
        if (!e || found) return;
        switch (e->kind) {
        case ast::NodeKind::UnaryExpr: {
            auto *u = static_cast<ast::UnaryExpr *>(e);
            // `await fut` -> primitiva cooperativa.
            if (u->op == ast::UnOp::Await) {
                found = true;
                return;
            }
            visit_expr(u->operand.get());
            return;
        }
        case ast::NodeKind::CallExpr: {
            auto *c = static_cast<ast::CallExpr *>(e);
            if (c->callee && c->callee->kind == ast::NodeKind::IdentExpr) {
                const std::string &nm =
                    static_cast<ast::IdentExpr *>(c->callee.get())->name;
                if (nm == "msgrecv" || nm == "msgsend" || nm == "fulfill" ||
                    nm == "future_alloc") {
                    found = true;
                    return;
                }
            }
            visit_expr(c->callee.get());
            for (auto &arg : c->args)
                visit_expr(arg.get());
            return;
        }
        case ast::NodeKind::BinaryExpr: {
            auto *b = static_cast<ast::BinaryExpr *>(e);
            visit_expr(b->lhs.get());
            visit_expr(b->rhs.get());
            return;
        }
        case ast::NodeKind::AssignExpr: {
            auto *a = static_cast<ast::AssignExpr *>(e);
            visit_expr(a->target.get());
            visit_expr(a->value.get());
            return;
        }
        case ast::NodeKind::FieldAccessExpr:
            visit_expr(static_cast<ast::FieldAccessExpr *>(e)->base.get());
            return;
        case ast::NodeKind::IndexExpr: {
            auto *ix = static_cast<ast::IndexExpr *>(e);
            visit_expr(ix->base.get());
            visit_expr(ix->index.get());
            return;
        }
        case ast::NodeKind::CastExpr:
            visit_expr(static_cast<ast::CastExpr *>(e)->operand.get());
            return;
        case ast::NodeKind::TernaryExpr: {
            auto *te = static_cast<ast::TernaryExpr *>(e);
            visit_expr(te->cond.get());
            visit_expr(te->then_expr.get());
            visit_expr(te->else_expr.get());
            return;
        }
        default: return;
        }
    };

    visit_stmt = [&](ast::Stmt *st) {
        if (!st || found) return;
        switch (st->kind) {
        case ast::NodeKind::BlockStmt: {
            auto *b = static_cast<ast::BlockStmt *>(st);
            for (auto &child : b->body)
                visit_stmt(child.get());
            return;
        }
        case ast::NodeKind::VarDeclStmt: {
            auto *vd = static_cast<ast::VarDeclStmt *>(st);
            if (vd->init) visit_expr(vd->init.get());
            return;
        }
        case ast::NodeKind::ExprStmt:
            visit_expr(static_cast<ast::ExprStmt *>(st)->expr.get());
            return;
        case ast::NodeKind::IfStmt: {
            auto *si = static_cast<ast::IfStmt *>(st);
            visit_expr(si->cond.get());
            visit_stmt(si->then_branch.get());
            visit_stmt(si->else_branch.get());
            return;
        }
        case ast::NodeKind::WhileStmt: {
            auto *w = static_cast<ast::WhileStmt *>(st);
            visit_expr(w->cond.get());
            visit_stmt(w->body.get());
            return;
        }
        case ast::NodeKind::DoWhileStmt: {
            auto *dw = static_cast<ast::DoWhileStmt *>(st);
            visit_stmt(dw->body.get());
            visit_expr(dw->cond.get());
            return;
        }
        case ast::NodeKind::ForStmt: {
            auto *f = static_cast<ast::ForStmt *>(st);
            visit_stmt(f->init.get());
            visit_expr(f->cond.get());
            visit_expr(f->step.get());
            visit_stmt(f->body.get());
            return;
        }
        case ast::NodeKind::TryStmt: {
            auto *ts = static_cast<ast::TryStmt *>(st);
            visit_stmt(ts->body.get());
            for (auto &cc : ts->catches)
                visit_stmt(cc.body.get());
            if (ts->finally_body) visit_stmt(ts->finally_body.get());
            return;
        }
        case ast::NodeKind::ReturnStmt:
            visit_expr(static_cast<ast::ReturnStmt *>(st)->value.get());
            return;
        case ast::NodeKind::SynchronizedStmt: {
            auto *sy = static_cast<ast::SynchronizedStmt *>(st);
            visit_expr(sy->target.get());
            visit_stmt(sy->body.get());
            return;
        }
        default: return;
        }
    };
    visit_stmt(s);
    return found;
}

// ---------------------------------------------------------------------
// scan_escaping_locals: pre-pase que recorre el body buscando
// patrones donde el handle de un local escapa del scope:
//
//   - return ident;            -> ident escapa via valor de retorno.
//   - this.field   = ident;    -> ident escapa via campo de objeto.
//   - obj.field    = ident;    -> idem.
//   - *ptr         = ident;    -> escapa via deref-store.
//   - arr[i]       = ident;    -> escapa via slot de array.
//   - p->field     = ident;    -> escapa via field deref.
//
// Los locales detectados se añaden a @c escaping_locals_; el cleanup
// automatico los omite y queda como responsabilidad del caller (o del
// futuro GC roots) liberar el handle.
//
// Conservador: solo detecta escape via los patrones listados.  Pasar el
// local como argumento a una funcion NO se considera escape (el callee
// tipicamente solo lee el handle; si retiene una copia es responsabilidad
// suya marcar el escape via su propio analisis).
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Errores y helpers de diagnostico.
// ---------------------------------------------------------------------

void Lowering::unsupported(SourceLoc loc, const char *feature) {
    diags_.error(std::move(loc),
                 std::string("lowering: caracteristica aun no soportada: ") +
                     feature);
}

/**
 * @brief Un builtin usado mal: lo dice, no da valor, y da el caso por atendido.
 *
 * Las tres cosas van juntas siempre y por una razon: el builtin SI era suyo
 * -- el nombre estaba bien, lo que fallo son los argumentos --, asi que
 * devolver @c false haria que el despacho siguiera buscando y acabara diciendo
 * que ese nombre no existe.  El mensaje correcto es el que ya se ha dado.
 *
 * Y dejar el valor "sin valor" no es cosmetico: quien pidio el resultado tiene
 * que ver que no lo hay.  Devolverlo a medias produce un segundo error mas
 * abajo, lejos y sin relacion aparente con lo que el programador escribio mal.
 *
 * Estaba escrito a mano 127 veces, cuatro lineas cada una.
 *
 * @param loc Donde esta el error, para citarlo.
 * @param msg Que le pasa.
 * @param out Donde dejar el resultado: queda sin valor.
 * @return Siempre @c true -- el caso queda atendido --.
 */
bool Lowering::builtin_error(SourceLoc loc, std::string msg,
                             ir::IrValueId &out) {
    error_at(loc, std::move(msg));
    out = ir::IR_NO_VALUE;
    return true;
}

void Lowering::error_at(SourceLoc loc, std::string msg) {
    diags_.error(std::move(loc), std::move(msg));
}

// ---------------------------------------------------------------------
// Exportacion de metadata POO al IrModule (para port transpilers).
// ---------------------------------------------------------------------

// =====================================================================
// BugFix R1: super(args) y super.method(args)
// =====================================================================
//
// super(args) (SuperCallExpr): dentro de un ctor de clase derivada,
// invoca el ctor del super con this como receptor.  El this implicito
// se obtiene del primer parametro (lookup("this")).
//
// Implementacion correcta: emitir el opcode bytecode `callsuper`
// (0xFC) que dispatcha a la vtable de la SUPER class (no del
// receiver dinamico).  Esto evita:
//   (1) Recursion infinita en ctor: `callvirt this, 0` con un
//       Derived as receiver resolveria vtable[0]=Derived.__ctor
//       (no Base.__ctor) -> recursion.
//   (2) Override-en-medio: si Derived overridea un metodo de Base,
//       `super.foo()` desde Derived debe llamar Base.foo, NO
//       Derived.foo.  CALLVIRT lo haria mal; CALLSUPER lo hace bien.
//
// El IR no tiene un IrOp::CALLSUPER dedicado, asi que el lowering
// usa RAW_ASM con la sintaxis textual `callsuper r_cls, vtable_idx`
// del assembler de la VM.  El bloque RAW_ASM emite:
//   findclass <super_name> -> r_cls (host_ptr a ClassInfo del super)
//   mov r1, this
//   mov r2..rN, args
//   mov r15, argc
//   callsuper r_cls, vtable_idx
//
// super.method(args) (SuperMethodCallExpr): igual patron pero busca
// el metodo non-ctor por nombre en la cadena super (BFS) y emite
// callsuper con su vtable_index dentro de la SUPER class.  Si hay
// overrides intermedios entre Derived y la clase que define el
// metodo, el dispatch va a la clase mas cercana en la jerarquia
// super (Java's `super.method` semantica).

ir::IrValueId
Lowering::lower_super_method_call_expr(ast::SuperMethodCallExpr *e) {
    const ir::IrValueId v_this = lookup("this");
    if (v_this == ir::IR_NO_VALUE) {
        error_at(e->loc,
                 "super." + e->method_name + "(...): no se encontro 'this'");
        return ir::IR_NO_VALUE;
    }
    if (current_class_lowering_.empty()) {
        error_at(e->loc, "super.<metodo>(...) fuera de cuerpo de clase");
        return ir::IR_NO_VALUE;
    }
    auto it = tc_.class_layouts().find(current_class_lowering_);
    if (it == tc_.class_layouts().end() || it->second.super_name.empty()) {
        error_at(e->loc, "super.<metodo>(...) en clase sin super");
        return ir::IR_NO_VALUE;
    }
    // Buscar el metodo en la cadena super (BFS).
    std::string cur = it->second.super_name;
    const ClassMethodInfo *found = nullptr;
    for (int depth = 0; depth < 32; ++depth) {
        auto it_s = tc_.class_layouts().find(cur);
        if (it_s == tc_.class_layouts().end()) break;
        for (const auto &m : it_s->second.methods) {
            if (!m.is_constructor && m.name == e->method_name) {
                found = &m;
                break;
            }
        }
        if (found) break;
        if (it_s->second.super_name.empty()) break;
        cur = it_s->second.super_name;
    }
    if (!found) {
        error_at(e->loc, "super." + e->method_name + ": metodo no encontrado");
        return ir::IR_NO_VALUE;
    }
    std::vector<ir::IrValueId> arg_vals;
    arg_vals.reserve(e->args.size());
    for (auto &a : e->args) {
        const ir::IrValueId av = lower_expr(a.get());
        if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        arg_vals.push_back(av);
    }
    const ir::IrType ret_ir = ir_type_from_primitive(found->return_type.kind);
    const ir::IrValueId dst =
        (ret_ir == ir::IrType::VOID) ? ir::IR_NO_VALUE : fn_->new_value(ret_ir);
    // AOT (native_poo_): el metodo base es estaticamente conocido ->
    // CALL DIRECTO a <defining_class>__<metodo>(this, args).  Evita
    // findclass + callsuper (runtime).  Habilita super.metodo() en AOT.
    if (native_poo_) {
        const std::string owner = found->defining_class.empty()
                                      ? it->second.super_name
                                      : found->defining_class;
        ir::IrInstr ca{};
        ca.op = ir::IrOp::CALL;
        ca.type = ret_ir;
        ca.dst = dst;
        ca.func_name = owner + "__" + found->name;
        ca.operands.push_back(v_this);
        for (auto av : arg_vals)
            ca.operands.push_back(av);
        ca.source_line = e->loc.line;
        emit(current_block_, std::move(ca));
        return dst;
    }
    // Resolver ClassInfo* del super via findclass inline.
    const std::string &super_name = it->second.super_name;
    const uint64_t super_name_idx = intern_class_name(*out_mod_, super_name);
    const uint32_t super_name_len = static_cast<uint32_t>(super_name.size());
    // Sprint 5: findclass via IR ops.
    const ir::IrValueId v_cls =
        emit_findclass_by_name(super_name_idx, super_name_len, e->loc.line);
    // Emit CALLSUPER IR (mismo patron que super(args) ctor).
    ir::IrInstr cs{};
    cs.op = ir::IrOp::CALLSUPER;
    cs.type = ret_ir;
    cs.dst = dst;
    cs.operands.push_back(v_cls);
    cs.operands.push_back(v_this);
    for (auto av : arg_vals)
        cs.operands.push_back(av);
    cs.imm = static_cast<uint64_t>(found->vtable_index);
    cs.source_line = e->loc.line;
    emit(current_block_, std::move(cs));
    return dst;
}
} // namespace vx
