/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/async.cpp
 * @brief Bajada de lo que se ejecuta en otro sitio: `spawn`, `@Async` y el
 *        `spawn` remoto.
 *
 * Los tres tienen el mismo problema y por eso viven juntos: el cuerpo que se
 * escribio dentro de la funcion NO se ejecuta ahi.  Hay que sacarlo a una
 * funcion propia y averiguar QUE se lleva consigo -- los nombres que usa y no
 * define son capturas, y hay que pasarselos --.  Ese analisis es el grueso del
 * fichero; lo demas es la convencion con la que el proceso hijo recibe sus
 * argumentos y devuelve su resultado.
 */
#include "vx/lowering.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {

// BugFix R3: scan recursivo del body para detectar IdentExprs que
// referencian nombres NO definidos dentro del propio body.  Esos son
// candidatos a captures que el spawn helper recibira como params.
// Devuelve la lista de nombres unicos (orden de aparicion) que estan
// en el scope encerrante actual via @c lookup.
static void collect_spawn_captures_in_expr(
    const ast::Expr *e, std::unordered_set<std::string> &locals_defined,
    std::vector<std::string> &out_captures,
    std::unordered_set<std::string> &seen, Lowering &lw);

static void collect_spawn_captures_in_stmt(
    const ast::Stmt *s, std::unordered_set<std::string> &locals_defined,
    std::vector<std::string> &out_captures,
    std::unordered_set<std::string> &seen, Lowering &lw);

static void collect_spawn_captures_in_expr(
    const ast::Expr *e, std::unordered_set<std::string> &locals_defined,
    std::vector<std::string> &out_captures,
    std::unordered_set<std::string> &seen, Lowering &lw) {
    if (!e) return;
    switch (e->kind) {
    case ast::NodeKind::IdentExpr: {
        const auto *id = static_cast<const ast::IdentExpr *>(e);
        if (locals_defined.count(id->name)) return;
        if (seen.count(id->name)) return;
        // Buscar el nombre en TODOS los scopes activos del lowering.
        // Accedemos a scopes_ via friend-style desde el contexto
        // estatico (Lowering nos da acceso indirecto via lookup
        // publico mediante un wrapper inline).
        if (lw.spawn_capture_resolve_public(id->name) != ir::IR_NO_VALUE) {
            seen.insert(id->name);
            out_captures.push_back(id->name);
        }
        return;
    }
    case ast::NodeKind::FieldAccessExpr: {
        const auto *fa = static_cast<const ast::FieldAccessExpr *>(e);
        collect_spawn_captures_in_expr(fa->base.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::BinaryExpr: {
        const auto *b = static_cast<const ast::BinaryExpr *>(e);
        collect_spawn_captures_in_expr(b->lhs.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(b->rhs.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::UnaryExpr: {
        const auto *u = static_cast<const ast::UnaryExpr *>(e);
        collect_spawn_captures_in_expr(u->operand.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::AssignExpr: {
        const auto *a = static_cast<const ast::AssignExpr *>(e);
        collect_spawn_captures_in_expr(a->target.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(a->value.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::CallExpr: {
        const auto *c = static_cast<const ast::CallExpr *>(e);
        collect_spawn_captures_in_expr(c->callee.get(), locals_defined,
                                       out_captures, seen, lw);
        for (const auto &a : c->args)
            collect_spawn_captures_in_expr(a.get(), locals_defined,
                                           out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::IndexExpr: {
        const auto *ix = static_cast<const ast::IndexExpr *>(e);
        collect_spawn_captures_in_expr(ix->base.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(ix->index.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::NewExpr: {
        const auto *n = static_cast<const ast::NewExpr *>(e);
        for (const auto &a : n->args)
            collect_spawn_captures_in_expr(a.get(), locals_defined,
                                           out_captures, seen, lw);
        if (n->array_size)
            collect_spawn_captures_in_expr(n->array_size.get(), locals_defined,
                                           out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::CastExpr: {
        const auto *c = static_cast<const ast::CastExpr *>(e);
        collect_spawn_captures_in_expr(c->operand.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::TernaryExpr: {
        const auto *t = static_cast<const ast::TernaryExpr *>(e);
        collect_spawn_captures_in_expr(t->cond.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(t->then_expr.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(t->else_expr.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    default: return;
    }
}

static void collect_spawn_captures_in_stmt(
    const ast::Stmt *s, std::unordered_set<std::string> &locals_defined,
    std::vector<std::string> &out_captures,
    std::unordered_set<std::string> &seen, Lowering &lw) {
    if (!s) return;
    switch (s->kind) {
    case ast::NodeKind::BlockStmt: {
        const auto *b = static_cast<const ast::BlockStmt *>(s);
        for (const auto &st : b->body)
            collect_spawn_captures_in_stmt(st.get(), locals_defined,
                                           out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::VarDeclStmt: {
        const auto *v = static_cast<const ast::VarDeclStmt *>(s);
        if (v->init)
            collect_spawn_captures_in_expr(v->init.get(), locals_defined,
                                           out_captures, seen, lw);
        locals_defined.insert(v->name);
        return;
    }
    case ast::NodeKind::ExprStmt: {
        const auto *e = static_cast<const ast::ExprStmt *>(s);
        collect_spawn_captures_in_expr(e->expr.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::IfStmt: {
        const auto *i = static_cast<const ast::IfStmt *>(s);
        collect_spawn_captures_in_expr(i->cond.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_stmt(i->then_branch.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_stmt(i->else_branch.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::WhileStmt: {
        const auto *w = static_cast<const ast::WhileStmt *>(s);
        collect_spawn_captures_in_expr(w->cond.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_stmt(w->body.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::ForStmt: {
        const auto *f = static_cast<const ast::ForStmt *>(s);
        collect_spawn_captures_in_stmt(f->init.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(f->cond.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(f->step.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_stmt(f->body.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::SynchronizedStmt: {
        const auto *sy = static_cast<const ast::SynchronizedStmt *>(s);
        collect_spawn_captures_in_expr(sy->target.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_stmt(sy->body.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::ReturnStmt: {
        const auto *r = static_cast<const ast::ReturnStmt *>(s);
        if (r->value)
            collect_spawn_captures_in_expr(r->value.get(), locals_defined,
                                           out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::ThrowStmt: {
        const auto *t = static_cast<const ast::ThrowStmt *>(s);
        if (t->value)
            collect_spawn_captures_in_expr(t->value.get(), locals_defined,
                                           out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::TryStmt: {
        // Bug fix audit Z.2: scan recursivo del try body + catches + finally.
        // Sin esto, capturas usadas dentro de try{} se reportan como
        // "nombre no resuelto" en el spawn body.
        const auto *t = static_cast<const ast::TryStmt *>(s);
        if (t->body)
            collect_spawn_captures_in_stmt(
                static_cast<const ast::Stmt *>(t->body.get()), locals_defined,
                out_captures, seen, lw);
        for (const auto &cc : t->catches) {
            if (cc.body)
                collect_spawn_captures_in_stmt(
                    static_cast<const ast::Stmt *>(cc.body.get()),
                    locals_defined, out_captures, seen, lw);
        }
        if (t->finally_body)
            collect_spawn_captures_in_stmt(
                static_cast<const ast::Stmt *>(t->finally_body.get()),
                locals_defined, out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::DoWhileStmt: {
        const auto *dw = static_cast<const ast::DoWhileStmt *>(s);
        collect_spawn_captures_in_stmt(dw->body.get(), locals_defined,
                                       out_captures, seen, lw);
        collect_spawn_captures_in_expr(dw->cond.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    case ast::NodeKind::ForEachStmt: {
        const auto *fe = static_cast<const ast::ForEachStmt *>(s);
        collect_spawn_captures_in_expr(fe->iter_expr.get(), locals_defined,
                                       out_captures, seen, lw);
        locals_defined.insert(fe->iter_name);
        collect_spawn_captures_in_stmt(fe->body.get(), locals_defined,
                                       out_captures, seen, lw);
        return;
    }
    default: return;
    }
}

std::string Lowering::generate_spawn_helper(ast::BlockStmt *body,
                                            const SourceLoc &loc) {
    const size_t spawn_idx = spawn_func_counter_++;
    const std::string fn_name = "__spawn_" + std::to_string(spawn_idx);

    // BugFix R3: pre-scan del body para detectar capturas (idents
    // libres que estan en el scope encerrante).  Cada captura se
    // pasara como param al helper via la convencion @c spawnargs.
    std::vector<std::string> captures;
    {
        std::unordered_set<std::string> locals_defined;
        std::unordered_set<std::string> seen;
        collect_spawn_captures_in_stmt(body, locals_defined, captures, seen,
                                       *this);
        // Limitamos a 11 captures (R1..R12 menos el implicit return reg).
        if (captures.size() > 11) {
            error_at(
                loc,
                "spawn { body }: maximo 11 capturas soportadas (recibidos " +
                    std::to_string(captures.size()) + ")");
            captures.resize(11);
        }
    }
    // Capturar los SSA values de las capturas en el caller ANTES de
    // cambiar de contexto.  Esos seran los args de spawnargs.
    spawn_captured_ssa_values_.clear();
    spawn_captured_names_ = captures;
    for (const auto &nm : captures) {
        ir::IrValueId v = lookup(nm);
        spawn_captured_ssa_values_.push_back(v);
    }

    //  Z.9: escape analysis cross-process.  Para cada captura que
    // es un objeto GC (is_gc_object=true en su SSA value) Y NO fue
    // declarada con @c shared, emitir warning con sugerencia clara.
    // Esto detecta el bug clasico (t13): pasar un objeto local al
    // spawn body, que no puede resolverlo cross-process.
    for (size_t i = 0; i < captures.size(); ++i) {
        const ir::IrValueId v = spawn_captured_ssa_values_[i];
        if (v == ir::IR_NO_VALUE) continue;
        if (v >= fn_->values.size()) continue;
        const auto &val = fn_->values[v];
        // Solo warn para GC objects (host_ptrs a objetos GC).
        if (!val.is_gc_object) continue;
        // Si el local fue declarado con @c shared, todo OK.
        if (shared_locals_.count(captures[i])) continue;
        // Sugerencia con loc del spawn (no del var-decl original; el
        // user vera el spawn body que es donde el problema importa).
        diags_.warning(
            loc, "spawn captura '" + captures[i] +
                     "' (objeto GC local-only); el child no podra resolver el "
                     "host_ptr cross-process.\n"
                     "  sugerencia: declara con 'shared': `shared T " +
                     captures[i] + " = new T();`  o llama `" + captures[i] +
                     " = share(" + captures[i] + ")` antes del spawn.");
    }

    /* Estamos dentro de la funcion padre que invoca spawn: el guarda se lleva
     * su contexto y lo devuelve solo al salir de este alcance. */
    ChildFunctionScope parent(*this);

    ir::IrFunction child_fn;
    child_fn.name = fn_name;
    child_fn.ret_type = ir::IrType::VOID;
    const ir::IrBlockId entry = child_fn.new_block("entry");

    fn_ = &child_fn;
    current_block_ = entry;
    push_scope();

    // Registrar las capturas.
    // - Ruta VM (no native_poo): cada captura es un PARAM del helper que llega
    //   via la calling convention spawnargs (R1, R2, ...).
    // - Ruta AOT (native_poo, hilo real): CreateThread/pthread pasan UN SOLO
    // arg
    //   -> el helper recibe UN param `cap_ptr` (host_ptr a un struct heap con
    //   las N capturas, alocado por el caller); las LEE de cap_ptr[i], bindea
    //   los nombres, y LIBERA el struct (RAW_FREE) tras leerlas.
    if (native_poo_ && !captures.empty()) {
        ir::IrValueId cap_ptr =
            child_fn.new_value(ir::IrType::PTR, "%__cap_ptr");
        child_fn.values[cap_ptr].is_param = true;
        child_fn.values[cap_ptr].is_host_ptr = true;
        child_fn.params.push_back(cap_ptr);
        for (size_t i = 0; i < captures.size(); ++i) {
            // addr = cap_ptr + i*8  (mantiene is_host_ptr).
            ir::IrValueId addr = cap_ptr;
            if (i != 0) {
                addr = child_fn.new_value(ir::IrType::PTR);
                child_fn.values[addr].is_host_ptr = true;
                ir::IrValueId off = emit_const(
                    ir::IrType::I64, static_cast<int64_t>(i * 8), loc.line);
                ir::IrInstr ad{};
                ad.op = ir::IrOp::ADD;
                ad.type = ir::IrType::PTR;
                ad.dst = addr;
                ad.operands = {cap_ptr, off};
                ad.source_line = loc.line;
                emit(current_block_, std::move(ad));
            }
            // val = LOAD [addr] (host, qword).
            ir::IrValueId val =
                child_fn.new_value(ir::IrType::I64, "%" + captures[i]);
            if (spawn_captured_ssa_values_[i] != ir::IR_NO_VALUE &&
                spawn_captured_ssa_values_[i] <
                    parent.parent_fn()->values.size()) {
                const auto &src_val =
                    parent.parent_fn()->values[spawn_captured_ssa_values_[i]];
                if (src_val.is_host_ptr)
                    child_fn.values[val].is_host_ptr = true;
                if (src_val.is_gc_object)
                    child_fn.values[val].is_gc_object = true;
            }
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            ld.type = ir::IrType::I64;
            ld.dst = val;
            ld.operands = {addr};
            ld.source_line = loc.line;
            emit(current_block_, std::move(ld));
            scopes_.back()[captures[i]] = val;
        }
        // Liberar el struct de capturas (ya leidas a locales).
        ir::IrInstr fr{};
        fr.op = ir::IrOp::RAW_FREE;
        fr.type = ir::IrType::VOID;
        fr.dst = ir::IR_NO_VALUE;
        fr.operands = {cap_ptr};
        fr.source_line = loc.line;
        emit(current_block_, std::move(fr));
    } else {
        // BugFix R3: capturas como params (R1..R12) via spawnargs (ruta VM).
        for (size_t i = 0; i < captures.size(); ++i) {
            ir::IrValueId v =
                child_fn.new_value(ir::IrType::I64, "%" + captures[i]);
            child_fn.values[v].is_param = true;
            // Si el SSA value original era host_ptr CLASS, propagarlo.
            if (spawn_captured_ssa_values_[i] != ir::IR_NO_VALUE &&
                spawn_captured_ssa_values_[i] <
                    parent.parent_fn()->values.size()) {
                const auto &src_val =
                    parent.parent_fn()->values[spawn_captured_ssa_values_[i]];
                if (src_val.is_host_ptr) child_fn.values[v].is_host_ptr = true;
                if (src_val.is_gc_object)
                    child_fn.values[v].is_gc_object = true;
            }
            child_fn.params.push_back(v);
            // Bindear el nombre en el topmost scope para que IdentExpr
            // resuelva via @c lookup.
            scopes_.back()[captures[i]] = v;
        }
    }

    // Setup de pila: ahora lo hace exec_instr_spawn directamente al
    // crear el proceso hijo (rsp/rbp = base unica por local_pid).
    // El frontend solo necesita asegurarse de que las instrucciones
    // de `enter`/`leave` y las locales caben en la region (1 MiB
    // por defecto, mas que suficiente para spawn bodies tipicos).

    /* Mientras se baja el cuerpo, un `return` escrito a mano tiene que acabar
     * igual que llegar al final: parando el proceso.  Se dice aqui porque el
     * cuerpo puede llevar dentro otra cosa que se baje aparte -- una lambda --
     * y esa si es una funcion de verdad. */
    is_spawn_body_ = true;
    if (body) lower_block(body);

    if (!block_terminated_) emit_process_body_end(loc.line);

    pop_scope();
    // Guardar el helper en la cola pendiente; se añadira a out_mod_
    // al final de run() para que main se mantenga como primera funcion
    // (el emisor IR la trata como entry point y termina con hlt).
    pending_spawn_helpers_.push_back(std::move(child_fn));

    return fn_name;
}

// ---------------------------------------------------------------------
// rspawn helper generator.  Identico a generate_spawn_helper
// pero con `is_rspawn_body_ = true` activado mientras se baja el body
// para que cualquier `return X` se intercepte en `lower_return` y se
// transforme en `mov r0, X + hlt`.  El runtime distribuido captura R0
// al detectar HALT en un proceso con `rspawn_future_id != 0` y envia
// VDP_FUTURE_FULFILL al nodo origen con ese valor.
// ---------------------------------------------------------------------
std::string Lowering::generate_rspawn_helper(ast::BlockStmt *body,
                                             const SourceLoc &loc) {
    const size_t spawn_idx = spawn_func_counter_++;
    const std::string fn_name = "__rspawn_" + std::to_string(spawn_idx);

    // Guardar contexto del lowering del padre.
    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction child_fn;
    child_fn.name = fn_name;
    child_fn.ret_type = ir::IrType::VOID;
    const ir::IrBlockId entry = child_fn.new_block("entry");

    fn_ = &child_fn;
    current_block_ = entry;
    push_scope();
    is_rspawn_body_ = true; // activar interception de return en lower_return

    if (body) lower_block(body);

    // Sprint 6.D: terminador HLT con R0=0 via IR op puro.
    if (!block_terminated_) {
        const ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, loc.line);
        ir::IrInstr h{};
        h.op = ir::IrOp::HLT;
        h.type = ir::IrType::VOID;
        h.dst = ir::IR_NO_VALUE;
        h.operands = {v_zero};
        h.source_line = loc.line;
        emit(current_block_, std::move(h));
        block_terminated_ = true;
    }

    pop_scope();
    pending_spawn_helpers_.push_back(std::move(child_fn));

    return fn_name;
}

ir::IrValueId Lowering::lower_rspawn_expr(ast::RSpawnExpr *e) {
    if (!e || !e->body || !e->node_idx) {
        error_at(e ? e->loc : SourceLoc{},
                 "lowering: rspawn sin body o sin node_idx");
        return ir::IR_NO_VALUE;
    }
    // 1. Generar la funcion remota y obtener su nombre (label .vel).
    const std::string fn_name = generate_rspawn_helper(e->body.get(), e->loc);

    // 2. Cargar la direccion absoluta del helper en un SSA value.
    const ir::IrValueId v_pc = emit_label_addr(fn_name, e->loc.line);

    // 3. Bajar la expresion del node_idx y promover a I64.
    ir::IrValueId v_node = lower_expr(e->node_idx.get());
    if (v_node == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    const ir::IrType src_t = fn_->values[v_node].type;
    v_node = cast_if_needed(v_node, src_t, ir::IrType::I64, e->loc.line);

    // 4. RSPAWN IR op (0xD2): node_idx + fn_addr -> Future handle en R0.
    const ir::IrValueId v_fut = fn_->new_value(ir::IrType::I64);
    {
        ir::IrInstr rs{};
        rs.op = ir::IrOp::RSPAWN;
        rs.type = ir::IrType::I64;
        rs.dst = v_fut;
        // Convencion del IR emitter de RSPAWN: operands[0]=node_idx,
        // operands[1]=fn_addr.  Ver case IrOp::RSPAWN en ir_emitter.cpp.
        rs.operands = {v_node, v_pc};
        rs.is_call_site = true;
        rs.source_line = e->loc.line;
        emit(current_block_, std::move(rs));
    }
    return v_fut;
}

ir::IrValueId Lowering::lower_spawn_expr(ast::SpawnExpr *e) {
    if (!e || !e->body) {
        error_at(e ? e->loc : SourceLoc{}, "lowering: spawn sin body");
        return ir::IR_NO_VALUE;
    }
    // 1. Generar la funcion hijo y obtener su nombre (label .vel).
    const std::string fn_name = generate_spawn_helper(e->body.get(), e->loc);

    // 2. Emit RAW_ASM en el bloque actual del padre:
    //    a) cargar la direccion absoluta de fn_name en {dst_pc}.
    //    b) ejecutar `spawn {dst_pc}` (Auto) o `spawnon {dst_pc}, {src1}`
    //       (Here / Pinned) segun la policy del SpawnExpr.
    //    c) capturar R0 al SSA value de la expresion via {dst}.
    const ir::IrValueId v_pc = emit_label_addr(fn_name, e->loc.line);

    // BugFix R3: si hay capturas, usar `spawnargs` en lugar de `spawn`.
    // Convencion: R1..R[N]=capturas, R15=N, spawnargs r_pc copia los
    // regs al child antes de make_ready.  Aplica para Auto policy.
    const auto &caps = spawn_captured_ssa_values_;

    // AOT/bare (native_poo_): `spawn { }` tiene DOS bajadas segun el body:
    //
    //  (A) COOPERATIVA (el body usa mailbox/future/await:
    //  msgrecv/msgsend/fulfill/
    //      future_alloc/await) -> es una TAREA del scheduler cooperativo de
    //      vx_async (single-thread, run-to-completion), NO un hilo paralelo.
    //      Baja a CALL __vx_spawn(body) que ENCOLA la tarea y devuelve un pid
    //      (que msgsend/await usan).  Identico a la semantica del
    //      interprete/JIT.
    //
    //  (B) HILO REAL del SO (cualquier otro body: computo puro / synchronized)
    //  via
    //      CALL __vx_thread_run (CreateThread en Win, pthread en Linux),
    //      bundle-ado desde vx_thread.vx.  El HANDLE se registra para el
    //      join-all implicito que se inyecta al final de main.  Capturas:
    //      struct heap (RAW_ALLOC N*8) que el helper LEE de cap_ptr[i] y
    //      libera; sin capturas, arg=0.
    //
    // La distincion refleja el modelo del lenguaje: async = cooperativo un
    // hilo; spawn de computo = paralelismo real.
    if (native_poo_ && caps.empty() && spawn_body_uses_coop(e->body.get())) {
        const ir::IrValueId v_pid = fn_->new_value(ir::IrType::I64);
        ir::IrInstr c{};
        c.op = ir::IrOp::CALL;
        c.type = ir::IrType::I64;
        c.dst = v_pid;
        c.func_name = "__vx_spawn"; // encola tarea cooperativa; devuelve pid
        c.operands = {v_pc};
        c.is_call_site = true;
        c.source_line = e->loc.line;
        emit(current_block_, std::move(c));
        // NO marca vx_thread_used_: no es hilo real; el await bombea la cola.
        return v_pid;
    }
    if (native_poo_) {
        vx_thread_used_ = true;
        ir::IrValueId v_arg;
        if (caps.empty()) {
            v_arg = emit_const(ir::IrType::I64, 0, e->loc.line);
        } else {
            ir::IrValueId v_size =
                emit_const(ir::IrType::I64,
                           static_cast<int64_t>(caps.size() * 8), e->loc.line);
            ir::IrValueId cap_ptr = fn_->new_value(ir::IrType::PTR);
            fn_->values[cap_ptr].is_host_ptr = true;
            ir::IrInstr al{};
            al.op = ir::IrOp::RAW_ALLOC;
            al.type = ir::IrType::PTR;
            al.dst = cap_ptr;
            al.operands = {v_size};
            al.source_line = e->loc.line;
            emit(current_block_, std::move(al));
            for (size_t i = 0; i < caps.size(); ++i) {
                ir::IrValueId addr = cap_ptr;
                if (i != 0) {
                    addr = fn_->new_value(ir::IrType::PTR);
                    fn_->values[addr].is_host_ptr = true;
                    ir::IrValueId off =
                        emit_const(ir::IrType::I64, static_cast<int64_t>(i * 8),
                                   e->loc.line);
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::PTR;
                    ad.dst = addr;
                    ad.operands = {cap_ptr, off};
                    ad.source_line = e->loc.line;
                    emit(current_block_, std::move(ad));
                }
                emit_store_typed(addr, caps[i], ir::IrType::I64, e->loc.line);
            }
            v_arg = cap_ptr;
        }
        const ir::IrValueId v_pid = fn_->new_value(ir::IrType::I64);
        ir::IrInstr c{};
        c.op = ir::IrOp::CALL;
        c.type = ir::IrType::I64;
        c.dst = v_pid;
        c.func_name = "__vx_thread_run";
        c.operands = {v_pc, v_arg};
        c.is_call_site = true;
        c.source_line = e->loc.line;
        emit(current_block_, std::move(c));
        return v_pid;
    }

    if (e->policy == ast::SpawnExpr::Policy::Auto && !caps.empty()) {
        // raw_asm-elim wave 2: usar IrOp::SPAWN_ARGS nativo en lugar de
        // raw_asm.  El IR emitter ya genera el parallel-move correcto
        // del regalloc + spawnargs + restore.  operands[0]=r_pc,
        // [1..N]=args; dst=PID encoded en R0.
        const ir::IrValueId v_pid = fn_->new_value(ir::IrType::I64);
        std::vector<ir::IrValueId> ops;
        ops.push_back(v_pc);
        for (auto v : caps)
            ops.push_back(v);
        ir::IrInstr sa{};
        sa.op = ir::IrOp::SPAWN_ARGS;
        sa.type = ir::IrType::I64;
        sa.dst = v_pid;
        sa.operands = std::move(ops);
        sa.source_line = e->loc.line;
        sa.is_call_site = true;
        emit(current_block_, std::move(sa));
        return v_pid;
    }

    // si la policy es Auto, mantener el opcode SPAWN
    // (sin overhead).  Para Here y Pinned usar SPAWN_ON con el hint en
    // el segundo registro:
    //   - Here:   hint = -1 (signed) -> mismo scheduler que el padre.
    //   - Pinned: hint = expr        -> scheduler hint % num_schedulers.
    if (e->policy == ast::SpawnExpr::Policy::Auto) {
        // SPAWN IR op (0xF3): crea proceso hijo, PID encoded en R0/dst.
        const ir::IrValueId v_pid = fn_->new_value(ir::IrType::I64);
        ir::IrInstr sp{};
        sp.op = ir::IrOp::SPAWN;
        sp.type = ir::IrType::I64;
        sp.dst = v_pid;
        sp.operands = {v_pc};
        sp.is_call_site = true;
        sp.source_line = e->loc.line;
        emit(current_block_, std::move(sp));
        return v_pid;
    }

    // Construir el SSA value del hint segun la policy.
    ir::IrValueId v_hint = ir::IR_NO_VALUE;
    if (e->policy == ast::SpawnExpr::Policy::Here) {
        // hint = -1 como i64 inmediato.
        v_hint = emit_const(ir::IrType::I64, static_cast<uint64_t>(-1LL),
                            e->loc.line);
    } else {
        // Pinned
        if (!e->sched_idx) {
            error_at(e->loc, "lowering: spawn on(...) sin expresion");
            return ir::IR_NO_VALUE;
        }
        v_hint = lower_expr(e->sched_idx.get());
        if (v_hint == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        // Promover a I64 si es necesario para que el runtime lea int64.
        const ir::IrType src_t = fn_->values[v_hint].type;
        v_hint = cast_if_needed(v_hint, src_t, ir::IrType::I64, e->loc.line);
    }

    // spawn_on IR op: combines fn_addr + hint -> PID encoded en R0.
    const ir::IrValueId v_pid = fn_->new_value(ir::IrType::I64);
    ir::IrInstr sp{};
    sp.op = ir::IrOp::SPAWN_ON;
    sp.type = ir::IrType::I64;
    sp.dst = v_pid;
    sp.operands = {v_pc, v_hint};
    sp.is_call_site = true;
    sp.source_line = e->loc.line;
    emit(current_block_, std::move(sp));
    return v_pid;
}

void Lowering::lower_async_function(ast::FunctionDecl *fd, ir::IrModule &out) {
    if (!fd || !fd->body) {
        error_at(fd ? fd->loc : SourceLoc{}, "@Async: funcion sin body");
        return;
    }
    const std::string helper_name = std::string("__async_") + fd->name;

    // Mejora II optimizada: numero de parametros del usuario.  Pasamos
    // los args al helper via @c spawnargs (R1..R[argc]) en lugar de
    // serializarlos a un buffer y enviarlos via msgsend.  El handle
    // del Future tambien viaja por R1 (slot 0 en la nueva calling
    // convention del helper: arg[0] = future handle, arg[1..N] = args).
    // Asi:
    //   - Wrapper: emit args en R2..R[N+1] + R1=fut + R15=N+1 + spawnargs.
    //     ~3 instr en lugar de ~12 (alloca + N+1 stores + msgsend).
    //   - Helper:  los params estan ya en R1..R[N+1], NO necesita
    //     ALLOCA + msgrecv + N+1 LOADs + casts.
    // Total: ~26 instr -> ~3 instr por @Async call (~9x mas rapido).
    const size_t n_params = fd->params.size();
    if (n_params + 1 > 12) {
        // Calling convention de spawnargs: R1..R[argc] con argc <= 12.
        // Reservamos R1 para el handle del Future, asi quedan 11 slots
        // para args del usuario.
        error_at(fd->loc, "@Async: numero de parametros excede el maximo (11)");
        return;
    }

    // ---------------------------------------------------------------
    // 1. Construir el SPAWN HELPER (lo encolamos en pending_spawn_helpers_
    //    para que se vuelque al final, despues de main).
    // ---------------------------------------------------------------
    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);

    ir::IrFunction helper_fn;
    helper_fn.name = helper_name;
    helper_fn.ret_type = ir::IrType::VOID;
    const ir::IrBlockId entry = helper_fn.new_block("entry");

    fn_ = &helper_fn;
    current_block_ = entry;
    push_scope();

    // Mejora II optimizada: el helper recibe args directos en R1..R[N+1]
    // gracias a @c spawnargs (sin msgrecv + buffer).  Calling convention:
    //   R1         = handle del Future
    //   R2..R[N+1] = parametros del usuario en el orden declarado
    // Declarar formalmente los params como un IrFunction normal: el
    // primer param es el handle (siempre I64), el resto son los del
    // usuario con su tipo declarado.
    ir::IrValueId v_my_fut;
    {
        // Primer parametro IR: future handle (I64).
        v_my_fut = fn_->new_value(ir::IrType::I64, "__async_fut");
        fn_->values[v_my_fut].is_param = true;
        fn_->params.push_back(v_my_fut);
    }
    for (size_t pi = 0; pi < n_params; ++pi) {
        auto &p = fd->params[pi];
        /* Un parametro se ve igual desde el IR aqui que en cualquier otra
         * funcion: la anchura y el signo son parte de la convencion de
         * llamada, y quien llama y quien es llamado tienen que coincidir. */
        const ParamAbi abi = param_abi(*p);
        const ir::IrValueId pv = fn_->new_value(abi.type, p->name);
        fn_->values[pv].is_param = true;
        apply_type_memory(*fn_, pv, abi.mem);
        fn_->params.push_back(pv);
        bind(p->name, pv);
    }

    // 1b. Activar interception de return en lower_return.
    async_fut_id_ = v_my_fut;

    // 1c. Bajar el body original.  Cada `return X` -> fulfill + hlt.
    lower_block(fd->body.get());

    // 1d. Fallback: si el body cae naturalmente sin return, emitir
    //     fulfillhlt(my_fut, 0) para terminar el child con valor 0.
    //     Optimizado: 1 instr en lugar de fulfill+hlt separados.
    if (!block_terminated_) {
        const ir::IrValueId v_zero =
            emit_const(ir::IrType::I64, 0, fd->loc.line);
        emit_fulfill_hlt(v_my_fut, v_zero, fd->loc.line);
        block_terminated_ = true;
    }

    pop_scope();
    // Encolamos el helper para volcarse al final de run() (despues de
    // main para preservar el orden de entry point).
    pending_spawn_helpers_.push_back(std::move(helper_fn));

    /* El helper acaba aqui.  Lo que viene despues -- la envoltura publica que
     * el usuario llama -- es una funcion NORMAL: sale retornando, no
     * resolviendo el futuro, asi que deja de estar en un cuerpo asincrono. */
    async_fut_id_ = ir::IR_NO_VALUE;

    // ---------------------------------------------------------------
    // 2. Construir el WRAPPER publico con el nombre de la funcion.
    //    El wrapper recibe los args del usuario via la calling convention
    //    normal CALLVM (R1..R12), aloca un Future, spawnea el helper,
    //    serializa (handle, args) en un buffer y los envia al helper
    //    via msgsend.  Devuelve el handle del Future al caller.
    // ---------------------------------------------------------------
    ir::IrFunction wrapper_fn;
    wrapper_fn.name = fd->name;
    wrapper_fn.ret_type = ir::IrType::I64; // bytecode level: handle
    const ir::IrBlockId w_entry = wrapper_fn.new_block("entry");

    fn_ = &wrapper_fn;
    current_block_ = w_entry;
    push_scope();

    // Mejora II: declarar los parametros del wrapper igual que en una
    // funcion normal.  Cada param se mapea a un IrType y se vincula
    // con su nombre para que su SSA value se pueda leer mas abajo
    // cuando serializamos los args al buffer.
    std::vector<ir::IrValueId> param_vals;
    param_vals.reserve(n_params);
    for (size_t pi = 0; pi < n_params; ++pi) {
        auto &p = fd->params[pi];
        /* La envoltura publica declara los MISMOS parametros que el ayudante:
         * es la que el usuario llama, asi que su firma tiene que ser la que el
         * resto del programa espera.  Aqui habia una lista a mano de doce
         * nombres, y lo que no estaba en ella -- un puntero, un struct, un
         * `usize`, un typedef -- caia al valor por omision. */
        const ParamAbi abi = param_abi(*p);
        const ir::IrValueId pv = fn_->new_value(abi.type, p->name);
        fn_->values[pv].is_param = true;
        apply_type_memory(*fn_, pv, abi.mem);
        fn_->params.push_back(pv);
        bind(p->name, pv);
        param_vals.push_back(pv);
    }

    // 2a. fut = future_alloc() via IR op FUTURE.
    const ir::IrValueId v_fut = fn_->new_value(ir::IrType::I64);
    {
        // AOT (native_poo_): CALL nativo __vx_future_new (scheduler coop).
        ir::IrInstr fu{};
        fu.op = native_poo_ ? ir::IrOp::CALL : ir::IrOp::FUTURE;
        if (native_poo_) fu.func_name = "__vx_future_new";
        fu.type = ir::IrType::I64;
        fu.dst = v_fut;
        fu.is_call_site = true;
        fu.source_line = fd->loc.line;
        emit(current_block_, std::move(fu));
    }

    // Mejora II optimizada: el wrapper usa IrOp::SPAWN_ARGS que aprovecha
    // el parallel-move del regalloc para colocar args correctamente en
    // R1..R[N+1] sin conflictos.  Calling convention:
    //   R1            = handle del Future
    //   R2..R[N+1]    = parametros del usuario coerced a i64
    //   R15           = N+1 (argc total, lo setea el emisor IR)
    //   spawnargs r_pc -> child PID encoded en R0 (devuelto al caller)
    //
    // Esto reemplaza la version previa con buffer + msgsend (~12 instr)
    // por ~2-3 instr fijas + N moves resueltos por parallel-move +
    // 1 spawnargs.  Elimina la contencion del lock del mailbox y la
    // copia de buffer.

    // 2b.1: Coerce cada param del usuario a i64 preservando bits.
    std::vector<ir::IrValueId> qword_args;
    qword_args.reserve(n_params);
    for (size_t pi = 0; pi < n_params; ++pi) {
        const ir::IrValueId v_param = param_vals[pi];
        const ir::IrType pt_ir = fn_->values[v_param].type;
        ir::IrValueId v_qword = v_param;
        if (pt_ir == ir::IrType::F64) {
            v_qword = emit_ir_unop(ir::IrOp::BITCAST, v_param, ir::IrType::I64,
                                   fd->loc.line);
        } else if (pt_ir == ir::IrType::F32) {
            ir::IrValueId v_i32 = emit_ir_unop(ir::IrOp::BITCAST, v_param,
                                               ir::IrType::I32, fd->loc.line);
            v_qword = cast_if_needed(v_i32, ir::IrType::I32, ir::IrType::I64,
                                     fd->loc.line);
        } else if (pt_ir != ir::IrType::I64 && pt_ir != ir::IrType::U64 &&
                   pt_ir != ir::IrType::PTR) {
            v_qword =
                cast_if_needed(v_param, pt_ir, ir::IrType::I64, fd->loc.line);
        }
        qword_args.push_back(v_qword);
    }

    // 2b.2: Cargar la direccion del helper en un SSA value PTR.
    const ir::IrValueId v_pc = emit_label_addr(helper_name, fd->loc.line);

    // SPAWN_ARGS dedicado.  El emisor IR usa parallel-move para
    // resolver conflictos al colocar args en sus regs destino.
    // Operands: [r_pc, fut, arg1, arg2, ..., argN]
    const ir::IrValueId v_child = fn_->new_value(ir::IrType::I64);
    if (native_poo_) {
        // AOT (native_poo_): scheduler cooperativo.  Args por PUNTERO (sin
        // limite de aridad ni bug de stack-args de Win64): construimos un
        // argbuf en la pila con [fut, args...], y llamamos
        //   __vx_spawn_argv(helper, argc, &argbuf[0])
        // que copia los args al slot de la tarea.  Al despacharla, pump castea
        // el body a `fn(...)` y lo llama (CALLCLOSURE) con los args.
        std::vector<ir::IrValueId> real_args;
        real_args.push_back(v_fut);
        for (auto v : qword_args)
            real_args.push_back(v);
        const uint64_t argc = real_args.size();
        // argbuf = ALLOCA(argc*8) en host-stack.
        const ir::IrValueId v_buf =
            stack_alloc_buf(argc * 8, fd->loc.line, true);
        // STORE cada arg en argbuf[i].
        for (size_t k = 0; k < real_args.size(); ++k) {
            ir::IrValueId slot = v_buf;
            if (k != 0) {
                slot = fn_->new_value(ir::IrType::PTR);
                const ir::IrValueId off =
                    emit_const(ir::IrType::I64, k * 8, fd->loc.line);
                ir::IrInstr ad{};
                ad.op = ir::IrOp::ADD;
                ad.type = ir::IrType::I64;
                ad.dst = slot;
                ad.operands = {v_buf, off};
                ad.source_line = fd->loc.line;
                emit(current_block_, std::move(ad));
                fn_->values[slot].is_host_ptr = true;
            }
            ir::IrInstr st{};
            st.op = ir::IrOp::STORE;
            st.type = ir::IrType::I64;
            st.operands = {real_args[k], slot};
            st.source_line = fd->loc.line;
            emit(current_block_, std::move(st));
        }
        const ir::IrValueId v_argc =
            emit_const(ir::IrType::I64, argc, fd->loc.line);
        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALL;
        ins.func_name = "__vx_spawn_argv";
        ins.type = ir::IrType::I64;
        ins.dst = v_child;
        ins.operands = {v_pc, v_argc, v_buf};
        ins.is_call_site = true;
        ins.source_line = fd->loc.line;
        emit(current_block_, std::move(ins));
    } else {
        ir::IrInstr ins{};
        ins.op = ir::IrOp::SPAWN_ARGS;
        ins.type = ir::IrType::I64;
        ins.dst = v_child;
        ins.operands.reserve(2 + n_params);
        ins.operands.push_back(v_pc);  // r_pc
        ins.operands.push_back(v_fut); // R1 = fut
        for (auto v : qword_args)      // R2..R[N+1] = args
            ins.operands.push_back(v);
        ins.source_line = fd->loc.line;
        emit(current_block_, std::move(ins));
    }
    (void)v_child; // no usado mas; el child ya esta ejecutando

    // 2c. return fut.
    {
        ir::IrInstr ret{};
        ret.op = ir::IrOp::RET;
        ret.type = ir::IrType::I64;
        ret.operands = {v_fut};
        ret.source_line = fd->loc.line;
        emit(current_block_, std::move(ret));
        block_terminated_ = true;
    }

    pop_scope();
    propagate_is_gc_object_through_phis(wrapper_fn);
    out.add_function(std::move(wrapper_fn));
}

/**
 * @brief Termina el cuerpo de un proceso: parar, o retornar en nativo.
 *
 * Un proceso de la maquina virtual acaba parando: su pila no tiene ninguna
 * direccion de retorno porque nadie lo llamo, lo LANZARON.  En un binario
 * nativo el mismo cuerpo ES la funcion de entrada de un hilo del sistema, que
 * se recoge cuando esa funcion retorna, asi que ahi si se retorna.
 *
 * La regla vive aqui porque el cuerpo tiene DOS finales posibles -- llegar al
 * ultimo statement, o escribir un `return` -- y antes solo el primero la
 * conocia.
 *
 * @param line Linea del fuente a la que atribuir la instruccion.
 */
void Lowering::emit_process_body_end(uint32_t line) {
    ir::IrInstr h{};
    h.op = native_poo_ ? ir::IrOp::RET : ir::IrOp::HLT;
    h.type = ir::IrType::VOID;
    h.dst = ir::IR_NO_VALUE;
    h.source_line = line;
    emit(current_block_, std::move(h));
    block_terminated_ = true;
}
} // namespace vx
