/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/exceptions.cpp
 * @brief Bajada de lo que altera el curso normal de una funcion: try/catch/
 *        finally, lanzar, y la seccion protegida por un monitor.
 *
 * Van juntas porque comparten el problema de fondo: al salir de un ambito por
 * una via que no es la normal hay que dejar las cosas como estaban -- soltar el
 * monitor, liberar lo que el ambito posee, ejecutar el `finally` -- y ese
 * desmontaje es el mismo tanto si se sale por el final, por un `return` o por
 * una excepcion.  Un `synchronized` es, en el fondo, un try/finally con el
 * desbloqueo dentro.
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
/**
 * @brief Apunta que nombres de FUERA se asignan dentro de un `try`.
 *
 * Hace falta porque lanzar salta a otro sitio con los registros a medias: una
 * variable que el `try` cambio puede estar en un registro que el salto se
 * lleva por delante, y el `catch` leeria basura.  A las que se listan aqui se
 * les da un hueco en memoria, que el salto no toca.
 *
 * Solo cuentan las que YA existian fuera: una declarada dentro del `try` no
 * sobrevive a el, asi que no hay nada que conservar.
 *
 * @param st    Sentencia por la que empezar.
 * @param outer Los nombres visibles al entrar.
 * @param out   Donde anñadir los que se asignan.
 */
/**
 * @brief Apunta que nombres de @p outer se asignan dentro de una expresion.
 *
 * Asignar es una EXPRESION en este lenguaje, asi que un `x = 5` puede estar
 * en cualquier sitio donde quepa un valor: dentro de una suma, como argumento
 * de una llamada, o en el inicializador de otra variable.  Buscarlo solo donde
 * la sentencia es una asignacion se deja fuera todos esos.
 *
 * @param e     Expresion por la que empezar.
 * @param outer Los nombres visibles al entrar al `try`.
 * @param out   Donde anñadir los que se asignan.
 */
static void scan_assigned_in_expr(
    const ast::Expr *e,
    const std::unordered_map<std::string, ir::IrValueId> &outer,
    std::unordered_set<std::string> &out) {
    if (!e) return;
    switch (e->kind) {
    case ast::NodeKind::AssignExpr: {
        auto *ae = static_cast<const ast::AssignExpr *>(e);
        if (ae->target && ae->target->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<const ast::IdentExpr *>(ae->target.get());
            if (outer.count(id->name)) out.insert(id->name);
        }
        scan_assigned_in_expr(ae->value.get(), outer, out);
        return;
    }
    case ast::NodeKind::BinaryExpr: {
        auto *be = static_cast<const ast::BinaryExpr *>(e);
        scan_assigned_in_expr(be->lhs.get(), outer, out);
        scan_assigned_in_expr(be->rhs.get(), outer, out);
        return;
    }
    case ast::NodeKind::CallExpr: {
        auto *ce = static_cast<const ast::CallExpr *>(e);
        for (auto &a : ce->args)
            scan_assigned_in_expr(a.get(), outer, out);
        return;
    }
    default: return;
    }
}

static void
scan_assigned_names(const ast::Stmt *st,
                    const std::unordered_map<std::string, ir::IrValueId> &outer,
                    std::unordered_set<std::string> &out) {
    if (!st) return;
    // Casos relevantes: ExprStmt con AssignExpr o BinaryExpr con
    // op=ASSIGN; BlockStmt con multiples stmts; If con then/else;
    // While/For con body; ReturnStmt; throw, try (anidado).
    switch (st->kind) {
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<const ast::ExprStmt *>(st);
        scan_assigned_in_expr(es->expr.get(), outer, out);
        break;
    }
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<const ast::BlockStmt *>(st);
        for (auto &s2 : b->body)
            scan_assigned_names(s2.get(), outer, out);
        break;
    }
    case ast::NodeKind::IfStmt: {
        auto *ifs = static_cast<const ast::IfStmt *>(st);
        scan_assigned_names(ifs->then_branch.get(), outer, out);
        scan_assigned_names(ifs->else_branch.get(), outer, out);
        break;
    }
    case ast::NodeKind::WhileStmt: {
        auto *ws = static_cast<const ast::WhileStmt *>(st);
        scan_assigned_names(ws->body.get(), outer, out);
        break;
    }
    case ast::NodeKind::ForStmt: {
        auto *fs = static_cast<const ast::ForStmt *>(st);
        scan_assigned_names(fs->body.get(), outer, out);
        break;
    }
    case ast::NodeKind::TryStmt: {
        auto *ts = static_cast<const ast::TryStmt *>(st);
        scan_assigned_names(ts->body.get(), outer, out);
        for (auto &cc : ts->catches)
            scan_assigned_names(cc.body.get(), outer, out);
        if (ts->finally_body)
            scan_assigned_names(ts->finally_body.get(), outer, out);
        break;
    }
    case ast::NodeKind::VarDeclStmt: {
        // var-decl introduce nuevo nombre; el init expr
        // puede contener assigns a otras vars.
        auto *vd = static_cast<const ast::VarDeclStmt *>(st);
        if (vd->init) scan_assigned_in_expr(vd->init.get(), outer, out);
        break;
    }
    default: break;
    }
}

void Lowering::lower_try(ast::TryStmt *s) {
    if (!s->body) {
        error_at(s->loc, "lowering: try sin body");
        return;
    }
    if (s->catches.empty() && !s->finally_body) return;

    // Snapshot del scope ANTES del try.  Necesario para
    // detectar variables modificadas dentro del body o de algun
    // catch y emitir PHI nodes en el merge.  Sin esto, el binding
    // del nombre tras el try queda con el del UlTIMO branch lowered
    // (no determinista) y, en runtime, el regalloc puede colocar la
    // variable en registros distintos en cada rama -> el merge lee
    // el registro equivocado.  Ej: `i32 v=0; try { v=42; } catch
    // (E e) { v=99; } println(v);` antes y devolvia basura.
    // Snapshot del scope chain APLANADO: combina todos los scopes
    // visibles desde el current_block_ en un solo mapa, con el
    // innermost ganando en caso de colision.  Necesario para que
    // `this` y los parametros del metodo (que viven en el outer
    // scope, NO en scopes_.back()) sean spillables a traves de
    // try/catch.  Sin esto, entry_bindings.find("this") fallaba y
    // la reload del catch leia basura.
    std::unordered_map<std::string, ir::IrValueId> entry_bindings;
    for (const auto &sc : scopes_) {
        for (const auto &kv : sc) {
            entry_bindings[kv.first] = kv.second; // innermost wins
        }
    }

    // Pre-scan: detectar variables del scope outer que se
    // asignan dentro del body o de algun catch.  Reservamos un slot
    // 8 bytes para cada una y guardamos su valor de entrada.
    // Durante el body+catches, write_local emite STORE adicional al
    // slot.  En el merge LOAD del slot -> bind nombre.  Esto evita
    // el problema del regalloc: el throw salta los pop pendientes
    // pero el slot vive en stack VM y conserva el valor correcto.
    std::unordered_set<std::string> assigned_in_try;
    scan_assigned_names(s->body.get(), entry_bindings, assigned_in_try);
    for (const auto &cc : s->catches)
        scan_assigned_names(cc.body.get(), entry_bindings, assigned_in_try);

    // Pre-scan adicional: detectar variables del scope outer que se
    // LEEN dentro de los catches (incluyendo `this` y parametros del
    // metodo).  Sin esto, un throw clobreaba los registros y el
    // catch leia basura: por ejemplo `try { foo(); } catch (E e)
    // { this.dlog(...); }` fallaba con CALLVIRT null porque r1
    // (this) ya no era valido tras el throw.  Tratamos READ-en-catch
    // igual que assign-en-body: spill al entry value y reload por LOAD
    // en el merge.  Cubre `this`, parametros, locales no-modificadas
    // y cualquier otro binding del entry scope.
    // NOTA: solo escaneamos los CATCH bodies (no el try-body) porque
    // dentro del try-body los registros se mantienen normales hasta
    // el throw; el problema es post-throw -> handler.
    for (const auto &cc : s->catches)
        scan_read_names_stmt(cc.body.get(), assigned_in_try);
    if (s->finally_body)
        scan_read_names_stmt(s->finally_body.get(), assigned_in_try);

    // Reservar slots y guardar entry value para cada var asignada.
    // Save try_spill_slots_ previo (puede haber try anidado).
    auto saved_spill_slots = try_spill_slots_;
    for (const auto &name : assigned_in_try) {
        // Solo si no esta ya address-taken (otro mecanismo cubre).
        if (address_taken_locals_.count(name)) continue;
        // Alocar slot 8 bytes y STORE entry value.
        ir::IrValueId v_slot = stack_alloc_buf(8, s->loc.line);
        // STORE entry binding al slot (sera visible en catch via LOAD).
        auto it_e = entry_bindings.find(name);
        if (it_e != entry_bindings.end() && it_e->second != ir::IR_NO_VALUE) {
            // Usar el tipo real del valor (no i64 hardcoded) para
            // que la STORE coincida con la LOAD posterior y no haya
            // ambiguedad sobre los bytes altos del slot 8-byte.
            ir::IrType st_ty = ir::IrType::I64;
            if (it_e->second < fn_->values.size()) {
                st_ty = fn_->values[it_e->second].type;
            }
            emit_store_typed(v_slot, it_e->second, st_ty, s->loc.line);
        }
        try_spill_slots_[name] = v_slot;
    }

    // Multi-catch: cada catch tiene su propio tryenter ANTES del body.
    // El runtime apila los frames; do_throw los recorre desde el tope
    // (el ultimo apilado se prueba primero).  Para que el ORDEN
    // textual del codigo Vesta se respete (catch[0] se prueba primero),
    // apilamos los catches en orden INVERSO: ultimo primero, primero
    // ultimo (queda en el tope).
    const size_t n_catches = s->catches.size();
    std::vector<ir::IrBlockId> handler_bbs;
    handler_bbs.reserve(n_catches);
    for (size_t i = 0; i < n_catches; ++i) {
        handler_bbs.push_back(fn_->new_block("try_handler"));
    }
    const ir::IrBlockId body_bb = fn_->new_block("try_body");
    const ir::IrBlockId merge_bb = fn_->new_block("try_merge");

    // ---------------------------------------------------------------
    // AOT/Embed (native_poo_): modelo setjmp/longjmp (sin VM runtime).
    // En vez de N TRYENTER + br body, emitimos UN frame catch-all:
    //   buf = ALLOCA(96); __vx_push_frame(buf, 0); r = __vx_setjmp(buf);
    //   br_cond r ? handler[0] : body   (r!=0 = el longjmp reanudo).
    // v1: type matching = catch-all (el throw no transporta tipo aun);
    // multi-catch enruta todo a handler[0].  Las funciones __vx_* viven
    // en stdlib/vx/vx_exc.vx (enlazado en el .exe AOT).
    // ---------------------------------------------------------------
    if (native_poo_) {
        emit_try_frame_native(s, body_bb, handler_bbs);
    } else {
        // bloque del path VM (TRYENTER): cerrar el scope de sus locales
        // (br_to_body, etc.) ANTES del label try_after_entry para que el
        // goto del path native no salte sobre destructores en scope.
        // 1. Por cada catch (en orden inverso): emitir handler_pc + type
        //    como SSA values con {dst}/{src} substitution, luego emitir
        //    tryenter con esos SSA values.  CRITICO: NO usar mov r1/r2
        //    hardcoded (destruiria SSA values vivos del caller, e.g. el
        //    target de un synchronized o cualquier variable local que el
        //    regalloc haya colocado en r1 o r2).
        for (size_t i = n_catches; i > 0; --i) {
            const size_t ci = i - 1;
            const ast::CatchClause &cc = s->catches[ci];
            const std::string handler_label =
                fn_->name + "_" + fn_->blocks[handler_bbs[ci]].name;

            // type SSA value: 0 (catch-all) o findclass(name).
            ir::IrValueId v_type = ir::IR_NO_VALUE;
            if (cc.exc_class_name.empty()) {
                v_type = emit_const(ir::IrType::I64, 0, cc.loc.line);
            } else {
                // Sprint 5: emit_findclass_by_name reemplaza la RAW_ASM
                // textual con secuencia IR pura (ALLOCA + STORE + FINDCLASS).
                const uint64_t cls_idx =
                    intern_class_name(*out_mod_, cc.exc_class_name);
                const uint32_t cls_len =
                    static_cast<uint32_t>(cc.exc_class_name.size());
                v_type = emit_findclass_by_name(cls_idx, cls_len, cc.loc.line);
            }

            // 1b. handler_pc SSA value via LABEL_ADDR IR op (Sprint 3).
            const ir::IrValueId v_handler_pc =
                emit_label_addr(handler_label, cc.loc.line);

            // 1c. tryenter usando los dos SSA values.  El regalloc los
            // coloca en regs disponibles (NO clobbers SSA values vivos).
            {
                ir::IrInstr ra{};
                ra.op = ir::IrOp::TRYENTER;
                ra.type = ir::IrType::VOID;
                ra.dst = ir::IR_NO_VALUE;
                ra.operands = {v_handler_pc, v_type};
                /* Bloque handler (catch) en target_block: lo usa el backend JIT
                 * (Opcion B in-JIT catch) para capturar la direccion nativa del
                 * catch (LEA_LABEL) y registrar el edge abnormal (extra_succs)
                 * para la liveness/force-spill.  El interp lo ignora (usa
                 * v_handler_pc bytecode). */
                ra.target_block = handler_bbs[ci];
                /* imm = 1 si el catch puede capturar un AV de OS (catch-all o
                 * FatalError): el in-JIT catch es inseguro en ese caso (el path
                 * av_recovery longjmp-ea al scheduler y throw_fatal/do_throw
                 * corren sobre la region de stack del frame JIT muerto,
                 * clobbeando sus slots antes del resume).  El backend JIT baila
                 * -> esos try corren en interp (correcto, como antes).  Los
                 * catch de tipo-usuario (no-AV) SI van in-JIT. */
                ra.imm = (cc.exc_class_name.empty() ||
                          cc.exc_class_name == "FatalError")
                             ? 1u
                             : 0u;
                ra.source_line = cc.loc.line;
                emit(current_block_, std::move(ra));
            }
        }

        // br body_bb.
        emit_br(body_bb, s->loc.line);
        // Edges fantasmas a cada handler (alcanzables via excepcion).
        for (ir::IrBlockId hb : handler_bbs) {
            fn_->blocks[current_block_].succs.push_back(hb);
            fn_->blocks[hb].preds.push_back(current_block_);
        }
    }

    // Helper local: emite el bloque finally (clonado en cada salida) y
    // luego un branch al merge.  El finally en MVP se INLINEA en cada
    // exit point; alternativa mas eficiente es un bloque compartido
    // con tabla de continuaciones (outer de scope).
    auto emit_finally_then_merge = [&](ir::IrBlockId from, uint32_t line) {
        (void)from;
        if (s->finally_body) {
            lower_stmt(s->finally_body.get());
            if (block_terminated_) return; // finally returned/threw
        }
        emit_br(merge_bb, line);
        block_terminated_ = true;
    };

    // 2. Body del try.
    current_block_ = body_bb;
    block_terminated_ = false;
    lower_stmt(s->body.get());

    // Snapshot post-body para PHI.  Si el body alcanza el
    // merge (no terminado por return/throw/break), guardamos su
    // binding final para cada variable que diferia del entry.
    std::unordered_map<std::string, ir::IrValueId> body_bindings;
    ir::IrBlockId body_pred = ir::IR_NO_BLOCK;
    bool body_reaches_merge = false;
    if (!block_terminated_) {
        body_bindings = scopes_.back();
        body_pred = current_block_;
        body_reaches_merge = true;

        if (native_poo_) {
            // AOT: salida normal -> pop del frame setjmp (top = prev).
            emit_call("__vx_pop_frame", {}, ir::IrType::VOID, s->loc.line);
        } else {
            // Sprint 6.D: tryleave por cada catch via IR ops puros.
            for (size_t i = 0; i < n_catches; ++i) {
                ir::IrInstr tl{};
                tl.op = ir::IrOp::TRYLEAVE;
                tl.type = ir::IrType::VOID;
                tl.dst = ir::IR_NO_VALUE;
                tl.source_line = s->loc.line;
                emit(current_block_, std::move(tl));
            }
        }
        emit_finally_then_merge(current_block_, s->loc.line);
    }

    // NO resetear scopes_.back() = entry_bindings.  Esa operacion creaba
    // shadows de outer-scope vars (e.g. el contador @c j de un while loop
    // enclosing) en el inner scope, lo que rompia el back-edge phi del
    // loop: cuando el inner scope se pop'aba, las actualizaciones de outer
    // vars hechas DESPUES del try se perdian.
    //
    // El reset originalmente intentaba que cada catch viera el "estado
    // entry" de las vars.  Eso esta garantizado por OTROS mecanismos:
    //   - Vars asignadas en try o leidas en catch estan en try_spill_slots_
    //     y se reload via LOAD desde el slot en el catch entry.
    //   - Vars no tocadas en try mantienen su valor entry (ningun
    //     update_scope se llamo para ellas).
    // Asi el reset era redundante para vars relevantes y daninyo para
    // vars outer-scope no relacionadas.

    // 3. Handlers (uno por catch).  do_throw consume el frame del
    //    catch que captura.  Los catches MAS EXTERNOS (declarados
    //    despues en source) tambien ya se consumieron porque el
    //    matching va de arriba hacia abajo en exc_frame_stack y al
    //    saltar al handler ese frame se elimina.  Pero los catches
    //    MAS INTERNOS (declarados antes) podrian seguir en la pila
    //    si no fueron el match.  Para simplificar: dentro del handler
    //    no necesitamos re-pop porque do_throw ya consumio el frame
    //    matched, y los demas frames eran adicionales (catches
    //    posteriores no relacionados).  En el modelo actual cada
    //    catch tiene un tryenter independiente por lo que el
    //    do_throw consume exactamente uno; los otros siguen vivos
    //    hasta que terminemos el bloque try.  Solucion: emitir
    //    `tryleave` por cada catch RESTANTE en el handler.
    // Por cada catch, capturamos: post-bindings (para PHI)
    // + pred final + flag de alcance del merge.  Tras lower del catch
    // restauramos el scope a entry_bindings para que el siguiente
    // catch (o el merge) parta de un estado limpio.
    struct CatchSnapshot {
        std::unordered_map<std::string, ir::IrValueId> bindings;
        ir::IrBlockId pred;
        bool reaches_merge;
    };
    std::vector<CatchSnapshot> catch_snaps;
    catch_snaps.reserve(n_catches);

    for (size_t ci = 0; ci < n_catches; ++ci) {
        const ast::CatchClause &cc = s->catches[ci];
        current_block_ = handler_bbs[ci];
        block_terminated_ = false;
        // NO reset a entry_bindings (creaba shadows -- ver explicacion arriba).
        // El catch reload via LOAD desde spill slots se encarga de restaurar
        // las vars relevantes al valor entry.
        // Pop tryenters restantes (todos excepto el que se consumio).
        // Los restantes son: todos excepto el del catch[ci].
        // Como tryenter se apilaron en orden INVERSO (catch[n-1] en el
        // fondo, catch[0] en el tope), el frame consumido por
        // do_throw para catch[ci] es el ci-esimo desde el tope.
        // Frames POR ENCIMA (mas recientes que ci) ya fueron
        // descartados por do_throw mientras buscaba el match.
        // Frames POR DEBAJO (anteriores a ci) siguen vivos: hay que
        // popearlos.  Numero a popear: n_catches - 1 - ci.
        const size_t to_pop = n_catches - 1 - ci;
        if (native_poo_) {
            // AOT: el frame YA se popeo en dispatch_bb (antes de elegir el
            // catch), asi que el handler NO popea de nuevo.  El get_value del
            // catch var se emite mas abajo.
        } else {
            // Sprint 6.D: tryleave por catch via IR ops puros.
            for (size_t k = 0; k < to_pop; ++k) {
                ir::IrInstr tl{};
                tl.op = ir::IrOp::TRYLEAVE;
                tl.type = ir::IrType::VOID;
                tl.dst = ir::IR_NO_VALUE;
                tl.source_line = cc.loc.line;
                emit(current_block_, std::move(tl));
            }
        }
        push_scope();
        // CRITICO: la primera instruccion del catch debe ser el
        // `mov {dst}, r0` que captura la excepcion -- r0 lleva el
        // puntero al FatalError y CUALQUIER instruccion previa
        // (LOAD desde stack, etc.) puede clobrearlo.
        if (!cc.var_name.empty()) {
            if (native_poo_) {
                // AOT: el valor lanzado lo devuelve __vx_get_value().
                // Si el catch declara una clase, el valor es un ptr host
                // (throw new E()); si no, un i64 (throw <valor>).
                const bool exc_is_ptr = !cc.exc_class_name.empty();
                const ir::IrValueId v_exc = fn_->new_value(
                    exc_is_ptr ? ir::IrType::PTR : ir::IrType::I64);
                if (exc_is_ptr) fn_->values[v_exc].is_host_ptr = true;
                ir::IrInstr cg{};
                cg.op = ir::IrOp::CALL;
                cg.type = exc_is_ptr ? ir::IrType::PTR : ir::IrType::I64;
                cg.dst = v_exc;
                cg.func_name = "__vx_get_value";
                cg.source_line = cc.loc.line;
                emit(current_block_, std::move(cg));
                bind(cc.var_name, v_exc);
            } else {
                const ir::IrValueId v_exc = fn_->new_value(ir::IrType::PTR);
                fn_->values[v_exc].is_host_ptr =
                    true; // catch recibe FatalError* host
                ir::IrInstr lp{};
                lp.op = ir::IrOp::LANDINGPAD;
                lp.type = ir::IrType::PTR;
                lp.dst = v_exc;
                lp.source_line = cc.loc.line;
                emit(current_block_, std::move(lp));
                bind(cc.var_name, v_exc);
            }
        }
        // Recargar TODOS los nombres spilled desde su slot DESPUES
        // del bind de la excepcion (para no clobrear r0).  Bindeamos
        // en el scope OUTER (no en el inner del catch) para que:
        //   1. El write_local del catch body actualice ese scope.
        //   2. El binding sobreviva al pop_scope siguiente.
        //   3. La rama finally+merge vea el ultimo valor.
        // Sin esto, las vars spilled (incluido `this` y parametros)
        // quedaban con valor stale tras el throw -- el regalloc
        // clobreaba sus registros durante el unwind.
        // Buscar el scope outer (penultimo); el inner es el catch
        // que acabamos de pushear.
        std::unordered_map<std::string, ir::IrValueId> *outer_scope =
            (scopes_.size() >= 2) ? &scopes_[scopes_.size() - 2]
                                  : &scopes_.back();
        for (const auto &kv : try_spill_slots_) {
            const std::string &name = kv.first;
            const ir::IrValueId v_slot = kv.second;
            /* Una sola busqueda: preguntar si esta y luego pedirlo son dos
             * recorridos de la tabla para la misma pregunta. */
            const auto it_prev = saved_spill_slots.find(name);
            if (it_prev != saved_spill_slots.end() && it_prev->second == v_slot)
                continue; // slot heredado de try outer
            ir::IrType ity = ir::IrType::I64;
            auto it_e = entry_bindings.find(name);
            if (it_e != entry_bindings.end() &&
                it_e->second != ir::IR_NO_VALUE &&
                it_e->second < fn_->values.size()) {
                ity = fn_->values[it_e->second].type;
            }
            ir::IrValueId v_load = fn_->new_value(ity);
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            // Usar el tipo REAL del valor (no i64 hardcoded).  Si
            // el value era i32 pero leemos i64, los bytes altos del
            // slot 8-byte alloca son basura no inicializada (la
            // STORE inicial solo escribio 4 bytes) y corrompen la
            // aritmetica posterior.
            ld.type = ity;
            ld.dst = v_load;
            ld.operands = {v_slot};
            ld.source_line = cc.loc.line;
            emit(current_block_, std::move(ld));
            // Propagar is_host_ptr / is_gc_object del entry_value
            // si lo tenia, para que el catch maneje host pointers
            // y GC objects correctamente sin perder los flags.
            if (it_e != entry_bindings.end() &&
                it_e->second != ir::IR_NO_VALUE &&
                it_e->second < fn_->values.size()) {
                const auto &src_val = fn_->values[it_e->second];
                fn_->values[v_load].is_host_ptr = src_val.is_host_ptr;
                fn_->values[v_load].is_gc_object = src_val.is_gc_object;
                fn_->values[v_load].pointee_is_host_ptr =
                    src_val.pointee_is_host_ptr;
            }
            // Buscar el scope (NO el inner del catch) donde el name
            // vive y actualizarlo.  Si esta en multiples niveles,
            // actualizamos el mas cercano al exterior (sin tocar
            // el inner del catch).
            bool updated = false;
            if (scopes_.size() >= 2) {
                for (auto it = scopes_.rbegin() + 1; it != scopes_.rend();
                     ++it) {
                    if (it->count(name)) {
                        (*it)[name] = v_load;
                        updated = true;
                        break;
                    }
                }
            }
            if (!updated) {
                (*outer_scope)[name] = v_load;
            }
        }
        if (cc.body) lower_stmt(cc.body.get());
        pop_scope();
        // capturar snapshot del scope antes de pop_scope NO
        // porque queremos las modificaciones de variables del scope
        // ENCLOSING (no las del catch var, que vivian en el inner
        // scope ya popeado).
        CatchSnapshot snap;
        snap.reaches_merge = !block_terminated_;
        if (snap.reaches_merge) {
            snap.bindings = scopes_.back();
            snap.pred = current_block_;
            emit_finally_then_merge(current_block_, cc.loc.line);
        } else {
            snap.pred = ir::IR_NO_BLOCK;
        }
        catch_snaps.push_back(std::move(snap));
    }

    // 4. Merge + PHI.
    current_block_ = merge_bb;
    block_terminated_ = false;
    // NO RESETEAMOS scopes_.back() a entry_bindings.  Esa operacion
    // creaba sombras de variables outer-scope dentro del inner scope
    // del while-body / for-body / etc, lo que rompia loops con
    // try/catch dentro: cuando el inner scope se desapilaba al cierre
    // del body, las actualizaciones de las vars outer (e.g. el
    // contador de iteracion @c j en @c j=j+1) se perdian.  El PHI
    // back-edge subsequent tomaba el valor STALE del outer scope,
    // creando un self-loop @c j = phi[entry, j] -> loop infinito.
    //
    // En su lugar, propagamos las actualizaciones via @c update_scope
    // que walks scopes inside-out y actualiza el binding en su scope
    // nativo.  Asi outer-scope vars se actualizan en outer, inner-scope
    // vars (e.g. catch var) en inner.  Sin shadowing.

    // Coleccionar todos los predecesores que alcanzan el merge.
    // Cada uno aporta su binding final para cada variable.
    struct MergeContrib {
        ir::IrBlockId pred;
        const std::unordered_map<std::string, ir::IrValueId> *bindings;
    };
    std::vector<MergeContrib> contribs;
    contribs.reserve(1 + n_catches);
    if (body_reaches_merge) {
        contribs.push_back({body_pred, &body_bindings});
    }
    for (auto &cs : catch_snaps) {
        if (cs.reaches_merge) {
            contribs.push_back({cs.pred, &cs.bindings});
        }
    }
    // Solo necesitamos PHI si >= 2 predecesores aportan al merge
    // y la variable difiere entre alguno de ellos y el entry.
    if (contribs.size() >= 2) {
        for (const auto &kv : entry_bindings) {
            const std::string &name = kv.first;
            const ir::IrValueId entry_val = kv.second;
            // Detectar si algun pred difiere del entry.
            bool any_diff = false;
            for (const auto &c : contribs) {
                auto it = c.bindings->find(name);
                if (it == c.bindings->end()) continue;
                if (it->second != entry_val) {
                    any_diff = true;
                    break;
                }
            }
            if (!any_diff) continue;

            // Construir PHI: por cada pred, su binding (entry si
            // el pred no tiene binding actualizado).
            ir::IrType ity = ir::IrType::I64;
            if (entry_val != ir::IR_NO_VALUE &&
                entry_val < fn_->values.size()) {
                ity = fn_->values[entry_val].type;
            }
            ir::IrValueId v_phi = fn_->new_value(ity);
            ir::IrInstr phi{};
            phi.op = ir::IrOp::PHI;
            phi.type = ity;
            phi.dst = v_phi;
            phi.source_line = s->loc.line;
            for (const auto &c : contribs) {
                auto it = c.bindings->find(name);
                ir::IrValueId in_val =
                    (it != c.bindings->end()) ? it->second : entry_val;
                ir::IrPhiArg arg{};
                arg.value = in_val;
                arg.block = c.pred;
                phi.phi_args.push_back(arg);
            }
            // Insertar al INICIO del merge_bb (PHI siempre al tope).
            fn_->blocks[merge_bb].instrs.insert(
                fn_->blocks[merge_bb].instrs.begin(), std::move(phi));
            // Update in-place en el scope NATIVO de la variable, no
            // en scopes_.back() (que creaba shadow + perdia el update
            // al pop_scope del while/for body).  Si la var no esta en
            // ningun scope (debio ser declarada en outer pero por algun
            // motivo no aparece), fallback a scopes_.back() crea binding
            // local -- aceptable.
            update_scope(name, v_phi);
        }
    } else if (contribs.size() == 1) {
        // Solo un predecesor alcanza el merge: copiar SOLO los
        // bindings que difieren del entry, y propagarlos a su scope
        // nativo via update_scope (no shadow en scopes_.back()).
        for (const auto &kv : *contribs[0].bindings) {
            auto it_entry = entry_bindings.find(kv.first);
            if (it_entry == entry_bindings.end() ||
                it_entry->second != kv.second) {
                update_scope(kv.first, kv.second);
            }
        }
    }

    // LOAD del slot de cada var spilled y bind al nombre.
    // Esto OVERRIDES el PHI o single-pred binding: el slot tiene la
    // verdad mas reciente independientemente de regalloc.  Necesario
    // porque el throw + RSP unwind puede dejar registros corruptos.
    for (const auto &kv : try_spill_slots_) {
        const std::string &name = kv.first;
        const ir::IrValueId v_slot = kv.second;
        // Solo override para vars que estaban en el slot ESTE try
        // (no las del saved_spill_slots de un try outer).
        const auto it_prev = saved_spill_slots.find(name);
        if (it_prev != saved_spill_slots.end() && it_prev->second == v_slot)
            continue;
        ir::IrType ity = ir::IrType::I64;
        auto it_e = entry_bindings.find(name);
        if (it_e != entry_bindings.end() && it_e->second != ir::IR_NO_VALUE &&
            it_e->second < fn_->values.size()) {
            ity = fn_->values[it_e->second].type;
        }
        ir::IrValueId v_load = fn_->new_value(ity);
        ir::IrInstr ld{};
        ld.op = ir::IrOp::LOAD;
        // Usar el tipo real del valor (no i64 hardcoded) para
        // evitar leer bytes basura del slot 8-byte alloca.
        ld.type = ity;
        ld.dst = v_load;
        ld.operands = {v_slot};
        ld.source_line = s->loc.line;
        emit(current_block_, std::move(ld));
        // Propagar flags is_host_ptr/is_gc_object del entry value.
        if (it_e != entry_bindings.end() && it_e->second != ir::IR_NO_VALUE &&
            it_e->second < fn_->values.size()) {
            const auto &src_val = fn_->values[it_e->second];
            fn_->values[v_load].is_host_ptr = src_val.is_host_ptr;
            fn_->values[v_load].is_gc_object = src_val.is_gc_object;
            fn_->values[v_load].pointee_is_host_ptr =
                src_val.pointee_is_host_ptr;
        }
        // Update en scope nativo via update_scope (no shadow).
        // Mismo razonamiento que el merge PHI arriba: la sombra
        // en scopes_.back() se perdia al pop_scope del while body
        // y dejaba al back-edge del while leyendo el binding stale
        // del outer scope.
        update_scope(name, v_load);
    }

    // Restaurar try_spill_slots_ del nivel exterior.
    try_spill_slots_ = std::move(saved_spill_slots);
}
void Lowering::lower_synchronized(ast::SynchronizedStmt *s) {
    if (!s || !s->target) {
        error_at(s ? s->loc : SourceLoc{}, "lowering: synchronized sin target");
        return;
    }
    if (!s->body) {
        error_at(s->loc, "lowering: synchronized sin body");
        return;
    }

    // 1. Bajar el target a un valor SSA (host pointer al ObjectHeader).
    const ir::IrValueId v_obj = lower_expr(s->target.get());
    if (v_obj == ir::IR_NO_VALUE) return;

    // -----------------------------------------------------------------
    // AOT/Embed (native_poo_): modelo setjmp/longjmp (sin VM runtime ni
    // ops TRYENTER/TRYLEAVE/RETHROW, que el backend nativo no soporta).
    //   monenter(obj)
    //   buf = ALLOCA(96); __vx_push_frame(buf, 0); r = __vx_setjmp(buf)
    //   br r ? handler : body
    //   body... (normal) -> __vx_pop_frame + monexit(obj) + br merge
    //   handler (longjmp) -> __vx_pop_frame + monexit(obj) + rethrow
    //   return temprano    -> cleanup SYNC_EXIT = pop_frame + monexit
    // El monitor se libera SIEMPRE (los 3 caminos).  __vx_* viven en
    // vx_exc.vx; __vx_monenter/monexit en vx_sync.vx (auto-bundle).
    // -----------------------------------------------------------------
    if (native_poo_) {
        const ir::IrBlockId nbody = fn_->new_block("sync_body");
        const ir::IrBlockId nhandler = fn_->new_block("sync_handler");
        const ir::IrBlockId nmerge = fn_->new_block("sync_merge");

        // Helper local: CALL void por nombre (sin args salvo los dados).
        auto vcall = [&](const char *name,
                         std::vector<ir::IrValueId> args = {}) {
            emit_call(name, std::move(args), ir::IrType::VOID, s->loc.line);
        };

        // monenter(obj).
        emit_monitor_op(v_obj, /*enter=*/true, s->loc.line);

        // buf + push_frame catch-all + setjmp.
        const ir::IrValueId v_buf = stack_alloc_buf(96, s->loc.line, true);
        const ir::IrValueId v_type0 =
            emit_const(ir::IrType::I64, 0, s->loc.line);
        vcall("__vx_push_frame", {v_buf, v_type0});
        const ir::IrValueId v_r =
            emit_call("__vx_setjmp", {v_buf}, ir::IrType::I64, s->loc.line);
        emit_br_cond(v_r, nhandler, nbody, s->loc.line);

        // Cleanup para return temprano: pop_frame + monexit.
        {
            CleanupAction act;
            act.kind = CleanupAction::Kind::SYNC_EXIT;
            act.operands = {v_obj};
            act.source_line = s->loc.line;
            cleanup_stack_.push_back(std::move(act));
        }

        // Body.
        current_block_ = nbody;
        block_terminated_ = false;
        lower_block(s->body.get());
        cleanup_stack_.pop_back();

        // Salida normal del body: pop_frame + monexit + br merge.
        if (!block_terminated_) {
            vcall("__vx_pop_frame");
            emit_monitor_op(v_obj, /*enter=*/false, s->loc.line);
            emit_br(nmerge, s->loc.line);
            block_terminated_ = true;
        }

        // Handler (longjmp reanudo): pop_frame + monexit + rethrow.
        current_block_ = nhandler;
        block_terminated_ = false;
        vcall("__vx_pop_frame");
        emit_monitor_op(v_obj, /*enter=*/false, s->loc.line);
        {
            // rethrow nativo: leer value+type del estado de excepcion y
            // re-lanzar (longjmp al frame externo).  El frame propio ya
            // fue popeado arriba.
            const ir::IrValueId v_v =
                emit_call("__vx_get_value", {}, ir::IrType::I64, s->loc.line);
            const ir::IrValueId v_ty =
                emit_call("__vx_get_type", {}, ir::IrType::I64, s->loc.line);
            ir::IrInstr th{};
            th.op = ir::IrOp::THROW;
            th.type = ir::IrType::VOID;
            th.dst = ir::IR_NO_VALUE;
            th.operands = {v_v, v_ty};
            th.source_line = s->loc.line;
            emit(current_block_, std::move(th));
        }
        block_terminated_ = true;

        // Continuar en merge (salida normal).
        current_block_ = nmerge;
        block_terminated_ = false;
        return;
    }

    // Crear bloques: body + handler (excepcion) + merge (continuacion).
    const ir::IrBlockId body_bb = fn_->new_block("sync_body");
    const ir::IrBlockId handler_bb = fn_->new_block("sync_handler");
    const ir::IrBlockId merge_bb = fn_->new_block("sync_merge");

    // 2. ptr -> handle + monenter en un RAW_ASM con {dst}={src0} (SSA-aware).
    // El regalloc asigna v_handle a un registro libre y monenter usa
    // ese mismo registro.  Crucial: no hardcodear r1/r2 aqui porque
    // colisionan con valores SSA vivos (el regalloc no inspecciona el
    // texto del RAW_ASM y no sabe que clobreamos).
    // Sprint 6.C: ptr -> handle via GC_HANDLE_FOR_PTR IR op + MONENTER IR op.
    // AOT (native_poo_): NO hay handle table -> el monitor opera sobre el
    // host_ptr del objeto directamente (palabra inline en obj+16).  El resto
    // de tiers convierten el ptr a GcHandle.  emit_monitor_op encapsula ambos.
    // Con @SyncImpl override, el operando es el host_ptr al ObjectHeader
    // (v_obj), NO el GcHandle: emit_monitor_op emite un CALL a la fn del
    // usuario, que trabaja sobre el ptr.  Sin override, el path interp/JIT
    // convierte el ptr a GcHandle para el opcode MONENTER/MONEXIT.
    const bool has_sync_ovr = !sync_enter_override_.empty();
    const ir::IrValueId v_handle =
        has_sync_ovr ? v_obj : emit_gc_handle_for_ptr(v_obj, s->loc.line);
    emit_monitor_op(v_handle, /*enter=*/true, s->loc.line);

    // tryenter catch-all: setup handler_pc y type=NULL via SSA values.
    const std::string handler_label =
        fn_->name + "_" + fn_->blocks[handler_bb].name;
    const ir::IrValueId v_handler_pc =
        emit_label_addr(handler_label, s->loc.line);
    const ir::IrValueId v_type_null =
        emit_const(ir::IrType::I64, 0, s->loc.line);
    {
        ir::IrInstr ra{};
        ra.op = ir::IrOp::TRYENTER;
        ra.type = ir::IrType::VOID;
        ra.dst = ir::IR_NO_VALUE;
        ra.operands = {v_handler_pc, v_type_null};
        /* Bloque handler en target_block (Opcion B in-JIT catch). */
        ra.target_block = handler_bb;
        /* El handler del synchronized es catch-all (cleanup + rethrow) -> puede
         * capturar un AV -> in-JIT inseguro -> imm=1 (baila a interp). */
        ra.imm = 1u;
        ra.source_line = s->loc.line;
        emit(current_block_, std::move(ra));
    }

    /* El salto va al cuerpo.  Al manejador NO se salta: se llega lanzando,
     * asi que su arista se anota aparte -- sin instruccion que la respalde --
     * para que quien recorra el grafo sepa que ese bloque es alcanzable. */
    emit_br(body_bb, s->loc.line);
    add_cfg_edge(current_block_, handler_bb);

    // 3. Push cleanup: tryleave + monexit en early-return.
    // Sprint 6.C: Kind::SYNC_EXIT emite TRYLEAVE + MONEXIT como IR ops.
    {
        CleanupAction act;
        act.kind = CleanupAction::Kind::SYNC_EXIT;
        act.operands = {v_handle};
        act.source_line = s->loc.line;
        cleanup_stack_.push_back(std::move(act));
    }

    // 4. Bajar el body.
    current_block_ = body_bb;
    block_terminated_ = false;
    lower_block(s->body.get());

    // 5. Pop cleanup (el body ya no necesita protegerse via emit_cleanups_all).
    cleanup_stack_.pop_back();

    // 6. Salida normal del body: TRYLEAVE + MONEXIT IR ops + br merge.
    if (!block_terminated_) {
        // Sprint 6.C: TRYLEAVE y MONEXIT son IR ops puros.
        {
            ir::IrInstr tl{};
            tl.op = ir::IrOp::TRYLEAVE;
            tl.type = ir::IrType::VOID;
            tl.dst = ir::IR_NO_VALUE;
            tl.source_line = s->loc.line;
            emit(current_block_, std::move(tl));
        }
        emit_monitor_op(v_handle, /*enter=*/false, s->loc.line);

        emit_br(merge_bb, s->loc.line);
        block_terminated_ = true;
    }

    // 7. Handler: alcanzable solo via excepcion del body.  do_throw nos
    // dejo el objeto excepcion en r0.  Hacemos monexit + rethrow para
    // que el caller decida que hacer con la excepcion.  Notese que NO
    // necesitamos tryleave aqui: do_throw ya consumio el frame al saltar.
    current_block_ = handler_bb;
    block_terminated_ = false;
    {
        // Sprint 6.C: handler = MONEXIT IR op + rethrow (RAW_ASM minimal).
        emit_monitor_op(v_handle, /*enter=*/false, s->loc.line);
        // raw_asm-elim wave 3: rethrow IR op dedicado.  Terminator del
        // bloque (re-lanza current_exception; nada sigue a esta instr).
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RETHROW;
        rt.type = ir::IrType::VOID;
        rt.dst = ir::IR_NO_VALUE;
        rt.source_line = s->loc.line;
        emit(current_block_, std::move(rt));
    }
    block_terminated_ = true; // rethrow es terminador del bloque

    // Continuar en merge (alcanzable solo via salida normal).
    current_block_ = merge_bb;
    block_terminated_ = false;
}
void Lowering::lower_throw(ast::ThrowStmt *s) {
    if (!s->value) {
        error_at(s->loc, "lowering: throw sin valor");
        return;
    }
    const ir::IrValueId v_obj = lower_expr(s->value.get());
    if (v_obj == ir::IR_NO_VALUE) return;
    // throw r_obj: el bytecode `throw` (0xD3) busca handler en
    // exc_frame_stack y salta al handler_pc.  Emitimos via RAW_ASM
    // con {src0} = reg de v_obj para que el regalloc materialice el
    // valor en algun reg accesible.
    ir::IrInstr ra{};
    ra.op = ir::IrOp::THROW;
    ra.type = ir::IrType::VOID;
    ra.dst = ir::IR_NO_VALUE;
    ra.operands = {v_obj};
    // AOT (native_poo): el throw transporta el type-id (intervalo lo) del tipo
    // ESTATICO lanzado, para que el catch despache por tipo (subtipo via el
    // intervalo).  operands[1] = CONST(lo).  El backend HOST_LEAF lo pasa como
    // 2o arg a __vx_throw(value, type_id).  En el path VM se ignora.
    if (native_poo_) {
        uint32_t lo = 0;
        const std::string &cn = s->value->result_type.struct_name;
        auto it = type_intervals_.find(cn);
        if (it != type_intervals_.end()) lo = it->second.first;
        const ir::IrValueId v_type =
            emit_const(ir::IrType::I64, static_cast<int64_t>(lo), s->loc.line);
        ra.operands.push_back(v_type);
    }
    ra.source_line = s->loc.line;
    emit(current_block_, std::move(ra));
    // throw es un terminador del flujo: marcamos el bloque para que
    // el emisor no intente continuar tras el throw.  El IR optimizer
    // reportara unreachable code si lo hay despues.
    block_terminated_ = true;
}

ir::IrValueId Lowering::lower_try_expr(ast::TryExpr *e) {
    if (!e || !e->operand) {
        error_at(e ? e->loc : SourceLoc{}, "lowering: TryExpr sin operand");
        return ir::IR_NO_VALUE;
    }
    const uint32_t src_line = e->loc.line;

    // 1. Bajar el operand -> SSA PTR al slot Result.
    const ir::IrValueId v_buf = lower_expr(e->operand.get());
    if (v_buf == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;

    // 2. LOAD i32 del tag en offset 0.
    const ir::IrValueId tag_v =
        emit_load_typed(v_buf, ir::IrType::I32, src_line);

    // 3. Comparacion tag == 0 (=Err).
    const ir::IrValueId zero_v = emit_const(ir::IrType::I32, 0, src_line);
    const ir::IrValueId cond_v = emit_ir_binop(ir::IrOp::CMP_EQ, tag_v, zero_v,
                                               ir::IrType::BOOL, src_line);

    // 4. Crear bloques: err_bb (early-return), ok_bb (extract value).
    const ir::IrBlockId err_bb =
        fn_->new_block("try_err_" + std::to_string(ternary_counter_));
    const ir::IrBlockId ok_bb =
        fn_->new_block("try_ok_" + std::to_string(ternary_counter_));
    ++ternary_counter_;

    // br_cond: si tag==0 -> err_bb, else -> ok_bb.
    {
        emit_br_cond(cond_v, err_bb, ok_bb, src_line);
    }

    // 5. err_bb: copia v_buf (24 bytes) al sret_retbuf + RET.
    // Mismo patron que lower_return cuando sret_active_ es true.
    current_block_ = err_bb;
    block_terminated_ = false;
    if (sret_active_ && sret_retbuf_ != ir::IR_NO_VALUE) {
        const uint64_t qwords = sret_buf_size_ / 8;
        for (uint64_t qi = 0; qi < qwords; ++qi) {
            const uint64_t off = qi * 8;
            const ir::IrValueId v_off =
                emit_const(ir::IrType::I64, off, src_line);
            const ir::IrValueId v_src_at = emit_ptr_add(v_buf, v_off, src_line);
            // BugFix 163 (2026-06-05): propagar is_host_ptr de v_buf al LOAD
            // side (igual que el STORE side abajo).  Sin esto el LOAD del
            // Err a copiar usaba `mov` (VM) en vez de `movh` (host) y leia
            // basura -> error(r) != el valor real (path de error de `?`).
            fn_->values[v_src_at].is_host_ptr = fn_->values[v_buf].is_host_ptr;
            const ir::IrValueId v_tmp =
                emit_load_typed(v_src_at, ir::IrType::I64, src_line);
            const ir::IrValueId v_off2 =
                emit_const(ir::IrType::I64, off, src_line);
            const ir::IrValueId v_dst_at =
                emit_ptr_add(sret_retbuf_, v_off2, src_line);
            // BugFix sret-cross-mem (2026-06-04): propagar is_host_ptr.
            fn_->values[v_dst_at].is_host_ptr =
                fn_->values[sret_retbuf_].is_host_ptr;
            emit_store_typed(v_dst_at, v_tmp, ir::IrType::I64, src_line);
        }
    }
    // Emit cleanups (synchronized, etc.) y RET.
    emit_cleanups_all();
    {
        ir::IrInstr ret{};
        ret.op = ir::IrOp::RET;
        ret.type = ir::IrType::VOID;
        ret.source_line = src_line;
        emit(current_block_, std::move(ret));
        block_terminated_ = true;
    }

    // 6. ok_bb: extraer V de v_buf+8.  El tipo V se obtiene del result_type
    // que el type checker ya validamos (pointee del Result).
    current_block_ = ok_bb;
    block_terminated_ = false;
    const Type result_t = e->result_type;
    const ir::IrType payload_t = (result_t.kind != PrimitiveKind::VOID &&
                                  result_t.kind != PrimitiveKind::COUNT)
                                     ? ir_type_from_primitive(result_t.kind)
                                     : ir::IrType::I64;
    const ir::IrValueId v_off8 = emit_const(ir::IrType::I64, 8, src_line);
    const ir::IrValueId v_at8 = emit_ptr_add(v_buf, v_off8, src_line);
    // BugFix 163 (2026-06-05): propagar is_host_ptr de v_buf a v_at8.  El
    // buffer del Result temporal del operando es un host_ptr; sin esta
    // marca, el LOAD de V emitia `mov` (VM mem) en vez de `movh` (host) y
    // leia 0/basura.  La rama err ya lo propagaba (de ahi que err funcione
    // y ok no).  Aplica al value extraction de la rama ok.
    fn_->values[v_at8].is_host_ptr = fn_->values[v_buf].is_host_ptr;
    const ir::IrValueId v_dst = emit_load_typed(v_at8, payload_t, src_line);
    return v_dst;
}

/**
 * @brief Monta el `try` del modo NATIVO, sin maquina virtual detras.
 *
 * Sin VM no hay pila de marcos de excepcion que consultar, asi que el modelo es
 * el de C: se guarda el estado del punto de entrada y lanzar es volver a el.
 * El mismo sitio se ejecuta DOS veces y lo unico que los distingue es lo que
 * devuelve guardar -- cero la primera, distinto de cero cuando se vuelve --,
 * asi que la bifurcacion de ahi no es del programa: es "entro por primera vez"
 * contra "he vuelto porque alguien lanzo".
 *
 * De momento el marco es uno solo y atrapa todo: lo que se lanza no lleva
 * todavia su tipo, asi que varios `catch` van todos al primero.
 *
 * @param s           El `try` que se esta bajando.
 * @param body_bb     Bloque del cuerpo, al que se entra la primera vez.
 * @param handler_bbs Bloques de los `catch`, en orden.
 */
void Lowering::emit_try_frame_native(
    ast::TryStmt *s, ir::IrBlockId body_bb,
    const std::vector<ir::IrBlockId> &handler_bbs) {
    // buf en host-stack: 96B cubre el peor caso (Win64 buf 80 +
    // prev 8 + type 8); SysV/x86-32 usan menos.  El layout interno
    // (offsets prev/type) lo conoce vx_exc.vx via comptime const.
    const ir::IrValueId v_buf = stack_alloc_buf(96, s->loc.line, true);
    // type = 0 (catch-all).  v2: findclass del tipo del catch.
    const ir::IrValueId v_type = emit_const(ir::IrType::I64, 0, s->loc.line);
    emit_call("__vx_push_frame", {v_buf, v_type}, ir::IrType::VOID,
              s->loc.line);
    const ir::IrValueId v_r =
        emit_call("__vx_setjmp", {v_buf}, ir::IrType::I64, s->loc.line);
    // Bloques del dispatch por tipo (type matching v2): tras el setjmp,
    // si el longjmp reanudo (r!=0) saltamos a dispatch_bb que popea el
    // frame, lee el type-id y elige el catch que matchea (o re-throw).
    const ir::IrBlockId dispatch_bb = fn_->new_block("try_dispatch");
    const ir::IrBlockId rethrow_bb = fn_->new_block("try_rethrow");
    // Distinto de cero = se volvio aqui por una excepcion, asi que toca
    // buscarle un `catch`; cero = se entra al bloque por primera vez.
    emit_br_cond(v_r, dispatch_bb, body_bb, s->loc.line);

    // Helpers locales para emitir CALLs al runtime de excepciones.
    auto emit_void_call = [&](ir::IrBlockId blk, const char *name) {
        ir::IrInstr c{};
        c.op = ir::IrOp::CALL;
        c.type = ir::IrType::VOID;
        c.dst = ir::IR_NO_VALUE;
        c.func_name = name;
        c.source_line = s->loc.line;
        emit(blk, std::move(c));
    };
    auto emit_i64_call = [&](ir::IrBlockId blk,
                             const char *name) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ir::IrType::I64);
        ir::IrInstr c{};
        c.op = ir::IrOp::CALL;
        c.type = ir::IrType::I64;
        c.dst = d;
        c.func_name = name;
        c.source_line = s->loc.line;
        emit(blk, std::move(c));
        return d;
    };

    // dispatch_bb: pop del frame consumido + leer el type-id.
    current_block_ = dispatch_bb;
    emit_void_call(dispatch_bb, "__vx_pop_frame");
    const ir::IrValueId v_t = emit_i64_call(dispatch_bb, "__vx_get_type");
    // Cadena de chequeos: por cada catch, si su tipo es desconocido
    // (catch-all, builtin como FatalError, o base no registrada) matchea
    // SIEMPRE; si es una clase con intervalo, matchea si lo<=t<=hi (el
    // intervalo cubre la clase y sus subclases).
    const size_t n_catches = s->catches.size();
    ir::IrBlockId cur_check = dispatch_bb;
    for (size_t ci = 0; ci < n_catches && cur_check != ir::IR_NO_BLOCK; ++ci) {
        const ast::CatchClause &cc = s->catches[ci];
        current_block_ = cur_check;
        auto itv = cc.exc_class_name.empty()
                       ? type_intervals_.end()
                       : type_intervals_.find(cc.exc_class_name);
        const bool catch_all = (itv == type_intervals_.end());
        if (catch_all) {
            // BR incondicional al handler; el resto de catches queda
            // muerto.
            emit_br_from(cur_check, handler_bbs[ci], cc.loc.line);
            cur_check = ir::IR_NO_BLOCK;
            break;
        }
        const uint32_t lo = itv->second.first, hi = itv->second.second;
        const ir::IrValueId v_lo =
            emit_const(ir::IrType::I64, static_cast<int64_t>(lo), cc.loc.line);
        const ir::IrValueId v_hi =
            emit_const(ir::IrType::I64, static_cast<int64_t>(hi), cc.loc.line);
        const ir::IrValueId v_ge = fn_->new_value(ir::IrType::BOOL);
        {
            ir::IrInstr cm{};
            cm.op = ir::IrOp::CMP_GE;
            cm.type = ir::IrType::BOOL;
            cm.dst = v_ge;
            cm.operands = {v_t, v_lo};
            cm.source_line = cc.loc.line;
            emit(cur_check, std::move(cm));
        }
        const ir::IrValueId v_le = fn_->new_value(ir::IrType::BOOL);
        {
            ir::IrInstr cm{};
            cm.op = ir::IrOp::CMP_LE;
            cm.type = ir::IrType::BOOL;
            cm.dst = v_le;
            cm.operands = {v_t, v_hi};
            cm.source_line = cc.loc.line;
            emit(cur_check, std::move(cm));
        }
        const ir::IrValueId v_and = fn_->new_value(ir::IrType::BOOL);
        {
            ir::IrInstr an{};
            an.op = ir::IrOp::AND;
            an.type = ir::IrType::BOOL;
            an.dst = v_and;
            an.operands = {v_ge, v_le};
            an.source_line = cc.loc.line;
            emit(cur_check, std::move(an));
        }
        const ir::IrBlockId next_check =
            (ci + 1 < n_catches) ? fn_->new_block("try_check") : rethrow_bb;
        emit_br_cond_from(cur_check, v_and, handler_bbs[ci], next_check,
                          cc.loc.line);
        cur_check = next_check;
    }

    // rethrow_bb: ningun catch matcheo -> re-lanzar al frame externo.
    // El frame ya se popeo en dispatch_bb, asi que el __vx_throw del
    // THROW hace longjmp al handler de outer (propagacion).
    current_block_ = rethrow_bb;
    {
        const ir::IrValueId v_v = emit_i64_call(rethrow_bb, "__vx_get_value");
        const ir::IrValueId v_ty = emit_i64_call(rethrow_bb, "__vx_get_type");
        ir::IrInstr th{};
        th.op = ir::IrOp::THROW;
        th.type = ir::IrType::VOID;
        th.dst = ir::IR_NO_VALUE;
        th.operands = {v_v, v_ty};
        th.source_line = s->loc.line;
        emit(rethrow_bb, std::move(th));
    }
}

/**
 * @copydoc vx::Lowering::scan_read_names_expr
 */
void Lowering::scan_read_names_expr(const ast::Expr *e,
                                    std::unordered_set<std::string> &out) {
    if (!e) return;
    switch (e->kind) {
    case ast::NodeKind::IdentExpr: {
        auto *id = static_cast<const ast::IdentExpr *>(e);
        if (name_visible_in_any_scope(id->name)) {
            out.insert(id->name);
        }
        return;
    }
    case ast::NodeKind::ThisExpr: {
        // `this` se resuelve via lookup("this") en
        // lower_this_expr, igual que un IdentExpr.  Vive
        // en el outer scope (function-level binding), no
        // en entry_bindings (innermost).  Por eso usamos
        // is_visible_in_any_scope.
        if (name_visible_in_any_scope("this")) {
            out.insert("this");
        }
        return;
    }
    case ast::NodeKind::AssignExpr: {
        auto *ae = static_cast<const ast::AssignExpr *>(e);
        scan_read_names_expr(ae->target.get(), out);
        scan_read_names_expr(ae->value.get(), out);
        return;
    }
    case ast::NodeKind::BinaryExpr: {
        auto *be = static_cast<const ast::BinaryExpr *>(e);
        scan_read_names_expr(be->lhs.get(), out);
        scan_read_names_expr(be->rhs.get(), out);
        return;
    }
    case ast::NodeKind::UnaryExpr: {
        auto *ue = static_cast<const ast::UnaryExpr *>(e);
        scan_read_names_expr(ue->operand.get(), out);
        return;
    }
    case ast::NodeKind::CallExpr: {
        auto *ce = static_cast<const ast::CallExpr *>(e);
        scan_read_names_expr(ce->callee.get(), out);
        for (auto &a : ce->args)
            scan_read_names_expr(a.get(), out);
        return;
    }
    case ast::NodeKind::FieldAccessExpr: {
        auto *fa = static_cast<const ast::FieldAccessExpr *>(e);
        scan_read_names_expr(fa->base.get(), out);
        return;
    }
    case ast::NodeKind::IndexExpr: {
        auto *ix = static_cast<const ast::IndexExpr *>(e);
        scan_read_names_expr(ix->base.get(), out);
        scan_read_names_expr(ix->index.get(), out);
        return;
    }
    case ast::NodeKind::CastExpr: {
        auto *ce = static_cast<const ast::CastExpr *>(e);
        scan_read_names_expr(ce->operand.get(), out);
        return;
    }
    case ast::NodeKind::NewExpr: {
        auto *ne = static_cast<const ast::NewExpr *>(e);
        for (auto &a : ne->args)
            scan_read_names_expr(a.get(), out);
        return;
    }
    default: return;
    }
}

/**
 * @copydoc vx::Lowering::scan_read_names_stmt
 */
void Lowering::scan_read_names_stmt(const ast::Stmt *st,
                                    std::unordered_set<std::string> &out) {
    if (!st) return;
    switch (st->kind) {
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<const ast::ExprStmt *>(st);
        scan_read_names_expr(es->expr.get(), out);
        return;
    }
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<const ast::BlockStmt *>(st);
        for (auto &s2 : b->body)
            scan_read_names_stmt(s2.get(), out);
        return;
    }
    case ast::NodeKind::VarDeclStmt: {
        auto *vd = static_cast<const ast::VarDeclStmt *>(st);
        if (vd->init) scan_read_names_expr(vd->init.get(), out);
        return;
    }
    case ast::NodeKind::IfStmt: {
        auto *ifs = static_cast<const ast::IfStmt *>(st);
        scan_read_names_expr(ifs->cond.get(), out);
        scan_read_names_stmt(ifs->then_branch.get(), out);
        scan_read_names_stmt(ifs->else_branch.get(), out);
        return;
    }
    case ast::NodeKind::WhileStmt: {
        auto *ws = static_cast<const ast::WhileStmt *>(st);
        scan_read_names_expr(ws->cond.get(), out);
        scan_read_names_stmt(ws->body.get(), out);
        return;
    }
    case ast::NodeKind::ForStmt: {
        auto *fs = static_cast<const ast::ForStmt *>(st);
        scan_read_names_stmt(fs->init.get(), out);
        scan_read_names_expr(fs->cond.get(), out);
        scan_read_names_expr(fs->step.get(), out);
        scan_read_names_stmt(fs->body.get(), out);
        return;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *rs = static_cast<const ast::ReturnStmt *>(st);
        if (rs->value) scan_read_names_expr(rs->value.get(), out);
        return;
    }
    case ast::NodeKind::ThrowStmt: {
        auto *ts = static_cast<const ast::ThrowStmt *>(st);
        if (ts->value) scan_read_names_expr(ts->value.get(), out);
        return;
    }
    case ast::NodeKind::TryStmt: {
        auto *ts = static_cast<const ast::TryStmt *>(st);
        scan_read_names_stmt(ts->body.get(), out);
        for (auto &cc : ts->catches)
            scan_read_names_stmt(cc.body.get(), out);
        if (ts->finally_body) scan_read_names_stmt(ts->finally_body.get(), out);
        return;
    }
    case ast::NodeKind::SynchronizedStmt: {
        auto *ss = static_cast<const ast::SynchronizedStmt *>(st);
        scan_read_names_expr(ss->target.get(), out);
        scan_read_names_stmt(ss->body.get(), out);
        return;
    }
    default: return;
    }
}

/**
 * @copydoc vx::Lowering::name_visible_in_any_scope
 */
bool Lowering::name_visible_in_any_scope(const std::string &name) const {
    for (const auto &sc : scopes_)
        if (sc.count(name)) return true;
    return false;
}

} // namespace vx
