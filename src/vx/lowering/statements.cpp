/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/statements.cpp
 * @brief Bajada de las sentencias: el control de flujo y el retorno.
 *
 * Un `if`, un bucle o un `return` no producen un valor: producen una FORMA en
 * el grafo de bloques.  Aqui se construye esa forma, y se construye ya en SSA
 * -- se decide sobre la marcha de que bloque viene cada valor en lugar de
 * arreglarlo despues --, que es lo que hace que un bucle salga con sus phi
 * puestas y no haya que reconstruirlas.
 *
 * El `return` esta aqui y no con las expresiones porque es lo mismo: no
 * devuelve un valor sin mas, tiene que desmontar el ambito antes de irse.
 */
#include "vx/lowering.h"
#include "vx/comptime/comptime_introspect.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {
void Lowering::lower_block(ast::BlockStmt *b) {
    push_scope();
    // scope-local cleanup deferido por interaccion con
    // try/catch (el catch handler puede saltar en medio de un body
    // dejando cleanups de inner scopes en estado intermedio que
    // causan SEGFAULT al RET).
    //
    // Mantenemos el comportamiento original (cleanup al RET via
    // emit_cleanups_all en lower_return / final de lower_function).
    // Resultado: destructores corren al RET, no por iteracion del
    // loop.  Para destructores por iteracion, refactorizar el body
    // del loop a un helper auxiliar (cuyo RET dispara el dtor).
    bool warned_unreachable = false;
    for (auto &s : b->body) {
        if (block_terminated_) {
            if (s && s->kind == ast::NodeKind::LabelStmt) {
                lower_stmt(s.get());
                warned_unreachable = false;
                continue;
            }
            if (!warned_unreachable) {
                diags_.warning(s->loc, "codigo inalcanzable tras terminador");
                warned_unreachable = true;
            }
            continue;
        }
        lower_stmt(s.get());
    }
    pop_scope();
}

void Lowering::lower_stmt(ast::Stmt *s) {
    if (!s) return;
    /* Se anota el TRAMO de la sentencia -- fichero, linea, columna y longitud
     * -- en el punto por el que pasan todas.  La posicion ya la traia el arbol;
     * lo que faltaba era hacerla viajar, porque una linea no basta: en `return
     * foo(a) / bar(b);` hay tres cosas que pueden fallar y todas estan en la
     * misma.  Reconstruirlo despues seria adivinar. */
    if (fn_ && !fn_->name.empty() && s->loc.line > 0) {
        /* Si la sentencia es una expresion, se apunta la EXPRESION y no la
         * sentencia: en `return x / this.valor;` lo que se evalua -- y por
         * tanto lo que puede fallar -- es `x / this.valor`; el `return` no
         * falla nunca.  Subrayarlo entero mandaria a mirar una palabra clave.
         */
        const ast::Expr *e = nullptr;
        if (s->kind == ast::NodeKind::ReturnStmt)
            e = static_cast<const ast::ReturnStmt *>(s)->value.get();
        else if (s->kind == ast::NodeKind::ExprStmt)
            e = static_cast<const ast::ExprStmt *>(s)->expr.get();
        const vx::SourceLoc &loc =
            (e && e->loc.line == s->loc.line && e->loc.length > 0) ? e->loc
                                                                   : s->loc;
        StmtSpan sp;
        sp.symbol = fn_->name;
        sp.line = loc.line;
        sp.column = loc.column;
        sp.length = loc.length;
        emitted_spans_.push_back(std::move(sp));
        pend_stmt_column_ = loc.column;
        pend_stmt_len_ = loc.length;
    }
    /* Y se sella esa columna en lo que la sentencia emita.  Se hace al TERMINAR
     * y no en cada uno de los mil sitios que ponen la linea: bastaria olvidar
     * uno para que ese caso concreto perdiera la columna en silencio, que es la
     * forma en que estas cosas se rompen. */
    struct SellarColumna {
        ir::IrFunction *fn;
        uint32_t bloque;
        size_t desde;
        uint32_t columna;
        uint32_t longitud;

        ~SellarColumna() {
            if (!fn || columna == 0) return;
            if (bloque >= fn->blocks.size()) return;
            auto &ins = fn->blocks[bloque].instrs;
            for (size_t i = desde; i < ins.size(); ++i)
                if (ins[i].source_column == 0) {
                    ins[i].source_column = columna;
                    if (ins[i].source_len == 0) ins[i].source_len = longitud;
                }
        }
    } sellar{fn_, current_block_,
             (fn_ && current_block_ < fn_->blocks.size())
                 ? fn_->blocks[current_block_].instrs.size()
                 : 0,
             pend_stmt_column_, pend_stmt_len_};

    switch (s->kind) {
    case ast::NodeKind::BlockStmt:
        lower_block(static_cast<ast::BlockStmt *>(s));
        return;
    case ast::NodeKind::VarDeclStmt: {
        /* A.39: `comptime const NAME = expr;` local NO emite
         * codigo runtime.  Para comptime const declarados dentro
         * de un `comptime for` body, los re-evaluamos en CADA
         * iteracion via el stack dinamico del lowering -- el
         * type checker solo evalua una vez con el valor inicial.
         * Asi `comptime const SQ = j * j;` se actualiza por iter. */
        auto *vd = static_cast<ast::VarDeclStmt *>(s);
        /*  MC.17.1: cuando estamos dentro de un @Macro body
         * que se baja a IR, las VarDeclStmt marcadas
         * @c is_comptime se tratan como vars runtime regulares.
         * El macro corre en VM y los locales se computan en
         * cada invocacion -- mismo resultado semantico que la
         * evaluacion AST que ocurria one-time. */
        if (vd->is_comptime && current_fn_is_macro_) {
            lower_var_decl(vd);
            return;
        }
        if (vd->is_comptime) {
            if (!lowering_comptime_scopes_.empty() && vd->init) {
                /* Re-evaluar el init con el stack dinamico actual. */
                auto &mut_tc = const_cast<TypeChecker &>(tc_);
                const ComptimeEvalResult r =
                    comptime_eval_expr(mut_tc, vd->init.get());
                if (r.ok) {
                    ComptimeLocalEntry ent;
                    if (r.is_str) {
                        ent.is_str = true;
                        ent.str_value = r.str;
                    } else {
                        ent.value = r.value;
                    }
                    ent.ir_t = ir::IrType::I64;
                    /* Bind en el scope DEL TOPE actual (cae al pop
                     * del enclosing comptime for o block). */
                    lowering_comptime_scopes_.back()[vd->name] = ent;
                    /* Tambien actualizar tc para que evaluaciones
                     * posteriores en el body lo vean. */
                    TypeChecker::ComptimeConst c;
                    c.type = tc_.resolve_type_node(vd->type.get());
                    c.is_str = r.is_str;
                    if (r.is_str)
                        c.str_value = r.str;
                    else
                        c.value = r.value;
                    mut_tc.register_comptime_local(vd->name, std::move(c));
                }
            }
            return;
        }
        lower_var_decl(vd);
        return;
    }
    case ast::NodeKind::ComptimeBlockStmt:
        /* A.39: el bloque comptime no emite codigo runtime.  El
         * type checker ya proceso sus stmts (comptime const +
         * static_assert + comptime for/if).  Cualquier valor
         * comptime queda anotado en los IdentExpr correspondientes. */
        return;
    case ast::NodeKind::ComptimeForStmt:
        lower_comptime_for(static_cast<ast::ComptimeForStmt *>(s));
        return;
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<ast::ExprStmt *>(s);
        if (es->expr) (void)lower_expr(es->expr.get());
        return;
    }
    case ast::NodeKind::IfStmt: lower_if(static_cast<ast::IfStmt *>(s)); return;
    case ast::NodeKind::ReturnStmt:
        lower_return(static_cast<ast::ReturnStmt *>(s));
        return;
    case ast::NodeKind::WhileStmt:
        lower_while(static_cast<ast::WhileStmt *>(s));
        return;
    case ast::NodeKind::DoWhileStmt:
        lower_do_while(static_cast<ast::DoWhileStmt *>(s));
        return;
    case ast::NodeKind::ForStmt:
        lower_for(static_cast<ast::ForStmt *>(s));
        return;
    case ast::NodeKind::BreakStmt: {
        if (loop_targets_.empty()) {
            error_at(s->loc, "'break' fuera de un loop");
            return;
        }
        LoopTargets &lt = loop_targets_.back();
        // Registrar este bloque y el snapshot del scope para que
        // lower_while/for complete los PHIs del exit_bb con los SSA
        // values en este punto.  Sin esto, las variables modificadas
        // en el body antes del `break` NO se propagan al exit del
        // loop (los lectores del exit ven los SSA values del
        // INICIO de la iteracion, no del final).  Mismo patron que
        // continue_preds/continue_scopes.
        lt.break_preds.push_back(current_block_);
        lt.break_scopes.push_back(scopes_);
        emit_br(lt.break_bb, s->loc.line);
        block_terminated_ = true;
        return;
    }
    case ast::NodeKind::ContinueStmt: {
        if (loop_targets_.empty()) {
            error_at(s->loc, "'continue' fuera de un loop");
            return;
        }
        LoopTargets &lt = loop_targets_.back();
        // Registrar este bloque y el snapshot del scope para
        // que el lower_while/for complete los PHIs del header
        // con los SSA values en este punto de la ejecucion.
        lt.continue_preds.push_back(current_block_);
        lt.continue_scopes.push_back(scopes_);
        emit_br(lt.continue_bb, s->loc.line);
        block_terminated_ = true;
        return;
    }
    case ast::NodeKind::LabelStmt: {
        // Buscar/crear el bloque destino para esta label.  Si
        // ya hay un goto que la referencio, el bloque ya esta
        // creado (declared=false en ese momento); aqui lo
        // declaramos.  Caemos al label_bb desde el bloque
        // actual via BR (transparente: el codigo lineal
        // continua en label_bb tras la label).
        auto *ls = static_cast<ast::LabelStmt *>(s);
        auto it = goto_labels_.find(ls->name);
        ir::IrBlockId lab_bb;
        if (it == goto_labels_.end()) {
            lab_bb = fn_->new_block(std::string("lbl_") + ls->name);
            GotoEntry ge;
            ge.block = lab_bb;
            ge.declared = true;
            ge.first_use_loc = ls->loc;
            goto_labels_[ls->name] = ge;
        } else {
            if (it->second.declared) {
                error_at(ls->loc, std::string("label '") + ls->name +
                                      "' ya declarada en esta funcion");
                return;
            }
            it->second.declared = true;
            lab_bb = it->second.block;
        }
        // Conectar el bloque actual al label_bb si todavia no
        // termino (fall-through al label).
        if (!block_terminated_) {
            emit_br(lab_bb, ls->loc.line);
        }
        current_block_ = lab_bb;
        block_terminated_ = false;
        return;
    }
    case ast::NodeKind::GotoStmt: {
        auto *gs = static_cast<ast::GotoStmt *>(s);
        auto it = goto_labels_.find(gs->label);
        ir::IrBlockId lab_bb;
        if (it == goto_labels_.end()) {
            // Forward goto: crear el bloque ahora; se marcara
            // declarado al ver la label correspondiente.
            lab_bb = fn_->new_block(std::string("lbl_") + gs->label);
            GotoEntry ge;
            ge.block = lab_bb;
            ge.declared = false;
            ge.first_use_loc = gs->loc;
            goto_labels_[gs->label] = ge;
        } else {
            lab_bb = it->second.block;
        }
        emit_br(lab_bb, gs->loc.line);
        block_terminated_ = true;
        return;
    }
    case ast::NodeKind::TryStmt:
        lower_try(static_cast<ast::TryStmt *>(s));
        return;
    case ast::NodeKind::ThrowStmt:
        lower_throw(static_cast<ast::ThrowStmt *>(s));
        return;
    case ast::NodeKind::ForEachStmt:
        lower_foreach(static_cast<ast::ForEachStmt *>(s));
        return;
    case ast::NodeKind::SynchronizedStmt:
        lower_synchronized(static_cast<ast::SynchronizedStmt *>(s));
        return;
    case ast::NodeKind::AsmStmt:
        lower_asm(static_cast<ast::AsmStmt *>(s));
        return;
    default:
        unsupported(s->loc, "statement no soportado por el lowering actual");
        return;
    }
}

void Lowering::lower_if(ast::IfStmt *s) {
    // Sprint 3-B: `comptime if` -- dead-branch elimination.
    // El type checker ya valido que `cond` es comptime-evaluable y
    // ya descarto la rama no tomada del check.  Aqui simplemente
    // bajamos al SIN if/branch/phi.  Cero overhead vs codigo
    // hardcoded: el bytecode emitido es identico al de la rama
    // tomada sin marcador alguno de la condicion.
    if (s->is_comptime && s->cond) {
        const ComptimeEvalResult r = comptime_eval_expr(tc_, s->cond.get());
        if (r.ok) {
            if (r.value != 0) {
                if (s->then_branch) lower_stmt(s->then_branch.get());
            } else {
                if (s->else_branch) lower_stmt(s->else_branch.get());
            }
            return;
        }
        /* Si por algun motivo la evaluacion falla aqui (no deberia,
         * el type checker ya valido), caemos al lowering normal --
         * mas vale conservador que crash. */
    }

    // Patron CFG: cond -> br_cond %c, then, else; cada rama termina
    // con br merge (si no aborto antes en otro terminador).
    //
    // SSA construction (Braun on-the-fly): si una variable es asignada
    // en al menos una rama, en el merge insertamos un PHI con un arg
    // por cada predecesor del merge.  Sin esto, el binding del scope
    // tras el if seria el del UlTIMO branch ejecutado por el lowering
    // (no-determinista entre runs distintos del compilador y, mas
    // importante, INCORRECTO en runtime ya que el regalloc puede
    // poner la variable en registros distintos en cada rama).
    //
    // Algoritmo:
    //   1. Snapshot completo de los bindings ANTES del if (entry_bindings).
    //   2. Tras lower del then -> snapshot then_bindings y restaurar entry.
    //   3. Tras lower del else (si existe) -> snapshot else_bindings.
    //      Si no hay else, else_bindings = entry_bindings.
    //   4. En el merge: por cada nombre cuyo binding difiere entre
    //      then_bindings y else_bindings (o difiere de entry), emitir
    //      un PHI con args [(then_val, then_pred), (else_val, else_pred)]
    //      y rebindear el nombre al PHI.
    //
    // Solo aplicamos esto a variables del scope ENCLOSING (no a
    // declaradas dentro de las propias ramas; esas mueren al pop_scope
    // implicito del block).
    //
    // Casos especiales:
    //   - Si then o else terminan abruptamente (return/break/throw),
    //     ese predecesor no llega al merge y no contribuye al PHI.
    //   - Si AMBAS ramas terminan, no hay merge alcanzable; el codigo
    //     post-if es muerto.  Pero el lowering aun lo procesa.
    const ir::IrValueId cond = lower_expr(s->cond.get());
    // Si el tipo no es BOOL ya, el optimizador / emisor lo trataran
    // como "non-zero is true".  Para mas claridad podriamos insertar
    // un cmp_ne con 0 explicito, pero el bytecode @c jmp.jne ya hace
    // exactamente esa comparacion contra 0 sin instruccion adicional,
    // asi que delegar al backend es la opcion mas eficiente.

    const ir::IrBlockId then_bb = fn_->new_block("if_then");
    const bool has_else = s->else_branch != nullptr;
    const ir::IrBlockId else_bb =
        has_else ? fn_->new_block("if_else") : ir::IR_NO_BLOCK;
    const ir::IrBlockId merge_bb = fn_->new_block("if_merge");

    // Snapshot de los bindings activos antes de empezar las ramas.
    // Lo usamos despues para detectar variables modificadas en cada
    // rama y para restaurar el entry antes de bajar la rama else.
    std::vector<std::unordered_map<std::string, ir::IrValueId>> entry_scopes =
        scopes_;

    // Sin `else`, la salida falsa es directamente el punto de reunion.
    emit_br_cond(cond, then_bb, has_else ? else_bb : merge_bb, s->loc.line);

    // Rama then.
    current_block_ = then_bb;
    block_terminated_ = false;
    lower_stmt(s->then_branch.get());
    // Snapshot de los bindings tras el then; bloque actual al final
    // del then (si no termino).
    std::vector<std::unordered_map<std::string, ir::IrValueId>> then_scopes =
        scopes_;
    ir::IrBlockId then_pred = current_block_;
    const bool then_falls_through = !block_terminated_;
    if (then_falls_through) {
        // br merge_bb
        emit_br(merge_bb, s->loc.line);
        block_terminated_ = true;
    }

    // Restaurar bindings antes de bajar la rama else (los bindings de
    // then no deben "filtrarse" al else; cada rama parte del entry).
    scopes_ = entry_scopes;

    // Rama else (si existe).
    ir::IrBlockId else_pred = ir::IR_NO_BLOCK;
    bool else_falls_through = false;
    std::vector<std::unordered_map<std::string, ir::IrValueId>> else_scopes;
    if (has_else) {
        current_block_ = else_bb;
        block_terminated_ = false;
        lower_stmt(s->else_branch.get());
        else_scopes = scopes_;
        else_pred = current_block_;
        else_falls_through = !block_terminated_;
        if (else_falls_through) {
            emit_br(merge_bb, s->loc.line);
            block_terminated_ = true;
        }
    } else {
        // Sin else: el "branch else" es el propio entry, que cae
        // directo al merge sin pasar por else_bb.  Su pred del merge
        // es el bloque del que venia el if (añadido arriba via
        // fn_->blocks[merge_bb].preds.push_back(current_block_)
        // antes de la rama then).  El else_pred en ese caso es ese
        // pred original (current_block_ ANTES del then).  Recuperamos
        // de la CFG: el primer pred del merge tras llamar a anadir el
        // entry-no-else es exactamente ese.
        // Como simplificacion: dejamos else_scopes = entry_scopes y
        // else_pred = el primer pred del merge (que es current_block_
        // del entry original justo antes del br).  Lo identificamos
        // por exclusion: cualquier pred != then_pred.
        else_scopes = entry_scopes;
        for (auto pid : fn_->blocks[merge_bb].preds) {
            if (pid != then_pred) {
                else_pred = pid;
                break;
            }
        }
        else_falls_through = true; // el camino "no-else" siempre llega
    }

    // -------- Insertar PHIs en el merge --------
    // Solo si AMBAS ramas (o then-fall + no-else) llegan al merge.
    // Si una sola rama llega, el binding correcto es el de esa rama
    // (no necesita PHI; la otra es codigo muerto pre-merge).
    current_block_ = merge_bb;
    block_terminated_ = false;
    const bool then_reaches = then_falls_through;
    const bool else_reaches = else_falls_through;
    if (then_reaches && else_reaches) {
        // Recorremos cada nivel de scope (ENTRY = referencia comun).
        // Para cada nombre que existia en entry_scopes, comparamos
        // los bindings finales de then y else.  Si difieren entre si
        // o respecto al entry, emitimos PHI.
        //
        // Notacion: scope_idx = nivel; tomamos como referencia el
        // depth original (entry_scopes.size()).  Si las ramas
        // añaden scopes nuevos, los ignoramos (variables locales a
        // la rama).
        const size_t depth = entry_scopes.size();
        const size_t depth_then = then_scopes.size();
        const size_t depth_else = else_scopes.size();
        for (size_t lvl = 0; lvl < depth; ++lvl) {
            if (lvl >= depth_then || lvl >= depth_else) break;
            for (auto &kv : entry_scopes[lvl]) {
                const std::string &name = kv.first;
                auto itt = then_scopes[lvl].find(name);
                auto ite = else_scopes[lvl].find(name);
                if (itt == then_scopes[lvl].end() ||
                    ite == else_scopes[lvl].end())
                    continue;
                const ir::IrValueId vt = itt->second;
                const ir::IrValueId ve = ite->second;
                // Si ambas ramas dejan el mismo SSA value, no hay
                // necesidad de PHI: el binding ya es coherente.
                if (vt == ve) {
                    // Asegurar que el scope merge tiene el valor
                    // correcto (en caso de que entry_scopes lo
                    // tuviera distinto pero ambas ramas coinciden).
                    scopes_[lvl][name] = vt;
                    continue;
                }
                // Crear el PHI en el merge.  Usamos el tipo del SSA
                // del then (deberia ser igual al del else; el type
                // checker lo garantiza al haber validado las dos
                // asignaciones contra el tipo declarado).
                const ir::IrType phi_ty = fn_->values[vt].type;
                ir::IrValueId phi_v = fn_->new_value(phi_ty);
                ir::IrInstr phi{};
                phi.op = ir::IrOp::PHI;
                phi.type = phi_ty;
                phi.dst = phi_v;
                phi.phi_args.push_back({vt, then_pred});
                if (else_pred != ir::IR_NO_BLOCK) {
                    phi.phi_args.push_back({ve, else_pred});
                }
                phi.source_line = s->loc.line;
                // INSERTAR al INICIO del merge_bb (PHIs siempre van al
                // principio del bloque).  fn_->append solo hace
                // push_back, asi que insertamos manualmente.
                fn_->blocks[merge_bb].instrs.insert(
                    fn_->blocks[merge_bb].instrs.begin(), std::move(phi));
                scopes_[lvl][name] = phi_v;
            }
        }
    } else if (then_reaches) {
        // Solo then llega: usa los bindings de then.
        scopes_ = then_scopes;
    } else if (else_reaches) {
        // Solo else llega: usa los bindings de else.
        scopes_ = else_scopes;
    } else {
        // Ninguna rama llega al merge (ambas hicieron return / break /
        // throw).  El merge es codigo muerto pero el lowering aun lo
        // procesa; mantener entry_scopes evita usos indefinidos.
        scopes_ = entry_scopes;
    }
}

// ---------------------------------------------------------------------
// Lowering de loops via SSA construction on-the-fly (Braun et al.).
//
// Patron general para 'while (cond) body':
//
//     entry:
//         ...
//         br header
//     header:
//         x = phi.T [x_pre, entry], [x_loop, body_end]    ; uno por var
//         cond_v = lower(cond)
//         br.cond cond_v, body, exit
//     body:
//         (lowering del body; las asignaciones cambian scope[x] -> nuevo
//         IrValueId) br header                                      ; back-edge
//     exit:
//         (continuacion del codigo posterior al loop)
//
// El paso clave es identificar las variables que se modifican dentro
// del cond+body y emitir un PHI por cada una en el header.  El primer
// arg del PHI viene del entry (el valor previo al loop); el segundo
// arg se añade al final, una vez bajado el body, con el valor que
// queda en scope tras la ultima iteracion.
//
// Las variables NO modificadas no necesitan PHI: el lookup() las
// encuentra a traves del scope chain con su valor pre-loop.
// ---------------------------------------------------------------------

// Nota: la auto-vectorizacion de bucles (try_lower_memcpy_idiom / _for,
// mc_match_copy_assign, mc_emit_copy) vive en src/vx/vectorize.cpp para no
// inflar este TU; son metodos de Lowering declarados en vx/lowering.h.

void Lowering::lower_while(ast::WhileStmt *s) {
    if (!s) return;

    // Auto-vectorizacion: si el while es EXACTAMENTE el idioma de copia de
    // bytes/elementos `while (i < N) { dst[i] = src[i]; i++; }` sobre punteros
    // HOST, lo reemplazamos por un MEMCPY (rep movsb / SIMD en JIT/AOT; bucle
    // host->host en el interprete).  Si no matchea, seguimos con el lowering
    // normal del while.
    static const bool no_vec = util::flag_on(util::FlagId::NoVectorize);
    if (!no_vec) {
        if (try_lower_memcpy_idiom(s)) return;
        // Auto-vectorizacion aritmetica/unaria/reduccion sobre la forma
        // `while`: `while (i < N) { c[i] = a[i] OP b[i]; i++; }` (y
        // unaria/reduccion) -> mismo VEC_BINOP/VEC_UNOP que el `for`.  Los
        // matchers extraen el descriptor de loop de un for o while via
        // mc_extract_vec_loop.
        if (try_vectorize_elementwise_for(s)) return;
        if (try_vectorize_scalar_for(s)) return;
        if (try_vectorize_unary_for(s)) return;
        if (try_vectorize_compound_for(s)) return;
        if (try_vectorize_reduction_for(s)) return;
    } // !no_vec

    // Pre-walk: variables mutadas en cond+body.
    std::set<std::string> modified;
    collect_assigned_vars(s->cond.get(), modified);
    collect_assigned_vars(s->body.get(), modified);

    // Filtrar: solo nos interesan las que ya existen en el scope antes
    // del loop (variables externas).  Las locales declaradas dentro del
    // body no necesitan PHI.
    struct VarInfo {
        std::string name;
        ir::IrType type;
        ir::IrValueId pre_loop;
        ir::IrValueId phi_value;
        size_t phi_idx; // posicion del PHI dentro de header.instrs
    };
    std::vector<VarInfo> vars;
    vars.reserve(modified.size());
    for (const auto &name : modified) {
        ir::IrValueId pre = lookup(name);
        if (pre == ir::IR_NO_VALUE) continue; // variable local al body, ignorar
        VarInfo vi;
        vi.name = name;
        vi.type = fn_->values[pre].type;
        vi.pre_loop = pre;
        vars.push_back(vi);
    }

    // Crear bloques para el patron CFG estandar de while.
    const ir::IrBlockId entry_block = current_block_;
    const ir::IrBlockId header_id = fn_->new_block("while_header");
    const ir::IrBlockId body_id = fn_->new_block("while_body");
    const ir::IrBlockId exit_id = fn_->new_block("while_exit");

    // 1. Entry -> header (BR incondicional).
    emit_br_from(entry_block, header_id, s->loc.line);

    // 2. En el header, emitir un PHI por cada variable mutada.  Solo
    //    se añade el primer arg (entry); el back-edge se completa
    //    despues de bajar el body.
    for (auto &vi : vars) {
        vi.phi_value = fn_->new_value(vi.type);
        ir::IrInstr phi{};
        phi.op = ir::IrOp::PHI;
        phi.type = vi.type;
        phi.dst = vi.phi_value;
        phi.phi_args.push_back({vi.pre_loop, entry_block});
        phi.source_line = s->loc.line;
        emit(header_id, std::move(phi));
        vi.phi_idx = fn_->blocks[header_id].instrs.size() - 1;
        // Dentro del loop, las lecturas de `name` deben ver el valor del PHI.
        update_scope(vi.name, vi.phi_value);
    }

    // 3. Bajar la condicion en el header y emitir BR_COND.  La cond
    //    puede crear bloques intermedios (e.g. short-circuit `&&`/`||`
    //    construye rhs_bb + default_bb + merge_bb).  En ese caso al
    //    volver de @c lower_expr el @c current_block_ NO es header_id
    //    sino el merge_bb del short-circuit.  Emitir el BR_COND en
    //    @c current_block_ y registrar el predecesor real del body/exit
    //    es lo correcto; el header_id queda terminado por el BR_COND
    //    interno del short-circuit.
    current_block_ = header_id;
    block_terminated_ = false;
    ir::IrValueId cond_v = lower_expr(s->cond.get());
    if (cond_v == ir::IR_NO_VALUE) {
        // Defensa: si la condicion fallo en bajar, abortar el loop.
        return;
    }
    const ir::IrBlockId cond_end_block = current_block_;
    emit_br_cond_from(cond_end_block, cond_v, body_id, exit_id, s->loc.line);
    block_terminated_ = true;
    // 4. Bajar el body en body_id.  Push targets de break/continue
    //    para que cualquier @c BreakStmt o @c ContinueStmt anidado
    //    sepa adonde saltar.
    loop_targets_.push_back({header_id, exit_id, {}, {}});
    current_block_ = body_id;
    block_terminated_ = false;
    lower_stmt(s->body.get());
    // Capturar targets ANTES del pop para usar continue_preds en
    // la fase de completar PHIs.
    LoopTargets lt = std::move(loop_targets_.back());
    loop_targets_.pop_back();

    // Completar PHIs del header con cada `continue` que se hizo
    //     dentro del body.  Cada continue contribuye con un arg al
    //     PHI usando los SSA values del scope al momento del
    //     continue (capturados en lt.continue_scopes).
    for (size_t ci = 0; ci < lt.continue_preds.size(); ++ci) {
        const ir::IrBlockId cpred = lt.continue_preds[ci];
        const auto &csnap = lt.continue_scopes[ci];
        for (auto &vi : vars) {
            ir::IrValueId v = ir::IR_NO_VALUE;
            // Buscar la var en el scope-snapshot (de mas profundo
            // al mas externo, igual que lookup() haria).
            for (auto it = csnap.rbegin(); it != csnap.rend(); ++it) {
                auto j = it->find(vi.name);
                if (j != it->end()) {
                    v = j->second;
                    break;
                }
            }
            if (v == ir::IR_NO_VALUE) v = vi.phi_value;
            fn_->blocks[header_id].instrs[vi.phi_idx].phi_args.push_back(
                {v, cpred});
        }
    }

    // Si el body no termino con un return/break, añadir el back-edge
    //    al header.  Si fue break/continue, el lowering de esos statements
    //    ya emitio BR al target adecuado y marco @c block_terminated_.
    if (!block_terminated_) {
        const ir::IrBlockId body_end_id = current_block_;
        emit_br_from(body_end_id, header_id, s->loc.line);
        block_terminated_ = true;

        // 6. Completar PHIs con el valor que queda en scope tras la
        //    ultima iteracion (back-edge).
        for (auto &vi : vars) {
            ir::IrValueId post = lookup(vi.name);
            if (post == ir::IR_NO_VALUE) post = vi.phi_value;
            fn_->blocks[header_id].instrs[vi.phi_idx].phi_args.push_back(
                {post, body_end_id});
            // Bug D fix: si algun arg del PHI es is_gc_object (e.g.
            // una asignacion en el body propaga un host_ptr GC al
            // PHI value), el PHI value mismo debe heredar el flag
            // para que save_live_regs de futuros CALLs lo guarde
            // como gchandle (estable a evacuacion del GC).  Sin
            // esto, valores CLASS que entran al loop como NULL
            // (no-GC) y se asignan en iter 1 a un objeto real,
            // tienen sus host_ptrs invalidados en iter 2+.
            if (static_cast<size_t>(post) < fn_->values.size() &&
                fn_->values[post].is_gc_object) {
                fn_->values[vi.phi_value].is_gc_object = true;
            }
            if (static_cast<size_t>(vi.pre_loop) < fn_->values.size() &&
                fn_->values[vi.pre_loop].is_gc_object) {
                fn_->values[vi.phi_value].is_gc_object = true;
            }
            // Mismo razonamiento para is_host_ptr: si algun arg del PHI es un
            // host_ptr (p.ej. un gc<T> o un malloc que entra por el back-edge),
            // el PHI value DEBE heredar el flag.  Sin esto, el stackmap del GC
            // etiqueta el slot como HANDLE en vez de HOSTPTR -> el scan preciso
            // lo trata como un indice de handle (basura) y el forward-pass del
            // GC movible NO reescribe el slot tras evacuar -> host_ptr rancio +
            // objeto perdido (UAF).  Ademas LOAD/STORE emitirian mov en vez de
            // movh.  Todos los args no-null de un mismo PHI comparten host-ness
            // (null=0 es indiferente), asi que el OR es correcto.
            if (static_cast<size_t>(post) < fn_->values.size() &&
                fn_->values[post].is_host_ptr) {
                fn_->values[vi.phi_value].is_host_ptr = true;
            }
            if (static_cast<size_t>(vi.pre_loop) < fn_->values.size() &&
                fn_->values[vi.pre_loop].is_host_ptr) {
                fn_->values[vi.phi_value].is_host_ptr = true;
            }
        }
    } else {
        // Body termina con un return: el back-edge nunca se ejecuta.
        // Completamos el PHI con el propio phi_value (placeholder
        // semanticamente correcto: si nunca se llega, no se observa).
        for (auto &vi : vars) {
            fn_->blocks[header_id].instrs[vi.phi_idx].phi_args.push_back(
                {vi.phi_value, header_id});
        }
    }

    // 7. Continuar en exit_id.  Las variables modificadas tienen como
    //    valor "vivo" el del PHI: al salir del loop por la condicion
    //    falsa, la ultima escritura observable es la del header.
    // 7.b LANG.fix-7: si hay breaks, el exit_id tiene multiples preds
    //    (cond_end_block + cada break_pred).  Cada break visita el
    //    exit con un snapshot distinto del scope, asi que necesitamos
    //    insertar PHIs al inicio del exit_id para que las variables
    //    modificadas converjan correctamente.  Sin esto, el codigo
    //    despues del while ve el valor del header (vi.phi_value)
    //    incluso cuando el break vino tras modificaciones (e.g.
    //    `while (true) { i = i + 1; if (i >= 5) break; }` -- el
    //    `i` post-loop debe ser 5, no el phi del header que es 4).
    current_block_ = exit_id;
    block_terminated_ = false;
    if (!lt.break_preds.empty()) {
        // Por cada var modificada, crear PHI en el exit_id con args
        // {phi_value @ cond_end_block} + un arg por cada break_pred
        // con el snapshot del scope en ese punto.
        for (auto &vi : vars) {
            ir::IrInstr phi{};
            phi.op = ir::IrOp::PHI;
            phi.dst = fn_->new_value(vi.type);
            phi.type = vi.type;
            phi.source_line = s->loc.line;
            // Propagar flags importantes del PHI del header.
            if (static_cast<size_t>(vi.phi_value) < fn_->values.size()) {
                fn_->values[phi.dst].is_gc_object =
                    fn_->values[vi.phi_value].is_gc_object;
                fn_->values[phi.dst].is_host_ptr =
                    fn_->values[vi.phi_value].is_host_ptr;
            }
            // Edge desde cond_end_block: trae el phi_value del header
            // (visto al evaluar la condicion como falsa).
            phi.phi_args.push_back({vi.phi_value, cond_end_block});
            // Edges desde cada break_pred: usan el snapshot del scope.
            for (size_t bi = 0; bi < lt.break_preds.size(); ++bi) {
                const ir::IrBlockId bpred = lt.break_preds[bi];
                const auto &bsnap = lt.break_scopes[bi];
                ir::IrValueId v = ir::IR_NO_VALUE;
                for (auto it = bsnap.rbegin(); it != bsnap.rend(); ++it) {
                    auto j = it->find(vi.name);
                    if (j != it->end()) {
                        v = j->second;
                        break;
                    }
                }
                if (v == ir::IR_NO_VALUE) v = vi.phi_value;
                // Propagar flags GC si el value tiene.
                if (static_cast<size_t>(v) < fn_->values.size() &&
                    fn_->values[v].is_gc_object) {
                    fn_->values[phi.dst].is_gc_object = true;
                }
                phi.phi_args.push_back({v, bpred});
            }
            // Insertar el PHI al inicio del exit_id (PHIs van al
            // inicio del bloque por convencion SSA).
            fn_->blocks[exit_id].instrs.insert(
                fn_->blocks[exit_id].instrs.begin(), std::move(phi));
            update_scope(vi.name, fn_->blocks[exit_id].instrs[0].dst);
        }
    } else {
        for (auto &vi : vars) {
            update_scope(vi.name, vi.phi_value);
        }
    }
}

// ---------------------------------------------------------------------
// do-while.
//
// Patron CFG (la primera iteracion del body se ejecuta sin chequear cond):
//
//     entry:
//         ...
//         br body
//     body:
//         x = phi.T [x_pre, entry], [x_loop, header]    ; uno por var
//         (lowering del body)
//         br header
//     header:
//         cond_v = lower(cond)
//         br.cond cond_v, body, exit                    ; back-edge a body
//     exit:
//
// Diferencia con while: el body es donde se insertan los PHIs (no el
// header), porque body es el unico bloque con dos predecesores
// (entry para la primera iteracion + header para las siguientes).  El
// header solo evalua la condicion y no escribe variables, asi que el
// valor que "llega" al body desde el header coincide con el valor al
// final del body (lookup tras bajar el body).
// ---------------------------------------------------------------------
void Lowering::lower_do_while(ast::DoWhileStmt *s) {
    if (!s) return;

    std::set<std::string> modified;
    collect_assigned_vars(s->body.get(), modified);
    collect_assigned_vars(s->cond.get(), modified);

    struct VarInfo {
        std::string name;
        ir::IrType type;
        ir::IrValueId pre_loop;
        ir::IrValueId phi_value;
        size_t phi_idx;
    };
    std::vector<VarInfo> vars;
    vars.reserve(modified.size());
    for (const auto &name : modified) {
        ir::IrValueId pre = lookup(name);
        if (pre == ir::IR_NO_VALUE) continue;
        VarInfo vi;
        vi.name = name;
        vi.type = fn_->values[pre].type;
        vi.pre_loop = pre;
        vars.push_back(vi);
    }

    const ir::IrBlockId entry_block = current_block_;
    const ir::IrBlockId body_id = fn_->new_block("dowhile_body");
    const ir::IrBlockId header_id = fn_->new_block("dowhile_header");
    const ir::IrBlockId exit_id = fn_->new_block("dowhile_exit");

    // entry -> body (BR incondicional para la primera iteracion).
    emit_br_from(entry_block, body_id, s->loc.line);

    // PHIs en body.  El primer pred es entry; el segundo (header) se
    // completa al final.
    for (auto &vi : vars) {
        vi.phi_value = fn_->new_value(vi.type);
        ir::IrInstr phi{};
        phi.op = ir::IrOp::PHI;
        phi.type = vi.type;
        phi.dst = vi.phi_value;
        phi.phi_args.push_back({vi.pre_loop, entry_block});
        phi.source_line = s->loc.line;
        emit(body_id, std::move(phi));
        vi.phi_idx = fn_->blocks[body_id].instrs.size() - 1;
        update_scope(vi.name, vi.phi_value);
    }

    // Bajar body en body_id.  Push targets de break/continue del
    // do-while.  En do-while continue salta al header (que evalua
    // cond y decide back-edge); break salta al exit.
    loop_targets_.push_back({header_id, exit_id, {}, {}});
    current_block_ = body_id;
    block_terminated_ = false;
    lower_stmt(s->body.get());
    loop_targets_.pop_back();

    // Si el body no termino con return, BR a header.
    if (!block_terminated_) {
        const ir::IrBlockId body_end_id = current_block_;
        emit_br_from(body_end_id, header_id, s->loc.line);
        block_terminated_ = true;
    } else {
        // body termina con return: header nunca se alcanza.  Aun asi
        // necesitamos completar los PHIs con un placeholder para
        // mantener el IR estructuralmente valido.
        for (auto &vi : vars) {
            fn_->blocks[body_id].instrs[vi.phi_idx].phi_args.push_back(
                {vi.phi_value, body_id});
        }
        current_block_ = exit_id;
        block_terminated_ = false;
        for (auto &vi : vars)
            update_scope(vi.name, vi.phi_value);
        return;
    }

    // En header: bajar cond + BR_COND a body|exit.  Como en lower_while,
    // la cond puede crear bloques intermedios (short-circuit `&&`/`||`);
    // el BR_COND debe emitirse en @c current_block_ tras lower_expr.
    current_block_ = header_id;
    block_terminated_ = false;
    ir::IrValueId cond_v = lower_expr(s->cond.get());
    if (cond_v == ir::IR_NO_VALUE) return;
    const ir::IrBlockId cond_end_block = current_block_;
    // El destino verdadero es el back-edge: vuelve al cuerpo del bucle.
    emit_br_cond_from(cond_end_block, cond_v, body_id, exit_id, s->loc.line);
    block_terminated_ = true;
    // Patchar PHIs de body con el back-edge desde el bloque que termina
    // la cond (puede ser != header si hubo short-circuit).
    for (auto &vi : vars) {
        ir::IrValueId loop_val = lookup(vi.name);
        if (loop_val == ir::IR_NO_VALUE) loop_val = vi.phi_value;
        fn_->blocks[body_id].instrs[vi.phi_idx].phi_args.push_back(
            {loop_val, cond_end_block});
    }

    current_block_ = exit_id;
    block_terminated_ = false;
    // Tras salir del loop, las variables tienen su ultimo valor:
    // como el body se ejecuto y luego el header decidio salir, el
    // valor "vivo" en exit es el mismo que llego al header (lookup
    // en el momento del BR_COND).  No hace falta tocar scope aqui.
    (void)vars;
}

void Lowering::lower_for(ast::ForStmt *s) {
    if (!s) return;

    // VESTA_NO_VECTORIZE=1 desactiva TODA la auto-vectorizacion (loops
    // escalares)
    // -> linea base para benchmarks (escalar vs SSE2 vs AVX2).
    static const bool no_vec = util::flag_on(util::FlagId::NoVectorize);
    if (!no_vec) {
        // Auto-vectorizacion: la forma canonica del memcpy
        // `for (T i = init; i < N; i++) dst[i] = src[i];` (ver vectorize.cpp).
        if (try_lower_memcpy_idiom_for(s)) return;
        // Auto-vectorizacion aritmetica: `for (...) c[i] = a[i] OP b[i];` f64
        // host
        // -> loop W=2 con VEC_BINOP (SIMD) + cola escalar.
        if (try_vectorize_elementwise_for(s)) return;
        // Auto-vectorizacion scalar broadcast: `for (...) c[i] = a[i] OP
        // scalar;` f64 host -> loop W=2 con VEC_BINOP_S (scalar difundido) +
        // cola escalar.
        if (try_vectorize_scalar_for(s)) return;
        // Auto-vectorizacion unaria: `for (...) b[i] = OP a[i];` (-a/sqrt/fabs)
        // f64 host -> loop W=2 con VEC_UNOP (SIMD) + cola escalar.
        if (try_vectorize_unary_for(s)) return;
        // Auto-vectorizacion COMPOUND: `for (...) c[i] = a[i]*k + b[i];`
        // (cadena multi-op) -> cadena de VEC ops con c acumulador + cola
        // escalar.  Tras los matchers de 1-op (que cubren las formas simples).
        if (try_vectorize_compound_for(s)) return;
        // Auto-vectorizacion de reduccion: `for (...) acc = acc + a[i];` f64
        // host
        // -> acumulador vectorial W=2 + reduccion horizontal + cola escalar.
        if (try_vectorize_reduction_for(s)) return;
    } // !no_vec

    // for(init; cond; step) body
    //
    // Lowering con vars de loop ADDRESS-TAKEN: las variables modificadas
    // en cond/body/step se convierten en stack slots (ALLOCA + LOAD/STORE)
    // durante la vida del loop.  Sin esto, los PHI nodes cross-block
    // disparan un bug del linear scan (back-edges con def lineal posterior
    // al use), reusando el reg de la var del loop dentro del body y
    // corrompiendo el back-edge.  El coste es 1 LOAD/STORE extra por
    // acceso a var del loop, despreciable comparado con la operacion del
    // loop tipica.
    //
    // CFG:
    //   entry -> [init] -> [ALLOCA + STORE init] -> header
    //   header -> br_cond cond -> body | exit
    //   body  -> step (fall-through al final, o via continue)
    //   step  -> header (back-edge; las vars se actualizan via STORE)
    //   exit  (target de break; tras el loop, las vars vuelven a SSA
    //   leyendo del slot)
    push_scope();
    if (s->init) {
        lower_stmt(s->init.get());
        if (block_terminated_) {
            pop_scope();
            return;
        }
    }

    // Pre-walk: variables mutadas en cond+body+step.
    std::set<std::string> modified;
    if (s->cond) collect_assigned_vars(s->cond.get(), modified);
    if (s->body) collect_assigned_vars(s->body.get(), modified);
    if (s->step) collect_assigned_vars(s->step.get(), modified);

    // Para cada var: alocar slot, STORE el valor inicial, marcarla como
    // address-taken, bindear el name al addr.  Las lecturas usaran LOAD
    // y las escrituras usaran STORE (mismo mecanismo que &local).
    struct LoopVarInfo {
        std::string name;
        ir::IrType type;
        ir::IrValueId addr;     // SSA value del puntero (PTR)
        ir::IrValueId pre_loop; // SSA original antes del loop
    };
    std::vector<LoopVarInfo> vars;
    vars.reserve(modified.size());
    for (const auto &name : modified) {
        ir::IrValueId pre = lookup(name);
        if (pre == ir::IR_NO_VALUE) continue;
        LoopVarInfo vi;
        vi.name = name;

        // Si la var ya esta address-taken (e.g. usada en un loop
        // previo, o el usuario hizo &name), `pre` ES la addr del slot
        // existente.  En ese caso NO alocamos un slot nuevo: reusamos
        // el slot existente.  Sin esta deteccion, dos for/while
        // consecutivos sobre la misma variable creaban slots nuevos
        // sin sincronizar y los STORE/LOAD posteriores leeran el slot
        // viejo del primer loop.
        if (address_taken_locals_.count(name)) {
            // pre es la addr del slot existente.  El tipo del valor
            // que vive en el slot lo recuperamos del bind original
            // (la addr es PTR pero el slot guarda i32/i64/etc).
            // Como mi info de tipo solo se materializa al alocar,
            // inferimos i64 para tipo desconocido aqui.
            vi.type = ir::IrType::I64;
            vi.addr = pre;
            vi.pre_loop = pre;
            vars.push_back(vi);
            continue;
        }
        vi.type = fn_->values[pre].type;
        vi.pre_loop = pre;

        // ALLOCA 8 bytes (i64) en current block (entry block del for).
        ir::IrValueId addr = stack_alloc_buf(8, s->loc.line);

        // STORE pre_loop (el VALOR original SSA) al slot.
        emit_store_typed(addr, pre, vi.type, s->loc.line);

        vi.addr = addr;
        vars.push_back(vi);
        // Marcar address-taken y bindear el nombre a la direccion del slot
        // (igual que `&x` haria con un local).  read_local/write_local
        // detectan esto y emiten LOAD/STORE.
        address_taken_locals_.insert(name);
        update_scope(name, addr);
    }

    const ir::IrBlockId entry_block = current_block_;
    const ir::IrBlockId header_id = fn_->new_block("for_header");
    const ir::IrBlockId body_id = fn_->new_block("for_body");
    const ir::IrBlockId step_id = fn_->new_block("for_step");
    const ir::IrBlockId exit_id = fn_->new_block("for_exit");

    // entry -> header
    emit_br_from(entry_block, header_id, s->loc.line);

    // header: bajar cond + br_cond.  Si no hay cond, asumimos true.
    current_block_ = header_id;
    block_terminated_ = false;
    ir::IrValueId cond_v;
    if (s->cond) {
        cond_v = lower_expr(s->cond.get());
        if (cond_v == ir::IR_NO_VALUE) {
            pop_scope();
            return;
        }
    } else {
        cond_v = emit_const(ir::IrType::BOOL, 1, s->loc.line);
    }
    const ir::IrBlockId cond_end_block = current_block_;
    emit_br_cond_from(cond_end_block, cond_v, body_id, exit_id, s->loc.line);
    // Body: push targets {continue=step, break=exit}.
    loop_targets_.push_back({step_id, exit_id, {}, {}});
    current_block_ = body_id;
    block_terminated_ = false;
    if (s->body) lower_stmt(s->body.get());
    LoopTargets lt = std::move(loop_targets_.back());
    loop_targets_.pop_back();

    // Si el body cayo (no return/break), BR a step.
    if (!block_terminated_) {
        const ir::IrBlockId body_end_id = current_block_;
        emit_br_from(body_end_id, step_id, s->loc.line);
    }

    current_block_ = step_id;
    block_terminated_ = false;
    if (s->step) {
        (void)lower_expr(s->step.get());
    }
    if (!block_terminated_) {
        const ir::IrBlockId step_end_id = current_block_;
        emit_br_from(step_end_id, header_id, s->loc.line);
    }
    // Suprimir el unused warning si hay continue_preds (las edges ya
    // estan registradas por ContinueStmt; no hace falta hacer nada
    // adicional aqui).
    (void)lt;

    // Continuar en exit.  Las vars del loop siguen address-taken; los
    // accesos posteriores van por LOAD del slot.  No las desmarcamos
    // de @c address_taken_locals_ porque tipicamente la var muere al
    // salir del scope del for (e.g. `j` declarada en el init).  Para
    // vars del scope exterior (e.g. `sum`), permanecer address-taken
    // tiene un costo despreciable y mantiene la semantica consistente.
    current_block_ = exit_id;
    block_terminated_ = false;
    pop_scope();
}

void Lowering::lower_return(ast::ReturnStmt *s) {
    // Multihilo AOT: join-all implicito de los hilos lanzados por `spawn` ANTES
    // del RET de main, para que sus efectos (sobre globals compartidos) esten
    // completos cuando main lee su valor de retorno.  Se inyecta en CADA return
    // de main; __vx_thread_join_all es no-op si no hay hilos.
    if (native_poo_ && vx_thread_used_ && fn_ != nullptr &&
        fn_->name == "main") {
        ir::IrInstr jc{};
        jc.op = ir::IrOp::CALL;
        jc.type = ir::IrType::VOID;
        jc.dst = ir::IR_NO_VALUE;
        jc.func_name = "__vx_thread_join_all";
        jc.is_call_site = true;
        jc.source_line = s->loc.line;
        emit(current_block_, std::move(jc));
    }
    // sret: si la funcion declara devolver Optional/Result, no
    // emitimos un RET con valor; en cambio:
    //   1. Bajamos s->value a un buffer local (Some/Ok/Err producen
    //      una ALLOCA stack-local en esta funcion).
    //   2. MEMCPY del buffer local al retbuf que recibimos del caller.
    //   3. RET void.
    // Esto es la convencion sret estandar: sin heap allocation, sin
    // leaks; el caller decide donde vive el resultado.
    if (sret_active_ && s->value) {
        // M7 -- in-place SRET para `return unique_box(...)`: si la
        // funcion devuelve un smart pointer (sret_buf_size_=16) y el
        // value retornado es un CallExpr a `unique_box`/`shared_box`,
        // construimos el smart pointer DIRECTAMENTE en el retbuf del
        // caller, saltandonos la copia qword-a-qword al final.  El
        // lowering de unique_box consulta @c unique_box_target_slot_
        // y lo usa como slot en vez de hacer stack_alloc_buf.
        bool inplace_sret = false;
        if (sret_buf_size_ == 16 && s->value->kind == ast::NodeKind::CallExpr) {
            auto *ce = static_cast<ast::CallExpr *>(s->value.get());
            if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr) {
                auto *id = static_cast<ast::IdentExpr *>(ce->callee.get());
                if (id->name == "unique_box" || id->name == "shared_box" ||
                    id->name == "unique_with" || id->name == "shared_with") {
                    inplace_sret = true;
                    unique_box_target_slot_ = sret_retbuf_;
                }
            }
        }
        // Vesta Embed (native_poo_): si la funcion retorna `string`
        // value-type y el `return <expr>` es un literal NO interpolado,
        // construir el value-string nativo ({ptr,len,cap} con buffer
        // heap propio) en vez de devolver el str_lit_addr crudo (que
        // apunta a los BYTES en static_data, no a un value-string).
        // Sin esto, la copia SRET leeria los bytes del literal como si
        // fueran {ptr,len,cap} -> basura -> segfault.
        ir::IrValueId v_local;
        if (current_fn_sret_str_value_ &&
            s->value->kind == ast::NodeKind::StringLitExpr &&
            !static_cast<ast::StringLitExpr *>(s->value.get())
                 ->is_interpolated()) {
            v_local = build_native_string_from_literal(
                static_cast<ast::StringLitExpr *>(s->value.get()), s->loc.line);
        } else {
            v_local = lower_expr(s->value.get());
        }
        unique_box_target_slot_ = ir::IR_NO_VALUE; // limpiar siempre
        if (inplace_sret) {
            // El smart pointer ya se construyo IN-PLACE sobre el
            // retbuf del caller.  No hace falta copia final; saltamos
            // al RET directamente.
            emit_cleanups_all();
            // Instrumentacion: emitir vx_trace:leave antes del RET
            // tambien en este path SRET (mismo filtro que lower_return
            // del path normal).  Sin esto, fns que retornan
            // unique<T>/shared<T> NO cierran el trace y producen un
            // arbol descuadrado.
            if (instrument_mode_ != "none" && instrument_mode_ != "" &&
                fn_ != nullptr) {
                const std::string &fname = fn_->name;
                const bool is_helper = is_compiler_generated_fn(fn_->name);
                if (!is_helper) {
                    emit_instrument_exit(fname, sret_retbuf_, s->loc.line);
                }
            }
            ir::IrInstr ret{};
            ret.op = ir::IrOp::RET;
            ret.type = ir::IrType::VOID;
            ret.source_line = s->loc.line;
            emit(current_block_, std::move(ret));
            block_terminated_ = true;
            return;
        }
        // String Inc 5 (SSO): el retorno de un value-string por valor copia
        // los 24 bytes via MEMCPY (rep movsb) en lugar de 3 LOAD/STORE i64.
        // Los i64 LOADs de qword2 mal-resolvian el store-forwarding (data
        // inline SSO + byte[23]) -> el retbuf perdia la longitud.  MEMCPY
        // lee la memoria directamente.  Solo aplica al value-string nativo
        // (host buffers); Optional/Result/enum siguen con el loop qword.
        if (v_local != ir::IR_NO_VALUE && native_poo_ &&
            current_fn_sret_str_value_) {
            emit_native_str_move_copy(sret_retbuf_, v_local, s->loc.line);
            // Invalidar la fuente si es un ident (move por valor).
            if (s->value->kind == ast::NodeKind::IdentExpr) {
                emit_native_str_invalidate_moved(v_local, s->loc.line);
            }
            // Saltar el loop qword + el zero-de-ptr@0 de abajo (ya hechos).
            v_local = ir::IR_NO_VALUE;
        }
        if (v_local != ir::IR_NO_VALUE) {
            // Copia qword-a-qword (16 bytes = 2 qwords; 24 = 3).
            // No usamos MEMCPY/vmcopy porque vmcopy es VM->host y
            // ambos buffers (local y retbuf) viven en VM memory.
            // El bucle desenrollado emite LOAD i64 + STORE i64 por
            // cada slot; el regalloc reusa los temporales.
            const uint64_t qwords = sret_buf_size_ / 8; // 2 o 3
            for (uint64_t qi = 0; qi < qwords; ++qi) {
                const uint64_t off = qi * 8;
                // src+off
                const ir::IrValueId v_off =
                    emit_const(ir::IrType::I64, off, s->loc.line);
                const ir::IrValueId v_src_at =
                    emit_ptr_add(v_local, v_off, s->loc.line);
                // Vesta Embed (native_poo_): el value-string fuente vive en
                // host stack (ALLOCA host) -> propagar is_host_ptr del
                // v_local al v_src_at para que el LOAD use `movh` (host) en
                // lugar de `mov` (VM mem).  Sin esto, el retorno de un
                // value-string leeria 24 bytes de vm_mem (cero/basura).
                fn_->values[v_src_at].is_host_ptr =
                    fn_->values[v_local].is_host_ptr;
                // LOAD i64 from src+off
                const ir::IrValueId v_tmp =
                    emit_load_typed(v_src_at, ir::IrType::I64, s->loc.line);
                // dst+off
                const ir::IrValueId v_off2 =
                    emit_const(ir::IrType::I64, off, s->loc.line);
                const ir::IrValueId v_dst_at =
                    emit_ptr_add(sret_retbuf_, v_off2, s->loc.line);
                // BugFix sret-cross-mem (2026-06-04): propagar
                // is_host_ptr de sret_retbuf_ al v_dst_at para que el
                // STORE downstream emita `movh` (host) en lugar de
                // `mov` (VM mem).  El retbuf SIEMPRE vive en host
                // memory (ALLOCA del caller); sin esta propagacion
                // el STORE escribe a vm_mem mientras el caller lee
                // host -> Result tag/value/error siempre en cero.
                fn_->values[v_dst_at].is_host_ptr =
                    fn_->values[sret_retbuf_].is_host_ptr;
                // STORE i64 [dst+off] = tmp
                emit_store_typed(v_dst_at, v_tmp, ir::IrType::I64, s->loc.line);
            }
            // Vesta Embed (native_poo_): `return <ident_string>` (devolver
            // una variable/param string POR VALOR) hace MOVE: tras copiar
            // los 24 bytes al retbuf, ZERAR el ptr@0 del slot fuente para
            // transferir el ownership del buffer al caller.  Sin esto, la
            // fuente y el retbuf comparten el mismo buffer -> doble-free
            // (la fuente lo libera en su scope Y el caller lo libera via el
            // retbuf).  El concat `a+b` produce un buffer fresco (no es
            // ident) -> no se zera nada (no hay aliasing).
            if (current_fn_sret_str_value_ && v_local != ir::IR_NO_VALUE &&
                s->value->kind == ast::NodeKind::IdentExpr) {
                // Inc 5 (SSO): invalidar la fuente flag-aware.  HEAP ->
                // ptr@0=0 (el caller posee el buffer via retbuf, sin
                // doble-free); SSO -> sin cambio (data inline ya copiada
                // al retbuf; no hay buffer compartido).
                emit_native_str_invalidate_moved(v_local, s->loc.line);
            }
        }
        // ejecutar cleanups (e.g. monexit de synchronized
        // activos) justo ANTES del RET sret.  Las copias al retbuf ya
        // se completaron arriba; los cleanups solo modifican estado
        // global (mailboxes, monitores) sin tocar el retbuf.
        emit_cleanups_all();
        // Instrumentacion: emitir vx_trace:leave antes del RET sret.
        // Sin esto, fns que retornan Optional<T>/Result<V,E> NO cierran
        // el trace y producen un arbol descuadrado en la salida.
        if (instrument_mode_ != "none" && instrument_mode_ != "" &&
            fn_ != nullptr) {
            const std::string &fname = fn_->name;
            const bool is_helper = is_compiler_generated_fn(fn_->name);
            if (!is_helper) {
                emit_instrument_exit(fname, sret_retbuf_, s->loc.line);
            }
        }
        ir::IrInstr ret{};
        ret.op = ir::IrOp::RET;
        ret.type = ir::IrType::VOID;
        ret.source_line = s->loc.line;
        emit(current_block_, std::move(ret));
        block_terminated_ = true;
        return;
    }
    // Camino normal (no sret): bajar el valor de retorno PRIMERO, luego
    // emitir los cleanups (que pueden tocar registros pero no afectan
    // el SSA value computado), y finalmente el RET.
    ir::IrValueId v_ret = ir::IR_NO_VALUE;
    if (s->value) {
        // Auto-promotion: si la funcion declara devolver `string` y el
        // valor de retorno es un string literal sin interpolacion,
        // promocionar al StringObject GC-managed via STRMAKE (mismo
        // patron que `lower_var_decl` para `string s = "lit"`).  Sin
        // esto, `return "abc"` devolveria el ptr crudo (host) a los
        // bytes en static_data y el caller intentaria tratarlo como
        // GcHandle, llamando a strraw/strlen sobre basura.
        if (current_fn_returns_string_ &&
            s->value->kind == ast::NodeKind::StringLitExpr) {
            // Tanto literales puros como interpolados: el helper
            // construye el StringObject (1 STRMAKE para puros,
            // cadena de STRMAKE+STRCAT para interpolados).
            auto *slit = static_cast<ast::StringLitExpr *>(s->value.get());
            v_ret = lower_string_literal_to_string_object(slit);
        } else {
            v_ret = lower_expr(s->value.get());
            if (v_ret != ir::IR_NO_VALUE) {
                // Item 9: si estamos en el helper @Async, NO castear
                // al ret_type del helper (que es VOID o i64).  El block
                // siguiente (async_fut_id_) hace el BITCAST/cast
                // correcto para preservar bits (no value).  Sin esto,
                // un `return f64_value` se castea F64->I64 via FTOUI
                // (cambia value, no preserva bits), corrompiendo el
                // payload del fulfill.
                if (async_fut_id_ == ir::IR_NO_VALUE) {
                    v_ret = cast_if_needed(v_ret, fn_->values[v_ret].type,
                                           fn_->ret_type, s->loc.line);
                }
            }
        }
    }
    // si estamos en el body de una funcion @Async lowered
    // como spawn helper, intercepta el return: en lugar de RET, emite
    // `fulfill(async_fut, value) + hlt`.  El caller obtendra el valor
    // via `await`.  El hlt es necesario porque el child no debe hacer
    // ret (no hay caller en el stack del child).
    //
    // Mejora II: el bytecode `fulfill r_fut, r_value` espera un i64
    // raw como payload.  Si el `return X` del usuario produjo un valor
    // de tipo distinto (i32/i16/i8/bool/char/f32/f64), debemos coercerlo
    // a i64 preservando la semantica de bits para que el `await` del
    // caller pueda recuperarlo correctamente.  Para floats: BITCAST
    // (no ITOF que cambiaria el valor).  Para enteros estrechos:
    // cast_if_needed (zext/sext segun signedness).
    if (async_fut_id_ != ir::IR_NO_VALUE) {
        ir::IrValueId v_payload = v_ret;
        if (v_payload == ir::IR_NO_VALUE) {
            v_payload = emit_const(ir::IrType::I64, 0, s->loc.line);
        } else {
            const ir::IrType pt = fn_->values[v_payload].type;
            if (pt == ir::IrType::F64) {
                ir::IrValueId v_bits = emit_ir_unop(
                    ir::IrOp::BITCAST, v_payload, ir::IrType::I64, s->loc.line);
                v_payload = v_bits;
            } else if (pt == ir::IrType::F32) {
                // f32 -> bits i32 -> zero-extend a i64.
                ir::IrValueId v_i32 = emit_ir_unop(
                    ir::IrOp::BITCAST, v_payload, ir::IrType::I32, s->loc.line);
                v_payload = cast_if_needed(v_i32, ir::IrType::I32,
                                           ir::IrType::I64, s->loc.line);
            } else if (pt != ir::IrType::I64 && pt != ir::IrType::U64 &&
                       pt != ir::IrType::PTR) {
                v_payload =
                    cast_if_needed(v_payload, pt, ir::IrType::I64, s->loc.line);
            }
        }
        // raw_asm-elim 2026-05-28: usar IrOp::FULFILL_HLT directo.
        // Fusion atomica fulfill+hlt en 1 instr VM, mismo bytecode.
        // AOT (native_poo_): el helper @Async es una tarea del scheduler coop
        // -> CALL __vx_fulfill(fut, val) + RET (la tarea retorna al pump, no
        // hay HLT del scheduler de la VM).
        if (native_poo_) {
            emit_call("__vx_fulfill", {async_fut_id_, v_payload},
                      ir::IrType::VOID, s->loc.line);
            emit_ret_void(s->loc.line);
            return;
        }
        ir::IrInstr fh{};
        fh.op = ir::IrOp::FULFILL_HLT;
        fh.type = ir::IrType::VOID;
        fh.dst = ir::IR_NO_VALUE;
        fh.operands = {async_fut_id_, v_payload};
        fh.source_line = s->loc.line;
        emit(current_block_, std::move(fh));
        block_terminated_ = true;
        return;
    }
    // rspawn body return -> mov r0, X + hlt.  El runtime remoto
    // detecta HALT en un proceso con rspawn_future_id != 0 y envia
    // VDP_FUTURE_FULFILL al nodo origen con R0 como payload.  El caller
    // local recibe el valor via `await fut`.
    if (is_rspawn_body_) {
        // raw_asm-elim wave 3: rspawn body return via IrOp::RSPAWN_RETURN.
        // Emite `mov r0, payload + hlt` fusionado; el runtime VDP detecta
        // HALT en un proceso con rspawn_future_id != 0 y envia el valor.
        ir::IrValueId v_payload = v_ret;
        if (v_payload == ir::IR_NO_VALUE) {
            v_payload = emit_const(ir::IrType::I64, 0, s->loc.line);
        }
        ir::IrInstr rr{};
        rr.op = ir::IrOp::RSPAWN_RETURN;
        rr.type = ir::IrType::VOID;
        rr.dst = ir::IR_NO_VALUE;
        rr.operands = {v_payload};
        rr.source_line = s->loc.line;
        emit(current_block_, std::move(rr));
        block_terminated_ = true;
        return;
    }
    /* Y el tercer cuerpo que tampoco es una funcion: el de un `spawn { }` de
     * aqui.  No hay futuro que resolver ni nodo al que contestar -- un spawn
     * local devuelve el identificador del proceso, no un valor --, asi que un
     * `return` solo dice "acaba".  Termina como si se hubiera llegado al final
     * del bloque, que es lo unico correcto: en la pila de un proceso no hay
     * ninguna direccion de retorno a la que ir. */
    if (is_spawn_body_) {
        /* Devolver un VALOR desde aqui no llega: el comprobador de tipos ya lo
         * rechaza antes -- para el, el cuerpo es void -- y con mejor mensaje
         * del que se daria aqui.  Asi que esto solo atiende al `return;` seco.
         */
        emit_cleanups_all();
        emit_process_body_end(s->loc.line);
        return;
    }
    // ejecutar cleanups activos (synchronized -> tryleave + monexit).
    // El SSA value v_ret sobrevive: el regalloc garantiza que se mantenga
    // vivo hasta el RET (o se reescriba antes si conviene).
    emit_cleanups_all();
    // Instrumentacion: vx_trace:exit antes del RET explicito.  Skipea
    // helpers internos (mismo filtro que en lower_function).
    if (instrument_mode_ != "none" && instrument_mode_ != "" &&
        fn_ != nullptr) {
        const std::string &fname = fn_->name;
        const bool is_helper = is_compiler_generated_fn(fn_->name);
        if (!is_helper) {
            emit_instrument_exit(fname, v_ret, s->loc.line);
        }
    }
    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.type = fn_->ret_type;
    ret.source_line = s->loc.line;
    if (v_ret != ir::IR_NO_VALUE) {
        ret.operands.push_back(v_ret);
    }
    emit(current_block_, std::move(ret));
    block_terminated_ = true;
}

void Lowering::lower_foreach(ast::ForEachStmt *s) {
    if (!s->iter_expr) {
        error_at(s->loc, "lowering: foreach sin coleccion");
        return;
    }
    // El tipo del iter_expr debe ser ARRAY[N].  Lo extraemos del
    // result_type que el type checker fija.
    const Type col_t = s->iter_expr->result_type;
    if (col_t.kind != PrimitiveKind::ARRAY) {
        error_at(s->loc, "lowering: foreach requiere un array (no se soporta "
                         "T[] sin tamano en MVP)");
        return;
    }
    if (col_t.array_size == 0) {
        error_at(s->loc,
                 "lowering: foreach requiere un array con tamano fijo T[N]");
        return;
    }
    const uint64_t N = static_cast<uint64_t>(col_t.array_size);

    // Sintetizamos el cuerpo extendido como AST nuevo y lo bajamos
    // via lower_stmt (mas robusto que generar IR a mano y permite
    // reusar todas las optimizaciones).  Usamos nombres "__"
    // prefijados para evitar choque con identificadores del usuario.

    auto block = std::make_unique<ast::BlockStmt>();
    block->loc = s->loc;

    // i64 __idx = 0;
    auto idx_decl = std::make_unique<ast::VarDeclStmt>();
    idx_decl->loc = s->loc;
    {
        auto pt = std::make_unique<ast::PrimitiveTypeNode>();
        pt->loc = s->loc;
        pt->prim = PrimitiveKind::I64;
        idx_decl->type = std::move(pt);
        idx_decl->name = "__fe_idx";
        auto z = std::make_unique<ast::IntLitExpr>();
        z->loc = s->loc;
        z->value = 0;
        z->result_type = Type{PrimitiveKind::I64};
        idx_decl->init = std::move(z);
    }
    block->body.push_back(std::move(idx_decl));

    // while (__fe_idx < N) { ... }
    auto while_stmt = std::make_unique<ast::WhileStmt>();
    while_stmt->loc = s->loc;
    {
        auto cond = std::make_unique<ast::BinaryExpr>();
        cond->loc = s->loc;
        cond->op = ast::BinOp::Lt;
        auto lhs = std::make_unique<ast::IdentExpr>();
        lhs->loc = s->loc;
        lhs->name = "__fe_idx";
        lhs->result_type = Type{PrimitiveKind::I64};
        auto rhs = std::make_unique<ast::IntLitExpr>();
        rhs->loc = s->loc;
        rhs->value = N;
        rhs->result_type = Type{PrimitiveKind::I64};
        cond->lhs = std::move(lhs);
        cond->rhs = std::move(rhs);
        cond->result_type = Type{PrimitiveKind::BOOL};
        while_stmt->cond = std::move(cond);
    }
    // body interno: { T x = col[__fe_idx]; user_body; __fe_idx = __fe_idx+1; }
    auto inner_block = std::make_unique<ast::BlockStmt>();
    inner_block->loc = s->loc;
    // T x = col[__fe_idx];
    const Type elem_t =
        (col_t.pointee != nullptr) ? *col_t.pointee : Type{PrimitiveKind::I64};
    {
        auto vd = std::make_unique<ast::VarDeclStmt>();
        vd->loc = s->loc;
        auto pt = std::make_unique<ast::PrimitiveTypeNode>();
        pt->loc = s->loc;
        pt->prim = elem_t.kind;
        vd->type = std::move(pt);
        vd->name = s->iter_name;
        // expr: col[__fe_idx].  IMPORTANTE: rellenamos result_type a
        // mano porque este nodo no pasa por check_expr.  Sin esto el
        // LOAD del lowering usaria size por defecto (8 bytes) y
        // leeria mas alla del slot del array.
        auto idx_expr = std::make_unique<ast::IndexExpr>();
        idx_expr->loc = s->loc;
        idx_expr->result_type = elem_t;
        // base: cloning iter_expr is delicate (unique_ptr); the simplest
        // is moving it INTO the desugared tree.  iter_expr ya no se
        // usara mas alla de este lowering, asi que es seguro mover.
        idx_expr->base = std::move(s->iter_expr);
        // El base preservaba su result_type (ARRAY[N] o PTR) ya
        // resuelto por el type checker.
        auto idx_id = std::make_unique<ast::IdentExpr>();
        idx_id->loc = s->loc;
        idx_id->name = "__fe_idx";
        idx_id->result_type = Type{PrimitiveKind::I64};
        idx_expr->index = std::move(idx_id);
        vd->init = std::move(idx_expr);
        inner_block->body.push_back(std::move(vd));
    }
    // user body
    if (s->body) inner_block->body.push_back(std::move(s->body));
    // __fe_idx = __fe_idx + 1;
    {
        auto inc_stmt = std::make_unique<ast::ExprStmt>();
        inc_stmt->loc = s->loc;
        auto assign = std::make_unique<ast::AssignExpr>();
        assign->loc = s->loc;
        assign->op = ast::AssignOp::Assign;
        auto target = std::make_unique<ast::IdentExpr>();
        target->loc = s->loc;
        target->name = "__fe_idx";
        target->result_type = Type{PrimitiveKind::I64};
        assign->target = std::move(target);
        auto add = std::make_unique<ast::BinaryExpr>();
        add->loc = s->loc;
        add->op = ast::BinOp::Add;
        auto a_lhs = std::make_unique<ast::IdentExpr>();
        a_lhs->loc = s->loc;
        a_lhs->name = "__fe_idx";
        a_lhs->result_type = Type{PrimitiveKind::I64};
        auto a_rhs = std::make_unique<ast::IntLitExpr>();
        a_rhs->loc = s->loc;
        a_rhs->value = 1;
        a_rhs->result_type = Type{PrimitiveKind::I64};
        add->lhs = std::move(a_lhs);
        add->rhs = std::move(a_rhs);
        add->result_type = Type{PrimitiveKind::I64};
        assign->value = std::move(add);
        assign->result_type = Type{PrimitiveKind::I64};
        inc_stmt->expr = std::move(assign);
        inner_block->body.push_back(std::move(inc_stmt));
    }
    while_stmt->body = std::move(inner_block);
    block->body.push_back(std::move(while_stmt));

    // Bajar el bloque sintetico.  Como las expresiones internas no
    // pasaron por check_expr, sus result_type pueden estar incompletos
    // (especialmente IndexExpr).  Para minimizar fallos, marcamos
    // los tipos manualmente arriba; el lowering tolera ausencia de
    // result_type en ciertos casos.
    lower_stmt(block.get());
}

/**
 * @brief Salta a un bloque, y deja el grafo contado.
 *
 * Emitir el salto es la mitad; la otra es que el bloque de salida sepa a donde
 * va y el de llegada sepa de donde viene.  Escrito a mano son cuatro lineas y
 * las dos ultimas son las faciles de olvidar: sin ellas el codigo generado es
 * correcto pero el GRAFO miente, y quien lo recorra despues -- el que decide
 * que valor vive donde, el que quita lo inalcanzable -- toma sus decisiones
 * sobre un mapa equivocado.  No da error: da codigo peor, o mal.
 *
 * Estaba escrito cuatro veces, una por funcion que construye un bucle a mano.
 *
 * @param target      El bloque al que saltar.
 * @param source_line Linea fuente, para la depuracion.
 */
void Lowering::emit_br(ir::IrBlockId target, uint32_t source_line) {
    emit_br_from(current_block_, target, source_line);
}

/**
 * @brief Salta a un bloque DESDE otro que no es el actual.
 *
 * Hace falta mas de lo que parece: al construir un bucle, el salto de entrada
 * sale del bloque de ANTES del bucle, y para entonces el bajador ya esta
 * emitiendo en la cabecera.  Lo mismo al cerrar las dos ramas de un
 * condicional, que saltan al bloque comun desde donde cada una termino.
 *
 * @param from        Bloque del que sale el salto.
 * @param target      Bloque al que va.
 * @param source_line Linea fuente, para la depuracion.
 */
void Lowering::emit_br_from(ir::IrBlockId from, ir::IrBlockId target,
                            uint32_t source_line) {
    ir::IrInstr b{};
    b.op = ir::IrOp::BR;
    b.type = ir::IrType::VOID;
    b.dst = ir::IR_NO_VALUE;
    b.target_block = target;
    b.source_line = source_line;
    emit(from, std::move(b));
    add_cfg_edge(from, target);
}

/**
 * @brief Salta a un bloque o a otro segun @p cond, y deja el grafo contado.
 *
 * Lo mismo que @ref emit_br pero con dos salidas, y por eso son CUATRO aristas
 * las que hay que anotar en vez de dos: es donde mas facil es dejarse una.
 *
 * @param cond        El valor que decide.
 * @param t_true      Bloque al que ir si no es cero.
 * @param t_false     Bloque al que ir si lo es.
 * @param source_line Linea fuente, para la depuracion.
 */
void Lowering::emit_br_cond_from(ir::IrBlockId from, ir::IrValueId cond,
                                 ir::IrBlockId t_true, ir::IrBlockId t_false,
                                 uint32_t source_line) {
    ir::IrInstr b{};
    b.op = ir::IrOp::BR_COND;
    b.type = ir::IrType::VOID;
    b.dst = ir::IR_NO_VALUE;
    b.operands = {cond};
    b.target_block = t_true;
    b.false_block = t_false;
    b.source_line = source_line;
    emit(from, std::move(b));
    add_cfg_edge(from, t_true);
    add_cfg_edge(from, t_false);
}

void Lowering::emit_br_cond(ir::IrValueId cond, ir::IrBlockId t_true,
                            ir::IrBlockId t_false, uint32_t source_line) {
    emit_br_cond_from(current_block_, cond, t_true, t_false, source_line);
}

/**
 * @brief Anota que de @p from se puede llegar a @p to.
 *
 * No emite nada: solo cuenta la arista en los dos extremos.  Hace falta suelto
 * -- sin salto -- cuando el salto ya lo pone otra cosa: un `match` construye su
 * despacho y luego dice a que bloques puede ir, y esas aristas no salen de un
 * `br` sino de la propia tabla.
 *
 * Es la mitad de @ref emit_br, y la que se olvida: sin ella el grafo miente y
 * quien lo recorra despues decide sobre un mapa equivocado.
 *
 * @param from Bloque de salida.
 * @param to   Bloque de llegada.
 */
void Lowering::add_cfg_edge(ir::IrBlockId from, ir::IrBlockId to) {
    fn_->blocks[from].succs.push_back(to);
    fn_->blocks[to].preds.push_back(from);
}

/**
 * @brief Termina la funcion actual sin devolver nada.
 *
 * Marca el bloque como terminado, que es la mitad que se olvida: un bloque que
 * ya retorno no puede seguir recibiendo instrucciones, y si el bajador no lo
 * sabe emite codigo detras del retorno -- inalcanzable, pero ahi --.
 *
 * @param source_line Linea fuente, para la depuracion.
 */
void Lowering::emit_ret_void(uint32_t source_line) {
    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.type = ir::IrType::VOID;
    ret.dst = ir::IR_NO_VALUE;
    ret.source_line = source_line;
    emit(current_block_, std::move(ret));
}

} // namespace vx
