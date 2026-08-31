/*
 * VestaVM - Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file transpiler_base.cpp
 * @brief Implementacion del core compartido del transpiler IR -> codigo.
 *
 * Algoritmo principal (en @c Transpiler::run):
 *
 *   1. Backend.emit_prelude -- includes, defines, typedefs.
 *   2. Para cada IrFunction:
 *      a. Backend.emit_fn_signature(...)
 *      b. Backend.emit_fn_open()
 *      c. Para cada IrValue: backend.emit_local_decl(...)
 *      d. Para cada IrBlock en orden:
 *         - backend.emit_label_def(block_id)
 *         - Para cada IrInstr no-PHI no-terminator: dispatch a emit_*
 *         - Antes del terminator, emit_phi_copies_for_edge(...) si BR / BR_COND
 *         - emit_goto / emit_cond_branch / emit_return
 *      e. Backend.emit_fn_close()
 *   3. Backend.emit_postamble
 *
 * El algoritmo de PHI lowering es el clasico parallel-move:
 *
 *   En cada PRED del block B con PHIs, ANTES de su terminador, emitir:
 *       v_phi_dst = v_phi_arg_for_pred;
 *
 *   Si hay ciclos en las asignaciones (raro pero posible con PHI swaps),
 *   se usa un temporal -- pero el frontend Vesta/IR genera siempre PHIs sin
 *   ciclos auto-resolubles, asi que en v1 no manejamos ese caso.
 */

#include "port/transpiler_base.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <sstream>

namespace port {

// =========================================================================
//  Parseo de strings CLI a enums (definicion en port_options.h)
// =========================================================================

bool parse_gc_mode(const std::string &s, GcMode &out) {
    if (s == "none") {
        out = GcMode::None;
        return true;
    }
    if (s == "vesta") {
        out = GcMode::Vesta;
        return true;
    }
    if (s == "boehm") {
        out = GcMode::Boehm;
        return true;
    }
    return false;
}

bool parse_exc_mode(const std::string &s, ExcMode &out) {
    if (s == "none") {
        out = ExcMode::None;
        return true;
    }
    if (s == "setjmp") {
        out = ExcMode::SetJmp;
        return true;
    }
    if (s == "returncode") {
        out = ExcMode::ReturnCode;
        return true;
    }
    return false;
}

bool parse_type_style(const std::string &s, TypeStyle &out) {
    if (s == "stdint") {
        out = TypeStyle::StdInt;
        return true;
    }
    if (s == "builtin") {
        out = TypeStyle::Builtin;
        return true;
    }
    return false;
}

bool parse_string_mode(const std::string &s, StringMode &out) {
    if (s == "raw") {
        out = StringMode::Raw;
        return true;
    }
    if (s == "managed") {
        out = StringMode::Managed;
        return true;
    }
    return false;
}

bool parse_instrument_mode(const std::string &s, InstrumentMode &out) {
    if (s == "none" || s.empty()) {
        out = InstrumentMode::None;
        return true;
    }
    if (s == "trace") {
        out = InstrumentMode::Trace;
        return true;
    }
    if (s == "profile") {
        out = InstrumentMode::Profile;
        return true;
    }
    return false;
}

// =========================================================================
//  EmitContext helpers
// =========================================================================

void EmitContext::indent() const {
    // Emitir 4 espacios por nivel de indentacion.  Convencion C
    // estandar.  Si el backend tiene preferencia distinta puede
    // override desde sus hooks (e.g. tabs en lugar de spaces).
    for (int i = 0; i < indent_level; ++i) {
        out << "    ";
    }
}

// =========================================================================
//  IPortBackend defaults
// =========================================================================

void IPortBackend::emit_cond_branch(EmitContext &ctx, ir::IrValueId cond,
                                    ir::IrBlockId true_id,
                                    ir::IrBlockId false_id) {
    // Forma C/Java idiomatica: if + goto a ambos targets.  El compilador
    // host (gcc/clang -O3) suele simplificar a una sola comparacion +
    // condicional jump sin rama extra.  Usamos @c format_value para que
    // si el cond es un CMP single-use, la expresion completa se inlinee
    // (@c "if ((v0 <= v1)) goto ..." en lugar de @c "if (v_cmp) ...").
    ctx.indent();
    ctx.out << "if (" << format_value(ctx, cond) << ") goto "
            << label_for(true_id) << ";\n";
    ctx.indent();
    ctx.out << "goto " << label_for(false_id) << ";\n";
}

void IPortBackend::emit_unsupported(EmitContext &ctx,
                                    const ir::IrInstr &instr) {
    // Caso default: comentario + stub que asigna 0 al destino.  El
    // backend C lo sobreescribe para tambien marcar el codigo
    // generado con un define visible.  El transpiler core agrega
    // un warning a la lista TranspileResult::warnings.
    ctx.indent();
    ctx.out << "/* TODO unsupported IR op: " << ir::ir_op_name(instr.op);
    if (instr.source_line > 0) {
        ctx.out << " (line " << instr.source_line << ")";
    }
    ctx.out << " */\n";
    if (instr.dst != ir::IR_NO_VALUE) {
        ctx.indent();
        ctx.out << "v" << instr.dst << " = 0;\n";
    }
}

void IPortBackend::emit_phi_copy(EmitContext &ctx, ir::IrValueId dst,
                                 ir::IrValueId src, ir::IrType t) {
    // Asignacion directa.  Funciona en C, Java, JS.
    (void)t; // tipo implicito por la declaracion previa
    ctx.indent();
    ctx.out << "v" << dst << " = v" << src << ";\n";
}

// =========================================================================
//  Transpiler::run
// =========================================================================

TranspileResult Transpiler::run() {
    TranspileResult res;
    std::ostringstream oss;
    EmitContext ctx{oss, 0, nullptr, nullptr, &opts_, this};

    // 1. Prelude del lenguaje destino: includes, typedefs, defines.
    backend_.emit_prelude(ctx, mod_);

    // 2. Una funcion a la vez.  El orden de funciones afecta forward
    //    declarations en C; el backend C las maneja en emit_prelude
    //    via una pasada previa de declaraciones.  El backend puede
    //    filtrar funciones via @c should_skip_function (e.g. @c __module_init,
    //    @c __new_<X> reemplazados por helpers POO del backend).
    for (const auto &fn : mod_.functions) {
        if (backend_.should_skip_function(fn, mod_)) continue;
        emit_function(ctx, fn);
    }

    // 3. Postamble: cleanup, main wrapper, etc.
    backend_.emit_postamble(ctx, mod_);

    res.source_text = oss.str();
    res.ok = res.errors.empty();
    return res;
}

// =========================================================================
//  Transpiler::analyze_function
// =========================================================================

/**
 * @brief Se puede MOVER esta operacion a su punto de uso?
 *
 * Se llamaba @c is_pure_op, y no es la pureza: hay otro @c is_pure_op en la
 * huella de funcion (@c analyze/fingerprint.cpp) que responde otra cosa -- si
 * la funcion tiene efectos de dato observables, para validar un @c \@pure
 * declarado -- y cuenta 142 operaciones frente a las 49 de aqui.  Compartir
 * nombre los hacia parecer dos copias de la misma tabla, y no lo son: esta es
 * una POLITICA de este transpilador sobre donde puede colocar una expresion.
 *
 * Solo los operadores listados aqui son candidatos a inlining.  LOAD,
 * STORE, CALL, ALLOCA, RAW_ALLOC y RAW_FREE NO son inlineables porque
 * tienen efectos colaterales o dependen del estado de memoria.
 *
 * DIV y MOD son tecnicamente inlineables (no acceden a memoria) pero
 * NO los marcamos para evitar mover un divide-by-zero potencial dentro
 * de una rama condicional: en SSA single-use el operando puede ya estar
 * fuera del branch original, pero al inlinearlo en el use site cambiamos
 * cuando se evalua.  Cambiar el lugar de un trap es practicamente seguro
 * (UB en ambos casos) pero conservador es preferible.  Ahi se ve que no es la
 * pureza: una division ES pura y aun asi no se mueve.
 */
static bool is_inlinable_expr_op(ir::IrOp op) {
    using ir::IrOp;
    switch (op) {
    case IrOp::CONST:
    case IrOp::MOV:
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::MUL:
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::NEG:
    case IrOp::NOT:
    case IrOp::SHL:
    case IrOp::SHR:
    case IrOp::SAR:
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
    case IrOp::FMIN:
    case IrOp::FMAX:
    case IrOp::CMP_EQ:
    case IrOp::CMP_NE:
    case IrOp::CMP_LT:
    case IrOp::CMP_GT:
    case IrOp::CMP_LE:
    case IrOp::CMP_GE:
    case IrOp::CMP_ULT:
    case IrOp::CMP_UGT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGE:
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE:
    case IrOp::CAST:
    case IrOp::ZEXT:
    case IrOp::SEXT:
    case IrOp::TRUNC:
    case IrOp::ITOF:
    case IrOp::UITOF:
    case IrOp::FTOI:
    case IrOp::FTOUI:
    case IrOp::F32TOF64:
    case IrOp::F64TOF32:
    case IrOp::BITCAST: return true;
    // DIV/MOD: no inlinear (ver comentario).
    // LOAD/STORE/CALL/CALL_*: nunca.
    default: return false;
    }
}

void Transpiler::analyze_function(const ir::IrFunction &fn) {
    const size_t N = fn.values.size();
    ana_.use_count.assign(N, 0);
    ana_.def_instr.assign(N, nullptr);
    ana_.is_inline_candidate.assign(N, false);
    ana_.single_use_block.assign(N, ir::IR_NO_BLOCK);
    // Marca SSA values usados como argumento de algun PHI.  Estos NO se
    // inlinean: las phi-copies se emiten en el predecesor como una
    // secuencia de asignaciones, y si una asignacion previa sobreescribe
    // un valor que el expr inlineado referencia, obtenemos el valor NUEVO
    // en vez del antiguo.  Ejemplo concreto: en un loop con phi[a=b, b=t]
    // donde t = a+b, inlinear t produce @c "a=b; b=(a+b);" que evalua
    // @c b a partir del NUEVO @c a, no del antiguo -> resultado erroneo.
    std::vector<bool> used_in_phi(N, false);

    const size_t B = fn.blocks.size();
    ana_.block_preds.assign(B, {});

    // Pasada unica sobre todas las instrucciones: contar usos, registrar
    // defs, computar predecesores del CFG.
    for (const auto &bb : fn.blocks) {
        // Predecesores via terminadores del bloque actual.
        if (!bb.instrs.empty()) {
            const auto &term = bb.instrs.back();
            if (term.op == ir::IrOp::BR) {
                if (term.target_block < B) {
                    ana_.block_preds[term.target_block].push_back(bb.id);
                }
            } else if (term.op == ir::IrOp::BR_COND) {
                if (term.target_block < B) {
                    ana_.block_preds[term.target_block].push_back(bb.id);
                }
                if (term.false_block < B) {
                    ana_.block_preds[term.false_block].push_back(bb.id);
                }
            }
        }

        for (const auto &ins : bb.instrs) {
            if (ins.dst != ir::IR_NO_VALUE && ins.dst < N) {
                ana_.def_instr[ins.dst] = &ins;
            }
            for (auto op_id : ins.operands) {
                if (op_id != ir::IR_NO_VALUE && op_id < N) {
                    ana_.use_count[op_id]++;
                    if (ana_.use_count[op_id] == 1) {
                        ana_.single_use_block[op_id] = bb.id;
                    }
                }
            }
            for (const auto &phi_arg : ins.phi_args) {
                if (phi_arg.value < N) {
                    ana_.use_count[phi_arg.value]++;
                    // El uso "real" para PHI esta conceptualmente en el
                    // predecesor (donde se hace el parallel-move), no en
                    // el bloque que contiene el PHI.
                    if (ana_.use_count[phi_arg.value] == 1) {
                        ana_.single_use_block[phi_arg.value] = phi_arg.block;
                    }
                    used_in_phi[phi_arg.value] = true;
                }
            }
            if (ins.func_ptr != ir::IR_NO_VALUE && ins.func_ptr < N) {
                ana_.use_count[ins.func_ptr]++;
                if (ana_.use_count[ins.func_ptr] == 1) {
                    ana_.single_use_block[ins.func_ptr] = bb.id;
                }
            }
        }
    }

    // Identificar inline candidates: single-use + def es operacion pura
    // + NO usado como phi-arg.  El ultimo criterio cierra el caso del
    // parallel-move PHI con dependencias cruzadas:
    //   loop body emits  v_t = v_a + v_b; phi[v_a := v_b, v_b := v_t]
    //   inlinear v_t produciria  v_a = v_b; v_b = (v_a + v_b);
    //   donde v_b se evalua con el NUEVO valor de v_a -> incorrecto.
    // Conservativo: no inlinear ningun phi-arg.  El optimizer del
    // compilador host (gcc -O3) sigue siendo capaz de eliminar la
    // variable intermedia tras DCE/copy-prop.  Cero perdida real.
    for (size_t v = 0; v < N; ++v) {
        if (ana_.use_count[v] != 1) continue;
        if (!ana_.def_instr[v]) continue;
        if (!is_inlinable_expr_op(ana_.def_instr[v]->op)) continue;
        if (used_in_phi[v]) continue;
        ana_.is_inline_candidate[v] = true;
    }
}

// =========================================================================
//  Transpiler::emit_function
// =========================================================================

void Transpiler::emit_function(EmitContext &ctx, const ir::IrFunction &fn) {
    // Skip funciones nativas (stubs).  El frontend genera estos para
    // representar imports CALLN, pero no tienen cuerpo y no se transpilan.
    if (fn.is_native) {
        ctx.out << "/* native stub: " << fn.name << " -- linker provides */\n";
        return;
    }

    // Pre-pasada de analisis: cuenta usos, identifica inline candidates,
    // computa predecesores del CFG.  Necesario para que los hooks del
    // backend puedan decidir si emitir asignacion o inlinear expresion.
    analyze_function(fn);

    ctx.fn = &fn;
    ctx.tx = this;
    backend_.emit_fn_signature(ctx, fn);
    ctx.out << " ";
    backend_.emit_fn_open(ctx);

    // Declarar TODOS los SSA values al inicio.  Necesario en C donde las
    // variables no pueden cruzar labels sin estar declaradas antes.  Java
    // y JS tambien aceptan esto sin queja.  Cada backend escoge el tipo
    // real segun IrValue::type via type_for.
    emit_value_declarations(ctx, fn);

    // Nivel C: emision estructurada via deteccion de patrones de bloques.
    // Detecta loops (BR_COND con back-edge) y if-then-else (BR_COND con
    // merge convergente) y emite @c while/if/else en lugar de @c goto.
    // Bloques no estructurables se emiten en estilo goto como fallback.
    if (!fn.blocks.empty()) {
        std::vector<bool> visited(fn.blocks.size(), false);
        emit_region(ctx, fn, /*start=*/0, /*stop=*/ir::IR_NO_BLOCK, visited);

        // Defensa: bloques no alcanzados por la emision estructurada
        // (CFG con regiones desconectadas).  No deberia ocurrir en IR
        // bien formado, pero los emitimos goto-style por consistencia.
        for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
            if (!visited[bi]) {
                emit_block(ctx, fn.blocks[bi], fn);
            }
        }
    }

    ctx.fn = nullptr;
    backend_.emit_fn_close(ctx);
}

// =========================================================================
//  Transpiler::emit_value_declarations
// =========================================================================

void Transpiler::emit_value_declarations(EmitContext &ctx,
                                         const ir::IrFunction &fn) {
    // Cada SSA value que NO es parametro y NO es inline candidate se
    // declara como variable local.  Los parametros ya estan en la firma
    // de la funcion; los inline candidates se emiten via @c value_expr
    // del backend cuando se usan, ahorrando la variable intermedia.
    size_t declared = 0;
    for (const auto &v : fn.values) {
        if (v.id == ir::IR_NO_VALUE) continue;
        if (v.is_param) continue;
        // Skip values no usados (DCE-able), EXCEPTO si su def tiene
        // side effects (ALLOCA, CALL, RAW_ALLOC, etc.).  Esos siempre
        // emiten un assignment al dst y por tanto requieren la
        // declaracion para que C no genere "undeclared variable".
        // Esto silencia warnings @c -Wunused-variable.
        if (ana_.use_count[v.id] == 0) {
            const ir::IrInstr *def =
                (v.id < ana_.def_instr.size()) ? ana_.def_instr[v.id] : nullptr;
            bool side_effecting = false;
            if (def != nullptr) {
                using ir::IrOp;
                switch (def->op) {
                case IrOp::ALLOCA:
                case IrOp::RAW_ALLOC:
                case IrOp::CALL:
                case IrOp::CALLN:
                case IrOp::CALLIND:
                case IrOp::CALLVIRT:
                case IrOp::NEWOBJ:
                case IrOp::GC_ALLOC:
                case IrOp::RAW_ASM: side_effecting = true; break;
                default: break;
                }
            }
            if (!side_effecting) continue;
        }
        // Skip inline candidates: su expresion se construye en el use site.
        if (ana_.is_inline_candidate[v.id]) continue;
        backend_.emit_local_decl(ctx, v.id, v);
        declared++;
    }
    if (declared > 0) ctx.out << "\n";
}

// =========================================================================
//  Transpiler::emit_block
// =========================================================================

void Transpiler::emit_block(EmitContext &ctx, const ir::IrBlock &bb,
                            const ir::IrFunction &fn) {
    ctx.bb = &bb;

    // Suprimir label si el bloque NO tiene predecesores en el CFG.
    // Esto cubre el entry block (que se alcanza por fall-through) y
    // cualquier bloque inalcanzable accidentalmente (raro pero defensivo).
    // Resultado: menos warnings @c -Wunused-label de GCC.
    //
    // Excepcion: bloques try_handler_* / try_body_* / try_merge_* /
    // *_handler son destinos de @c goto computado via labels-as-values
    // emitido por raw_asm "tryenter".  Forzamos emission del label
    // aunque no haya predecesor CFG normal.
    const bool has_preds = block_has_preds(bb.id);
    const bool is_handler_block =
        (!bb.name.empty()) && (bb.name.rfind("try_handler_", 0) == 0 ||
                               bb.name.rfind("try_body_", 0) == 0 ||
                               bb.name.rfind("try_merge_", 0) == 0 ||
                               bb.name.find("_handler") != std::string::npos);
    if (has_preds || is_handler_block) {
        backend_.emit_label_def(ctx, bb.id);
    }

    // Anotacion opcional con el nombre legible del bloque.
    if (opts_.emit_comments && !bb.name.empty()) {
        ctx.indent();
        ctx.out << "/* " << bb.name << " */\n";
    }

    // Las instrucciones se dividen en 3 grupos:
    //   - PHI nodes (skip aqui; los resuelve emit_phi_copies_for_edge en
    //     el predecesor antes de saltar a este bloque).
    //   - No-terminators (assignments, calls, etc.) -- dispatch al backend.
    //   - Terminator final (BR, BR_COND, RET, UNREACHABLE) -- requiere
    //     manejo especial para emitir PHI copies ANTES del salto.
    for (const auto &ins : bb.instrs) {
        if (ins.op == ir::IrOp::PHI) {
            // PHIs no se emiten aqui; se resuelven en los predecesores.
            continue;
        }

        // Manejar terminators.  Los predecesores (en su BR/BR_COND)
        // ya emitieron las phi-copies que correspondan; aqui solo el
        // terminator.
        switch (ins.op) {
        case ir::IrOp::BR: {
            // Phi copies del edge actual -> target_block.
            emit_phi_copies_for_edge(ctx, fn, bb.id, ins.target_block);
            // Optimizacion: si el target es el bloque INMEDIATAMENTE
            // siguiente (fall-through natural en C), suprimimos el
            // @c goto -- el compilador hace fall-through gratis y el
            // codigo queda mas limpio.  Solo aplica si NO hay otros
            // predecesores del target que necesiten el label (label
            // ya se emitio igualmente).
            bool is_fallthrough = false;
            for (size_t k = 0; k < fn.blocks.size(); ++k) {
                if (&fn.blocks[k] == &bb) {
                    if (k + 1 < fn.blocks.size() &&
                        fn.blocks[k + 1].id == ins.target_block) {
                        is_fallthrough = true;
                    }
                    break;
                }
            }
            if (!is_fallthrough) {
                backend_.emit_goto(ctx, ins.target_block);
            } else if (opts_.emit_comments) {
                ctx.indent();
                ctx.out << "/* fall-through to " << ins.target_block << " */\n";
            }
            break;
        }
        case ir::IrOp::BR_COND: {
            // Caso complejo: el target y el false_block pueden tener
            // PHIs distintas.  Las phi copies del TRUE branch deben
            // emitirse SOLO si la cond se cumple, idem para FALSE.
            // Si NINGUNO de los targets tiene PHIs, emit directo:
            //     if (v_cond) goto T; else goto F;
            // Si ALGUNO tiene PHIs:
            //     if (v_cond) { copies_for_T; goto T; }
            //     copies_for_F; goto F;
            bool t_has_phi = block_has_phis(fn, ins.target_block);
            bool f_has_phi = block_has_phis(fn, ins.false_block);
            if (!t_has_phi && !f_has_phi) {
                backend_.emit_cond_branch(ctx, ins.operands[0],
                                          ins.target_block, ins.false_block);
            } else {
                // Forma con bloques anidados.  El backend C lo
                // emite como "if (cond) { ... goto T; } ... goto F;".
                // Usamos @c format_value para que la expresion de
                // la condicion se inlinee si es candidato (CMP
                // single-use).
                std::string cond_expr =
                    backend_.format_value(ctx, ins.operands[0]);
                ctx.indent();
                ctx.out << "if (" << cond_expr << ") {\n";
                ctx.indent_level++;
                emit_phi_copies_for_edge(ctx, fn, bb.id, ins.target_block);
                backend_.emit_goto(ctx, ins.target_block);
                ctx.indent_level--;
                ctx.indent();
                ctx.out << "}\n";
                emit_phi_copies_for_edge(ctx, fn, bb.id, ins.false_block);
                backend_.emit_goto(ctx, ins.false_block);
            }
            break;
        }
        case ir::IrOp::RET: {
            backend_.emit_return(ctx, ins.operands.empty() ? ir::IR_NO_VALUE
                                                           : ins.operands[0]);
            break;
        }
        case ir::IrOp::UNREACHABLE: {
            ctx.indent();
            if (opts_.emit_comments) {
                ctx.out << "/* unreachable */\n";
                ctx.indent();
            }
            // C: __builtin_unreachable() en GCC/Clang; default abort.
            ctx.out << "/* unreachable */ ;\n";
            break;
        }
        default: emit_instr(ctx, ins); break;
        }
    }

    ctx.bb = nullptr;
}

// =========================================================================
//  Helper: bloque tiene PHIs?
// =========================================================================

bool Transpiler::block_has_phis(const ir::IrFunction &fn,
                                ir::IrBlockId bid) const {
    // Detecta si el bloque sucesor tiene PHIs (para decidir si emitimos
    // parallel-move antes del salto).  Por convencion del lowering Vesta,
    // los PHIs estan SIEMPRE al principio del bloque -- en cuanto vemos
    // otra op, ya no hay PHIs.
    if (bid == ir::IR_NO_BLOCK || bid >= fn.blocks.size()) return false;
    for (const auto &ins : fn.blocks[bid].instrs) {
        if (ins.op == ir::IrOp::PHI) return true;
        break;
    }
    return false;
}

// =========================================================================
//  Transpiler::emit_phi_copies_for_edge
// =========================================================================

void Transpiler::emit_phi_copies_for_edge(EmitContext &ctx,
                                          const ir::IrFunction &fn,
                                          ir::IrBlockId from_bb,
                                          ir::IrBlockId to_bb) {
    if (to_bb == ir::IR_NO_BLOCK || to_bb >= fn.blocks.size()) return;
    const auto &target = fn.blocks[to_bb];
    // Iterar PHIs del bloque destino (siempre al principio).
    for (const auto &ins : target.instrs) {
        if (ins.op != ir::IrOp::PHI) break;
        // Buscar el phi_arg cuyo block == from_bb.
        for (const auto &arg : ins.phi_args) {
            if (arg.block == from_bb) {
                backend_.emit_phi_copy(ctx, ins.dst, arg.value, ins.type);
                break;
            }
        }
    }
}

// =========================================================================
//  Transpiler::emit_instr (dispatch al backend)
// =========================================================================

void Transpiler::emit_instr(EmitContext &ctx, const ir::IrInstr &ins) {
    using ir::IrOp;
    // Dispatch sobre el opcode.  Cada caso llama al hook apropiado del
    // backend.  Las IR ops no listadas explicitamente caen al
    // @c emit_unsupported, que el backend puede sobreescribir.
    switch (ins.op) {
    case IrOp::NOP:
        if (opts_.emit_comments) {
            ctx.indent();
            ctx.out << "/* nop */\n";
        }
        return;

    case IrOp::CONST:
        backend_.emit_const(ctx, ins.dst, ins.imm, ins.type);
        return;

    case IrOp::MOV:
        if (!ins.operands.empty()) {
            backend_.emit_mov(ctx, ins.dst, ins.operands[0], ins.type);
        }
        return;

    // Aritmetica entera + bitwise + shifts.
    case IrOp::ADD:
    case IrOp::SUB:
    case IrOp::MUL:
    case IrOp::DIV:
    case IrOp::MOD:
    case IrOp::AND:
    case IrOp::OR:
    case IrOp::XOR:
    case IrOp::SHL:
    case IrOp::SHR:
    case IrOp::SAR:
    // Aritmetica float binaria.
    case IrOp::FADD:
    case IrOp::FSUB:
    case IrOp::FMUL:
    case IrOp::FDIV:
    case IrOp::FMIN:
    case IrOp::FMAX:
        if (ins.operands.size() >= 2) {
            backend_.emit_binop(ctx, ins.op, ins.dst, ins.operands[0],
                                ins.operands[1], ins.type);
        }
        return;

    case IrOp::FMA:
        if (ins.operands.size() >= 3) {
            backend_.emit_fma(ctx, ins.dst, ins.operands[0], ins.operands[1],
                              ins.operands[2], ins.type);
        }
        return;

    // Aritmetica unaria (entera y float).
    case IrOp::NEG:
    case IrOp::NOT:
    case IrOp::FNEG:
    case IrOp::FABS:
    case IrOp::FSQRT:
        if (!ins.operands.empty()) {
            backend_.emit_unop(ctx, ins.op, ins.dst, ins.operands[0], ins.type);
        }
        return;

    // Comparaciones (enteras y float).  El operando_type es el del
    // dato comparado (NO del resultado, que es BOOL).
    case IrOp::CMP_EQ:
    case IrOp::CMP_NE:
    case IrOp::CMP_LT:
    case IrOp::CMP_GT:
    case IrOp::CMP_LE:
    case IrOp::CMP_GE:
    case IrOp::CMP_ULT:
    case IrOp::CMP_UGT:
    case IrOp::CMP_ULE:
    case IrOp::CMP_UGE:
    case IrOp::FCMP_EQ:
    case IrOp::FCMP_NE:
    case IrOp::FCMP_LT:
    case IrOp::FCMP_GT:
    case IrOp::FCMP_LE:
    case IrOp::FCMP_GE: {
        if (ins.operands.size() >= 2) {
            // Resolver el tipo de los operandos.  La IrInstr::type
            // es BOOL (el resultado); el tipo real esta en los
            // values referenciados.
            ir::IrType op_t = ir::IrType::I64;
            if (ctx.fn && ins.operands[0] < ctx.fn->values.size()) {
                op_t = ctx.fn->values[ins.operands[0]].type;
            }
            backend_.emit_cmp(ctx, ins.op, ins.dst, ins.operands[0],
                              ins.operands[1], op_t);
        }
        return;
    }

    // Conversiones de tipo.
    case IrOp::CAST:
    case IrOp::ZEXT:
    case IrOp::SEXT:
    case IrOp::TRUNC:
    case IrOp::ITOF:
    case IrOp::UITOF:
    case IrOp::FTOI:
    case IrOp::FTOUI:
    case IrOp::F32TOF64:
    case IrOp::F64TOF32:
    case IrOp::BITCAST: {
        if (!ins.operands.empty()) {
            ir::IrType src_t = ir::IrType::I64;
            if (ctx.fn && ins.operands[0] < ctx.fn->values.size()) {
                src_t = ctx.fn->values[ins.operands[0]].type;
            }
            // Preferir el tipo del SSA value destino al de la
            // instruccion (algunos frontends dejan @c ins.type
            // a VOID para conversiones cuyo tipo queda implicito).
            ir::IrType dst_t = ins.type;
            if (dst_t == ir::IrType::VOID && ctx.fn &&
                ins.dst < ctx.fn->values.size()) {
                dst_t = ctx.fn->values[ins.dst].type;
            }
            // Final fallback: si BITCAST queda con destino VOID,
            // usar el tipo source (es una identidad).
            if (dst_t == ir::IrType::VOID && ins.op == ir::IrOp::BITCAST) {
                dst_t = src_t;
            }
            backend_.emit_convert(ctx, ins.op, ins.dst, ins.operands[0], dst_t,
                                  src_t);
        }
        return;
    }

    // Memoria
    case IrOp::ALLOCA: backend_.emit_alloca(ctx, ins.dst, ins.imm); return;

    case IrOp::LOAD: {
        if (!ins.operands.empty() && ctx.fn) {
            bool host = false;
            if (ins.operands[0] < ctx.fn->values.size()) {
                host = ctx.fn->values[ins.operands[0]].is_host_ptr;
            }
            backend_.emit_load(ctx, ins.dst, ins.operands[0], ins.type, host);
        }
        return;
    }

    case IrOp::STORE: {
        if (ins.operands.size() >= 2 && ctx.fn) {
            bool host = false;
            if (ins.operands[1] < ctx.fn->values.size()) {
                host = ctx.fn->values[ins.operands[1]].is_host_ptr;
            }
            backend_.emit_store(ctx, ins.operands[0], ins.operands[1], ins.type,
                                host);
        }
        return;
    }

    case IrOp::RAW_ALLOC:
        if (!ins.operands.empty()) {
            backend_.emit_raw_alloc(ctx, ins.dst, ins.operands[0]);
        }
        return;

    case IrOp::RAW_FREE:
        if (!ins.operands.empty()) {
            backend_.emit_raw_free(ctx, ins.operands[0]);
        }
        return;

    // Llamadas
    case IrOp::CALL:
    case IrOp::CALLN:
        // CALL y CALLN comparten el mismo dispatch.  El backend
        // distingue via @c func_name: si contiene ":" es nativa
        // (lib:func) y el backend la trata con linkage real.
        backend_.emit_call(ctx, ins.dst, ins.func_name, ins.operands, ins.type);
        return;

    case IrOp::TAILCALL: {
        // TAILCALL: termina la funcion con el resultado de la
        // llamada.  C no tiene keyword nativa; emitimos
        // @c "return func(args...);" directo.  GCC -O3 hace
        // tail-call optimization automaticamente cuando sea legal.
        ctx.indent();
        if (ins.type != ir::IrType::VOID) {
            ctx.out << "return ";
        } else {
            // void tail call: emit como statement + return.
        }
        ctx.out << ins.func_name << "(";
        for (size_t i = 0; i < ins.operands.size(); ++i) {
            if (i) ctx.out << ", ";
            ctx.out << backend_.format_value(ctx, ins.operands[i]);
        }
        ctx.out << ");\n";
        if (ins.type == ir::IrType::VOID) {
            ctx.indent();
            ctx.out << "return;\n";
        }
        return;
    }

    case IrOp::CALLIND:
        if (ins.func_ptr != ir::IR_NO_VALUE) {
            backend_.emit_call_indirect(ctx, ins.dst, ins.func_ptr,
                                        ins.operands, ins.type);
        }
        return;

    case IrOp::CALLCLOSURE: {
        // CALLCLOSURE: el func_ptr apunta al slot de 16 bytes que
        // contiene {fn_addr, env_addr}.  En port C lo lowers a:
        //   tipo (*fn)(void*, args...) = *(tipo(*)(void*,...))slot[0];
        //   ret = fn(slot[8], args...);
        if (ins.func_ptr == ir::IR_NO_VALUE) return;
        backend_.emit_call_closure(ctx, ins.dst, ins.func_ptr, ins.operands,
                                   ins.type, ins);
        return;
    }

    case IrOp::CALLVIRT: {
        // CALLVIRT: operands[0]=obj, imm=vtable_idx, operands[1..]=args.
        if (ins.operands.empty()) return;
        ir::IrValueId obj = ins.operands[0];
        std::vector<ir::IrValueId> args(ins.operands.begin() + 1,
                                        ins.operands.end());
        backend_.emit_callvirt(ctx, ins.dst, obj,
                               static_cast<uint32_t>(ins.imm), args, ins.type);
        return;
    }

    case IrOp::CALLM: {
        // CALLM: operands[0]=obj, operands[1]=method_ptr, [2..]=args.
        // Dispatch dinamico via @c MethodInfo*; en port C requiere
        // que el backend deduzca el metodo a llamar (via concrete
        // type del receiver + nombre del metodo).
        if (ins.operands.size() < 2) return;
        ir::IrValueId obj = ins.operands[0];
        ir::IrValueId method_ptr = ins.operands[1];
        std::vector<ir::IrValueId> args(ins.operands.begin() + 2,
                                        ins.operands.end());
        backend_.emit_callm(ctx, ins.dst, obj, method_ptr, args, ins.type);
        return;
    }

    // Markers semanticos ( B): no-op para transpiler.
    case IrOp::MAKE_VARIANT:
    case IrOp::MATCH_VARIANT:
    case IrOp::MAKE_CLOSURE:
        if (opts_.emit_comments) {
            ctx.indent();
            ctx.out << "/* marker: " << ir::ir_op_name(ins.op) << " */\n";
        }
        return;

    case IrOp::STR_LIT_ADDR:
        backend_.emit_str_lit_addr(ctx, ins.dst, ins.imm, ins.type);
        return;

    case IrOp::SPAWN_ARGS: {
        // SPAWN_ARGS: operands[0]=fn_ptr, operands[1]=future,
        // operands[2..]=args adicionales.
        //
        // Caso 1 arg (solo future): direct @c vx_spawn(fn, fut).
        // Caso N>1: alocar array @c int64_t[N], rellenar y pasar
        // un trampoline-by-pointer que el backend genera al emit
        // del modulo (ver @c emit_spawn_trampolines).
        if (ins.operands.size() < 2) return;
        ctx.indent();
        if (ins.operands.size() == 2) {
            /* Direct path: helper toma solo future. */
            ctx.out << "vx_spawn((void(*)(int64_t))(intptr_t)"
                    << backend_.format_value(ctx, ins.operands[0]) << ", "
                    << backend_.format_value(ctx, ins.operands[1]) << ");\n";
        } else {
            /* Multi-arg: empaquetar (fn_ptr, future, args...) en
             * @c int64_t[N+1] heap-alloc.  Un trampoline generico
             * por aridad recibe el ptr, llama @c fn(future, args...).
             * Cero trampolines especificos por helper. */
            size_t n_extra = ins.operands.size() - 2;
            /* Total slots: fn_ptr + future + extras */
            size_t n_total = 2 + n_extra;
            ctx.out << "{\n";
            ctx.indent_level++;
            ctx.indent();
            ctx.out << "int64_t *__sa = (int64_t*)malloc(sizeof(int64_t) * "
                    << n_total << ");\n";
            ctx.indent();
            ctx.out << "__sa[0] = (int64_t)(intptr_t)"
                    << backend_.format_value(ctx, ins.operands[0]) << ";\n";
            ctx.indent();
            ctx.out << "__sa[1] = "
                    << backend_.format_value(ctx, ins.operands[1]) << ";\n";
            for (size_t i = 0; i < n_extra; ++i) {
                ctx.indent();
                ctx.out << "__sa[" << (i + 2) << "] = "
                        << backend_.format_value(ctx, ins.operands[2 + i])
                        << ";\n";
            }
            /* Llamada al trampoline generico de aridad N=n_extra+1
             * (future + extras).  El backend C registra el N en
             * @c emit_spawn_trampoline_call para emitir el
             * @c __vx_trampoline_N una sola vez en el postamble. */
            backend_.emit_spawn_trampoline_call(ctx, ins.operands[0],
                                                n_extra + 1, "__sa");
            ctx.indent_level--;
            ctx.indent();
            ctx.out << "}\n";
        }
        return;
    }

    case IrOp::RAW_ASM:
        backend_.emit_raw_asm(ctx, ins.dst, ins.func_name, ins.operands,
                              ins.type);
        return;

    //  AS inc.3: inline asm nativo de la CPU host.  El backend
    // que lo soporte (port-C) emite @c __asm__ __volatile__; el resto
    // cae a emit_unsupported via el default del hook.
    case IrOp::INLINE_ASM: backend_.emit_inline_asm(ctx, ins); return;

    default: backend_.emit_unsupported(ctx, ins); return;
    }
}

// =========================================================================
//  Nivel C: structured emission (while/if/else)
// =========================================================================

/// Helper: el bloque @c bid termina con @c BR(target)?
static bool block_ends_with_br_to(const ir::IrFunction &fn, ir::IrBlockId bid,
                                  ir::IrBlockId target) {
    if (bid >= fn.blocks.size()) return false;
    const auto &b = fn.blocks[bid];
    if (b.instrs.empty()) return false;
    const auto &t = b.instrs.back();
    return t.op == ir::IrOp::BR && t.target_block == target;
}

/// Helper: el bloque @c bid termina con @c RET o @c UNREACHABLE?
static bool block_ends_terminal(const ir::IrFunction &fn, ir::IrBlockId bid) {
    if (bid >= fn.blocks.size()) return false;
    const auto &b = fn.blocks[bid];
    if (b.instrs.empty()) return false;
    const auto &t = b.instrs.back();
    return t.op == ir::IrOp::RET || t.op == ir::IrOp::UNREACHABLE;
}

/// Helper: el bloque @c bid termina con @c BR a otro?  Devuelve true y
/// llena @c out con el target.  False si el terminator no es BR.
static bool block_br_target(const ir::IrFunction &fn, ir::IrBlockId bid,
                            ir::IrBlockId &out) {
    if (bid >= fn.blocks.size()) return false;
    const auto &b = fn.blocks[bid];
    if (b.instrs.empty()) return false;
    const auto &t = b.instrs.back();
    if (t.op == ir::IrOp::BR) {
        out = t.target_block;
        return true;
    }
    return false;
}

/// Helper: el bloque solo contiene PHIs + cmp + br_cond?  Si tiene otras
/// instrucciones que producirian side effects al re-evaluarse cada
/// iteracion del loop, NO podemos estructurar como @c while.
static bool block_is_clean_loop_header(const ir::IrBlock &bb) {
    // Recorrer: solo permitir PHI, CONST, MOV, comparaciones, conversiones
    // y BR_COND al final.  Cualquier otra instruccion (CALL, LOAD, STORE,
    // ALLOCA, NEWOBJ, etc.) hace que la cabeza del loop tenga side effects.
    size_t n = bb.instrs.size();
    if (n == 0) return false;
    for (size_t i = 0; i + 1 < n; ++i) {
        const auto &ins = bb.instrs[i];
        using ir::IrOp;
        switch (ins.op) {
        case IrOp::PHI:
        case IrOp::CONST:
        case IrOp::MOV:
        case IrOp::ADD:
        case IrOp::SUB:
        case IrOp::MUL:
        case IrOp::AND:
        case IrOp::OR:
        case IrOp::XOR:
        case IrOp::NEG:
        case IrOp::NOT:
        case IrOp::SHL:
        case IrOp::SHR:
        case IrOp::SAR:
        case IrOp::CMP_EQ:
        case IrOp::CMP_NE:
        case IrOp::CMP_LT:
        case IrOp::CMP_GT:
        case IrOp::CMP_LE:
        case IrOp::CMP_GE:
        case IrOp::CMP_ULT:
        case IrOp::CMP_UGT:
        case IrOp::CMP_ULE:
        case IrOp::CMP_UGE:
        case IrOp::FCMP_EQ:
        case IrOp::FCMP_NE:
        case IrOp::FCMP_LT:
        case IrOp::FCMP_GT:
        case IrOp::FCMP_LE:
        case IrOp::FCMP_GE:
        case IrOp::CAST:
        case IrOp::ZEXT:
        case IrOp::SEXT:
        case IrOp::TRUNC:
        case IrOp::ITOF:
        case IrOp::UITOF:
        case IrOp::FTOI:
        case IrOp::FTOUI:
        case IrOp::F32TOF64:
        case IrOp::F64TOF32:
        case IrOp::BITCAST: continue;
        default: return false;
        }
    }
    return bb.instrs.back().op == ir::IrOp::BR_COND;
}

Transpiler::StructureInfo
Transpiler::classify_structure(const ir::IrFunction &fn,
                               const ir::IrBlock &bb) const {
    StructureInfo s;
    if (bb.instrs.empty()) return s;
    const auto &term = bb.instrs.back();
    if (term.op != ir::IrOp::BR_COND) return s;

    const ir::IrBlockId T = term.target_block;
    const ir::IrBlockId E = term.false_block;
    if (T >= fn.blocks.size() || E >= fn.blocks.size()) return s;

    // ---- Patron LOOP simple: uno de los targets vuelve directo a bb ----
    if (block_is_clean_loop_header(bb)) {
        if (block_ends_with_br_to(fn, T, bb.id)) {
            s.kind = StructureInfo::SIMPLE_LOOP;
            s.then_block = T;  // cuerpo del loop
            s.merge_block = E; // bloque exit
            s.inverted = false;
            return s;
        }
        if (block_ends_with_br_to(fn, E, bb.id)) {
            // Patron @c do-while con cond invertida ("seguir mientras
            // false branch loopea").  Marcamos invertido para que el
            // backend emita @c while (!cond).
            s.kind = StructureInfo::SIMPLE_LOOP;
            s.then_block = E;
            s.merge_block = T;
            s.inverted = true;
            return s;
        }
    }

    // ---- Patron IF_THEN_ELSE: ambos branches convergen en un merge ----
    ir::IrBlockId t_dest = ir::IR_NO_BLOCK;
    ir::IrBlockId e_dest = ir::IR_NO_BLOCK;
    const bool t_has_br = block_br_target(fn, T, t_dest);
    const bool e_has_br = block_br_target(fn, E, e_dest);

    if (t_has_br && e_has_br && t_dest == e_dest && t_dest != bb.id) {
        s.kind = StructureInfo::IF_THEN_ELSE;
        s.then_block = T;
        s.else_block = E;
        s.merge_block = t_dest;
        return s;
    }

    // ---- Patron IF_THEN sin else: T->BR(E), E es merge ----
    if (t_has_br && t_dest == E) {
        s.kind = StructureInfo::IF_THEN;
        s.then_block = T;
        s.merge_block = E;
        return s;
    }
    if (e_has_br && e_dest == T) {
        // Cond invertida: el else es el branch real, then es vacio.
        // Emit: @c if (!cond) {else_code} ... continua T.
        s.kind = StructureInfo::IF_THEN;
        s.then_block = E;
        s.merge_block = T;
        s.inverted = true;
        return s;
    }

    // ---- Patron IF_THEN con early return: T termina con RET/UNREACHABLE ----
    if (block_ends_terminal(fn, T)) {
        // Then branch retorna o aborta; el resto del codigo es E.
        s.kind = StructureInfo::IF_THEN;
        s.then_block = T;
        s.merge_block = E;
        return s;
    }
    if (block_ends_terminal(fn, E)) {
        // Else branch retorna; tras el if continuamos por T.  Cond invertida.
        s.kind = StructureInfo::IF_THEN;
        s.then_block = E;
        s.merge_block = T;
        s.inverted = true;
        return s;
    }

    return s; // NONE
}

void Transpiler::emit_block_body_no_term(EmitContext &ctx,
                                         const ir::IrBlock &bb) {
    // Emite todas las instrucciones excepto la ultima (que es terminator).
    // Tambien skip PHIs (resueltas por predecesores).
    if (bb.instrs.empty()) return;
    for (size_t i = 0; i + 1 < bb.instrs.size(); ++i) {
        const auto &ins = bb.instrs[i];
        if (ins.op == ir::IrOp::PHI) continue;
        emit_instr(ctx, ins);
    }
}

void Transpiler::emit_block_terminator(EmitContext &ctx,
                                       const ir::IrFunction &fn,
                                       const ir::IrBlock &bb) {
    if (bb.instrs.empty()) return;
    const auto &ins = bb.instrs.back();
    switch (ins.op) {
    case ir::IrOp::BR: {
        emit_phi_copies_for_edge(ctx, fn, bb.id, ins.target_block);
        backend_.emit_goto(ctx, ins.target_block);
        return;
    }
    case ir::IrOp::BR_COND: {
        // Sin estructura: fallback goto-style.
        bool t_phi = block_has_phis(fn, ins.target_block);
        bool f_phi = block_has_phis(fn, ins.false_block);
        if (!t_phi && !f_phi) {
            backend_.emit_cond_branch(ctx, ins.operands[0], ins.target_block,
                                      ins.false_block);
        } else {
            std::string cond_expr = backend_.format_value(ctx, ins.operands[0]);
            ctx.indent();
            ctx.out << "if (" << cond_expr << ") {\n";
            ctx.indent_level++;
            emit_phi_copies_for_edge(ctx, fn, bb.id, ins.target_block);
            backend_.emit_goto(ctx, ins.target_block);
            ctx.indent_level--;
            ctx.indent();
            ctx.out << "}\n";
            emit_phi_copies_for_edge(ctx, fn, bb.id, ins.false_block);
            backend_.emit_goto(ctx, ins.false_block);
        }
        return;
    }
    case ir::IrOp::RET: {
        backend_.emit_return(ctx, ins.operands.empty() ? ir::IR_NO_VALUE
                                                       : ins.operands[0]);
        return;
    }
    case ir::IrOp::UNREACHABLE: {
        ctx.indent();
        ctx.out << "/* unreachable */ ;\n";
        return;
    }
    default: return;
    }
}

void Transpiler::emit_region(EmitContext &ctx, const ir::IrFunction &fn,
                             ir::IrBlockId start, ir::IrBlockId stop,
                             std::vector<bool> &visited) {
    ir::IrBlockId cur = start;
    while (cur != ir::IR_NO_BLOCK && cur != stop) {
        if (cur >= fn.blocks.size()) return;
        if (visited[cur]) return; // ya emitido; el caller se encarga
        visited[cur] = true;

        const auto &bb = fn.blocks[cur];
        ctx.bb = &bb;

        // Clasificar la estructura PRIMERO -- si el bloque es header de
        // un @c while o un @c if-then-else, NO emitir label.  Los preds
        // de un loop header son (a) entrada por fall-through (no goto)
        // y (b) back-edge implicito del @c while.  Ninguno necesita label.
        // Para un if-header, los preds son fall-through del bloque previo.
        // Solo emitimos label si la entrada al bloque requiere @c goto
        // explicito (preds que escapan del flujo estructurado, como
        // multiples paths que no son estructurables).
        StructureInfo info = classify_structure(fn, bb);
        bool is_structured_header = (info.kind == StructureInfo::SIMPLE_LOOP ||
                                     info.kind == StructureInfo::IF_THEN ||
                                     info.kind == StructureInfo::IF_THEN_ELSE);

        // Emitir label si el bloque tiene mas de un predecesor Y NO es
        // un header estructurable (cuyo flujo de entrada es implicito).
        // Tambien forzar emission para handlers de try/catch que son
        // destino de @c goto computado via labels-as-values.
        const bool is_try_block =
            (!bb.name.empty()) && (bb.name.rfind("try_handler_", 0) == 0 ||
                                   bb.name.rfind("try_body_", 0) == 0 ||
                                   bb.name.rfind("try_merge_", 0) == 0);
        if (cur != start && !is_structured_header &&
            (ana_.block_preds[cur].size() > 1 || is_try_block)) {
            backend_.emit_label_def(ctx, cur);
        }

        if (info.kind == StructureInfo::SIMPLE_LOOP) {
            // Anotacion opcional con el nombre del bloque.
            if (opts_.emit_comments && !bb.name.empty()) {
                ctx.indent();
                ctx.out << "/* " << bb.name << " (loop) */\n";
            }
            // Emitir cualquier non-PHI instr ANTES del cmp (raramente
            // hay, pero por si acaso).  La instruccion CMP esta entre
            // las non-terminator y NO se emite aqui -- se inlinea en
            // la condicion del @c while.  Para eso, el CMP debe ser
            // inline candidate (single-use por la BR_COND).  Si NO lo
            // es, lo emitimos como statement antes del while; el while
            // referencia la variable.
            const auto &term = bb.instrs.back();
            ir::IrValueId cond_id =
                term.operands.empty() ? ir::IR_NO_VALUE : term.operands[0];
            // Emitir instrs del header que NO son PHI ni el cmp del cond.
            for (size_t i = 0; i + 1 < bb.instrs.size(); ++i) {
                const auto &ins = bb.instrs[i];
                if (ins.op == ir::IrOp::PHI) continue;
                if (ins.dst == cond_id && ana_.is_inline_candidate[cond_id]) {
                    continue; // inlineado en el @c while (...)
                }
                emit_instr(ctx, ins);
            }

            std::string cond_expr = backend_.format_value(ctx, cond_id);
            if (info.inverted) cond_expr = "!(" + cond_expr + ")";

            ctx.indent();
            ctx.out << "while (" << cond_expr << ") {\n";
            ctx.indent_level++;

            // Emitir el cuerpo: subregion hasta el back-edge a bb.id.
            emit_region(ctx, fn, info.then_block, bb.id, visited);
            // Las PHI copies del back-edge se emiten via el BR del ultimo
            // bloque del body, que es @c bb.id como destino.
            // El terminator @c BR(bb.id) del back-edge ya fue manejado
            // por @c emit_block_terminator dentro de la subregion -- pero
            // produjo @c "goto bb_X;" como salida.  Para evitarlo, el
            // emit_region detecta que el destino del BR == el header del
            // loop actual y suprime el goto (es implicito por la
            // estructura del while).  Esto se hace via @c suppress_back_edge_.
            // En esta version simplificada, el goto residual se vera; lo
            // limpiaremos en la siguiente iteracion del refactor.

            ctx.indent_level--;
            ctx.indent();
            ctx.out << "}\n";

            // Continuar tras el while con el bloque exit.
            cur = info.merge_block;
            continue;
        }

        if (info.kind == StructureInfo::IF_THEN ||
            info.kind == StructureInfo::IF_THEN_ELSE) {
            if (opts_.emit_comments && !bb.name.empty()) {
                ctx.indent();
                ctx.out << "/* " << bb.name << " (if) */\n";
            }

            // Emitir non-terminator instrs (incluido el cmp si NO es
            // inline candidate -- en cuyo caso queda variable v_cmp).
            const auto &term = bb.instrs.back();
            ir::IrValueId cond_id =
                term.operands.empty() ? ir::IR_NO_VALUE : term.operands[0];
            for (size_t i = 0; i + 1 < bb.instrs.size(); ++i) {
                const auto &ins = bb.instrs[i];
                if (ins.op == ir::IrOp::PHI) continue;
                if (ins.dst == cond_id && ana_.is_inline_candidate[cond_id]) {
                    continue;
                }
                emit_instr(ctx, ins);
            }

            std::string cond_expr = backend_.format_value(ctx, cond_id);
            if (info.inverted) cond_expr = "!(" + cond_expr + ")";

            // Phi copies para el edge bb -> then_block (si el then tiene PHIs).
            // Las emitimos DENTRO del if {} para que solo corran si la cond es
            // true.
            ctx.indent();
            ctx.out << "if (" << cond_expr << ") {\n";
            ctx.indent_level++;
            emit_phi_copies_for_edge(ctx, fn, bb.id, info.then_block);
            emit_region(ctx, fn, info.then_block, info.merge_block, visited);
            ctx.indent_level--;
            ctx.indent();
            ctx.out << "}";

            if (info.kind == StructureInfo::IF_THEN_ELSE) {
                ctx.out << " else {\n";
                ctx.indent_level++;
                emit_phi_copies_for_edge(ctx, fn, bb.id, info.else_block);
                emit_region(ctx, fn, info.else_block, info.merge_block,
                            visited);
                ctx.indent_level--;
                ctx.indent();
                ctx.out << "}\n";
            } else {
                // Phi copies del edge bb -> merge (para if-then sin else).
                // CRITICO: estas copias deben emitirse SOLO cuando la cond
                // es false (rama no tomada).  Si no hay PHIs, no emitimos
                // un else vacio; si hay, lo envolvemos en @c else {}.
                bool merge_has_phis = false;
                if (info.merge_block < fn.blocks.size()) {
                    for (const auto &mi : fn.blocks[info.merge_block].instrs) {
                        if (mi.op == ir::IrOp::PHI) {
                            merge_has_phis = true;
                            break;
                        }
                    }
                }
                if (merge_has_phis) {
                    ctx.out << " else {\n";
                    ctx.indent_level++;
                    emit_phi_copies_for_edge(ctx, fn, bb.id, info.merge_block);
                    ctx.indent_level--;
                    ctx.indent();
                    ctx.out << "}\n";
                } else {
                    ctx.out << "\n";
                }
            }

            cur = info.merge_block;
            continue;
        }

        // ---- NONE: bloque no estructurable; emit_block_body + terminator ----
        if (opts_.emit_comments && !bb.name.empty()) {
            ctx.indent();
            ctx.out << "/* " << bb.name << " */\n";
        }
        emit_block_body_no_term(ctx, bb);
        // Decidir el "siguiente" bloque segun el terminator.  El emisor
        // de terminator se encarga de phi copies + goto/return.
        if (bb.instrs.empty()) {
            cur = ir::IR_NO_BLOCK;
            continue;
        }
        const auto &term = bb.instrs.back();
        switch (term.op) {
        case ir::IrOp::BR: {
            // Optimizacion: si el target es el siguiente bloque a
            // procesar (fall-through natural en la emision), suprimir
            // el @c goto.  Caso especial: si el target == stop, el
            // emit_region terminara naturalmente.
            ir::IrBlockId target = term.target_block;
            emit_phi_copies_for_edge(ctx, fn, bb.id, target);
            if (target == stop) {
                // El caller continuara desde @c stop; no emitir goto.
                cur = ir::IR_NO_BLOCK;
            } else if (target < fn.blocks.size() && !visited[target]) {
                // Fall-through al target: lo emite la proxima iter.
                cur = target;
            } else {
                // Goto a bloque ya visitado o invalido: emit explicito.
                backend_.emit_goto(ctx, target);
                cur = ir::IR_NO_BLOCK;
            }
            break;
        }
        case ir::IrOp::BR_COND: {
            // No estructurable: emit cond_branch goto-style y termina
            // la region (los dos targets se emitiran si son alcanzables
            // por otro camino).
            emit_block_terminator(ctx, fn, bb);
            // Tratar de continuar por el false branch si no visitado.
            if (term.false_block < fn.blocks.size() &&
                !visited[term.false_block] && term.false_block != stop) {
                cur = term.false_block;
            } else if (term.target_block < fn.blocks.size() &&
                       !visited[term.target_block] &&
                       term.target_block != stop) {
                cur = term.target_block;
            } else {
                cur = ir::IR_NO_BLOCK;
            }
            break;
        }
        case ir::IrOp::RET:
            backend_.emit_return(ctx, term.operands.empty() ? ir::IR_NO_VALUE
                                                            : term.operands[0]);
            cur = ir::IR_NO_BLOCK;
            break;
        case ir::IrOp::UNREACHABLE:
            ctx.indent();
            ctx.out << "/* unreachable */ ;\n";
            cur = ir::IR_NO_BLOCK;
            break;
        case ir::IrOp::TAILCALL:
            // TAILCALL es terminator: emit como return func(args).
            emit_instr(ctx, term);
            cur = ir::IR_NO_BLOCK;
            break;
        case ir::IrOp::RAW_ASM:
            // El frontend Vesta usa raw_asm como ultimo instr para
            // emitir @c fulfillhlt (async helpers) y otros patrones
            // de exit-from-function.  Tratarlo como instruccion
            // normal + terminar region.
            emit_instr(ctx, term);
            cur = ir::IR_NO_BLOCK;
            break;
        default: cur = ir::IR_NO_BLOCK; break;
        }
    }
}

} // namespace port
