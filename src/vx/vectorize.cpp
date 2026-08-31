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
 * @file vectorize.cpp
 * @brief Auto-vectorizacion del frontend Vesta.
 *
 * Reconocimiento de idiomas de bucle (de momento la COPIA de elementos
 * `dst[i] = src[i]` en su forma @c while y @c for) y su bajada a operaciones
 * eficientes: un unico @c MEMCPY que el JIT/AOT materializan como @c rep
 * @c movsb / SIMD y el interprete como un bucle host->host.
 *
 * Estos son metodos de @c vx::Lowering (declarados en @c vx/lowering.h) pero
 * se definen en este TU separado para mantener la vectorizacion agrupada y
 * poder evolucionarla (unroll xW, fusion SIMD, memset, anchos AVX/AVX512) sin
 * inflar @c lowering.cpp ni dificultar un futuro split en mas archivos.
 *
 * Decision de diseno (host vs VM): el idioma solo se aplica sobre punteros
 * HOST (malloc/FFI).  El JIT baja @c MEMCPY a @c rep @c movsb (host->host) y el
 * interprete a un bucle host->host; sobre arrays VM-virtuales (@c T[N],
 * @c &local) eso seria incorrecto, asi que esos casos bailan y siguen como
 * bucle escalar normal.
 */

#include "util/env_flags.h"
#include "vx/lowering.h"

#include "jit/vec_isa.h" // ancho del chunk vectorizado (SSE2/AVX2/AVX512)

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>

namespace vx {

// Helper file-local: true si la expresion @p e referencia el identificador
// @p name en cualquier parte (recursivo, conservador).  Usado para verificar
// que un operando "escalar" de una cadena compound es INVARIANTE del loop (no
// depende del indice) antes de izarlo al preheader.
static bool mc_expr_refs_ident(ast::Expr *e, const std::string &name) {
    using namespace ast;
    if (!e) return false;
    switch (e->kind) {
    case NodeKind::IdentExpr: return static_cast<IdentExpr *>(e)->name == name;
    case NodeKind::BinaryExpr: {
        auto *b = static_cast<BinaryExpr *>(e);
        return mc_expr_refs_ident(b->lhs.get(), name) ||
               mc_expr_refs_ident(b->rhs.get(), name);
    }
    case NodeKind::UnaryExpr:
        return mc_expr_refs_ident(static_cast<UnaryExpr *>(e)->operand.get(),
                                  name);
    case NodeKind::IndexExpr: {
        auto *ix = static_cast<IndexExpr *>(e);
        return mc_expr_refs_ident(ix->base.get(), name) ||
               mc_expr_refs_ident(ix->index.get(), name);
    }
    case NodeKind::CallExpr: {
        auto *c = static_cast<CallExpr *>(e);
        if (mc_expr_refs_ident(c->callee.get(), name)) return true;
        for (auto &arg : c->args)
            if (mc_expr_refs_ident(arg.get(), name)) return true;
        return false;
    }
    case NodeKind::CastExpr:
        return mc_expr_refs_ident(static_cast<CastExpr *>(e)->operand.get(),
                                  name);
    case NodeKind::FieldAccessExpr:
        return mc_expr_refs_ident(static_cast<FieldAccessExpr *>(e)->base.get(),
                                  name);
    default:
        // Literales y otras formas sin sub-exprs: conservador, asumimos que un
        // nodo no manejado PODRIA referenciar idx -> tratarlo como dependiente
        // solo si es complejo; para literales puros devolvemos false.
        return false;
    }
}

// Helper file-local: true si @p e es un incremento de @p idx en 1, en
// cualquiera de las formas `idx++`, `++idx`, `idx = idx + 1`, `idx += 1`.
static bool mc_is_increment_expr(ast::Expr *e, const std::string &idx) {
    using namespace ast;
    if (!e) return false;
    if (e->kind == NodeKind::UnaryExpr) {
        auto *un = static_cast<UnaryExpr *>(e);
        return (un->op == UnOp::PostInc || un->op == UnOp::PreInc) &&
               un->operand && un->operand->kind == NodeKind::IdentExpr &&
               static_cast<IdentExpr *>(un->operand.get())->name == idx;
    }
    if (e->kind == NodeKind::AssignExpr) {
        auto *ia = static_cast<AssignExpr *>(e);
        if (!ia->target || ia->target->kind != NodeKind::IdentExpr)
            return false;
        if (static_cast<IdentExpr *>(ia->target.get())->name != idx)
            return false;
        if (ia->op == AssignOp::AddAssign) { // idx += 1
            return ia->value && ia->value->kind == NodeKind::IntLitExpr &&
                   static_cast<IntLitExpr *>(ia->value.get())->value == 1;
        }
        if (ia->op == AssignOp::Assign && ia->value && // idx = idx + 1
            ia->value->kind == NodeKind::BinaryExpr) {
            auto *add = static_cast<BinaryExpr *>(ia->value.get());
            return add->op == BinOp::Add && add->lhs &&
                   add->lhs->kind == NodeKind::IdentExpr &&
                   static_cast<IdentExpr *>(add->lhs.get())->name == idx &&
                   add->rhs && add->rhs->kind == NodeKind::IntLitExpr &&
                   static_cast<IntLitExpr *>(add->rhs.get())->value == 1;
        }
    }
    return false;
}

namespace {
/// Descriptor normalizado de un loop contador vectorizable, extraido de un
/// @c for o un @c while.  @c body_exprs son las sentencias del cuerpo (sin el
/// incremento), cada una un @c AssignExpr; @c for_init es la expr del valor
/// inicial de @c idx para @c for (el frontend la baja fresca), o @c nullptr
/// para @c while (el indice ya esta declarado -> el valor inicial es el binding
/// SSA actual via lookup).
struct VecLoop {
    std::string idx_name;
    ast::Expr *limit = nullptr;          // N (cond.rhs)
    std::vector<ast::Expr *> body_exprs; // sentencias del cuerpo (AssignExpr)
    ast::Expr *for_init = nullptr;       // vd->init (for) o nullptr (while)
};

/**
 * @brief Reconoce la condicion de un bucle contado: `i < N`.
 *
 * Es la forma que TODOS los idiomas de este fichero exigen antes de mirar nada
 * mas -- copiar un bloque, vectorizar una operacion, reducir --, y estaba
 * escrita tres veces: aqui dentro como lambda y dos mas a mano en los dos
 * reconocedores de copia.
 *
 * `N` puede ser un nombre o un numero escrito, pero no una expresion: una
 * expresion habria que evaluarla, y en un bucle se evaluaria en CADA vuelta, de
 * modo que sacarla fuera cambiaria el programa si tiene efectos.
 *
 * @param cond     La condicion.
 * @param idx_name Donde dejar el nombre del indice.
 * @param limit    Donde dejar el limite, sin evaluar.
 * @return @c false si la forma no encaja; entonces el bucle se baja normal.
 */
static bool mc_parse_counted_cond(ast::Expr *cond, std::string &idx_name,
                                  ast::Expr *&limit) {
    using namespace ast;
    if (!cond || cond->kind != NodeKind::BinaryExpr) return false;
    auto *c = static_cast<BinaryExpr *>(cond);
    if (c->op != BinOp::Lt) return false;
    if (!c->lhs || c->lhs->kind != NodeKind::IdentExpr) return false;
    if (!c->rhs) return false;
    const NodeKind rk = c->rhs->kind;
    if (rk != NodeKind::IdentExpr && rk != NodeKind::IntLitExpr) return false;
    idx_name = static_cast<IdentExpr *>(c->lhs.get())->name;
    limit = c->rhs.get();
    return true;
}

/// Extrae un @c VecLoop de un @c for(T i=init; i<N; i++) BODY o de un
/// @c while(i<N){ BODY; i=i+1; }.  El cuerpo del @c for es 1 sentencia; el del
/// @c while son las sentencias previas a un incremento final de @c i.  Devuelve
/// false si la forma no encaja (cualquier desviacion -> el loop se baja
/// normal).
bool mc_extract_vec_loop(ast::Stmt *s, VecLoop &out) {
    using namespace ast;
    if (!s) return false;
    auto parse_cond = [&](ast::Expr *cond) -> bool {
        return mc_parse_counted_cond(cond, out.idx_name, out.limit);
    };
    // extrae el ExprStmt(AssignExpr) de una sentencia; null si no lo es.
    auto as_assign = [](ast::Stmt *st) -> ast::Expr * {
        if (!st || st->kind != NodeKind::ExprStmt) return nullptr;
        auto *e = static_cast<ExprStmt *>(st)->expr.get();
        return (e && e->kind == NodeKind::AssignExpr) ? e : nullptr;
    };
    if (s->kind == NodeKind::ForStmt) {
        auto *f = static_cast<ForStmt *>(s);
        if (!f->cond || !f->body || !f->init || !f->step) return false;
        if (!parse_cond(f->cond.get())) return false;
        if (f->init->kind != NodeKind::VarDeclStmt) return false;
        auto *vd = static_cast<VarDeclStmt *>(f->init.get());
        if (vd->name != out.idx_name || !vd->init) return false;
        if (!mc_is_increment_expr(f->step.get(), out.idx_name)) return false;
        // cuerpo = 1 sentencia (ExprStmt directo o Block de 1).
        ast::Expr *be = nullptr;
        if (f->body->kind == NodeKind::ExprStmt) {
            be = as_assign(f->body.get());
        } else if (f->body->kind == NodeKind::BlockStmt) {
            auto *b = static_cast<BlockStmt *>(f->body.get());
            if (b->body.size() != 1) return false;
            be = as_assign(b->body[0].get());
        }
        if (!be) return false;
        out.body_exprs.push_back(be);
        out.for_init = vd->init.get();
        return true;
    }
    if (s->kind == NodeKind::WhileStmt) {
        auto *w = static_cast<WhileStmt *>(s);
        if (!w->cond || !w->body) return false;
        if (!parse_cond(w->cond.get())) return false;
        if (w->body->kind != NodeKind::BlockStmt) return false;
        auto *b = static_cast<BlockStmt *>(w->body.get());
        // cuerpo = [AssignExpr...; incremento de idx final].  >=2 sentencias.
        if (b->body.size() < 2) return false;
        if (!mc_is_increment_expr(
                b->body.back()->kind == NodeKind::ExprStmt
                    ? static_cast<ExprStmt *>(b->body.back().get())->expr.get()
                    : nullptr,
                out.idx_name))
            return false;
        for (size_t i = 0; i + 1 < b->body.size(); ++i) {
            ast::Expr *be = as_assign(b->body[i].get());
            if (!be) return false;
            out.body_exprs.push_back(be);
        }
        out.for_init = nullptr; // while: valor inicial = binding SSA actual
        return true;
    }
    return false;
}
} // namespace

bool Lowering::mc_match_copy_assign(ast::AssignExpr *asg,
                                    const std::string &idx_name,
                                    ast::IdentExpr **out_dst,
                                    ast::IdentExpr **out_src, size_t *out_esz) {
    using namespace ast;
    if (!asg || asg->op != AssignOp::Assign) return false;
    if (!asg->target || asg->target->kind != NodeKind::IndexExpr) return false;
    if (!asg->value || asg->value->kind != NodeKind::IndexExpr) return false;
    auto *dst_ix = static_cast<IndexExpr *>(asg->target.get());
    auto *src_ix = static_cast<IndexExpr *>(asg->value.get());
    // Sin overloads de operador ni slices/ranges.
    if (!dst_ix->overload_method.empty() || !dst_ix->index_set_method.empty() ||
        dst_ix->is_range)
        return false;
    if (!src_ix->overload_method.empty() || src_ix->is_range) return false;
    // base = ident; index = el MISMO idx del loop en ambos.
    if (!dst_ix->base || dst_ix->base->kind != NodeKind::IdentExpr)
        return false;
    if (!src_ix->base || src_ix->base->kind != NodeKind::IdentExpr)
        return false;
    if (!dst_ix->index || dst_ix->index->kind != NodeKind::IdentExpr)
        return false;
    if (!src_ix->index || src_ix->index->kind != NodeKind::IdentExpr)
        return false;
    if (static_cast<IdentExpr *>(dst_ix->index.get())->name != idx_name)
        return false;
    if (static_cast<IdentExpr *>(src_ix->index.get())->name != idx_name)
        return false;
    auto *dst_base = static_cast<IdentExpr *>(dst_ix->base.get());
    auto *src_base = static_cast<IdentExpr *>(src_ix->base.get());
    // Tipos: ambos PTR/ARRAY HOST con pointee del MISMO tamano.
    const Type &dt = dst_base->result_type;
    const Type &stt = src_base->result_type;
    auto is_ptr_like = [](const Type &t) {
        return (t.kind == PrimitiveKind::PTR ||
                t.kind == PrimitiveKind::ARRAY) &&
               static_cast<bool>(t.pointee);
    };
    if (!is_ptr_like(dt) || !is_ptr_like(stt)) return false;
    if (dt.is_virtual || stt.is_virtual) return false; // solo punteros HOST
    const size_t esz = size_of_type(*dt.pointee);
    if (esz == 0 || size_of_type(*stt.pointee) != esz) return false;
    *out_dst = dst_base;
    *out_src = src_base;
    *out_esz = esz;
    return true;
}

bool Lowering::mc_emit_copy(ir::IrValueId v_idx, ast::Expr *limit,
                            ast::IdentExpr *dst_base, ast::IdentExpr *src_base,
                            size_t esz, uint32_t ln,
                            const std::string &idx_name_for_post) {
    if (v_idx == ir::IR_NO_VALUE) return false;
    const ir::IrType idx_ty = fn_->values[v_idx].type;
    // El indice debe ser un ENTERO valor.  Si es PTR (p.ej. la var del loop es
    // address-taken y su binding es la direccion del slot, no el valor) o un
    // host_ptr, bailar: usarlo como indice produciria basura.
    if (idx_ty == ir::IrType::PTR || idx_ty == ir::IrType::F32 ||
        idx_ty == ir::IrType::F64 || fn_->values[v_idx].is_host_ptr)
        return false;
    const ir::IrValueId base_dst = lower_expr(dst_base);
    const ir::IrValueId base_src = lower_expr(src_base);
    if (base_dst == ir::IR_NO_VALUE || base_src == ir::IR_NO_VALUE)
        return false;
    const ir::IrValueId v_lim = lower_expr(limit);
    if (v_lim == ir::IR_NO_VALUE) return false;

    // idx y limite a i64 para la aritmetica de tamano.
    const ir::IrValueId idx64 =
        cast_if_needed(v_idx, idx_ty, ir::IrType::I64, ln);
    const ir::IrValueId lim64 =
        cast_if_needed(v_lim, fn_->values[v_lim].type, ir::IrType::I64, ln);

    auto bin = [&](ir::IrOp op, ir::IrValueId a,
                   ir::IrValueId b) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ir::IrType::I64);
        ir::IrInstr i{};
        i.op = op;
        i.type = ir::IrType::I64;
        i.dst = d;
        i.operands = {a, b};
        i.source_line = ln;
        fn_->append(current_block_, std::move(i));
        return d;
    };

    // diff = lim - idx;  count = diff & ~(diff >> 63)  (0 si diff<=0).
    const ir::IrValueId diff = bin(ir::IrOp::SUB, lim64, idx64);
    const ir::IrValueId sar =
        bin(ir::IrOp::SAR, diff, emit_const(ir::IrType::I64, 63, ln));
    const ir::IrValueId notmask = fn_->new_value(ir::IrType::I64);
    {
        ir::IrInstr i{};
        i.op = ir::IrOp::NOT;
        i.type = ir::IrType::I64;
        i.dst = notmask;
        i.operands = {sar};
        i.source_line = ln;
        fn_->append(current_block_, std::move(i));
    }
    const ir::IrValueId count = bin(ir::IrOp::AND, diff, notmask);

    // bytes = count * esz;  byteoff = idx * esz.
    const ir::IrValueId v_esz = emit_const(ir::IrType::I64, (uint64_t)esz, ln);
    const ir::IrValueId bytes =
        (esz == 1) ? count : bin(ir::IrOp::MUL, count, v_esz);
    const ir::IrValueId byteoff =
        (esz == 1) ? idx64 : bin(ir::IrOp::MUL, idx64, v_esz);

    // dst_ptr = base_dst + byteoff;  src_ptr = base_src + byteoff (HOST).
    auto ptr_add = [&](ir::IrValueId base, ir::IrValueId off) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ir::IrType::PTR);
        fn_->values[d].is_host_ptr = true; // verificado HOST en mc_match_copy
        ir::IrInstr i{};
        i.op = ir::IrOp::ADD;
        i.type = ir::IrType::PTR;
        i.dst = d;
        i.operands = {base, off};
        i.source_line = ln;
        fn_->append(current_block_, std::move(i));
        return d;
    };
    const ir::IrValueId dst_ptr = ptr_add(base_dst, byteoff);
    const ir::IrValueId src_ptr = ptr_add(base_src, byteoff);

    // MEMCPY dst_ptr, src_ptr, bytes  (rep movsb / SIMD en JIT/AOT; bucle
    // host->host en el interprete).
    {
        ir::IrInstr mc{};
        mc.op = ir::IrOp::MEMCPY;
        mc.type = ir::IrType::I8;
        mc.dst = ir::IR_NO_VALUE;
        mc.operands = {dst_ptr, src_ptr, bytes};
        mc.source_line = ln;
        fn_->append(current_block_, std::move(mc));
    }

    // idx post-loop = idx_init + count  (== N si corrio, == idx_init si no).
    // Solo para el while con idx EXTERNA; el for que declara la var en init la
    // tiene loop-local y no se observa tras el loop (idx_name_for_post vacio).
    if (!idx_name_for_post.empty()) {
        const ir::IrValueId post64 = bin(ir::IrOp::ADD, idx64, count);
        const ir::IrValueId post =
            cast_if_needed(post64, ir::IrType::I64, idx_ty, ln);
        update_scope(idx_name_for_post, post);
    }
    return true;
}

bool Lowering::try_lower_memcpy_idiom(ast::WhileStmt *s) {
    // @NoIdiom: no reescribir un bucle de copia a `memcpy` dentro de quien
    // IMPLEMENTA memcpy -- seria una llamada a si mismo.
    if (current_fn_no_idiom_) return false;
    using namespace ast;
    static const bool MC_DBG = util::flag_on(util::FlagId::McIdiomDebug);
    if (!s->cond || !s->body) return false;

    // cond = (idx < limit): idx ident, limit libre de efectos (1 evaluacion).
    std::string idx_name;
    ast::Expr *limit = nullptr;
    if (!mc_parse_counted_cond(s->cond.get(), idx_name, limit)) return false;
    if (lookup(idx_name) == ir::IR_NO_VALUE) return false;

    // body = bloque con EXACTAMENTE 2 statements (la copia + el incremento).
    if (s->body->kind != NodeKind::BlockStmt) return false;
    auto *blk = static_cast<BlockStmt *>(s->body.get());
    if (blk->body.size() != 2) return false;
    if (!blk->body[0] || blk->body[0]->kind != NodeKind::ExprStmt) return false;
    if (!blk->body[1] || blk->body[1]->kind != NodeKind::ExprStmt) return false;
    auto *st0 = static_cast<ExprStmt *>(blk->body[0].get());
    auto *st1 = static_cast<ExprStmt *>(blk->body[1].get());
    if (!st0->expr || !st1->expr) return false;

    // stmt0 = dst[idx] = src[idx]; stmt1 = incremento de idx.
    if (st0->expr->kind != NodeKind::AssignExpr) return false;
    ast::IdentExpr *dst_base = nullptr, *src_base = nullptr;
    size_t esz = 0;
    if (!mc_match_copy_assign(static_cast<AssignExpr *>(st0->expr.get()),
                              idx_name, &dst_base, &src_base, &esz))
        return false;
    if (!mc_is_increment_expr(st1->expr.get(), idx_name)) return false;

    if (MC_DBG)
        std::fprintf(stderr, "[mc-idiom] MATCH while idx=%s esz=%zu\n",
                     idx_name.c_str(), esz);
    // idx es una var EXTERNA: su valor actual viene del scope; tras el loop hay
    // que escribir el idx post-loop (idx_name_for_post = idx_name).
    return mc_emit_copy(lookup(idx_name), limit, dst_base, src_base, esz,
                        s->loc.line, /*idx_name_for_post=*/idx_name);
}

bool Lowering::try_lower_memcpy_idiom_for(ast::ForStmt *s) {
    // @NoIdiom: no reescribir un bucle de copia a `memcpy` dentro de quien
    // IMPLEMENTA memcpy -- seria una llamada a si mismo.
    if (current_fn_no_idiom_) return false;
    using namespace ast;
    static const bool MC_DBG = util::flag_on(util::FlagId::McIdiomDebug);
    if (!s->cond || !s->body || !s->init || !s->step) return false;

    // cond = (idx < limit).
    std::string idx_name;
    ast::Expr *limit = nullptr;
    if (!mc_parse_counted_cond(s->cond.get(), idx_name, limit)) return false;

    // init DECLARA la var del loop con inicializador -> loop-local (sin
    // writeback de scope tras el loop).  Otras formas de init bailan (el
    // lower_for normal las maneja).
    if (s->init->kind != NodeKind::VarDeclStmt) return false;
    auto *vd = static_cast<VarDeclStmt *>(s->init.get());
    if (vd->name != idx_name || !vd->init) return false;

    // step = incremento de idx.
    if (!mc_is_increment_expr(s->step.get(), idx_name)) return false;

    // body = la copia dst[idx]=src[idx] (bloque de 1 stmt o ExprStmt directo).
    ast::Expr *copy_expr = nullptr;
    if (s->body->kind == NodeKind::ExprStmt) {
        copy_expr = static_cast<ExprStmt *>(s->body.get())->expr.get();
    } else if (s->body->kind == NodeKind::BlockStmt) {
        auto *b = static_cast<BlockStmt *>(s->body.get());
        if (b->body.size() != 1 || !b->body[0] ||
            b->body[0]->kind != NodeKind::ExprStmt)
            return false;
        copy_expr = static_cast<ExprStmt *>(b->body[0].get())->expr.get();
    } else {
        return false;
    }
    if (!copy_expr || copy_expr->kind != NodeKind::AssignExpr) return false;
    ast::IdentExpr *dst_base = nullptr, *src_base = nullptr;
    size_t esz = 0;
    if (!mc_match_copy_assign(static_cast<AssignExpr *>(copy_expr), idx_name,
                              &dst_base, &src_base, &esz))
        return false;

    if (MC_DBG)
        std::fprintf(stderr, "[mc-idiom] MATCH for idx=%s esz=%zu\n",
                     idx_name.c_str(), esz);

    // MATCH: la var del loop es loop-local y solo necesitamos su VALOR inicial
    // para los limites del memcpy; NO la declaramos (evita el caso
    // address-taken donde su binding seria la direccion del slot, no el valor).
    // Bajamos directamente el init.  Sin push_scope ni post-update.
    const ir::IrValueId v_init = lower_expr(vd->init.get());
    if (v_init == ir::IR_NO_VALUE) return false;
    return mc_emit_copy(v_init, limit, dst_base, src_base, esz, s->loc.line,
                        /*idx_name_for_post=*/std::string());
}

/**
 * @brief Abre un bucle contado y deja listo su cuerpo.
 *
 * Es la unica descripcion de como se construye un bucle en el vectorizador.
 * Antes cada idioma la escribia entera -- los phis, la condicion, el salto, la
 * arista de vuelta y las listas de predecesores y sucesores -- y son cuarenta
 * lineas donde los fallos no dan error: una arista contada dos veces o una
 * entrada de phi que apunta al bloque equivocado producen codigo que compila y
 * hace otra cosa.
 *
 * Los bloques los crea quien llama.  Podria crearlos esto, pero entonces el
 * nombre y el ORDEN en que aparecen en el volcado del IR dejarian de ser cosa
 * del idioma, y esos dos detalles son justamente por donde se lee lo que hizo.
 *
 * @param f            Marco a rellenar.
 * @param hdr          Bloque de la cabecera.
 * @param body         Bloque del cuerpo.
 * @param after        Bloque al que se sale.
 * @param i_init       Valor inicial del indice.
 * @param bound        Contra que se compara.
 * @param step         Cuanto avanza el indice por vuelta.
 * @param guard        Cuando se entra a una vuelta.
 * @param carried_init Valor inicial de cada cosa que viaje entre vueltas.
 * @param ln           Linea del fuente.
 */
void Lowering::vec_loop_open(VecLoopFrame &f, ir::IrBlockId hdr,
                             ir::IrBlockId body, ir::IrBlockId after,
                             ir::IrValueId i_init, ir::IrValueId bound,
                             ir::IrValueId step, uint64_t step_imm,
                             VecLoopGuard guard,
                             const std::vector<ir::IrValueId> &carried_init,
                             uint32_t ln, ir::IrBlockId from_hint) {
    /* Se puede llegar a la cabecera de dos maneras, y confundirlas produce un
     * bucle infinito que compila sin quejarse: o se viene de un bloque
     * anterior -- y entonces hay que saltar aqui --, o ya se esta dentro
     * porque el bucle de antes salio justo a esta cabecera, y entonces el
     * salto sobra y el phi tiene que apuntar a quien de verdad manda el
     * control, no a la cabecera misma. */
    const ir::IrBlockId from = from_hint ? from_hint : current_block_;
    f.hdr = hdr;
    f.body = body;
    f.after = after;
    f.step = step;
    f.step_imm = step_imm;
    f.idx_ty = fn_->values[i_init].type;
    if (!from_hint) emit_br(f.hdr, ln);

    current_block_ = f.hdr;
    /* El phi del indice va SIEMPRE el primero: quien cierra el bucle ata la
     * arista de vuelta por posicion, y los que viajan van detras en el orden en
     * que se pasaron. */
    f.phi_idx = fn_->new_value(f.idx_ty);
    {
        ir::IrInstr phi{};
        phi.op = ir::IrOp::PHI;
        phi.type = f.idx_ty;
        phi.dst = f.phi_idx;
        phi.source_line = ln;
        phi.phi_args.push_back({i_init, from});
        fn_->append(f.hdr, std::move(phi));
    }
    f.phi_carried.clear();
    f.phi_carried.reserve(carried_init.size());
    for (const ir::IrValueId v : carried_init) {
        const ir::IrType ty = fn_->values[v].type;
        const ir::IrValueId p = fn_->new_value(ty);
        ir::IrInstr phi{};
        phi.op = ir::IrOp::PHI;
        phi.type = ty;
        phi.dst = p;
        phi.source_line = ln;
        phi.phi_args.push_back({v, from});
        fn_->append(f.hdr, std::move(phi));
        f.phi_carried.push_back(p);
    }

    ir::IrValueId cond;
    if (guard == VecLoopGuard::WholeStep) {
        const ir::IrValueId next =
            vec_bin(ir::IrOp::ADD, f.idx_ty, f.phi_idx, f.step, ln);
        cond = vec_bin(ir::IrOp::CMP_LE, ir::IrType::BOOL, next, bound, ln);
    } else {
        cond =
            vec_bin(ir::IrOp::CMP_LT, ir::IrType::BOOL, f.phi_idx, bound, ln);
    }
    emit_br_cond(cond, f.body, f.after, ln);

    current_block_ = f.body;
}

/**
 * @brief Cierra el cuerpo de un bucle contado y sale a su bloque de salida.
 *
 * @param f            El marco.
 * @param carried_next Con que sigue cada valor que viaja, en el mismo orden.
 * @param ln           Linea del fuente.
 */
void Lowering::vec_loop_close(VecLoopFrame &f,
                              const std::vector<ir::IrValueId> &carried_next,
                              uint32_t ln) {
    const ir::IrBlockId from = current_block_;
    const ir::IrValueId paso = (f.step != ir::IR_NO_VALUE)
                                   ? f.step
                                   : emit_const(f.idx_ty, f.step_imm, ln);
    const ir::IrValueId i_next =
        vec_bin(ir::IrOp::ADD, f.idx_ty, f.phi_idx, paso, ln);
    emit_br(f.hdr, ln);
    /* Mismo orden que al abrirlo: el indice y detras los que viajan. */
    fn_->blocks[f.hdr].instrs[0].phi_args.push_back({i_next, from});
    for (size_t k = 0; k < f.phi_carried.size() && k < carried_next.size(); ++k)
        fn_->blocks[f.hdr].instrs[k + 1].phi_args.push_back(
            {carried_next[k], from});

    current_block_ = f.after;
    block_terminated_ = false;
}

/**
 * @brief Monta la primera mitad del andamio y deja listo el cuerpo ancho.
 *
 * Los cinco bloques del vectorizador son dos bucles contados encadenados: uno
 * que avanza de W en W y otro que recoge de uno en uno lo que sobra.  Los monta
 * @ref vec_loop_open.
 *
 * @param sk       Donde queda el andamio.
 * @param prefijo  Con que nombrar los bloques, para leer el IR.
 * @param i_init   Con que valor empieza el indice.
 * @param v_N      Cuantos elementos hay.
 * @param w        Cuantos carriles caben de golpe.
 * @param ln       Linea del fuente.
 */
void Lowering::vec_begin(VecSkeleton &sk, const char *prefijo,
                         ir::IrValueId i_init, ir::IrValueId v_N, uint64_t w,
                         uint32_t ln) {
    sk.idx_ty = fn_->values[i_init].type;
    sk.entry = current_block_;
    sk.mhdr = fn_->new_block(std::string(prefijo) + "_main_hdr");
    sk.mbody = fn_->new_block(std::string(prefijo) + "_main_body");
    sk.thdr = fn_->new_block(std::string(prefijo) + "_tail_hdr");
    sk.tbody = fn_->new_block(std::string(prefijo) + "_tail_body");
    sk.exit = fn_->new_block(std::string(prefijo) + "_exit");

    sk.v_W = emit_const(sk.idx_ty, w, ln);
    /* El bucle ancho sale al de uno en uno cuando ya no caben W enteros. */
    vec_loop_open(sk.main, sk.mhdr, sk.mbody, sk.thdr, i_init, v_N, sk.v_W, w,
                  VecLoopGuard::WholeStep, {}, ln);
    sk.phi_main = sk.main.phi_idx;
}

/**
 * @brief Cierra el cuerpo ancho y deja listo el de uno en uno.
 *
 * Avanza el indice de W, vuelve a la cabecera del bucle ancho, y monta la
 * cabecera del otro: su propio indice -- que ENTRA con el que dejo el ancho --
 * y la condicion de que aun quede algo.
 *
 * @param sk  El andamio.
 * @param v_N Cuantos elementos hay.
 * @param ln  Linea del fuente.
 */
void Lowering::vec_to_tail(VecSkeleton &sk, ir::IrValueId v_N, uint32_t ln) {
    /* Cerrar el ancho deja el programa en su salida, que es la cabecera del
     * otro; alli el indice arranca donde lo dejo el ancho. */
    vec_loop_close(sk.main, {}, ln);
    /* Al de uno en uno se llega por la arista que sale de la cabecera del
     * ancho cuando ya no caben W enteros; no hay que saltar otra vez. */
    vec_loop_open(sk.tail, sk.thdr, sk.tbody, sk.exit, sk.phi_main, v_N,
                  ir::IR_NO_VALUE, 1, VecLoopGuard::Remaining, {}, ln, sk.mhdr);
    sk.phi_tail = sk.tail.phi_idx;
}

/**
 * @brief Cierra el cuerpo de uno en uno y deja el programa en la salida.
 *
 * @param sk El andamio.
 * @param ln Linea del fuente.
 */
void Lowering::vec_end(VecSkeleton &sk, uint32_t ln) {
    vec_loop_close(sk.tail, {}, ln);
}

/**
 * @brief Emite una operacion binaria en el bloque actual.
 *
 * Los ayudantes de constantes y conversiones tambien emiten en el bloque
 * actual, y por eso aqui se lleva el bloque a mano en vez de emitir a uno
 * cualquiera.
 *
 * @param op El operador.
 * @param ty De que tipo es el resultado.
 * @param a  Primer operando.
 * @param b  Segundo operando.
 * @param ln Linea del fuente.
 * @return El valor resultante.
 */
ir::IrValueId Lowering::vec_bin(ir::IrOp op, ir::IrType ty, ir::IrValueId a,
                                ir::IrValueId b, uint32_t ln) {
    const ir::IrValueId d = fn_->new_value(ty);
    ir::IrInstr in{};
    in.op = op;
    in.type = ty;
    in.dst = d;
    in.operands = {a, b};
    in.source_line = ln;
    fn_->append(current_block_, std::move(in));
    return d;
}

/**
 * @brief Que tipo de elemento es, y cuanto ocupa, para vectorizar.
 *
 * Ver la declaracion: estaba escrita tres veces y una de las copias se habia
 * quedado sin `f32`.
 *
 * @param k Tipo del elemento.
 * @param out_ty Tipo equivalente del IR.
 * @param out_esz Bytes que ocupa.
 * @param out_fp Si es de coma flotante.
 * @return false si no es un tipo que se pueda vectorizar.
 */
bool Lowering::vec_elem_info(PrimitiveKind k, ir::IrType *out_ty,
                             uint64_t *out_esz, bool *out_fp) noexcept {
    switch (k) {
    case PrimitiveKind::F64: *out_ty = ir::IrType::F64; break;
    case PrimitiveKind::F32: *out_ty = ir::IrType::F32; break;
    case PrimitiveKind::I64: *out_ty = ir::IrType::I64; break;
    case PrimitiveKind::U64: *out_ty = ir::IrType::U64; break;
    case PrimitiveKind::I32: *out_ty = ir::IrType::I32; break;
    case PrimitiveKind::U32: *out_ty = ir::IrType::U32; break;
    case PrimitiveKind::I16: *out_ty = ir::IrType::I16; break;
    case PrimitiveKind::U16: *out_ty = ir::IrType::U16; break;
    case PrimitiveKind::I8: *out_ty = ir::IrType::I8; break;
    case PrimitiveKind::U8: *out_ty = ir::IrType::U8; break;
    default: return false;
    }
    *out_fp = (k == PrimitiveKind::F64 || k == PrimitiveKind::F32);
    switch (k) {
    case PrimitiveKind::I8:
    case PrimitiveKind::U8: *out_esz = 1; break;
    case PrimitiveKind::I16:
    case PrimitiveKind::U16: *out_esz = 2; break;
    case PrimitiveKind::I32:
    case PrimitiveKind::U32:
    case PrimitiveKind::F32: *out_esz = 4; break;
    default: *out_esz = 8; break;
    }
    return true;
}

/**
 * @brief Es @p e un `array[i]` que se puede ensanchar?
 *
 * Ver la declaracion: estaba escrita tres veces, una por idioma.
 *
 * @param e Expresion candidata.
 * @param idx_name Nombre del indice del bucle.
 * @param expected Tipo de las hojas ya vistas, o @c COUNT si es la primera.
 * @param out_base Sale con el array.
 * @return false si no es esa forma.
 */
bool Lowering::vec_index_leaf(ast::Expr *e, const std::string &idx_name,
                              PrimitiveKind *expected,
                              ast::IdentExpr **out_base) {
    using namespace ast;
    if (!e || e->kind != NodeKind::IndexExpr) return false;
    auto *ix = static_cast<IndexExpr *>(e);
    /* Un indice con operador redefinido o un rango no son un acceso plano: hay
     * codigo del usuario por medio y no se puede leer de W en W. */
    if (!ix->overload_method.empty() || !ix->index_set_method.empty() ||
        ix->is_range)
        return false;
    if (!ix->base || ix->base->kind != NodeKind::IdentExpr) return false;
    if (!ix->index || ix->index->kind != NodeKind::IdentExpr) return false;
    if (static_cast<IdentExpr *>(ix->index.get())->name != idx_name)
        return false;
    auto *base = static_cast<IdentExpr *>(ix->base.get());
    const Type &t = base->result_type;
    const bool ptr_like =
        (t.kind == PrimitiveKind::PTR || t.kind == PrimitiveKind::ARRAY) &&
        static_cast<bool>(t.pointee);
    if (!ptr_like || t.is_virtual) return false; // solo memoria del proceso
    ir::IrType ety;
    uint64_t esz;
    bool fp;
    if (!vec_elem_info(t.pointee->kind, &ety, &esz, &fp)) return false;
    /* Todas las hojas del mismo bucle, del mismo tipo: ninguno de los idiomas
     * convierte, asi que mezclar anchos daria otro numero. */
    if (*expected == PrimitiveKind::COUNT)
        *expected = t.pointee->kind;
    else if (*expected != t.pointee->kind)
        return false;
    *out_base = base;
    return true;
}

/**
 * @brief Cuantos BYTES avanza de golpe un bucle vectorizado.
 *
 * Estaba escrito en cada idioma, y cuatro de las cinco copias decian lo mismo.
 * La quinta no -- la reduccion corre a 128 bits porque su acumulador vive en un
 * registro y no se parte --, y esa diferencia, siendo deliberada, era
 * indistinguible de un despiste: se leia como una copia que se habia quedado
 * atras.  Aqui es un argumento, que es lo que era.
 *
 * @param auto_width Ancho a usar en el automatico nativo.
 * @return Bytes por vuelta del bucle ancho.
 */
uint64_t Lowering::vec_chunk_width(uint64_t auto_width) const noexcept {
    if (native_poo_)
        return aot_auto_vec_ ? auto_width
                             : static_cast<uint64_t>(aot_vec_width_);
    return jit::vec_isa_width(jit::vec_chunk_isa());
}

/**
 * @brief Direccion de un elemento: @p base desplazada @p off bytes.
 *
 * La aritmetica de punteros HEREDA la naturaleza de la base, y eso no es un
 * detalle de estilo: un array de `malloc` vive en memoria del proceso y uno
 * local vive en la pila de la maquina virtual.  Marcarlo host a ciegas hacia
 * que el acceso saliera con la instruccion equivocada -- leer memoria de la
 * maquina como si fuera del proceso -- y el programa moria al recorrer un array
 * local vectorizado.
 *
 * Esto estaba escrito cinco veces, una por idioma, con este mismo comentario al
 * lado.  Basta con que una de las copias se quede sin la linea que hereda la
 * naturaleza para que vuelva aquel fallo, y en un sitio distinto.
 *
 * @param base Puntero de partida.
 * @param off Desplazamiento en BYTES.
 * @param ln Linea del fuente.
 * @return El puntero al elemento.
 */
ir::IrValueId Lowering::vec_elem_ptr(ir::IrValueId base, ir::IrValueId off,
                                     uint32_t ln) {
    const ir::IrValueId d = fn_->new_value(ir::IrType::PTR);
    fn_->values[d].is_host_ptr =
        (base < fn_->values.size()) && fn_->values[base].is_host_ptr;
    ir::IrInstr in{};
    in.op = ir::IrOp::ADD;
    in.type = ir::IrType::PTR;
    in.dst = d;
    in.operands = {base, off};
    in.source_line = ln;
    fn_->append(current_block_, std::move(in));
    return d;
}

/**
 * @brief Lee un elemento de la direccion @p at.
 * @param at Direccion.
 * @param elem_ty Tipo del elemento.
 * @param ln Linea del fuente.
 * @return El valor leido.
 */
ir::IrValueId Lowering::vec_load_elem(ir::IrValueId at, ir::IrType elem_ty,
                                      uint32_t ln) {
    const ir::IrValueId v = fn_->new_value(elem_ty);
    ir::IrInstr ld{};
    ld.op = ir::IrOp::LOAD;
    ld.type = elem_ty;
    ld.dst = v;
    ld.operands = {at};
    ld.source_line = ln;
    fn_->append(current_block_, std::move(ld));
    return v;
}

bool Lowering::try_vectorize_elementwise_for(ast::Stmt *s) {
    using namespace ast;
    static const bool MC_DBG = util::flag_on(util::FlagId::McIdiomDebug);

    // --- estructura: for/while  c[i] = a[i] OP b[i];  i++ ---
    VecLoop vl;
    if (!mc_extract_vec_loop(s, vl)) return false;
    if (vl.body_exprs.size() != 1) return false; // un solo stmt vectorizable
    const std::string &idx_name = vl.idx_name;
    auto *bexpr = vl.body_exprs[0];
    if (!bexpr || bexpr->kind != NodeKind::AssignExpr) return false;
    auto *asg = static_cast<AssignExpr *>(bexpr);
    // target = c[idx]
    if (!asg->target || asg->target->kind != NodeKind::IndexExpr) return false;
    auto *c_ix = static_cast<IndexExpr *>(asg->target.get());
    int subop = -1;
    ast::IndexExpr *a_ix = nullptr, *b_ix = nullptr;
    if (asg->op == AssignOp::Assign) {
        // c[idx] = a[idx] OP b[idx]
        if (!asg->value || asg->value->kind != NodeKind::BinaryExpr)
            return false;
        auto *rhs = static_cast<BinaryExpr *>(asg->value.get());
        switch (rhs->op) {
        case BinOp::Add: subop = 0; break;
        case BinOp::Sub: subop = 1; break;
        case BinOp::Mul: subop = 2; break;
        case BinOp::Div: subop = 3; break;
        default: return false;
        }
        if (!rhs->lhs || rhs->lhs->kind != NodeKind::IndexExpr) return false;
        if (!rhs->rhs || rhs->rhs->kind != NodeKind::IndexExpr) return false;
        a_ix = static_cast<IndexExpr *>(rhs->lhs.get());
        b_ix = static_cast<IndexExpr *>(rhs->rhs.get());
    } else {
        // compound: c[idx] OP= a[idx]  ==  c[idx] = c[idx] OP a[idx]
        switch (asg->op) {
        case AssignOp::AddAssign: subop = 0; break;
        case AssignOp::SubAssign: subop = 1; break;
        case AssignOp::MulAssign: subop = 2; break;
        case AssignOp::DivAssign: subop = 3; break;
        default: return false;
        }
        if (!asg->value || asg->value->kind != NodeKind::IndexExpr)
            return false;
        a_ix = c_ix; // a = c (lhs implicito)
        b_ix = static_cast<IndexExpr *>(asg->value.get()); // b = el operando
    }

    // Tipos de elemento vectorizables (HOST): f64 (todas las ops) e enteros
    // i64/i32 (solo add/sub -- SSE2 no tiene mul/div packed de enteros).  El
    // valor de salida es el PrimitiveKind comun a las 3 bases.
    ast::IdentExpr *c_base = nullptr, *a_base = nullptr, *b_base = nullptr;
    /* Las tres hojas, con la regla de que sean del mismo tipo aplicada por el
     * propio comprobador segun las va viendo. */
    PrimitiveKind ck = PrimitiveKind::COUNT;
    if (!vec_index_leaf(c_ix, idx_name, &ck, &c_base)) return false;
    if (!vec_index_leaf(a_ix, idx_name, &ck, &a_base)) return false;
    if (!vec_index_leaf(b_ix, idx_name, &ck, &b_base)) return false;
    ir::IrType elem_ty;
    uint64_t esz;
    bool elem_fp;
    vec_elem_info(ck, &elem_ty, &esz, &elem_fp);
    // Enteros: nunca div packed (subop 3 bail).  mul (subop 2) solo donde hay
    // packed mul: i16/u16 (PMULLW) e i32/u32 (PMULLD); i8/u8 e i64/u64 sin mul.
    if (!elem_fp) {
        if (subop == 3) return false; // div entera -> escalar
        if (subop == 2) {             // mul entera
            const bool has_pmul = (esz == 2 || esz == 4); // word/dword
            if (!has_pmul) return false;
        }
    }

    if (MC_DBG)
        std::fprintf(stderr, "[mc-idiom] MATCH vec_for idx=%s subop=%d\n",
                     idx_name.c_str(), subop);

    // ======== Emitir el loop vectorizado + cola escalar. ========
    // El chunk (16/32/64 bytes) lo elige la ISA: SSE2 W=2, AVX2 W=4, AVX512 W=8
    // (f64).  El IR es portable: el JIT descompone el chunk al ancho del host.
    const uint32_t ln = s->loc.line;
    // AOT (native_poo): el chunk lo fija el TARGET (--float-isa,
    // aot_vec_width_)
    // -> cross-compile correcto + la reduccion (acc de 1 reg, no splittea) cabe
    // (chunk==host_w del codegen).  Fuera de AOT: host (vec_chunk_isa) para que
    // el .velb sea portable (el JIT descompone el chunk al ancho del host).
    const uint64_t width = vec_chunk_width(64u);
    const uint64_t W = width / esz; // lanes segun ancho/tipo

    // Bajar el VALOR inicial + las bases directamente (NO lower_stmt(init), que
    // declararia `i` address-taken -> ALLOCA).  NO re-bajamos el AST del cuerpo
    // para la cola (la var `i` es address-taken en el AST -> el load del index
    // leeria de un slot inexistente); emitimos la op escalar de la cola a mano
    // con phi_it + las bases.  Sin push_scope: solo leemos vars externas.
    // for: baja el init fresco.  while: el indice ya esta declarado -> usa su
    // binding SSA actual (lookup), igual que el memcpy-idiom while.
    const ir::IrValueId i_init =
        vl.for_init ? lower_expr(vl.for_init) : lookup(idx_name);
    const ir::IrValueId v_a = lower_expr(a_base);
    const ir::IrValueId v_b = lower_expr(b_base);
    const ir::IrValueId v_c = lower_expr(c_base);
    const ir::IrValueId v_N = lower_expr(vl.limit);
    if (i_init == ir::IR_NO_VALUE || v_a == ir::IR_NO_VALUE ||
        v_b == ir::IR_NO_VALUE || v_c == ir::IR_NO_VALUE ||
        v_N == ir::IR_NO_VALUE)
        return false;
    /* El andamio -- los cinco bloques, los dos indices y sus condiciones -- lo
     * monta `vec_begin`; aqui solo queda lo que este idioma hace dentro.  Al
     * volver se emite en el cuerpo ancho. */
    VecSkeleton sk;
    vec_begin(sk, "vec", i_init, v_N, (uint64_t)W, ln);
    const ir::IrType idx_ty = sk.idx_ty;
    const ir::IrValueId v_esz = emit_const(ir::IrType::I64, esz, ln);
    const ir::IrValueId phi_im = sk.phi_main;
    auto bin = [&](ir::IrOp op, ir::IrType ty, ir::IrValueId a,
                   ir::IrValueId b) { return vec_bin(op, ty, a, b, ln); };

    auto ptr_at = [&](ir::IrValueId base, ir::IrValueId off) {
        return vec_elem_ptr(base, off, ln);
    };
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_im, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off =
            bin(ir::IrOp::MUL, ir::IrType::I64, i64, v_esz);
        const ir::IrValueId c_at = ptr_at(v_c, off);
        const ir::IrValueId a_at = ptr_at(v_a, off);
        const ir::IrValueId b_at = ptr_at(v_b, off);
        ir::IrInstr vb{};
        vb.op = ir::IrOp::VEC_BINOP;
        vb.type = elem_ty;
        vb.dst = ir::IR_NO_VALUE;
        vb.operands = {c_at, a_at, b_at};
        vb.imm = ((uint64_t)subop << 8) | width;
        vb.source_line = ln;
        fn_->append(current_block_, std::move(vb));
    }
    /* Cierra el cuerpo ancho y abre el que recoge los que sobran. */
    vec_to_tail(sk, v_N, ln);
    const ir::IrValueId phi_it = sk.phi_tail;

    // --- cuerpo de uno en uno: la misma operacion, escalar ---
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_it, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off = bin(ir::IrOp::MUL, ir::IrType::I64, i64,
                                      emit_const(ir::IrType::I64, esz, ln));
        auto load_el = [&](ir::IrValueId base) {
            return vec_load_elem(ptr_at(base, off), elem_ty, ln);
        };
        const ir::IrValueId v_ai = load_el(v_a);
        const ir::IrValueId v_bi = load_el(v_b);
        ir::IrOp eop;
        if (elem_fp)
            eop = (subop == 0)   ? ir::IrOp::FADD
                  : (subop == 1) ? ir::IrOp::FSUB
                  : (subop == 2) ? ir::IrOp::FMUL
                                 : ir::IrOp::FDIV;
        else // enteros: add/sub/mul (div ya bailo arriba)
            eop = (subop == 0)   ? ir::IrOp::ADD
                  : (subop == 1) ? ir::IrOp::SUB
                                 : ir::IrOp::MUL;
        const ir::IrValueId v_res = bin(eop, elem_ty, v_ai, v_bi);
        const ir::IrValueId c_at = ptr_at(v_c, off);
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = elem_ty;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {v_res, c_at};
        st.source_line = ln;
        fn_->append(current_block_, std::move(st));
    }
    vec_end(sk, ln);
    return true;
}

// ===========================================================================
// Patron COMPOUND (cadena lineal multi-op):
//   for/while  c[i] = a[i] OP0 r0 OP1 r1 ... ;   i++
// donde la expresion es left-leaning `((a OP0 r0) OP1 r1) ...` (la precedencia
// natural de p.ej. `a[i] * k + b[i]`), la hoja inicial es array[i] HOST f64 y
// cada operando derecho r_k es array[i] (mismo tipo) o un escalar INVARIANTE
// f64.  Como minimo 2 ops (1-op lo cubren elementwise/scalar).  v1: f64 y <=1
// escalar (izado a XMM13 a ancho completo).
//
// Emision: el loop principal usa `c` como ACUMULADOR -> una cadena de VEC ops
// memoria-a-memoria por chunk (c = a OP0 r0 ; c = c OP1 r1 ; ...), cada op a
// ancho W (SSE2/AVX2/AVX512 segun --float-isa) + cola escalar identica.  Cubre
// el idioma axpy/FMA que los matchers de 1-op rechazan.
// ===========================================================================
bool Lowering::try_vectorize_compound_for(ast::Stmt *s) {
    using namespace ast;
    static const bool MC_DBG = util::flag_on(util::FlagId::McIdiomDebug);

    VecLoop vl;
    if (!mc_extract_vec_loop(s, vl)) return false;
    if (vl.body_exprs.size() != 1) return false;
    const std::string &idx_name = vl.idx_name;
    auto *bexpr = vl.body_exprs[0];
    if (!bexpr || bexpr->kind != NodeKind::AssignExpr) return false;
    auto *asg = static_cast<AssignExpr *>(bexpr);
    if (asg->op != AssignOp::Assign) return false; // solo `c[i] = <cadena>`
    if (!asg->target || asg->target->kind != NodeKind::IndexExpr) return false;
    if (!asg->value || asg->value->kind != NodeKind::BinaryExpr) return false;

    auto subop_of = [](BinOp op, int *out) -> bool {
        switch (op) {
        case BinOp::Add: *out = 0; return true;
        case BinOp::Sub: *out = 1; return true;
        case BinOp::Mul: *out = 2; return true;
        case BinOp::Div: *out = 3; return true;
        default: return false;
        }
    };
    // Array f32/f64 HOST indexado por idx.  El tipo de elemento se captura en
    // @p c_kind (todas las hojas array deben ser del MISMO tipo que el
    // destino).
    PrimitiveKind c_kind =
        PrimitiveKind::COUNT; // se fija al clasificar el destino
    /* Sin restringir: para saber si algo ES un acceso, no de que tipo.  El tipo
     * que se descarta va a una variable local a proposito. */
    auto as_arr_any = [&](ast::Expr *e, IdentExpr **base) -> bool {
        PrimitiveKind libre = PrimitiveKind::COUNT;
        return vec_index_leaf(e, idx_name, &libre, base);
    };
    /* Restringido al tipo del destino, que para entonces ya esta fijado. */
    auto as_arr_c = [&](ast::Expr *e, IdentExpr **base) -> bool {
        return vec_index_leaf(e, idx_name, &c_kind, base);
    };
    // Hoja ESCALAR: invariante del loop (ni array[idx] ni referencia a idx).
    auto is_scalar_leaf = [&](ast::Expr *e) -> bool {
        if (!e) return false;
        IdentExpr *tmp = nullptr;
        if (as_arr_any(e, &tmp)) return false; // array -> no escalar
        if (mc_expr_refs_ident(e, idx_name)) return false; // depende de idx
        return true;
    };

    IdentExpr *c_base = nullptr;
    if (!as_arr_any(asg->target.get(), &c_base)) return false;
    c_kind = c_base->result_type.pointee->kind; // F32 o F64 (fija el tipo)

    struct Step {
        int subop;
        bool is_scalar;
        IdentExpr *arr;
        ast::Expr *scal;
        bool is_scaled_arr = false; // c OP (arr[i]*scal) -> VEC_FMA_S
    };
    // Hoja "array escalado": arr[i]*escalar o escalar*arr[i] (escalar
    // invariante).  Es el segundo termino de a[i]*k1 + b[i]*k2.
    auto as_scaled_arr = [&](ast::Expr *e, IdentExpr **base,
                             ast::Expr **scal) -> bool {
        if (!e || e->kind != NodeKind::BinaryExpr) return false;
        auto *be = static_cast<BinaryExpr *>(e);
        if (be->op != BinOp::Mul) return false;
        IdentExpr *b = nullptr;
        if (as_arr_c(be->lhs.get(), &b) && is_scalar_leaf(be->rhs.get())) {
            *base = b;
            *scal = be->rhs.get();
            return true;
        }
        if (as_arr_c(be->rhs.get(), &b) && is_scalar_leaf(be->lhs.get())) {
            *base = b;
            *scal = be->lhs.get();
            return true;
        }
        return false;
    };
    // Aplanado RECURSIVO con normalizacion de nodos CONMUTATIVOS: para Add/Mul
    // se puede intercambiar operandos (a OP b == b OP a, bit-exacto en IEEE)
    // para poner la sub-cadena array a la izquierda.  Asi vectorizan tambien
    // `b[i] + a[i]*k` (right-leaning) y `k*a[i] + b[i]` (escalar primero), no
    // solo el left-leaning `a[i]*k + b[i]`.  NO re-asocia (eso si cambiaria el
    // redondeo): solo swap de operandos de un mismo nodo.  Atomico
    // (save/restore de S) para reintentar el swap sin dejar estado sucio.
    IdentExpr *start_base = nullptr;
    std::vector<Step> S;
    std::function<bool(ast::Expr *)> flatten = [&](ast::Expr *e) -> bool {
        IdentExpr *ab = nullptr;
        if (as_arr_c(e, &ab)) {
            start_base = ab;
            return true;
        } // hoja inicial
        if (!e || e->kind != NodeKind::BinaryExpr) return false;
        auto *be = static_cast<BinaryExpr *>(e);
        int so;
        if (!subop_of(be->op, &so)) return false;
        const bool commutative = (be->op == BinOp::Add || be->op == BinOp::Mul);
        // Intenta: prefijo (sub-cadena) a la izquierda, hoja a la derecha.
        auto try_chain = [&](ast::Expr *prefix, ast::Expr *leaf) -> bool {
            IdentExpr *lb = nullptr;
            const bool arr = as_arr_c(leaf, &lb);
            const bool scal = !arr && is_scalar_leaf(leaf);
            IdentExpr *sab = nullptr;
            ast::Expr *sscal = nullptr;
            const bool scaled =
                !arr && !scal && as_scaled_arr(leaf, &sab, &sscal);
            if (!arr && !scal && !scaled) return false; // hoja no vectorizable
            const size_t save = S.size();
            IdentExpr *save_start = start_base;
            if (!flatten(prefix)) { // prefijo no es cadena -> restaurar
                S.resize(save);
                start_base = save_start;
                return false;
            }
            if (scaled)
                S.push_back({so, false, sab, sscal, true}); // arr[i]*scal
            else
                S.push_back({so, scal, arr ? lb : nullptr,
                             scal ? leaf : nullptr, false});
            return true;
        };
        if (try_chain(be->lhs.get(), be->rhs.get())) return true;
        if (commutative && try_chain(be->rhs.get(), be->lhs.get())) return true;
        return false;
    };
    if (!flatten(asg->value.get())) return false;
    if (S.size() < 2) return false; // 1-op -> matchers mas simples
    if (!start_base) return false;
    int n_scalar = 0;
    for (auto &st : S)
        if (st.is_scalar && ++n_scalar > 4)
            return false; // <=4 escalares (XMM10-13)
    // f32 con escalar YA soportado: VEC_BCAST/VEC_BINOP_S difunden el f32 via
    // SHUFPS(0) (SSE2 128b) o VBROADCASTSS (AVX/AVX512), y operan packed-single
    // (ADDPS/MULPS/...).  El escalar se castea a elem_ty (F32) mas abajo.
    const bool is_f32 = (c_kind == PrimitiveKind::F32);
    ir::IrType elem_ty;
    uint64_t esz;
    bool elem_fp;
    if (!vec_elem_info(c_kind, &elem_ty, &esz, &elem_fp)) return false;
    /* Con enteros, la cadena entera tiene que estar hecha de operaciones que
     * existan empaquetadas para ese ancho.  No hay division entera en ninguna
     * de las dos maquinas, y el producto solo de 16 y de 32 bits.  Basta con
     * que UNA de la cadena no exista para que no se pueda: el resultado
     * intermedio ya no seria el que toca. */
    if (!elem_fp)
        for (const auto &st : S) {
            if (st.subop == 3) return false; // division entera
            if (st.subop == 2 && esz != 2 && esz != 4)
                return false; // producto solo de 16 y 32 bits
        }

    // FMA fusion del patron `c[i] = a[i]*b[i] + d[i]` (2 pasos array Mul+Add,
    // sin escalares) -> UN VFMADD231 (4 instr vs 8 de mul+add) + 1 redondeo
    // (estilo -ffast-math de C).  GATE: el VFMADD requiere AVX.  En AOT solo si
    // el target es fixed avx/avx512 (NO sse2, NO auto cuya variante sse2
    // romperia).  En el .velb (interp/jit) si: el interp emula fused (oraculo),
    // el jit usa FMA en host AVX o cae a interp -> resultado determinista
    // (siempre fused).
    bool can_fma;
    if (native_poo_)
        can_fma = (!aot_auto_vec_ && aot_vec_width_ >= 32);
    else
        can_fma = true;
    /* Y solo en coma flotante.  La multiplicacion-suma fusionada existe porque
     * ahorra UN REDONDEO, que es un concepto de la coma flotante: en enteros no
     * hay tal instruccion.  Al abrir las cadenas a los enteros, un
     * `a[i]*b[i] + a[i]` entraba por aqui y salia como una operacion de
     * flotantes sobre bits de entero -- daba otro numero, y el mismo en los
     * tres modos, que es lo que lo hace dificil de ver. */
    if (!elem_fp) can_fma = false;
    // FMA element-wise: c = a*b + d  (subop Add)  o  c = a*b - d  (subop Sub).
    // Ambos array-only (2 pasos, sin escalares); Sub -> VFMSUB231.
    const bool is_fma = can_fma && S.size() == 2 && !S[0].is_scalar &&
                        S[0].subop == 2 /*Mul*/ && !S[1].is_scalar &&
                        (S[1].subop == 0 /*Add*/ || S[1].subop == 1 /*Sub*/);
    const bool fma_sub = is_fma && S[1].subop == 1;

    // Pasos "array escalado" (c OP a[i]*k, p.ej. el 2o termino de a*k1 + b*k2):
    // se bajan a VEC_FMA_S (c += a*k), que requiere VFMADD (AVX).  Solo subop
    // Add/Sub (el Sub se maneja negando el escalar).  Mul/Div de un array
    // escalado no encaja -> bail.
    bool has_scaled = false;
    for (const auto &st : S) {
        if (st.is_scaled_arr) {
            has_scaled = true;
            if (st.subop != 0 && st.subop != 1) return false;
        }
    }
    if (has_scaled && !can_fma) return false; // VFMADD requiere AVX

    if (MC_DBG)
        std::fprintf(stderr,
                     "[mc-idiom] MATCH compound idx=%s steps=%zu scalars=%d\n",
                     idx_name.c_str(), S.size(), n_scalar);

    // ===== Emision (CFG espejo de elementwise) =====
    const uint32_t ln = s->loc.line;
    const uint64_t width = vec_chunk_width(64u);
    const uint64_t W = width / esz;

    const ir::IrValueId i_init =
        vl.for_init ? lower_expr(vl.for_init) : lookup(idx_name);
    const ir::IrValueId v_c = lower_expr(c_base);
    const ir::IrValueId v_start = lower_expr(start_base);
    const ir::IrValueId v_N = lower_expr(vl.limit);
    if (i_init == ir::IR_NO_VALUE || v_c == ir::IR_NO_VALUE ||
        v_start == ir::IR_NO_VALUE || v_N == ir::IR_NO_VALUE)
        return false;
    // Bajar las bases array + cada escalar (a F64), asignando a cada paso
    // escalar un INDICE de registro de broadcast distinto (0..3 -> XMM13-idx)
    // para que multiples escalares NO colisionen en XMM13 y todos corran a
    // ancho COMPLETO (sin penalizacion de transicion AVX<->SSE del no-hoisted).
    std::vector<ir::IrValueId> step_base(S.size(), ir::IR_NO_VALUE);
    std::vector<ir::IrValueId> step_scalar(S.size(), ir::IR_NO_VALUE);
    std::vector<int> step_sidx(S.size(), -1);
    int next_sidx = 0;
    for (size_t k = 0; k < S.size(); ++k) {
        if (S[k].is_scaled_arr) {
            // array base + escalar difundido; c += arr*k (VEC_FMA_S).  Sub ->
            // c - arr*k = c + arr*(-k): negamos el escalar aqui.
            const ir::IrValueId vb = lower_expr(S[k].arr);
            if (vb == ir::IR_NO_VALUE) return false;
            step_base[k] = vb;
            ir::IrValueId raw = lower_expr(S[k].scal);
            if (raw == ir::IR_NO_VALUE) return false;
            raw = cast_if_needed(raw, fn_->values[raw].type, elem_ty, ln);
            if (S[k].subop == 1) { // Sub -> negar el escalar
                const ir::IrValueId neg = fn_->new_value(elem_ty);
                ir::IrInstr fn{};
                fn.op = ir::IrOp::FNEG;
                fn.type = elem_ty;
                fn.dst = neg;
                fn.operands = {raw};
                fn.source_line = ln;
                fn_->append(current_block_, std::move(fn));
                raw = neg;
            }
            step_scalar[k] = raw;
            step_sidx[k] = next_sidx++;
        } else if (S[k].is_scalar) {
            const ir::IrValueId raw = lower_expr(S[k].scal);
            if (raw == ir::IR_NO_VALUE) return false;
            // Escalar al tipo del elemento (F32 o F64) para que el broadcast y
            // la op packed sean del ancho de lane correcto.
            step_scalar[k] =
                cast_if_needed(raw, fn_->values[raw].type, elem_ty, ln);
            step_sidx[k] = next_sidx++;
        } else {
            const ir::IrValueId vb = lower_expr(S[k].arr);
            if (vb == ir::IR_NO_VALUE) return false;
            step_base[k] = vb;
        }
    }
    // Los broadcasts (escalares + escalados) viven en XMM10-13 (4 regs, sidx
    // 0-3).  Mas de 4 colisionaria con regs allocatables -> bail.
    if (next_sidx > 4) return false;
    const ir::IrType idx_ty = fn_->values[i_init].type;

    auto bin = [&](ir::IrOp op, ir::IrType ty, ir::IrValueId a,
                   ir::IrValueId b) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ty);
        ir::IrInstr in{};
        in.op = op;
        in.type = ty;
        in.dst = d;
        in.operands = {a, b};
        in.source_line = ln;
        fn_->append(current_block_, std::move(in));
        return d;
    };

    /* Los escalares de la cadena se reparten a todos los carriles UNA vez,
     * antes de entrar al bucle: dentro no cambian.  Va antes de montar el
     * andamio porque tiene que quedar en el bloque de entrada. */
    const ir::IrValueId v_esz = emit_const(ir::IrType::I64, esz, ln);
    for (size_t k = 0; k < S.size(); ++k) {
        if (!S[k].is_scalar && !S[k].is_scaled_arr) continue;
        ir::IrInstr bc{};
        bc.op = ir::IrOp::VEC_BCAST;
        bc.type = elem_ty;
        bc.dst = ir::IR_NO_VALUE;
        bc.operands = {step_scalar[k]};
        // imm: bits 0-7 = ancho ; bits 8-10 = indice de reg (XMM13-idx).
        bc.imm = width | ((uint64_t)(step_sidx[k] & 0x7) << 8);
        bc.source_line = ln;
        fn_->append(current_block_, std::move(bc));
    }
    /* El andamio -- los cinco bloques, los dos indices y sus condiciones -- lo
     * monta `vec_begin`; aqui solo queda lo que este idioma hace dentro.  Al
     * volver se emite en el cuerpo ancho. */
    VecSkeleton sk;
    vec_begin(sk, "vcp", i_init, v_N, (uint64_t)W, ln);
    const ir::IrValueId phi_im = sk.phi_main;

    // --- cuerpo ancho: la cadena de operaciones, de W en W ---
    auto ptr_at = [&](ir::IrValueId base, ir::IrValueId off) {
        return vec_elem_ptr(base, off, ln);
    };
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_im, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off =
            bin(ir::IrOp::MUL, ir::IrType::I64, i64, v_esz);
        const ir::IrValueId c_at = ptr_at(v_c, off);
        const ir::IrValueId start_at = ptr_at(v_start, off);
        if (is_fma) {
            // c = a*b +/- d  ->  VEC_FMA (4 ops: {c, d, a, b}, 1 redondeo).
            // bit 8 del imm = SUB (VFMSUB231: a*b - d).
            const ir::IrValueId b_at = ptr_at(step_base[0], off); // S[0]=Mul b
            const ir::IrValueId d_at =
                ptr_at(step_base[1], off); // S[1]=Add/Sub
            ir::IrInstr vf{};
            vf.op = ir::IrOp::VEC_FMA;
            vf.type = elem_ty;
            vf.dst = ir::IR_NO_VALUE;
            vf.operands = {c_at, d_at, start_at, b_at};
            vf.imm = width | (fma_sub ? (1ull << 8) : 0ull);
            vf.source_line = ln;
            fn_->append(current_block_, std::move(vf));
        } else
            for (size_t k = 0; k < S.size(); ++k) {
                const ir::IrValueId src0 =
                    (k == 0) ? start_at : c_at; // acumulador
                // Cadena register-resident: el acumulador c del chunk vive en
                // un XMM (fp0) ENTRE pasos, en vez de round-trip a memoria. bit
                // 20 = SRC0_IN_REG (c ya en reg; salta la carga); bit 21 =
                // DST_IN_REG (deja c en reg; salta el store).  El PRIMER paso
                // carga start de memoria; el ULTIMO escribe c a memoria.  El
                // interp los IGNORA (memoria siempre = mismo valor); solo
                // JIT/AOT los honran cuando n_pieces==1.  Reduce ~2x el trafico
                // de memoria del element-wise.
                const uint64_t rr = ((k > 0) ? (1ull << 20) : 0ull) |
                                    ((k + 1 < S.size()) ? (1ull << 21) : 0ull);
                if (S[k].is_scaled_arr) {
                    // c += arr[i]*escalar (VEC_FMA_S lee/escribe c_at; escalar
                    // hoisted, ya negado si Sub).  Siempre k>=1 -> src0 ==
                    // c_at.
                    const ir::IrValueId leaf_at = ptr_at(step_base[k], off);
                    ir::IrInstr vf{};
                    vf.op = ir::IrOp::VEC_FMA_S;
                    vf.type = elem_ty;
                    vf.dst = ir::IR_NO_VALUE;
                    vf.operands = {c_at, leaf_at, step_scalar[k]};
                    vf.imm = width | (1ull << 16) |
                             ((uint64_t)(step_sidx[k] & 0x7) << 17) | rr;
                    vf.source_line = ln;
                    fn_->append(current_block_, std::move(vf));
                } else if (S[k].is_scalar) {
                    ir::IrInstr vb{};
                    vb.op = ir::IrOp::VEC_BINOP_S;
                    vb.type = elem_ty;
                    vb.dst = ir::IR_NO_VALUE;
                    vb.operands = {c_at, src0, step_scalar[k]};
                    // imm: subop(8-15) | ancho(0-7) | hoisted(16) |
                    // sidx(17-19).
                    vb.imm = ((uint64_t)S[k].subop << 8) | width |
                             (1ull << 16) |
                             ((uint64_t)(step_sidx[k] & 0x7) << 17) | rr;
                    vb.source_line = ln;
                    fn_->append(current_block_, std::move(vb));
                } else {
                    const ir::IrValueId leaf_at = ptr_at(step_base[k], off);
                    ir::IrInstr vb{};
                    vb.op = ir::IrOp::VEC_BINOP;
                    vb.type = elem_ty;
                    vb.dst = ir::IR_NO_VALUE;
                    vb.operands = {c_at, src0, leaf_at};
                    vb.imm = ((uint64_t)S[k].subop << 8) | width | rr;
                    vb.source_line = ln;
                    fn_->append(current_block_, std::move(vb));
                }
            }
    }
    /* Cierra el cuerpo ancho y abre el que recoge los que sobran. */
    vec_to_tail(sk, v_N, ln);
    const ir::IrValueId phi_it = sk.phi_tail;

    // --- cuerpo de uno en uno: la misma cadena, escalar ---
    block_terminated_ = false;
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_it, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off = bin(ir::IrOp::MUL, ir::IrType::I64, i64,
                                      emit_const(ir::IrType::I64, esz, ln));
        auto load_el = [&](ir::IrValueId base) {
            return vec_load_elem(ptr_at(base, off), elem_ty, ln);
        };
        /* La operacion depende del TIPO, no solo del simbolo.  Esta cola se
         * escribio cuando la cadena solo admitia flotantes, asi que emitia
         * siempre las de coma flotante; al abrirla a enteros, un `a[i]*b[i]`
         * salia como un producto de flotantes sobre bits de entero -- daba otro
         * numero, y el mismo en los tres modos, que es lo que lo hace dificil
         * de ver. */
        auto fop_of = [&](int so) -> ir::IrOp {
            if (elem_fp)
                return (so == 0)   ? ir::IrOp::FADD
                       : (so == 1) ? ir::IrOp::FSUB
                       : (so == 2) ? ir::IrOp::FMUL
                                   : ir::IrOp::FDIV;
            return (so == 0)   ? ir::IrOp::ADD
                   : (so == 1) ? ir::IrOp::SUB
                               : ir::IrOp::MUL; // la division entera no llega
        };
        ir::IrValueId acc = load_el(v_start);
        for (size_t k = 0; k < S.size(); ++k) {
            if (S[k].is_scaled_arr) {
                // acc += arr[i]*escalar (escalar ya negado si Sub -> suma).
                const ir::IrValueId ai = load_el(step_base[k]);
                const ir::IrValueId prod =
                    bin(elem_fp ? ir::IrOp::FMUL : ir::IrOp::MUL, elem_ty, ai,
                        step_scalar[k]);
                acc = bin(elem_fp ? ir::IrOp::FADD : ir::IrOp::ADD, elem_ty,
                          acc, prod);
            } else {
                const ir::IrValueId rhs =
                    S[k].is_scalar ? step_scalar[k] : load_el(step_base[k]);
                acc = bin(fop_of(S[k].subop), elem_ty, acc, rhs);
            }
        }
        const ir::IrValueId c_at = ptr_at(v_c, off);
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = elem_ty;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {acc, c_at};
        st.source_line = ln;
        fn_->append(current_block_, std::move(st));
    }
    vec_end(sk, ln);
    return true;
}

// ===========================================================================
// Patron de difusion escalar (scalar broadcast):
//   for/while  c[i] = a[i] OP scalar;   i++    (scalar loop-invariante)
//   for/while  c[i] = scalar OP a[i];   i++    (add/mul, conmutativo)
//   for/while  c[i] OP= scalar;         i++
// El escalar es un valor f64 invariante del loop; se DIFUNDE a todos los
// lanes (UNPCKLPD/VBROADCASTSD).  Solo f64 hoy (VEC_BINOP_S es f64).
// ===========================================================================
bool Lowering::try_vectorize_scalar_for(ast::Stmt *s) {
    using namespace ast;
    static const bool MC_DBG = util::flag_on(util::FlagId::McIdiomDebug);

    VecLoop vl;
    if (!mc_extract_vec_loop(s, vl)) return false;
    if (vl.body_exprs.size() != 1) return false;
    const std::string &idx_name = vl.idx_name;
    auto *bexpr = vl.body_exprs[0];
    if (!bexpr || bexpr->kind != NodeKind::AssignExpr) return false;
    auto *asg = static_cast<AssignExpr *>(bexpr);
    if (!asg->target || asg->target->kind != NodeKind::IndexExpr) return false;
    auto *c_ix = static_cast<IndexExpr *>(asg->target.get());

    // refs_idx: true si @p e referencia el indice del loop (no es invariante).
    std::function<bool(const Expr *)> refs_idx = [&](const Expr *e) -> bool {
        if (!e) return false;
        switch (e->kind) {
        case NodeKind::IdentExpr:
            return static_cast<const IdentExpr *>(e)->name == idx_name;
        case NodeKind::BinaryExpr: {
            auto *b = static_cast<const BinaryExpr *>(e);
            return refs_idx(b->lhs.get()) || refs_idx(b->rhs.get());
        }
        case NodeKind::UnaryExpr:
            return refs_idx(static_cast<const UnaryExpr *>(e)->operand.get());
        case NodeKind::IndexExpr: {
            auto *ix = static_cast<const IndexExpr *>(e);
            return refs_idx(ix->base.get()) || refs_idx(ix->index.get());
        }
        case NodeKind::FloatLitExpr:
        case NodeKind::IntLitExpr: return false;
        default:
            // Conservador: cualquier nodo no reconocido -> no vectorizar.
            return true;
        }
    };

    int subop = -1;
    ast::IndexExpr *a_ix = nullptr;
    ast::Expr *scalar_expr = nullptr;
    if (asg->op == AssignOp::Assign) {
        if (!asg->value || asg->value->kind != NodeKind::BinaryExpr)
            return false;
        auto *rhs = static_cast<BinaryExpr *>(asg->value.get());
        switch (rhs->op) {
        case BinOp::Add: subop = 0; break;
        case BinOp::Sub: subop = 1; break;
        case BinOp::Mul: subop = 2; break;
        case BinOp::Div: subop = 3; break;
        default: return false;
        }
        Expr *lhs = rhs->lhs.get(), *rrhs = rhs->rhs.get();
        const bool l_ix = lhs && lhs->kind == NodeKind::IndexExpr;
        const bool r_ix = rrhs && rrhs->kind == NodeKind::IndexExpr;
        if (l_ix && !r_ix) {
            // a[idx] OP scalar  (cualquier op)
            a_ix = static_cast<IndexExpr *>(lhs);
            scalar_expr = rrhs;
        } else if (r_ix && !l_ix) {
            // scalar OP a[idx]  -- solo conmutativo (add/mul)
            if (subop != 0 && subop != 2) return false;
            a_ix = static_cast<IndexExpr *>(rrhs);
            scalar_expr = lhs;
        } else {
            return false; // ambos o ninguno indexados -> no es scalar broadcast
        }
    } else {
        // compound: c[idx] OP= scalar  ==  c[idx] = c[idx] OP scalar
        switch (asg->op) {
        case AssignOp::AddAssign: subop = 0; break;
        case AssignOp::SubAssign: subop = 1; break;
        case AssignOp::MulAssign: subop = 2; break;
        case AssignOp::DivAssign: subop = 3; break;
        default: return false;
        }
        if (!asg->value || asg->value->kind == NodeKind::IndexExpr)
            return false; // si es indexado -> es elementwise, no scalar
        a_ix = c_ix;      // a = c (lhs implicito)
        scalar_expr = asg->value.get();
    }
    if (!scalar_expr || refs_idx(scalar_expr)) return false;

    // Tipo de elemento vectorizable (HOST): f64 (todas las ops) + enteros
    // i8..i64/u8..u64.  El escalar se DIFUNDE a todos los lanes.
    // Valida c_ix / a_ix son base[idx] HOST de un tipo vectorizable; devuelve
    // la base + su PrimitiveKind de elemento.
    auto check_idx = [&](IndexExpr *ix, IdentExpr **out_base,
                         PrimitiveKind *out_kind) -> bool {
        if (!ix->overload_method.empty() || !ix->index_set_method.empty() ||
            ix->is_range)
            return false;
        if (!ix->base || ix->base->kind != NodeKind::IdentExpr) return false;
        if (!ix->index || ix->index->kind != NodeKind::IdentExpr) return false;
        if (static_cast<IdentExpr *>(ix->index.get())->name != idx_name)
            return false;
        auto *base = static_cast<IdentExpr *>(ix->base.get());
        const Type &t = base->result_type;
        const bool ptr_like =
            (t.kind == PrimitiveKind::PTR || t.kind == PrimitiveKind::ARRAY) &&
            static_cast<bool>(t.pointee);
        if (!ptr_like || t.is_virtual) return false;
        ir::IrType ety;
        uint64_t es2;
        bool fp2;
        if (!vec_elem_info(t.pointee->kind, &ety, &es2, &fp2)) return false;
        *out_base = base;
        *out_kind = t.pointee->kind;
        return true;
    };
    ast::IdentExpr *c_base = nullptr, *a_base = nullptr;
    PrimitiveKind ck, ak;
    if (!check_idx(c_ix, &c_base, &ck)) return false;
    if (!check_idx(a_ix, &a_base, &ak)) return false;
    if (ck != ak) return false; // mismo tipo de elemento
    ir::IrType elem_ty;
    uint64_t esz;
    bool elem_fp;
    vec_elem_info(ck, &elem_ty, &esz, &elem_fp);
    // Enteros: div siempre escalar; mul solo donde hay packed (i16/i32, esz
    // 2/4).
    if (!elem_fp) {
        if (subop == 3) return false;
        if (subop == 2 && esz != 2 && esz != 4) return false;
    }

    if (MC_DBG)
        std::fprintf(stderr, "[mc-idiom] MATCH vec_scalar idx=%s subop=%d\n",
                     idx_name.c_str(), subop);

    // ======== Emitir el loop vectorizado + cola escalar. ========
    const uint32_t ln = s->loc.line;
    // AOT: chunk del TARGET (--float-isa); fuera de AOT, host (portabilidad
    // .velb).
    const uint64_t width = vec_chunk_width(64u);
    const uint64_t W = width / esz;

    const ir::IrValueId i_init =
        vl.for_init ? lower_expr(vl.for_init) : lookup(idx_name);
    const ir::IrValueId v_a = lower_expr(a_base);
    const ir::IrValueId v_c = lower_expr(c_base);
    const ir::IrValueId v_N = lower_expr(vl.limit);
    ir::IrValueId v_s_raw = lower_expr(scalar_expr);
    if (i_init == ir::IR_NO_VALUE || v_a == ir::IR_NO_VALUE ||
        v_c == ir::IR_NO_VALUE || v_N == ir::IR_NO_VALUE ||
        v_s_raw == ir::IR_NO_VALUE)
        return false;
    const ir::IrType idx_ty = fn_->values[i_init].type;

    auto bin = [&](ir::IrOp op, ir::IrType ty, ir::IrValueId a,
                   ir::IrValueId b) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ty);
        ir::IrInstr in{};
        in.op = op;
        in.type = ty;
        in.dst = d;
        in.operands = {a, b};
        in.source_line = ln;
        fn_->append(current_block_, std::move(in));
        return d;
    };

    // El escalar SSA que recibe VEC_BINOP_S:
    //  - f64: el valor coercido a F64 (el JIT lo difunde con MOVSD+broadcast).
    //  - enteros: los esz bytes bajos REPLICADOS a lo ancho de 64 bits, de modo
    //    que un broadcast de lane de 64 bits (UNPCKLPD/VBROADCASTSD) llene
    //    todos los sub-lanes con el escalar.  Hecho con IR (portable
    //    interp+jit).
    ir::IrValueId v_s;
    if (elem_fp) {
        v_s = cast_if_needed(v_s_raw, fn_->values[v_s_raw].type,
                             ir::IrType::F64, ln);
    } else {
        // coercer a i64 + zero-extender los esz bytes bajos + replicar.
        ir::IrValueId r = cast_if_needed(v_s_raw, fn_->values[v_s_raw].type,
                                         ir::IrType::I64, ln);
        if (esz < 8) {
            const uint64_t b = 8 * esz; // bits del escalar
            // zero-extender los b bits bajos: (r << (64-b)) >>u (64-b).
            r = bin(ir::IrOp::SHL, ir::IrType::I64, r,
                    emit_const(ir::IrType::I64, 64 - b, ln));
            r = bin(ir::IrOp::SHR, ir::IrType::U64, r, // logico (unsigned)
                    emit_const(ir::IrType::I64, 64 - b, ln));
            // replicar por duplicacion: r |= r << b; r |= r << 2b; ...
            for (uint64_t sh = b; sh < 64; sh *= 2) {
                const ir::IrValueId shifted =
                    bin(ir::IrOp::SHL, ir::IrType::I64, r,
                        emit_const(ir::IrType::I64, sh, ln));
                r = bin(ir::IrOp::OR, ir::IrType::I64, r, shifted);
            }
        }
        v_s = r;
    }

    const ir::IrValueId v_esz = emit_const(ir::IrType::I64, esz, ln);
    /* El escalar se reparte a todos los carriles UNA vez, antes de entrar: no
     * depende del indice, asi que dentro del bucle solo queda la operacion.
     * Va antes de montar el andamio porque tiene que quedar en la entrada. */
    {
        ir::IrInstr bc{};
        bc.op = ir::IrOp::VEC_BCAST;
        bc.type = elem_ty;
        bc.dst = ir::IR_NO_VALUE;
        bc.operands = {v_s};
        bc.imm = width;
        bc.source_line = ln;
        fn_->append(current_block_, std::move(bc));
    }
    /* El andamio -- los cinco bloques, los dos indices y sus condiciones -- lo
     * monta `vec_begin`; aqui solo queda lo que este idioma hace dentro. */
    VecSkeleton sk;
    vec_begin(sk, "vsc", i_init, v_N, (uint64_t)W, ln);
    const ir::IrValueId phi_im = sk.phi_main;

    // --- cuerpo ancho: VEC_BINOP_S(c+off, a+off, escalar) ---
    auto ptr_at = [&](ir::IrValueId base, ir::IrValueId off) {
        return vec_elem_ptr(base, off, ln);
    };
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_im, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off =
            bin(ir::IrOp::MUL, ir::IrType::I64, i64, v_esz);
        const ir::IrValueId c_at = ptr_at(v_c, off);
        const ir::IrValueId a_at = ptr_at(v_a, off);
        ir::IrInstr vb{};
        vb.op = ir::IrOp::VEC_BINOP_S;
        vb.type = elem_ty;
        vb.dst = ir::IR_NO_VALUE;
        vb.operands = {c_at, a_at, v_s};
        // bit16 = HOISTED: el broadcast esta pre-hecho en XMM13 (VEC_BCAST del
        // preheader) -> el JIT usa VX puro a ancho de host sin re-broadcast.
        vb.imm = ((uint64_t)subop << 8) | width | (1ull << 16);
        vb.source_line = ln;
        fn_->append(current_block_, std::move(vb));
    }
    /* Cierra el cuerpo ancho y abre el que recoge los que sobran. */
    vec_to_tail(sk, v_N, ln);
    const ir::IrValueId phi_it = sk.phi_tail;

    // --- cuerpo de uno en uno: c[i] = a[i] OP escalar ---
    block_terminated_ = false;
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_it, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off = bin(ir::IrOp::MUL, ir::IrType::I64, i64,
                                      emit_const(ir::IrType::I64, esz, ln));
        const ir::IrValueId a_at = ptr_at(v_a, off);
        const ir::IrValueId v_ai = fn_->new_value(elem_ty);
        {
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            ld.type = elem_ty;
            ld.dst = v_ai;
            ld.operands = {a_at};
            ld.source_line = ln;
            fn_->append(current_block_, std::move(ld));
        }
        // escalar de la cola con el tipo del elemento (no el i64 replicado).
        const ir::IrValueId v_s_tail =
            elem_fp ? v_s
                    : cast_if_needed(v_s_raw, fn_->values[v_s_raw].type,
                                     elem_ty, ln);
        const ir::IrOp eop = elem_fp ? ((subop == 0)   ? ir::IrOp::FADD
                                        : (subop == 1) ? ir::IrOp::FSUB
                                        : (subop == 2) ? ir::IrOp::FMUL
                                                       : ir::IrOp::FDIV)
                                     : ((subop == 0)   ? ir::IrOp::ADD
                                        : (subop == 1) ? ir::IrOp::SUB
                                                       : ir::IrOp::MUL);
        const ir::IrValueId v_res = bin(eop, elem_ty, v_ai, v_s_tail);
        const ir::IrValueId c_at = ptr_at(v_c, off);
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = elem_ty;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {v_res, c_at};
        st.source_line = ln;
        fn_->append(current_block_, std::move(st));
    }
    vec_end(sk, ln);
    return true;
}

bool Lowering::try_vectorize_unary_for(ast::Stmt *s) {
    using namespace ast;
    static const bool MC_DBG = util::flag_on(util::FlagId::McIdiomDebug);

    // --- estructura: for/while  b[i] = OP a[i];  i++ ---
    VecLoop vl;
    if (!mc_extract_vec_loop(s, vl)) return false;
    if (vl.body_exprs.size() != 1) return false;
    const std::string &idx_name = vl.idx_name;
    auto *bexpr = vl.body_exprs[0];
    if (!bexpr || bexpr->kind != NodeKind::AssignExpr) return false;
    auto *asg = static_cast<AssignExpr *>(bexpr);
    if (asg->op != AssignOp::Assign) return false;
    // target = b[idx]
    if (!asg->target || asg->target->kind != NodeKind::IndexExpr) return false;
    auto *b_ix = static_cast<IndexExpr *>(asg->target.get());

    // value = OP a[idx].  OP in: -a[idx] (UnaryExpr Neg=fneg), sqrt(a[idx])
    // (CallExpr fsqrt), fabs(a[idx]) (CallExpr fabs).  La COPIA pura
    // (b[i]=a[i]) la cubre el memcpy-idiom (loop entero -> 1 rep movsb).
    int subop = -1; // 1=fneg, 2=fabs, 3=fsqrt
    ast::IndexExpr *a_ix = nullptr;
    if (asg->value && asg->value->kind == NodeKind::UnaryExpr) {
        auto *u = static_cast<UnaryExpr *>(asg->value.get());
        if (u->op != UnOp::Neg) return false;
        if (!u->overload_method.empty()) return false; // operator overload
        if (!u->operand || u->operand->kind != NodeKind::IndexExpr)
            return false;
        subop = 1;
        a_ix = static_cast<IndexExpr *>(u->operand.get());
    } else if (asg->value && asg->value->kind == NodeKind::CallExpr) {
        auto *cl = static_cast<CallExpr *>(asg->value.get());
        if (!cl->callee || cl->callee->kind != NodeKind::IdentExpr)
            return false;
        if (!cl->type_args.empty() || cl->args.size() != 1) return false;
        const std::string &fname =
            static_cast<IdentExpr *>(cl->callee.get())->name;
        if (fname == "fabs")
            subop = 2;
        else if (fname == "sqrt")
            subop = 3;
        else
            return false;
        if (!cl->args[0] || cl->args[0]->kind != NodeKind::IndexExpr)
            return false;
        a_ix = static_cast<IndexExpr *>(cl->args[0].get());
    } else {
        return false;
    }

    ast::IdentExpr *b_base = nullptr, *a_base = nullptr;
    PrimitiveKind un_kind = PrimitiveKind::COUNT;
    if (!vec_index_leaf(b_ix, idx_name, &un_kind, &b_base)) return false;
    if (!vec_index_leaf(a_ix, idx_name, &un_kind, &a_base)) return false;
    ir::IrType elem_ty;
    uint64_t esz;
    bool elem_fp;
    if (!vec_elem_info(un_kind, &elem_ty, &esz, &elem_fp)) return false;
    /* Negar existe para cualquier ancho -- en enteros es restar de cero --,
     * pero el valor absoluto y la raiz solo tienen sentido en coma flotante, y
     * el absoluto entero ademas no se emite todavia. */
    if (!elem_fp && subop != 1) return false;

    if (MC_DBG)
        std::fprintf(stderr, "[mc-idiom] MATCH vec_unop idx=%s subop=%d\n",
                     idx_name.c_str(), subop);

    // ======== Emitir el loop vectorizado + cola escalar. ========
    // Chunk por ISA (SSE2/AVX2/AVX512); el JIT descompone al ancho del host.
    const uint32_t ln = s->loc.line;
    // AOT: chunk del TARGET (--float-isa); fuera de AOT, host (portabilidad
    // .velb).
    const uint64_t width = vec_chunk_width(64u);
    const uint64_t W = width / esz;

    const ir::IrValueId i_init =
        vl.for_init ? lower_expr(vl.for_init) : lookup(idx_name);
    const ir::IrValueId v_a = lower_expr(a_base);
    const ir::IrValueId v_b = lower_expr(b_base);
    const ir::IrValueId v_N = lower_expr(vl.limit);
    if (i_init == ir::IR_NO_VALUE || v_a == ir::IR_NO_VALUE ||
        v_b == ir::IR_NO_VALUE || v_N == ir::IR_NO_VALUE)
        return false;
    const ir::IrType idx_ty = fn_->values[i_init].type;

    auto bin = [&](ir::IrOp op, ir::IrType ty, ir::IrValueId a,
                   ir::IrValueId b) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ty);
        ir::IrInstr in{};
        in.op = op;
        in.type = ty;
        in.dst = d;
        in.operands = {a, b};
        in.source_line = ln;
        fn_->append(current_block_, std::move(in));
        return d;
    };
    auto ptr_at = [&](ir::IrValueId base, ir::IrValueId off) {
        return vec_elem_ptr(base, off, ln);
    };

    /* El andamio -- los cinco bloques, los dos indices y sus condiciones -- lo
     * monta `vec_begin`; aqui solo queda lo que este idioma hace dentro.  Al
     * volver se emite en el cuerpo ancho. */
    VecSkeleton sk;
    vec_begin(sk, "vun", i_init, v_N, (uint64_t)W, ln);
    const ir::IrValueId phi_im = sk.phi_main;
    const ir::IrValueId v_esz = emit_const(ir::IrType::I64, esz, ln);

    // --- cuerpo ancho: VEC_UNOP(b+i*esz, a+i*esz) ---
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_im, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off =
            bin(ir::IrOp::MUL, ir::IrType::I64, i64, v_esz);
        const ir::IrValueId b_at = ptr_at(v_b, off);
        const ir::IrValueId a_at = ptr_at(v_a, off);
        ir::IrInstr vu{};
        vu.op = ir::IrOp::VEC_UNOP;
        vu.type = elem_ty;
        vu.dst = ir::IR_NO_VALUE;
        vu.operands = {b_at, a_at};
        vu.imm = ((uint64_t)subop << 8) | width;
        vu.source_line = ln;
        fn_->append(current_block_, std::move(vu));
    }
    /* Cierra el cuerpo ancho y abre el que recoge los que sobran. */
    vec_to_tail(sk, v_N, ln);
    const ir::IrValueId phi_it = sk.phi_tail;

    // --- cuerpo de uno en uno: b[i] = OP a[i] ---
    block_terminated_ = false;
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_it, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off = bin(ir::IrOp::MUL, ir::IrType::I64, i64,
                                      emit_const(ir::IrType::I64, esz, ln));
        const ir::IrValueId a_at = ptr_at(v_a, off);
        const ir::IrValueId v_ai = vec_load_elem(a_at, elem_ty, ln);
        ir::IrValueId v_res;
        if (elem_fp) {
            const ir::IrOp uop = (subop == 1)   ? ir::IrOp::FNEG
                                 : (subop == 2) ? ir::IrOp::FABS
                                                : ir::IrOp::FSQRT;
            v_res = fn_->new_value(elem_ty);
            ir::IrInstr un{};
            un.op = uop;
            un.type = elem_ty;
            un.dst = v_res;
            un.operands = {v_ai};
            un.source_line = ln;
            fn_->append(current_block_, std::move(un));
        } else {
            /* Entero: -a es 0 - a.  El IR tiene NEG, pero la resta deja el
             * mismo codigo y no obliga a que todos los caminos la conozcan. */
            v_res =
                bin(ir::IrOp::SUB, elem_ty, emit_const(elem_ty, 0, ln), v_ai);
        }
        const ir::IrValueId b_at = ptr_at(v_b, off);
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = elem_ty;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {v_res, b_at};
        st.source_line = ln;
        fn_->append(current_block_, std::move(st));
    }
    vec_end(sk, ln);
    return true;
}

bool Lowering::try_vectorize_reduction_for(ast::Stmt *s) {
    using namespace ast;
    static const bool MC_DBG = util::flag_on(util::FlagId::McIdiomDebug);

    // --- estructura: for/while  acc = acc + a[i];  i++ ---
    VecLoop vl;
    if (!mc_extract_vec_loop(s, vl)) return false;
    if (vl.body_exprs.size() != 1) return false;
    const std::string &idx_name = vl.idx_name;
    auto *bexpr = vl.body_exprs[0];
    if (!bexpr || bexpr->kind != NodeKind::AssignExpr) return false;
    auto *asg = static_cast<AssignExpr *>(bexpr);
    if (asg->op != AssignOp::Assign) return false;
    // target = acc (ident f64)
    if (!asg->target || asg->target->kind != NodeKind::IdentExpr) return false;
    auto *acc_id = static_cast<IdentExpr *>(asg->target.get());
    // Tipos de acumulador vectorizables: f64 e enteros i64/i32 (suma).
    ir::IrType elem_ty;
    uint64_t esz;
    bool elem_fp;
    if (!vec_elem_info(acc_id->result_type.kind, &elem_ty, &esz, &elem_fp))
        return false;
    /* Los de 1 y 2 bytes quedan fuera por una razon que no es de la maquina:
     * el acumulador tendria el ancho del elemento y una suma de unos pocos
     * cientos de valores ya se sale.  Quien quiera sumar bytes que los
     * convierta antes al ancho en el que quiera el total. */
    if (esz < 4) return false;
    const std::string acc_name = acc_id->name;
    // value = acc + a[idx]  (reduccion) o  acc + a[idx]*b[idx]
    // (dot-product/FMA)
    if (!asg->value || asg->value->kind != NodeKind::BinaryExpr) return false;
    auto *rhs = static_cast<BinaryExpr *>(asg->value.get());
    if (rhs->op != BinOp::Add) return false;
    if (!rhs->lhs || rhs->lhs->kind != NodeKind::IdentExpr) return false;
    if (static_cast<IdentExpr *>(rhs->lhs.get())->name != acc_name)
        return false; // lhs debe ser el MISMO acc
    // Valida base_ident[idx] HOST del MISMO tipo que el acumulador; devuelve
    // base.
    auto check_idx_base = [&](ast::Expr *e) -> ast::IdentExpr * {
        if (!e || e->kind != NodeKind::IndexExpr) return nullptr;
        auto *ix = static_cast<IndexExpr *>(e);
        if (!ix->overload_method.empty() || ix->is_range) return nullptr;
        if (!ix->base || ix->base->kind != NodeKind::IdentExpr) return nullptr;
        if (!ix->index || ix->index->kind != NodeKind::IdentExpr)
            return nullptr;
        if (static_cast<IdentExpr *>(ix->index.get())->name != idx_name)
            return nullptr;
        auto *base = static_cast<IdentExpr *>(ix->base.get());
        const Type &t = base->result_type;
        const bool ptr_like =
            (t.kind == PrimitiveKind::PTR || t.kind == PrimitiveKind::ARRAY) &&
            static_cast<bool>(t.pointee);
        if (!ptr_like || t.is_virtual) return nullptr; // solo HOST
        if (t.pointee->kind != acc_id->result_type.kind) return nullptr;
        return base;
    };
    ast::IdentExpr *a_base = nullptr, *b_base = nullptr;
    bool is_fma = false;
    bool is_scalar_fma = false; // acc += a[i]*c (c invariante) -> FMA con bcast
    ast::Expr *c_expr = nullptr;
    if (rhs->rhs && rhs->rhs->kind == NodeKind::IndexExpr) {
        // reduccion simple: acc += a[i]
        a_base = check_idx_base(rhs->rhs.get());
        if (!a_base) return false;
    } else if (rhs->rhs && rhs->rhs->kind == NodeKind::BinaryExpr) {
        /* Producto escalar: `acc += a[i] * b[i]`.  Solo en coma flotante.
         *
         * En enteros la instruccion que multiplica y acumula de una vez no
         * existe, y hacerlo en dos -- multiplicar y sumar -- se INTENTO: el
         * reconocedor y los tres caminos de ejecucion lo aceptaban, y cada uno
         * daba un numero DISTINTO y ninguno el correcto.  Queda fuera hasta que
         * se entienda por que; una respuesta equivocada es peor que no
         * vectorizar. */
        auto *mul = static_cast<BinaryExpr *>(rhs->rhs.get());
        if (mul->op != BinOp::Mul || !elem_fp) return false;
        a_base = check_idx_base(mul->lhs.get());
        b_base = check_idx_base(mul->rhs.get());
        if (a_base && b_base) {
            is_fma = true; // a[i]*b[i]
        } else {
            // scalar-factor: acc += a[i]*c  o  c*a[i]  (c loop-invariante).
            // El array queda en a_base; el escalar (invariante) en c_expr.  Se
            // difunde a un buffer host y se reusa la maquinaria VFMADD.
            ast::Expr *scal_e = nullptr;
            if (a_base) {
                scal_e = mul->rhs.get(); // a[i] * c
            } else if (b_base) {
                a_base = b_base; // c * a[i]  -> array a la izquierda
                b_base = nullptr;
                scal_e = mul->lhs.get();
            } else {
                return false;
            }
            if (!scal_e || mc_expr_refs_ident(scal_e, idx_name)) return false;
            c_expr = scal_e;
            is_fma = true;
            is_scalar_fma = true;
        }
    } else {
        return false;
    }

    if (MC_DBG)
        std::fprintf(stderr, "[mc-idiom] MATCH %s idx=%s acc=%s\n",
                     is_fma ? "vec_fma" : "vec_reduce", idx_name.c_str(),
                     acc_name.c_str());

    // ======== Emitir: acumulador vectorial + reduccion horizontal + cola.
    // El ancho del acumulador vectorial lo elige la ISA (16/32/64 = W lanes).
    // UNROLL: U acumuladores INDEPENDIENTES (XMM10-13 reservados) -> oculta la
    // latencia de la cadena vaddpd.  El bucle desenrollado procesa U*W
    // elems/iter acumulando en acc0..acc{U-1}; al final se combinan en acc0 y
    // el bucle W-granular existente sirve de remainder.
    const uint32_t ln = s->loc.line;
    // AOT: chunk del TARGET (--float-isa); fuera de AOT, host (portabilidad
    // .velb). AUTO (multiversion): la REDUCCION hornea chunk=16 (128b) -> el
    // acumulador register-resident (1 reg, no splittea) cabe en TODAS las
    // variantes (sse2/avx2/avx512); las 3 corren la reduccion a 128b (correcto;
    // el unroll multi-acc compensa la falta de width win).
    /* 16 y no 64: el acumulador vive en UN registro y no se parte, asi que las
     * tres variantes corren la reduccion a 128 bits.  Lo que se pierde de
     * ancho lo compensa el desenrollado con varios acumuladores. */
    const uint64_t width = vec_chunk_width(16u);
    const uint64_t W = width / esz; // lanes segun ancho/tipo
    const uint64_t U = 4;           // acumuladores (XMM13,12,11,10)
    // imm de las VEC_ACC ops: ancho | acc_idx<<8 | src_idx<<12 | disp<<16.
    // disp (bits 16-31) = displacement de bytes en el array a[]/b[] para las
    // U piezas del unroll: en vez de recalcular el puntero (MUL+ADD) por pieza,
    // el matcher computa el puntero base UNA vez y cada VEC_ACC_ADD/FMA lee con
    // `movupd disp(base)` (direccionamiento gcc-style).  Quita los adds enteros
    // por elemento que nos dejaban ~4x detras de gcc en reducciones float.
    auto acc_imm = [&](uint8_t aidx, uint8_t sidx,
                       uint64_t disp = 0) -> uint64_t {
        return width | ((uint64_t)aidx << 8) | ((uint64_t)sidx << 12) |
               ((disp & 0xFFFFull) << 16);
    };

    // acc puede ser un valor SSA directo (caso simple: acc vive en un registro
    // SSA) o un PTR a un SLOT de memoria (caso loop-carried: un loop EXTERNO
    // arrastra acc, asi que la bajada lo materializa en un ALLOCA y el binding
    // es el puntero al slot).  Soportamos AMBOS: si es slot, cargamos el valor
    // inicial del slot antes del loop y escribimos el resultado al slot al
    // final (en vez de re-vincular un SSA).  Sin esto, la reduccion con acc
    // loop-carried (p.ej. `for(k) for(i) acc+=a[i]`) caia a escalar -> ~4x gcc.
    const ir::IrValueId acc_binding = lookup(acc_name);
    const ir::IrValueId i_init =
        vl.for_init ? lower_expr(vl.for_init) : lookup(idx_name);
    const ir::IrValueId v_a = lower_expr(a_base);
    // v_b: el array b (dot-product) o el buffer host difundido (scalar-factor,
    // se llena mas abajo en el entry).  v_c: el escalar (scalar-factor), usado
    // por la cola directamente.
    ir::IrValueId v_b = ir::IR_NO_VALUE;
    ir::IrValueId v_c = ir::IR_NO_VALUE;
    if (is_scalar_fma) {
        const ir::IrValueId raw = lower_expr(c_expr);
        if (raw == ir::IR_NO_VALUE) return false;
        v_c = cast_if_needed(raw, fn_->values[raw].type, elem_ty, ln);
    } else if (is_fma) {
        v_b = lower_expr(b_base);
    }
    const ir::IrValueId v_N = lower_expr(vl.limit);
    if (acc_binding == ir::IR_NO_VALUE || i_init == ir::IR_NO_VALUE ||
        v_a == ir::IR_NO_VALUE || v_N == ir::IR_NO_VALUE ||
        (is_fma && !is_scalar_fma && v_b == ir::IR_NO_VALUE) ||
        (is_scalar_fma && v_c == ir::IR_NO_VALUE))
        return false;
    // Resolver el valor inicial (acc_init) y, si es memory-based, el slot
    // externo (acc_slot_ext) al que escribir el resultado final.
    ir::IrValueId acc_init;
    ir::IrValueId acc_slot_ext = ir::IR_NO_VALUE;
    const ir::IrType acc_bt = fn_->values[acc_binding].type;
    if (acc_bt == elem_ty) {
        acc_init = acc_binding; // valor SSA directo
    } else if (acc_bt == ir::IrType::PTR) {
        // acc en slot: cargar el valor inicial (hereda is_host_ptr del
        // binding).
        acc_slot_ext = acc_binding;
        const ir::IrValueId loaded = fn_->new_value(elem_ty);
        ir::IrInstr ld{};
        ld.op = ir::IrOp::LOAD;
        ld.type = elem_ty;
        ld.dst = loaded;
        ld.operands = {acc_binding};
        ld.source_line = ln;
        fn_->append(current_block_, std::move(ld));
        acc_init = loaded;
    } else {
        return false; // tipo de binding inesperado
    }
    const ir::IrType idx_ty = fn_->values[i_init].type;

    auto bin = [&](ir::IrOp op, ir::IrType ty, ir::IrValueId a,
                   ir::IrValueId b) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ty);
        ir::IrInstr in{};
        in.op = op;
        in.type = ty;
        in.dst = d;
        in.operands = {a, b};
        in.source_line = ln;
        fn_->append(current_block_, std::move(in));
        return d;
    };
    auto ptr_at = [&](ir::IrValueId base, ir::IrValueId off) {
        return vec_elem_ptr(base, off, ln);
    };
    // load/store del tipo de elemento (acumulador y array).
    auto load_el = [&](ir::IrValueId at) {
        return vec_load_elem(at, elem_ty, ln);
    };
    // op de acumulacion: FADD para float, ADD para entero.
    const ir::IrOp acc_op = elem_fp ? ir::IrOp::FADD : ir::IrOp::ADD;
    // store crudo de 8 bytes a 0 (zero-init del slot de 16B, cualquier tipo).
    auto store_zero8 = [&](ir::IrValueId at, ir::IrValueId vz) {
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir::IrType::I64;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {vz, at};
        st.source_line = ln;
        fn_->append(current_block_, std::move(st));
    };

    const ir::IrBlockId entry = current_block_;
    const ir::IrBlockId uhdr = fn_->new_block("vred_unroll_hdr");
    const ir::IrBlockId ubody = fn_->new_block("vred_unroll_body");
    const ir::IrBlockId comb = fn_->new_block("vred_combine");
    const ir::IrBlockId mhdr = fn_->new_block("vred_main_hdr");
    const ir::IrBlockId mbody = fn_->new_block("vred_main_body");
    const ir::IrBlockId redb = fn_->new_block("vred_reduce");
    const ir::IrBlockId thdr = fn_->new_block("vred_tail_hdr");
    const ir::IrBlockId tbody = fn_->new_block("vred_tail_body");
    const ir::IrBlockId exit = fn_->new_block("vred_exit");

    // --- entry: acc_slot host U*width bytes; zero U accs; BR uhdr ---
    current_block_ = entry;
    const ir::IrValueId acc_slot = fn_->new_value(ir::IrType::PTR);
    fn_->values[acc_slot].is_host_ptr = true;
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = acc_slot;
        al.imm = static_cast<int64_t>(U * width);
        al.host_alloca = true;
        al.source_line = ln;
        fn_->append(entry, std::move(al));
    }
    for (uint8_t u = 0; u < U; ++u) {
        ir::IrInstr az{};
        az.op = ir::IrOp::VEC_ACC_ZERO;
        az.type = elem_ty;
        az.dst = ir::IR_NO_VALUE;
        az.operands = {acc_slot};
        az.imm = acc_imm(u, 0);
        az.source_line = ln;
        fn_->append(entry, std::move(az));
    }
    // Scalar-factor (acc += a[i]*c): difundir el escalar c a un buffer host de
    // U*width bytes (U*W elementos) UNA vez.  El VFMADD del cuerpo lo lee como
    // el "array b" (cada lane = c); la cola escalar usa v_c directamente.  El
    // buffer cubre el rango de disp del unroll (0..(U-1)*width).
    if (is_scalar_fma) {
        v_b = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_b].is_host_ptr = true;
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = v_b;
        al.imm = static_cast<int64_t>(U * width);
        al.host_alloca = true;
        al.source_line = ln;
        fn_->append(entry, std::move(al));
        for (uint64_t e = 0; e < U * W; ++e) {
            ir::IrValueId at = v_b;
            if (e > 0)
                at = ptr_at(v_b, emit_const(ir::IrType::I64, e * esz, ln));
            ir::IrInstr st{};
            st.op = ir::IrOp::STORE;
            st.type = elem_ty;
            st.dst = ir::IR_NO_VALUE;
            st.operands = {v_c, at};
            st.source_line = ln;
            fn_->append(entry, std::move(st));
        }
    }
    const ir::IrValueId v_W = emit_const(idx_ty, (uint64_t)W, ln);
    const ir::IrValueId v_UW = emit_const(idx_ty, (uint64_t)(U * W), ln);
    const ir::IrValueId v_esz = emit_const(ir::IrType::I64, esz, ln);
    /* Primer bucle: el desenrollado, que avanza de U*W en U*W con U
     * acumuladores a la vez.  Se sale a `comb`, donde se juntan. */
    VecLoopFrame lu;
    vec_loop_open(lu, uhdr, ubody, comb, i_init, v_N, v_UW, (uint64_t)(U * W),
                  VecLoopGuard::WholeStep, {}, ln);
    const ir::IrValueId phi_iu = lu.phi_idx;

    // --- ubody: acc_u += a[i + u*W] para u=0..U-1; i += U*W; BR uhdr ---
    // OPTIMIZACION de direccionamiento: en vez de recalcular el puntero por
    // pieza (iu = i + u*W; off = iu*esz; a_at = base + off  ->  ADD+MUL+ADD por
    // pieza), computamos el puntero BASE una sola vez (a_at0 = base + i*esz) y
    // cada VEC_ACC_ADD/FMA lee con displacement constante `u*W*esz` plegado en
    // el imm (codegen: `movupd disp(base)`).  Esto elimina los adds enteros por
    // elemento que nos dejaban ~4x detras de gcc -- ahora el bucle gasta solo
    // 1 MUL + 1-2 ADD para el base por iteracion del unroll, igual que gcc.
    current_block_ = ubody;
    const ir::IrValueId iu64 =
        cast_if_needed(phi_iu, idx_ty, ir::IrType::I64, ln);
    const ir::IrValueId off_base =
        bin(ir::IrOp::MUL, ir::IrType::I64, iu64, v_esz);
    const ir::IrValueId a_at0 = ptr_at(v_a, off_base);
    // scalar-factor: b = c_buf FIJO (no avanza con el loop; el VEC_ACC_FMA ya
    // suma el disp de pieza, que cabe en los U*W elementos del buffer).
    const ir::IrValueId b_at0 = is_scalar_fma ? v_b
                                : is_fma      ? ptr_at(v_b, off_base)
                                              : ir::IR_NO_VALUE;
    for (uint8_t u = 0; u < U; ++u) {
        const uint64_t disp = (uint64_t)u * W * esz; // constante de pieza
        ir::IrInstr v{};
        v.type = elem_ty;
        v.dst = ir::IR_NO_VALUE;
        v.imm = acc_imm(u, 0, disp);
        v.source_line = ln;
        if (is_fma) {
            v.op = ir::IrOp::VEC_ACC_FMA;
            v.operands = {acc_slot, a_at0, b_at0};
        } else {
            v.op = ir::IrOp::VEC_ACC_ADD;
            v.operands = {acc_slot, a_at0};
        }
        fn_->append(ubody, std::move(v));
    }
    /* Cerrar el desenrollado deja el programa en `comb`. */
    vec_loop_close(lu, {}, ln);

    // --- comb: acc0 += acc_u (u=1..U-1); BR mhdr ---
    for (uint8_t u = 1; u < U; ++u) {
        ir::IrInstr c{};
        c.op = ir::IrOp::VEC_ACC_COMBINE;
        c.type = elem_ty;
        c.dst = ir::IR_NO_VALUE;
        c.operands = {acc_slot};
        c.imm = acc_imm(0, u);
        c.source_line = ln; // acc0 += acc_u
        fn_->append(comb, std::move(c));
    }
    /* Segundo bucle: el ancho, de W en W y con un solo acumulador.  El indice
     * continua donde lo dejo el desenrollado.  Se sale a `redb`, que junta los
     * carriles en un escalar. */
    VecLoopFrame lm;
    vec_loop_open(lm, mhdr, mbody, redb, phi_iu, v_N, v_W, (uint64_t)W,
                  VecLoopGuard::WholeStep, {}, ln);
    const ir::IrValueId phi_im = lm.phi_idx;

    // --- mbody: acc += a[i..]  (VEC_ACC_ADD) o  acc += a*b (VEC_ACC_FMA);
    //     acc REGISTER-RESIDENT (XMM dedicado en JIT, sin round-trip a
    //     memoria); i += W; BR mhdr ---
    current_block_ = mbody;
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_im, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off =
            bin(ir::IrOp::MUL, ir::IrType::I64, i64, v_esz);
        const ir::IrValueId a_at = ptr_at(v_a, off);
        if (is_fma) {
            // scalar-factor: b = c_buf FIJO (imm=width -> disp 0, dentro de W).
            const ir::IrValueId b_at = is_scalar_fma ? v_b : ptr_at(v_b, off);
            ir::IrInstr vf{};
            vf.op = ir::IrOp::VEC_ACC_FMA;
            vf.type = elem_ty;
            vf.dst = ir::IR_NO_VALUE;
            vf.operands = {acc_slot, a_at, b_at}; // acc += a*b
            vf.imm = width;
            vf.source_line = ln;
            fn_->append(current_block_, std::move(vf));
        } else {
            ir::IrInstr va{};
            va.op = ir::IrOp::VEC_ACC_ADD;
            va.type = elem_ty;
            va.dst = ir::IR_NO_VALUE;
            va.operands = {acc_slot, a_at}; // acc += a
            va.imm = width;
            va.source_line = ln;
            fn_->append(current_block_, std::move(va));
        }
    }
    /* Cerrar el ancho deja el programa en `redb`. */
    vec_loop_close(lm, {}, ln);

    // --- redb: vuelca el acc register-resident al slot (JIT; no-op interp) y
    //     reduce horizontalmente sum_{k<W} acc_slot[k] + acc_init; BR thdr ---
    {
        ir::IrInstr st{};
        st.op = ir::IrOp::VEC_ACC_STORE;
        st.type = elem_ty;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {acc_slot};
        st.imm = width;
        st.source_line = ln;
        fn_->append(redb, std::move(st));
    }
    ir::IrValueId result0 = acc_init;
    for (uint64_t k = 0; k < W; ++k) {
        const ir::IrValueId at =
            (k == 0)
                ? acc_slot
                : ptr_at(acc_slot, emit_const(ir::IrType::I64, k * esz, ln));
        const ir::IrValueId lane = load_el(at);
        result0 = bin(acc_op, elem_ty, result0, lane);
    }
    /* Tercer bucle: la cola, de uno en uno.  Es el unico de los tres que
     * ademas del indice lleva un valor viajando entre vueltas -- la suma
     * parcial --, porque aqui ya no hay carriles: el acumulador es un escalar
     * normal y tiene que pasar de una vuelta a la siguiente. */
    VecLoopFrame lt;
    vec_loop_open(lt, thdr, tbody, exit, phi_im, v_N, ir::IR_NO_VALUE, 1,
                  VecLoopGuard::Remaining, {result0}, ln);
    const ir::IrValueId phi_it = lt.phi_idx;
    const ir::IrValueId phi_res = lt.phi_carried[0];

    // --- tbody: result += a[i]  o  result += a[i]*b[i] (FMA); i++; BR thdr ---
    // La cola usa FMUL+FADD separados (2 redondeos) en interp Y jit por igual
    // (son IR ops escalares lowereadas identicamente) -> interp==jit; los lanes
    // vectorizados usan fused (fmadd / VFMADD) en ambos.
    current_block_ = tbody;
    {
        const ir::IrValueId i64 =
            cast_if_needed(phi_it, idx_ty, ir::IrType::I64, ln);
        const ir::IrValueId off =
            bin(ir::IrOp::MUL, ir::IrType::I64, i64, v_esz);
        const ir::IrValueId ai = load_el(ptr_at(v_a, off));
        ir::IrValueId addend = ai;
        if (is_scalar_fma) {
            // a[i]*c: el escalar directo (el buffer solo tiene U*W elementos;
            // en la cola i puede exceder ese rango).
            addend = bin(ir::IrOp::FMUL, elem_ty, ai, v_c);
        } else if (is_fma) {
            const ir::IrValueId bi = load_el(ptr_at(v_b, off));
            addend = bin(ir::IrOp::FMUL, elem_ty, ai, bi); // a[i]*b[i]
        }
        const ir::IrValueId rnext = bin(acc_op, elem_ty, phi_res, addend);
        /* La suma parcial es lo que viaja: entra al cierre y sale por el phi.
         */
        vec_loop_close(lt, {rnext}, ln);
    }

    // --- exit: resultado final = phi_res ---
    if (acc_slot_ext != ir::IR_NO_VALUE) {
        // acc vive en un slot: escribir el resultado de vuelta (el binding
        // sigue siendo el slot; lecturas posteriores de acc cargan de ahi).
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = elem_ty;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {phi_res, acc_slot_ext};
        st.source_line = ln;
        fn_->append(exit, std::move(st));
    } else {
        update_scope(acc_name, phi_res); // valor SSA directo
    }
    return true;
}

} // namespace vx
