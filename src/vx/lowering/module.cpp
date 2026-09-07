/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/module.cpp
 * @brief El recorrido de arriba: bajar un modulo entero y bajar una funcion.
 *
 * Es la parte que ORQUESTA, no la que traduce.  Recorre lo que el fuente
 * declara -- globales, funciones, clases, structs, bloques de datos, aspectos
 * -- y decide en que orden se emite cada cosa, que hay que generar aunque nadie
 * lo escribiera (los ayudantes de construccion, el arranque del modulo) y que
 * se puede omitir.
 *
 * Y bajar una funcion es montar su marco antes de traducir su cuerpo: los
 * parametros, donde vive cada uno, el ambito, y la salida por cualquiera de sus
 * vias.  El cuerpo en si lo bajan los demas ficheros de esta carpeta; aqui se
 * les prepara el sitio.
 */
#include "vx/lowering.h"
#include "loader/oop_types.h" // ADVICE_*: el orden de la cadena
#include "vx/asm/asm_effects.h" // asm_canonical_reg: canonicaliza el alias de ancho
#include <chrono>
#include <iostream>
#include "vx/comptime/comptime_introspect.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "analysis/facts/definite_store.h" // si un `out` se escribe SIEMPRE
#include "lowering_internal.h"             // la cocina compartida del lowering

namespace vx {

namespace {
/**
 * @brief Bits IEEE de @p d listos para grabarse en el slot de un global
 *        de coma flotante.
 *
 * El ancho lo manda el TIPO DECLARADO, no el literal: los literales de coma
 * flotante se parsean como @c double, pero el slot de un @c f32 guarda un
 * binary32 y su LOAD lee 4 bytes.  Grabar ahi los bits de un double deja en
 * esos 4 bytes el resto de la mantisa (para 0.5 son ceros -> el global valia
 * 0).  El resultado va en los bytes bajos del qword del slot.
 *
 * @param d      Valor del literal (ya parseado como double).
 * @param is_f32 true si el global se declaro @c f32; false si @c f64.
 * @return Patron de bits a grabar en el slot.
 */

/**
 * @brief Bytes que ocupa un array global nativo @c T[N] con @c N sabido al
 *        compilar.
 *
 * Cero si no es un array de tamano fijo con elemento dimensionable: entonces
 * no se le reserva sitio estatico.  Es lo que permite un buffer global de
 * verdad -- @c u8[4096] @c g_heap; para el monton de un asignador sencillo en
 * codigo sin sistema operativo -- en vez de una reserva en tiempo de
 * ejecucion.
 */
static uint64_t vx_global_array_bytes(const ast::TypeNode *tn,
                                      const TypeChecker &tc) {
    if (!tn || tn->kind != ast::NodeKind::ArrayTypeNode) return 0;
    auto *at = static_cast<const ast::ArrayTypeNode *>(tn);
    if (!at->element_type || !at->size_expr)
        return 0; // T[] decay = sin storage
    if (at->size_expr->kind != ast::NodeKind::IntLitExpr) return 0;
    const uint64_t count =
        static_cast<const ast::IntLitExpr *>(at->size_expr.get())->value;
    uint64_t esz = 0;
    if (at->element_type->kind == ast::NodeKind::PrimitiveTypeNode)
        esz = primitive_size_bytes(
            static_cast<const ast::PrimitiveTypeNode *>(at->element_type.get())
                ->prim);
    else if (at->element_type->kind == ast::NodeKind::PointerTypeNode)
        esz = 8;
    else if (at->element_type->kind == ast::NodeKind::NamedTypeNode) {
        // Elemento newtype (typedef-new, p.ej. `uintptr[256]`): tamano del
        // primitivo subyacente (accesor const del type checker).
        const auto *nt =
            static_cast<const ast::NamedTypeNode *>(at->element_type.get());
        if (const Type *u = tc.newtype_underlying(nt->name))
            esz = primitive_size_bytes(u->kind);
        else {
            // Elemento `@overlay struct` (p.ej. `Foo[4] g_hs;`): el valor de
            // una vista ES un puntero de 8 bytes -> el array guarda N punteros.
            // Sin esto esz=0 y el global se quedaba SIN storage estatico.
            auto sit = tc.struct_layouts().find(nt->name);
            if (sit != tc.struct_layouts().end() && sit->second.is_overlay)
                esz = 8;
        }
    }
    if (esz == 0 || count == 0) return 0;
    return count * esz;
}
} // namespace
bool Lowering::run(ir::IrModule &out_module, const std::string &module_name) {
    /* Reparto del coste de la bajada.  Es la fase mas cara del frontend en un
     * fichero de un solo modulo -- 1,0 s de los 1,2 que costaba uno de 5.700
     * lineas -- y hasta ahora se publicaba como un solo numero, que no dice si
     * el trabajo esta en las funciones o en lo que se prepara antes. */
    const bool medir_bajada = util::flag_on(util::FlagId::Times);
    using RelojBajada = std::chrono::steady_clock;
    const auto marca_run = RelojBajada::now();
    long us_previo = 0, n_bajadas = 0;

    const size_t initial_errors = diags_.error_count();
    out_module.name = module_name;
    out_module.format = "velb";
    // Guardar puntero al modulo de salida para que los lowering de
    // expresiones (StringLitExpr, builtins FFI) puedan registrar
    // datos estaticos y imports nativos sin pasar el modulo en cada
    // signature.
    out_mod_ = &out_module;

    // AOT: precomputar los intervalos de tipo (encoding nested-set) para el
    // type matching de catch.  Barato y necesario antes de bajar cualquier
    // try/throw.
    if (native_poo_) compute_type_intervals();

    /* La cadena de aspectos de cada metodo, EN ORDEN.  Se recoge ANTES de bajar
     * ningun cuerpo por dos motivos: cada sitio de llamada la consulta para
     * decidir si puede especular, y el `proceed()` de un `@Around` necesita
     * saber a que llama, que depende de su posicion en la cadena.
     *
     * El orden es el de declaracion, que es el mismo en que `__module_init`
     * llama a `addadvice` y por tanto el que tendra la cadena en ejecucion. */
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::ClassDecl) continue;
        auto *cd_asp = static_cast<ast::ClassDecl *>(decl.get());
        for (auto &m_uptr : cd_asp->methods) {
            auto *m = m_uptr.get();
            if (!m || m->advice_kind == 0) continue;
            const std::string &t = m->advice_target;
            const size_t p = t.find('.');
            /* Un pointcut mal formado lo diagnostica la emision del advice;
             * aqui basta con NO poder atribuirlo, que es lo prudente. */
            if (p == std::string::npos || p == 0 || p + 1 >= t.size()) {
                all_advices_attributed_ = false;
                continue;
            }
            const std::string target = t.substr(0, p) + "__" + t.substr(p + 1);
            ir::IrModule::ChainedAdvice entry;
            entry.kind = static_cast<uint8_t>(m->advice_kind - 1);
            entry.method_ir_name = cd_asp->name + "__" + m->name;
            advice_chains_[target].push_back(std::move(entry));
        }
    }
    /* A que llama el `proceed()` de cada `@Around`.
     *
     * Un `@Around` envuelve al SIGUIENTE de su cadena, y el ultimo al metodo.
     * Como un advice tiene un solo objetivo -- el pointcut es `Clase.metodo`
     * exacto -- su `proceed` tiene UN destino, conocido aqui.  Eso es lo que
     * permite llamarlo directo en vez de por el marco. */
    for (const auto &kv : advice_chains_) {
        const std::string *prev = nullptr;
        for (const auto &a : kv.second) {
            if (a.kind != loader::ADVICE_AROUND) continue;
            if (prev != nullptr) proceed_target_[*prev] = a.method_ir_name;
            prev = &a.method_ir_name;
        }
        /* El mas interno llama al metodo. */
        if (prev != nullptr) proceed_target_[*prev] = kv.first;
    }
    out_module.advice_chains = advice_chains_;
    out_module.all_advices_attributed = all_advices_attributed_;

    // AOT / Embed (native_poo_): el AOP (@Aspect + advice) se registra en
    // RUNTIME (MethodInfo::advice_chain via addadvice en __module_init), que
    // native_poo NO emite.  Sin esto, el advice se ignoraria SILENCIOSAMENTE y
    // los metodos correrian sin sus before/after/around -> resultado erroneo
    // (16_aop daba 1 en vez de 99).  Rechazar en compile-time es lo correcto:
    // un fallo ruidoso es mejor que un resultado incorrecto.
    if (native_poo_) {
        for (const auto &kv : tc_.class_layouts()) {
            if (kv.second.is_aspect) {
                error_at(SourceLoc{},
                         "AOP (@Aspect '" + kv.first +
                             "') no soportado en compilacion nativa "
                             "(--target bare/embed): el advice se registra en "
                             "runtime y se ignoraria. Usa --target full o "
                             "elimina los aspectos.");
                return false;
            }
        }
    }

    // Inferir el fichero fuente del primer AST node con loc.file no
    // vacio.  Esto se usa en warnings emitidos por @c cast_if_needed
    // que solo recibe @c source_line.  Sin esta inferencia, los
    // warnings se imprimirian sin nombre de fichero.
    for (auto &d : mod_.decls) {
        if (!d) continue;
        if (!d->loc.file().empty()) {
            current_file_ = d->loc.file();
            break;
        }
    }

    // EMITIR PRIMERO los IntrospectInfo chunks
    // y poblar @c introspect_idx_by_name_ ANTES de bajar funciones,
    // para que @c find_type("Literal") pueda resolver el indice del
    // chunk en compile-time durante el lowering de main / otras
    // funciones.  Los layouts ya estan calculados por el type checker.
    emit_introspect_info_chunks();

    // Pase 1: registrar el tipo de retorno de cada funcion para validar
    // las llamadas.  Esto en un programa real ya esta en el type checker,
    // pero lo replicamos aqui para no acoplar la API.
    //
    // Adicionalmente registramos el PrimitiveKind semantico (OPTIONAL/
    // RESULT/...) en @c fn_ret_kind_ para que @c lower_call detecte
    // las funciones sret y aloque el retbuf en el caller.
    for (auto &decl : mod_.decls) {
        if (!decl) continue;
        if (decl->kind == ast::NodeKind::FunctionDecl) {
            auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
            /* El tipo devuelto, ENTERO.  Antes se guardaba solo su especie, y
             * el tamano de un `Optional` depende de lo que envuelva: quien
             * llamaba tenia que ir a buscarlo por otro lado, y donde no podia,
             * suponia dieciseis. */
            Type ret_sem;
            ret_sem.kind = PrimitiveKind::VOID;
            if (fd->return_type &&
                fd->return_type->kind == ast::NodeKind::PrimitiveTypeNode &&
                static_cast<ast::PrimitiveTypeNode *>(fd->return_type.get())
                        ->prim != PrimitiveKind::GC_PTR) {
                auto *pt = static_cast<ast::PrimitiveTypeNode *>(
                    fd->return_type.get());
                ret_sem.kind = pt->prim;
            } else if (fd->return_type) {
                // NOTA gc<T>: `gc<unique<i64>>` es un PrimitiveTypeNode(GC_PTR)
                // con type_args, pero su tipo REAL de retorno es el inner T
                // (UNIQUE_PTR/SHARED_PTR/CLASS/...) con gc_managed=true -- ver
                // TypeChecker::type_from_node.  Debemos resolverlo por
                // `resolve_type_node` (NO quedarnos en GC_PTR) para que la
                // deteccion de SRET del CALLER (fn_returns_smartptr_, etc.)
                // coincida con la del CALLEE (lower_function, que usa
                // resolve_type_node).  Sin esto, una fn que devuelve
                // gc<unique<T>>/gc<shared<T>> es SRET en el callee (retbuf)
                // pero el caller no pasa retbuf -> escritura a puntero basura
                // (SEGV en AOT, bug 248).  Por eso GC_PTR se excluye de la
                // rama PrimitiveTypeNode de arriba y cae aqui.
                // Para tipos no-primitivos (NamedTypeNode con CLASS,
                // Optional<T>, Result<V,E>, ARRAY, PTR, alias), usar
                // el tipo semantico resuelto.  Sin esto, las llamadas
                // a funciones que devuelven Result/Optional pierden
                // su PTR de retorno y la asignacion al var-decl falla.
                const Type sem = tc_.resolve_type_node(fd->return_type.get());
                if (sem.kind != PrimitiveKind::COUNT &&
                    sem.kind != PrimitiveKind::VOID) {
                    ret_sem = sem;
                }
            }
            // El registro (incluida la decision del buffer de retorno) vive en
            // un unico sitio, compartido con las funciones importadas -- ver
            // register_fn_ret_info.
            register_fn_ret_info(fd->name, ret_sem, fd->is_async);
        } else if (decl->kind == ast::NodeKind::ExternFnDecl) {
            // FFI declarativo: registrar tipo de retorno y
            // mapeo nombre -> libreria nativa para que @c lower_call
            // emita CALLN @Method("<lib>:<name>") en vez de CALLVM.
            auto *efd = static_cast<ast::ExternFnDecl *>(decl.get());
            ir::IrType rt = ir::IrType::VOID;
            if (efd->return_type &&
                efd->return_type->kind == ast::NodeKind::PrimitiveTypeNode) {
                auto *pt = static_cast<ast::PrimitiveTypeNode *>(
                    efd->return_type.get());
                if (pt->prim != PrimitiveKind::VOID) {
                    rt = ir_type_from_primitive(pt->prim);
                }
            } else if (efd->return_type) {
                const Type sem = tc_.resolve_type_node(efd->return_type.get());
                if (sem.kind != PrimitiveKind::COUNT &&
                    sem.kind != PrimitiveKind::VOID) {
                    rt = ir_type_from_primitive(sem.kind);
                }
            }
            fn_return_types_[efd->name] = rt;
            extern_lib_by_fn_name_[efd->name] = efd->lib;
            // Lo DEFINIDO sobre la nativa: `in`/`out`/`inout` de cada param a
            // las mascaras por argumento.  Que sean por ARGUMENTO y no una
            // frase suelta es lo que hace que se escriba una vez y siga siendo
            // preciso en cada sitio de llamada: el analisis resuelve "lo que
            // apunta su primer argumento" con points-to alli donde se llama.
            //
            // `declared` solo si alguien dijo algo.  Al ser una DESCRIPCION
            // COMPLETA -- lo que no se escribe, no ocurre --, marcarla sin que
            // nadie haya escrito nada afirmaria que la funcion es inofensiva
            // por el mero hecho de existir.
            {
                ir::IrNativeEffects fx;
                for (size_t pi = 0; pi < efd->params.size() && pi < 32; ++pi) {
                    const ast::ParamDecl *p = efd->params[pi].get();
                    if (!p || p->dir == ParamDir::None) continue;
                    fx.declared = true;
                    const uint32_t bit = 1u << (uint32_t)pi;
                    if (p->dir == ParamDir::In || p->dir == ParamDir::InOut)
                        fx.reads_pointee |= bit;
                    if (p->dir == ParamDir::Out || p->dir == ParamDir::InOut)
                        fx.writes_pointee |= bit;
                }
                // Y los ejes que hablan de la funcion entera, ya resueltos por
                // el parser contra el objetivo activo.  `any` es lo que
                // distingue "dijeron que no hace nada" de "nadie dijo nada":
                // sin el, un `@pure` a secas -- que no pone ningun eje -- no se
                // notaria, y es justo la forma mas util de describir una nativa
                // inofensiva.
                if (efd->effects.any) {
                    fx.declared = true;
                    fx.io = efd->effects.io;
                    fx.may_throw = efd->effects.may_throw;
                    fx.may_panic = efd->effects.may_panic;
                    fx.allocates = efd->effects.allocates;
                    fx.reads_global = efd->effects.reads_global;
                    fx.writes_global = efd->effects.writes_global;
                    fx.nondeterministic = efd->effects.nondeterministic;
                    fx.may_block = efd->effects.may_block;
                    fx.may_trap = efd->effects.may_trap;
                    fx.throw_origin = efd->effects.throw_origin;
                    fx.panic_origin = efd->effects.panic_origin;
                    fx.trap_kinds = efd->effects.trap_kinds;
                    fx.reads_world = efd->effects.reads_world;
                    fx.writes_world = efd->effects.writes_world;
                    fx.returns_fresh = efd->effects.returns_fresh;
                    fx.frees_pointee = efd->effects.frees_pointee;
                }
                if (fx.declared) extern_effects_by_fn_name_[efd->name] = fx;
            }
        }
    }

    // Pase 1b: registrar el retorno de las funciones IMPORTADAS de otro
    // modulo.  No estan en @c mod_.decls (el modulo actual solo ve su propio
    // AST); llegan como @c FunctionSig inyectada desde el .vxi, con su Type
    // ya reconstruido por @c resolve_type_string.  Sin este pase el caller
    // no sabria que una fn cross-modulo devuelve Optional/Result/enum/... y
    // omitiria el retbuf hidden de la convencion SRET: el callee escribiria
    // en lo que hubiera en el registro del primer argumento (el primer arg
    // real) -> escritura a puntero basura -> SEGV.  Se usa el MISMO helper
    // que las locales, asi que caller y callee no pueden divergir.
    for (const auto &kv : tc_.function_sigs_by_name()) {
        const std::string &fname = kv.first;
        // Las locales (y las extern declaradas aqui) ya estan registradas
        // arriba con su AST, que es la fuente mas precisa.
        if (fn_return_types_.find(fname) != fn_return_types_.end()) continue;
        const FunctionSig *sig = tc_.function_sig_by_name(fname);
        if (!sig) continue;
        // FFI nativo: convencion CALLN propia (valor en R0), nunca SRET.
        if (!sig->extern_lib.empty()) continue;
        register_fn_ret_info(fname, sig->return_type, /*is_async=*/false);
    }

    // Pase 2: bajar cada funcion.
    //
    // ORDEN IMPORTANTE: el emisor IR (ir_emitter.cpp::ir_emit_module)
    // marca como "entry point" la PRIMERA funcion del modulo, lo que
    // hace que esa funcion termine con 'hlt' (detiene la VM) en lugar
    // de 'ret'.  Por tanto si dejamos las funciones en el orden en que
    // aparecen en el .vx, una funcion como 'factorial' que se declara
    // antes de 'main' acabaria como entry point y la primera llamada
    // recursiva detendria la VM.  Solucion: bajamos 'main' primero
    // (si existe), luego el resto en orden de declaracion.
    ast::FunctionDecl *main_decl = nullptr;
    for (auto &decl : mod_.decls) {
        if (decl && decl->kind == ast::NodeKind::FunctionDecl) {
            auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
            if (fd->name == "main") {
                main_decl = fd;
                break;
            }
        }
    }
    // Los `@Hook` se recogen ANTES de bajar ninguna funcion: el gancho puede
    // estar escrito despues de las funciones que instrumenta, y el orden en el
    // fichero no puede decidir que se mide.
    collect_hook_providers();
    lower_global_storage(out_module);

    us_previo =
        static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
                              RelojBajada::now() - marca_run)
                              .count());
    const auto marca_fns = RelojBajada::now();

    if (main_decl) {
        lower_function(main_decl, out_module);
        ++n_bajadas;
    }

    for (auto &decl : mod_.decls) {
        if (!decl) continue;
        if (decl->kind == ast::NodeKind::FunctionDecl) {
            auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
            if (fd == main_decl) continue; // ya bajada
            ++n_bajadas;
            if (fd->is_async) {
                lower_async_function(fd, out_module);
            } else {
                lower_function(fd, out_module);
            }
        } else if (decl->kind == ast::NodeKind::GlobalVarDecl) {
            // Las variables globales con storage real no estan soportadas
            // en el frontend Vesta actual.  Pero `const T NAME = lit;` SI
            // funciona porque @c lower_ident las inlinea como CONST en
            // cada uso (no necesitan storage).  Solo avisamos para las
            // globales NO-const o las que tienen inicializador no-literal
            // (que efectivamente se ignoran).
            auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
            /* Una global `const` con inicializador LITERAL no necesita
             * almacenamiento: cada uso la inlina.  Lo que cuenta como
             * literal son las tres formas del lenguaje -- entero, coma
             * flotante y cadena -- mas el signo delante de las dos
             * numericas.
             *
             * El flotante FALTABA, y el modo de fallar era el peor: la
             * declaracion compilaba con un aviso que decia que se
             * ignoraba, y el error salia mucho despues, en el primer USO,
             * acusando al nombre de no estar resuelto. */
            auto es_literal_inlinable = [](const ast::Expr *x) {
                return x && (x->kind == ast::NodeKind::IntLitExpr ||
                             x->kind == ast::NodeKind::FloatLitExpr ||
                             x->kind == ast::NodeKind::StringLitExpr);
            };
            bool literal_const = false;
            if (gv->is_const && gv->init) {
                literal_const = es_literal_inlinable(gv->init.get());
                if (!literal_const &&
                    gv->init->kind == ast::NodeKind::UnaryExpr) {
                    auto *u = static_cast<ast::UnaryExpr *>(gv->init.get());
                    literal_const =
                        u->op == ast::UnOp::Neg && u->operand &&
                        u->operand->kind != ast::NodeKind::StringLitExpr &&
                        es_literal_inlinable(u->operand.get());
                }
            }
            /* A.38/A.39: `comptime const` y `static_assert` (que se
             * envuelve como GlobalVarDecl dummy con type=void) no
             * tienen storage runtime y NO necesitan warning. */
            bool is_comptime_silent =
                gv->is_comptime ||
                (gv->type &&
                 gv->type->kind == ast::NodeKind::PrimitiveTypeNode &&
                 static_cast<ast::PrimitiveTypeNode *>(gv->type.get())->prim ==
                     PrimitiveKind::VOID);
            // L2.2: globales runtime no-const obtienen storage real
            // via slot en static_data inicializado por __module_init.
            // Solo se reserva si tiene tipo basico soportado: STRING o
            // enteros/floats que caben en 8 bytes.
            bool runtime_global_supported = false;
            // Global array nativo T[N]: ya tiene slot (pre-pase); soportado.
            if (!gv->is_const && !is_comptime_silent && gv->type &&
                gv->type->kind == ast::NodeKind::ArrayTypeNode &&
                vx_global_array_bytes(gv->type.get(), tc_) > 0) {
                runtime_global_supported = true;
            }
            // Tipo primitivo directo O un newtype (typedef-new) que resuelve a
            // un primitivo de <=8 bytes (p.ej. `uintptr` -> u64).  Resolvemos
            // via resolve_type_node para que los tipos semanticos de std.types
            // tengan storage global igual que su underlying.
            if (!gv->is_const && !is_comptime_silent && gv->type &&
                (gv->type->kind == ast::NodeKind::PrimitiveTypeNode ||
                 gv->type->kind == ast::NodeKind::NamedTypeNode)) {
                PrimitiveKind gpk =
                    (gv->type->kind == ast::NodeKind::PrimitiveTypeNode)
                        ? static_cast<ast::PrimitiveTypeNode *>(gv->type.get())
                              ->prim
                        : tc_.resolve_type_node(gv->type.get()).kind;
                // Global de tipo overlay: su valor runtime es un puntero (8
                // bytes)
                // -> tratarlo como PTR (slot de 8 bytes, init por asignacion).
                if (gpk == PrimitiveKind::STRUCT &&
                    gv->type->kind == ast::NodeKind::NamedTypeNode) {
                    Type rt = tc_.resolve_type_node(gv->type.get());
                    auto sit = tc_.struct_layouts().find(rt.struct_name);
                    if (sit != tc_.struct_layouts().end() &&
                        sit->second.is_overlay)
                        gpk = PrimitiveKind::PTR;
                }
                switch (gpk) {
                case PrimitiveKind::STRING:
                case PrimitiveKind::I8:
                case PrimitiveKind::I16:
                case PrimitiveKind::I32:
                case PrimitiveKind::I64:
                case PrimitiveKind::U8:
                case PrimitiveKind::U16:
                case PrimitiveKind::U32:
                case PrimitiveKind::U64:
                case PrimitiveKind::F32:
                case PrimitiveKind::F64:
                case PrimitiveKind::BOOL:
                case PrimitiveKind::CHAR:
                case PrimitiveKind::PTR:
                    runtime_global_supported = true;
                    {
                        uint64_t slot =
                            get_or_create_runtime_global_slot(gv->name);
                        // AOT/bare: __module_init NO se ejecuta (el entry es
                        // main/kmain directo).  Para que el global tenga su
                        // valor inicial sin depender de __module_init, si el
                        // init es una constante la grabamos DIRECTAMENTE en los
                        // bytes de .data.  El STORE de __module_init (VM/JIT)
                        // re-escribe el mismo valor; en AOT esos bytes son la
                        // unica fuente.  (Inits no-constantes -- p.ej. llamadas
                        // -- siguen necesitando __module_init: no soportado en
                        // AOT puro, pero raro en codigo bare.)
                        uint64_t cval = 0;
                        bool have = false;
                        // Un `f32 g = 0.5` guarda los bits de un binary32 (4
                        // bytes), NO los de un double: el LOAD lee 4 bytes y
                        // con los bits de f64 solo veria el resto de la
                        // mantisa (0.5 en f64 tiene los 4 bytes bajos a cero
                        // -> el global salia 0).
                        const bool g_is_f32 = (gpk == PrimitiveKind::F32);
                        const ast::Expr *ie = gv->init.get();
                        if (ie) {
                            switch (ie->kind) {
                            case ast::NodeKind::IntLitExpr:
                                cval = static_cast<const ast::IntLitExpr *>(ie)
                                           ->value;
                                have = true;
                                break;
                            case ast::NodeKind::BoolLitExpr:
                                cval = static_cast<const ast::BoolLitExpr *>(ie)
                                               ->value
                                           ? 1u
                                           : 0u;
                                have = true;
                                break;
                            case ast::NodeKind::CharLitExpr:
                                cval = static_cast<const ast::CharLitExpr *>(ie)
                                           ->codepoint;
                                have = true;
                                break;
                            case ast::NodeKind::FloatLitExpr: {
                                const double d =
                                    static_cast<const ast::FloatLitExpr *>(ie)
                                        ->value;
                                cval = float_bits_from_double(d, g_is_f32);
                                have = true;
                                break;
                            }
                            case ast::NodeKind::UnaryExpr: {
                                auto *u =
                                    static_cast<const ast::UnaryExpr *>(ie);
                                if (u->op == ast::UnOp::Neg && u->operand &&
                                    u->operand->kind ==
                                        ast::NodeKind::IntLitExpr) {
                                    cval =
                                        (uint64_t)(-(int64_t)static_cast<
                                                        const ast::IntLitExpr
                                                            *>(u->operand.get())
                                                        ->value);
                                    have = true;
                                } else if (u->op == ast::UnOp::Neg &&
                                           u->operand &&
                                           u->operand->kind ==
                                               ast::NodeKind::FloatLitExpr) {
                                    const double d =
                                        -static_cast<const ast::FloatLitExpr *>(
                                             u->operand.get())
                                             ->value;
                                    cval = float_bits_from_double(d, g_is_f32);
                                    have = true;
                                }
                                break;
                            }
                            default: break;
                            }
                        }
                        if (have &&
                            slot < out_mod_->static_data.entries.size()) {
                            uint32_t off =
                                out_mod_->static_data.entries[slot].byte_offset;
                            for (int k = 0; k < 8; ++k)
                                out_mod_->static_data.bytes[off + (size_t)k] =
                                    (uint8_t)((cval >> (8 * k)) & 0xFF);
                        }
                    }
                    break;
                default: break;
                }
            }
            if (!literal_const && !is_comptime_silent &&
                !runtime_global_supported) {
                diags_.warning(decl->loc,
                               "variable global no-const ignorada (sin storage "
                               "real en este frontend)");
            }
        }
    }

    // Bajar metodos de clases al final.  Vienen DESPUES de las
    // funciones top-level para no tomar la posicion de "entry point"
    // del emisor IR (que termina la primera funcion con hlt).  Cada
    // metodo se compila como IrFunction con nombre <Class>__<method>
    // y un primer parametro implicito 'this' de tipo PTR.
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::ClassDecl) continue;
        auto *cd = static_cast<ast::ClassDecl *>(decl.get());
        lower_class_methods(cd, out_module);
    }

    // Bajar metodos de structs (value-types, dispatch estatico).  Cada
    // uno se compila como funcion libre <Struct>__<metodo> con un
    // primer parametro implicito 'this' (PTR a la direccion del struct).
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::StructDecl) continue;
        auto *sd = static_cast<ast::StructDecl *>(decl.get());
        lower_struct_methods(sd, out_module);
    }

    // NS.6-ext: metodos de extension / impl (funciones libres <clave>__metodo).
    lower_extension_methods(out_module);

    // Generar funciones auxiliares de POO:
    //  - __new_<X>(args) por cada clase: encapsula findclass+newobj+ctor.
    //  - __module_init(): registra todas las clases via defclass+...
    // Estas se añaden al modulo despues de las funciones de usuario;
    // el prologo de main incluye una llamada a __module_init para
    // garantizar que las clases esten registradas antes del cuerpo.
    generate_new_helpers(out_module);
    // Thunks para `&extern` usado como cfn (se rellenan durante el lowering).
    generate_extern_cfn_thunks(out_module);
    // Los ayudantes que liberan la ranura de un campo unique al reasignarlo,
    // uno
    //  AOT.2.b: en POO nativa no hay ClassRegistry -> no se genera
    // __module_init (las clases son layout estatico compile-time).
    if (!native_poo_) generate_module_init_function(out_module);

    // Exportar metadata POO al @c IrModule para que el port transpiler
    // (port-C, etc.) emita codigo POO eficiente sin reconstruir las
    // clases desde @c __module_init.  Llamar tras lower_class_methods
    // para que los @c IrMethod::ir_fn_name apunten a IrFunctions ya
    // emitidas en @c out_module.functions.
    export_classes_to_ir(out_module);
    // Y las vistas `@overlay`, por la misma razon y con el mismo criterio: es
    // lo que el comprobador de tipos SABE de ellas, puesto donde se puede
    // preguntar.
    export_overlays_to_ir(out_module);

    // volcar las funciones sinteticas de spawn DESPUES de las
    // de usuario y POO.  Asi main sigue siendo la primera funcion del
    // modulo (entry point con hlt) y los helpers de spawn quedan al
    // final como funciones normales (cierran con ret, pero el body
    // siempre incluye un hlt explicito antes del fin del bloque).
    for (auto &h : pending_spawn_helpers_) {
        propagate_is_gc_object_through_phis(h);
        out_module.add_function(std::move(h));
    }
    pending_spawn_helpers_.clear();

    // Bloques `bytes name { db/dw/dd/dq/times }` (datos crudos NASM, AOT):
    // se internan como entradas de static_data en su @section (default
    // .rodata) y se marcan FORCE_EMIT para que el emisor AOT las coloque
    // aunque ningun codigo las referencie (firmas, tablas, boot sectors).
    // NON_DEDUP evita que el dedup post-merge colapse dos bloques con los
    // mismos bytes en secciones distintas.
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::BytesDecl) continue;
        auto *bd = static_cast<ast::BytesDecl *>(decl.get());

        // Bloque `asm`: ensamblar el cuerpo NASM via Keystone a la bitness
        // indicada (@bits) y colocarlo en su seccion como datos crudos.
        // Las directivas $/$$/times NO las soporta Keystone; el usuario usa
        // un bloque `bytes` con @at/times para padding/firma.
        if (bd->is_asm) {
            std::vector<uint8_t> asm_bytes;
            std::string aerr;
            // Mini-ensamblador: instrucciones via Keystone + db/dw/dd/dq/
            // times/$/$$ propios, intercalados en orden (estilo NASM).  Los
            // call/jmp a un simbolo (funcion Vesta) salen como sym_refs REL32.
            std::vector<ir::IrModule::StaticDataMeta::SymRef> asm_syms;
            if (!asmblk_assemble(bd->asm_body, bd->asm_bits, asm_bytes, aerr,
                                 &asm_syms)) {
                diags_.error(bd->loc, "bloque asm '" + bd->name + "': " + aerr);
                continue;
            }
            const size_t idx =
                out_module.static_data.push_back(std::move(asm_bytes));
            auto &m = out_module.static_data.meta_at(idx);
            m.section_name =
                bd->attr_section.empty() ? ".text" : bd->attr_section;
            m.section_perms = bd->attr_section_perms;
            m.section_at = bd->attr_at;
            m.section_order = bd->attr_order;
            m.sym_refs = std::move(asm_syms); // call/jmp -> funcion Vesta
            //  NR / dev-OS: exportar el nombre del bloque como simbolo
            // resoluble por otros bloques (cross-block jmp/call/dd).
            m.symbol_name = bd->name;
            m.flags |= ir::IrModule::SD_FLAG_FORCE_EMIT |
                       ir::IrModule::SD_FLAG_NON_DEDUP;
            continue;
        }

        // Reconstruir el blob resolviendo los operandos identificador.  Un
        // identificador puede ser:
        //   (a) comptime const entero -> literal del ancho de la directiva.
        //   (b) comptime array        -> sus elementos (cada uno del ancho).
        //   (c) simbolo de funcion     -> reloc ABS64 (requiere dq=8).
        // Los sym_refs vienen en orden de offset creciente (el parser los
        // añade segun avanza); reconstruimos de izquierda a derecha.
        const auto &ccv = tc_.comptime_const_values();
        std::vector<uint8_t> rebuilt;
        std::vector<ir::IrModule::StaticDataMeta::SymRef> kept;
        rebuilt.reserve(bd->data.size());
        size_t cursor = 0;
        bool ok = true;
        for (const auto &sr : bd->sym_refs) {
            if (sr.offset > bd->data.size()) {
                ok = false;
                break;
            }
            // Bytes literales que preceden a este operando.
            rebuilt.insert(rebuilt.end(), bd->data.begin() + cursor,
                           bd->data.begin() + sr.offset);
            auto cit = ccv.find(sr.sym);
            if (cit != ccv.end()) {
                const auto &cc = cit->second;
                if (cc.is_str || cc.is_struct || cc.is_type) {
                    diags_.error(
                        bd->loc,
                        "bytes: comptime '" + sr.sym +
                            "' no es entero ni array; no es embebible");
                    ok = false;
                    break;
                }
                if (cc.is_array) {
                    for (const auto &ev : cc.array_vals) {
                        if (!ev || ev->is_str || ev->is_array ||
                            ev->is_struct) {
                            diags_.error(bd->loc,
                                         "bytes: el array comptime '" + sr.sym +
                                             "' tiene elementos no enteros");
                            ok = false;
                            break;
                        }
                        const uint64_t v = (uint64_t)ev->value;
                        for (int i = 0; i < sr.width; ++i)
                            rebuilt.push_back((uint8_t)(v >> (8 * i)));
                    }
                    if (!ok) break;
                } else {
                    const uint64_t v = (uint64_t)cc.value;
                    for (int i = 0; i < sr.width; ++i)
                        rebuilt.push_back((uint8_t)(v >> (8 * i)));
                }
            } else {
                // Simbolo (funcion u otro bloque) -> reloc absoluta.  Se
                // admite `dq` (ABS64) y `dd` (ABS32): un dev-OS pone la base
                // de un GDTR / un puntero far de 32 bits con `dd gdt`, donde
                // la direccion cabe en 32 bits (binario plano bajo 4GB).
                if (sr.width != 8 && sr.width != 4) {
                    diags_.error(
                        bd->loc,
                        "bytes: la referencia al simbolo '" + sr.sym +
                            "' requiere 'dd' (32 bits) o 'dq' (64 bits)");
                    ok = false;
                    break;
                }
                ir::IrModule::StaticDataMeta::SymRef d;
                d.offset = (uint32_t)rebuilt.size(); // offset en el blob nuevo
                d.sym = sr.sym;
                d.width = sr.width; // 4 -> ABS32, 8 -> ABS64
                d.is_rel = sr.is_rel ? 1 : 0;
                kept.push_back(std::move(d));
                for (int i = 0; i < sr.width; ++i)
                    rebuilt.push_back(0); // placeholder
            }
            cursor =
                (size_t)sr.offset + sr.width; // saltar el placeholder original
        }
        if (!ok) continue; // error ya emitido; saltar este bloque
        // Resto de bytes literales tras el ultimo operando.
        if (cursor <= bd->data.size())
            rebuilt.insert(rebuilt.end(), bd->data.begin() + cursor,
                           bd->data.end());

        const size_t idx = out_module.static_data.push_back(std::move(rebuilt));
        auto &m = out_module.static_data.meta_at(idx);
        m.section_name =
            bd->attr_section.empty() ? ".rodata" : bd->attr_section;
        m.section_perms = bd->attr_section_perms;
        m.section_at = bd->attr_at;
        m.section_order = bd->attr_order;
        //  NR / dev-OS: exportar el nombre del bloque bytes como simbolo
        // resoluble cross-block (p.ej. `lgdt [gdtr]` / `dd gdt` desde otro).
        m.symbol_name = bd->name;
        m.flags |=
            ir::IrModule::SD_FLAG_FORCE_EMIT | ir::IrModule::SD_FLAG_NON_DEDUP;
        // Solo las refs de funcion sobreviven como relocs (las comptime
        // consts ya se materializaron como bytes).
        m.sym_refs = std::move(kept);
    }

    emit_startup_wiring(out_module);

    if (medir_bajada) {
        const long us_total = static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                RelojBajada::now() - marca_run)
                .count());
        const long us_fns = static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                RelojBajada::now() - marca_fns)
                .count());
        std::cerr << "[bajada] " << n_bajadas << " funciones | preparar "
                  << us_previo << " us | bajar+resto " << us_fns
                  << " us | total " << us_total << " us\n";
    }
    // Ya se sabe a que llego cada `@Hook`: uno que no alcanzo nada se dice
    // AQUI, no al recogerlo -- al recogerlo todavia no hay a que compararlo.
    warn_unreached_hooks();
    return diags_.error_count() == initial_errors;
}

void Lowering::lower_function(ast::FunctionDecl *fd, ir::IrModule &out) {
    // Bug fix 2026-05-23: forward declarations no tienen body -- skip.
    if (fd->is_forward_decl || !fd->body) return;
    // Cross-module: una comptime/macro fn re-parseada de un dep NO se re-baja
    // aqui (el dep ya bajo su `__macro_<X>` + helpers, que el importer mergea).
    // Solo el AST se conserva para AST-eval al invocarla.
    if (fd->is_imported_comptime) return;
    // Templates genericos (con type_params) y especializaciones (#7) se
    // omiten: sus monomorphizaciones concretas (que SI aparecen en
    // mod_.decls) se bajan normalmente.
    if (!fd->type_params.empty() || fd->is_specialization) return;
    /* A.39: comptime fn (no-macro) NO se baja a IR.  Su body solo
     * se evalua en compile-time cuando es invocada desde un contexto
     * comptime.
     *
     *  MC.1 (A.43.22): @Macro bodies SI se lowean al IR (con
     * nombre `__macro_<original>`) cuando el body es lowerable.
     * Esto valida que la pipeline IR -> bytecode soporta el codigo
     * del macro; futuros sprints MC.2+ ejecutan ese bytecode via
     * una ComptimeVM para acelerar la metaprogramacion ~10-1000x.
     * Por ahora el IR queda en el modulo como dead code; el call
     * site del macro sigue usando el evaluator AST. */
    /* F1: una `comptime fn` (no-macro) con inline asm se baja a IR y se
     * ejecuta en el ComptimeVM (JIT + interp fallback).  Funciona en .velb
     * (interp/JIT) y en AOT: ambos hacen el two- que compila el codigo
     * comptime a un `.velb` cacheado y lo carga, asi que los call sites
     * comptime invocan la VM y el valor se pliega a constante. */
    const bool is_vm_comptime_fn =
        fd->is_comptime && !fd->is_macro && comptime_fn_needs_vm(tc_, fd);
    /* Force-lower: una comptime fn (no-macro) que un @Macro lowereable
     * referencia (recolectada en el pre-pase de run()) SI se baja, como fn
     * runtime normal (nombre plano `fd->name`), para que el `callvm code.<X>`
     * del macro resuelva. */
    const bool is_force_lowered_comptime =
        fd->is_comptime && !fd->is_macro &&
        comptime_fns_to_force_lower_.count(fd->name) != 0;
    if (fd->is_comptime && !fd->is_macro) {
        /* comptime fn (no-macro): por defecto NO se baja (se evalua en
         * compile-time y se elide).  Solo-LSP: con emit_comptime_fns_ la
         * bajamos como funcion normal para poder inspeccionar su codegen
         * (JIT/AOT/bytecode del hover).  No pasa por el setup de macro.
         * F1: si usa asm, SI se baja (para ejecutar en el ComptimeVM).
         * Force-lower: si un macro la referencia, tambien se baja. */
        if (!emit_comptime_fns_ && !is_vm_comptime_fn &&
            !is_force_lowered_comptime)
            return;
    } else if (fd->is_comptime) {
        /* @Macro con un param `expr`: el parser tipa `expr` como STRING
         * (captura el texto crudo del call site como StringLitExpr).  Es
         * VM-evaluable como cualquier macro con param string -> se baja a
         * `__macro_<X>` y corre en la ComptimeVM (interp/JIT), marshalando el
         * texto como StringObject.  El unico caso que NO puede ir a la VM es el
         * FORWARDING del expr a un helper expr-capture
         * (`source(e)`/`inject(e)`), donde el texto debe re-capturarse en el
         * sitio del helper: esos SI se dejan a AST-eval.  (Antes se forzaba
         * AST-eval para TODO expr-param macro; el usuario exige "nada de
         * AST-eval, todo interp/JIT".) */
        bool has_expr_param = false;
        for (const auto &p : fd->params)
            if (p && p->is_expr_capture) {
                has_expr_param = true;
                break;
            }
        if (has_expr_param &&
            macro_body_forwards_expr_capture(tc_, fd->body.get())) {
            ++macro_skipped_count_;
            macro_skip_reasons_.emplace_back(
                fd->name,
                "forwarding de `expr` a helper expr-capture (AST-eval)");
            return;
        }
        /* @Macro: intentar lowear el body al IR.  Si contiene
         * caracteristicas no soportadas todavia (introspect,
         * comptime var, builtins comptime-only), saltar limpiamente
         * y dejar que el evaluator AST haga el trabajo.
         *
         * Activamos el contexto force-lower para que las llamadas a comptime
         * fns lowereables NO se rechacen (se bajaran junto al macro). */
        set_macro_force_lower(&comptime_fns_to_force_lower_);
        std::unordered_set<std::string> ml_visiting;
        set_macro_visiting(&ml_visiting);
        const std::string reason =
            macro_body_unsupported_reason(tc_, fd->body.get());
        set_macro_force_lower(nullptr);
        set_macro_visiting(nullptr);
        if (!reason.empty()) {
            /* No soportado -- fallback silencioso al AST eval.
             * Capturamos el reason para diagnostico via
             * VESTA_MC_VERBOSE (el usuario lo ve como
             * "[mc-lower] M_xxx: AST-only (usa Y)"). */
            ++macro_skipped_count_;
            macro_skip_reasons_.emplace_back(fd->name, reason);
            return;
        }
        /* Pre-pase de annotation: los macros no pasan por
         * `check_functions` asi que los IdentExpr en el body tienen
         * result_type=VOID.  Anotamos los IdentExpr que matcheen
         * params del macro para que `lower_binary` detecte el caso
         * `code == "OK"` con `code: string` y emita STRCMP runtime.
         *
         * Bug en demo 162: comparaciones de string dentro del body
         * del macro emitian `cmpjmp` directo sobre los handles GC
         * sin invocar STRMAKE/STRCMP -> resultados incorrectos. */
        std::unordered_map<std::string, Type> macro_param_types;
        for (auto &p : fd->params) {
            if (p && p->type) {
                macro_param_types[p->name] =
                    tc_.resolve_type_node(p->type.get());
            }
        }
        if (!macro_param_types.empty()) {
            annotate_macro_param_idents(fd->body.get(), macro_param_types);
        }
        /* Continuar al lowering normal con nombre prefijado. */
    }
    /*  MC.17.1: setear flag para que lower_var_decl trate
     * `comptime var/const` LOCALES como vars runtime regulares.
     * Reset al salir de la funcion. */
    const bool prev_is_macro = current_fn_is_macro_;
    /* P1: fn-VM comparte modo macro. */
    current_fn_is_macro_ =
        (fd->is_comptime && fd->is_macro) || is_vm_comptime_fn;
    struct ScopeGuard {
        bool *flag;
        bool saved;

        ~ScopeGuard() { *flag = saved; }
    } macro_flag_guard{&current_fn_is_macro_, prev_is_macro};

    ir::IrFunction fn;
    /*  MC.1: nombre prefijado para macros lowered al IR.
     * Asi no colisionan con funciones runtime y son identificables
     * por el TypeChecker para invocacion desde ComptimeVM (MC.2). */
    if ((fd->is_macro && fd->is_comptime) || is_vm_comptime_fn) {
        /* @Macro, o comptime fn con asm (F1): nombre prefijado + registro en
         * el ComptimeRuntime para invocacion via VM.  El prefijo `__macro_`
         * identifica "codigo comptime lowered" (macro o fn). */
        fn.name = "__macro_" + fd->name;
        fn.is_macro_compiled = true;
        ++macro_lowered_count_;
        /* Registrar el nombre en el ComptimeRuntime para que el chequeo de
         * tipos sepa que el macro EXISTE y pueda intentar invocarlo mas
         * adelante.  La direccion todavia no se sabe -- aqui no hay bytecode --
         * asi que va el centinela: `0` no vale como marcador porque es una
         * direccion legitima (la primera funcion del artefacto vive ahi). */
        const_cast<TypeChecker &>(tc_).comptime_runtime().register_macro(
            fn.name, ComptimeRuntime::kPcUnresolved);
    } else {
        fn.name = fd->name;
    }
    // Igual que con los metodos: el vinculo se anota donde se crea el nombre.
    // Sin esto, un fallo dentro de una funcion libre salia con el nombre a
    // secas
    // -- sin firma, sin fichero -- porque el mapa del artefacto no la tenia.
    note_emitted_function(fn.name, fd->name);

    // @fp(strict|fast): politica de contraccion FMA de la funcion.  El pase
    // ir_pass_fuse_fma solo contrae si fn.fp_contract; @fp(strict) -> false.
    fn.fp_contract = fd->fp_contract;

    // AOT 2b (dev OS): seccion de salida del codigo + permisos.  Metadata
    // pura para el codegen AOT; el interp/JIT la ignoran.
    fn.section = fd->attr_section;
    fn.section_perms = fd->attr_section_perms;
    fn.section_at = fd->attr_at;
    fn.section_order = fd->attr_order;
    //  NR: @Naked -- el codegen suprime prologo/epilogo/ret.
    fn.is_naked = fd->is_naked;
    fn.no_idiom = fd->is_no_idiom;

    /* Hasta donde llega lo que se puede afirmar de ella.  De una funcion
     * privada el modulo tiene TODOS los sitios de llamada, asi que lo que
     * aportan es todo lo que le llega; de una publica puede llamarla cualquiera
     * desde otro sitio, y entonces no haberlo visto no es que no exista. */
    fn.is_public = fd->is_public;

    // Subsistema de coste (modo --analyze): propagar el contrato
    // @complexity del AST al IR.  Metadata pura -- el codegen la ignora;
    // solo la consume el analizador estatico analyze::bigo.
    fn.complexity_expr = fd->complexity_expr;
    fn.complexity_vars = fd->complexity_vars;
    fn.complexity_partial_pre = fd->complexity_partial_pre;
    fn.complexity_partial_post = fd->complexity_partial_post;
    fn.complexity_total_pre = fd->complexity_total_pre;
    fn.complexity_total_post = fd->complexity_total_post;
    // Contratos de huella (recurso/efecto): metadata para la verificacion.

    // Tipo de retorno.  Aceptamos tipos primitivos directamente o
    // pasamos por resolve_type_node para PointerTypeNode/ArrayTypeNode
    // (mapeados a IrType::PTR via ir_type_from_primitive).
    Type sem_ret = fd->return_type
                       ? tc_.resolve_type_node(fd->return_type.get())
                       : Type{PrimitiveKind::VOID};
    // sret: si la funcion declara devolver Optional<T>,
    // Result<V,E> o un enum declarado por usuario, internamente la
    // convertimos en void + un parametro hidden retbuf:ptr al inicio.
    // El callee escribe el resultado en el buffer del caller, evitando
    // heap allocation y leaks.
    const auto &elays_check = tc_.enum_layouts();
    const bool sret_enum =
        sem_ret.kind == PrimitiveKind::STRUCT &&
        elays_check.find(sem_ret.struct_name) != elays_check.end();
    // (gap O): SRET para funciones que retornan FUNCTION.  El
    // slot del function value tiene 16 bytes (fn_addr + env_addr).
    const bool sret_function = (sem_ret.kind == PrimitiveKind::FUNCTION);
    // Smart pointers: SRET de 8 bytes para `unique<T>` / `shared<T>`.
    const bool sret_smartptr = (sem_ret.kind == PrimitiveKind::UNIQUE_PTR ||
                                sem_ret.kind == PrimitiveKind::SHARED_PTR);
    // Vesta Embed (native_poo_): `string` value-type de 24 bytes -> SRET.
    const bool sret_str_value =
        (native_poo_ && sem_ret.kind == PrimitiveKind::STRING);
    // STRUCT por valor -> SRET.  Era el UNICO agregado que no lo usaba, y por
    // eso estaba roto: `return r` devolvia un PUNTERO al buffer de `r`, que
    // vive en el frame del callee -- muerto tras el `ret`.  El caller leia esa
    // memoria despues, y lo que hubiera pasado por la pila entre medias (el
    // propio restore de registros del call) la pisaba.  Funcionaba de milagro
    // cuando el caller copiaba antes de tocar la pila; con un `println` de por
    // medio, el struct llegaba a ceros (medido).
    //
    // Un `@overlay struct` NO entra: su valor ES un puntero de 8 bytes a
    // memoria ajena, asi que devolverlo por registro es correcto.
    const auto &slays_check = tc_.struct_layouts();
    auto it_slay_ret = slays_check.find(sem_ret.struct_name);
    const bool sret_struct = sem_ret.kind == PrimitiveKind::STRUCT &&
                             !sret_enum && it_slay_ret != slays_check.end() &&
                             !it_slay_ret->second.is_overlay;
    /* Si hace falta buffer, cuanto mide y donde vive lo contesta un solo
     * sitio, el mismo que consulta quien llama.  Las banderas de arriba se
     * quedan porque cada una dispara ademas otra cosa (el entorno de un
     * lambda en el monton, la promocion de un literal a cadena), pero ya no
     * deciden esto. */
    const SretInfo sret_i = sret_info(sem_ret);
    const bool sret = sret_i.uses_buffer;
    if (fd->return_type &&
        fd->return_type->kind == ast::NodeKind::PrimitiveTypeNode && !sret) {
        auto *pt = static_cast<ast::PrimitiveTypeNode *>(fd->return_type.get());
        fn.ret_type = ir_type_from_primitive(pt->prim);
    } else if (fd->return_type) {
        if (sret) {
            fn.ret_type = ir::IrType::VOID;
        } else {
            fn.ret_type = (sem_ret.kind != PrimitiveKind::COUNT &&
                           sem_ret.kind != PrimitiveKind::VOID)
                              ? ir_type_from_primitive(sem_ret.kind)
                              : ir::IrType::VOID;
        }
    } else {
        fn.ret_type = ir::IrType::VOID;
    }

    // Parametros: cada uno es un IrValue con is_param=true.
    std::vector<std::pair<std::string, ir::IrValueId>> param_bindings;
    param_bindings.reserve(fd->params.size() + (sret ? 1 : 0));
    // ABI custom por funcion (register("rXX") en un param): materializamos
    // param_abi_regs SOLO si al menos un param lo declara -> alineado con
    // fn.params (retbuf/vacount = "" = ABI estandar).  push_abi() lo mantiene
    // en sincronia con cada fn.params.push_back().
    bool has_custom_abi = false;
    for (const auto &pp : fd->params)
        if (pp && !pp->abi_reg.empty()) {
            has_custom_abi = true;
            break;
        }
    auto push_abi = [&](const std::string &r) {
        // Canonicalizar a 64 bits (eax->rax): el prologo del callee
        // (canon_gp_to_mreg) reconoce igual x86-64 y x86-32.  "" (ABI estandar)
        // se mantiene "".
        if (has_custom_abi)
            fn.param_abi_regs.push_back(r.empty() ? std::string()
                                                  : asm_canonical_reg(r));
    };
    // register() en param -> variable register() mutable (desugar tras el
    // entry). El param llega en su registro por la ABI custom (caller+callee);
    // la variable register() reutiliza el modelo de `cas`: STORE inicial = IN,
    // LOAD (return) = OUT read-back -> `register("rax") id; asm{syscall};
    // return id` devuelve rax POST-asm (el resultado), no el valor de entrada.
    struct CustomAbiParam {
        std::string name;
        ir::IrValueId vid;
        std::string reg;
        ir::IrType pt;
    };
    std::vector<CustomAbiParam> custom_abi_params;
    /* Parametros de SALIDA por referencia (`out T x` sobre un valor).  Lo que
     * llega es la DIRECCION de un hueco del llamante, y el cuerpo lo escribe
     * como si fuera una `T`.  Eso es exactamente lo que hace un local cuya
     * direccion se ha tomado, asi que se marcan como tales y `read_local` /
     * `write_local` hacen el resto -- sin ALLOCA, porque la direccion ya
     * viene --.
     *
     * Se guardan y se re-insertan mas abajo por la misma razon que los de ABI
     * custom: `address_taken_locals_` se limpia despues de este punto. */
    std::vector<ByRefParam> by_ref_params;
    // Hidden retbuf param para sret (si aplica): primero en la lista.
    ir::IrValueId v_retbuf = ir::IR_NO_VALUE;
    if (sret) {
        v_retbuf = fn.new_value(ir::IrType::PTR, "%__retbuf");
        fn.values[v_retbuf].is_param = true;
        // BugFix sret-cross-mem (2026-06-04): SOLO marcar host_ptr para
        // SRET de Optional/Result/enum (donde el caller aloca host).
        // Para FUNCTION/smart-ptr el callee tiene su propio manejo y
        // marcarlo host rompe el copia in-place.
        // El value-string (native_poo_) vive en host stack (ALLOCA host)
        // -> su retbuf tambien es host_ptr para que las copias usen `movh`.
        // El retbuf de un agregado vive en host, como el propio agregado
        // (ver lower_var_decl): el `return` copia ahi con `movh`.
        if (sret_i.host_buffer) {
            fn.values[v_retbuf].is_host_ptr = true;
        }
        fn.params.push_back(v_retbuf);
        push_abi(""); // retbuf SRET: ABI estandar (primer arg-reg)
    }
    /* Cuantos parametros llevan ya puestos, para saber la casilla de cada uno.
     * Arranca donde acaba lo que el bajado puso por su cuenta -- un buffer de
     * retorno, que nadie declara --, asi que sigue alineado con `fn.params`. */
    size_t declared_pos = fn.params.size();
    for (const DeclaredParam &d :
         declare_params(fn, fd->params, param_bindings,
                        /*reserved_slots=*/0, &by_ref_params)) {
        /* El registro que cada parametro pidio, en el orden en que quedaron.
         * El contador oculto de un variadico no pide ninguno: va por donde
         * diga la convencion. */
        push_abi(d.decl ? d.decl->abi_reg : std::string());
        if (d.decl && !d.decl->abi_reg.empty())
            custom_abi_params.push_back(
                {d.decl->name, d.value, d.decl->abi_reg, d.type});
        /* El contrato del parametro, al IR.  Se apunta AQUI y no recorriendo el
         * fuente aparte, porque es aqui donde se sabe en que posicion de
         * `fn.params` acabo cada uno: delante puede ir un buffer de retorno, y
         * en medio la cuenta oculta de un variadico, que no los declara nadie y
         * por tanto no tienen contrato que llevar.
         *
         * Las tres formas del lenguaje escriben en el MISMO eje -- son formas
         * de escribir lo mismo, no tres mecanismos --, y lo que las separa es
         * QUIEN responde por la exclusividad: la direccion es un contrato del
         * que llama, el prestamo exclusivo y el dueno unico los demuestra el
         * compilador. */
        /* La posicion REAL de este parametro, contada aqui.
         *
         * No vale `fn.params.size() - 1`: `declare_params` devuelve el vector
         * ya completo, asi que cuando este bucle corre los parametros YA estan
         * todos puestos y ese tamano es el final para todas las vueltas.  Con
         * el, los contratos se escribian todos en la ultima casilla y solo
         * sobrevivia el del ultimo parametro. */
        const size_t pos = declared_pos++;
        if (d.decl != nullptr) {
            ir::IrParamContract c;
            using Claim = ir::IrParamClaim;
            /* Dos niveles de entrada: [0] el puntero que se recibe, [1] lo que
             * apunta.  Casi todo lo que se declara habla del segundo -- "por
             * aqui se lee", "por aqui se escribe" son sobre el CONTENIDO --, y
             * el primero solo lo toca `T* const`. */
            c.levels.resize(2);
            ir::IrParamLevel &ptr = c.levels[0];
            ir::IrParamLevel &pointee = c.levels[1];
            /* La DIRECCION es un contrato del que llama, asi que lo que
             * afirma queda DECLARADO: hay que comprobarlo donde se vea la
             * llamada, y avisar si se incumple.  Y habla de lo APUNTADO, que
             * es lo que dice su propia definicion. */
            switch (d.decl->dir) {
            /* Las tres van con `by_author`: la escribio el programador, asi que
             * hay que COMPROBARSELA en cada sitio de llamada.  Es lo que separa
             * esto de lo que el compilador deriva del tipo, y sin ese eje las
             * dos cosas se publicaban igual. */
            case ParamDir::In:
                pointee.set(Claim::MayRead, false, /*by_author=*/true);
                /* `in` no solo dice que se lee: dice que SOLO se lee.  Negar la
                 * escritura es la mitad util -- sin ella, "no consta que
                 * escriba" y "declarado que no escribe" serian el mismo bit
                 * ausente. */
                pointee.deny(Claim::MayWrite, false, /*by_author=*/true);
                break;
            case ParamDir::Out:
                pointee.set(Claim::MayWrite, false, /*by_author=*/true);
                pointee.set(Claim::ExclusiveCall, false, /*by_author=*/true);
                break;
            case ParamDir::InOut:
                pointee.set(Claim::MayRead, false, /*by_author=*/true);
                pointee.set(Claim::MayWrite, false, /*by_author=*/true);
                pointee.set(Claim::ExclusiveCall, false, /*by_author=*/true);
                break;
            case ParamDir::None: break;
            }
            /* Y lo que dice el TIPO, que no es una alternativa a lo anterior
             * sino otra forma de escribirlo -- y la unica que llega
             * DEMOSTRADA, porque detras hay un comprobador que la hace
             * cumplir. */
            if (d.decl->type) {
                const Type sem = tc_.resolve_type_node(d.decl->type.get());
                switch (sem.kind) {
                case PrimitiveKind::BORROW:
                    pointee.set(Claim::MayRead, true);
                    /* Un prestamo compartido no escribe, y eso lo hace cumplir
                     * el comprobador de prestamos: negado y DEMOSTRADO. */
                    pointee.deny(Claim::MayWrite, true);
                    /* Y mientras dura el prestamo no escribe NADIE MAS: el
                     * comprobador prohibe que coexista un prestamo exclusivo y
                     * que se mute el dueno.  Es justo lo que permite sacar una
                     * lectura de un bucle que contenga llamadas.
                     *
                     * Sin demostrar a proposito: el comprobador razona sobre
                     * NOMBRES dentro de una funcion, no sobre hilos, asi que
                     * otro hilo con el mismo dueno se le escapa.  Como
                     * "apunta ahi pero pudo quedar algo sin ver" sirve para
                     * especular con red; como demostrado autorizaria a quitar
                     * la comprobacion, y ahi un fallo daria otro resultado. */
                    pointee.set(Claim::ImmutableDuringCall, false);
                    break;
                case PrimitiveKind::BORROW_MUT:
                    /* Leer y escribir SI: eso lo hace cumplir el comprobador de
                     * prestamos dentro de la funcion, que es donde vale. */
                    pointee.set(Claim::MayRead, true);
                    pointee.set(Claim::MayWrite, true);
                    /* Y la exclusividad en la llamada NO se afirma todavia,
                     * aunque el tipo parezca darla.
                     *
                     * El comprobador lleva sus prestamos por NOMBRE de variable
                     * (`owners_` va indexado por cadena), asi que dos nombres de
                     * la misma region no chocan y un prestamo tomado DENTRO del
                     * llamado es otra entrada distinta.  Pasar el dueno a otra
                     * funcion que lo vuelve a prestar no lo ve nadie, y entonces
                     * dos `borrow_mut` de la MISMA region llegan a la misma
                     * llamada.
                     *
                     * Que el agujero existe esta COMPROBADO: los dos programas
                     * de arriba compilan sin una queja.  Que hoy produzca un
                     * resultado equivocado NO se ha conseguido reproducir --
                     * con la promesa puesta y con ella quitada, incluso sin
                     * inline, el mismo caso da lo correcto --, asi que esto no
                     * es el arreglo de un fallo medido.
                     *
                     * Asi que se DICE, pero sin demostrar.  El mecanismo sigue
                     * entero -- quien quiera afinar con ella puede -- y el hecho
                     * no miente: sale `inferred`, que en el ASA significa "la
                     * evidencia apunta ahi pero pudo quedar algo sin ver".  Lo
                     * que no se hace es venderla como garantia.
                     *
                     * Y sin `by_author`, que es la otra mitad: esto lo DERIVA el
                     * compilador del tipo, no lo escribio nadie, asi que no hay
                     * ninguna declaracion que ir a comprobar a los sitios de
                     * llamada.
                     *
                     * Pasa a demostrada en cuanto exista quien la verifique: el
                     * prestamo indexado por localizacion abstracta en vez de por
                     * nombre, mas la comprobacion en el sitio de llamada. */
                    pointee.set(Claim::ExclusiveCall, /*is_proven=*/false);
                    break;
                case PrimitiveKind::UNIQUE_PTR:
                    pointee.set(Claim::MayRead, true);
                    pointee.set(Claim::MayWrite, true);
                    /* Aqui SI, y por una razon que no vale para el prestamo:
                     * pasar un `unique<T>` exige moverlo, y mover un dueno
                     * prestado ya lo rechaza el comprobador (VX2034).  El
                     * agujero de arriba es de los duenos que se COPIAN, y este
                     * no se copia. */
                    pointee.set(Claim::ExclusiveCall, true);
                    /* La exclusividad en la EJECUCION -- que no la alcance otro
                     * hilo ni un puntero guardado antes -- no se afirma: nadie
                     * la hace cumplir, y `ptr_of` entrega el puntero crudo sin
                     * consumir el dueno.  Inferirla seria creerla, porque no hay
                     * guarda posible en ejecucion para "nadie mas la alcanza".
                     * Se emitira cuando la alcanzabilidad por hilos sea un hecho
                     * del ASA y la pueda DEMOSTRAR. */
                    break;
                default: break;
                }
                if (d.decl->type->is_nonnull) ptr.set(Claim::NonNull, true);
                /* `const` es POR NIVEL, y el sistema de tipos ya lo modela asi:
                 * `is_const` es de ESTE nivel y el del apuntado vive en su
                 * `pointee`.  `const T*` niega escribir lo APUNTADO; `T* const`
                 * niega escribir el PUNTERO.  Colapsarlos haria inexpresable lo
                 * segundo, que es lo que ya avisa el propio tipo.
                 *
                 * Va DEMOSTRADO: la correccion de const la hace cumplir el
                 * compilador, no es una palabra que haya que creerse. */
                if (sem.is_const) ptr.deny(Claim::MayWrite, true);
                if (sem.pointee != nullptr && sem.pointee->is_const)
                    pointee.deny(Claim::MayWrite, true);
                /* `volatile`, por el mismo eje y el mismo nivel.  Va SIN
                 * demostrar y como cosa DECLARADA porque eso es lo que es: una
                 * afirmacion del programador sobre de donde se ve esa region,
                 * que el compilador no puede comprobar leyendo el programa.
                 *
                 * Y no apaga nada por si sola.  Lo demostrado de esa region
                 * sigue ahi al lado; cuando las dos cosas se contradigan -- una
                 * region que provablemente no sale de aqui declarada observable
                 * desde fuera -- lo interesante es DECIRLO, no obedecer sin
                 * mirar: casi siempre significa que el `volatile` sobra o que
                 * tapa otro problema. */
                if (sem.is_volatile) ptr.set(Claim::Observable, false);
                if (sem.pointee != nullptr && sem.pointee->is_volatile)
                    pointee.set(Claim::Observable, false);
                /* Hasta DONDE vale, cuando el tipo lo dice.  Un `T[N]` de
                 * parametro decae a puntero, pero la N no se pierde: es la
                 * promesa de que hay N elementos ahi, y sin ella el
                 * comprobador de limites tiene que dar por buena cualquier
                 * posicion.
                 *
                 * El calculo sale del mismo sitio que el de un array global,
                 * no de una cuenta escrita otra vez aqui: son la misma
                 * pregunta ("cuantos bytes ocupa `T[N]`") y dos respuestas
                 * acaban discrepando en cuanto una de las dos aprenda algo. */
                const uint64_t bytes =
                    vx_global_array_bytes(d.decl->type.get(), tc_);
                if (bytes > 0)
                    pointee.extent_bytes = static_cast<int64_t>(bytes);
                /* Y COMO esta alineada, que sale del tipo y no hace falta que
                 * nadie lo escriba: un `T*` apunta a algo alineado a lo que
                 * pida T.  Lo pregunta la vectorizacion -- una lane ancha
                 * quiere saber si puede usar la carga alineada -- y hasta ahora
                 * el dato existia en el sistema de tipos y no llegaba a quien
                 * decide.  La cuenta es la de `alignof<T>`, la misma que ve el
                 * programador. */
                if (sem.pointee != nullptr) {
                    const uint64_t al = comptime_type_align(tc_, *sem.pointee);
                    if (al > 1 && al <= 0xFFFFu)
                        pointee.align_bytes = static_cast<uint32_t>(al);
                }
            }
            /* Solo se materializa el vector cuando ALGUIEN promete algo: en
             * casi ninguna funcion lo hace nadie, y un vector vacio no cuesta
             * nada.  Se rellena hasta la posicion actual con contratos vacios
             * para que siga alineado con `params` -- delante puede ir un buffer
             * de retorno, que no promete nada por no declararlo nadie. */
            if (!c.empty() && pos < fn.params.size()) {
                if (fn.param_contracts.size() < fn.params.size())
                    fn.param_contracts.resize(fn.params.size());
                fn.param_contracts[pos] = c;
            }
        }
    }

    // Bloque entry.
    const ir::IrBlockId entry = fn.new_block("entry");
    // Conectar el estado del lowering al de esta funcion.
    fn_ = &fn;
    current_block_ = entry;
    block_terminated_ = false;
    scopes_.clear();
    push_scope();
    for (auto &kv : param_bindings)
        bind(kv.first, kv.second);

    // register() en params: desugar a variable register() mutable ligada al
    // reg. Se hace AQUI (no en el bucle de params) porque el entry block y
    // current_block_ ya existen.  Reutiliza el modelo de las vars register()
    // (asm_reg_bindings + STORE inicial + LOAD read-back en lower_asm): el body
    // y el/los asm{} usan la variable, y `return id` lee el registro POST-asm.
    for (const auto &cp : custom_abi_params) {
        const size_t bytes = ir::type_access_bytes(cp.pt);
        const ir::IrValueId addr = fn.new_value(ir::IrType::PTR);
        ir::IrInstr ai{};
        ai.op = ir::IrOp::ALLOCA;
        ai.type = ir::IrType::I8; // unidad: 1 byte
        ai.dst = addr;
        ai.imm = static_cast<uint64_t>(bytes < 8 ? 8 : bytes);
        ai.host_alloca = true;
        fn.values[addr].is_host_ptr = true;
        ai.source_line = fd->loc.line;
        fn.append(current_block_, std::move(ai));
        const bool is_vec =
            cp.reg.rfind("xmm", 0) == 0 || cp.reg.rfind("ymm", 0) == 0 ||
            cp.reg.rfind("zmm", 0) == 0 || cp.reg.rfind("XMM", 0) == 0 ||
            cp.reg.rfind("YMM", 0) == 0 || cp.reg.rfind("ZMM", 0) == 0;
        {
            // La clase con la que se declaro: aqui el registro es CONCRETO, asi
            // que la clase es el registro mismo.  Es lo que dira su ancho a
            // quien lo pregunte despues.
            ir::AsmRegBinding b{addr, cp.reg, cp.pt, is_vec, cp.name};
            b.reg_class = cp.reg;
            fn.asm_reg_bindings.push_back(std::move(b));
        }
        // La variable vive en un ALLOCA (como cualquier var register()): marcar
        // address-taken para que read_local emita un LOAD del slot en cada uso
        // (p.ej. `return id`) en lugar de devolver la DIRECCION del alloca. Sin
        // esto, un callee standalone con param register retornaba el puntero de
        // pila (el inline lo ocultaba porque elimina el desugar).
        address_taken_locals_.insert(cp.name);
        // STORE inicial: variable register() = param (que llega en ese registro
        // por la ABI custom; el mov reg,reg resultante es no-op).
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = cp.pt;
        st.dst = ir::IR_NO_VALUE;
        st.operands = {cp.vid, addr};
        st.source_line = fd->loc.line;
        fn.append(current_block_, std::move(st));
        // Re-bind: el body y el asm usan la VARIABLE (su ALLOCA), no el param.
        bind(cp.name, addr);
    }

    // sret: configurar el contexto de la funcion actual.  Si
    // declara devolver Optional/Result, retbuf es el primer param
    // hidden y todos los `return` copiaran al buffer del caller en
    // vez de devolver un valor.
    sret_active_ = sret;
    sret_retbuf_ = v_retbuf;
    sret_buf_size_ = sret_i.bytes;
    // (gap O): activar el modo "env en heap" para todos los
    // lambdas creados dentro del body de esta funcion.  Asi el env
    // sobrevive al RET y el caller puede invocar la closure sin
    // use-after-free.  Se restaura al salir de @c lower_function.
    const bool prev_returns_fn = current_fn_returns_function_;
    current_fn_returns_function_ = sret_function;
    // Para `string get_x() { return "lit"; }` -- propaga al
    // lower_return para que detecte el literal y lo promueva via
    // STRMAKE en vez de devolver el ptr crudo.
    const bool prev_returns_str = current_fn_returns_string_;
    current_fn_returns_string_ = (sem_ret.kind == PrimitiveKind::STRING);
    // native_poo_: marca que el return de `string` baja por SRET de
    // value-type (24 bytes) -> lower_return construye el value-string.
    const bool prev_sret_str_value = current_fn_sret_str_value_;
    current_fn_sret_str_value_ = sret_str_value;

    // nonnull en parametros: por cada parametro declarado con
    // `T !!name` (o `nonnull T name`), inyectamos un `unwrap` al
    // entry de la funcion.  Si el caller pasa null, la excepcion
    // NullPointerException se lanza inmediatamente con stack trace
    // apuntando al entry del callee, lo que da diagnosticos
    // tempranos en vez de fallos lejanos al primer uso del param.
    for (size_t pi = 0; pi < fd->params.size(); ++pi) {
        const auto &p = fd->params[pi];
        if (!p || !p->type || !p->type->is_nonnull) continue;
        const ir::IrValueId v_old = param_bindings[pi].second;
        // Misma comprobacion que en cualquier otro sitio donde se hace cumplir
        // un `nonnull` -- ver enforce_nonnull.
        const ir::IrValueId v_new = enforce_nonnull(v_old, p->loc.line);
        // Re-bind: futuros usos de p->name resuelven al valor unwrapped.
        // Sustituir el binding del scope (push_scope nuevo + el viejo
        // se reemplaza re-bindeando con bind() que sobrescribe).
        bind(p->name, v_new);
    }

    /* Y el `string[] args` de `main`, que nadie rellenaba: la firma se
     * aceptaba, `args[0]` compilaba, y al ejecutarlo se leia de la direccion
     * cero.  Va aqui, con los parametros ya atados y antes del cuerpo. */
    emit_main_args_prologue(fd);

    // Pre-pase: identificar variables locales cuya direccion se toma con
    // '&'.  Influye en lower_var_decl (ALLOCA en lugar de SSA) y en
    // read_local / write_local (LOAD/STORE).
    address_taken_locals_.clear();
    host_bearing_locals_.clear();
    // `static` locals: mapa nombre->slot global, unico por funcion.
    static_local_slots_.clear();
    // Limpiar mapa de labels de goto (per-funcion).
    goto_labels_.clear();
    /* Y con el, que nombres pueden CAMBIAR en esta funcion.  Es lo que acota
     * los PHIs de una etiqueta: un `goto` hacia atras la convierte en
     * cabecera de bucle, y sin PHI las lecturas de despues se quedan con el
     * valor de la primera vuelta. */
    fn_assigned_vars_.clear();
    if (fd->body) collect_assigned_vars(fd->body.get(), fn_assigned_vars_);
    if (fd->body) scan_address_taken(fd->body.get());
    // Los params con ABI custom (register) viven en un ALLOCA (desugar mas
    // arriba, ANTES de este pre-pase).  El clear() de address_taken_locals_
    // recien borro el marcado que el desugar puso -> re-insertarlo AQUI para
    // que read_local emita un LOAD del slot en cada uso (`return id`) en vez de
    // devolver la DIRECCION del alloca (un callee retornaba el puntero de
    // pila).
    for (const auto &cp : custom_abi_params)
        address_taken_locals_.insert(cp.name);
    // Y los de salida por referencia, por lo mismo: el clear() de arriba borra
    // el marcado, y sin el `read_local` devolveria la DIRECCION en vez de leer
    // el hueco -- el cuerpo veria un puntero donde escribio una `T`.
    mark_by_ref_params_address_taken(by_ref_params);
    // fix9 - eliminados los pre-pases scan_try / scan_loops.
    // Las flags `current_fn_has_try_` y `current_fn_has_loops_` solo
    // se usaban para decidir si emitir el cleanup RAW_ASM de fix
    // / fix5.  Tras fix8 (GC stack scanning conservativo),
    // esos cleanups ya no se emiten; los handles sin roots los colecta
    // el major_gc automaticamente.  Las flags quedan declaradas pero
    // siempre false, para minimizar el delta del header (eliminarlas
    // requiere actualizar miembros que pueden estar referenciados en
    // codigo no escaneado).
    current_fn_has_try_ = false;
    current_fn_has_loops_ = false;
    current_fn_no_idiom_ = fd->is_no_idiom;
    // escape detection para colecciones primitivas: detectar
    //  locales cuyo handle se devuelve, asigna a campo o se almacena en
    //  memoria.  Los marcados quedan fuera del cleanup automatico.
    const_str_locals_.clear();
    escaping_locals_.clear();
    reassigned_locals_.clear();
    if (fd->body) scan_escaping_locals(fd->body.get());
    // Los deleters estaticos por-variable son por-funcion (los nombres de
    // variables se reusan entre funciones); limpiar al entrar a una nueva.
    unique_var_deleter_.clear();

    // CRITICO: los IDs de SSA value son POR-FUNCION; ssa_concrete_class_ (mapa
    // vid->clase concreta para devirt nativa) DEBE limpiarse entre funciones o
    // un vid de la funcion anterior (p.ej. %1 = new Square en main) colisiona
    // con un param de esta (b = %1 en total) -> devirt al tipo equivocado.
    // (Bug AOT-especifico: solo native_poo devirta clases via este mapa.)
    ssa_concrete_class_.clear();

    // limpiar el stack de cleanups (synchronized activos) al
    // entrar a una nueva funcion.  Cada funcion arranca sin cleanups;
    // las acciones se acumulan al bajar synchronized y se consumen al
    // emitir return o al cerrar el scope normalmente.
    cleanup_stack_.clear();

    // Si esta es 'main' y el modulo declara clases, insertar prologo
    // que invoca __module_init para registrarlas en el ClassRegistry
    // antes de ejecutar el cuerpo del usuario.
    if (fd->name == "main") {
        bool any_class = false;
        for (auto &decl : mod_.decls) {
            if (decl && decl->kind == ast::NodeKind::ClassDecl) {
                any_class = true;
                break;
            }
        }
        //  M6.b L.6: el root puede no declarar clases pero importar
        // alguna de un dep via `import "lib" only Counter;`.  En ese
        // caso, class_layouts() del TypeChecker contiene la clase
        // importada y necesitamos llamar a __module_init (que el merge
        // trae del dep) para registrarla en el ClassRegistry runtime.
        //
        // IMPORTANTE: filtrar las clases runtime-predefined (FatalError
        // etc.) que SIEMPRE estan en class_layouts y no requieren
        // __module_init.  Tambien filtrar clases declaradas localmente
        // en mod_.decls (ya cubiertas por el check de any_class arriba).
        if (!any_class) {
            std::unordered_set<std::string> local_class_names;
            for (auto &decl : mod_.decls) {
                if (decl && decl->kind == ast::NodeKind::ClassDecl) {
                    local_class_names.insert(
                        static_cast<const ast::ClassDecl *>(decl.get())->name);
                }
            }
            for (const auto &kv : tc_.class_layouts()) {
                if (kv.second.is_runtime_predefined) continue;
                if (local_class_names.count(kv.first)) continue;
                // Clase no-local + no-runtime = importada de un dep.
                any_class = true;
                break;
            }
        }
        // L2.2: tambien llamar __module_init si hay globals runtime
        // que requieren inicializacion (string="lit" etc.).
        //  AOT.2.b: en POO nativa NO hay ClassRegistry -> main no
        // llama a __module_init (las clases son layout estatico).
        bool need_init = any_class || !runtime_global_slots_.empty();
        if (need_init && !native_poo_) {
            ir::IrInstr call_init{};
            call_init.op = ir::IrOp::CALL;
            call_init.type = ir::IrType::VOID;
            call_init.dst = ir::IR_NO_VALUE;
            call_init.func_name = "__module_init";
            call_init.source_line = fd->loc.line;
            fn.append(current_block_, std::move(call_init));
        }
    }

    // Instrumentacion: vx_trace:enter al inicio.  Solo para funciones
    // de usuario (saltamos __module_init, __new_*, __async_*, __lambda_*,
    // __spawn_* y wrappers internos).  El bytecode VM, JIT y ports
    // heredan la instrumentacion porque vive en el IR.
    if (instrument_mode_ != "none" && instrument_mode_ != "" &&
        fd->name != "__module_init" && fd->name.rfind("__new_", 0) != 0 &&
        fd->name.rfind("__async_", 0) != 0 &&
        fd->name.rfind("__lambda_", 0) != 0 &&
        fd->name.rfind("__spawn_", 0) != 0) {
        emit_instrument_enter(fd->name, fd->loc.line);
    }

    // Instrumentacion en COMPILACION (`@Hook(enter)`).  Es un eje distinto de
    // --instrument: aquel llama a un plugin nativo con el contexto de la VM
    // (`getproc`) y por eso no llega a nativo; este se resuelve entero al
    // compilar y baja a una llamada normal, asi que funciona en --target bare.
    emit_hook_calls(HookPoint::Enter, fd->name, ir::IR_NO_VALUE, fd->loc.line);

    // C-3: dentro del cuerpo de la PROPIA fn override desactivar el
    // ruteo, o un `a + b` / `str_concat(a, b)` en su body se rutearia a
    // si mismo (recursion infinita).  Se restaura al cerrar la funcion.
    const std::string saved_concat_ovr = string_concat_override_;
    const std::string saved_eq_ovr = string_eq_override_;
    if (!string_concat_override_.empty() && fd->name == string_concat_override_)
        string_concat_override_.clear();
    if (!string_eq_override_.empty() && fd->name == string_eq_override_)
        string_eq_override_.clear();

    // Cuerpo.
    if (fd->body) {
        lower_block(fd->body.get());
    }
    string_concat_override_ = saved_concat_ovr;
    string_eq_override_ = saved_eq_ovr;

    // Cerrar la funcion: si la ultima instruccion no es terminador,
    // añadir RET con valor por defecto (0) en funciones no-void, o
    // RET sin valor en void.
    if (!block_terminated_) {
        // Multihilo AOT: join-all implicito de los hilos de `spawn` en el RET
        // por caida-al-final de main (sin return explicito).
        if (native_poo_ && vx_thread_used_ && fd->name == "main") {
            ir::IrInstr jc{};
            jc.op = ir::IrOp::CALL;
            jc.type = ir::IrType::VOID;
            jc.dst = ir::IR_NO_VALUE;
            jc.func_name = "__vx_thread_join_all";
            jc.is_call_site = true;
            jc.source_line = fd->loc.line;
            fn.append(current_block_, std::move(jc));
        }
        // emitir cleanups de auto-free de colecciones antes
        // del RET implicito.  Garantiza liberacion incluso si la
        // funcion cae al final sin un return explicito.
        emit_cleanups_all();
        // Instrumentacion: vx_trace:exit antes del RET implicito.
        if (instrument_mode_ != "none" && instrument_mode_ != "" &&
            fd->name != "__module_init" && fd->name.rfind("__new_", 0) != 0 &&
            fd->name.rfind("__async_", 0) != 0 &&
            fd->name.rfind("__lambda_", 0) != 0 &&
            fd->name.rfind("__spawn_", 0) != 0) {
            emit_instrument_exit(fd->name, ir::IR_NO_VALUE, fd->loc.line);
        }
        // Caida por el final, sin `return` escrito.  Tambien es una salida:
        // no cerrarla dejaria un `enter` sin su `exit` en toda funcion void.
        emit_hook_calls(HookPoint::Exit, fd->name, ir::IR_NO_VALUE,
                        fd->loc.line);
        ir::IrInstr ret{};
        ret.op = ir::IrOp::RET;
        ret.type = fn.ret_type;
        // RET sintetico de caida-al-final (no proviene de un `return`
        // explicito): en @Naked el codegen NO lo materializa (el asm provee
        // ret/iretq).
        ret.ret_implicit = true;
        if (fn.ret_type != ir::IrType::VOID) {
            const ir::IrValueId zero = emit_const(fn.ret_type, 0, fd->loc.line);
            ret.operands.push_back(zero);
        }
        ret.source_line = fd->loc.line;
        fn.append(current_block_, std::move(ret));
        block_terminated_ = true;
    }

    pop_scope();
    // (gap O): restaurar el flag de "funcion retorna FUNCTION".
    current_fn_returns_function_ = prev_returns_fn;
    current_fn_returns_string_ = prev_returns_str;
    current_fn_sret_str_value_ = prev_sret_str_value;
    // Validar que todas las labels referenciadas por gotos esten
    // declaradas; si alguna se quedo sin declarar es uso de una
    // label inexistente (`goto missing_label`).
    for (const auto &kv : goto_labels_) {
        if (!kv.second.declared) {
            error_at(kv.second.first_use_loc,
                     std::string("label '") + kv.first +
                         "' usada en goto pero nunca declarada");
        }
    }
    propagate_is_gc_object_through_phis(fn);
    /* `out T x` PROMETE que quien llama recibira un valor.  Escribirlo en una
     * rama y no en la otra es justo lo que el llamante paga -- lee lo que
     * hubiera en su hueco --, asi que se pregunta AQUI: es el primer punto
     * donde existe el grafo de flujo, y sigue estando delante la declaracion
     * que puso la marca.
     *
     * Solo habla cuando esta DEMOSTRADO que falta.  Si el analisis no entendio
     * algo -- el puntero se pasa a otra funcion, que es una forma legitima de
     * rellenarlo -- se calla: acusar a codigo correcto es peor que no avisar.
     *
     * `inout` no entra: alli ya llega un valor y no cambiarlo es legitimo. */
    check_by_ref_params_written(by_ref_params, fn);
    out.add_function(std::move(fn));
    fn_ = nullptr;
}

void Lowering::emit_instrument_enter(const std::string &fn_name,
                                     uint32_t line) {
    if (!fn_ || !out_mod_) return;
    // 1. Internar el nombre como literal en static_data.  Incluye nul
    //    terminator para que sea NUL-terminated C string utilizable
    //    por strdup/printf en cualquier backend hosted.
    std::vector<uint8_t> bytes(fn_name.begin(), fn_name.end());
    bytes.push_back(0);
    const uint64_t name_idx = out_mod_->intern_static_data(std::move(bytes));

    // 2. STR_LIT_ADDR: cargar ptr al literal en un SSA value.
    const ir::IrValueId v_name = emit_str_lit_addr(name_idx, line);

    // 3. CALLN void a "vx_trace:enter"(proc_ptr, name_ptr).
    //    El proc_ptr lo obtenemos via @c getproc; el plugin nativo
    //    lo usa para @c vm_read_bytes del nombre.  En port C el
    //    bridge ignora el proc_ptr.
    // El nombre de la biblioteca incluye el subdir bajo @c stdlib/native/ para
    // que el cargador resuelva la DLL por ruta relativa al @c vm.exe (igual
    // convencion que vesta_io / vesta_math).
    const ir::IrValueId v_proc = emit_getproc(line);
    emit_native_call(kVestaTraceLib, "enter", {v_proc, v_name},
                     ir::IrType::VOID, line);
}

void Lowering::emit_instrument_exit(const std::string &fn_name,
                                    ir::IrValueId v_ret, uint32_t line) {
    if (!fn_ || !out_mod_) return;
    std::vector<uint8_t> bytes(fn_name.begin(), fn_name.end());
    bytes.push_back(0);
    const uint64_t name_idx = out_mod_->intern_static_data(std::move(bytes));

    const ir::IrValueId v_name = emit_str_lit_addr(name_idx, line);

    // Si la funcion es void, pasar 0 como return value placeholder.
    ir::IrValueId v_val = v_ret;
    if (v_val == ir::IR_NO_VALUE) {
        v_val = emit_const(ir::IrType::I64, 0, line);
    }

    // Se llama @c leave y no @c exit para no chocar con el @c exit() de la
    // libc cuando el port a C emite las declaraciones extern.
    const ir::IrValueId v_proc = emit_getproc(line);
    emit_native_call(kVestaTraceLib, "leave", {v_proc, v_name, v_val},
                     ir::IrType::VOID, line);
}

/**
 * @brief Comprueba un glob sencillo (`*` comodin) contra un nombre.
 *
 * Se implementa aqui, con dos indices y sin recursion, en vez de tirar de
 * expresiones regulares: el selector se evalua una vez por funcion del modulo
 * y una regex costaria construirla mas que todo el tejido.
 *
 * @param patron Patron con cero o mas `*`.
 * @param texto  Nombre cualificado de la funcion.
 * @return @c true si casa.
 */
static bool glob_matches(const std::string &pattern, const std::string &text) {
    size_t p = 0, t = 0;
    size_t star = std::string::npos, mark = 0;
    while (t < text.size()) {
        if (p < pattern.size() &&
            (pattern[p] == '?' || pattern[p] == text[t])) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            // Se anota donde estaba la estrella para poder retroceder: es lo
            // que permite que un patron con varias case sin explorar arboles.
            star = p++;
            mark = t;
        } else if (star != std::string::npos) {
            p = star + 1;
            t = ++mark;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

/**
 * @copydoc vx::Lowering::collect_hook_providers
 */
void Lowering::collect_hook_providers() {
    /* Los del propio modulo y los que vienen del RAIZ, en una sola lista.
     *
     * Un modulo importado no ve las declaraciones del que lo importa, asi que
     * sin los del raiz la stdlib se quedaria sin instrumentar -- que es justo
     * lo que se quiere medir.  El raiz recoge los suyos por el primer camino,
     * y esta lista le llega vacia. */
    std::vector<std::pair<ast::FunctionDecl *, std::string>> candidates;
    candidates.reserve(mod_.decls.size() / 8 + root_hook_decls_.size());
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::FunctionDecl) continue;
        auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
        if (fd->is_no_instrument) hook_excluded_.insert(fd->name);
        // Los de casa ya tienen el nombre bueno en el propio nodo.
        if (!fd->hook_point.empty()) candidates.push_back({fd, fd->name});
    }
    for (const auto &rh : root_hook_decls_)
        if (rh.first) candidates.push_back(rh);

    for (const auto &cand : candidates) {
        ast::FunctionDecl *fd = cand.first;
        const std::string &call_name = cand.second;
        /* El contador COMPARTIDO de este gancho, si lo tiene: un gancho del
         * raiz se teje en cada modulo por separado y solo la suma dice si
         * llego a alguna parte.  Se busca por NOMBRE porque el raiz recoge los
         * suyos de su propio arbol y no hay indice comun. */
        std::shared_ptr<std::atomic<size_t>> total_counter;
        {
            auto itc = hook_counters_.find(call_name);
            if (itc != hook_counters_.end()) total_counter = itc->second;
        }

        // El parser ya rechazo un punto que no este en la tabla, asi que aqui
        // resolver no puede fallar; si fallara seria un desajuste entre las
        // dos, y callarlo dejaria el gancho sin tejer sin decir por que.
        HookPoint point = HookPoint::Enter;
        if (!hook_point_from_name(fd->hook_point, point)) {
            diags_.diag(fd->loc, DiagLevel::ERR, "VXE931",
                        {fd->hook_point, hook_points_available()});
            continue;
        }

        HookProvider hp;
        hp.fn_name = call_name;
        hp.selector = fd->hook_selector;
        hp.point = point;
        hp.loc = fd->loc;
        hp.reached_total = total_counter;

        // La firma la decide el gancho: se valida CADA parametro contra la
        // tabla del punto.  Uno que ese punto no ofrezca es un error con la
        // lista de lo que si hay -- rellenarlo con basura daria un numero
        // plausible y una medicion equivocada, que es peor que no medir.
        bool signature_ok = true;
        for (const auto &pd : fd->params) {
            if (!pd) continue;
            const HookFieldInfo *field = hook_field_for(pd->name, point);
            if (!field) {
                diags_.diag(fd->loc, DiagLevel::ERR, "VXE933",
                            {fd->hook_point, pd->name,
                             hook_fields_available(point)});
                signature_ok = false;
                continue;
            }
            // Lo que la tabla ofrece pero el tejido todavia no sabe rellenar
            // se DICE aqui, una sola vez.  Callarlo seria pasar un cero que
            // parece un dato: el gancho mediria y el resultado seria mentira.
            if (pd->name != "fn_id" && pd->name != "ret_value" &&
                pd->name != "call_site" && pd->name != "fn_name") {
                diags_.diag(fd->loc, DiagLevel::WARN, "VXW930",
                            {pd->name});
            }
            hp.params.push_back(pd->name);
        }
        if (!signature_ok) continue;

        // Un gancho no puede instrumentarse a si mismo: se llamaria sin fin.
        // Es la misma precaucion que ya toma el ruteo de los override de
        // string dentro del cuerpo de la propia funcion que rutea.
        hook_excluded_.insert(call_name);
        hook_providers_.push_back(std::move(hp));
    }
}

/**
 * @copydoc vx::Lowering::warn_hooks_sin_alcance
 */
void Lowering::warn_unreached_hooks() {
    // Un `@Hook(exit)` sin `@Hook(unwind)` en un modulo que lanza excepciones
    // CUENTA DE MENOS y no lo dice: la excepcion salta el epilogo de las
    // funciones que atraviesa.  Medido con tres funciones anidadas: 3
    // entradas, 1 salida, igual en interprete, JIT y nativo.  El aviso no
    // obliga a nada -- hay ganchos a los que no les importa cerrar --, pero
    // que la cuenta no cuadre no puede ser una sorpresa.
    bool has_exit = false, has_unwind = false;
    for (const auto &hp : hook_providers_) {
        if (hp.point == HookPoint::Exit) has_exit = true;
        if (hp.point == HookPoint::Unwind) has_unwind = true;
    }
    if (has_exit && !has_unwind && module_throws_) {
        for (const auto &hp : hook_providers_) {
            if (hp.point != HookPoint::Exit) continue;
            diags_.diag(hp.loc, DiagLevel::WARN, "VXW932", {hp.fn_name});
            break;
        }
    }
    for (const auto &hp : hook_providers_) {
        /* Un gancho del raiz se teje modulo a modulo, y lo NORMAL es que no
         * case en todos: `"std.*"` no alcanza nada en el programa que lo
         * declara.  Por eso se mira el total de la compilacion cuando lo hay;
         * mirando solo este modulo, el aviso decia "no se instalo en ningun
         * sitio" con la stdlib entera instrumentada. */
        if (hp.reached != 0) continue;
        if (hp.reached_total && hp.reached_total->load() != 0) continue;
        // Un codigo por caso, y no uno solo con el motivo de argumento: una
        // frase pasada como dato no la traduce nadie, y el aviso saldria
        // mitad en un idioma y mitad en otro.
        if (hp.selector.empty())
            diags_.diag(hp.loc, DiagLevel::WARN, "VXW933", {hp.fn_name});
        else
            diags_.diag(hp.loc, DiagLevel::WARN, "VXW931",
                        {hp.fn_name, hp.selector});
    }
}

/**
 * @copydoc vx::Lowering::should_instrument
 */
bool Lowering::should_instrument(const std::string &fn_name) const {
    if (hook_providers_.empty()) return false;
    if (hook_excluded_.count(fn_name)) return false;
    // Los envoltorios que fabrica el compilador no son codigo del usuario:
    // medirlos ensucia el perfil con nombres que no aparecen en su fuente.
    if (fn_name == "__module_init") return false;
    if (fn_name.rfind("__new_", 0) == 0) return false;
    if (fn_name.rfind("__async_", 0) == 0) return false;
    if (fn_name.rfind("__lambda_", 0) == 0) return false;
    if (fn_name.rfind("__spawn_", 0) == 0) return false;
    return true;
}

/**
 * @copydoc vx::Lowering::hook_fn_id
 */
uint32_t Lowering::hook_fn_id(const std::string &fn_name) {
    auto it = hook_fn_ids_.find(fn_name);
    if (it != hook_fn_ids_.end()) return it->second;
    const uint32_t id = static_cast<uint32_t>(hook_fn_ids_.size());
    hook_fn_ids_.emplace(fn_name, id);
    return id;
}

/**
 * @copydoc vx::Lowering::emit_hook_calls
 */
void Lowering::emit_hook_calls(HookPoint point, const std::string &fn_name,
                               ir::IrValueId v_ret, uint32_t line) {
    if (!fn_ || !out_mod_) return;
    if (!should_instrument(fn_name)) return;

    // El selector se escribe con PUNTOS, como el usuario escribe los
    // namespaces (`"std.*"`), pero por dentro el nombre ya viene aplanado con
    // `__` (`std__collections__Vector`).  Comparar solo contra el aplanado
    // haria que un selector escrito de la forma natural no casara NUNCA, y sin
    // casar no se instrumenta nada -- callando.  Se prueban las dos formas.
    std::string fn_dotted = fn_name;
    for (size_t i = 0; i + 1 < fn_dotted.size();) {
        if (fn_dotted[i] == '_' && fn_dotted[i + 1] == '_') {
            fn_dotted.replace(i, 2, ".");
            ++i;
        } else {
            ++i;
        }
    }

    for (auto &hp : hook_providers_) {
        if (hp.point != point) continue;
        // Selector vacio = todas las funciones.  Es el caso util por defecto:
        // perfilar un programa entero no puede exigir marcarlas una a una.
        if (!hp.selector.empty() && !glob_matches(hp.selector, fn_name) &&
            !glob_matches(hp.selector, fn_dotted))
            continue;
        ++hp.reached;
        if (hp.reached_total) hp.reached_total->fetch_add(1);

        // Se emite UN argumento por cada campo que el gancho pidio, y solo
        // esos: lo que no se declara no se calcula ni se pasa.
        std::vector<ir::IrValueId> args;
        args.reserve(hp.params.size());
        for (const auto &name : hp.params) {
            if (name == "fn_id") {
                args.push_back(emit_const(
                    ir::IrType::I32,
                    static_cast<int64_t>(hook_fn_id(fn_name)), line));
            } else if (name == "ret_value") {
                args.push_back(v_ret != ir::IR_NO_VALUE
                                   ? v_ret
                                   : emit_const(ir::IrType::I64, 0, line));
            } else if (name == "fn_name") {
                /* El nombre lo sabe el compilador, asi que se interna como
                 * literal y se construye un `string` de verdad con el MISMO
                 * mecanismo que el resto del lenguaje: eso elige la
                 * representacion segun el modo -- cadena por valor con
                 * optimizacion de cadena corta en nativo, objeto del
                 * recolector en interprete y JIT --, y por eso vale igual en
                 * `--target bare`.
                 *
                 * Pasar la direccion cruda no valia: el literal vive en la
                 * memoria de la maquina virtual y `print_cstr` espera una del
                 * proceso, asi que imprimirlo reventaba con un acceso
                 * invalido.  Es la distincion que el volcado del intermedio
                 * marca con `@host`. */
                std::vector<uint8_t> bytes(fn_name.begin(), fn_name.end());
                bytes.push_back(0); // nul, por si cruza a una API en C
                const uint64_t idx =
                    out_mod_->intern_static_data(std::move(bytes));
                const ir::IrValueId v_addr = emit_str_lit_addr(idx, line);
                const int64_t n = static_cast<int64_t>(fn_name.size());
                const ir::IrValueId v_len =
                    emit_const(ir::IrType::I64, n, line);
                args.push_back(
                    emit_string_literal_repr(v_addr, v_len, n, line));
            } else if (name == "call_site") {
                // Una instruccion, y solo si el gancho lo pide: la direccion
                // ya esta en la pila porque la puso la llamada.
                // Se marca AQUI, que es donde se sabe: quien comprueba
                // despues si un asm mueve la pila se salta el modulo entero
                // con una comparacion en vez de recorrerlo buscandolo.
                if (out_mod_) out_mod_->usa_return_addr = true;
                ir::IrInstr ra{};
                ra.op = ir::IrOp::RETURN_ADDR;
                ra.type = ir::IrType::I64;
                ra.dst = fn_->new_value(ir::IrType::I64);
                ra.source_line = line;
                const ir::IrValueId v_ra = ra.dst;
                emit(current_block_, std::move(ra));
                args.push_back(v_ra);
            } else {
                // `call_site` y `depth` necesitan apoyo que todavia no existe
                // (la direccion de retorno y un contador de anidamiento).  El
                // aviso se da UNA vez, al recoger el gancho, no aqui: aqui se
                // repetiria por cada funcion instrumentada.
                args.push_back(emit_const(ir::IrType::I64, 0, line));
            }
        }

        ir::IrInstr in{};
        in.op = ir::IrOp::CALL;
        in.type = ir::IrType::VOID;
        in.dst = ir::IR_NO_VALUE;
        in.func_name = hp.fn_name;
        in.operands = std::move(args);
        in.source_line = line;
        emit(current_block_, std::move(in));
    }
}

/**
 * @brief Reserva el almacenamiento de todo lo que vive fuera de las funciones.
 *
 * Corre ANTES de bajar ninguna funcion, y ese orden no es de comodidad: al
 * bajar `main`, un nombre global que todavia no tenga hueco se lee como no
 * resuelto.  Lo mismo con las globales que vienen de otro modulo: el prologo
 * de `main` decide si llamar al init del modulo mirando si hay algun hueco, y
 * uno que solo USA globales ajenas no tendria ninguno -- el init no correria y
 * el global se leeria a cero.
 *
 * Cuatro procedencias, y la de fuera no se distingue por como se escribe sino
 * por donde esta declarada: las del propio modulo, las importadas por nombre
 * suelto, las que se usan cualificadas -- que viven en el namespace, y ahi
 * estan tambien las PROPIAS, que ya tienen hueco y no hay que darles otro --,
 * y los campos estaticos de clase, que sin maquina virtual detras no son mas
 * que globales con un nombre largo.
 */
void Lowering::lower_global_storage(ir::IrModule &out_module) {
    // L2.2: pre-scan global runtime vars y reservar slots ANTES de
    // bajar main.  Sin esto, lower_ident("g") en main encuentra
    // runtime_global_slots_ vacio y emite "nombre no resuelto".
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::GlobalVarDecl) continue;
        auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
        if (gv->is_const || gv->is_comptime) continue;
        // thread_local: almacenamiento por-hilo (TLS NATIVO).  Su plantilla va
        // a una seccion SHF_TLS (.tdata) con SD_FLAG_TLS; el acceso usa el
        // thread pointer (fs/gs + TPOFF) que emite el codegen AOT.  El init
        // debe ser una constante (literal entero o ausente = 0): es la
        // plantilla estatica que el cargador copia por-hilo, no un store en
        // __module_init.
        if (gv->is_thread_local) {
            uint64_t nbytes = 8;
            uint16_t talign = 8;
            PrimitiveKind prim_kind = PrimitiveKind::I64;
            if (gv->type &&
                gv->type->kind == ast::NodeKind::PrimitiveTypeNode) {
                auto *pt =
                    static_cast<ast::PrimitiveTypeNode *>(gv->type.get());
                prim_kind = pt->prim;
                nbytes = primitive_size_bytes(pt->prim);
                if (nbytes == 0) nbytes = 8;
                talign = static_cast<uint16_t>(nbytes);
            }
            const bool is_f64 = (prim_kind == PrimitiveKind::F64);
            const bool is_f32 = (prim_kind == PrimitiveKind::F32);
            // Valor inicial: constante (literal entero/float/bool/char, negado,
            // o una referencia a un `comptime` const).  Es la plantilla
            // estatica que el cargador copia por-hilo.
            uint64_t init_val = 0;
            bool init_ok = true;
            if (gv->init) {
                const ast::Expr *ie = gv->init.get();
                int64_t sign = 1;
                if (ie->kind == ast::NodeKind::UnaryExpr) {
                    auto *u = static_cast<const ast::UnaryExpr *>(ie);
                    if (u->op == ast::UnOp::Neg && u->operand &&
                        (u->operand->kind == ast::NodeKind::IntLitExpr ||
                         u->operand->kind == ast::NodeKind::FloatLitExpr)) {
                        sign = -1;
                        ie = u->operand.get();
                    }
                }
                if (ie->kind == ast::NodeKind::FloatLitExpr) {
                    // Empaquetar los bits IEEE 754 (f64 o f32) de la plantilla.
                    double d =
                        sign *
                        static_cast<const ast::FloatLitExpr *>(ie)->value;
                    if (is_f32) {
                        float f = static_cast<float>(d);
                        uint32_t u32;
                        std::memcpy(&u32, &f, 4);
                        init_val = u32;
                    } else {
                        std::memcpy(&init_val, &d, 8);
                    }
                } else if (ie->kind == ast::NodeKind::IntLitExpr) {
                    int64_t iv =
                        sign *
                        static_cast<int64_t>(
                            static_cast<const ast::IntLitExpr *>(ie)->value);
                    // i64-literal en un thread_local float -> convertir a IEEE.
                    if (is_f64) {
                        double d = static_cast<double>(iv);
                        std::memcpy(&init_val, &d, 8);
                    } else if (is_f32) {
                        float f = static_cast<float>(iv);
                        uint32_t u32;
                        std::memcpy(&u32, &f, 4);
                        init_val = u32;
                    } else {
                        init_val = static_cast<uint64_t>(iv);
                    }
                } else if (ie->kind == ast::NodeKind::BoolLitExpr) {
                    init_val = static_cast<const ast::BoolLitExpr *>(ie)->value
                                   ? 1
                                   : 0;
                } else if (ie->kind == ast::NodeKind::CharLitExpr) {
                    init_val = static_cast<uint64_t>(
                        static_cast<const ast::CharLitExpr *>(ie)->codepoint);
                } else if (ie->kind == ast::NodeKind::IdentExpr) {
                    // Referencia a un `comptime` const entero -> su valor.
                    const auto &cgv = tc_.comptime_const_values();
                    auto cit =
                        cgv.find(static_cast<const ast::IdentExpr *>(ie)->name);
                    if (cit != cgv.end() && !cit->second.is_str &&
                        !cit->second.is_struct) {
                        int64_t cv = sign * cit->second.value;
                        if (is_f64) {
                            double d = static_cast<double>(cv);
                            std::memcpy(&init_val, &d, 8);
                        } else if (is_f32) {
                            float f = static_cast<float>(cv);
                            uint32_t u32;
                            std::memcpy(&u32, &f, 4);
                            init_val = u32;
                        } else {
                            init_val = static_cast<uint64_t>(cv);
                        }
                    } else {
                        init_ok = false;
                    }
                } else {
                    init_ok = false;
                }
            }
            if (!init_ok) {
                diags_.error(
                    gv->loc,
                    "thread_local '" + gv->name +
                        "': el inicializador debe ser una constante (literal "
                        "entero/float/bool/char, o un `comptime` const)");
                continue;
            }
            const uint64_t tls_slot = get_or_create_tls_global_slot(
                gv->name, nbytes, init_val, talign);
            // Init != 0: registrar para el TLS callback __vx_tls_init (la
            // plantilla a cero no necesita store -- el bloque ya esta a cero).
            if (init_val != 0)
                tls_nonzero_inits_.push_back({tls_slot, init_val});
            continue;
        }
        // Global de tipo STRUCT: reservar un slot de `size_bytes`, igual que un
        // array.  Sin esto no habia storage y cualquier uso daba "nombre no
        // resuelto" -- un struct simplemente no podia ser global, aunque un
        // array de structs si.  El caso natural (un contador compartido, una
        // config, un registro de estado) es justo una global.
        //
        // Un `@overlay struct` NO entra: su valor runtime es un puntero de 8
        // bytes y lo cubre la rama de primitivos de abajo (lo trata como PTR).
        if (gv->type && !gv->is_const && !gv->is_comptime &&
            gv->type->kind == ast::NodeKind::NamedTypeNode) {
            const Type gt = tc_.resolve_type_node(gv->type.get());
            if (gt.kind == PrimitiveKind::STRUCT && !gt.struct_name.empty()) {
                auto sit = tc_.struct_layouts().find(gt.struct_name);
                if (sit != tc_.struct_layouts().end() &&
                    !sit->second.is_overlay && sit->second.size_bytes > 0) {
                    (void)get_or_create_runtime_global_slot(
                        gv->name, (uint64_t)sit->second.size_bytes);
                    continue;
                }
            }
        }
        // Global array nativo T[N]: reservar slot de N*sizeof(T) bytes.
        if (gv->type && gv->type->kind == ast::NodeKind::ArrayTypeNode) {
            const uint64_t ab = vx_global_array_bytes(gv->type.get(), tc_);
            if (ab > 0) {
                const uint64_t slot =
                    get_or_create_runtime_global_slot(gv->name, ab);
                // Init-list constante `= {e0, e1, ...}`: grabar los bytes
                // directamente en el slot .data (en AOT no corre
                // __module_init).  Solo elementos enteros constantes.
                auto *at = static_cast<ast::ArrayTypeNode *>(gv->type.get());
                uint64_t esz = 8;
                if (at->element_type &&
                    at->element_type->kind == ast::NodeKind::PrimitiveTypeNode)
                    esz = primitive_size_bytes(
                        static_cast<ast::PrimitiveTypeNode *>(
                            at->element_type.get())
                            ->prim);
                if (gv->init && gv->init->kind == ast::NodeKind::InitListExpr &&
                    slot < out_mod_->static_data.entries.size() && esz > 0) {
                    auto *il = static_cast<ast::InitListExpr *>(gv->init.get());
                    const uint32_t base_off =
                        out_mod_->static_data.entries[slot].byte_offset;
                    for (size_t ei = 0; ei < il->elements.size(); ++ei) {
                        uint64_t cval = 0;
                        const ast::Expr *ie = il->elements[ei].get();
                        bool have = false;
                        if (ie && ie->kind == ast::NodeKind::IntLitExpr) {
                            cval =
                                static_cast<const ast::IntLitExpr *>(ie)->value;
                            have = true;
                        } else if (ie && ie->kind == ast::NodeKind::UnaryExpr) {
                            auto *u = static_cast<const ast::UnaryExpr *>(ie);
                            if (u->op == ast::UnOp::Neg && u->operand &&
                                u->operand->kind == ast::NodeKind::IntLitExpr) {
                                cval = (uint64_t)(-(int64_t)static_cast<
                                                       const ast::IntLitExpr *>(
                                                       u->operand.get())
                                                       ->value);
                                have = true;
                            }
                        } else if (ie &&
                                   ie->kind == ast::NodeKind::CharLitExpr) {
                            cval = static_cast<const ast::CharLitExpr *>(ie)
                                       ->codepoint;
                            have = true;
                        } else if (ie &&
                                   ie->kind == ast::NodeKind::BoolLitExpr) {
                            cval =
                                static_cast<const ast::BoolLitExpr *>(ie)->value
                                    ? 1u
                                    : 0u;
                            have = true;
                        }
                        if (!have) continue;
                        const uint64_t eoff = base_off + ei * esz;
                        for (uint64_t k = 0; k < esz; ++k)
                            out_mod_->static_data.bytes[eoff + k] =
                                (uint8_t)((cval >> (8 * k)) & 0xFF);
                    }
                }
            }
            continue;
        }
        // Tipo primitivo directo O newtype (typedef-new) que resuelve a un
        // primitivo (p.ej. `uintptr` -> u64): en ambos casos pre-creamos el
        // slot del global para que TODAS las funciones (no solo la que lo
        // escribe primero) resuelvan su lectura/escritura al mismo slot.
        // Sin esto, un global de tipo std.types leido/escrito desde otra
        // funcion daba "nombre no resuelto" o leia 0.
        if (!gv->type || (gv->type->kind != ast::NodeKind::PrimitiveTypeNode &&
                          gv->type->kind != ast::NodeKind::NamedTypeNode))
            continue;
        PrimitiveKind pt_prim =
            (gv->type->kind == ast::NodeKind::PrimitiveTypeNode)
                ? static_cast<ast::PrimitiveTypeNode *>(gv->type.get())->prim
                : tc_.resolve_type_node(gv->type.get()).kind;
        // Un global de tipo overlay (`@overlay struct`) tiene como VALOR
        // runtime un puntero al bloque host (8 bytes) -> darle slot como un
        // PTR.
        if (pt_prim == PrimitiveKind::STRUCT &&
            gv->type->kind == ast::NodeKind::NamedTypeNode) {
            Type rt = tc_.resolve_type_node(gv->type.get());
            auto sit = tc_.struct_layouts().find(rt.struct_name);
            if (sit != tc_.struct_layouts().end() && sit->second.is_overlay)
                pt_prim = PrimitiveKind::PTR;
        }
        switch (pt_prim) {
        case PrimitiveKind::STRING:
        case PrimitiveKind::I8:
        case PrimitiveKind::I16:
        case PrimitiveKind::I32:
        case PrimitiveKind::I64:
        case PrimitiveKind::U8:
        case PrimitiveKind::U16:
        case PrimitiveKind::U32:
        case PrimitiveKind::U64:
        case PrimitiveKind::F32:
        case PrimitiveKind::F64:
        case PrimitiveKind::BOOL:
        case PrimitiveKind::CHAR:
        case PrimitiveKind::PTR:
            (void)get_or_create_runtime_global_slot(gv->name);
            break;
        default: break;
        }
    }
    // Globals IMPORTADOS de otro modulo: mismo pre-pase.  Tiene que ser AQUI y
    // no al primer uso, porque el prologo de `main` decide si llama a
    // `__module_init` mirando si hay algun slot -- y un modulo que solo USA
    // globals de sus deps no tendria ninguno todavia, asi que el init no
    // correria y el global se leeria a cero.  Como el merge los unifica con los
    // del dep por `shared_key`, pre-crearlos no cuesta storage.
    for (const auto &kv : tc_.imported_global_storage())
        (void)ensure_imported_global_slot(kv.first);
    // Los que se usan cualificados (`lib.counter`) no estan en esa tabla: viven
    // en el namespace importado.  Mismo criterio (kind=1 = variable/constante,
    // sin valor inlineable, y no un string que se materializa desde su blob).
    //
    // OJO: la tabla de namespaces incluye tambien los DECLARADOS en este mismo
    // modulo (`namespace app;` registra sus propios simbolos para el acceso
    // cualificado).  Esos son locales: su storage ya lo decidio el bucle de
    // arriba, con el tipo delante -- y hay tipos que NO llevan slot (un global
    // de tipo funcion se resuelve como closure).  Darles uno aqui los
    // desviaria a la ruta de global plano y romperia su uso.
    for (auto &decl : mod_.decls) {
        if (decl && decl->kind == ast::NodeKind::GlobalVarDecl)
            local_global_names_.insert(
                static_cast<ast::GlobalVarDecl *>(decl.get())->name);
    }
    for (const auto &ns : tc_.imported_namespaces()) {
        for (const auto &sym : ns.symbols) {
            if (sym.kind != 1 || sym.has_const_value ||
                sym.mangled_label.empty())
                continue;
            if (sym.var_type.kind == PrimitiveKind::STRING) continue;
            if (local_global_names_.count(sym.mangled_label) != 0) continue;
            (void)shared_global_slot_for(sym.mangled_label, sym.var_type);
        }
    }
    // AOT (native_poo_): los campos estaticos de clase se mapean a globales
    // planos (slot __static_<Clase>_<campo>).  Pre-grabamos su inicializador
    // constante en los bytes del slot (no hay __module_init en bare).  Las
    // rutas de lectura/escritura usan el mismo slot via get_or_create.
    if (native_poo_) {
        for (auto &decl : mod_.decls) {
            if (!decl || decl->kind != ast::NodeKind::ClassDecl) continue;
            auto *cd = static_cast<ast::ClassDecl *>(decl.get());
            for (const auto &fld : cd->fields) {
                if (!fld.is_static) continue;
                const uint64_t slot = get_or_create_runtime_global_slot(
                    "__static_" + cd->name + "_" + fld.name, 8);
                if (!fld.init) continue;
                uint64_t cval = 0;
                bool have = false;
                const ast::Expr *ie = fld.init.get();
                if (ie->kind == ast::NodeKind::IntLitExpr) {
                    cval = static_cast<const ast::IntLitExpr *>(ie)->value;
                    have = true;
                } else if (ie->kind == ast::NodeKind::BoolLitExpr) {
                    cval = static_cast<const ast::BoolLitExpr *>(ie)->value
                               ? 1u
                               : 0u;
                    have = true;
                } else if (ie->kind == ast::NodeKind::CharLitExpr) {
                    cval = static_cast<const ast::CharLitExpr *>(ie)->codepoint;
                    have = true;
                } else if (ie->kind == ast::NodeKind::UnaryExpr) {
                    auto *u = static_cast<const ast::UnaryExpr *>(ie);
                    if (u->op == ast::UnOp::Neg && u->operand &&
                        u->operand->kind == ast::NodeKind::IntLitExpr) {
                        cval = (uint64_t)(-(int64_t)static_cast<
                                               const ast::IntLitExpr *>(
                                               u->operand.get())
                                               ->value);
                        have = true;
                    }
                }
                if (have && slot < out_module.static_data.entries.size()) {
                    uint32_t off =
                        out_module.static_data.entries[slot].byte_offset;
                    for (int k = 0; k < 8; ++k)
                        out_module.static_data.bytes[off + (size_t)k] =
                            (uint8_t)((cval >> (8 * k)) & 0xFF);
                }
            }
        }
    }
    /* PRE-PASE force-lower: determinar que comptime fns hay que bajar a runtime
     * porque un @Macro (o comptime fn con asm) lowereable las referencia
     * (transitivamente).  Sin esto, el `__macro_<X>` que llama a un helper
     * comptime emitiria un `callvm code.<helper>` colgante (los comptime
     * helpers no se bajan por defecto).  Poblamos @c
     * comptime_fns_to_force_lower_ ANTES del lowering para que el orden de
     * bajada de decls sea irrelevante. */
    {
        std::unordered_set<std::string> visiting;
        set_macro_force_lower(&comptime_fns_to_force_lower_);
        set_macro_visiting(&visiting);
        for (auto &decl : mod_.decls) {
            if (!decl || decl->kind != ast::NodeKind::FunctionDecl) continue;
            auto *fd = static_cast<ast::FunctionDecl *>(decl.get());
            if (!fd->body || fd->is_imported_comptime) continue;
            const bool is_lowerable_comptime =
                (fd->is_comptime && fd->is_macro) ||
                (fd->is_comptime && !fd->is_macro &&
                 comptime_fn_needs_vm(tc_, fd));
            if (!is_lowerable_comptime) continue;
            visiting.clear();
            // Efecto colateral: recolecta los helpers lowereables.  Si el macro
            // NO es lowereable, no pasa nada (sus helpers no se fuerzan; el
            // macro caera a AST-only en lower_function como antes).
            if (macro_body_unsupported_reason(tc_, fd->body.get()).empty()) {
                // macro lowereable: sus helpers ya estan en el set.
            } else {
                // No lowereable: quitar cualquier helper que solo el aportara
                // seria complejo; es inocuo dejarlos (una comptime fn lowerada
                // de mas es dead code si nadie la llama en runtime).  Los
                // helpers recolectados de un macro no-lowereable igual pueden
                // ser referenciados por otro macro lowereable.
            }
        }
        /* Los METODOS comptime (un constructor comptime, por ejemplo) tambien
         * llaman a helpers, y sin recorrerlos el helper no entra al set: su
         * llamada acababa rechazada como "no es comptime-evaluable" pese a
         * estar dentro de un cuerpo que se ejecuta al compilar. */
        auto scan_methods = [&](const auto &methods) {
            for (const auto &m : methods) {
                if (!m || !m->body || !m->is_comptime) continue;
                visiting.clear();
                (void)macro_body_unsupported_reason(tc_, m->body.get());
            }
        };
        for (auto &decl : mod_.decls) {
            if (!decl) continue;
            if (decl->kind == ast::NodeKind::StructDecl)
                scan_methods(
                    static_cast<ast::StructDecl *>(decl.get())->methods);
            else if (decl->kind == ast::NodeKind::ClassDecl)
                scan_methods(
                    static_cast<ast::ClassDecl *>(decl.get())->methods);
        }
        set_macro_force_lower(nullptr);
        set_macro_visiting(nullptr);
    }
}

/**
 * @brief Cablea al arranque lo que el modulo necesite antes del codigo propio.
 *
 * Solo compilando a nativo, y solo despues de bajarlo TODO: el disparador de
 * cada pieza puede aparecer en cualquier funcion, y `main` se baja la primera,
 * asi que mirarlo antes de tiempo daria que nadie la usa.  Cada pieza se
 * engancha metiendo su llamada al principio de `main`.
 *
 * Son tres: la deteccion de lo que sabe hacer el procesador, que tiene que
 * correr UNA vez antes que nada; la copia por-hilo de los `thread_local` con
 * valor inicial, que el cargador de Windows llama en cada hilo que empieza; y
 * el arranque del recolector, que ademas registra los mapas de pila -- sin
 * ellos el barrido no ve los objetos vivos de los marcos nativos -- y planta
 * el vaciado de finalizadores antes de cada salida de `main`.
 *
 * @param out_module El modulo IR ya bajado, que aqui se retoca.
 */
void Lowering::emit_startup_wiring(ir::IrModule &out_module) {
    // CPU dispatch (cimiento): si algun cpu_features() se uso, prepender
    // `call __vx_cpu_init` al ENTRY de main para que la deteccion corra UNA
    // VEZ antes de cualquier codigo del usuario.  Se hace AQUI (post-lowering)
    // y no en lower_function porque main se baja ANTES que el resto: un
    // cpu_features() en una funcion no-main marca cpu_features_used_ DESPUES
    // de cerrar main.  Solo en native_poo_ (AOT): el helper usa INLINE_ASM
    // (PURE_NATIVE) + el wiring no toca el stub _start.
    // AUTO multiversion (--float-isa auto): si main tiene ops VEC_*,
    // renombrarlo a __vx_main_body + sintetizar un main que despacha por cpuid.
    // Debe correr ANTES del wiring de inits (necesita que main exista como el
    // wrapper para prepender alli el call __vx_auto_init).
    ensure_auto_multiversion(out_module);

    if (native_poo_ && (cpu_features_used_ || cpu_dispatch_used_)) {
        // Asegurar que el global de features + el helper __vx_cpu_init existan
        // (idempotente).  El cpuid corre primero: el dispatch lee el bitmask.
        (void)ensure_cpu_features_global();
        // Cada init se prepone SOLO si su mecanismo de dispatch se emitio
        // (evita arrastrar la maquinaria memcpy a un programa que solo usa
        // strcmp/strlen, y viceversa).  Inc 5a: el strdisp_init setea los fp
        // de strcmp/strlen (override del usuario o baseline; sin cpuid).
        const bool mc_disp = memcpy_helpers_emitted_;
        const bool sd_disp = strdisp_emitted_;
        // Localizar main y prepender las CALL a su bloque de entrada.  El
        // ORDEN final de ejecucion debe ser:  __vx_cpu_init (cpuid) ->
        // __vx_memcpy_init -> __vx_strdisp_init -> codigo del usuario.
        // insert(begin()) prepende, asi que insertamos en orden inverso:
        // strdisp_init, luego memcpy_init, luego cpu_init (queda de primero).
        for (auto &f : out_module.functions) {
            if (f.name != "main") continue;
            if (f.blocks.empty()) break;
            auto &ins = f.blocks[0].instrs;
            if (sd_disp) {
                ir::IrInstr call_sd{};
                call_sd.op = ir::IrOp::CALL;
                call_sd.type = ir::IrType::VOID;
                call_sd.dst = ir::IR_NO_VALUE;
                call_sd.func_name = "__vx_strdisp_init";
                call_sd.source_line = 0;
                ins.insert(ins.begin(), std::move(call_sd));
            }
            if (mc_disp) {
                ir::IrInstr call_mc{};
                call_mc.op = ir::IrOp::CALL;
                call_mc.type = ir::IrType::VOID;
                call_mc.dst = ir::IR_NO_VALUE;
                call_mc.func_name = "__vx_memcpy_init";
                call_mc.source_line = 0;
                ins.insert(ins.begin(), std::move(call_mc));
            }
            if (auto_dispatch_emitted_) {
                // AUTO: el dispatch del main (setea __vx_main_body$fp).  Debe
                // ir DESPUES de cpu_init (lee el bitmask) y ANTES del CALLIND
                // del wrapper (que lee el fp).  Se inserta aqui (antes que
                // cpu_init) para quedar justo tras el en el orden final.
                ir::IrInstr call_auto{};
                call_auto.op = ir::IrOp::CALL;
                call_auto.type = ir::IrType::VOID;
                call_auto.dst = ir::IR_NO_VALUE;
                call_auto.func_name = "__vx_auto_init";
                call_auto.source_line = 0;
                ins.insert(ins.begin(), std::move(call_auto));
            }
            ir::IrInstr call_init{};
            call_init.op = ir::IrOp::CALL;
            call_init.type = ir::IrType::VOID;
            call_init.dst = ir::IR_NO_VALUE;
            call_init.func_name = "__vx_cpu_init";
            call_init.source_line = 0;
            ins.insert(ins.begin(), std::move(call_init));
            break;
        }
    }

    // TLS callback (thread_local PE): si el modulo tiene thread_local con init
    // != 0, sintetizar __vx_tls_init -- la funcion que el cargador de Windows
    // llama en cada attach de hilo (registrada en AddressOfCallBacks del
    // IMAGE_TLS_DIRECTORY).  Escribe la plantilla a la copia por-hilo (el
    // cargador no siempre la copia para el TLS de una .dll en un consumidor
    // minimal sin CRT).  Reusa el acceso TLS (STR_LIT_ADDR is_tls -> store),
    // que el driver baja a gs:[0x58]+secrel.  Idempotente y barato (N stores
    // por attach; N = thread_local con init != 0).
    if (native_poo_ && !tls_nonzero_inits_.empty()) {
        ir::IrFunction ti;
        ti.name = "__vx_tls_init";
        // Devuelve i64 1 (TRUE): __vx_tls_init es el ENTRY POINT (DllMain) de
        // la .dll -- el cargador lo llama en cada attach de hilo y aqui
        // aplicamos la plantilla por-hilo (ntdll no la copia para el TLS de una
        // .dll sin un entry que dispare su init).  DllMain debe devolver TRUE o
        // la carga falla.  (Tambien queda registrado como TLS callback, que
        // ignora el retorno.)
        ti.ret_type = ir::IrType::I64;
        const ir::IrBlockId e = ti.new_block("entry");
        for (const auto &pr : tls_nonzero_inits_) {
            const uint64_t slot = pr.first;
            const uint64_t val = pr.second;
            // %addr = &tls_var (STR_LIT_ADDR del slot; is_tls lo deriva el
            // driver desde SD_FLAG_TLS -> acceso por thread pointer).
            const ir::IrValueId v_addr = ti.new_value(ir::IrType::PTR);
            ti.values[v_addr].is_host_ptr = true;
            {
                ir::IrInstr a{};
                a.op = ir::IrOp::STR_LIT_ADDR;
                a.type = ir::IrType::PTR;
                a.dst = v_addr;
                a.imm = slot;
                ti.append(e, std::move(a));
            }
            // %v = CONST val (8B); el slot esta padded a 8 -> store uniforme
            // i64.
            const ir::IrValueId v_val = ti.new_value(ir::IrType::I64);
            {
                ir::IrInstr c{};
                c.op = ir::IrOp::CONST;
                c.type = ir::IrType::I64;
                c.dst = v_val;
                c.imm = val;
                ti.append(e, std::move(c));
            }
            {
                ir::IrInstr s{};
                s.op = ir::IrOp::STORE;
                s.type = ir::IrType::I64;
                s.operands = {v_val, v_addr};
                ti.append(e, std::move(s));
            }
        }
        // return 1 (TRUE) -- DllMain debe devolver no-cero o la carga falla.
        const ir::IrValueId v_one = ti.new_value(ir::IrType::I64);
        {
            ir::IrInstr c{};
            c.op = ir::IrOp::CONST;
            c.type = ir::IrType::I64;
            c.dst = v_one;
            c.imm = 1;
            ti.append(e, std::move(c));
        }
        {
            ir::IrInstr r{};
            r.op = ir::IrOp::RET;
            r.type = ir::IrType::I64;
            r.operands = {v_one};
            ti.append(e, std::move(r));
        }
        out_module.add_function(std::move(ti));
    }

    // gc<T> opt-in: si el modulo usa gc<T> (CLASE, unique, shared o primitivo),
    // generar __vxgc_init que (1) llama vx_gc_init -> construye el heap E
    // INSTALA el runner nativo de finalizadores, y (2) registra los stackmaps
    // AOT (seccion .vxgc_smap) en el GC al arranque, inyectando un CALL a el al
    // INICIO de main -> el scan preciso ve los frames nativos y los gc<T> vivos
    // sobreviven la coleccion.  El driver emite la seccion .vxgc_smap tras el
    // layout (con relocs a cada funcion).
    //
    // El gate no puede limitarse a `classes_used_gc_` (gc<Clase>): un
    // gc<unique<T>>/gc<shared<T>> NO es una clase pero SI aloca via vx_gc_* y
    // registra un finalizador -- sin vx_gc_init su runner no se instala y el
    // finalizador se descarta (deleter/dtor no corre -> FUGA en AOT, bugs
    // 248).  Detectamos el uso REAL de gc<T> escaneando si alguna funcion
    // emitida referencia un simbolo `vx_gc_*` (uniforme para clase/unique/
    // shared/primitivo).
    bool module_uses_gc =
        !classes_used_gc_.empty() || module_has_gc_finalizers_;
    if (native_poo_ && !module_uses_gc) {
        for (const auto &f : out_module.functions) {
            for (const auto &b : f.blocks) {
                for (const auto &ins : b.instrs)
                    if (ins.func_name.rfind("vx_gc_", 0) == 0) {
                        module_uses_gc = true;
                        break;
                    }
                if (module_uses_gc) break;
            }
            if (module_uses_gc) break;
        }
    }
    if (native_poo_ && module_uses_gc) {
        ir::IrFunction gi;
        gi.name = "__vxgc_init";
        gi.ret_type = ir::IrType::VOID;
        const ir::IrBlockId e = gi.new_block("entry");
        // CALL vx_gc_init(): construye el heap global E INSTALA el runner
        // nativo de finalizadores (gc_finalizer_run_native).  Debe correr antes
        // del primer alloc/register_finalizer para que los finalizadores de
        // objetos escapados se ejecuten (deleter/dtor nativo) al colectar/exit.
        {
            ir::IrInstr ci{};
            ci.op = ir::IrOp::CALL;
            ci.type = ir::IrType::VOID;
            ci.dst = ir::IR_NO_VALUE;
            ci.func_name = "vx_gc_init";
            ci.is_call_site = true;
            gi.append(e, std::move(ci));
        }
        // %start = section_start(".vxgc_smap")  (PTR)
        const ir::IrValueId v_start = gi.new_value(ir::IrType::PTR);
        gi.values[v_start].is_host_ptr = true;
        {
            ir::IrInstr r{};
            r.op = ir::IrOp::SECTION_REF;
            r.type = ir::IrType::PTR;
            r.dst = v_start;
            r.func_name = ".vxgc_smap";
            r.imm = 0; // START
            gi.append(e, std::move(r));
        }
        // call vx_gc_register_aot_stackmaps(%start)  -- el tamanño total va
        // EMBEBIDO en el header de la seccion (section_size seria una reloc
        // SIZE no soportada en .obj/.o; section_start es una ADDR normal).
        {
            ir::IrInstr c{};
            c.op = ir::IrOp::CALL;
            c.type = ir::IrType::VOID;
            c.dst = ir::IR_NO_VALUE;
            c.func_name = "vx_gc_register_aot_stackmaps";
            c.operands = {v_start};
            gi.append(e, std::move(c));
        }
        {
            ir::IrInstr r{};
            r.op = ir::IrOp::RET;
            r.type = ir::IrType::VOID;
            gi.append(e, std::move(r));
        }
        out_module.add_function(std::move(gi));
        // Inyectar CALL __vxgc_init al inicio de main (antes de todo, incl. los
        // inits de cpu): el registro debe correr antes del primer gc<T> alloc.
        for (auto &f : out_module.functions) {
            if (f.name != "main" || f.blocks.empty()) continue;
            ir::IrInstr cg{};
            cg.op = ir::IrOp::CALL;
            cg.type = ir::IrType::VOID;
            cg.dst = ir::IR_NO_VALUE;
            cg.func_name = "__vxgc_init";
            f.blocks[0].instrs.insert(f.blocks[0].instrs.begin(),
                                      std::move(cg));
            break;
        }
        // Shutdown-time: inyectar CALL vx_gc_finalize_all ANTES de cada RET de
        // main.  Garantiza cero fuga del recurso interno de objetos gc<T> con
        // finalizador que ESCAPARON su scope y el sweep no colecto todavia (el
        // finalizador corre su deleter/dtor nativo antes del exit).  El valor
        // de retorno de main (RET %v) se preserva: el CALL se inserta ANTES del
        // RET pero no toca su operando.  Solo si el modulo registra
        // finalizadores (algun gc<T> con recurso interno): si no, es no-op
        // inofensivo.
        if (module_has_gc_finalizers_) {
            for (auto &f : out_module.functions) {
                if (f.name != "main") continue;
                for (auto &blk : f.blocks) {
                    for (size_t i = 0; i < blk.instrs.size(); ++i) {
                        if (blk.instrs[i].op != ir::IrOp::RET) continue;
                        ir::IrInstr cf{};
                        cf.op = ir::IrOp::CALL;
                        cf.type = ir::IrType::VOID;
                        cf.dst = ir::IR_NO_VALUE;
                        cf.func_name = "vx_gc_finalize_all";
                        cf.is_call_site = true;
                        blk.instrs.insert(blk.instrs.begin() + i,
                                          std::move(cf));
                        ++i; // saltar el RET recien desplazado
                    }
                }
                break;
            }
        }
    }
}


/**
 * @brief Rellena el parametro `string[] args` de `main`.
 *
 * La firma `i32 main(string[] args)` se aceptaba y `args[0]` compilaba, pero
 * nadie llenaba nunca ese parametro: la variable traia lo que hubiera, asi
 * que indexarla leia de la direccion cero y el programa moria con
 * "invalid memory access".  Los argumentos solo se podian leer con
 * `args_count()` y `args_get(i)` -- que es de donde salen tambien ahora, para
 * que las dos formas no puedan discrepar.
 *
 * Se construye un bloque de `argc` huecos de ocho bytes en memoria del
 * anfitrion y se guarda en cada uno el identificador de la cadena que
 * devuelve `args_get(i)`.  El indice vive en un hueco de pila en vez de en un
 * PHI: la funcion todavia no tiene cuerpo bajado y un contador en memoria
 * evita tener que coser la confluencia a mano.
 *
 * `args[0]` es el PRIMER argumento del usuario, no el nombre del ejecutable,
 * porque es lo que ya devuelve `args_get(0)`: dos formas de leer lo mismo que
 * no empiecen a contar igual son una trampa, no una comodidad.
 *
 * Se emite SIEMPRE que el parametro este declarado, aunque el cuerpo no lo
 * toque.  Afinarlo pide saber si el nombre se USA, y ese calculo falla del
 * lado malo: si se equivoca por poco, el parametro se queda sin rellenar y
 * vuelve la lectura de la direccion cero -- un fallo mudo -- en vez de un
 * getargc de mas, que cuesta una llamada al entrar a `main`.
 *
 * @param fd La funcion que se esta bajando.
 * @return true si se relleno algo (o sea, si era `main` con ese parametro).
 */
bool Lowering::emit_main_args_prologue(const ast::FunctionDecl *fd) {
    if (!fd || fd->name != "main") return false;
    // El parametro que buscamos: `string[] nombre`, sin tamano escrito.
    const ast::ParamDecl *pd = nullptr;
    for (const auto &p : fd->params) {
        if (!p || !p->type || p->type->kind != ast::NodeKind::ArrayTypeNode)
            continue;
        const auto *at = static_cast<const ast::ArrayTypeNode *>(p->type.get());
        if (!at->element_type ||
            at->element_type->kind != ast::NodeKind::PrimitiveTypeNode)
            continue;
        const auto *et =
            static_cast<const ast::PrimitiveTypeNode *>(at->element_type.get());
        if (et->prim != PrimitiveKind::STRING) continue;
        pd = p.get();
        break;
    }
    if (!pd) return false;

    const uint32_t ln = static_cast<uint32_t>(pd->loc.line);
    const ir::IrValueId v_argc = emit_getargc(ln);
    const ir::IrValueId v_ocho = emit_const(ir::IrType::I64, 8, ln);
    // Un hueco de mas: con cero argumentos, pedir cero bytes puede devolver
    // nada, y entonces el propio `args` seria un puntero invalido en vez de
    // un array vacio.
    const ir::IrValueId v_uno = emit_const(ir::IrType::I64, 1, ln);
    const ir::IrValueId v_n1 =
        emit_ir_binop(ir::IrOp::ADD, v_argc, v_uno, ir::IrType::I64, ln);
    const ir::IrValueId v_bytes =
        emit_ir_binop(ir::IrOp::MUL, v_n1, v_ocho, ir::IrType::I64, ln);

    ir::IrValueId v_buf = fn_->new_value(ir::IrType::PTR);
    fn_->values[v_buf].is_host_ptr = true;
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::RAW_ALLOC;
        al.type = ir::IrType::PTR;
        al.dst = v_buf;
        al.operands = {v_bytes};
        al.source_line = ln;
        emit(current_block_, std::move(al));
    }

    // El contador, en un hueco de pila del anfitrion.
    const ir::IrValueId v_i_slot = stack_alloc_buf(8, ln, /*host_memory=*/true);
    emit_store_i64(v_i_slot, emit_const(ir::IrType::I64, 0, ln), ln);

    const ir::IrBlockId bb_test = fn_->new_block("args_test");
    const ir::IrBlockId bb_body = fn_->new_block("args_body");
    const ir::IrBlockId bb_done = fn_->new_block("args_done");
    emit_br(bb_test, ln);

    current_block_ = bb_test;
    block_terminated_ = false;
    const ir::IrValueId v_i = emit_load_i64(v_i_slot, ln);
    const ir::IrValueId v_sigue =
        emit_ir_binop(ir::IrOp::CMP_LT, v_i, v_argc, ir::IrType::BOOL, ln);
    emit_br_cond_from(bb_test, v_sigue, bb_body, bb_done, ln);

    current_block_ = bb_body;
    block_terminated_ = false;
    const ir::IrValueId v_i2 = emit_load_i64(v_i_slot, ln);
    const ir::IrValueId v_h = emit_getarg(v_i2, ln);
    const ir::IrValueId v_off =
        emit_ir_binop(ir::IrOp::MUL, v_i2, v_ocho, ir::IrType::I64, ln);
    ir::IrValueId v_addr =
        emit_ir_binop(ir::IrOp::ADD, v_buf, v_off, ir::IrType::PTR, ln);
    fn_->values[v_addr].is_host_ptr = true;
    emit_store_i64(v_addr, v_h, ln);
    emit_store_i64(v_i_slot,
                   emit_ir_binop(ir::IrOp::ADD, v_i2, v_uno, ir::IrType::I64,
                                 ln),
                   ln);
    emit_br(bb_test, ln);

    current_block_ = bb_done;
    block_terminated_ = false;
    // Y a partir de aqui, el nombre del parametro ES ese bloque.
    bind(pd->name, v_buf);
    return true;
}
} // namespace vx
