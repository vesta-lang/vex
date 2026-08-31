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
#include "lowering_internal.h" // la cocina compartida del lowering

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
static uint64_t float_bits_for_global(double d, bool is_f32) {
    uint64_t bits = 0;
    if (is_f32) {
        const float f = static_cast<float>(d);
        uint32_t u32 = 0;
        std::memcpy(&u32, &f, sizeof(u32));
        bits = u32;
    } else {
        std::memcpy(&bits, &d, sizeof(d));
    }
    return bits;
}

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
        if (!d->loc.file.empty()) {
            current_file_ = d->loc.file;
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
            bool literal_const =
                gv->is_const && gv->init &&
                (gv->init->kind == ast::NodeKind::IntLitExpr ||
                 gv->init->kind ==
                     ast::NodeKind::StringLitExpr // 2026-05-23 const string
                 // global
                 || (gv->init->kind == ast::NodeKind::UnaryExpr &&
                     static_cast<ast::UnaryExpr *>(gv->init.get())->op ==
                         ast::UnOp::Neg &&
                     static_cast<ast::UnaryExpr *>(gv->init.get())->operand &&
                     static_cast<ast::UnaryExpr *>(gv->init.get())
                             ->operand->kind == ast::NodeKind::IntLitExpr));
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
                                cval = float_bits_for_global(d, g_is_f32);
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
                                    cval = float_bits_for_global(d, g_is_f32);
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

    // Pre-pase: identificar variables locales cuya direccion se toma con
    // '&'.  Influye en lower_var_decl (ALLOCA en lugar de SSA) y en
    // read_local / write_local (LOAD/STORE).
    address_taken_locals_.clear();
    host_bearing_locals_.clear();
    // `static` locals: mapa nombre->slot global, unico por funcion.
    static_local_slots_.clear();
    // Limpiar mapa de labels de goto (per-funcion).
    goto_labels_.clear();
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

} // namespace vx
