/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/calls.cpp
 * @brief Bajada de invocar algo: llamadas, construccion de objetos y lambdas.
 *
 * "Llamar" en Vesta no es una sola cosa, y averiguar CUAL es el trabajo de este
 * fichero: una funcion del modulo, una nativa de una biblioteca, un puntero a
 * funcion, un metodo por la tabla virtual, una lambda con su entorno, un
 * builtin que el compilador baja el mismo, o un constructor -- que ademas tiene
 * que reservar el objeto antes de llamar --.  Cada una tiene su convencion para
 * pasar los argumentos y recoger el resultado, y elegir mal no falla al
 * compilar: falla al ejecutar.
 */
#include "vx/lowering.h"
#include "jit/naked_native.h" // la clave del despachador, calculada en UN sitio
#include "vx/collection_intrinsics.h"
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

/**
 * @brief Emite la llamada a una funcion @c @Naked a traves del despachador.
 *
 * Una funcion @c @Naked no tiene prologo ni epilogo: su cuerpo es ensamblador
 * puro, asi que no se puede llamar como a cualquier otra.  Se llama a un
 * despachador del runtime, que la localiza por una CLAVE calculada del nombre y
 * salta a ella con la convencion nativa.
 *
 * La clave la calcula @c jit::fnv1a64_name, y se usa la SUYA a proposito: quien
 * baja la llamada y quien la resuelve tienen que sacar exactamente el mismo
 * numero.  Antes esto estaba escrito a mano aqui -- dos veces, una por cada
 * forma de nombrar la funcion -- con la semilla y el primo copiados, y el
 * comentario de al lado avisando de que "DEBE coincidir".  Tres sitios donde
 * cambiar un digito rompe el enlace, y el fallo seria mudo: el despachador no
 * encuentra la funcion.
 *
 * Los tres primeros argumentos son fijos -- el proceso, la clave y cuantos
 * argumentos reales hay -- y detras van los del usuario.
 *
 * @param label   El nombre con el que la funcion quedo registrada.
 * @param e       La llamada.
 * @param ret_ir  El tipo que devuelve.
 * @param out_dst Donde dejar el valor devuelto (sin valor si es void).
 * @return @c false si alguno de los argumentos no se pudo bajar.
 */
bool Lowering::emit_naked_dispatch(const std::string &label, ast::CallExpr *e,
                                   ir::IrType ret_ir, ir::IrValueId &out_dst) {
    out_mod_->register_native_import("vrt", "naked_dispatch");

    std::vector<ir::IrValueId> arg_ids;
    arg_ids.reserve(e->args.size() + 3);
    arg_ids.push_back(emit_getproc(e->loc.line));
    arg_ids.push_back(emit_const(
        ir::IrType::I64, jit::fnv1a64_name(label.c_str()), e->loc.line));
    arg_ids.push_back(emit_const(
        ir::IrType::I64, static_cast<uint64_t>(e->args.size()), e->loc.line));

    for (auto &a : e->args) {
        const ir::IrValueId av = lower_expr(a.get());
        if (av == ir::IR_NO_VALUE) {
            out_dst = ir::IR_NO_VALUE;
            return false;
        }
        arg_ids.push_back(av);
    }

    out_dst =
        (ret_ir == ir::IrType::VOID) ? ir::IR_NO_VALUE : fn_->new_value(ret_ir);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::CALLN;
    ins.type = ret_ir;
    ins.dst = out_dst;
    ins.func_name = "vrt:naked_dispatch";
    ins.operands = std::move(arg_ids);
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));
    return true;
}
ir::IrValueId Lowering::lower_call(ast::CallExpr *e) {
    /* A.43.10: macros Lisp con splice/emit.  Si el type checker
     * sustituyo la llamada por un AST expandido (campo macro_expanded
     * no-null), bajamos directamente el AST sustituido en lugar de
     * emitir una llamada al builtin.  Esto convierte el call site
     * en codigo runtime real generado a partir de string compile-time. */
    if (e->macro_expanded) {
        // Si el @Macro se expandio a un literal string (`source(expr)` ->
        // `"texto"`), coaccionarlo a StringObject GC-managed en lugar de
        // bajarlo como puntero crudo (STR_LIT_ADDR).  Sin esto, `string s =
        // macro()` y
        // `${macro()}` recibian una direccion cruda en vez del contenido.
        if (e->macro_expanded->kind == ast::NodeKind::StringLitExpr) {
            return lower_string_literal_to_string_object(
                static_cast<ast::StringLitExpr *>(e->macro_expanded.get()));
        }
        return lower_expr(e->macro_expanded.get());
    }

    /* Constructor de STRUCT: `Struct(args)`.  El type checker dejo
     * result_type = STRUCT y el callee es el nombre de un struct con
     * constructor.  Value-type: alocamos el buffer del struct en host-stack,
     * llamamos `<Struct>__ctor(buffer, args...)` -- que lo inicializa via su
     * `this` -- y el resultado es el propio buffer (ptr al struct construido).
     */
    if (e->callee && e->callee->kind == ast::NodeKind::IdentExpr &&
        e->result_type.kind == PrimitiveKind::STRUCT) {
        auto *cid = static_cast<ast::IdentExpr *>(e->callee.get());
        auto it_sc = tc_.struct_layouts().find(cid->name);
        // El tipo resuelto se compara con el del LAYOUT, no con el nombre
        // escrito: uno importado se usa por su nombre local (`P`) y su
        // layout se llama con el cualificado (`t__p__P`).  Exigir que
        // coincidieran hacia que construir un tipo importado no se
        // reconociera como construccion, y acabara emitido como una
        // llamada a una funcion con el nombre del tipo.
        if (it_sc != tc_.struct_layouts().end() &&
            (it_sc->second.name.empty() ? cid->name : it_sc->second.name) ==
                e->result_type.struct_name) {
            const StructLayout &slay = it_sc->second;
            // F1b: si el struct tiene un ctor `comptime` para esta aridad, se
            // ejecuta en compile-time y el struct se materializa como datos
            // (sin llamada en runtime); si no aplica, sigue el ctor runtime.
            if (const ir::IrValueId v_ct =
                    try_lower_comptime_ctor_call(e, slay);
                v_ct != ir::IR_NO_VALUE)
                return v_ct;
            bool has_ctor = false;
            for (const auto &m : slay.methods)
                if (m.is_constructor) {
                    has_ctor = true;
                    break;
                }
            if (has_ctor) {
                const uint64_t buf_bytes =
                    (static_cast<uint64_t>(slay.size_bytes) + 7ULL) & ~7ULL;
                const ir::IrValueId v_buf =
                    stack_alloc_buf(buf_bytes, e->loc.line, true);
                fn_->values[v_buf].is_host_ptr = true;

                /* Los valores por defecto de los campos, ANTES del cuerpo: la
                 * semantica es "defectos primero, constructor encima".
                 *
                 * El bufer nace sin inicializar y el constructor solo escribe
                 * lo que escribe, asi que un campo con valor declarado que el
                 * constructor no toca se quedaba con lo que hubiera ahi -- y
                 * como el bufer suele venir limpio, se leia como un cero:
                 * `struct S { i64 n = 3; S() {} }` daba `n == 0`.  Y solo
                 * cuando la clase tenia constructor: sin el, la declaracion si
                 * pasa por aqui, asi que anyadir uno CAMBIABA el valor de un
                 * campo que no se habia tocado.
                 *
                 * El constructor `comptime` ya sembraba sus defectos por su
                 * cuenta (los escribe en el bufer antes de ejecutar el cuerpo
                 * en la maquina de compilacion); esto es lo mismo para el de
                 * ejecucion. */
                emit_struct_field_defaults(v_buf, slay, e->loc.line);

                std::vector<ir::IrValueId> operands;
                operands.reserve(e->args.size() + 1);
                operands.push_back(v_buf); // this = buffer a inicializar
                for (auto &a : e->args) {
                    const ir::IrValueId av = lower_expr(a.get());
                    if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                    operands.push_back(av);
                }
                ir::IrInstr ins{};
                ins.op = ir::IrOp::CALL;
                ins.type = ir::IrType::VOID;
                ins.dst = ir::IR_NO_VALUE;
                ins.func_name = (slay.name.empty() ? cid->name : slay.name) +
                                "__ctor_" + std::to_string(e->args.size());
                ins.operands = std::move(operands);
                ins.source_line = e->loc.line;
                emit(current_block_, std::move(ins));
                return v_buf;
            }
        }
    }

    /* `source(arg)` (y cualquier comptime fn IMPORTADA pass-through con un
     * unico param `expr` cuyo body es `return code`): es un quasi-quote --
     * captura su argumento como texto/plantilla y lo DEVUELVE tal cual.  No
     * tiene bytecode local que invocar (es importada), asi que un CALLVM
     * `code.__macro_source` colgaria en el linker.  La INLINEAMOS: `source(X)`
     * baja exactamente como `X`.  Cuando `X` es una plantilla con huecos
     * `${expr}` (StringLitExpr interpolado que arma el parser), se baja por el
     * path normal de interpolacion de strings -> funciona en interp/JIT/AOT
     * igual que cualquier `"...${x}..."`, no solo en comptime. */
    if (e->callee && e->callee->kind == ast::NodeKind::IdentExpr &&
        e->args.size() == 1 && e->args[0]) {
        const std::string &cn =
            static_cast<ast::IdentExpr *>(e->callee.get())->name;
        auto cf_it = tc_.comptime_fns().find(cn);
        if (cf_it != tc_.comptime_fns().end() && cf_it->second &&
            cf_it->second->is_imported_comptime && !cf_it->second->is_macro &&
            cf_it->second->params.size() == 1 && cf_it->second->params[0] &&
            cf_it->second->params[0]->is_expr_capture) {
            ast::Expr *arg = e->args[0].get();
            if (arg->kind == ast::NodeKind::StringLitExpr) {
                return lower_string_literal_to_string_object(
                    static_cast<ast::StringLitExpr *>(arg));
            }
            return lower_expr(arg);
        }
    }

    // Overlay F1: construccion `PEB(ptr)` de un `@overlay struct`.  El valor
    // del overlay ES el puntero base (memoria host ajena): lo bajamos y lo
    // marcamos como host_ptr para que el acceso a campos emita loads/stores
    // host.
    if (e->callee && e->callee->kind == ast::NodeKind::IdentExpr &&
        e->result_type.kind == PrimitiveKind::STRUCT) {
        const std::string &cn =
            static_cast<ast::IdentExpr *>(e->callee.get())->name;
        auto it = tc_.struct_layouts().find(cn);
        if (it != tc_.struct_layouts().end() && it->second.is_overlay &&
            e->args.size() == 1) {
            ir::IrValueId base = lower_expr(e->args[0].get());
            if (base == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            // El overlay es una VISTA sobre memoria host: forzar la naturaleza.
            fn_->values[base].is_host_ptr = true;
            return base;
        }
    }

    {
        ir::IrValueId v_def = ir::IR_NO_VALUE;
        if (try_lower_struct_default_ctor(e, v_def)) return v_def;
    }

    {
        ir::IrValueId v_ind = ir::IR_NO_VALUE;
        if (try_lower_indirect_call(e, v_ind)) return v_ind;
    }

    {
        ir::IrValueId v_ns = ir::IR_NO_VALUE;
        if (try_lower_namespaced_call(e, v_ns)) return v_ns;
    }

    {
        ir::IrValueId v_ct = ir::IR_NO_VALUE;
        if (try_lower_comptime_fn_call(e, v_ct)) return v_ct;
    }

    {
        ir::IrValueId v_enum = ir::IR_NO_VALUE;
        if (try_lower_enum_variant_ctor(e, v_enum)) return v_enum;
    }
    {
        ir::IrValueId v_meth = ir::IR_NO_VALUE;
        if (try_lower_method_call(e, v_meth)) return v_meth;
    }

    // Resto: llamada directa a funcion top-level.
    if (!e->callee || e->callee->kind != ast::NodeKind::IdentExpr) {
        error_at(e->loc, "lowering: callee no es identificador");
        return ir::IR_NO_VALUE;
    }
    auto *id = static_cast<ast::IdentExpr *>(e->callee.get());

    // FFI declarativo: si el callee es una funcion extern
    // (registrada en extern_lib_by_fn_name_ via ExternFnDecl), emitir
    // directamente CALLN @Method("<lib>:<name>") con args en R1..RN.
    // Cero overhead vs llamadas a plugins propios: usa exactamente la
    // misma maquinaria del ensamblador (LoadLibraryA + GetProcAddress).
    {
        auto it_ext = extern_lib_by_fn_name_.find(id->name);
        if (it_ext != extern_lib_by_fn_name_.end()) {
            const std::string &lib = it_ext->second;
            // FN.3: en AOT (native_poo) los externs de coordinacion de fibras
            // `vrt:jit_active` / `vrt:getproc` NO existen como simbolos nativos
            // (viven en el runtime interp/JIT).  Se pliegan a CONST 0:
            // jit_active=0 convierte la rama JIT del setup de fibras en codigo
            // muerto (lo elimina el optimizador), y getproc solo vive dentro
            // de esa rama.  Asi el binario AOT enlaza sin simbolos indefinidos
            // y usa el modelo directo (contexto/pila globales, entry nativa).
            if (native_poo_ && lib == "vrt" &&
                (id->name == "jit_active" || id->name == "getproc" ||
                 id->name == "fiber_jit_ctx" ||
                 id->name == "fiber_jit_scratch")) {
                ir::IrType rt = ir::IrType::I64;
                auto it_rt0 = fn_return_types_.find(id->name);
                if (it_rt0 != fn_return_types_.end() &&
                    it_rt0->second != ir::IrType::VOID)
                    rt = it_rt0->second;
                return emit_const(rt, 0, e->loc.line);
            }
            out_mod_->register_native_import(lib, id->name);
            std::vector<ir::IrValueId> arg_ids;
            arg_ids.reserve(e->args.size());
            for (auto &a : e->args) {
                arg_ids.push_back(lower_expr(a.get()));
            }
            ir::IrType ret_ir = ir::IrType::VOID;
            auto it_rt = fn_return_types_.find(id->name);
            if (it_rt != fn_return_types_.end()) ret_ir = it_rt->second;
            const ir::IrValueId dst = (ret_ir == ir::IrType::VOID)
                                          ? ir::IR_NO_VALUE
                                          : fn_->new_value(ret_ir);
            ir::IrInstr ins{};
            ins.op = ir::IrOp::CALLN;
            ins.type = ret_ir;
            ins.dst = dst;
            ins.func_name = lib + ":" + id->name;
            ins.operands = std::move(arg_ids);
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            return dst;
        }
    }

    // Bug/feature 198: llamada a una funcion @Naked.  En AOT todo es nativo y
    // la llamada normal ya funciona; pero en interp/JIT (VM_ABI) una @Naked no
    // tiene representacion en bytecode VM (su cuerpo es asm nativo puro con ABI
    // del host).  Enrutamos la llamada al dispatcher @c vrt:naked_dispatch, que
    // compila la @Naked al vuelo (con sus simbolos propios resueltos) y la
    // invoca con ABI nativo.  Convencion CALLN:
    //   R1 = proc, R2 = name_hash, R3 = argc_real, R4.. = args reales.
    if (!native_poo_) {
        const FunctionSig *sig = tc_.function_sig_by_name(id->name);
        if (sig != nullptr && sig->is_naked && sig->extern_lib.empty()) {
            const std::string label =
                sig->mangled_label.empty() ? id->name : sig->mangled_label;
            const ir::IrType ret_ir =
                ir_type_from_primitive(sig->return_type.kind);
            ir::IrValueId dst = ir::IR_NO_VALUE;
            if (!emit_naked_dispatch(label, e, ret_ir, dst))
                return ir::IR_NO_VALUE;
            return dst;
        }
    }

    // Antes de tomar el camino generico, intentamos identificarla como
    // un builtin (println / print) que se traduce a una llamada FFI
    // a vesta_io.  El builtin emite por su cuenta el codigo necesario
    // (registro de bytes en static_data, getproc, calln vio_println).
    ir::IrValueId builtin_ret = ir::IR_NO_VALUE;
    if (try_lower_builtin_call(e, builtin_ret)) {
        return builtin_ret;
    }

    // -----------------------------------------------------------------
    // closures: si el identificador es una variable LOCAL cuyo
    // tipo es FUNCTION (function pointer / closure), tratamos esto
    // como llamada indirecta.  El type checker ya marco
    // @c id->result_type como Type{FUNCTION, params, ret} en este caso
    // y la variable esta bindeada en el scope al SSA value que
    // devolvio @c lower_lambda_expr (puntero al function value de
    // 16 bytes).  Aqui:
    //   1. Cargar fn_addr de [fv_addr + 0]
    //   2. Cargar env_addr de [fv_addr + 8]
    //   3. Bajar args
    //   4. Emitir CALLCLOSURE(fn_addr, env_addr, args...)
    // El emisor IR (caso CALLCLOSURE) coloca env en R14, args en
    // R1..R12 y emite @c callvmr fn_addr.
    if (id->result_type.kind == PrimitiveKind::FUNCTION) {
        // cfn (puntero a funcion crudo estilo C): la VARIABLE guarda la
        // direccion del codigo tal cual (8 bytes), NO un slot de 16 bytes.
        // La llamada es CALLIND directo sobre ese valor, sin cargar fn_addr
        // de un slot ni env.  lambda (fn) != cfn.
        if (id->result_type.fn_is_raw) {
            const ir::IrValueId fnp = lookup(id->name);
            if (fnp == ir::IR_NO_VALUE) {
                error_at(e->loc,
                         "lowering: cfn no resuelto: '" + id->name + "'");
                return ir::IR_NO_VALUE;
            }
            std::vector<ir::IrValueId> args;
            args.reserve(e->args.size());
            // Promocion del literal a StringObject segun los tipos de parametro
            // que declara el cfn (ver la misma logica en la via indirecta
            // generica): sin ella, un literal en posicion `string` llegaba como
            // puntero crudo a static_data y el callee leia basura.
            for (size_t ai = 0; ai < e->args.size(); ++ai) {
                ast::Expr *a = e->args[ai].get();
                ir::IrValueId av;
                if (a && a->kind == ast::NodeKind::StringLitExpr &&
                    ai < id->result_type.fn_params.size() &&
                    id->result_type.fn_params[ai].kind ==
                        PrimitiveKind::STRING) {
                    av = lower_string_literal_to_string_object(
                        static_cast<ast::StringLitExpr *>(a));
                } else {
                    av = lower_expr(a);
                }
                if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                args.push_back(av);
            }
            const ir::IrType rt = ir_type_from_primitive(
                id->result_type.pointee ? id->result_type.pointee->kind
                                        : PrimitiveKind::VOID);
            const ir::IrValueId dst =
                (rt == ir::IrType::VOID) ? ir::IR_NO_VALUE : fn_->new_value(rt);
            ir::IrInstr ins{};
            ins.op = ir::IrOp::CALLIND;
            ins.type = rt;
            ins.dst = dst;
            ins.func_ptr = fnp;
            ins.operands = std::move(args);
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
            return dst;
        }
        // Direccion del function value (16 bytes en stack).  Si es
        // una variable address-taken, read_local devuelve el LOAD;
        // si es directa, devuelve el SSA value tal cual.  Para
        // function values el bind ya guarda la direccion del slot.
        ir::IrValueId fv_addr = lookup(id->name);
        if (fv_addr == ir::IR_NO_VALUE) {
            error_at(e->loc,
                     "lowering: closure no resuelto: '" + id->name + "'");
            return ir::IR_NO_VALUE;
        }

        // LOAD fn_addr de [fv_addr + 0].
        ir::IrValueId fn_addr =
            emit_load_typed(fv_addr, ir::IrType::I64, e->loc.line);

        // LOAD env_addr de [fv_addr + 8].
        ir::IrValueId env_addr;
        {
            ir::IrValueId fv_plus_8 = fn_->new_value(ir::IrType::PTR);
            ir::IrValueId off8 = emit_const(ir::IrType::I64, 8, e->loc.line);
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = fv_plus_8;
            ad.operands = {fv_addr, off8};
            ad.source_line = e->loc.line;
            emit(current_block_, std::move(ad));

            env_addr = fn_->new_value(ir::IrType::I64);
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            ld.type = ir::IrType::I64;
            ld.dst = env_addr;
            ld.operands = {fv_plus_8};
            ld.source_line = e->loc.line;
            emit(current_block_, std::move(ld));
        }

        // Bajar args.  El primer operando de CALLCLOSURE es env_addr
        // (convencion del opcode); luego van los args declarados.
        std::vector<ir::IrValueId> arg_ids;
        arg_ids.reserve(1 + e->args.size());
        arg_ids.push_back(env_addr);
        for (auto &a : e->args) {
            arg_ids.push_back(lower_expr(a.get()));
        }
        /* Si el ultimo parametro recoge los que sobren, se meten en un array y
         * se pasa su direccion y cuantos son.  El uno de mas es el entorno, que
         * va delante de todo por la convencion del opcode. */
        if (id->result_type.fn_is_variadic &&
            !id->result_type.fn_params.empty() &&
            id->result_type.fn_params.back().pointee) {
            const size_t fixed = id->result_type.fn_params.size() - 1;
            if (arg_ids.size() >= 1 + fixed)
                pack_variadic_args(
                    arg_ids, 1 + fixed,
                    ir_type_from_primitive(
                        id->result_type.fn_params.back().pointee->kind),
                    e->loc.line);
        }

        // Tipo de retorno deducido del FUNCTION type del callee.
        ir::IrType ret_ir = ir::IrType::VOID;
        if (id->result_type.pointee &&
            id->result_type.pointee->kind != PrimitiveKind::VOID) {
            ret_ir = ir_type_from_primitive(id->result_type.pointee->kind);
        }
        ir::IrValueId dst = (ret_ir == ir::IrType::VOID)
                                ? ir::IR_NO_VALUE
                                : fn_->new_value(ret_ir);

        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALLCLOSURE;
        ins.type = ret_ir;
        ins.dst = dst;
        ins.func_ptr = fn_addr;
        ins.operands = std::move(arg_ids);
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        return dst;
    }

    // Resolver tipo de retorno.
    ir::IrType ret_ir = ir::IrType::I64;
    auto it = fn_return_types_.find(id->name);
    if (it != fn_return_types_.end()) ret_ir = it->second;

    // sret: si el callee declara devolver Optional<T>, Result<V,E> o
    // un enum declarado por usuario, su firma IR real es void y
    // espera un retbuf hidden como primer argumento.  Aqui en el
    // caller alocamos el buffer (16, 24 o size_bytes del enum) en
    // stack y lo pasamos.  El "valor" SSA del CALL es la direccion
    // del retbuf, que el caller bindea a la variable del var-decl o
    // pasa como argumento a otras funciones.
    PrimitiveKind callee_kind = PrimitiveKind::VOID;
    auto it_kind = fn_ret_kind_.find(id->name);
    if (it_kind != fn_ret_kind_.end()) callee_kind = it_kind->second;
    /* Si hace falta buffer, cuanto mide y donde vive: lo que se anoto al
     * registrar la funcion.  Deducirlo aqui de nuevo era la tercera copia del
     * mismo criterio, y con menos datos: desde aqui no se sabe si un puntero
     * inteligente es `unique` o `shared`, asi que se reservaban dieciseis
     * siempre; y el tamano de un `Optional` salia del tipo del sitio de la
     * llamada en vez de lo que la funcion declara devolver. */
    const SretInfo si = sret_info_for(id->name);
    const bool callee_is_sret = si.uses_buffer;
    ir::IrValueId v_call_retbuf = ir::IR_NO_VALUE;
    if (callee_is_sret) {
        v_call_retbuf = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8; // unidad: 1 byte
        al.dst = v_call_retbuf;
        // Tiene que medir EXACTAMENTE lo que el llamado copia: el llamado
        // escribe `bytes/8` palabras, asi que quedarse corto es escribir
        // fuera, en el marco de quien llama.
        al.imm = si.bytes;
        al.source_line = e->loc.line;
        // Donde vive: en memoria del anfitrion para los agregados, porque el
        // llamado marca su parametro como puntero de anfitrion y escribe con
        // `movh`.  Un lambda y un puntero inteligente NO: su bajado tiene su
        // propio manejo de memoria (entorno en el monton, bloque de control).
        if (si.host_buffer) al.host_alloca = true;
        emit(current_block_, std::move(al));
        if (si.host_buffer) fn_->values[v_call_retbuf].is_host_ptr = true;
    }

    // Bajar argumentos.  Si es sret, el retbuf va PRIMERO (convencion
    // espejo al lower_function que lo recibe como primer parametro).
    //
    // Fix - auto-promocion literal -> StringObject cuando el
    // parametro espera STRING (mismo patron que operadores +/==/!=).
    //  Sin esto, pasar `helper("hola")` a
    // `void helper(string s)` empuja la direccion del literal en
    // memoria VM (PTR) en vez del GcHandle al StringObject, y el
    // callee crashea al hacer `strraw s` con un puntero invalido.
    const FunctionSig *callee_sig = tc_.function_sig_by_name(id->name);
    std::vector<ir::IrValueId> arg_ids;
    arg_ids.reserve(e->args.size() + (callee_is_sret ? 1 : 0));
    if (callee_is_sret) arg_ids.push_back(v_call_retbuf);
    // Vesta Embed (native_poo_): args que son value-strings TEMPORALES
    // (resultado de `mk(...)` SRET-string, concat `a+b`, o cast a string)
    // tienen un buffer heap owned que nadie libera tras pasarlo al call.
    // Los recolectamos y emitimos RAW_FREE de su ptr@0 DESPUES del CALL
    // (el callee ya copio/uso los bytes).  Sin esto, `mk(mk(a,b), c)`
    // fuga el buffer del intermedio.  Los IdentExpr (variables) NO se
    // liberan: su RAII en el scope dueno lo hace (no doble-free).
    std::vector<ir::IrValueId> tmp_str_args_to_free;
    // Ruta B (H1 paso por valor): copias de structs con copy-hook que pasamos
    // por valor.  Tras el CALL, el caller emite el `~dtor` de cada copia (la
    // callee no la posee).  Pares (copy_addr, struct_name).
    std::vector<std::pair<ir::IrValueId, std::string>> struct_clone_to_dtor;
    for (size_t i = 0; i < e->args.size(); ++i) {
        ast::Expr *ae = e->args[i].get();
        // Detectar (param STRING, arg StringLitExpr no interpolado) y
        // promover el literal a StringObject inline via STRMAKE.
        bool promote_to_string = false;
        if (callee_sig && i < callee_sig->param_types.size() &&
            callee_sig->param_types[i].kind == PrimitiveKind::STRING && ae &&
            ae->kind == ast::NodeKind::StringLitExpr) {
            auto *sl = static_cast<ast::StringLitExpr *>(ae);
            if (native_poo_) {
                // Vesta Embed: el param espera un value-string nativo (24B),
                // NO un StringObject GC.  Construimos el value-string desde
                // el literal (mismo path que `string s = "..."`) en vez de
                // STRMAKE.  Lo marcamos temporal -> liberar su buffer heap
                // tras el CALL (SSO corto = no-op).  Sin esto, pasar un
                // literal directo (`fn("hola")`) emitia strmake (GC) que el
                // analyze AOT rechaza.
                ir::IrValueId v =
                    build_native_string_from_literal(sl, sl->loc.line);
                arg_ids.push_back(v);
                if (v != ir::IR_NO_VALUE) tmp_str_args_to_free.push_back(v);
            } else {
                // Tanto literales puros como interpolados: el helper
                // construye el StringObject correcto.
                arg_ids.push_back(lower_string_literal_to_string_object(sl));
            }
            promote_to_string = true;
        }
        if (!promote_to_string) {
            ir::IrValueId v_arg = lower_expr(ae);
            // Fix nested-SRET (general): si el argumento es una llamada anidada
            // a una fn que devuelve un tipo de buffer PLANO via SRET (enum,
            // Optional, Result, o string value-type de Vesta Embed -- p.ej.
            // `emit(classify(x))`), su valor SSA ES el retbuf de esa llamada:
            // un slot fragil.  Al montar los args de ESTA llamada
            // (parallel-move
            // + presion de registros), el registro que sostiene ese retbuf
            // puede clobbearse y el callee recibiria un puntero equivocado ->
            // lee basura (match sobre la primera arm, Optional vacio, etc.).
            // Copiamos el buffer a un slot FRESCO justo aqui (mismo patron que
            // `T t = productor(x)`, que ya funcionaba) y pasamos ESE,
            // desacoplandolo del retbuf productor.  Antes solo cubria enum; el
            // bug es identico para TODO SRET de buffer plano, asi que se
            // atiende de forma uniforme (function/smart-ptr se excluyen: tienen
            // semantica de ownership -- copiar el buffer duplicaria el
            // env/ctrl).
            if (v_arg != ir::IR_NO_VALUE && ae &&
                ae->kind == ast::NodeKind::CallExpr) {
                auto *ce_arg = static_cast<ast::CallExpr *>(ae);
                if (ce_arg->callee &&
                    ce_arg->callee->kind == ast::NodeKind::IdentExpr) {
                    const std::string &cn =
                        static_cast<ast::IdentExpr *>(ce_arg->callee.get())
                            ->name;
                    bool fresh_is_host = false;
                    const uint64_t sret_sz =
                        nested_sret_flat_size(cn, &fresh_is_host);
                    if (sret_sz > 0) {
                        // Slot fresco cuya NATURALEZA coincide con como el
                        // callee lee su param: VM-STACK para enum (lectura VM),
                        // HOST para Optional/Result (lectura host).  Igual que
                        // el slot de un var-decl `T t = productor(x)` del tipo
                        // correspondiente.  La copia (emit_enum_copy) lee el
                        // retbuf productor con su naturaleza real y escribe al
                        // fresh; desacopla del retbuf fragil del productor.
                        const ir::IrValueId fresh =
                            fn_->new_value(ir::IrType::PTR);
                        ir::IrInstr al{};
                        al.op = ir::IrOp::ALLOCA;
                        al.type = ir::IrType::I8;
                        al.dst = fresh;
                        al.imm = sret_sz;
                        al.host_alloca = fresh_is_host;
                        al.source_line = e->loc.line;
                        emit(current_block_, std::move(al));
                        if (fresh_is_host)
                            fn_->values[fresh].is_host_ptr = true;
                        emit_enum_copy(fresh, v_arg,
                                       fn_->values[v_arg].is_host_ptr, sret_sz,
                                       e->loc.line);
                        v_arg = fresh;
                    }
                }
            }
            // Ruta B (H1 paso por valor): si el param es un STRUCT por valor
            // con copy-hook y el arg es un lvalue existente (IdentExpr), la
            // callee debe recibir una COPIA.  Copiamos + `copia.__clone__()` y
            // pasamos la copia; el `~dtor` de la copia se emite tras el CALL.
            // Un valor fresco (CallExpr) o un struct sin copy-hook no se clona
            // (move / alias actual). Coercionar la PRECISION float del arg al
            // tipo del parametro (p.ej. un literal f64 3.0 pasado a un param
            // f32).  Sin esto se pasan los bits f64 tal cual y el callee los
            // relee como f32 -> basura (fmul.f32 de dos params daba 0).  Solo
            // float<->float; los enteros/punteros/structs los coacciona el type
            // checker o los paths de arriba.  cast_if_needed es no-op si ya
            // coinciden.
            if (v_arg != ir::IR_NO_VALUE && callee_sig &&
                i < callee_sig->param_types.size()) {
                const ir::IrType pt =
                    ir_type_from_primitive(callee_sig->param_types[i].kind);
                const ir::IrType at = fn_->values[v_arg].type;
                const bool pt_f =
                    (pt == ir::IrType::F32 || pt == ir::IrType::F64);
                const bool at_f =
                    (at == ir::IrType::F32 || at == ir::IrType::F64);
                if (pt != at && pt_f && at_f)
                    v_arg = cast_if_needed(v_arg, at, pt, e->loc.line);
            }
            bool cloned_struct = false;
            if (v_arg != ir::IR_NO_VALUE && ae &&
                ae->kind == ast::NodeKind::IdentExpr && callee_sig &&
                i < callee_sig->param_types.size() &&
                callee_sig->param_types[i].kind == PrimitiveKind::STRUCT) {
                const std::string &sn = callee_sig->param_types[i].struct_name;
                auto it_sl = tc_.struct_layouts().find(sn);
                if (it_sl != tc_.struct_layouts().end() &&
                    it_sl->second.has_copy_hook) {
                    const ir::IrValueId copy =
                        emit_struct_arg_copy_clone(v_arg, sn, e->loc.line);
                    arg_ids.push_back(copy);
                    cloned_struct = true;
                    // ~dtor de la copia tras el CALL solo si el tipo lo define.
                    bool has_dtor = false;
                    for (const auto &mm : it_sl->second.methods)
                        if (mm.is_destructor) {
                            has_dtor = true;
                            break;
                        }
                    if (has_dtor) struct_clone_to_dtor.emplace_back(copy, sn);
                }
            }
            if (!cloned_struct) arg_ids.push_back(v_arg);
            // native_poo_: marcar arg como value-string temporal a liberar.
            if (native_poo_ && v_arg != ir::IR_NO_VALUE && ae &&
                ae->result_type.kind == PrimitiveKind::STRING) {
                const bool is_tmp_str =
                    (ae->kind == ast::NodeKind::CallExpr) ||
                    (ae->kind == ast::NodeKind::BinaryExpr &&
                     static_cast<ast::BinaryExpr *>(ae)->op ==
                         ast::BinOp::Add) ||
                    (ae->kind == ast::NodeKind::CastExpr);
                if (is_tmp_str) tmp_str_args_to_free.push_back(v_arg);
            }
        }
    }

    // Variadicos: empaquetar los args TRAILING (a partir del param fijo N-1)
    // en un array de pila host y reemplazarlos por (ptr, count).  El callee
    // recibe `T*` + el count (leido con vacount()).  Mismo patron que el argv
    // de vx_async, ahora como feature del lenguaje.
    if (callee_sig && callee_sig->is_variadic && !callee_sig->is_raw_variadic &&
        !callee_is_sret &&
        arg_ids.size() >= callee_sig->param_types.size() - 1) {
        pack_variadic_args(
            arg_ids, callee_sig->param_types.size() - 1,
            ir_type_from_primitive(callee_sig->variadic_elem.kind),
            e->loc.line);
    }

    // Para sret la "firma" de retorno es VOID; el dst SSA visible al
    // resto del lowering es el retbuf (PTR).  Para calls normales el
    // dst es el valor devuelto via RET.
    ir::IrValueId dst = ir::IR_NO_VALUE;
    if (!callee_is_sret) {
        dst = (ret_ir == ir::IrType::VOID) ? ir::IR_NO_VALUE
                                           : fn_->new_value(ret_ir);
    }
    ir::IrInstr ins{};
    ins.op = ir::IrOp::CALL;
    ins.type = callee_is_sret ? ir::IrType::VOID : ret_ir;
    ins.dst = dst;
    /*   : si el callee es una @Macro user-defined,
     * rewriting al nombre prefijado `__macro_<name>` que el lowering
     * uso al generar la IrFunction.  Esto permite que un @Macro
     * llame a otro via CALLVM normal sin pasar por AST eval. */
    std::string callee_name = id->name;
    {
        auto fn_it = tc_.comptime_fns().find(id->name);
        /* P1: rewrite a __macro_ para @Macros Y comptime fns-VM (recursion). */
        if (fn_it != tc_.comptime_fns().end() && fn_it->second &&
            (fn_it->second->is_macro ||
             comptime_fn_needs_vm(tc_, fn_it->second))) {
            callee_name = "__macro_" + id->name;
        }
    }
    /*  M.5: si la funcion fue importada cross-module con
     * mangling, el label emitido en el .vel es el mangled
     * (`lib__foo`) aunque el nombre visible del usuario es `foo`.
     * Consultamos function_sig_by_name para detectar el caso. */
    {
        const FunctionSig *fs = tc_.function_sig_by_name(id->name);
        if (fs && !fs->mangled_label.empty()) {
            callee_name = fs->mangled_label;
        }
    }
    ins.func_name = std::move(callee_name);
    ins.operands = std::move(arg_ids);
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));
    // Marcar el resultado del CALL como raiz GC cuando el callee devuelve una
    // CLASS (host_ptr a objeto gestionado por el GC).  CRITICO para el scan
    // preciso de raices: sin esto, un `Node keep = build(...)` que vive a
    // traves de un safepoint (p.ej. gc_collect / newobj) queda con
    // is_gc_object=false en su SSA value -> safepoint_gc_roots no lo reconoce
    // como raiz -> el GC lo colecta pese a estar vivo (UAF latente enmascarado
    // por el GC no-moving; corrupcion con el GC moving).  Mismo tratamiento que
    // el path CALLVIRT (metodos) que ya marcaba is_gc_object para retorno
    // CLASS.
    if (dst != ir::IR_NO_VALUE && callee_kind == PrimitiveKind::CLASS) {
        fn_->values[dst].is_host_ptr = true;
        fn_->values[dst].is_gc_object = true;
    }
    // BUG-1 fix: un callee que declara devolver un puntero/array HOST
    // (`T*` / `T[]` con is_virtual=false, p.ej. resultado de malloc) debe
    // producir un dst is_host_ptr=true en el llamante.  Sin esto, cuando el
    // callee NO se inlinea (cruce de modulo, o bloqueado por CALLN extern) o
    // cuando el retorno fusiona una rama `return null` (no-host) con la rama
    // host, el dst queda is_host_ptr=false -> el llamante emite `mov` (memoria
    // VM) en vez de `movh` (memoria host) al dereferenciarlo -> lee 0 /
    // SIGSEGV. La naturaleza host se decide desde la FIRMA declarada, no desde
    // el flujo interno del callee, por lo que es robusta ante ramas null.
    // VirtualPtr<T> (is_virtual=true) sigue siendo memoria VM -> NO se marca.
    if (dst != ir::IR_NO_VALUE && callee_sig &&
        (callee_sig->return_type.kind == PrimitiveKind::PTR ||
         callee_sig->return_type.kind == PrimitiveKind::ARRAY) &&
        !callee_sig->return_type.is_virtual) {
        mark_value_from_type(dst, callee_sig->return_type);
    }
    // native_poo_: liberar los buffers de los args value-string temporales
    // (ya copiados/usados por el callee).  Inc 5 (SSO): solo libera si el
    // arg estaba en HEAP; free(0)=no-op.
    for (ir::IrValueId v_tmp : tmp_str_args_to_free) {
        emit_native_str_free_if_heap(v_tmp, e->loc.line);
    }
    // Ruta B (H1 paso por valor): `~dtor` de las copias de structs con
    // copy-hook tras el CALL (la callee uso la copia; el caller la posee y la
    // destruye).
    for (const auto &pr : struct_clone_to_dtor) {
        emit_struct_method_on_host_field(
            pr.first, pr.second, pr.second + "__" + "__dtor", e->loc.line);
    }
    return callee_is_sret ? v_call_retbuf : dst;
}

ir::IrValueId Lowering::lower_new_expr(ast::NewExpr *e) {
    // bug4: array allocation `new T[N]`.  Emit RAW_ALLOC(N * sizeof(T))
    // y devolver host_ptr al primer elemento.  Cada slot zero-init
    // por RawAllocator.
    if (e->array_size) {
        // Resolver sizeof(T) en bytes.
        uint64_t elem_size = 8; // default qword (suficiente para
        // class refs, strings handles, ptrs).
        auto pk_size = [](const std::string &n) -> uint64_t {
            if (n == "i8" || n == "u8" || n == "bool" || n == "char") return 1;
            if (n == "i16" || n == "u16") return 2;
            if (n == "i32" || n == "u32" || n == "f32" || n == "float")
                return 4;
            if (n == "i64" || n == "u64" || n == "f64" || n == "double" ||
                n == "string")
                return 8;
            return 0; // no es primitivo
        };
        const uint64_t prim_sz = pk_size(e->class_name);
        if (prim_sz > 0) {
            elem_size = prim_sz;
        } else {
            // Clase user: host_ptr de 8 bytes por slot.
            auto it_cls = tc_.class_layouts().find(e->class_name);
            if (it_cls != tc_.class_layouts().end()) {
                elem_size = 8; // refs a objetos GC
            } else {
                // Struct value-type o enum.
                auto it_st = tc_.struct_layouts().find(e->class_name);
                if (it_st != tc_.struct_layouts().end()) {
                    elem_size = static_cast<uint64_t>(it_st->second.size_bytes);
                } else {
                    const EnumLayout *lay_cn =
                        tc_.find_enum_layout(e->class_name);
                    if (lay_cn != nullptr) {
                        elem_size = static_cast<uint64_t>(lay_cn->size_bytes);
                    }
                }
            }
        }
        // Lower count + multiplica por elem_size.
        const ir::IrValueId v_count = lower_expr(e->array_size.get());
        if (v_count == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        // Coerce count a i64 si no lo es.
        const ir::IrType ct = fn_->values[v_count].type;
        ir::IrValueId v_count_i64 =
            (ct == ir::IrType::I64 || ct == ir::IrType::U64)
                ? v_count
                : cast_if_needed(v_count, ct, ir::IrType::I64, e->loc.line,
                                 /*is_explicit=*/true);
        // total = count * elem_size.
        ir::IrValueId v_total;
        if (elem_size == 1) {
            v_total = v_count_i64;
        } else {
            const ir::IrValueId v_es = emit_const(
                ir::IrType::I64, static_cast<int64_t>(elem_size), e->loc.line);
            v_total = fn_->new_value(ir::IrType::I64);
            ir::IrInstr mul{};
            mul.op = ir::IrOp::MUL;
            mul.type = ir::IrType::I64;
            mul.dst = v_total;
            mul.operands = {v_count_i64, v_es};
            mul.source_line = e->loc.line;
            emit(current_block_, std::move(mul));
        }
        // RAW_ALLOC(total) -> host_ptr.
        const ir::IrValueId v_ptr = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_ptr].is_host_ptr = true;
        ir::IrInstr ra{};
        ra.op = ir::IrOp::RAW_ALLOC;
        ra.type = ir::IrType::PTR;
        ra.dst = v_ptr;
        ra.operands = {v_total};
        ra.source_line = e->loc.line;
        emit(current_block_, std::move(ra));
        return v_ptr;
    }
    // BugFix R4: `new ExceptionClass(msg)` para predefined exceptions
    // (RuntimeException, ArithmeticException, etc.).  No hay __new_<X>
    // synthetic helper; emitimos newobj + store message inline.
    {
        auto it_cls_pre = tc_.class_layouts().find(e->class_name);
        if (it_cls_pre != tc_.class_layouts().end() &&
            it_cls_pre->second.is_runtime_predefined &&
            e->class_name != "FatalError") {
            if (e->args.size() != 1) {
                error_at(e->loc, "new " + e->class_name +
                                     "(msg): se espera 1 argumento");
                return ir::IR_NO_VALUE;
            }
            // Auto-promocion literal -> StringObject (mismo patron que
            // lower_call para args string).
            ir::IrValueId v_msg;
            if (e->args[0]->kind == ast::NodeKind::StringLitExpr) {
                auto *sl = static_cast<ast::StringLitExpr *>(e->args[0].get());
                v_msg = lower_string_literal_to_string_object(sl);
            } else {
                v_msg = lower_expr(e->args[0].get());
            }
            if (v_msg == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            // findclass <exc_name> -> v_cls (host_ptr a ClassInfo).
            const uint64_t cname_idx =
                intern_class_name(*out_mod_, e->class_name);
            const uint32_t cname_len =
                static_cast<uint32_t>(e->class_name.size());
            const ir::IrValueId v_cls =
                emit_findclass_by_name(cname_idx, cname_len, e->loc.line);
            // Emit NEWOBJ IR (regalloc-aware) -> handle in v_handle.
            // Luego un minimal RAW_ASM convierte handle -> host_ptr
            // via `gcderef cur0, rX; xchg cur0, rX`.  La conversion
            // misma no tiene IR op dedicado, pero el resto de la
            // operacion (NEWOBJ + STORE) si esta en IR puro.
            const ir::IrValueId v_handle = fn_->new_value(ir::IrType::I64);
            {
                ir::IrInstr no{};
                no.op = ir::IrOp::NEWOBJ;
                no.type = ir::IrType::PTR; // tipo simbolico
                no.dst = v_handle;
                no.operands = {v_cls};
                no.source_line = e->loc.line;
                emit(current_block_, std::move(no));
            }
            // raw_asm-elim 2026-05-28: handle -> host_ptr via
            // IrOp::GC_DEREF_HOST. El IR op produce dst sin clobber del src;
            // equivalente semanticamente al RAW_ASM previo `gcderef + xchg +
            // mov`.
            const ir::IrValueId v_obj = fn_->new_value(ir::IrType::PTR);
            fn_->values[v_obj].is_host_ptr = true;
            fn_->values[v_obj].is_gc_object = true;
            {
                ir::IrInstr ra{};
                ra.op = ir::IrOp::GC_DEREF_HOST;
                ra.type = ir::IrType::PTR;
                ra.dst = v_obj;
                ra.operands = {v_handle};
                ra.source_line = e->loc.line;
                emit(current_block_, std::move(ra));
            }
            // store v_msg at v_obj + 24 (message field offset, after
            // ObjectHeader).  is_host_ptr=true for v_obj => emite movh.
            const ir::IrValueId v_off =
                emit_const(ir::IrType::I64, 24, e->loc.line);
            const ir::IrValueId v_addr =
                emit_ptr_add(v_obj, v_off, e->loc.line);
            emit_store_typed(v_addr, v_msg, ir::IrType::I64, e->loc.line);
            ssa_concrete_class_[v_obj] = e->class_name;
            return v_obj;
        }
    }

    // Bajar argumentos.  Bug fix 2026-05-23: si el ctor espera un
    // STRING param y el arg es un StringLitExpr, promover a StringObject.
    // Sin esto, `new P("alice")` pasaba el ptr raw del literal como
    // GcHandle invalido al ctor.
    const ClassMethodInfo *ctor_sig = nullptr;
    {
        auto it_cls_sig = tc_.class_layouts().find(e->class_name);
        if (it_cls_sig != tc_.class_layouts().end()) {
            for (const auto &m : it_cls_sig->second.methods) {
                if (m.is_constructor && m.defining_class == e->class_name) {
                    ctor_sig = &m;
                    break;
                }
            }
            if (!ctor_sig) {
                for (const auto &m : it_cls_sig->second.methods) {
                    if (m.is_constructor) {
                        ctor_sig = &m;
                        break;
                    }
                }
            }
        }
    }
    std::vector<ir::IrValueId> arg_vals;
    arg_vals.reserve(e->args.size());
    for (size_t ai = 0; ai < e->args.size(); ++ai) {
        auto &a = e->args[ai];
        const bool param_is_string =
            ctor_sig && ai < ctor_sig->param_types.size() &&
            ctor_sig->param_types[ai].kind == PrimitiveKind::STRING;
        ir::IrValueId av;
        if (param_is_string && a->kind == ast::NodeKind::StringLitExpr) {
            auto *slit = static_cast<ast::StringLitExpr *>(a.get());
            av = lower_string_literal_to_string_object(slit);
        } else {
            av = lower_expr(a.get());
        }
        if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        arg_vals.push_back(av);
    }

    /* Si el constructor recoge los que sobren, no van uno por uno: se meten en
     * un array y se pasa su direccion y cuantos son. */
    if (ctor_sig && ctor_sig->is_variadic && !ctor_sig->param_types.empty() &&
        arg_vals.size() >= ctor_sig->param_types.size() - 1) {
        pack_variadic_args(arg_vals, ctor_sig->param_types.size() - 1,
                           ir_type_from_primitive(ctor_sig->variadic_elem.kind),
                           e->loc.line);
    }

    // Emit IrInstr::CALL a __new_<ClassName>(args).  La funcion auxiliar
    // se genera al final de run() via generate_new_helpers.
    //
    //  Z.6: si @c e->is_shared, despachamos al helper
    // @c __new_<ClassName>_shared (emite @c newobjs en lugar de @c newobj
    // -> aloca en el SharedHeap).  El frontend marca @c is_shared cuando
    // el var-decl padre tiene modificador @c shared.
    const ir::IrValueId dst = fn_->new_value(ir::IrType::PTR);
    // fix - el resultado es un host_ptr a un objeto GESTIONADO por
    // GC.  Marcamos is_gc_object para que el regalloc, al spillarlo
    // alrededor de cualquier CALL posterior (que pueda disparar GC),
    // emita el dance gchandle/gcderef y refresque el host_ptr.
    fn_->values[dst].is_host_ptr = true;
    fn_->values[dst].is_gc_object = true;
    // M.L7 ext: clase importada cross-module.  El helper @c __new_<X>
    // en el dep fue emitido con el nombre LOCAL del dep (e.g. "Buffer"),
    // no con el mangled del consumer ("buffer__Buffer").  Si el layout
    // tiene @c imported_helper_suffix , lo usamos como sufijo del label.
    std::string helper_class_name = e->class_name;
    // `typedef Caja Sesion new;` -> `new Sesion()` construye la clase de
    // debajo, asi que el helper es `__new_Caja`.  El newtype no genera uno
    // propio: no tiene nada que construir de distinto, solo una identidad
    // distinta.
    if (const std::string real = tc_.underlying_layout_name(helper_class_name);
        !real.empty())
        helper_class_name = real;
    {
        const auto &class_layouts = tc_.class_layouts();
        auto it_lay = class_layouts.find(helper_class_name);
        if (it_lay != class_layouts.end() &&
            !it_lay->second.imported_helper_suffix.empty()) {
            helper_class_name = it_lay->second.imported_helper_suffix;
        }
    }
    ir::IrInstr ins{};
    ins.op = ir::IrOp::CALL;
    ins.type = ir::IrType::PTR;
    ins.dst = dst;
    ins.func_name = e->is_shared ? ("__new_" + helper_class_name + "_shared")
                    : e->is_gc   ? ("__new_" + helper_class_name + "_gc")
                                 : ("__new_" + helper_class_name);
    ins.operands = std::move(arg_vals);
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));
    // Trackear tipo concreto del resultado para devirtualizacion
    // de calls via interface receiver en compile time.
    ssa_concrete_class_[dst] = e->class_name;
    return dst;
}

std::string Lowering::generate_lambda_helper(ast::LambdaExpr *e) {
    const size_t lam_idx = lambda_counter_++;
    const std::string fn_name = "__lambda_" + std::to_string(lam_idx);

    // Salvar contexto del padre para poder restaurarlo despues.
    /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
    ChildFunctionScope parent(*this);
    /* El ayudante es una FUNCION SEPARADA con su firma: devuelve un escalar
     * por el registro de retorno, no por el hueco prestado que tuviera el
     * padre -- ese hueco es del marco del padre --.  Eso ya lo deja limpio el
     * guarda de arriba, que es quien sabe que se entra en otra funcion. */

    // Construir la nueva IrFunction.
    ir::IrFunction child_fn;
    child_fn.name = fn_name;
    // Determinar return type del helper a partir del tipo deducido en
    // la lambda (e->result_type es Type{FUNCTION, ...}; pointee es el
    // return type).  Por defecto VOID si no hay informacion.
    ir::IrType ret_ir = ir::IrType::VOID;
    if (e->result_type.kind == PrimitiveKind::FUNCTION &&
        e->result_type.pointee &&
        e->result_type.pointee->kind != PrimitiveKind::VOID) {
        ret_ir = ir_type_from_primitive(e->result_type.pointee->kind);
    }
    child_fn.ret_type = ret_ir;

    // Declarar parametros en la signature del helper IR.  Usamos los
    // mismos nombres y tipos que el AST de la lambda; la convencion
    // del emisor coloca cada param en r1, r2, ...
    // Modelo del IR: @c IrFunction::params es @c vector<IrValueId>;
    // los nombres se mantienen aparte para hacer el bind() en el
    // scope local del lowering tras crear el bloque entry.
    /* Los parametros de una lambda se declaran como los de cualquier otra
     * funcion: mismo tipo, misma naturaleza, y el contador oculto detras si el
     * ultimo recoge los que sobren.  Aqui habia una sexta copia del bucle que
     * no sabia ni lo uno ni lo otro. */
    std::vector<std::pair<std::string, ir::IrValueId>> param_bindings;
    param_bindings.reserve(e->params.size() + 1);
    declare_params(child_fn, e->params, param_bindings);

    // AOT (native_poo_) con capturas: el env se pasa como PARAMETRO OCULTO
    // FINAL (convencion C `void* userdata`), no por R14.  Asi el helper usa
    // el ABI nativo (sin READ_VM_REG) -> compilable en bare y llamable desde
    // C.  El prologue de capturas lee de este param en vez de R14.
    ir::IrValueId native_env_param = ir::IR_NO_VALUE;
    if (native_poo_ && !e->captures.empty()) {
        native_env_param = child_fn.new_value(ir::IrType::PTR, "%__env");
        child_fn.values[native_env_param].is_param = true;
        child_fn.values[native_env_param].is_host_ptr = true; // bare: env host
        child_fn.params.push_back(native_env_param);
    }

    const ir::IrBlockId entry = child_fn.new_block("entry");

    fn_ = &child_fn;
    current_block_ = entry;
    push_scope();

    // Bind de los params en el scope local.
    for (auto &kv : param_bindings)
        bind(kv.first, kv.second);

    // Prologue de captures: leer cada @c [r14 + 8*i] a un SSA value
    // que se bindea con el nombre del capture.  Asi el resto del body
    // referencia las capturas como si fueran variables ordinarias.
    //
    // El env_ptr esta en R14 por convencion (callvmr -> R14 ya cargado
    // por el emisor al ejecutar CALLCLOSURE).  Para acceder a R14
    // desde el IR usamos un RAW_ASM `mov {dst}, r14` que captura el
    // valor a un SSA value.
    ir::IrValueId env_ptr = ir::IR_NO_VALUE;
    if (!e->captures.empty()) {
        if (native_env_param != ir::IR_NO_VALUE) {
            // AOT: el env es el parametro oculto final (host_ptr ya marcado).
            // No se emite READ_VM_REG -> el helper no tiene ops runtime y
            // compila en bare.
            env_ptr = native_env_param;
        } else {
            env_ptr = child_fn.new_value(ir::IrType::PTR);
            // (gap O): si la lambda fue marcada como env_in_heap,
            // el env_ptr en R14 apunta a HEAP RAW (host_ptr), no a
            // stack VM.  Marcamos is_host_ptr para que LOAD/STORE
            // contra el env block emitan @c movh en lugar de @c mov.
            if (e->env_in_heap) {
                child_fn.values[env_ptr].is_host_ptr = true;
            }
            // raw_asm-elim wave 3: prologue del closure helper lee R14
            // (env_ptr) via IrOp::READ_VM_REG (path VM/JIT).
            ir::IrInstr rr{};
            rr.op = ir::IrOp::READ_VM_REG;
            rr.type = ir::IrType::PTR;
            rr.dst = env_ptr;
            rr.imm = 14; // R14 = env_ptr en la convention de callclosure
            rr.source_line = e->loc.line;
            child_fn.append(entry, std::move(rr));
        }

        for (size_t i = 0; i < e->captures.size(); ++i) {
            // Tipo del capture: usar el tipo guardado por el type
            // checker.  Si por algun motivo es COUNT/VOID, defaulteamos
            // a i64 (el ancho de los slots del env).
            ir::IrType cap_ir = ir::IrType::I64;
            if (i < e->capture_types.size() &&
                e->capture_types[i].kind != PrimitiveKind::COUNT &&
                e->capture_types[i].kind != PrimitiveKind::VOID) {
                cap_ir = ir_type_from_primitive(e->capture_types[i].kind);
            }

            // Es esta captura mutable?  Si lo es, el env contiene un
            // PUNTERO a la celda en el outer scope (capture-by-ref);
            // si no, contiene el VALOR (capture-by-value, copiado).
            bool is_mutable = false;
            for (const auto &nm : e->mutable_captures) {
                if (nm == e->captures[i]) {
                    is_mutable = true;
                    break;
                }
            }

            // addr_i = env_ptr + 8*i (0 -> reusamos env_ptr directamente)
            ir::IrValueId addr_i = env_ptr;
            if (i > 0) {
                addr_i = child_fn.new_value(ir::IrType::PTR);
                // Propagar is_host_ptr para que el LOAD siguiente sepa
                // emitir @c movh contra heap raw cuando el env vive en
                // heap (caso de closures retornadas por una funcion,
                // donde el env sobrevive al stack del creador via
                // alocacion en heap GC).
                if (child_fn.values[env_ptr].is_host_ptr) {
                    child_fn.values[addr_i].is_host_ptr = true;
                }
                ir::IrValueId off = emit_const(
                    ir::IrType::I64, static_cast<uint64_t>(i * 8), e->loc.line);
                ir::IrInstr ad{};
                ad.op = ir::IrOp::ADD;
                ad.type = ir::IrType::I64;
                ad.dst = addr_i;
                ad.operands = {env_ptr, off};
                ad.source_line = e->loc.line;
                child_fn.append(entry, std::move(ad));
            }

            // Leer 8 bytes (i64) del slot.  Para mutable_capture esto
            // es el PTR a la celda; para by-value es el valor.
            ir::IrValueId raw_v = child_fn.new_value(
                is_mutable ? ir::IrType::PTR : ir::IrType::I64);
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            ld.type = ir::IrType::I64;
            ld.dst = raw_v;
            ld.operands = {addr_i};
            ld.source_line = e->loc.line;
            child_fn.append(entry, std::move(ld));

            if (is_mutable) {
                // Capture-by-reference: el SSA value `raw_v` es el PTR
                // a la celda en el outer scope.  Lo bindeamos como
                // address_taken_local del helper para que read_local /
                // write_local emitan LOAD/STORE indirectos.
                //
                // Bug host-vs-VM (2026-07-15): esa celda vive en memoria HOST.
                // Una captura mutable obliga al owner a ser address-taken (el
                // env guarda el puntero a su slot), y todo local address-taken
                // se aloca ya en host -- ver @c lower_var_decl.  Sin marcarlo,
                // los LOAD/STORE indirectos del helper emitian `mov` (VM) y
                // escribian en una direccion VM mientras el owner leia la
                // celda host: las mutaciones de la lambda no se veian desde
                // fuera (el test 56_linkedlist_hof devolvia el `acc` base).
                child_fn.values[raw_v].is_host_ptr = true;
                address_taken_locals_.insert(e->captures[i]);
                bind(e->captures[i], raw_v);
            } else {
                // Capture-by-value: cast/trunc si el tipo es mas
                // estrecho que i64.
                ir::IrValueId final_v = raw_v;
                if (cap_ir != ir::IrType::I64 && cap_ir != ir::IrType::PTR) {
                    final_v = child_fn.new_value(cap_ir);
                    ir::IrInstr cv{};
                    cv.op = ir::IrOp::TRUNC;
                    cv.type = cap_ir;
                    cv.dst = final_v;
                    cv.operands = {raw_v};
                    cv.source_line = e->loc.line;
                    child_fn.append(entry, std::move(cv));
                }
                // El "valor" capturado de un AGREGADO (struct, enum/ADT, clase)
                // es su DIRECCION, y vive en memoria host (ver lower_var_decl).
                // Al releerla del env hay que devolverle esa naturaleza: sin
                // esto el body de la lambda leia los campos del receptor con
                // `mov` (VM) y los veia a cero.  Se notaba en `&mk(8).leer`
                // (metodo ligado sobre un struct): el helper inlinea el metodo,
                // asi que no pasa por el `this` de lower_struct_methods.
                if (i < e->capture_types.size()) {
                    const PrimitiveKind ck = e->capture_types[i].kind;
                    if (ck == PrimitiveKind::STRUCT ||
                        ck == PrimitiveKind::CLASS ||
                        ck == PrimitiveKind::OPTIONAL ||
                        ck == PrimitiveKind::RESULT) {
                        child_fn.values[final_v].is_host_ptr = true;
                    }
                }
                bind(e->captures[i], final_v);
            }
        }
    }

    // Lower del body.  Si no hay return explicito, anadimos un RET
    // void al final para garantizar terminador.  Este patron lo usan
    // tambien generate_spawn_helper / generate_rspawn_helper.
    if (e->body) lower_block(e->body.get());
    if (!block_terminated_) {
        ir::IrInstr rt{};
        rt.op = ir::IrOp::RET;
        rt.type = ir::IrType::VOID;
        rt.source_line = e->loc.line;
        emit(current_block_, std::move(rt));
        block_terminated_ = true;
    }

    pop_scope();
    // Encolar el helper para volcado al modulo al final de run().
    pending_spawn_helpers_.push_back(std::move(child_fn));

    return fn_name;
}

ir::IrValueId Lowering::lower_lambda_expr(ast::LambdaExpr *e) {
    if (!e || !e->body) {
        error_at(e ? e->loc : SourceLoc{}, "lowering: lambda sin body");
        return ir::IR_NO_VALUE;
    }
    // Capturar valores ANTES de generar el helper.  El helper modifica
    // pending_spawn_helpers_ y temporalmente intercambia el contexto
    // (fn_, scopes_), asi que los SSA values de los captures debemos
    // leerlos en el frame del CALLER, antes de cambiar de contexto.
    // El type checker ya pre-computo @c e->captures y @c e->capture_types
    // recorriendo el body y registrando IdentExpr externos.
    const size_t N = e->captures.size();
    std::vector<ir::IrValueId> capture_vals;
    capture_vals.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        // Es esta captura mutable?  Si lo es, guardamos el PTR a la
        // celda outer (capture-by-reference).  Si no, el VALOR
        // (capture-by-value, snapshot).
        bool is_mutable = false;
        for (const auto &nm : e->mutable_captures) {
            if (nm == e->captures[i]) {
                is_mutable = true;
                break;
            }
        }

        ir::IrType cap_ir = ir::IrType::I64;
        if (i < e->capture_types.size() &&
            e->capture_types[i].kind != PrimitiveKind::COUNT &&
            e->capture_types[i].kind != PrimitiveKind::VOID) {
            cap_ir = ir_type_from_primitive(e->capture_types[i].kind);
        }
        ir::IrValueId v = ir::IR_NO_VALUE;
        if (is_mutable) {
            // Para captures mutables, scan_address_taken ya marco
            // la variable outer como address-taken.  lookup devuelve
            // la direccion del ALLOCA estable; eso es lo que
            // queremos guardar en el env.
            v = lookup(e->captures[i]);
        } else {
            // Capture-by-value: leer el valor actual.  Si es
            // address-taken (por algun otro motivo, e.g. &var),
            // read_local emite el LOAD apropiado.
            v = read_local(e->captures[i], cap_ir, e->loc.line);
        }
        if (v == ir::IR_NO_VALUE) {
            v = emit_const(cap_ir, 0, e->loc.line);
        }
        capture_vals.push_back(v);
    }

    // (gap O): MARCAR el flag env_in_heap ANTES de generar
    // el helper, ya que el helper inspecciona @c e->env_in_heap para
    // marcar @c env_ptr.is_host_ptr=true en su prologue.  La
    // condicion: hay capturas (N>0) Y la funcion contenedora
    // retorna FUNCTION.
    if (N > 0 &&
        (current_fn_returns_function_ || current_lambda_store_escapes_)) {
        e->env_in_heap = true;
    }
    // Closure almacenado en un campo: el env es PROPIEDAD del objeto
    // contenedor y lo libera su destructor (modelo sin GC).  RAW_ALLOC host
    // owned, no GC.  Las capturas por REFERENCIA (variables mutadas dentro
    // del lambda) NO pueden escapar a un campo: el env guardaria un puntero
    // a un slot de stack que muere -> use-after-scope.  Rechazo en compile
    // time (decision de diseno; usa captura por valor).
    if (N > 0 && current_lambda_store_escapes_) {
        if (!e->mutable_captures.empty()) {
            error_at(e->loc,
                     "captura por referencia en un closure que se almacena en "
                     "un campo: '" +
                         e->mutable_captures.front() +
                         "' se mutaria fuera de su scope.  Captura por valor "
                         "(no la modifiques dentro del lambda).");
        }
        e->env_owned_by_field = true;
    }
    // Consumir el flag de escape-a-campo: no debe propagarse a lambdas
    // anidados dentro del body de este (su escape lo decide su propio
    // contexto via lower_assign).
    const bool _saved_store_escapes = current_lambda_store_escapes_;
    current_lambda_store_escapes_ = false;

    // Generar el helper sintetico con su prologue de captures.
    const std::string fn_name = generate_lambda_helper(e);
    current_lambda_store_escapes_ = _saved_store_escapes;
    e->synthetic_name = fn_name;

    // marker: emitir MAKE_CLOSURE ANTES de la secuencia explicita
    // de ALLOCA env + STOREs + ALLOCA fv + STORE fn + STORE env.
    // Identifica la construccion completa para que el C2 JIT
    // pueda hacer escape analysis y eventualmente promover env a stack /
    // eliminar la alocacion si la closure no escapa.  El IR emitter
    // actual lo trata como no-op; las instrucciones siguientes hacen el
    // trabajo real.  Capacidad de capturas marcadas como mutables: 16
    // (caben en bits 1..16 del imm; >= 16 deja el sobrante sin marcar y
    // el C2 cae al path conservativo).
    {
        uint64_t mutable_mask = 0;
        for (size_t i = 0; i < N && i < 16; ++i) {
            for (const auto &nm : e->mutable_captures) {
                if (nm == e->captures[i]) {
                    mutable_mask |= (1ULL << i);
                    break;
                }
            }
        }
        ir::IrInstr mc{};
        mc.op = ir::IrOp::MAKE_CLOSURE;
        mc.type = ir::IrType::VOID;
        mc.dst = ir::IR_NO_VALUE;
        mc.operands = capture_vals;             // N captures como SSA values
        mc.func_name = fn_name;                 // nombre del helper sintetico
        mc.imm = (e->env_in_heap ? 1ULL : 0ULL) // bit 0: env_kind
                 | (mutable_mask << 1);         // bits 1..16: mutable mask
        mc.source_line = e->loc.line;
        emit(current_block_, std::move(mc));
    }

    // -------------------------------------------------------------
    // 1. Alocar env block (8*N bytes; un qword por capture sin huecos).
    //
    // Por defecto va en STACK del caller (ALLOCA) - cero overhead GC,
    // suficiente para closures que no escapan al scope donde nacen.
    //
    // (gap O): si la funcion contenedora retorna FUNCTION (es
    // decir: probablemente esta cerrando esta lambda como su valor
    // de retorno), alocamos el env block en HEAP RAW via RAW_ALLOC.
    // El env sobrevive al RET y la closure es invocable por el caller
    // sin use-after-free.  Coste: un leak controlado por env (no hay
    // free automatico todavia; se libera cuando el proceso muere).
    // Se marca @c is_host_ptr en el SSA value para que LOAD/STORE
    // contra el env block emitan @c movh (host mem) en lugar de
    // @c mov (vm mem).
    // -------------------------------------------------------------
    ir::IrValueId env_addr;
    if (N == 0) {
        env_addr = emit_const(ir::IrType::I64, 0, e->loc.line);
    } else if (e->env_in_heap) {
        // Heap GC-tracked via GC_ALLOC.  El bloque entra en HandleTable
        // y el GC ve el payload (mark_reachable lo escanea como qword
        // array): si algun capture es un GcHandle vivo, se mantiene
        // marcado transitivamente; cuando ningun root referencia el
        // env (function value muere), se libera en el proximo major_gc.
        //
        // Marcamos is_host_ptr=true para que los STOREs siguientes (de
        // los captures al env) emitan movh (memoria HOST), ya que el
        // GcHeap usa ArenaManager con VirtualAlloc/mmap (host).
        //
        // Sustituye al RAW_ALLOC anterior (cerrado: gap O / leak en
        // closures que escapan).  Coste vs RAW_ALLOC: 1 slot extra en
        // HandleTable + zero-init del payload (que ya hacia rawalloc).
        env_addr = fn_->new_value(ir::IrType::PTR);
        fn_->values[env_addr].is_host_ptr = true;
        const ir::IrValueId v_size = emit_const(
            ir::IrType::I64, static_cast<uint64_t>(N * 8), e->loc.line);
        ir::IrInstr ins{};
        // Env escapante.  VM/JIT: GC_ALLOC (el GC lo libera).  AOT/bare
        // (native_poo): RAW_ALLOC etiquetado "__closure_env" -- el pase
        // ir_pass_own_closure_envs (tras inline+promote) busca el dueno
        // terminal de la closure e inserta el RAW_FREE en su scope-exit;
        // si no hay dueno limpio, revierte este alloc a GC_ALLOC para que
        // aot_analyze lo rechace (REGLA: nunca leak).  Los envs que NO
        // escapan ya los convierte promote a ALLOCA (stack) antes de este
        // pase, asi que aqui solo llegan los escapes cross-function reales.
        if (e->env_owned_by_field) {
            // Owned por el objeto contenedor: su destructor hace RAW_FREE del
            // env (RAII, modelo sin GC).  RAW_ALLOC host SIN etiqueta en
            // AMBOS backends -- el GC no participa y ir_pass_own_closure_envs
            // NO debe tocarlo (el dueno es el campo, no un buffer de stack).
            ins.op = ir::IrOp::RAW_ALLOC;
        } else if (native_poo_) {
            ins.op = ir::IrOp::RAW_ALLOC;
            ins.func_name = "__closure_env"; // tag p/ el pase de ownership
        } else {
            ins.op = ir::IrOp::GC_ALLOC;
        }
        ins.type = ir::IrType::PTR;
        ins.dst = env_addr;
        ins.operands = {v_size};
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
    } else {
        // Stack via ALLOCA (cero overhead, valido si la closure no
        // escapa al scope donde nace).
        env_addr = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8; // unidad: 1 byte
        al.dst = env_addr;
        al.imm = static_cast<uint64_t>(N * 8);
        al.source_line = e->loc.line;
        emit(current_block_, std::move(al));
    }

    // Escribir cada capture en su slot del env (ambos casos: stack y
    // heap).  STORE i64 para todos (uniformidad).  En el caso heap el
    // is_host_ptr propagado hace que el emisor IR use movh.
    if (N > 0) {
        for (size_t i = 0; i < N; ++i) {
            ir::IrValueId addr_i = env_addr;
            if (i > 0) {
                addr_i = fn_->new_value(ir::IrType::PTR);
                if (fn_->values[env_addr].is_host_ptr) {
                    fn_->values[addr_i].is_host_ptr = true;
                }
                ir::IrValueId off = emit_const(
                    ir::IrType::I64, static_cast<uint64_t>(i * 8), e->loc.line);
                ir::IrInstr ad{};
                ad.op = ir::IrOp::ADD;
                ad.type = ir::IrType::I64;
                ad.dst = addr_i;
                ad.operands = {env_addr, off};
                ad.source_line = e->loc.line;
                emit(current_block_, std::move(ad));
            }
            // Si el capture es de un tipo mas estrecho que i64,
            // primero promocionamos a i64 para que el slot sea
            // siempre 8 bytes.  Para PTR / I64 / valor de funcion
            // (16 bytes en sentido lexico, pero aqui el SSA value
            // es el puntero al slot, asi que i64 es correcto) la
            // promocion es identidad.
            ir::IrValueId v = capture_vals[i];
            ir::IrType vt = fn_->values[v].type;
            if (vt != ir::IrType::I64 && vt != ir::IrType::PTR) {
                v = cast_if_needed(v, vt, ir::IrType::I64, e->loc.line);
            }

            emit_store_typed(addr_i, v, ir::IrType::I64, e->loc.line);
        }
    }

    // -------------------------------------------------------------
    // 2. Alocar slot 16 bytes para el function value.
    //
    // Por defecto el slot va en STACK (ALLOCA, cero overhead).  PERO si el
    // closure se almacena en un CAMPO (env_owned_by_field), el slot debe
    // sobrevivir al scope donde nace (el campo guarda un puntero a el): lo
    // alocamos en HEAP via RAW_ALLOC, owned por el campo.  Su destructor
    // libera el slot Y el env (RAII puro, sin GC).  Sin esto el campo
    // apuntaria a un slot de stack que cuelga cuando el objeto escapa.
    // Ver doc/VMdoc/Vesta/ClosuresEnCampos.md y emit_free_closure_env_field.
    // -------------------------------------------------------------
    ir::IrValueId fv_addr = fn_->new_value(ir::IrType::PTR);
    if (e->env_owned_by_field) {
        fn_->values[fv_addr].is_host_ptr = true;
        const ir::IrValueId v_size =
            emit_const(ir::IrType::I64, 16, e->loc.line);
        ir::IrInstr al{};
        al.op = ir::IrOp::RAW_ALLOC;
        al.type = ir::IrType::PTR;
        al.dst = fv_addr;
        al.operands = {v_size};
        al.source_line = e->loc.line;
        emit(current_block_, std::move(al));
    } else {
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = fv_addr;
        al.imm = 16;
        al.source_line = e->loc.line;
        emit(current_block_, std::move(al));
    }

    // -------------------------------------------------------------
    // 3. Cargar fn_addr (= @Absolute("code.__lambda_<N>")) via LABEL_ADDR.
    // -------------------------------------------------------------
    ir::IrValueId fn_addr = emit_label_addr(fn_name, e->loc.line);

    // -------------------------------------------------------------
    // 4. STORE fn_addr en [fv_addr+0] y env_addr en [fv_addr+8].
    // -------------------------------------------------------------
    emit_store_typed(fv_addr, fn_addr, ir::IrType::I64, e->loc.line);
    {
        ir::IrValueId fv_plus_8 = fn_->new_value(ir::IrType::PTR);
        // Si el slot es heap (RAW_ALLOC, env_owned_by_field), el STORE a
        // [slot+8] debe usar movh (host).
        fn_->values[fv_plus_8].is_host_ptr = fn_->values[fv_addr].is_host_ptr;
        ir::IrValueId off8 = emit_const(ir::IrType::I64, 8, e->loc.line);
        ir::IrInstr ad{};
        ad.op = ir::IrOp::ADD;
        ad.type = ir::IrType::I64;
        ad.dst = fv_plus_8;
        ad.operands = {fv_addr, off8};
        ad.source_line = e->loc.line;
        emit(current_block_, std::move(ad));

        emit_store_typed(fv_plus_8, env_addr, ir::IrType::I64, e->loc.line);
    }

    // El SSA value de la lambda es la direccion del slot de 16 bytes.
    // Cuando se asigna a una variable @c fn(...), bind() la registra
    // tal cual; cuando se llama, lower_call carga fn_addr y env_addr
    // del slot y emite CALLCLOSURE.
    return fv_addr;
}

void Lowering::generate_extern_cfn_thunks(ir::IrModule &out) {
    // Por cada extern cuya direccion se tomo como cfn, sintetizamos un
    // thunk Vesta:  __cfnthunk_<fn>(params...) { return <lib>:<fn>(params...);
    // } El cuerpo es un unico CALLN (reenvio nativo) + RET.  Asi el cfn se
    // invoca por CALLIND -> entra al thunk -> el thunk hace el CALLN, que
    // cada backend resuelve normalmente (LoadLibrary/GetProcAddress, IAT/GOT).
    for (const auto &fn_name : extern_cfn_thunks_) {
        const FunctionSig *sig = tc_.function_sig_by_name(fn_name);
        if (!sig || sig->extern_lib.empty()) continue;

        ir::IrFunction fn;
        fn.name = "__cfnthunk_" + fn_name;
        const ir::IrType ret_ir =
            (sig->return_type.kind == PrimitiveKind::VOID ||
             sig->return_type.kind == PrimitiveKind::COUNT)
                ? ir::IrType::VOID
                : ir_type_from_primitive(sig->return_type.kind);
        fn.ret_type = ret_ir;

        // Params: uno por parametro del extern, en orden.
        std::vector<ir::IrValueId> param_vids;
        param_vids.reserve(sig->param_types.size());
        for (size_t i = 0; i < sig->param_types.size(); ++i) {
            const ir::IrType pt =
                ir_type_from_primitive(sig->param_types[i].kind);
            const ir::IrValueId vid =
                fn.new_value(pt, "%a" + std::to_string(i));
            fn.values[vid].is_param = true;
            /* De que memoria es lo contesta el mismo sitio que para todo lo
             * demas.  Aqui estaba la mitad: solo miraba puntero y array, asi
             * que un `T**` perdia que lo de dentro tambien es del anfitrion. */
            apply_type_memory(fn, vid, type_memory(sig->param_types[i]));
            fn.params.push_back(vid);
            param_vids.push_back(vid);
        }

        const ir::IrBlockId entry = fn.new_block("entry");
        // CALLN @Method("<lib>:<fn>") con los params como args.
        out.register_native_import(sig->extern_lib, fn_name);
        const ir::IrValueId dst = (ret_ir == ir::IrType::VOID)
                                      ? ir::IR_NO_VALUE
                                      : fn.new_value(ret_ir);
        {
            ir::IrInstr ins{};
            ins.op = ir::IrOp::CALLN;
            ins.type = ret_ir;
            ins.dst = dst;
            ins.func_name = sig->extern_lib + ":" + fn_name;
            ins.operands = param_vids;
            ins.source_line = 0;
            fn.append(entry, std::move(ins));
        }
        {
            ir::IrInstr ret{};
            ret.op = ir::IrOp::RET;
            ret.type = ret_ir;
            if (dst != ir::IR_NO_VALUE) ret.operands = {dst};
            ret.source_line = 0;
            fn.append(entry, std::move(ret));
        }
        out.add_function(std::move(fn));
    }
}

/**
 * @brief Llama a una funcion de Vesta.
 *
 * Si @p ret es VOID no se crea valor: la llamada no devuelve nada y pedir un
 * hueco para el resultado seria dejar un valor SSA que nadie define.
 *
 * Lo que NO hace falta poner aqui, y por eso no esta: la marca de "esto es una
 * llamada" para el asignador de registros.  Se la dice el propio opcode, y
 * ponerla a mano no anade nada -- ver `is_call_site` en ssa_ir.h --.
 *
 * @param name        Nombre de la funcion.
 * @param args        Argumentos, en orden.
 * @param ret         Tipo del resultado, o VOID si no devuelve.
 * @param source_line Linea fuente, para la depuracion.
 * @return El valor SSA del resultado, o IR_NO_VALUE si @p ret es VOID.
 */
ir::IrValueId Lowering::emit_call(const std::string &name,
                                  std::vector<ir::IrValueId> args,
                                  ir::IrType ret, uint32_t source_line) {
    const ir::IrValueId dst =
        (ret == ir::IrType::VOID) ? ir::IR_NO_VALUE : fn_->new_value(ret);
    ir::IrInstr in{};
    in.op = ir::IrOp::CALL;
    in.type = ret;
    in.dst = dst;
    in.func_name = name;
    in.operands = std::move(args);
    in.source_line = source_line;
    emit(current_block_, std::move(in));
    return dst;
}

/**
 * @brief Llama a una funcion NATIVA -- codigo que no es Vesta.
 *
 * Misma forma que @ref emit_call y otra instruccion, porque el destino no es
 * una funcion del programa sino un simbolo de fuera: quien la resuelve es el
 * cargador, no el enlazador de Vesta.  Quien la llama tiene que haber
 * registrado antes su importacion.
 *
 * @param name        Nombre del simbolo, con su biblioteca delante.
 * @param args        Argumentos, en orden.
 * @param ret         Tipo del resultado, o VOID si no devuelve.
 * @param source_line Linea fuente, para la depuracion.
 * @return El valor SSA del resultado, o IR_NO_VALUE si @p ret es VOID.
 */
ir::IrValueId Lowering::emit_calln(const std::string &name,
                                   std::vector<ir::IrValueId> args,
                                   ir::IrType ret, uint32_t source_line) {
    const ir::IrValueId dst =
        (ret == ir::IrType::VOID) ? ir::IR_NO_VALUE : fn_->new_value(ret);
    ir::IrInstr in{};
    in.op = ir::IrOp::CALLN;
    in.type = ret;
    in.dst = dst;
    in.func_name = name;
    in.operands = std::move(args);
    in.source_line = source_line;
    emit(current_block_, std::move(in));
    return dst;
}

/**
 * @copydoc vx::Lowering::emit_native_call
 */
ir::IrValueId Lowering::emit_native_call(const std::string &lib,
                                         const std::string &fn,
                                         std::vector<ir::IrValueId> args,
                                         ir::IrType ret, uint32_t source_line,
                                         const ir::IrNativeEffects *effects) {
    if (effects)
        out_mod_->register_native_import(lib, fn, *effects);
    else
        out_mod_->register_native_import(lib, fn);
    return emit_calln(lib + ":" + fn, std::move(args), ret, source_line);
}

/**
 * @brief Intenta bajar la llamada como el constructor de una variante de enum.
 *
 * `Color.Red` y `Color.Rgb(1, 2, 3)` se escriben como una llamada cuyo destino
 * es un acceso a campo, igual que un metodo, y no lo son: no hay objeto ni
 * funcion que llamar, hay un valor que construir.  Quien los distingue es el
 * comprobador de tipos, que ya los marco al resolverlos; aqui solo se mira esa
 * marca.
 *
 * De donde sale el nombre del enum depende de como se escribio: si se nombro
 * directo (`Color.Red`) esta en la base; si se llego por un modulo
 * (`edicion.Command.InsertChar`) la base es a su vez un acceso a campo, y el
 * nombre bueno -- ya con su modulo delante -- es el del tipo que el
 * comprobador le resolvio.  Tomar el otro daria un enum que no existe.
 *
 * @param e   La llamada.
 * @param out Donde dejar el valor construido.
 * @return @c true si era un constructor de variante y quedo bajado.
 */
bool Lowering::try_lower_enum_variant_ctor(ast::CallExpr *e,
                                           ir::IrValueId &out) {
    if (!e->callee || e->callee->kind != ast::NodeKind::FieldAccessExpr)
        return false;
    auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
    if (fa->property_kind != 99 || !fa->base) return false;

    if (fa->base->kind == ast::NodeKind::IdentExpr) {
        auto *base_id = static_cast<ast::IdentExpr *>(fa->base.get());
        out = lower_enum_constructor(base_id->name, fa->field_name, e->args,
                                     e->loc);
        return true;
    }
    if (fa->base->kind == ast::NodeKind::FieldAccessExpr) {
        const auto &bt = fa->base->result_type;
        if (bt.kind == PrimitiveKind::STRUCT && !bt.struct_name.empty()) {
            out = lower_enum_constructor(bt.struct_name, fa->field_name,
                                         e->args, e->loc);
            return true;
        }
    }
    return false;
}

/**
 * @brief Intenta bajar la llamada como `Tipo.default()` de un struct.
 *
 * Da un struct con los valores que su declaracion pone por defecto, y admite
 * dos formas que no hacen lo mismo: `Punto.default()` -- el nombre de un tipo
 * -- reserva uno nuevo, mientras que `p.default()` -- una variable -- resetea
 * el que ya existe.  Distinguirlas es mirar si ese nombre es una variable en
 * el ambito: si no lo es y si es un struct conocido, es la forma estatica.
 *
 * Y en las dos se pone a CERO antes de nada, aunque despues se escriba campo
 * por campo: un struct recien reservado tiene lo que hubiera en la pila, y un
 * campo sin valor por defecto se quedaria con esa basura en vez de en cero.
 *
 * @param e   La llamada.
 * @param out Donde dejar la direccion del struct.
 * @return @c true si era un `default()` y quedo bajado.
 */
bool Lowering::try_lower_struct_default_ctor(ast::CallExpr *e,
                                             ir::IrValueId &out) {
    if (!e->callee || e->callee->kind != ast::NodeKind::FieldAccessExpr ||
        e->result_type.kind != PrimitiveKind::STRUCT)
        return false;
    auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
    if (fa->field_name != "default") return false;
    const std::string &sname = e->result_type.struct_name;
    auto it = tc_.struct_layouts().find(sname);
    if (it != tc_.struct_layouts().end()) {
        const StructLayout &lay = it->second;
        bool is_static = false;
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            const std::string &bn =
                static_cast<ast::IdentExpr *>(fa->base.get())->name;
            if (lookup(bn) == ir::IR_NO_VALUE && tc_.struct_layouts().count(bn))
                is_static = true;
        }
        ir::IrValueId addr;
        if (is_static) {
            addr = fn_->new_value(ir::IrType::PTR);
            ir::IrInstr al{};
            al.op = ir::IrOp::ALLOCA;
            al.type = ir::IrType::I8;
            al.dst = addr;
            al.imm = (uint64_t)lay.size_bytes;
            al.source_line = e->loc.line;
            // Agregado -> host en los tres modos, no solo en AOT.
            al.host_alloca = true;
            emit(current_block_, std::move(al));
            fn_->values[addr].is_host_ptr = true;
        } else {
            addr = lower_expr(fa->base.get());
            if (addr == ir::IR_NO_VALUE) {
                out = ir::IR_NO_VALUE;
                return true;
            }
        }
        emit_zero_fill(addr, (uint64_t)lay.size_bytes, e->loc.line);
        if (e->args.size() == 1 &&
            e->args[0]->kind == ast::NodeKind::InitListExpr) {
            // emit_struct_init_fields ya aplica los defaults + el
            // override; evita duplicar los defaults.
            emit_struct_init_fields(
                addr, lay, static_cast<ast::InitListExpr *>(e->args[0].get()),
                e->loc.line);
        } else {
            emit_struct_field_defaults(addr, lay, e->loc.line);
        }
        out = addr;
        return true;
    }
    return false;
}

/**
 * @brief Intenta bajar la llamada como una funcion de un namespace importado.
 *
 * La forma es `lib.funcion(args)`, y el nombre visible no es el que acaba en
 * el binario: cada namespace mangla los suyos, asi que aqui se busca el
 * simbolo y se emite un CALL a su etiqueta manglada, igual que una llamada
 * normal.  Quien resolvio a que namespace apunta la base fue el type checker
 * -- lo dejo en @c ns_index --, porque el nombre por si solo no basta cuando
 * la base tiene varios segmentos (`ui.widgets.Boton`).
 *
 * Tres casos se salen del CALL directo y estan tratados aparte: un simbolo
 * @Naked no tiene cuerpo en bytecode y va por un despachador; uno que
 * devuelve un agregado usa SRET, con el hueco del retorno pasado como primer
 * argumento; y los literales de cadena promovidos se liberan tras la llamada,
 * que si no se quedan colgando al cruzar de modulo.
 *
 * @param e   La llamada.
 * @param out Donde dejar el valor que la llamada produce.
 * @return @c true si el callee era de un namespace y quedo bajado.
 */
bool Lowering::try_lower_namespaced_call(ast::CallExpr *e, ir::IrValueId &out) {
    //  M.7: llamada a funcion de namespace importado, ej.
    // `lib_a.valor_a(args)`.  El TypeChecker marca el FieldAccessExpr
    // callee con property_kind=4 y resuelve la firma del simbolo en
    // imported_namespaces_.  Aqui obtenemos el mangled_label y
    // emitimos CALL como si fuera una llamada normal.
    if (!e->callee || e->callee->kind != ast::NodeKind::FieldAccessExpr)
        return false;
    auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
    //  NS.1b: la base puede ser un IdentExpr (single-segment `ui`) o
    // una cadena de field-access (multi-segment `ui.widgets`).  La
    // resolucion usa @c fa->ns_index (autoritativo); @c idb solo se usa en
    // el fallback de static-method (ns_index no resuelto), que no aplica a
    // los namespaces multi-segmento.
    if (fa->property_kind != 4 || !fa->base ||
        (fa->base->kind != ast::NodeKind::IdentExpr &&
         fa->base->kind != ast::NodeKind::FieldAccessExpr))
        return false;
    ast::IdentExpr *idb = (fa->base->kind == ast::NodeKind::IdentExpr)
                              ? static_cast<ast::IdentExpr *>(fa->base.get())
                              : nullptr;
    // Localizar el namespace EXACTO via ns_index que el
    // TypeChecker dejo en el FieldAccessExpr.  Sentinel
    // UINT32_MAX significa no resuelto (defensivo).
    std::string mangled_label;
    ir::IrType ret_ir = ir::IrType::I64;
    bool found = false;
    // SRET cross-module: capturar el PrimitiveKind real del
    // retorno del callee para detectar Optional/Result que
    // requieren retbuf hidden como primer arg.
    PrimitiveKind callee_kind_ns = PrimitiveKind::VOID;
    /// Nombre del tipo devuelto cuando quien resuelve es la rama de metodo
    /// estatico de clase (no hay namespace del que sacarlo).
    std::string callee_struct_name_cls;
    /// El tipo devuelto ENTERO, no solo su clase: hace falta para saber cuanto
    /// mide el buffer de retorno de un `Optional`, que depende de lo que
    /// envuelve.
    Type callee_ret_type_ns;
    // Capturar tambien los tipos de parametros del callee para
    // auto-promotion literal -> StringObject al lowering args.
    std::vector<Type> ns_param_types;
    if (fa->ns_index != 0xFFFFFFFFu) {
        const auto &nss = tc_.imported_namespaces();
        if (fa->ns_index < nss.size()) {
            const auto &ns = nss[fa->ns_index];
            auto its = ns.by_name.find(fa->field_name);
            if (its != ns.by_name.end()) {
                const auto &sym = ns.symbols[its->second];
                mangled_label = sym.mangled_label;
                // Para namespaces inline la sig esta vacia
                // (se rellena durante run()); buscamos la
                // real via function_sig_by_name.
                const FunctionSig *real_sig =
                    tc_.function_sig_by_name(mangled_label);
                if (real_sig) {
                    ret_ir = ir_type_from_primitive(real_sig->return_type.kind);
                    callee_kind_ns = real_sig->return_type.kind;
                    callee_ret_type_ns = real_sig->return_type;
                    ns_param_types = real_sig->param_types;
                } else {
                    ret_ir = ir_type_from_primitive(sym.sig.return_type.kind);
                    callee_kind_ns = sym.sig.return_type.kind;
                    callee_ret_type_ns = sym.sig.return_type;
                    ns_param_types = sym.sig.param_types;
                }
                found = true;
            }
        }
    }
    if (!found && idb) {
        // L2.1: static method de clase cross-class (e.g.
        // `Stats.inc()`). El TypeChecker marca @c property_kind=4 pero
        // deja
        // @c ns_index=UINT32_MAX porque la "clase" no se registra como
        // namespace.  Aqui resolvemos el metodo via class_layouts del
        // tc y emitimos CALL al mangled label @c ClassName__method.
        /* Se mira en las clases Y en los structs: un metodo estatico se
         * declara igual en los dos y se llama igual, asi que resolverlo solo
         * en uno deja al otro sin el tratamiento del buffer de retorno. */
        auto it_cls = tc_.class_layouts().find(idb->name);
        const bool en_clases = it_cls != tc_.class_layouts().end();
        auto it_str = tc_.struct_layouts().find(idb->name);
        const bool en_structs =
            !en_clases && it_str != tc_.struct_layouts().end();
        if (en_clases || en_structs) {
            const auto &metodos =
                en_clases ? it_cls->second.methods : it_str->second.methods;
            for (const auto &m : metodos) {
                if (m.is_static && !m.is_constructor &&
                    m.name == fa->field_name) {
                    mangled_label = idb->name + "__" + m.name;
                    ret_ir = ir_type_from_primitive(m.return_type.kind);
                    /* Y QUE devuelve, no solo de que tipo IR es.  Lo que hay
                     * mas abajo decide con esto si la llamada necesita un
                     * buffer de retorno, y esta rama no lo rellenaba: un
                     * metodo estatico de clase que devolviera `Optional<T>`
                     * -- cuya firma real es void mas un buffer -- se llamaba
                     * SIN pasarlo y tratando el resultado como si volviera un
                     * puntero.  El metodo escribia en un parametro que nadie
                     * le habia dado; con el cuerpo inlinado, las escrituras
                     * acababan en `<void>` y la lectura en la direccion cero.
                     *
                     * La decision de si hace falta buffer estaba escrita en
                     * tres sitios -- el metodo de un struct, el estatico por
                     * el otro camino, y aqui -- y este no sabia que existia. */
                    callee_kind_ns = m.return_type.kind;
                    callee_struct_name_cls = m.return_type.struct_name;
                    callee_ret_type_ns = m.return_type;
                    found = true;
                    break;
                }
            }
        }
    }
    if (!found) {
        diags_.error(e->loc, "namespace '" +
                                 (idb ? idb->name : fa->field_name) +
                                 "' no resuelto en lowering");
        out = ir::IR_NO_VALUE;
        return true;
    }
    // LIM-A: si el simbolo importado es @Naked (asm nativo puro), su
    // cuerpo NO tiene representacion en bytecode VM.  En interp/JIT
    // (VM_ABI) enrutamos la llamada cross-modulo al dispatcher
    // @c vrt:naked_dispatch, que compila la @Naked al vuelo (viendo el
    // IR del modulo importado ya mergeado en el .velb) y la invoca con
    // ABI nativo.  En AOT (native_poo_) la llamada nativa directa ya
    // funciona, asi que este re-ruteo se limita al path VM_ABI.  Mismo
    // patron que la rama IdentExpr-callee de arriba, pero con el
    // @c mangled_label del simbolo importado como clave del hash.
    if (!native_poo_) {
        bool ns_is_naked = false;
        if (fa->ns_index != 0xFFFFFFFFu) {
            const auto &nss2 = tc_.imported_namespaces();
            if (fa->ns_index < nss2.size()) {
                const auto &ns2 = nss2[fa->ns_index];
                auto it2 = ns2.by_name.find(fa->field_name);
                if (it2 != ns2.by_name.end()) {
                    const auto &sig2 = ns2.symbols[it2->second].sig;
                    ns_is_naked = sig2.is_naked && sig2.extern_lib.empty();
                }
            }
        }
        if (ns_is_naked) {
            /* Se devuelve que SI se atendio pase lo que pase: si un argumento
             * no se pudo bajar, `out` queda sin valor y quien llamo ya lo mira.
             * Seguir buscando otra forma de bajarlo seria repetir el error. */
            ir::IrValueId dst = ir::IR_NO_VALUE;
            (void)emit_naked_dispatch(mangled_label, e, ret_ir, dst);
            out = dst;
            return true;
        }
    }
    // SRET cross-module: si el callee declara devolver
    // Optional<T>, Result<V,E>, un enum declarado por usuario
    // (encoded como STRUCT con struct_name = enum_name) o un
    // struct value-type, su firma IR real es void y espera un
    // retbuf hidden como primer argumento.  Sin este marshalling,
    // el callee escribe a R1 (garbage) y el caller lee basura.
    // Mismo patron que la rama IdentExpr-callee de lower_call.
    /* Las tres preguntas -- si hace falta buffer, cuanto mide y donde vive --
     * las contesta el mismo sitio que en el otro camino de llamada y que al
     * bajar la propia funcion.  Aqui estaban contestadas aparte, con una lista
     * MAS CORTA: se dejaba fuera devolver un lambda y devolver un puntero
     * inteligente, asi que no se reservaba nada y el metodo escribia sobre el
     * primer argumento de verdad.  Y el tamano de un struct no se redondeaba a
     * palabra, mientras que el llamado copia palabras enteras: uno de doce
     * reservaba doce y recibia dieciseis. */
    const SretInfo si_ns = sret_info(callee_ret_type_ns);
    const bool callee_is_sret_ns = si_ns.uses_buffer;
    ir::IrValueId v_call_retbuf_ns = ir::IR_NO_VALUE;
    if (callee_is_sret_ns) {
        v_call_retbuf_ns = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = v_call_retbuf_ns;
        al.imm = si_ns.bytes;
        if (si_ns.host_buffer) {
            al.host_alloca = true;
            fn_->values[v_call_retbuf_ns].is_host_ptr = true;
        }
        al.source_line = e->loc.line;
        emit(current_block_, std::move(al));
    }
    // Lower args.  Si es sret, el retbuf va PRIMERO.
    std::vector<ir::IrValueId> arg_vals;
    arg_vals.reserve(e->args.size() + (callee_is_sret_ns ? 1 : 0));
    if (callee_is_sret_ns) arg_vals.push_back(v_call_retbuf_ns);
    // value-strings TEMPORALES creados aqui (literal promovido) que
    // hay que liberar tras el CALL si quedaron en HEAP (SSO = no-op),
    // igual que el path same-module (tmp_str_args_to_free).  Sin esto
    // un literal HEAP (>22 chars) pasado cross-module fugaba.
    std::vector<ir::IrValueId> ns_tmp_str_to_free;
    // Auto-promotion literal -> StringObject cuando el
    // parametro espera STRING.  Mismo patron que el local
    // IdentExpr-callee path (lower_call lineas ~10125+).
    // Sin esto, `lib.fn("hola")` pushea el ptr crudo del
    // literal en lugar del GcHandle, y el callee crashea
    // al hacer strraw sobre puntero invalido.
    for (size_t ai = 0; ai < e->args.size(); ++ai) {
        auto &a = e->args[ai];
        bool promote = false;
        if (ai < ns_param_types.size() &&
            ns_param_types[ai].kind == PrimitiveKind::STRING && a &&
            a->kind == ast::NodeKind::StringLitExpr) {
            auto *slit = static_cast<ast::StringLitExpr *>(a.get());
            if (native_poo_) {
                // Vesta Embed cross-module: value-string nativo (24B),
                // no StringObject GC (mismo fix que el path regular).
                ir::IrValueId v_lit =
                    build_native_string_from_literal(slit, slit->loc.line);
                arg_vals.push_back(v_lit);
                if (v_lit != ir::IR_NO_VALUE)
                    ns_tmp_str_to_free.push_back(v_lit);
            } else {
                arg_vals.push_back(lower_string_literal_to_string_object(slit));
            }
            promote = true;
        }
        if (!promote) {
            ir::IrValueId v = lower_expr(a.get());
            // Coercionar el arg a la PRECISION del parametro cuando hay
            // mismatch float (p.ej. un literal f64 3.0 pasado a un
            // param f32).  Sin esto se pasan los bits f64 tal cual y el
            // callee los relee como f32 -> basura (fmul.f32 daba 0).
            // Solo float<->float: los enteros/punteros ya los coacciona
            // el type checker.  cast_if_needed es no-op si coinciden.
            if (v != ir::IR_NO_VALUE && ai < ns_param_types.size()) {
                const ir::IrType pt =
                    ir_type_from_primitive(ns_param_types[ai].kind);
                const ir::IrType at = fn_->values[v].type;
                const bool pt_f =
                    (pt == ir::IrType::F32 || pt == ir::IrType::F64);
                const bool at_f =
                    (at == ir::IrType::F32 || at == ir::IrType::F64);
                if (pt != at && pt_f && at_f)
                    v = cast_if_needed(v, at, pt, e->loc.line);
            }
            arg_vals.push_back(v);
        }
    }
    // Para sret la firma IR es VOID; el "valor" SSA del CALL es
    // el retbuf que se bindea al var-decl o se pasa a otras fns.
    ir::IrValueId dst = ir::IR_NO_VALUE;
    if (!callee_is_sret_ns) {
        dst = (ret_ir == ir::IrType::VOID) ? ir::IR_NO_VALUE
                                           : fn_->new_value(ret_ir);
    }
    ir::IrInstr ins{};
    ins.op = ir::IrOp::CALL;
    ins.type = callee_is_sret_ns ? ir::IrType::VOID : ret_ir;
    ins.dst = dst;
    ins.operands = std::move(arg_vals);
    ins.func_name = mangled_label;
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));
    // Liberar los value-strings temporales (literales promovidos):
    // el callee ya copio/uso sus bytes; libera el buffer HEAP si lo
    // hubo (SSO corto = no-op).  Evita la fuga cross-module.
    for (ir::IrValueId v_free : ns_tmp_str_to_free)
        emit_native_str_free_if_heap(v_free, e->loc.line);
    out = callee_is_sret_ns ? v_call_retbuf_ns : dst;
    return true;
    return false;
}

/**
 * @brief Intenta bajar la llamada como un metodo sobre un receptor.
 *
 * Todo lo que se escribe `algo.metodo(args)` entra aqui, y a donde va lo
 * decide el TIPO del receptor, no el nombre del metodo: una cadena reescribe
 * a su builtin equivalente pasando el receptor como primer argumento; una
 * clase va al despacho por vtable; un struct, a la llamada directa a su
 * funcion; y una coleccion primitiva, a la funcion nativa del plugin -- sin
 * vtable, porque no son objetos del GC sino punteros del anfitrion.
 *
 * Aparte quedan dos formas que no son "un metodo sobre un valor" pese a
 * escribirse igual: los estaticos (`Clase.metodo()`), que no tienen receptor,
 * y la reflexion ergonomica (`obj.getClass()`), que el type checker ya marco
 * para reescribir a su builtin suelto.
 *
 * @param e   La llamada.
 * @param out Donde dejar el valor que el metodo produce.
 * @return @c true si era un metodo y quedo bajado.
 */
bool Lowering::try_lower_method_call(ast::CallExpr *e, ir::IrValueId &out) {
    // Metodos OO sobre tipo string.  Mapping:
    //   s.length() -> str_length(s)
    //   s.bytes()  -> str_bytes(s)
    //   s.cstr()   -> str_cstr(s)
    //   s.wstr()   -> str_wstr(s)
    //   s.hash()   -> str_hash(s)
    //   s.intern() -> str_intern(s)
    //   s.equals(t)-> str_equals(s, t)
    //   s.concat(t)-> str_concat(s, t)
    // Cero overhead: se reescribe el call al builtin equivalente con
    // self como primer arg.
    if (!e->callee || e->callee->kind != ast::NodeKind::FieldAccessExpr)
        return false;
    auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());
    if (fa->base && fa->base->result_type.kind == PrimitiveKind::STRING) {
        static const char *METHOD_TO_BUILTIN[][2] = {
            {"length", "str_length"}, {"bytes", "str_bytes"},
            {"cstr", "str_cstr"},     {"wstr", "str_wstr"},
            {"hash", "str_hash"},     {"intern", "str_intern"},
            {"equals", "str_equals"}, {"concat", "str_concat"},
        };
        for (const auto &m : METHOD_TO_BUILTIN) {
            if (fa->field_name == m[0]) {
                // Construir un IdentExpr del builtin + reescribir
                // args: [base, ...e->args].
                ast::CallExpr synth;
                synth.loc = e->loc;
                auto id = std::make_unique<ast::IdentExpr>();
                id->loc = e->loc;
                id->name = m[1];
                synth.callee = std::move(id);
                // Ojo: NO movemos los originales (los devolvemos
                // intactos).  Para evitar deep-clone, hacemos un
                // approach sucio: temporalmente robamos los args
                // del CallExpr original, llamamos try_lower_builtin,
                // y restauramos.
                std::vector<std::unique_ptr<ast::Expr>> saved_args;
                saved_args.reserve(e->args.size() + 1);
                saved_args.push_back(std::move(fa->base));
                for (auto &a : e->args)
                    saved_args.push_back(std::move(a));
                synth.args = std::move(saved_args);
                ir::IrValueId v_builtin;
                bool ok = try_lower_builtin_call(&synth, v_builtin);
                // Restaurar: mover args de vuelta a originales.
                fa->base = std::move(synth.args[0]);
                for (size_t i = 0; i < e->args.size(); ++i) {
                    e->args[i] = std::move(synth.args[i + 1]);
                }
                if (ok) {
                    out = v_builtin;
                    return true;
                }
            }
        }
    }
    // Reflexion OO: dispatch ergonomico cuando el type checker
    // marco el FieldAccessExpr con property_kind 100..106.
    // Reescribe el call al builtin standalone equivalente.
    //   100: forName(name)               estatico, no toma self
    //   101: getMethod(cls, name)
    //   102: getField(cls, name)
    //   103: newInstance(cls)
    //   104: getMethods(cls)            (placeholder; no impl runtime aun)
    //   105: invoke(method, this, args...)
    //   106: getClass(obj)
    if (fa->property_kind >= 100 && fa->property_kind <= 106) {
        static const char *KIND_TO_BUILTIN[] = {
            "forName",     // 100
            "getMethod",   // 101
            "getField",    // 102
            "newInstance", // 103
            "getMethods",  // 104
            "invoke",      // 105
            "getClass",    // 106
        };
        const char *bn = KIND_TO_BUILTIN[fa->property_kind - 100];
        ast::CallExpr synth;
        synth.loc = e->loc;
        auto id = std::make_unique<ast::IdentExpr>();
        id->loc = e->loc;
        id->name = bn;
        synth.callee = std::move(id);
        // Para los metodos de instancia (101..103, 105, 106) prepend
        // el base (self) como primer argumento.  Para forName (100)
        // solo los args originales.  El base original sera devuelto
        // tras la lower.
        std::vector<std::unique_ptr<ast::Expr>> saved_args;
        const bool prepend_self = (fa->property_kind != 100);
        saved_args.reserve(e->args.size() + (prepend_self ? 1 : 0));
        if (prepend_self) {
            saved_args.push_back(std::move(fa->base));
        }
        for (auto &a : e->args)
            saved_args.push_back(std::move(a));
        synth.args = std::move(saved_args);
        ir::IrValueId v_builtin;
        const bool ok = try_lower_builtin_call(&synth, v_builtin);
        // Restaurar args originales para no afectar el AST.
        size_t k = 0;
        if (prepend_self) {
            fa->base = std::move(synth.args[k++]);
        }
        for (size_t i = 0; i < e->args.size(); ++i, ++k) {
            e->args[i] = std::move(synth.args[k]);
        }
        if (ok) {
            out = v_builtin;
            return true;
        }
        // try_lower_builtin_call devolvio false (e.g. argumento
        // ausente o mal formado); el error ya se reporto.  Devolvemos
        // un valor invalido para que el caller no use un IrValueId
        // basura.
        out = ir::IR_NO_VALUE;
        return true;
    }
    // Bug fix 2026-05-23: metodos estaticos.  property_kind=4 marca
    // llamada estatica `ClassName.method()` que NO tiene receptor
    // CLASS; el dispatch va a lower_class_method_call que detecta
    // property_kind=4 y emite CALLVM directo.
    if (fa->property_kind == 4 || fa->property_kind == 7) {
        out = lower_class_method_call(e);
        return true;
    }
    if (fa->base && fa->base->result_type.kind == PrimitiveKind::CLASS) {
        out = lower_class_method_call(e);
        return true;
    }
    // Metodo de struct (value-type, dispatch estatico).  Si la base
    // es STRUCT y el layout declara el metodo, emitimos CALL directo
    // a <Struct>__<metodo>(struct_addr, args...).  Si no es un
    // metodo conocido, cae a las rutas siguientes (colecciones, etc).
    // @Virtual: tambien enrutar `ptr.metodo()` sobre un `Struct*` (dispatch
    // dinamico por vtable).  El struct efectivo es el pointee.
    std::string sm_struct_name;
    if (fa->base) {
        const Type &rbt = fa->base->result_type;
        if (rbt.kind == PrimitiveKind::STRUCT && !rbt.struct_name.empty())
            sm_struct_name = rbt.struct_name;
        else if (rbt.kind == PrimitiveKind::PTR && rbt.pointee &&
                 rbt.pointee->kind == PrimitiveKind::STRUCT)
            sm_struct_name = rbt.pointee->struct_name;
    }
    if (!sm_struct_name.empty()) {
        auto it_s = tc_.struct_layouts().find(sm_struct_name);
        if (it_s != tc_.struct_layouts().end()) {
            if (find_method(it_s->second, fa->field_name) != nullptr) {
                out = lower_struct_method_call(e);
                return true;
            }
        }
    }
    // ===== dispatch de metodos de coleccion primitiva =====
    // Si la base es uno de los tipos coleccion (ARRAYLIST, HASHMAP,
    // ...), buscamos el metodo en la tabla COL_METHODS y emitimos
    // CALLN directo al native_fn con (handle, ...args).  Cero
    // overhead vs llamar el plugin manualmente; sin vtable ni
    // CALLVIRT (no son objetos GC, son handles host pointer).
    if (fa->base && is_col_kind(fa->base->result_type.kind)) {
        const ColMethod *cm =
            find_col_method(fa->base->result_type.kind, fa->field_name);
        if (cm) {
            // decidir si la coleccion retiene refs GC.
            // El frontend setea pointee/pointee2 al resolver el tipo
            // declarado (`ArrayList<string>` etc.).  Si es GC y la
            // operacion tiene variante *_gc, llamamos a esa con un
            // `getproc` extra como primer argumento.  Si la coleccion
            // se declaro sin <T> (legacy o tipo opaco i64), pointee
            // es nulo y caemos al camino no-GC de cero overhead.
            const Type &recv_ty = fa->base->result_type;
            PrimitiveKind elem_k = PrimitiveKind::VOID;
            PrimitiveKind val_k = PrimitiveKind::VOID;
            if (recv_ty.pointee) elem_k = recv_ty.pointee->kind;
            if (recv_ty.pointee2) val_k = recv_ty.pointee2->kind;
            // native_poo (AOT): sin VM -> sin getproc ni gc_addref/release;
            // usar la variante NO-GC (cero overhead, el handle/ptr se
            // guarda tal cual).  El lifetime lo gestiona el modelo nativo.
            const bool gc_aware =
                (cm->native_fn_gc != nullptr) && !native_poo_ &&
                col_needs_gc_aware(recv_ty.kind, elem_k, val_k);

            // Lower base (handle).
            const ir::IrValueId v_handle = lower_expr(fa->base.get());
            if (v_handle == ir::IR_NO_VALUE) {
                out = ir::IR_NO_VALUE;
                return true;
            }
            // Lower args.
            std::vector<ir::IrValueId> arg_ids;
            arg_ids.reserve(2 + e->args.size());
            if (gc_aware) {
                // proc va PRIMERO en las variantes *_gc.
                arg_ids.push_back(emit_getproc(e->loc.line));
            }
            arg_ids.push_back(v_handle);
            for (auto &a : e->args) {
                arg_ids.push_back(lower_expr(a.get()));
            }
            const char *fn_name = gc_aware ? cm->native_fn_gc : cm->native_fn;
            const ir::IrType ret_ir = ir_type_from_primitive(cm->ret);
            out = emit_native_call(COL_NATIVE_LIB, fn_name, std::move(arg_ids),
                                   ret_ir, e->loc.line);
            return true;
        }
    }
    return false;
}

/**
 * @brief Intenta bajar la llamada como INDIRECTA, por un puntero a funcion.
 *
 * A donde se salta no se sabe hasta ejecutar, asi que se evalua el callee a un
 * valor -- una variable de tipo funcion, un cast, un `&nombre` -- y se salta a
 * el.  Salvo cuando SI se sabe: si el puntero resulta ser una funcion conocida
 * aqui mismo, se emite la llamada directa, que ademas se puede meter en linea
 * despues; el salto indirecto impide las dos cosas.
 *
 * @param e   La llamada.
 * @param out Donde dejar el valor que la llamada produce.
 * @return @c true si era indirecta y quedo bajada.
 */
bool Lowering::try_lower_indirect_call(ast::CallExpr *e, ir::IrValueId &out) {
    if (!e->is_indirect_call) return false;
    // OPTIMIZACION (callback conocido): si el puntero a funcion es una
    // funcion CONOCIDA en compile-time -- `(cfn(...)) nombre` o `&nombre`
    // -- emitimos un CALL DIRECTO a la funcion en vez de CALLIND.  Mismo
    // coste que una llamada normal y el inliner del IR puede inlinearla.
    // (Un cfn que viene de un entero/tabla/variable sigue por CALLIND.)
    {
        ast::Expr *inner = nullptr;
        if (e->callee->kind == ast::NodeKind::CastExpr)
            inner =
                static_cast<ast::CastExpr *>(e->callee.get())->operand.get();
        else if (e->callee->kind == ast::NodeKind::UnaryExpr) {
            auto *u = static_cast<ast::UnaryExpr *>(e->callee.get());
            if (u->op == ast::UnOp::AddrOf) inner = u->operand.get();
        }
        if (inner && inner->kind == ast::NodeKind::IdentExpr) {
            auto *iid = static_cast<ast::IdentExpr *>(inner);
            if (iid->is_func_ref) {
                const std::string fname = iid->func_ref_mangled.empty()
                                              ? iid->name
                                              : iid->func_ref_mangled;
                std::vector<ir::IrValueId> dargs;
                dargs.reserve(e->args.size());
                for (auto &a : e->args) {
                    const ir::IrValueId av = lower_expr(a.get());
                    if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                    dargs.push_back(av);
                }
                const ir::IrType drt =
                    ir_type_from_primitive(e->result_type.kind);
                const ir::IrValueId ddst =
                    (e->result_type.kind == PrimitiveKind::VOID)
                        ? ir::IR_NO_VALUE
                        : fn_->new_value(drt);
                ir::IrInstr di{};
                di.op = ir::IrOp::CALL;
                di.func_name = fname;
                di.type = drt;
                di.dst = ddst;
                di.operands = std::move(dargs);
                // ABI del CFN del cast/&: cuando `(cfn con register) fn` se
                // devirtualiza a CALL directo, la ABI a usar es la del TIPO
                // del puntero (el cfn), NO la de la funcion destino -- que
                // puede ser un `invoke` @Naked SIN register en sus params
                // (la ABI vive solo en el cfn).  Sin esto el CALL usaria la
                // ABI estandar y el marshalling seria incorrecto.
                di.call_abi_regs = e->callee->result_type.fn_param_abi_regs;
                di.source_line = e->loc.line;
                emit(current_block_, std::move(di));
                out = ddst;
                return true;
            }
        }
    }
    const ir::IrValueId fnp = lower_expr(e->callee.get());
    std::vector<ir::IrValueId> args;
    args.reserve(e->args.size());
    // Promocion del literal a StringObject usando los tipos de parametro
    // que DECLARA el cfn.  En una llamada directa el lowering conoce la
    // firma del callee y la hace; por la via indirecta no se consultaba, y
    // un literal en posicion `string` llegaba como puntero crudo a
    // static_data -> el callee lo leia como StringObject y sacaba basura
    // (str_length daba 0).  Mismo criterio que el resto de sitios que
    // conocen el tipo esperado.
    const Type &fnty = e->callee->result_type;
    for (size_t ai = 0; ai < e->args.size(); ++ai) {
        ast::Expr *a = e->args[ai].get();
        ir::IrValueId av;
        if (a && a->kind == ast::NodeKind::StringLitExpr &&
            ai < fnty.fn_params.size() &&
            fnty.fn_params[ai].kind == PrimitiveKind::STRING) {
            av = lower_string_literal_to_string_object(
                static_cast<ast::StringLitExpr *>(a));
        } else {
            av = lower_expr(a);
        }
        if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        args.push_back(av);
    }
    const ir::IrType rt = ir_type_from_primitive(e->result_type.kind);
    const ir::IrValueId dst = (e->result_type.kind == PrimitiveKind::VOID)
                                  ? ir::IR_NO_VALUE
                                  : fn_->new_value(rt);
    // El callee puede ser un LAMBDA (fn(...), fat-pointer de 16 bytes) o un
    // puntero a funcion CRUDO (cfn(...), 8 bytes).  Lambda: fnp es el
    // PUNTERO al slot {fn_addr, env} -> cargar fn_addr de [fnp+0] y env de
    // [fnp+8] y emitir CALLCLOSURE (env en R14).  cfn: fnp ES la direccion
    // -> CALLIND directo (sin slot, sin env).
    const bool is_lambda =
        (e->callee->result_type.kind == PrimitiveKind::FUNCTION &&
         !e->callee->result_type.fn_is_raw);
    if (is_lambda) {
        const ir::IrValueId fn_addr =
            emit_load_typed(fnp, ir::IrType::I64, e->loc.line);
        const ir::IrValueId fnp8 = fn_->new_value(ir::IrType::PTR);
        {
            const ir::IrValueId off8 =
                emit_const(ir::IrType::I64, 8, e->loc.line);
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = fnp8;
            ad.operands = {fnp, off8};
            ad.source_line = e->loc.line;
            emit(current_block_, std::move(ad));
            // El slot {fn_addr, env} puede ser host (closure-en-campo de
            // clase, RAW_ALLOC) o VM (lambda local en stack, ALLOCA).  La
            // host-ness del slot+8 debe HEREDAR la del slot en TODOS los
            // backends para que la carga de env emita movh/mov correcto.
            // Antes solo se propagaba en native_poo (AOT) -> en VM/JIT un
            // closure-en-campo cargaba env con mov (vm_mem) -> basura.
            fn_->values[fnp8].is_host_ptr = fn_->values[fnp].is_host_ptr;
        }
        const ir::IrValueId env =
            emit_load_typed(fnp8, ir::IrType::I64, e->loc.line);
        std::vector<ir::IrValueId> cargs;
        cargs.reserve(1 + args.size());
        cargs.push_back(env);
        for (auto v : args)
            cargs.push_back(v);
        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALLCLOSURE;
        ins.type = rt;
        ins.dst = dst;
        ins.func_ptr = fn_addr;
        ins.operands = std::move(cargs);
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out = dst;
        return true;
    }
    // Naturaleza HOST vs VM del puntero: un cfn cuyo valor es una direccion
    // del proceso host (p.ej. un export resuelto con GetProcAddress/dlsym)
    // NO se puede invocar con CALLIND, que es una llamada indirecta DE LA
    // VM e interpreta la direccion como codigo VM -- los argumentos no
    // llegan y el fallo es silencioso.  Esa direccion se invoca por la via
    // nativa, la misma que usa `ffi_call`.  La distincion sale del dato que
    // el IR ya lleva por valor (@c is_host_ptr), igual que decide `mov`
    // frente a `movh`; no hace falta marcarla en el tipo.
    if (fnp != ir::IR_NO_VALUE && fn_->values[fnp].is_host_ptr) {
        ir::IrInstr ni{};
        ni.op = ir::IrOp::CALLN;
        ni.type = rt;
        ni.dst = dst;
        ni.func_name = "__callni__:"; // prefijo que el emitter baja a CALLNI
        ni.operands.reserve(args.size() + 1);
        ni.operands.push_back(fnp); // operando 0 = puntero a la funcion
        for (const auto &a : args)
            ni.operands.push_back(a);
        ni.source_line = e->loc.line;
        emit(current_block_, std::move(ni));
        out = dst;
        return true;
    }
    ir::IrInstr ins{};
    ins.op = ir::IrOp::CALLIND;
    ins.type = rt;
    ins.dst = dst;
    ins.func_ptr = fnp;
    ins.operands = std::move(args);
    // ABI custom: el tipo del puntero (cfn) LLEVA los abi_regs; los fijamos
    // en la instruccion en compile-time (el codegen coloca cada arg en su
    // registro).  Aunque el valor del puntero cambie en runtime, todas las
    // funciones asignables comparten esta ABI (garantia del type checker).
    ins.call_abi_regs = e->callee->result_type.fn_param_abi_regs;
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));
    out = dst;
    return true;
}

/**
 * @brief Intenta EJECUTAR la llamada ahora, si es a una funcion comptime.
 *
 * Si la funcion se declaro comptime y sus argumentos se conocen ya, la llamada
 * no llega al programa: se ejecuta aqui y lo que queda es su resultado como
 * constante.  Segun lo que devuelva eso es un entero, una cadena internada, o
 * un struct materializado campo a campo.
 *
 * Se renuncia -- y la llamada se baja como cualquier otra -- cuando algun
 * argumento no se conoce todavia, y cuando esto es una macro llamando a otra:
 * la funcion llamada aun no esta cargada en la maquina comptime, asi que
 * evaluarla ahora daria un resultado de relleno horneado como constante.
 * Entonces se emite la llamada de verdad, que corre cuando la macro corra.
 *
 * @param e   La llamada.
 * @param out Donde dejar la constante resultante.
 * @return @c true si se ejecuto en compilacion; @c false para bajarla normal.
 */
bool Lowering::try_lower_comptime_fn_call(ast::CallExpr *e,
                                          ir::IrValueId &out) {
    if (!e->callee || e->callee->kind != ast::NodeKind::IdentExpr) return false;
    auto *cid = static_cast<ast::IdentExpr *>(e->callee.get());
    const auto &cfns = tc_.comptime_fns();
    auto cit = cfns.find(cid->name);
    if (cit != cfns.end()) {
        /*  MC.17.3: si estamos dentro de un @Macro body
         * lowereado a IR Y el callee es OTRO @Macro, NO
         * intentamos comptime-eval; en su lugar caemos al
         * lowering normal mas abajo que emitira CALLVM regular
         * a `__macro_<callee>`.  Los args pueden ser params del
         * macro contenedor (runtime values) lo cual es valido.
         *
         * MA.2-nested-call: la misma regla aplica a una comptime
         * fn-VM llamada dentro de otra (`comptime Caja caja(){ c.min =
         * punto(2,3); }`).  Al bajar `__macro_caja` en el pass 1 la
         * ComptimeVM aun no tiene `__macro_punto`, asi que comptime-eval
         * daria DIFERIDO y hornearia ceros dentro de `__macro_caja`.  En
         * su lugar emitimos un CALLVM a `__macro_punto` (con SRET si el
         * callee devuelve struct por valor): cuando `__macro_caja` corre
         * en la VM (invocado desde el call site) llama al `__macro_punto`
         * ya cargado y el struct se rellena de verdad.  Se EXCLUYEN las
         * force-lowered (un @Macro las baja con nombre plano `code.<X>`;
         * el rewrite a `__macro_` las rompe -> caen a su propio path en
         * 18646). */
        const bool callee_is_vm_comptime =
            cit->second && !cit->second->is_macro &&
            comptime_fn_needs_vm(tc_, cit->second) &&
            comptime_fns_to_force_lower_.count(cid->name) == 0;
        if (current_fn_is_macro_ && cit->second &&
            (cit->second->is_macro || callee_is_vm_comptime)) {
            /* Caer al lowering normal de CallExpr -- no
             * intentar comptime eval aqui.  El rewrite del
             * nombre callee_name -> __macro_<name> se hace al
             * emitir el IrInstr::CALL al final de lower_call. */
            return false;
        }
        /* Solo-LSP: cuando bajamos comptime fns a IR para inspeccion
         * (emit_comptime_fns_), una llamada con args runtime -- p.ej. la
         * auto-llamada de una comptime fn RECURSIVA -- no es
         * comptime-evaluable; en vez de error, caemos al CALLVM normal
         * (la callee ya esta en el IR como funcion regular). */
        ComptimeEvalResult r = comptime_eval_expr(tc_, e);
        if (!r.ok && emit_comptime_fns_) {
            return false;
        }
        /* F1: comptime fn con asm -> ejecutar en el ComptimeVM (JIT +
         * interp fallback).  Con el two- (.velb y AOT), pass 2
         * (bytecode comptime cargado via prebuilt) da el valor real; el
         * pass 1 (sin bytecode) emite placeholder 0 -- inocuo, porque el
         * cr del pass 1 se descarta y el pass 2 recompila.  La fn ya se
         * bajo a `__macro_<name>` en lower_function. */
        if (!r.ok && comptime_fn_uses_asm(tc_, cit->second)) {
            const uint32_t src_line_asm = e->loc.line;
            ir::IrType t_asm = ir::IrType::I64;
            if (cit->second->return_type) {
                Type rt = tc_.resolve_type_node(cit->second->return_type.get());
                t_asm = ir_type_from_primitive(rt.kind);
            }
            std::vector<uint64_t> vm_args;
            bool args_ok = true;
            for (const auto &a : e->args) {
                ComptimeEvalResult av = comptime_eval_expr(tc_, a.get());
                if (!av.ok) {
                    args_ok = false;
                    break;
                }
                vm_args.push_back(static_cast<uint64_t>(av.value));
            }
            uint64_t r0 = 0;
            if (args_ok) {
                (void)const_cast<TypeChecker &>(tc_)
                    .comptime_runtime()
                    .invoke_simple_macro("__macro_" + cid->name, vm_args, r0);
            }
            out = emit_const(t_asm, r0, src_line_asm);
            return true;
        }
        /* Force-lower: si la comptime fn fue recolectada para bajarse a
         * runtime (porque un @Macro lowereable la referencia), su llamada
         * NO se comptime-evalua -- se emite un CALL normal a
         * `code.<helper>` (via el label mas abajo).  El arg puede ser un
         * param runtime del macro; el helper es ahora una fn runtime que lo
         * recibe.  El rewrite a `__macro_` NO aplica (la fn no es
         * is_macro), asi que el nombre queda plano y resuelve contra la fn
         * force-lowered. */
        if ((!r.ok || r.deferred) &&
            comptime_fns_to_force_lower_.count(cid->name)) {
            /* El fold en pass-1 puede devolver DIFERIDO (r.ok=true pero
             * r.deferred): la comptime fn corre en la ComptimeVM que aun no
             * tiene bytecode -> el fold da un valor vacio/placeholder. Para
             * una fn force-lowered (un @Macro lowereable la referencia), NO
             * hornear ese vacio: emitir CALLVM a code.<helper>, que se
             * ejecuta al INVOCAR el macro (cuando el helper ya existe). Sin
             * esto, un @Macro que llama a un helper comptime devolvia "".
             */
            return false;
        }
        if (!r.ok) {
            error_at(e->loc,
                     "llamada a comptime fn '" + cid->name +
                         "' no es comptime-evaluable (argumento runtime?)");
            out = ir::IR_NO_VALUE;
            return true;
        }
        const uint32_t src_line = e->loc.line;
        /* A.43.16: para @Macro fns, el type checker ya parseo +
         * type-checo la expresion generada y la guardo en
         * `e->macro_expanded`.  La rama temprana al inicio de
         * lower_call (A.43.10) ya hizo lower_expr del AST
         * sustituido y retorno antes de llegar aqui.  Asi que
         * en este punto NO esperamos un @Macro -- todos los
         * callees con string return son los comptime fns
         * regulares que materializan StringObject. */
        if (r.is_str) {
            /* Construir StringObject inline. */
            std::vector<uint8_t> bytes(r.str.begin(), r.str.end());
            const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));
            ir::IrValueId v_addr = emit_str_lit_addr(idx, src_line);
            ir::IrValueId v_len =
                emit_const(ir::IrType::I64, (uint64_t)r.str.size(), src_line);
            ir::IrValueId v_str =
                emit_string_literal_repr(v_addr, v_len, -1, src_line);
            out = v_str;
            return true;
        }
        /* Retorno struct por valor: la funcion comptime calculo el struct y
         * lo devolvio con un campo por miembro; lo materializamos como un
         * struct constante (buffer + STORE por campo), sin llamada en
         * tiempo de ejecucion. */
        if (r.is_struct) {
            auto *fn_decl_s = cfns.at(cid->name);
            if (fn_decl_s && fn_decl_s->return_type) {
                const Type rt =
                    tc_.resolve_type_node(fn_decl_s->return_type.get());
                auto it_sl = tc_.struct_layouts().find(rt.struct_name);
                if (it_sl != tc_.struct_layouts().end()) {
                    out =
                        materialize_comptime_struct(r, it_sl->second, src_line);
                    return true;
                }
            }
        }
        /* Tipo de retorno declarado por la fn. */
        ir::IrType t = ir::IrType::I64;
        auto *fn_decl = cfns.at(cid->name);
        if (fn_decl && fn_decl->return_type) {
            Type rt = tc_.resolve_type_node(fn_decl->return_type.get());
            t = ir_type_from_primitive(rt.kind);
        }
        out = emit_const(t, (uint64_t)r.value, src_line);
        return true;
    }
    return false;
}

} // namespace vx
