/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_runtime.cpp
 * @brief Builtins que piden algo al MUNDO: ficheros, memoria del anfitrion,
 *        fibras y modulos cargados en marcha.
 *
 * Lo que tienen en comun es que ninguno se resuelve dentro del programa: hay
 * que pedirselo a alguien de fuera y quedarse con lo que devuelva -- un
 * descriptor, una direccion, un modulo --.  De ahi que casi todos compartan la
 * misma forma: preparar los argumentos, llamar a la nativa que corresponde, y
 * recoger el resultado sabiendo que puede fallar.
 *
 * Y de ahi tambien la parte que no es obvia: lo que se recibe es memoria del
 * ANFITRION, no de la maquina virtual, y hay que marcarla como tal en el valor
 * -- si no, quien lo lea despues emitiria un acceso a la memoria equivocada --.
 * Ese bit es la diferencia entre leer lo que se pidio y leer basura.
 */
#include "vx/lowering.h"
#include "vx/collection_intrinsics.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering (no es su interfaz)

namespace vx {

/**
 * @brief Intenta bajar @p e como uno de los builtins que piden algo al mundo.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_runtime_builtins(ast::CallExpr *e, Builtin b,
                                          ir::IrValueId &out_value) {
    const bool is_fopen = (b == Builtin::Fopen);
    const bool is_fwrite = (b == Builtin::Fwrite);
    const bool is_fclose = (b == Builtin::Fclose);
    const bool is_malloc = (b == Builtin::Malloc);
    const bool is_free = (b == Builtin::Free);
    const bool is_fiber_swapctx = (b == Builtin::FiberSwapctx);
    const bool is_loadmodule = (b == Builtin::Loadmodule);
    const bool is_unloadmodule = (b == Builtin::Unloadmodule);
    const bool is_dispose = (b == Builtin::Dispose);
    /* Y llamar a codigo que no es Vesta decidiendo en marcha a cual: abrir la
     * biblioteca, buscar el simbolo, invocarlo. */
    const bool is_ffi_open = (b == Builtin::FfiOpen);
    const bool is_ffi_sym = (b == Builtin::FfiSym);
    const bool is_ffi_call = (b == Builtin::FfiCall);
    /* Y lo que el programa no sabe de si mismo hasta que corre. */
    const bool is_pid = (b == Builtin::Pid);
    const bool is_cpu_features = (b == Builtin::CpuFeatures);
    const bool is_args_count = (b == Builtin::ArgsCount);
    const bool is_args_get = (b == Builtin::ArgsGet);

    if (!(is_fopen || is_fwrite || is_fclose || is_malloc || is_free ||
          is_fiber_swapctx || is_loadmodule || is_unloadmodule || is_dispose ||
          is_ffi_open || is_ffi_sym || is_ffi_call || is_pid ||
          is_cpu_features || is_args_count || is_args_get))
        return false;

    // y emitir un STR_LIT_ADDR + CONST(len) en el bloque actual.
    // Devuelve par (str_ptr_ir_value, len_ir_value).

    // ----- fopen(path, mode) -> i64 -----
    // Args: (proc_ptr, path_addr, path_len, mode_addr, mode_len) = 5 args.
    // Devuelve uint64_t (FILE*).  Ambos args deben ser literales de string.
    if (is_fopen) {
        if (e->args.size() != 2 || !e->args[0] ||
            e->args[0]->kind != ast::NodeKind::StringLitExpr || !e->args[1] ||
            e->args[1]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(e->loc,
                                 "'fopen' requiere dos argumentos literales de "
                                 "string (path, mode)",
                                 out_value);
        }
        auto *path = static_cast<ast::StringLitExpr *>(e->args[0].get());
        auto *mode = static_cast<ast::StringLitExpr *>(e->args[1].get());

        const ir::IrValueId v_proc = emit_getproc(e->loc.line);
        auto [v_path, v_path_len] = emit_string_lit(path);
        auto [v_mode, v_mode_len] = emit_string_lit(mode);

        const ir::IrValueId dst =
            emit_native_call(kVestaIoLib, "vio_fopen",
                             {v_proc, v_path, v_path_len, v_mode, v_mode_len},
                             ir::IrType::I64, e->loc.line);
        out_value = dst;
        return true;
    }

    // ----- fwrite(fp, buf) -> i64 -----
    // En Vesta la firma natural es fwrite(fp, buf), pero la firma C
    // de vesta_io es vio_fwrite(proc_ptr, vm_addr, size, handle).
    // El lowering reordena: (proc, buf_addr, buf_len, fp).
    if (is_fwrite) {
        if (e->args.size() != 2 || !e->args[1] ||
            e->args[1]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(
                e->loc,
                "'fwrite' requiere (FILE*, literal_string) - el "
                "buffer debe ser literal",
                out_value);
        }
        ir::IrValueId v_fp = lower_expr(e->args[0].get());
        if (v_fp == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        v_fp = cast_if_needed(v_fp, fn_->values[v_fp].type, ir::IrType::I64,
                              e->loc.line);
        auto *buf = static_cast<ast::StringLitExpr *>(e->args[1].get());

        const ir::IrValueId v_proc = emit_getproc(e->loc.line);
        auto [v_buf, v_buf_len] = emit_string_lit(buf);

        const ir::IrValueId dst = emit_native_call(
            kVestaIoLib, "vio_fwrite",
            /* Orden de args segun signature C: (proc, vm_addr, size, handle).
             */
            {v_proc, v_buf, v_buf_len, v_fp}, ir::IrType::I64, e->loc.line);
        out_value = dst;
        return true;
    }

    // ----- fclose(fp) -> i32 -----
    if (is_fclose) {
        if (e->args.size() != 1) {
            return builtin_error(
                e->loc, "'fclose' requiere un argumento (FILE*)", out_value);
        }
        ir::IrValueId v_fp = lower_expr(e->args[0].get());
        if (v_fp == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        v_fp = cast_if_needed(v_fp, fn_->values[v_fp].type, ir::IrType::I64,
                              e->loc.line);

        const ir::IrValueId dst = emit_native_call(
            kVestaIoLib, "vio_fclose", {v_fp}, ir::IrType::I32, e->loc.line);
        out_value = dst;
        return true;
    }

    // ----- malloc(size) -----
    // Reserva un bloque host de `size` bytes y devuelve un void* con
    // is_host_ptr=true (LOAD/STORE consultan el flag para emitir movh).
    if (is_malloc) {
        if (e->args.size() != 1) {
            return builtin_error(
                e->loc, "'malloc' requiere exactamente un argumento de tamano",
                out_value);
        }
        ir::IrValueId v_size = lower_expr(e->args[0].get());
        if (v_size == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        v_size = cast_if_needed(v_size, fn_->values[v_size].type,
                                ir::IrType::I64, e->loc.line);
        const ir::IrValueId dst = fn_->new_value(ir::IrType::PTR);
        // Marcar el resultado como puntero a memoria host: cualquier
        // LOAD/STORE posterior cuyo puntero descienda de este value
        // emitira movh en el ir_emitter.
        fn_->values[dst].is_host_ptr = true;
        ir::IrInstr ins{};
        ins.op = ir::IrOp::RAW_ALLOC;
        ins.type = ir::IrType::PTR;
        ins.dst = dst;
        ins.operands = {v_size};
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out_value = dst;
        return true;
    }

    // ----- free(ptr) -----
    if (is_free) {
        if (e->args.size() != 1) {
            return builtin_error(
                e->loc, "'free' requiere exactamente un puntero", out_value);
        }
        const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
        if (v_ptr == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        ir::IrInstr ins{};
        ins.op = ir::IrOp::RAW_FREE;
        ins.type = ir::IrType::VOID;
        ins.dst = ir::IR_NO_VALUE;
        ins.operands = {v_ptr};
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    // ----- fiber_swapctx(from_ctx, to_ctx) -----
    // Materializacion del primitivo de fiber-switch en el path INTERPRETE
    // (FN.1): emite el opcode VM `swapctx dst, src` (guarda el contexto actual
    // en
    // @p from_ctx y carga el de @p to_ctx).  El opcode guarda/restaura
    // {PC,SP,BP,R0..R15} (152 bytes) en memoria VM -> el cuerpo de fibra corre
    // como bytecode NORMAL con su estado VM, sin necesidad de @Naked ni asm
    // host.
    //
    //   exec_instr_swapctx: reg1 = dst (a CARGAR), reg2 = src (a GUARDAR).
    //   Semantica de fiber_swapctx(from, to): GUARDA en from, CARGA to.
    //   -> dst(load) = to_ctx = args[1] ; src(save) = from_ctx = args[0].
    //   IrOp::SWAPCTX espera operands[0]=dst_ctx, operands[1]=src_ctx.
    if (is_fiber_swapctx) {
        if (e->args.size() != 2) {
            return builtin_error(
                e->loc,
                "'fiber_swapctx' requiere dos direcciones de contexto VM "
                "(from_ctx, to_ctx)",
                out_value);
        }
        const ir::IrValueId v_from = lower_expr(e->args[0].get()); // src (save)
        const ir::IrValueId v_to = lower_expr(e->args[1].get());   // dst (load)
        if (v_from == ir::IR_NO_VALUE || v_to == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // El primitivo de fiber-switch baja por BACKEND:
        //   - INTERPRETE (.velb): opcode VM `swapctx` (estado VM, portable).
        //   - AOT nativo (native_poo_, FN.2): CALL al context-switch NATIVO
        //     `__vx_swapctx` (host-stack, @Naked de vx_fiber.vx; auto-bundle
        //     al detectarse la llamada).  Mismo layout de contexto {PC,SP,BP,
        //     callee-saved} que inicializa el llamante; el cuerpo de fibra ya
        //     es codigo nativo (native_poo), asi que el switch nativo funciona
        //     con el sin necesitar @Naked en el cuerpo.  Args en el mismo orden
        //     que los operandos de SWAPCTX: (to_ctx=cargar, from_ctx=guardar).
        if (native_poo_) {
            ir::IrInstr call{};
            call.op = ir::IrOp::CALL;
            call.func_name = "__vx_swapctx";
            call.type = ir::IrType::VOID;
            call.dst = ir::IR_NO_VALUE;
            call.is_call_site = true;
            call.operands = {v_to, v_from}; // arg0=to_ctx, arg1=from_ctx
            call.source_line = e->loc.line;
            emit(current_block_, std::move(call));
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        ir::IrInstr ins{};
        ins.op = ir::IrOp::SWAPCTX;
        ins.type = ir::IrType::VOID;
        ins.dst = ir::IR_NO_VALUE;
        ins.operands = {v_to,
                        v_from}; // operands[0]=dst_ctx, operands[1]=src_ctx
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    // ----- loadmodule(string_lit) -----
    // Carga dinamica de un .velb adicional.  Acepta solo string literal
    // (path al archivo en el filesystem del host).  Genera RAW_ASM que:
    //   1. Carga la direccion del path (interned en static_data) en un reg.
    //   2. Carga la longitud en bytes en otro reg.
    //   3. Emite `loadmod r_path, r_len`.  El opcode loadmod abre el file,
    //      llama a Loader::load_module_dynamic + automaticamente hace el
    //      callvm-equivalente al init_pc del modulo cargado (cuyo prologo
    //      registra clases via __module_init).  Cuando el main del modulo
    //      hace RET, el flujo continua aqui con R0 = init_pc (success) o
    //      0 (failure file not found / parse error).
    //   4. Captura R0 al SSA value.
    if (is_loadmodule) {
        if (e->args.size() != 1 || !e->args[0] ||
            e->args[0]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(
                e->loc,
                "loadmodule: requiere un string literal con la ruta al .velb",
                out_value);
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[0].get());
        const uint64_t path_idx = intern_class_name(*out_mod_, slit->value);
        const uint32_t path_len = static_cast<uint32_t>(slit->value.size());
        // raw_asm-elim wave 2: usar STR_LIT_ADDR + emit_const + MOD_LOAD.
        const ir::IrValueId v_path_addr =
            emit_str_lit_addr(path_idx, e->loc.line);
        const ir::IrValueId v_path_len =
            emit_const(ir::IrType::I64, path_len, e->loc.line);
        const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I64);
        ir::IrInstr ml{};
        ml.op = ir::IrOp::MOD_LOAD;
        ml.type = ir::IrType::I64;
        ml.dst = v_dst;
        ml.operands = {v_path_addr, v_path_len};
        ml.imm = 0; /* loadmod */
        ml.source_line = e->loc.line;
        ml.is_call_site = true;
        emit(current_block_, std::move(ml));
        out_value = v_dst;
        return true;
    }

    // ----- unloadmodule(string_lit) -> i32 -----
    // Descarga modulo dinamico previamente cargado.  Mismo patron que
    // loadmodule: path interned en static_data, opcode unloadmod r_addr, r_len.
    // Devuelve 1 si descargado, 0 si no encontrado.
    if (is_unloadmodule) {
        if (e->args.size() != 1 || !e->args[0] ||
            e->args[0]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(
                e->loc,
                "unloadmodule: requiere un string literal con la "
                "ruta al .velb",
                out_value);
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[0].get());
        const uint64_t path_idx = intern_class_name(*out_mod_, slit->value);
        const uint32_t path_len = static_cast<uint32_t>(slit->value.size());
        // raw_asm-elim wave 2: MOD_LOAD con kind=1 (unloadmod).
        const ir::IrValueId v_path_addr =
            emit_str_lit_addr(path_idx, e->loc.line);
        const ir::IrValueId v_path_len =
            emit_const(ir::IrType::I64, path_len, e->loc.line);
        const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I32);
        ir::IrInstr ml{};
        ml.op = ir::IrOp::MOD_LOAD;
        ml.type = ir::IrType::I32;
        ml.dst = v_dst;
        ml.operands = {v_path_addr, v_path_len};
        ml.imm = 1; /* unloadmod */
        ml.source_line = e->loc.line;
        emit(current_block_, std::move(ml));
        out_value = v_dst;
        return true;
    }

    // ===== Builtin dispose(xs) =====
    // Libera explicitamente una coleccion antes del exit del scope.
    // Emite CALLN al free fn correspondiente al tipo del local + reescribe
    // el binding local a 0 para que el cleanup automatico al exit pase
    // 0 al free fn (que es no-op por null-check interno).  Asi se evita
    // double-free.
    if (is_dispose) {
        if (e->args.size() != 1 || !e->args[0] ||
            e->args[0]->kind != ast::NodeKind::IdentExpr) {
            return builtin_error(
                e->loc,
                "dispose: requiere un IdentExpr local de tipo coleccion",
                out_value);
        }
        auto *id_arg = static_cast<ast::IdentExpr *>(e->args[0].get());
        const Type arg_t = id_arg->result_type;
        if (!is_col_kind(arg_t.kind)) {
            return builtin_error(
                e->loc, "dispose: el argumento no es de tipo coleccion",
                out_value);
        }
        const ColType *ct = find_col_type(arg_t.kind);
        if (!ct) {
            return builtin_error(
                e->loc, "dispose: tipo coleccion sin entry en COL_TYPES",
                out_value);
        }
        // 1. Lower del IdentExpr para obtener el handle actual.
        const ir::IrValueId v_handle = lower_expr(id_arg);
        if (v_handle == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // elegir variante *_free_gc cuando el local fue
        // declarado con tipo de elemento GC (ArrayList<string> etc.).
        PrimitiveKind elem_k = PrimitiveKind::VOID;
        PrimitiveKind val_k = PrimitiveKind::VOID;
        if (arg_t.pointee) elem_k = arg_t.pointee->kind;
        if (arg_t.pointee2) val_k = arg_t.pointee2->kind;
        const bool gc_aware = (ct->native_free_fn_gc != nullptr) &&
                              col_needs_gc_aware(arg_t.kind, elem_k, val_k);
        const char *fn_name =
            gc_aware ? ct->native_free_fn_gc : ct->native_free_fn;
        // 2. CALLN al free fn (idempotente por null-check del plugin).
        std::vector<ir::IrValueId> args;
        if (gc_aware) {
            args.reserve(2);
            args.push_back(emit_getproc(e->loc.line));
        } else {
            args.reserve(1);
        }
        args.push_back(v_handle);
        emit_native_call(COL_NATIVE_LIB, fn_name, std::move(args),
                         ir::IrType::VOID, e->loc.line);
        // 3. Reescribir el binding local a 0 (handle invalido).  El
        // cleanup al exit del scope vera este 0 (via refresh_name) y
        // sera no-op.  Evita double-free.
        const ir::IrValueId v_zero =
            emit_const(ir::IrType::I64, 0, e->loc.line);
        write_local(id_arg->name, v_zero, ir::IrType::I64, e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    /* Cargar una biblioteca del sistema y llamar a un simbolo suyo, decidiendo
     * EN MARCHA cual.  Hay otra forma de llamar a codigo que no es Vesta -- la
     * declarativa, `extern "lib" { fn ... }` --, y esa se resuelve al compilar
     * y no cuesta nada.  Estos tres existen para cuando la biblioteca o la
     * funcion no se saben hasta que el programa corre: se paga una busqueda
     * por nombre a cambio de poder decidir tarde. */
    if (is_ffi_open) {
        if (e->args.size() != 1 || !e->args[0] ||
            e->args[0]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(e->loc,
                                 "ffi_open: requiere un string literal con el "
                                 "nombre/path de la DLL",
                                 out_value);
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[0].get());
        // NUL-terminar el path interned: en AOT nativo se baja a
        // LoadLibraryA/dlopen (APIs cstring que leen hasta el NUL).  El
        // path_len sigue siendo el tamano logico (sin NUL); el path VM/JIT usa
        // (addr,len) e ignora el NUL.
        const uint64_t path_idx =
            intern_class_name(*out_mod_, slit->value + std::string(1, '\0'));
        const uint32_t path_len = static_cast<uint32_t>(slit->value.size());
        // raw_asm-elim wave 2: DLOPEN IR op.
        const ir::IrValueId v_path_addr =
            emit_str_lit_addr(path_idx, e->loc.line);
        const ir::IrValueId v_path_len =
            emit_const(ir::IrType::I64, path_len, e->loc.line);
        const ir::IrValueId v_dst =
            emit_ir_binop(ir::IrOp::DLOPEN, v_path_addr, v_path_len,
                          ir::IrType::I64, e->loc.line);
        out_value = v_dst;
        return true;
    }

    // ----- ffi_sym(handle, string lit) -----
    // Resuelve simbolo en una DLL cargada.  El handle viene de un SSA
    // value (resultado de ffi_open o expression i64); el name es
    // string literal (interned en static_data).  Devuelve fn_addr i64.
    if (is_ffi_sym) {
        if (e->args.size() != 2 || !e->args[0] || !e->args[1] ||
            e->args[1]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(
                e->loc, "ffi_sym: requiere (i64 handle, string lit name)",
                out_value);
        }
        const ir::IrValueId v_handle = lower_expr(e->args[0].get());
        if (v_handle == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[1].get());
        // NUL-terminar: en AOT nativo se baja a GetProcAddress/dlsym (cstring).
        const uint64_t name_idx =
            intern_class_name(*out_mod_, slit->value + std::string(1, '\0'));
        const uint32_t name_len = static_cast<uint32_t>(slit->value.size());
        // raw_asm-elim wave 2: DLSYM IR op.
        const ir::IrValueId v_name_addr =
            emit_str_lit_addr(name_idx, e->loc.line);
        const ir::IrValueId v_name_len =
            emit_const(ir::IrType::I64, name_len, e->loc.line);
        const ir::IrValueId v_dst =
            emit_ir_op(ir::IrOp::DLSYM, {v_handle, v_name_addr, v_name_len},
                       ir::IrType::I64, e->loc.line);
        out_value = v_dst;
        return true;
    }

    // ----- ffi_call(fn, ...args) -----  (variadic 0-12 args)
    // Invoca funcion nativa via puntero (resuelto por ffi_sym/dlsym o
    // pasado como handle).  Calling convention espejo a CALLN estatico:
    // argc en R15, args en R01..R12, retorno en R00.
    //
    // Implementacion: emitir IrInstr CALLN con func_name="__callni__:"
    // y operands=[fn, args...].  El emitter detecta el prefix y emite
    // la secuencia completa (push regs vivos + parallel-move args ->
    // R1..RN + mov r15, N + callni reg_fn + capturar R0 + pop regs).
    // Reusa toda la maquinaria de CALLN para mantener una sola ruta.
    if (is_ffi_call) {
        if (e->args.empty()) {
            return builtin_error(
                e->loc, "ffi_call: requiere al menos el puntero a funcion",
                out_value);
        }
        if (e->args.size() > 13) {
            return builtin_error(e->loc,
                                 "ffi_call: maximo 12 args ademas del puntero",
                                 out_value);
        }
        std::vector<ir::IrValueId> arg_ids;
        arg_ids.reserve(e->args.size());
        for (auto &a : e->args) {
            arg_ids.push_back(lower_expr(a.get()));
        }
        const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I64);
        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALLN;
        ins.type = ir::IrType::I64;
        ins.dst = v_dst;
        ins.func_name = "__callni__:"; // prefix detectado en emitter
        ins.operands = std::move(arg_ids);
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out_value = v_dst;
        return true;
    }

    /* Y lo que el programa no sabe de si mismo hasta que corre: su numero de
     * proceso, en que maquina esta -- que instrucciones tiene esa CPU -- y con
     * que argumentos lo llamaron.  Nada de esto esta en el fuente: lo pone
     * quien lo ejecuta. */
    if (is_pid) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "pid: no acepta argumentos",
                                 out_value);
        }
        out_value = emit_getpid(e->loc.line);
        return true;
    }

    // ----- cpu_features() -> u64 (CPU dispatch, cimiento) -----
    // En native_poo_ (AOT): marca el uso (para wirear __vx_cpu_init en main),
    // asegura el global, y emite STR_LIT_ADDR(slot) + LOAD u64 (lectura del
    // bitmask que __vx_cpu_init dejo escrito al arranque).  En Full/interp
    // no hay cpuid native disponible -> devuelve 0 (consistente, sin error).
    if (is_cpu_features) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "cpu_features: no acepta argumentos",
                                 out_value);
        }
        if (!native_poo_) {
            // Path Full/interp/JIT: la VM corre sobre la CPU real -> emitimos
            // CALLN a la fn nativa `vesta_runtime:cpu_features` (registrada en
            // el virtual_lib_registry, sin DLL), que corre cpuid en el host y
            // devuelve el bitmask con el MISMO layout que el __vx_cpu_init de
            // AOT.  Resuelve igual en interp (loader/native_ffi) y en JIT
            // (auto_jit).  0 args, retorno u64 en R0.
            const int ln = e->loc.line;
            /* Un `cpuid` y devolver el bitmask: sin argumentos, sin memoria,
             * sin E/S.  Y determinista -- la CPU no cambia a mitad de
             * ejecucion --, que es lo que permite calcularlo UNA vez aunque se
             * consulte en un bucle. */
            ir::IrNativeEffects fx;
            fx.declared = true;
            ir::IrValueId v_feat = emit_native_call(
                "vesta_runtime", "cpu_features", {}, ir::IrType::U64, ln, &fx);
            out_value = v_feat;
            return true;
        }
        cpu_features_used_ = true;
        const uint64_t slot = ensure_cpu_features_global();
        const int ln = e->loc.line;
        ir::IrValueId v_addr = emit_str_lit_addr(slot, ln);
        ir::IrValueId v_feat = emit_load_typed(v_addr, ir::IrType::U64, ln);
        out_value = v_feat;
        return true;
    }

    // ----- args_count() -> i32 -----
    // Devuelve el numero de argumentos del script (vm->script_args.size()).
    // Baja a `getargc r_dst`, deposita uint64 que el caller trunca a i32.
    if (is_args_count) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "args_count: no acepta argumentos",
                                 out_value);
        }
        // getargc devuelve i64 a nivel IR; truncamos a i32 si el caller lo
        // espera.
        ir::IrValueId v_n = emit_getargc(e->loc.line);
        v_n = cast_if_needed(v_n, ir::IrType::I64, ir::IrType::I32, e->loc.line,
                             /*is_explicit=*/true);
        out_value = v_n;
        return true;
    }

    // ----- Builtins de terminal / VT100 -----
    // Cada uno emite via vio_print una secuencia ANSI estatica.
    // term_move(row, col) requiere format dinamico: emite la secuencia
    // como una mezcla de prints y print_int.  Sin overhead extra
    // gracias al buffer global de 64 KB del plugin vesta_io (todos
    // los prints en una misma frame se agrupan en 1 syscall).

    // ----- getMethods(cls) / getFields(cls) -> i32 -----
    // Devuelve el numero de metodos / fields de instancia de la clase
    // via los opcodes existentes methodcount (0xDB) / fieldcount (0xDA).
    // Ambos depositan el count en R00 (no toman r_dst); capturamos a SSA.

    // ----- args_get(i) -> string -----
    // Devuelve un StringObject GC-managed con el contenido de args[i].
    // Baja a `getarg r_dst, r_idx`.  Si i fuera de rango, devuelve
    // GC_NULL_HANDLE = 0 (que el frontend trata como string nulo).
    if (is_args_get) {
        if (e->args.size() != 1 || !e->args[0]) {
            return builtin_error(e->loc,
                                 "args_get: requiere 1 argumento (i32 indice)",
                                 out_value);
        }
        const ir::IrValueId v_idx = lower_expr(e->args[0].get());
        if (v_idx == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        out_value = emit_getarg(v_idx, e->loc.line);
        return true;
    }

    return false;
}

} // namespace vx
