/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/instructions.cpp
 * @brief Emitir UNA instruccion de la maquina, con su forma exacta.
 *
 * Veintiocho envoltorios de tres o cuatro lineas cada uno.  Parecen de mas
 * -- emitir una instruccion es rellenar una estructura -- y no lo son: cada
 * instruccion de la maquina tiene su forma, y esa forma es facil de escribir
 * mal de maneras que no dan error.  Un tipo de resultado equivocado no rompe
 * nada hasta que alguien lee el valor; olvidar que un identificador del
 * recolector NO es un puntero del anfitrion produce codigo que funciona hasta
 * que el recolector mueve algo.
 *
 * Concentrar aqui esa forma es lo que permite que el resto del bajador diga
 * QUE quiere y no COMO se escribe.  Y donde de verdad se nota es en las
 * marcas: si un valor es una direccion del anfitrion, si es un objeto que el
 * recolector conoce, si lo que devuelve es un indice opaco y no una direccion.
 * Esas marcas viajan con el valor por todo el IR y deciden despues que
 * instruccion de acceso a memoria se emite; ponerlas en un solo sitio evita
 * que cada llamante recuerde hacerlo.
 *
 * Vivian en el orquestador, que es lo que no tiene familia.  Esta si la tiene:
 * son la frontera entre el bajador y el juego de instrucciones.
 */
#include "vx/lowering.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include "lowering_internal.h" // la cocina compartida (no es la interfaz)
#include <utility>

namespace vx {

ir::IrValueId Lowering::emit_gc_handle_for_ptr(ir::IrValueId v_host_ptr,
                                               uint32_t source_line) {
    // GC_HANDLE_FOR_PTR devuelve un GcHandle uint32 zero-extended a i64.
    // No es is_host_ptr (es un indice opaco), no es is_gc_object (no es
    // el host_ptr al payload).
    const ir::IrValueId v_h = emit_ir_unop(
        ir::IrOp::GC_HANDLE_FOR_PTR, v_host_ptr, ir::IrType::I64, source_line);
    return v_h;
}

void Lowering::emit_monitor_op(ir::IrValueId v_obj_or_handle, bool enter,
                               uint32_t source_line) {
    // @SyncImpl: si el programa define monitor_enter/monitor_exit,
    // `synchronized` rutea a esas funciones en LOS 3 MODOS (interp/JIT/AOT).
    // Mecanismo, no politica: la impl del usuario decide el layout del lock. El
    // operando es el host_ptr al ObjectHeader (lower_synchronized ya pasa v_obj
    // sin convertir a GcHandle cuando hay override).
    const std::string &sync_ovr =
        enter ? sync_enter_override_ : sync_exit_override_;
    if (!sync_ovr.empty()) {
        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALL;
        ins.func_name = sync_ovr;
        ins.type = ir::IrType::VOID;
        ins.dst = ir::IR_NO_VALUE;
        ins.operands = {v_obj_or_handle};
        ins.is_call_site = true;
        ins.source_line = source_line;
        emit(current_block_, std::move(ins));
        return;
    }
    if (native_poo_) {
        // AOT/bare: monitor reentrante inline en el objeto (palabra en obj+16),
        // sin GC ni handle table.  Baja a CALL a la primitiva nativa
        // (__vx_monenter/__vx_monexit) que el auto-bundle de vx_sync.vx
        // fusiona en el .o.  v_obj_or_handle es el host_ptr al ObjectHeader.
        emit_call(enter ? "__vx_monenter" : "__vx_monexit", {v_obj_or_handle},
                  ir::IrType::VOID, source_line);
        return;
    }
    // Resto de tiers (Full/JIT/interp): IR op MONENTER/MONEXIT sobre el handle.
    ir::IrInstr ins{};
    ins.op = enter ? ir::IrOp::MONENTER : ir::IrOp::MONEXIT;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_obj_or_handle};
    ins.source_line = source_line;
    emit(current_block_, std::move(ins));
}

void Lowering::emit_mvtake(ir::IrValueId v_dst_addr, ir::IrValueId v_src_addr,
                           uint32_t source_line) {
    ir::IrInstr ins{};
    ins.op = ir::IrOp::MVTAKE_IR;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_dst_addr, v_src_addr};
    ins.source_line = source_line;
    emit(current_block_, std::move(ins));
}

void Lowering::emit_gc_set_finalizer(ir::IrValueId v_box, uint32_t kind,
                                     uint32_t source_line,
                                     ir::IrValueId v_dtor_addr) {
    // Registra (kind 1/2/3) el finalizador GC del box con recurso interno.
    module_has_gc_finalizers_ = true; // habilita el finalize_all al exit (AOT)
    if (native_poo_) {
        // AOT: CALL vx_gc_register_finalizer(payload, kind, aux) de
        // libvesta_gc.  El runner nativo ejecuta el deleter/dtor por CALL
        // directo cuando el sweep colecte el objeto (o el shutdown lo
        // finalice).  aux = a quien llamar: el `<Clase>____dtor` (kind 3) o el
        // liberador del `unique` (kind 1); cero cuando es el de por defecto o
        // el box lo resuelve solo (SHARED).  El auto-link de libvesta_gc.a se
        // dispara al detectar el simbolo vx_gc_*.
        const ir::IrValueId v_kind = emit_const(
            ir::IrType::I64, static_cast<int64_t>(kind), source_line);
        const ir::IrValueId v_aux =
            ((kind == 3 || kind == 1) && v_dtor_addr != ir::IR_NO_VALUE)
                ? v_dtor_addr
                : emit_const(ir::IrType::I64, 0, source_line);
        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALL;
        ins.type = ir::IrType::VOID;
        ins.dst = ir::IR_NO_VALUE;
        ins.func_name = "vx_gc_register_finalizer";
        ins.operands = {v_box, v_kind, v_aux};
        ins.is_call_site = true;
        ins.source_line = source_line;
        emit(current_block_, std::move(ins));
        return;
    }
    // interp/JIT: la variante con destino cuando se sabe A QUIEN llamar -- el
    // destructor de una clase (kind 3) o el liberador de un `unique` (kind 1);
    // la simple cuando no hay que decirlo.
    ir::IrInstr ins{};
    ins.op = ir::IrOp::GC_SET_FINALIZER;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    if ((kind == 3 || kind == 1) && v_dtor_addr != ir::IR_NO_VALUE)
        ins.operands = {v_box, v_dtor_addr};
    else
        ins.operands = {v_box};
    ins.imm = kind;
    ins.source_line = source_line;
    emit(current_block_, std::move(ins));
}

// ---- Sprint 2:  Z + reflexion + static + AOP ----

ir::IrValueId Lowering::emit_findmethod(ir::IrValueId v_params, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true; // MethodInfo* host
    ir::IrInstr ins{};
    ins.op = ir::IrOp::FINDMETHOD;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_params};
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_findfield(ir::IrValueId v_params, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ins{};
    ins.op = ir::IrOp::FINDFIELD;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_params};
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_gc_allocp(ir::IrValueId v_size, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ins{};
    if (native_poo_) {
        // AOT: usar el GC nativo (libvesta_gc) -> CALL vx_gc_alloc_ptr(size),
        // igual que __new_<Class>_gc.  Asi shared<T> aloca su control block sin
        // la VM; el GC gestiona el lifetime (stackmaps).  El auto-link de
        // libvesta_gc.a se dispara al detectar vx_gc_*.
        ins.op = ir::IrOp::CALL;
        ins.func_name = "vx_gc_alloc_ptr";
    } else {
        ins.op = ir::IrOp::GC_ALLOCP;
    }
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_size};
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_gc_promote(ir::IrValueId v_src, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ins{};
    ins.op = ir::IrOp::GC_PROMOTE;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_src};
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_gc_demote(ir::IrValueId v_src, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ins{};
    ins.op = ir::IrOp::GC_DEMOTE;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_src};
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_atomic_ld_i64(ir::IrValueId v_addr, uint32_t line,
                                           ir::IrType wt) {
    const ir::IrValueId v = fn_->new_value(wt);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::ATOMIC_LD;
    ins.type = wt; // ancho del atomico (1/2/4/8 -> mode del ctrl-byte)
    ins.dst = v;
    ins.operands = {v_addr};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

void Lowering::emit_atomic_st_i64(ir::IrValueId v_addr, ir::IrValueId v_val,
                                  uint32_t line, ir::IrType wt) {
    ir::IrInstr ins{};
    ins.op = ir::IrOp::ATOMIC_ST;
    // El resultado es VOID pero el ancho viaja en `type` (el ir_emitter lo lee
    // del tipo del valor almacenado; aqui lo fijamos directamente).
    ins.type = wt;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_addr, v_val};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
}

ir::IrValueId Lowering::emit_atomic_cas_i64(ir::IrValueId v_addr,
                                            ir::IrValueId v_exp,
                                            ir::IrValueId v_des, uint32_t line,
                                            ir::IrType wt) {
    const ir::IrValueId v = fn_->new_value(wt);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::ATOMIC_CAS;
    ins.type = wt;
    ins.dst = v;
    ins.operands = {v_addr, v_exp, v_des};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_atomic_add_i64(ir::IrValueId v_addr,
                                            ir::IrValueId v_delta,
                                            uint32_t line, ir::IrType wt) {
    const ir::IrValueId v = fn_->new_value(wt);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::ATOMIC_ADD;
    ins.type = wt;
    ins.dst = v;
    ins.operands = {v_addr, v_delta};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_getstatic(ir::IrValueId v_cls, uint64_t offset,
                                       uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::GETSTATIC;
    ins.type = ir::IrType::I64;
    ins.dst = v;
    ins.operands = {v_cls};
    ins.imm = offset;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

void Lowering::emit_setstatic(ir::IrValueId v_cls, ir::IrValueId v_val,
                              uint64_t offset, uint32_t line) {
    ir::IrInstr ins{};
    ins.op = ir::IrOp::SETSTATIC;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_cls, v_val};
    ins.imm = offset;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
}

ir::IrValueId Lowering::emit_proceed(uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::I64);

    /* `proceed()` con destino conocido se emite como una llamada normal.
     *
     * La instruccion `proceed` no lleva operandos: reusa los registros vivos y
     * lee a donde ir del MARCO, que se lo prepara el despacho al recorrer la
     * cadena.  Eso obliga a entrar por el despacho aunque se sepa todo.
     *
     * Y se sabe todo: un advice tiene un solo objetivo -- el pointcut es
     * `Clase.metodo` exacto, sin comodines -- y una sola posicion en su cadena,
     * asi que su `proceed` tiene UN destino, que es el siguiente `@Around` o el
     * metodo.  Se calcula en @c run() y se llama directo, pasando lo mismo que
     * pasaria el despacho: los parametros de este advice, que son los de la
     * llamada original (el receptor incluido, en el primero).
     *
     * Ademas de ahorrarse la indireccion, esto es lo que permite despues TEJER
     * la cadena en el sitio de llamada: un `@Around` tejido se invoca directo,
     * sin marco, y entonces la instruccion `proceed` no tendria de donde leer.
     *
     * Se conserva la forma antigua para lo que no se pueda atribuir, que sigue
     * despachandose por la cadena en ejecucion. */
    auto it = fn_ ? proceed_target_.find(fn_->name) : proceed_target_.end();
    if (it != proceed_target_.end() && !it->second.empty()) {
        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALL;
        ins.type = ir::IrType::I64;
        ins.dst = v;
        ins.func_name = it->second;
        ins.operands = fn_->params; // this + args, tal cual llegaron
        ins.is_call_site = true;
        ins.source_line = line;
        emit(current_block_, std::move(ins));
        return v;
    }

    ir::IrInstr ins{};
    ins.op = ir::IrOp::PROCEED;
    ins.type = ir::IrType::I64;
    ins.dst = v;
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

// ---- Sprint 3: label-addr + CLI args + async helper fusion ----

ir::IrValueId Lowering::emit_label_addr(const std::string &label_name,
                                        uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::LABEL_ADDR;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.func_name = label_name; // se interpreta como @Absolute("code.<name>")
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_getpid(uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ins{};
    if (native_poo_) {
        // AOT: pid() -> CALL __vx_pid (vx_async.vx, devuelve
        // __vasync_current_pid).  Sin la VM; el runtime cooperativo lo provee.
        ins.op = ir::IrOp::CALL;
        ins.func_name = "__vx_pid";
        ins.is_call_site = true;
    } else {
        ins.op = ir::IrOp::GETPID;
    }
    ins.type = ir::IrType::I64;
    ins.dst = v;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_getargc(uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::I64);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::GETARGC;
    ins.type = ir::IrType::I64;
    ins.dst = v;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_getarg(ir::IrValueId v_idx, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true; // host_ptr al string del arg
    ir::IrInstr ins{};
    ins.op = ir::IrOp::GETARG;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_idx};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

void Lowering::emit_fulfill_hlt(ir::IrValueId v_fut, ir::IrValueId v_val,
                                uint32_t line) {
    ir::IrInstr ins{};
    ins.op = ir::IrOp::FULFILL_HLT;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_fut, v_val};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
}

// ---- Sprint 4: meta-OOP ----

ir::IrValueId Lowering::emit_findclass(ir::IrValueId v_params, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ins{};
    ins.op = ir::IrOp::FINDCLASS;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_params};
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

ir::IrValueId Lowering::emit_defclass(ir::IrValueId v_params, uint32_t line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    fn_->values[v].is_host_ptr = true;
    ir::IrInstr ins{};
    ins.op = ir::IrOp::DEFCLASS;
    ins.type = ir::IrType::PTR;
    ins.dst = v;
    ins.operands = {v_params};
    ins.is_call_site = true;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
    return v;
}

void Lowering::emit_deffield(ir::IrValueId v_cls, ir::IrValueId v_params,
                             uint32_t line) {
    ir::IrInstr ins{};
    ins.op = ir::IrOp::DEFFIELD;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_cls, v_params};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
}

void Lowering::emit_defmethod(ir::IrValueId v_cls, ir::IrValueId v_params,
                              uint32_t line) {
    ir::IrInstr ins{};
    ins.op = ir::IrOp::DEFMETHOD;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_cls, v_params};
    ins.source_line = line;
    emit(current_block_, std::move(ins));
}

void Lowering::emit_addadvice(ir::IrValueId v_target, ir::IrValueId v_advice,
                              uint64_t kind, uint32_t line) {
    ir::IrInstr ins{};
    ins.op = ir::IrOp::ADDADVICE;
    ins.type = ir::IrType::VOID;
    ins.dst = ir::IR_NO_VALUE;
    ins.operands = {v_target, v_advice};
    ins.imm = kind;
    ins.source_line = line;
    emit(current_block_, std::move(ins));
}

ir::IrValueId Lowering::emit_findclass_by_name(uint64_t name_idx,
                                               uint32_t name_len,
                                               uint32_t line) {
    // 1. ALLOCA 16 bytes para FindClassParams.
    ir::IrValueId v_params = stack_alloc_buf(16, line);
    // 2. LABEL_ADDR @Absolute("code.s_<idx>") -> name_addr.
    ir::IrValueId v_name_addr =
        emit_label_addr("s_" + std::to_string(name_idx), line);
    // 3. STORE name_addr at [v_params + 0].
    {
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir::IrType::I64;
        st.operands = {v_name_addr, v_params};
        st.source_line = line;
        emit(current_block_, std::move(st));
    }
    // 4. STORE name_len at [v_params + 8].
    ir::IrValueId v_name_len =
        emit_const(ir::IrType::I64, static_cast<uint64_t>(name_len), line);
    ir::IrValueId v_off8 = emit_const(ir::IrType::I64, 8, line);
    ir::IrValueId v_params8 = emit_ptr_add(v_params, v_off8, line);
    {
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir::IrType::I64;
        st.operands = {v_name_len, v_params8};
        st.source_line = line;
        emit(current_block_, std::move(st));
    }
    // 5. FINDCLASS -> ClassInfo*.
    return emit_findclass(v_params, line);
}

ir::IrValueId Lowering::emit_getproc(uint32_t source_line) {
    const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
    ir::IrInstr ip{};
    ip.op = ir::IrOp::GETPROC;
    ip.type = ir::IrType::PTR;
    ip.dst = v;
    ip.source_line = source_line;
    emit(current_block_, std::move(ip));
    return v;
}

/**
 * @brief  MC.17.2 -- obtiene (o aloca) el slot de @c static_data
 * para un comptime global.
 *
 * Lookup en @c comptime_global_slots_; si no esta, lee el valor
 * inicial desde @c tc_.comptime_const_values_, emite un slot de 8
 * bytes con esos bits y registra el mapping name -> idx.
 *
 * Solo soporta valores int (i64/u64/bool) en v1.  Strings/structs
 * requeririan inicializacion en @c __module_init via STRMAKE/etc.,
 * lo que es un sprint adicional.
 *
 * @return Indice valido (`s_<idx>` referenciable via STR_LIT_ADDR),
 *         o @c UINT64_MAX si el global no es soportado en v1.
 */
// L2.2: slot para global runtime no-const.  Zero-init en static_data;
// @c __module_init emite las instrucciones que copian el init real (e.g.
// un STRMAKE para strings, una constante para ints) al slot.
//
// CRITICO: usar push_back directo (no intern_static_data) para evitar
// dedup -- cada global necesita SU PROPIO slot aunque comparta bytes
// iniciales (typicamente todos los globals empiezan en {0,0,...,0} y
// si los dedupeamos colisionan en el mismo storage).
uint64_t Lowering::get_or_create_runtime_global_slot(const std::string &name,
                                                     uint64_t nbytes) {
    auto it = runtime_global_slots_.find(name);
    if (it != runtime_global_slots_.end()) return it->second;
    if (nbytes < 8) nbytes = 8; // minimo un qword (alineacion)
    std::vector<uint8_t> bytes(static_cast<size_t>(nbytes), 0); // zero-init
    const uint64_t idx = static_cast<uint64_t>(
        out_mod_->static_data.push_back(std::move(bytes)));
    auto &gmeta = out_mod_->static_data.meta_at(idx);
    // Marcar el slot como NON_DEDUP para que el merge cross-module
    // no colapse multiples globals con bytes iniciales identicos.
    gmeta.flags |= ir::IrModule::SD_FLAG_NON_DEDUP;
    // Un global es UNO en todo el programa, identificado por su nombre (ya
    // mangled por modulo/namespace, `lib__counter`).  El merge cross-module
    // unifica por `shared_key`, asi que el modulo que DEFINE el global y el
    // que solo lo USA (que crea su slot al vuelo, sin ver el AST del dep)
    // acaban compartiendo el mismo storage en vez de tener uno cada uno.
    gmeta.shared_key = name;
    // AOT: un global runtime es MUTABLE -> debe vivir en .data (rw), no en
    // .rodata (r): escribir a un slot read-only segfaultea en nativo.  El
    // interp/JIT ignoran section_name; solo lo consume el codegen AOT.
    gmeta.section_name = ".data";
    runtime_global_slots_[name] = idx;
    return idx;
}

uint64_t Lowering::shared_global_slot_for(const std::string &mangled_label,
                                          const Type &t) {
    // Tamano real del tipo: el slot del consumidor y el del dep se unifican por
    // shared_key y gana el PRIMERO que aparezca en el merge, asi que los dos
    // tienen que pedir el mismo tamano (con un global array, uno de 8 bytes
    // recortaria el storage).  Minimo un qword, como todo global.
    uint64_t nbytes = static_cast<uint64_t>(size_of_type(t));
    if (nbytes < 8) nbytes = 8;
    return get_or_create_runtime_global_slot(mangled_label, nbytes);
}

} // namespace vx
