/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_concurrent.cpp
 * @brief Bajada de los builtins que hablan CON OTRO: memoria compartida,
 *        operaciones atomicas, buzones y futuros.
 *
 * Lo que une a estos trece no es lo que hacen sino con QUIEN: todos suponen
 * que hay alguien mas -- otro proceso, otro hilo -- y su razon de ser es que
 * lo que uno escribe lo vea el otro, y en el orden correcto.  De ahi que
 * `share` no sea reservar memoria (eso lo hace `malloc`) sino sacarla del
 * monton privado del proceso y ponerla donde el vecino pueda leerla, y que un
 * `atomic_add` no sea sumar (eso es `+`) sino sumar SIN que el vecino vea el
 * estado a medias.
 *
 * Los futuros y los buzones son la misma idea a otra escala: en vez de
 * compartir bytes se comparte un aviso.  `msgsend` deja un mensaje y sigue;
 * `future_alloc` reserva la casilla de una respuesta que todavia no existe, y
 * `fulfill` la rellena cuando llega, despertando a quien la esperaba.
 *
 * Todos bajan a instrucciones que la maquina virtual ya tiene, asi que aqui no
 * hay logica de sincronizacion: solo se traduce la llamada a la instruccion, y
 * se comprueba que los argumentos tienen sentido antes.
 *
 * Se separo de la funcion que despacha todos los builtins.  Entra por su
 * propio punto: si el nombre no es de esta familia, contesta que no y quien
 * pregunta sigue con las demas.
 */
#include "vx/lowering.h"
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
 * @brief Intenta bajar @p e como uno de los builtins de concurrencia.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_concurrent_builtins(ast::CallExpr *e, Builtin b,
                                             ir::IrValueId &out_value) {
    // Memoria compartida entre procesos: sacarla del monton privado y
    // devolverla, mas saber si una direccion dada ya esta compartida.
    const bool is_z6_isshared = (b == Builtin::IsShared);
    const bool is_z6_share = (b == Builtin::Share);
    const bool is_z6_unshare = (b == Builtin::Unshare);
    // Operaciones atomicas sobre esa memoria: leer/escribir sin ver estados a
    // medias, y las dos que hacen falta para construir cualquier otra cosa.
    const bool is_z8_atomic_load = (b == Builtin::AtomicLoadI64);
    const bool is_z8_atomic_store = (b == Builtin::AtomicStoreI64);
    const bool is_z8_atomic_cas = (b == Builtin::AtomicCasI64);
    const bool is_z8_atomic_add = (b == Builtin::AtomicAddI64);
    const bool is_z8_shared_malloc = (b == Builtin::SharedMalloc);
    const bool is_z8_shared_free = (b == Builtin::SharedFree);
    // Buzones: dejar un mensaje a otro proceso y recogerlo del propio.
    const bool is_msgsend = (b == Builtin::Msgsend);
    const bool is_msgrecv = (b == Builtin::Msgrecv);
    // Futuros: la casilla de una respuesta que aun no existe, y rellenarla.
    const bool is_future_alloc = (b == Builtin::FutureAlloc);
    const bool is_fulfill = (b == Builtin::Fulfill);
    // Y mirar como esta ese monton: vivos, bytes, y forzar una recogida.
    const bool is_z10_live_count = (b == Builtin::SharedHeapLiveCount);
    const bool is_z10_bytes = (b == Builtin::SharedHeapBytes);
    const bool is_z10_gc_collect = (b == Builtin::SharedGcCollect);
    /* Los atomicos SIN sufijo: el ancho lo da el tipo del puntero. */
    const bool is_atomic_load_g = (b == Builtin::AtomicLoad);
    const bool is_atomic_store_g = (b == Builtin::AtomicStore);
    const bool is_atomic_cas_g = (b == Builtin::AtomicCas);
    const bool is_atomic_add_g = (b == Builtin::AtomicAdd);
    /* Y esperar el turno: un monitor no es memoria compartida, es el turno. */
    const bool is_wait = (b == Builtin::Wait);
    const bool is_notify = (b == Builtin::Notify);
    const bool is_notifyAll = (b == Builtin::NotifyAll);

    /* Salida rapida: si no es de esta familia no se mira nada de lo de abajo.
     */
    if (!(is_z6_isshared || is_z6_share || is_z6_unshare || is_z8_atomic_load ||
          is_z8_atomic_store || is_z8_atomic_cas || is_z8_atomic_add ||
          is_z8_shared_malloc || is_z8_shared_free || is_msgsend ||
          is_msgrecv || is_future_alloc || is_fulfill || is_z10_live_count ||
          is_z10_bytes || is_z10_gc_collect || is_atomic_load_g ||
          is_atomic_store_g || is_atomic_cas_g || is_atomic_add_g || is_wait ||
          is_notify || is_notifyAll))
        return false;

    /* Preguntar si una direccion ya esta compartida no es una llamada: el
     * dato esta en el propio identificador del objeto, en su bit mas alto.
     * Sacarlo son cuatro operaciones sin tocar memoria:
     *   1. RAW_ASM gchandle dst,src  -> dst = el identificador de 32 bits.
     *   2. CONST u64 0x80000000      -> la mascara de ese bit.
     *   3. AND_BIT                   -> queda el bit, o cero.
     *   4. SHR_U 31                  -> bajarlo a la posicion 0.
     * y un cast a bool. */
    if (is_z6_isshared) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "is_shared: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_obj = lower_expr(e->args[0].get());
        if (v_obj == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // 1) gchandle obj -> handle (u64)
        const ir::IrValueId v_h = emit_gc_handle_for_ptr(v_obj, e->loc.line);
        // 2) const mask
        const ir::IrValueId v_mask =
            emit_const(ir::IrType::U64, 0x80000000ULL, e->loc.line);
        // 3) handle & mask
        const ir::IrValueId v_and = emit_ir_binop(ir::IrOp::AND, v_h, v_mask,
                                                  ir::IrType::U64, e->loc.line);
        // 4) shr 31 -> bit 0 = 0|1
        const ir::IrValueId v_shift =
            emit_const(ir::IrType::U64, 31ULL, e->loc.line);
        const ir::IrValueId v_bit = emit_ir_binop(ir::IrOp::SHR, v_and, v_shift,
                                                  ir::IrType::U64, e->loc.line);
        // 5) cast a bool
        const ir::IrValueId v_bool =
            cast_if_needed(v_bit, ir::IrType::U64, ir::IrType::BOOL,
                           e->loc.line, /*explicit=*/true);
        out_value = v_bool;
        return true;
    }

    // ----- Z.7: share(obj) -> obj (in-place promotion via gcpromote) -----
    // Emite el opcode bytecode @c gcpromote (extended 0xA7) que aloca
    // en el SharedHeap, copia el objeto, registra en SharedHandleTable
    // y devuelve el nuevo host_ptr.  Si el objeto ya esta shared
    // (bit 31 en hash_code), el opcode es no-op idempotente.
    //
    // NOTA: el resultado de share() es una NUEVA referencia.  El
    // original sigue en el gc_heap local (se libera por sweep).
    // Patron correcto en Vesta:
    //   Counter c = new Counter();
    //   c = share(c);                  // c ahora apunta a la copia shared
    if (is_z6_share) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "share: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_obj = lower_expr(e->args[0].get());
        if (v_obj == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const ir::IrValueId v_new = emit_gc_promote(v_obj, e->loc.line);
        fn_->values[v_new].is_gc_object =
            true; // marca de host_ptr a payload GC
        out_value = v_new;
        return true;
    }

    // ----- Z.7: unshare(obj) -> obj (deep copy a heap local) -----
    // Emite @c gcdemote (extended 0xA8).  Idempotente si NO es shared.
    if (is_z6_unshare) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "unshare: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_obj = lower_expr(e->args[0].get());
        if (v_obj == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const ir::IrValueId v_new = emit_gc_demote(v_obj, e->loc.line);
        fn_->values[v_new].is_gc_object = true;
        out_value = v_new;
        return true;
    }

    // ============================================================
    // Z.8 atomic primitives: bajan a opcodes atomicld/st/cas/add.
    // El host_ptr es un i64 que se interpreta como direccion
    // absoluta del host (no VM addr).  El usuario es responsable
    // de la alineacion a 8 bytes para lock-free.
    // ============================================================

    // atomic_load_i64(ptr) -> i64
    if (is_z8_atomic_load) {
        if (e->args.size() != 1) {
            return builtin_error(
                e->loc, "atomic_load_i64: requiere 1 argumento", out_value);
        }
        const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
        out_value = emit_atomic_ld_i64(v_ptr, e->loc.line);
        return true;
    }

    // atomic_store_i64(ptr, val) -> void
    if (is_z8_atomic_store) {
        if (e->args.size() != 2) {
            return builtin_error(
                e->loc, "atomic_store_i64: requiere 2 argumentos", out_value);
        }
        const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
        const ir::IrValueId v_val = lower_expr(e->args[1].get());
        emit_atomic_st_i64(v_ptr, v_val, e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    // atomic_cas_i64(ptr, exp, des) -> i64 (old value)
    if (is_z8_atomic_cas) {
        if (e->args.size() != 3) {
            return builtin_error(
                e->loc, "atomic_cas_i64: requiere 3 argumentos", out_value);
        }
        const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
        const ir::IrValueId v_exp = lower_expr(e->args[1].get());
        const ir::IrValueId v_des = lower_expr(e->args[2].get());
        out_value = emit_atomic_cas_i64(v_ptr, v_exp, v_des, e->loc.line);
        return true;
    }

    // atomic_add_i64(ptr, delta) -> i64 (old value)
    if (is_z8_atomic_add) {
        if (e->args.size() != 2) {
            return builtin_error(
                e->loc, "atomic_add_i64: requiere 2 argumentos", out_value);
        }
        const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
        const ir::IrValueId v_delta = lower_expr(e->args[1].get());
        out_value = emit_atomic_add_i64(v_ptr, v_delta, e->loc.line);
        return true;
    }

    // shared_malloc(size) -> i64* (host_ptr).  Implementacion via CALLN
    // a un wrapper que usa @c vm.shared_heap.alloc.  Por ahora
    // delegamos al @c malloc estandar (raw_allocator) que tambien da
    // memoria host accesible cross-process (mismo address space).
    if (is_z8_shared_malloc) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "shared_malloc: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_size = lower_expr(e->args[0].get());
        const ir::IrValueId v_ptr = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_ptr].is_host_ptr = true;
        // Reuse @c alloc opcode (RAW_ALLOC IR op).  La memoria que
        // retorna es host_ptr, identico en todos los procesos (mismo
        // address space del OS).  Para promocion al SharedHeap real
        // (con tracking de GC), usar @c share() en el objeto creado.
        ir::IrInstr ins{};
        ins.op = ir::IrOp::RAW_ALLOC;
        ins.type = ir::IrType::PTR;
        ins.dst = v_ptr;
        ins.operands = {v_size};
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        out_value = v_ptr;
        return true;
    }

    // shared_free(ptr) -> void
    if (is_z8_shared_free) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "shared_free: requiere 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
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

    if (is_msgsend) {
        if (e->args.size() != 2) {
            return builtin_error(e->loc,
                                 "msgsend: requiere 2 argumentos (pid, valor)",
                                 out_value);
        }
        const ir::IrValueId v_pid = lower_expr(e->args[0].get());
        const ir::IrValueId v_val = lower_expr(e->args[1].get());
        if (v_pid == ir::IR_NO_VALUE || v_val == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // AOT (native_poo_): mailbox por valor -> CALL __vx_msgsend(pid, val)
        // (sin buffer ni VM memory).  Devuelve 1 (ok) en el scheduler coop.
        if (native_poo_) {
            const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I32);
            ir::IrInstr ms{};
            ms.op = ir::IrOp::CALL;
            ms.func_name = "__vx_msgsend";
            ms.type = ir::IrType::I32;
            ms.dst = v_dst;
            ms.operands = {v_pid, v_val};
            ms.is_call_site = true;
            ms.source_line = e->loc.line;
            emit(current_block_, std::move(ms));
            out_value = v_dst;
            return true;
        }
        // ALLOCA 8 bytes en stack para el buffer del mensaje.
        const ir::IrValueId v_buf = stack_alloc_buf(8, e->loc.line);
        // STORE i64 v_val en v_buf.
        emit_store_typed(v_buf, v_val, ir::IrType::I64, e->loc.line);
        // msgsend r_pid, r_addr, r_len  -- usar IR op MSGSEND (0xD0) en lugar
        // de RAW_ASM.  Devuelve bool en R0 (1=ok, 0=error).
        const ir::IrValueId v_len = emit_const(ir::IrType::I64, 8, e->loc.line);
        const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I32);
        ir::IrInstr ms{};
        ms.op = ir::IrOp::MSGSEND;
        ms.type = ir::IrType::I32;
        ms.dst = v_dst;
        ms.operands = {v_pid, v_buf, v_len};
        ms.is_call_site = true;
        ms.source_line = e->loc.line;
        emit(current_block_, std::move(ms));
        out_value = v_dst;
        return true;
    }

    // ----- msgrecv() -----
    // Reservamos 8 bytes en el frame, llamamos msgrecv (bloquea si
    // mailbox vacio; al despertar el proceso re-ejecuta msgrecv y
    // pasa con datos), y leemos el i64 del buffer.
    if (is_msgrecv) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "msgrecv: no acepta argumentos",
                                 out_value);
        }
        // AOT (native_poo_): mailbox por valor -> CALL __vx_msgrecv() -> i64
        // (lee de la mailbox de la tarea actual; no bloquea en Fase 2 -- el
        // mensaje ya esta porque main hace el setup antes de bombear).
        if (native_poo_) {
            const ir::IrValueId v_val = fn_->new_value(ir::IrType::I64);
            ir::IrInstr mr{};
            mr.op = ir::IrOp::CALL;
            mr.func_name = "__vx_msgrecv";
            mr.type = ir::IrType::I64;
            mr.dst = v_val;
            mr.is_call_site = true;
            mr.source_line = e->loc.line;
            emit(current_block_, std::move(mr));
            out_value = v_val;
            return true;
        }
        // ALLOCA 8 bytes para el buffer destino.
        const ir::IrValueId v_buf = stack_alloc_buf(8, e->loc.line);
        // msgrecv r_buf, r_max  -- primer reg = buffer dest, segundo = max len.
        // Convencion del decoder/exec: reg1=r_buf, reg2=r_max (ver
        // exec_instr_msgrecv en exec_instruction_distrib.cpp).
        const ir::IrValueId v_max = emit_const(ir::IrType::I64, 8, e->loc.line);
        {
            ir::IrInstr mr{};
            mr.op = ir::IrOp::MSGRECV;
            mr.type = ir::IrType::VOID;
            mr.dst = ir::IR_NO_VALUE;
            mr.operands = {v_buf, v_max};
            mr.is_call_site = true; // bloquea -> save/restore live regs
            mr.source_line = e->loc.line;
            emit(current_block_, std::move(mr));
        }
        // LOAD i64 desde v_buf -> v_val (resultado).
        const ir::IrValueId v_val =
            emit_load_typed(v_buf, ir::IrType::I64, e->loc.line);
        out_value = v_val;
        return true;
    }

    // ----- future_alloc() -----
    // Emite la instruccion bytecode `future` (0x29) que crea un nuevo
    // FutureObject GC-managed en estado PENDING y deposita su GcHandle
    // en R0.  Capturamos R0 a {dst} como i64 para pasarlo a fulfill/await.
    if (is_future_alloc) {
        if (!e->args.empty()) {
            return builtin_error(e->loc, "future_alloc: no acepta argumentos",
                                 out_value);
        }
        // future -> aloca FutureObject; R0 contiene el handle.
        const ir::IrValueId v_fut = fn_->new_value(ir::IrType::I64);
        // AOT (native_poo_): CALL nativo al scheduler cooperativo
        // (__vx_future_new -> handle), bundle-ado desde vx_async.vx.
        ir::IrInstr fu{};
        fu.op = native_poo_ ? ir::IrOp::CALL : ir::IrOp::FUTURE;
        if (native_poo_) fu.func_name = "__vx_future_new";
        fu.type = ir::IrType::I64;
        fu.dst = v_fut;
        fu.is_call_site = true; // GC alloc
        fu.source_line = e->loc.line;
        emit(current_block_, std::move(fu));
        out_value = v_fut;
        return true;
    }

    // ----- fulfill(fut, value) -----
    // Emite `fulfill r_fut, r_val` (0x2B): resuelve el future con el
    // valor, despierta al waiter (si lo hay) via make_ready.  Devuelve
    // void (no captura R0).
    if (is_fulfill) {
        if (e->args.size() != 2) {
            return builtin_error(e->loc,
                                 "fulfill: requiere 2 argumentos (fut, valor)",
                                 out_value);
        }
        const ir::IrValueId v_fut = lower_expr(e->args[0].get());
        const ir::IrValueId v_val = lower_expr(e->args[1].get());
        if (v_fut == ir::IR_NO_VALUE || v_val == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // AOT (native_poo_): CALL nativo __vx_fulfill(fut, val).
        ir::IrInstr fu{};
        fu.op = native_poo_ ? ir::IrOp::CALL : ir::IrOp::FULFILL;
        if (native_poo_) fu.func_name = "__vx_fulfill";
        fu.type = ir::IrType::VOID;
        fu.dst = ir::IR_NO_VALUE;
        fu.operands = {v_fut, v_val};
        fu.source_line = e->loc.line;
        emit(current_block_, std::move(fu));
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    /* Mirar como esta el monton compartido: cuantos objetos vivos tiene,
     * cuantos bytes ocupa, y forzar una pasada de recogida.  Los tres bajan
     * igual -- una constante que dice cual de los tres y una instruccion --,
     * asi que van en el mismo bloque. */
    if (is_z10_live_count || is_z10_bytes || is_z10_gc_collect) {
        const int op_code = is_z10_live_count ? 0 : is_z10_bytes ? 1 : 2;
        const ir::IrType ret_type =
            is_z10_bytes
                ? ir::IrType::U64
                : (is_z10_live_count ? ir::IrType::U32 : ir::IrType::VOID);
        // raw_asm-elim wave 3: SHARED_STAT IR op dedicado.  El emit
        // del bytecode usa `r14` como dst dummy para el caso VOID
        // (op_code=2 gc_collect) automaticamente.
        const ir::IrValueId v_op =
            emit_const(ir::IrType::I32, (uint64_t)op_code, e->loc.line);
        const ir::IrValueId v_dst = (ret_type == ir::IrType::VOID)
                                        ? ir::IR_NO_VALUE
                                        : fn_->new_value(ret_type);
        ir::IrInstr ss{};
        ss.op = ir::IrOp::SHARED_STAT;
        ss.type = ret_type;
        ss.dst = v_dst;
        ss.operands = {v_op};
        ss.source_line = e->loc.line;
        emit(current_block_, std::move(ss));
        out_value = v_dst;
        return true;
    }

    /* Los atomicos SIN sufijo de ancho: el ancho sale del tipo al que apunta
     * el puntero, no del nombre.  `atomic_add(p, 1)` sobre un `u8*` suma un
     * byte y sobre un `u64*` suma ocho, y quien lo decide es el tipo -- de ahi
     * que esto no se pueda resolver sin haber comprobado tipos antes. */
    if (is_atomic_load_g || is_atomic_store_g || is_atomic_cas_g ||
        is_atomic_add_g) {
        ir::IrType wt = ir::IrType::I64;
        if (!e->args.empty() && e->args[0]->result_type.pointee)
            wt = ir_type_from_primitive(e->args[0]->result_type.pointee->kind);
        // Los atomicos operan sobre BITS enteros (banco GP + instruccion `lock`
        // del ancho).  Un pointee FLOAT (f32/f64) vive en el banco ZMM: la
        // operacion se hace sobre el entero del MISMO ancho (F32->I32,
        // F64->I64) y el valor cruza con BITCAST puro (misma anchura, mismos
        // bits IEEE), que baja a movd/movq -- cero coste.  Sin esto, un
        // `atomic_store` de f32 guardaba los 32 bits bajos de un patron f64 (=
        // 0).
        const bool is_flt = (wt == ir::IrType::F32 || wt == ir::IrType::F64);
        const ir::IrType iwt = (wt == ir::IrType::F32)   ? ir::IrType::I32
                               : (wt == ir::IrType::F64) ? ir::IrType::I64
                                                         : wt;
        auto emit_bc = [&](ir::IrValueId src, ir::IrType tgt) -> ir::IrValueId {
            ir::IrValueId d =
                emit_ir_unop(ir::IrOp::BITCAST, src, tgt, e->loc.line);
            return d;
        };
        if (is_atomic_load_g) {
            if (e->args.size() != 1) {
                return builtin_error(e->loc,
                                     "atomic_load: requiere 1 argumento (T*)",
                                     out_value);
            }
            const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
            ir::IrValueId bits = emit_atomic_ld_i64(v_ptr, e->loc.line, iwt);
            out_value =
                is_flt ? emit_bc(bits, wt) : bits; // bits GP -> float ZMM
            return true;
        }
        if (is_atomic_store_g) {
            if (e->args.size() != 2) {
                return builtin_error(
                    e->loc, "atomic_store: requiere 2 argumentos (T*, T)",
                    out_value);
            }
            const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
            ir::IrValueId v_val = lower_expr(e->args[1].get());
            if (is_flt) {
                // El valor puede llegar como f64 (un literal `5.0`, que es f64
                // por defecto, propagado por la cadena de inline sin
                // re-estrecharse) mientras la celda es f32.  Coaccionar al
                // ancho float REAL de T antes de tomar sus bits.
                v_val = cast_if_needed(v_val, fn_->values[v_val].type, wt,
                                       e->loc.line, true);
                v_val = emit_bc(v_val, iwt); // float ZMM -> bits GP
            }
            emit_atomic_st_i64(v_ptr, v_val, e->loc.line, iwt);
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        if (is_atomic_cas_g) {
            if (e->args.size() != 3) {
                return builtin_error(
                    e->loc, "atomic_cas: requiere 3 argumentos (T*, exp, des)",
                    out_value);
            }
            const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
            ir::IrValueId v_exp = lower_expr(e->args[1].get());
            ir::IrValueId v_des = lower_expr(e->args[2].get());
            if (is_flt) {
                // comparar/escribir los BITS, no el valor
                v_exp = cast_if_needed(v_exp, fn_->values[v_exp].type, wt,
                                       e->loc.line, true);
                v_des = cast_if_needed(v_des, fn_->values[v_des].type, wt,
                                       e->loc.line, true);
                v_exp = emit_bc(v_exp, iwt);
                v_des = emit_bc(v_des, iwt);
            }
            ir::IrValueId res =
                emit_atomic_cas_i64(v_ptr, v_exp, v_des, e->loc.line, iwt);
            out_value = is_flt ? emit_bc(res, wt) : res; // OLD bits -> float
            return true;
        }
        // is_atomic_add_g.  El delta de un xadd es entero por naturaleza; el
        // .vx nunca invoca atomic_add con float (fetch_add sobre float usa el
        // bucle CAS de arriba).  Se baja como entero del ancho de T.
        if (e->args.size() != 2) {
            return builtin_error(
                e->loc, "atomic_add: requiere 2 argumentos (T*, delta)",
                out_value);
        }
        const ir::IrValueId v_ptr = lower_expr(e->args[0].get());
        const ir::IrValueId v_delta = lower_expr(e->args[1].get());
        out_value = emit_atomic_add_i64(v_ptr, v_delta, e->loc.line, iwt);
        return true;
    }

    /* Y esperar a que otro avise.  Un monitor no es memoria compartida: es el
     * turno.  `wait` suelta el cerrojo y se duerme, `notify` despierta a uno y
     * `notifyAll` a todos -- y que suelte el cerrojo es lo que evita que dos
     * procesos se queden esperandose el uno al otro --. */
    if (is_wait || is_notify || is_notifyAll) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc,
                                 std::string(builtin_name(b)) +
                                     ": requiere exactamente 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_obj = lower_expr(e->args[0].get());
        if (v_obj == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // raw_asm-elim 2026-05-28: reemplazado el blob RAW_ASM original
        // por una secuencia de IR ops nativos (GC_HANDLE_FOR_PTR +
        // MONWAIT/MONNOTI/MONNOTA + MONENTER opcional).  Beneficios:
        //   (a) DCE puede eliminar el handle si la op se elimina.
        //   (b) El Selector JIT no tiene que parsear texto raw_asm.
        //   (c) Cada paso es individualmente reorderable por el optimizer.
        //   (d) Cero overhead vs el RAW_ASM previo: mismo bytecode emitido.
        //
        // BugFix t13 preservado: wait(obj) re-adquiere el monitor tras
        // despertar (semantica Java/POSIX condvar) via MONENTER explicito.
        const ir::IrValueId v_handle =
            emit_gc_handle_for_ptr(v_obj, e->loc.line);
        ir::IrOp mop = is_wait     ? ir::IrOp::MONWAIT
                       : is_notify ? ir::IrOp::MONNOTI
                                   : ir::IrOp::MONNOTA;
        {
            ir::IrInstr mi{};
            mi.op = mop;
            mi.type = ir::IrType::VOID;
            mi.dst = ir::IR_NO_VALUE;
            mi.operands = {v_handle};
            mi.source_line = e->loc.line;
            emit(current_block_, std::move(mi));
        }
        if (is_wait) {
            // Re-adquirir el monitor tras wake.
            ir::IrInstr me{};
            me.op = ir::IrOp::MONENTER;
            me.type = ir::IrType::VOID;
            me.dst = ir::IR_NO_VALUE;
            me.operands = {v_handle};
            me.source_line = e->loc.line;
            emit(current_block_, std::move(me));
        }
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    return false;
}

} // namespace vx
