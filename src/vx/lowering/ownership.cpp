/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/ownership.cpp
 * @brief Quien posee cada cosa, y que hay que soltar al salir de un ambito.
 *
 * Vesta libera sin recolector: lo que un ambito posee se suelta al salir de el,
 * y el compilador emite ese desmontaje en cada via de salida -- el final, un
 * `return`, un `break`, una excepcion --, en orden inverso al de adquisicion.
 *
 * Que se emite depende de QUIEN posee: un `unique` con su liberador, uno con
 * uno propio del programador, un `shared` que solo baja su cuenta, un objeto
 * con destructor, una coleccion.  Y sobre todo depende de si el valor SIGUE
 * siendo del ambito: si se devuelve, se guarda en un campo o se presta hacia
 * fuera, ya no es suyo y soltarlo seria liberar algo vivo.  Averiguar eso -- a
 * donde ESCAPA un valor, y de quien se toma la direccion -- es la otra mitad
 * del fichero, y es lo que hace que el desmontaje sea correcto y no solo
 * puntual.
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
void Lowering::emit_cleanups_range(size_t start, size_t end) {
    if (end > cleanup_stack_.size()) end = cleanup_stack_.size();
    if (start >= end) return;
    // Recorrer [start, end) en orden INVERSO (LIFO).  El cleanup mas
    // reciente (top del stack) se ejecuta primero, igual que destructores
    // C++ en el orden inverso a su construccion.
    for (size_t k = end; k-- > start;) {
        const CleanupAction *it = &cleanup_stack_[k];
        std::vector<ir::IrValueId> opnds = it->operands;
        // refresh: sustituir operands[0] con el binding ACTUAL
        // del local (permite dispose(xs)+cleanup idempotente, etc.).
        if (!it->refresh_name.empty() && !opnds.empty()) {
            const ir::IrValueId v_now = lookup(it->refresh_name);
            if (v_now != ir::IR_NO_VALUE) {
                opnds[0] = v_now;
            }
        }
        switch (it->kind) {
        case CleanupAction::Kind::CALL_DTOR: {
            if (!it->func_name.empty()) {
                // Dispatch estatico: el dtor sintetizado del contenedor se
                // resuelve por el tipo declarado (no polimorfico).  CALL
                // DIRECTO -> mas rapido (sin vtable lookup) y compilable en
                // AOT --target=bare.  El regalloc lo trata como CALL y
                // preserva los regs vivos del scope (incluido v_ret).
                emit_call(it->func_name, std::move(opnds), ir::IrType::VOID,
                          it->source_line);
                break;
            }
            // Dtor polimorfico (herencia/interfaz): emitir CALLVIRT real
            // para que el regalloc lo trate como CALL y preserve regs
            // caller-saved vivos (especialmente el reg que lleva v_ret en
            // lower_return).
            ir::IrInstr cv{};
            cv.op = ir::IrOp::CALLVIRT;
            cv.type = ir::IrType::VOID;
            cv.dst = ir::IR_NO_VALUE;
            cv.operands = std::move(opnds);
            cv.imm = static_cast<uint64_t>(it->dtor_vtable_index);
            cv.source_line = it->source_line;
            emit(current_block_, std::move(cv));
            break;
        }
        case CleanupAction::Kind::STRUCT_DTOR: {
            // CALL directo a <Struct>__dtor(addr): dispatch estatico (los
            // structs no tienen vtable).  IrOp::CALL -> CALLVM en interp/JIT,
            // call nativo en AOT; el inliner puede inlinearlo (dtor trivial =
            // coste ~0).  El regalloc lo trata como CALL y preserva los regs
            // vivos del scope (incluido el reg de v_ret en lower_return).
            emit_call(it->func_name, std::move(opnds), ir::IrType::VOID,
                      it->source_line);
            break;
        }
        case CleanupAction::Kind::CLOSURE_ENV_FREE: {
            // Ownership: liberar el env+slot heap de cada campo closure del
            // struct (move-on-return: el productor suprimio su cleanup via
            // escaping_locals_, asi que este consumidor es el unico que
            // libera).  opnds[0] = PTR al struct (refrescado).  Por campo,
            // reusa emit_free_closure_env_field (null-guard interno).
            if (!opnds.empty()) {
                for (uint32_t off : it->closure_field_offsets) {
                    emit_free_closure_env_field(opnds[0], off, it->source_line);
                }
            }
            break;
        }
        case CleanupAction::Kind::NATIVE_FREE: {
            //  AOT.2.d: invocar `~T()` (CALL directo al dtor del
            // tipo estatico) ANTES de liberar -> el dtor libera sus
            // recursos propios (RAII).  Luego RAW_FREE de la instancia
            // (host_ptr de calloc) -> aot_lower lo baja a call<free>.
            // RAW_FREE(0)/free(NULL) es no-op -> seguro si fue movido.
            if (it->native_dtor_virtual) {
                // AOT.2.d (4): dtor polimorfico via vtable de la
                // instancia.  %vt = LOAD [obj+0]; %fn = LOAD
                // [%vt + idx*8]; CALLIND %fn(obj).  Asi una ref base
                // que posee una instancia derivada ejecuta el dtor
                // DERIVADO (la vtable de obj[0] la puso __new_<Derived>).
                const ir::IrValueId obj = opnds[0];
                // El destructor es un metodo de la CLASE: su ranura va detras
                // del tramo reservado a las interfaces.
                const ir::IrValueId v_fn = emit_vtable_method_ptr(
                    obj, native_class_slot(it->dtor_vtable_index),
                    it->source_line);
                ir::IrInstr ci{};
                ci.op = ir::IrOp::CALLIND;
                ci.type = ir::IrType::VOID;
                ci.dst = ir::IR_NO_VALUE;
                ci.func_ptr = v_fn;
                ci.operands = {obj};
                ci.source_line = it->source_line;
                emit(current_block_, std::move(ci));
            } else if (!it->func_name.empty()) {
                ir::IrInstr dc{};
                dc.op = ir::IrOp::CALL;
                dc.type = ir::IrType::VOID;
                dc.dst = ir::IR_NO_VALUE;
                dc.func_name = it->func_name;
                dc.operands = opnds; // this
                dc.source_line = it->source_line;
                emit(current_block_, std::move(dc));
            }
            ir::IrInstr rf{};
            rf.op = ir::IrOp::RAW_FREE;
            rf.type = ir::IrType::VOID;
            rf.dst = ir::IR_NO_VALUE;
            rf.operands = std::move(opnds);
            rf.source_line = it->source_line;
            emit(current_block_, std::move(rf));
            break;
        }
        case CleanupAction::Kind::STRING_FREE: {
            // Vesta Embed Inc 0 / Inc 5 (SSO): liberar el buffer de un
            // string value-type al exit del scope.  opnds[0] = PTR al slot
            // de 24 bytes.  emit_native_str_free_if_heap libera SOLO si el
            // slot esta en modo HEAP (la data SSO es inline, no se libera)
            // y free(0) es no-op -> seguro tras un move-out.
            emit_native_str_free_if_heap(opnds[0], it->source_line);
            break;
        }
        case CleanupAction::Kind::RAW_ASM: {
            // raw_asm-elim wave 2: dead code.  Todas las creaciones
            // de CleanupAction setean su @c kind explicitamente a un
            // valor especifico (CALL_DTOR/CALLN_FREE/SMARTPTR_FREE/
            // SHAREDPTR_REL/SYNC_EXIT).  Si esta rama se alcanza, es
            // un bug del frontend que olvido setear el kind; emitir
            // diagnostico claro en lugar de raw_asm opaco.
            error_at(
                SourceLoc{"", it->source_line, 1},
                "internal: CleanupAction con Kind::RAW_ASM (default) "
                "alcanzado al exit del scope; el frontend debe setear "
                "un kind especifico (CALL_DTOR/CALLN_FREE/SMARTPTR_FREE/etc.)");
            break;
        }
        case CleanupAction::Kind::SYNC_EXIT: {
            // Sprint 6.C: tryleave + monexit como IR ops puros.
            // AOT (native_poo_): el frame de excepcion es setjmp/longjmp ->
            // se popea con __vx_pop_frame (no TRYLEAVE op, que el backend
            // nativo no soporta); el monitor se libera con __vx_monexit.
            if (native_poo_) {
                emit_call("__vx_pop_frame", {}, ir::IrType::VOID,
                          it->source_line);
            } else {
                ir::IrInstr tl{};
                tl.op = ir::IrOp::TRYLEAVE;
                tl.type = ir::IrType::VOID;
                tl.dst = ir::IR_NO_VALUE;
                tl.source_line = it->source_line;
                emit(current_block_, std::move(tl));
            }
            if (!opnds.empty()) {
                emit_monitor_op(opnds[0], /*enter=*/false, it->source_line);
            }
            break;
        }
        case CleanupAction::Kind::CALLN_FREE: {
            // CALLN al free nativo de la coleccion (variante GC
            // o no-GC).  Para la variante *_gc prependemos un
            // GETPROC como primer argumento; el
            // regalloc trata el CALLN como call normal y preserva
            // los regs vivos del caller.
            std::vector<ir::IrValueId> args;
            if (it->needs_proc) {
                args.reserve(opnds.size() + 1);
                args.push_back(emit_getproc(it->source_line));
            } else {
                args.reserve(opnds.size());
            }
            for (auto vid : opnds)
                args.push_back(vid);
            emit_calln(it->func_name, std::move(args), ir::IrType::VOID,
                       it->source_line);
            break;
        }
        case CleanupAction::Kind::SMARTPTR_FREE: {
            // Cleanup de @c unique<T> en scope exit.
            //
            // Tier 1 layout: slot[+0]=ptr, slot[+8]=deleter_addr.
            //   deleter_addr == 0 -> sentinel: RAW_FREE(ptr).
            //   deleter_addr != 0 -> CALLVMR(deleter_addr, ptr).
            //
            // Si literal_deleter esta poblado (caso comun:
            // var-decl con init = unique_box/unique_with), usamos
            // ese conocimiento compile-time para emitir el cleanup
            // mas eficiente (RAW_FREE directo, CALLVM @Absolute
            // fijo, o CALLN @Method para extern wrappers).
            //
            // Si NO esta poblado (caso SRET: el unique vino de
            // una funcion que lo creo internamente), leemos el
            // deleter_addr del slot+8 y dispatchamos dinamicamente.
            const ir::IrValueId v_ptr =
                emit_load_host_ptr(opnds[0], it->source_line); // [v_slot]

            // Bug fix bug2: si el inner T es una CLASS Vesta con
            // destructor, invocar `~T()` ANTES del free.  El
            // CALLVIRT requiere host_ptr no nulo; emitimos guard
            // implicito via skip si v_ptr == 0 (no debe ocurrir
            // tras unique_box(new T()), pero defensive).
            //
            // Bug fix adicional: si inner_is_gc_class, el host_ptr
            // que vive en el slot apunta a un objeto GC-managed
            // (no a RAW_ALLOC memory).  Hacer RAW_FREE corromperia
            // el heap.  Solo invocamos el destructor + dejamos
            // que el GC libere el objeto cuando ningun root lo
            // referencie (stack scanning A.34.fix8).
            /* Se pregunta si HAY destructor, no si su indice es distinto de
             * cero: cero es el indice del primer metodo de la tabla, y usarlo
             * como "no hay" hacia que una clase sin constructor -- donde el
             * destructor cae justo el primero -- perdiera su limpieza sin decir
             * nada. */
            if (it->inner_has_dtor) {
                // AOT (native_poo): el inner de un unique<T> tiene tipo
                // ESTATICO conocido (T == tipo dinamico salvo polimorfismo).
                // Si NO es polimorfico, despachar el dtor con un CALL DIRECTO a
                // `<Class>____dtor` (PURE_NATIVE) en vez de CALLVIRT (que el
                // selector AOT no soporta).  Asi unique<T> con dtor compila a
                // nativo.  Para inner polimorfico o el path VM/JIT, CALLVIRT.
                if (native_poo_ && !it->inner_dtor_virtual &&
                    !it->inner_dtor_func_name.empty()) {
                    ir::IrInstr cd{};
                    cd.op = ir::IrOp::CALL;
                    cd.type = ir::IrType::VOID;
                    cd.dst = ir::IR_NO_VALUE;
                    cd.operands = {v_ptr};
                    cd.func_name = it->inner_dtor_func_name; // <Class>____dtor
                    cd.source_line = it->source_line;
                    emit(current_block_, std::move(cd));
                } else {
                    ir::IrInstr cv{};
                    cv.op = ir::IrOp::CALLVIRT;
                    cv.type = ir::IrType::VOID;
                    cv.dst = ir::IR_NO_VALUE;
                    cv.operands = {v_ptr};
                    cv.imm = static_cast<uint64_t>(it->inner_dtor_vtable_index);
                    cv.source_line = it->source_line;
                    emit(current_block_, std::move(cv));
                }
            }
            if (it->inner_is_gc_class) {
                // El objeto inner es GC-managed: NO hacer RAW_FREE
                // del host_ptr (el GC se encarga del inner object).
                // El SLOT (raw-alloced de 8/16 bytes) tambien necesita
                // liberarse, pero usa slot_addr (opnds[0]) no v_ptr.
                // Sin embargo, el slot RAW_ALLOC vive solo si fue
                // unique_box (que sigue siendo Tier 0 sin slot RAW).
                // En Tier 1 el slot es ALLOCA stack (no requiere free).
                // Por simplicidad: skip el free completo en este caso.
                // El GC libera el inner; el ALLOCA stack se libera
                // al exit del frame automaticamente.
                break;
            }

            // AOT (native_poo): el selector HOST_LEAF NO soporta el op
            // SMARTPTR_FREE.  Bajamos el cleanup a ops nativas que el selector
            // ya conoce: guard de null (el slot se zerifica tras un move -> no
            // llamar al deleter sobre un null) + CALL al deleter (Vesta) /
            // CALLN (extern) / RAW_FREE (default "free", null-safe) / CALLIND
            // dinamico (SRET).  El path VM/JIT (no native) sigue usando el op
            // SMARTPTR_FREE mas abajo.
            if (native_poo_) {
                const uint32_t ln = it->source_line;
                // El de por defecto es null-safe (RAW_FREE(0)=no-op) -> sin
                // guarda.
                if (is_default_deleter(it->literal_deleter)) {
                    ir::IrInstr fr{};
                    fr.op = ir::IrOp::RAW_FREE;
                    fr.type = ir::IrType::VOID;
                    fr.dst = ir::IR_NO_VALUE;
                    fr.operands = {v_ptr};
                    fr.source_line = ln;
                    emit(current_block_, std::move(fr));
                    break;
                }
                // Resto (deleter custom/extern/SRET): guard `if (ptr != 0)`.
                const ir::IrBlockId bb_do = fn_->new_block("sp_do");
                const ir::IrBlockId bb_skip = fn_->new_block("sp_skip");
                const ir::IrValueId v_z = emit_const(ir::IrType::I64, 0, ln);
                const ir::IrValueId v_cond = emit_ir_binop(
                    ir::IrOp::CMP_NE, v_ptr, v_z, ir::IrType::BOOL, ln);
                {
                    emit_br_cond(v_cond, bb_do, bb_skip, ln);
                }
                current_block_ = bb_do;
                if (it->literal_deleter.rfind("@extern:", 0) == 0) {
                    // deleter extern "<lib>:<fn>" -> CALLN (HOST_LEAF lo baja a
                    // CALL_SYM; el linker lo resuelve).
                    const std::string sym = it->literal_deleter.substr(8);
                    ir::IrInstr cn{};
                    cn.op = ir::IrOp::CALLN;
                    cn.type = ir::IrType::VOID;
                    cn.dst = ir::IR_NO_VALUE;
                    cn.func_name = sym;
                    cn.operands = {v_ptr};
                    cn.source_line = ln;
                    cn.is_call_site = true;
                    emit(current_block_, std::move(cn));
                } else {
                    // deleter Vesta (fn por nombre) -> CALL directo.
                    ir::IrInstr ca{};
                    ca.op = ir::IrOp::CALL;
                    ca.type = ir::IrType::VOID;
                    ca.dst = ir::IR_NO_VALUE;
                    ca.func_name = it->literal_deleter;
                    ca.operands = {v_ptr};
                    ca.source_line = ln;
                    ca.is_call_site = true;
                    emit(current_block_, std::move(ca));
                }
                // bb_do -> bb_skip (para extern/vesta; SRET ya retorno).
                {
                    emit_br(bb_skip, ln);
                }
                current_block_ = bb_skip;
                break;
            }

            /* Aqui habia un tercer camino DINAMICO -- leer quien libera de la
             * palabra de al lado de la ranura y saltar a el -- para cuando el
             * puntero venia de una funcion y no se sabia.  Ahora se sabe
             * siempre: viaja en el TIPO, y una firma lo dice. */
            if (is_default_deleter(it->literal_deleter)) {
                // Deleter por defecto: RAW_FREE (null-safe).
                ir::IrInstr fr{};
                fr.op = ir::IrOp::RAW_FREE;
                fr.type = ir::IrType::VOID;
                fr.dst = ir::IR_NO_VALUE;
                fr.operands = {v_ptr};
                fr.source_line = it->source_line;
                emit(current_block_, std::move(fr));
            } else if (it->literal_deleter.rfind("@extern:", 0) == 0) {
                // raw_asm-elim wave 2: SMARTPTR_FREE kind=1 (EXTERN_CALLN).
                const std::string fn_label =
                    it->literal_deleter.substr(8); // skip "@extern:"
                ir::IrInstr sf{};
                sf.op = ir::IrOp::SMARTPTR_FREE;
                sf.type = ir::IrType::VOID;
                sf.dst = ir::IR_NO_VALUE;
                sf.operands = {v_ptr};
                sf.imm = 1;              /* EXTERN_CALLN */
                sf.func_name = fn_label; /* "<lib>:<fn>" */
                sf.source_line = it->source_line;
                sf.is_call_site = true;
                emit(current_block_, std::move(sf));
            } else {
                // raw_asm-elim wave 2: SMARTPTR_FREE kind=2 (VESTA_CALLVM).
                ir::IrInstr sf{};
                sf.op = ir::IrOp::SMARTPTR_FREE;
                sf.type = ir::IrType::VOID;
                sf.dst = ir::IR_NO_VALUE;
                sf.operands = {v_ptr};
                sf.imm = 2;                         /* VESTA_CALLVM */
                sf.func_name = it->literal_deleter; /* "<fn_label>" */
                sf.source_line = it->source_line;
                sf.is_call_site = true;
                emit(current_block_, std::move(sf));
            }
            break;
        }
        case CleanupAction::Kind::SHAREDPTR_REL: {
            // Sprint 6.C: cleanup de @c shared<T> via IR ops puros.
            //
            // Implementacion: LOAD ctrl; si ctrl != 0, LOAD rc; SUB 1; STORE
            // rc. No emitimos free explicito porque el GcHeap se encarga de
            // liberar bloques sin roots cuando se ejecuta major_gc.
            //
            // Antes: 7 lineas de RAW_ASM con jmp.je por label.
            // Ahora: 7 IR ops (LOAD + CMP + BR_COND + 2 bloques + LOAD + SUB +
            // STORE).
            if (opnds.empty()) break;
            const ir::IrValueId v_slot = opnds[0];
            // ctrl = LOAD i64 [v_slot]   (host_ptr al control block).
            const ir::IrValueId v_ctrl =
                emit_load_host_ptr(v_slot, it->source_line);
            // cmp ctrl, 0  -- si moved/null, skip.
            const ir::IrValueId v_zero =
                emit_const(ir::IrType::I64, 0, it->source_line);
            const ir::IrValueId v_cmp = fn_->new_value(ir::IrType::BOOL);
            {
                ir::IrInstr cmp{};
                cmp.op = ir::IrOp::CMP_NE;
                cmp.type = ir::IrType::I64;
                cmp.dst = v_cmp;
                cmp.operands = {v_ctrl, v_zero};
                cmp.source_line = it->source_line;
                emit(current_block_, std::move(cmp));
            }
            // br.cond v_cmp, dec_bb, skip_bb.
            const ir::IrBlockId dec_bb = fn_->new_block("sh_dec");
            const ir::IrBlockId skip_bb = fn_->new_block("sh_skip");
            {
                emit_br_cond(v_cmp, dec_bb, skip_bb, it->source_line);
            }
            // dec_bb: refcount-- (LOAD + SUB + STORE).
            current_block_ = dec_bb;
            const ir::IrValueId v_rc =
                emit_load_typed(v_ctrl, ir::IrType::I64, it->source_line);
            const ir::IrValueId v_one =
                emit_const(ir::IrType::I64, 1, it->source_line);
            const ir::IrValueId v_rc_dec = emit_ir_binop(
                ir::IrOp::SUB, v_rc, v_one, ir::IrType::I64, it->source_line);
            emit_store_typed(v_ctrl, v_rc_dec, ir::IrType::I64,
                             it->source_line);
            // H3 no-GC: si el refcount cayo a 0, liberar el bloque de control
            // (RAW_FREE).  Refcount puro determinista -> sin GC.  cmp rc==0.
            const ir::IrValueId v_zero2 =
                emit_const(ir::IrType::I64, 0, it->source_line);
            const ir::IrValueId v_is0 = fn_->new_value(ir::IrType::BOOL);
            {
                ir::IrInstr cmp{};
                cmp.op = ir::IrOp::CMP_EQ;
                cmp.type = ir::IrType::I64;
                cmp.dst = v_is0;
                cmp.operands = {v_rc_dec, v_zero2};
                cmp.source_line = it->source_line;
                emit(current_block_, std::move(cmp));
            }
            const ir::IrBlockId free_bb = fn_->new_block("sh_free");
            emit_br_cond(v_is0, free_bb, skip_bb, it->source_line);
            // free_bb: RAW_FREE(v_ctrl) + br skip_bb.
            current_block_ = free_bb;
            {
                ir::IrInstr fr{};
                fr.op = ir::IrOp::RAW_FREE;
                fr.type = ir::IrType::VOID;
                fr.operands = {v_ctrl};
                fr.source_line = it->source_line;
                emit(current_block_, std::move(fr));
            }
            {
                emit_br(skip_bb, it->source_line);
            }
            // current_block_ = skip_bb para que el siguiente cleanup
            // se siga emitiendo en orden lineal.
            current_block_ = skip_bb;
            break;
        }
        }
    }
}

void Lowering::scan_address_taken(ast::Stmt *s) {
    if (!s) return;
    /* Cuenta de ramas CONDICIONALES por encima (then/else de un if, cuerpo de
     * catch).  Va por referencia porque los dos recorridos la comparten: la
     * sube al entrar en una rama y la baja al salir. */
    int cond_depth = 0;
    scan_address_taken_stmt(s, cond_depth);
}

void Lowering::scan_escaping_locals(ast::Stmt *body) {
    if (!body) return;

    // Grafo de aliasing entre locales: alias[A] = {B, C, ...} significa que A
    // puede contener un valor que vino de B o de C, por asignaciones `A = B;`.
    // Sirve para la propagacion de abajo.
    AliasGraph alias;
    scan_escaping_stmt(body, alias);

    // ----- Propagacion transitiva del escape via alias -----
    // Si `target = source` y target ya esta marcado como escaping, source
    // tambien debe estarlo (aliasing semantico).  Iteramos hasta punto fijo.
    // Coste: O(N*M) donde N=#locales escaping, M=longitud cadena alias.
    // En la practica las cadenas son cortas (1-3 hops); converge rapido.
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto &kv : alias) {
            const std::string &target = kv.first;
            if (escaping_locals_.count(target) == 0) continue;
            for (const std::string &source : kv.second) {
                if (escaping_locals_.insert(source).second) {
                    changed = true;
                }
            }
        }
    }
}
void Lowering::store_slot_fields_prestado(ir::IrValueId v_slot,
                                          ir::IrValueId v_buf, uint64_t len,
                                          uint32_t source_line) {
    auto store_at = [&](uint64_t off, ir::IrValueId v_val, ir::IrType ty) {
        ir::IrValueId v_addr = v_slot;
        if (off > 0) {
            ir::IrValueId v_off = emit_const(ir::IrType::I64, off, source_line);
            v_addr = emit_ptr_add(v_slot, v_off, source_line);
        }
        emit_store_typed(v_addr, v_val, ty, source_line);
    };
    store_at(0, v_buf, ir::IrType::I64);
    store_at(8, emit_const(ir::IrType::I64, len, source_line), ir::IrType::I64);
    // Capacidad 0: no hay sitio libre detras, cualquier escritura tiene que
    // copiar antes.  byte[23] = 0xC0 -> bit 7 (los datos estan detras del
    // puntero) + bit 6 (prestado).
    store_at(16, emit_const(ir::IrType::I64, 0, source_line), ir::IrType::I64);
    store_at(23, emit_const(ir::IrType::U8, 0xC0, source_line), ir::IrType::U8);
}

void Lowering::emit_shared_refcount_dec(ir::IrValueId v_slot, uint32_t line) {
    // Ownership ruta B (H3/H5 dec-on-drop): decrementa el refcount del bloque
    // de control de un shared<T> y, si cae a 0, lo libera (RAW_FREE).  El slot
    // guarda el host_ptr al ctrl; refcount en [ctrl+0].  No-op si ctrl==0
    // (movido/null).  Lo usan el cleanup SHAREDPTR_REL del scope local y el
    // destructor del contenedor para un campo shared (H5).
    if (v_slot == ir::IR_NO_VALUE) return;
    const ir::IrValueId v_ctrl = emit_load_host_ptr(v_slot, line);
    const ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, line);
    const ir::IrValueId v_cmp = fn_->new_value(ir::IrType::BOOL);
    {
        ir::IrInstr cmp{};
        cmp.op = ir::IrOp::CMP_NE;
        cmp.type = ir::IrType::I64;
        cmp.dst = v_cmp;
        cmp.operands = {v_ctrl, v_zero};
        cmp.source_line = line;
        emit(current_block_, std::move(cmp));
    }
    const ir::IrBlockId dec_bb = fn_->new_block("shf_dec");
    const ir::IrBlockId skip_bb = fn_->new_block("shf_skip");
    {
        emit_br_cond(v_cmp, dec_bb, skip_bb, line);
    }
    current_block_ = dec_bb;
    const ir::IrValueId v_rc = emit_load_typed(v_ctrl, ir::IrType::I64, line);
    const ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, line);
    const ir::IrValueId v_rc_dec =
        emit_ir_binop(ir::IrOp::SUB, v_rc, v_one, ir::IrType::I64, line);
    emit_store_typed(v_ctrl, v_rc_dec, ir::IrType::I64, line);
    const ir::IrValueId v_is0 = fn_->new_value(ir::IrType::BOOL);
    {
        ir::IrInstr cmp{};
        cmp.op = ir::IrOp::CMP_EQ;
        cmp.type = ir::IrType::I64;
        cmp.dst = v_is0;
        cmp.operands = {v_rc_dec, v_zero};
        cmp.source_line = line;
        emit(current_block_, std::move(cmp));
    }
    const ir::IrBlockId free_bb = fn_->new_block("shf_free");
    emit_br_cond(v_is0, free_bb, skip_bb, line);
    current_block_ = free_bb;
    {
        ir::IrInstr fr{};
        fr.op = ir::IrOp::RAW_FREE;
        fr.type = ir::IrType::VOID;
        fr.operands = {v_ctrl};
        fr.source_line = line;
        emit(current_block_, std::move(fr));
    }
    {
        emit_br(skip_bb, line);
    }
    current_block_ = skip_bb;
}

void Lowering::emit_shared_refcount_inc(ir::IrValueId v_slot, uint32_t line) {
    // Ownership ruta B (H3 inc-on-copy): al COPIAR un shared<T> (`b = a`, campo
    // = a, paso por valor) incrementamos el refcount del bloque de control.
    // El slot guarda el host_ptr al ctrl block; refcount esta en [ctrl + 0].
    // Si ctrl == 0 (movido/null) es no-op.  Simetrico al SHAREDPTR_REL (dec).
    if (v_slot == ir::IR_NO_VALUE) return;
    const ir::IrValueId v_ctrl = emit_load_host_ptr(v_slot, line);
    const ir::IrValueId v_zero = emit_const(ir::IrType::I64, 0, line);
    const ir::IrValueId v_cmp = fn_->new_value(ir::IrType::BOOL);
    {
        ir::IrInstr cmp{};
        cmp.op = ir::IrOp::CMP_NE;
        cmp.type = ir::IrType::I64;
        cmp.dst = v_cmp;
        cmp.operands = {v_ctrl, v_zero};
        cmp.source_line = line;
        emit(current_block_, std::move(cmp));
    }
    const ir::IrBlockId inc_bb = fn_->new_block("sh_inc");
    const ir::IrBlockId skip_bb = fn_->new_block("sh_inc_skip");
    {
        emit_br_cond(v_cmp, inc_bb, skip_bb, line);
    }
    current_block_ = inc_bb;
    const ir::IrValueId v_rc = emit_load_typed(v_ctrl, ir::IrType::I64, line);
    const ir::IrValueId v_one = emit_const(ir::IrType::I64, 1, line);
    const ir::IrValueId v_rc_inc =
        emit_ir_binop(ir::IrOp::ADD, v_rc, v_one, ir::IrType::I64, line);
    emit_store_typed(v_ctrl, v_rc_inc, ir::IrType::I64, line);
    {
        emit_br(skip_bb, line);
    }
    current_block_ = skip_bb;
}

void Lowering::emit_free_closure_env_field(ir::IrValueId this_vid,
                                           uint32_t field_offset,
                                           uint32_t line) {
    const ir::IrBlockId skip_bb = fn_->new_block("free_clo_skip");
    const ir::IrValueId zero = emit_const(ir::IrType::I64, 0, line);

    // slot = LOAD [this + field_offset]  (host_ptr al slot RAW_ALLOC).
    const ir::IrValueId slot_addr =
        emit_field_addr(fn_, current_block_, this_vid, field_offset, line);
    const ir::IrValueId slot =
        emit_load_typed(slot_addr, ir::IrType::I64, line, /*host_ptr=*/true);
    // if (slot == 0) -> skip  (campo nunca asignado / closure null).
    const ir::IrBlockId slot_ok = fn_->new_block("free_clo_slot_ok");
    {
        const ir::IrValueId is_null =
            emit_ir_binop(ir::IrOp::CMP_EQ, slot, zero, ir::IrType::BOOL, line);
        // Campo nunca asignado -> no hay nada que soltar.
        emit_br_cond(is_null, skip_bb, slot_ok, line);
        current_block_ = slot_ok;
    }
    // env = LOAD [slot + 8]
    const ir::IrValueId env_addr = fn_->new_value(ir::IrType::PTR);
    fn_->values[env_addr].is_host_ptr = true;
    {
        const ir::IrValueId eight = emit_const(ir::IrType::I64, 8, line);
        ir::IrInstr ad{};
        ad.op = ir::IrOp::ADD;
        ad.type = ir::IrType::I64;
        ad.dst = env_addr;
        ad.operands = {slot, eight};
        ad.source_line = line;
        emit(current_block_, std::move(ad));
    }
    const ir::IrValueId env =
        emit_load_typed(env_addr, ir::IrType::I64, line, /*host_ptr=*/true);
    // Bloque que SIEMPRE libera el slot (heap owned), tras (quiza) liberar env.
    const ir::IrBlockId free_slot_bb = fn_->new_block("free_clo_slot");
    // if (env == 0) -> free_slot; else RAW_FREE(env) -> free_slot
    {
        const ir::IrValueId is_null =
            emit_ir_binop(ir::IrOp::CMP_EQ, env, zero, ir::IrType::BOOL, line);
        const ir::IrBlockId free_env_bb = fn_->new_block("free_clo_env");
        // Sin entorno solo hay que soltar la ranura.
        emit_br_cond(is_null, free_slot_bb, free_env_bb, line);
        current_block_ = free_env_bb;
    }
    {
        ir::IrInstr rf{};
        rf.op = ir::IrOp::RAW_FREE;
        rf.type = ir::IrType::VOID;
        rf.dst = ir::IR_NO_VALUE;
        rf.operands = {env};
        rf.source_line = line;
        emit(current_block_, std::move(rf));
        emit_br(free_slot_bb, line);
    }
    // free_slot_bb: RAW_FREE(slot); br skip.
    current_block_ = free_slot_bb;
    {
        ir::IrInstr rf{};
        rf.op = ir::IrOp::RAW_FREE;
        rf.type = ir::IrType::VOID;
        rf.dst = ir::IR_NO_VALUE;
        rf.operands = {slot};
        rf.source_line = line;
        emit(current_block_, std::move(rf));
        emit_br(skip_bb, line);
    }
    current_block_ = skip_bb;
    block_terminated_ = false;
}

void Lowering::emit_free_unique_slot(ir::IrValueId slot,
                                     const std::string &deleter, uint32_t line,
                                     bool slot_is_owned) {
    const ir::IrBlockId skip_bb = fn_->new_block("free_uniq_skip");
    const ir::IrValueId zero = emit_const(ir::IrType::I64, 0, line);
    // if (slot == 0) -> skip  (slot nulo / unique movido).
    const ir::IrBlockId slot_ok = fn_->new_block("free_uniq_slot_ok");
    {
        const ir::IrValueId is_null =
            emit_ir_binop(ir::IrOp::CMP_EQ, slot, zero, ir::IrType::BOOL, line);
        emit_br_cond(is_null, skip_bb, slot_ok, line);
        current_block_ = slot_ok;
    }
    // ptr = LOAD [slot + 0]  (el valor/host_ptr a liberar).
    const ir::IrValueId ptr =
        emit_load_typed(slot, ir::IrType::I64, line, /*host_ptr=*/true);
    /* Y si lo que hay DENTRO es cero, no se libera: solo se suelta la ranura.
     *
     * Comprobar que la ranura no es nula NO basta.  Al mover un `unique` fuera
     * de un CAMPO, lo que se vacia es el contenido de la ranura, no el campo:
     * el campo sigue apuntando a una ranura que existe y esta a cero.  El
     * destructor del contenedor la encontraba, cargaba el cero y llamaba al
     * liberador CON EL CERO -- una segunda liberacion del mismo recurso --.
     *
     * Se vio al ejecutar `238_move_from_field_nofree` en nativo: daba dos
     * liberaciones donde tenia que dar una.  No se veia porque ese caso solo
     * se probaba en UN modo. */
    const ir::IrBlockId ptr_ok = fn_->new_block("free_uniq_ptr_ok");
    const ir::IrBlockId solo_ranura = fn_->new_block("free_uniq_solo_ranura");
    {
        const ir::IrValueId sin_valor =
            emit_ir_binop(ir::IrOp::CMP_EQ, ptr, zero, ir::IrType::BOOL, line);
        emit_br_cond(sin_valor, solo_ranura, ptr_ok, line);
        current_block_ = ptr_ok;
    }
    /* Y se llama a QUIEN LIBERA, que lo dice el tipo: una liberacion normal
     * cuando es el de por defecto, y una llamada directa por su nombre cuando
     * es propio.  Vacio quiere decir el de por defecto, y ese criterio vive
     * AQUI y en ningun otro sitio.
     *
     * Debajo habia otro camino, de sesenta y siete lineas, para cuando no se
     * sabia: leia la direccion de la palabra de al lado de la ranura y saltaba
     * a ella.  Eso es lo que obligaba a que un `unique<T>` midiera dos palabras
     * en vez de una.  Ya no lo usa nadie -- todos los sitios conocen el tipo --
     * asi que se va entero.  */
    if (is_default_deleter(deleter)) {
        ir::IrInstr rf{};
        rf.op = ir::IrOp::RAW_FREE;
        rf.type = ir::IrType::VOID;
        rf.dst = ir::IR_NO_VALUE;
        rf.operands = {ptr};
        rf.source_line = line;
        emit(current_block_, std::move(rf));
    } else {
        ir::IrInstr cv{};
        cv.op = ir::IrOp::CALL;
        cv.type = ir::IrType::VOID;
        cv.dst = ir::IR_NO_VALUE;
        cv.func_name = deleter;
        cv.operands = {ptr};
        cv.source_line = line;
        cv.is_call_site = true;
        emit(current_block_, std::move(cv));
    }
    emit_br(solo_ranura, line);
    /* Los dos caminos -- con recurso y sin el -- se juntan aqui.  Lo que cambia
     * es si antes se llamo a quien libera.
     *
     * Y la RANURA solo se suelta si es una reserva propia.  La de un campo no
     * lo es: es un trozo del objeto que la contiene, y se va con el.  (Antes
     * SIEMPRE se soltaba, porque siempre habia una reserva aparte que ya no se
     * hace.)  La de una variable local tampoco: vive en la pila. */
    current_block_ = solo_ranura;
    if (slot_is_owned) {
        ir::IrInstr rf{};
        rf.op = ir::IrOp::RAW_FREE;
        rf.type = ir::IrType::VOID;
        rf.dst = ir::IR_NO_VALUE;
        rf.operands = {slot};
        rf.source_line = line;
        emit(current_block_, std::move(rf));
    }
    emit_br(skip_bb, line);
    current_block_ = skip_bb;
    block_terminated_ = false;
}

/**
 * @copydoc vx::Lowering::mark_loop_assigned_vars
 */
void Lowering::mark_loop_assigned_vars(const ast::Node *n) {
    if (!n) return;
    std::set<std::string> tmp;
    collect_assigned_vars(n, tmp);
    for (const auto &nm : tmp)
        address_taken_locals_.insert(nm);
}

/**
 * @copydoc vx::Lowering::scan_address_taken_expr
 */
void Lowering::scan_address_taken_expr(ast::Expr *e, int &depth) {
    if (!e) return;
    switch (e->kind) {
    case ast::NodeKind::UnaryExpr: {
        auto *u = static_cast<ast::UnaryExpr *>(e);
        if (u->op == ast::UnOp::AddrOf && u->operand &&
            u->operand->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(u->operand.get());
            address_taken_locals_.insert(id->name);
        }
        scan_address_taken_expr(u->operand.get(), depth);
        return;
    }
    case ast::NodeKind::LambdaExpr: {
        // Captures mutables: las variables modificadas dentro
        // del cuerpo de la lambda deben ser address-taken en
        // el outer scope para que el modelo de captura-por-
        // referencia funcione.  El env block guarda el PUNTERO
        // al slot del owner; el helper de la lambda hace
        // LOAD/STORE indirectos sobre ese puntero, de modo
        // que las mutaciones se ven desde fuera del lambda.
        auto *lam = static_cast<ast::LambdaExpr *>(e);
        for (const auto &nm : lam->mutable_captures) {
            address_taken_locals_.insert(nm);
        }
        if (lam->body) scan_address_taken_stmt(lam->body.get(), depth);
        return;
    }
    case ast::NodeKind::BinaryExpr: {
        auto *b = static_cast<ast::BinaryExpr *>(e);
        scan_address_taken_expr(b->lhs.get(), depth);
        scan_address_taken_expr(b->rhs.get(), depth);
        return;
    }
    case ast::NodeKind::AssignExpr: {
        auto *a = static_cast<ast::AssignExpr *>(e);
        scan_address_taken_expr(a->target.get(), depth);
        scan_address_taken_expr(a->value.get(), depth);
        return;
    }
    case ast::NodeKind::CallExpr: {
        auto *c = static_cast<ast::CallExpr *>(e);
        // Borrow checker: lend(x) / lend_mut(x) sobre una
        // variable local plain requiere tomar su direccion
        // (un borrow ES, en runtime, un host_ptr al slot
        // donde vive el local; cero overhead vs un T*).
        // Forzamos address-taken promotion para que el lowering
        // deje el local en stack via ALLOCA + LOAD/STORE en
        // lugar de en registro SSA puro.  Sin esto, lend(local)
        // devuelve un valor (no una direccion) y read_borrow/
        // write_borrow dereferencian basura.  EXCEPCION: si la
        // var ya es de tipo borrow<T>/borrow_mut<T> (es un
        // borrow_var, no un local plain), NO la promocionamos
        // (su SSA value ya es host_ptr; el lend lo bypassa).
        if (c->callee && c->callee->kind == ast::NodeKind::IdentExpr &&
            c->args.size() == 1 &&
            c->args[0]->kind == ast::NodeKind::IdentExpr) {
            auto *cid = static_cast<ast::IdentExpr *>(c->callee.get());
            if (cid->name == "lend" || cid->name == "lend_mut") {
                auto *aid = static_cast<ast::IdentExpr *>(c->args[0].get());
                const Type at = aid->result_type;
                if (at.kind != PrimitiveKind::BORROW &&
                    at.kind != PrimitiveKind::BORROW_MUT &&
                    at.kind != PrimitiveKind::UNIQUE_PTR &&
                    at.kind != PrimitiveKind::SHARED_PTR) {
                    address_taken_locals_.insert(aid->name);
                }
            }
        }
        /* Un argumento que va a un parametro de SALIDA tambien tiene su
         * direccion tomada, aunque en el fuente no haya ningun `&`: es
         * justamente lo que la marca evita escribir.  Sin marcarlo aqui, el
         * bajado pide la direccion de un local que se quedo en un registro SSA
         * y falla con "sobre variable no promocionada".
         *
         * La condicion sale del MISMO predicado que uso la firma, sobre lo
         * apuntado por el parametro -- que es donde la firma dejo la `T`. */
        if (c->callee && c->callee->kind == ast::NodeKind::IdentExpr) {
            auto *cid = static_cast<ast::IdentExpr *>(c->callee.get());
            const FunctionSig *sg = tc_.function_sig_by_name(cid->name);
            if (sg != nullptr && sg->param_by_ref_mask != 0) {
                const size_t n = std::min<size_t>(c->args.size(), 64);
                for (size_t i = 0; i < n; ++i) {
                    if ((sg->param_by_ref_mask & (1ull << i)) == 0) continue;
                    ast::Expr *a = c->args[i].get();
                    if (a && a->kind == ast::NodeKind::IdentExpr)
                        address_taken_locals_.insert(
                            static_cast<ast::IdentExpr *>(a)->name);
                }
            }
        }
        scan_address_taken_expr(c->callee.get(), depth);
        for (auto &arg : c->args)
            scan_address_taken_expr(arg.get(), depth);
        return;
    }
    case ast::NodeKind::FieldAccessExpr: {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e);
        scan_address_taken_expr(fa->base.get(), depth);
        return;
    }
    case ast::NodeKind::IndexExpr: {
        auto *ix = static_cast<ast::IndexExpr *>(e);
        scan_address_taken_expr(ix->base.get(), depth);
        scan_address_taken_expr(ix->index.get(), depth);
        return;
    }
    case ast::NodeKind::CastExpr: {
        // `(T)(&x)`: el cast ENVUELVE el `&x`.  Sin recursar en el
        // operando, el `&x` interno no se veia y `x` no se promocionaba a
        // address-taken
        // -> error "& sobre variable no promocionada".  Bug de deteccion.
        auto *ce = static_cast<ast::CastExpr *>(e);
        scan_address_taken_expr(ce->operand.get(), depth);
        return;
    }
    case ast::NodeKind::TernaryExpr: {
        // `cond ? &a : &b` -- recursar en las 3 ramas por el mismo motivo.
        auto *te = static_cast<ast::TernaryExpr *>(e);
        scan_address_taken_expr(te->cond.get(), depth);
        scan_address_taken_expr(te->then_expr.get(), depth);
        scan_address_taken_expr(te->else_expr.get(), depth);
        return;
    }
    default: return; // literales, IdentExpr puro, etc. no aportan
    }
}

/**
 * @copydoc vx::Lowering::scan_address_taken_stmt
 */
void Lowering::scan_address_taken_stmt(ast::Stmt *st, int &depth) {
    if (!st) return;
    switch (st->kind) {
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<ast::BlockStmt *>(st);
        for (auto &child : b->body)
            scan_address_taken_stmt(child.get(), depth);
        return;
    }
    case ast::NodeKind::VarDeclStmt: {
        auto *vd = static_cast<ast::VarDeclStmt *>(st);
        if (vd->init) scan_address_taken_expr(vd->init.get(), depth);
        return;
    }
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<ast::ExprStmt *>(st);
        scan_address_taken_expr(es->expr.get(), depth);
        return;
    }
    case ast::NodeKind::IfStmt: {
        auto *si = static_cast<ast::IfStmt *>(st);
        scan_address_taken_expr(si->cond.get(), depth);
        // then/else son ramas condicionales: un loop dentro de ellas es el
        // caso del bug (su ALLOCA no domina la rama hermana).
        ++depth;
        scan_address_taken_stmt(si->then_branch.get(), depth);
        scan_address_taken_stmt(si->else_branch.get(), depth);
        --depth;
        return;
    }
    case ast::NodeKind::WhileStmt: {
        auto *w = static_cast<ast::WhileStmt *>(st);
        // Toda variable ASIGNADA dentro de un loop es loop-carried: el
        // lowering le crea un ALLOCA para persistir su valor entre
        // iteraciones (linea ~6377).  Si el loop esta dentro de una rama
        // condicional, ese ALLOCA (creado en el bloque del loop) NO domina
        // la rama HERMANA -> el merge del `if` termina con un PHI que
        // mezcla la DIRECCION del alloca (rama del loop) con el VALOR
        // original (rama sin loop) -> un `load` posterior deref-ea un valor
        // como si fuera puntero (SIGSEGV / basura).  Marcarla address-taken
        // AQUI (pre-pase) fuerza el ALLOCA en su DECLARACION (que domina
        // todo) y todas las ramas la ven como memoria -> representacion
        // consistente. Cero coste: el optimizer re-promueve a SSA los
        // allocas que no escapan (mem2reg / promote_local_allocas).
        if (depth > 0) {
            mark_loop_assigned_vars(w->cond.get());
            mark_loop_assigned_vars(w->body.get());
        }
        scan_address_taken_expr(w->cond.get(), depth);
        scan_address_taken_stmt(w->body.get(), depth);
        return;
    }
    case ast::NodeKind::DoWhileStmt: {
        auto *dw = static_cast<ast::DoWhileStmt *>(st);
        if (depth > 0) {
            mark_loop_assigned_vars(dw->body.get());
            mark_loop_assigned_vars(dw->cond.get());
        }
        scan_address_taken_stmt(dw->body.get(), depth);
        scan_address_taken_expr(dw->cond.get(), depth);
        return;
    }
    case ast::NodeKind::ForStmt: {
        auto *f = static_cast<ast::ForStmt *>(st);
        // Ver la nota en WhileStmt: toda variable asignada dentro del loop
        // se marca address-taken para que su ALLOCA nazca en la declaracion
        // (que domina todo), evitando el PHI direccion-vs-valor cuando el
        // loop esta anidado en una rama condicional.
        if (depth > 0) {
            mark_loop_assigned_vars(f->cond.get());
            mark_loop_assigned_vars(f->step.get());
            mark_loop_assigned_vars(f->body.get());
        }
        scan_address_taken_stmt(f->init.get(), depth);
        scan_address_taken_expr(f->cond.get(), depth);
        scan_address_taken_expr(f->step.get(), depth);
        scan_address_taken_stmt(f->body.get(), depth);
        return;
    }
    case ast::NodeKind::TryStmt: {
        // Sin esta rama, las variables declaradas dentro de un
        // try/catch/finally no se promocionan a address-taken
        // aunque aparezca `&var` en el body (error: '&x' sobre
        // variable no promocionada).  Y el cascade de errores
        // "nombre no resuelto" surge porque el lowering del
        // var-decl falla al evaluar `&var` y deja el binding
        // sin registrar.
        auto *ts = static_cast<ast::TryStmt *>(st);
        // try/catch introducen ramas (el catch se alcanza por un edge
        // de excepcion): un loop dentro puede sufrir el mismo PHI mixto.
        ++depth;
        scan_address_taken_stmt(ts->body.get(), depth);
        for (auto &cc : ts->catches)
            scan_address_taken_stmt(cc.body.get(), depth);
        if (ts->finally_body)
            scan_address_taken_stmt(ts->finally_body.get(), depth);
        --depth;
        return;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *r = static_cast<ast::ReturnStmt *>(st);
        scan_address_taken_expr(r->value.get(), depth);
        return;
    }
    case ast::NodeKind::SynchronizedStmt: {
        auto *sy = static_cast<ast::SynchronizedStmt *>(st);
        scan_address_taken_expr(sy->target.get(), depth);
        scan_address_taken_stmt(sy->body.get(), depth);
        return;
    }
    default: return;
    }
}

/**
 * @copydoc vx::Lowering::mark_escaping_if_ident
 */
void Lowering::mark_escaping_if_ident(ast::Expr *e) {
    if (e && e->kind == ast::NodeKind::IdentExpr)
        escaping_locals_.insert(static_cast<ast::IdentExpr *>(e)->name);
}

/**
 * @copydoc vx::Lowering::value_has_copy_hook
 */
bool Lowering::value_has_copy_hook(ast::Expr *e) const {
    if (!e || e->kind != ast::NodeKind::IdentExpr) return false;
    const Type &t = e->result_type;
    // Un compartido guardado en un campo es una COPIA: se incrementa la cuenta
    // al guardarlo, el origen conserva la suya y su destructor la decrementa.
    // No es un traslado, asi que no escapa.
    if (t.kind == PrimitiveKind::SHARED_PTR) return true;
    if (t.kind != PrimitiveKind::STRUCT) return false;
    auto it = tc_.struct_layouts().find(t.struct_name);
    return it != tc_.struct_layouts().end() && it->second.has_copy_hook;
}

/**
 * @copydoc vx::Lowering::scan_escaping_expr
 */
void Lowering::scan_escaping_expr(ast::Expr *e, AliasGraph &alias) {
    if (!e) return;
    switch (e->kind) {
    case ast::NodeKind::AssignExpr: {
        auto *a = static_cast<ast::AssignExpr *>(e);
        // El target NO escapa por la asignacion misma.  El value
        // SI escapa cuando el target es un campo/slot/deref:
        //   - FieldAccessExpr: this.x = value, obj.x = value
        //   - IndexExpr:       arr[i] = value, p[i] = value
        //   - UnaryExpr Deref: *p = value
        if (a->target) {
            switch (a->target->kind) {
            case ast::NodeKind::FieldAccessExpr:
                if (!value_has_copy_hook(a->value.get()))
                    mark_escaping_if_ident(a->value.get());
                break;
            case ast::NodeKind::IndexExpr: {
                mark_escaping_if_ident(a->value.get());
                /* `s[i] = c` sobre una CADENA la vuelve suya.  Si nacio de un
                 * literal largo, el slot era una vista prestada sobre el
                 * binario y escribir obliga a copiar antes (ver
                 * `emit_native_str_make_writable`): a partir de ahi hay un
                 * buffer que liberar.  Sin apuntarlo aqui, la limpieza del
                 * ambito se omitia -- se decide mirando este conjunto -- y ese
                 * buffer se quedaba sin liberar. */
                auto *ix_t = static_cast<ast::IndexExpr *>(a->target.get());
                if (ix_t->base &&
                    ix_t->base->kind == ast::NodeKind::IdentExpr &&
                    ix_t->base->result_type.kind == PrimitiveKind::STRING) {
                    reassigned_locals_.insert(
                        static_cast<ast::IdentExpr *>(ix_t->base.get())->name);
                }
                break;
            }
            case ast::NodeKind::UnaryExpr: {
                auto *u = static_cast<ast::UnaryExpr *>(a->target.get());
                if (u->op == ast::UnOp::Deref) {
                    mark_escaping_if_ident(a->value.get());
                }
                break;
            }
            case ast::NodeKind::IdentExpr: {
                // Asignacion local-a-local: `target = source`.
                // No marcamos escape ahora; registramos en el
                // grafo de alias para propagacion transitiva.
                // Si `target` resulta escaping al final, `source`
                // tambien lo sera.
                auto *id_t = static_cast<ast::IdentExpr *>(a->target.get());
                // Una variable que se reasigna (o a la que se le anade con
                // `+=`) puede pasar a tener buffer propio, asi que su
                // limpieza al salir del ambito NO se puede omitir.  Se
                // apunta aqui, que es el unico sitio que ya recorre el
                // cuerpo entero.
                reassigned_locals_.insert(id_t->name);
                if (a->value && a->value->kind == ast::NodeKind::IdentExpr) {
                    auto *id_v = static_cast<ast::IdentExpr *>(a->value.get());
                    alias[id_t->name].push_back(id_v->name);
                }
                break;
            }
            default: break;
            }
        }
        scan_escaping_expr(a->target.get(), alias);
        scan_escaping_expr(a->value.get(), alias);
        return;
    }
    case ast::NodeKind::BinaryExpr: {
        auto *b = static_cast<ast::BinaryExpr *>(e);
        scan_escaping_expr(b->lhs.get(), alias);
        scan_escaping_expr(b->rhs.get(), alias);
        return;
    }
    case ast::NodeKind::UnaryExpr: {
        auto *u = static_cast<ast::UnaryExpr *>(e);
        scan_escaping_expr(u->operand.get(), alias);
        return;
    }
    case ast::NodeKind::CallExpr: {
        auto *c = static_cast<ast::CallExpr *>(e);
        scan_escaping_expr(c->callee.get(), alias);
        for (auto &arg : c->args)
            scan_escaping_expr(arg.get(), alias);
        return;
    }
    case ast::NodeKind::FieldAccessExpr: {
        auto *fa = static_cast<ast::FieldAccessExpr *>(e);
        scan_escaping_expr(fa->base.get(), alias);
        return;
    }
    case ast::NodeKind::IndexExpr: {
        auto *ix = static_cast<ast::IndexExpr *>(e);
        scan_escaping_expr(ix->base.get(), alias);
        scan_escaping_expr(ix->index.get(), alias);
        return;
    }
    default: return;
    }
}

/**
 * @copydoc vx::Lowering::scan_escaping_stmt
 */
void Lowering::scan_escaping_stmt(ast::Stmt *st, AliasGraph &alias) {
    if (!st) return;
    switch (st->kind) {
    case ast::NodeKind::BlockStmt: {
        auto *b = static_cast<ast::BlockStmt *>(st);
        for (auto &child : b->body)
            scan_escaping_stmt(child.get(), alias);
        return;
    }
    case ast::NodeKind::VarDeclStmt: {
        auto *vd = static_cast<ast::VarDeclStmt *>(st);
        // `T target = source;` propaga alias para tracking transitivo.
        if (vd->init && vd->init->kind == ast::NodeKind::IdentExpr) {
            auto *id_v = static_cast<ast::IdentExpr *>(vd->init.get());
            alias[vd->name].push_back(id_v->name);
            // Ruta B (move-only): `S b = a` de un struct GESTIONADO (con
            // dtor o campo destructible) SIN copy-hook es un MOVE (estilo
            // Rust): `b` toma el ownership y el dtor de `a` se SUPRIME. Sin
            // esto la copia bit a bit dejaria a `a` y `b` con el mismo
            // recurso -> doble free.  Para tipos con copy-hook NO es move
            // (la copia es real, ambos gestionan via __clone__).
            const Type &st_t = id_v->result_type;
            if (st_t.kind == PrimitiveKind::STRUCT) {
                auto it = tc_.struct_layouts().find(st_t.struct_name);
                if (it != tc_.struct_layouts().end()) {
                    const StructLayout &sl = it->second;
                    bool managed = sl.has_destructible_field;
                    if (!managed)
                        for (const auto &mm : sl.methods)
                            if (mm.is_destructor) {
                                managed = true;
                                break;
                            }
                    if (managed && !sl.has_copy_hook)
                        escaping_locals_.insert(id_v->name);
                }
            }
        }
        if (vd->init) scan_escaping_expr(vd->init.get(), alias);
        return;
    }
    case ast::NodeKind::ExprStmt: {
        auto *es = static_cast<ast::ExprStmt *>(st);
        scan_escaping_expr(es->expr.get(), alias);
        return;
    }
    case ast::NodeKind::IfStmt: {
        auto *si = static_cast<ast::IfStmt *>(st);
        scan_escaping_expr(si->cond.get(), alias);
        scan_escaping_stmt(si->then_branch.get(), alias);
        scan_escaping_stmt(si->else_branch.get(), alias);
        return;
    }
    case ast::NodeKind::WhileStmt: {
        auto *w = static_cast<ast::WhileStmt *>(st);
        scan_escaping_expr(w->cond.get(), alias);
        scan_escaping_stmt(w->body.get(), alias);
        return;
    }
    case ast::NodeKind::DoWhileStmt: {
        auto *dw = static_cast<ast::DoWhileStmt *>(st);
        scan_escaping_stmt(dw->body.get(), alias);
        scan_escaping_expr(dw->cond.get(), alias);
        return;
    }
    case ast::NodeKind::ForStmt: {
        auto *f = static_cast<ast::ForStmt *>(st);
        scan_escaping_stmt(f->init.get(), alias);
        scan_escaping_expr(f->cond.get(), alias);
        scan_escaping_expr(f->step.get(), alias);
        scan_escaping_stmt(f->body.get(), alias);
        return;
    }
    case ast::NodeKind::TryStmt: {
        // Recursar tambien en try para detectar escapes de
        // locales dentro de body, catches y finally.
        auto *ts = static_cast<ast::TryStmt *>(st);
        scan_escaping_stmt(ts->body.get(), alias);
        for (auto &cc : ts->catches)
            scan_escaping_stmt(cc.body.get(), alias);
        if (ts->finally_body) scan_escaping_stmt(ts->finally_body.get(), alias);
        return;
    }
    case ast::NodeKind::SynchronizedStmt: {
        auto *sy = static_cast<ast::SynchronizedStmt *>(st);
        scan_escaping_expr(sy->target.get(), alias);
        scan_escaping_stmt(sy->body.get(), alias);
        return;
    }
    case ast::NodeKind::ReturnStmt: {
        auto *r = static_cast<ast::ReturnStmt *>(st);
        // return ident; -> ident escapa.
        mark_escaping_if_ident(r->value.get());
        scan_escaping_expr(r->value.get(), alias);
        return;
    }
    default: return;
    }
}

} // namespace vx
