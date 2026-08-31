/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_ownership.cpp
 * @brief Bajada de quien es dueno de que, y quien lo suelta.
 *
 * Vesta no tiene un recolector que decida cuando se libera la memoria: lo
 * decide el codigo, y estos builtins son la manera de decirlo.  Un
 * `unique<T>` tiene un solo dueno y se suelta al salir del ambito que lo
 * creo; un `shared<T>` se cuenta, y lo suelta el ultimo; un `borrow<T>` no es
 * dueno de nada -- solo mira --, y el compilador comprueba que no se quede
 * mirando algo que ya se solto.
 *
 * Lo que hace que esto no cueste nada en ejecucion es que casi todo se decide
 * ANTES.  Un prestamo es literalmente una direccion, ocho bytes: las reglas de
 * quien puede mirar y quien puede escribir se comprueban al compilar, y del
 * codigo generado desaparecen.  Mover tampoco es copiar: `move` traslada el
 * valor y deja el origen a cero en UNA instruccion, y ese cero es lo que hace
 * que soltarlo dos veces sea imposible sin llevar la cuenta de nada.
 *
 * Y de ahi el detalle que mas se nota al leer el codigo generado: el que
 * suelta no siempre es el mismo.  Puede ser el `free` del anfitrion, puede ser
 * una funcion escrita en Vesta, puede ser una del sistema -- cerrar un
 * fichero, devolver memoria virtual --.  El programador la elige al construir
 * y aqui solo se emite la llamada que toque.
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
 * @brief Intenta bajar @p e como uno de los builtins de propiedad y prestamo.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_ownership_builtins(ast::CallExpr *e, Builtin b,
                                            ir::IrValueId &out_value) {
    // Construir con el que suelta por omision: `free` del anfitrion para el de
    // dueno unico, la cuenta de referencias para el compartido.
    const bool is_unique_box = (b == Builtin::UniqueBox);
    const bool is_shared_box = (b == Builtin::SharedBox);
    // Construir eligiendo QUIEN suelta: cualquier funcion de un argumento,
    // escrita en Vesta o del sistema.  Es lo que permite adoptar un fichero
    // abierto, un descriptor o memoria pedida al sistema operativo.
    const bool is_unique_with = (b == Builtin::UniqueWith);
    const bool is_shared_with = (b == Builtin::SharedWith);
    // Y el que deja el valor donde el recolector lo ve.
    const bool is_gc_box = (b == Builtin::GcBox);
    // Trasladar la propiedad: el origen queda a cero, que es lo que hace
    // imposible soltarlo dos veces sin llevar ninguna cuenta.
    const bool is_move = (b == Builtin::Move);
    // Mirar dentro sin quedarse con nada: el puntero de dentro y cuantos
    // duenos hay.
    const bool is_get = (b == Builtin::PtrOf);
    const bool is_use_count = (b == Builtin::UseCount);
    // Prestar: mirar, o mirar y escribir.  Un prestamo es una direccion y
    // nada mas; quien puede que se comprueba al compilar.
    const bool is_lend = (b == Builtin::Lend);
    const bool is_lend_mut = (b == Builtin::LendMut);
    const bool is_read_borrow = (b == Builtin::ReadBorrow);
    const bool is_write_borrow = (b == Builtin::WriteBorrow);

    /* Salida rapida: si no es de esta familia no se mira nada de lo de abajo. */
    if (!(is_unique_box || is_shared_box || is_unique_with ||
          is_shared_with || is_gc_box || is_move || is_get || is_use_count ||
          is_lend || is_lend_mut || is_read_borrow || is_write_borrow))
        return false;

    if (is_gc_box) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "gc_box: requiere 1 argumento", out_value);
        }
        const ir::IrValueId v_payload = lower_expr(e->args[0].get());
        if (v_payload == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const ir::IrType payload_t = fn_->values[v_payload].type;
        const Type sem_payload = e->args[0]->result_type;
        // Clasificacion identica a unique_box/shared_box: un struct value o
        // un smart-pointer wrapper tienen su "valor" en un BUFFER apuntado por
        // v_payload (payload_t==PTR al slot) -> se copia qword-a-qword.  Un
        // primitivo / raw-ptr / cfn es un VALOR de sizeof bytes -> STORE
        // directo.  Una CLASS es un host_ptr a objeto -> STORE directo del ptr.
        const bool payload_is_struct_value =
            (sem_payload.kind == PrimitiveKind::STRUCT) &&
            (tc_.struct_layouts().find(sem_payload.struct_name) !=
             tc_.struct_layouts().end());
        const bool payload_is_smart_wrapper =
            (sem_payload.kind == PrimitiveKind::UNIQUE_PTR ||
             sem_payload.kind == PrimitiveKind::SHARED_PTR ||
             sem_payload.kind == PrimitiveKind::BORROW ||
             sem_payload.kind == PrimitiveKind::BORROW_MUT);
        // sizeof(T) del contenido del box.
        uint64_t box_size = ir::type_access_bytes(payload_t);
        if (payload_is_struct_value) {
            box_size = static_cast<uint64_t>(
                tc_.struct_layouts().at(sem_payload.struct_name).size_bytes);
        } else if (payload_is_smart_wrapper) {
            box_size = smart_ptr_slot_bytes(sem_payload.kind);
        }
        if (box_size == 0) box_size = 8u; // defensivo: nunca alocar 0 bytes.
        // %box = GC_ALLOCP(sizeof(T))  (host_ptr GC-managed).
        const ir::IrValueId v_box = emit_gc_allocp(
            emit_const(ir::IrType::I64, static_cast<int64_t>(box_size),
                       e->loc.line),
            e->loc.line);
        fn_->values[v_box].is_gc_object = true;
        fn_->values[v_box].is_host_ptr = true;
        if (payload_is_struct_value || payload_is_smart_wrapper) {
            // El payload es un PTR a un buffer (slot del wrapper / struct
            // value): copiar qword-a-qword al box.  Mismo mecanismo que
            // unique_box con struct/smart-wrapper.
            const uint64_t qwords = (box_size + 7) / 8;
            for (uint64_t i = 0; i < qwords; ++i) {
                const ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, static_cast<int64_t>(i * 8), e->loc.line);
                const ir::IrValueId v_src_p = fn_->new_value(ir::IrType::PTR);
                fn_->values[v_src_p].is_host_ptr =
                    fn_->values[v_payload].is_host_ptr;
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = v_src_p;
                    ad.operands = {v_payload, v_off};
                    ad.source_line = e->loc.line;
                    emit(current_block_, std::move(ad));
                }
                const ir::IrValueId v_word =
                    emit_load_typed(v_src_p, ir::IrType::I64, e->loc.line);
                const ir::IrValueId v_dst_p =
                    emit_ptr_add(v_box, v_off, e->loc.line);
                emit_store_typed(v_dst_p, v_word, ir::IrType::I64, e->loc.line);
            }
            // Refcount inc-on-copy: si el payload es un shared<T> que viene de
            // COPIAR otra variable shared (IdentExpr, no shared_box/move), el
            // box es un DUEnO adicional del control block -> incrementar el
            // refcount.  Su SHAREDPTR_REL al exit lo decrementa (balance).  Un
            // shared_box(...) / move recien construido tiene refcount=1 y su
            // ownership se transfiere al box sin inc (mismo criterio que el
            // var-decl `shared<T> b = a` vs `shared<T> b = shared_box(...)`).
            if (sem_payload.kind == PrimitiveKind::SHARED_PTR &&
                e->args[0]->kind == ast::NodeKind::IdentExpr) {
                emit_shared_refcount_inc(v_box, e->loc.line);
            }
            // FINALIZADOR GC (cero fuga en escape): el box POSEE un recurso
            // interno (el deleter del unique / el control block del shared).
            // Si el box escapa su scope, el cleanup determinista no corre ->
            // registramos un finalizador GC que ejecuta EXACTAMENTE el mismo
            // deleter/dtor (resuelto por el contenido del propio box) cuando el
            // sweep colecte el box.  El caso no-escape lo desregistra en su
            // cleanup de scope (anti-doble-free).  Cero coste para
            // gc<primitivo> (no es smart-wrapper -> no lleva finalizador).
            if (sem_payload.kind == PrimitiveKind::UNIQUE_PTR) {
                /* Y se le dice A QUIEN llamar, que lo sabemos por el TIPO del
                 * puntero.  Antes se registraba con un cero y el recolector lo
                 * leia del propio box, que es la unica razon por la que un
                 * `unique<T>` tenia que medir dos palabras.  Vacio = el
                 * liberador de por defecto, y ahi el cero sigue valiendo. */
                ir::IrValueId v_del = ir::IR_NO_VALUE;
                if (!sem_payload.deleter_name.empty() &&
                    sem_payload.deleter_name != "free" &&
                    tc_.lookup_extern_qualified(sem_payload.deleter_name)
                        .empty()) {
                    v_del =
                        emit_label_addr(sem_payload.deleter_name, e->loc.line);
                }
                emit_gc_set_finalizer(v_box, /*UNIQUE*/ 1, e->loc.line, v_del);
            } else if (sem_payload.kind == PrimitiveKind::SHARED_PTR) {
                emit_gc_set_finalizer(v_box, /*SHARED*/ 2, e->loc.line);
            }
        } else {
            // Primitivo / raw-ptr / cfn / CLASS: STORE directo del VALOR al
            // box.
            emit_store_typed(v_box, v_payload, payload_t, e->loc.line);
        }
        out_value = v_box;
        return true;
    }

    // ----- unique_box(value) -----  unique<T> Tier 0 con deleter=free.
    // Layout: ALLOCA 8 bytes (slot) + malloc(sizeof(T)) (host) +
    // STORE value en host + STORE host_ptr en slot.  Cleanup al exit
    // del scope: LOAD slot; CMP_EQ 0; CALL free(ptr) si no-null.
    if (is_unique_box || is_shared_box) return lower_owner_box(e, b, out_value);

    // ----- unique_with(value, deleter_fn) / shared_with(...) -----
    // Forma generica donde el programador especifica el deleter.
    // No se hace alloc: el value es el RESULTADO de una alocacion ya
    // hecha (VirtualAlloc, malloc, fopen, socket(), etc.).  El
    // cleanup en scope exit invoca deleter_fn(value) automaticamente.
    //
    // Layout: ALLOCA 8 (slot) + STORE value at [slot].  Cleanup:
    // LOAD ptr; if (ptr != 0) CALL deleter(ptr); zero slot.
    //
    // El nombre del deleter se almacena en CleanupAction::literal_deleter
    // con prefijo "@extern:kVestaIoLib:fn" si es extern, o el nombre puro si
    // es Vesta.  El emit_cleanups_all elige CALLN o CALLVM.
    if (is_unique_with || is_shared_with)
        return lower_owner_box_with(e, b, out_value);

    // ----- move(p) -----  transfer ownership.
    // Cuando `move(p)` es el init DIRECTO de un var-decl, lo maneja
    // lower_var_decl (emite mvtake al slot del var + zerifica el origen) y
    // NUNCA llega aqui.  Pero `move(p)` tambien aparece como ARGUMENTO de
    // funcion (`consume(move(data))`), en una asignacion o en un return.  En
    // esos casos DEBEMOS emitir el mvtake a un TEMPORAL aqui mismo, o el slot
    // origen NO se zerifica -> tanto el origen como el destino liberan el
    // MISMO box -> doble-free (en GC/interp es no-op, en native abort).
    //
    // Replicamos la logica del var-decl: ALLOCA temporal + mvtake [tmp+0]<-
    // [src+0] (+ [tmp+8]<-[src+8] para unique<T>), que MUEVE el contenido y
    // ZERIFICA el origen.  Devolvemos el temporal (el call lee tmp[0] = box).
    if (is_move) return lower_owner_move(e, out_value);

    if (is_get) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "ptr_of: requiere 1 argumento", out_value);
        }
        const Type arg_t = e->args[0]->result_type;
        const ir::IrValueId v_slot = lower_expr(e->args[0].get());
        if (v_slot == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // LOAD ptr from [v_slot].
        const ir::IrValueId v_ptr = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_ptr].is_host_ptr = true;
        // BugFix R2: si el inner T es CLASS, marcar is_gc_object=true
        // para que el regalloc trate al SSA value como handle GC y
        // preserve su naturaleza a traves de CALLVIRTs (el GC scan
        // pratico de A.34.fix8 lo encuentra como root via stack).
        const bool inner_is_class =
            arg_t.pointee && arg_t.pointee->kind == PrimitiveKind::CLASS;
        if (inner_is_class) {
            fn_->values[v_ptr].is_gc_object = true;
        }
        {
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            ld.type = ir::IrType::I64;
            ld.dst = v_ptr;
            ld.operands = {v_slot};
            ld.source_line = e->loc.line;
            emit(current_block_, std::move(ld));
        }
        if (arg_t.kind == PrimitiveKind::SHARED_PTR) {
            // shared<T>: payload esta en +16 del control block.
            const ir::IrValueId v_sixteen =
                emit_const(ir::IrType::I64, 16, e->loc.line);
            const ir::IrValueId v_pay =
                emit_ptr_add(v_ptr, v_sixteen, e->loc.line);
            // BugFix R2: si inner es CLASS, el slot @+16 guarda el
            // host_ptr al objeto.  Hacer otro LOAD para obtenerlo y
            // marcarlo como is_gc_object para CALLVIRT.  Sin esto,
            // ptr_of(shared<Class>).method() recibia el addr del SLOT
            // (no del Class) -> CALLVIRT con this invalido.
            if (inner_is_class) {
                const ir::IrValueId v_obj = fn_->new_value(ir::IrType::PTR);
                fn_->values[v_obj].is_host_ptr = true;
                fn_->values[v_obj].is_gc_object = true;
                ir::IrInstr ld2{};
                ld2.op = ir::IrOp::LOAD;
                ld2.type = ir::IrType::I64;
                ld2.dst = v_obj;
                ld2.operands = {v_pay};
                ld2.source_line = e->loc.line;
                emit(current_block_, std::move(ld2));
                out_value = v_obj;
                return true;
            }
            out_value = v_pay;
            return true;
        }
        // unique<T>: ptr ES el payload.
        out_value = v_ptr;
        return true;
    }

    // ----- use_count(s) -----  i64 refcount del shared<T>.
    if (is_use_count) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "use_count: requiere 1 argumento", out_value);
        }
        const ir::IrValueId v_slot = lower_expr(e->args[0].get());
        if (v_slot == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // LOAD ctrl from [slot].
        const ir::IrValueId v_ctrl = emit_load_host_ptr(v_slot, e->loc.line);
        // LOAD refcount from [ctrl + 0] (host memory).
        const ir::IrValueId v_rc =
            emit_load_typed(v_ctrl, ir::IrType::I64, e->loc.line);
        out_value = v_rc;
        return true;
    }

    // =====================================================================
    // Borrow checker builtins: lend / lend_mut / read_borrow / write_borrow.
    // =====================================================================
    //
    // El borrow checker compile-time ya valido las reglas R1-R4.  El
    // lowering solo emite el codigo correspondiente con cero overhead
    // vs un raw pointer:
    //
    //   lend(owner)       -> ptr_of equivalente al unique<T>/shared<T>.
    //                        Para owner que NO es smart pointer (var
    //                        local plain), emite &owner via slot stack.
    //   lend_mut(owner)   -> mismo bytecode que lend; la distincion
    //                        es puramente compile-time.
    //   read_borrow(b)    -> LOAD a traves del host_ptr (movh).
    //   write_borrow(m,v) -> STORE a traves del host_ptr (movh).
    if (is_lend || is_lend_mut) return lower_borrow_of(e, b, out_value);
    if (is_read_borrow) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc, "read_borrow: requiere 1 argumento (borrow)", out_value);
        }
        const ir::IrValueId v_b = lower_expr(e->args[0].get());
        if (v_b == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // El borrow es un host_ptr.  Marcamos is_host_ptr=true.
        // Para borrow derivado de unique<T>/shared<T> ya lo esta;
        // para `lend(local_plain)` el local fue promocionado a host
        // heap (RAW_ALLOC) en el lowering de su var-decl, asi que
        // el slot ES un host_ptr.  Param borrows tambien son host
        // por convencion (caller responsabilidad).
        fn_->values[v_b].is_host_ptr = true;
        // B2 fix: para STRUCT (y otros tipos cuyo "valor" SSA es PTR
        // a buffer: ARRAY/OPTIONAL/RESULT/CLASS), pass-through del
        // host_ptr al struct.  Sin esto, LOAD payload_t=PTR cargaria
        // los primeros 8 bytes del struct como si fueran otro ptr
        // (mismo bug que tenia el Deref).  Con pass-through, el
        // caller puede hacer (read_borrow(b)).x que baja a ADD off +
        // LOAD i32 correctamente.
        const Type inner = e->args[0]->result_type.pointee
                               ? *e->args[0]->result_type.pointee
                               : Type{};
        if (inner.kind == PrimitiveKind::STRUCT ||
            inner.kind == PrimitiveKind::ARRAY ||
            inner.kind == PrimitiveKind::OPTIONAL ||
            inner.kind == PrimitiveKind::RESULT ||
            inner.kind == PrimitiveKind::CLASS) {
            out_value = v_b;
            return true;
        }
        // LOAD T from [v_b] para tipos escalares.
        const ir::IrType payload_t = ir_type_from_primitive(inner.kind);
        const ir::IrValueId v_dst =
            emit_load_typed(v_b, payload_t, e->loc.line);
        out_value = v_dst;
        return true;
    }
    if (is_write_borrow) {
        if (e->args.size() != 2) {
            return builtin_error(e->loc,
                                 "write_borrow: requiere 2 argumentos (borrow_mut, value)", out_value);
        }
        const ir::IrValueId v_b = lower_expr(e->args[0].get());
        const ir::IrValueId v_v = lower_expr(e->args[1].get());
        if (v_b == ir::IR_NO_VALUE || v_v == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        fn_->values[v_b].is_host_ptr = true;
        const Type inner = e->args[0]->result_type.pointee
                               ? *e->args[0]->result_type.pointee
                               : Type{};
        /* Un AGREGADO no cabe en un STORE.  Su valor SSA es un PUNTERO a su
         * buffer -- `read_borrow` de un struct hace pass-through del host_ptr,
         * arriba --, asi que un `STORE` escribia esa DIRECCION sobre los ocho
         * primeros bytes del propio struct.  Con `P {i32 x; i32 y;}` los dos
         * campos salian siendo las dos mitades de un puntero:
         *
         *     escribir(m): b.x = 99; b.y = 77; write_borrow(m, b);
         *     -> x=1136459712 y=569        (y distinto en cada ejecucion)
         *
         * Lo que toca es COPIAR los bytes.  El tamano sale del layout del
         * struct; si no se conoce, no se inventa: se avisa y no se emite una
         * escritura que corromperia el valor. */
        if (inner.kind == PrimitiveKind::STRUCT) {
            auto it_l = tc_.struct_layouts().find(inner.struct_name);
            if (it_l == tc_.struct_layouts().end()) {
                return builtin_error(e->loc,
                                     "write_borrow: no se conoce la disposicion de '" +
                                         inner.struct_name +
                                         "'; no se puede copiar el valor", out_value);
            }
            const ir::IrValueId v_n = emit_const(
                ir::IrType::I64,
                static_cast<uint64_t>(it_l->second.size_bytes), e->loc.line);
            fn_->values[v_v].is_host_ptr = true;
            ir::IrInstr mc{};
            mc.op = ir::IrOp::MEMCPY;
            mc.type = ir::IrType::I8;
            mc.dst = ir::IR_NO_VALUE;
            mc.operands = {v_b, v_v, v_n};
            mc.source_line = e->loc.line;
            emit(current_block_, std::move(mc));
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const ir::IrType payload_t = ir_type_from_primitive(inner.kind);
        emit_store_typed(v_b, v_v, payload_t, e->loc.line);
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    return false;
}

/**
 * @brief Construye un valor con dueno y el soltador de siempre.
 *
 * `unique_box(v)` y `shared_box(v)`, que se diferencian en quien lo suelta --
 * el `free` del anfitrion o la cuenta de referencias -- pero construyen igual,
 * y de ahi que compartan camino.
 *
 * Lo que se guarda no siempre se copia: si el valor se acaba de construir en
 * el sitio, se construye YA dentro del bloque del monton y no hay copia
 * ninguna.  La copia queda para cuando lo que se guarda es una variable que ya
 * existia, que es el unico caso donde hay dos sitios de verdad.
 *
 * @param e         La llamada.
 * @param b         Cual de los dos es.
 * @param out_value Donde dejar el valor con dueno.
 * @return Siempre @c true; @c false solo si la llamada estaba mal escrita.
 */
bool Lowering::lower_owner_box(ast::CallExpr *e, Builtin b,
                               ir::IrValueId &out_value) {
    const bool is_unique_box = (b == Builtin::UniqueBox);
    if (e->args.size() != 1) {
        return builtin_error(e->loc, std::string(builtin_name(b)) + ": requiere 1 argumento", out_value);
    }
    // Construccion IN-PLACE para `unique<Punto> p = {.x=10, .y=20}`:
    // si el arg es un InitListExpr con target_type_name anotado
    // (desugar de Opcion B en check_var_decl), alocamos host heap
    // PRIMERO y escribimos los campos DIRECTO sobre el host_ptr.
    // Cero memcpy stack -> heap.  Coste = solo los STOREs del init
    // list, igual que un struct value-type normal.
    //
    // El path generico mas abajo (lower_expr del arg + memcpy)
    // sigue cubriendo `unique_box(struct_var_existente)` y otros
    // casos donde el arg ya es un PTR a struct construido.
    if (is_unique_box && e->args[0]->kind == ast::NodeKind::InitListExpr) {
        auto *il = static_cast<ast::InitListExpr *>(e->args[0].get());
        if (!il->target_type_name.empty()) {
            const auto &layouts = tc_.struct_layouts();
            auto it_lay = layouts.find(il->target_type_name);
            if (it_lay != layouts.end()) {
                const StructLayout &lay = it_lay->second;
                // 1. Slot del unique<T> Tier 1 (16 bytes).  M7:
                //    si lower_return seteo unique_box_target_slot_,
                //    construimos directo en el retbuf del caller
                //    (saltamos el stack_alloc_buf intermedio).
                const ir::IrValueId v_slot =
                    (unique_box_target_slot_ != ir::IR_NO_VALUE)
                        ? unique_box_target_slot_
                        : stack_alloc_buf(16, e->loc.line);
                // 2. RAW_ALLOC(sizeof_struct) -> host_ptr.
                const ir::IrValueId v_size = emit_const(
                    ir::IrType::I64, static_cast<int64_t>(lay.size_bytes),
                    e->loc.line);
                const ir::IrValueId v_host =
                    fn_->new_value(ir::IrType::PTR);
                fn_->values[v_host].is_host_ptr = true;
                {
                    ir::IrInstr ins{};
                    ins.op = ir::IrOp::RAW_ALLOC;
                    ins.type = ir::IrType::PTR;
                    ins.dst = v_host;
                    ins.operands = {v_size};
                    ins.source_line = e->loc.line;
                    emit(current_block_, std::move(ins));
                }
                // 3. STOREs por campo directo al host_ptr.  Soporta
                //    designated (.x=10) y posicional ({10, 20}).
                for (size_t i = 0; i < il->elements.size(); ++i) {
                    // Encontrar el StructFieldInfo correspondiente.
                    const StructFieldInfo *fld = nullptr;
                    if (il->is_designated && i < il->field_names.size()) {
                        const std::string &fname = il->field_names[i];
                        fld = find_field(lay, fname);
                        if (!fld) {
                            error_at(il->elements[i]->loc,
                                     "init list: campo '" + fname +
                                         "' no existe en struct '" +
                                         il->target_type_name + "'");
                            continue;
                        }
                    } else {
                        if (i >= lay.fields.size()) {
                            error_at(il->elements[i]->loc,
                                     "init list: demasiados elementos para "
                                     "struct '" +
                                         il->target_type_name + "'");
                            continue;
                        }
                        fld = &lay.fields[i];
                    }
                    // Lower el valor.
                    const ir::IrValueId v_val =
                        lower_expr(il->elements[i].get());
                    if (v_val == ir::IR_NO_VALUE) continue;
                    const ir::IrType ft =
                        ir_type_from_primitive(fld->type.kind);
                    // Cast si hace falta (literal int -> i32 del field,
                    // etc.).
                    const ir::IrType vt_from = fn_->values[v_val].type;
                    const ir::IrValueId v_casted = cast_if_needed(
                        v_val, vt_from, ft, il->elements[i]->loc.line,
                        /*is_explicit=*/true);
                    // Calcular addr destino = v_host + fld->offset.
                    ir::IrValueId v_dst = v_host;
                    if (fld->offset > 0) {
                        const ir::IrValueId v_off = emit_const(
                            ir::IrType::I64,
                            static_cast<int64_t>(fld->offset), e->loc.line);
                        const ir::IrValueId v_addr =
                            fn_->new_value(ir::IrType::PTR);
                        fn_->values[v_addr].is_host_ptr = true;
                        ir::IrInstr ad{};
                        ad.op = ir::IrOp::ADD;
                        ad.type = ir::IrType::I64;
                        ad.dst = v_addr;
                        ad.operands = {v_host, v_off};
                        ad.source_line = e->loc.line;
                        emit(current_block_, std::move(ad));
                        v_dst = v_addr;
                    }
                    // STORE val at [v_dst].
                    emit_store_typed(v_dst, v_casted,
                                     ft, il->elements[i]->loc.line);
                }
                // 4. STORE host_ptr al slot+0 del unique<T>.
                emit_store_typed(v_slot, v_host,
                                 ir::IrType::I64, e->loc.line);
                // 5. Y nada mas: la ranura es UNA palabra.  Aqui se escribia
                //    ademas un cero en la de al lado -- el liberador "por
                //    defecto" --, que ahora vive en el tipo.
                out_value = v_slot;
                return true;
            }
        }
    }
    const ir::IrValueId v_payload = lower_expr(e->args[0].get());
    if (v_payload == ir::IR_NO_VALUE) {
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    const ir::IrType payload_t = fn_->values[v_payload].type;
    // Determinar el tipo Vesta semantico para saber si es struct value
    // (necesita memcpy a host heap) o si es CLASS/primitivo.
    const Type sem_payload = e->args[0]->result_type;
    const bool payload_is_struct_value =
        (sem_payload.kind == PrimitiveKind::STRUCT) &&
        (tc_.struct_layouts().find(sem_payload.struct_name) !=
         tc_.struct_layouts().end());
    // Un cfn (puntero a funcion crudo) es un VALOR de 8 bytes, igual que
    // un i64 -- NO un host_ptr a un objeto.  Aunque su IR type sea PTR,
    // debe alojar una celda heap de 8 bytes y guardar la direccion ahi
    // (como un primitivo), para que `ptr_of(p)` devuelva un cfn* y
    // `*ptr_of(p)` recupere el cfn con un solo LOAD.  Sin esto tomaria
    // la rama class-PTR (store directo) y `*ptr_of` deref-earia el codigo
    // de la funcion -> basura/#UD.
    const bool payload_is_cfn =
        (sem_payload.kind == PrimitiveKind::FUNCTION);
    // bug1: el payload es OTRO smart pointer (unique<T>/shared<T>/borrow).
    // Su @c lower_expr devuelve la DIRECCION del slot (igual que un struct
    // inline: su valor ES su buffer), con @c payload_t == PTR.  Si lo
    // trataramos como un host_ptr-a-objeto (store directo + free), el
    // cleanup haria RAW_FREE sobre la direccion del slot fuente (una ALLOCA
    // en vm_mem) -> SIGSEGV en VM/JIT.  La semantica correcta: el wrapper
    // externo POSEE una COPIA en heap del wrapper interno (sus bytes de
    // slot: shared/borrow=8, unique Tier 1=16).  Copiamos qword-a-qword
    // (mismo mecanismo que un struct value-type) para que el cleanup
    // RAW_FREE libere la copia heap -- NO el control block interno, que el
    // dueno interno (la variable `s`/`a`, aun en scope) decrementa/libera
    // por su cuenta.  Asi no hay double-free ni free de stack address.
    const bool payload_is_smart_wrapper =
        (sem_payload.kind == PrimitiveKind::UNIQUE_PTR ||
         sem_payload.kind == PrimitiveKind::SHARED_PTR ||
         sem_payload.kind == PrimitiveKind::BORROW ||
         sem_payload.kind == PrimitiveKind::BORROW_MUT);
    // bug2: el payload es un PUNTERO RAW (`i64*`, `void*`, etc.) -- un
    // VALOR de 8 bytes, NO un host_ptr a un objeto gestionado (a diferencia
    // de `new Class()` cuyo sem kind es CLASS).  Debe alojarse en una celda
    // heap de 8 bytes y guardar el puntero ahi (igual que cfn / primitivo),
    // para que `ptr_of(u)` devuelva `T**` (la celda) y `*ptr_of(u)`
    // recupere el `T*` con un solo LOAD.  Sin esto se tomaba la rama
    // store-directo (pensada para objetos CLASS) y `*ptr_of` deref-eaba el
    // VALOR del puntero como si fuera una direccion de slot -> se leia el
    // i64 apuntado y luego se deref-eaba ESE como direccion -> SIGSEGV.
    const bool payload_is_raw_ptr =
        (sem_payload.kind == PrimitiveKind::PTR);
    // sizeof(T): para primitivos usar ir_type_size; para structs
    // value-type consultar struct_layouts; para PTR/CLASS no se usa
    // (no alocamos memoria extra, guardamos el host_ptr directo).
    uint64_t payload_size = ir::type_access_bytes(payload_t);
    if (payload_is_struct_value) {
        payload_size = static_cast<uint64_t>(
            tc_.struct_layouts().at(sem_payload.struct_name).size_bytes);
    } else if (payload_is_smart_wrapper) {
        payload_size = smart_ptr_slot_bytes(sem_payload.kind);
    }
    if (is_unique_box) {
        // unique<T> Tier 1 (16 bytes):
        //   [+0 i64 ptr][+8 i64 deleter_addr]
        // deleter_addr = 0 (sentinel) -> cleanup hace RAW_FREE.
        // Layout 16 bytes para que el deleter info sobreviva
        // cuando la funcion devuelve el unique<T> via SRET.
        // M7: si lower_return seteo target slot, usar el retbuf del
        // caller directamente (skip allocacion intermedia en stack).
        const ir::IrValueId v_slot =
            (unique_box_target_slot_ != ir::IR_NO_VALUE)
                ? unique_box_target_slot_
                : unique_slot_buf(e->loc.line);

        // Bug fix bug2: si el payload ya es un host_ptr (e.g.
        // `new Recurso(1)` devuelve PTR), guardarlo DIRECTAMENTE
        // en slot[+0] sin doble indireccion via RAW_ALLOC.  De
        // lo contrario, el cleanup CALLVIRT al destructor opera
        // sobre el malloc'd region (8 bytes basura) en vez del
        // objeto Recurso real, y el dtor nunca se invoca.
        //
        // Para primitivos (i32, f64, etc.) seguimos usando
        // RAW_ALLOC porque `ptr_of(p)` debe devolver `T*` (host
        // memory).  Para PTR el `ptr_of` devuelve el mismo
        // host_ptr almacenado.
        ir::IrValueId v_to_store = v_payload;
        if (payload_is_struct_value || payload_is_smart_wrapper) {
            // Struct value-type O smart-pointer wrapper (bug1):
            // RAW_ALLOC(N) + memcpy qword-by-qword desde v_payload (PTR al
            // slot fuente) hacia v_payload_ptr (host heap).  Asi el
            // unique<T> ES dueno exclusivo de una copia en heap; el slot
            // fuente original puede morir al exit del scope sin afectar la
            // copia.  Para un wrapper interno, la copia contiene el
            // host_ptr/ctrl del wrapper (que su dueno original libera); el
            // cleanup del externo solo RAW_FREE-a esta celda de N bytes.
            const ir::IrValueId v_size =
                emit_const(ir::IrType::I64,
                           static_cast<int64_t>(payload_size), e->loc.line);
            const ir::IrValueId v_payload_ptr =
                fn_->new_value(ir::IrType::PTR);
            fn_->values[v_payload_ptr].is_host_ptr = true;
            {
                ir::IrInstr ins{};
                ins.op = ir::IrOp::RAW_ALLOC;
                ins.type = ir::IrType::PTR;
                ins.dst = v_payload_ptr;
                ins.operands = {v_size};
                ins.source_line = e->loc.line;
                emit(current_block_, std::move(ins));
            }
            // Copy qword-by-qword (size redondeado hacia arriba a
            // multiplos de 8 bytes; el ultimo qword puede tener
            // padding pero no afecta correctness porque escribimos
            // sobre RAW_ALLOC zero-init y leemos desde el slot
            // ALLOCA que tiene tamano >= size_bytes).
            const uint64_t qwords = (payload_size + 7) / 8;
            for (uint64_t i = 0; i < qwords; ++i) {
                const ir::IrValueId v_off =
                    emit_const(ir::IrType::I64, static_cast<int64_t>(i * 8),
                               e->loc.line);
                const ir::IrValueId v_src_p =
                    fn_->new_value(ir::IrType::PTR);
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = v_src_p;
                    ad.operands = {v_payload, v_off};
                    ad.source_line = e->loc.line;
                    emit(current_block_, std::move(ad));
                }
                const ir::IrValueId v_word =
                    fn_->new_value(ir::IrType::I64);
                {
                    ir::IrInstr ld{};
                    ld.op = ir::IrOp::LOAD;
                    ld.type = ir::IrType::I64;
                    ld.dst = v_word;
                    ld.operands = {v_src_p};
                    ld.source_line = e->loc.line;
                    emit(current_block_, std::move(ld));
                }
                const ir::IrValueId v_dst_p =
                    fn_->new_value(ir::IrType::PTR);
                fn_->values[v_dst_p].is_host_ptr = true;
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = v_dst_p;
                    ad.operands = {v_payload_ptr, v_off};
                    ad.source_line = e->loc.line;
                    emit(current_block_, std::move(ad));
                }
                emit_store_typed(v_dst_p, v_word,
                                 ir::IrType::I64, e->loc.line);
            }
            v_to_store = v_payload_ptr;
        } else if (payload_t != ir::IrType::PTR || payload_is_cfn ||
                   payload_is_raw_ptr) {
            // RAW_ALLOC(payload_size) -> v_payload_ptr (host ptr).
            // (cfn y punteros raw entran aqui pese a ser PTR: son valores
            //  de 8 bytes que se cajean, no host_ptrs a objetos.)
            const ir::IrValueId v_size =
                emit_const(ir::IrType::I64,
                           static_cast<int64_t>(payload_size), e->loc.line);
            const ir::IrValueId v_payload_ptr =
                fn_->new_value(ir::IrType::PTR);
            fn_->values[v_payload_ptr].is_host_ptr = true;
            {
                ir::IrInstr ins{};
                ins.op = ir::IrOp::RAW_ALLOC;
                ins.type = ir::IrType::PTR;
                ins.dst = v_payload_ptr;
                ins.operands = {v_size};
                ins.source_line = e->loc.line;
                emit(current_block_, std::move(ins));
            }
            // STORE payload at [v_payload_ptr] (host memory).
            emit_store_typed(v_payload_ptr, v_payload,
                             payload_t, e->loc.line);
            v_to_store = v_payload_ptr;
        }
        // STORE v_to_store at [v_slot+0].
        //   Para primitivos: v_to_store = malloc'd ptr -> RAW_FREE valido.
        //   Para PTR (class/struct): v_to_store = host_ptr al objeto;
        //                            cleanup hace CALLVIRT dtor + skip
        //                            free.
        emit_store_typed(v_slot, v_to_store, ir::IrType::I64, e->loc.line);
        /* Y nada mas: la ranura es UNA palabra.  Aqui se escribia ademas un
         * cero en la de al lado -- el liberador "de por defecto" --, ocho bytes
         * por una constante en el caso mas frecuente.  Quien libera vive ahora
         * en el TIPO y quien limpia lo llama por su nombre. */
        fn_->values[v_slot].pointee_is_host_ptr = true;
        out_value = v_slot;
        return true;
    } else {
        // shared<T> (H3 no-GC): RAW_ALLOC(16 + 8) del bloque de control.
        // Layout: [+0 i64 refcount=1][+8 u64 deleter=0][+16 T payload].
        // El slot stack guarda host_ptr al control block.  El cleanup
        // SHAREDPTR_REL hace `free` cuando el refcount cae a 0 (refcount
        // puro, determinista, sin GC -> funciona en AOT standalone).
        const ir::IrValueId v_slot = stack_alloc_buf(8, e->loc.line);
        const ir::IrValueId v_ctrl_size = emit_const(
            ir::IrType::I64, 16 + 8, e->loc.line); // 24 bytes total
        // RAW_ALLOC -> host_ptr al bloque de control.
        const ir::IrValueId v_ctrl = fn_->new_value(ir::IrType::PTR);
        fn_->values[v_ctrl].is_host_ptr = true;
        {
            ir::IrInstr ins{};
            ins.op = ir::IrOp::RAW_ALLOC;
            ins.type = ir::IrType::PTR;
            ins.dst = v_ctrl;
            ins.operands = {v_ctrl_size};
            ins.source_line = e->loc.line;
            emit(current_block_, std::move(ins));
        }
        // STORE refcount=1 at [v_ctrl + 0].
        {
            const ir::IrValueId v_one =
                emit_const(ir::IrType::I64, 1, e->loc.line);
            emit_store_typed(v_ctrl, v_one, ir::IrType::I64, e->loc.line);
        }
        // STORE deleter=0 at [v_ctrl + 8] (placeholder; cleanup usa free
        // literal).
        {
            const ir::IrValueId v_eight =
                emit_const(ir::IrType::I64, 8, e->loc.line);
            const ir::IrValueId v_ctrl8 =
                emit_ptr_add(v_ctrl, v_eight, e->loc.line);
            const ir::IrValueId v_zero =
                emit_const(ir::IrType::I64, 0, e->loc.line);
            emit_store_typed(v_ctrl8, v_zero, ir::IrType::I64, e->loc.line);
        }
        // STORE payload at [v_ctrl + 16].
        {
            const ir::IrValueId v_sixteen =
                emit_const(ir::IrType::I64, 16, e->loc.line);
            const ir::IrValueId v_ctrl16 =
                emit_ptr_add(v_ctrl, v_sixteen, e->loc.line);
            emit_store_typed(v_ctrl16, v_payload, payload_t, e->loc.line);
        }
        // STORE v_ctrl at [v_slot] (VM memory).
        emit_store_typed(v_slot, v_ctrl, ir::IrType::I64, e->loc.line);
        fn_->values[v_slot].pointee_is_host_ptr = true;
        out_value = v_slot;
        return true;
    }
    return true;
}

/**
 * @brief Construye un valor con dueno eligiendo QUIEN lo suelta.
 *
 * `unique_with(v, soltar)` y `shared_with(v, soltar)`, con cualquier funcion
 * de un argumento -- escrita en Vesta o del sistema.  Es lo que permite poner
 * bajo dueno cosas que no salieron de pedir memoria: un fichero abierto, un
 * descriptor, memoria que dio el sistema operativo.
 *
 * Aqui no se pide nada: el valor YA es el resultado de haberlo hecho, asi que
 * solo se guarda y se apunta con que soltarlo al salir del ambito.
 *
 * @param e         La llamada.
 * @param b         Cual de los dos es.
 * @param out_value Donde dejar el valor con dueno.
 * @return Siempre @c true; @c false si la llamada estaba mal escrita.
 */
bool Lowering::lower_owner_box_with(ast::CallExpr *e, Builtin b,
                                    ir::IrValueId &out_value) {
    const bool is_unique_with = (b == Builtin::UniqueWith);
    if (e->args.size() != 2) {
        return builtin_error(e->loc, std::string(builtin_name(b)) + ": requiere 2 argumentos", out_value);
    }
    const ir::IrValueId v_payload = lower_expr(e->args[0].get());
    if (v_payload == ir::IR_NO_VALUE) {
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    // Validar que arg[1] sea IdentExpr (type_checker ya lo verifico).
    if (e->args[1]->kind != ast::NodeKind::IdentExpr) {
        return builtin_error(e->args[1]->loc,
                             std::string(builtin_name(b)) +
                                 ": el deleter debe ser un identificador de funcion", out_value);
    }
    const auto *deleter_id =
        static_cast<const ast::IdentExpr *>(e->args[1].get());
    // Capturamos el nombre del deleter; el cleanup lo usara.
    std::string deleter_label =
        tc_.lookup_extern_qualified(deleter_id->name);
    if (deleter_label.empty()) {
        // No es extern -> es funcion Vesta.  Usamos el nombre puro;
        // el cleanup emitira CALLVM @Absolute("code.<name>").
        deleter_label = deleter_id->name;
    } // else: ya viene con prefijo "@extern:kVestaIoLib:fn".
    /* UNA palabra: el manejador y nada mas.
     *
     * Aqui se escribia ademas la DIRECCION del liberador en la palabra de al
     * lado, y con ella venia todo lo demas: materializarla con un `label_addr`,
     * un centinela cero para los liberadores que no son funciones Vesta
     * -- `free` y los `extern` no tienen direccion que apuntar --, y cuidar de
     * que la escritura usara la misma memoria que la del manejador.
     *
     * Nada de eso hace falta ya: quien libera va en el TIPO, asi que quien
     * limpia lo sabe al compilar y lo llama por su nombre.  Y de paso
     * desaparece la limitacion que estaba escrita aqui -- que un liberador
     * `extern` no sobrevivia a cruzar una funcion, porque no habia direccion
     * que guardar --: el tipo lo dice igual, sea Vesta o extern. */
    const ir::IrValueId v_slot = unique_slot_buf(e->loc.line);
    emit_store_typed(v_slot, v_payload, ir::IrType::I64, e->loc.line);
    /* Y nada mas: la ranura es UNA palabra, el manejador.
     *
     * Aqui se escribia ademas la DIRECCION de quien libera en la de al lado, y
     * con ella todo lo que hacia falta para ponerla: materializarla, y un cero
     * para los liberadores que no son funciones Vesta -- `free` y los `extern`
     * no tienen direccion que apuntar --.  Quien limpia lo saca del TIPO, asi
     * que no hay nada que guardar; y de paso desaparece esa limitacion, porque
     * el tipo lo dice igual sea Vesta o extern. */
    (void)deleter_label;
    // El slot contiene un valor con semantica de host_ptr / handle.
    fn_->values[v_slot].pointee_is_host_ptr = true;
    out_value = v_slot;
    return true;
}

/**
 * @brief Traslada la propiedad de un valor: `move(p)`.
 *
 * Deja el origen a CERO, y esa es toda la garantia: al salir del ambito se
 * sueltan los dos, pero el que ya no es dueno tiene un cero, y soltar un cero
 * no hace nada.  Sin llevar ninguna cuenta ni marcar nada en ejecucion.
 *
 * Copiar sin mas no valdria: origen y destino soltarian lo MISMO, que en el
 * anfitrion es un fallo de verdad, no un no-op.
 *
 * @param e         La llamada.
 * @param out_value Donde dejar el valor que ahora tiene la propiedad.
 * @return Siempre @c true; @c false si la llamada estaba mal escrita.
 */
bool Lowering::lower_owner_move(ast::CallExpr *e, ir::IrValueId &out_value) {
    if (e->args.size() != 1) {
        return builtin_error(e->loc, "move: requiere 1 argumento", out_value);
    }
    const ir::IrValueId v_src = lower_expr(e->args[0].get());
    if (v_src == ir::IR_NO_VALUE) {
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    // La ranura de los dos es UNA palabra: el manejador (unique) o el bloque
    // de control (shared).  Quien libera va en el tipo, no aqui.
    const bool is_unique =
        (e->args[0]->result_type.kind == PrimitiveKind::UNIQUE_PTR);
    const uint32_t slot_bytes = static_cast<uint32_t>(smart_ptr_slot_bytes(
        is_unique ? PrimitiveKind::UNIQUE_PTR : PrimitiveKind::SHARED_PTR));
    /* La ranura de destino es SIEMPRE de la pila.
     *
     * Habia una segunda via que la reservaba en el monton cuando el resultado
     * del traspaso iba a parar a un CAMPO, para que sobreviviera a quien lo
     * creo.  Ya no hace falta -- un campo es su propia ranura --, y con ella se
     * va la copia palabra a palabra que hacia falta porque `mvtake` no sabe
     * escribir en memoria del anfitrion.  Quien guarda en el campo hace el
     * traspaso alli. */
    const ir::IrValueId v_tmp = fn_->new_value(ir::IrType::PTR);
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = v_tmp;
        al.imm = slot_bytes;
        al.source_line = e->loc.line;
        emit(current_block_, std::move(al));
    }
    // mvtake [tmp+0] <- [src+0]  (mueve el box-ptr + zerifica origen).
    emit_mvtake(v_tmp, v_src, e->loc.line);
    if (slot_bytes == 16) {
        // Segundo qword: deleter.
        const ir::IrValueId v_eight =
            emit_const(ir::IrType::I64, 8, e->loc.line);
        const ir::IrValueId v_tmp8 = fn_->new_value(ir::IrType::PTR);
        const ir::IrValueId v_src8 = fn_->new_value(ir::IrType::PTR);
        {
            ir::IrInstr add{};
            add.op = ir::IrOp::ADD;
            add.type = ir::IrType::I64;
            add.dst = v_tmp8;
            add.operands = {v_tmp, v_eight};
            add.source_line = e->loc.line;
            emit(current_block_, std::move(add));
        }
        {
            ir::IrInstr add{};
            add.op = ir::IrOp::ADD;
            add.type = ir::IrType::I64;
            add.dst = v_src8;
            add.operands = {v_src, v_eight};
            add.source_line = e->loc.line;
            emit(current_block_, std::move(add));
        }
        emit_mvtake(v_tmp8, v_src8, e->loc.line);
    }
    fn_->values[v_tmp].pointee_is_host_ptr = true;
    out_value = v_tmp;
    return true;
    return true;
}

/**
 * @brief Presta un valor: `lend(o)` y `lend_mut(o)`.
 *
 * Un prestamo es una direccion y nada mas -- ni cuenta, ni marca, ni nada en
 * ejecucion --, asi que los dos emiten lo MISMO: quien puede leer y quien
 * puede escribir se comprueba al compilar y no deja rastro.
 *
 * De donde sale la direccion depende de a quien se presta: de un valor con
 * dueno es lo que guarda dentro; de otro prestamo es el mismo puntero, y ahi
 * ademas se suspende el original mientras el nuevo viva; y de una variable
 * cuya direccion ya se tomo, ella misma.
 *
 * @param e         La llamada.
 * @param out_value Donde dejar la direccion prestada.
 * @return Siempre @c true; @c false si la llamada estaba mal escrita.
 */
bool Lowering::lower_borrow_of(ast::CallExpr *e, Builtin b,
                               ir::IrValueId &out_value) {
    const bool is_lend_mut = (b == Builtin::LendMut);
    if (e->args.size() != 1) {
        return builtin_error(e->loc, std::string(builtin_name(b)) + ": requiere 1 argumento (owner)", out_value);
    }
    /* El prestamo no deja rastro en el IR -- esto no emite instruccion, el
     * puntero es el mismo --, asi que lo que el borrow checker demuestra se
     * quedaba dentro del type checker.  Se apunta como HECHO del IR, con su
     * procedencia, para que el analisis pueda componerlo con regiones y
     * efectos.  Anotar no cambia el codigo generado. */
    auto anota_prestamo = [&](ir::IrValueId v_pres, ir::IrValueId v_owner) {
        if (v_pres == ir::IR_NO_VALUE || !fn_) return;
        ir::IrFunction::BorrowFact bf;
        bf.value = v_pres;
        bf.owner = v_owner;
        bf.mutable_ = is_lend_mut;
        /* La naturaleza de lo prestado viaja con el hecho: prestar un
         * `unique` no es lo mismo que prestar un local, y nadie debe
         * confundirlos despues. */
        const Type &ot = e->args[0]->result_type;
        using OK = ir::IrFunction::BorrowOwnerKind;
        bf.owner_kind = (ot.kind == PrimitiveKind::UNIQUE_PTR) ? OK::Unique
                        : (ot.kind == PrimitiveKind::SHARED_PTR)
                            ? OK::Shared
                        : (ot.kind == PrimitiveKind::BORROW ||
                           ot.kind == PrimitiveKind::BORROW_MUT)
                            ? OK::Reborrow
                            : OK::Plain;
        bf.line = e->loc.line;
        if (e->args[0]->kind == ast::NodeKind::IdentExpr)
            bf.owner_name =
                static_cast<ast::IdentExpr *>(e->args[0].get())->name;
        fn_->borrow_facts.push_back(std::move(bf));
    };
    // Si el owner es unique<T>/shared<T>, equivale a ptr_of(owner)
    // que carga slot+0.  Si es una variable plain, devolvemos
    // &owner (su SSA value, que ya tiene is_host_ptr correcto
    // gracias al pre-pase de address-taken promotion: cualquier
    // local cuya direccion se toma con @c & se promociona a slot
    // estable en stack en lugar de vivir solo en un SSA value).
    const Type owner_t = e->args[0]->result_type;
    // F3 reborrow: si el arg ES un borrow/borrow_mut (var o param),
    // su SSA value YA ES el host_ptr al payload.  No queremos
    // emitir LOAD via read_local (eso es para slots de unique).
    // Bypass: usar lookup directamente cuando el arg es un
    // IdentExpr cuyo tipo es borrow.
    if (e->args[0]->kind == ast::NodeKind::IdentExpr &&
        (owner_t.kind == PrimitiveKind::BORROW ||
         owner_t.kind == PrimitiveKind::BORROW_MUT)) {
        auto *id = static_cast<ast::IdentExpr *>(e->args[0].get());
        const ir::IrValueId v = lookup(id->name);
        if (v != ir::IR_NO_VALUE) {
            // El borrow_var ya es host_ptr; lo devolvemos tal cual.
            // (read_borrow/write_borrow lo usaran con movh.)
            anota_prestamo(v, v); // represtamo: el owner ES otro prestamo
            out_value = v;
            return true;
        }
    }
    // Owner plain (i32, i64, etc.): si es un IdentExpr de variable
    // address-taken, el SSA value del scope es la DIRECCION del
    // ALLOCA (no el valor).  Hacer lower_expr pasaria por lower_ident
    // que para address-taken locals emite un LOAD i32 (devuelve el
    // VALOR), corrompiendo read_borrow/write_borrow posteriores.
    // Bypass: lookup directo cuando el arg es IdentExpr y la var
    // esta address-taken (lo cual el scan_address_taken garantiza
    // que sea verdad para `lend(local)` en owner plain).
    if (e->args[0]->kind == ast::NodeKind::IdentExpr) {
        auto *id = static_cast<ast::IdentExpr *>(e->args[0].get());
        if (address_taken_locals_.count(id->name)) {
            const ir::IrValueId v = lookup(id->name);
            if (v != ir::IR_NO_VALUE) {
                // v es PTR al slot del local.  Marcamos is_host_ptr
                // (es un slot vm-mem en stack, pero la convencion
                // para borrows es host_ptr; read_borrow/write_borrow
                // emiten LOAD/STORE indirecto con movh sobre este).
                // En realidad el slot vive en vm_mem (ALLOCA),
                // asi que NO marcamos is_host_ptr aqui: los LOAD/
                // STORE de read/write_borrow ya consultan eso del
                // SSA value y emiten mov (no movh) si es slot VM.
                anota_prestamo(v, v);
                out_value = v;
                return true;
            }
        }
    }
    const ir::IrValueId v_arg = lower_expr(e->args[0].get());
    if (v_arg == ir::IR_NO_VALUE) {
        out_value = ir::IR_NO_VALUE;
        return true;
    }
    if (owner_t.kind == PrimitiveKind::UNIQUE_PTR ||
        owner_t.kind == PrimitiveKind::SHARED_PTR) {
        // LOAD slot+0 (para unique) o ctrl+16 (shared payload).
        const ir::IrValueId v_ptr = emit_load_host_ptr(v_arg, e->loc.line);
        if (owner_t.kind == PrimitiveKind::SHARED_PTR) {
            // Para shared, sumar 16 (offset del payload inline en
            // ctrl_block: refcount@0 + deleter@8 + payload@16).
            const ir::IrValueId v_sixteen =
                emit_const(ir::IrType::I64, 16, e->loc.line);
            const ir::IrValueId v_pay =
                emit_ptr_add(v_ptr, v_sixteen, e->loc.line);
            anota_prestamo(v_pay, v_arg);
            out_value = v_pay;
            return true;
        }
        anota_prestamo(v_ptr, v_arg);
        out_value = v_ptr;
        return true;
    }
    // owner plain: el SSA value ya es la direccion (address-taken).
    // Lo devolvemos tal cual.
    anota_prestamo(v_arg, v_arg);
    out_value = v_arg;
    return true;
    return true;
}

} // namespace vx
