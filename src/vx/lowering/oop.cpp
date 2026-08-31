/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/oop.cpp
 * @brief Bajada de la orientacion a objetos: clases, structs con metodos, el
 *        arranque del modulo y la llamada a un metodo.
 *
 * En Vesta las clases NO son metadatos del binario: se CONSTRUYEN al arrancar.
 * El compilador emite una funcion de arranque -- @c __module_init -- que llama
 * a las instrucciones que definen clase, campos y metodos, y solo despues corre
 * @c main.  Eso es lo que hace que una clase declarada en el fuente, una creada
 * desde el propio programa y una que llega de otro modulo sean lo mismo, y que
 * la reflexion no cueste nada aparte.
 *
 * Aqui vive ese camino entero:
 *
 *   - los metodos de una clase y los de un struct, bajados a funciones;
 *   - los ayudantes de construccion (@c __new_X) que reservan el objeto y
 *     llaman al constructor;
 *   - la funcion de arranque del modulo;
 *   - la llamada a un metodo, con lo que decide si va por la tabla virtual o
 *     directa.
 *
 * Estaban repartidas por lowering.cpp; son el mismo tema y se leen juntas.
 */
#include "vx/lowering.h"
#include "ir/ir_optimizer.h"
#include "loader/oop_types.h"
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {

void Lowering::lower_class_methods(ast::ClassDecl *cd, ir::IrModule &out) {
    // Para cada metodo / constructor de la clase, generamos una
    // IrFunction con nombre <Class>__<method> y un primer parametro
    // implicito 'this' de tipo PTR.  Reusamos la maquinaria del
    // lowering normal: preparamos param_bindings, scope, address-taken
    // pre-pase y bajamos el body con lower_block.
    //
    // Las interfaces se omiten: sus metodos son abstractos (sin body)
    // y solo aportan la metadata de la firma para validacion.
    if (cd->is_interface) return;
    // Templates genericos (con type_params) y especializaciones (#7) se
    // omiten: sus monomorphizaciones concretas (que SI aparecen en
    // mod_.decls) se procesan normalmente.
    if (!cd->type_params.empty() || cd->is_specialization) return;
    for (auto &m_uptr : cd->methods) {
        auto *m = m_uptr.get();
        if (!m || !m->body) continue;
        // Metodo generico template (`R metodo<U>(...)`, #4): se omite.  Sus
        // monomorphizaciones concretas (`metodo_<U>`) tambien estan en
        // cd->methods (anyadidas por drain_pending_method_monos) y se bajan
        // normalmente en este mismo bucle.
        if (!m->method_type_params.empty()) continue;

        ir::IrFunction fn;
        // Mangling: ClassName__methodName; constructor usa "ctor".
        std::string suffix = m->is_constructor ? std::string("ctor") : m->name;
        fn.name = cd->name + "__" + suffix;

        // @complexity del metodo al IR, igual que en una funcion libre (ver
        // lower_function): metadata pura que solo consume el analizador.
        fn.complexity_expr = m->complexity_expr;
        fn.complexity_vars = m->complexity_vars;
        fn.complexity_partial_pre = m->complexity_partial_pre;
        fn.complexity_partial_post = m->complexity_partial_post;
        fn.complexity_total_pre = m->complexity_total_pre;
        fn.complexity_total_post = m->complexity_total_post;

        // Tipo de retorno + detect SRET (Result/Optional).  Para class
        // methods retornando Result/Optional cross-module, el callee
        // necesita retbuf hidden como SEGUNDO param (this=r1, retbuf=r2,
        // args=r3..).  Sin esto el callee alocaba retbuf en su propio
        // stack y devolvia el ptr via R0 -> use-after-free post-leave.
        Type sem_ret_m = Type{PrimitiveKind::VOID};
        if (m->return_type)
            sem_ret_m = tc_.resolve_type_node(m->return_type.get());
        // Y el STRUCT por valor, que arrastraba EXACTAMENTE el use-after-free
        // que describe el comentario de arriba: era el unico agregado sin SRET.
        // Un enum (STRUCT con enum_layout) y un `@overlay struct` (que ES un
        // puntero de 8 bytes) van por registro y no entran.
        const StructLayout *m_ret_slay = nullptr;
        if (sem_ret_m.kind == PrimitiveKind::STRUCT &&
            !sem_ret_m.struct_name.empty() &&
            tc_.find_enum_layout(sem_ret_m.struct_name) == nullptr) {
            auto it_ms = tc_.struct_layouts().find(sem_ret_m.struct_name);
            if (it_ms != tc_.struct_layouts().end() &&
                !it_ms->second.is_overlay)
                m_ret_slay = &it_ms->second;
        }
        /* Si hace falta buffer, cuanto mide y donde vive: lo contesta el mismo
         * sitio que para una funcion suelta y que para quien llama.  Aqui
         * estaba contestado aparte y con CUATRO casos de los siete: faltaban
         * el enum, el lambda y el puntero inteligente, asi que un metodo que
         * devolvia uno de esos no declaraba el buffer, devolvia un puntero a
         * su propio marco -- muerto tras el `ret` -- y quien llamaba leia lo
         * que hubiera pasado por esa pila.  Un constructor nunca lleva buffer:
         * no devuelve nada. */
        const SretInfo msi =
            m->is_constructor ? SretInfo{} : sret_info(sem_ret_m);
        const bool method_sret = msi.uses_buffer;
        if (m->is_constructor) {
            fn.ret_type = ir::IrType::VOID;
        } else if (method_sret) {
            fn.ret_type = ir::IrType::VOID;
        } else if (m->return_type &&
                   m->return_type->kind == ast::NodeKind::PrimitiveTypeNode) {
            auto *pt =
                static_cast<ast::PrimitiveTypeNode *>(m->return_type.get());
            fn.ret_type = ir_type_from_primitive(pt->prim);
        } else if (m->return_type) {
            fn.ret_type = (sem_ret_m.kind != PrimitiveKind::COUNT &&
                           sem_ret_m.kind != PrimitiveKind::VOID)
                              ? ir_type_from_primitive(sem_ret_m.kind)
                              : ir::IrType::VOID;
        } else {
            fn.ret_type = ir::IrType::VOID;
        }

        // Param 0: 'this' como PTR.  Sin contar en m->params.
        // Bug fix 2026-05-23: metodos estaticos NO tienen 'this' implicito.
        std::vector<std::pair<std::string, ir::IrValueId>> bindings;
        ir::IrValueId this_vid = ir::IR_NO_VALUE;
        if (!m->is_static) {
            this_vid = fn.new_value(ir::IrType::PTR, "%this");
            fn.values[this_vid].is_param = true;
            // fix - this es siempre un host_ptr a un objeto GC; debe
            // ser refrescado tras cualquier CALL que pueda disparar GC.
            fn.values[this_vid].is_host_ptr = true;
            fn.values[this_vid].is_gc_object = true;
            fn.params.push_back(this_vid);
            bindings.emplace_back("this", this_vid);
        }

        // SRET retbuf: param hidden tras `this` para methods que
        // retornan Result/Optional.  CALLVIRT debe marshalear retbuf
        // a r2 y args a r3..r(N+2).
        ir::IrValueId v_method_retbuf = ir::IR_NO_VALUE;
        if (method_sret) {
            v_method_retbuf = fn.new_value(ir::IrType::PTR, "%__retbuf");
            fn.values[v_method_retbuf].is_param = true;
            // BugFix sret-cross-mem (2026-06-04): metodos de clase con
            // SRET tambien reciben retbuf como host_ptr (caller hace
            // ALLOCA en host memory).  Sin esta marca el callee escribe
            // al retbuf con `mov` (VM mem) en lugar de `movh` (host)
            // -> el Result llega siempre en ceros al caller.  Caso
            // observado: file_io.FileReader.read_all retornaba con
            // tag=0, error=0 aunque el archivo se hubiera leido OK.
            fn.values[v_method_retbuf].is_host_ptr = msi.host_buffer;
            fn.params.push_back(v_method_retbuf);
        }

        // Resto de parametros declarados.
        declare_params(fn, m->params, bindings, /*reserved_slots=*/1);

        // Configurar contexto del lowering para esta funcion.
        const ir::IrBlockId entry = fn.new_block("entry");
        fn_ = &fn;
        current_block_ = entry;
        block_terminated_ = false;
        scopes_.clear();
        push_scope();
        for (auto &kv : bindings)
            bind(kv.first, kv.second);

        // Pre-pase de address-taken para variables locales del cuerpo.
        address_taken_locals_.clear();
        host_bearing_locals_.clear();
        // fix.cleanup-leak - limpiar el stack de cleanups entre
        // metodos de clase.  Sin esto, si un metodo anterior (e.g. el
        // ctor o un metodo previo) dejo cleanups colgados, el siguiente
        // metodo los hereda y al hacer `return` los ejecuta sobre
        // valores SSA que no le pertenecen, generando CALLVIRT a la
        // dtor con `this` apuntando a un i32 arbitrario -> crash.
        cleanup_stack_.clear();
        const_str_locals_.clear();
        escaping_locals_.clear();
        try_spill_slots_.clear();
        scan_address_taken(m->body.get());
        // fix5 - escape detection tambien para metodos de clase.
        // Sin esto, vars locales que escapan via `this.field = local`
        // (ej. `this.head = n` en LinkedList.prepend) NO se marcaban
        // como escaping y mi cleanup RAW_ASM las dropeaba al exit del
        // metodo, dejando `this.field` con un handle invalido.
        scan_escaping_locals(m->body.get());
        // fix9 - eliminado el pre-pase scan_loops del metodo.
        // Las flags solo se usaban para decidir si activar cleanup
        // RAW_ASM (eliminado tras fix8 stack scanning).  Reset
        // a false explicito por consistencia con lower_function.
        current_fn_has_loops_ = false;
        current_fn_has_try_ = false;

        // Marcar que estamos dentro del lowering de un metodo de clase
        // (el resto del lowering puede consultar current_class_lowering_
        // para saber a que ClassLayout pertenece 'this').
        const std::string saved_class = current_class_lowering_;
        current_class_lowering_ = cd->name;

        // Bug fix 2026-05-23 (Audit 14): metodos con return type STRING
        // necesitan auto-promotion de string literals a StringObject en
        // `return "lit"`.  Sin propagar `current_fn_returns_string_` aqui,
        // `lower_return` solo veia el flag para funciones top-level y
        // emitia `mov r0, @Absolute(s_N)` (ptr crudo) en metodos -> el
        // caller recibia un ptr raw como GcHandle -> str_equals/strraw
        // sobre garbage.  Reset al salir del metodo.
        const bool saved_returns_str = current_fn_returns_string_;
        {
            bool is_string_ret = false;
            if (m->return_type &&
                m->return_type->kind == ast::NodeKind::PrimitiveTypeNode) {
                auto *ptn =
                    static_cast<ast::PrimitiveTypeNode *>(m->return_type.get());
                is_string_ret = (ptn->prim == PrimitiveKind::STRING);
            } else if (m->return_type) {
                const Type sem = tc_.resolve_type_node(m->return_type.get());
                is_string_ret = (sem.kind == PrimitiveKind::STRING);
            }
            current_fn_returns_string_ = is_string_ret;
        }

        // Instrumentacion: vx_trace:enter al inicio del metodo
        // (igual filtro que en lower_function -- saltamos solo helpers
        // sinteticos; los ctors/dtors/metodos normales se instrumentan).
        if (instrument_mode_ != "none" && instrument_mode_ != "" &&
            fn.name != "__module_init" && fn.name.rfind("__new_", 0) != 0 &&
            fn.name.rfind("__async_", 0) != 0 &&
            fn.name.rfind("__lambda_", 0) != 0 &&
            fn.name.rfind("__spawn_", 0) != 0) {
            emit_instrument_enter(fn.name, m->loc.line);
        }

        // SRET context para metodos retornando Result/Optional.
        // `lower_return` consulta @c sret_active_ para copiar el slot al
        // retbuf en vez de devolver ptr via R0.
        const bool saved_sret_active = sret_active_;
        ir::IrValueId saved_sret_retbuf = sret_retbuf_;
        uint64_t saved_sret_buf_size = sret_buf_size_;
        // native_poo_ string SRET (mismo tratamiento que structs/funciones):
        // construir el value-string real en el `return`.
        const bool saved_sret_str_value_c = current_fn_sret_str_value_;
        // SIEMPRE fijar segun ESTE metodo (ver nota en lower_struct_methods):
        // un metodo no-string debe tener el flag en false aunque un metodo
        // string previo lo dejara true, o su `return <cte>` se compilaria como
        // copia value-string de 24 bytes -> deref invalido en AOT.
        current_fn_sret_str_value_ =
            (native_poo_ && sem_ret_m.kind == PrimitiveKind::STRING);
        sret_active_ = method_sret;
        sret_retbuf_ = method_sret ? v_method_retbuf : ir::IR_NO_VALUE;
        // El tamano manda la copia al retbuf (palabra a palabra) de cada
        // `return`, y es el MISMO que reserva quien llama.
        sret_buf_size_ = msi.bytes;

        lower_block(m->body.get());

        // Restaurar SIEMPRE (se fijaron incondicionalmente arriba).
        sret_active_ = saved_sret_active;
        sret_retbuf_ = saved_sret_retbuf;
        sret_buf_size_ = saved_sret_buf_size;
        current_fn_sret_str_value_ = saved_sret_str_value_c;

        current_class_lowering_ = saved_class;
        current_fn_returns_string_ = saved_returns_str;

        // augmentacion automatica del destructor: si este metodo
        // es @c is_destructor, antes del cierre invocamos los dtors de
        // todos los fields destructibles (CLASS con has_destructor o
        // has_destructible_field).  Esto implementa RAII recursivo: el
        // dtor del contenedor libera la cadena ownerships sin que el
        // usuario tenga que escribir el codigo manualmente.
        //
        // Orden: campos en orden de declaracion (no inverso) por
        // simplicidad.  Para clases con ciclos (LinkedList -> Node ->
        // Node ...), el primer @c null encontrado corta la cadena
        // gracias al if (field != null) check.
        //
        // El check de null se hace via cmp_eq + br_cond.  Sin esto,
        // CALLVIRT a un puntero null crashea con NPE.
        if (m->is_destructor && !block_terminated_) {
            auto it_lay = tc_.class_layouts().find(cd->name);
            if (it_lay != tc_.class_layouts().end()) {
                const ClassLayout &lay = it_lay->second;
                for (const auto &f : lay.fields) {
                    // Campo FUNCTION (lambda): el campo guarda un PTR a un slot
                    // HEAP de 16 bytes {fn,env} (RAW_ALLOC owned por el campo).
                    // Liberamos el env (si tiene capturas) y el slot -- RAII
                    // puro, sin GC.  Ver doc/VMdoc/Vesta/ClosuresEnCampos.md.
                    if (f.type.kind == PrimitiveKind::FUNCTION &&
                        !f.type.fn_is_raw) {
                        emit_free_closure_env_field(this_vid, f.offset,
                                                    m->loc.line);
                        continue;
                    }
                    // Campo unique<T> (ownership): liberar el inner via el
                    // deleter del slot (default free o custom).  El dtor del
                    // contenedor es el unico dueno -> un solo free.
                    if (f.type.kind == PrimitiveKind::UNIQUE_PTR) {
                        // Quien libera lo dice el TIPO del campo.
                        emit_free_unique_field(this_vid, f.offset,
                                               f.type.deleter_name,
                                               m->loc.line);
                        continue;
                    }
                    // Campo shared<T> (H5): decrementar el refcount del bloque
                    // de control; si cae a 0, liberarlo (free-when-0).  El
                    // campo guarda el host_ptr al ctrl; el dec lee
                    // [this+offset].  No-op si el campo es 0 (nunca asignado /
                    // movido).
                    if (f.type.kind == PrimitiveKind::SHARED_PTR) {
                        const ir::IrValueId saddr =
                            emit_field_addr(fn_, current_block_, this_vid,
                                            f.offset, m->loc.line);
                        emit_shared_refcount_dec(saddr, m->loc.line);
                        continue;
                    }
                    // Campo STRUCT inline destructible (Fase 2b
                    // clase-contenedor): el valor del campo ES su direccion
                    // (this + offset), no un puntero.  Despachamos su dtor con
                    // CALL directo <Struct>____dtor(addr) -- value-type, sin
                    // null-check, sin LOAD, identico interp/JIT/AOT
                    // (PURE_NATIVE).
                    if (f.type.kind == PrimitiveKind::STRUCT) {
                        auto it_sl =
                            tc_.struct_layouts().find(f.type.struct_name);
                        if (it_sl == tc_.struct_layouts().end()) continue;
                        bool sdestr = it_sl->second.has_destructible_field;
                        if (!sdestr)
                            for (const auto &im : it_sl->second.methods)
                                if (im.is_destructor) {
                                    sdestr = true;
                                    break;
                                }
                        if (!sdestr) continue;
                        const ir::IrValueId saddr =
                            emit_field_addr(fn_, current_block_, this_vid,
                                            f.offset, m->loc.line);
                        // El campo struct vive en el payload HOST de la clase;
                        // su dtor (compilado con this=VM en interp/JIT) leeria
                        // this.campo con `mov` sobre una direccion host ->
                        // basura
                        // -> free de basura (fuga).  El helper copia el campo a
                        // un temp VM y llama el dtor sobre el temp.
                        emit_struct_method_on_host_field(
                            saddr, f.type.struct_name,
                            f.type.struct_name + "__" + "__dtor", m->loc.line);
                        continue;
                    }
                    if (f.type.kind != PrimitiveKind::CLASS) continue;
                    auto it_inner =
                        tc_.class_layouts().find(f.type.struct_name);
                    if (it_inner == tc_.class_layouts().end()) continue;
                    const ClassLayout &inner = it_inner->second;
                    if (!inner.has_destructor) continue;
                    // Localizar vtable_index del dtor del inner + su nombre IR
                    // directo (<owner>__<dtor>) para CALL directo en
                    // native_poo.
                    uint32_t inner_dtor_idx = UINT32_MAX;
                    std::string inner_dtor_name;
                    for (const auto &im : inner.methods) {
                        if (im.is_destructor) {
                            inner_dtor_idx = im.vtable_index;
                            const std::string owner = im.defining_class.empty()
                                                          ? f.type.struct_name
                                                          : im.defining_class;
                            inner_dtor_name = owner + "__" + im.name;
                            break;
                        }
                    }
                    if (inner_dtor_idx == UINT32_MAX) continue;
                    // El field tiene tipo ESTATICO conocido -> en native_poo,
                    // si el de dentro NO es polimorfico, despachar el dtor con
                    // CALL directo (PURE_NATIVE) en vez de CALLVIRT, que el
                    // selector nativo no atiende.
                    const bool inner_dtor_direct =
                        native_poo_ && !class_has_vtable(f.type.struct_name) &&
                        !inner_dtor_name.empty();

                    // 1) addr = this + offset
                    const ir::IrValueId addr = emit_field_addr(
                        fn_, current_block_, this_vid, f.offset, m->loc.line);
                    // 2) handle = LOAD i64 addr (handle al inner obj
                    //    almacenado por @c lower_class_field_store).
                    const ir::IrValueId v_handle =
                        fn_->new_value(ir::IrType::I64);
                    ir::IrInstr ld{};
                    ld.op = ir::IrOp::LOAD;
                    ld.type = ir::IrType::I64;
                    ld.dst = v_handle;
                    ld.operands = {addr};
                    ld.source_line = m->loc.line;
                    emit(current_block_, std::move(ld));
                    // raw_asm-elim 2026-05-28: 2b) host_ptr fresco via
                    // IrOp::GC_DEREF_HOST.
                    const ir::IrValueId field_val =
                        fn_->new_value(ir::IrType::I64);
                    fn_->values[field_val].is_host_ptr = true;
                    fn_->values[field_val].is_gc_object = true;
                    ir::IrInstr deref{};
                    deref.op = ir::IrOp::GC_DEREF_HOST;
                    deref.type = ir::IrType::PTR;
                    deref.dst = field_val;
                    deref.operands = {v_handle};
                    deref.source_line = m->loc.line;
                    emit(current_block_, std::move(deref));
                    // 3) is_null = (field_val == 0)
                    const ir::IrValueId zero =
                        emit_const(ir::IrType::I64, 0, m->loc.line);
                    const ir::IrValueId is_null =
                        fn_->new_value(ir::IrType::BOOL);
                    ir::IrInstr cmp{};
                    cmp.op = ir::IrOp::CMP_EQ;
                    cmp.type = ir::IrType::BOOL;
                    cmp.dst = is_null;
                    cmp.operands = {field_val, zero};
                    cmp.source_line = m->loc.line;
                    emit(current_block_, std::move(cmp));
                    // 4) br_cond is_null skip do_dtor
                    const ir::IrBlockId do_bb = fn_->new_block("dtor_field");
                    const ir::IrBlockId skip_bb = fn_->new_block("dtor_skip");
                    // true (null) -> saltar; false -> llamar al destructor.
                    emit_br_cond(is_null, skip_bb, do_bb, m->loc.line);
                    // 5) do_bb: dtor del field; br skip.  CALL directo en
                    //    native_poo no-polimorfico; CALLVIRT en otro caso.
                    current_block_ = do_bb;
                    ir::IrInstr cv{};
                    if (inner_dtor_direct) {
                        cv.op = ir::IrOp::CALL;
                        cv.func_name = inner_dtor_name; // <Class>____dtor
                    } else {
                        cv.op = ir::IrOp::CALLVIRT;
                        cv.imm = static_cast<uint64_t>(inner_dtor_idx);
                    }
                    cv.type = ir::IrType::VOID;
                    cv.dst = ir::IR_NO_VALUE;
                    cv.operands = {field_val};
                    cv.source_line = m->loc.line;
                    emit(current_block_, std::move(cv));
                    emit_br(skip_bb, m->loc.line);
                    // 6) merge en skip_bb -> continuar con el siguiente field.
                    current_block_ = skip_bb;
                    block_terminated_ = false;
                }

                /* Y por ultimo el destructor de la SUPERCLASE.  Un destructor
                 * es un metodo mas de la tabla, asi que el de una derivada
                 * SUSTITUYE al heredado; sin esto, lo que la base liberaba --
                 * un fichero abierto, memoria cruda -- se quedaba sin liberar
                 * en cuanto la derivada declaraba el suyo, y sin decir nada.
                 *
                 * Va DESPUES del cuerpo y de los campos: primero se deshace lo
                 * que anadio la derivada y luego lo de la base, que es el orden
                 * inverso al de construccion.
                 *
                 * La llamada es DIRECTA, nunca por la tabla: por la tabla se
                 * volveria a encontrar el de la derivada -- que es el que la
                 * sustituyo -- y el destructor se llamaria a si mismo sin fin.
                 * Encadenar de nivel en nivel sale solo: el de la base hace lo
                 * mismo con la suya. */
                if (!lay.super_name.empty()) {
                    auto it_sup = tc_.class_layouts().find(lay.super_name);
                    if (it_sup != tc_.class_layouts().end()) {
                        const ClassMethodInfo *sup_dtor = nullptr;
                        for (const auto &sm : it_sup->second.methods)
                            if (sm.is_destructor) {
                                sup_dtor = &sm;
                                break;
                            }
                        /* Solo si el destructor de la base es OTRO: si la
                         * derivada no declaro el suyo, la ficha heredada ES la
                         * misma y llamarla seria repetirla. */
                        if (sup_dtor != nullptr &&
                            sup_dtor->defining_class != cd->name) {
                            const std::string owner =
                                sup_dtor->defining_class.empty()
                                    ? lay.super_name
                                    : sup_dtor->defining_class;
                            ir::IrInstr sc{};
                            sc.op = ir::IrOp::CALL;
                            sc.func_name = owner + "__" + sup_dtor->name;
                            sc.type = ir::IrType::VOID;
                            sc.dst = ir::IR_NO_VALUE;
                            sc.operands = {this_vid};
                            sc.source_line = m->loc.line;
                            emit(current_block_, std::move(sc));
                        }
                    }
                }
            }
        }

        // Cierre: anadir RET por defecto si el body no termino con uno.
        if (!block_terminated_) {
            // Instrumentacion: vx_trace:leave antes del RET implicito.
            if (instrument_mode_ != "none" && instrument_mode_ != "" &&
                fn.name != "__module_init" && fn.name.rfind("__new_", 0) != 0 &&
                fn.name.rfind("__async_", 0) != 0 &&
                fn.name.rfind("__lambda_", 0) != 0 &&
                fn.name.rfind("__spawn_", 0) != 0) {
                emit_instrument_exit(fn.name, ir::IR_NO_VALUE, m->loc.line);
            }
            ir::IrInstr ret{};
            ret.op = ir::IrOp::RET;
            ret.type = fn.ret_type;
            if (fn.ret_type != ir::IrType::VOID) {
                const ir::IrValueId zero =
                    emit_const(fn.ret_type, 0, m->loc.line);
                ret.operands.push_back(zero);
            }
            ret.source_line = m->loc.line;
            fn.append(current_block_, std::move(ret));
            block_terminated_ = true;
        }

        pop_scope();
        propagate_is_gc_object_through_phis(fn);

        // B.3 contract: si la clase es una instanciacion generica
        // (e.g., `Box_i32` viene de `class Box<T>`), marcar la
        // IrFunction con el template + type args legibles.  Util
        // para C2 / AOT (dedup de specializations) y para tools
        // (mostrar "Box<i32>::get" en stack traces vs "Box_i32__get").
        if (const auto *mi = tc_.monomorph_info(cd->name)) {
            fn.generic_template_name = mi->template_name;
            fn.generic_type_args = mi->type_args;
        }

        // Se deja constancia de que declaracion produjo este simbolo, AQUI, que
        // es donde el nombre queda fijado.  Reconstruirlo despues obligaria a
        // replicar el mangling, y esa copia se queda atras en cuanto cambie: un
        // constructor no es `Clase__nombre` sino `Clase__ctor`, y quien lo
        // adivinara desde fuera dejaria justo esos sin ligar sin decir nada.
        note_emitted_symbol(fn.name, cd->name, m->name);
        out.add_function(std::move(fn));
        fn_ = nullptr;
    }
}

void Lowering::generate_new_helpers(ir::IrModule &out) {
    // Para cada clase declarada en el modulo, generamos una funcion
    // __new_<Class>(arg1, ..., argN) -> handle (GcHandle).  El cuerpo
    // es RAW_ASM que hace findclass + newobj + callvirt al ctor.
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::ClassDecl) continue;
        auto *cd = static_cast<ast::ClassDecl *>(decl.get());
        // No se genera helper para interfaces: no son instanciables.
        if (cd->is_interface) continue;
        // Templates genericos y especializaciones (#7): no instanciables tal
        // cual; solo sus monomorphizaciones concretas.
        if (!cd->type_params.empty() || cd->is_specialization) continue;
        auto it = tc_.class_layouts().find(cd->name);
        if (it == tc_.class_layouts().end()) continue;
        const ClassLayout &lay = it->second;

        // Localizar el constructor PROPIO (no heredado del super).
        // BugFix R1: si la clase deriva de un Base con ctor, los
        // methods incluyen Base.__ctor copiado al inicio (inherited).
        // Sin priorizar el ctor cuyo defining_class == cd->name, el
        // helper __new_<Derived> usaria los params del Base.__ctor
        // -> faltarian args en la llamada -> los campos propios del
        // Derived quedaban a 0.
        const ClassMethodInfo *ctor = nullptr;
        for (const auto &m : lay.methods) {
            if (m.is_constructor && m.defining_class == cd->name) {
                ctor = &m;
                break;
            }
        }
        // Fallback: si no hay ctor propio, usar el primero inherited.
        if (!ctor) {
            for (const auto &m : lay.methods) {
                if (m.is_constructor) {
                    ctor = &m;
                    break;
                }
            }
        }
        // fix12 - si el ctor es zero-init trivial (solo asigna
        // campos a 0/null/false), saltarlo: el `gc_heap.alloc` ya
        // memset el payload a 0.  Solo aplica si el ctor existe Y
        // no tiene argumentos (ctor con args debe correr para que
        // los argumentos lleguen a campos).
        const bool ctor_is_trivial_zero_init = ctor != nullptr &&
                                               ctor->is_zero_init_ctor &&
                                               ctor->param_types.empty();
        // Si el ctor es trivial zero-init, lo tratamos como si no existiera
        // (el helper omitira el callvirt y devolvera el objeto recien
        // alocado).  Esto ahorra ~9 instrucciones VM por `new` para POCs.
        const ClassMethodInfo *effective_ctor =
            ctor_is_trivial_zero_init ? nullptr : ctor;
        const size_t nargs =
            effective_ctor ? effective_ctor->ir_param_count() : 0;
        const uint32_t ctor_vtable_idx =
            effective_ctor ? effective_ctor->vtable_index : 0;

        // -------------------------------------------------------------
        //  AOT.2.b -- POO NATIVA: __new_<Class>(args) sin runtime.
        //   %obj = call calloc(1, size_bytes)   ; heap zero-init, host_ptr
        //   [si hay ctor efectivo:] call <Class>__ctor(%obj, args...)
        //   ret %obj
        // calloc zerifica (como hacia gc_heap.alloc) -> los campos no
        // inicializados por el ctor quedan a 0 sin garbage.  El ptr de
        // calloc ES el objeto (sin GcHandle, sin ObjectHeader header
        // logico -- los offsets de campo del layout se respetan tal cual).
        // El simbolo calloc es EXTERNO (lo resuelve el linker; overridable
        // por @AllocatorOverride en 2.d).  free pareado via RAII (cleanup).
        // -------------------------------------------------------------
        if (native_poo_) {
            // AOT.2.c: vtable estatica si la clase participa en una jerarquia
            // (tiene super o es extendida) -> dispatch virtual nativo.  La
            // vtable = blob en .rodata con sym_refs a <owner>__<metodo> por
            // vtable_index (mismo mecanismo que `dq func` del bloque bytes).
            bool needs_vtable = class_has_vtable(cd->name);
            uint64_t vtable_idx = UINT64_MAX;
            // Hoisted fuera del bloque needs_vtable: el DESCRIPTOR DE TIPO de
            // una clase gc<X> (ver mas abajo) reusa el numero de slots y la
            // tabla slot->simbolo aunque la clase no requiera vtable propia.
            uint32_t nslots = 0;
            std::map<uint32_t, std::string> slot_sym;
            if (needs_vtable) {
                /* Los metodos de la clase van DETRAS del tramo reservado a las
                 * interfaces.  Cada despacho numera por su cuenta -- la clase
                 * por su cadena de herencia, la interfaz por el orden en que
                 * declara los suyos --, y antes compartian tabla: los de
                 * interfaz se colocaban ENCIMA de los de la clase, dando por
                 * muerta la ranura del constructor.  Eso se cae de dos formas,
                 * las dos normales: si la clase no declara constructor, esa
                 * ranura la ocupa un metodo de verdad; y si la interfaz tiene
                 * mas de un metodo, el segundo cae sobre otro metodo de la
                 * clase aunque el constructor exista.  En los dos casos la
                 * llamada acababa en el metodo equivocado, sin aviso. */
                for (const auto &mi : lay.methods)
                    if (native_class_slot(mi.vtable_index) + 1u > nslots)
                        nslots = native_class_slot(mi.vtable_index) + 1u;
                struct IfaceSlot {
                    uint32_t slot;
                    std::string sym;
                };
                std::vector<IfaceSlot> iface_slots;
                // Recolectar las interfaces de la clase Y de TODA su cadena de
                // superclases.  Una clase que hereda (E : C, C : Sh) implementa
                // Sh transitivamente, pero su `interface_names` solo lista las
                // DIRECTAS -> sin esto, la vtable de E no colocaria el metodo
                // de Sh en su slot de interfaz y el dispatch dinamico leeria
                // basura (bug: s[1].a() sobre un E heredado daba garbage).
                /* Y de la cadena de las propias INTERFACES: una interfaz que
                 * extiende a otra obliga a quien la cumple a cumplir tambien la
                 * de arriba, y su padre no esta en su lista de interfaces sino
                 * en su superclase -- la promocion a esa lista solo ocurre
                 * cuando quien declara no es una interfaz --.  Sin cerrar por
                 * ahi, la tabla de la clase se quedaba sin los metodos de las
                 * interfaces intermedias y una llamada por el tipo de arriba
                 * leia una ranura vacia. */
                std::vector<std::string> all_ifaces;
                {
                    std::vector<std::string> pendientes;
                    std::string cur = cd->name;
                    int guard = 0;
                    while (!cur.empty() && guard++ < 64) {
                        auto itc = tc_.class_layouts().find(cur);
                        if (itc == tc_.class_layouts().end()) break;
                        for (const auto &in : itc->second.interface_names)
                            pendientes.push_back(in);
                        cur = itc->second.super_name;
                    }
                    // Cierre hacia arriba, sin repetir.
                    for (size_t k = 0; k < pendientes.size() && k < 256; ++k) {
                        const std::string n = pendientes[k];
                        if (std::find(all_ifaces.begin(), all_ifaces.end(),
                                      n) != all_ifaces.end())
                            continue;
                        all_ifaces.push_back(n);
                        auto itn = tc_.class_layouts().find(n);
                        if (itn == tc_.class_layouts().end()) continue;
                        if (!itn->second.super_name.empty())
                            pendientes.push_back(itn->second.super_name);
                        for (const auto &sup : itn->second.interface_names)
                            pendientes.push_back(sup);
                    }
                }
                for (const auto &iname : all_ifaces) {
                    auto it_if = tc_.class_layouts().find(iname);
                    if (it_if == tc_.class_layouts().end()) continue;
                    for (const auto &im : it_if->second.methods) {
                        if (im.is_constructor) continue;
                        // Buscar el metodo implementador en la clase y, si no
                        // esta (metodo heredado no aplanado), en la cadena de
                        // superclases.  owner = clase que DEFINE el metodo.
                        const ClassMethodInfo *impl = nullptr;
                        std::string impl_owner;
                        {
                            std::string cur = cd->name;
                            int guard = 0;
                            while (!cur.empty() && guard++ < 64 && !impl) {
                                auto itc = tc_.class_layouts().find(cur);
                                if (itc == tc_.class_layouts().end()) break;
                                for (const auto &cm : itc->second.methods)
                                    if (!cm.is_constructor &&
                                        cm.name == im.name) {
                                        impl = &cm;
                                        impl_owner = cm.defining_class.empty()
                                                         ? itc->second.name
                                                         : cm.defining_class;
                                        break;
                                    }
                                cur = itc->second.super_name;
                            }
                        }
                        if (!impl) continue;
                        const uint32_t slot =
                            native_iface_slot(iname, im.vtable_index);
                        iface_slots.push_back(
                            {slot, impl_owner + "__" + impl->name});
                        if (slot + 1u > nslots) nslots = slot + 1u;
                    }
                }
                if (nslots == 0) {
                    needs_vtable = false;
                } else {
                    std::vector<uint8_t> vt(static_cast<size_t>(nslots) * 8u,
                                            0);
                    vtable_idx = out.static_data.push_back(std::move(vt));
                    auto &vm = out.static_data.meta_at(vtable_idx);
                    // .data.rel.ro: seccion de la vtable (punteros absolutos
                    // a metodos -> relocs ABS64).  Es read-only TRAS la
                    // relocacion (RELRO), como las vtables de C++.  Evita el
                    // TEXTREL que daria .rodata con relocs.
                    vm.section_name = ".data.rel.ro";
                    vm.flags |= ir::IrModule::SD_FLAG_FORCE_EMIT |
                                ir::IrModule::SD_FLAG_NON_DEDUP;
                    // Un simbolo por ranura (desplazamiento).  Los tramos
                    // de la clase y de las interfaces son DISJUNTOS, asi que
                    // ya no hay colocacion que prime sobre otra y el orden en
                    // que se escriben da igual.
                    for (const auto &mi : lay.methods) {
                        const std::string owner = mi.defining_class.empty()
                                                      ? cd->name
                                                      : mi.defining_class;
                        slot_sym[native_class_slot(mi.vtable_index) * 8u] =
                            owner + "__" +
                            (mi.is_constructor ? std::string("ctor") : mi.name);
                    }
                    for (const auto &is : iface_slots)
                        slot_sym[is.slot * 8u] = is.sym;
                    for (const auto &kv : slot_sym) {
                        ir::IrModule::StaticDataMeta::SymRef sr;
                        sr.offset = kv.first;
                        sr.sym = kv.second;
                        sr.width = 8;
                        sr.is_rel = 0;
                        vm.sym_refs.push_back(std::move(sr));
                    }
                }
            }

            // -----------------------------------------------------------
            // DESCRIPTOR DE TIPO gc<X> (para la compactacion del GC en AOT).
            //
            // Solo las clases usadas como gc<Clase> (classes_used_gc_) llevan
            // descriptor: el GC (libvesta_gc) lo necesita para (a) trazar
            // preciso el interior de cada objeto y (b) reescribir sus punteros
            // internos al compactar (mover) el OldGen.  Las clases RAII
            // normales (no-GC) NO lo llevan -> cero coste en binarios sin
            // gc<T>.
            //
            // Layout del descriptor (blob en .data.rel.ro, referenciado por
            // obj[0]).  Cabecera fija de 32 bytes ANTES de la vtable para NO
            // romper el dispatch: obj[0] apunta a &descriptor + 32 = vtable[0],
            // asi [obj[0] + idx*8] sigue siendo la entrada idx de la vtable.
            //   [ -32 ]  field_map_ptr (8)  -> &field-map (o 0 si sin
            //   campos-ref) [ -24 ]  size_bytes    (8)  -> tamano del payload
            //   (compact/refl) [ -16 ]  dtor_ptr      (8)  -> 0 (reservado:
            //   unificacion futura) [  -8 ]  magic 'VXTD'  (4) + flags (4)  ->
            //   sanity del verificador [   0 ]  vtable[0], vtable[1], ...   <-
            //   obj[0] apunta AQUI
            // Field-map (blob en .rodata): [u32 count][u32 pad][u32 off]...
            // offN = offset de un campo-referencia gc<Y> desde obj[0] (incluye
            // el ObjectHeader de 24 bytes).  Solo se listan campos con
            // Type.gc_managed == true (NUNCA
            // unique/shared/raw/RAII/primitivos).
            uint64_t desc_idx = UINT64_MAX;
            if (classes_used_gc_.count(cd->name) > 0) {
                // 1. Field-map: recolectar offsets de campos-referencia gc.
                std::vector<uint32_t> gc_field_offsets;
                for (const auto &f : lay.fields)
                    if (f.type.gc_managed) gc_field_offsets.push_back(f.offset);
                uint64_t fmap_idx = UINT64_MAX;
                if (!gc_field_offsets.empty()) {
                    std::vector<uint8_t> fmap(8 + gc_field_offsets.size() * 4u,
                                              0);
                    const uint32_t cnt =
                        static_cast<uint32_t>(gc_field_offsets.size());
                    std::memcpy(fmap.data(), &cnt, 4); // count @0
                    // pad @4 = 0
                    for (size_t k = 0; k < gc_field_offsets.size(); ++k)
                        std::memcpy(fmap.data() + 8 + k * 4u,
                                    &gc_field_offsets[k], 4);
                    fmap_idx = out.static_data.push_back(std::move(fmap));
                    auto &fm = out.static_data.meta_at(fmap_idx);
                    fm.section_name = ".rodata";
                    fm.symbol_name = "__vx_fmap_" + cd->name;
                    fm.flags |= ir::IrModule::SD_FLAG_FORCE_EMIT |
                                ir::IrModule::SD_FLAG_NON_DEDUP;
                }
                // 2. Descriptor: cabecera 32B + vtable (copia de slot_sym).
                const uint32_t kHdr = 32;
                std::vector<uint8_t> desc(
                    kHdr + static_cast<size_t>(nslots) * 8u, 0);
                const uint64_t sz64 = lay.size_bytes;
                std::memcpy(desc.data() + 8, &sz64, 8);   // size @8
                const uint32_t magic = 0x44545856u;       // 'VXTD' LE
                std::memcpy(desc.data() + 24, &magic, 4); // magic @24
                desc_idx = out.static_data.push_back(std::move(desc));
                auto &dm = out.static_data.meta_at(desc_idx);
                dm.section_name = ".data.rel.ro";
                dm.symbol_name = "__vx_tdesc_" + cd->name;
                dm.flags |= ir::IrModule::SD_FLAG_FORCE_EMIT |
                            ir::IrModule::SD_FLAG_NON_DEDUP;
                if (fmap_idx != UINT64_MAX) {
                    ir::IrModule::StaticDataMeta::SymRef sr;
                    sr.offset = 0; // field_map_ptr @0
                    sr.sym = "__vx_fmap_" + cd->name;
                    sr.width = 8;
                    sr.is_rel = 0;
                    dm.sym_refs.push_back(std::move(sr));
                }
                // Vtable embebida en el descriptor (a partir de +32): copia de
                // los mismos simbolos que la vtable standalone.  Asi los
                // objetos gc despachan por esta vtable y el descriptor unifica
                // metadata + vtable en un solo blob que obj[0] localiza.
                for (const auto &kv : slot_sym) {
                    ir::IrModule::StaticDataMeta::SymRef sr;
                    sr.offset = kHdr + kv.first;
                    sr.sym = kv.second;
                    sr.width = 8;
                    sr.is_rel = 0;
                    dm.sym_refs.push_back(std::move(sr));
                }
            }

            ir::IrFunction nf;
            nf.name = "__new_" + cd->name;
            nf.ret_type = ir::IrType::PTR;
            for (size_t i = 0; i < nargs; ++i) {
                const ir::IrType pt =
                    ir_type_from_primitive(effective_ctor->param_types[i].kind);
                const ir::IrValueId vid =
                    nf.new_value(pt, "%a" + std::to_string(i));
                nf.values[vid].is_param = true;
                nf.params.push_back(vid);
            }
            const ir::IrBlockId e = nf.new_block("entry");
            // %n = 1 ; %sz = size_bytes
            const ir::IrValueId v_n = nf.new_value(ir::IrType::I64);
            {
                ir::IrInstr c{};
                c.op = ir::IrOp::CONST;
                c.type = ir::IrType::I64;
                c.dst = v_n;
                c.imm = 1;
                c.source_line = cd->loc.line;
                nf.append(e, std::move(c));
            }
            const ir::IrValueId v_sz = nf.new_value(ir::IrType::I64);
            {
                ir::IrInstr c{};
                c.op = ir::IrOp::CONST;
                c.type = ir::IrType::I64;
                c.dst = v_sz;
                c.imm = lay.size_bytes;
                c.source_line = cd->loc.line;
                nf.append(e, std::move(c));
            }
            // %obj = call calloc(%n, %sz) -> host_ptr zero-init
            const ir::IrValueId v_obj = nf.new_value(ir::IrType::PTR);
            nf.values[v_obj].is_host_ptr = true;
            {
                ir::IrInstr ca{};
                ca.op = ir::IrOp::CALL;
                ca.type = ir::IrType::PTR;
                ca.dst = v_obj;
                ca.func_name = "calloc";
                ca.operands = {v_n, v_sz};
                ca.source_line = cd->loc.line;
                nf.append(e, std::move(ca));
            }
            // AOT.2.c: si la clase tiene vtable, guardar su direccion en
            // obj[0] (STORE &vtable, obj) -> el dispatch virtual la lee.
            if (needs_vtable && vtable_idx != UINT64_MAX) {
                ir::IrValueId v_vt = nf.new_value(ir::IrType::PTR);
                nf.values[v_vt].is_host_ptr = true;
                {
                    ir::IrInstr sa{};
                    sa.op = ir::IrOp::STR_LIT_ADDR;
                    sa.type = ir::IrType::PTR;
                    sa.dst = v_vt;
                    sa.imm = vtable_idx;
                    sa.source_line = cd->loc.line;
                    nf.append(e, std::move(sa));
                }
                {
                    ir::IrInstr st{};
                    st.op = ir::IrOp::STORE;
                    st.type = ir::IrType::I64;
                    st.operands = {v_vt, v_obj};
                    st.source_line = cd->loc.line;
                    nf.append(e, std::move(st));
                }
            }
            // [ctor] call <Class>__ctor(%obj, args...) -- CALL directo
            if (effective_ctor) {
                ir::IrInstr cc{};
                cc.op = ir::IrOp::CALL;
                cc.type = ir::IrType::VOID;
                cc.dst = ir::IR_NO_VALUE;
                cc.func_name = cd->name + "__ctor";
                cc.operands.reserve(nargs + 1);
                cc.operands.push_back(v_obj);
                for (size_t i = 0; i < nargs; ++i)
                    cc.operands.push_back(nf.params[i]);
                cc.source_line = cd->loc.line;
                nf.append(e, std::move(cc));
            }
            {
                ir::IrInstr r{};
                r.op = ir::IrOp::RET;
                r.type = ir::IrType::PTR;
                r.operands = {v_obj};
                r.source_line = cd->loc.line;
                nf.append(e, std::move(r));
            }
            out.add_function(std::move(nf));

            // gc<T> opt-in: si la clase se uso como gc<Class>, generar tambien
            // __new_<Class>_gc.  Identico al native (calloc+ctor) pero alocando
            // con vx_gc_alloc_ptr (GC-managed, no-RAII).  El GC (libvesta_gc)
            // colecta el objeto cuando deja de ser alcanzable via stackmaps.
            if (classes_used_gc_.count(cd->name) > 0) {
                ir::IrFunction gf;
                gf.name = "__new_" + cd->name + "_gc";
                gf.ret_type = ir::IrType::PTR;
                for (size_t i = 0; i < nargs; ++i) {
                    const ir::IrType pt = ir_type_from_primitive(
                        effective_ctor->param_types[i].kind);
                    const ir::IrValueId vid =
                        gf.new_value(pt, "%a" + std::to_string(i));
                    gf.values[vid].is_param = true;
                    gf.params.push_back(vid);
                }
                const ir::IrBlockId ge = gf.new_block("entry");
                // %sz = size_bytes
                const ir::IrValueId g_sz = gf.new_value(ir::IrType::I64);
                {
                    ir::IrInstr c{};
                    c.op = ir::IrOp::CONST;
                    c.type = ir::IrType::I64;
                    c.dst = g_sz;
                    c.imm = lay.size_bytes;
                    c.source_line = cd->loc.line;
                    gf.append(ge, std::move(c));
                }
                // %obj = call vx_gc_alloc_ptr(%sz)  (host_ptr al payload)
                const ir::IrValueId g_obj = gf.new_value(ir::IrType::PTR);
                gf.values[g_obj].is_host_ptr = true;
                gf.values[g_obj].is_gc_object = true;
                {
                    ir::IrInstr ca{};
                    ca.op = ir::IrOp::CALL;
                    ca.type = ir::IrType::PTR;
                    ca.dst = g_obj;
                    ca.func_name = "vx_gc_alloc_ptr";
                    ca.operands = {g_sz};
                    ca.source_line = cd->loc.line;
                    gf.append(ge, std::move(ca));
                }
                // obj[0] = &descriptor + 32 (= vtable[0]).  El descriptor
                // unifica field-map + metadata + vtable en un solo blob.  El
                // +32 salta la cabecera fija para que [obj[0] + idx*8] siga
                // siendo la entrada idx de la vtable (dispatch intacto); el GC
                // lee la metadata en [obj[0] - 32].  desc_idx SIEMPRE existe
                // para una clase gc (se construyo arriba), con o sin vtable.
                if (desc_idx != UINT64_MAX) {
                    ir::IrValueId g_db = gf.new_value(ir::IrType::PTR);
                    gf.values[g_db].is_host_ptr = true;
                    {
                        ir::IrInstr sa{};
                        sa.op = ir::IrOp::STR_LIT_ADDR;
                        sa.type = ir::IrType::PTR;
                        sa.dst = g_db;
                        sa.imm = desc_idx;
                        sa.source_line = cd->loc.line;
                        gf.append(ge, std::move(sa));
                    }
                    const ir::IrValueId g_k = gf.new_value(ir::IrType::I64);
                    {
                        ir::IrInstr c{};
                        c.op = ir::IrOp::CONST;
                        c.type = ir::IrType::I64;
                        c.dst = g_k;
                        c.imm = 32;
                        c.source_line = cd->loc.line;
                        gf.append(ge, std::move(c));
                    }
                    ir::IrValueId g_vt = gf.new_value(ir::IrType::PTR);
                    gf.values[g_vt].is_host_ptr = true;
                    {
                        ir::IrInstr ad{};
                        ad.op = ir::IrOp::ADD;
                        ad.type = ir::IrType::PTR;
                        ad.dst = g_vt;
                        ad.operands = {g_db, g_k};
                        ad.source_line = cd->loc.line;
                        gf.append(ge, std::move(ad));
                    }
                    {
                        ir::IrInstr st{};
                        st.op = ir::IrOp::STORE;
                        st.type = ir::IrType::I64;
                        st.operands = {g_vt, g_obj};
                        st.source_line = cd->loc.line;
                        gf.append(ge, std::move(st));
                    }
                }
                // ctor(obj, args...)
                if (effective_ctor) {
                    ir::IrInstr cc{};
                    cc.op = ir::IrOp::CALL;
                    cc.type = ir::IrType::VOID;
                    cc.dst = ir::IR_NO_VALUE;
                    cc.func_name = cd->name + "__ctor";
                    cc.operands.reserve(nargs + 1);
                    cc.operands.push_back(g_obj);
                    for (size_t i = 0; i < nargs; ++i)
                        cc.operands.push_back(gf.params[i]);
                    cc.source_line = cd->loc.line;
                    gf.append(ge, std::move(cc));
                }
                {
                    ir::IrInstr r{};
                    r.op = ir::IrOp::RET;
                    r.type = ir::IrType::PTR;
                    r.operands = {g_obj};
                    r.source_line = cd->loc.line;
                    gf.append(ge, std::move(r));
                }
                out.add_function(std::move(gf));
            }
            continue; // ruta nativa lista; saltar el path runtime de esta clase
        }

        // Registrar el nombre de la clase como datos estaticos.
        const uint64_t name_idx = intern_class_name(out, cd->name);
        const uint32_t name_len = static_cast<uint32_t>(cd->name.size());
        // fix11 - reservar slot de cache para ClassInfo*.
        const uint64_t cache_idx = intern_class_cache_slot(out, cd->name);
        (void)name_idx;
        (void)name_len; // ya no se usa findclass aqui

        //  Z.6: emitir TANTO el helper local (__new_<Class>) como,
        // si la clase se uso con `shared` en algun var-decl, su variante
        // shared (__new_<Class>_shared).  El cuerpo es identico salvo
        // que la instruccion `newobj r1` se reemplaza por `newobjs r1`
        // (aloca en SharedHeap).  Generar ambos en el mismo bucle ahorra
        // duplicar toda la logica de calculo de ctor / cache slot.
        const bool need_shared_variant =
            (classes_used_shared_.count(cd->name) > 0);
        const int n_variants = need_shared_variant ? 2 : 1;

        for (int variant = 0; variant < n_variants; ++variant) {
            const bool is_shared_variant = (variant == 1);

            // Construir IrFunction __new_<Class>[_shared].
            ir::IrFunction fn;
            fn.name = is_shared_variant ? ("__new_" + cd->name + "_shared")
                                        : ("__new_" + cd->name);
            fn.ret_type = ir::IrType::PTR;

            // Params: replicar tipos del ctor (si existe).  El ultimo puede ser
            // el contador oculto de un variadico, que no tiene declaracion.
            for (size_t i = 0; i < nargs; ++i) {
                const ir::IrType pt =
                    (i < ctor->param_types.size())
                        ? ir_type_from_primitive(ctor->param_types[i].kind)
                        : ir::IrType::I64;
                const ir::IrValueId vid =
                    fn.new_value(pt, "%a" + std::to_string(i));
                fn.values[vid].is_param = true;
                fn.params.push_back(vid);
            }

            const ir::IrBlockId entry = fn.new_block("entry");

            // raw_asm-elim Fase 1 (__new_X a IR): la variante LOCAL del helper
            // se construye con IR ops estructurados en vez de RAW_ASM textual,
            // para que el path vreg y el optimizer lo compilen sin el
            // mini-parser de raw_asm.  Patron equivalente al RAW_ASM del
            // bloque `else` de abajo:
            //   v_slot = STR_LIT_ADDR(cache_idx)   (@Absolute("code.s_N"))
            //   v_cls  = LOAD(v_slot)              (ClassInfo* cacheado,
            //   vm_mem) v_h    = NEWOBJ(v_cls)             (GcHandle, r0)
            //   v_this = GC_DEREF_HOST(v_h)        (host_ptr al ObjectHeader)
            //   --- si hay ctor efectivo: ---
            //   CALLVIRT(this=v_this, args=params, vtable_idx=ctor)
            //   v_ret  = GC_DEREF_HOST(v_h)        (RE-deref: el GC del ctor
            //                                       puede haber movido el obj)
            //   RET v_ret
            //   --- sin ctor: RET v_this (campos ya a 0 por gc_heap.alloc) ---
            // raw_asm-elim: la variante SHARED (__new_<X>_shared) tambien se
            // emite estructurada usando IrOp::NEWOBJS (newobjs -> SharedHeap)
            // en lugar de NEWOBJ.  Asi NINGUN __new_<X> queda en RAW_ASM.
            {
                // v_slot = direccion del slot ClassInfo* cacheado
                // (static_data).
                const ir::IrValueId v_slot = fn.new_value(ir::IrType::PTR);
                {
                    ir::IrInstr sa{};
                    sa.op = ir::IrOp::STR_LIT_ADDR;
                    sa.type = ir::IrType::PTR;
                    sa.dst = v_slot;
                    sa.imm = cache_idx;
                    sa.source_line = cd->loc.line;
                    fn.append(entry, std::move(sa));
                }
                // v_cls = LOAD(v_slot): ClassInfo* leido del slot (vm_mem).
                const ir::IrValueId v_cls = fn.new_value(ir::IrType::I64);
                {
                    ir::IrInstr ld{};
                    ld.op = ir::IrOp::LOAD;
                    ld.type = ir::IrType::I64;
                    ld.dst = v_cls;
                    ld.operands = {v_slot};
                    ld.source_line = cd->loc.line;
                    fn.append(entry, std::move(ld));
                }
                // v_h = NEWOBJ/NEWOBJS(v_cls): aloca el objeto -> GcHandle.  La
                // variante shared usa NEWOBJS (SharedHeap); el handle lleva el
                // bit 31 y GC_DEREF_HOST de abajo lo resuelve por el path
                // shared.
                const ir::IrValueId v_h = fn.new_value(ir::IrType::I64);
                {
                    ir::IrInstr no{};
                    no.op = is_shared_variant ? ir::IrOp::NEWOBJS
                                              : ir::IrOp::NEWOBJ;
                    no.type = ir::IrType::I64;
                    no.dst = v_h;
                    no.operands = {v_cls};
                    no.source_line = cd->loc.line;
                    fn.append(entry, std::move(no));
                }
                // v_this = GC_DEREF_HOST(v_h): host_ptr al ObjectHeader.
                const ir::IrValueId v_this = fn.new_value(ir::IrType::PTR);
                fn.values[v_this].is_host_ptr = true;
                fn.values[v_this].is_gc_object = true;
                {
                    ir::IrInstr ra{};
                    ra.op = ir::IrOp::GC_DEREF_HOST;
                    ra.type = ir::IrType::PTR;
                    ra.dst = v_this;
                    ra.operands = {v_h};
                    ra.source_line = cd->loc.line;
                    fn.append(entry, std::move(ra));
                }

                if (effective_ctor) {
                    // CALLVIRT(this=v_this, args=params del helper).  El ctor
                    // es void; argc = nargs + 1 (this + args).
                    //
                    // CLAVE: v_this (host_ptr GC) vive a traves del call (se
                    // usa en el RET de abajo).  El mecanismo de preservacion de
                    // GC roots lo convierte a handle ANTES del call y lo
                    // refresca a host_ptr DESPUES (save_live_regs
                    // gchandle/push/pop/gcderef en el interp; spill + stackmap
                    // del commit 6 en el vreg) -- exactamente lo que el RAW_ASM
                    // legacy hacia a mano.  Por eso NO re-derefamos ni marcamos
                    // el handle: marcar v_h (que YA es handle) como GC hacia
                    // que el interp le aplicara gchandle (host_ptr->handle)
                    // sobre un handle -> basura.
                    ir::IrInstr cv{};
                    cv.op = ir::IrOp::CALLVIRT;
                    cv.type = ir::IrType::VOID;
                    cv.dst = ir::IR_NO_VALUE;
                    cv.operands.reserve(nargs + 1);
                    cv.operands.push_back(v_this);
                    for (size_t i = 0; i < nargs; ++i) {
                        cv.operands.push_back(fn.params[i]);
                    }
                    cv.imm = static_cast<uint64_t>(ctor_vtable_idx);
                    cv.source_line = cd->loc.line;
                    fn.append(entry, std::move(cv));
                }

                // RET v_this (host_ptr al objeto; preservado/refrescado a
                // traves del callvirt si habia ctor).
                {
                    ir::IrInstr ret{};
                    ret.op = ir::IrOp::RET;
                    ret.type = ir::IrType::PTR;
                    ret.operands = {v_this};
                    ret.source_line = cd->loc.line;
                    fn.append(entry, std::move(ret));
                }
            }

            propagate_is_gc_object_through_phis(fn);

            // B.3 contract: el helper @c __new_<Class> tambien lleva
            // metadata de monomorphizacion cuando la clase es una
            // instanciacion generica.  Asi C2/AOT pueden agrupar todas
            // las funciones (metodos + helpers) de una specialization
            // como una unidad.
            if (const auto *mi = tc_.monomorph_info(cd->name)) {
                fn.generic_template_name = mi->template_name;
                fn.generic_type_args = mi->type_args;
            }

            // Bug fix 2026-05-23: registrar como helper PURO si el ctor
            // es trivial (sin callvirt al ctor user-defined).  Solo entonces
            // el DCE puede eliminar el __new_<X> cuando el handle no se usa.
            // Sin esto, ctors que pueden throw veian sus excepciones
            // swallow-eadas cuando el resultado del `new X()` no se usaba.
            if (!effective_ctor) {
                ir::register_pure_new_helper(fn.name);
            }
            out.add_function(std::move(fn));
        } // for variant in {local, shared}
    }
}

void Lowering::generate_module_init_function(ir::IrModule &out) {
    // Si no hay clases NI runtime globals que inicializar, no
    // generamos __module_init.
    bool any_class = false;
    for (auto &decl : mod_.decls) {
        if (decl && decl->kind == ast::NodeKind::ClassDecl) {
            any_class = true;
            break;
        }
    }
    const bool has_runtime_globals = !runtime_global_slots_.empty();
    if (!any_class && !has_runtime_globals) return;

    ir::IrFunction fn;
    fn.name = "__module_init";
    fn.ret_type = ir::IrType::VOID;
    const ir::IrBlockId entry = fn.new_block("entry");

    // raw_asm-elim Fase 2c: __module_init se construye con IR ESTRUCTURADO
    // (en vez de un unico bloque RAW_ASM monolitico), para que el path vreg
    // del JIT lo compile sin el mini-parser de raw_asm y para que el futuro
    // AOT no vea bytecode opaco.  Patron equivalente al RAW_ASM legacy:
    //   - Un buffer de params FRESCO (ALLOCA 40 bytes = max de los structs
    //     24/32/40) por operacion.  El buffer NO se promueve a host (sus
    //     usos como operando de DEF*/FIND* son escape para
    //     promote_local_allocas) -> queda como vaddr valido que los ops de
    //     meta-OOP leen via params_vaddr.
    //   - STORE a vm_mem (el buffer es vaddr) arma cada struct; el DEF/FIND
    //     correspondiente lo consume inmediatamente.  Los ops meta-OOP son
    //     side-effecting + barreras de DSE/scheduler -> el optimizer no
    //     reordena ni elimina los STORE que arman el struct.
    //   - CADA clase y CADA advice se emiten en su PROPIO basic block
    //     (encadenados por BR).  Razon: el regalloc del .vel (interp) es
    //     fragil con un unico bloque enorme de cientos de temporales (una
    //     instruccion de mas voltea el spill a codigo incorrecto -> findclass
    //     lee params de una direccion basura).  Con un bloque por clase/
    //     advice los valores son LOCALES al bloque (buffers frescos, v_cls
    //     recargado del cache slot, valores AOP intra-advice) -> el liveness
    //     se resetea en cada frontera -> presion acotada -> regalloc correcto.
    //     Sin PHIs ni valores cross-block.
    const int ln = 0;          // ops sinteticas (sin linea fuente propia)
    ir::IrBlockId cur = entry; // bloque actual (avanza con new_seg)

    // Crea un nuevo segmento (basic block) y encadena con BR desde el actual.
    auto new_seg = [&](const std::string &name) {
        const ir::IrBlockId nb = fn.new_block(name);
        ir::IrInstr br{};
        br.op = ir::IrOp::BR;
        br.type = ir::IrType::VOID;
        br.target_block = nb;
        br.source_line = ln;
        fn.append(cur, std::move(br));
        cur = nb;
    };

    // --- helpers locales para emitir IR sobre fn/cur ---
    auto emit_const64 = [&](uint64_t k) -> ir::IrValueId {
        const ir::IrValueId v = fn.new_value(ir::IrType::I64);
        ir::IrInstr c{};
        c.op = ir::IrOp::CONST;
        c.type = ir::IrType::I64;
        c.dst = v;
        c.imm = k;
        c.source_line = ln;
        fn.append(cur, std::move(c));
        return v;
    };
    auto emit_strlit = [&](uint64_t idx) -> ir::IrValueId {
        // Direccion vaddr del slot static_data idx (@Absolute("code.s_N")).
        const ir::IrValueId v = fn.new_value(ir::IrType::PTR);
        ir::IrInstr s{};
        s.op = ir::IrOp::STR_LIT_ADDR;
        s.type = ir::IrType::PTR;
        s.dst = v;
        s.imm = idx;
        s.source_line = ln;
        fn.append(cur, std::move(s));
        return v;
    };
    auto emit_label_addr = [&](const std::string &label) -> ir::IrValueId {
        // Direccion vaddr de un label de codigo (@Absolute("code.LABEL")).
        const ir::IrValueId v = fn.new_value(ir::IrType::PTR);
        ir::IrInstr s{};
        s.op = ir::IrOp::LABEL_ADDR;
        s.type = ir::IrType::PTR;
        s.dst = v;
        s.func_name = label;
        s.source_line = ln;
        fn.append(cur, std::move(s));
        return v;
    };
    // Buffer de params UNICO (40 bytes = max de los structs 24/32/40) en el
    // VM stack, alocado UNA sola vez y reusado para todos los defclass/
    // deffield/defmethod/findmethod/setmethdbg/findclass/addadvice.  Razones:
    //   - Un ALLOCA por OP inflaria el VM stack (subsp por op sin addsp hasta
    //     el `leave`); con muchas clases/metodos eso baja el VM-RSP cientos de
    //     bytes y cambia el layout VM-stack/heap -> destapa bugs latentes de
    //     scan/GC dependientes del layout (99/133/179 crasheaban en interp).
    //     Un solo ALLOCA mantiene el VM stack casi plano (como el RAW_ASM).
    //   - El multi-bloque (un block por clase/advice) + el SPILL cross-bloque
    //     del .vel regalloc evitan el clobber del registro del buffer (el bug
    //     del single-block era tenerlo en un registro vivo a traves de ~80
    //     ops; spillado a un slot y recargado por uso, no se clobbea).
    //   - La DSE-barrera de los ops meta-OOP preserva los STORE que arman el
    //     struct aunque se reuse buf+0 entre defs.
    ir::IrValueId shared_buf = ir::IR_NO_VALUE;
    auto fresh_buf = [&]() -> ir::IrValueId {
        if (shared_buf != ir::IR_NO_VALUE) return shared_buf;
        const ir::IrValueId v = fn.new_value(ir::IrType::PTR);
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8; // unidad 1 byte
        al.dst = v;
        al.imm = 40;
        al.source_line = ln;
        fn.append(cur, std::move(al)); // is_host_ptr=false -> VM stack
        shared_buf = v;
        return v;
    };
    // STORE v_val en buf + off (vm_mem; el buffer es vaddr).
    auto store_at = [&](ir::IrValueId buf, uint64_t off, ir::IrValueId v_val) {
        ir::IrValueId v_addr = buf;
        if (off != 0) {
            v_addr = fn.new_value(ir::IrType::PTR);
            ir::IrInstr ad{};
            ad.op = ir::IrOp::ADD;
            ad.type = ir::IrType::I64;
            ad.dst = v_addr;
            ad.operands = {buf, emit_const64(off)};
            ad.source_line = ln;
            fn.append(cur, std::move(ad)); // is_host_ptr=false (vaddr)
        }
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir::IrType::I64;
        st.operands = {v_val, v_addr};
        st.source_line = ln;
        fn.append(cur, std::move(st));
    };
    // FINDCLASS/DEFCLASS/FINDMETHOD: dst = op(buf).  ClassInfo*/MethodInfo*
    // son host_ptr nativos (no GC) -> is_host_ptr=true, is_gc_object=false.
    auto emit_find1 = [&](ir::IrOp op, ir::IrValueId buf) -> ir::IrValueId {
        const ir::IrValueId v = fn.new_value(ir::IrType::PTR);
        fn.values[v].is_host_ptr = true;
        ir::IrInstr i{};
        i.op = op;
        i.type = ir::IrType::PTR;
        i.dst = v;
        i.operands = {buf};
        i.source_line = ln;
        fn.append(cur, std::move(i));
        return v;
    };
    // DEFFIELD/DEFMETHOD: op(v_cls, buf) sin dst.
    auto emit_def2 = [&](ir::IrOp op, ir::IrValueId v_cls, ir::IrValueId buf) {
        ir::IrInstr i{};
        i.op = op;
        i.type = ir::IrType::VOID;
        i.operands = {v_cls, buf};
        i.source_line = ln;
        fn.append(cur, std::move(i));
    };

    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::ClassDecl) continue;
        auto *cd = static_cast<ast::ClassDecl *>(decl.get());
        auto it = tc_.class_layouts().find(cd->name);
        if (it == tc_.class_layouts().end()) continue;
        const ClassLayout &lay = it->second;

        // Bloque propio para esta clase (presion de registros acotada).
        new_seg("cls_" + cd->name);

        const uint64_t cname_idx = intern_class_name(out, cd->name);
        const uint32_t cname_len = static_cast<uint32_t>(cd->name.size());

        // 1) Si hay superclase: FindClassParams (16B) + findclass -> v_super.
        ir::IrValueId v_super = ir::IR_NO_VALUE;
        if (!cd->super_name.empty()) {
            const uint64_t sname_idx = intern_class_name(out, cd->super_name);
            const uint32_t sname_len =
                static_cast<uint32_t>(cd->super_name.size());
            const ir::IrValueId b = fresh_buf();
            store_at(b, 0, emit_strlit(sname_idx));
            store_at(b, 8, emit_const64(sname_len));
            v_super = emit_find1(ir::IrOp::FINDCLASS, b);
        }

        // 2) DefClassParams (32B) + defclass -> v_cls.
        const ir::IrValueId b_dc = fresh_buf();
        store_at(b_dc, 0, emit_strlit(cname_idx));
        // [+8] (flags<<32)|name_len con flags=CLASS_VIS_PUBLIC=1.
        store_at(b_dc, 8,
                 emit_const64((uint64_t(1) << 32) | uint64_t(cname_len)));
        // [+16] super_class (ClassInfo* o 0).
        store_at(b_dc, 16,
                 (v_super != ir::IR_NO_VALUE) ? v_super : emit_const64(0));
        // [+24] reserved = 0.
        store_at(b_dc, 24, emit_const64(0));
        const ir::IrValueId v_cls = emit_find1(ir::IrOp::DEFCLASS, b_dc);

        // 2.5) Cachear el ClassInfo* en su slot static_data (lo lee
        // __new_<Class> sin findclass).  STORE a vm_mem (slot = vaddr).
        const uint64_t cache_idx = intern_class_cache_slot(out, cd->name);
        {
            const ir::IrValueId v_cache = emit_strlit(cache_idx);
            ir::IrInstr st{};
            st.op = ir::IrOp::STORE;
            st.type = ir::IrType::I64;
            st.operands = {v_cls, v_cache};
            st.source_line = ln;
            fn.append(cur, std::move(st));
        }

        // Helper: recargar el ClassInfo* desde el cache slot (corto-vivo en
        // cada def para no estresar el regalloc con un v_cls vivo a traves
        // de muchos deffield/defmethod).
        auto reload_cls = [&]() -> ir::IrValueId {
            const ir::IrValueId v_a = emit_strlit(cache_idx);
            const ir::IrValueId v = fn.new_value(ir::IrType::PTR);
            fn.values[v].is_host_ptr = true;
            ir::IrInstr ld{};
            ld.op = ir::IrOp::LOAD;
            ld.type = ir::IrType::I64;
            ld.dst = v;
            ld.operands = {v_a};
            ld.source_line = ln;
            fn.append(cur, std::move(ld));
            return v;
        };

        // 3) Fields PROPIOS (los heredados ya los copio define_class).
        for (size_t fi = lay.inherited_field_count; fi < lay.fields.size();
             ++fi) {
            const auto &f = lay.fields[fi];
            const uint64_t fname_idx = intern_class_name(out, f.name);
            const uint32_t fname_len = static_cast<uint32_t>(f.name.size());
            const ir::IrValueId b = fresh_buf();
            store_at(b, 0, emit_strlit(fname_idx));
            // [+8] name_len (kind/access/is_static = 0 para field de
            // instancia).
            store_at(b, 8, emit_const64(uint64_t(fname_len)));
            store_at(b, 16, emit_const64(8)); // size_bytes = 8 (1 slot)
            store_at(b, 24, emit_const64(0)); // type_class = 0 (primitive)
            emit_def2(ir::IrOp::DEFFIELD, reload_cls(), b);
        }

        // 3.5) Static fields PROPIOS (is_static=1 en bit +48 del packed).
        for (size_t si = lay.inherited_static_field_count;
             si < lay.static_fields.size(); ++si) {
            const auto &f = lay.static_fields[si];
            const uint64_t fname_idx = intern_class_name(out, f.name);
            const uint32_t fname_len = static_cast<uint32_t>(f.name.size());
            const ir::IrValueId b = fresh_buf();
            store_at(b, 0, emit_strlit(fname_idx));
            store_at(b, 8,
                     emit_const64(uint64_t(fname_len) | (uint64_t(1) << 48)));
            store_at(b, 16, emit_const64(8));
            store_at(b, 24, emit_const64(0));
            emit_def2(ir::IrOp::DEFFIELD, reload_cls(), b);
        }

        // 3.6) INICIALIZAR los static fields con su valor por defecto.
        // El DEFFIELD solo reserva el slot (zero).  Sin esto,
        // `static i64 base = 40;` quedaba en 0 (bug general: el init del
        // static nunca se aplicaba en VM/JIT).  Emitimos SETSTATIC con el
        // literal constante.  (Solo constantes; un init no-constante de
        // static es raro y queda como 0 -- mismo criterio que el AOT.)
        for (const auto &fld : cd->fields) {
            if (!fld.is_static || !fld.init) continue;
            uint64_t s_off = 0;
            bool s_ok = false;
            for (const auto &lf : lay.static_fields)
                if (lf.name == fld.name) {
                    s_off = lf.offset;
                    s_ok = true;
                    break;
                }
            if (!s_ok) continue;
            uint64_t cval = 0;
            bool have = false;
            const ast::Expr *ie = fld.init.get();
            if (ie->kind == ast::NodeKind::IntLitExpr) {
                cval = static_cast<const ast::IntLitExpr *>(ie)->value;
                have = true;
            } else if (ie->kind == ast::NodeKind::BoolLitExpr) {
                cval =
                    static_cast<const ast::BoolLitExpr *>(ie)->value ? 1u : 0u;
                have = true;
            } else if (ie->kind == ast::NodeKind::CharLitExpr) {
                cval = static_cast<const ast::CharLitExpr *>(ie)->codepoint;
                have = true;
            } else if (ie->kind == ast::NodeKind::UnaryExpr) {
                auto *u = static_cast<const ast::UnaryExpr *>(ie);
                if (u->op == ast::UnOp::Neg && u->operand &&
                    u->operand->kind == ast::NodeKind::IntLitExpr)
                    cval = (uint64_t)(-(int64_t)static_cast<
                                           const ast::IntLitExpr *>(
                                           u->operand.get())
                                           ->value),
                    have = true;
            }
            if (have) {
                const ir::IrValueId vc = reload_cls();
                const ir::IrValueId vv = emit_const64(cval);
                ir::IrInstr ss{};
                ss.op = ir::IrOp::SETSTATIC;
                ss.type = ir::IrType::VOID;
                ss.dst = ir::IR_NO_VALUE;
                ss.operands = {vc, vv};
                ss.imm = s_off;
                ss.source_line = ln;
                fn.append(cur, std::move(ss));
            }
        }

        // Las interfaces no emiten defmethod (metodos abstractos sin code).
        if (cd->is_interface) continue;

        // 4) Metodos PROPIOS o sobreescritos (defining_class == cd->name).
        for (const auto &m : lay.methods) {
            if (!m.defining_class.empty() && m.defining_class != cd->name)
                continue; // heredado puro
            const std::string suffix =
                m.is_constructor ? std::string("ctor") : m.name;
            const std::string owner_class =
                m.defining_class.empty() ? cd->name : m.defining_class;
            const std::string method_label = owner_class + "__" + suffix;
            const uint64_t mname_idx = intern_class_name(out, m.name);
            const uint32_t mname_len = static_cast<uint32_t>(m.name.size());
            const std::string desc_str = "()";
            const uint64_t desc_idx = intern_class_name(out, desc_str);
            const uint32_t desc_len = static_cast<uint32_t>(desc_str.size());

            uint64_t mflags = 0;
            if (m.is_constructor)
                mflags |= (1ULL << 9); // METHOD_FLAG_CONSTRUCTOR
            else
                mflags |= (1ULL << 10); // METHOD_FLAG_VIRTUAL

            // DefMethodParams (40B) + defmethod.
            const ir::IrValueId b = fresh_buf();
            store_at(b, 0, emit_strlit(mname_idx));
            store_at(
                b, 8,
                emit_const64(uint64_t(mname_len) | (uint64_t(desc_len) << 32)));
            store_at(b, 16, emit_strlit(desc_idx));
            store_at(b, 24, emit_label_addr(method_label)); // code_vaddr
            store_at(b, 32, emit_const64(mflags));
            emit_def2(ir::IrOp::DEFMETHOD, reload_cls(), b);

            // Debug info (file:line) si la hay: findmethod + setmethdbg.
            if (!m.source_file.empty() && m.source_line > 0) {
                const uint64_t fname_idx =
                    intern_class_name(out, m.source_file);
                const uint32_t fname_len =
                    static_cast<uint32_t>(m.source_file.size());

                // FindMethodParams (24B) + findmethod -> v_method.
                const ir::IrValueId bf = fresh_buf();
                store_at(bf, 0, reload_cls());
                store_at(bf, 8, emit_strlit(mname_idx));
                store_at(bf, 16, emit_const64(uint64_t(mname_len)));
                const ir::IrValueId v_method =
                    emit_find1(ir::IrOp::FINDMETHOD, bf);

                // SetMethDebugParams (24B) + setmethdbg.
                const ir::IrValueId bs = fresh_buf();
                store_at(bs, 0, v_method);
                store_at(bs, 8, emit_strlit(fname_idx));
                store_at(bs, 16,
                         emit_const64(uint64_t(fname_len) |
                                      (uint64_t(m.source_line) << 32)));
                ir::IrInstr smd{};
                smd.op = ir::IrOp::SETMETHDBG;
                smd.type = ir::IrType::VOID;
                smd.operands = {v_method, bs};
                smd.source_line = ln;
                fn.append(cur, std::move(smd));
            }
        }
    }

    // -----------------------------------------------------------------
    // 2do pase: AOP.  Tras registrar todas las clases/metodos, recorremos
    // los aspectos y emitimos findclass + findmethod (x2) + addadvice por
    // cada @Before/@After/@Around (cada advice en su propio bloque).
    // Requiere que las clases target ya esten registradas (2do pase).
    // -----------------------------------------------------------------
    for (auto &decl : mod_.decls) {
        if (!decl || decl->kind != ast::NodeKind::ClassDecl) continue;
        auto *cd = static_cast<ast::ClassDecl *>(decl.get());
        if (!cd->type_params.empty() || cd->is_specialization)
            continue; // template / especializacion (#7), no se procesa
        for (auto &m_uptr : cd->methods) {
            auto *m = m_uptr.get();
            if (!m || m->advice_kind == 0) continue;

            const std::string &target = m->advice_target;
            const size_t dot = target.find('.');
            if (dot == std::string::npos || dot == 0 ||
                dot + 1 >= target.size()) {
                error_at(m->loc, "AOP: pointcut '" + target +
                                     "' no tiene formato 'Clase.metodo'");
                continue;
            }
            const std::string tcls = target.substr(0, dot);
            const std::string tmeth = target.substr(dot + 1);
            const uint8_t rt_kind = static_cast<uint8_t>(m->advice_kind - 1);

            // Bloque propio para este advice (presion acotada).
            new_seg("aop_" + cd->name + "_" + m->name);

            // 1) findclass de la clase target -> v_tc.
            const uint64_t tcls_idx = intern_class_name(out, tcls);
            const uint32_t tcls_len = static_cast<uint32_t>(tcls.size());
            const ir::IrValueId b1 = fresh_buf();
            store_at(b1, 0, emit_strlit(tcls_idx));
            store_at(b1, 8, emit_const64(tcls_len));
            const ir::IrValueId v_tc = emit_find1(ir::IrOp::FINDCLASS, b1);

            // 2) findmethod del target -> v_tm.
            const uint64_t tmeth_idx = intern_class_name(out, tmeth);
            const uint32_t tmeth_len = static_cast<uint32_t>(tmeth.size());
            const ir::IrValueId b2 = fresh_buf();
            store_at(b2, 0, v_tc);
            store_at(b2, 8, emit_strlit(tmeth_idx));
            store_at(b2, 16, emit_const64(tmeth_len));
            const ir::IrValueId v_tm = emit_find1(ir::IrOp::FINDMETHOD, b2);

            // 3) findclass del aspecto -> v_ac.
            const uint64_t acls_idx = intern_class_name(out, cd->name);
            const uint32_t acls_len = static_cast<uint32_t>(cd->name.size());
            const ir::IrValueId b3 = fresh_buf();
            store_at(b3, 0, emit_strlit(acls_idx));
            store_at(b3, 8, emit_const64(acls_len));
            const ir::IrValueId v_ac = emit_find1(ir::IrOp::FINDCLASS, b3);

            // 4) findmethod del advice -> v_am.
            const uint64_t adm_idx = intern_class_name(out, m->name);
            const uint32_t adm_len = static_cast<uint32_t>(m->name.size());
            const ir::IrValueId b4 = fresh_buf();
            store_at(b4, 0, v_ac);
            store_at(b4, 8, emit_strlit(adm_idx));
            store_at(b4, 16, emit_const64(adm_len));
            const ir::IrValueId v_am = emit_find1(ir::IrOp::FINDMETHOD, b4);

            // 5) addadvice(target, advice, kind).
            ir::IrInstr aa{};
            aa.op = ir::IrOp::ADDADVICE;
            aa.type = ir::IrType::VOID;
            aa.operands = {v_tm, v_am};
            aa.imm = rt_kind;
            aa.source_line = ln;
            fn.append(cur, std::move(aa));
        }
    }

    // L2.2: inicializar runtime globals con su literal de init.
    // Activamos el contexto del lowering (fn_=&fn, current_block_=cur)
    // temporalmente para reutilizar emit_const/STRMAKE/STORE.  Usamos
    // @c cur (el ultimo bloque encadenado), no @c entry, porque el
    // generador parte __module_init en multiples bloques.
    if (has_runtime_globals) {
        /* El guarda se lleva el contexto del padre y lo devuelve al salir. */
        ChildFunctionScope parent(*this);
        fn_ = &fn;
        current_block_ = cur;
        block_terminated_ = false;
        for (auto &decl : mod_.decls) {
            if (!decl || decl->kind != ast::NodeKind::GlobalVarDecl) continue;
            auto *gv = static_cast<ast::GlobalVarDecl *>(decl.get());
            if (gv->is_const || !gv->init) continue;
            // thread_local: la plantilla por-hilo ya esta en los bytes del slot
            // .tdata (estatica); el cargador la copia por-hilo.  NO se
            // inicializa via __module_init (eso escribiria una sola copia).
            if (gv->is_thread_local) continue;
            // Los arrays globales (T[N]) ya tienen su contenido grabado en los
            // bytes del slot static_data (pre-pase, init-list constante o
            // zero-init).  __module_init NO debe intentar lowerar su init-list
            // (InitListExpr no es lowerable como expresion de valor) -> skip.
            if (gv->type && gv->type->kind == ast::NodeKind::ArrayTypeNode)
                continue;
            auto rit = runtime_global_slots_.find(gv->name);
            if (rit == runtime_global_slots_.end()) continue;
            const uint64_t slot_idx = rit->second;
            const int ln = gv->loc.line;
            // Computar el valor inicial via lower_expr (cubre IntLit,
            // StringLit-no-interpolado promovido a StringObject por
            // lower_string_literal_to_string_object, etc.).
            ir::IrValueId v_init = ir::IR_NO_VALUE;
            if (gv->init->kind == ast::NodeKind::StringLitExpr) {
                auto *slit = static_cast<ast::StringLitExpr *>(gv->init.get());
                v_init = lower_string_literal_to_string_object(slit);
            } else {
                v_init = lower_expr(gv->init.get());
            }
            if (v_init == ir::IR_NO_VALUE) continue;
            // El STORE tiene que respetar el TIPO DECLARADO del global.  Los
            // literales de coma flotante se parsean como double, asi que un
            // `f32 g = 0.5` produce un valor f64; guardarlo tal cual mete 8
            // bytes de bits f64 en un slot cuyo LOAD lee 4 -> el global valia
            // 0 (y ademas machacaba en runtime los bytes correctos que el
            // pre-pase ya habia grabado en el slot).
            ir::IrType sty = ir::IrType::I64;
            if (gv->type &&
                gv->type->kind == ast::NodeKind::PrimitiveTypeNode) {
                const PrimitiveKind gpk =
                    static_cast<ast::PrimitiveTypeNode *>(gv->type.get())->prim;
                if (gpk == PrimitiveKind::F32 || gpk == PrimitiveKind::F64) {
                    sty = ir_type_from_primitive(gpk);
                    const ir::IrType from =
                        (gv->init->result_type.kind == PrimitiveKind::F32)
                            ? ir::IrType::F32
                            : ir::IrType::F64;
                    v_init = cast_if_needed(v_init, from, sty, gv->loc);
                }
            }
            // La direccion del slot, y luego el STORE del valor inicial.  El
            // slot vive en memoria host (seccion `gdata`).
            const ir::IrValueId v_addr =
                emit_str_lit_addr(slot_idx, ln, /*host_ptr=*/true);
            emit_store_typed(v_addr, v_init, sty, ln);
        }
    }

    ir::IrInstr ret{};
    ret.op = ir::IrOp::RET;
    ret.type = ir::IrType::VOID;
    ret.source_line = 0;
    fn.append(cur, std::move(ret)); // ultimo bloque encadenado

    propagate_is_gc_object_through_phis(fn);
    /* Y se entrega partida en tandas: de una pieza es la funcion mas grande
     * del modulo, reparte mal entre hilos y cuesta de mas.  Si la forma no
     * encaja con lo que el troceador sabe garantizar, se queda entera. */
    split_module_init_into_chunks(fn, out);
    out.add_function(std::move(fn));
}

ir::IrValueId Lowering::lower_class_method_call(ast::CallExpr *e) {
    // El callee es FieldAccessExpr cuyo base es de tipo CLASS.  Bajamos
    // el receptor, localizamos el vtable_index del metodo y emitimos
    // CALLVIRT.  El IR emitter coloca obj en r1 y args en r2..r_{N+1}
    // antes de la instruccion bytecode 'callvirt r1, vtable_idx'.
    if (!e->callee || e->callee->kind != ast::NodeKind::FieldAccessExpr) {
        error_at(e->loc,
                 "lowering: callee no es field-access en class method call");
        return ir::IR_NO_VALUE;
    }
    auto *fa = static_cast<ast::FieldAccessExpr *>(e->callee.get());

    // Bug fix 2026-05-23: metodos estaticos.  property_kind=4 marca una
    // llamada estatica `ClassName.method(args)`.  Emitimos CALLVM directo
    // a `<Class>__<method>` sin pasar this como primer arg.
    {
        ir::IrValueId v_static = ir::IR_NO_VALUE;
        if (try_lower_static_method_call(e, fa, v_static)) return v_static;
    }

    const Type bt = fa->base->result_type;
    if (bt.kind != PrimitiveKind::CLASS) {
        error_at(e->loc, "lowering: receptor no es CLASS en method call");
        return ir::IR_NO_VALUE;
    }
    auto it = tc_.class_layouts().find(bt.struct_name);
    if (it == tc_.class_layouts().end()) {
        error_at(e->loc,
                 "lowering: clase desconocida '" + bt.struct_name + "'");
        return ir::IR_NO_VALUE;
    }
    const ClassLayout &lay = it->second;
    const ClassMethodInfo *mtd = nullptr;
    for (const auto &m : lay.methods) {
        if (!m.is_constructor && m.name == fa->field_name) {
            mtd = &m;
            break;
        }
    }
    if (!mtd) {
        error_at(e->loc, "lowering: metodo '" + fa->field_name +
                             "' no encontrado en la clase '" + bt.struct_name +
                             "'");
        return ir::IR_NO_VALUE;
    }
    // Bajar receptor y argumentos.
    const ir::IrValueId obj = lower_expr(fa->base.get());
    if (obj == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
    std::vector<ir::IrValueId> arg_vals;
    arg_vals.reserve(e->args.size());
    for (size_t ai = 0; ai < e->args.size(); ++ai) {
        auto &a = e->args[ai];
        if (!a) return ir::IR_NO_VALUE;
        // Auto-promocion literal -> StringObject cuando el parametro
        // espera STRING y el arg es un StringLit no interpolado.
        // Mismo patron que @c lower_call usa para funciones libres:
        // sin esto, pasar @c helper("hola") a @c void helper(string s)
        // pushearia la direccion cruda del literal como i64 (PTR) y
        // el callee crashearia al hacer @c strraw s con ptr invalido.
        // Sin esto, str_cstr/str_bytes dentro del metodo trataban el
        // PTR del literal como GcHandle invalido y leian garbage.
        const bool param_is_string =
            ai < mtd->param_types.size() &&
            mtd->param_types[ai].kind == PrimitiveKind::STRING;
        if (param_is_string && a->kind == ast::NodeKind::StringLitExpr) {
            auto *slit = static_cast<ast::StringLitExpr *>(a.get());
            // Tanto literales puros como interpolados: el helper
            // construye el StringObject correcto.
            const ir::IrValueId av =
                lower_string_literal_to_string_object(slit);
            if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
            arg_vals.push_back(av);
            continue;
        }
        const ir::IrValueId av = lower_expr(a.get());
        if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
        arg_vals.push_back(av);
    }
    /* Si el ultimo parametro recoge los que sobren, los que sobran no van uno
     * por uno: se meten en un array y se pasa su direccion y cuantos son. */
    if (mtd->is_variadic && !mtd->param_types.empty() &&
        arg_vals.size() >= mtd->param_types.size() - 1) {
        pack_variadic_args(arg_vals, mtd->param_types.size() - 1,
                           ir_type_from_primitive(mtd->variadic_elem.kind),
                           e->loc.line);
    }
    const ir::IrType ret_ir_decl =
        ir_type_from_primitive(mtd->return_type.kind);

    // SRET en class method: si el metodo declara devolver Optional/Result,
    // su firma IR real es void + retbuf hidden como segundo param (tras
    // this).  El caller alloca el buffer (16 / 24 bytes) y lo pasa como
    // primer "arg" del CALLVIRT (entre obj y los args declarados).  El
    // dst del CALLVIRT es VOID; el SSA value visible al lowering es el
    // retbuf (PTR), que se bindea a la var-decl o se pasa a otras fns.
    /* Las tres respuestas salen del mismo sitio que las del metodo llamado.
     * Aqui estaban contestadas aparte y con TRES casos de los siete, mientras
     * que el lado del metodo tenia cuatro: devolver un struct por valor lo
     * contaba el metodo -- declaraba el buffer -- y no quien llamaba, que ni
     * lo reservaba ni lo pasaba. */
    const SretInfo mcsi = sret_info(mtd->return_type);
    const bool method_call_sret = mcsi.uses_buffer;
    ir::IrValueId v_method_call_retbuf = ir::IR_NO_VALUE;
    if (method_call_sret) {
        v_method_call_retbuf = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.imm = mcsi.bytes;
        al.dst = v_method_call_retbuf;
        al.source_line = e->loc.line;
        // BugFix sret-cross-mem (2026-06-04): en memoria del anfitrion, para
        // que el metodo escriba con `movh` y quien llama lea con `movh`.
        al.host_alloca = mcsi.host_buffer;
        emit(current_block_, std::move(al));
        fn_->values[v_method_call_retbuf].is_host_ptr = mcsi.host_buffer;
    }
    const ir::IrType ret_ir = method_call_sret ? ir::IrType::VOID : ret_ir_decl;

    // si el metodo esta marcado @Inline y el receptor NO es
    // interfaz (necesitamos la implementacion concreta), buscar el
    // AST ClassMethodDecl y expandir el cuerpo en el call site.
    // MVP: solo metodos cuyo body sea exactamente `{ return expr; }`.
    if (mtd->is_inline && !lay.is_interface) {
        const ast::ClassDecl *cd_orig = nullptr;
        for (auto &d : mod_.decls) {
            if (!d || d->kind != ast::NodeKind::ClassDecl) continue;
            auto *cdp = static_cast<const ast::ClassDecl *>(d.get());
            if (cdp->name == mtd->defining_class) {
                cd_orig = cdp;
                break;
            }
        }
        if (cd_orig) {
            const ast::ClassMethodDecl *mdecl = nullptr;
            for (const auto &um : cd_orig->methods) {
                if (um && um->name == mtd->name && !um->is_constructor) {
                    mdecl = um.get();
                    break;
                }
            }
            if (mdecl && mdecl->body && mdecl->body->body.size() == 1 &&
                mdecl->body->body[0] &&
                mdecl->body->body[0]->kind == ast::NodeKind::ReturnStmt) {
                auto *rs =
                    static_cast<ast::ReturnStmt *>(mdecl->body->body[0].get());
                if (rs->value) {
                    // Push scope con bindings: this -> obj, params -> args.
                    push_scope();
                    bind("this", obj);
                    const size_t np =
                        std::min(mdecl->params.size(), arg_vals.size());
                    for (size_t i = 0; i < np; ++i) {
                        bind(mdecl->params[i]->name, arg_vals[i]);
                    }
                    const ir::IrValueId v = lower_expr(rs->value.get());
                    pop_scope();
                    return v;
                }
            }
            // Si no se cumple la forma esperada, caer al CALLVIRT.
        }
    }

    const ir::IrValueId dst =
        (ret_ir == ir::IrType::VOID) ? ir::IR_NO_VALUE : fn_->new_value(ret_ir);
    // Sprint edge-bugs (2026-06-03): marcar dst con is_host_ptr/
    // is_gc_object cuando el metodo retorna CLASS/PTR.  Critico
    // para que el regalloc preserve el value a traves de calls
    // GC posteriores (save/restore con conversion a GcHandle).
    mark_value_from_type(dst, mtd->return_type);
    // El valor SSA "visible" al lowering tras el CALLVIRT.  Para SRET
    // es el retbuf (PTR); para calls normales es dst.
    const ir::IrValueId visible_dst =
        method_call_sret ? v_method_call_retbuf : dst;

    // NS.6-ext: metodo anyadido por una extension / impl -> dispatch ESTATICO
    // (CALL directo a <defining_class>__<name>), NO CALLVIRT.  El label usa
    // defining_class (la clave del layout, mangled si el tipo es importado).
    // Correcto tambien cross-modulo: el metodo se emitio como funcion libre en
    // el modulo de la extension y el linker resuelve el simbolo.
    if (mtd->is_extension) {
        ir::IrInstr ca{};
        ca.op = ir::IrOp::CALL;
        ca.type = method_call_sret ? ir::IrType::VOID : ret_ir_decl;
        ca.dst = method_call_sret ? ir::IR_NO_VALUE : dst;
        ca.func_name = mtd->defining_class + "__" + mtd->name;
        ca.operands.push_back(obj);
        if (method_call_sret) ca.operands.push_back(v_method_call_retbuf);
        for (const ir::IrValueId av : arg_vals)
            ca.operands.push_back(av);
        ca.source_line = e->loc.line;
        emit(current_block_, std::move(ca));
        return visible_dst;
    }

    // -----------------------------------------------------------------
    // Devirtualizacion compile-time: si el tipo concreto del receptor
    // es estaticamente conocido (via @c ssa_concrete_class_), reescribir
    // el dispatch a CALLVIRT directo usando el vtable_idx del metodo en
    // la clase concreta.  Tanto port C como JIT consumen este CALLVIRT
    // como direct call, sin coste runtime de findmethod/callm.
    //
    // Aplica cuando el receptor es una variable interface tipada pero
    // su SSA value viene directamente de un @c new ConcreteClass()
    // (caso comun: @c IServicio s = new ImplA();).
    // -----------------------------------------------------------------
    // Devirtualizacion cuando el tipo concreto del receptor se conoce
    // estaticamente.  En native_poo (AOT) se aplica SIEMPRE (HOST_LEAF no
    // soporta CALLVIRT y la vtable nativa sufre slot-mismatch interfaz/clase
    // -> el CALL directo es la unica via correcta); en no-native solo para
    // interfaces (el backend ya devirta los CALLVIRT de clase base).
    if (lay.is_interface || native_poo_) {
        auto it_conc = ssa_concrete_class_.find(obj);
        if (it_conc != ssa_concrete_class_.end()) {
            const std::string &concrete_name = it_conc->second;
            auto it_lay = tc_.class_layouts().find(concrete_name);
            if (it_lay != tc_.class_layouts().end()) {
                const auto &conc_lay = it_lay->second;
                // Buscar metodo por nombre en la clase concreta.
                for (const auto &cm : conc_lay.methods) {
                    if (cm.name == mtd->name && !cm.is_constructor) {
                        if (native_poo_) {
                            // AOT (HOST_LEAF no soporta CALLVIRT): el tipo
                            // concreto se conoce -> CALL DIRECTO a
                            // <concreto>__<metodo>.  Correcto y mas rapido,
                            // y EVITA el bug de slot-mismatch entre el
                            // vtable_index de la interfaz (area=slot0) y el
                            // de la clase concreta (el ctor ocupa slot0 ->
                            // area=slot1).  Sin esto el dispatch de interfaz
                            // nativo leia el slot equivocado (resultado
                            // silenciosamente erroneo).
                            // BUG-5: clase importada cross-module.  El body del
                            // metodo en el dep se emitio con el nombre LOCAL de
                            // la clase (imported_helper_suffix), no con el
                            // mangled del consumer ("widget__Widget").  Al
                            // devirtualizar a un CALL directo hay que usar el
                            // nombre local para que el simbolo case con el
                            // body; si no, el linker AOT deja
                            // `<mangled>__<metodo>` indefinido (y el dead-elim
                            // descarta el body). Mismo patron que el ctor
                            // (__new_<suffix>).
                            std::string owner_class = cm.defining_class.empty()
                                                          ? concrete_name
                                                          : cm.defining_class;
                            {
                                auto it_ol =
                                    tc_.class_layouts().find(owner_class);
                                if (it_ol != tc_.class_layouts().end() &&
                                    !it_ol->second.imported_helper_suffix
                                         .empty())
                                    owner_class =
                                        it_ol->second.imported_helper_suffix;
                            }
                            const std::string callee =
                                owner_class + "__" + cm.name;
                            ir::IrInstr ca{};
                            ca.op = ir::IrOp::CALL;
                            ca.type = ret_ir;
                            ca.dst = dst;
                            ca.func_name = callee;
                            ca.operands.push_back(obj);
                            if (method_call_sret)
                                ca.operands.push_back(v_method_call_retbuf);
                            for (auto av : arg_vals)
                                ca.operands.push_back(av);
                            ca.source_line = e->loc.line;
                            emit(current_block_, std::move(ca));
                            return visible_dst;
                        }
                        // CALLVIRT directo con el vtable_idx de la
                        // clase concreta -> backend devirtaliza.
                        ir::IrInstr cv{};
                        cv.op = ir::IrOp::CALLVIRT;
                        cv.type = ret_ir;
                        cv.dst = dst;
                        cv.imm = static_cast<uint64_t>(cm.vtable_index);
                        cv.operands.push_back(obj);
                        // SRET: retbuf tras obj, antes de args.
                        if (method_call_sret)
                            cv.operands.push_back(v_method_call_retbuf);
                        for (auto av : arg_vals)
                            cv.operands.push_back(av);
                        cv.source_line = e->loc.line;
                        emit(current_block_, std::move(cv));
                        // Propagar tipo concreto del retorno si es
                        // tambien tipo class conocido.
                        return visible_dst;
                    }
                }
            }
        }
    }
    // AOT.2.c: dispatch de INTERFAZ polimorfico nativo via la vtable del
    // objeto (obj[0]).  El metodo de interfaz esta en el slot
    // mtd->vtable_index (posicion en la interfaz); los implementadores
    // colocan los metodos de interfaz en esos mismos slots de su vtable
    // (verificado por ejecucion).  Misma secuencia que CALLVIRT: LOAD
    // vtable; LOAD fn[idx]; CALLIND.
    if (lay.is_interface && native_poo_) {
        fn_->values[obj].is_host_ptr = true;
        // La ranura sale del tramo reservado a ESTA interfaz, no del indice a
        // secas: el indice a secas cae encima de los metodos de la clase.
        const ir::IrValueId v_fn = emit_vtable_method_ptr(
            obj, native_iface_slot(lay.name, mtd->vtable_index), e->loc.line);
        ir::IrInstr ci{};
        ci.op = ir::IrOp::CALLIND;
        ci.type = ret_ir;
        ci.dst = dst;
        ci.func_ptr = v_fn;
        ci.operands.push_back(obj);
        if (method_call_sret) ci.operands.push_back(v_method_call_retbuf);
        for (auto av : arg_vals)
            ci.operands.push_back(av);
        ci.source_line = e->loc.line;
        emit(current_block_, std::move(ci));
        if (dst != ir::IR_NO_VALUE &&
            mtd->return_type.kind == PrimitiveKind::CLASS) {
            fn_->values[dst].is_host_ptr = true;
            fn_->values[dst].is_gc_object = true;
        }
        return visible_dst;
    }
    if (lay.is_interface) {
        // Marcar obj como host_ptr (instancia GC-derivada).
        fn_->values[obj].is_host_ptr = true;

        // Dispatch de interfaz via ITABLE (en vez de findmethod+callm):
        // construimos un @c ItfCallParams (32 bytes) en stack con el
        // nombre de la interfaz, el nombre del metodo, el indice del metodo
        // (posicion en la declaracion de la interfaz = vtable_index) y el
        // numero de metodos de la interfaz, y emitimos un solo CALLITF.
        //   +0  iface_name_addr (8)
        //   +8  iface_name_len (lo32) | method_index (hi32)
        //   +16 method_name_addr (8)
        //   +24 method_name_len (lo32) | count (hi32)
        // El interp despacha via la itable lazy de la clase concreta
        // (indice O(1) tras el warmup); el JIT inlinea el scan de itables.
        const std::string &iface_name = bt.struct_name; // == lay.name
        const std::string &method_name = mtd->name;
        const uint64_t iface_idx = intern_class_name(*out_mod_, iface_name);
        const uint32_t iface_len = static_cast<uint32_t>(iface_name.size());
        const uint64_t method_idx_str =
            intern_class_name(*out_mod_, method_name);
        const uint32_t method_len = static_cast<uint32_t>(method_name.size());
        const uint32_t method_index = mtd->vtable_index;
        const uint32_t mcount = static_cast<uint32_t>(lay.methods.size());

        // Buffer de ItfCallParams (32 bytes) construido UNA VEZ en el entry
        // block (block 0) de la funcion -- su contenido es 100%
        // loop-invariante (nombres + indices constantes).  El @c callitf en
        // el loop solo LEE el buffer.  Critico para correctness:
        //   (1) un ALLOCA por dispatch creceria el VM stack en loops
        //       calientes (pic_real 3M iter desbordaba el stack);
        //   (2) construir el struct DENTRO del loop hacia que el LICM/
        //       regalloc hoisteara un CONST a un reg de arg (r1) que el
        //       marshalling del call clobbeaba -> v_buf corrupto en iter 2+.
        // Construir en el entry (dominador de todo) evita ambos.  Cada call
        // site tiene su propio buffer (params distintos); como el call site
        // se baja UNA vez, son pocos buffers (1 por dispatch textual).
        //
        // Insertamos las instrucciones de construccion en block 0 ANTES de
        // su terminador (o al final si aun no esta terminado).
        std::vector<ir::IrInstr> setup;
        const ir::IrValueId v_buf = fn_->new_value(ir::IrType::PTR);
        {
            ir::IrInstr al{};
            al.op = ir::IrOp::ALLOCA;
            al.type = ir::IrType::I8;
            al.imm = 32;
            al.dst = v_buf;
            al.source_line = e->loc.line;
            setup.push_back(std::move(al));
        }
        // Helper local: STORE i64 @c val a @c v_buf + @c off (instrs -> setup).
        auto setup_store_at = [&](uint64_t off, ir::IrValueId val) {
            ir::IrValueId base = v_buf;
            if (off != 0) {
                const ir::IrValueId v_off = fn_->new_value(ir::IrType::I64);
                ir::IrInstr c{};
                c.op = ir::IrOp::CONST;
                c.type = ir::IrType::I64;
                c.imm = off;
                c.dst = v_off;
                c.source_line = e->loc.line;
                setup.push_back(std::move(c));
                base = fn_->new_value(ir::IrType::PTR);
                ir::IrInstr add{};
                add.op = ir::IrOp::ADD;
                add.type = ir::IrType::I64;
                add.dst = base;
                add.operands = {v_buf, v_off};
                add.source_line = e->loc.line;
                setup.push_back(std::move(add));
            }
            ir::IrInstr st{};
            st.op = ir::IrOp::STORE;
            st.type = ir::IrType::I64;
            st.dst = ir::IR_NO_VALUE;
            st.operands = {val, base};
            st.source_line = e->loc.line;
            setup.push_back(std::move(st));
        };
        auto setup_const = [&](uint64_t k) -> ir::IrValueId {
            const ir::IrValueId v = fn_->new_value(ir::IrType::I64);
            ir::IrInstr c{};
            c.op = ir::IrOp::CONST;
            c.type = ir::IrType::I64;
            c.imm = k;
            c.dst = v;
            c.source_line = e->loc.line;
            setup.push_back(std::move(c));
            return v;
        };
        auto setup_str_lit = [&](uint64_t idx) -> ir::IrValueId {
            const ir::IrValueId v = fn_->new_value(ir::IrType::PTR);
            ir::IrInstr ns{};
            ns.op = ir::IrOp::STR_LIT_ADDR;
            ns.type = ir::IrType::PTR;
            ns.dst = v;
            ns.imm = idx;
            ns.source_line = e->loc.line;
            setup.push_back(std::move(ns));
            return v;
        };
        // [+0] iface_name_addr ; [+8] iface_len|method_index<<32 ;
        // [+16] method_name_addr ; [+24] method_len|count<<32.
        setup_store_at(0, setup_str_lit(iface_idx));
        setup_store_at(
            8, setup_const(static_cast<uint64_t>(iface_len) |
                           (static_cast<uint64_t>(method_index) << 32)));
        setup_store_at(16, setup_str_lit(method_idx_str));
        setup_store_at(24, setup_const(static_cast<uint64_t>(method_len) |
                                       (static_cast<uint64_t>(mcount) << 32)));
        // ----------------------------------------------------------------
        // (C2): preparar devirt especulativa estatica del CALLITF.
        // Si la interfaz tiene pocos (<=K) implementors concretos NO-aspecto
        // con el metodo inlineable, resolvemos el ClassInfo* de cada uno
        // (findclass en el entry, loop-invariante) y registramos los
        // candidatos; el pase ir_pass_spec_devirt reescribe el CALLITF en
        // un guard-chain por tipo + fallback al dispatch via itable.
        //  - Solo metodos que devuelven valor (dst != IR_NO_VALUE) y
        //    no-SRET (v1).
        //  - Conservador con AOP: si el modulo declara cualquier @Aspect,
        //    NO especulamos (un advice podria targetear el metodo y el CALL
        //    directo del fast path lo saltaria); el dispatch via itable
        //    recorre la advice_chain correctamente.
        // Resolucion v1 (2a): findclass directo en el entry, 1x/invocacion
        // (despreciable para dispatch-en-loop).  2b lo cambiara a slot-cache
        // eager en __module_init (1x total).
        std::vector<ir::DevirtCandidate> spec_cands;
        if (dst != ir::IR_NO_VALUE && !method_call_sret) {
            for (const auto &pr :
                 spec_devirt_impls(iface_name, method_name, true)) {
                spec_cands.push_back(ir::DevirtCandidate{
                    emit_findclass_into(setup, pr.first, e->loc.line),
                    pr.second});
            }
        }

        splice_into_entry_block(setup);

        // CALLITF: operands[0]=obj, [1]=params_ptr, [2..]=args (retbuf SRET
        // como [2] si aplica).  func_name = "iface\x1fmethod", imm packed.
        ir::IrInstr ci{};
        ci.op = ir::IrOp::CALLITF;
        ci.type = ret_ir;
        ci.dst = dst;
        ci.func_name = iface_name;
        ci.func_name.push_back('\x1f');
        ci.func_name += method_name;
        ci.imm = (static_cast<uint64_t>(mcount) << 32) |
                 static_cast<uint64_t>(method_index);
        ci.operands.push_back(obj);
        ci.operands.push_back(v_buf);
        if (method_call_sret) ci.operands.push_back(v_method_call_retbuf);
        for (auto av : arg_vals)
            ci.operands.push_back(av);
        ci.source_line = e->loc.line;
        emit(current_block_, std::move(ci));
        // registrar el site especulativo (keyed por el dst del
        // CALLITF).  El pase ir_pass_spec_devirt lo consume @O2.
        if (!spec_cands.empty())
            fn_->spec_devirt_sites[dst] = std::move(spec_cands);
        return visible_dst;
    }

    //  AOT.2.c: POO nativa -- DEVIRT MONOMORFICA.  Si la clase
    // receptora estatica es HOJA (ninguna otra clase la extiende), el tipo
    // dinamico == el estatico, por lo que la llamada NO puede resolver a un
    // override de subclase -> emitimos un CALL DIRECTO a <owner>__<metodo>
    // (cero overhead, igual que C++ con tipo final).  El dispatch virtual
    // real (vtable) para clases base con subclases llega en el siguiente
    // slice de 2.c.  Mismo orden de operandos que el CALLVIRT (obj, retbuf
    // SRET, args).
    if (native_poo_) {
        bool is_leaf = true;
        for (const auto &kv : tc_.class_layouts())
            if (kv.second.super_name == bt.struct_name) {
                is_leaf = false;
                break;
            }
        if (is_leaf) {
            const std::string owner = mtd->defining_class.empty()
                                          ? bt.struct_name
                                          : mtd->defining_class;
            ir::IrInstr dc{};
            dc.op = ir::IrOp::CALL;
            dc.type = ret_ir;
            dc.dst = dst;
            dc.func_name = owner + "__" + mtd->name;
            dc.operands.push_back(obj);
            if (method_call_sret) dc.operands.push_back(v_method_call_retbuf);
            for (auto av : arg_vals)
                dc.operands.push_back(av);
            dc.source_line = e->loc.line;
            emit(current_block_, std::move(dc));
            if (dst != ir::IR_NO_VALUE &&
                mtd->return_type.kind == PrimitiveKind::CLASS) {
                fn_->values[dst].is_host_ptr = true;
                fn_->values[dst].is_gc_object = true;
            }
            return visible_dst;
        }
        // No-hoja (clase base con subclases): DISPATCH VIRTUAL nativo via la
        // vtable estatica guardada en obj[0] (la pone __new_<Class>).
        //   %vt   = LOAD [obj+0]            (puntero a la vtable)
        //   %slot = %vt + vtable_index*8
        //   %fn   = LOAD [%slot]            (direccion del metodo)
        //   CALLIND %fn (obj, retbuf?, args)
        {
            const ir::IrValueId v_fn = emit_vtable_method_ptr(
                obj, native_class_slot(mtd->vtable_index), e->loc.line);
            ir::IrInstr ci{};
            ci.op = ir::IrOp::CALLIND;
            ci.type = ret_ir;
            ci.dst = dst;
            ci.func_ptr = v_fn;
            ci.operands.push_back(obj);
            if (method_call_sret) ci.operands.push_back(v_method_call_retbuf);
            for (auto av : arg_vals)
                ci.operands.push_back(av);
            ci.source_line = e->loc.line;
            emit(current_block_, std::move(ci));
            if (dst != ir::IR_NO_VALUE &&
                mtd->return_type.kind == PrimitiveKind::CLASS) {
                fn_->values[dst].is_host_ptr = true;
                fn_->values[dst].is_gc_object = true;
            }
            return visible_dst;
        }
    }

    /* Adivinar la clase del receptor, igual que ya se hacia en las llamadas
     * por INTERFAZ.  El pase que lo aprovecha sabe reescribir tambien esto --
     * CALLVIRT esta en su lista desde siempre --, pero nadie le daba de comer:
     * los sitios solo se registraban en la interfaz.  Resultado: la llamada a
     * un metodo de interfaz se resolvia con una comparacion y una llamada
     * directa, y la de un metodo de clase -- que es el despacho corriente de
     * todo el lenguaje -- pasaba entera por la tabla. */
    std::vector<ir::DevirtCandidate> cv_spec;
    if (dst != ir::IR_NO_VALUE && !method_call_sret && !native_poo_) {
        std::vector<ir::IrInstr> cv_setup;
        for (const auto &pr :
             spec_devirt_impls(bt.struct_name, mtd->name, false)) {
            cv_spec.push_back(ir::DevirtCandidate{
                emit_findclass_into(cv_setup, pr.first, e->loc.line),
                pr.second});
        }
        splice_into_entry_block(cv_setup);
    }

    // Path por defecto: dispatch via vtable_idx (clase concreta).
    ir::IrInstr ins{};
    ins.op = ir::IrOp::CALLVIRT;
    ins.type = ret_ir;
    ins.dst = dst;
    // operands[0] = obj, operands[1..] = args declarados
    ins.operands.push_back(obj);
    // SRET: retbuf tras obj, antes de args declarados.
    if (method_call_sret) ins.operands.push_back(v_method_call_retbuf);
    for (auto av : arg_vals)
        ins.operands.push_back(av);
    ins.imm = static_cast<uint64_t>(mtd->vtable_index);
    ins.source_line = e->loc.line;
    emit(current_block_, std::move(ins));
    if (!cv_spec.empty()) fn_->spec_devirt_sites[dst] = std::move(cv_spec);
    // Sprint edge-bugs (2026-06-03): marcar dst con flags GC.  Critico
    // para que el regalloc trate el value como host_ptr GC-managed
    // (save/restore convierte a GcHandle).  Esto es la correccion
    // arquitectural; queda un bug latente del INTERP en CALLVIRT
    // chained (p2 = factory(); p3 = p2.factory(); p3.field) donde el
    // host_ptr retornado puede ser stale -- el bug NO afecta JIT.
    // Documentado en limitaciones; los tests del Lombok @With usan
    // verificacion sin encadenar para evitar el bug latente.
    if (dst != ir::IR_NO_VALUE &&
        mtd->return_type.kind == PrimitiveKind::CLASS) {
        fn_->values[dst].is_host_ptr = true;
        fn_->values[dst].is_gc_object = true;
    }
    return visible_dst;
}

void Lowering::lower_extension_methods(ir::IrModule &out) {
    for (auto &decl : mod_.decls) {
        if (!decl) continue;
        const bool is_ext = decl->kind == ast::NodeKind::ExtensionDecl;
        const bool is_impl = decl->kind == ast::NodeKind::ImplDecl;
        if (!is_ext && !is_impl) continue;
        std::string target_src;
        std::vector<std::unique_ptr<ast::ClassMethodDecl>> *methods = nullptr;
        if (is_ext) {
            auto *e = static_cast<ast::ExtensionDecl *>(decl.get());
            target_src = e->target_type;
            methods = &e->methods;
        } else {
            auto *im = static_cast<ast::ImplDecl *>(decl.get());
            target_src = im->target_type;
            methods = &im->methods;
        }
        // Resolver la clave del layout destino (misma logica que el checker).
        std::string key;
        bool is_class = false;
        auto set_key = [&](const std::string &k) -> bool {
            if (tc_.struct_layouts().count(k)) {
                key = k;
                is_class = false;
                return true;
            }
            if (tc_.class_layouts().count(k)) {
                key = k;
                is_class = true;
                return true;
            }
            return false;
        };
        if (!set_key(target_src)) {
            std::string mangled = target_src;
            for (size_t p = mangled.find('.'); p != std::string::npos;
                 p = mangled.find('.'))
                mangled.replace(p, 1, "__");
            if (mangled == target_src || !set_key(mangled)) {
                const Type rt = tc_.resolve_type_string(target_src);
                if (rt.kind == PrimitiveKind::STRUCT ||
                    rt.kind == PrimitiveKind::CLASS)
                    set_key(rt.struct_name);
            }
        }
        if (key.empty()) continue;
        // StructDecl temporal: name = clave, methods = los de la extension
        // (movidos temporalmente y devueltos al terminar).
        ast::StructDecl tmp;
        tmp.name = key;
        tmp.methods = std::move(*methods);
        const bool saved = ext_this_is_class_;
        ext_this_is_class_ = is_class;
        lower_struct_methods(&tmp, out);
        ext_this_is_class_ = saved;
        *methods = std::move(tmp.methods); // devolver para no invalidar el AST
    }
}

void Lowering::export_classes_to_ir(ir::IrModule &out) {
    const auto &layouts = tc_.class_layouts();
    out.classes.reserve(layouts.size());
    for (const auto &kv : layouts) {
        const auto &cl = kv.second;
        // Saltar clases predefinidas en runtime (e.g. FatalError):
        // el port no debe re-emitirlas; el runtime las provee.
        if (cl.is_runtime_predefined) continue;

        ir::IrClass icls;
        icls.name = cl.name;
        icls.super_name = cl.super_name;
        icls.interfaces = cl.interface_names;
        icls.size_bytes = cl.size_bytes;
        icls.is_final = false; /* Vesta frontend lo trackea por metodo;
                agregado lo deducimos en transpiler
                via hierarchy analysis cuando es
                necesario.  Default false = seguro. */
        icls.is_interface = cl.is_interface;
        icls.is_aspect = cl.is_aspect;
        icls.has_destructor = cl.has_destructor;
        icls.has_destructible_field = cl.has_destructible_field;
        icls.is_runtime_predefined = false;

        // Convertir fields de instancia.  Mantenemos el orden del
        // ClassLayout (heredados primero, luego propios) -- el
        // transpiler los emite tal cual en el struct C.
        icls.fields.reserve(cl.fields.size());
        for (const auto &f : cl.fields) {
            ir::IrField ifld;
            ifld.name = f.name;
            ifld.type = ir_type_from_primitive(f.type.kind);
            ifld.offset = f.offset;
            ifld.size_bytes = f.size;
            ifld.is_static = false;
            /* Si el tipo del field es CLASS, registrar el nombre de la
             * clase apuntada -- el transpiler lo necesita para emitir
             * el tipo C correcto (`ClassY *` vs `void *`). */
            if (f.type.kind == PrimitiveKind::CLASS) {
                ifld.class_type_name = f.type.struct_name;
            }
            icls.fields.push_back(std::move(ifld));
        }

        // Static fields.
        icls.static_fields.reserve(cl.static_fields.size());
        for (const auto &f : cl.static_fields) {
            ir::IrField ifld;
            ifld.name = f.name;
            ifld.type = ir_type_from_primitive(f.type.kind);
            ifld.offset = f.offset;
            ifld.size_bytes = f.size;
            ifld.is_static = true;
            if (f.type.kind == PrimitiveKind::CLASS) {
                ifld.class_type_name = f.type.struct_name;
            }
            icls.static_fields.push_back(std::move(ifld));
        }

        // Convertir metodos.  El @c ir_fn_name sigue el mangling de
        // @c lower_class_methods: "<Class>__ctor" para constructores,
        // "<Class>__<name>" para el resto (destructor usa name="__dtor"
        // -> ir_fn_name="<Class>____dtor" con 4 underscores).
        icls.methods.reserve(cl.methods.size());
        for (const auto &m : cl.methods) {
            ir::IrMethod imeth;
            imeth.name = m.name;
            if (m.is_constructor) {
                imeth.ir_fn_name = cl.name + "__ctor";
            } else {
                // Si el metodo es heredado puro (no override), apuntar al
                // simbolo del defining_class para evitar emitir referencia
                // a un Class__method que no existe.  El transpiler C usa
                // este nombre como label de funcion.
                const std::string &defc = m.defining_class;
                const std::string &owner =
                    (!defc.empty() && defc != cl.name) ? defc : cl.name;
                imeth.ir_fn_name = owner + "__" + m.name;
            }
            imeth.return_type = ir_type_from_primitive(m.return_type.kind);
            imeth.param_types.reserve(m.param_types.size());
            for (const auto &pt : m.param_types) {
                imeth.param_types.push_back(ir_type_from_primitive(pt.kind));
            }
            imeth.vtable_index = static_cast<int32_t>(m.vtable_index);
            imeth.is_static = m.is_static;
            imeth.is_final = m.is_final;
            imeth.is_constructor = m.is_constructor;
            imeth.is_destructor = m.is_destructor;
            imeth.is_inline = m.is_inline;
            imeth.defining_class = m.defining_class;
            icls.methods.push_back(std::move(imeth));
        }

        out.classes.push_back(std::move(icls));
    }
}

/**
 * @brief Intenta bajar la llamada como un metodo ESTATICO de la clase.
 *
 * `Clase.metodo(args)` no tiene receptor: no hay objeto sobre el que llamar,
 * asi que no se pasa `this` y no hay tabla que consultar -- el destino se sabe
 * al compilar y es una llamada directa a `<Clase>__<metodo>`.
 *
 * @param e   La llamada.
 * @param fa  Su callee, que es de donde sale el nombre de la clase.
 * @param out Donde dejar el valor que la llamada produce.
 * @return @c true si era estatica y quedo bajada.
 */
bool Lowering::try_lower_static_method_call(ast::CallExpr *e,
                                            ast::FieldAccessExpr *fa,
                                            ir::IrValueId &out) {
    if (fa->property_kind != 4 && fa->property_kind != 7) return false;
    {
        std::string class_name;
        if (fa->base && fa->base->kind == ast::NodeKind::IdentExpr) {
            class_name = static_cast<ast::IdentExpr *>(fa->base.get())->name;
        }
        if (class_name.empty()) {
            error_at(e->loc,
                     "lowering: nombre de clase vacio en llamada estatica");
            out = ir::IR_NO_VALUE;
            return true;
        }
        // El metodo static puede vivir en una CLASE o en un STRUCT (factorias
        // tipo `u128.zero()`).  Buscar en ambos mapas.
        const ClassMethodInfo *static_mtd = nullptr;
        auto it_cls = tc_.class_layouts().find(class_name);
        if (it_cls != tc_.class_layouts().end()) {
            for (const auto &m : it_cls->second.methods)
                if (!m.is_constructor && m.is_static &&
                    m.name == fa->field_name) {
                    static_mtd = &m;
                    break;
                }
        }
        if (!static_mtd) {
            auto it_str = tc_.struct_layouts().find(class_name);
            if (it_str != tc_.struct_layouts().end())
                for (const auto &m : it_str->second.methods)
                    if (!m.is_constructor && m.is_static &&
                        m.name == fa->field_name) {
                        static_mtd = &m;
                        break;
                    }
        }
        if (!static_mtd) {
            error_at(e->loc, "lowering: metodo estatico '" + class_name + "." +
                                 fa->field_name + "' no encontrado");
            out = ir::IR_NO_VALUE;
            return true;
        }
        // SRET si el retorno es un agregado value-type (struct por valor /
        // Optional / Result): el caller aloca el retbuf en host-stack y lo pasa
        // como PRIMER operando (no hay `this` en un metodo static).  Simetrico
        // con el callee en lower_struct_methods (que ya trata static sin this +
        // retbuf hidden).
        const StructLayout *ret_slay = nullptr;
        if (static_mtd->return_type.kind == PrimitiveKind::STRUCT &&
            !static_mtd->return_type.struct_name.empty() &&
            tc_.enum_layouts().find(static_mtd->return_type.struct_name) ==
                tc_.enum_layouts().end()) {
            auto it_rs =
                tc_.struct_layouts().find(static_mtd->return_type.struct_name);
            if (it_rs != tc_.struct_layouts().end() &&
                !it_rs->second.is_overlay)
                ret_slay = &it_rs->second;
        }
        /* La misma respuesta que da el metodo al declararse y que dan los
         * otros caminos de llamada.  Aqui habia una nota que decia que esta
         * condicion NO coincidia con la del metodo, que anadirle el caso que
         * le faltaba no bastaba, y que quedaba un tercer sitio sin localizar.
         * Eran SIETE, cada uno con una lista distinta; ya no hay listas. */
        const SretInfo ssi = sret_info(static_mtd->return_type);
        const bool sret = ssi.uses_buffer;
        ir::IrValueId v_retbuf = ir::IR_NO_VALUE;
        if (sret) {
            v_retbuf = fn_->new_value(ir::IrType::PTR);
            ir::IrInstr al{};
            al.op = ir::IrOp::ALLOCA;
            al.type = ir::IrType::I8;
            al.imm = ssi.bytes;
            al.dst = v_retbuf;
            al.host_alloca = ssi.host_buffer;
            al.source_line = e->loc.line;
            emit(current_block_, std::move(al));
            fn_->values[v_retbuf].is_host_ptr = ssi.host_buffer;
        }
        // Bajar args (retbuf primero si SRET).
        std::vector<ir::IrValueId> arg_vals;
        arg_vals.reserve(e->args.size() + (sret ? 1 : 0));
        if (sret) arg_vals.push_back(v_retbuf);
        for (size_t ai = 0; ai < e->args.size(); ++ai) {
            auto &a = e->args[ai];
            if (!a) return ir::IR_NO_VALUE;
            const bool param_is_string =
                ai < static_mtd->param_types.size() &&
                static_mtd->param_types[ai].kind == PrimitiveKind::STRING;
            if (param_is_string && a->kind == ast::NodeKind::StringLitExpr) {
                auto *slit = static_cast<ast::StringLitExpr *>(a.get());
                arg_vals.push_back(lower_string_literal_to_string_object(slit));
            } else {
                const ir::IrValueId av = lower_expr(a.get());
                if (av == ir::IR_NO_VALUE) return ir::IR_NO_VALUE;
                arg_vals.push_back(av);
            }
        }
        const ir::IrType ret_ir =
            sret ? ir::IrType::VOID
                 : ir_type_from_primitive(static_mtd->return_type.kind);
        ir::IrValueId dst = (ret_ir == ir::IrType::VOID)
                                ? ir::IR_NO_VALUE
                                : fn_->new_value(ret_ir);
        ir::IrInstr ins{};
        ins.op = ir::IrOp::CALL;
        ins.type = ret_ir;
        ins.dst = dst;
        // Metodo static IMPORTADO cross-module: usar el simbolo real del .velb
        // origen (link_name); si no, "<Name>__<metodo>".
        ins.func_name = static_mtd->link_name.empty()
                            ? (class_name + "__" + fa->field_name)
                            : static_mtd->link_name;
        ins.operands = arg_vals;
        ins.source_line = e->loc.line;
        emit(current_block_, std::move(ins));
        // El resultado de una factoria SRET es el retbuf (ptr al struct).
        out = sret ? v_retbuf : dst;
    }
    return true;
}

/**
 * @copydoc vx::Lowering::spec_devirt_impls
 */
std::vector<std::pair<std::string, std::string>>
Lowering::spec_devirt_impls(const std::string &static_class,
                            const std::string &method_name,
                            bool is_interface) const {
    std::vector<std::pair<std::string, std::string>> impls;
    /* Basta un aspecto que no se haya podido atribuir a un metodo concreto
     * para no adivinar en ningun sitio: podria apuntar a cualquiera. */
    if (!all_advices_attributed_) return impls;

    constexpr size_t K_MAX = 4;
    for (const auto &kv : tc_.class_layouts()) {
        const ClassLayout &cl = kv.second;
        if (cl.is_interface || cl.is_aspect) continue;

        /* Que la clase encaje: que cumpla la interfaz, o que sea el tipo
         * declarado o descienda de el. */
        bool encaja = false;
        if (is_interface) {
            for (const auto &in : cl.interface_names)
                if (in == static_class) {
                    encaja = true;
                    break;
                }
        } else {
            std::string cur = cl.name;
            for (int guard = 0; !cur.empty() && guard < 64; ++guard) {
                if (cur == static_class) {
                    encaja = true;
                    break;
                }
                const auto itc = tc_.class_layouts().find(cur);
                if (itc == tc_.class_layouts().end()) break;
                cur = itc->second.super_name;
            }
        }
        if (!encaja) continue;

        /* Quien DEFINE el metodo: puede estar heredado sin aplanar, asi que se
         * sube por la cadena.  No vale buscar el primero con ese nombre: un
         * constructor puede llamarse igual y dejaria sin encontrar al que se
         * busca. */
        const std::string *owner = nullptr;
        for (const ClassMethodInfo &mm : cl.methods) {
            if (mm.name != method_name || mm.is_constructor) continue;
            owner = mm.defining_class.empty() ? &cl.name : &mm.defining_class;
            break;
        }
        if (!owner) continue;

        const std::string callee = *owner + "__" + method_name;
        if (advice_chains_.count(callee) != 0) continue; // lleva aspectos
        impls.emplace_back(cl.name, callee);
        if (impls.size() > K_MAX) return {}; // demasiados: no compensa
    }
    return impls;
}

/**
 * @copydoc vx::Lowering::emit_findclass_into
 */
ir::IrValueId Lowering::emit_findclass_into(std::vector<ir::IrInstr> &setup,
                                            const std::string &cls_name,
                                            uint32_t source_line) {
    const uint32_t ln = source_line;
    auto konst = [&](uint64_t v) -> ir::IrValueId {
        const ir::IrValueId d = fn_->new_value(ir::IrType::I64);
        ir::IrInstr c{};
        c.op = ir::IrOp::CONST;
        c.type = ir::IrType::I64;
        c.dst = d;
        c.imm = v;
        c.source_line = ln;
        setup.push_back(std::move(c));
        return d;
    };

    const uint64_t nidx = intern_class_name(*out_mod_, cls_name);
    const uint32_t nlen = static_cast<uint32_t>(cls_name.size());

    // Los parametros de findclass: {direccion del nombre, longitud}.
    const ir::IrValueId vp = fn_->new_value(ir::IrType::PTR);
    {
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = vp;
        al.imm = 16;
        al.source_line = ln;
        setup.push_back(std::move(al));
    }
    const ir::IrValueId vna = fn_->new_value(ir::IrType::PTR);
    {
        ir::IrInstr la{};
        la.op = ir::IrOp::LABEL_ADDR;
        la.type = ir::IrType::PTR;
        la.dst = vna;
        la.func_name = "s_" + std::to_string(nidx);
        la.source_line = ln;
        setup.push_back(std::move(la));
    }
    {
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir::IrType::I64;
        st.operands = {vna, vp};
        st.source_line = ln;
        setup.push_back(std::move(st));
    }
    const ir::IrValueId vlen = konst(static_cast<uint64_t>(nlen));
    const ir::IrValueId voff = konst(8);
    const ir::IrValueId vp8 = fn_->new_value(ir::IrType::PTR);
    {
        ir::IrInstr add{};
        add.op = ir::IrOp::ADD;
        add.type = ir::IrType::I64;
        add.dst = vp8;
        add.operands = {vp, voff};
        add.source_line = ln;
        setup.push_back(std::move(add));
    }
    {
        ir::IrInstr st{};
        st.op = ir::IrOp::STORE;
        st.type = ir::IrType::I64;
        st.operands = {vlen, vp8};
        st.source_line = ln;
        setup.push_back(std::move(st));
    }
    const ir::IrValueId vc = fn_->new_value(ir::IrType::PTR);
    fn_->values[vc].is_host_ptr = true;
    {
        ir::IrInstr fc{};
        fc.op = ir::IrOp::FINDCLASS;
        fc.type = ir::IrType::PTR;
        fc.dst = vc;
        fc.operands = {vp};
        fc.is_call_site = true;
        fc.source_line = ln;
        setup.push_back(std::move(fc));
    }
    return vc;
}

/**
 * @copydoc vx::Lowering::splice_into_entry_block
 */
void Lowering::splice_into_entry_block(std::vector<ir::IrInstr> &setup) {
    if (setup.empty()) return;
    auto &e0 = fn_->blocks[0].instrs;
    size_t pos = e0.size();
    if (pos > 0) {
        const ir::IrOp last = e0.back().op;
        // Si el bloque ya termina en un salto, va ANTES de el.
        if (last == ir::IrOp::BR || last == ir::IrOp::BR_COND ||
            last == ir::IrOp::RET || last == ir::IrOp::UNREACHABLE ||
            last == ir::IrOp::TAILCALL || last == ir::IrOp::RETHROW ||
            last == ir::IrOp::THROW) {
            pos = e0.size() - 1;
        }
    }
    e0.insert(e0.begin() + pos, std::make_move_iterator(setup.begin()),
              std::make_move_iterator(setup.end()));
    setup.clear();
}

} // namespace vx
