/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/declarations.cpp
 * @brief Bajada de declarar una variable y de asignarle un valor.
 *
 * Las dos caras del mismo asunto: donde vive un valor y como llega ahi.
 * Declarar no es reservar sitio y ya -- hay que decidir SI hace falta sitio
 * (muchos valores viven en un registro y nunca tocan memoria), donde ponerlo
 * (la pila de la maquina virtual o el monton del anfitrion, y eso lo decide si
 * alguien va a tomar su direccion o a prestarlo), inicializarlo, y anotar quien
 * lo posee para que se libere al salir del ambito.
 *
 * Asignar tampoco es un almacenamiento: el destino puede ser una variable, un
 * campo, un elemento, lo apuntado por un puntero o una propiedad con `set`, y
 * si lo que se asigna posee algo hay que soltar antes lo que habia.
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
#include "lowering_internal.h" // la cocina compartida del lowering

namespace vx {

void Lowering::lower_var_decl(ast::VarDeclStmt *vd) {
    // Propagacion de literal para el plegado de str_cstr/str_wstr: una
    // `const string p = "x";` deja el texto accesible por nombre.  Solo const
    // (no se puede reasignar); si el nombre se redeclara con otro texto se
    // descarta, para no equivocarse con el sombreado entre ambitos.
    if (vd && vd->is_const && vd->init &&
        vd->init->kind == ast::NodeKind::StringLitExpr &&
        !static_cast<ast::StringLitExpr *>(vd->init.get())->is_interpolated()) {
        const Type vt = vd->type ? tc_.resolve_type_node(vd->type.get())
                                 : vd->init->result_type;
        if (vt.kind == PrimitiveKind::STRING) {
            const std::string &txt =
                static_cast<ast::StringLitExpr *>(vd->init.get())->value;
            auto it = const_str_locals_.find(vd->name);
            if (it != const_str_locals_.end() && it->second != txt) {
                const_str_locals_.erase(it); // redeclarado: ambiguo
            } else {
                const_str_locals_[vd->name] = txt;
            }
        }
    }

    // Resolver el Type semantico (aplicando aliases y structs).
    // A.43.7: con `auto`/`var` (vd->infer_type), el AST no tiene
    // TypeNode -> el type checker ya computo y guardo el tipo en
    // `vd->init->result_type` durante check_expr.  Lo reusamos sin
    // re-evaluar el init.
    Type sem_type = vd->type ? tc_.resolve_type_node(vd->type.get())
                             : (vd->init ? vd->init->result_type : Type{});
    /* El liberador que la variable adopto de su inicializador: resolver el
     * tipo desde el nodo no lo ve, porque en el nodo no esta escrito.  Lo
     * anoto el comprobador, que es quien decidio la adopcion. */
    if (!vd->declared_deleter.empty() && sem_type.deleter_name.empty())
        sem_type.deleter_name = vd->declared_deleter;

    // `static T x = init;` local: duracion estatica (gdata) + init-once.
    // Se desvia por completo del camino ALLOCA (stack).
    if (vd->is_static) {
        lower_static_local(vd, sem_type);
        return;
    }

    // `T c = T();` constructor por defecto de struct (sin ctor declarado, 0
    // args): equivale a `T c;` -- cada campo toma su valor por defecto.  Se
    // descarta el init para que el camino de struct sin init emita los
    // defaults (emit_struct_field_defaults).  No aplica a agregados static
    // (los maneja lower_static_local con su propio init-once).
    if (sem_type.kind == PrimitiveKind::STRUCT && vd->init &&
        vd->init->kind == ast::NodeKind::CallExpr &&
        static_cast<ast::CallExpr *>(vd->init.get())->is_default_struct_ctor) {
        vd->init.reset();
    }

    // Overlay F1: `PEB peb = PEB(ptr);`.  Un overlay ES un puntero (la vista);
    // NO se aloca buffer.  Bajamos el init (que produce el puntero base host) y
    // bindeamos la variable directamente a ese valor.  El acceso a campos
    // (lower_field_access) reusa el camino de struct (base + offset + LOAD) con
    // is_host_ptr=true -> loads/stores host.
    if (sem_type.kind == PrimitiveKind::STRUCT) {
        auto it = tc_.struct_layouts().find(sem_type.struct_name);
        if (it != tc_.struct_layouts().end() && it->second.is_overlay) {
            if (!vd->init) {
                error_at(vd->loc, "un overlay '" + sem_type.struct_name +
                                      "' requiere un puntero base en su "
                                      "declaracion");
                return;
            }
            ir::IrValueId base = lower_expr(vd->init.get());
            if (base == ir::IR_NO_VALUE) return;
            fn_->values[base].is_host_ptr = true;
            bind(vd->name, base);
            return;
        }
    }

    //  Z.6: propagar el modificador @c shared del var-decl al
    // @c NewExpr del init.  Si el init es `new T(...)` y el var-decl
    // tiene `shared`, el `new` debe alocar en el SharedHeap en lugar
    // del gc_heap local.  El @c lower_new_expr detecta la marca y
    // emite `__new_<Class>_shared` (que internamente usa @c newobjs).
    if (vd->is_shared && vd->init && vd->init->kind == ast::NodeKind::NewExpr) {
        auto *ne = static_cast<ast::NewExpr *>(vd->init.get());
        ne->is_shared = true;
        // Registrar la clase como usada en modo shared para que
        // generate_new_helpers genere su variante `__new_<X>_shared`.
        if (!ne->class_name.empty()) {
            classes_used_shared_.insert(ne->class_name);
        }
    }

    //  Z.9: si el var-decl tiene `shared`, registrar el nombre en
    // @c shared_locals_ para que el escape analyzer en spawn capture
    // no genere warning (es shared explicitamente).
    if (vd->is_shared) {
        shared_locals_.insert(vd->name);
    }

    // gc<T> opt-in: si el var-decl es `gc<Class>` (sem_type.gc_managed) y el
    // init es `new Class(...)`, marcar el NewExpr para que el lowering despache
    // a __new_<Class>_gc (vx_gc_alloc) y registrar la clase para generar ese
    // helper.  El valor es un host_ptr GC-managed (marcado is_gc_object); NO se
    // registra cleanup RAII (el GC colecta).
    if (native_poo_ && sem_type.gc_managed && vd->init &&
        vd->init->kind == ast::NodeKind::NewExpr) {
        auto *ne = static_cast<ast::NewExpr *>(vd->init.get());
        ne->is_gc = true;
        if (!ne->class_name.empty()) classes_used_gc_.insert(ne->class_name);
    }

    //  AS inc.3: si el var-decl tiene storage-class register("reg"),
    // forzar el camino ALLOCA (slot estable) marcando el nombre como
    // address-taken.  Sin esto, un primitivo register-bound se baja a un
    // SSA value efimero que el optimizer pliega/elimina (el body asm es
    // una string opaca que no referencia SSA values).  Con el ALLOCA + el
    // INLINE_ASM listandolo como operando (op no-safe -> escapa), el slot
    // sobrevive y el backend lo cablea al registro fisico.  El registro
    // real en @c fn_->asm_reg_bindings se hace en la rama ALLOCA de abajo.
    if (!vd->reg_binding.empty()) {
        address_taken_locals_.insert(vd->name);
    }

    // Tracking para fix #1 newInstance: si el tipo declarado es alias
    // `Class` y el init es `Class.forName("X")` con X literal, registrar
    // var_name -> "X" para que `cls.newInstance()` luego pueda emitir
    // `new X()` directo (con ctor invocado).  Detectamos via
    // FieldAccessExpr con property_kind=100 (forName) que el type
    // checker ya marco.
    if (vd->type && vd->type->kind == ast::NodeKind::NamedTypeNode) {
        const auto *nt =
            static_cast<const ast::NamedTypeNode *>(vd->type.get());
        const bool is_class_alias = (nt->name == "Class");
        if (is_class_alias && vd->init &&
            vd->init->kind == ast::NodeKind::CallExpr) {
            auto *ce = static_cast<ast::CallExpr *>(vd->init.get());
            if (ce->callee &&
                ce->callee->kind == ast::NodeKind::FieldAccessExpr) {
                auto *fa =
                    static_cast<ast::FieldAccessExpr *>(ce->callee.get());
                // property_kind 100 = forName (estatico, sin self).
                if (fa->property_kind == 100 && ce->args.size() == 1 &&
                    ce->args[0] &&
                    ce->args[0]->kind == ast::NodeKind::StringLitExpr) {
                    auto *slit =
                        static_cast<ast::StringLitExpr *>(ce->args[0].get());
                    if (!slit->is_interpolated()) {
                        class_origin_of_local_[vd->name] = slit->value;
                    }
                }
            }
        } else if (is_class_alias) {
            // Init no-trackeable -> borrar entrada previa por seguridad.
            class_origin_of_local_.erase(vd->name);
        }
    }

    // Array init C-style: `i32 arr[N] = {e0, e1, ...};`.
    if (sem_type.kind == PrimitiveKind::ARRAY && vd->init &&
        vd->init->kind == ast::NodeKind::InitListExpr) {
        auto *il = static_cast<ast::InitListExpr *>(vd->init.get());
        if (il->is_designated) {
            error_at(vd->loc,
                     "lowering: init designado '.field=' no aplica a arrays");
            return;
        }
        const Type elem_t = sem_type.pointee ? *sem_type.pointee : Type{};
        const uint32_t elem_sz = (uint32_t)primitive_size_bytes(elem_t.kind);
        if (elem_sz == 0) {
            error_at(vd->loc, "lowering: tipo del elemento sin sizeof");
            return;
        }
        const uint32_t arr_size = sem_type.array_size > 0
                                      ? (uint32_t)sem_type.array_size
                                      : (uint32_t)il->elements.size();
        if (il->elements.size() > arr_size) {
            error_at(vd->loc, "lowering: init list excede tamano de array");
            return;
        }
        ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = addr;
        al.imm = (uint64_t)arr_size * elem_sz;
        al.source_line = vd->loc.line;
        /* Buffer en memoria HOST, como en las demas rutas de array local:
         * todo lo que lo consume (`a` decaido a `T*`, `&a[i]`, la funcion que
         * lo recibe) emite accesos de host, asi que dejarlo en la pila de la
         * VM mata el proceso en cuanto se recorre. */
        al.host_alloca = true;
        fn_->values[addr].is_host_ptr = true;
        emit(current_block_, std::move(al));
        const ir::IrType ir_elem = ir_type_from_primitive(elem_t.kind);
        for (size_t i = 0; i < il->elements.size(); ++i) {
            ir::IrValueId v_val = lower_expr(il->elements[i].get());
            if (v_val == ir::IR_NO_VALUE) continue;
            // Suprimir warning de narrowing si el elemento es literal
            // (`{10, 20, ...}` con i64-defaulted literals encajando en
            // el tipo de elemento).  Mismo razonamiento que en
            // var-decl con init literal.
            const bool elem_is_literal =
                il->elements[i]->kind == ast::NodeKind::IntLitExpr ||
                il->elements[i]->kind == ast::NodeKind::FloatLitExpr ||
                il->elements[i]->kind == ast::NodeKind::BoolLitExpr ||
                il->elements[i]->kind == ast::NodeKind::CharLitExpr ||
                il->elements[i]->kind == ast::NodeKind::NullLitExpr;
            v_val = cast_if_needed(v_val, fn_->values[v_val].type, ir_elem,
                                   vd->loc.line,
                                   /*is_explicit=*/elem_is_literal);
            ir::IrValueId v_addr_i = addr;
            if (i > 0) {
                ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, (uint64_t)(i * elem_sz), vd->loc.line);
                v_addr_i = emit_ptr_add(addr, v_off, vd->loc.line);
            }
            emit_store_typed(v_addr_i, v_val, ir_elem, vd->loc.line);
        }
        bind(vd->name, addr);
        return;
    }

    // Struct init C-style: `Point p = {.x=1, .y=2};` o
    // posicional `Point p = {1, 2};`.
    if (try_lower_struct_init_list(vd, sem_type)) return;

    // Variable de tipo struct.  Reservamos memoria local con ALLOCA del IR
    // (el emisor lo baja a 'subsp rsp, N + readcur') y guardamos el
    // IrValueId del puntero como "current value" de la variable en scope.
    // El acceso a campos via FieldAccessExpr calcula offsets desde esa base.
    if (try_lower_struct_var(vd, sem_type)) return;

    // Array nativo T[N]: identico a struct desde la optica del lowering.
    if (try_lower_array_var(vd, sem_type)) return;

    // Caso 2: tipos primitivos / PTR (camino tradicional).
    ir::IrType vt = ir::IrType::I64;
    if (vd->type && vd->type->kind == ast::NodeKind::PrimitiveTypeNode) {
        auto *pt = static_cast<ast::PrimitiveTypeNode *>(vd->type.get());
        vt = ir_type_from_primitive(pt->prim);
    } else if (sem_type.kind != PrimitiveKind::COUNT &&
               sem_type.kind != PrimitiveKind::VOID) {
        // Alias resuelto a primitivo / PTR.
        vt = ir_type_from_primitive(sem_type.kind);
    }
    // bug6 - gc<T> para T CUALQUIERA (primitivo / smart ptr / anidado): la
    // variable guarda un host_ptr al box GC (gc_box).  El IR type debe ser PTR
    // (no el tipo interno T), si no un cast_if_needed insertaria un bitcast
    // PTR->T que descartaria is_host_ptr -> el `*g` posterior leeria memoria
    // VM en lugar del box host y devolveria basura.  Para gc<Clase> el tipo ya
    // era CLASS->PTR; esto extiende el mismo modelo a T no-clase.
    if (sem_type.gc_managed) {
        vt = ir::IrType::PTR;
    }

    if (try_lower_address_taken_var(vd, sem_type, vt)) return;
    ir::IrValueId v = ir::IR_NO_VALUE;
    if (try_lower_var_init(vd, sem_type, vt, v)) return;
    bind(vd->name, v);

    // auto-free de colecciones primitivas.  Si el tipo del var
    // es uno de los tipos coleccion (ARRAYLIST, HASHMAP, etc), registrar
    // un cleanup en cleanup_stack_ que llame al free fn correspondiente
    // del plugin nativo al exit del scope/funcion.  El cleanup se emite
    // como RAW_ASM (consistente con synchronized) que prepara R1=handle,
    // R15=1, y emite calln al @Method del free.  Cero overhead en el
    // hot path (solo se emite al exit; CALL clean exits sin frame).
    //
    // Limitacion: si el handle se devuelve (return xs) o se asigna a
    // otra variable que vive mas, el free aqui dejaria al caller con
    // un handle invalido.  El escape analysis basico marca esos
    // locales en @c escaping_locals_ y omite el cleanup para ellos;
    // los locales realmente locales si reciben el free automatico.

    // FINALIZADOR CLASS_DTOR: un gc<Clase> con ~Clase() que POSEE un recurso
    // (campo owned, file handle, etc.) no tiene cleanup determinista (el GC lo
    // colecta).  Sin finalizador, ~Clase() nunca corre -> FUGA del recurso.
    // Registramos un finalizador GC que invoca el <Clase>____dtor CONCRETO
    // (dispatch estatico, CALL directo) cuando el sweep colecte el objeto.
    // Aplica ESCAPE o NO-escape indistintamente (el GC colecta cada objeto
    // exactamente una vez -> el dtor corre exactamente una vez; no hay cleanup
    // determinista que pudiera duplicarlo).  interp/JIT via gcfinalc; AOT via
    // CALL vx_gc_register_finalizer (emit_gc_set_finalizer bifurca por target).
    if (v != ir::IR_NO_VALUE && sem_type.kind == PrimitiveKind::CLASS &&
        sem_type.gc_managed && vd->init &&
        vd->init->kind == ast::NodeKind::NewExpr) {
        const auto &class_layouts = tc_.class_layouts();
        auto it_cls = class_layouts.find(sem_type.struct_name);
        if (it_cls != class_layouts.end()) {
            const ClassLayout &lay = it_cls->second;
            const ClassMethodInfo *dtor = nullptr;
            for (const auto &mi : lay.methods)
                if (mi.is_destructor) {
                    dtor = &mi;
                    break;
                }
            // Solo registrar si el dtor NO es polimorfico (dispatch estatico:
            // sin super, sin interfaces, sin subclases).  Si fuera virtual, el
            // finalizador tendria que resolver por vtable (fuera del contrato
            // "CALL directo"); ese caso (gc<Clase> polimorfica con dtor +
            // escape) queda como incremento futuro (fallback: se colecta sin
            // dtor).
            if (dtor != nullptr) {
                if (!class_has_vtable(sem_type.struct_name)) {
                    const std::string owner = dtor->defining_class.empty()
                                                  ? sem_type.struct_name
                                                  : dtor->defining_class;
                    const std::string dtor_label =
                        owner + "__" + dtor->name; // <Clase>____dtor
                    // vaddr del dtor via LABEL_ADDR (dispatch estatico).
                    const ir::IrValueId v_dtor =
                        emit_label_addr(dtor_label, vd->loc.line);
                    emit_gc_set_finalizer(v, /*CLASS_DTOR*/ 3, vd->loc.line,
                                          v_dtor);
                }
            }
        }
    }

    // Destructor automatico (RAII) para instancias locales de
    // clase Vesta que tienen `~ClassName()` declarado y NO escapan.
    // Emite CALLVIRT al destructor al exit del scope/funcion via
    // cleanup_stack_, mismo mecanismo que el auto-free de colecciones.
    // gc<Clase>: se EXCLUYE -- su ~Clase() lo corre el finalizador GC
    // (CLASS_DTOR, registrado arriba), no el cleanup determinista de scope.
    // Sin esta exclusion, un gc<Clase> no-escape ejecutaria el dtor DOS veces
    // (CALL_DTOR del scope + finalizador GC al colectar) -> doble-free.
    if (v != ir::IR_NO_VALUE && sem_type.kind == PrimitiveKind::CLASS &&
        !sem_type.gc_managed &&
        escaping_locals_.find(vd->name) == escaping_locals_.end()) {
        const auto &class_layouts = tc_.class_layouts();
        auto it_cls = class_layouts.find(sem_type.struct_name);
        if (it_cls != class_layouts.end()) {
            const ClassLayout &lay = it_cls->second;
            const ClassMethodInfo *dtor = nullptr;
            for (const auto &mi : lay.methods) {
                if (mi.is_destructor) {
                    dtor = &mi;
                    break;
                }
            }
            //  AOT.2.b/c/d: POO nativa -> al exit del scope, para una
            // instancia HEAP (`= new`): invocar `~T()` (si existe) y luego
            // liberar la memoria (RAW_FREE).  RAII determinista, sin GC, sin
            // leak.  Una instancia STACK (`Rect r;` -> alloca) NO se libera
            // (la pila se reclama sola).  El dtor se llama DIRECTO al tipo
            // estatico (`<owner>__<dtor>`); el resto del cuerpo del dtor (que
            // libera recursos propios, p.ej. free de un campo malloc) corre.
            const bool is_heap_new =
                vd->init && vd->init->kind == ast::NodeKind::NewExpr;
            // gc<T>: NO registrar cleanup RAII -- el GC (libvesta_gc) colecta
            // el objeto cuando deja de ser alcanzable (incl. ciclos). Liberarlo
            // por RAII seria un double-free (el GC ya lo gestiona).
            if (native_poo_ && is_heap_new && !sem_type.gc_managed) {
                CleanupAction act;
                act.kind = CleanupAction::Kind::NATIVE_FREE;
                act.operands = {v};
                act.source_line = vd->loc.line;
                act.refresh_name = vd->name;
                if (dtor) {
                    // AOT.2.d: nombre IR del dtor del tipo estatico ->
                    // se invoca antes del free.
                    const std::string owner = dtor->defining_class.empty()
                                                  ? sem_type.struct_name
                                                  : dtor->defining_class;
                    act.func_name =
                        owner + "__" + dtor->name; // <Class>____dtor
                    // AOT.2.d (4): dtor polimorfico.  Si la clase estatica
                    // tiene vtable (es base/derivada o implementa interfaz),
                    // el dtor es virtual -> despachar por la vtable de la
                    // INSTANCIA (no por el tipo estatico) para que
                    // `Base b = new Derived()` ejecute ~Derived().
                    if (class_has_vtable(sem_type.struct_name)) {
                        act.native_dtor_virtual = true;
                        act.dtor_vtable_index = dtor->vtable_index;
                    }
                }
                cleanup_stack_.push_back(std::move(act));
            } else if (dtor) {
                // cleanup CALL_DTOR: el regalloc ve un CALL/CALLVIRT
                // real y preserva los regs vivos del scope (incluido el
                // reg de v_ret en lower_return).  refresh_name garantiza
                // que el cleanup vea el binding actual del local si fue
                // reasignado tras el var-decl.
                CleanupAction act;
                act.kind = CleanupAction::Kind::CALL_DTOR;
                act.operands = {v};
                act.source_line = vd->loc.line;
                act.refresh_name = vd->name;
                act.dtor_vtable_index = dtor->vtable_index;
                // Dispatch estatico cuando el dtor NO es polimorfico: el tipo
                // declarado del contenedor coincide con el dinamico (no hay
                // super, ni interfaces, ni subclases) -> el dtor sintetizado se
                // resuelve en compile-time.  Emitir CALL DIRECTO al
                // `<owner>____dtor` en lugar de CALLVIRT: mas rapido (sin
                // vtable lookup) en interp/JIT y compilable en AOT
                // --target=bare (que no tiene vtable runtime).  Solo cuando
                // existe vtable (herencia/interfaz real) se conserva el
                // CALLVIRT.
                if (!class_has_vtable(sem_type.struct_name)) {
                    const std::string owner = dtor->defining_class.empty()
                                                  ? sem_type.struct_name
                                                  : dtor->defining_class;
                    act.func_name =
                        owner + "__" + dtor->name; // <Class>____dtor
                }
                cleanup_stack_.push_back(std::move(act));
            }
            // fix9 - eliminado el cleanup RAW_ASM `gchandle+drop`
            // para CLASS sin destructor (era el fix).  Ya no
            // necesario tras fix8 (GC stack scanning conservativo
            // con interior scan en OldGen): los handles que no aparecen
            // en stack/regs/external_refs son barridos automaticamente
            // por el major_gc.  Las restricciones que el fix antiguo
            // imponia (scopes_.size()<=2, !current_fn_has_try_) ya no
            // aplican.
        }
    }

    // fix9 - eliminado el cleanup RAW_ASM para `i64 obj =
    // newInstance(cls)` (era el fix2).  Mismo razonamiento que
    // el caso CLASS sin destructor: el GC stack scanning fix8
    // colecta automaticamente cualquier handle que no aparezca en
    // stack/regs vivos, sin importar si el var-decl es CLASS o I64
    // ni si la funcion tiene try/catch.

    // BugFix R9: SOLO registrar cleanup si el init es directamente un
    // constructor de coleccion (`arraylist(n)`, `hashmap(n)`, etc.).
    // Otras formas (cast, asignacion de otra var, return de func)
    // son ALIAS del mismo handle -> el owner original ya tiene cleanup;
    // duplicarlo causa double-free al exit.  Ejemplo: `ArrayList l1 =
    // (ArrayList)groups.get(1)` crea un alias del handle ya owned por
    // list1; sin este check, l1 se libera al exit Y list1 tambien
    // -> corrupcion del heap (exit 127).
    bool init_is_col_ctor = false;
    if (vd->init && vd->init->kind == ast::NodeKind::CallExpr) {
        auto *ce = static_cast<ast::CallExpr *>(vd->init.get());
        if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(ce->callee.get());
            if (find_col_ctor(id->name) != nullptr) {
                init_is_col_ctor = true;
            }
        }
    }
    if (v != ir::IR_NO_VALUE && is_col_kind(sem_type.kind) &&
        init_is_col_ctor &&
        escaping_locals_.find(vd->name) == escaping_locals_.end()) {
        // solo registramos cleanup si el local NO escapa
        // (ni return ni asignacion a campo/slot/deref).  Si escapa,
        // el caller toma posesion del handle y lo libera.
        const ColType *ct = find_col_type(sem_type.kind);
        if (ct) {
            // elegir variante *_free_gc cuando la coleccion
            // retiene refs GC (e.g. ArrayList<string>).  El frontend
            // setea pointee/pointee2 en sem_type al resolver el tipo
            // declarado; col_needs_gc_aware decide.
            PrimitiveKind elem_k = PrimitiveKind::VOID;
            PrimitiveKind val_k = PrimitiveKind::VOID;
            if (sem_type.pointee) elem_k = sem_type.pointee->kind;
            if (sem_type.pointee2) val_k = sem_type.pointee2->kind;
            // En native_poo (AOT) no hay VM -> no hay getproc ni el gc_addref/
            // release del runtime de la VM.  Usamos la variante NO-GC (libera
            // solo el almacenamiento de la coleccion); el lifetime de los
            // elementos lo gestiona el modelo nativo (RAII / gc<T>), no el
            // refcount de la VM.
            const bool gc_aware =
                (ct->native_free_fn_gc != nullptr) && !native_poo_ &&
                col_needs_gc_aware(sem_type.kind, elem_k, val_k);
            const char *fn_name =
                gc_aware ? ct->native_free_fn_gc : ct->native_free_fn;
            out_mod_->register_native_import(COL_NATIVE_LIB, fn_name);
            CleanupAction act;
            act.kind = CleanupAction::Kind::CALLN_FREE;
            act.operands = {v};
            act.source_line = vd->loc.line;
            act.refresh_name = vd->name;
            act.func_name = std::string(COL_NATIVE_LIB) + ":" + fn_name;
            act.needs_proc = gc_aware;
            cleanup_stack_.push_back(std::move(act));
        }
    }

    // ---- Smart pointers (H3 inc-on-copy): `shared<T> b = a` es una COPIA ----
    // (init es un IdentExpr de otro shared, no `shared_box`/`move`/factory).
    // Incrementamos el refcount del bloque de control: cada copia es un dueno
    // mas, y su SHAREDPTR_REL al exit lo decrementa.  Asi use_count es correcto
    // y (con free-when-0) el bloque se libera tras el ultimo dueno.  El move
    // (CallExpr `move`) y la construccion (`shared_box`) NO incrementan.
    if (sem_type.kind == PrimitiveKind::SHARED_PTR && v != ir::IR_NO_VALUE &&
        vd->init && vd->init->kind == ast::NodeKind::IdentExpr &&
        vd->init->result_type.kind == PrimitiveKind::SHARED_PTR) {
        emit_shared_refcount_inc(v, vd->loc.line);
    }

    // ---- Smart pointers: registrar cleanup automatico al scope exit ----
    //
    // Para @c unique<T>: SMARTPTR_FREE con literal_deleter="free" (default
    // Tier 0) o nombre de funcion deleter custom (set por unique_with).
    // Para @c shared<T>: SHAREDPTR_REL (refcount--; GC libera).
    //
    // Solo se registra si el local NO escapa (escaping_locals_).  Si
    // escapa, el caller toma posesion (return) o lo guarda
    // (asignacion a field/slot/deref), por lo que NO se debe liberar
    // aqui.
    if (v != ir::IR_NO_VALUE &&
        (sem_type.kind == PrimitiveKind::UNIQUE_PTR ||
         sem_type.kind == PrimitiveKind::SHARED_PTR) &&
        escaping_locals_.find(vd->name) == escaping_locals_.end()) {
        CleanupAction act;
        act.operands = {v};
        act.source_line = vd->loc.line;
        act.refresh_name = vd->name;
        if (sem_type.kind == PrimitiveKind::UNIQUE_PTR) {
            act.kind = CleanupAction::Kind::SMARTPTR_FREE;
            /* QUIEN LIBERA LO DICE EL TIPO.
             *
             * Aqui habia sesenta lineas de heuristica para adivinarlo desde el
             * sitio de la declaracion: un estado pendiente que ponia
             * `unique_with`, un mapa de nombre a liberador para resolver un
             * `move`, deteccion de "esto parece una fabrica" y, cuando nada de
             * eso alcanzaba, un despacho DINAMICO que leia el liberador de la
             * ranura EN EJECUCION -- que es la razon de que la ranura midiera
             * dos palabras en vez de una.
             *
             * Con el liberador en el tipo (@c Type::deleter_name) no hay nada
             * que adivinar: un `move` devuelve el tipo de su argumento y una
             * fabrica el que declara su firma, asi que los dos lo traen
             * puesto.  Vacio = el de por defecto. */
            // Tal cual lo dice el tipo: que vacio signifique el de por defecto
            // lo sabe quien emite la liberacion, y se dice en un solo sitio.
            act.literal_deleter = sem_type.deleter_name;
            act.slot_size = smart_ptr_slot_bytes(PrimitiveKind::UNIQUE_PTR);

            // Bug fix bug2: si el inner T es una CLASS Vesta con destructor,
            // registrar el vtable_index para que el cleanup invoque
            // `~T()` sobre el objeto contenido ANTES de liberar el slot.
            // Sin esto, `unique_box(new Recurso(1))` perdia el destructor
            // al exit del scope -- el slot se RAW_FREE'aba pero el
            // Recurso quedaba huerfano (eventual GC pero sin ~Recurso).
            if (sem_type.pointee &&
                sem_type.pointee->kind == PrimitiveKind::CLASS) {
                const auto &cls_layouts = tc_.class_layouts();
                auto it_cls = cls_layouts.find(sem_type.pointee->struct_name);
                if (it_cls != cls_layouts.end()) {
                    // Marcar siempre como inner GC class para que el
                    // cleanup NO haga RAW_FREE del host_ptr (que es un
                    // host_ptr a un objeto GC, no a memoria RAW_ALLOC).
                    act.inner_is_gc_class = true;
                    const ClassLayout &ilay = it_cls->second;
                    for (const auto &mi : ilay.methods) {
                        if (mi.is_destructor) {
                            act.inner_has_dtor = true;
                            act.inner_dtor_vtable_index = mi.vtable_index;
                            // Nombre directo del dtor (<owner>__<dtor>) para
                            // CALL directo en native_poo (AOT).
                            const std::string owner =
                                mi.defining_class.empty()
                                    ? sem_type.pointee->struct_name
                                    : mi.defining_class;
                            act.inner_dtor_func_name = owner + "__" + mi.name;
                            // Polimorfico si la clase de dentro tiene tabla de
                            // metodos: el destructor hay que buscarlo por lo
                            // que el objeto ES, no por como se declaro.
                            act.inner_dtor_virtual =
                                class_has_vtable(sem_type.pointee->struct_name);
                            break;
                        }
                    }
                }
            }
        } else {
            act.kind = CleanupAction::Kind::SHAREDPTR_REL;
            act.slot_size = 8;
        }
        cleanup_stack_.push_back(std::move(act));

        // gc<unique<T>>/gc<shared<T>> NO-escape (AOT): el box lleva un
        // finalizador GC (registrado por gc_box) para el caso ESCAPE, pero este
        // var NO escapa -> el cleanup RAII determinista de arriba libera el
        // recurso.  Si ademas corriera el finalizador al `gc_finalize_all` del
        // exit, el bloque de control se liberaria DOS VECES (RAW_FREE del
        // cleanup + free del finalizador; ademas con allocadores distintos:
        // slab vx_mem vs libc) -> corrupcion de heap (bug 245,
        // gc<shared<unique<i64>>> anidado).  Desregistramos el finalizador aqui
        // para que finalize_all lo salte (anti-doble-free, el modelo que la doc
        // de emit_gc_set_finalizer ya describia).  Solo en native_poo_ (AOT):
        // en interp/JIT el finalizador y el cleanup conviven sin corrupcion (la
        // memoria del box es del VM y su liberacion es idempotente).
        if (native_poo_ && sem_type.gc_managed) {
            ir::IrInstr ur{};
            ur.op = ir::IrOp::CALL;
            ur.type = ir::IrType::VOID;
            ur.dst = ir::IR_NO_VALUE;
            ur.func_name = "vx_gc_unregister_finalizer";
            ur.operands = {v};
            ur.is_call_site = true;
            ur.source_line = vd->loc.line;
            emit(current_block_, std::move(ur));
        }
    }
    // Limpiar pending_smartptr_deleter_ tras consumirlo (o si el
    // var-decl no era smart pointer pero hubo un unique_with previo
    // sin var-decl asociado, evitar contaminacion del siguiente).
    pending_smartptr_deleter_.clear();
}

/**
 * @brief Declara un struct dado por una lista de inicializacion.
 *
 * Cubre `Point p = {1, 2}` y `Point p = {.x=1, .y=2}`, que se escriben
 * distinto pero acaban igual: el struct se reserva en memoria del anfitrion y
 * cada campo se escribe en su desplazamiento.  Lo unico que cambia es de
 * donde sale el valor de cada campo -- de la posicion o del nombre --, y que
 * en la forma con nombres un campo puede no aparecer, en cuyo caso toma el
 * valor por defecto que declare el struct.
 *
 * @param vd       La declaracion.
 * @param sem_type El tipo ya resuelto (alias aplicados).
 * @return @c true si era esta forma y quedo bajada.
 */
bool Lowering::try_lower_struct_init_list(ast::VarDeclStmt *vd,
                                          const Type &sem_type) {
    if (sem_type.kind != PrimitiveKind::STRUCT || !vd->init ||
        vd->init->kind != ast::NodeKind::InitListExpr)
        return false;
    auto *il = static_cast<ast::InitListExpr *>(vd->init.get());
    const auto &layouts = tc_.struct_layouts();
    auto it_l = layouts.find(sem_type.struct_name);
    if (it_l == layouts.end()) {
        error_at(vd->loc,
                 "lowering: struct '" + sem_type.struct_name + "' sin layout");
        return true;
    }
    const StructLayout &lay = it_l->second;
    ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
    ir::IrInstr al{};
    al.op = ir::IrOp::ALLOCA;
    al.type = ir::IrType::I8;
    al.dst = addr;
    al.imm = (uint64_t)lay.size_bytes;
    // Host SIEMPRE: ver el comentario extenso de la rama sin init-list.
    al.host_alloca = true;
    fn_->values[addr].is_host_ptr = true;
    al.source_line = vd->loc.line;
    emit(current_block_, std::move(al));
    // Seguridad: zero-inicializar TODO el struct antes de escribir los
    // campos listados.  Asi los campos NO presentes en el init-list quedan
    // a 0 (no basura de la pila).  Subsume el zero de los bit fields.
    emit_zero_fill(addr, (uint64_t)lay.size_bytes, vd->loc.line);
    // Valores por defecto de los campos (`u8 a = 0x10`); el init-list
    // explicito de abajo sobrescribe los campos que liste.
    emit_struct_field_defaults(addr, lay, vd->loc.line);
    // @Virtual: fijar el vptr del struct polimorfico a su vtable (tras el
    // zero_fill; el init-list solo escribe campos, no el vptr en offset 0).
    if (lay.is_polymorphic) emit_struct_vptr_init(addr, lay, vd->loc.line);
    // Zero los storage words de bit fields antes del
    // loop para evitar que el RMW lea basura del ALLOCA.  Los
    // unique (offset, size) ya estan en lay.fields para bit
    // fields; emit STORE 0 una sola vez por word.
    std::set<std::pair<uint32_t, uint32_t>> zeroed_bf;
    for (const auto &f : lay.fields) {
        if (f.bit_width == 0) continue;
        auto key = std::make_pair(f.offset, f.size);
        if (!zeroed_bf.insert(key).second) continue;
        ir::IrType ft_zero = ir_type_from_primitive(f.type.kind);
        ir::IrValueId v_zero = emit_const(ft_zero, 0, vd->loc.line);
        ir::IrValueId v_addr_w = addr;
        if (f.offset > 0) {
            ir::IrValueId v_off =
                emit_const(ir::IrType::I64, (uint64_t)f.offset, vd->loc.line);
            v_addr_w = emit_ptr_add(addr, v_off, vd->loc.line);
        }
        emit_store_typed(v_addr_w, v_zero, ft_zero, vd->loc.line);
    }
    for (size_t i = 0; i < il->elements.size(); ++i) {
        const StructFieldInfo *fi = nullptr;
        if (il->is_designated) {
            const std::string &fname = il->field_names[i];
            fi = find_field(lay, fname);
            if (!fi) {
                error_at(vd->loc, "lowering: campo '" + fname + "' no existe");
                continue;
            }
        } else {
            if (i >= lay.fields.size()) {
                error_at(vd->loc, "lowering: init list excede campos");
                break;
            }
            fi = &lay.fields[i];
        }
        // Campo STRUCT inicializado con un init-list ANIDADO
        // (`{.min = {.x=.., .y=..}}` o `{.min = Punto{...}}`): se rellena
        // RECURSIVAMENTE in-place en la direccion del campo.  lower_expr no
        // baja un InitListExpr como valor -> hay que tratarlo aqui.
        if (fi->type.kind == PrimitiveKind::STRUCT &&
            il->elements[i]->kind == ast::NodeKind::InitListExpr) {
            ir::IrValueId v_faddr = addr;
            if (fi->offset > 0) {
                ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, (uint64_t)fi->offset, vd->loc.line);
                v_faddr = emit_ptr_add(addr, v_off, vd->loc.line);
            }
            auto it_sl = tc_.struct_layouts().find(fi->type.struct_name);
            if (it_sl == tc_.struct_layouts().end()) {
                error_at(vd->loc, "lowering: struct '" + fi->type.struct_name +
                                      "' sin layout (init anidado)");
                continue;
            }
            emit_struct_init_fields(
                v_faddr, it_sl->second,
                static_cast<ast::InitListExpr *>(il->elements[i].get()),
                vd->loc.line);
            continue;
        }
        ir::IrValueId v_val = lower_expr(il->elements[i].get());
        if (v_val == ir::IR_NO_VALUE) continue;
        const ir::IrType ir_ft = ir_type_from_primitive(fi->type.kind);
        const bool elem_is_literal =
            il->elements[i]->kind == ast::NodeKind::IntLitExpr ||
            il->elements[i]->kind == ast::NodeKind::FloatLitExpr ||
            il->elements[i]->kind == ast::NodeKind::BoolLitExpr ||
            il->elements[i]->kind == ast::NodeKind::CharLitExpr ||
            il->elements[i]->kind == ast::NodeKind::NullLitExpr;
        v_val =
            cast_if_needed(v_val, fn_->values[v_val].type, ir_ft, vd->loc.line,
                           /*is_explicit=*/elem_is_literal);
        ir::IrValueId v_addr = addr;
        if (fi->offset > 0) {
            ir::IrValueId v_off =
                emit_const(ir::IrType::I64, (uint64_t)fi->offset, vd->loc.line);
            v_addr = emit_ptr_add(addr, v_off, vd->loc.line);
        }
        // Campo AGREGADO inline (struct/array value-type): @c v_val es la
        // DIRECCION del agregado origen -> copia memberwise (qword a
        // qword) sus bytes al campo, NO un STORE escalar (que guardaria la
        // direccion origen).  Sin esto un `Outer o = {.w = inner}`
        // guardaba &inner en o.w y leer o.w.v devolvia la direccion
        // (bug struct-en-struct, value-type anidado).
        // Un campo de tipo `@overlay struct` NO es un agregado inline:
        // guarda el HANDLE de la vista (8 bytes) -> STORE escalar (abajo).
        if ((fi->type.kind == PrimitiveKind::STRUCT &&
             !type_is_overlay(fi->type)) ||
            fi->type.kind == PrimitiveKind::ARRAY) {
            uint64_t sz = size_of_type(fi->type);
            if (sz == 0 && fi->type.kind == PrimitiveKind::STRUCT) {
                auto it_sl = tc_.struct_layouts().find(fi->type.struct_name);
                if (it_sl != tc_.struct_layouts().end())
                    sz = (uint64_t)it_sl->second.size_bytes;
            }
            if (sz == 0) sz = 8;
            emit_memberwise_copy(v_addr, v_val, sz, vd->loc.line);
            if (fi->type.kind == PrimitiveKind::STRUCT) {
                auto it_sl = tc_.struct_layouts().find(fi->type.struct_name);
                if (it_sl != tc_.struct_layouts().end() &&
                    it_sl->second.has_copy_hook) {
                    emit_struct_method_on_host_field(
                        v_addr, fi->type.struct_name,
                        fi->type.struct_name + "____clone__", vd->loc.line);
                }
            }
            continue;
        }
        // Bit field en init list: read-modify-write.
        // El ALLOCA inicial deja basura; debemos LOAD el storage
        // word actual, limpiar los bits del rango con AND ~mask,
        // OR con (val<<offset), STORE.  Igual que en lower_assign
        // para bit fields.
        if (fi->bit_width > 0) {
            ir::IrValueId v_old = emit_load_typed(v_addr, ir_ft, vd->loc.line);
            const uint64_t mask = (fi->bit_width == 64)
                                      ? UINT64_MAX
                                      : ((uint64_t(1) << fi->bit_width) - 1);
            const uint64_t inv_mask = ~(mask << fi->bit_offset);
            ir::IrValueId v_inv = emit_const(ir_ft, inv_mask, vd->loc.line);
            ir::IrValueId v_clr = fn_->new_value(ir_ft);
            {
                ir::IrInstr an{};
                an.op = ir::IrOp::AND;
                an.type = ir_ft;
                an.dst = v_clr;
                an.operands = {v_old, v_inv};
                an.source_line = vd->loc.line;
                emit(current_block_, std::move(an));
            }
            ir::IrValueId v_msk = emit_const(ir_ft, mask, vd->loc.line);
            ir::IrValueId v_tr = fn_->new_value(ir_ft);
            {
                ir::IrInstr an{};
                an.op = ir::IrOp::AND;
                an.type = ir_ft;
                an.dst = v_tr;
                an.operands = {v_val, v_msk};
                an.source_line = vd->loc.line;
                emit(current_block_, std::move(an));
            }
            ir::IrValueId v_sh = v_tr;
            if (fi->bit_offset > 0) {
                ir::IrValueId v_amt =
                    emit_const(ir_ft, (uint64_t)fi->bit_offset, vd->loc.line);
                v_sh = fn_->new_value(ir_ft);
                ir::IrInstr sh{};
                sh.op = ir::IrOp::SHL;
                sh.type = ir_ft;
                sh.dst = v_sh;
                sh.operands = {v_tr, v_amt};
                sh.source_line = vd->loc.line;
                emit(current_block_, std::move(sh));
            }
            ir::IrValueId v_new = fn_->new_value(ir_ft);
            {
                ir::IrInstr or_{};
                or_.op = ir::IrOp::OR;
                or_.type = ir_ft;
                or_.dst = v_new;
                or_.operands = {v_clr, v_sh};
                or_.source_line = vd->loc.line;
                emit(current_block_, std::move(or_));
            }
            emit_store_typed(v_addr, v_new, ir_ft, vd->loc.line);
            continue;
        }
        emit_store_typed(v_addr, v_val, ir_ft, vd->loc.line);
    }
    bind(vd->name, addr);
    return true;
}

/**
 * @brief Declara una variable de tipo struct (o enum, que comparte camino).
 *
 * Reserva el hueco en memoria del anfitrion -- en los tres modos, porque el
 * callee solo recibe una direccion y no sabria si lo que hay detras es de la
 * pila de la maquina o del anfitrion -- y ata el nombre a esa direccion.  Los
 * campos se acceden despues como base + desplazamiento.
 *
 * El hueco se pone a cero antes de escribir nada: la pila trae lo que hubiera,
 * y un campo sin valor declarado se quedaria con esa basura.  Si el struct
 * tiene destructor o guarda punteros con dueno, aqui se apunta ademas la
 * limpieza que toca al salir del ambito.
 *
 * @param vd       La declaracion.
 * @param sem_type El tipo ya resuelto (alias aplicados).
 * @return @c true si era un struct y quedo bajado.
 */
bool Lowering::try_lower_struct_var(ast::VarDeclStmt *vd,
                                    const Type &sem_type) {
    if (sem_type.kind != PrimitiveKind::STRUCT) return false;
    const auto &layouts = tc_.struct_layouts();
    auto it = layouts.find(sem_type.struct_name);
    // ADTs: si NO esta en struct_layouts, puede ser un enum
    // (compartimos PrimitiveKind::STRUCT para reusar el camino
    // de value-type).  Buscar en enum_layouts_ y alocar slot
    // de @c size_bytes (8 + 8*max_payload_fields).
    if (it == layouts.end()) {
        const auto &elays = tc_.enum_layouts();
        auto ite = elays.find(sem_type.struct_name);
        if (ite != elays.end()) {
            const EnumLayout &elay = ite->second;
            const ir::IrValueId eaddr = fn_->new_value(ir::IrType::PTR);
            ir::IrInstr eal{};
            eal.op = ir::IrOp::ALLOCA;
            eal.type = ir::IrType::I8;
            eal.dst = eaddr;
            eal.imm = static_cast<uint64_t>(elay.size_bytes);
            // Todo agregado (struct Y enum) vive en memoria HOST en los
            // tres modos.  Ver la rama STRUCT: si unos acaban en host y
            // otros en la pila VM, el callee -- que solo recibe una
            // direccion -- lee unos u otros como basura.
            eal.host_alloca = true;
            eal.source_line = vd->loc.line;
            emit(current_block_, std::move(eal));
            fn_->values[eaddr].is_host_ptr = true;
            // La variable es un value-type: se bindea a un SLOT ESTABLE
            // (@c eaddr, ALLOCA en VM stack) y el inicializador se COPIA
            // qword-by-qword al slot -- MISMO modelo que un struct
            // (ver rama STRUCT abajo).  Antes se bindeaba la variable al
            // slot del constructor (repunte del puntero); eso rompia con
            // una asignacion condicional (`if { t = X }` / arm de match):
            // el var-decl apuntaba a un slot (p.ej. GC-host) y el assign
            // a otro (ALLOCA VM), un PHI mezclaba punteros de naturaleza
            // distinta y el LOAD del tag del `match t` usaba movh sobre
            // una direccion VM -> SIGSEGV.  Con el slot estable, `t`
            // tiene UNA sola direccion (VM) y el match lee siempre con mov.
            bind(vd->name, eaddr);
            if (vd->init) {
                const ir::IrValueId init_addr = lower_expr(vd->init.get());
                if (init_addr != ir::IR_NO_VALUE) {
                    emit_enum_copy(eaddr, init_addr,
                                   fn_->values[init_addr].is_host_ptr,
                                   elay.size_bytes, vd->loc.line);
                }
            }
            return true;
        }
        error_at(vd->loc, "lowering: struct/enum desconocido '" +
                              sem_type.struct_name + "'");
        return true;
    }
    const StructLayout &lay = it->second;
    // ALLOCA del IR reserva count * sizeof(T) bytes; pasamos
    // tipo i8 para que count sea exactamente size_bytes.  El
    // emisor lo traduce a 'subsp rsp, N' + 'readcur rDst'.
    const ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
    ir::IrInstr ins{};
    ins.op = ir::IrOp::ALLOCA;
    ins.type = ir::IrType::I8; // unidad: 1 byte
    ins.dst = addr;
    ins.imm = (uint64_t)lay.size_bytes;
    ins.source_line = vd->loc.line;
    // AOT bare (native_poo_): NO hay VM stack -> el struct debe vivir
    // en la pila nativa (host_alloca).  Sin esto, un struct que
    // escapa (p.ej. se pasa por puntero a un metodo s.metodo()) se
    // aloca con ALLOCA_VM ([rbx+0x40]); el .exe standalone no tiene
    // ProcessVM en rbx -> SIGSEGV.
    //
    // Bug host-vs-VM (2026-07-15): tambien en interp/JIT cuando se toma
    // `&p`.  El comentario anterior daba por bueno que "los escapantes
    // usan VM stack que el runtime mapea", pero el consumidor del `P*`
    // resultante (param, campo o elemento) lo deref-ea con movh por la
    // convencion `T*`=host -> movh sobre direccion VM -> SIGSEGV.  Solo
    // pasaba inadvertido mientras el inliner borraba la llamada.  Un
    // struct que NO se address-takea se queda en la pila VM (y el
    // ir_optimizer ya lo promueve por perf si no escapa).
    // Host SIEMPRE, no solo en AOT ni solo si se toma la direccion.  Mismo
    // criterio (y mismo motivo) que el buffer de un `T[N]` local.
    //
    // Que fuera CONDICIONAL era el bug: cualquier cosa que marcara UN local
    // lo mandaba a host y dejaba al de al lado en la pila VM.  El callee no
    // puede distinguirlos -- recibe una direccion y punto -- asi que leia
    // uno de los dos como basura, con el otro funcionando (que es lo que lo
    // hacia dificil de ver).  Medido: dos structs y un metodo con arg ->
    // this=(0,0) y o=(1,2).  Con TODOS los agregados en host, caller y
    // callee coinciden siempre.  Memoria VM explicita = `VirtualPtr<T>`.
    ins.host_alloca = true;
    const bool struct_is_host = ins.host_alloca;
    emit(current_block_, std::move(ins));
    if (struct_is_host) fn_->values[addr].is_host_ptr = true;
    bind(vd->name, addr);
    // Seguridad + RAII: zero-inicializar SIEMPRE el buffer del struct.  Un
    // struct local en pila NO se zeroea solo (a diferencia de un objeto
    // GC); sin esto, (a) los campos no asignados exponen basura de la pila
    // (seguridad), y (b) un campo shared/unique/closure sin asignar tendria
    // un ctrl/slot basura y su dtor haria free de basura (UAF).  El
    // init-list / copy posterior sobrescribe los campos que toque.
    emit_zero_fill(addr, (uint64_t)lay.size_bytes, vd->loc.line);
    // Declaracion sin init (`P p;`): aplicar los valores por defecto de los
    // campos.  Si hay init (copia de otro struct/llamada) el copy de abajo
    // sobrescribe todo, asi que los defaults solo aplican sin init.
    if (!vd->init) emit_struct_field_defaults(addr, lay, vd->loc.line);
    // @Virtual: un struct polimorfico recien construido apunta su vptr
    // (offset 0) a la vtable de SU tipo declarado.  Va tras el zero_fill
    // (que dejo el vptr en 0) y los defaults.  Para `Derivado d;` fija
    // vptr=vtable_Derivado, de modo que un dispatch posterior por `Base*`
    // resuelve al metodo del derivado (dispatch dinamico correcto).
    if (lay.is_polymorphic && !vd->init)
        emit_struct_vptr_init(addr, lay, vd->loc.line);
    // Ownership ruta B (copy-hook): `S b = a;` donde S declara `__clone__`
    // y `a` es un lvalue struct existente (IdentExpr) es una COPIA.  Modelo
    // (estilo Rust Clone): memcpy bit a bit a->b (abajo) y DESPUES
    // `b.__clone__()` (CALL <S>____clone__(b)) que aplica el efecto sobre
    // la copia (p.ej. ++refcount de su recurso).  Opera sobre `this`=b
    // (misma memory class que cualquier metodo de struct -> sin mismatch
    // host/VM). `S b = move(a)` o `S b = call()` (valor
    // fresco/transferencia) NO entran.
    const bool do_copy_hook =
        vd->init && vd->init->kind == ast::NodeKind::IdentExpr &&
        lay.has_copy_hook &&
        escaping_locals_.find(vd->name) == escaping_locals_.end();
    // B3 fix: si hay inicializador, lower-lo como PTR al struct
    // origen y copiar qword-by-qword al slot ALLOCA recien creado.
    // Soporta:
    //   - Call result: `Punto v = funcion_que_devuelve_struct(...)`
    //   - read_borrow: `Punto v = read_borrow(b)` (B2 pass-through)
    //   - Otros SSA values PTR a struct.
    // El init list (que SI estaba soportado) se maneja en la rama
    // de mas arriba antes de llegar aqui (linea 1837).
    if (vd->init) {
        const ir::IrValueId v_src = lower_expr(vd->init.get());
        if (v_src != ir::IR_NO_VALUE) {
            // Heredar is_host_ptr del source para los LOADs.  Si
            // el src viene de read_borrow / ptr_of (unique), es
            // host_ptr; si viene de un struct stack ALLOCA es VM.
            const bool src_is_host = fn_->values[v_src].is_host_ptr;
            // Copia qword-by-qword (size_bytes redondeado a 8).
            const uint64_t qwords = (lay.size_bytes + 7) / 8;
            for (uint64_t qi = 0; qi < qwords; ++qi) {
                const uint64_t off = qi * 8;
                const ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, static_cast<int64_t>(off), vd->loc.line);
                // src + off
                const ir::IrValueId v_src_at = fn_->new_value(ir::IrType::PTR);
                fn_->values[v_src_at].is_host_ptr = src_is_host;
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = v_src_at;
                    ad.operands = {v_src, v_off};
                    ad.source_line = vd->loc.line;
                    emit(current_block_, std::move(ad));
                }
                // LOAD i64 from src+off
                const ir::IrValueId v_word = fn_->new_value(ir::IrType::I64);
                {
                    ir::IrInstr ld{};
                    ld.op = ir::IrOp::LOAD;
                    ld.type = ir::IrType::I64;
                    ld.dst = v_word;
                    ld.operands = {v_src_at};
                    ld.source_line = vd->loc.line;
                    emit(current_block_, std::move(ld));
                }
                // dst slot + off.  Su naturaleza se HEREDA del slot: dar
                // por hecho que es VM hacia que la copia escribiera con
                // `mov` sobre una direccion host -> el struct se quedaba a
                // ceros (y su copy-hook/dtor operaban sobre basura).
                const ir::IrValueId v_dst_at = fn_->new_value(ir::IrType::PTR);
                fn_->values[v_dst_at].is_host_ptr =
                    fn_->values[addr].is_host_ptr;
                {
                    ir::IrInstr ad{};
                    ad.op = ir::IrOp::ADD;
                    ad.type = ir::IrType::I64;
                    ad.dst = v_dst_at;
                    ad.operands = {addr, v_off};
                    ad.source_line = vd->loc.line;
                    emit(current_block_, std::move(ad));
                }
                // STORE i64 [dst+off] = word
                emit_store_typed(v_dst_at, v_word, ir::IrType::I64,
                                 vd->loc.line);
            }
        }
    }
    // Copy-hook: tras el memcpy, `b.__clone__()` aplica el efecto de copia
    // sobre la nueva copia (this = addr = b).
    if (do_copy_hook) {
        ir::IrInstr cc{};
        cc.op = ir::IrOp::CALL;
        cc.type = ir::IrType::VOID;
        cc.dst = ir::IR_NO_VALUE;
        cc.operands = {addr}; // this = b (la copia)
        cc.func_name = sem_type.struct_name + "__" + "__clone__";
        cc.source_line = vd->loc.line;
        emit(current_block_, std::move(cc));
    }
    // Fase 2a interop C / ownership: destructor automatico (RAII) del
    // struct value-type local con `~Struct()` declarado y que NO escapa.
    // CALL directo a <Struct>__dtor(addr) al exit del scope (dispatch
    // estatico, sin vtable; inlineable -> un dtor trivial cuesta ~0).  Si
    // el struct ESCAPA (return/store -> escaping_locals_), se SUPRIME el
    // cleanup: move-on-return (el caller re-registra el dtor de su copia
    // -> un solo free).  Cero overhead para structs sin `~Struct()`.
    if (escaping_locals_.find(vd->name) == escaping_locals_.end()) {
        bool has_dtor = false;
        for (const auto &mi : lay.methods)
            if (mi.is_destructor) {
                has_dtor = true;
                break;
            }
        if (has_dtor) {
            CleanupAction act;
            act.kind = CleanupAction::Kind::STRUCT_DTOR;
            act.operands = {addr};
            act.source_line = vd->loc.line;
            act.refresh_name = vd->name;
            // Naming de lower_struct_methods: <Struct>__ + __dtor.
            act.func_name = sem_type.struct_name + "__" + "__dtor";
            cleanup_stack_.push_back(std::move(act));
        }
        // Ownership escape-sensitive: si el struct tiene campos closure
        // (lambda con captura) y su valor llega POR MOVE desde una call
        // (init = CallExpr) que retorna un struct con closure escapado, su
        // env vive en HEAP y este consumidor es el unico responsable de
        // liberarlo al exit del scope (el productor suprimio su cleanup via
        // escaping_locals_ al hacer return).  Registramos CLOSURE_ENV_FREE
        // con los offsets de los campos fn.  El caso local-no-escapa NO
        // entra aqui (su env vive en stack, sin liberacion).
        if (vd->init && vd->init->kind == ast::NodeKind::CallExpr) {
            std::vector<uint32_t> fn_offs;
            for (const auto &f : lay.fields)
                if (f.type.kind == PrimitiveKind::FUNCTION && !f.type.fn_is_raw)
                    fn_offs.push_back(f.offset);
            if (!fn_offs.empty()) {
                CleanupAction act;
                act.kind = CleanupAction::Kind::CLOSURE_ENV_FREE;
                act.operands = {addr};
                act.source_line = vd->loc.line;
                act.refresh_name = vd->name;
                act.closure_field_offsets = std::move(fn_offs);
                cleanup_stack_.push_back(std::move(act));
            }
        }
    }
    return true;
}

/**
 * @brief Declara una variable de tipo array nativo `T[N]`.
 *
 * Desde el lowering un array es lo mismo que un struct: un hueco contiguo y un
 * nombre atado a su direccion base, con `arr[i]` resuelto luego como base mas
 * i por el tamano del elemento.  Lo que cambia es de donde salen los bytes
 * iniciales, y hay tres formas:
 *
 *   - de un literal de cadena (`u8[N] s = "hola"`), que se escribe byte a byte
 *     sin promoverlo a objeto cadena, porque esto es memoria cruda sin GC; si
 *     el texto no cabe es un error, y si sobra hueco el resto queda a cero;
 *   - de una lista (`i32 v[3] = {1, 2, 3}`), solo posicional -- un array no
 *     tiene nombres de campo que designar;
 *   - sin inicializador, que reserva y pone a cero.
 *
 * @param vd       La declaracion.
 * @param sem_type El tipo ya resuelto (alias aplicados).
 * @return @c true si era un array y quedo bajado.
 */
bool Lowering::try_lower_array_var(ast::VarDeclStmt *vd, const Type &sem_type) {
    if (sem_type.kind != PrimitiveKind::ARRAY) return false;
    // C-style string init para arrays byte-like: `u8[N] arr = "literal"`.
    // Detecta el patron y emite STOREs byte-a-byte del contenido del
    // string literal, con zerificacion del resto si N > strlen.  Si
    // strlen > N reporta error (truncation, comportamiento C).
    // No se promueve el literal a StringObject (es array de bytes
    // crudo, sin GC).  Aceptamos solo literales no interpolados.
    if (vd->init && vd->init->kind == ast::NodeKind::StringLitExpr &&
        sem_type.pointee &&
        (sem_type.pointee->kind == PrimitiveKind::U8 ||
         sem_type.pointee->kind == PrimitiveKind::I8 ||
         sem_type.pointee->kind == PrimitiveKind::CHAR)) {
        auto *sl = static_cast<ast::StringLitExpr *>(vd->init.get());
        if (sl->is_interpolated()) {
            error_at(vd->loc,
                     "init de array con string no acepta interpolacion");
            return true;
        }
        const std::string &bytes = sl->value;
        const uint32_t str_n = (uint32_t)bytes.size();
        const uint32_t arr_n =
            sem_type.array_size > 0 ? (uint32_t)sem_type.array_size : str_n;
        if (str_n > arr_n) {
            error_at(vd->loc, "literal de string (" + std::to_string(str_n) +
                                  " bytes) mas grande que el array (" +
                                  std::to_string(arr_n) + ")");
            return true;
        }
        const Type elem_t = *sem_type.pointee;
        const ir::IrType ir_elem = ir_type_from_primitive(elem_t.kind);
        const uint32_t elem_sz = (uint32_t)primitive_size_bytes(elem_t.kind);
        // ALLOCA del array (siempre arr_n elementos).
        ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
        {
            ir::IrInstr al{};
            al.op = ir::IrOp::ALLOCA;
            al.type = ir::IrType::I8;
            al.dst = addr;
            al.imm = (uint64_t)arr_n * elem_sz;
            al.source_line = vd->loc.line;
            /* Buffer HOST: ver la nota de las otras rutas de array local. */
            al.host_alloca = true;
            fn_->values[addr].is_host_ptr = true;
            emit(current_block_, std::move(al));
        }
        // STORE byte-a-byte del string.
        for (uint32_t i = 0; i < str_n; ++i) {
            ir::IrValueId v_val =
                emit_const(ir_elem, (uint64_t)(uint8_t)bytes[i], vd->loc.line);
            ir::IrValueId v_addr_i = addr;
            if (i > 0) {
                ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, (uint64_t)i * elem_sz, vd->loc.line);
                v_addr_i = emit_ptr_add(addr, v_off, vd->loc.line);
            }
            emit_store_typed(v_addr_i, v_val, ir_elem, vd->loc.line);
        }
        // Zerificar el resto (semantica C: padding a cero).
        for (uint32_t i = str_n; i < arr_n; ++i) {
            ir::IrValueId v_zero = emit_const(ir_elem, 0, vd->loc.line);
            ir::IrValueId v_off = emit_const(
                ir::IrType::I64, (uint64_t)i * elem_sz, vd->loc.line);
            ir::IrValueId v_addr_i = emit_ptr_add(addr, v_off, vd->loc.line);
            emit_store_typed(v_addr_i, v_zero, ir_elem, vd->loc.line);
        }
        bind(vd->name, addr);
        return true;
    }

    // Array init C-style: `i32 arr[N] = {e0, e1, ...};`.
    // Detectamos InitListExpr en el inicializador y emitimos:
    //   ALLOCA del array (igual que sin init).
    //   Por cada elemento: STORE val a (base + i * sizeof(T)).
    //   bind nombre al PTR base.
    // Solo positional (sin .field=); reportamos error si is_designated.
    if (vd->init && vd->init->kind == ast::NodeKind::InitListExpr) {
        auto *il = static_cast<ast::InitListExpr *>(vd->init.get());
        if (il->is_designated) {
            error_at(vd->loc,
                     "lowering: init designado '.field=' no aplica a arrays");
            return true;
        }
        const Type elem_t = sem_type.pointee ? *sem_type.pointee : Type{};
        const uint32_t elem_sz = (uint32_t)primitive_size_bytes(elem_t.kind);
        if (elem_sz == 0) {
            error_at(vd->loc, "lowering: tipo del elemento sin sizeof");
            return true;
        }
        const uint32_t arr_size = sem_type.array_size > 0
                                      ? (uint32_t)sem_type.array_size
                                      : (uint32_t)il->elements.size();
        if (il->elements.size() > arr_size) {
            error_at(vd->loc, "lowering: init list mas elementos que el array");
            return true;
        }
        // ALLOCA arr_size * elem_sz bytes.
        ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr al{};
        al.op = ir::IrOp::ALLOCA;
        al.type = ir::IrType::I8;
        al.dst = addr;
        al.imm = (uint64_t)arr_size * elem_sz;
        al.source_line = vd->loc.line;
        /* El buffer va a memoria HOST, igual que el de un array local SIN
         * inicializador (ver la otra rama y su nota de 2026-07-15).  Este
         * camino -- el de `T[N] a = {...}` -- se quedo sin marcar, asi que el
         * array acababa en la pila de la VM mientras todo lo que lo consume
         * (`a` decaido a `T*`, `&a[i]`, la funcion que lo recibe) emitia
         * accesos de HOST.  Leer una direccion VM como si fuera host mata el
         * proceso, y solo se notaba al RECORRERLO con indice variable: con
         * indices constantes el optimizador resolvia los accesos antes. */
        al.host_alloca = true;
        fn_->values[addr].is_host_ptr = true;
        emit(current_block_, std::move(al));
        // STORE de cada elemento.
        const ir::IrType ir_elem = ir_type_from_primitive(elem_t.kind);
        for (size_t i = 0; i < il->elements.size(); ++i) {
            ir::IrValueId v_val = lower_expr(il->elements[i].get());
            if (v_val == ir::IR_NO_VALUE) continue;
            // Suprimir warning de narrowing si el elemento es literal
            // (`{10, 20, ...}` con i64-defaulted literals encajando en
            // el tipo de elemento).  Mismo razonamiento que en
            // var-decl con init literal.
            const bool elem_is_literal =
                il->elements[i]->kind == ast::NodeKind::IntLitExpr ||
                il->elements[i]->kind == ast::NodeKind::FloatLitExpr ||
                il->elements[i]->kind == ast::NodeKind::BoolLitExpr ||
                il->elements[i]->kind == ast::NodeKind::CharLitExpr ||
                il->elements[i]->kind == ast::NodeKind::NullLitExpr;
            v_val = cast_if_needed(v_val, fn_->values[v_val].type, ir_elem,
                                   vd->loc.line,
                                   /*is_explicit=*/elem_is_literal);
            ir::IrValueId v_addr_i = addr;
            if (i > 0) {
                ir::IrValueId v_off = emit_const(
                    ir::IrType::I64, (uint64_t)(i * elem_sz), vd->loc.line);
                v_addr_i = emit_ptr_add(addr, v_off, vd->loc.line);
            }
            emit_store_typed(v_addr_i, v_val, ir_elem, vd->loc.line);
        }
        bind(vd->name, addr);
        return true;
    }

    // Array nativo T[N]: identico a struct desde la optica del lowering.
    // Reservamos N*sizeof(T) bytes en stack y guardamos la direccion base
    // como "valor" de la variable.  Los accesos arr[i] se desugan a
    // ADD(addr, i*sizeof(T)) + LOAD/STORE igual que para T*; el tipo del
    // pointee se obtiene del propio sem_type para escalar el offset.
    {
        // bug4: array dinamico `T[]` con init `new T[N]` o assigned
        // desde otro host_ptr.  El slot guarda el host_ptr al buffer
        // alocado en heap.  Cuando array_size == 0 y hay init, bindeo
        // el local al SSA value del init (host_ptr) sin ALLOCA stack.
        if (!sem_type.pointee || sem_type.array_size == 0) {
            if (vd->init) {
                const ir::IrValueId v_init = lower_expr(vd->init.get());
                if (v_init != ir::IR_NO_VALUE) {
                    // Mark is_host_ptr para que LOAD/STORE indirectos
                    // emitan movh.  El IR del new T[N] ya lo marca.
                    bind(vd->name, v_init);
                    return true;
                }
            }
            error_at(
                vd->loc,
                "lowering: array sin tamano fijo requiere init con `new T[N]`");
            return true;
        }
        const size_t bytes = size_of_type(sem_type);
        if (bytes == 0) {
            error_at(vd->loc, "lowering: tamano del array es 0 (tipo de "
                              "elemento desconocido?)");
            return true;
        }
        const ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr ins{};
        ins.op = ir::IrOp::ALLOCA;
        ins.type = ir::IrType::I8;
        ins.dst = addr;
        ins.imm = (uint64_t)bytes;
        ins.source_line = vd->loc.line;
        // Bug host-vs-VM (2026-07-15): el buffer de un `T[N]` local va SIEMPRE
        // a memoria host, no solo en AOT.  Su tipo es un array NO virtual (ver
        // @c type_from_node), asi que `arr` decaido a `T[]`/`T*` y `&arr[i]`
        // son direcciones host y sus consumidores emiten movh.  Cuando el
        // buffer se quedaba en la pila VM (interp/JIT) las dos rutas
        // discrepaban: `sum_array(arr, n)` leia el array con movh sobre una
        // direccion VM.  Un array VM explicito se nombra con `VirtualPtr<T>`.
        ins.host_alloca = true;
        emit(current_block_, std::move(ins));
        fn_->values[addr].is_host_ptr = true;
        bind(vd->name, addr);
        // Zero-inicializar SIEMPRE el buffer del array local (mismo motivo que
        // los structs, ~L4415): un array en pila NO se zeroea solo.  El interp
        // daba 0 solo porque su VM stack esta a cero; el JIT (pila HOST) leia
        // basura -> DIVERGENCIA interp/JIT (un `i32[N] a` leido sin escribir, o
        // `a[i]++` sobre un elemento no inicializado, daba garbage en JIT).
        // Ademas es seguridad: sin esto el array expone basura de la pila.
        emit_zero_fill(addr, (uint64_t)bytes, vd->loc.line);
        if (vd->init) {
            error_at(vd->loc, "lowering: inicializador de array aun no "
                              "soportado en esta ruta");
        }
    }
    return true;
}

/**
 * @brief Baja el valor con el que arranca una variable.
 *
 * De aqui sale el valor que se ata al nombre, pero varias formas no dejan un
 * valor que atar: trasladar la propiedad de un puntero con dueno mueve el
 * contenido y no produce nada nuevo, y una funcion que devuelve un agregado lo
 * escribe en el hueco de la variable en vez de devolverlo.  Esas terminan la
 * declaracion aqui mismo.
 *
 * Sin inicializador el valor es CERO, y no es un capricho: una variable con la
 * basura que hubiera en la pila se lee distinto cada vez que se ejecuta.
 *
 * @param vd       La declaracion.
 * @param sem_type El tipo ya resuelto.
 * @param vt       Ese tipo, en el vocabulario del IR.
 * @param v        Donde dejar el valor inicial.
 * @return @c true si la declaracion quedo bajada ENTERA; @c false si lo unico
 *         que falta es atar @p v al nombre.
 */
bool Lowering::try_lower_var_init(ast::VarDeclStmt *vd, const Type &sem_type,
                                  ir::IrType vt, ir::IrValueId &v) {
    v = ir::IR_NO_VALUE;
    if (vd->init) {
        // ----- Smart pointer move: unique/shared = move(p) -----
        // Patron especial: si el tipo destino es unique<T>/shared<T>
        // y el init es CallExpr(IdentExpr("move"), [p]), transferimos
        // ownership via mvtake (1 instr VM: copia + zero source).
        //
        // Lowering:
        //   1. lower p -> v_src_slot (SSA value que es la direccion
        //                            del slot stack del origen).
        //   2. ALLOCA 8 bytes -> v_dst_slot.
        //   3. Emit `mvtake [dst], [src]` via RAW_ASM.
        //   4. Marcar pointee_is_host_ptr en v_dst_slot.
        //
        // El cleanup del origen (registrado al declarar p) seguira
        // ejecutandose al exit del scope; vera 0 en el slot (zerificado
        // por mvtake) y RAW_FREE(0) sera no-op limpio.
        if ((sem_type.kind == PrimitiveKind::UNIQUE_PTR ||
             sem_type.kind == PrimitiveKind::SHARED_PTR) &&
            vd->init->kind == ast::NodeKind::CallExpr) {
            auto *ce = static_cast<ast::CallExpr *>(vd->init.get());
            if (ce->callee && ce->callee->kind == ast::NodeKind::IdentExpr &&
                ce->args.size() == 1) {
                auto *cid = static_cast<ast::IdentExpr *>(ce->callee.get());
                if (cid->name == "move") {
                    const ir::IrValueId v_src = lower_expr(ce->args[0].get());
                    if (v_src != ir::IR_NO_VALUE) {
                        const uint32_t slot_bytes = static_cast<uint32_t>(
                            smart_ptr_slot_bytes(sem_type.kind));
                        // ALLOCA para el slot destino.
                        const ir::IrValueId v_dst =
                            fn_->new_value(ir::IrType::PTR);
                        {
                            ir::IrInstr al{};
                            al.op = ir::IrOp::ALLOCA;
                            al.type = ir::IrType::I8;
                            al.dst = v_dst;
                            al.imm = slot_bytes;
                            al.source_line = vd->loc.line;
                            emit(current_block_, std::move(al));
                        }
                        // Emit mvtake [v_dst+0], [v_src+0] (ptr).
                        // Para unique<T> tambien emit mvtake [v_dst+8],
                        // [v_src+8] (deleter).
                        emit_mvtake(v_dst, v_src, vd->loc.line);
                        if (slot_bytes == 16) {
                            // Segundo qword: deleter.  Calculamos los dos
                            // punteros +8 y emitimos otro mvtake.
                            const ir::IrValueId v_eight =
                                emit_const(ir::IrType::I64, 8, vd->loc.line);
                            const ir::IrValueId v_dst8 =
                                fn_->new_value(ir::IrType::PTR);
                            const ir::IrValueId v_src8 =
                                fn_->new_value(ir::IrType::PTR);
                            {
                                ir::IrInstr add{};
                                add.op = ir::IrOp::ADD;
                                add.type = ir::IrType::I64;
                                add.dst = v_dst8;
                                add.operands = {v_dst, v_eight};
                                add.source_line = vd->loc.line;
                                emit(current_block_, std::move(add));
                            }
                            {
                                ir::IrInstr add{};
                                add.op = ir::IrOp::ADD;
                                add.type = ir::IrType::I64;
                                add.dst = v_src8;
                                add.operands = {v_src, v_eight};
                                add.source_line = vd->loc.line;
                                emit(current_block_, std::move(add));
                            }
                            emit_mvtake(v_dst8, v_src8, vd->loc.line);
                        }
                        fn_->values[v_dst].pointee_is_host_ptr = true;
                        v = v_dst;
                        return false; // el valor ya esta; solo falta atarlo
                    }
                }
            }
        }
        // Vesta Embed Inc 0: en modo native_poo_ (AOT) el tipo `string`
        // es VALUE-TYPE (struct {ptr,len,cap} de 24 bytes en stack,
        // HEAP-ALWAYS, RAII), NO un StringObject GC.  Dos casos:
        //   (a) `string s = "literal"`  -> construir el repr (ALLOCA +
        //       RAW_ALLOC + copia + nul + STOREs).
        //   (b) `string b = a`          -> MOVE: copiar los 24 bytes del
        //       slot de `a` al de `b` y ZERAR el ptr@0 del slot fuente
        //       (para que su cleanup sea no-op, sin doble-free).
        // El path Full/JIT/interp (sin native_poo_) NO entra aqui: cae a
        // la promocion StringObject GC de abajo.
        if (native_poo_ && sem_type.kind == PrimitiveKind::STRING && vd->init) {
            // Caso (a): literal NO interpolado (Inc 0 no cubre
            // interpolacion ni concat -- esos son Inc 1-4).
            if (vd->init->kind == ast::NodeKind::StringLitExpr) {
                auto *slit = static_cast<ast::StringLitExpr *>(vd->init.get());
                if (!slit->is_interpolated()) {
                    v = build_native_string_from_literal(slit, vd->loc.line);
                    bind(vd->name, v);
                    // Una cadena que sale de un literal no tiene buffer propio
                    // -- o cabe inline, o es una vista sobre .rodata -- asi que
                    // mientras nadie la reasigne no hay nada que liberar.
                    // Registrar la limpieza igualmente no era gratis: emite un
                    // `free`, y ESO es lo que hacia que cualquier programa con
                    // una cadena constante enlazara el asignador entero.
                    const bool puede_acabar_siendo_suyo =
                        reassigned_locals_.count(vd->name) != 0;
                    // RAII: liberar el buffer al exit del scope, salvo
                    // que el string escape (return/asignacion a campo).
                    if (puede_acabar_siendo_suyo &&
                        escaping_locals_.find(vd->name) ==
                            escaping_locals_.end()) {
                        CleanupAction act;
                        act.kind = CleanupAction::Kind::STRING_FREE;
                        act.operands = {v};
                        act.source_line = vd->loc.line;
                        act.refresh_name = vd->name;
                        cleanup_stack_.push_back(std::move(act));
                    }
                    return true;
                }
            }
            // Caso (b): MOVE desde otra variable string (IdentExpr).
            if (vd->init->kind == ast::NodeKind::IdentExpr &&
                vd->init->result_type.kind == PrimitiveKind::STRING) {
                const ir::IrValueId v_src = lower_expr(vd->init.get());
                if (v_src != ir::IR_NO_VALUE) {
                    // Nuevo slot de 24 bytes para `b` (host stack en native).
                    const ir::IrValueId v_slot =
                        fn_->new_value(ir::IrType::PTR);
                    if (native_poo_) fn_->values[v_slot].is_host_ptr = true;
                    {
                        ir::IrInstr al{};
                        al.op = ir::IrOp::ALLOCA;
                        al.type = ir::IrType::I8;
                        al.dst = v_slot;
                        al.imm = 24;
                        al.host_alloca = native_poo_;
                        al.source_line = vd->loc.line;
                        emit(current_block_, std::move(al));
                    }
                    // String Inc 5 (SSO): copiar los 24 bytes via MEMCPY
                    // (no 3 LOAD/STORE i64) -> evita el store-forwarding
                    // sobre qword2 que perdia la longitud SSO.
                    emit_native_str_move_copy(v_slot, v_src, vd->loc.line);
                    // Invalidar el slot fuente (move-out).  Inc 5 (SSO):
                    // si era HEAP -> ptr@0=0 (su cleanup hara free(0)=
                    // no-op; el buffer ahora lo posee `b`); si era SSO ->
                    // sin cambio (data inline, no hay buffer compartido).
                    emit_native_str_invalidate_moved(v_src, vd->loc.line);
                    bind(vd->name, v_slot);
                    // RAII para `b` (poseedor del buffer tras el move).
                    if (escaping_locals_.find(vd->name) ==
                        escaping_locals_.end()) {
                        CleanupAction act;
                        act.kind = CleanupAction::Kind::STRING_FREE;
                        act.operands = {v_slot};
                        act.source_line = vd->loc.line;
                        act.refresh_name = vd->name;
                        cleanup_stack_.push_back(std::move(act));
                    }
                    return true;
                }
            }
            // Caso (c): init es una EXPRESION que produce un value-string
            // owned (concat `a + b`, str_concat(a, b), o futuras ops Inc
            // 2+).  lower_expr devuelve el PTR al slot nativo.  Bind +
            // RAII STRING_FREE (el resultado de un concat es owned).
            {
                const ir::IrValueId v_slot = lower_expr(vd->init.get());
                if (v_slot != ir::IR_NO_VALUE) {
                    bind(vd->name, v_slot);
                    if (escaping_locals_.find(vd->name) ==
                        escaping_locals_.end()) {
                        CleanupAction act;
                        act.kind = CleanupAction::Kind::STRING_FREE;
                        act.operands = {v_slot};
                        act.source_line = vd->loc.line;
                        act.refresh_name = vd->name;
                        cleanup_stack_.push_back(std::move(act));
                    }
                    return true;
                }
            }
        }
        // Lazy promotion: si el tipo destino es STRING y el
        // init es un string literal puro (StringLitExpr), promover
        // a StringObject GC-managed via STRMAKE.  Asi `string s =
        // "hola"` aloca 1 vez; `print("hola")` (sin var-decl) sigue
        // sin alocar.
        if (sem_type.kind == PrimitiveKind::STRING && vd->init &&
            vd->init->kind == ast::NodeKind::StringLitExpr) {
            // Tanto literales puros como interpolados se promueven
            // a StringObject GC-managed; el helper detecta el caso
            // y emite STRMAKE simple o cadena de STRMAKE+STRCAT
            // segun corresponda.
            auto *slit = static_cast<ast::StringLitExpr *>(vd->init.get());
            v = lower_string_literal_to_string_object(slit);
            bind(vd->name, v);
            return true;
        }
        v = lower_expr(vd->init.get());
        if (v != ir::IR_NO_VALUE) {
            const ir::IrType vfrom = fn_->values[v].type;
            // Misma supresion de warning que en la rama
            // address-taken: literales no merecen alarma de
            // narrowing porque el valor es compile-time conocido.
            const bool init_is_literal =
                vd->init->kind == ast::NodeKind::IntLitExpr ||
                vd->init->kind == ast::NodeKind::FloatLitExpr ||
                vd->init->kind == ast::NodeKind::BoolLitExpr ||
                vd->init->kind == ast::NodeKind::CharLitExpr ||
                vd->init->kind == ast::NodeKind::NullLitExpr;
            v = cast_if_needed(v, vfrom, vt, vd->init->loc,
                               /*is_explicit=*/init_is_literal);
            /* `nonnull T x = expr;` -- hacer cumplir lo que el tipo promete.
             * Solo se rechazaba escribir `null` LITERAL; asignar una variable
             * o el resultado de una funcion que valiera nulo pasaba entero, y
             * el tipo quedaba mintiendo.  Un parametro `nonnull` ya se
             * comprobaba asi desde el principio -- lo que faltaba era la
             * variable --.  Lo normal es que no cueste nada: el pase que quita
             * comprobaciones de nulo demostrables la borra cuando el valor es
             * la direccion de algo, un objeto recien creado o una constante. */
            if (vd->type && vd->type->is_nonnull)
                v = enforce_nonnull(v, vd->init->loc.line);
        }
    } else {
        // Sin init: defecto 0.  Las variables sin init son raras
        // en uso normal pero el type checker no las prohibe.
        v = emit_const(vt, 0, vd->loc.line);
    }
    return false;
}

/**
 * @brief Declara una variable de la que alguien toma la direccion.
 *
 * Una variable normal es un valor SSA y nada mas -- vive donde el asignador
 * decida, incluso solo en un registro --.  Pero si en algun sitio aparece
 * `&x`, hay que poder dar una direccion, asi que se le reserva su hueco y lo
 * que el ambito guarda es la DIRECCION y no el valor: cada lectura y cada
 * escritura pasan por memoria.
 *
 * Se sabe antes de bajar nada porque el recorrido previo del cuerpo apunto que
 * nombres tienen su direccion tomada: cuando se ve el `&x` ya es tarde para
 * decidirlo -- los usos anteriores se habrian bajado como valor --.
 *
 * @param vd       La declaracion.
 * @param sem_type El tipo ya resuelto.
 * @param vt       Ese tipo, en el vocabulario del IR.
 * @return @c true si era una de estas y quedo bajada.
 */
bool Lowering::try_lower_address_taken_var(ast::VarDeclStmt *vd,
                                           const Type &sem_type,
                                           ir::IrType vt) {
    if (!address_taken_locals_.count(vd->name)) return false;
    {
        const size_t bytes =
            ir::type_access_bytes(vt); // tamano del tipo escalar
        const ir::IrValueId addr = fn_->new_value(ir::IrType::PTR);
        ir::IrInstr ai{};
        ai.op = ir::IrOp::ALLOCA;
        ai.type = ir::IrType::I8; // unidad: 1 byte
        ai.dst = addr;
        ai.imm = (uint64_t)bytes;
        // Bug host-vs-VM (2026-07-15): si se toma `&x`, el puntero resultante
        // es un `T*` y por convencion del lenguaje un `T*` es una direccion
        // HOST: el callee que reciba `T*`, o el campo/elemento `T*` donde se
        // guarde, lo deref-earan con movh.  Por tanto el slot debe vivir en
        // memoria host desde el principio.  Antes se quedaba en la pila VM y
        // solo "funcionaba" mientras el inliner o el store-to-load forwarding
        // borraban el deref; en cuanto el puntero cruzaba una frontera real
        // (callee no inlineado, o guardado en un struct/array y releido) se
        // hacia movh sobre una direccion VM -> SIGSEGV.
        //
        // Es el mismo criterio que @c ir_pass_promote_callned_allocas aplica a
        // los args de CALLN.  Se marca AQUI (y no en un pase del IR) porque
        // solo el lowering distingue un consumidor host (`T*`) de uno VM: los
        // structs de params de los opcodes meta viven en la pila VM y NO se
        // address-takean desde el codigo del usuario, asi que no se ven
        // afectados.  `VirtualPtr<T>` sigue siendo la via para memoria VM.
        ai.host_alloca = true;
        fn_->values[addr].is_host_ptr = true;
        ai.source_line = vd->loc.line;
        emit(current_block_, std::move(ai));
        bind(vd->name, addr);

        //  AS inc.3: registrar el binding register("reg") -> slot.
        // El backend port-C materializa este ALLOCA como una variable C
        // con register-pin de GCC y traduce sus LOAD/STORE a accesos
        // directos a la variable.
        if (!vd->reg_binding.empty()) {
            const std::string &rb = vd->reg_binding;
            const bool is_vec =
                rb.rfind("xmm", 0) == 0 || rb.rfind("ymm", 0) == 0 ||
                rb.rfind("zmm", 0) == 0 || rb.rfind("XMM", 0) == 0 ||
                rb.rfind("YMM", 0) == 0 || rb.rfind("ZMM", 0) == 0;
            ir::AsmRegBinding b{addr, rb, vt, is_vec, vd->name};
            b.reg_class = rb; // registro concreto: la clase es el registro.
            fn_->asm_reg_bindings.push_back(std::move(b));
        }

        // Store del valor inicial (o 0 si no hay init).
        ir::IrValueId v0 = ir::IR_NO_VALUE;
        if (vd->init) {
            v0 = lower_expr(vd->init.get());
            if (v0 != ir::IR_NO_VALUE) {
                const ir::IrType vfrom = fn_->values[v0].type;
                // Suprimir el warning de cast implicito cuando el
                // init es un literal: `u8 init = 0` no merece
                // alarma porque el valor es estatico y conocido en
                // compile-time; es un patron habitual y el type
                // checker ya valida el rango.
                const bool init_is_literal =
                    vd->init->kind == ast::NodeKind::IntLitExpr ||
                    vd->init->kind == ast::NodeKind::FloatLitExpr ||
                    vd->init->kind == ast::NodeKind::BoolLitExpr ||
                    vd->init->kind == ast::NodeKind::CharLitExpr ||
                    vd->init->kind == ast::NodeKind::NullLitExpr;
                v0 = cast_if_needed(v0, vfrom, vt, vd->init->loc,
                                    /*is_explicit=*/init_is_literal);
            }
        }
        if (v0 == ir::IR_NO_VALUE) v0 = emit_const(vt, 0, vd->loc.line);

        emit_store_typed(addr, v0, vt, vd->loc.line);
    }
    return true;
}

} // namespace vx
