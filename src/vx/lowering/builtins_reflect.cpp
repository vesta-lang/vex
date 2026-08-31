/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins_reflect.cpp
 * @brief Bajada de preguntarle al programa por si mismo: reflexion.
 *
 * Todo lo demas que baja este compilador se decide AL COMPILAR: cuando el
 * tipo se conoce, `obj.campo` es leer en un desplazamiento fijo y
 * `obj.metodo()` es un salto a una ranura conocida.  Estos once builtins son
 * lo contrario -- buscar la clase por su nombre, el campo por el suyo, el
 * metodo por el suyo, y llamarlo sin saber cual es hasta ese momento --.
 *
 * Que eso sea posible no es gratuito y aqui esta la razon: las clases de
 * Vesta NO son metadatos del ejecutable, son objetos que el propio programa
 * construye al arrancar llamando a `defclass` / `deffield` / `defmethod`.  Al
 * quedar en el registro de la maquina, preguntar por ellas en marcha es mirar
 * donde ya estan, no reconstruir nada.  Por eso la reflexion sale casi de
 * balde y por eso una clase declarada en el fuente y otra creada en marcha se
 * consultan igual.
 *
 * El coste esta donde debe: quien conoce el tipo no pasa por aqui.  Un campo
 * buscado por nombre cuesta un hash y una o dos sondas; leerlo cuando el tipo
 * se sabe cuesta un desplazamiento.  La reflexion no encarece al que no la
 * usa.
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
 * @brief Intenta bajar @p e como uno de los builtins de reflexion.
 *
 * @param e         La llamada.
 * @param b         Que builtin es, ya resuelto por quien despacha.
 * @param out_value Donde dejar el resultado; sin valor si el builtin no lo da.
 * @return @c true si @p b era de esta familia y quedo bajado.
 */
bool Lowering::try_lower_reflect_builtins(ast::CallExpr *e, Builtin b,
                                          ir::IrValueId &out_value) {
    // Encontrar: la clase por su nombre, y la de un objeto que ya se tiene.
    const bool is_forName = (b == Builtin::ForName);
    const bool is_getClass = (b == Builtin::GetClass);
    // Encontrar dentro de una clase: un campo o un metodo, por su nombre.
    const bool is_getField = (b == Builtin::GetField);
    const bool is_getMethod = (b == Builtin::GetMethod);
    // Usar lo encontrado: crear un objeto y llamar a un metodo sin saber
    // cual era hasta este momento.
    const bool is_newInstance = (b == Builtin::NewInstance);
    const bool is_invoke = (b == Builtin::Invoke);
    // Dentro de un aspecto @Around: llamar a lo que se estaba interceptando.
    const bool is_proceed = (b == Builtin::Proceed);
    // Recorrer: cuantos hay y cual es el de la posicion N.
    const bool is_getMethods = (b == Builtin::GetMethods);
    const bool is_getFields = (b == Builtin::GetFields);
    const bool is_getMethodAt = (b == Builtin::GetMethodAt);
    const bool is_getFieldAt = (b == Builtin::GetFieldAt);

    /* Salida rapida: si no es de esta familia no se mira nada de lo de abajo.
     */
    if (!(is_forName || is_getClass || is_getField || is_getMethod ||
          is_newInstance || is_invoke || is_proceed || is_getMethods ||
          is_getFields || is_getMethodAt || is_getFieldAt))
        return false;

    if (is_forName) {
        if (e->args.size() != 1 || !e->args[0] ||
            e->args[0]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(e->loc,
                                 "forName: requiere un string literal con el "
                                 "nombre de la clase",
                                 out_value);
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[0].get());
        const uint64_t name_idx = intern_class_name(*out_mod_, slit->value);
        const uint32_t name_len = static_cast<uint32_t>(slit->value.size());

        // RAW_ASM con dst = SSA val.  Usamos {dst} como placeholder
        // Sprint 5: emit_findclass_by_name reemplaza emit_findclass_inline
        // (textual) por secuencia IR pura.
        out_value = emit_findclass_by_name(name_idx, name_len, e->loc.line);
        return true;
    }

    // ----- getField(cls, "name") -----
    // Reflexion: devuelve FieldInfo* (i64 opaco) buscando el campo
    // por nombre dentro de la clase indicada.  Args: cls = i64
    // (ClassInfo* obtenido via forName/getClass), name = string lit.
    // El lowering construye FindMethodParamsLayout (mismo shape que
    // findfield espera) en stack y emite la instruccion findfield.
    if (is_getField) {
        if (e->args.size() != 2 || !e->args[0] || !e->args[1] ||
            e->args[1]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(
                e->loc, "getField: requiere (i64 cls, string lit name)",
                out_value);
        }
        const ir::IrValueId v_cls = lower_expr(e->args[0].get());
        if (v_cls == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[1].get());
        const uint64_t name_idx = intern_class_name(*out_mod_, slit->value);
        const uint32_t name_len = static_cast<uint32_t>(slit->value.size());

        // Construir FindFieldParams (24 bytes: class_ptr, name_addr,
        // name_len, _pad) en stack y llamar findfield.  El SCRATCH r12
        // se usa como puntero a la struct y receptor del resultado.
        std::ostringstream oss;
        oss << "subsp rsp, 24\n";
        oss << "mov r12, rsp\n";
        // [+0] class_ptr -- usamos un mov via emit_store: lo cargamos
        // de un valor SSA conocido v_cls.  Como en el bloque RAW_ASM
        // no podemos referenciar SSA values, primero materializamos
        // v_cls en r0 via un MOV IR que precede al RAW_ASM.

        // Materializar v_cls en r0 antes del RAW_ASM.  Usamos MOV IR
        // que el regalloc resolvera moviendo el reg de v_cls a r0.
        ir::IrInstr mv_cls{};
        mv_cls.op = ir::IrOp::MOV;
        mv_cls.type = ir::IrType::I64;
        // Sin dst SSA: solo queremos el side effect de poner v_cls en
        // r0.  Usamos un nuevo SSA con regalloc forzado a r0 mediante
        // RAW_ASM con {dst} - mas simple: incrustamos en RAW_ASM un
        // load directo del SSA reg via la convencion de load_src.
        //
        // Alternativa mas limpia: emitimos un solo RAW_ASM que toma
        // el reg de v_cls como string y lo usa.  Pero RAW_ASM no
        // expone los regs de operandos.
        //
        // Solucion: usamos CALL a una funcion sintetica? No, demasiado.
        //
        // Plan B: construir la struct via un RAW_ASM previo + un
        // MOV IR que pone v_cls en SCRATCH (r14) que el RAW_ASM puede
        // referenciar literalmente.  Hack: emitimos un MOV IR
        // (dst=v_cls, op=MOV, src=v_cls) -- no-op, pero garantiza que
        // v_cls este en su reg asignado.  Luego en RAW_ASM hacemos
        // mov r14, <reg_of_v_cls> -- pero no sabemos su nombre.
        //
        // La forma correcta: usar un nuevo IR op CONST_ADDR que
        // construye la struct.  Es un overhead bajo pero requiere
        // mas cambios.  limitado a soportar el caso
        // mas comun: el primer arg viene de forName (que fija el
        // resultado en r0 antes de la captura {dst}).  Pero v_cls ya
        // esta en su propio reg post-regalloc.
        //
        // Workaround: emitir un MOV IR explicito a un nuevo SSA con
        // la pista de que su reg sera r0.  Esto no esta soportado
        // limpiamente; usaremos un patron similar al de CALL:
        // emitir CALL a un nombre magico que sabe escribir la
        // struct.  Demasiado.
        //
        // SOLUCION FINAL: emitir un STORE de v_cls en una posicion
        // de stack fija, luego el RAW_ASM lee desde alli.  Mantiene
        // todo dentro del IR.
        (void)mv_cls; // descartar el plan abortado anterior

        // Reservar 24 bytes en stack: usamos ALLOCA i8 con count 24.
        const ir::IrValueId v_buf = stack_alloc_buf(24, e->loc.line);
        // STORE v_cls en buf+0 (8 bytes).
        emit_store_typed(v_buf, v_cls, ir::IrType::I64, e->loc.line);
        // STORE name_addr en buf+8.  Para esto necesitamos un puntero
        // a buf+8 -- usamos ADD.
        const ir::IrValueId v_eight =
            emit_const(ir::IrType::I64, 8, e->loc.line);
        const ir::IrValueId v_buf8 = emit_ptr_add(v_buf, v_eight, e->loc.line);
        // Cargar name_addr via STR_LIT_ADDR.
        const ir::IrValueId v_name = emit_str_lit_addr(name_idx, e->loc.line);
        emit_store_typed(v_buf8, v_name, ir::IrType::I64, e->loc.line);
        // STORE name_len en buf+16.
        const ir::IrValueId v_sixteen =
            emit_const(ir::IrType::I64, 16, e->loc.line);
        const ir::IrValueId v_buf16 =
            emit_ptr_add(v_buf, v_sixteen, e->loc.line);
        const ir::IrValueId v_len = emit_const(
            ir::IrType::I64, static_cast<uint64_t>(name_len), e->loc.line);
        emit_store_typed(v_buf16, v_len, ir::IrType::I64, e->loc.line);
        // findfield via RAW_ASM: r12 = buf, dst = SSA capturado con {dst}.
        // El reg de v_buf debe ir a r12; lo movemos via patron MOV.
        // Mas simple: emitimos `mov r12, <reg_v_buf>` mediante MOV IR
        // explicito y luego `findfield {dst}, r12` en RAW_ASM.
        //
        // El RAW_ASM con {dst} substitution maneja el destino, pero
        // los operandos (v_buf) requieren que sepamos su reg.  Como
        // no conocemos el reg en lowering time, usamos otro truco:
        // emitir un MOV IR que tenga como source v_buf y dst sera
        // un nuevo SSA cuya regalloc no controlamos.  Sin embargo el
        // emisor IR ya emite mov rA, rB donde rA es el reg de dst.
        //
        // Para forzar v_buf en r12 antes del findfield, agregamos
        // una IR_op especial... no la tengo.  Hagamos: usar el RAW_ASM
        // pero referirlo a memoria via direccion absoluta.  Imposible
        // sin acceso al reg.
        //
        // SOLUCION SIMPLE: usar un CALL falso a una funcion sintetica
        // implementada como RAW_ASM body, pasando v_buf como arg.
        // El IR emitter colocara v_buf en r1 segun la calling
        // convention.  Luego el RAW_ASM mueve r1 a r12 y llama findfield.
        //
        // Pero CALL requiere una funcion declarada.  Generemos una
        // helper inline que cumpla este rol; mas limpio: emitir un
        // RAW_ASM que use load_src... no es accesible.
        //
        // Alternativa minimal: mover v_buf a r12 via STORE+LOAD por
        // medio de un slot reservado (ALLOCA otro de 8 bytes), o
        // forzando regalloc.  El regalloc no soporta hints de reg.
        //
        // Estrategia FINAL: emitir el RAW_ASM con substitucion {src0}
        // que el emisor reemplaza por el reg del primer operando.
        // Requiere extender RAW_ASM para conocer operands tambien.
        // Lo implemento ahora.
        out_value = emit_findfield(v_buf, e->loc.line);
        return true;
    }

    // ----- getMethod(cls, "name") -----
    // Reflexion: devuelve MethodInfo* (i64 opaco) buscando el metodo
    // por nombre dentro de la clase.  Args: cls = i64 (ClassInfo*),
    // name = string lit.  Misma estructura que getField pero usando
    // el opcode bytecode `findmethod` (0xCD).  El struct param es
    // FindMethodParams (24 bytes: class_ptr, name_addr, name_len).
    if (is_getMethod) {
        if (e->args.size() != 2 || !e->args[0] || !e->args[1] ||
            e->args[1]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(
                e->loc, "getMethod: requiere (i64 cls, string lit name)",
                out_value);
        }
        const ir::IrValueId v_cls = lower_expr(e->args[0].get());
        if (v_cls == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[1].get());
        const uint64_t name_idx = intern_class_name(*out_mod_, slit->value);
        const uint32_t name_len = static_cast<uint32_t>(slit->value.size());
        // ALLOCA 24 bytes para FindMethodParams.
        const ir::IrValueId v_buf = stack_alloc_buf(24, e->loc.line);
        // [+0] class_ptr.
        emit_store_typed(v_buf, v_cls, ir::IrType::I64, e->loc.line);
        // [+8] name_addr.
        const ir::IrValueId v_eight =
            emit_const(ir::IrType::I64, 8, e->loc.line);
        const ir::IrValueId v_buf8 = emit_ptr_add(v_buf, v_eight, e->loc.line);
        const ir::IrValueId v_name = emit_str_lit_addr(name_idx, e->loc.line);
        emit_store_typed(v_buf8, v_name, ir::IrType::I64, e->loc.line);
        // [+16] name_len.
        const ir::IrValueId v_sixteen =
            emit_const(ir::IrType::I64, 16, e->loc.line);
        const ir::IrValueId v_buf16 =
            emit_ptr_add(v_buf, v_sixteen, e->loc.line);
        const ir::IrValueId v_len = emit_const(
            ir::IrType::I64, static_cast<uint64_t>(name_len), e->loc.line);
        emit_store_typed(v_buf16, v_len, ir::IrType::I64, e->loc.line);
        out_value = emit_findmethod(v_buf, e->loc.line);
        return true;
    }

    // ----- newInstance(cls) -----
    // Crea una instancia nueva de la clase indicada (sin invocar
    // ningun constructor).  Equivalente a `Object.newInstance` de Java.
    // El usuario es responsable de inicializar los campos despues.
    // El opcode `newobj r_dst, r_cls` (0xC9) aloca un objeto en el
    // GC heap con espacio para todos los fields y devuelve un GcHandle
    // en R0.  Convertimos a host_ptr via gcderef + xchg (igual que
    // hace __new_<X>) para que el resultado sea utilizable como objeto.
    if (is_newInstance) {
        if (e->args.size() != 1 || !e->args[0]) {
            return builtin_error(e->loc,
                                 "newInstance: requiere un argumento (i64 cls)",
                                 out_value);
        }
        // Fix #1 (caso estatico): si el arg es un IdentExpr con origen
        // conocido (`Class cls = Class.forName("X")`), emitir `new X()`
        // que invoca el constructor via `__new_<X>` synthetic.  Cero
        // overhead vs newInstance directo (mismo bytecode que el frontend
        // genera para `new X()`).  Para casos dinamicos donde el origen
        // no se conoce, fallback a NEWOBJ raw (sin ctor; documentado).
        if (e->args[0]->kind == ast::NodeKind::IdentExpr) {
            auto *id = static_cast<ast::IdentExpr *>(e->args[0].get());
            auto it = class_origin_of_local_.find(id->name);
            if (it != class_origin_of_local_.end()) {
                const std::string &class_name = it->second;
                // Verificar que la clase existe en class_layouts y
                // tiene un constructor sin argumentos.  Si no, fallback.
                const auto &layouts = tc_.class_layouts();
                auto it2 = layouts.find(class_name);
                if (it2 != layouts.end()) {
                    // Sintetizar NewExpr equivalente a `new X()` y
                    // delegar en lower_new_expr (que invoca el helper
                    // sintetico __new_X que SI llama al ctor).
                    ast::NewExpr nx;
                    nx.loc = e->loc;
                    nx.class_name = class_name;
                    // Sin args (no-arg constructor).
                    out_value = lower_new_expr(&nx);
                    if (out_value != ir::IR_NO_VALUE) return true;
                    // Si lower_new_expr fallo, caer al path NEWOBJ raw.
                }
            }
        }
        const ir::IrValueId v_cls = lower_expr(e->args[0].get());
        if (v_cls == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // Usar IR_OP NEWOBJ con operands[0] = cls.
        const ir::IrValueId v_handle =
            emit_ir_unop(ir::IrOp::NEWOBJ, v_cls, ir::IrType::I64, e->loc.line);
        // Convertir handle a host_ptr (igual que __new_<X> antes del
        // ctor).  El resultado es un host_ptr GC-managed.
        const ir::IrValueId v_host = fn_->new_value(ir::IrType::I64);
        fn_->values[v_host].is_host_ptr = true;
        fn_->values[v_host].is_gc_object = true;
        {
            // raw_asm-elim 2026-05-28: gcderef + xchg -> IrOp::GC_DEREF_HOST.
            ir::IrInstr ra{};
            ra.op = ir::IrOp::GC_DEREF_HOST;
            ra.type = ir::IrType::PTR;
            ra.dst = v_host;
            ra.operands = {v_handle};
            ra.source_line = e->loc.line;
            emit(current_block_, std::move(ra));
        }
        out_value = v_host;
        return true;
    }

    // ----- invoke(method, this, args...) -----
    // Reflexion completa: invoca un MethodInfo* obtenido via getMethod
    // sobre un receiver `this`, con N args.  Equivalente a
    // `Method.invoke(receiver, args...)` de Java.  La ABI sigue el
    // patron CALLVIRT: r1 = this, r2..r12 = args, r15 = argc, r0 = ret.
    // Internamente usa el opcode bytecode `callm r_obj, r_method`
    // (0xFD) que dispara la cadena AOP advice_chain como CALLVIRT.
    if (is_invoke) {
        if (e->args.size() < 2 || !e->args[0] || !e->args[1]) {
            return builtin_error(
                e->loc, "invoke: requiere (i64 method, T this, args...)",
                out_value);
        }
        const ir::IrValueId v_method = lower_expr(e->args[0].get());
        if (v_method == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        const ir::IrValueId v_this = lower_expr(e->args[1].get());
        if (v_this == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        std::vector<ir::IrValueId> v_args;
        v_args.reserve(e->args.size() - 2);
        for (size_t k = 2; k < e->args.size(); ++k) {
            if (!e->args[k]) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            ir::IrValueId av = lower_expr(e->args[k].get());
            if (av == ir::IR_NO_VALUE) {
                out_value = ir::IR_NO_VALUE;
                return true;
            }
            v_args.push_back(av);
        }
        const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I64);
        ir::IrInstr cm{};
        cm.op = ir::IrOp::CALLM;
        cm.type = ir::IrType::I64;
        cm.dst = v_dst;
        cm.operands.push_back(v_this);   // [0] = obj
        cm.operands.push_back(v_method); // [1] = method
        for (auto av : v_args)
            cm.operands.push_back(av);
        cm.source_line = e->loc.line;
        emit(current_block_, std::move(cm));
        out_value = v_dst;
        return true;
    }

    // ----- proceed() -----
    // Re-invoca el target original de un advice @Around.  El opcode
    // `proceed` lee `frame.proceed_target` y dispatcha como CALLM con
    // los registros actuales (r1=this, args en r2..rN, ya colocados
    // por el caller del advice).  Devuelve r0 = resultado del target.
    // Capturamos r0 en el SSA dst via el patron RAW_ASM `{dst}`.
    if (is_proceed) {
        out_value = emit_proceed(e->loc.line);
        return true;
    }

    // ----- getClass(obj) -----
    // ObjectHeader::class_ptr esta en offset 0 del objeto.  El objeto
    // es un host_ptr (resultado del gcderef en __new_<X>), por lo que
    // marcamos el operando con is_host_ptr=true para que el emisor IR
    // genere `movh` en vez de `mov` y lea desde memoria HOST.
    if (is_getClass) {
        if (e->args.size() != 1) {
            return builtin_error(e->loc,
                                 "getClass: requiere exactamente 1 argumento",
                                 out_value);
        }
        const ir::IrValueId v_obj = lower_expr(e->args[0].get());
        if (v_obj == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // Las instancias creadas con `new` viven en memoria host (gcderef
        // ya las convirtio a host_ptr en __new_<X>); el flag puede
        // perderse al pasar por una variable local con register-allocation,
        // asi que lo forzamos aqui antes del LOAD.
        fn_->values[v_obj].is_host_ptr = true;
        const ir::IrValueId v_dst =
            emit_load_typed(v_obj, ir::IrType::I64, e->loc.line);
        out_value = v_dst;
        return true;
    }

    if (is_getMethods || is_getFields) {
        if (e->args.size() != 1 || !e->args[0]) {
            return builtin_error(
                e->loc,
                std::string(is_getMethods ? "getMethods" : "getFields") +
                    ": requiere 1 argumento (cls)",
                out_value);
        }
        const ir::IrValueId v_cls = lower_expr(e->args[0].get());
        if (v_cls == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // raw_asm-elim wave 2: REFLECT_COUNT con imm=0(methods) o 1(fields).
        const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I32);
        ir::IrInstr rc{};
        rc.op = ir::IrOp::REFLECT_COUNT;
        rc.type = ir::IrType::I32;
        rc.dst = v_dst;
        rc.operands = {v_cls};
        rc.imm = is_getMethods ? 0 : 1;
        rc.source_line = e->loc.line;
        emit(current_block_, std::move(rc));
        out_value = v_dst;
        return true;
    }

    // ----- getMethodAt(cls, i) / getFieldAt(cls, i) -> i64 -----
    // Devuelve &cls->methods[i] / &cls->fields[i] via los opcodes nuevos
    // getmethat / getfldat (0x6E / 0x6F, variante reg-reg de getmethod /
    // getfield).  Ambos depositan el puntero (MethodInfo* / FieldInfo*)
    // en R00, o 0 si i fuera de rango / cls nulo.
    if (is_getMethodAt || is_getFieldAt) {
        if (e->args.size() != 2 || !e->args[0] || !e->args[1]) {
            return builtin_error(
                e->loc,
                std::string(is_getMethodAt ? "getMethodAt" : "getFieldAt") +
                    ": requiere 2 argumentos (cls, i)",
                out_value);
        }
        const ir::IrValueId v_cls = lower_expr(e->args[0].get());
        const ir::IrValueId v_idx = lower_expr(e->args[1].get());
        if (v_cls == ir::IR_NO_VALUE || v_idx == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        // raw_asm-elim wave 2: REFLECT_AT con imm=0(method_at) o 1(field_at).
        const ir::IrValueId v_dst = fn_->new_value(ir::IrType::I64);
        ir::IrInstr ra{};
        ra.op = ir::IrOp::REFLECT_AT;
        ra.type = ir::IrType::I64;
        ra.dst = v_dst;
        ra.operands = {v_cls, v_idx};
        ra.imm = is_getMethodAt ? 0 : 1;
        ra.source_line = e->loc.line;
        emit(current_block_, std::move(ra));
        out_value = v_dst;
        return true;
    }

    return false;
}

} // namespace vx
