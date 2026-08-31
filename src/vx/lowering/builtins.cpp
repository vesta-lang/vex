/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file vx/lowering/builtins.cpp
 * @brief Bajada de las funciones que el lenguaje trae puestas.
 *
 * Los builtins de Vesta son las llamadas que el compilador reconoce por su
 * NOMBRE y baja el mismo, sin que exista una funcion que llamar: imprimir,
 * prestamos, atomicos, cadenas, reflexion, introspeccion en tiempo de
 * compilacion, colecciones, primitivas de concurrencia.
 *
 * Estaban dentro de lowering.cpp, en una funcion de mas de siete mil lineas --
 * el diecisiete por ciento de un fichero de cuarenta y tres mil --, y de ahi
 * sale: es un area con tema propio y se lee entera sin tener delante el resto
 * del lowering.
 *
 * Lo que queda por hacer, y conviene tenerlo escrito: dentro de esta funcion el
 * despacho sigue siendo una cascada de comparaciones -- ciento treinta
 * comparaciones de cadena que se evaluan SIEMPRE, y despues hasta ciento once
 * `if` encadenados, para bajar cualquier builtin --.  Repartir por familias y
 * despachar por tabla es el siguiente paso; este solo mueve el bloque de sitio,
 * sin tocar una linea de su logica.
 */
#include "vx/lowering.h"
#include "vx/collection_intrinsics.h"
#include "vx/generics/concepts.h"
#include "vx/comptime/comptime_introspect.h"
#include "vx/builtin_names.h" // reconocer el nombre de una vez, no comparandolo 200 veces
#include "ir/ir_type_info.h" // vocabulario UNICO de anchura/clase de un IrType
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include "lowering_internal.h" // la cocina compartida del lowering (no es su interfaz)

namespace vx {

bool Lowering::try_lower_builtin_call(ast::CallExpr *e,
                                      ir::IrValueId &out_value) {
    // Solo manejamos identifier-callees (validado en lower_call).
    if (!e->callee || e->callee->kind != ast::NodeKind::IdentExpr) return false;
    const auto *id = static_cast<const ast::IdentExpr *>(e->callee.get());
    const std::string &name = id->name;

    /* Lo primero: ¿es siquiera un builtin?  Casi ninguna llamada de un
     * programa lo es -- son funciones del usuario --, y averiguarlo costaba
     * recorrer las familias y evaluar doscientas comparaciones de cadena antes
     * de contestar que no.  Una busqueda binaria lo decide de una vez, y ni
     * siquiera llega a buscar si la longitud del nombre no cae en el rango de
     * los que hay.
     *
     * Con UNA excepcion, y no es un detalle: un concepto usado como predicado
     * -- `Comparable<T>()` -- se baja aqui abajo, y su nombre lo pone el
     * usuario, asi que no puede estar en ninguna lista.  Lo que lo distingue
     * no es como se llama sino su FORMA: lleva argumentos de tipo y ninguno de
     * ejecucion.  Los conceptos que trae el lenguaje se invocan igual, asi que
     * la misma comprobacion los cubre a los dos. */
    const bool looks_like_concept = !e->type_args.empty() && e->args.empty();
    const Builtin b = builtin_from_name(name);
    if (!looks_like_concept && b == Builtin::Unknown) return false;

    /* Cada familia atiende un grupo de builtins y son DISJUNTAS, asi que no
     * hace falta preguntarles por turno: la tabla dice cual es la suya y se va
     * derecho.  Antes se les preguntaba a las siete, y como cada una empieza
     * descartando los nombres que no son suyos, eso era recorrer las listas de
     * las seis que iban a decir que no.
     *
     * Una familia puede contestar que NO aunque el nombre sea suyo -- cuando
     * la forma de la llamada no encaja con ninguno de sus casos --, y entonces
     * el flujo sigue hacia abajo, al despacho general, igual que antes. */
    switch (builtin_family(b)) {
    case BuiltinFamily::Print:
        /* Imprimir: no es escribir sino averiguar QUE se escribe -- cada tipo
         * va distinto -- y con que forma.  Mas las secuencias del terminal,
         * que salen por la misma primitiva. */
        if (try_lower_print_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Runtime:
        /* Lo que pide algo al MUNDO: ficheros, memoria del anfitrion, fibras,
         * modulos cargados en marcha.  Ninguno se resuelve dentro del
         * programa. */
        if (try_lower_runtime_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Concurrent:
        /* Lo que supone que hay ALGUIEN MAS: memoria compartida, atomicos,
         * buzones y futuros.  Existen porque lo que uno escribe lo tiene que
         * ver el otro, y en el orden correcto. */
        if (try_lower_concurrent_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Optional:
        /* Lo que puede NO estar: Optional y Result.  Los dos son la misma
         * idea -- un valor que lleva consigo si esta -- y ninguno toca el
         * monton. */
        if (try_lower_optional_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Reflect:
        /* Preguntarle al programa por si mismo: la clase por su nombre, el
         * campo por el suyo, llamar sin saber a que hasta ese momento.  Es lo
         * contrario de todo lo demas, que se decide al compilar. */
        if (try_lower_reflect_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Ownership:
        /* Quien es dueno de que y quien lo suelta.  Casi todo se decide al
         * COMPILAR: un prestamo son ocho bytes y sus reglas desaparecen del
         * codigo generado. */
        if (try_lower_ownership_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::String:
        /* Lo que se hace CON una cadena: medirla, cortarla, unirla,
         * compararla, sacarla al exterior.  Cada uno baja a UNA instruccion de
         * la maquina, no a una llamada. */
        if (try_lower_string_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Math:
        /* Las operaciones matematicas.  Los numeros con decimales viajan a la
         * nativa como sus BITS metidos en un entero, porque la maquina pasa
         * los argumentos en registros de proposito general; las que devuelven
         * un entero NO hacen esa conversion. */
        if (try_lower_math_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Introspect:
        /* Lo que se responde MIRANDO LOS TIPOS al compilar: cuanto mide, como
         * se alinea, cuantos campos tiene.  Su respuesta no se calcula, se
         * sabe: `sizeof<Punto>()` baja a la constante 16, no a una lectura.
         * Junto con los conceptos, es la unica familia cuyo coste en ejecucion
         * es exactamente cero. */
        if (try_lower_introspect_builtins(e, b, out_value)) return true;
        break;
    case BuiltinFamily::Other:
        /* Los que aun no tienen familia propia: caen al despacho de abajo. */
        break;
    }

    // -----------------------------------------------------------------
    // AOT 2c (dev OS): simbolos de seccion.  section_start/end(".x") -> void*,
    // section_size(".x") -> u64.  El arg debe ser un string LITERAL (el nombre
    // de la seccion); emitimos SECTION_REF(func_name=nombre, imm=kind).  El
    // writer AOT lo resuelve via reloc tras el layout; en interp/JIT -> 0.
    // -----------------------------------------------------------------
    if ((b == Builtin::SectionStart || b == Builtin::SectionEnd ||
         b == Builtin::SectionSize) &&
        e->args.size() == 1) {
        auto *lit = dynamic_cast<ast::StringLitExpr *>(e->args[0].get());
        if (lit == nullptr || !lit->interp_parts.empty()) {
            return builtin_error(
                e->loc,
                name + ": el argumento debe ser un string "
                       "literal con el nombre de la seccion (e.g. "
                       "\".boot\")",
                out_value);
        }
        const uint64_t kind = (b == Builtin::SectionStart) ? 0u
                              : (b == Builtin::SectionEnd) ? 1u
                                                           : 2u;
        const ir::IrType rt =
            (b == Builtin::SectionSize) ? ir::IrType::I64 : ir::IrType::PTR;
        const ir::IrValueId dst = fn_->new_value(rt);
        // section_start/end devuelven un host_ptr real (la VA de la seccion);
        // marcarlo asi para que un LOAD/STORE posterior use el path host.
        if (kind != 2) fn_->values[dst].is_host_ptr = true;
        ir::IrInstr is{};
        is.op = ir::IrOp::SECTION_REF;
        is.type = rt;
        is.dst = dst;
        is.func_name = lit->value; // nombre de la seccion
        is.imm = kind;
        is.source_line = e->loc.line;
        emit(current_block_, std::move(is));
        out_value = dst;
        return true;
    }

    // -----------------------------------------------------------------
    // Sprint 1: builtins comptime de introspection.
    // Disparan SOLO cuando hay type_args.size()>=1.  Devuelven UN
    // valor constante computado a partir del tipo resuelto:
    //   sizeof<T>()   -> u64
    //   alignof<T>()  -> u64
    //   typename<T>() -> string (StringObject)
    //   type_id<T>()  -> u32
    //   kind<T>()     -> i32 (ComptimeKind enum)
    // Cero overhead runtime: la salida es un solo IrOp::CONST (o
    // STRMAKE para strings).
    // -----------------------------------------------------------------
    // Sprint B.1: as_native_callback(fn) -> i64 (host_ptr al thunk).
    //
    // Lowering: emite CALLN a vesta_runtime:vx_get_native_thunk con:
    //   r1 = @Absolute("code.<fn_name>")  (PC virtual de la fn Vesta)
    //   r2 = argc (numero de parametros que la fn Vesta recibe)
    // El runtime genera (o reusa) un thunk x86-64 callable con cc C
    // nativa y devuelve el host_ptr.
    if (b == Builtin::AsNativeCallback && e->args.size() == 1) {
        auto *fn_id = dynamic_cast<ast::IdentExpr *>(e->args[0].get());
        if (fn_id == nullptr) {
            return builtin_error(
                e->loc,
                "as_native_callback: arg debe ser identificador de fn Vesta",
                out_value);
        }
        /* Resolver la signature de la fn Vesta para conocer argc. */
        uint32_t argc = 0;
        const FunctionSig *fsig = tc_.function_sig_by_name(fn_id->name);
        if (fsig != nullptr) {
            argc = (uint32_t)fsig->param_types.size();
        }
        const uint32_t src_line = e->loc.line;
        /* v_fn_pc = LABEL_ADDR("code.<fn_name>") */
        ir::IrValueId v_fn_pc = emit_label_addr(fn_id->name, src_line);
        /* v_argc = CONST i64 */
        ir::IrValueId v_argc =
            emit_const(ir::IrType::I64, (uint64_t)argc, src_line);
        /* CALLN @Method("vesta_runtime:vx_get_native_thunk", v_fn_pc, v_argc).
         */
        ir::IrValueId v_dst =
            emit_native_call("vesta_runtime", "vx_get_native_thunk",
                             {v_fn_pc, v_argc}, ir::IrType::I64, src_line);
        out_value = v_dst;
        return true;
    }

    // fiber_entry(fn) -> VA de bytecode VM de la funcion (PC de arranque de una
    // fibra en el path INTERPRETE, FN.1).  Emite LABEL_ADDR("code.<fn>") sin
    // pasar por el enrutado a naked_fnaddr del cast `(cfn) fn` -> el `swapctx`
    // fija este PC y el interprete ejecuta el cuerpo como bytecode NORMAL.
    if (b == Builtin::FiberEntry && e->args.size() == 1) {
        auto *fn_id = dynamic_cast<ast::IdentExpr *>(e->args[0].get());
        if (fn_id == nullptr) {
            return builtin_error(
                e->loc, "fiber_entry: arg debe ser identificador de fn cuerpo",
                out_value);
        }
        out_value = emit_label_addr(fn_id->name, e->loc.line);
        return true;
    }

    // -----------------------------------------------------------------
    // Concepto como PREDICADO: `Concepto<T>()` -> CONST bool.  El type
    // checker ya valido que sea un concepto (built-in o de usuario) con
    // 1 type-arg y 0 args runtime.
    // -----------------------------------------------------------------
    if (!e->type_args.empty() && e->args.empty() &&
        (is_builtin_concept(name) ||
         tc_.concepts().find(name) != tc_.concepts().end())) {
        const uint32_t src_line = e->loc.line;
        const Type t1 = tc_.resolve_type_node(e->type_args[0].get());
        const ConceptEval ce = comptime_eval_concept(tc_, name, t1);
        out_value =
            emit_const(ir::IrType::BOOL,
                       (ce.found && ce.satisfied) ? 1ULL : 0ULL, src_line);
        return true;
    }

    // Conjunto de nombres builtin reconocidos.  Si el nombre no esta
    // aqui devolvemos false para que lower_call siga con la ruta
    // generica (CALL a una funcion del usuario).
    // monitor builtins.  Cada uno baja a 1 instruccion bytecode.
    // Variadicos: vacount() -> lee el param oculto __vacount (numero de args
    // variadicos empaquetados por el caller).
    if (b == Builtin::Vacount) {
        const ir::IrValueId v = lookup("__vacount");
        if (v == ir::IR_NO_VALUE) {
            return builtin_error(
                e->loc,
                "vacount() solo es valido dentro de una funcion "
                "con un parametro variadico 'T... name'",
                out_value);
        }
        out_value = v;
        return true;
    }
    // argv del script: bajan a getargc/getarg.
    // futures builtins.
    // constructor de tipo coleccion primitivo (arraylist, hashmap,
    // hashset, queue, deque, treemap, treeset, stack).  Si find_col_ctor
    // devuelve no-null, el lowering emite CALLN al native_new_fn del
    // plugin vesta_collections con el argumento de capacidad inicial
    // (o sin args para tipos sin default_cap como TreeMap).
    const ColType *col_ctor = find_col_ctor(name);
    const bool is_col_ctor = (col_ctor != nullptr);
    // panic("msg") -> opcode panic con FATAL_USER_ABORT.
    const bool is_panic = (b == Builtin::Panic);
    const bool is_gensym_b = (b == Builtin::Gensym);
    const bool is_static_assert_b = (b == Builtin::StaticAssert);
    /* Aqui NO estan los que atienden las familias, y no es un olvido: se
     * despachan arriba, asi que si el flujo llega hasta este punto es que el
     * nombre no era de ninguna de ellas. */
    const bool is_any_builtin =
        is_panic || is_gensym_b || is_static_assert_b || is_col_ctor;
    if (!is_any_builtin) return false;

    // Helper interno para registrar un literal de string en static_data

    // ===== Constructor de coleccion primitiva =====
    // arraylist(N) -> CALLN vcol_alist_new(N), retorno i64 handle.
    // Para tipos sin default_cap (TreeMap/TreeSet) la firma del builtin
    // no toma argumentos; emitimos CALLN con argc=0.
    if (is_col_ctor) {
        std::vector<ir::IrValueId> arg_ids;
        for (auto &a : e->args) {
            arg_ids.push_back(lower_expr(a.get()));
        }
        // Si el ctor tiene default_cap > 0 y el usuario llamo sin args,
        // sintetizamos la cap por defecto.  El type checker valida que
        // siempre haya 1 arg para los ctors con default_cap; pero por
        // seguridad emitimos default cuando el array de args esta vacio.
        if (arg_ids.empty() && col_ctor->default_cap > 0) {
            arg_ids.push_back(emit_const(
                ir::IrType::I64, static_cast<uint64_t>(col_ctor->default_cap),
                e->loc.line));
        }
        const ir::IrValueId v_dst =
            emit_native_call(COL_NATIVE_LIB, col_ctor->native_new_fn,
                             std::move(arg_ids), ir::IrType::I64, e->loc.line);
        out_value = v_dst;
        return true;
    }

    // ----- ffi_open(string lit) -----
    // Carga DLL en runtime via opcode dlopen (extended 0x62).  Path
    // siempre como string literal (interned en static_data).  Devuelve
    // handle host como i64.

    // ----- panic("msg") -----
    // dispara FatalError(USER_ABORT, msg).  Capturable con
    // try/catch FatalError; si no hay handler, mata el proceso.
    // Acepta string literal (interna en static_data + emite panic
    // directo) o expresion string-typed (no soportado todavia).
    if (is_panic) {
        if (e->args.size() != 1 || !e->args[0] ||
            e->args[0]->kind != ast::NodeKind::StringLitExpr) {
            return builtin_error(
                e->loc, "panic: requiere un string literal con el mensaje",
                out_value);
        }
        auto *slit = static_cast<ast::StringLitExpr *>(e->args[0].get());
        const uint64_t msg_idx = intern_class_name(*out_mod_, slit->value);
        const uint32_t msg_len = static_cast<uint32_t>(slit->value.size());
        // Sprint 6.D: panic via IR op puro (STR_LIT_ADDR + CONST + PANIC).
        // AOT.2.d: en native el msg vive en static_data y el HOST_LEAF lo baja
        // a una ref .rodata.
        //
        // El indice viaja como NUMERO (`imm`), nunca como el nombre textual
        // "s_<idx>" de un LABEL_ADDR: al mergear modulos, el pool de
        // static_data se concatena y se deduplica, y los dos pases que
        // renumeran (compiler_project.cpp) reescriben `STR_LIT_ADDR.imm` --
        // no el `func_name` de un LABEL_ADDR.  Un `panic()` dentro de un
        // modulo IMPORTADO conservaba su indice local y acababa apuntando al
        // slot que ese indice ocupa en el modulo consumidor (p.ej. el storage
        // de una variable global, que ademas vive en `gdata` y no en `code`)
        // -> "RelocationError: simbolo no resuelto: code.s_0".
        ir::IrValueId v_addr = fn_->new_value(ir::IrType::PTR);
        // Solo en native el literal es memoria del host; en la VM el mensaje
        // vive en su espacio de direcciones y PANIC lo lee de ahi.
        if (native_poo_) fn_->values[v_addr].is_host_ptr = true;
        {
            ir::IrInstr sa{};
            sa.op = ir::IrOp::STR_LIT_ADDR;
            sa.type = ir::IrType::PTR;
            sa.dst = v_addr;
            sa.imm = msg_idx;
            sa.source_line = e->loc.line;
            emit(current_block_, std::move(sa));
        }
        const ir::IrValueId v_len = emit_const(
            ir::IrType::I64, static_cast<uint64_t>(msg_len), e->loc.line);
        ir::IrInstr p{};
        p.op = ir::IrOp::PANIC;
        p.type = ir::IrType::VOID;
        p.dst = ir::IR_NO_VALUE;
        p.operands = {v_addr, v_len};
        p.source_line = e->loc.line;
        emit(current_block_, std::move(p));
        block_terminated_ =
            true; // panic es terminador (no retorna salvo via catch)
        out_value = ir::IR_NO_VALUE;
        return true;
    }

    /*  MC.15C: builtins comptime aliasados a codigo runtime.
     * Cuando aparecen en cuerpos de @Macro lowereados a IR, se
     * compilan a una secuencia de bytecode equivalente al AST eval. */

    if (is_static_assert_b) {
        /*  MC.20: `static_assert(cond, msg)` se baja a CALLN
         * a la virtual kVestaIoLib `vesta_comptime:static_assert`.  El fn
         * recibe (cond_i64, msg_cstr) y emite diagnostic error si
         * cond es 0.  Cuando el macro corre via VM en compile time,
         * la check se ejecuta tambien en compile time -- mismo
         * resultado que el AST eval inline. */
        if (e->args.size() != 2) {
            return builtin_error(
                e->loc, "static_assert: se esperaba 2 args (cond, msg)",
                out_value);
        }
        const ir::IrValueId v_cond = lower_expr(e->args[0].get());
        if (v_cond == ir::IR_NO_VALUE) {
            out_value = ir::IR_NO_VALUE;
            return true;
        }
        /* msg: cualquier string comptime-evaluable, no solo un literal.  El
         * type checker ya lo admite explicitamente -- una `const string` con el
         * mensaje, o una concatenacion -- porque exigir el literal obliga a
         * repetir el mismo texto en cada assert.  Exigirlo AQUI contradecia esa
         * regla: el mismo assert pasaba el chequeo y luego se rechazaba al
         * bajarlo.  Va como host_ptr al buffer estable de static_data,
         * NUL-terminado por construccion. */
        const ast::Expr *msg_e = e->args[1].get();
        std::string msg_text;
        const auto *slit =
            (msg_e && msg_e->kind == ast::NodeKind::StringLitExpr)
                ? static_cast<const ast::StringLitExpr *>(msg_e)
                : nullptr;
        if (slit && !slit->is_interpolated()) {
            msg_text = slit->value;
        } else if (ComptimeEvalResult mv =
                       comptime_eval_expr(tc_, const_cast<ast::Expr *>(msg_e));
                   mv.ok && mv.is_str) {
            msg_text = mv.str;
        } else {
            return builtin_error(
                e->loc,
                "static_assert: el msg debe ser un string "
                "comptime-evaluable (un literal, una 'const string' o una "
                "concatenacion de ambos)",
                out_value);
        }
        /* El mensaje viaja como (direccion, longitud) del espacio de la VM y
         * el helper lo lee con la API del proceso, igual que cualquier otro
         * nativo (`vio_print` y companyia).  Antes se le pasaba la direccion a
         * secas y el helper la trataba como puntero del anfitrion: un numero
         * como 0x27050 que al leerse se llevaba el proceso por delante.  Nunca
         * se habia notado porque esta ruta no llegaba a ejecutarse -- la
         * asercion se descartaba siempre. */
        std::vector<uint8_t> bytes(msg_text.begin(), msg_text.end());
        const uint64_t idx = out_mod_->intern_static_data(std::move(bytes));
        ir::IrValueId v_msg = fn_->new_value(ir::IrType::PTR);
        if (native_poo_) fn_->values[v_msg].is_host_ptr = true;
        {
            ir::IrInstr is{};
            is.op = ir::IrOp::STR_LIT_ADDR;
            is.type = ir::IrType::PTR;
            is.dst = v_msg;
            is.imm = idx;
            is.source_line = e->loc.line;
            emit(current_block_, std::move(is));
        }
        const ir::IrValueId v_len =
            emit_const(ir::IrType::I64, static_cast<uint64_t>(msg_text.size()),
                       e->loc.line);
        const ir::IrValueId v_proc = emit_getproc(e->loc.line);
        /* Corre AL COMPILAR: comprueba la condicion y, si falla, corta la
         * compilacion con el mensaje.  Lo unico que toca del programa es leer
         * ese mensaje (tercer argumento), que es un literal.
         *
         * Lo que hace el codigo comptime son efectos sobre la COMPILACION, no
         * sobre el programa compilado; de ahi que no haya nada mas que declarar
         * aunque aborte. */
        ir::IrNativeEffects fx;
        fx.declared = true;
        fx.comptime = true;
        fx.reads_pointee = 1u << 2; // el mensaje
        ir::IrValueId v_dst = emit_native_call(
            "vesta_comptime", "static_assert", {v_proc, v_cond, v_msg, v_len},
            ir::IrType::I64, e->loc.line, &fx);
        /* Una asercion incumplida CORTA la ejecucion aqui mismo.
         *
         * El helper devuelve el veredicto y antes se ignoraba, con lo que el
         * cuerpo seguia corriendo sobre datos que ya se sabian invalidos.  El
         * corte es un `panic` y no un `hlt`: lleva el mensaje, construye la
         * traza de llamadas y -- lo que de verdad importa -- se puede capturar
         * con `try`/`catch` desde el propio codigo comptime, que un `hlt` no
         * permitiria. */
        const ir::IrBlockId sa_fail = fn_->new_block("assert_fail");
        const ir::IrBlockId sa_cont = fn_->new_block("assert_ok");
        // El helper devuelve != 0 cuando la asercion NO se cumple.
        emit_br_cond(v_dst, sa_fail, sa_cont, e->loc.line);
        {
            /* PANIC lee el mensaje de la memoria de la VM, igual que el helper:
             * se reusan las mismas direccion y longitud. */
            ir::IrInstr p{};
            p.op = ir::IrOp::PANIC;
            p.type = ir::IrType::VOID;
            p.dst = ir::IR_NO_VALUE;
            p.operands = {v_msg, v_len};
            p.source_line = e->loc.line;
            emit(sa_fail, std::move(p));
        }
        current_block_ = sa_cont;
        out_value = v_dst;
        return true;
    }

    if (is_gensym_b) {
        /* gensym() -> u64.  Counter incrementado en cada call.
         * Implementado via CALLN a vio_gensym() en el plugin
         * vesta_io que mantiene un counter estatico. */
        if (!e->args.empty()) {
            return builtin_error(e->loc, "gensym: no acepta argumentos",
                                 out_value);
        }
        ir::IrValueId v_dst = emit_native_call(kVestaIoLib, "vio_gensym", {},
                                               ir::IrType::U64, e->loc.line);
        out_value = v_dst;
        return true;
    }

    // ----- forName(string_lit) -----
    // Reflexion: devuelve ClassInfo* (i64 opaco) registrado en el
    // ClassRegistry por nombre.  Acepta SOLO un string literal.
    // Internamos el nombre en static_data (deduplicado:
    // si la clase ya esta declarada en __module_init, comparten idx).

    // ----- wait(obj) / notify(obj) / notifyAll(obj) -----
    // El argumento es CLASS (host pointer); las instrucciones monwait/
    // monnoti/monnota requieren GcHandle.  Convertimos primero via
    // gchandle (O(1) en el GcHeap) y luego ejecutamos la operacion.
    // Devuelven void; no participan en expresiones.

    // =====================================================================
    // Smart pointers builtins: unique<T> / shared<T>.
    // =====================================================================
    //
    // Modelo de slot: una variable @c unique<T> p esta bound a un SSA
    // value que es la DIRECCION de un slot stack de 8 bytes que
    // contiene el host_ptr al recurso.  Todas las operaciones acceden
    // al recurso via ese slot:
    //   get(p)            -> LOAD [slot]
    //   move(p) -> q      -> mvtake [q_slot], [p_slot]  (1 instr VM)
    //   cleanup scope exit -> LOAD ptr; CMP_EQ 0; CALL free(ptr) si no-null
    //
    // Para shared<T> el slot contiene un host_ptr al control block
    // gestionado por GC.  El control block tiene refcount@0, deleter@8,
    // payload inline desde +16.

    // ----- bug6 gc_box(value) -----  gc<T> para T CUALQUIERA.
    // Aloja el valor en un bloque GC-managed (GC_ALLOCP en interp/JIT,
    // vx_gc_alloc_ptr en AOT) de sizeof(T) bytes y devuelve el host_ptr al
    // box.  El GC recolecta el box cuando deja de ser alcanzable (stackmaps
    // precisos); no hay RAII (mismo modelo que gc<Clase>).  El valor interno
    // se lee con `*g` (deref).  Generaliza el modelo gc<Clase> (que aloja una
    // INSTANCIA de clase) a primitivos (gc<i64>), smart pointers (gc<unique<
    // i64>>) y anidamiento arbitrario (gc<shared<unique<i64>>>).

    // ----- ptr_of(p) -----  T* host, sin consumir el smart pointer.
    // unique<T>: LOAD ptr from [slot]; resultado is_host_ptr.
    // shared<T>: LOAD ctrl from [slot]; ADD 16; resultado is_host_ptr.

    // ----- pid() -----
    // Devuelve el PID encoded del proceso actual via getpid r_dst.

    // ----- msgsend(pid, value) -----
    // Reservamos 8 bytes en el frame del caller (alloca i8[8]),
    // escribimos `value` ahi como i64, y emitimos:
    //   msgsend r_pid, r_addr, r_len   (r_len = 8)
    // El opcode bytecode deposita 1/0 en R0 (ok flag), que capturamos
    // como i32 dst de la expresion.

    // No deberia alcanzarse: todos los builtins listados arriba estan
    // cubiertos.
    return false;
}

} // namespace vx
